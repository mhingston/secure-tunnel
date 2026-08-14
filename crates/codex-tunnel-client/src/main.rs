use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
use codex_tunnel::{
    ClientHandshake, Preface, TransportReceiver, TransportSender, generate_keypair,
};
use codex_tunnel_client::config::ClientConfig;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore, pki_types::ServerName};
use sha2::{Digest, Sha256};
use socket2::SockRef;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::{Instant as TokioInstant, timeout},
};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Loopback client for the Codex Secure Tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "client.toml")]
        config: PathBuf,
    },
    Keygen {
        #[arg(long)]
        private_key_file: PathBuf,
    },
    Doctor {
        #[arg(long, default_value = "client.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("info")
        .without_time()
        .init();
    match Cli::parse().command {
        Command::Serve { config } => serve(&config).await,
        Command::Keygen { private_key_file } => keygen(&private_key_file),
        Command::Doctor { config } => doctor(&config).await,
    }
}

fn keygen(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        bail!(
            "refusing to overwrite existing private key {}",
            path.display()
        );
    }
    let keypair = generate_keypair().context("could not generate Noise identity")?;
    write_private_key(path, keypair.private_key())?;
    println!("Private key written: {}", path.display());
    println!("Public key: {}", STANDARD.encode(keypair.public_key()));
    println!("Fingerprint: SHA256:{}", fingerprint(keypair.public_key()));
    Ok(())
}

async fn doctor(path: &std::path::Path) -> Result<()> {
    enforce_config_permissions(path)?;
    let config = ClientConfig::load(path)?;
    let private = read_private_key(&config.identity.private_key_file)?;
    let server = decode_public_key(&config.peer.server_public_key)?;
    println!("[ok] configuration valid");
    println!("[ok] client private key readable with protected permissions");
    println!("[ok] pinned server identity configured");
    if config.outer_tls.enabled {
        println!("[ok] outer TLS 1.3 trust roots and server name configured");
    }
    let socket = TcpListener::bind(config.listen.address).await?;
    drop(socket);
    println!("[ok] local listener available");
    verify_remote_noise(&config, *private, server).await?;
    println!("[ok] remote tunnel reachable and pinned Noise identity authenticated");
    Ok(())
}

async fn serve(config_path: &std::path::Path) -> Result<()> {
    enforce_config_permissions(config_path)?;
    let config = ClientConfig::load(config_path)?;
    enforce_private_permissions(&config.identity.private_key_file)?;
    let tls = config
        .outer_tls
        .enabled
        .then(|| tls_connector(&config.outer_tls))
        .transpose()?;
    let listener = TcpListener::bind(config.listen.address)
        .await
        .with_context(|| format!("could not bind local listener {}", config.listen.address))?;
    let config = Arc::new(config);
    let tls = tls.map(Arc::new);
    let metrics = Arc::new(TunnelMetrics::default());
    let limit = Arc::new(Semaphore::new(config.limits.max_connections));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut sessions = JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    info!(listen = %listener.local_addr()?, "tunnel client listening");
    loop {
        tokio::select! {
            signal = &mut shutdown => {
                signal?;
                info!("shutdown signal received; stopping client listener");
                let _ = shutdown_tx.send(true);
                break;
            }
            accepted = listener.accept() => {
                let (local, peer) = accepted?;
                let permit = match Arc::clone(&limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(remote_address = %peer, reason = "connection_limit", "local connection rejected at configured limit");
                        continue;
                    }
                };
                let telemetry = Arc::new(metrics.connection_opened());
                let config = Arc::clone(&config);
                let tls = tls.as_ref().map(Arc::clone);
                let metrics = Arc::clone(&metrics);
                let shutdown = shutdown_rx.clone();
                info!(
                    connection_id = telemetry.id,
                    remote_address = %peer,
                    protocol_version = 1,
                    "tunnel connection opened"
                );
                sessions.spawn(async move {
                    let _permit = permit;
                    let result = handle_local(local, config, tls, Arc::clone(&telemetry), shutdown).await;
                    finish_connection(metrics, telemetry, peer, result);
                });
            }
            Some(result) = sessions.join_next(), if !sessions.is_empty() => {
                if let Err(error) = result {
                    warn!(reason = "session_task_panicked", error = %error, "tunnel session task failed");
                }
            }
        }
    }
    drop(listener);
    while let Some(result) = sessions.join_next().await {
        if let Err(error) = result {
            warn!(reason = "session_task_panicked", error = %error, "tunnel session task failed");
        }
    }
    metrics.log_snapshot();
    Ok(())
}

async fn handle_local(
    local: TcpStream,
    config: Arc<ClientConfig>,
    tls: Option<Arc<TlsConnector>>,
    telemetry: Arc<ConnectionTelemetry>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if *shutdown.borrow() {
        bail!("shutdown requested");
    }
    local
        .set_nodelay(true)
        .context("local TCP nodelay setup failed")?;
    enable_tcp_keepalive(&local).context("local TCP keepalive setup failed")?;
    let remote = tokio::select! {
        result = timeout(
            Duration::from_secs(config.timeouts.connect_seconds),
            TcpStream::connect(&config.remote.address),
        ) => result.context("remote connect timed out")??,
        changed = shutdown.changed() => {
            let _ = changed;
            bail!("shutdown requested");
        }
    };
    remote
        .set_nodelay(true)
        .context("remote TCP nodelay setup failed")?;
    enable_tcp_keepalive(&remote).context("remote TCP keepalive setup failed")?;
    if let Some(tls) = tls {
        let server_name = tls_server_name(&config.outer_tls)?;
        let remote = tokio::select! {
            result = timeout(
                Duration::from_secs(config.timeouts.handshake_seconds),
                tls.connect(server_name, remote),
            ) => result.context("outer TLS handshake timed out")??,
            changed = shutdown.changed() => {
                let _ = changed;
                bail!("shutdown requested");
            }
        };
        return run_noise(local, remote, config, telemetry, shutdown).await;
    }
    run_noise(local, remote, config, telemetry, shutdown).await
}

async fn run_noise<S>(
    local: TcpStream,
    mut remote: S,
    config: Arc<ClientConfig>,
    telemetry: Arc<ConnectionTelemetry>,
    shutdown: watch::Receiver<bool>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let private = read_private_key(&config.identity.private_key_file)?;
    let server = decode_public_key(&config.peer.server_public_key)?;
    let session = complete_noise_handshake(
        &mut remote,
        *private,
        server,
        Duration::from_secs(config.timeouts.handshake_seconds),
    )
    .await?;
    telemetry.handshake_succeeded.store(true, Ordering::Relaxed);
    info!(
        connection_id = telemetry.id,
        handshake_result = "success",
        protocol_version = 1,
        "tunnel handshake complete"
    );
    relay(
        local,
        remote,
        session.split(),
        config.timeouts.idle_seconds,
        telemetry,
        shutdown,
    )
    .await
}

async fn verify_remote_noise(
    config: &ClientConfig,
    private: [u8; 32],
    server: [u8; 32],
) -> Result<()> {
    let remote = timeout(
        Duration::from_secs(config.timeouts.connect_seconds),
        TcpStream::connect(&config.remote.address),
    )
    .await
    .context("remote connect timed out")??;
    remote.set_nodelay(true)?;
    enable_tcp_keepalive(&remote)?;
    if config.outer_tls.enabled {
        let tls = tls_connector(&config.outer_tls)?;
        let server_name = tls_server_name(&config.outer_tls)?;
        let mut remote = timeout(
            Duration::from_secs(config.timeouts.handshake_seconds),
            tls.connect(server_name, remote),
        )
        .await
        .context("outer TLS handshake timed out")??;
        complete_noise_handshake(
            &mut remote,
            private,
            server,
            Duration::from_secs(config.timeouts.handshake_seconds),
        )
        .await?;
        return Ok(());
    }
    let mut remote = remote;
    complete_noise_handshake(
        &mut remote,
        private,
        server,
        Duration::from_secs(config.timeouts.handshake_seconds),
    )
    .await
    .map(|_| ())
}

async fn complete_noise_handshake<S>(
    remote: &mut S,
    private: [u8; 32],
    server: [u8; 32],
    handshake_timeout: Duration,
) -> Result<codex_tunnel::TransportSession>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    remote.write_all(&Preface::V1.encode()).await?;
    let mut handshake = ClientHandshake::new(private, server)?;
    remote
        .write_all(
            &handshake
                .first_message()
                .context("Noise handshake failed")?,
        )
        .await?;
    remote.flush().await?;
    let reply = timeout(handshake_timeout, read_handshake_frame(remote))
        .await
        .context("Noise handshake timed out")??;
    handshake.finish(&reply).context("Noise handshake failed")
}

async fn relay(
    local: TcpStream,
    remote: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    crypto: (TransportSender, TransportReceiver),
    idle_seconds: u64,
    telemetry: Arc<ConnectionTelemetry>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let (sender, receiver) = crypto;
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);
    let (activity_tx, mut activity_rx) = mpsc::channel(1);
    let uplink_telemetry = Arc::clone(&telemetry);
    let uplink_activity = activity_tx.clone();
    let mut uplink = tokio::spawn(async move {
        copy_encrypt(
            &mut local_read,
            &mut remote_write,
            sender,
            uplink_telemetry,
            uplink_activity,
        )
        .await
    });
    let downlink_activity = activity_tx;
    let mut downlink = tokio::spawn(async move {
        copy_decrypt(
            &mut remote_read,
            &mut local_write,
            receiver,
            telemetry,
            downlink_activity,
        )
        .await
    });
    let idle = Duration::from_secs(idle_seconds);
    let idle_deadline = TokioInstant::now() + idle;
    let idle_timer = tokio::time::sleep_until(idle_deadline);
    tokio::pin!(idle_timer);
    let mut uplink_complete = false;
    let result = loop {
        tokio::select! {
            result = &mut uplink, if !uplink_complete => {
                uplink_complete = true;
                match result.context("uplink task panicked")? {
                    Ok(()) => {},
                    Err(error) => break Err(error),
                }
            }
            result = &mut downlink => {
                match result.context("downlink task panicked")? {
                    // The remote side has completed its stream. `copy_decrypt`
                    // has already delivered every authenticated record before
                    // its clean EOF, so v1 now fully closes instead of waiting
                    // forever for a local writer that may not notice it.
                    Ok(()) => break Ok(()),
                    Err(error) => break Err(error),
                }
            }
            activity = activity_rx.recv() => {
                if activity.is_some() {
                    idle_timer.as_mut().reset(TokioInstant::now() + idle);
                }
            }
            _ = &mut idle_timer => break Err(anyhow::anyhow!("idle timeout")),
            changed = shutdown.changed() => {
                let _ = changed;
                break Err(anyhow::anyhow!("shutdown requested"));
            }
        }
    };
    uplink.abort();
    downlink.abort();
    result
}

fn tls_connector(config: &codex_tunnel_client::config::OuterTlsConfig) -> Result<TlsConnector> {
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        bail!(
            "could not load all system TLS trust roots: {:?}",
            native.errors
        );
    }
    if native.certs.is_empty() {
        bail!("system TLS trust store is empty");
    }
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(native.certs);
    if let Some(path) = &config.additional_ca_file {
        let file = File::open(path)
            .with_context(|| format!("could not open additional TLS CA {}", path.display()))?;
        let certificates = rustls_pemfile::certs(&mut BufReader::new(file))
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("could not parse additional TLS CA {}", path.display()))?;
        if certificates.is_empty() {
            bail!(
                "additional TLS CA {} contains no certificates",
                path.display()
            );
        }
        let (added, _) = roots.add_parsable_certificates(certificates);
        if added == 0 {
            bail!(
                "additional TLS CA {} contained no usable certificates",
                path.display()
            );
        }
    }
    let config = RustlsClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn tls_server_name(
    config: &codex_tunnel_client::config::OuterTlsConfig,
) -> Result<ServerName<'static>> {
    let server_name = config
        .server_name
        .as_deref()
        .context("outer_tls.server_name is required when outer TLS is enabled")?;
    ServerName::try_from(server_name)
        .map(|server_name| server_name.to_owned())
        .map_err(|_| anyhow::anyhow!("outer_tls.server_name is not a valid DNS name"))
}

async fn copy_encrypt<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    sender: TransportSender,
    telemetry: Arc<ConnectionTelemetry>,
    activity: mpsc::Sender<()>,
) -> Result<()> {
    let mut buffer = [0u8; codex_tunnel::MAX_PLAINTEXT_RECORD];
    loop {
        let read_bytes = read.read(&mut buffer).await?;
        if read_bytes == 0 {
            // `tokio::io::split` does not turn dropping this write half into a
            // TCP/TLS half-close while the downlink still owns the read half.
            // Propagate the local application's EOF explicitly: it lets the
            // ingress tear down its destination connection promptly, while
            // the downlink continues to drain records already in flight.
            write.shutdown().await?;
            return Ok(());
        }
        write
            .write_all(&sender.encrypt_record(&buffer[..read_bytes])?)
            .await?;
        write.flush().await?;
        telemetry
            .bytes_client_to_server
            .fetch_add(read_bytes as u64, Ordering::Relaxed);
        let _ = activity.try_send(());
    }
}

async fn copy_decrypt<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    receiver: TransportReceiver,
    telemetry: Arc<ConnectionTelemetry>,
    activity: mpsc::Sender<()>,
) -> Result<()> {
    loop {
        let Some(record) = read_record_frame(read).await? else {
            // A clean record-boundary EOF is the other tunnel peer's full
            // session close. All preceding authenticated records have been
            // delivered; expose EOF to the local application before relay
            // drops the remaining halves.
            write.shutdown().await?;
            return Ok(());
        };
        let plaintext = receiver.decrypt_record(&record)?;
        write.write_all(&plaintext).await?;
        write.flush().await?;
        telemetry
            .bytes_server_to_client
            .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
        let _ = activity.try_send(());
    }
}

async fn read_handshake_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    read_length_framed(reader, 2, codex_tunnel::MAX_HANDSHAKE_MESSAGE).await
}
async fn read_record_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    // Read one byte first so a clean EOF at the start of a record is distinct
    // from a truncated length/payload, which remains a protocol failure.
    let mut header = [0u8; 4];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > codex_tunnel::MAX_CIPHERTEXT_RECORD {
        bail!("invalid frame length {length}");
    }
    let mut frame = header.to_vec();
    frame.resize(header.len() + length, 0);
    reader.read_exact(&mut frame[header.len()..]).await?;
    Ok(Some(frame))
}
async fn read_length_framed<R: AsyncRead + Unpin>(
    reader: &mut R,
    header_len: usize,
    maximum: usize,
) -> Result<Vec<u8>> {
    let mut header = vec![0; header_len];
    reader.read_exact(&mut header).await?;
    let length = if header_len == 2 {
        u16::from_be_bytes([header[0], header[1]]) as usize
    } else {
        u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize
    };
    if length > maximum {
        bail!("received oversized protocol frame");
    }
    let mut frame = header;
    frame.resize(header_len + length, 0);
    reader.read_exact(&mut frame[header_len..]).await?;
    Ok(frame)
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(value.trim())
        .context("invalid base64 public key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Noise public key must be 32 bytes"))
}
fn read_private_key(path: &std::path::Path) -> Result<Zeroizing<[u8; 32]>> {
    enforce_private_permissions(path)?;
    let bytes = STANDARD.decode(std::fs::read_to_string(path)?.trim())?;
    Ok(Zeroizing::new(bytes.try_into().map_err(|_| {
        anyhow::anyhow!("Noise private key must be 32 bytes")
    })?))
}
fn write_private_key(path: &std::path::Path, key: &[u8; 32]) -> Result<()> {
    prepare_private_key_parent(path)?;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut key_file = options
        .open(path)
        .with_context(|| format!("could not create private key {}", path.display()))?;
    key_file.write_all(STANDARD.encode(key).as_bytes())?;
    key_file.sync_all()?;
    Ok(())
}

fn prepare_private_key_parent(path: &std::path::Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    if parent.exists() {
        enforce_private_parent_permissions(parent)?;
        return Ok(());
    }
    std::fs::create_dir(parent).with_context(|| {
        format!(
            "could not create dedicated private-key parent directory {}",
            parent.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn enforce_private_parent_permissions(path: &std::path::Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "private-key parent directory {} must be a real directory",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "private-key parent directory {} must not grant group/world access (mode {:o})",
                path.display(),
                mode
            );
        }
    }
    Ok(())
}
fn enforce_private_permissions(path: &std::path::Path) -> Result<()> {
    enforce_sensitive_permissions(path, "private key")
}

fn enforce_config_permissions(path: &std::path::Path) -> Result<()> {
    enforce_sensitive_permissions(path, "configuration")
}

fn enforce_sensitive_permissions(path: &std::path::Path, kind: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!(
            "{kind} {} must be a regular non-symlink file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{kind} {} must not be group/world readable (mode {:o})",
                path.display(),
                mode
            );
        }
    }
    Ok(())
}
fn fingerprint(key: &[u8; 32]) -> String {
    STANDARD.encode(Sha256::digest(key))
}

fn enable_tcp_keepalive(stream: &TcpStream) -> Result<()> {
    SockRef::from(stream)
        .set_keepalive(true)
        .context("could not enable TCP keepalive")
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CloseReason {
    PeerClosed,
    Shutdown,
    IdleTimeout,
    OuterTlsFailed,
    NoiseHandshakeFailed,
    DecryptFailed,
    DestinationConnectFailed,
    UnauthorizedClient,
    TransportError,
}

fn error_stage(error: &anyhow::Error) -> &'static str {
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("local tcp nodelay") {
        "local_nodelay"
    } else if message.contains("local tcp keepalive") {
        "local_keepalive"
    } else if message.contains("remote connect") {
        "remote_connect"
    } else if message.contains("remote tcp nodelay") {
        "remote_nodelay"
    } else if message.contains("remote tcp keepalive") {
        "remote_keepalive"
    } else if message.contains("noise handshake") || message.contains("preface") {
        "noise_handshake"
    } else {
        "other"
    }
}

impl CloseReason {
    fn from_error(error: &anyhow::Error) -> Self {
        let message = format!("{error:#}").to_ascii_lowercase();
        if message.contains("shutdown requested") {
            Self::Shutdown
        } else if message.contains("idle timeout") {
            Self::IdleTimeout
        } else if message.contains("outer tls") || message.contains("certificate") {
            Self::OuterTlsFailed
        } else if message.contains("decrypt") {
            Self::DecryptFailed
        } else if message.contains("destination connect") {
            Self::DestinationConnectFailed
        } else if message.contains("unauthorised client") || message.contains("unauthorized client")
        {
            Self::UnauthorizedClient
        } else if message.contains("noise handshake")
            || message.contains("preface")
            || message.contains("handshake")
        {
            Self::NoiseHandshakeFailed
        } else {
            Self::TransportError
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::PeerClosed => "peer_closed",
            Self::Shutdown => "shutdown",
            Self::IdleTimeout => "idle_timeout",
            Self::OuterTlsFailed => "outer_tls_failed",
            Self::NoiseHandshakeFailed => "noise_handshake_failed",
            Self::DecryptFailed => "decrypt_failed",
            Self::DestinationConnectFailed => "destination_connect_failed",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::TransportError => "transport_error",
        }
    }
}

struct ConnectionTelemetry {
    id: u64,
    opened_at: Instant,
    handshake_succeeded: AtomicBool,
    bytes_client_to_server: AtomicU64,
    bytes_server_to_client: AtomicU64,
}

impl ConnectionTelemetry {
    fn new(id: u64) -> Self {
        Self {
            id,
            opened_at: Instant::now(),
            handshake_succeeded: AtomicBool::new(false),
            bytes_client_to_server: AtomicU64::new(0),
            bytes_server_to_client: AtomicU64::new(0),
        }
    }
}

#[derive(Default)]
struct TunnelMetrics {
    active_connections: AtomicUsize,
    next_connection_id: AtomicU64,
    handshake_success_total: AtomicU64,
    handshake_failure_total: AtomicU64,
    unauthorized_client_total: AtomicU64,
    decrypt_failure_total: AtomicU64,
    connections_total: AtomicU64,
    bytes_in_total: AtomicU64,
    bytes_out_total: AtomicU64,
    connection_duration_ms_total: AtomicU64,
    destination_connect_failure_total: AtomicU64,
}

struct TunnelMetricsSnapshot {
    active_connections: usize,
    handshake_success_total: u64,
    handshake_failure_total: u64,
    unauthorized_client_total: u64,
    decrypt_failure_total: u64,
    connections_total: u64,
    bytes_in_total: u64,
    bytes_out_total: u64,
    connection_duration_ms_total: u64,
    destination_connect_failure_total: u64,
}

impl TunnelMetrics {
    fn connection_opened(&self) -> ConnectionTelemetry {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        ConnectionTelemetry::new(self.next_connection_id.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn connection_closed(
        &self,
        telemetry: &ConnectionTelemetry,
        reason: CloseReason,
        duration_ms: u64,
    ) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        let handshaken = telemetry.handshake_succeeded.load(Ordering::Relaxed);
        if handshaken {
            self.handshake_success_total.fetch_add(1, Ordering::Relaxed);
        } else if reason != CloseReason::Shutdown {
            self.handshake_failure_total.fetch_add(1, Ordering::Relaxed);
        }
        if reason == CloseReason::UnauthorizedClient {
            self.unauthorized_client_total
                .fetch_add(1, Ordering::Relaxed);
        }
        if reason == CloseReason::DecryptFailed {
            self.decrypt_failure_total.fetch_add(1, Ordering::Relaxed);
        }
        if reason == CloseReason::DestinationConnectFailed {
            self.destination_connect_failure_total
                .fetch_add(1, Ordering::Relaxed);
        }
        self.bytes_in_total.fetch_add(
            telemetry.bytes_client_to_server.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.bytes_out_total.fetch_add(
            telemetry.bytes_server_to_client.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.connection_duration_ms_total
            .fetch_add(duration_ms, Ordering::Relaxed);
    }

    fn snapshot(&self) -> TunnelMetricsSnapshot {
        TunnelMetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            handshake_success_total: self.handshake_success_total.load(Ordering::Relaxed),
            handshake_failure_total: self.handshake_failure_total.load(Ordering::Relaxed),
            unauthorized_client_total: self.unauthorized_client_total.load(Ordering::Relaxed),
            decrypt_failure_total: self.decrypt_failure_total.load(Ordering::Relaxed),
            connections_total: self.connections_total.load(Ordering::Relaxed),
            bytes_in_total: self.bytes_in_total.load(Ordering::Relaxed),
            bytes_out_total: self.bytes_out_total.load(Ordering::Relaxed),
            connection_duration_ms_total: self.connection_duration_ms_total.load(Ordering::Relaxed),
            destination_connect_failure_total: self
                .destination_connect_failure_total
                .load(Ordering::Relaxed),
        }
    }

    fn log_snapshot(&self) {
        let snapshot = self.snapshot();
        info!(
            active_connections = snapshot.active_connections,
            handshake_success_total = snapshot.handshake_success_total,
            handshake_failure_total = snapshot.handshake_failure_total,
            unauthorized_client_total = snapshot.unauthorized_client_total,
            decrypt_failure_total = snapshot.decrypt_failure_total,
            connections_total = snapshot.connections_total,
            bytes_in_total = snapshot.bytes_in_total,
            bytes_out_total = snapshot.bytes_out_total,
            connection_duration_ms_total = snapshot.connection_duration_ms_total,
            destination_connect_failure_total = snapshot.destination_connect_failure_total,
            "tunnel metrics"
        );
    }
}

fn finish_connection(
    metrics: Arc<TunnelMetrics>,
    telemetry: Arc<ConnectionTelemetry>,
    peer: std::net::SocketAddr,
    result: Result<()>,
) {
    let reason = result
        .as_ref()
        .err()
        .map_or(CloseReason::PeerClosed, CloseReason::from_error);
    let stage = result.as_ref().err().map_or("complete", error_stage);
    let duration_ms = telemetry
        .opened_at
        .elapsed()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let handshake_result = if telemetry.handshake_succeeded.load(Ordering::Relaxed) {
        "success"
    } else {
        "failure"
    };
    metrics.connection_closed(&telemetry, reason, duration_ms);
    info!(
        connection_id = telemetry.id,
        remote_address = %peer,
        protocol_version = 1,
        handshake_result,
        close_reason = reason.as_str(),
        error_stage = stage,
        session_duration_ms = duration_ms,
        bytes_client_to_server = telemetry.bytes_client_to_server.load(Ordering::Relaxed),
        bytes_server_to_client = telemetry.bytes_server_to_client.load(Ordering::Relaxed),
        "tunnel connection closed"
    );
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("could not register SIGTERM handler")?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .context("could not register SIGINT handler")?;
        tokio::select! {
            _ = terminate.recv() => Ok(()),
            _ = interrupt.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("could not register shutdown handler")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_include_closed_session_traffic_and_duration() {
        let metrics = TunnelMetrics::default();
        let telemetry = ConnectionTelemetry::new(7);
        telemetry
            .bytes_client_to_server
            .store(31, Ordering::Relaxed);
        telemetry
            .bytes_server_to_client
            .store(47, Ordering::Relaxed);
        telemetry.handshake_succeeded.store(true, Ordering::Relaxed);

        metrics.connection_opened();
        metrics.connection_closed(&telemetry, CloseReason::PeerClosed, 19);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.active_connections, 0);
        assert_eq!(snapshot.connections_total, 1);
        assert_eq!(snapshot.handshake_success_total, 1);
        assert_eq!(snapshot.bytes_in_total, 31);
        assert_eq!(snapshot.bytes_out_total, 47);
        assert_eq!(snapshot.connection_duration_ms_total, 19);
    }

    #[test]
    fn close_reason_never_includes_the_raw_error_text() {
        let reason = CloseReason::from_error(&anyhow::anyhow!(
            "record decryption failed for secret application payload"
        ));
        assert_eq!(reason, CloseReason::DecryptFailed);
        assert_eq!(reason.as_str(), "decrypt_failed");
    }

    #[test]
    fn error_stage_is_a_fixed_safe_category() {
        let error = anyhow::anyhow!("local TCP keepalive setup failed: secret application payload");
        assert_eq!(error_stage(&error), "local_keepalive");
        assert_ne!(error_stage(&error), "secret application payload");
    }

    #[cfg(unix)]
    #[test]
    fn configuration_permissions_reject_group_or_world_access() {
        use std::os::unix::fs::PermissionsExt;

        let path =
            std::env::temp_dir().join(format!("codex-tunnel-client-config-{}", std::process::id()));
        std::fs::write(&path, "[listen]\n").expect("write test config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("make unsafe");
        let error = enforce_config_permissions(&path).expect_err("unsafe config must fail");
        assert!(error.to_string().contains("configuration"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("make safe");
        enforce_config_permissions(&path).expect("safe config accepted");
        std::fs::remove_file(path).expect("remove test config");
    }

    #[cfg(unix)]
    #[test]
    fn keygen_refuses_an_existing_shared_parent_without_chmodding_it() {
        use std::os::unix::fs::PermissionsExt;

        let parent = std::env::temp_dir().join(format!(
            "codex-tunnel-client-key-parent-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir(&parent).expect("create test parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("make shared");
        let key = parent.join("client.key");
        let error = write_private_key(&key, &[3; 32]).expect_err("shared parent must be rejected");
        assert!(error.to_string().contains("parent directory"));
        assert_eq!(
            std::fs::metadata(&parent)
                .expect("parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(!key.exists());
        std::fs::remove_dir_all(parent).expect("remove test parent");
    }

    #[cfg(unix)]
    #[test]
    fn configuration_permissions_reject_a_symlink() {
        use std::os::unix::{fs::PermissionsExt, fs::symlink};

        let directory = std::env::temp_dir().join(format!(
            "codex-tunnel-client-config-link-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).expect("create test directory");
        let target = directory.join("target.toml");
        let link = directory.join("client.toml");
        std::fs::write(&target, "[listen]\n").expect("write target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("protect target");
        symlink(&target, &link).expect("create link");
        let error = enforce_config_permissions(&link).expect_err("symlink must be rejected");
        assert!(error.to_string().contains("regular non-symlink"));
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[tokio::test]
    async fn established_client_socket_has_tcp_keepalive_enabled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let client = TcpStream::connect(address).await.expect("connect");
        let (_server, _) = listener.accept().await.expect("accept");
        enable_tcp_keepalive(&client).expect("enable keepalive");
        assert!(SockRef::from(&client).keepalive().expect("read keepalive"));
    }

    #[tokio::test]
    async fn doctor_handshake_authenticates_the_pinned_server_identity() {
        let client_identity = generate_keypair().expect("client identity");
        let server_identity = generate_keypair().expect("server identity");
        let (mut client_wire, mut server_wire) = tokio::io::duplex(16 * 1024);
        let allowed_client = *client_identity.public_key();
        let server_private = *server_identity.private_key();
        let server = tokio::spawn(async move {
            let mut preface = [0u8; 6];
            server_wire
                .read_exact(&mut preface)
                .await
                .expect("read preface");
            let mut header = [0u8; 2];
            server_wire
                .read_exact(&mut header)
                .await
                .expect("read handshake header");
            let mut frame = header.to_vec();
            frame.resize(2 + u16::from_be_bytes(header) as usize, 0);
            server_wire
                .read_exact(&mut frame[2..])
                .await
                .expect("read handshake body");
            let mut responder =
                codex_tunnel::ServerHandshake::new(server_private, [allowed_client])
                    .expect("responder");
            responder.accept_preface(&preface).expect("accept preface");
            let mut reply = responder.receive_client(&frame).expect("authorised client");
            server_wire
                .write_all(&reply.message().expect("reply"))
                .await
                .expect("write reply");
        });

        complete_noise_handshake(
            &mut client_wire,
            *client_identity.private_key(),
            *server_identity.public_key(),
            Duration::from_secs(1),
        )
        .await
        .expect("pinned server handshake succeeds");
        server.await.expect("join test server");

        let wrong_server = generate_keypair().expect("wrong server identity");
        // A wrong pinned identity cannot complete even if a peer connection is present.
        let (mut client_wire, mut server_wire) = tokio::io::duplex(16 * 1024);
        let allowed_client = *client_identity.public_key();
        let server_private = *server_identity.private_key();
        let server = tokio::spawn(async move {
            let mut preface = [0u8; 6];
            server_wire
                .read_exact(&mut preface)
                .await
                .expect("read preface");
            let mut header = [0u8; 2];
            server_wire
                .read_exact(&mut header)
                .await
                .expect("read handshake header");
            let mut frame = header.to_vec();
            frame.resize(2 + u16::from_be_bytes(header) as usize, 0);
            server_wire
                .read_exact(&mut frame[2..])
                .await
                .expect("read handshake body");
            let mut responder =
                codex_tunnel::ServerHandshake::new(server_private, [allowed_client])
                    .expect("responder");
            responder.accept_preface(&preface).expect("accept preface");
            if let Ok(mut reply) = responder.receive_client(&frame) {
                server_wire
                    .write_all(&reply.message().expect("reply"))
                    .await
                    .expect("write reply");
            }
        });
        assert!(
            complete_noise_handshake(
                &mut client_wire,
                *client_identity.private_key(),
                *wrong_server.public_key(),
                Duration::from_secs(1),
            )
            .await
            .is_err(),
            "wrong pinned server key must fail the diagnostic handshake"
        );
        server.await.expect("join test server");
    }
}
