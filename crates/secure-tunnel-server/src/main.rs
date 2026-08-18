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
use rustls::ServerConfig as RustlsServerConfig;
use secure_tunnel::{ServerHandshake, TransportReceiver, TransportSender, generate_keypair};
use secure_tunnel_server::config::ServerConfig;
use sha2::{Digest, Sha256};
use socket2::SockRef;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::{Instant as TokioInstant, timeout},
};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Remote ingress for the Secure Tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "server.toml")]
        config: PathBuf,
    },
    Keygen {
        #[arg(long)]
        private_key_file: PathBuf,
    },
    Doctor {
        #[arg(long, default_value = "server.toml")]
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
    let keypair = generate_keypair()?;
    write_private_key(path, keypair.private_key())?;
    println!("Private key written: {}", path.display());
    println!("Public key: {}", STANDARD.encode(keypair.public_key()));
    println!("Fingerprint: SHA256:{}", fingerprint(keypair.public_key()));
    Ok(())
}
async fn doctor(path: &std::path::Path) -> Result<()> {
    enforce_config_permissions(path)?;
    let config = ServerConfig::load(path)?;
    let _ = read_server_private_keys(&config.identity)?;
    if config.outer_tls.enabled {
        let _ = tls_acceptor(&config.outer_tls)?;
    }
    for client in &config.authorized_clients {
        let _ = decode_public_key(&client.public_key)
            .with_context(|| format!("invalid key for {}", client.name))?;
    }
    let listener = TcpListener::bind(config.listen.address).await?;
    drop(listener);
    let _ = TcpStream::connect(config.destination.address)
        .await
        .context("compatibility destination unavailable")?;
    println!(
        "[ok] configuration valid\n[ok] server private key readable with protected permissions\n[ok] authorised client keys configured\n[ok] listen socket and compatibility destination available"
    );
    Ok(())
}
async fn serve(config_path: &std::path::Path) -> Result<()> {
    enforce_config_permissions(config_path)?;
    let config = ServerConfig::load(config_path)?;
    for private_key_file in std::iter::once(&config.identity.private_key_file)
        .chain(config.identity.additional_private_key_files.iter())
    {
        enforce_private_permissions(private_key_file)?;
    }
    let tls = config
        .outer_tls
        .enabled
        .then(|| tls_acceptor(&config.outer_tls))
        .transpose()?;
    let listener = TcpListener::bind(config.listen.address).await?;
    let config = Arc::new(config);
    let tls = tls.map(Arc::new);
    let limit = Arc::new(Semaphore::new(config.limits.max_connections));
    let metrics = Arc::new(TunnelMetrics::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut sessions = JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    info!(listen = %listener.local_addr()?, destination = %config.destination.address, "tunnel ingress listening");
    loop {
        tokio::select! {
            signal = &mut shutdown => {
                signal?;
                info!("shutdown signal received; stopping ingress listener");
                let _ = shutdown_tx.send(true);
                break;
            }
            accepted = listener.accept() => {
                let (outer, peer) = accepted?;
                let permit = match Arc::clone(&limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(remote_address = %peer, reason = "connection_limit", "connection rejected at configured limit");
                        continue;
                    }
                };
                let telemetry = Arc::new(metrics.connection_opened());
                let config = Arc::clone(&config);
                let tls = tls.as_ref().map(Arc::clone);
                let metrics = Arc::clone(&metrics);
                let shutdown = shutdown_rx.clone();
                info!(connection_id = telemetry.id, remote_address = %peer, protocol_version = 1, "tunnel connection opened");
                sessions.spawn(async move {
                    let _permit = permit;
                    let result = handle_outer(outer, config, tls, Arc::clone(&telemetry), shutdown).await;
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
async fn handle_outer(
    outer: TcpStream,
    config: Arc<ServerConfig>,
    tls: Option<Arc<TlsAcceptor>>,
    telemetry: Arc<ConnectionTelemetry>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if *shutdown.borrow() {
        bail!("shutdown requested");
    }
    outer.set_nodelay(true)?;
    enable_tcp_keepalive(&outer)?;
    if let Some(tls) = tls {
        let outer = tokio::select! {
            result = timeout(Duration::from_secs(config.timeouts.handshake_seconds), tls.accept(outer)) => result.context("outer TLS handshake timed out")??,
            changed = shutdown.changed() => { let _ = changed; bail!("shutdown requested"); }
        };
        return run_noise(outer, config, telemetry, shutdown).await;
    }
    run_noise(outer, config, telemetry, shutdown).await
}

async fn run_noise<S>(
    mut outer: S,
    config: Arc<ServerConfig>,
    telemetry: Arc<ConnectionTelemetry>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let private_keys = read_server_private_keys(&config.identity)?;
    let clients: Vec<[u8; 32]> = config
        .authorized_clients
        .iter()
        .map(|c| decode_public_key(&c.public_key))
        .collect::<Result<_>>()?;
    let mut preface = [0; 6];
    tokio::select! {
        result = timeout(Duration::from_secs(config.timeouts.handshake_seconds), outer.read_exact(&mut preface)) => result.context("preface timeout")??,
        changed = shutdown.changed() => { let _ = changed; bail!("shutdown requested"); }
    };
    let mut handshake = ServerHandshake::new_with_static_identities(
        private_keys.iter().map(|private| **private),
        clients,
    )?;
    handshake.accept_preface(&preface)?;
    let first = tokio::select! {
        result = timeout(Duration::from_secs(config.timeouts.handshake_seconds), read_handshake_frame(&mut outer)) => result.context("Noise handshake timeout")??,
        changed = shutdown.changed() => { let _ = changed; bail!("shutdown requested"); }
    };
    let mut reply = handshake
        .receive_client(&first)
        .context("Noise handshake failed")?;
    outer.write_all(&reply.message()?).await?;
    outer.flush().await?;
    let session = reply.into_session()?;
    telemetry.handshake_succeeded.store(true, Ordering::Relaxed);
    info!(
        connection_id = telemetry.id,
        handshake_result = "success",
        protocol_version = 1,
        "tunnel handshake complete"
    );
    let destination = tokio::select! {
        result = timeout(Duration::from_secs(config.timeouts.destination_connect_seconds), TcpStream::connect(config.destination.address)) => result.context("destination connect timeout")??,
        changed = shutdown.changed() => { let _ = changed; bail!("shutdown requested"); }
    };
    destination.set_nodelay(true)?;
    enable_tcp_keepalive(&destination)?;
    relay(
        outer,
        destination,
        session.split(),
        config.timeouts.idle_seconds,
        telemetry,
        shutdown,
    )
    .await
}
async fn relay(
    outer: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    destination: TcpStream,
    crypto: (TransportSender, TransportReceiver),
    idle_seconds: u64,
    telemetry: Arc<ConnectionTelemetry>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let (sender, receiver) = crypto;
    let (mut outer_read, mut outer_write) = tokio::io::split(outer);
    let (mut destination_read, mut destination_write) = tokio::io::split(destination);
    let (activity_tx, mut activity_rx) = mpsc::channel(1);
    let inbound_telemetry = Arc::clone(&telemetry);
    let inbound_activity = activity_tx.clone();
    let mut inbound = tokio::spawn(async move {
        copy_decrypt(
            &mut outer_read,
            &mut destination_write,
            receiver,
            inbound_telemetry,
            inbound_activity,
        )
        .await
    });
    let outbound_activity = activity_tx;
    let mut outbound = tokio::spawn(async move {
        copy_encrypt(
            &mut destination_read,
            &mut outer_write,
            sender,
            telemetry,
            outbound_activity,
        )
        .await
    });
    let idle = Duration::from_secs(idle_seconds);
    let idle_timer = tokio::time::sleep_until(TokioInstant::now() + idle);
    tokio::pin!(idle_timer);
    let mut inbound_complete = false;
    let result = loop {
        tokio::select! {
            result = &mut inbound, if !inbound_complete => {
                inbound_complete = true;
                match result.context("inbound task panicked")? {
                    Ok(()) => {},
                    Err(error) => break Err(error),
                }
            }
            result = &mut outbound => {
                match result.context("outbound task panicked")? {
                    // The destination has closed its response direction. Its
                    // final records were flushed before this task returned;
                    // v1 has no half-close forwarding, so terminate the
                    // remaining ingress direction immediately.
                    Ok(()) => break Ok(()),
                    Err(error) => break Err(error),
                }
            }
            activity = activity_rx.recv() => if activity.is_some() { idle_timer.as_mut().reset(TokioInstant::now() + idle); },
            _ = &mut idle_timer => break Err(anyhow::anyhow!("idle timeout")),
            changed = shutdown.changed() => { let _ = changed; break Err(anyhow::anyhow!("shutdown requested")); }
        }
    };
    inbound.abort();
    outbound.abort();
    result
}

fn tls_acceptor(config: &secure_tunnel_server::config::OuterTlsConfig) -> Result<TlsAcceptor> {
    let certificate_path = config
        .certificate_file
        .as_ref()
        .context("outer_tls.certificate_file is required when outer TLS is enabled")?;
    let private_key_path = config
        .private_key_file
        .as_ref()
        .context("outer_tls.private_key_file is required when outer TLS is enabled")?;
    enforce_private_permissions(private_key_path)?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(
        File::open(certificate_path).with_context(|| {
            format!(
                "could not open TLS certificate {}",
                certificate_path.display()
            )
        })?,
    ))
    .collect::<std::result::Result<Vec<_>, _>>()
    .with_context(|| {
        format!(
            "could not parse TLS certificate {}",
            certificate_path.display()
        )
    })?;
    if certificates.is_empty() {
        bail!(
            "TLS certificate {} contains no certificates",
            certificate_path.display()
        );
    }
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(
        File::open(private_key_path).with_context(|| {
            format!(
                "could not open TLS private key {}",
                private_key_path.display()
            )
        })?,
    ))
    .with_context(|| {
        format!(
            "could not parse TLS private key {}",
            private_key_path.display()
        )
    })?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "TLS private key {} contains no private key",
            private_key_path.display()
        )
    })?;
    let config = RustlsServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certificates, private_key)
    .context("TLS certificate and private key do not match")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}
async fn copy_encrypt<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    sender: TransportSender,
    telemetry: Arc<ConnectionTelemetry>,
    activity: mpsc::Sender<()>,
) -> Result<()> {
    let mut buffer = [0; secure_tunnel::MAX_PLAINTEXT_RECORD];
    loop {
        let count = read.read(&mut buffer).await?;
        if count == 0 {
            // Keep the opposite direction alive long enough to drain records
            // already received, but explicitly half-close the tunnel.  A
            // dropped generic split write half alone leaves the transport open
            // as long as its read half is still retained.
            write.shutdown().await?;
            return Ok(());
        }
        write
            .write_all(&sender.encrypt_record(&buffer[..count])?)
            .await?;
        write.flush().await?;
        telemetry
            .bytes_server_to_client
            .fetch_add(count as u64, Ordering::Relaxed);
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
            // The client-side tunnel writer ended cleanly at a record
            // boundary. Close the destination request writer so it can emit
            // any final response; relay keeps the outbound direction alive
            // long enough to encrypt and deliver those bytes.
            write.shutdown().await?;
            return Ok(());
        };
        let plaintext = receiver.decrypt_record(&record)?;
        write.write_all(&plaintext).await?;
        write.flush().await?;
        telemetry
            .bytes_client_to_server
            .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
        let _ = activity.try_send(());
    }
}
async fn read_handshake_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    read_length_framed(reader, 2, secure_tunnel::MAX_HANDSHAKE_MESSAGE).await
}
async fn read_record_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    // Clean EOF between frames is orderly session termination. EOF after any
    // frame byte stays an error via `read_exact`, preventing a truncated
    // ciphertext record from being treated as a valid close.
    let mut header = [0u8; 4];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > secure_tunnel::MAX_CIPHERTEXT_RECORD {
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
        if telemetry.handshake_succeeded.load(Ordering::Relaxed) {
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
    info!(connection_id = telemetry.id, remote_address = %peer, protocol_version = 1, handshake_result, close_reason = reason.as_str(), session_duration_ms = duration_ms, bytes_client_to_server = telemetry.bytes_client_to_server.load(Ordering::Relaxed), bytes_server_to_client = telemetry.bytes_server_to_client.load(Ordering::Relaxed), "tunnel connection closed");
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
        tokio::select! { _ = terminate.recv() => Ok(()), _ = interrupt.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("could not register shutdown handler")
    }
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
fn read_server_private_keys(
    identity: &secure_tunnel_server::config::IdentityConfig,
) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    std::iter::once(&identity.private_key_file)
        .chain(identity.additional_private_key_files.iter())
        .map(|path| {
            read_private_key(path)
                .with_context(|| format!("could not read server private key {}", path.display()))
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_count_destination_and_handshake_failures() {
        let metrics = TunnelMetrics::default();
        let telemetry = ConnectionTelemetry::new(3);

        metrics.connection_opened();
        metrics.connection_closed(&telemetry, CloseReason::DestinationConnectFailed, 11);
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.active_connections, 0);
        assert_eq!(snapshot.connections_total, 1);
        assert_eq!(snapshot.handshake_failure_total, 1);
        assert_eq!(snapshot.destination_connect_failure_total, 1);
        assert_eq!(snapshot.connection_duration_ms_total, 11);
    }

    #[test]
    fn close_reason_is_a_fixed_safe_category() {
        let reason = CloseReason::from_error(&anyhow::anyhow!("unauthorised client key"));
        assert_eq!(reason, CloseReason::UnauthorizedClient);
        assert_eq!(reason.as_str(), "unauthorized_client");
    }

    #[cfg(unix)]
    #[test]
    fn configuration_permissions_reject_group_or_world_access() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "secure-tunnel-server-config-{}",
            std::process::id()
        ));
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
            "secure-tunnel-server-key-parent-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir(&parent).expect("create test parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("make shared");
        let key = parent.join("server.key");
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
            "secure-tunnel-server-config-link-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).expect("create test directory");
        let target = directory.join("target.toml");
        let link = directory.join("server.toml");
        std::fs::write(&target, "[listen]\n").expect("write target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("protect target");
        symlink(&target, &link).expect("create link");
        let error = enforce_config_permissions(&link).expect_err("symlink must be rejected");
        assert!(error.to_string().contains("regular non-symlink"));
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[tokio::test]
    async fn established_server_socket_has_tcp_keepalive_enabled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let client = TcpStream::connect(address).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        enable_tcp_keepalive(&server).expect("enable keepalive");
        assert!(SockRef::from(&server).keepalive().expect("read keepalive"));
        drop(client);
    }
}
