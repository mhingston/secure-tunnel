//! Black-box and security-contract tests for the TCP and optional-TLS transport.
//! They exercise the shipped binaries for the unauthenticated network boundary
//! and the public core API for captured-record attacks a raw relay can perform.

use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use codex_tunnel::{
    ClientHandshake, Preface, ServerHandshake, StaticKeypair, TransportSession, TunnelError,
    generate_keypair,
};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const WAIT: Duration = Duration::from_secs(10);
static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
// Each test launches multiple released binaries and uses time-sensitive
// loopback fixtures. Serialising those process-level scenarios makes their
// timeout evidence deterministic without weakening any assertion.
static PROCESS_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn security_contracts() {
    tcp_binaries_are_transparent_and_reject_unauthenticated_peers_before_destination_connect();
    captured_transport_records_cannot_be_modified_replayed_or_moved_between_sessions();
    tls_mitm_can_terminate_tls_but_cannot_recover_noise_protected_markers();
    valid_tls_does_not_override_a_wrong_pinned_noise_server_identity();
}

fn tcp_binaries_are_transparent_and_reject_unauthenticated_peers_before_destination_connect() {
    let _guard = PROCESS_FIXTURE_LOCK.lock().expect("fixture lock");
    opaque_bidirectional_relay();
    wrong_pinned_server_cannot_receive_application_bytes();
    unauthorised_client_never_reaches_destination();
}

fn captured_transport_records_cannot_be_modified_replayed_or_moved_between_sessions() {
    let _guard = PROCESS_FIXTURE_LOCK.lock().expect("fixture lock");
    let (mut client_a, mut server_a) = authenticated_sessions();
    let record = client_a
        .encrypt_record(b"APPLICATION_SECRET_MARKER_7f3c_request")
        .expect("encrypt captured record");

    let mut altered = record.clone();
    *altered
        .last_mut()
        .expect("record has an authentication tag") ^= 0x80;
    assert!(matches!(
        server_a.decrypt_record(&altered),
        Err(TunnelError::Noise(_))
    ));
    assert!(matches!(
        server_a.decrypt_record(&record),
        Err(TunnelError::ClosedSession)
    ));

    let (mut client_b, mut server_b) = authenticated_sessions();
    let replay = client_b
        .encrypt_record(b"record accepted exactly once")
        .expect("encrypt replay candidate");
    assert_eq!(
        server_b
            .decrypt_record(&replay)
            .expect("first record accepted"),
        b"record accepted exactly once"
    );
    assert!(matches!(
        server_b.decrypt_record(&replay),
        Err(TunnelError::Noise(_))
    ));
    assert!(matches!(
        server_b.decrypt_record(&replay),
        Err(TunnelError::ClosedSession)
    ));

    // Session A has a distinct handshake hash and directional cipher keys.
    // A captured record must never authenticate in a second completed session,
    // even when both sessions deliberately reuse the same long-term identities.
    let shared_client_identity = generate_keypair().expect("generate shared client identity");
    let shared_server_identity = generate_keypair().expect("generate shared server identity");
    let (mut client_c, mut server_c) =
        authenticated_sessions_for(&shared_client_identity, &shared_server_identity);
    let cross_session = client_c
        .encrypt_record(b"cross-session replay marker")
        .expect("encrypt cross-session candidate");
    let (_client_d, mut server_d) =
        authenticated_sessions_for(&shared_client_identity, &shared_server_identity);
    assert!(matches!(
        server_d.decrypt_record(&cross_session),
        Err(TunnelError::Noise(_))
    ));
    assert!(matches!(
        server_d.decrypt_record(&cross_session),
        Err(TunnelError::ClosedSession)
    ));

    // Keep both directions exercised: a captured server-to-client frame has
    // the opposite cipher state and cannot be opened by the server receiver.
    let response = server_c
        .encrypt_record(b"APPLICATION_SECRET_MARKER_7f3c_response")
        .expect("encrypt response");
    assert!(matches!(
        client_c.decrypt_record(&response),
        Ok(ref bytes) if bytes == b"APPLICATION_SECRET_MARKER_7f3c_response"
    ));
}

fn tls_mitm_can_terminate_tls_but_cannot_recover_noise_protected_markers() {
    let _guard = PROCESS_FIXTURE_LOCK.lock().expect("fixture lock");
    let fixture = Fixture::new();
    let tls = TlsMaterial::new(fixture.root.path());
    let request_marker = b"APPLICATION_SECRET_MARKER_7f3c_request";
    let response_marker = b"APPLICATION_SECRET_MARKER_7f3c_response";
    let mut expected_response = b"opaque response from compatibility fixture: ".to_vec();
    expected_response.extend_from_slice(response_marker);
    let destination = MarkerDestination::start(request_marker, expected_response.clone());
    let server = fixture.start_server_tls(destination.address(), fixture.client.public_key(), &tls);
    let mitm = TlsMitm::start(server.address(), &tls);
    let client = fixture.start_client_tls(mitm.address(), fixture.server.public_key(), &tls);

    let mut local = connect_retry(client.address());
    local
        .set_read_timeout(Some(WAIT))
        .expect("configure local read timeout");
    let mut request = b"opaque request: ".to_vec();
    request.extend_from_slice(request_marker);
    local
        .write_all(&request)
        .expect("write through intercepted TLS");
    local.flush().expect("flush through intercepted TLS");
    let mut echoed = vec![0; expected_response.len()];
    local
        .read_exact(&mut echoed)
        .expect("response survives successful TLS interception");
    assert_eq!(echoed, expected_response);

    // Give both forwarding tasks an opportunity to append the decrypted TLS
    // application data before inspecting the interceptor capture.
    thread::sleep(Duration::from_millis(100));
    let captured = mitm.captured_application_data();
    assert!(
        !contains(&captured, request_marker),
        "a TLS-terminating interceptor recovered the request marker"
    );
    assert!(
        !contains(&captured, response_marker),
        "a TLS-terminating interceptor recovered the response marker"
    );
    assert!(
        !captured.is_empty(),
        "the fixture must prove that it observed decrypted outer TLS application data"
    );

    drop(local);
    drop(client);
    drop(mitm);
    drop(server);
    drop(destination);
}

fn valid_tls_does_not_override_a_wrong_pinned_noise_server_identity() {
    let _guard = PROCESS_FIXTURE_LOCK.lock().expect("fixture lock");
    let fixture = Fixture::new();
    let tls = TlsMaterial::new(fixture.root.path());
    let destination = CountingDestination::start();
    let server = fixture.start_server_tls(destination.address(), fixture.client.public_key(), &tls);
    let mitm = TlsMitm::start(server.address(), &tls);
    let wrong_noise_server = generate_keypair().expect("generate wrong Noise server identity");
    let client = fixture.start_client_tls(mitm.address(), wrong_noise_server.public_key(), &tls);

    let mut local = connect_retry(client.address());
    local
        .set_read_timeout(Some(WAIT))
        .expect("configure read timeout");
    local
        .write_all(b"valid outer TLS must not bypass Noise pinning")
        .expect("write local payload");
    let mut one = [0u8; 1];
    let closed = match local.read(&mut one) {
        Ok(0) => true,
        Err(error) => is_connection_close(&error),
        Ok(_) => false,
    };
    assert!(closed, "the local side must observe a plain TCP close");
    assert_eq!(
        destination.accepted_within(Duration::from_millis(400)),
        0,
        "a valid TLS certificate must not allow a wrong Noise identity to reach the destination"
    );
}

fn opaque_bidirectional_relay() {
    let fixture = Fixture::new();
    let destination = EchoDestination::start();
    let server = fixture.start_server(destination.address(), fixture.client.public_key());
    let client = fixture.start_client(server.address(), fixture.server.public_key());

    let mut local = connect_retry(client.address());
    local
        .set_read_timeout(Some(WAIT))
        .expect("configure local read timeout");
    let mut request =
        b"POST /v1/responses HTTP/1.1\r\ncontent-type: application/json\r\n\r\n".to_vec();
    request.extend_from_slice(b"{\"input\":\"APPLICATION_SECRET_MARKER_7f3c_request\"}");
    request.extend((0..(64 * 1024)).map(|index| (index % 251) as u8));
    local.write_all(&request).expect("write opaque bytes");
    local.flush().expect("flush opaque bytes");

    let mut response = vec![0; request.len()];
    local
        .read_exact(&mut response)
        .expect("receive complete echoed response");
    assert_eq!(
        response, request,
        "the tunnel must not parse or rewrite bytes"
    );

    drop(local);
    drop(client);
    drop(server);
    drop(destination);
}

fn wrong_pinned_server_cannot_receive_application_bytes() {
    let fixture = Fixture::new();
    let destination = CountingDestination::start();
    let server = fixture.start_server(destination.address(), fixture.client.public_key());
    let wrong_server = generate_keypair().expect("generate different server identity");
    let client = fixture.start_client(server.address(), wrong_server.public_key());

    let mut local = connect_retry(client.address());
    local
        .set_read_timeout(Some(WAIT))
        .expect("configure local read timeout");
    local
        .write_all(b"must not leave the client after wrong-server rejection")
        .expect("write local payload");
    let mut one = [0u8; 1];
    let closed = match local.read(&mut one) {
        Ok(0) => true,
        Err(error) => is_connection_close(&error),
        Ok(_) => false,
    };
    assert!(closed, "the local side must observe a plain TCP close");
    assert_eq!(
        destination.accepted_within(Duration::from_millis(400)),
        0,
        "the server must not connect to the destination for a wrong pinned identity"
    );

    drop(client);
    drop(server);
    drop(destination);
}

fn unauthorised_client_never_reaches_destination() {
    let fixture = Fixture::new();
    let allowed_client = generate_keypair().expect("generate allow-listed identity");
    let destination = CountingDestination::start();
    let server = fixture.start_server(destination.address(), allowed_client.public_key());
    let client = fixture.start_client(server.address(), fixture.server.public_key());

    let mut local = connect_retry(client.address());
    local
        .set_read_timeout(Some(WAIT))
        .expect("configure local read timeout");
    local
        .write_all(b"unauthorised client application bytes")
        .expect("write local payload");
    let mut one = [0u8; 1];
    let closed = match local.read(&mut one) {
        Ok(0) => true,
        Err(error) => is_connection_close(&error),
        Ok(_) => false,
    };
    assert!(closed, "an unauthorised client must receive a TCP close");
    assert_eq!(
        destination.accepted_within(Duration::from_millis(400)),
        0,
        "unknown client keys must be rejected before destination connect"
    );

    drop(client);
    drop(server);
    drop(destination);
}

fn authenticated_sessions() -> (TransportSession, TransportSession) {
    let client = generate_keypair().expect("generate client key");
    let server = generate_keypair().expect("generate server key");
    authenticated_sessions_for(&client, &server)
}

fn authenticated_sessions_for(
    client: &StaticKeypair,
    server: &StaticKeypair,
) -> (TransportSession, TransportSession) {
    let mut initiator =
        ClientHandshake::new(*client.private_key(), *server.public_key()).expect("build initiator");
    let mut responder = ServerHandshake::new(*server.private_key(), [*client.public_key()])
        .expect("build responder");
    responder
        .accept_preface(&Preface::V1.encode())
        .expect("accept preface");
    let first = initiator.first_message().expect("first handshake message");
    let mut reply = responder
        .receive_client(&first)
        .expect("authenticate client");
    let second = reply.message().expect("second handshake message");
    (
        initiator.finish(&second).expect("finish client handshake"),
        reply.into_session().expect("finish server handshake"),
    )
}

struct Fixture {
    root: TempDir,
    client: StaticKeypair,
    server: StaticKeypair,
}

impl Fixture {
    fn new() -> Self {
        Self {
            root: TempDir::new(),
            client: generate_keypair().expect("generate client identity"),
            server: generate_keypair().expect("generate server identity"),
        }
    }

    fn start_server(&self, destination: std::net::SocketAddr, allowed: &[u8; 32]) -> Process {
        let listen = unused_loopback_address();
        let key_path = self.root.path().join("server.key");
        write_private_key(&key_path, &self.server);
        let config = format!(
            "[listen]\naddress = \"{listen}\"\n\n[destination]\naddress = \"{destination}\"\n\n[identity]\nprivate_key_file = \"{}\"\n\n[timeouts]\ndestination_connect_seconds = 2\nhandshake_seconds = 2\nidle_seconds = 30\n\n[[authorized_clients]]\nname = \"test-client\"\npublic_key = \"{}\"\n",
            toml_path(&key_path),
            STANDARD.encode(allowed),
        );
        let config_path = self.root.path().join(format!("server-{listen}.toml"));
        write_protected_config(&config_path, &config);
        Process::start(server_binary(), "server", &config_path, listen)
    }

    fn start_server_tls(
        &self,
        destination: std::net::SocketAddr,
        allowed: &[u8; 32],
        tls: &TlsMaterial,
    ) -> Process {
        let listen = unused_loopback_address();
        let key_path = self.root.path().join("server.key");
        write_private_key(&key_path, &self.server);
        let config = format!(
            "[listen]\naddress = \"{listen}\"\n\n[destination]\naddress = \"{destination}\"\n\n[identity]\nprivate_key_file = \"{}\"\n\n[outer_tls]\nenabled = true\ncertificate_file = \"{}\"\nprivate_key_file = \"{}\"\n\n[timeouts]\ndestination_connect_seconds = 2\nhandshake_seconds = 2\nidle_seconds = 30\n\n[[authorized_clients]]\nname = \"test-client\"\npublic_key = \"{}\"\n",
            toml_path(&key_path),
            toml_path(&tls.server_certificate),
            toml_path(&tls.server_private_key),
            STANDARD.encode(allowed),
        );
        let config_path = self.root.path().join(format!("server-tls-{listen}.toml"));
        write_protected_config(&config_path, &config);
        Process::start(server_binary(), "TLS server", &config_path, listen)
    }

    fn start_client(&self, remote: std::net::SocketAddr, pinned: &[u8; 32]) -> Process {
        let listen = unused_loopback_address();
        let key_path = self.root.path().join("client.key");
        write_private_key(&key_path, &self.client);
        let config = format!(
            "[listen]\naddress = \"{listen}\"\n\n[remote]\naddress = \"{remote}\"\n\n[identity]\nprivate_key_file = \"{}\"\n\n[peer]\nserver_public_key = \"{}\"\n\n[timeouts]\nconnect_seconds = 2\nhandshake_seconds = 2\nidle_seconds = 30\n",
            toml_path(&key_path),
            STANDARD.encode(pinned),
        );
        let config_path = self.root.path().join(format!("client-{listen}.toml"));
        write_protected_config(&config_path, &config);
        Process::start(client_binary(), "client", &config_path, listen)
    }

    fn start_client_tls(
        &self,
        remote: std::net::SocketAddr,
        pinned: &[u8; 32],
        tls: &TlsMaterial,
    ) -> Process {
        let listen = unused_loopback_address();
        let key_path = self.root.path().join("client.key");
        write_private_key(&key_path, &self.client);
        let config = format!(
            "[listen]\naddress = \"{listen}\"\n\n[remote]\naddress = \"{remote}\"\n\n[identity]\nprivate_key_file = \"{}\"\n\n[peer]\nserver_public_key = \"{}\"\n\n[outer_tls]\nenabled = true\nserver_name = \"mitm.test\"\nadditional_ca_file = \"{}\"\n\n[timeouts]\nconnect_seconds = 2\nhandshake_seconds = 2\nidle_seconds = 30\n",
            toml_path(&key_path),
            STANDARD.encode(pinned),
            toml_path(&tls.ca_certificate),
        );
        let config_path = self.root.path().join(format!("client-tls-{listen}.toml"));
        write_protected_config(&config_path, &config);
        Process::start(client_binary(), "TLS client", &config_path, listen)
    }
}

struct Process {
    child: Child,
    address: std::net::SocketAddr,
}

impl Process {
    fn start(binary: PathBuf, role: &str, config: &Path, address: std::net::SocketAddr) -> Self {
        let child = Command::new(binary)
            .args(["serve", "--config"])
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("start {role} binary: {error}"));
        // Do not probe by connecting: that would establish a real tunnel
        // session and consume a single-connection destination fixture.
        thread::sleep(Duration::from_millis(50));
        Self { child, address }
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

struct TlsMaterial {
    ca_certificate: PathBuf,
    mitm_certificate: PathBuf,
    mitm_private_key: PathBuf,
    server_certificate: PathBuf,
    server_private_key: PathBuf,
}

impl TlsMaterial {
    fn new(directory: &Path) -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new());
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = Certificate::from_params(ca_params).expect("generate test CA");
        let mitm = Certificate::from_params(CertificateParams::new(vec!["mitm.test".into()]))
            .expect("generate interception certificate");
        let server = Certificate::from_params(CertificateParams::new(vec!["server.test".into()]))
            .expect("generate server certificate");
        let result = Self {
            ca_certificate: directory.join("test-ca.pem"),
            mitm_certificate: directory.join("mitm-cert.pem"),
            mitm_private_key: directory.join("mitm-key.pem"),
            server_certificate: directory.join("server-cert.pem"),
            server_private_key: directory.join("server-tls-key.pem"),
        };
        fs::write(
            &result.ca_certificate,
            ca.serialize_pem().expect("encode test CA"),
        )
        .expect("write test CA");
        fs::write(
            &result.mitm_certificate,
            mitm.serialize_pem_with_signer(&ca)
                .expect("sign interception certificate"),
        )
        .expect("write interception certificate");
        fs::write(&result.mitm_private_key, mitm.serialize_private_key_pem())
            .expect("write interception private key");
        fs::write(
            &result.server_certificate,
            server
                .serialize_pem_with_signer(&ca)
                .expect("sign server certificate"),
        )
        .expect("write server certificate");
        fs::write(
            &result.server_private_key,
            server.serialize_private_key_pem(),
        )
        .expect("write server TLS private key");
        protect_private_key(&result.mitm_private_key);
        protect_private_key(&result.server_private_key);
        result
    }
}

struct TlsMitm {
    address: std::net::SocketAddr,
    captured: Arc<std::sync::Mutex<Vec<u8>>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TlsMitm {
    fn start(server: std::net::SocketAddr, material: &TlsMaterial) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS MITM listener");
        let address = listener.local_addr().expect("TLS MITM listener address");
        listener
            .set_nonblocking(true)
            .expect("make TLS MITM listener nonblocking");
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let captured_for_thread = Arc::clone(&captured);
        let stop = Arc::clone(&shutdown);
        let inbound = tls_acceptor(&material.mitm_certificate, &material.mitm_private_key);
        let outbound = tls_connector(&material.ca_certificate);
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("create TLS MITM runtime");
            runtime.block_on(async move {
                let listener = TokioTcpListener::from_std(listener).expect("adopt MITM listener");
                while !stop.load(Ordering::Relaxed) {
                    let accepted = listener.accept().await;
                    let Ok((client, _)) = accepted else {
                        continue;
                    };
                    let inbound = inbound.clone();
                    let outbound = outbound.clone();
                    let captured = Arc::clone(&captured_for_thread);
                    tokio::spawn(async move {
                        let Ok(client) = inbound.accept(client).await else {
                            return;
                        };
                        let Ok(server_tcp) = TokioTcpStream::connect(server).await else {
                            return;
                        };
                        let server_name = ServerName::try_from("server.test")
                            .expect("valid fixture server name")
                            .to_owned();
                        let Ok(server) = outbound.connect(server_name, server_tcp).await else {
                            return;
                        };
                        let _ = relay_and_capture(client, server, captured).await;
                    });
                }
            });
        });
        Self {
            address,
            captured,
            shutdown,
            thread: Some(thread),
        }
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn captured_application_data(&self) -> Vec<u8> {
        self.captured.lock().expect("MITM capture lock").clone()
    }
}

impl Drop for TlsMitm {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join TLS MITM");
        }
    }
}

fn tls_acceptor(certificate: &Path, private_key: &Path) -> TlsAcceptor {
    let certificates = read_certificates(certificate);
    let private_key = read_private_key_der(private_key);
    let config = RustlsServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("enable TLS 1.3")
    .with_no_client_auth()
    .with_single_cert(certificates, private_key)
    .expect("build TLS MITM server config");
    TlsAcceptor::from(Arc::new(config))
}

fn tls_connector(ca_certificate: &Path) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(read_certificates(ca_certificate));
    assert_eq!(added, 1, "fixture CA must be trusted by the interceptor");
    let config = RustlsClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("enable TLS 1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn read_certificates(path: &Path) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut io::BufReader::new(
        fs::File::open(path).expect("open certificate"),
    ))
    .collect::<Result<Vec<_>, _>>()
    .expect("parse certificate")
}

fn read_private_key_der(path: &Path) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut io::BufReader::new(
        fs::File::open(path).expect("open private key"),
    ))
    .expect("parse private key")
    .expect("private key exists")
}

async fn relay_and_capture(
    client: tokio_rustls::server::TlsStream<TokioTcpStream>,
    server: tokio_rustls::client::TlsStream<TokioTcpStream>,
    captured: Arc<std::sync::Mutex<Vec<u8>>>,
) -> io::Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);
    tokio::try_join!(
        copy_and_capture(&mut client_read, &mut server_write, Arc::clone(&captured)),
        copy_and_capture(&mut server_read, &mut client_write, captured),
    )?;
    Ok(())
}

async fn copy_and_capture<R, W>(
    reader: &mut R,
    writer: &mut W,
    captured: Arc<std::sync::Mutex<Vec<u8>>>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16_384];
    let mut total = 0;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(total);
        }
        captured
            .lock()
            .expect("MITM capture lock")
            .extend_from_slice(&buffer[..count]);
        writer.write_all(&buffer[..count]).await?;
        writer.flush().await?;
        total += count as u64;
    }
}

struct EchoDestination {
    address: std::net::SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl EchoDestination {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind destination");
        listener
            .set_nonblocking(true)
            .expect("set destination nonblocking");
        let address = listener.local_addr().expect("destination address");
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let thread = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .expect("set echo timeout");
                        let mut buffer = [0u8; 16_384];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(count) => {
                                    if stream.write_all(&buffer[..count]).is_err() {
                                        break;
                                    }
                                }
                                Err(error)
                                    if error.kind() == io::ErrorKind::WouldBlock
                                        || error.kind() == io::ErrorKind::TimedOut =>
                                {
                                    continue;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            shutdown,
            thread: Some(thread),
        }
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }
}

impl Drop for EchoDestination {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A compatibility-service stand-in that proves the reverse marker originates
/// at the destination, rather than being reflected from the client request.
struct MarkerDestination {
    address: std::net::SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MarkerDestination {
    fn start(request_marker: &[u8], response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind marker destination");
        listener
            .set_nonblocking(true)
            .expect("set marker destination nonblocking");
        let address = listener.local_addr().expect("marker destination address");
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let request_marker = request_marker.to_vec();
        let thread = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .expect("set marker destination timeout");
                        let mut received = Vec::new();
                        let mut buffer = [0u8; 16_384];
                        while !stop.load(Ordering::Relaxed) {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(count) => {
                                    received.extend_from_slice(&buffer[..count]);
                                    if contains(&received, &request_marker) {
                                        stream
                                            .write_all(&response)
                                            .expect("write destination response marker");
                                        return;
                                    }
                                }
                                Err(error)
                                    if error.kind() == io::ErrorKind::WouldBlock
                                        || error.kind() == io::ErrorKind::TimedOut =>
                                {
                                    continue;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            shutdown,
            thread: Some(thread),
        }
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }
}

impl Drop for MarkerDestination {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join marker destination");
        }
    }
}

struct CountingDestination {
    address: std::net::SocketAddr,
    accepted: Receiver<()>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl CountingDestination {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind destination");
        listener
            .set_nonblocking(true)
            .expect("set destination nonblocking");
        let address = listener.local_addr().expect("destination address");
        let (sender, accepted) = mpsc::channel();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let thread = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((_stream, _)) => {
                        let _ = sender.send(());
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            accepted,
            shutdown,
            thread: Some(thread),
        }
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn accepted_within(&self, duration: Duration) -> usize {
        let deadline = Instant::now() + duration;
        let mut count = 0;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match self.accepted.recv_timeout(remaining) {
                Ok(()) => count += 1,
                Err(mpsc::RecvTimeoutError::Timeout)
                | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        count
    }
}

impl Drop for CountingDestination {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join counting destination");
        }
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "codex-tunnel-security-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create isolated fixture directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_private_key(path: &Path, keypair: &StaticKeypair) {
    fs::write(path, STANDARD.encode(keypair.private_key())).expect("write private key");
    protect_private_key(path);
}

fn write_protected_config(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write protected config");
    protect_private_key(path);
}

fn protect_private_key(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("protect private key permissions");
    }
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("integration tests directory has project root")
        .to_owned()
}

fn client_binary() -> PathBuf {
    required_binary("codex-tunnel")
}

fn server_binary() -> PathBuf {
    required_binary("codex-tunnel-server")
}

fn required_binary(name: &str) -> PathBuf {
    let binary = project_root().join("target/debug").join(name);
    assert!(
        binary.is_file(),
        "{name} is required for black-box tests; run `cargo build -p codex-tunnel-client -p codex-tunnel-server` before this test target"
    );
    binary
}

fn unused_loopback_address() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let address = listener.local_addr().expect("reserved listener address");
    drop(listener);
    address
}

fn connect_retry(address: std::net::SocketAddr) -> TcpStream {
    let deadline = Instant::now() + WAIT;
    loop {
        match TcpStream::connect(address) {
            Ok(stream) => return stream,
            Err(error)
                if Instant::now() < deadline
                    && error.kind() == io::ErrorKind::ConnectionRefused =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("connect to {address}: {error}"),
        }
    }
}

fn is_connection_close(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn toml_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
