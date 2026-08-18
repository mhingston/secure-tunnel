//! Local byte-transparency compatibility contract.
//!
//! The fixtures in `fixtures/` are deliberately canned raw TCP conversations.
//! This harness never parses HTTP, SSE, WebSocket, Responses, tool, or
//! reasoning data: it writes and compares the fixture bytes exactly. It is not
//! a substitute for authorised live application + ChatGPT end-to-end validation.

use std::{
    fs,
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use secure_tunnel::{StaticKeypair, generate_keypair};

const WAIT: Duration = Duration::from_secs(10);
// The first tunneled request also initiates Noise, so leave headroom for a
// fresh handshake while retaining a full half-second margin before the fixture
// makes the rest of the response available. A whole-response buffer cannot
// satisfy this condition.
const LONG_STREAM_PAUSE: Duration = Duration::from_secs(2);
const FIRST_CHUNK_DEADLINE: Duration = Duration::from_millis(1500);
// A cancellation is only useful if it reaches the destination before that
// destination starts producing its deliberately delayed response.  This is
// intentionally much shorter than `WAIT`, which is for ordinary fixture I/O.
const CANCELLATION_RESPONSE_DELAY: Duration = Duration::from_millis(400);
static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

#[test]
fn models_like_http_is_byte_identical_direct_and_tunneled() {
    run_raw_comparison(FixtureCase::Models);
}

#[test]
fn normal_sse_is_byte_identical_direct_and_tunneled() {
    run_raw_comparison(FixtureCase::NormalSse);
}

#[test]
fn long_sse_streams_byte_identically_direct_and_tunneled() {
    run_raw_comparison(FixtureCase::LongSse);
}

#[test]
fn tool_and_reasoning_payload_bytes_are_byte_identical_direct_and_tunneled() {
    run_raw_comparison(FixtureCase::ToolAndReasoning);
}

#[test]
fn raw_cancellation_upstream_error_and_rate_limit_responses_are_identical() {
    for case in [
        FixtureCase::Cancellation,
        FixtureCase::UpstreamError,
        FixtureCase::RateLimit,
    ] {
        run_raw_comparison(case);
    }
}

#[test]
fn client_disconnect_reaches_destination_before_delayed_response_direct_and_tunneled() {
    let destination =
        CancellationProbeDestination::start(include_bytes!("fixtures/cancellation.request"));

    disconnect_after_write(
        destination.address(),
        include_bytes!("fixtures/cancellation.request"),
    );
    let direct = destination.next_observation("direct");

    let fixture = TunnelFixture::new();
    let server = fixture.start_server(destination.address());
    let client = fixture.start_client(server.address());
    disconnect_after_write(
        client.address(),
        include_bytes!("fixtures/cancellation.request"),
    );
    let tunneled = destination.next_observation("tunneled");

    for (path, observation) in [("direct", direct), ("tunneled", tunneled)] {
        assert!(
            observation.eof_after < CANCELLATION_RESPONSE_DELAY,
            "{path} destination did not observe client EOF before its delayed response: {:?}",
            observation.eof_after
        );
        assert!(
            observation.delayed_response_suppressed,
            "{path} left a destination response eligible to continue after client cancellation"
        );
    }

    drop(client);
    drop(server);
    destination.assert_clean();
}

#[test]
fn client_orderly_eof_drains_final_destination_bytes_then_fully_closes_direct_and_tunneled() {
    const REQUEST: &[u8] = b"opaque request whose writer closes\n";
    const FINAL_RESPONSE: &[u8] = b"opaque final response after request EOF\n";

    let destination = OrderlyCloseDestination::start(REQUEST, FINAL_RESPONSE);

    let direct = write_then_close_and_read_final(destination.address(), REQUEST, FINAL_RESPONSE);

    let fixture = TunnelFixture::new();
    let server = fixture.start_server(destination.address());
    let client = fixture.start_client(server.address());
    let tunneled = write_then_close_and_read_final(client.address(), REQUEST, FINAL_RESPONSE);

    assert_eq!(direct, FINAL_RESPONSE, "direct final response changed");
    assert_eq!(
        tunneled, FINAL_RESPONSE,
        "tunnel truncated or changed final response"
    );

    drop(client);
    drop(server);
    destination.assert_clean();
}

#[test]
fn destination_orderly_eof_drains_final_bytes_then_fully_closes_direct_and_tunneled() {
    const REQUEST: &[u8] = b"opaque request while local writer stays open\n";
    const FINAL_RESPONSE: &[u8] = b"opaque final response before destination EOF\n";

    let destination = OrderlyCloseDestination::start_after_request(REQUEST, FINAL_RESPONSE);

    let direct = write_and_read_final(destination.address(), REQUEST, FINAL_RESPONSE);

    let fixture = TunnelFixture::new();
    let server = fixture.start_server(destination.address());
    let client = fixture.start_client(server.address());
    let tunneled = write_and_read_final(client.address(), REQUEST, FINAL_RESPONSE);

    assert_eq!(direct, FINAL_RESPONSE, "direct final response changed");
    assert_eq!(
        tunneled, FINAL_RESPONSE,
        "tunnel truncated destination's final response"
    );

    drop(client);
    drop(server);
    destination.assert_clean();
}

#[test]
fn idle_tunneled_session_closes_after_the_configured_inactivity_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind silent destination");
    let destination = listener.local_addr().expect("silent destination address");
    let destination_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept tunnel destination");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("destination read timeout");
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Ok(_) => panic!("idle destination received unexpected plaintext"),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::NotConnected
                ) => {}
            Err(error) => panic!("silent destination read: {error}"),
        }
    });

    let fixture = TunnelFixture::new();
    let server = fixture.start_server_with_idle(destination, 1);
    let client = fixture.start_client_with_idle(server.address(), 1);
    let mut local = connect_retry(client.address());
    local
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("configure local idle read timeout");
    let started = Instant::now();
    let mut byte = [0u8; 1];
    match local.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
            ) => {}
        Ok(_) => panic!("idle tunnel emitted unexpected plaintext"),
        Err(error) => panic!("idle tunnel did not close: {error}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "idle tunnel exceeded its configured close window"
    );

    drop(local);
    drop(client);
    drop(server);
    destination_thread.join().expect("join silent destination");
}

#[test]
fn bidirectional_activity_resets_the_idle_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo destination");
    let destination = listener.local_addr().expect("echo destination address");
    let destination_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept tunnel destination");
        for expected in *b"abc" {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).expect("read activity byte");
            assert_eq!(byte, [expected]);
            stream.write_all(&byte).expect("write activity echo");
            stream.flush().expect("flush activity echo");
        }
    });

    let fixture = TunnelFixture::new();
    let server = fixture.start_server_with_idle(destination, 1);
    let client = fixture.start_client_with_idle(server.address(), 1);
    let mut local = connect_retry(client.address());
    local
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("configure local read timeout");
    for byte in *b"abc" {
        local.write_all(&[byte]).expect("write activity byte");
        local.flush().expect("flush activity byte");
        let mut echoed = [0u8; 1];
        local.read_exact(&mut echoed).expect("read activity echo");
        assert_eq!(echoed, [byte]);
        thread::sleep(Duration::from_millis(650));
    }

    drop(local);
    drop(client);
    drop(server);
    destination_thread.join().expect("join echo destination");
}

#[test]
fn websocket_like_upgrade_and_frames_are_byte_identical_direct_and_tunneled() {
    run_raw_comparison(FixtureCase::WebSocket);
}

#[test]
fn http_connection_reuse_is_byte_identical_direct_and_tunneled() {
    run_raw_comparison(FixtureCase::ConnectionReuse);
}

#[derive(Clone, Copy, Debug)]
enum FixtureCase {
    Models,
    NormalSse,
    LongSse,
    ToolAndReasoning,
    Cancellation,
    UpstreamError,
    RateLimit,
    WebSocket,
    ConnectionReuse,
}

struct Scenario {
    name: &'static str,
    exchanges: Vec<Exchange>,
    deliberately_streamed: bool,
}

struct Exchange {
    request: &'static [u8],
    response: Vec<ResponsePart>,
}

#[derive(Clone)]
struct ResponsePart {
    bytes: &'static [u8],
    pause_after: Duration,
}

impl FixtureCase {
    fn scenario(self) -> Scenario {
        let one = |name, request, response| Scenario {
            name,
            exchanges: vec![Exchange {
                request,
                response: vec![ResponsePart {
                    bytes: response,
                    pause_after: Duration::ZERO,
                }],
            }],
            deliberately_streamed: false,
        };
        match self {
            Self::Models => one(
                "models-like HTTP",
                include_bytes!("fixtures/models.request"),
                include_bytes!("fixtures/models.response"),
            ),
            Self::NormalSse => one(
                "normal SSE",
                include_bytes!("fixtures/normal-sse.request"),
                include_bytes!("fixtures/normal-sse.response"),
            ),
            Self::LongSse => Scenario {
                name: "long SSE",
                exchanges: vec![Exchange {
                    request: include_bytes!("fixtures/long-sse.request"),
                    response: vec![
                        ResponsePart {
                            bytes: include_bytes!("fixtures/long-sse.response.first"),
                            pause_after: LONG_STREAM_PAUSE,
                        },
                        ResponsePart {
                            bytes: include_bytes!("fixtures/long-sse.response.rest"),
                            pause_after: Duration::ZERO,
                        },
                    ],
                }],
                deliberately_streamed: true,
            },
            Self::ToolAndReasoning => one(
                "native tool and reasoning payload",
                include_bytes!("fixtures/tool-reasoning.request"),
                include_bytes!("fixtures/tool-reasoning.response"),
            ),
            Self::Cancellation => one(
                "cancellation response",
                include_bytes!("fixtures/cancellation.request"),
                include_bytes!("fixtures/cancellation.response"),
            ),
            Self::UpstreamError => one(
                "upstream-error response",
                include_bytes!("fixtures/upstream-error.request"),
                include_bytes!("fixtures/upstream-error.response"),
            ),
            Self::RateLimit => one(
                "rate-limit response",
                include_bytes!("fixtures/rate-limit.request"),
                include_bytes!("fixtures/rate-limit.response"),
            ),
            Self::WebSocket => one(
                "WebSocket-like upgrade and frames",
                include_bytes!("fixtures/websocket.request"),
                include_bytes!("fixtures/websocket.response"),
            ),
            Self::ConnectionReuse => Scenario {
                name: "HTTP connection reuse",
                exchanges: vec![
                    Exchange {
                        request: include_bytes!("fixtures/reuse.first.request"),
                        response: vec![ResponsePart {
                            bytes: include_bytes!("fixtures/reuse.first.response"),
                            pause_after: Duration::ZERO,
                        }],
                    },
                    Exchange {
                        request: include_bytes!("fixtures/reuse.second.request"),
                        response: vec![ResponsePart {
                            bytes: include_bytes!("fixtures/reuse.second.response"),
                            pause_after: Duration::ZERO,
                        }],
                    },
                ],
                deliberately_streamed: false,
            },
        }
    }
}

fn run_raw_comparison(case: FixtureCase) {
    let scenario = case.scenario();
    let destination = OpaqueFixtureDestination::start(&scenario);

    let direct = execute_raw_conversation(destination.address(), &scenario);
    let fixture = TunnelFixture::new();
    let server = fixture.start_server(destination.address());
    let client = fixture.start_client(server.address());
    let tunneled = execute_raw_conversation(client.address(), &scenario);

    assert_eq!(
        direct.bytes,
        scenario.response_bytes(),
        "direct {} fixture changed before it reached the tunnel",
        scenario.name
    );
    assert_eq!(
        tunneled.bytes,
        scenario.response_bytes(),
        "tunnel changed {} fixture bytes",
        scenario.name
    );
    assert_eq!(
        direct.bytes, tunneled.bytes,
        "direct and tunneled {} bytes differ",
        scenario.name
    );
    if scenario.deliberately_streamed {
        assert!(
            direct.first_response_at < FIRST_CHUNK_DEADLINE,
            "direct {} first chunk was not flushed promptly: {:?}",
            scenario.name,
            direct.first_response_at
        );
        assert!(
            tunneled.first_response_at < FIRST_CHUNK_DEADLINE,
            "tunnel buffered the first {} chunk until too late: {:?}",
            scenario.name,
            tunneled.first_response_at
        );
    }

    drop(client);
    drop(server);
    destination.assert_clean();
}

impl Scenario {
    fn response_bytes(&self) -> Vec<u8> {
        self.exchanges
            .iter()
            .flat_map(|exchange| exchange.response.iter())
            .flat_map(|part| part.bytes.iter().copied())
            .collect()
    }
}

struct Conversation {
    bytes: Vec<u8>,
    first_response_at: Duration,
}

fn execute_raw_conversation(address: std::net::SocketAddr, scenario: &Scenario) -> Conversation {
    let mut stream = connect_retry(address);
    stream
        .set_read_timeout(Some(WAIT))
        .expect("configure fixture read timeout");
    stream
        .set_write_timeout(Some(WAIT))
        .expect("configure fixture write timeout");

    let mut bytes = Vec::new();
    let started = Instant::now();
    let mut first_response_at = None;
    for exchange in &scenario.exchanges {
        stream
            .write_all(exchange.request)
            .expect("write opaque fixture request");
        stream.flush().expect("flush opaque fixture request");
        for part in &exchange.response {
            let mut actual = vec![0; part.bytes.len()];
            stream
                .read_exact(&mut actual)
                .expect("read opaque fixture response bytes");
            first_response_at.get_or_insert_with(|| started.elapsed());
            assert_eq!(
                actual, part.bytes,
                "fixture destination did not preserve its own canned response bytes"
            );
            bytes.extend_from_slice(&actual);
        }
    }
    Conversation {
        bytes,
        first_response_at: first_response_at.expect("all fixture conversations return bytes"),
    }
}

/// A loopback-only canned destination. It only performs exact byte reads and
/// writes; in particular it never identifies routes, headers, SSE events, or
/// WebSocket frames. Two connections are served: first direct, then tunneled.
struct OpaqueFixtureDestination {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl OpaqueFixtureDestination {
    fn start(scenario: &Scenario) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture destination");
        listener
            .set_nonblocking(true)
            .expect("make fixture destination nonblocking");
        let address = listener.local_addr().expect("fixture destination address");
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let stop_for_thread = Arc::clone(&stop);
        let failure_for_thread = Arc::clone(&failure);
        let exchanges = scenario
            .exchanges
            .iter()
            .map(|exchange| (exchange.request, exchange.response.clone()))
            .collect::<Vec<_>>();
        let thread = thread::spawn(move || {
            let mut served = 0;
            while served < 2 && !stop_for_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        served += 1;
                        if let Err(error) = serve_opaque_connection(stream, &exchanges) {
                            *failure_for_thread.lock().expect("fixture failure lock") = Some(error);
                            return;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => {
                        *failure_for_thread.lock().expect("fixture failure lock") =
                            Some(format!("fixture listener failed: {error}"));
                        return;
                    }
                }
            }
            if served != 2 && !stop_for_thread.load(Ordering::Relaxed) {
                *failure_for_thread.lock().expect("fixture failure lock") = Some(format!(
                    "fixture served {served} connections; expected direct plus tunneled connections"
                ));
            }
        });
        Self {
            address,
            stop,
            failure,
            thread: Some(thread),
        }
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn assert_clean(mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join fixture destination");
        }
        if let Some(error) = self.failure.lock().expect("fixture failure lock").take() {
            panic!("opaque fixture destination error: {error}");
        }
    }
}

impl Drop for OpaqueFixtureDestination {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_opaque_connection(
    mut stream: TcpStream,
    exchanges: &[(&'static [u8], Vec<ResponsePart>)],
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(WAIT))
        .map_err(|error| format!("set fixture read timeout: {error}"))?;
    for (expected_request, response) in exchanges {
        let mut actual_request = vec![0; expected_request.len()];
        stream
            .read_exact(&mut actual_request)
            .map_err(|error| format!("read opaque fixture request: {error}"))?;
        if actual_request != *expected_request {
            return Err("fixture received bytes different from its canned request".to_owned());
        }
        for part in response {
            stream
                .write_all(part.bytes)
                .map_err(|error| format!("write opaque fixture response: {error}"))?;
            stream
                .flush()
                .map_err(|error| format!("flush opaque fixture response: {error}"))?;
            if !part.pause_after.is_zero() {
                thread::sleep(part.pause_after);
            }
        }
    }
    Ok(())
}

/// A cancellation-specific loopback destination.  It does the same opaque
/// exact request read as the canned fixture destination, but waits for the
/// peer to close before its response deadline.  A peer that remains connected
/// across that deadline would be able to receive the delayed response, so the
/// fixture reports it instead of sending a synthetic `499` response.
struct CancellationProbeDestination {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    observations: mpsc::Receiver<Result<CancellationObservation, String>>,
    failure: Arc<Mutex<Option<String>>>,
    thread: Option<thread::JoinHandle<()>>,
}

struct CancellationObservation {
    eof_after: Duration,
    delayed_response_suppressed: bool,
}

impl CancellationProbeDestination {
    fn start(expected_request: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind cancellation destination");
        listener
            .set_nonblocking(true)
            .expect("make cancellation destination nonblocking");
        let address = listener
            .local_addr()
            .expect("cancellation destination address");
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let (observation_tx, observations) = mpsc::channel();
        let stop_for_thread = Arc::clone(&stop);
        let failure_for_thread = Arc::clone(&failure);
        let thread = thread::spawn(move || {
            let mut served = 0;
            while served < 2 && !stop_for_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        served += 1;
                        let result = observe_cancellation(stream, expected_request);
                        if observation_tx.send(result).is_err() {
                            return;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => {
                        *failure_for_thread
                            .lock()
                            .expect("cancellation failure lock") =
                            Some(format!("cancellation listener failed: {error}"));
                        return;
                    }
                }
            }
            if served != 2 && !stop_for_thread.load(Ordering::Relaxed) {
                *failure_for_thread
                    .lock()
                    .expect("cancellation failure lock") = Some(format!(
                    "cancellation fixture served {served} connections; expected direct plus tunneled connections"
                ));
            }
        });
        Self {
            address,
            stop,
            observations,
            failure,
            thread: Some(thread),
        }
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn next_observation(&self, path: &str) -> CancellationObservation {
        match self
            .observations
            .recv_timeout(WAIT + CANCELLATION_RESPONSE_DELAY)
            .unwrap_or_else(|error| panic!("wait for {path} cancellation observation: {error}"))
        {
            Ok(observation) => observation,
            Err(error) => panic!("{path} cancellation fixture error: {error}"),
        }
    }

    fn assert_clean(mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join cancellation destination");
        }
        if let Some(error) = self
            .failure
            .lock()
            .expect("cancellation failure lock")
            .take()
        {
            panic!("cancellation destination error: {error}");
        }
    }
}

impl Drop for CancellationProbeDestination {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn observe_cancellation(
    mut stream: TcpStream,
    expected_request: &'static [u8],
) -> Result<CancellationObservation, String> {
    stream
        .set_read_timeout(Some(WAIT))
        .map_err(|error| format!("set cancellation read timeout: {error}"))?;
    let mut actual_request = vec![0; expected_request.len()];
    stream
        .read_exact(&mut actual_request)
        .map_err(|error| format!("read opaque cancellation request: {error}"))?;
    if actual_request != expected_request {
        return Err("cancellation fixture received bytes different from its canned request".into());
    }

    stream
        .set_read_timeout(Some(CANCELLATION_RESPONSE_DELAY))
        .map_err(|error| format!("set cancellation deadline: {error}"))?;
    let closed_at = Instant::now();
    let mut extra = [0u8; 1];
    match stream.read(&mut extra) {
        Ok(0) => Ok(CancellationObservation {
            eof_after: closed_at.elapsed(),
            delayed_response_suppressed: true,
        }),
        Ok(_) => Err("cancellation fixture received unexpected bytes after request".into()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(CancellationObservation {
                eof_after: CANCELLATION_RESPONSE_DELAY,
                delayed_response_suppressed: false,
            })
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
            ) =>
        {
            Ok(CancellationObservation {
                eof_after: closed_at.elapsed(),
                delayed_response_suppressed: true,
            })
        }
        Err(error) => Err(format!("observe cancellation connection close: {error}")),
    }
}

fn disconnect_after_write(address: std::net::SocketAddr, request: &[u8]) {
    let mut stream = connect_retry(address);
    stream
        .set_nodelay(true)
        .expect("disable Nagle for cancellation fixture client");
    stream
        .write_all(request)
        .expect("write opaque cancellation request");
    stream.flush().expect("flush opaque cancellation request");
    stream
        .shutdown(Shutdown::Both)
        .expect("disconnect cancellation fixture client");
}

fn write_then_close_and_read_final(
    address: std::net::SocketAddr,
    request: &[u8],
    expected_final_response: &[u8],
) -> Vec<u8> {
    let mut stream = connect_retry(address);
    stream
        .set_read_timeout(Some(WAIT))
        .expect("set orderly-close read timeout");
    stream
        .write_all(request)
        .expect("write orderly-close opaque request");
    stream.flush().expect("flush orderly-close opaque request");
    stream
        .shutdown(Shutdown::Write)
        .expect("close orderly-close request writer");

    let mut final_response = vec![0; expected_final_response.len()];
    stream
        .read_exact(&mut final_response)
        .expect("read final bytes after orderly request EOF");
    let mut trailing = [0u8; 1];
    assert_eq!(
        stream
            .read(&mut trailing)
            .expect("observe full session close after final bytes"),
        0,
        "session remained half-open after final bytes"
    );
    final_response
}

fn write_and_read_final(
    address: std::net::SocketAddr,
    request: &[u8],
    expected_final_response: &[u8],
) -> Vec<u8> {
    let mut stream = connect_retry(address);
    stream
        .set_read_timeout(Some(WAIT))
        .expect("set destination-close read timeout");
    stream
        .write_all(request)
        .expect("write destination-close opaque request");
    stream
        .flush()
        .expect("flush destination-close opaque request");

    let mut final_response = vec![0; expected_final_response.len()];
    stream
        .read_exact(&mut final_response)
        .expect("read final bytes before destination EOF");
    let mut trailing = [0u8; 1];
    assert_eq!(
        stream
            .read(&mut trailing)
            .expect("observe full close after destination EOF"),
        0,
        "session remained half-open after destination EOF"
    );
    final_response
}

/// A destination that requires a request-side EOF before it sends its final
/// opaque bytes.  It exercises v1's full-close policy: the tunnel must relay
/// the already-produced reverse bytes, then close rather than forwarding a
/// half-close indefinitely.
struct OrderlyCloseDestination {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl OrderlyCloseDestination {
    fn start(expected_request: &'static [u8], final_response: &'static [u8]) -> Self {
        Self::start_with_request_eof(expected_request, final_response, true)
    }

    fn start_after_request(expected_request: &'static [u8], final_response: &'static [u8]) -> Self {
        Self::start_with_request_eof(expected_request, final_response, false)
    }

    fn start_with_request_eof(
        expected_request: &'static [u8],
        final_response: &'static [u8],
        require_request_eof: bool,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind orderly-close destination");
        listener
            .set_nonblocking(true)
            .expect("make orderly-close destination nonblocking");
        let address = listener
            .local_addr()
            .expect("orderly-close destination address");
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let stop_for_thread = Arc::clone(&stop);
        let failure_for_thread = Arc::clone(&failure);
        let thread = thread::spawn(move || {
            let mut served = 0;
            while served < 2 && !stop_for_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        served += 1;
                        if let Err(error) = serve_orderly_close(
                            stream,
                            expected_request,
                            final_response,
                            require_request_eof,
                        ) {
                            *failure_for_thread
                                .lock()
                                .expect("orderly-close failure lock") = Some(error);
                            return;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => {
                        *failure_for_thread
                            .lock()
                            .expect("orderly-close failure lock") =
                            Some(format!("orderly-close listener failed: {error}"));
                        return;
                    }
                }
            }
            if served != 2 && !stop_for_thread.load(Ordering::Relaxed) {
                *failure_for_thread
                    .lock()
                    .expect("orderly-close failure lock") = Some(format!(
                    "orderly-close fixture served {served} connections; expected direct plus tunneled connections"
                ));
            }
        });
        Self {
            address,
            stop,
            failure,
            thread: Some(thread),
        }
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn assert_clean(mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join orderly-close destination");
        }
        if let Some(error) = self
            .failure
            .lock()
            .expect("orderly-close failure lock")
            .take()
        {
            panic!("orderly-close destination error: {error}");
        }
    }
}

impl Drop for OrderlyCloseDestination {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_orderly_close(
    mut stream: TcpStream,
    expected_request: &[u8],
    final_response: &[u8],
    require_request_eof: bool,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(WAIT))
        .map_err(|error| format!("set orderly-close read timeout: {error}"))?;
    let mut actual_request = vec![0; expected_request.len()];
    stream
        .read_exact(&mut actual_request)
        .map_err(|error| format!("read orderly-close request: {error}"))?;
    if actual_request != expected_request {
        return Err("orderly-close fixture received changed request bytes".into());
    }
    if require_request_eof {
        let mut trailing = [0u8; 1];
        match stream.read(&mut trailing) {
            Ok(0) => {}
            Ok(_) => {
                return Err(
                    "orderly-close fixture received unexpected trailing request bytes".into(),
                );
            }
            Err(error) => return Err(format!("wait for orderly-close request EOF: {error}")),
        }
    }
    stream
        .write_all(final_response)
        .map_err(|error| format!("write orderly-close final response: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("flush orderly-close final response: {error}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|error| format!("close orderly-close response writer: {error}"))
}

struct TunnelFixture {
    root: TempDir,
    client: StaticKeypair,
    server: StaticKeypair,
}

impl TunnelFixture {
    fn new() -> Self {
        Self {
            root: TempDir::new(),
            client: generate_keypair().expect("generate client identity"),
            server: generate_keypair().expect("generate server identity"),
        }
    }

    fn start_server(&self, destination: std::net::SocketAddr) -> Process {
        self.start_server_with_idle(destination, 30)
    }

    fn start_server_with_idle(
        &self,
        destination: std::net::SocketAddr,
        idle_seconds: u64,
    ) -> Process {
        let listen = unused_loopback_address();
        let key_path = self.root.path().join("server.key");
        write_private_key(&key_path, &self.server);
        let config = format!(
            "[listen]\naddress = \"{listen}\"\n\n[destination]\naddress = \"{destination}\"\n\n[identity]\nprivate_key_file = \"{}\"\n\n[timeouts]\ndestination_connect_seconds = 2\nhandshake_seconds = 2\nidle_seconds = {idle_seconds}\n\n[[authorized_clients]]\nname = \"compatibility-fixture\"\npublic_key = \"{}\"\n",
            toml_path(&key_path),
            STANDARD.encode(self.client.public_key()),
        );
        let config_path = self.root.path().join("server.toml");
        write_protected_config(&config_path, &config);
        Process::start(server_binary(), "server", &config_path, listen)
    }

    fn start_client(&self, remote: std::net::SocketAddr) -> Process {
        self.start_client_with_idle(remote, 30)
    }

    fn start_client_with_idle(&self, remote: std::net::SocketAddr, idle_seconds: u64) -> Process {
        let listen = unused_loopback_address();
        let key_path = self.root.path().join("client.key");
        write_private_key(&key_path, &self.client);
        let config = format!(
            "[listen]\naddress = \"{listen}\"\n\n[remote]\naddress = \"{remote}\"\n\n[identity]\nprivate_key_file = \"{}\"\n\n[peer]\nserver_public_key = \"{}\"\n\n[timeouts]\nconnect_seconds = 2\nhandshake_seconds = 2\nidle_seconds = {idle_seconds}\n",
            toml_path(&key_path),
            STANDARD.encode(self.server.public_key()),
        );
        let config_path = self.root.path().join("client.toml");
        write_protected_config(&config_path, &config);
        Process::start(client_binary(), "client", &config_path, listen)
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

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "secure-tunnel-compatibility-{}-{}",
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("protect private key permissions");
    }
}

fn write_protected_config(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write tunnel config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("protect tunnel config permissions");
    }
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("compatibility test crate is in project tests directory")
        .to_owned()
}

fn client_binary() -> PathBuf {
    required_binary("secure-tunnel")
}

fn server_binary() -> PathBuf {
    required_binary("secure-tunnel-server")
}

fn required_binary(name: &str) -> PathBuf {
    let binary = project_root().join("target/debug").join(name);
    assert!(
        binary.is_file(),
        "{name} is required for black-box compatibility tests; run `cargo build -p secure-tunnel-client -p secure-tunnel-server` before this test target"
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

fn toml_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
