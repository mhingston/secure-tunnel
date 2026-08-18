#![forbid(unsafe_code)]

//! Cryptographic handshake and record framing for Secure Tunnel.

use std::sync::{Arc, Mutex};
use std::{collections::HashSet, fmt};

use snow::{HandshakeState, TransportState};
use thiserror::Error;

pub const MAX_HANDSHAKE_MESSAGE: usize = 4_096;
pub const MAX_PLAINTEXT_RECORD: usize = 16_384;
pub const MAX_CIPHERTEXT_RECORD: usize = 16_400;
/// Maximum server identities allowed during a planned key-rotation overlap.
/// This bounds cryptographic work triggered by a hostile first IK message.
pub const MAX_SERVER_STATIC_IDENTITIES: usize = 8;
/// Hard upper bound for concurrently active tunnel sessions per process.
/// It keeps configuration from turning a local listener into an unbounded
/// task/descriptor allocator and remains well below Tokio's semaphore limit.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 1_024;
const PREFACE: [u8; 6] = *b"CDXT\x01\x00";
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Fail-closed protocol errors. Callers must close the connection on any error.
#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("invalid protocol preface")]
    InvalidPreface,
    #[error("unsupported protocol version {major}.{minor}")]
    UnsupportedVersion { major: u8, minor: u8 },
    #[error("handshake message is too large: {0} bytes")]
    HandshakeMessageTooLarge(usize),
    #[error("plaintext record is too large: {0} bytes")]
    PlaintextTooLarge(usize),
    #[error("ciphertext record is too large: {0} bytes")]
    CiphertextTooLarge(usize),
    #[error("truncated frame: expected {expected} bytes, got {actual}")]
    TruncatedFrame { expected: usize, actual: usize },
    #[error("frame contains trailing bytes")]
    TrailingFrameBytes,
    #[error("handshake operation is out of order")]
    HandshakeOrder,
    #[error("handshake or transport session is closed after completion or failure")]
    ClosedSession,
    #[error("client static key is not authorised")]
    UnauthorisedClient,
    #[error("at least one server static identity is required")]
    MissingServerStaticIdentity,
    #[error("too many server static identities: {0} (maximum {MAX_SERVER_STATIC_IDENTITIES})")]
    TooManyServerStaticIdentities(usize),
    #[error("invalid Noise static key material")]
    InvalidKeyMaterial,
    #[error("cryptographic operation failed")]
    Noise(#[from] snow::Error),
    #[error("transport cipher state lock poisoned")]
    PoisonedCipherState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preface {
    V1,
}

impl Preface {
    pub const fn encode(self) -> [u8; 6] {
        PREFACE
    }

    pub fn parse(value: &[u8]) -> Result<Self, TunnelError> {
        if value.len() != PREFACE.len() || value[..4] != PREFACE[..4] {
            return Err(TunnelError::InvalidPreface);
        }
        if value[4] != 1 {
            return Err(TunnelError::UnsupportedVersion {
                major: value[4],
                minor: value[5],
            });
        }
        if value[5] != 0 {
            return Err(TunnelError::UnsupportedVersion {
                major: value[4],
                minor: value[5],
            });
        }
        Ok(Self::V1)
    }
}

/// A newly generated X25519 static Noise identity. Provision the public key
/// out of band; persist the private key only in protected local storage.
#[derive(Clone, PartialEq, Eq)]
pub struct StaticKeypair {
    private: [u8; 32],
    public: [u8; 32],
}

impl fmt::Debug for StaticKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticKeypair")
            .field("private", &"[REDACTED]")
            .field("public", &self.public)
            .finish()
    }
}

impl StaticKeypair {
    pub const fn private_key(&self) -> &[u8; 32] {
        &self.private
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    pub const fn into_parts(self) -> ([u8; 32], [u8; 32]) {
        (self.private, self.public)
    }
}

/// Generates an X25519 identity using Snow's operating-system-backed RNG.
pub fn generate_keypair() -> Result<StaticKeypair, TunnelError> {
    let keypair = noise_builder()?.generate_keypair()?;
    Ok(StaticKeypair {
        private: keypair
            .private
            .try_into()
            .map_err(|_| TunnelError::InvalidKeyMaterial)?,
        public: keypair
            .public
            .try_into()
            .map_err(|_| TunnelError::InvalidKeyMaterial)?,
    })
}

fn noise_builder() -> Result<snow::Builder<'static>, TunnelError> {
    Ok(snow::Builder::new(NOISE_PARAMS.parse()?).prologue(&PREFACE)?)
}

pub fn encode_handshake_frame(message: &[u8]) -> Result<Vec<u8>, TunnelError> {
    if message.len() > MAX_HANDSHAKE_MESSAGE {
        return Err(TunnelError::HandshakeMessageTooLarge(message.len()));
    }
    let length: u16 = message
        .len()
        .try_into()
        .map_err(|_| TunnelError::HandshakeMessageTooLarge(message.len()))?;
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(message);
    Ok(frame)
}

pub fn decode_handshake_frame(frame: &[u8]) -> Result<&[u8], TunnelError> {
    decode_frame(frame, 2, MAX_HANDSHAKE_MESSAGE, true)
}

pub fn decode_record_frame(frame: &[u8]) -> Result<&[u8], TunnelError> {
    decode_frame(frame, 4, MAX_CIPHERTEXT_RECORD, false)
}

fn decode_frame(
    frame: &[u8],
    header_len: usize,
    maximum: usize,
    handshake: bool,
) -> Result<&[u8], TunnelError> {
    if frame.len() < header_len {
        return Err(TunnelError::TruncatedFrame {
            expected: header_len,
            actual: frame.len(),
        });
    }
    let claimed = if header_len == 2 {
        u16::from_be_bytes([frame[0], frame[1]]) as usize
    } else {
        u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize
    };
    if claimed > maximum {
        return Err(if handshake {
            TunnelError::HandshakeMessageTooLarge(claimed)
        } else {
            TunnelError::CiphertextTooLarge(claimed)
        });
    }
    let expected = header_len + claimed;
    if frame.len() < expected {
        return Err(TunnelError::TruncatedFrame {
            expected,
            actual: frame.len(),
        });
    }
    if frame.len() > expected {
        return Err(TunnelError::TrailingFrameBytes);
    }
    Ok(&frame[header_len..])
}

pub struct ClientHandshake {
    state: Option<HandshakeState>,
    sent_first: bool,
}

impl ClientHandshake {
    pub fn new(client_private: [u8; 32], pinned_server: [u8; 32]) -> Result<Self, TunnelError> {
        let state = noise_builder()?
            .local_private_key(&client_private)?
            .remote_public_key(&pinned_server)?
            .build_initiator()?;
        Ok(Self {
            state: Some(state),
            sent_first: false,
        })
    }

    /// Returns the first, length-prefixed IK message. Send the V1 preface first.
    pub fn first_message(&mut self) -> Result<Vec<u8>, TunnelError> {
        if self.sent_first {
            return Err(TunnelError::HandshakeOrder);
        }
        let mut message = vec![0; MAX_HANDSHAKE_MESSAGE];
        let mut state = self.state.take().ok_or(TunnelError::ClosedSession)?;
        let written = state.write_message(&[], &mut message)?;
        message.truncate(written);
        self.sent_first = true;
        let frame = encode_handshake_frame(&message)?;
        self.state = Some(state);
        Ok(frame)
    }

    /// Authenticates the server's pinned static key through Noise IK and yields
    /// the encrypted transport session.
    pub fn finish(&mut self, server_frame: &[u8]) -> Result<TransportSession, TunnelError> {
        if !self.sent_first {
            return Err(TunnelError::HandshakeOrder);
        }
        let message = decode_handshake_frame(server_frame)?;
        let mut plaintext = vec![0; MAX_HANDSHAKE_MESSAGE];
        let mut state = self.state.take().ok_or(TunnelError::ClosedSession)?;
        state.read_message(message, &mut plaintext)?;
        Ok(TransportSession::new(state.into_transport_mode()?))
    }
}

pub struct ServerHandshake {
    /// Taken before attempting the first IK message, ensuring each connection
    /// receives only one chance to process its first handshake frame.
    static_identities: Option<Vec<[u8; 32]>>,
    allow_list: HashSet<[u8; 32]>,
    preface_accepted: bool,
}

impl ServerHandshake {
    pub fn new(
        server_private: [u8; 32],
        authorised_clients: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<Self, TunnelError> {
        Self::new_with_static_identities([server_private], authorised_clients)
    }

    /// Creates a responder that accepts a bounded overlap of server static
    /// identities. The first IK message is tried against each configured
    /// identity, and only a successful handshake from an allow-listed client
    /// can yield a reply. This does not create any client-side key fallback.
    pub fn new_with_static_identities(
        server_privates: impl IntoIterator<Item = [u8; 32]>,
        authorised_clients: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<Self, TunnelError> {
        let static_identities: Vec<_> = server_privates.into_iter().collect();
        if static_identities.is_empty() {
            return Err(TunnelError::MissingServerStaticIdentity);
        }
        if static_identities.len() > MAX_SERVER_STATIC_IDENTITIES {
            return Err(TunnelError::TooManyServerStaticIdentities(
                static_identities.len(),
            ));
        }
        Ok(Self {
            static_identities: Some(static_identities),
            allow_list: authorised_clients.into_iter().collect(),
            preface_accepted: false,
        })
    }

    /// Checks the clear preface before accepting any handshake bytes.
    pub fn accept_preface(&mut self, preface: &[u8]) -> Result<(), TunnelError> {
        if self.preface_accepted {
            return Err(TunnelError::HandshakeOrder);
        }
        Preface::parse(preface)?;
        self.preface_accepted = true;
        Ok(())
    }

    /// Authenticates the initiator and rejects unauthorised client static keys
    /// before producing a responder handshake message.
    pub fn receive_client(&mut self, client_frame: &[u8]) -> Result<ServerReply, TunnelError> {
        if !self.preface_accepted {
            return Err(TunnelError::HandshakeOrder);
        }
        let message = decode_handshake_frame(client_frame)?;
        let mut plaintext = vec![0; MAX_HANDSHAKE_MESSAGE];
        let static_identities = self
            .static_identities
            .take()
            .ok_or(TunnelError::ClosedSession)?;
        let mut unauthorised_client = false;
        let mut last_error = None;

        for server_private in static_identities {
            let mut state = noise_builder()?
                .local_private_key(&server_private)?
                .build_responder()?;
            match state.read_message(message, &mut plaintext) {
                Ok(_) => {
                    let remote: [u8; 32] = state
                        .get_remote_static()
                        .ok_or(TunnelError::UnauthorisedClient)?
                        .try_into()
                        .map_err(|_| TunnelError::UnauthorisedClient)?;
                    if self.allow_list.contains(&remote) {
                        return Ok(ServerReply {
                            state: Some(state),
                            sent_reply: false,
                        });
                    }
                    unauthorised_client = true;
                }
                Err(error) => last_error = Some(error),
            }
        }
        if unauthorised_client {
            Err(TunnelError::UnauthorisedClient)
        } else {
            Err(TunnelError::Noise(
                last_error.expect("at least one bounded static identity was tried"),
            ))
        }
    }
}

pub struct ServerReply {
    state: Option<HandshakeState>,
    sent_reply: bool,
}

impl ServerReply {
    pub fn message(&mut self) -> Result<Vec<u8>, TunnelError> {
        if self.sent_reply {
            return Err(TunnelError::HandshakeOrder);
        }
        let mut message = vec![0; MAX_HANDSHAKE_MESSAGE];
        let mut state = self.state.take().ok_or(TunnelError::ClosedSession)?;
        let written = state.write_message(&[], &mut message)?;
        message.truncate(written);
        self.sent_reply = true;
        let frame = encode_handshake_frame(&message)?;
        self.state = Some(state);
        Ok(frame)
    }

    pub fn into_session(mut self) -> Result<TransportSession, TunnelError> {
        if !self.sent_reply {
            return Err(TunnelError::HandshakeOrder);
        }
        let state = self.state.take().ok_or(TunnelError::ClosedSession)?;
        Ok(TransportSession::new(state.into_transport_mode()?))
    }
}

/// An authenticated Noise transport. Call `split` before passing the two
/// traffic directions to separate async relay tasks.
pub struct TransportSession {
    state: Arc<Mutex<Option<TransportState>>>,
}

impl TransportSession {
    fn new(state: TransportState) -> Self {
        Self {
            state: Arc::new(Mutex::new(Some(state))),
        }
    }

    pub fn encrypt_record(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TunnelError> {
        seal_record(&self.state, plaintext)
    }

    pub fn decrypt_record(&mut self, frame: &[u8]) -> Result<Vec<u8>, TunnelError> {
        open_record(&self.state, frame)
    }

    pub fn split(self) -> (TransportSender, TransportReceiver) {
        (
            TransportSender {
                state: Arc::clone(&self.state),
            },
            TransportReceiver { state: self.state },
        )
    }
}

pub struct TransportSender {
    state: Arc<Mutex<Option<TransportState>>>,
}

impl TransportSender {
    pub fn encrypt_record(&self, plaintext: &[u8]) -> Result<Vec<u8>, TunnelError> {
        seal_record(&self.state, plaintext)
    }
}

pub struct TransportReceiver {
    state: Arc<Mutex<Option<TransportState>>>,
}

impl TransportReceiver {
    pub fn decrypt_record(&self, frame: &[u8]) -> Result<Vec<u8>, TunnelError> {
        open_record(&self.state, frame)
    }
}

fn seal_record(
    state: &Mutex<Option<TransportState>>,
    plaintext: &[u8],
) -> Result<Vec<u8>, TunnelError> {
    if plaintext.len() > MAX_PLAINTEXT_RECORD {
        return Err(TunnelError::PlaintextTooLarge(plaintext.len()));
    }
    let mut locked = state.lock().map_err(|_| TunnelError::PoisonedCipherState)?;
    let mut transport = locked.take().ok_or(TunnelError::ClosedSession)?;
    let mut ciphertext = vec![0; plaintext.len() + 16];
    let written = transport.write_message(plaintext, &mut ciphertext)?;
    ciphertext.truncate(written);
    if ciphertext.len() > MAX_CIPHERTEXT_RECORD {
        return Err(TunnelError::CiphertextTooLarge(ciphertext.len()));
    }
    let length: u32 = ciphertext
        .len()
        .try_into()
        .map_err(|_| TunnelError::CiphertextTooLarge(ciphertext.len()))?;
    let mut frame = Vec::with_capacity(ciphertext.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&ciphertext);
    *locked = Some(transport);
    Ok(frame)
}

fn open_record(
    state: &Mutex<Option<TransportState>>,
    frame: &[u8],
) -> Result<Vec<u8>, TunnelError> {
    let ciphertext = decode_record_frame(frame)?;
    let mut plaintext = vec![0; ciphertext.len().saturating_sub(16)];
    let mut locked = state.lock().map_err(|_| TunnelError::PoisonedCipherState)?;
    let mut transport = locked.take().ok_or(TunnelError::ClosedSession)?;
    let written = transport.read_message(ciphertext, &mut plaintext)?;
    plaintext.truncate(written);
    if plaintext.len() > MAX_PLAINTEXT_RECORD {
        return Err(TunnelError::PlaintextTooLarge(plaintext.len()));
    }
    *locked = Some(transport);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn static_keypair() -> ([u8; 32], [u8; 32]) {
        let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256"
            .parse()
            .expect("valid Noise parameters");
        let keypair = snow::Builder::new(params)
            .generate_keypair()
            .expect("generate static key pair");
        (
            keypair.private.try_into().expect("32-byte private key"),
            keypair.public.try_into().expect("32-byte public key"),
        )
    }

    #[test]
    fn preface_round_trips_and_rejects_incompatible_versions() {
        assert_eq!(Preface::V1.encode(), *b"CDXT\x01\x00");
        assert_eq!(
            Preface::parse(b"CDXT\x01\x00").expect("v1 preface"),
            Preface::V1
        );
        assert!(matches!(
            Preface::parse(b"CDXT\x02\x00"),
            Err(TunnelError::UnsupportedVersion { major: 2, minor: 0 })
        ));
        assert!(matches!(
            Preface::parse(b"nope"),
            Err(TunnelError::InvalidPreface)
        ));
    }

    #[test]
    fn handshake_frame_rejects_declared_oversize_before_allocation() {
        assert!(matches!(
            decode_handshake_frame(&[0x10, 0x01]),
            Err(TunnelError::HandshakeMessageTooLarge(4097))
        ));
        assert!(matches!(
            encode_handshake_frame(&vec![0; MAX_HANDSHAKE_MESSAGE + 1]),
            Err(TunnelError::HandshakeMessageTooLarge(4097))
        ));
    }

    #[test]
    fn ik_handshake_pins_server_and_authorises_client() {
        let (client_private, client_public) = static_keypair();
        let (server_private, server_public) = static_keypair();

        let mut client = ClientHandshake::new(client_private, server_public).expect("client");
        let mut server = ServerHandshake::new(server_private, [client_public]).expect("server");

        server
            .accept_preface(&Preface::V1.encode())
            .expect("preface accepted");
        let first = client
            .first_message()
            .expect("client first handshake message");
        let mut reply = server.receive_client(&first).expect("authorised client");
        let second = reply.message().expect("server response");
        let mut client_transport = client.finish(&second).expect("pinned server accepted");
        let mut server_transport = reply.into_session().expect("server transport");

        let record = client_transport
            .encrypt_record(b"opaque application bytes")
            .expect("encrypt");
        assert_eq!(
            server_transport.decrypt_record(&record).expect("decrypt"),
            b"opaque application bytes"
        );
    }

    #[test]
    fn wrong_server_key_and_unknown_client_fail_closed() {
        let (client_private, client_public) = static_keypair();
        let (server_private, _server_public) = static_keypair();
        let (_wrong_private, wrong_server_public) = static_keypair();
        let (_other_private, other_client_public) = static_keypair();

        let mut client = ClientHandshake::new(client_private, wrong_server_public).expect("client");
        let mut server = ServerHandshake::new(server_private, [client_public]).expect("server");
        server
            .accept_preface(&Preface::V1.encode())
            .expect("preface accepted");
        let first = client.first_message().expect("first message");
        assert!(matches!(
            server.receive_client(&first),
            Err(TunnelError::Noise(_))
        ));
        assert!(matches!(
            server.receive_client(&first),
            Err(TunnelError::ClosedSession)
        ));

        let (server_private, server_public) = static_keypair();
        let mut unauthorised_client =
            ClientHandshake::new(client_private, server_public).expect("client");
        let mut restrictive_server =
            ServerHandshake::new(server_private, [other_client_public]).expect("server");
        restrictive_server
            .accept_preface(&Preface::V1.encode())
            .expect("preface accepted");
        let first = unauthorised_client.first_message().expect("first message");
        assert!(matches!(
            restrictive_server.receive_client(&first),
            Err(TunnelError::UnauthorisedClient)
        ));
    }

    #[test]
    fn server_static_key_overlap_accepts_current_and_rotated_keys_only() {
        let (client_private, client_public) = static_keypair();
        let (current_private, current_public) = static_keypair();
        let (rotated_private, rotated_public) = static_keypair();
        let (_unknown_private, unknown_public) = static_keypair();

        for (pinned_server, label) in [(current_public, "current"), (rotated_public, "rotated")] {
            let mut client = ClientHandshake::new(client_private, pinned_server).expect(label);
            let mut server = ServerHandshake::new_with_static_identities(
                [current_private, rotated_private],
                [client_public],
            )
            .expect("bounded overlap");
            server
                .accept_preface(&Preface::V1.encode())
                .expect("preface accepted");
            let first = client.first_message().expect("first message");
            let mut reply = server.receive_client(&first).expect(label);
            let second = reply.message().expect("server response");
            let _client_transport = client.finish(&second).expect(label);
            let _server_transport = reply.into_session().expect(label);
        }

        let mut client = ClientHandshake::new(client_private, unknown_public).expect("client");
        let mut server = ServerHandshake::new_with_static_identities(
            [current_private, rotated_private],
            [client_public],
        )
        .expect("bounded overlap");
        server
            .accept_preface(&Preface::V1.encode())
            .expect("preface accepted");
        let first = client.first_message().expect("first message");
        assert!(matches!(
            server.receive_client(&first),
            Err(TunnelError::Noise(_))
        ));
    }

    #[test]
    fn server_static_key_overlap_is_non_empty_and_bounded() {
        let (_client_private, client_public) = static_keypair();
        assert!(matches!(
            ServerHandshake::new_with_static_identities([], [client_public]),
            Err(TunnelError::MissingServerStaticIdentity)
        ));
        let identities = std::iter::repeat_n([7; 32], MAX_SERVER_STATIC_IDENTITIES + 1);
        assert!(matches!(
            ServerHandshake::new_with_static_identities(identities, [client_public]),
            Err(TunnelError::TooManyServerStaticIdentities(count))
                if count == MAX_SERVER_STATIC_IDENTITIES + 1
        ));
    }

    #[test]
    fn records_enforce_wire_limits_and_reject_tampering() {
        let (client_private, client_public) = static_keypair();
        let (server_private, server_public) = static_keypair();
        let (mut client_transport, mut server_transport) =
            complete_handshake(client_private, client_public, server_private, server_public);

        assert!(matches!(
            client_transport.encrypt_record(&vec![0; MAX_PLAINTEXT_RECORD + 1]),
            Err(TunnelError::PlaintextTooLarge(16385))
        ));
        assert!(matches!(
            server_transport.decrypt_record(&[0, 0, 0x40, 0x11]),
            Err(TunnelError::CiphertextTooLarge(16401))
        ));

        let mut record = client_transport
            .encrypt_record(b"integrity")
            .expect("encrypt");
        *record.last_mut().expect("ciphertext") ^= 1;
        assert!(matches!(
            server_transport.decrypt_record(&record),
            Err(TunnelError::Noise(_))
        ));
        let later_record = client_transport
            .encrypt_record(b"must not continue after authentication failure")
            .expect("client can produce a later record");
        assert!(matches!(
            server_transport.decrypt_record(&later_record),
            Err(TunnelError::ClosedSession)
        ));
    }

    #[test]
    fn record_parser_rejects_truncation_and_trailing_bytes() {
        assert!(matches!(
            decode_record_frame(&[0, 0, 0, 16]),
            Err(TunnelError::TruncatedFrame {
                expected: 20,
                actual: 4
            })
        ));
        assert!(matches!(
            decode_record_frame(&[0, 0, 0, 1, 7, 8]),
            Err(TunnelError::TrailingFrameBytes)
        ));
    }

    #[test]
    fn split_transport_supports_independent_async_relay_directions() {
        let (client_private, client_public) = static_keypair();
        let (server_private, server_public) = static_keypair();
        let (client, server) =
            complete_handshake(client_private, client_public, server_private, server_public);
        let (client_sender, client_receiver) = client.split();
        let (server_sender, server_receiver) = server.split();

        let outbound = client_sender
            .encrypt_record(b"client-to-server")
            .expect("seal");
        assert_eq!(
            server_receiver.decrypt_record(&outbound).expect("open"),
            b"client-to-server"
        );
        let inbound = server_sender
            .encrypt_record(b"server-to-client")
            .expect("seal");
        assert_eq!(
            client_receiver.decrypt_record(&inbound).expect("open"),
            b"server-to-client"
        );
    }

    #[test]
    fn generated_identity_is_a_usable_32_byte_x25519_keypair() {
        let identity = generate_keypair().expect("key generation");
        assert_ne!(identity.private_key(), identity.public_key());
        assert_eq!(identity.private_key().len(), 32);
        assert_eq!(identity.public_key().len(), 32);
    }

    #[test]
    fn static_keypair_debug_never_exposes_private_key_material() {
        let identity = generate_keypair().expect("key generation");
        let private_debug = format!("{:?}", identity.private_key());
        let debug = format!("{identity:?}");
        assert!(!debug.contains(&private_debug));
        assert!(debug.contains("private: \"[REDACTED]\""));
    }

    fn complete_handshake(
        client_private: [u8; 32],
        client_public: [u8; 32],
        server_private: [u8; 32],
        server_public: [u8; 32],
    ) -> (TransportSession, TransportSession) {
        let mut client = ClientHandshake::new(client_private, server_public).expect("client");
        let mut server = ServerHandshake::new(server_private, [client_public]).expect("server");
        server
            .accept_preface(&Preface::V1.encode())
            .expect("preface");
        let first = client.first_message().expect("first");
        let mut reply = server
            .receive_client(&first)
            .expect("server receives first");
        let second = reply.message().expect("second");
        let client_transport = client.finish(&second).expect("client finishes");
        let server_transport = reply.into_session().expect("server finishes");
        (client_transport, server_transport)
    }
}
