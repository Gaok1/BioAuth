//! The two-message handshake.
//!
//! ```text
//!   verifier (server)                        authenticator (client)
//!         │                                            │
//!         │  QR: session id, nonce, SHA-256(identity)  │
//!         │ ─────────────  out of band  ──────────────▶│
//!         │                                            │
//!         │  ServerHello: bootstrap, identity, ephem.  │
//!         │  ────────────  signed  ───────────────────▶│  checks the hash
//!         │                                            │  from the QR
//!         │  ClientHello: echo, device id, identity,   │
//!         │◀──────────  ephemeral, signed  ───────────│
//!         │                                            │
//!      X25519 ─▶ HKDF(salt = transcript) ─▶ keys, exporter
//! ```
//!
//! Signed ephemeral Diffie-Hellman with a transcript-bound key schedule. The
//! signatures authenticate; the ephemerals provide forward secrecy; salting
//! the KDF with the transcript ties the keys to the exact bytes exchanged.
//!
//! Each side signs a message that names the other side's contribution, so
//! neither signature can be lifted into a different handshake.

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use phone_auth_protocol::cbor::{Reader, Writer};

use crate::bootstrap::ServerBootstrap;
use crate::channel::{Role, SecureChannel};
use crate::identity::{hash_identity, verify, IdentityKey};
use crate::keys::{session_binding, verification_code, KeySchedule, SessionBindingInputs};
use crate::{SessionError, MAX_HANDSHAKE_FRAME, VERSION};

const SERVER_HELLO: u64 = 16;
const CLIENT_HELLO: u64 = 17;

/// Who the verifier will accept at the other end.
#[derive(Debug, Clone, Copy)]
pub enum PeerExpectation<'a> {
    /// Already paired: only this exact device and key are acceptable.
    Paired {
        device_id: &'a str,
        identity_spki: &'a [u8],
    },
    /// First contact: accept whichever identity is presented and report it, so
    /// the caller can have the user confirm it out of band before storing it.
    ///
    /// A session established this way authenticates nothing on its own. The
    /// caller must treat it as a proposal, not as a trusted peer.
    Pairing,
}

/// Who the authenticator will accept as the verifier.
#[derive(Debug, Clone, Copy)]
pub enum VerifierExpectation<'a> {
    /// Already paired. The hello carries its own session id, nonce and
    /// deadline, and they are trustworthy because the stored key signed them;
    /// there is no scanned code to compare against, because the phone did not
    /// scan anything to reach an already-paired desktop.
    Paired { identity_spki: &'a [u8] },
    /// First contact. The hello must match this scanned code exactly, and the
    /// key it presents must match the code's commitment. Nothing else vouches
    /// for the verifier at this point.
    Scanned { bootstrap: &'a ServerBootstrap },
}

/// A completed handshake.
pub struct HandshakeOutcome {
    pub channel: SecureChannel,
    /// The identity the peer presented. Under [`PeerExpectation::Paired`] this
    /// equals what was expected; under `Pairing` it is new information.
    pub peer_identity_spki: Vec<u8>,
    pub peer_device_id: String,
    /// Six digits both ends derive. Shown on both screens during pairing.
    pub verification_code: String,
    /// True when the peer was accepted without a prior pairing record.
    pub was_pairing: bool,
}

/// The verifier's side, between sending its hello and receiving the answer.
pub struct PendingServerHandshake {
    bootstrap: ServerBootstrap,
    secret: StaticSecret,
    public: [u8; 32],
    server_unsigned: Vec<u8>,
}

impl PendingServerHandshake {
    /// Builds the server hello. Returns the frame to send.
    pub fn begin(
        bootstrap: ServerBootstrap,
        identity: &IdentityKey,
    ) -> Result<(Self, Vec<u8>), SessionError> {
        bootstrap.validate()?;
        let identity_spki = identity.public_key_spki()?;

        // The bootstrap the phone scanned commits to a key. Publishing a hello
        // signed by a different one would be undiagnosable on the phone, which
        // can only report "signature did not match".
        if bootstrap.verifier_identity_hash != hash_identity(&identity_spki) {
            return Err(SessionError::InvalidBootstrap(
                "bootstrap does not commit to this identity key",
            ));
        }

        let secret = ephemeral_secret();
        let public = X25519PublicKey::from(&secret).to_bytes();
        let server_unsigned = encode_server_hello(&bootstrap, &identity_spki, &public);
        let hello = envelope(&server_unsigned, &identity.sign(&server_unsigned));

        Ok((
            Self {
                bootstrap,
                secret,
                public,
                server_unsigned,
            },
            hello,
        ))
    }

    pub fn ephemeral_public_key(&self) -> [u8; 32] {
        self.public
    }

    pub fn bootstrap(&self) -> &ServerBootstrap {
        &self.bootstrap
    }

    /// Checks the client hello and derives the channel.
    pub fn finish(
        self,
        client_frame: &[u8],
        expectation: PeerExpectation<'_>,
        transport_name: &str,
    ) -> Result<HandshakeOutcome, SessionError> {
        let (client_unsigned, signature) = decode_envelope(client_frame)?;
        let client = decode_client_hello(client_unsigned)?;

        // The client must echo this handshake's bootstrap and this server's
        // ephemeral key. Without the echo, a hello captured from one session
        // could be presented in another.
        if client.session_id != self.bootstrap.session_id
            || client.verifier_id != self.bootstrap.verifier_id
            || client.nonce != self.bootstrap.nonce
            || client.expires_at_ms != self.bootstrap.expires_at_ms
            || client.server_ephemeral != self.public
        {
            return Err(SessionError::PeerMismatch);
        }

        let was_pairing = match expectation {
            PeerExpectation::Paired {
                device_id,
                identity_spki,
            } => {
                if client.device_id != device_id || client.identity_spki != identity_spki {
                    return Err(SessionError::PeerMismatch);
                }
                false
            }
            PeerExpectation::Pairing => true,
        };

        // Always verify against the key the client actually presented. Under
        // `Paired` that key was just checked to be the stored one; under
        // `Pairing` this proves possession of whatever key it claims, which is
        // what the verification code then binds to a human.
        verify(client.identity_spki, client_unsigned, signature)?;

        let shared = self
            .secret
            .diffie_hellman(&X25519PublicKey::from(client.ephemeral));
        let transcript = transcript_hash(&self.server_unsigned, client_unsigned);
        let schedule = KeySchedule::derive(shared.as_bytes(), &transcript)?;

        let binding = session_binding(&SessionBindingInputs {
            transport_name,
            session_id: &self.bootstrap.session_id,
            server_ephemeral: &self.public,
            client_ephemeral: &client.ephemeral,
            exporter: &schedule.exporter,
        });

        Ok(HandshakeOutcome {
            channel: SecureChannel::new(Role::Server, &schedule, binding),
            peer_identity_spki: client.identity_spki.to_vec(),
            peer_device_id: client.device_id.to_owned(),
            verification_code: verification_code(&schedule.exporter),
            was_pairing,
        })
    }
}

/// The authenticator's side: one call, because it answers and finishes at once.
pub struct ClientHandshake;

impl ClientHandshake {
    /// Answers a server hello.
    ///
    /// Returns the frame to send back and the established channel. The channel
    /// is usable immediately; the server's half completes when it receives the
    /// frame.
    pub fn respond(
        server_frame: &[u8],
        expectation: VerifierExpectation<'_>,
        device_id: &str,
        identity: &IdentityKey,
        transport_name: &str,
        now_ms: i64,
    ) -> Result<(Vec<u8>, HandshakeOutcome), SessionError> {
        if device_id.is_empty() || device_id.len() > 64 {
            return Err(SessionError::InvalidFrame("invalid device identifier"));
        }

        let (server_unsigned, signature) = decode_envelope(server_frame)?;
        let server = decode_server_hello(server_unsigned)?;

        // Authenticate the verifier before deriving anything with its key.
        let was_pairing = match expectation {
            VerifierExpectation::Paired { identity_spki } => {
                if server.identity_spki != identity_spki {
                    return Err(SessionError::PeerMismatch);
                }
                false
            }
            VerifierExpectation::Scanned { bootstrap } => {
                bootstrap.validate()?;
                if server.session_id != bootstrap.session_id
                    || server.verifier_id != bootstrap.verifier_id
                    || server.nonce != bootstrap.nonce
                    || server.expires_at_ms != bootstrap.expires_at_ms
                {
                    return Err(SessionError::PeerMismatch);
                }
                // The scanned code is the only thing vouching for this key.
                if hash_identity(server.identity_spki) != bootstrap.verifier_identity_hash {
                    return Err(SessionError::VerifierIdentityMismatch);
                }
                true
            }
        };

        // The deadline is inside the signed hello either way, so a stale
        // session is refused whether or not a code was scanned.
        if now_ms >= server.expires_at_ms {
            return Err(SessionError::BootstrapExpired);
        }
        verify(server.identity_spki, server_unsigned, signature)?;

        let secret = ephemeral_secret();
        let public = X25519PublicKey::from(&secret).to_bytes();
        let identity_spki = identity.public_key_spki()?;
        let client_unsigned = encode_client_hello(
            server.session_id,
            &server.nonce,
            server.verifier_id,
            server.expires_at_ms,
            device_id,
            &server.ephemeral,
            &public,
            &identity_spki,
        );
        let client_frame = envelope(&client_unsigned, &identity.sign(&client_unsigned));

        let shared = secret.diffie_hellman(&X25519PublicKey::from(server.ephemeral));
        let transcript = transcript_hash(server_unsigned, &client_unsigned);
        let schedule = KeySchedule::derive(shared.as_bytes(), &transcript)?;

        let binding = session_binding(&SessionBindingInputs {
            transport_name,
            session_id: server.session_id,
            server_ephemeral: &server.ephemeral,
            client_ephemeral: &public,
            exporter: &schedule.exporter,
        });

        Ok((
            client_frame,
            HandshakeOutcome {
                channel: SecureChannel::new(Role::Client, &schedule, binding),
                peer_identity_spki: server.identity_spki.to_vec(),
                peer_device_id: server.verifier_id.to_owned(),
                verification_code: verification_code(&schedule.exporter),
                was_pairing,
            },
        ))
    }
}

fn ephemeral_secret() -> StaticSecret {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("operating system CSPRNG is unavailable");
    let secret = StaticSecret::from(bytes);
    bytes.fill(0);
    secret
}

struct ServerHello<'a> {
    session_id: &'a str,
    nonce: [u8; 32],
    verifier_id: &'a str,
    expires_at_ms: i64,
    identity_spki: &'a [u8],
    ephemeral: [u8; 32],
}

struct ClientHello<'a> {
    session_id: &'a str,
    nonce: [u8; 32],
    verifier_id: &'a str,
    expires_at_ms: i64,
    device_id: &'a str,
    server_ephemeral: [u8; 32],
    ephemeral: [u8; 32],
    identity_spki: &'a [u8],
}

fn encode_server_hello(
    bootstrap: &ServerBootstrap,
    identity_spki: &[u8],
    ephemeral: &[u8; 32],
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.array(8);
    writer.uint(SERVER_HELLO);
    writer.uint(VERSION);
    writer.text(&bootstrap.session_id);
    writer.bytes(&bootstrap.nonce);
    writer.text(&bootstrap.verifier_id);
    // Signing the deadline means a captured hello cannot be re-offered later
    // with a longer one.
    writer.int(bootstrap.expires_at_ms);
    writer.bytes(identity_spki);
    writer.bytes(ephemeral);
    writer.into_bytes()
}

fn decode_server_hello(frame: &[u8]) -> Result<ServerHello<'_>, SessionError> {
    let mut reader = Reader::new(frame);
    if reader.array()? != 8 || reader.uint()? != SERVER_HELLO || reader.uint()? != VERSION {
        return Err(SessionError::InvalidFrame("invalid server hello"));
    }
    let hello = ServerHello {
        session_id: reader.text()?,
        nonce: fixed(reader.bytes()?, "invalid nonce")?,
        verifier_id: reader.text()?,
        expires_at_ms: reader.int()?,
        identity_spki: reader.bytes()?,
        ephemeral: fixed(reader.bytes()?, "invalid verifier ephemeral key")?,
    };
    reader.finish()?;
    Ok(hello)
}

#[allow(clippy::too_many_arguments)]
fn encode_client_hello(
    session_id: &str,
    nonce: &[u8; 32],
    verifier_id: &str,
    expires_at_ms: i64,
    device_id: &str,
    server_ephemeral: &[u8; 32],
    ephemeral: &[u8; 32],
    identity_spki: &[u8],
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.array(10);
    writer.uint(CLIENT_HELLO);
    writer.uint(VERSION);
    writer.text(session_id);
    writer.bytes(nonce);
    writer.text(verifier_id);
    writer.int(expires_at_ms);
    writer.text(device_id);
    writer.bytes(server_ephemeral);
    writer.bytes(ephemeral);
    writer.bytes(identity_spki);
    writer.into_bytes()
}

fn decode_client_hello(frame: &[u8]) -> Result<ClientHello<'_>, SessionError> {
    let mut reader = Reader::new(frame);
    if reader.array()? != 10 || reader.uint()? != CLIENT_HELLO || reader.uint()? != VERSION {
        return Err(SessionError::InvalidFrame("invalid client hello"));
    }
    let hello = ClientHello {
        session_id: reader.text()?,
        nonce: fixed(reader.bytes()?, "invalid nonce")?,
        verifier_id: reader.text()?,
        expires_at_ms: reader.int()?,
        device_id: reader.text()?,
        server_ephemeral: fixed(reader.bytes()?, "invalid verifier ephemeral key")?,
        ephemeral: fixed(reader.bytes()?, "invalid client ephemeral key")?,
        identity_spki: reader.bytes()?,
    };
    reader.finish()?;
    Ok(hello)
}

fn envelope(unsigned: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.array(2);
    writer.bytes(unsigned);
    writer.bytes(signature);
    writer.into_bytes()
}

fn decode_envelope(frame: &[u8]) -> Result<(&[u8], &[u8]), SessionError> {
    if frame.is_empty() || frame.len() > MAX_HANDSHAKE_FRAME {
        return Err(SessionError::InvalidFrame("invalid handshake frame size"));
    }
    let mut reader = Reader::new(frame);
    if reader.array()? != 2 {
        return Err(SessionError::InvalidFrame("invalid handshake envelope"));
    }
    let unsigned = reader.bytes()?;
    let signature = reader.bytes()?;
    reader.finish()?;
    Ok((unsigned, signature))
}

fn fixed<const N: usize>(bytes: &[u8], message: &'static str) -> Result<[u8; N], SessionError> {
    bytes
        .try_into()
        .map_err(|_| SessionError::InvalidFrame(message))
}

/// Hashes both hello bodies, length-prefixed.
///
/// Signatures are excluded: ECDSA is randomised, so including them would make
/// the transcript depend on a value neither side can predict, without adding
/// anything — each body already covers the other side's contribution.
fn transcript_hash(server: &[u8], client: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"PhoneAuth/handshake-transcript/v1");
    for field in [server, client] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod wire_vectors {
    use super::*;

    // Produced by the same independent reference as
    // `tests/handshake_vectors.rs`. These pin the exact bytes each side signs
    // and hashes; a change to either encoding invalidates every signature and
    // every derived key.
    const SERVER_HELLO_HEX: &str = concat!(
        "8810016973657373696f6e2d31",
        "5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "696465736b746f702d31",
        "1b000001a03df1ec60",
        "585ba0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1",
        "e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa",
        "58201111111111111111111111111111111111111111111111111111111111111111",
    );

    const CLIENT_HELLO_HEX: &str = concat!(
        "8a11016973657373696f6e2d31",
        "5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "696465736b746f702d31",
        "1b000001a03df1ec60",
        "6770686f6e652d31",
        "58201111111111111111111111111111111111111111111111111111111111111111",
        "58202222222222222222222222222222222222222222222222222222222222222222",
        "585b505152535455565758595a5b5c5d5e5f60616263646566676869",
        "6a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687888",
        "98a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aa",
    );

    const TRANSCRIPT_HEX: &str =
        "76b72c40a881574d332adada02a0960e39c3236f4a14b6bd53c42c565e01860d";

    const SESSION_ID: &str = "session-1";
    const VERIFIER_ID: &str = "desktop-1";
    const DEVICE_ID: &str = "phone-1";
    const EXPIRES_AT_MS: i64 = 1_787_745_660_000;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn nonce() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    fn server_spki() -> Vec<u8> {
        (0..91).map(|i| (0xa0u16 + i) as u8).collect()
    }

    fn client_spki() -> Vec<u8> {
        (0..91).map(|i| (0x50u16 + i) as u8).collect()
    }

    fn bootstrap() -> ServerBootstrap {
        ServerBootstrap {
            session_id: SESSION_ID.into(),
            nonce: nonce(),
            verifier_id: VERIFIER_ID.into(),
            verifier_identity_hash: [0; 32],
            endpoint: String::new(),
            expires_at_ms: EXPIRES_AT_MS,
        }
    }

    #[test]
    fn the_server_hello_encoding_matches_the_reference() {
        let encoded = encode_server_hello(&bootstrap(), &server_spki(), &[0x11; 32]);
        assert_eq!(to_hex(&encoded), SERVER_HELLO_HEX);
    }

    #[test]
    fn the_client_hello_encoding_matches_the_reference() {
        let encoded = encode_client_hello(
            SESSION_ID,
            &nonce(),
            VERIFIER_ID,
            EXPIRES_AT_MS,
            DEVICE_ID,
            &[0x11; 32],
            &[0x22; 32],
            &client_spki(),
        );
        assert_eq!(to_hex(&encoded), CLIENT_HELLO_HEX);
    }

    #[test]
    fn the_transcript_hash_matches_the_reference() {
        let server = encode_server_hello(&bootstrap(), &server_spki(), &[0x11; 32]);
        let client = encode_client_hello(
            SESSION_ID,
            &nonce(),
            VERIFIER_ID,
            EXPIRES_AT_MS,
            DEVICE_ID,
            &[0x11; 32],
            &[0x22; 32],
            &client_spki(),
        );
        assert_eq!(to_hex(&transcript_hash(&server, &client)), TRANSCRIPT_HEX);
    }

    #[test]
    fn the_hellos_decode_back_to_what_was_encoded() {
        let encoded = encode_server_hello(&bootstrap(), &server_spki(), &[0x11; 32]);
        let decoded = decode_server_hello(&encoded).expect("decode");
        assert_eq!(decoded.session_id, SESSION_ID);
        assert_eq!(decoded.verifier_id, VERIFIER_ID);
        assert_eq!(decoded.expires_at_ms, EXPIRES_AT_MS);
        assert_eq!(decoded.identity_spki, server_spki());
        assert_eq!(decoded.ephemeral, [0x11; 32]);
        assert_eq!(decoded.nonce, nonce());
    }
}
