//! Authenticated secure sessions above an arbitrary reliable frame transport.
//!
//! Persistent identities use P-256 signatures for Android Keystore
//! interoperability. X25519 keys are ephemeral and traffic is protected with
//! HKDF-SHA256 plus ChaCha20-Poly1305. Bluetooth addresses and transport data
//! never participate in identity.
//!
//! # What a completed handshake means
//!
//! It gives a confidential, peer-authenticated channel and a session binding.
//! It establishes *which device* is on the other end. It says nothing about
//! whether a human approved anything: that comes later, from a biometric
//! signature over an authorization request, and this layer only carries those
//! bytes.
//!
//! # Relationship to the verifier
//!
//! This crate deliberately does not depend on `phone-auth-verifier`. The
//! verifier consumes the `SecureSession` trait, and an edge pointing this way
//! would make the abstraction depend on one of its implementations. The
//! adapter that joins them lives in the agent, which already has both.

pub mod bootstrap;
mod channel;
mod handshake;
mod identity;
pub mod keys;

pub use bootstrap::{ServerBootstrap, BOOTSTRAP_PREFIX, DEFAULT_LIFETIME_MS};
pub use channel::{Role, SecureChannel, MAX_FRAME};
pub use handshake::{
    ClientHandshake, HandshakeOutcome, PeerExpectation, PendingServerHandshake,
    VerifierExpectation,
};
pub use identity::{hash_identity, IdentityKey};
pub use keys::{session_binding, verification_code, SessionBindingInputs};

use phone_auth_protocol::cbor::CborError;

/// The only handshake version this build speaks.
pub const VERSION: u64 = 1;

/// Ceiling on a handshake frame. Larger than a protocol frame because a hello
/// carries a DER public key and a DER signature.
pub const MAX_HANDSHAKE_FRAME: usize = 8192;

#[derive(Debug)]
pub enum SessionError {
    InvalidBootstrap(&'static str),
    /// The hello, or the code it came from, is past its deadline.
    BootstrapExpired,
    InvalidFrame(&'static str),
    Cbor(CborError),
    /// A key would not parse, or could not be encoded.
    IdentityKey,
    /// A handshake signature did not verify.
    Signature,
    /// The peer is not the one this handshake was for.
    PeerMismatch,
    /// The verifier's key does not match the commitment in the scanned code.
    /// On first contact this is the signature of a machine-in-the-middle.
    VerifierIdentityMismatch,
    Kdf,
    Encrypt,
    /// A record failed authentication.
    Decrypt,
    /// A record arrived out of order, or twice.
    Replay,
    /// The record counter would wrap, which would reuse a nonce.
    CounterExhausted,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBootstrap(message) | Self::InvalidFrame(message) => f.write_str(message),
            Self::BootstrapExpired => f.write_str("the pairing code has expired"),
            Self::Cbor(error) => write!(f, "CBOR: {error}"),
            Self::IdentityKey => f.write_str("invalid P-256 identity key"),
            Self::Signature => f.write_str("invalid handshake signature"),
            Self::PeerMismatch => f.write_str("handshake peer does not match pairing"),
            Self::VerifierIdentityMismatch => {
                f.write_str("verifier key does not match the scanned code")
            }
            Self::Kdf => f.write_str("secure-session key derivation failed"),
            Self::Encrypt => f.write_str("secure-session record encryption failed"),
            Self::Decrypt => f.write_str("secure-session record authentication failed"),
            Self::Replay => f.write_str("replayed or out-of-order secure-session record"),
            Self::CounterExhausted => f.write_str("secure-session record counter exhausted"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<CborError> for SessionError {
    fn from(value: CborError) -> Self {
        Self::Cbor(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_787_745_600_000;
    const TRANSPORT: &str = "QrNetworkTransport";
    const DEVICE_ID: &str = "phone-1";
    const VERIFIER_ID: &str = "desktop-1";

    struct Parties {
        server_identity: IdentityKey,
        client_identity: IdentityKey,
        bootstrap: ServerBootstrap,
    }

    fn parties() -> Parties {
        let server_identity = IdentityKey::generate();
        let bootstrap = ServerBootstrap::new(
            "session-1",
            VERIFIER_ID,
            "127.0.0.1:8765",
            &server_identity,
            NOW,
            DEFAULT_LIFETIME_MS,
        )
        .expect("bootstrap");

        Parties {
            server_identity,
            client_identity: IdentityKey::generate(),
            bootstrap,
        }
    }

    /// Sends the server hello for a fresh handshake over `parties`' bootstrap.
    fn server_hello(parties: &Parties) -> (PendingServerHandshake, Vec<u8>) {
        PendingServerHandshake::begin(parties.bootstrap.clone(), &parties.server_identity)
            .expect("server hello")
    }

    /// Runs a full first-contact handshake and returns both outcomes.
    fn run_pairing(parties: &Parties) -> (HandshakeOutcome, HandshakeOutcome) {
        let (pending, hello) = server_hello(parties);

        let (client_frame, client_outcome) = ClientHandshake::respond(
            &hello,
            VerifierExpectation::Scanned {
                bootstrap: &parties.bootstrap,
            },
            DEVICE_ID,
            &parties.client_identity,
            TRANSPORT,
            NOW,
        )
        .expect("client responds");

        let server_outcome = pending
            .finish(&client_frame, PeerExpectation::Pairing, TRANSPORT)
            .expect("server finishes");

        (server_outcome, client_outcome)
    }

    #[test]
    fn a_pairing_handshake_agrees_on_everything_that_matters() {
        let parties = parties();
        let (mut server, mut client) = run_pairing(&parties);

        assert_eq!(
            server.channel.session_binding(),
            client.channel.session_binding(),
            "both ends must bind requests to the same session"
        );
        assert_eq!(
            server.verification_code, client.verification_code,
            "the user compares these on two screens"
        );
        assert!(server.was_pairing && client.was_pairing);

        let record = server.channel.seal(b"request").expect("seal");
        assert_eq!(client.channel.open(&record).expect("open"), b"request");
        let record = client.channel.seal(b"response").expect("seal");
        assert_eq!(server.channel.open(&record).expect("open"), b"response");
    }

    #[test]
    fn each_side_learns_the_others_identity() {
        let parties = parties();
        let (server, client) = run_pairing(&parties);

        assert_eq!(
            server.peer_identity_spki,
            parties.client_identity.public_key_spki().expect("spki"),
            "pairing must report the phone's key so it can be stored"
        );
        assert_eq!(server.peer_device_id, DEVICE_ID);
        assert_eq!(
            client.peer_identity_spki,
            parties.server_identity.public_key_spki().expect("spki")
        );
        assert_eq!(client.peer_device_id, VERIFIER_ID);
    }

    #[test]
    fn a_paired_handshake_needs_no_scanned_code() {
        // An already-paired phone never scans anything: it trusts the hello's
        // own session values because the stored key signed them.
        let parties = parties();
        let server_spki = parties.server_identity.public_key_spki().expect("spki");
        let client_spki = parties.client_identity.public_key_spki().expect("spki");

        let (pending, hello) = server_hello(&parties);
        let (client_frame, client) = ClientHandshake::respond(
            &hello,
            VerifierExpectation::Paired {
                identity_spki: &server_spki,
            },
            DEVICE_ID,
            &parties.client_identity,
            TRANSPORT,
            NOW,
        )
        .expect("client responds");

        let server = pending
            .finish(
                &client_frame,
                PeerExpectation::Paired {
                    device_id: DEVICE_ID,
                    identity_spki: &client_spki,
                },
                TRANSPORT,
            )
            .expect("server finishes");

        assert!(!server.was_pairing && !client.was_pairing);
        assert_eq!(
            server.channel.session_binding(),
            client.channel.session_binding()
        );
    }

    #[test]
    fn a_paired_phone_refuses_a_verifier_with_another_key() {
        let parties = parties();
        let stranger = IdentityKey::generate().public_key_spki().expect("spki");
        let (_, hello) = server_hello(&parties);

        assert!(matches!(
            ClientHandshake::respond(
                &hello,
                VerifierExpectation::Paired {
                    identity_spki: &stranger,
                },
                DEVICE_ID,
                &parties.client_identity,
                TRANSPORT,
                NOW,
            ),
            Err(SessionError::PeerMismatch)
        ));
    }

    #[test]
    fn an_unpaired_phone_is_refused_by_a_paired_verifier() {
        let parties = parties();
        let stranger = IdentityKey::generate().public_key_spki().expect("spki");

        let (pending, hello) = server_hello(&parties);
        let (client_frame, _) = ClientHandshake::respond(
            &hello,
            VerifierExpectation::Scanned {
                bootstrap: &parties.bootstrap,
            },
            DEVICE_ID,
            &parties.client_identity,
            TRANSPORT,
            NOW,
        )
        .expect("client responds");

        assert!(matches!(
            pending.finish(
                &client_frame,
                PeerExpectation::Paired {
                    device_id: DEVICE_ID,
                    identity_spki: &stranger,
                },
                TRANSPORT,
            ),
            Err(SessionError::PeerMismatch)
        ));
    }

    #[test]
    fn a_phone_using_another_devices_id_is_refused() {
        let parties = parties();
        let client_spki = parties.client_identity.public_key_spki().expect("spki");

        let (pending, hello) = server_hello(&parties);
        let (client_frame, _) = ClientHandshake::respond(
            &hello,
            VerifierExpectation::Scanned {
                bootstrap: &parties.bootstrap,
            },
            "some-other-phone",
            &parties.client_identity,
            TRANSPORT,
            NOW,
        )
        .expect("client responds");

        assert!(matches!(
            pending.finish(
                &client_frame,
                PeerExpectation::Paired {
                    device_id: DEVICE_ID,
                    identity_spki: &client_spki,
                },
                TRANSPORT,
            ),
            Err(SessionError::PeerMismatch)
        ));
    }

    #[test]
    fn a_machine_in_the_middle_cannot_complete_first_contact() {
        // The attacker relays, running their own verifier with their own key.
        // They publish a code committing to *their* key, but the phone checks
        // against the hash it scanned from the real screen.
        let parties = parties();
        let attacker = IdentityKey::generate();

        let mut attacker_bootstrap = parties.bootstrap.clone();
        attacker_bootstrap.verifier_identity_hash = attacker.public_key_hash().expect("hash");
        let (_, attacker_hello) =
            PendingServerHandshake::begin(attacker_bootstrap, &attacker).expect("attacker hello");

        assert!(
            matches!(
                ClientHandshake::respond(
                    &attacker_hello,
                    VerifierExpectation::Scanned {
                        bootstrap: &parties.bootstrap,
                    },
                    DEVICE_ID,
                    &parties.client_identity,
                    TRANSPORT,
                    NOW,
                ),
                Err(SessionError::VerifierIdentityMismatch)
            ),
            "a relay must not be able to complete first contact"
        );
    }

    #[test]
    fn a_verifier_cannot_publish_a_code_for_a_key_it_does_not_hold() {
        let parties = parties();
        let other = IdentityKey::generate();

        assert!(
            matches!(
                PendingServerHandshake::begin(parties.bootstrap.clone(), &other),
                Err(SessionError::InvalidBootstrap(_))
            ),
            "a hello signed by a key the code does not commit to is undiagnosable on the phone"
        );
    }

    #[test]
    fn an_expired_handshake_is_refused_by_the_phone() {
        let parties = parties();
        let (_, hello) = server_hello(&parties);

        assert!(matches!(
            ClientHandshake::respond(
                &hello,
                VerifierExpectation::Scanned {
                    bootstrap: &parties.bootstrap,
                },
                DEVICE_ID,
                &parties.client_identity,
                TRANSPORT,
                parties.bootstrap.expires_at_ms,
            ),
            Err(SessionError::BootstrapExpired)
        ));
    }

    #[test]
    fn the_deadline_is_enforced_for_paired_sessions_too() {
        // There is no scanned code here, so the only deadline is the signed
        // one inside the hello.
        let parties = parties();
        let server_spki = parties.server_identity.public_key_spki().expect("spki");
        let (_, hello) = server_hello(&parties);

        assert!(matches!(
            ClientHandshake::respond(
                &hello,
                VerifierExpectation::Paired {
                    identity_spki: &server_spki,
                },
                DEVICE_ID,
                &parties.client_identity,
                TRANSPORT,
                parties.bootstrap.expires_at_ms,
            ),
            Err(SessionError::BootstrapExpired)
        ));
    }

    #[test]
    fn a_hello_from_another_session_is_refused() {
        let first = parties();
        let second = parties();
        let (_, foreign_hello) = server_hello(&second);

        // The phone scanned `first`'s code but was handed `second`'s hello.
        assert!(matches!(
            ClientHandshake::respond(
                &foreign_hello,
                VerifierExpectation::Scanned {
                    bootstrap: &first.bootstrap,
                },
                DEVICE_ID,
                &first.client_identity,
                TRANSPORT,
                NOW,
            ),
            Err(SessionError::PeerMismatch | SessionError::VerifierIdentityMismatch)
        ));
    }

    #[test]
    fn a_client_hello_cannot_be_moved_between_handshakes() {
        let parties = parties();
        let (_, hello) = server_hello(&parties);
        let (client_frame, _) = ClientHandshake::respond(
            &hello,
            VerifierExpectation::Scanned {
                bootstrap: &parties.bootstrap,
            },
            DEVICE_ID,
            &parties.client_identity,
            TRANSPORT,
            NOW,
        )
        .expect("client responds");

        let (second, _) = server_hello(&parties);
        assert!(
            matches!(
                second.finish(&client_frame, PeerExpectation::Pairing, TRANSPORT),
                Err(SessionError::PeerMismatch)
            ),
            "each handshake has a fresh ephemeral key, so a captured hello cannot be reused"
        );
    }

    #[test]
    fn every_single_byte_mutation_of_a_client_hello_is_rejected() {
        let parties = parties();
        let (pending, hello) = server_hello(&parties);
        let (client_frame, _) = ClientHandshake::respond(
            &hello,
            VerifierExpectation::Scanned {
                bootstrap: &parties.bootstrap,
            },
            DEVICE_ID,
            &parties.client_identity,
            TRANSPORT,
            NOW,
        )
        .expect("client responds");

        // The untouched frame must still be accepted, so the loop below cannot
        // pass by rejecting everything.
        for index in 0..client_frame.len() {
            let mut mutated = client_frame.clone();
            mutated[index] ^= 0x01;

            let (fresh, _) = server_hello(&parties);
            assert!(
                fresh
                    .finish(&mutated, PeerExpectation::Pairing, TRANSPORT)
                    .is_err(),
                "byte {index} was accepted after mutation"
            );
        }

        assert!(pending
            .finish(&client_frame, PeerExpectation::Pairing, TRANSPORT)
            .is_ok());
    }

    #[test]
    fn every_single_byte_mutation_of_a_server_hello_is_rejected() {
        let parties = parties();
        let (_, hello) = server_hello(&parties);

        for index in 0..hello.len() {
            let mut mutated = hello.clone();
            mutated[index] ^= 0x01;

            assert!(
                ClientHandshake::respond(
                    &mutated,
                    VerifierExpectation::Scanned {
                        bootstrap: &parties.bootstrap,
                    },
                    DEVICE_ID,
                    &parties.client_identity,
                    TRANSPORT,
                    NOW,
                )
                .is_err(),
                "byte {index} of the server hello was accepted after mutation"
            );
        }
    }

    #[test]
    fn two_handshakes_over_one_code_produce_different_keys() {
        // Forward secrecy: the ephemerals are fresh even when the scanned code
        // is the same, so recording one session does not expose another.
        let parties = parties();
        let (first, _) = run_pairing(&parties);
        let (second, _) = run_pairing(&parties);

        assert_ne!(
            first.channel.session_binding(),
            second.channel.session_binding()
        );
        assert_ne!(first.verification_code, second.verification_code);
    }

    #[test]
    fn the_binding_depends_on_the_transport_name() {
        // The same peers over a different transport must not agree on a
        // binding, or a request could be replayed across the two.
        let parties = parties();
        let (pending, hello) = server_hello(&parties);
        let (client_frame, client) = ClientHandshake::respond(
            &hello,
            VerifierExpectation::Scanned {
                bootstrap: &parties.bootstrap,
            },
            DEVICE_ID,
            &parties.client_identity,
            "BleTransport",
            NOW,
        )
        .expect("client responds");

        let server = pending
            .finish(&client_frame, PeerExpectation::Pairing, "QrNetworkTransport")
            .expect("server finishes");

        assert_ne!(
            server.channel.session_binding(),
            client.channel.session_binding(),
            "a transport mismatch must not silently agree"
        );
    }

    #[test]
    fn oversized_and_empty_handshake_frames_are_refused() {
        let parties = parties();
        for frame in [Vec::new(), vec![0u8; MAX_HANDSHAKE_FRAME + 1]] {
            let (pending, _) = server_hello(&parties);
            assert!(matches!(
                pending.finish(&frame, PeerExpectation::Pairing, TRANSPORT),
                Err(SessionError::InvalidFrame(_))
            ));
        }
    }
}
