//! In-process fixtures: a session with no transport, and an authenticator with
//! no phone.
//!
//! # This is not an authenticator
//!
//! [`SoftwareAuthenticator`] holds a private key in ordinary process memory and
//! signs whatever it is handed. It exists to exercise the verifier's decision
//! path with real ECDSA, and it deliberately reports [`KeyKind::Software`] so
//! that the verifier's own boot-time gate refuses it. Nothing it produces is
//! evidence that a human was present.

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
use p256::pkcs8::EncodePublicKey;

use phone_auth_protocol::{
    AuthRequest, AuthResponse, Decision, ALGORITHM_ECDSA_P256_SHA256, PUBLIC_KEY_EC_P256_SPKI,
    SESSION_BINDING_LEN,
};

use crate::pairing::{CredentialPurpose, KeyKind, PairedCredential, PairedDevice};
use crate::policy::Permission;
use crate::session::{SecureSession, TransportSecurity};

/// Encodes a signing key's public half as X.509 SubjectPublicKeyInfo DER,
/// which is the shape Android's Keystore hands back and therefore the shape
/// the pairing store holds.
pub fn spki_der(signing_key: &SigningKey) -> Vec<u8> {
    p256::PublicKey::from(*signing_key.verifying_key())
        .to_public_key_der()
        .expect("encode SubjectPublicKeyInfo")
        .as_bytes()
        .to_vec()
}

/// A [`SecureSession`] that moves frames through in-memory queues.
///
/// Tests drive both directions by hand rather than wiring a fake peer, which
/// keeps it obvious what bytes each side actually saw.
#[derive(Debug)]
pub struct LoopbackSession {
    origin: String,
    binding: [u8; SESSION_BINDING_LEN],
    security: TransportSecurity,
    sent: Vec<Vec<u8>>,
    incoming: VecDeque<Vec<u8>>,
    closed: bool,
}

impl LoopbackSession {
    /// A session claiming the properties sensitive authorization requires.
    pub fn secure() -> Self {
        Self {
            origin: "Loopback • in-process test peer".into(),
            binding: [0x5a; SESSION_BINDING_LEN],
            security: TransportSecurity {
                transport_name: "LoopbackTransport".into(),
                confidential: true,
                peer_authenticated: true,
                requires_network: false,
                proximity_signal: false,
                is_development: true,
            },
            sent: Vec::new(),
            incoming: VecDeque::new(),
            closed: false,
        }
    }

    /// A session that reports itself as a production transport.
    ///
    /// Only for exercising code paths gated on `is_development`, such as
    /// boot-time unlock. It is still a loopback queue with no real handshake.
    pub fn posing_as_production() -> Self {
        let mut session = Self::secure();
        session.security.is_development = false;
        session.security.transport_name = "LoopbackTransport(posing as production)".into();
        session
    }

    /// A session that has not authenticated its peer, used to prove the
    /// verifier refuses it.
    pub fn unauthenticated() -> Self {
        let mut session = Self::secure();
        session.security.peer_authenticated = false;
        session
    }

    /// A session that does not encrypt.
    pub fn cleartext() -> Self {
        let mut session = Self::secure();
        session.security.confidential = false;
        session
    }

    pub fn with_binding(mut self, binding: [u8; SESSION_BINDING_LEN]) -> Self {
        self.binding = binding;
        self
    }

    /// Frames the verifier wrote, oldest first.
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }

    /// The most recent frame the verifier wrote.
    pub fn last_sent(&self) -> Option<&Vec<u8>> {
        self.sent.last()
    }

    /// Queues a frame for the verifier to read.
    pub fn push_incoming(&mut self, frame: Vec<u8>) {
        self.incoming.push_back(frame);
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl SecureSession for LoopbackSession {
    fn origin_label(&self) -> &str {
        &self.origin
    }

    fn session_binding(&self) -> [u8; SESSION_BINDING_LEN] {
        self.binding
    }

    fn security(&self) -> &TransportSecurity {
        &self.security
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        self.sent.push(frame.to_vec());
        Ok(())
    }

    fn receive(&mut self, _timeout: Duration) -> io::Result<Vec<u8>> {
        self.incoming
            .pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "no frame queued"))
    }

    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }
}

/// How the fixture authenticator answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatorBehaviour {
    /// Sign the request as presented.
    Authorize,
    /// Answer with a denial and no proof, as a user tapping "deny" would.
    Decline,
    /// Sign a *different* request than the one received, modelling a phone
    /// that signs the wrong context.
    SignMismatchedRequest,
    /// Return a syntactically valid signature made by an unrelated key.
    SignWithForeignKey,
}

/// A stand-in authenticator backed by a software P-256 key.
///
/// See the module docs: this is a test fixture, not a credential.
#[derive(Debug)]
pub struct SoftwareAuthenticator {
    device_id: String,
    display_name: String,
    credential_id: String,
    signing_key: SigningKey,
    foreign_key: SigningKey,
    /// Handshake identity, deliberately not the authorization key.
    session_identity: SigningKey,
    public_key_der: Vec<u8>,
    session_identity_der: Vec<u8>,
    pub behaviour: AuthenticatorBehaviour,
}

impl SoftwareAuthenticator {
    /// Builds a deterministic authenticator. `seed` selects the key.
    pub fn new(device_id: &str, credential_id: &str, seed: u8) -> Self {
        let signing_key =
            SigningKey::from_bytes(&[seed.max(1); 32].into()).expect("valid P-256 scalar");
        let foreign_key = SigningKey::from_bytes(&[seed.wrapping_add(37).max(1); 32].into())
            .expect("valid P-256 scalar");
        // A third, unrelated key. The handshake identity and the authorization
        // credential are separate on a real phone — one lives in the app, the
        // other behind a biometric gate in the Keystore — so a fixture that
        // reused one key for both would hide any place that conflates them.
        let session_identity = SigningKey::from_bytes(&[seed.wrapping_add(97).max(1); 32].into())
            .expect("valid P-256 scalar");
        let public_key_der = spki_der(&signing_key);
        let session_identity_der = spki_der(&session_identity);

        Self {
            device_id: device_id.to_owned(),
            display_name: format!("Test phone {device_id}"),
            credential_id: credential_id.to_owned(),
            signing_key,
            foreign_key,
            session_identity,
            public_key_der,
            session_identity_der,
            behaviour: AuthenticatorBehaviour::Authorize,
        }
    }

    /// The handshake identity this authenticator presents, as P-256 SPKI.
    pub fn session_identity_spki(&self) -> &[u8] {
        &self.session_identity_der
    }

    /// The handshake identity's private half, for driving the client side of a
    /// secure-session handshake in tests.
    pub fn session_identity_key(&self) -> &SigningKey {
        &self.session_identity
    }

    pub fn with_behaviour(mut self, behaviour: AuthenticatorBehaviour) -> Self {
        self.behaviour = behaviour;
        self
    }

    /// The pairing record a verifier would store for this authenticator.
    ///
    /// Reports [`KeyKind::Software`] truthfully, so a verifier that asks for a
    /// disk-unlock credential will refuse it.
    pub fn pairing_record(&self, permissions: Vec<Permission>) -> PairedDevice {
        self.pairing_record_with(
            permissions,
            CredentialPurpose::Authorization,
            KeyKind::Software,
        )
    }

    /// A pairing record with an overridden purpose and key kind, for tests
    /// that need to reach past the boot-time gate.
    pub fn pairing_record_with(
        &self,
        permissions: Vec<Permission>,
        purpose: CredentialPurpose,
        key_kind: KeyKind,
    ) -> PairedDevice {
        PairedDevice {
            device_id: self.device_id.clone(),
            display_name: self.display_name.clone(),
            paired_at_ms: 1_787_745_600_000,
            session_identity_public_key: self.session_identity_der.clone(),
            credentials: vec![PairedCredential {
                credential_id: self.credential_id.clone(),
                algorithm: PUBLIC_KEY_EC_P256_SPKI.to_owned(),
                public_key: self.public_key_der.clone(),
                key_kind,
                purpose,
                permissions,
            }],
        }
    }

    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// Produces the response frame for a request frame.
    pub fn answer(&self, request_frame: &[u8]) -> Vec<u8> {
        let request = AuthRequest::decode(request_frame).expect("verifier sent a valid request");
        self.answer_request(&request)
    }

    fn answer_request(&self, request: &AuthRequest) -> Vec<u8> {
        let (decision, algorithm, signature) = match self.behaviour {
            AuthenticatorBehaviour::Decline => (Decision::Denied, String::new(), Vec::new()),
            AuthenticatorBehaviour::Authorize => (
                Decision::Authorized,
                ALGORITHM_ECDSA_P256_SHA256.to_owned(),
                self.sign(&self.signing_key, &request.signing_payload()),
            ),
            AuthenticatorBehaviour::SignMismatchedRequest => {
                let mut other = request.clone();
                other.action = format!("{}-tampered", other.action);
                (
                    Decision::Authorized,
                    ALGORITHM_ECDSA_P256_SHA256.to_owned(),
                    self.sign(&self.signing_key, &other.signing_payload()),
                )
            }
            AuthenticatorBehaviour::SignWithForeignKey => (
                Decision::Authorized,
                ALGORITHM_ECDSA_P256_SHA256.to_owned(),
                self.sign(&self.foreign_key, &request.signing_payload()),
            ),
        };

        AuthResponse {
            protocol_version: request.protocol_version,
            request_id: request.request_id.clone(),
            verifier_id: request.verifier_id.clone(),
            credential_id: request.credential_id.clone(),
            decision,
            algorithm,
            signature,
        }
        .encode()
    }

    fn sign(&self, key: &SigningKey, payload: &[u8]) -> Vec<u8> {
        let signature: DerSignature = key.sign(payload);
        signature.as_bytes().to_vec()
    }
}
