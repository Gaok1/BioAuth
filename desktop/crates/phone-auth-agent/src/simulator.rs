//! A stand-in phone, for developing the desktop while the mobile app is built.
//!
//! # Not a phone
//!
//! There is no biometric prompt here and no hardware key. It signs with
//! software keys held in this process's memory, and it approves whatever it is
//! asked. The verifier's own gates treat it accordingly: it enrols as
//! [`KeyKind::Software`], which is enough on its own to make a boot-time
//! unlock request fail.
//!
//! # Why it uses the real transport
//!
//! It connects over TCP, runs the real handshake, sends a real enrolment and
//! signs real requests. An in-process shortcut would have tested the verifier
//! against a fixture rather than against the wire, and would have left the
//! handshake, the framing and the record layer unexercised — which is exactly
//! where the desktop and the phone have to agree.
//!
//! It doubles as the reference the mobile implementation is written against;
//! `docs/protocol-handshake.md` describes what it does.
//!
//! Compiled only under the `dev-simulator` feature, and even then only started
//! by an explicit `--dev-simulator` flag.

use std::thread;
use std::time::Duration;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePublicKey;

use phone_auth_protocol::{
    AuthRequest, AuthResponse, CredentialPurpose, Decision, Enrolment, KeyKind,
    ALGORITHM_ECDSA_P256_SHA256, PUBLIC_KEY_EC_P256_SPKI,
};
use phone_auth_session::{IdentityKey, ServerBootstrap};

use crate::framing::{read_frame, write_frame};
use crate::qr_network::client;

pub const DEVICE_ID: &str = "dev-simulator-phone";
pub const DEVICE_NAME: &str = "Simulated phone (development)";
pub const CREDENTIAL_ID: &str = "dev-simulator-authorization-v1";

/// A software phone.
pub struct SimulatedPhone {
    /// Signs authorization requests. On a real phone this sits behind a
    /// per-use biometric gate in the Keystore.
    credential: SigningKey,
    /// Authenticates handshakes. Separate key, as on a real phone.
    identity: IdentityKey,
}

impl SimulatedPhone {
    /// Builds a phone with a stable identity.
    ///
    /// Deterministic so that a pairing made in one run still works in the
    /// next; a phone that forgot its keys on every restart would make the
    /// desktop's pairing store impossible to exercise.
    pub fn new() -> Self {
        Self {
            credential: SigningKey::from_bytes(&[200u8; 32].into()).expect("valid P-256 scalar"),
            identity: IdentityKey::from_pkcs8_der(&identity_pkcs8()).expect("valid identity key"),
        }
    }

    fn credential_spki(&self) -> Vec<u8> {
        p256::PublicKey::from(*self.credential.verifying_key())
            .to_public_key_der()
            .expect("encode SubjectPublicKeyInfo")
            .as_bytes()
            .to_vec()
    }

    /// What this phone offers at pairing.
    pub fn enrolment(&self) -> Enrolment {
        Enrolment {
            protocol_version: phone_auth_protocol::PROTOCOL_VERSION,
            device_name: DEVICE_NAME.to_owned(),
            credential_id: CREDENTIAL_ID.to_owned(),
            algorithm: PUBLIC_KEY_EC_P256_SPKI.to_owned(),
            public_key: self.credential_spki(),
            // Truthful, and the reason this can never unlock a disk.
            key_kind: KeyKind::Software,
            purpose: CredentialPurpose::Authorization,
        }
    }

    pub fn identity_spki(&self) -> Vec<u8> {
        self.identity.public_key_spki().expect("spki")
    }

    /// Scans a code and pairs.
    pub fn pair(&self, bootstrap: &ServerBootstrap, now_ms: i64) -> Result<String, String> {
        let endpoint = dial(&bootstrap.endpoint);
        let (_, stream, code) = client::pair(
            &endpoint,
            bootstrap,
            DEVICE_ID,
            &self.identity,
            &self.enrolment(),
            now_ms,
        )?;
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(code)
    }

    /// Connects as a paired device and answers one authorization request.
    ///
    /// Real phones wait on a user; this answers immediately, which is exactly
    /// why it must never be mistaken for one.
    pub fn serve_once(
        &self,
        endpoint: &str,
        verifier_identity_spki: &[u8],
        now_ms: i64,
    ) -> Result<(), String> {
        let (mut channel, mut stream) = client::connect(
            &dial(endpoint),
            verifier_identity_spki,
            DEVICE_ID,
            &self.identity,
            now_ms,
        )?;

        stream
            .set_read_timeout(Some(Duration::from_secs(120)))
            .map_err(|error| error.to_string())?;

        let record = read_frame(&mut stream).map_err(|error| error.to_string())?;
        let frame = channel.open(&record).map_err(|error| error.to_string())?;
        let request = AuthRequest::decode(&frame).map_err(|error| error.to_string())?;

        let response = self.authorize(&request);
        let record = channel
            .seal(&response.encode())
            .map_err(|error| error.to_string())?;
        write_frame(&mut stream, &record).map_err(|error| error.to_string())?;

        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }

    /// Signs the canonical request, standing in for a biometric prompt.
    fn authorize(&self, request: &AuthRequest) -> AuthResponse {
        let signature: DerSignature = self.credential.sign(&request.signing_payload());
        AuthResponse {
            protocol_version: request.protocol_version,
            request_id: request.request_id.clone(),
            verifier_id: request.verifier_id.clone(),
            credential_id: request.credential_id.clone(),
            decision: Decision::Authorized,
            algorithm: ALGORITHM_ECDSA_P256_SHA256.to_owned(),
            signature: signature.as_bytes().to_vec(),
        }
    }

    /// Keeps a connection available so the verifier always has a session.
    ///
    /// A real phone connects when its user acts. This reconnects in a loop so
    /// that `phone-auth authorize` works without a human in the way.
    pub fn run_in_background(self, endpoint: String, verifier_identity_spki: Vec<u8>) {
        thread::spawn(move || loop {
            let now = phone_auth_verifier::verifier::now_ms();
            if let Err(error) = self.serve_once(&endpoint, &verifier_identity_spki, now) {
                // Nothing to authorize yet is the normal case, not a fault.
                if !error.contains("timed out") && !error.contains("os error") {
                    eprintln!("phone-auth-agent: simulator: {error}");
                }
                thread::sleep(Duration::from_millis(500));
            }
        });
    }
}

impl Default for SimulatedPhone {
    fn default() -> Self {
        Self::new()
    }
}

/// Rewrites a wildcard bind address into something connectable.
///
/// The agent advertises `0.0.0.0:<port>` because it does not know which
/// interface a phone will use. Connecting to that address is not meaningful,
/// so the simulator dials the loopback instead.
fn dial(endpoint: &str) -> String {
    match endpoint.rsplit_once(':') {
        Some((host, port)) if host.is_empty() || host == "0.0.0.0" => {
            format!("127.0.0.1:{port}")
        }
        _ => endpoint.to_owned(),
    }
}

/// A fixed PKCS#8 P-256 key, so the simulated phone keeps one identity.
fn identity_pkcs8() -> Vec<u8> {
    use p256::pkcs8::EncodePrivateKey;
    let secret = p256::SecretKey::from_bytes(&[177u8; 32].into()).expect("valid P-256 scalar");
    secret
        .to_pkcs8_der()
        .expect("encode PKCS#8")
        .as_bytes()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_simulated_phone_enrols_as_a_software_key() {
        let enrolment = SimulatedPhone::new().enrolment();
        assert_eq!(
            enrolment.key_kind,
            KeyKind::Software,
            "the simulator must never look hardware-backed"
        );
        assert_eq!(enrolment.purpose, CredentialPurpose::Authorization);
        assert_eq!(enrolment.validate(), Ok(()));
    }

    #[test]
    fn its_identity_is_stable_across_restarts() {
        assert_eq!(
            SimulatedPhone::new().identity_spki(),
            SimulatedPhone::new().identity_spki(),
            "a restart must not invalidate the simulated pairing"
        );
        assert_eq!(
            SimulatedPhone::new().enrolment().public_key,
            SimulatedPhone::new().enrolment().public_key
        );
    }

    #[test]
    fn the_handshake_key_is_not_the_credential_key() {
        // Conflating them on a real phone would mean a handshake, which needs
        // no user present, touched the key that approves logins.
        let phone = SimulatedPhone::new();
        assert_ne!(phone.identity_spki(), phone.enrolment().public_key);
    }

    #[test]
    fn a_wildcard_endpoint_is_dialled_on_the_loopback() {
        assert_eq!(dial("0.0.0.0:8765"), "127.0.0.1:8765");
        assert_eq!(dial(":8765"), "127.0.0.1:8765");
        assert_eq!(dial("192.168.1.10:8765"), "192.168.1.10:8765");
    }
}
