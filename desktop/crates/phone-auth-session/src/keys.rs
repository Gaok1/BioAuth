//! Key schedule, session binding and the pairing verification code.
//!
//! Both ends of a handshake run exactly this code. That is the point of the
//! module: the previous shape had the server derive its keys in `finish` while
//! the client's half existed only inside a test, computed by hand from slice
//! indices. Two hand-written copies of a key schedule diverge, and when they
//! do the failure is a decryption error with no obvious cause.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::SessionError;

/// Length of every key and of the session binding.
pub const KEY_LEN: usize = 32;

const KDF_DOMAIN: &[u8] = b"PhoneAuth/secure-session/v1";
const BINDING_DOMAIN: &[u8] = b"PhoneAuth/session-binding/v1";
const VERIFICATION_DOMAIN: &[u8] = b"PhoneAuth/pairing-verification/v1";

/// Number of digits in the pairing verification code.
pub const VERIFICATION_CODE_DIGITS: u32 = 6;

/// Everything derived from one completed handshake.
///
/// Directions are named rather than positional. A caller cannot pick the wrong
/// half without writing the wrong field name.
pub struct KeySchedule {
    pub client_to_server: [u8; KEY_LEN],
    pub server_to_client: [u8; KEY_LEN],
    /// Secret output bound into the session binding and the verification code.
    /// Never sent, and never used to encrypt anything.
    pub exporter: [u8; KEY_LEN],
}

impl KeySchedule {
    /// Expands the X25519 shared secret, salted with the handshake transcript.
    ///
    /// Salting with the transcript is what ties the keys to the exact messages
    /// exchanged: an attacker who replays a recorded handshake against a fresh
    /// nonce gets a different transcript and therefore different keys.
    pub fn derive(shared_secret: &[u8], transcript_hash: &[u8; 32]) -> Result<Self, SessionError> {
        let mut material = [0u8; KEY_LEN * 3];
        Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret)
            .expand(KDF_DOMAIN, &mut material)
            .map_err(|_| SessionError::Kdf)?;

        let schedule = Self {
            client_to_server: split(&material, 0),
            server_to_client: split(&material, 1),
            exporter: split(&material, 2),
        };
        material.fill(0);
        Ok(schedule)
    }
}

fn split(material: &[u8], index: usize) -> [u8; KEY_LEN] {
    material[index * KEY_LEN..(index + 1) * KEY_LEN]
        .try_into()
        .expect("fixed key length")
}

/// Inputs both peers must agree on to derive the same session binding.
#[derive(Debug, Clone, Copy)]
pub struct SessionBindingInputs<'a> {
    pub transport_name: &'a str,
    pub session_id: &'a str,
    /// The verifier's ephemeral X25519 public key.
    pub server_ephemeral: &'a [u8],
    /// The authenticator's ephemeral X25519 public key.
    pub client_ephemeral: &'a [u8],
    /// [`KeySchedule::exporter`].
    pub exporter: &'a [u8],
}

/// Derives the 32-byte session binding that goes inside the signed request.
///
/// Every field is length-prefixed. Plain concatenation would let a transport
/// name ending in digits and a session id starting with them hash the same as
/// a different split of the same characters.
///
/// The exporter is what makes this unforgeable: an observer who saw the whole
/// handshake still cannot compute a valid binding, because it never went on
/// the wire.
pub fn session_binding(inputs: &SessionBindingInputs<'_>) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    for field in [
        inputs.transport_name.as_bytes(),
        inputs.session_id.as_bytes(),
        inputs.server_ephemeral,
        inputs.client_ephemeral,
        inputs.exporter,
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Six digits both ends derive from the same handshake.
///
/// Shown on the desktop and on the phone during pairing so the user can
/// confirm they match. The QR already authenticates the desktop to the phone;
/// this closes the other direction, where someone who photographed the QR
/// races to pair their own device. A relay sitting between the two ends
/// produces a different transcript on each side, so the codes differ.
pub fn verification_code(exporter: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(VERIFICATION_DOMAIN);
    hasher.update(exporter);
    let digest = hasher.finalize();

    let value = u32::from_be_bytes(digest[..4].try_into().expect("four bytes"));
    let modulus = 10u32.pow(VERIFICATION_CODE_DIGITS);
    format!(
        "{:0width$}",
        value % modulus,
        width = VERIFICATION_CODE_DIGITS as usize
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule() -> KeySchedule {
        KeySchedule::derive(&[1; 32], &[2; 32]).expect("derive")
    }

    #[test]
    fn the_three_outputs_are_distinct() {
        // A slicing mistake that handed the same bytes to both directions
        // would silently make the channel decrypt its own traffic.
        let schedule = schedule();
        assert_ne!(schedule.client_to_server, schedule.server_to_client);
        assert_ne!(schedule.client_to_server, schedule.exporter);
        assert_ne!(schedule.server_to_client, schedule.exporter);
    }

    #[test]
    fn derivation_is_deterministic() {
        let first = schedule();
        let second = schedule();
        assert_eq!(first.client_to_server, second.client_to_server);
        assert_eq!(first.server_to_client, second.server_to_client);
        assert_eq!(first.exporter, second.exporter);
    }

    #[test]
    fn a_different_transcript_gives_different_keys() {
        let base = KeySchedule::derive(&[1; 32], &[2; 32]).expect("derive");
        let other = KeySchedule::derive(&[1; 32], &[3; 32]).expect("derive");
        assert_ne!(base.client_to_server, other.client_to_server);
        assert_ne!(base.exporter, other.exporter);
    }

    #[test]
    fn a_different_shared_secret_gives_different_keys() {
        let base = KeySchedule::derive(&[1; 32], &[2; 32]).expect("derive");
        let other = KeySchedule::derive(&[9; 32], &[2; 32]).expect("derive");
        assert_ne!(base.client_to_server, other.client_to_server);
    }

    fn inputs<'a>(transport: &'a str, session: &'a str) -> SessionBindingInputs<'a> {
        SessionBindingInputs {
            transport_name: transport,
            session_id: session,
            server_ephemeral: &[1; 32],
            client_ephemeral: &[2; 32],
            exporter: &[3; 32],
        }
    }

    #[test]
    fn binding_is_deterministic() {
        assert_eq!(
            session_binding(&inputs("loopback", "s-1")),
            session_binding(&inputs("loopback", "s-1"))
        );
    }

    #[test]
    fn binding_changes_with_every_input() {
        let base = session_binding(&inputs("loopback", "s-1"));
        assert_ne!(base, session_binding(&inputs("loopback", "s-2")));
        assert_ne!(base, session_binding(&inputs("ble", "s-1")));

        let mut exporter = inputs("loopback", "s-1");
        exporter.exporter = &[4; 32];
        assert_ne!(base, session_binding(&exporter));

        let mut peer = inputs("loopback", "s-1");
        peer.client_ephemeral = &[9; 32];
        assert_ne!(base, session_binding(&peer));

        let mut server = inputs("loopback", "s-1");
        server.server_ephemeral = &[9; 32];
        assert_ne!(base, session_binding(&server));
    }

    #[test]
    fn length_prefixes_prevent_field_boundary_collisions() {
        // "ble" + "12" and "ble1" + "2" would collide under plain concatenation.
        assert_ne!(
            session_binding(&inputs("ble", "12")),
            session_binding(&inputs("ble1", "2"))
        );
    }

    #[test]
    fn verification_codes_are_six_digits() {
        for seed in 0u8..64 {
            let code = verification_code(&[seed; 32]);
            assert_eq!(code.len(), 6, "code `{code}` for seed {seed}");
            assert!(code.chars().all(|c| c.is_ascii_digit()), "code `{code}`");
        }
    }

    #[test]
    fn verification_codes_differ_between_sessions() {
        assert_ne!(verification_code(&[1; 32]), verification_code(&[2; 32]));
    }

    #[test]
    fn verification_codes_keep_leading_zeroes() {
        // Formatting the number without padding would produce a code the two
        // screens render differently, e.g. "42" against "000042".
        let padded = (0u8..=255)
            .map(|seed| verification_code(&[seed; 32]))
            .find(|code| code.starts_with('0'));
        assert!(
            padded.is_some_and(|code| code.len() == 6),
            "expected at least one code with a leading zero, all six digits"
        );
    }
}
