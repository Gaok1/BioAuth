//! Long-lived handshake identities.
//!
//! P-256 rather than Ed25519 so that a phone can hold the matching key in the
//! Android Keystore, which offers EC but not Ed25519.
//!
//! This is *not* the authorization credential. The authorization key lives
//! behind a per-use biometric gate and signs requests; this one authenticates
//! transport handshakes and is used without any user interaction. Keeping them
//! separate means a handshake, which happens whenever a phone comes into
//! range, never touches the key that approves a login.

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use sha2::{Digest, Sha256};

use crate::SessionError;

/// A handshake identity's private half.
///
/// Persist with [`IdentityKey::to_pkcs8_der`]. There is deliberately no
/// `Debug`, `Display` or `Clone`: the only way out is the explicit encoder, so
/// a private key cannot reach a log through a derived formatter.
pub struct IdentityKey(SigningKey);

impl IdentityKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        loop {
            getrandom::getrandom(&mut bytes).expect("operating system CSPRNG is unavailable");
            // Rejection sampling: a scalar of zero or one at or above the group
            // order is invalid, and retrying is the correct handling.
            if let Ok(key) = SigningKey::from_bytes((&bytes).into()) {
                bytes.fill(0);
                return Self(key);
            }
        }
    }

    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, SessionError> {
        p256::SecretKey::from_pkcs8_der(bytes)
            .map(SigningKey::from)
            .map(Self)
            .map_err(|_| SessionError::IdentityKey)
    }

    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, SessionError> {
        p256::SecretKey::from_bytes(&self.0.to_bytes())
            .map_err(|_| SessionError::IdentityKey)?
            .to_pkcs8_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| SessionError::IdentityKey)
    }

    /// The public half, as X.509 SubjectPublicKeyInfo DER.
    pub fn public_key_spki(&self) -> Result<Vec<u8>, SessionError> {
        p256::PublicKey::from(*self.0.verifying_key())
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| SessionError::IdentityKey)
    }

    /// SHA-256 of the SPKI: the short commitment a QR code can carry.
    pub fn public_key_hash(&self) -> Result<[u8; 32], SessionError> {
        Ok(hash_identity(&self.public_key_spki()?))
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: DerSignature = self.0.sign(message);
        signature.as_bytes().to_vec()
    }
}

/// Commits to an identity in 32 bytes.
pub fn hash_identity(spki: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"PhoneAuth/identity/v1");
    hasher.update(spki);
    hasher.finalize().into()
}

/// Checks a handshake signature against an SPKI public key.
pub(crate) fn verify(spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), SessionError> {
    let key = VerifyingKey::from_public_key_der(spki).map_err(|_| SessionError::IdentityKey)?;
    let signature = DerSignature::try_from(signature).map_err(|_| SessionError::Signature)?;
    key.verify(message, &signature)
        .map_err(|_| SessionError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_pkcs8() {
        let key = IdentityKey::generate();
        let encoded = key.to_pkcs8_der().expect("encode");
        let loaded = IdentityKey::from_pkcs8_der(&encoded).expect("decode");
        assert_eq!(
            key.public_key_spki().expect("spki"),
            loaded.public_key_spki().expect("spki")
        );
    }

    #[test]
    fn generated_keys_are_distinct() {
        let first = IdentityKey::generate().public_key_spki().expect("spki");
        let second = IdentityKey::generate().public_key_spki().expect("spki");
        assert_ne!(first, second);
    }

    #[test]
    fn signatures_verify_against_the_matching_key() {
        let key = IdentityKey::generate();
        let spki = key.public_key_spki().expect("spki");
        let signature = key.sign(b"handshake transcript");
        assert!(verify(&spki, b"handshake transcript", &signature).is_ok());
    }

    #[test]
    fn signatures_do_not_verify_against_another_key() {
        let key = IdentityKey::generate();
        let other = IdentityKey::generate().public_key_spki().expect("spki");
        let signature = key.sign(b"handshake transcript");
        assert!(matches!(
            verify(&other, b"handshake transcript", &signature),
            Err(SessionError::Signature)
        ));
    }

    #[test]
    fn signatures_do_not_verify_over_other_bytes() {
        let key = IdentityKey::generate();
        let spki = key.public_key_spki().expect("spki");
        let signature = key.sign(b"handshake transcript");
        assert!(matches!(
            verify(&spki, b"handshake transcripT", &signature),
            Err(SessionError::Signature)
        ));
    }

    #[test]
    fn a_malformed_key_is_refused() {
        assert!(matches!(
            verify(b"not a key", b"message", b"signature"),
            Err(SessionError::IdentityKey)
        ));
        assert!(matches!(
            IdentityKey::from_pkcs8_der(b"not a key"),
            Err(SessionError::IdentityKey)
        ));
    }

    #[test]
    fn the_identity_hash_commits_to_the_key() {
        let key = IdentityKey::generate();
        let spki = key.public_key_spki().expect("spki");
        assert_eq!(key.public_key_hash().expect("hash"), hash_identity(&spki));

        let other = IdentityKey::generate();
        assert_ne!(
            key.public_key_hash().expect("hash"),
            other.public_key_hash().expect("hash")
        );
    }

    #[test]
    fn the_identity_hash_is_domain_separated() {
        // A bare SHA-256 of the SPKI could be confused with a hash computed
        // for some other purpose over the same bytes.
        let key = IdentityKey::generate();
        let spki = key.public_key_spki().expect("spki");
        let bare: [u8; 32] = Sha256::digest(&spki).into();
        assert_ne!(hash_identity(&spki), bare);
    }
}
