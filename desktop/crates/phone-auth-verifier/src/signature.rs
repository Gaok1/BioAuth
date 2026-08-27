//! Signature checking for authorization proofs.

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use phone_auth_protocol::{ALGORITHM_ECDSA_P256_SHA256, PUBLIC_KEY_EC_P256_SPKI};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The response named an algorithm this build does not implement.
    UnsupportedAlgorithm(String),
    /// The pairing record's key encoding is not one this build understands.
    UnsupportedKeyEncoding(String),
    /// The stored public key did not parse as a P-256 SubjectPublicKeyInfo.
    MalformedPublicKey,
    /// The signature was not a well-formed ECDSA DER structure.
    MalformedSignature,
    /// The signature did not verify over the payload.
    Invalid,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(name) => write!(f, "unsupported algorithm `{name}`"),
            Self::UnsupportedKeyEncoding(name) => write!(f, "unsupported key encoding `{name}`"),
            Self::MalformedPublicKey => f.write_str("stored public key is malformed"),
            Self::MalformedSignature => f.write_str("signature is not valid DER"),
            Self::Invalid => f.write_str("signature did not verify"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Verifies an authorization proof over the canonical request bytes.
///
/// `algorithm` and `key_encoding` are checked against the identifiers the
/// Android authenticator emits rather than being inferred from the key. An
/// unknown identifier fails closed instead of falling back to a guess.
///
/// ECDSA signatures are malleable: `(r, s)` and `(r, -s)` both verify, and
/// this function accepts either, as Android's signer does not normalise `s`.
/// That is safe here because a signature is never used as an identifier or a
/// deduplication key — replay is prevented by the single-use request id and
/// challenge, not by signature uniqueness.
pub fn verify_authorization(
    key_encoding: &str,
    public_key_der: &[u8],
    algorithm: &str,
    payload: &[u8],
    signature_der: &[u8],
) -> Result<(), SignatureError> {
    if algorithm != ALGORITHM_ECDSA_P256_SHA256 {
        return Err(SignatureError::UnsupportedAlgorithm(algorithm.to_owned()));
    }
    if key_encoding != PUBLIC_KEY_EC_P256_SPKI {
        return Err(SignatureError::UnsupportedKeyEncoding(
            key_encoding.to_owned(),
        ));
    }

    let key = VerifyingKey::from_public_key_der(public_key_der)
        .map_err(|_| SignatureError::MalformedPublicKey)?;
    let signature =
        DerSignature::try_from(signature_der).map_err(|_| SignatureError::MalformedSignature)?;

    key.verify(payload, &signature)
        .map_err(|_| SignatureError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    struct TestKey {
        signing: SigningKey,
        spki: Vec<u8>,
    }

    fn test_key(seed: u8) -> TestKey {
        let signing = SigningKey::from_bytes(&[seed.max(1); 32].into()).expect("valid scalar");
        let spki = crate::testing::spki_der(&signing);
        TestKey { signing, spki }
    }

    fn sign(key: &TestKey, payload: &[u8]) -> Vec<u8> {
        let signature: DerSignature = key.signing.sign(payload);
        signature.as_bytes().to_vec()
    }

    #[test]
    fn accepts_a_genuine_signature() {
        let key = test_key(7);
        let payload = b"canonical request bytes";
        let signature = sign(&key, payload);

        assert_eq!(
            verify_authorization(
                PUBLIC_KEY_EC_P256_SPKI,
                &key.spki,
                ALGORITHM_ECDSA_P256_SHA256,
                payload,
                &signature
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_signature_over_different_bytes() {
        let key = test_key(7);
        let signature = sign(&key, b"canonical request bytes");

        assert_eq!(
            verify_authorization(
                PUBLIC_KEY_EC_P256_SPKI,
                &key.spki,
                ALGORITHM_ECDSA_P256_SHA256,
                b"canonical request byteS",
                &signature
            ),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn rejects_a_signature_from_another_key() {
        let signer = test_key(7);
        let other = test_key(9);
        let payload = b"canonical request bytes";
        let signature = sign(&signer, payload);

        assert_eq!(
            verify_authorization(
                PUBLIC_KEY_EC_P256_SPKI,
                &other.spki,
                ALGORITHM_ECDSA_P256_SHA256,
                payload,
                &signature
            ),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn rejects_unknown_identifiers_without_guessing() {
        let key = test_key(7);
        let payload = b"canonical request bytes";
        let signature = sign(&key, payload);

        assert_eq!(
            verify_authorization(
                PUBLIC_KEY_EC_P256_SPKI,
                &key.spki,
                "Ed25519",
                payload,
                &signature
            ),
            Err(SignatureError::UnsupportedAlgorithm("Ed25519".into()))
        );
        assert_eq!(
            verify_authorization(
                "RSA_PKCS8",
                &key.spki,
                ALGORITHM_ECDSA_P256_SHA256,
                payload,
                &signature
            ),
            Err(SignatureError::UnsupportedKeyEncoding("RSA_PKCS8".into()))
        );
    }

    #[test]
    fn rejects_malformed_inputs() {
        let key = test_key(7);
        let payload = b"canonical request bytes";

        assert_eq!(
            verify_authorization(
                PUBLIC_KEY_EC_P256_SPKI,
                b"not a key",
                ALGORITHM_ECDSA_P256_SHA256,
                payload,
                &sign(&key, payload)
            ),
            Err(SignatureError::MalformedPublicKey)
        );
        assert_eq!(
            verify_authorization(
                PUBLIC_KEY_EC_P256_SPKI,
                &key.spki,
                ALGORITHM_ECDSA_P256_SHA256,
                payload,
                b"\x30\x00not der"
            ),
            Err(SignatureError::MalformedSignature)
        );
        assert_eq!(
            verify_authorization(
                PUBLIC_KEY_EC_P256_SPKI,
                &key.spki,
                ALGORITHM_ECDSA_P256_SHA256,
                payload,
                &[]
            ),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn rejects_a_truncated_signature() {
        let key = test_key(7);
        let payload = b"canonical request bytes";
        let mut signature = sign(&key, payload);
        signature.pop();

        assert!(matches!(
            verify_authorization(
                PUBLIC_KEY_EC_P256_SPKI,
                &key.spki,
                ALGORITHM_ECDSA_P256_SHA256,
                payload,
                &signature
            ),
            Err(SignatureError::MalformedSignature | SignatureError::Invalid)
        ));
    }
}
