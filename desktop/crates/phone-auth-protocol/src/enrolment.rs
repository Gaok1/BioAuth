//! Credential enrolment: what a phone sends after a pairing handshake.
//!
//! The handshake establishes *which device* is talking. It exchanges session
//! identity keys and nothing else. The key that actually signs authorizations
//! lives behind a biometric gate in the phone's keystore, and this frame is
//! how its public half reaches the verifier.
//!
//! Sent inside the encrypted channel, never in the clear, and never in a QR
//! code.

use crate::cbor::{Reader, Writer};
use crate::{
    bytes_equal, check_frame_size, check_text, ProtocolError, Result, MESSAGE_TYPE_ENROLMENT,
    PROTOCOL_VERSION,
};

const ENROLMENT_FRAME_LEN: u64 = 9;

/// Where the enrolled credential's private key lives.
///
/// Reported by the phone. The verifier cannot prove it, and uses it only to
/// *withhold* authority — a software key is never enough for disk unlock —
/// never to grant more than the paired public key already establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// A discrete secure element: Android StrongBox, iOS Secure Enclave.
    StrongBox = 0,
    /// TEE-backed keystore without a separate secure element.
    Hardware = 1,
    /// Not hardware-backed. Development fixtures only.
    Software = 2,
}

impl KeyKind {
    fn from_wire(value: i64) -> Result<Self> {
        match value {
            0 => Ok(Self::StrongBox),
            1 => Ok(Self::Hardware),
            2 => Ok(Self::Software),
            other => Err(ProtocolError::InvalidKeyKind(other)),
        }
    }
}

/// What the credential may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPurpose {
    /// Interactive authorization: login, sudo, unlocking an app.
    Authorization = 0,
    /// Boot-time volume unwrapping. Requires a hardware-backed key.
    DiskUnlock = 1,
    /// WebAuthn assertions. Never shared with desktop authorization keys.
    WebAuthn = 2,
    /// Password-vault encryption and release operations.
    Vault = 3,
    /// File-locker key wrapping and release operations.
    FileLocker = 4,
}

impl CredentialPurpose {
    fn from_wire(value: i64) -> Result<Self> {
        match value {
            0 => Ok(Self::Authorization),
            1 => Ok(Self::DiskUnlock),
            2 => Ok(Self::WebAuthn),
            3 => Ok(Self::Vault),
            4 => Ok(Self::FileLocker),
            other => Err(ProtocolError::InvalidPurpose(other)),
        }
    }
}

/// One credential offered for enrolment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolment {
    pub protocol_version: u64,
    /// Name the user will see in the paired-devices list.
    pub device_name: String,
    pub credential_id: String,
    /// Public key encoding identifier, e.g. `EC_P256_SPKI`.
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub key_kind: KeyKind,
    pub purpose: CredentialPurpose,
}

impl Enrolment {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.protocol_version));
        }
        check_text("deviceName", &self.device_name, 128)?;
        check_text("credentialId", &self.credential_id, 64)?;
        check_text("algorithm", &self.algorithm, 64)?;

        // A SubjectPublicKeyInfo for P-256 is 91 bytes; the bound is generous
        // enough for other curves without accepting an arbitrary blob.
        if self.public_key.is_empty() || self.public_key.len() > 512 {
            return Err(ProtocolError::FieldLength {
                field: "publicKey",
                expected: 91,
                actual: self.public_key.len(),
            });
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(ENROLMENT_FRAME_LEN);
        writer.uint(MESSAGE_TYPE_ENROLMENT);
        writer.uint(self.protocol_version);
        writer.text(&self.device_name);
        writer.text(&self.credential_id);
        writer.text(&self.algorithm);
        writer.bytes(&self.public_key);
        writer.uint(self.key_kind as u64);
        writer.uint(self.purpose as u64);
        // Reserved for a future field; keeping the arity fixed means adding
        // one is a version bump rather than a silent shape change.
        writer.uint(0);
        writer.into_bytes()
    }

    pub fn decode(frame: &[u8]) -> Result<Self> {
        check_frame_size(frame)?;
        let mut reader = Reader::new(frame);

        let len = reader.array()?;
        if len != ENROLMENT_FRAME_LEN {
            return Err(ProtocolError::FrameShape {
                expected: ENROLMENT_FRAME_LEN,
                actual: len,
            });
        }
        let message_type = reader.uint()?;
        if message_type != MESSAGE_TYPE_ENROLMENT {
            return Err(ProtocolError::UnexpectedMessageType(message_type));
        }

        let enrolment = Self {
            protocol_version: reader.uint()?,
            device_name: reader.text()?.to_owned(),
            credential_id: reader.text()?.to_owned(),
            algorithm: reader.text()?.to_owned(),
            public_key: reader.bytes()?.to_vec(),
            key_kind: KeyKind::from_wire(reader.int()?)?,
            purpose: CredentialPurpose::from_wire(reader.int()?)?,
        };
        let reserved = reader.uint()?;
        if reserved != 0 {
            return Err(ProtocolError::InvalidReservedField(reserved));
        }
        reader.finish()?;
        enrolment.validate()?;

        if !bytes_equal(frame, &enrolment.encode()) {
            return Err(ProtocolError::NotCanonical);
        }
        Ok(enrolment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrolment() -> Enrolment {
        Enrolment {
            protocol_version: 1,
            device_name: "Pixel 8".into(),
            credential_id: "desktop-1-sudo-v1".into(),
            algorithm: crate::PUBLIC_KEY_EC_P256_SPKI.into(),
            public_key: vec![7; 91],
            key_kind: KeyKind::StrongBox,
            purpose: CredentialPurpose::Authorization,
        }
    }

    #[test]
    fn round_trips_through_the_wire_format() {
        let original = enrolment();
        assert_eq!(Enrolment::decode(&original.encode()), Ok(original));
    }

    #[test]
    fn wire_values_are_pinned() {
        // The desktop stores these as its own enums. A reordering here would
        // silently turn a software key into a StrongBox one.
        assert_eq!(KeyKind::StrongBox as u64, 0);
        assert_eq!(KeyKind::Hardware as u64, 1);
        assert_eq!(KeyKind::Software as u64, 2);
        assert_eq!(CredentialPurpose::Authorization as u64, 0);
        assert_eq!(CredentialPurpose::DiskUnlock as u64, 1);
        assert_eq!(CredentialPurpose::WebAuthn as u64, 2);
        assert_eq!(CredentialPurpose::Vault as u64, 3);
        assert_eq!(CredentialPurpose::FileLocker as u64, 4);
    }

    #[test]
    fn every_key_kind_and_purpose_round_trips() {
        for kind in [KeyKind::StrongBox, KeyKind::Hardware, KeyKind::Software] {
            for purpose in [
                CredentialPurpose::Authorization,
                CredentialPurpose::DiskUnlock,
                CredentialPurpose::WebAuthn,
                CredentialPurpose::Vault,
                CredentialPurpose::FileLocker,
            ] {
                let original = Enrolment {
                    key_kind: kind,
                    purpose,
                    ..enrolment()
                };
                let decoded = Enrolment::decode(&original.encode()).expect("decode");
                assert_eq!(decoded.key_kind, kind);
                assert_eq!(decoded.purpose, purpose);
            }
        }
    }

    #[test]
    fn an_unknown_key_kind_is_refused() {
        let mut writer = Writer::new();
        writer.array(ENROLMENT_FRAME_LEN);
        writer.uint(MESSAGE_TYPE_ENROLMENT);
        writer.uint(1);
        writer.text("Pixel 8");
        writer.text("cred-1");
        writer.text("EC_P256_SPKI");
        writer.bytes(&[7; 91]);
        writer.uint(9);
        writer.uint(0);
        writer.uint(0);

        assert_eq!(
            Enrolment::decode(&writer.into_bytes()),
            Err(ProtocolError::InvalidKeyKind(9))
        );
    }

    #[test]
    fn an_empty_public_key_is_refused() {
        let offered = Enrolment {
            public_key: Vec::new(),
            ..enrolment()
        };
        assert!(matches!(
            offered.validate(),
            Err(ProtocolError::FieldLength { .. })
        ));
    }

    #[test]
    fn a_request_frame_offered_as_an_enrolment_is_refused() {
        let request = crate::request::tests::fixture();
        assert!(matches!(
            Enrolment::decode(&request.encode()),
            Err(ProtocolError::FrameShape { .. } | ProtocolError::UnexpectedMessageType(_))
        ));
    }

    #[test]
    fn a_blank_device_name_is_refused() {
        let offered = Enrolment {
            device_name: "   ".into(),
            ..enrolment()
        };
        assert_eq!(
            offered.validate(),
            Err(ProtocolError::FieldEmpty("deviceName"))
        );
    }
}
