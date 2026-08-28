//! Versioned vault/locker frames carried inside an authenticated session.
//!
//! These frames are never biometric-signature payloads. The secure channel
//! authenticates and encrypts them; the explicit session binding prevents a
//! decoded response from being accepted in another live session.

use crate::cbor::{Reader, Writer};
use crate::{
    bytes_equal, check_frame_size, check_text, ProtocolError, Result, MAX_VALIDITY_MS,
    MESSAGE_TYPE_APPLICATION, PROTOCOL_VERSION, SESSION_BINDING_LEN,
};

const APPLICATION_FRAME_LEN: u64 = 9;
const APPLICATION_ERROR_LEN: u64 = 2;

/// Leaves room for the envelope inside the transport's 8 KiB frame limit.
pub const MAX_APPLICATION_PAYLOAD_BYTES: usize = 6 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationFrameKind {
    Request,
    Response,
    Cancel,
    Error,
}

/// Stable, deliberately coarse application errors.
///
/// In particular, missing items and stale revisions are both [`Rejected`]. A
/// peer that is not entitled to a secret must not learn whether it exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationErrorCode {
    Rejected,
    InvalidRequest,
    Unavailable,
}

impl ApplicationErrorCode {
    pub fn encode(self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(APPLICATION_ERROR_LEN);
        writer.uint(PROTOCOL_VERSION);
        writer.uint(match self {
            Self::Rejected => 0,
            Self::InvalidRequest => 1,
            Self::Unavailable => 2,
        });
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(payload);
        let len = reader.array()?;
        if len != APPLICATION_ERROR_LEN {
            return Err(ProtocolError::FrameShape {
                expected: APPLICATION_ERROR_LEN,
                actual: len,
            });
        }
        let version = reader.uint()?;
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let code = match reader.uint()? {
            0 => Self::Rejected,
            1 => Self::InvalidRequest,
            2 => Self::Unavailable,
            value => return Err(ProtocolError::InvalidApplicationError(value)),
        };
        reader.finish()?;
        if !bytes_equal(payload, &code.encode()) {
            return Err(ProtocolError::NotCanonical);
        }
        Ok(code)
    }
}

impl ApplicationFrameKind {
    fn wire(self) -> u64 {
        match self {
            Self::Request => 0,
            Self::Response => 1,
            Self::Cancel => 2,
            Self::Error => 3,
        }
    }

    fn from_wire(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Request),
            1 => Ok(Self::Response),
            2 => Ok(Self::Cancel),
            3 => Ok(Self::Error),
            _ => Err(ProtocolError::InvalidApplicationKind(value)),
        }
    }
}

/// Envelope shared by every `vault.*` and `locker.*` operation.
///
/// Deliberately does not implement `Debug`: payloads may contain secrets after
/// the secure channel is opened and must not be logged accidentally.
#[derive(Clone, PartialEq, Eq)]
pub struct ApplicationFrame {
    pub protocol_version: u64,
    pub kind: ApplicationFrameKind,
    pub request_id: String,
    pub session_binding: [u8; SESSION_BINDING_LEN],
    pub operation: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub payload: Vec<u8>,
}

impl ApplicationFrame {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.protocol_version));
        }
        check_text("requestId", &self.request_id, 64)?;
        if !valid_operation(&self.operation) {
            return Err(ProtocolError::InvalidOperation);
        }
        if self.payload.len() > MAX_APPLICATION_PAYLOAD_BYTES {
            return Err(ProtocolError::PayloadSize(self.payload.len()));
        }
        let window = self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .ok_or(ProtocolError::ValidityWindow)?;
        if window <= 0 || window > MAX_VALIDITY_MS {
            return Err(ProtocolError::ValidityWindow);
        }
        Ok(())
    }

    pub fn is_expired_at(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Checks every field that binds a response/error to one pending request.
    pub fn is_reply_to(&self, request: &Self, now_ms: i64) -> bool {
        request.kind == ApplicationFrameKind::Request
            && matches!(
                self.kind,
                ApplicationFrameKind::Response | ApplicationFrameKind::Error
            )
            && self.request_id == request.request_id
            && self.session_binding == request.session_binding
            && self.operation == request.operation
            && self.issued_at_ms == request.issued_at_ms
            && self.expires_at_ms == request.expires_at_ms
            && !self.is_expired_at(now_ms)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(APPLICATION_FRAME_LEN);
        writer.uint(MESSAGE_TYPE_APPLICATION);
        writer.uint(self.protocol_version);
        writer.uint(self.kind.wire());
        writer.text(&self.request_id);
        writer.bytes(&self.session_binding);
        writer.text(&self.operation);
        writer.int(self.issued_at_ms);
        writer.int(self.expires_at_ms);
        writer.bytes(&self.payload);
        writer.into_bytes()
    }

    pub fn decode(frame: &[u8]) -> Result<Self> {
        check_frame_size(frame)?;
        let mut reader = Reader::new(frame);
        let len = reader.array()?;
        if len != APPLICATION_FRAME_LEN {
            return Err(ProtocolError::FrameShape {
                expected: APPLICATION_FRAME_LEN,
                actual: len,
            });
        }
        let message_type = reader.uint()?;
        if message_type != MESSAGE_TYPE_APPLICATION {
            return Err(ProtocolError::UnexpectedMessageType(message_type));
        }
        let decoded = Self {
            protocol_version: reader.uint()?,
            kind: ApplicationFrameKind::from_wire(reader.uint()?)?,
            request_id: reader.text()?.to_owned(),
            session_binding: fixed_bytes("sessionBinding", reader.bytes()?)?,
            operation: reader.text()?.to_owned(),
            issued_at_ms: reader.int()?,
            expires_at_ms: reader.int()?,
            payload: reader.bytes()?.to_vec(),
        };
        reader.finish()?;
        decoded.validate()?;
        if !bytes_equal(frame, &decoded.encode()) {
            return Err(ProtocolError::NotCanonical);
        }
        Ok(decoded)
    }
}

fn valid_operation(value: &str) -> bool {
    let suffix = value
        .strip_prefix("vault.")
        .or_else(|| value.strip_prefix("locker."));
    matches!(suffix, Some(suffix) if !suffix.is_empty()
        && value.len() <= 64
        && !suffix.contains("..")
        && suffix.bytes().all(|byte| byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'-')))
}

fn fixed_bytes<const N: usize>(field: &'static str, value: &[u8]) -> Result<[u8; N]> {
    value.try_into().map_err(|_| ProtocolError::FieldLength {
        field,
        expected: N,
        actual: value.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ApplicationFrame {
        ApplicationFrame {
            protocol_version: 1,
            kind: ApplicationFrameKind::Request,
            request_id: "request-1".into(),
            session_binding: core::array::from_fn(|index| index as u8),
            operation: "vault.list".into(),
            issued_at_ms: 1_787_745_600_000,
            expires_at_ms: 1_787_745_660_000,
            payload: vec![1, 2, 3],
        }
    }

    #[test]
    fn round_trips_without_exposing_a_debug_payload() {
        let frame = fixture();
        assert_eq!(
            crate::encoding::to_hex(&frame.encode()),
            concat!(
                "8904010069726571756573742d315820000102030405060708090a0b0c0d0e0f",
                "101112131415161718191a1b1c1d1e1f6a7661756c742e6c6973741b000001a0",
                "3df102001b000001a03df1ec6043010203"
            )
        );
        let decoded = ApplicationFrame::decode(&frame.encode()).expect("decode");
        assert!(decoded == frame);
    }

    #[test]
    fn rejects_foreign_services_oversized_payloads_and_bad_windows() {
        let mut frame = fixture();
        frame.operation = "sudo.run".into();
        assert_eq!(frame.validate(), Err(ProtocolError::InvalidOperation));

        frame = fixture();
        frame.payload = vec![0; MAX_APPLICATION_PAYLOAD_BYTES + 1];
        assert_eq!(
            frame.validate(),
            Err(ProtocolError::PayloadSize(
                MAX_APPLICATION_PAYLOAD_BYTES + 1
            ))
        );

        frame = fixture();
        frame.expires_at_ms = frame.issued_at_ms;
        assert_eq!(frame.validate(), Err(ProtocolError::ValidityWindow));
    }

    #[test]
    fn expiry_is_inclusive_and_binding_is_exactly_32_bytes() {
        let frame = fixture();
        assert!(!frame.is_expired_at(frame.expires_at_ms - 1));
        assert!(frame.is_expired_at(frame.expires_at_ms));

        let mut encoded = frame.encode();
        let binding_header = encoded
            .windows(2)
            .position(|window| window == [0x58, 0x20])
            .expect("32-byte binding header");
        encoded[binding_header + 1] = 31;
        encoded.remove(binding_header + 2);
        assert!(matches!(
            ApplicationFrame::decode(&encoded),
            Err(ProtocolError::FieldLength {
                field: "sessionBinding",
                ..
            })
        ));
    }

    #[test]
    fn a_reply_matches_only_the_same_pending_request() {
        let request = fixture();
        let mut reply = fixture();
        reply.kind = ApplicationFrameKind::Response;
        assert!(reply.is_reply_to(&request, request.expires_at_ms - 1));

        reply.session_binding[0] ^= 1;
        assert!(!reply.is_reply_to(&request, request.expires_at_ms - 1));
        reply.session_binding = request.session_binding;
        assert!(!reply.is_reply_to(&request, request.expires_at_ms));
    }

    #[test]
    fn application_errors_are_coarse_and_canonical() {
        for code in [
            ApplicationErrorCode::Rejected,
            ApplicationErrorCode::InvalidRequest,
            ApplicationErrorCode::Unavailable,
        ] {
            assert_eq!(ApplicationErrorCode::decode(&code.encode()), Ok(code));
        }
        // Pinned, and pinned to the same bytes in
        // `mobile/test/application_frame_test.dart`. A round trip alone would
        // still pass if both the writer and the reader on this side changed
        // together, which is exactly how the two ends drift apart.
        assert_eq!(ApplicationErrorCode::Rejected.encode(), [0x82, 0x01, 0x00]);
        assert_eq!(
            ApplicationErrorCode::InvalidRequest.encode(),
            [0x82, 0x01, 0x01]
        );
        assert_eq!(
            ApplicationErrorCode::Unavailable.encode(),
            [0x82, 0x01, 0x02]
        );
        assert!(ApplicationErrorCode::decode(&[0x82, 0x01, 0x03]).is_err());
    }
}
