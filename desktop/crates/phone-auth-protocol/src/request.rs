//! The authorization request: the object a phone displays and signs.

use crate::cbor::{Reader, Writer};
use crate::{
    bytes_equal, check_frame_size, check_text, ProtocolError, Result, CHALLENGE_LEN,
    MAX_VALIDITY_MS, MESSAGE_TYPE_REQUEST, PROTOCOL_VERSION, SESSION_BINDING_LEN,
};

/// Element count of the request frame. Kept next to the encoder so that adding
/// a field without bumping this is a compile-adjacent mistake rather than a
/// silent wire change.
const REQUEST_FRAME_LEN: u64 = 14;

/// What the user is being asked to approve.
///
/// Split out from [`AuthRequest`] because a verifier builds this part from
/// policy and the rest — identifiers, challenge, timing, session binding —
/// from freshly generated material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// Display name of the verifier, shown in the biometric prompt title.
    pub verifier_name: String,
    /// Coarse capability being exercised, e.g. `sudo`, `login`, `luks`.
    pub service: String,
    /// The specific operation, e.g. `nixos-rebuild switch`.
    pub action: String,
    /// What the action applies to, e.g. a hostname or a volume.
    pub resource: String,
    /// The account the action runs as.
    pub user: String,
}

/// A transport-independent authorization request.
///
/// The signed payload is the canonical encoding of this whole struct, not just
/// the challenge. That is what stops a signature collected for one service or
/// one session from being replayed against another.
///
/// `origin` is deliberately absent: it is a property of the session the frame
/// arrived on, is not signed, and must never be treated as identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub protocol_version: u64,
    pub request_id: String,
    pub verifier_id: String,
    pub verifier_name: String,
    pub credential_id: String,
    pub challenge: [u8; CHALLENGE_LEN],
    pub service: String,
    pub action: String,
    pub resource: String,
    pub user: String,
    /// Milliseconds since the Unix epoch, UTC.
    pub issued_at_ms: i64,
    /// Milliseconds since the Unix epoch, UTC.
    pub expires_at_ms: i64,
    pub session_binding: [u8; SESSION_BINDING_LEN],
}

impl AuthRequest {
    /// Checks every field bound the phone will check, so that a request this
    /// verifier builds cannot be rejected as malformed after the user has
    /// already been prompted.
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.protocol_version));
        }
        check_text("requestId", &self.request_id, 64)?;
        check_text("verifierId", &self.verifier_id, 64)?;
        check_text("verifierName", &self.verifier_name, 128)?;
        check_text("credentialId", &self.credential_id, 64)?;
        check_text("service", &self.service, 64)?;
        check_text("action", &self.action, 128)?;
        check_text("resource", &self.resource, 256)?;
        check_text("user", &self.user, 128)?;

        let window = self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .ok_or(ProtocolError::ValidityWindow)?;
        if window <= 0 || window > MAX_VALIDITY_MS {
            return Err(ProtocolError::ValidityWindow);
        }
        Ok(())
    }

    /// True once `now_ms` has reached the expiry instant.
    ///
    /// The boundary is inclusive, matching the phone: a request that expires
    /// exactly now is already expired.
    pub fn is_expired_at(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Groups requests that ask for the same thing, for duplicate detection.
    /// Deliberately excludes the request id, challenge and timing.
    pub fn fingerprint(&self) -> String {
        [
            self.verifier_id.as_str(),
            self.credential_id.as_str(),
            self.service.as_str(),
            self.action.as_str(),
            self.resource.as_str(),
            self.user.as_str(),
        ]
        .join("\u{0}")
    }

    /// Encodes the frame, which is also the exact byte string that gets signed.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(REQUEST_FRAME_LEN);
        writer.uint(MESSAGE_TYPE_REQUEST);
        writer.uint(self.protocol_version);
        writer.text(&self.request_id);
        writer.text(&self.verifier_id);
        writer.text(&self.verifier_name);
        writer.text(&self.credential_id);
        writer.bytes(&self.challenge);
        writer.text(&self.service);
        writer.text(&self.action);
        writer.text(&self.resource);
        writer.text(&self.user);
        writer.int(self.issued_at_ms);
        writer.int(self.expires_at_ms);
        writer.bytes(&self.session_binding);
        writer.into_bytes()
    }

    /// The payload a phone signs for this request.
    ///
    /// Identical to [`AuthRequest::encode`] today, and named separately so
    /// that call sites reading as "verify this signature over X" do not have
    /// to assume the two can never diverge.
    pub fn signing_payload(&self) -> Vec<u8> {
        self.encode()
    }

    /// Parses and fully validates a request frame.
    pub fn decode(frame: &[u8]) -> Result<Self> {
        check_frame_size(frame)?;
        let mut reader = Reader::new(frame);

        let len = reader.array()?;
        if len != REQUEST_FRAME_LEN {
            return Err(ProtocolError::FrameShape {
                expected: REQUEST_FRAME_LEN,
                actual: len,
            });
        }
        let message_type = reader.uint()?;
        if message_type != MESSAGE_TYPE_REQUEST {
            return Err(ProtocolError::UnexpectedMessageType(message_type));
        }

        let request = Self {
            protocol_version: reader.uint()?,
            request_id: reader.text()?.to_owned(),
            verifier_id: reader.text()?.to_owned(),
            verifier_name: reader.text()?.to_owned(),
            credential_id: reader.text()?.to_owned(),
            challenge: fixed_bytes("challenge", reader.bytes()?)?,
            service: reader.text()?.to_owned(),
            action: reader.text()?.to_owned(),
            resource: reader.text()?.to_owned(),
            user: reader.text()?.to_owned(),
            issued_at_ms: reader.int()?,
            expires_at_ms: reader.int()?,
            session_binding: fixed_bytes("sessionBinding", reader.bytes()?)?,
        };
        reader.finish()?;
        request.validate()?;

        // Re-encoding and comparing is what the Dart codec does, and it is the
        // check that actually matters: the signature covers these bytes, so a
        // frame that does not reproduce itself must never reach a verifier.
        if !bytes_equal(frame, &request.encode()) {
            return Err(ProtocolError::NotCanonical);
        }
        Ok(request)
    }
}

/// Converts a variable-length byte string into a fixed-size array, reporting
/// the field name when the length is wrong.
fn fixed_bytes<const N: usize>(field: &'static str, value: &[u8]) -> Result<[u8; N]> {
    value.try_into().map_err(|_| ProtocolError::FieldLength {
        field,
        expected: N,
        actual: value.len(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The shared cross-language fixture. `mobile/test/protocol_codec_test.dart`
    /// builds the same request, so its encoding is the contract between the two
    /// implementations.
    pub(crate) fn fixture() -> AuthRequest {
        let issued_at_ms = 1_787_745_600_000; // 2026-08-26T12:00:00Z
        AuthRequest {
            protocol_version: 1,
            request_id: "request-1".into(),
            verifier_id: "desktop-1".into(),
            verifier_name: "Desktop-Casa".into(),
            credential_id: "desktop-1-sudo-v1".into(),
            challenge: core::array::from_fn(|i| i as u8),
            service: "sudo".into(),
            action: "nixos-rebuild switch".into(),
            resource: "Desktop-NixOS".into(),
            user: "alice".into(),
            issued_at_ms,
            expires_at_ms: issued_at_ms + 60_000,
            session_binding: core::array::from_fn(|i| 255 - i as u8),
        }
    }

    #[test]
    fn round_trips_through_the_wire_format() {
        let request = fixture();
        let decoded = AuthRequest::decode(&request.encode()).expect("frame should decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn signing_payload_is_the_request_frame() {
        let request = fixture();
        assert_eq!(request.signing_payload(), request.encode());
    }

    #[test]
    fn rejects_a_flipped_message_type() {
        let mut frame = fixture().encode();
        frame[1] = 0x02;
        assert_eq!(
            AuthRequest::decode(&frame),
            Err(ProtocolError::UnexpectedMessageType(2))
        );
    }

    #[test]
    fn rejects_oversized_and_empty_frames() {
        assert_eq!(AuthRequest::decode(&[]), Err(ProtocolError::FrameSize(0)));
        assert_eq!(
            AuthRequest::decode(&vec![0u8; 9000]),
            Err(ProtocolError::FrameSize(9000))
        );
    }

    #[test]
    fn rejects_an_unknown_protocol_version() {
        let mut request = fixture();
        request.protocol_version = 2;
        assert_eq!(
            AuthRequest::decode(&request.encode()),
            Err(ProtocolError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn rejects_a_validity_window_longer_than_two_minutes() {
        let mut request = fixture();
        request.expires_at_ms = request.issued_at_ms + MAX_VALIDITY_MS + 1;
        assert_eq!(request.validate(), Err(ProtocolError::ValidityWindow));

        request.expires_at_ms = request.issued_at_ms + MAX_VALIDITY_MS;
        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn rejects_a_non_positive_validity_window() {
        let mut request = fixture();
        request.expires_at_ms = request.issued_at_ms;
        assert_eq!(request.validate(), Err(ProtocolError::ValidityWindow));

        request.expires_at_ms = request.issued_at_ms - 1;
        assert_eq!(request.validate(), Err(ProtocolError::ValidityWindow));
    }

    #[test]
    fn rejects_blank_and_overlong_text_fields() {
        let mut request = fixture();
        request.user = "   ".into();
        assert_eq!(request.validate(), Err(ProtocolError::FieldEmpty("user")));

        let mut request = fixture();
        request.resource = "r".repeat(257);
        assert_eq!(
            request.validate(),
            Err(ProtocolError::FieldTooLong {
                field: "resource",
                max: 256,
                actual: 257
            })
        );
    }

    #[test]
    fn measures_field_length_in_utf16_code_units() {
        // Each emoji is one `char` but two UTF-16 code units, which is what
        // Dart's `String.length` counts. 33 of them exceed the 64-unit bound.
        let mut request = fixture();
        request.service = "\u{1F510}".repeat(33);
        assert_eq!(
            request.validate(),
            Err(ProtocolError::FieldTooLong {
                field: "service",
                max: 64,
                actual: 66
            })
        );

        request.service = "\u{1F510}".repeat(32);
        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let request = fixture();
        assert!(!request.is_expired_at(request.expires_at_ms - 1));
        assert!(request.is_expired_at(request.expires_at_ms));
    }

    #[test]
    fn fingerprint_ignores_request_id_and_timing() {
        let first = fixture();
        let mut second = fixture();
        second.request_id = "request-2".into();
        second.issued_at_ms += 5_000;
        second.expires_at_ms += 5_000;
        assert_eq!(first.fingerprint(), second.fingerprint());

        second.action = "reboot".into();
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn rejects_a_challenge_of_the_wrong_length() {
        // Rebuild the frame by hand with a 31-byte challenge.
        let request = fixture();
        let mut writer = Writer::new();
        writer.array(REQUEST_FRAME_LEN);
        writer.uint(MESSAGE_TYPE_REQUEST);
        writer.uint(request.protocol_version);
        writer.text(&request.request_id);
        writer.text(&request.verifier_id);
        writer.text(&request.verifier_name);
        writer.text(&request.credential_id);
        writer.bytes(&request.challenge[..31]);
        writer.text(&request.service);
        writer.text(&request.action);
        writer.text(&request.resource);
        writer.text(&request.user);
        writer.int(request.issued_at_ms);
        writer.int(request.expires_at_ms);
        writer.bytes(&request.session_binding);

        assert_eq!(
            AuthRequest::decode(&writer.into_bytes()),
            Err(ProtocolError::FieldLength {
                field: "challenge",
                expected: 32,
                actual: 31
            })
        );
    }
}
