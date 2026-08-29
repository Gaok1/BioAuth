//! Session attach: which credential the phone opened this session with.
//!
//! A paired phone runs one connection per credential, because the credential a
//! session was opened with decides which key signs on it — a desktop naming a
//! different credential in a request is refused rather than served from another
//! key. So the verifier has to know which of a phone's sessions is which
//! before it picks one to send a request down; without it, a vault request
//! goes out over the login session about as often as not and comes back as a
//! denial the user never made.
//!
//! Sent by the phone immediately after a *non-pairing* handshake, inside the
//! encrypted channel. It is a routing hint and nothing more: it grants no
//! authority, and a phone that claims a credential it does not hold has only
//! arranged to be sent requests it will refuse.

use crate::cbor::{Reader, Writer};
use crate::{
    bytes_equal, check_frame_size, check_text, ProtocolError, Result, MESSAGE_TYPE_ATTACH,
    PROTOCOL_VERSION,
};

const ATTACH_FRAME_LEN: u64 = 4;

/// The phone declaring what this session is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAttach {
    pub protocol_version: u64,
    pub credential_id: String,
}

impl SessionAttach {
    pub fn new(credential_id: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            credential_id: credential_id.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.protocol_version));
        }
        check_text("credentialId", &self.credential_id, 64)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(ATTACH_FRAME_LEN);
        writer.uint(MESSAGE_TYPE_ATTACH);
        writer.uint(self.protocol_version);
        writer.text(&self.credential_id);
        // Reserved, as everywhere else: a fixed arity makes adding a field a
        // version bump rather than a silent shape change.
        writer.uint(0);
        writer.into_bytes()
    }

    pub fn decode(frame: &[u8]) -> Result<Self> {
        check_frame_size(frame)?;
        let mut reader = Reader::new(frame);

        let len = reader.array()?;
        if len != ATTACH_FRAME_LEN {
            return Err(ProtocolError::FrameShape {
                expected: ATTACH_FRAME_LEN,
                actual: len,
            });
        }
        let message_type = reader.uint()?;
        if message_type != MESSAGE_TYPE_ATTACH {
            return Err(ProtocolError::UnexpectedMessageType(message_type));
        }

        let attach = Self {
            protocol_version: reader.uint()?,
            credential_id: reader.text()?.to_owned(),
        };
        let reserved = reader.uint()?;
        if reserved != 0 {
            return Err(ProtocolError::InvalidReservedField(reserved));
        }
        reader.finish()?;
        attach.validate()?;

        if !bytes_equal(frame, &attach.encode()) {
            return Err(ProtocolError::NotCanonical);
        }
        Ok(attach)
    }

    /// Whether a frame looks like an attach, without committing to decoding it.
    ///
    /// The listener reads one frame and has to tell an attach from the first
    /// application frame of a phone too old to send one. Peeking the message
    /// type is enough, and it keeps a malformed attach an error rather than
    /// something silently handled as another kind of frame.
    pub fn recognizes(frame: &[u8]) -> bool {
        let mut reader = Reader::new(frame);
        reader.array().is_ok() && reader.uint() == Ok(MESSAGE_TYPE_ATTACH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_round_trips() {
        let attach = SessionAttach::new("desktop-1-vault-v1");
        assert_eq!(SessionAttach::decode(&attach.encode()), Ok(attach));
    }

    #[test]
    fn an_empty_credential_is_refused() {
        // The whole point of the frame is to name one session out of several.
        // An empty name selects nothing and must not become a key in the pool.
        assert!(SessionAttach::new("").encode_and_decode().is_err());
    }

    #[test]
    fn a_non_zero_reserved_field_is_refused() {
        let mut writer = Writer::new();
        writer.array(ATTACH_FRAME_LEN);
        writer.uint(MESSAGE_TYPE_ATTACH);
        writer.uint(PROTOCOL_VERSION);
        writer.text("credential-1");
        writer.uint(1);
        assert_eq!(
            SessionAttach::decode(&writer.into_bytes()),
            Err(ProtocolError::InvalidReservedField(1))
        );
    }

    #[test]
    fn another_message_type_is_not_mistaken_for_one() {
        // The listener uses this to tell an attach from the first frame of a
        // phone that predates it, so a false positive would swallow traffic.
        let mut writer = Writer::new();
        writer.array(ATTACH_FRAME_LEN);
        writer.uint(crate::MESSAGE_TYPE_ENROLMENT);
        writer.uint(PROTOCOL_VERSION);
        writer.text("credential-1");
        writer.uint(0);
        let frame = writer.into_bytes();
        assert!(!SessionAttach::recognizes(&frame));
        assert!(matches!(
            SessionAttach::decode(&frame),
            Err(ProtocolError::UnexpectedMessageType(_))
        ));
    }

    #[test]
    fn a_short_frame_is_refused() {
        let mut writer = Writer::new();
        writer.array(3);
        writer.uint(MESSAGE_TYPE_ATTACH);
        writer.uint(PROTOCOL_VERSION);
        writer.text("credential-1");
        assert!(SessionAttach::decode(&writer.into_bytes()).is_err());
    }

    impl SessionAttach {
        fn encode_and_decode(&self) -> Result<Self> {
            Self::decode(&self.encode())
        }
    }
}
