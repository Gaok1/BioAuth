//! Payloads for the three File Locker operations.
//!
//! These ride inside an [`crate::ApplicationFrame`], which is itself inside the
//! authenticated encrypted session. That is what lets a data key cross the
//! link at all: the frame is bound to the session and to one request, and the
//! container binding travels with it so an approval for one locker can never be
//! replayed onto another.
//!
//! None of these types implement `Debug`. Two of them carry a data key, and the
//! remaining ones carry a file name the user did not agree to publish.

use crate::cbor::{Reader, Writer};
use crate::{
    bytes_equal, check_text, ProtocolError, Result, MAX_APPLICATION_PAYLOAD_BYTES,
    SESSION_BINDING_LEN,
};

/// Ask the phone to wrap a new locker's data key.
pub const OPERATION_CREATE: &str = "locker.create";
/// Ask the phone to unwrap an existing locker's data key.
pub const OPERATION_UNLOCK: &str = "locker.unlock";
/// Ask the phone to unwrap a locker so it can be bound to a new key.
///
/// Structurally identical to an unlock, and deliberately a separate operation:
/// the phone tells the user that this container is about to change hands, and
/// the audit trail says so too.
pub const OPERATION_REKEY: &str = "locker.rekey";

/// Only schema this build speaks. Unknown schemas fail closed.
pub const LOCKER_SCHEMA: u64 = 1;

/// Length of a locker data key.
pub const DATA_KEY_LEN: usize = 32;

/// Longest wrapped-key blob a phone may return.
pub const MAX_WRAPPER_BYTES: usize = 512;

const WRAP_REQUEST_FIELDS: u64 = 6;
const WRAP_RESPONSE_FIELDS: u64 = 3;
const UNWRAP_REQUEST_FIELDS: u64 = 7;
const UNWRAP_RESPONSE_FIELDS: u64 = 2;

const MAX_NAME_UNITS: usize = 255;
const MAX_ID_UNITS: usize = 64;

/// Wipes a key buffer that is about to be dropped.
///
/// `phone-auth-protocol` has no dependencies, so this is the whole of the
/// crate's key hygiene: enough that a freed payload is not still a key, and
/// deliberately not a claim about pages, cores or optimisers.
fn wipe(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        // `write_volatile` is what stops this being optimised away as a store
        // to memory nothing reads again.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// `locker.create`: the desktop hands over a fresh data key to be wrapped.
#[derive(Clone, PartialEq, Eq)]
pub struct WrapRequest {
    /// The computer asking, as the user named it.
    pub verifier_name: String,
    /// Shown on the phone before the biometric prompt.
    pub file_name: String,
    pub plaintext_len: u64,
    /// The container's binding. The phone's own tag covers it.
    pub container_binding: [u8; SESSION_BINDING_LEN],
    pub data_key: Vec<u8>,
}

impl Drop for WrapRequest {
    fn drop(&mut self) {
        wipe(&mut self.data_key);
    }
}

impl WrapRequest {
    pub fn validate(&self) -> Result<()> {
        check_text("verifierName", &self.verifier_name, MAX_NAME_UNITS)?;
        check_text("fileName", &self.file_name, MAX_NAME_UNITS)?;
        if self.data_key.len() != DATA_KEY_LEN {
            return Err(ProtocolError::FieldLength {
                field: "dataKey",
                expected: DATA_KEY_LEN,
                actual: self.data_key.len(),
            });
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(WRAP_REQUEST_FIELDS);
        writer.uint(LOCKER_SCHEMA);
        writer.text(&self.verifier_name);
        writer.text(&self.file_name);
        writer.uint(self.plaintext_len);
        writer.bytes(&self.container_binding);
        writer.bytes(&self.data_key);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, WRAP_REQUEST_FIELDS)?;
        let decoded = Self {
            verifier_name: reader.text()?.to_owned(),
            file_name: reader.text()?.to_owned(),
            plaintext_len: reader.uint()?,
            container_binding: fixed("containerBinding", reader.bytes()?)?,
            data_key: reader.bytes()?.to_vec(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// The phone's answer to `locker.create`.
#[derive(Clone, PartialEq, Eq)]
pub struct WrapResponse {
    /// Which credential wrapped it. Stored in the container so a later unlock
    /// asks the phone that can actually answer.
    pub credential_id: String,
    /// Opaque to the desktop, and never logged.
    pub wrapper: Vec<u8>,
}

impl WrapResponse {
    pub fn validate(&self) -> Result<()> {
        check_text("credentialId", &self.credential_id, MAX_ID_UNITS)?;
        check_wrapper(&self.wrapper)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(WRAP_RESPONSE_FIELDS);
        writer.uint(LOCKER_SCHEMA);
        writer.text(&self.credential_id);
        writer.bytes(&self.wrapper);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, WRAP_RESPONSE_FIELDS)?;
        let decoded = Self {
            credential_id: reader.text()?.to_owned(),
            wrapper: reader.bytes()?.to_vec(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// `locker.unlock` and `locker.rekey`: the desktop hands back a wrapped key.
#[derive(Clone, PartialEq, Eq)]
pub struct UnwrapRequest {
    pub verifier_name: String,
    /// The container's name, shown on the phone. It is the container's file
    /// name, not the encrypted name inside it, which the desktop cannot read
    /// until this very request succeeds.
    pub file_name: String,
    pub plaintext_len: u64,
    pub container_binding: [u8; SESSION_BINDING_LEN],
    pub credential_id: String,
    pub wrapper: Vec<u8>,
}

impl UnwrapRequest {
    pub fn validate(&self) -> Result<()> {
        check_text("verifierName", &self.verifier_name, MAX_NAME_UNITS)?;
        check_text("fileName", &self.file_name, MAX_NAME_UNITS)?;
        check_text("credentialId", &self.credential_id, MAX_ID_UNITS)?;
        check_wrapper(&self.wrapper)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(UNWRAP_REQUEST_FIELDS);
        writer.uint(LOCKER_SCHEMA);
        writer.text(&self.verifier_name);
        writer.text(&self.file_name);
        writer.uint(self.plaintext_len);
        writer.bytes(&self.container_binding);
        writer.text(&self.credential_id);
        writer.bytes(&self.wrapper);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, UNWRAP_REQUEST_FIELDS)?;
        let decoded = Self {
            verifier_name: reader.text()?.to_owned(),
            file_name: reader.text()?.to_owned(),
            plaintext_len: reader.uint()?,
            container_binding: fixed("containerBinding", reader.bytes()?)?,
            credential_id: reader.text()?.to_owned(),
            wrapper: reader.bytes()?.to_vec(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// The phone's answer to `locker.unlock` or `locker.rekey`.
#[derive(Clone, PartialEq, Eq)]
pub struct UnwrapResponse {
    pub data_key: Vec<u8>,
}

impl Drop for UnwrapResponse {
    fn drop(&mut self) {
        wipe(&mut self.data_key);
    }
}

impl UnwrapResponse {
    pub fn validate(&self) -> Result<()> {
        if self.data_key.len() != DATA_KEY_LEN {
            return Err(ProtocolError::FieldLength {
                field: "dataKey",
                expected: DATA_KEY_LEN,
                actual: self.data_key.len(),
            });
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(UNWRAP_RESPONSE_FIELDS);
        writer.uint(LOCKER_SCHEMA);
        writer.bytes(&self.data_key);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, UNWRAP_RESPONSE_FIELDS)?;
        let decoded = Self {
            data_key: reader.bytes()?.to_vec(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

fn check_wrapper(wrapper: &[u8]) -> Result<()> {
    if wrapper.is_empty() || wrapper.len() > MAX_WRAPPER_BYTES {
        return Err(ProtocolError::PayloadSize(wrapper.len()));
    }
    Ok(())
}

/// Shared front of every decode: bounds, shape and schema.
fn open(payload: &[u8], fields: u64) -> Result<Reader<'_>> {
    if payload.is_empty() || payload.len() > MAX_APPLICATION_PAYLOAD_BYTES {
        return Err(ProtocolError::PayloadSize(payload.len()));
    }
    let mut reader = Reader::new(payload);
    let len = reader.array()?;
    if len != fields {
        return Err(ProtocolError::FrameShape {
            expected: fields,
            actual: len,
        });
    }
    let schema = reader.uint()?;
    if schema != LOCKER_SCHEMA {
        return Err(ProtocolError::UnsupportedVersion(schema));
    }
    Ok(reader)
}

/// Shared tail: nothing left over, and one spelling per value.
fn finish(reader: Reader<'_>, reencoded: &[u8], payload: &[u8]) -> Result<()> {
    reader.finish()?;
    if !bytes_equal(reencoded, payload) {
        return Err(ProtocolError::NotCanonical);
    }
    Ok(())
}

fn fixed<const N: usize>(field: &'static str, value: &[u8]) -> Result<[u8; N]> {
    value.try_into().map_err(|_| ProtocolError::FieldLength {
        field,
        expected: N,
        actual: value.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::to_hex;

    fn wrap_request() -> WrapRequest {
        WrapRequest {
            verifier_name: "Workstation".into(),
            file_name: "tax return.pdf".into(),
            plaintext_len: 100_000,
            container_binding: core::array::from_fn(|index| index as u8),
            data_key: vec![7; DATA_KEY_LEN],
        }
    }

    fn unwrap_request() -> UnwrapRequest {
        UnwrapRequest {
            verifier_name: "Workstation".into(),
            file_name: "tax return.pdf.balock".into(),
            plaintext_len: 100_000,
            container_binding: core::array::from_fn(|index| index as u8),
            credential_id: "locker-cred-1".into(),
            wrapper: vec![9; 60],
        }
    }

    #[test]
    fn a_wrap_request_pins_its_bytes() {
        assert_eq!(
            to_hex(&wrap_request().encode()),
            concat!(
                "86016b576f726b73746174696f6e6e7461782072657475726e2e7064661a0001",
                "86a05820000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
                "1c1d1e1f58200707070707070707070707070707070707070707070707070707",
                "070707070707"
            )
        );
        assert!(WrapRequest::decode(&wrap_request().encode()).expect("decode") == wrap_request());
    }

    #[test]
    fn every_payload_round_trips() {
        let response = WrapResponse {
            credential_id: "locker-cred-1".into(),
            wrapper: vec![3; 60],
        };
        assert!(WrapResponse::decode(&response.encode()).expect("decode") == response);
        assert!(
            UnwrapRequest::decode(&unwrap_request().encode()).expect("decode") == unwrap_request()
        );
        let key = UnwrapResponse {
            data_key: vec![5; DATA_KEY_LEN],
        };
        assert!(UnwrapResponse::decode(&key.encode()).expect("decode") == key);
    }

    #[test]
    fn a_payload_of_the_wrong_shape_is_not_read_as_another_one() {
        // The three requests share a session and differ only by operation, so
        // decoding must not be able to slide one into another's slot.
        assert!(WrapRequest::decode(&unwrap_request().encode()).is_err());
        assert!(UnwrapRequest::decode(&wrap_request().encode()).is_err());
        assert!(UnwrapResponse::decode(&wrap_request().encode()).is_err());
    }

    #[test]
    fn a_key_that_is_not_a_key_length_is_refused() {
        for length in [0, DATA_KEY_LEN - 1, DATA_KEY_LEN + 1] {
            // Written out rather than updated from a template: `WrapRequest`
            // wipes its key on drop, and a `Drop` type cannot be moved out of.
            let offered = WrapRequest {
                verifier_name: "Workstation".into(),
                file_name: "tax return.pdf".into(),
                plaintext_len: 0,
                container_binding: [0; SESSION_BINDING_LEN],
                data_key: vec![1; length],
            };
            assert!(matches!(
                offered.validate(),
                Err(ProtocolError::FieldLength {
                    field: "dataKey",
                    ..
                })
            ));
            let answered = UnwrapResponse {
                data_key: vec![1; length],
            };
            assert!(answered.validate().is_err());
        }
    }

    #[test]
    fn a_wrapper_that_is_empty_or_oversized_is_refused() {
        for length in [0, MAX_WRAPPER_BYTES + 1] {
            let offered = UnwrapRequest {
                wrapper: vec![1; length],
                ..unwrap_request()
            };
            assert!(matches!(
                offered.validate(),
                Err(ProtocolError::PayloadSize(_))
            ));
        }
    }

    #[test]
    fn an_unknown_schema_fails_closed() {
        let mut writer = Writer::new();
        writer.array(UNWRAP_RESPONSE_FIELDS);
        writer.uint(2);
        writer.bytes(&[0; DATA_KEY_LEN]);
        assert!(matches!(
            UnwrapResponse::decode(&writer.into_bytes()),
            Err(ProtocolError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn a_non_canonical_payload_is_refused() {
        let mut encoded = unwrap_request().encode();
        // Trailing bytes are the cheapest way to say "this is not the payload
        // that was agreed".
        encoded.push(0);
        assert!(UnwrapRequest::decode(&encoded).is_err());
    }

    #[test]
    fn operations_are_the_ones_the_envelope_will_accept() {
        for operation in [OPERATION_CREATE, OPERATION_UNLOCK, OPERATION_REKEY] {
            let frame = crate::ApplicationFrame {
                protocol_version: crate::PROTOCOL_VERSION,
                kind: crate::ApplicationFrameKind::Request,
                request_id: "request-1".into(),
                session_binding: [0; SESSION_BINDING_LEN],
                operation: operation.into(),
                issued_at_ms: 1_787_745_600_000,
                expires_at_ms: 1_787_745_660_000,
                payload: wrap_request().encode(),
            };
            frame
                .validate()
                .expect("the envelope accepts the operation");
        }
    }
}
