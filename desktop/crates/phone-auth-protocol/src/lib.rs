//! The PhoneAuth wire format, as consumed by a verifier.
//!
//! This crate owns the exact protocol bytes shared with the phone. Authorization
//! requests are biometric-signature payloads; application frames are instead
//! authenticated and encrypted by the secure session. Every rule has a Dart
//! counterpart, so both sides must be changed together.
//!
//! Nothing in this crate performs I/O, allocates a transport, or knows what a
//! Bluetooth address is. A frame is a byte string; where it came from is the
//! caller's problem, and never contributes to identity.

mod application;
mod attach;
pub mod cbor;
pub mod encoding;
mod enrolment;
pub mod locker;
mod request;
mod response;
pub mod ssh;
pub mod vault;

pub use application::{
    ApplicationErrorCode, ApplicationFrame, ApplicationFrameKind, MAX_APPLICATION_PAYLOAD_BYTES,
};
pub use attach::SessionAttach;
pub use enrolment::{CredentialPurpose, Enrolment, KeyKind};
pub use request::{AuthRequest, RequestContext};
pub use response::{AuthResponse, Decision};

use core::fmt;

/// The only protocol version this build speaks. Unknown versions fail closed.
pub const PROTOCOL_VERSION: u64 = 1;

/// Upper bound on a single frame, matching the Dart codec and the Android
/// plugin's payload guard.
pub const MAX_FRAME_BYTES: usize = 8192;

/// Length of the verifier-generated challenge, in bytes.
pub const CHALLENGE_LEN: usize = 32;

/// Length of the handshake-derived session binding, in bytes.
pub const SESSION_BINDING_LEN: usize = 32;

/// Longest validity window a request may declare.
pub const MAX_VALIDITY_MS: i64 = 120_000;

/// Signature algorithm identifier produced by the Android authenticator.
///
/// The string is Android's JCA name; on the wire it means ECDSA over P-256
/// with SHA-256 and an ASN.1 DER encoded signature.
pub const ALGORITHM_ECDSA_P256_SHA256: &str = "SHA256withECDSA";

/// Public key encoding identifier produced by the Android authenticator:
/// an X.509 SubjectPublicKeyInfo DER document over the P-256 curve.
pub const PUBLIC_KEY_EC_P256_SPKI: &str = "EC_P256_SPKI";

const MESSAGE_TYPE_REQUEST: u64 = 1;
const MESSAGE_TYPE_RESPONSE: u64 = 2;
const MESSAGE_TYPE_ENROLMENT: u64 = 3;
const MESSAGE_TYPE_APPLICATION: u64 = 4;
const MESSAGE_TYPE_ATTACH: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Cbor(cbor::CborError),
    /// Frame was empty or exceeded [`MAX_FRAME_BYTES`].
    FrameSize(usize),
    /// The array did not have the element count this message type requires.
    FrameShape {
        expected: u64,
        actual: u64,
    },
    UnsupportedVersion(u64),
    UnexpectedMessageType(u64),
    FieldEmpty(&'static str),
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    FieldLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// `expiresAt` was not after `issuedAt`, or the window exceeded two minutes.
    ValidityWindow,
    /// The frame decoded, but re-encoding it did not reproduce the input.
    NotCanonical,
    InvalidDecision(i64),
    /// An authorized response carried no algorithm or no signature.
    MissingProof,
    InvalidKeyKind(i64),
    InvalidPurpose(i64),
    InvalidApplicationKind(u64),
    InvalidApplicationError(u64),
    InvalidOperation,
    PayloadSize(usize),
    /// A vault item declared a kind this build does not know.
    InvalidItemKind(u64),
    /// A vault message carried revision zero. Revisions start at one, so this
    /// is a caller that never read the item it is trying to replace.
    InvalidRevision,
    /// A field reserved for a future version was not zero. Fails closed rather
    /// than ignoring a value this build does not understand.
    InvalidReservedField(u64),
    /// A length-prefixed field claimed more bytes than the input holds.
    ///
    /// Distinct from [`Self::FrameSize`]: that one is a frame outside its
    /// bounds, and this is a frame that ended mid-field. Reporting either as
    /// the other sends whoever reads the log looking at the wrong thing.
    UnexpectedEnd,
    /// A field that must be UTF-8 was not.
    InvalidText(&'static str),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => write!(f, "{error}"),
            Self::FrameSize(size) => write!(f, "invalid frame size: {size} bytes"),
            Self::FrameShape { expected, actual } => {
                write!(f, "expected a {expected}-element frame, got {actual}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported protocol version: {version}")
            }
            Self::UnexpectedMessageType(kind) => write!(f, "unexpected message type: {kind}"),
            Self::FieldEmpty(field) => write!(f, "field `{field}` is empty"),
            Self::FieldTooLong { field, max, actual } => {
                write!(f, "field `{field}` is {actual} units, maximum is {max}")
            }
            Self::FieldLength {
                field,
                expected,
                actual,
            } => write!(f, "field `{field}` must be {expected} bytes, got {actual}"),
            Self::ValidityWindow => f.write_str("invalid request validity window"),
            Self::NotCanonical => f.write_str("frame is not canonical CBOR"),
            Self::InvalidDecision(value) => write!(f, "invalid authorization decision: {value}"),
            Self::MissingProof => {
                f.write_str("authorized response carried no algorithm or signature")
            }
            Self::InvalidKeyKind(value) => write!(f, "invalid key kind: {value}"),
            Self::InvalidPurpose(value) => write!(f, "invalid credential purpose: {value}"),
            Self::InvalidApplicationKind(value) => {
                write!(f, "invalid application frame kind: {value}")
            }
            Self::InvalidApplicationError(value) => {
                write!(f, "invalid application error code: {value}")
            }
            Self::InvalidOperation => f.write_str("invalid application operation"),
            Self::UnexpectedEnd => f.write_str("input ended inside a length-prefixed field"),
            Self::InvalidText(field) => write!(f, "field `{field}` is not UTF-8"),
            Self::PayloadSize(size) => write!(f, "invalid application payload size: {size}"),
            Self::InvalidReservedField(value) => {
                write!(f, "reserved field must be zero, got {value}")
            }
            Self::InvalidItemKind(kind) => write!(f, "unknown vault item kind: {kind}"),
            Self::InvalidRevision => f.write_str("vault revision must start at one"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<cbor::CborError> for ProtocolError {
    fn from(error: cbor::CborError) -> Self {
        Self::Cbor(error)
    }
}

pub(crate) type Result<T> = core::result::Result<T, ProtocolError>;

/// Counts UTF-16 code units.
///
/// Dart's `String.length` is a UTF-16 code unit count, so a field that Dart
/// accepts at exactly its limit must be measured the same way here. Counting
/// `char`s instead would let an astral-plane string past a bound the phone
/// enforces, or reject one it allows.
pub(crate) fn utf16_len(value: &str) -> usize {
    value.chars().map(char::len_utf16).sum()
}

/// Applies the shared "non-blank, bounded length" rule for text fields.
pub(crate) fn check_text(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(ProtocolError::FieldEmpty(field));
    }
    let actual = utf16_len(value);
    if actual > max {
        return Err(ProtocolError::FieldTooLong { field, max, actual });
    }
    Ok(())
}

/// Rejects frames that are empty or larger than the protocol maximum before
/// any parsing work happens.
pub(crate) fn check_frame_size(frame: &[u8]) -> Result<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameSize(frame.len()));
    }
    Ok(())
}

/// Constant-time-ish byte equality used for canonicality checks.
///
/// These comparisons are over public frame bytes, not secrets, so this exists
/// for clarity rather than for side-channel resistance.
pub(crate) fn bytes_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(a, b)| a == b)
}
