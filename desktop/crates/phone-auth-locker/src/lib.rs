//! The File Locker container: one encrypted file, one data key, two ways back.
//!
//! The phone authorizes unwrapping the data key. It never holds the ciphertext
//! and is never needed to read a container whose offline recovery code the user
//! still has. Everything here runs on the desktop; the format is specified in
//! `docs/locker-format.md` and that document is the contract, not this comment.
//!
//! Nothing in this crate logs, prints, or `Debug`-formats key material. The
//! data key is a [`Dek`], which exists to make that hard to get wrong by
//! accident.

mod engine;
mod format;
mod recovery;
mod secret;
mod stream;

pub use engine::{
    inspect, lock_file, rekey_file, unlock_file, KeyCustodian, LockOutcome, LockPlan, LockerInfo,
    UnlockKey, UnlockOutcome, UnwrapRequest, WrapRequest, WrapperInfo,
};
pub use format::{
    binding_of, wrapper_aad, CoreHeader, Metadata, Wrapper, WrapperKind, CHUNK_SIZE,
    CONTAINER_VERSION, LOCKER_EXTENSION, MAX_WRAPPERS,
};
pub use recovery::{format_recovery_code, parse_recovery_code, RecoveryKey};
pub use secret::Dek;

use core::fmt;

/// Everything that can go wrong while reading or writing a container.
///
/// Deliberately coarse about *why* a tag failed: "this byte was wrong" is a
/// useful message for a debugger and an oracle for an attacker, and the user
/// can do exactly the same thing in either case.
#[derive(Debug)]
pub enum LockerError {
    Io(std::io::Error),
    /// The file is not a locker container at all.
    NotAContainer,
    /// A container of a version this build does not understand.
    UnsupportedVersion(u8),
    /// The header decoded but broke a structural rule.
    Malformed(&'static str),
    /// A section exceeded its documented limit before anything was allocated.
    TooLarge {
        section: &'static str,
        limit: usize,
    },
    /// Authentication failed: the container, or the key, is not what it claims.
    Corrupt,
    /// No wrapper of the kind this operation needs.
    NoWrapper(WrapperKind),
    /// The recovery code was not well formed.
    BadRecoveryCode,
    /// The name inside the container could not be used as a file name.
    UnsafeName,
    /// The destination already exists. The locker never writes over a file.
    DestinationExists(std::path::PathBuf),
    /// The input changed size while it was being read.
    InputChanged,
    /// The phone declined, was unreachable, or answered something the desktop
    /// could not use. Carries a message meant for a person, never a key.
    Denied(String),
}

impl fmt::Display for LockerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::NotAContainer => f.write_str("not a locker container"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported container version: {version}")
            }
            Self::Malformed(reason) => write!(f, "malformed container: {reason}"),
            Self::TooLarge { section, limit } => {
                write!(f, "container {section} exceeds the {limit} byte limit")
            }
            Self::Corrupt => f.write_str("container failed authentication"),
            Self::NoWrapper(kind) => match kind {
                WrapperKind::Phone => f.write_str("this container has no phone wrapper"),
                WrapperKind::Recovery => f.write_str("this container has no recovery wrapper"),
            },
            Self::BadRecoveryCode => f.write_str("invalid recovery code"),
            Self::UnsafeName => f.write_str("container holds an unusable file name"),
            Self::DestinationExists(path) => write!(f, "{} already exists", path.display()),
            Self::InputChanged => f.write_str("the file changed while it was being read"),
            Self::Denied(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for LockerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for LockerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<phone_auth_protocol::cbor::CborError> for LockerError {
    fn from(_: phone_auth_protocol::cbor::CborError) -> Self {
        Self::Malformed("invalid CBOR")
    }
}

pub type Result<T> = core::result::Result<T, LockerError>;
