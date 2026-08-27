//! The PhoneAuth verifier: everything a desktop needs to ask a phone for an
//! authorization and to decide whether the answer is worth anything.
//!
//! Deliberately free of UI, IPC and transport implementations so that the same
//! logic runs in the background agent, in the CLI used by PAM, and in the
//! initrd binary that unlocks a disk before a desktop exists.
//!
//! The one invariant everything else serves: a [`verifier::Grant`] can only be
//! produced by a fresh, single-use, policy-permitted request that a paired
//! phone signed with a hardware-backed key over a confidential,
//! peer-authenticated session.

pub mod encoding;
pub mod pairing;
pub mod policy;
pub mod random;
pub mod replay;
pub mod session;
pub mod signature;
pub mod verifier;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use pairing::{CredentialPurpose, KeyKind, PairedCredential, PairedDevice, PairingStore};
pub use policy::Permission;
pub use session::{SecureSession, TransportSecurity};
pub use verifier::{
    AuthorizationError, Grant, PendingAuthorization, RequestSpec, Verifier, VerifierIdentity,
};
