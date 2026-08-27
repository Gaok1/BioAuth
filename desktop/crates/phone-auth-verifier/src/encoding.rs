//! Hex and base64url helpers.
//!
//! These live in `phone-auth-protocol` so that the session crate can use them
//! without depending on this one — the verifier consumes the `SecureSession`
//! abstraction, and an edge pointing the other way would make the abstraction
//! depend on one of its implementations.
//!
//! Re-exported here because the agent, the CLI and the pairing store all reach
//! for `phone_auth_verifier::encoding`.

pub use phone_auth_protocol::encoding::*;
