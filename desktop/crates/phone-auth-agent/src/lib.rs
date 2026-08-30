//! The PhoneAuth background agent, as a library.
//!
//! Exposed so that the CLI, the initrd helper and the integration tests speak
//! the agent's IPC protocol from shared types rather than from a second,
//! drifting copy of them.

pub mod api;
pub mod audit;
#[cfg(target_os = "linux")]
pub mod ble;
pub mod ble_framing;
pub mod client;
pub mod clipboard;
pub mod config;
pub mod framing;
pub mod identity;
pub mod ipc;
pub mod locker;
pub mod luks;
pub mod password;
pub mod paths;
pub mod private_files;
pub mod qr_network;
pub mod secret_memory;
pub mod service;
#[cfg(feature = "dev-simulator")]
pub mod simulator;
pub mod ssh_agent;
pub mod ssh_client;
pub mod ssh_policy;
pub mod ssh_session;
pub mod transport;
pub mod vault;

/// How much longer than a request's own deadline this side keeps listening.
///
/// A request carries `expires_at_ms` and the answer is refused once that has
/// passed -- `ApplicationFrame::is_reply_to` checks it. So the only honest
/// receive timeout is the request's remaining validity plus the time an answer
/// needs to come back over the link.
///
/// Every path here used to wait a flat ninety seconds against requests stamped
/// valid for a hundred and twenty, hanging up thirty seconds before this side's
/// own deadline. A person who reached their phone at a hundred seconds -- well
/// inside the window this machine had granted -- approved, the phone unlocked
/// the secret and wrote it into a socket that was already closed, and the
/// desktop reported the phone as unavailable. Nothing on either screen said
/// the answer had been thrown away for being early.
pub(crate) const ANSWER_TRAVEL_MARGIN: std::time::Duration = std::time::Duration::from_secs(15);

pub use client::{AgentClient, ClientError};
pub use paths::Paths;
pub use service::{Service, ServiceError};
