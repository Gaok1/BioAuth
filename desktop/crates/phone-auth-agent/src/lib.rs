//! The PhoneAuth background agent, as a library.
//!
//! Exposed so that the CLI, the initrd helper and the integration tests speak
//! the agent's IPC protocol from shared types rather than from a second,
//! drifting copy of them.

pub mod api;
pub mod audit;
pub mod client;
pub mod config;
pub mod framing;
pub mod identity;
pub mod ipc;
pub mod paths;
pub mod qr_network;
pub mod service;
#[cfg(feature = "dev-simulator")]
pub mod simulator;
pub mod transport;

pub use client::{AgentClient, ClientError};
pub use paths::Paths;
pub use service::{Service, ServiceError};
