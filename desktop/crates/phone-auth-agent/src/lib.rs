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
pub mod password;
pub mod paths;
pub mod qr_network;
pub mod secret_memory;
pub mod service;
#[cfg(feature = "dev-simulator")]
pub mod simulator;
pub mod transport;
pub mod vault;

pub use client::{AgentClient, ClientError};
pub use paths::Paths;
pub use service::{Service, ServiceError};
