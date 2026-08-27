//! Transport registry.
//!
//! The agent does not care how frames travel; it cares whether a transport can
//! give it a confidential, peer-authenticated session right now. Transports
//! that are planned but not built report themselves as such, so the tray and
//! the CLI can say precisely what is missing instead of failing vaguely.

use std::sync::Arc;

use phone_auth_verifier::SecureSession;
use serde::Serialize;

/// Why a transport can or cannot be used at this moment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum TransportAvailability {
    /// Implemented and able to open a session.
    Ready,
    /// Implemented, but nothing to connect to right now, e.g. the Bluetooth
    /// adapter is off or the phone is out of range.
    Unavailable { reason: String },
    /// Not built in this version.
    Unimplemented {
        /// The concrete work this waits on, quoted in UI and CLI output.
        ///
        /// Renamed explicitly: `rename_all` on an enum applies to variant
        /// names, not to the fields inside them, so without this the payload
        /// would be the only snake_case key in the API.
        #[serde(rename = "blockedOn")]
        blocked_on: String,
    },
}

impl TransportAvailability {
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Opens sessions to paired authenticators.
///
/// `connect` takes `&self`: a listening transport is driven by inbound
/// connections on its own thread, so it needs interior mutability regardless,
/// and requiring `&mut` would stop the agent from holding a handle alongside
/// the registry.
pub trait Transport: Send + Sync {
    fn name(&self) -> &str;

    /// One line the user can read in the tray.
    fn description(&self) -> &str;

    fn availability(&self) -> TransportAvailability;

    /// Opens a session, or explains why not.
    fn connect(&self, device_id: &str) -> Result<Box<dyn SecureSession + Send>, String>;
}

/// Snapshot of one transport for the IPC status payload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportStatus {
    pub name: String,
    pub description: String,
    #[serde(flatten)]
    pub availability: TransportAvailability,
}

/// The transports this build knows about, in preference order.
pub struct TransportRegistry {
    transports: Vec<Arc<dyn Transport>>,
}

impl TransportRegistry {
    /// Builds the registry from the transports that are actually available.
    ///
    /// The unimplemented entries are listed deliberately rather than omitted:
    /// a user whose phone will not connect needs to see that BLE is not built
    /// yet, not an empty list that looks like a hardware fault.
    pub fn new(available: Vec<Arc<dyn Transport>>) -> Self {
        let mut transports = available;
        transports.push(Arc::new(PlannedTransport {
            name: "BleTransport",
            description: "Bluetooth Low Energy link to a paired phone",
            blocked_on:
                "mobile: BleTransport implementation over the shared handshake (roadmap phase 1A)",
        }));
        Self { transports }
    }

    pub fn status(&self) -> Vec<TransportStatus> {
        self.transports
            .iter()
            .map(|transport| TransportStatus {
                name: transport.name().to_owned(),
                description: transport.description().to_owned(),
                availability: transport.availability(),
            })
            .collect()
    }

    pub fn has_ready_transport(&self) -> bool {
        self.transports
            .iter()
            .any(|transport| transport.availability().is_ready())
    }

    /// Opens a session over the first ready transport.
    pub fn connect(&self, device_id: &str) -> Result<Box<dyn SecureSession + Send>, String> {
        let transport = self
            .transports
            .iter()
            .find(|transport| transport.availability().is_ready())
            .ok_or_else(|| {
                "no transport can reach a phone yet; see `transports` in `phone-auth status`"
                    .to_owned()
            })?;
        transport.connect(device_id)
    }
}

/// A transport that is designed but not implemented.
///
/// Present so that its absence is visible and attributable rather than silent.
struct PlannedTransport {
    name: &'static str,
    description: &'static str,
    blocked_on: &'static str,
}

impl Transport for PlannedTransport {
    fn name(&self) -> &str {
        self.name
    }

    fn description(&self) -> &str {
        self.description
    }

    fn availability(&self) -> TransportAvailability {
        TransportAvailability::Unimplemented {
            blocked_on: self.blocked_on.to_owned(),
        }
    }

    fn connect(&self, _device_id: &str) -> Result<Box<dyn SecureSession + Send>, String> {
        Err(format!(
            "{} is not implemented: {}",
            self.name, self.blocked_on
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registry_with_nothing_available_has_nothing_ready() {
        let registry = TransportRegistry::new(Vec::new());
        assert!(!registry.has_ready_transport());
    }

    #[test]
    fn planned_transports_are_listed_with_what_blocks_them() {
        let registry = TransportRegistry::new(Vec::new());
        let status = registry.status();

        assert!(!status.is_empty(), "planned transports stay visible");
        for entry in &status {
            match &entry.availability {
                TransportAvailability::Unimplemented { blocked_on } => {
                    assert!(
                        blocked_on.contains("mobile"),
                        "`{}` must name the mobile work it waits on",
                        entry.name
                    );
                }
                other => panic!("expected an unimplemented transport, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_status_payload_uses_camel_case_throughout() {
        // The UI and the CLI read these keys directly.
        let registry = TransportRegistry::new(Vec::new());
        let json = serde_json::to_string(&registry.status()).expect("serialize");
        assert!(json.contains("\"blockedOn\""), "{json}");
        assert!(!json.contains("blocked_on"), "{json}");
        assert!(json.contains("\"state\":\"unimplemented\""), "{json}");
    }

    #[test]
    fn connecting_without_a_ready_transport_explains_itself() {
        let registry = TransportRegistry::new(Vec::new());
        // `Box<dyn SecureSession>` has no `Debug`, so unwrap by hand.
        match registry.connect("phone-1") {
            Ok(_) => panic!("a registry with no ready transport must not connect"),
            Err(error) => assert!(error.contains("no transport"), "{error}"),
        }
    }
}
