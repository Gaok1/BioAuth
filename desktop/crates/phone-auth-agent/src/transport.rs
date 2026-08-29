//! Transport registry.
//!
//! The agent does not care how frames travel; it cares whether a transport can
//! give it a confidential, peer-authenticated session right now. Transports
//! that are planned but not built report themselves as such, so the tray and
//! the CLI can say precisely what is missing instead of failing vaguely.

use std::collections::HashMap;
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

    /// Mirrors paired device ids to session identity keys for inbound links.
    /// Outbound transports do not need the map and keep the default no-op.
    fn set_known_peers(&self, _peers: HashMap<String, Vec<u8>>) {}

    /// Opens the session that device opened for `credential_id`, or explains
    /// why not.
    ///
    /// The credential is part of the address, not a filter applied afterwards.
    /// A phone runs one connection per credential and refuses a request naming
    /// a different one, so a session picked without regard to the credential
    /// produces a denial the user never made rather than a wrong answer.
    fn connect(
        &self,
        device_id: &str,
        credential_id: &str,
    ) -> Result<Box<dyn SecureSession + Send>, String>;
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
        if !transports
            .iter()
            .any(|transport| transport.name() == "BleTransport")
        {
            transports.push(Arc::new(PlannedTransport {
                name: "BleTransport",
                description: "Bluetooth Low Energy link to a paired phone",
                blocked_on: "a supported desktop GATT peripheral (Linux BlueZ is implemented)",
            }));
        }
        Self { transports }
    }

    pub fn set_known_peers(&self, peers: HashMap<String, Vec<u8>>) {
        for transport in &self.transports {
            transport.set_known_peers(peers.clone());
        }
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
    pub fn connect(
        &self,
        device_id: &str,
        credential_id: &str,
    ) -> Result<Box<dyn SecureSession + Send>, String> {
        let ready: Vec<_> = self
            .transports
            .iter()
            .filter(|transport| transport.availability().is_ready())
            .collect();
        if ready.is_empty() {
            return Err(
                "no transport can reach a phone yet; see `transports` in `phone-auth status`"
                    .to_owned(),
            );
        }

        let mut errors = Vec::new();
        for transport in ready {
            match transport.connect(device_id, credential_id) {
                Ok(session) => return Ok(session),
                Err(error) => errors.push(format!("{}: {error}", transport.name())),
            }
        }
        Err(errors.join("; "))
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

    fn connect(
        &self,
        _device_id: &str,
        _credential_id: &str,
    ) -> Result<Box<dyn SecureSession + Send>, String> {
        Err(format!(
            "{} is not implemented: {}",
            self.name, self.blocked_on
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingTransport(&'static str);

    impl Transport for FailingTransport {
        fn name(&self) -> &str {
            self.0
        }

        fn description(&self) -> &str {
            self.0
        }

        fn availability(&self) -> TransportAvailability {
            TransportAvailability::Ready
        }

        fn connect(
            &self,
            _device_id: &str,
            _credential_id: &str,
        ) -> Result<Box<dyn SecureSession + Send>, String> {
            Err(format!("{} cannot reach it", self.0))
        }
    }

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
                        blocked_on.contains("desktop") || blocked_on.contains("BlueZ"),
                        "`{}` must name the platform support it waits on",
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
        match registry.connect("phone-1", "credential-1") {
            Ok(_) => panic!("a registry with no ready transport must not connect"),
            Err(error) => assert!(error.contains("no transport"), "{error}"),
        }
    }

    #[test]
    fn connection_attempts_every_ready_transport() {
        let registry = TransportRegistry::new(vec![
            Arc::new(FailingTransport("first")),
            Arc::new(FailingTransport("second")),
        ]);
        let error = match registry.connect("phone-1", "credential-1") {
            Ok(_) => panic!("both transports fail"),
            Err(error) => error,
        };
        assert!(error.contains("first"), "{error}");
        assert!(error.contains("second"), "{error}");
        // Attempt order is the registration order. The service relies on it to
        // keep BLE's ten-second wait behind the LAN transport.
        assert!(
            error.find("first") < error.find("second"),
            "transports are tried in registration order: {error}"
        );
    }
}
