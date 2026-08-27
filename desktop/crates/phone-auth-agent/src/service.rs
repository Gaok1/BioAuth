//! Agent state and the operations the IPC surface exposes.
//!
//! Everything here runs behind one mutex. The work is short — build a request,
//! wait for one answer, check a signature — and a single lock keeps the replay
//! guard and the pairing store consistent without a scheduler.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use phone_auth_session::ServerBootstrap;

use crate::api::PairingProposalSummary;
use crate::qr_network::QrNetworkTransport;

use phone_auth_verifier::pairing::{CredentialPurpose, PairedDevice};
use phone_auth_verifier::policy::{self, Permission};
use phone_auth_verifier::verifier::{now_ms, AuthorizationError};
use phone_auth_verifier::{
    encoding, random, PairingStore, RequestSpec, Verifier, VerifierIdentity,
};

use crate::api::{
    AuthorizeParams, AuthorizeResult, CredentialSummary, DeviceSummary, Event, PairingBootstrap,
    PermissionSummary, StatusPayload, WebAuthnParams, WebAuthnResult,
};
use crate::audit::{AuditEntry, AuditLog, Outcome};
use crate::config::AgentConfig;
use crate::paths::Paths;
use crate::transport::{Transport, TransportAvailability, TransportRegistry};

/// How long a pairing bootstrap stays scannable.
const PAIRING_WINDOW_MS: i64 = 120_000;

/// How long to wait for a phone to answer before giving up on the session.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    /// Stable code the CLI turns into an exit status.
    pub code: &'static str,
    pub message: String,
}

impl ServiceError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

pub struct Service {
    config: AgentConfig,
    paths: Paths,
    verifier: Verifier,
    transports: TransportRegistry,
    /// The listening transport, held directly so that pairing can arm a code
    /// on it. `None` on a build or platform where it could not bind.
    network: Option<Arc<QrNetworkTransport>>,
    /// A completed pairing handshake waiting for the user to confirm its code.
    ///
    /// Behind its own lock so the UI can poll for it without taking the
    /// service lock, which may be held for the length of an authorization.
    held_proposal: Mutex<Option<crate::qr_network::PairingProposal>>,
    audit: AuditLog,
    development_mode: bool,
    subscribers: Vec<Sender<Event>>,
}

impl Service {
    pub fn new(
        config: AgentConfig,
        paths: Paths,
        network: Option<Arc<QrNetworkTransport>>,
        mut additional_transports: Vec<Arc<dyn Transport>>,
        development_mode: bool,
    ) -> Result<Self, ServiceError> {
        let store = PairingStore::load(paths.pairing_file())
            .map_err(|error| ServiceError::new("store-unreadable", error.to_string()))?;
        let identity = VerifierIdentity {
            verifier_id: config.verifier_id.clone(),
            verifier_name: config.verifier_name.clone(),
        };
        let audit = AuditLog::new(paths.audit_file());

        // The registry tries transports in order, and BLE's connect waits ten
        // seconds for the phone to park a session. Putting the LAN transport
        // first keeps that wait off the common path and mirrors the phone,
        // which also treats the network as primary and BLE as the fallback.
        if let Some(network) = network.clone() {
            additional_transports.insert(0, network as Arc<dyn Transport>);
        }

        let service = Self {
            verifier: Verifier::new(identity, store),
            transports: TransportRegistry::new(additional_transports),
            network,
            held_proposal: Mutex::new(None),
            audit,
            development_mode,
            subscribers: Vec::new(),
            config,
            paths,
        };
        service.publish_known_peers();
        Ok(service)
    }

    /// Mirrors the paired devices into the transport.
    ///
    /// The listener needs to know which session identity belongs to which
    /// device to authenticate an inbound connection, and it must be able to do
    /// that without locking the service — the service may be blocked waiting
    /// on that very connection.
    fn publish_known_peers(&self) {
        let peers = self
            .verifier
            .store()
            .devices()
            .map(|device| {
                (
                    device.device_id.clone(),
                    device.session_identity_public_key.clone(),
                )
            })
            .collect();
        self.transports.set_known_peers(peers);
    }

    pub fn development_mode(&self) -> bool {
        self.development_mode
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Registers a client for event pushes.
    pub fn subscribe(&mut self) -> Receiver<Event> {
        let (sender, receiver) = mpsc::channel();
        self.subscribers.push(sender);
        receiver
    }

    /// Sends an event to every live subscriber, dropping closed ones.
    fn broadcast(&mut self, event: Event) {
        self.subscribers
            .retain(|subscriber| subscriber.send(event.clone()).is_ok());
    }

    pub fn status(&self) -> StatusPayload {
        let transports = self.transports.status();
        let blocked_on = transports
            .iter()
            .filter_map(|transport| match &transport.availability {
                TransportAvailability::Unimplemented { blocked_on } => {
                    Some(format!("{}: {}", transport.name, blocked_on))
                }
                _ => None,
            })
            .collect();

        StatusPayload {
            verifier_id: self.config.verifier_id.clone(),
            verifier_name: self.config.verifier_name.clone(),
            development_mode: self.development_mode,
            paired_devices: self.devices(),
            can_authorize: self.transports.has_ready_transport()
                && !self.verifier.store().is_empty(),
            transports,
            blocked_on,
        }
    }

    pub fn devices(&self) -> Vec<DeviceSummary> {
        self.verifier
            .store()
            .devices()
            .map(|device| DeviceSummary {
                device_id: device.device_id.clone(),
                display_name: device.display_name.clone(),
                paired_at_ms: device.paired_at_ms,
                credentials: device
                    .credentials
                    .iter()
                    .map(|credential| CredentialSummary {
                        credential_id: credential.credential_id.clone(),
                        key_kind: format!("{:?}", credential.key_kind),
                        purpose: format!("{:?}", credential.purpose),
                        usable_at_boot: credential.key_kind.allowed_at_boot()
                            && credential.purpose == CredentialPurpose::DiskUnlock,
                        permissions: credential
                            .permissions
                            .iter()
                            .map(|permission| PermissionSummary {
                                service: permission.service.clone(),
                                action: permission.action.clone(),
                                resource: permission.resource.clone(),
                                user: permission.user.clone(),
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect()
    }

    pub fn forget(&mut self, device_id: &str) -> Result<(), ServiceError> {
        self.verifier
            .store_mut()
            .remove(device_id)
            .map_err(|error| ServiceError::new("unknown-device", error.to_string()))?;
        self.broadcast(Event::DevicesChanged);
        Ok(())
    }

    /// Replaces a credential's permissions.
    ///
    /// Narrowing takes effect immediately, including for a request already in
    /// flight, because the verifier re-checks policy when the answer arrives.
    pub fn set_permissions(
        &mut self,
        device_id: &str,
        credential_id: &str,
        permissions: Vec<PermissionSummary>,
    ) -> Result<(), ServiceError> {
        let mut device = self
            .verifier
            .store()
            .device(device_id)
            .cloned()
            .ok_or_else(|| {
                ServiceError::new("unknown-device", format!("no device `{device_id}`"))
            })?;

        let credential = device
            .credentials
            .iter_mut()
            .find(|credential| credential.credential_id == credential_id)
            .ok_or_else(|| {
                ServiceError::new(
                    "unknown-credential",
                    format!("no credential `{credential_id}` on `{device_id}`"),
                )
            })?;

        credential.permissions = permissions
            .into_iter()
            .map(|permission| Permission {
                service: permission.service,
                action: permission.action,
                resource: permission.resource,
                user: permission.user,
            })
            .collect();

        self.verifier
            .store_mut()
            .insert(device)
            .map_err(|error| ServiceError::new("store-write-failed", error.to_string()))?;
        self.broadcast(Event::DevicesChanged);
        Ok(())
    }

    /// Puts a pairing code on screen and arms the listener to accept it.
    ///
    /// The code commits to this agent's handshake identity, which is what lets
    /// the phone tell this desktop from a relay on first contact. It carries no
    /// secret: losing the picture lets someone attempt a pairing, not complete
    /// one, because the user still has to confirm the verification code.
    pub fn begin_pairing(&mut self) -> Result<PairingBootstrap, ServiceError> {
        let network = self.network.as_ref().ok_or_else(|| {
            ServiceError::new(
                "no-transport",
                "no listening transport, so a phone would have nowhere to connect",
            )
        })?;

        // Resolved here rather than carried from startup: the answer changes
        // when the machine changes network, and a code naming an address this
        // machine no longer answers on fails with no way for the user to tell
        // why.
        let address = crate::qr_network::advertised_address().map_err(|error| {
            ServiceError::new(
                "no-address",
                format!(
                    "this computer has no usable address on the local network, \
                     so a phone would have nowhere to connect: {error}"
                ),
            )
        })?;
        let endpoint = format!("{address}:{}", network.port());

        let bootstrap = ServerBootstrap::new(
            random::session_id(),
            self.config.verifier_id.clone(),
            endpoint,
            network.identity(),
            now_ms(),
            PAIRING_WINDOW_MS,
        )
        .map_err(|error| ServiceError::new("pairing-failed", error.to_string()))?;

        network.arm_pairing(bootstrap.clone());

        Ok(PairingBootstrap {
            protocol_version: phone_auth_protocol::PROTOCOL_VERSION,
            verifier_id: bootstrap.verifier_id.clone(),
            verifier_name: self.config.verifier_name.clone(),
            session_id: bootstrap.session_id.clone(),
            nonce: encoding::to_base64url(&bootstrap.nonce),
            expires_at_ms: bootstrap.expires_at_ms,
            endpoint: bootstrap.endpoint.clone(),
            qr_payload: bootstrap.to_uri(),
            blocked_on: None,
        })
    }

    pub fn cancel_pairing(&self) {
        if let Some(network) = &self.network {
            network.cancel_pairing();
        }
    }

    /// Reports a pairing that completed its handshake and is awaiting
    /// confirmation.
    pub fn pending_pairing(&self) -> Option<PairingProposalSummary> {
        let network = self.network.as_ref()?;
        let proposal = network.take_proposal()?;
        let summary = PairingProposalSummary::from_proposal(&proposal);
        // Taking it out of the transport would lose it if the UI polls twice,
        // so hold it here until the user answers.
        self.hold_proposal(proposal);
        Some(summary)
    }

    fn hold_proposal(&self, proposal: crate::qr_network::PairingProposal) {
        *self.held_proposal.lock().expect("proposal mutex") = Some(proposal);
    }

    /// Stores a confirmed pairing.
    ///
    /// Called only after the user has said the verification code matches what
    /// the phone shows. Until then nothing about the peer is trusted: the
    /// handshake proved possession of *a* key, not that it belongs to the
    /// phone in the user's hand.
    pub fn confirm_pairing(&mut self, expected_code: &str) -> Result<(), ServiceError> {
        let proposal = self
            .held_proposal
            .lock()
            .expect("proposal mutex")
            .take()
            .ok_or_else(|| {
                ServiceError::new("no-pairing", "no pairing is awaiting confirmation")
            })?;

        if proposal.verification_code != expected_code {
            return Err(ServiceError::new(
                "code-mismatch",
                "the confirmation code does not match the one from the handshake",
            ));
        }

        let device = PairedDevice {
            device_id: proposal.device_id,
            display_name: proposal.device_name,
            paired_at_ms: now_ms(),
            session_identity_public_key: proposal.session_identity_spki,
            credentials: vec![phone_auth_verifier::PairedCredential {
                credential_id: proposal.credential_id,
                algorithm: proposal.algorithm,
                public_key: proposal.credential_public_key,
                key_kind: map_key_kind(proposal.key_kind),
                purpose: map_purpose(proposal.purpose),
                // A freshly paired credential authorizes nothing. The user
                // grants permissions deliberately, from the tray.
                permissions: Vec::new(),
            }],
        };

        self.install_pairing(device)
    }

    /// Installs a pairing record directly. A real pairing arrives through
    /// [`Self::confirm_pairing`]; this is the shared tail of that path.
    pub fn install_pairing(&mut self, device: PairedDevice) -> Result<(), ServiceError> {
        self.verifier
            .store_mut()
            .insert(device)
            .map_err(|error| ServiceError::new("pairing-rejected", error.to_string()))?;
        self.publish_known_peers();
        self.broadcast(Event::DevicesChanged);
        Ok(())
    }

    pub fn audit_recent(&self, limit: usize) -> Vec<AuditEntry> {
        self.audit.recent(limit.min(500))
    }

    /// Runs one full authorization: pick a credential, open a session, ask,
    /// and check the answer.
    pub fn authorize(&mut self, params: &AuthorizeParams) -> Result<AuthorizeResult, ServiceError> {
        let (device_id, credential_id) = self.select_credential(params)?;

        let mut session = self
            .transports
            .connect(&device_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;

        let spec = RequestSpec::new(
            credential_id,
            params.service.clone(),
            params.action.clone(),
            params.resource.clone(),
            params.user.clone(),
        )
        .with_validity_ms(self.config.request_validity_ms);

        let pending = self
            .verifier
            .issue(&spec, session.as_ref(), now_ms())
            .map_err(authorization_error)?;

        let device_name = self
            .verifier
            .store()
            .device(&device_id)
            .map(|device| device.display_name.clone())
            .unwrap_or_else(|| device_id.clone());
        let development = session.security().is_development;
        let request = pending.request().clone();

        self.broadcast(Event::RequestStarted {
            request_id: request.request_id.clone(),
            service: request.service.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            user: request.user.clone(),
            device_name: device_name.clone(),
            origin: pending.origin().to_owned(),
            expires_at_ms: request.expires_at_ms,
            development,
        });

        let outcome = self.exchange(&mut session, pending);
        let _ = session.close();

        match outcome {
            Ok(grant) => {
                let entry = AuditEntry::granted(&grant, development);
                // A failed audit write must not undo a decision the user
                // already made on their phone.
                if let Err(error) = self.audit.append(&entry) {
                    eprintln!("phone-auth-agent: could not write audit entry: {error}");
                }
                self.broadcast(Event::RequestFinished {
                    request_id: grant.request_id.clone(),
                    granted: true,
                    reason: None,
                });
                Ok(AuthorizeResult {
                    granted: true,
                    request_id: grant.request_id,
                    device_name,
                    origin: grant.origin,
                    development,
                })
            }
            Err(error) => {
                let entry = AuditEntry {
                    at_ms: now_ms(),
                    outcome: if error.code == "declined" {
                        Outcome::Denied
                    } else {
                        Outcome::Failed
                    },
                    request_id: request.request_id.clone(),
                    service: request.service.clone(),
                    action: request.action.clone(),
                    resource: request.resource.clone(),
                    user: request.user.clone(),
                    device_name: device_name.clone(),
                    origin: String::new(),
                    detail: Some(error.message.clone()),
                    development,
                };
                if let Err(write_error) = self.audit.append(&entry) {
                    eprintln!("phone-auth-agent: could not write audit entry: {write_error}");
                }
                self.broadcast(Event::RequestFinished {
                    request_id: request.request_id,
                    granted: false,
                    reason: Some(error.message.clone()),
                });
                Err(error)
            }
        }
    }

    /// Relays a browser WebAuthn operation over an already authenticated phone
    /// session. The browser extension's origin claim is shown on the phone and
    /// validated there against the RP ID; it is not upgraded into session identity.
    pub fn perform_webauthn(
        &mut self,
        params: &WebAuthnParams,
    ) -> Result<WebAuthnResult, ServiceError> {
        if !matches!(params.operation.as_str(), "create" | "get")
            || params.origin.len() > 2048
            || !params.origin.starts_with("https://")
            || params.origin.chars().any(char::is_whitespace)
            || !params.options.is_object()
        {
            return Err(ServiceError::new("bad-request", "invalid WebAuthn request"));
        }
        let encoded_options = serde_json::to_vec(&params.options)
            .map_err(|_| ServiceError::new("bad-request", "invalid WebAuthn options"))?;
        if encoded_options.len() > 6000 {
            return Err(ServiceError::new(
                "bad-request",
                "WebAuthn options exceed the relay limit",
            ));
        }

        let device_id = self.select_webauthn_device(params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        if !session.security().suitable_for_authorization() {
            let _ = session.close();
            return Err(ServiceError::new(
                "channel-unsuitable",
                "desktop passkeys require an authenticated confidential session",
            ));
        }

        let request_id = random::request_id();
        let envelope = serde_json::json!({
            "version": 1,
            "type": "webauthn.request",
            "requestId": request_id,
            "verifierId": self.config.verifier_id,
            "operation": params.operation,
            "origin": params.origin,
            "options": params.options,
        });
        let frame = webauthn_frame(&envelope)?;
        let result = (|| {
            session
                .send(&frame)
                .map_err(|error| ServiceError::new("transport-failed", error.to_string()))?;
            let response = session
                .receive(RECEIVE_TIMEOUT)
                .map_err(|error| ServiceError::new("transport-failed", error.to_string()))?;
            decode_webauthn_response(&response, &request_id)
        })();
        let _ = session.close();
        result.map(|response| WebAuthnResult { response })
    }

    fn select_webauthn_device(&self, credential_id: Option<&str>) -> Result<String, ServiceError> {
        if let Some(credential_id) = credential_id {
            return self
                .verifier
                .store()
                .find_credential(credential_id)
                .map(|(device, _)| device.device_id.clone())
                .ok_or_else(|| {
                    ServiceError::new("unknown-credential", "unknown paired credential")
                });
        }
        let devices: Vec<_> = self.verifier.store().devices().collect();
        match devices.as_slice() {
            [] => Err(ServiceError::new(
                "not-paired",
                "no phone is paired with this computer",
            )),
            [device] => Ok(device.device_id.clone()),
            _ => Err(ServiceError::new(
                "ambiguous-credential",
                "more than one phone is paired; select a credential",
            )),
        }
    }

    /// Sends the request and checks the answer.
    fn exchange(
        &mut self,
        session: &mut Box<dyn phone_auth_verifier::SecureSession + Send>,
        pending: phone_auth_verifier::PendingAuthorization,
    ) -> Result<phone_auth_verifier::Grant, ServiceError> {
        session
            .send(&pending.frame())
            .map_err(|error| ServiceError::new("transport-failed", error.to_string()))?;

        let response = session
            .receive(RECEIVE_TIMEOUT)
            .map_err(|error| ServiceError::new("transport-failed", error.to_string()))?;

        self.verifier
            .accept(pending, &response, session.as_ref(), now_ms())
            .map_err(authorization_error)
    }

    /// Chooses which paired credential should be asked.
    ///
    /// Refuses to guess when several could serve the request: silently picking
    /// one would make which phone approved a login depend on map ordering.
    fn select_credential(
        &self,
        params: &AuthorizeParams,
    ) -> Result<(String, String), ServiceError> {
        let store = self.verifier.store();

        if let Some(requested) = &params.credential_id {
            let (device, _) = store.find_credential(requested).ok_or_else(|| {
                ServiceError::new("unknown-credential", format!("no credential `{requested}`"))
            })?;
            return Ok((device.device_id.clone(), requested.clone()));
        }

        let mut candidates: Vec<(String, String)> = Vec::new();
        for device in store.devices() {
            for credential in &device.credentials {
                if credential.purpose == CredentialPurpose::Authorization
                    && policy::permits_fields(
                        &credential.permissions,
                        &params.service,
                        &params.action,
                        &params.resource,
                        &params.user,
                    )
                {
                    candidates.push((device.device_id.clone(), credential.credential_id.clone()));
                }
            }
        }

        match candidates.len() {
            0 if store.is_empty() => Err(ServiceError::new(
                "not-paired",
                "no phone is paired with this computer",
            )),
            0 => Err(ServiceError::new(
                "policy-denied",
                format!(
                    "no paired credential is allowed to authorize `{} / {}` for `{}`",
                    params.service, params.action, params.user
                ),
            )),
            1 => Ok(candidates.remove(0)),
            _ => Err(ServiceError::new(
                "ambiguous-credential",
                format!(
                    "{} credentials could authorize this; pass credentialId to choose",
                    candidates.len()
                ),
            )),
        }
    }
}

const WEBAUTHN_MAGIC: &[u8] = b"BAWA1\n";

fn webauthn_frame(value: &serde_json::Value) -> Result<Vec<u8>, ServiceError> {
    let mut frame = WEBAUTHN_MAGIC.to_vec();
    serde_json::to_writer(&mut frame, value)
        .map_err(|_| ServiceError::new("bad-request", "could not encode WebAuthn request"))?;
    if frame.len() > phone_auth_session::MAX_FRAME {
        return Err(ServiceError::new(
            "bad-request",
            "WebAuthn request exceeds the secure-session frame limit",
        ));
    }
    Ok(frame)
}

fn decode_webauthn_response(
    frame: &[u8],
    expected_request_id: &str,
) -> Result<serde_json::Value, ServiceError> {
    let json = frame.strip_prefix(WEBAUTHN_MAGIC).ok_or_else(|| {
        ServiceError::new("bad-frame", "phone returned an invalid WebAuthn frame")
    })?;
    let value: serde_json::Value = serde_json::from_slice(json)
        .map_err(|_| ServiceError::new("bad-frame", "phone returned invalid WebAuthn JSON"))?;
    if value.get("version").and_then(|v| v.as_u64()) != Some(1)
        || value.get("type").and_then(|v| v.as_str()) != Some("webauthn.response")
        || value.get("requestId").and_then(|v| v.as_str()) != Some(expected_request_id)
    {
        return Err(ServiceError::new(
            "bad-frame",
            "WebAuthn response did not match the request",
        ));
    }
    if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(ServiceError::new(
            "declined",
            "passkey operation was cancelled or rejected",
        ));
    }
    value
        .get("response")
        .filter(|response| response.is_object())
        .cloned()
        .ok_or_else(|| ServiceError::new("bad-frame", "phone returned no WebAuthn response"))
}

impl PairingProposalSummary {
    fn from_proposal(proposal: &crate::qr_network::PairingProposal) -> Self {
        let key_kind = map_key_kind(proposal.key_kind);
        let purpose = map_purpose(proposal.purpose);
        Self {
            device_id: proposal.device_id.clone(),
            device_name: proposal.device_name.clone(),
            credential_id: proposal.credential_id.clone(),
            key_kind: format!("{key_kind:?}"),
            purpose: format!("{purpose:?}"),
            verification_code: proposal.verification_code.clone(),
            usable_at_boot: key_kind.allowed_at_boot() && purpose == CredentialPurpose::DiskUnlock,
        }
    }
}

/// Translates the wire enum into the verifier's own.
///
/// Two enums rather than one shared type because the wire values are a
/// protocol contract that must not change, while the verifier's may grow
/// variants that never appear on the wire.
fn map_key_kind(kind: phone_auth_protocol::KeyKind) -> phone_auth_verifier::KeyKind {
    match kind {
        phone_auth_protocol::KeyKind::StrongBox => phone_auth_verifier::KeyKind::StrongBox,
        phone_auth_protocol::KeyKind::Hardware => phone_auth_verifier::KeyKind::Hardware,
        phone_auth_protocol::KeyKind::Software => phone_auth_verifier::KeyKind::Software,
    }
}

fn map_purpose(purpose: phone_auth_protocol::CredentialPurpose) -> CredentialPurpose {
    match purpose {
        phone_auth_protocol::CredentialPurpose::Authorization => CredentialPurpose::Authorization,
        phone_auth_protocol::CredentialPurpose::DiskUnlock => CredentialPurpose::DiskUnlock,
        phone_auth_protocol::CredentialPurpose::WebAuthn => CredentialPurpose::WebAuthn,
    }
}

/// Maps a verifier error to a stable IPC code.
///
/// The codes are what the CLI and PAM see, so each distinct failure the user
/// might have to act on gets its own rather than collapsing into "denied".
fn authorization_error(error: AuthorizationError) -> ServiceError {
    let code = match &error {
        AuthorizationError::Declined => "declined",
        AuthorizationError::Expired => "expired",
        AuthorizationError::Replayed => "replayed",
        AuthorizationError::PolicyDenied => "policy-denied",
        AuthorizationError::UnknownCredential(_) => "unknown-credential",
        AuthorizationError::ChannelUnsuitable { .. } => "channel-unsuitable",
        AuthorizationError::PurposeMismatch { .. } => "purpose-mismatch",
        AuthorizationError::KeyKindUnsuitableForBoot { .. } => "key-unsuitable-for-boot",
        AuthorizationError::DevelopmentTransportRefused { .. } => "development-transport",
        AuthorizationError::SessionBindingMismatch => "session-mismatch",
        AuthorizationError::ResponseMismatch { .. } => "response-mismatch",
        AuthorizationError::Signature(_) => "bad-signature",
        AuthorizationError::Protocol(_) => "bad-frame",
        AuthorizationError::Malformed(_) => "bad-request",
    };
    ServiceError::new(code, error.to_string())
}

#[cfg(test)]
mod webauthn_tests {
    use super::*;

    #[test]
    fn response_is_bound_to_the_request_id() {
        let matching = serde_json::json!({
            "version": 1,
            "type": "webauthn.response",
            "requestId": "request-1",
            "ok": true,
            "response": {"id": "credential-1"},
        });
        let frame = webauthn_frame(&matching).unwrap();
        assert_eq!(
            decode_webauthn_response(&frame, "request-1").unwrap()["id"],
            "credential-1"
        );
        assert!(decode_webauthn_response(&frame, "request-2").is_err());
    }

    #[test]
    fn rejected_operation_never_becomes_a_response() {
        let denied = serde_json::json!({
            "version": 1,
            "type": "webauthn.response",
            "requestId": "request-1",
            "ok": false,
            "error": "secret detail that must not cross",
        });
        let frame = webauthn_frame(&denied).unwrap();
        let error = decode_webauthn_response(&frame, "request-1").unwrap_err();
        assert_eq!(error.code, "declined");
        assert!(!error.message.contains("secret detail"));
    }
}
