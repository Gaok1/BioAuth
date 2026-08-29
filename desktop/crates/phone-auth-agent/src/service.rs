//! Agent state and the operations the IPC surface exposes.
//!
//! Everything here runs behind one mutex. The work is short — build a request,
//! wait for one answer, check a signature — and a single lock keeps the replay
//! guard and the pairing store consistent without a scheduler.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use phone_auth_locker::{LockPlan, UnlockKey};

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
    AuthorizeParams, AuthorizeResult, CredentialSummary, DeviceSummary, Event, LockerLockParams,
    LockerLockResult, LockerRekeyParams, LockerRekeyResult, LockerUnlockParams, LockerUnlockResult,
    PairingBootstrap, PermissionSummary, SshSignParams, SshSignResult, StatusPayload,
    VaultCopyParams, VaultCopyResult, VaultFillParams, VaultFillResult, VaultItem, VaultListParams,
    VaultListResult, WebAuthnParams, WebAuthnResult,
};
use crate::audit::{AuditEntry, AuditLog, Outcome};
use crate::clipboard;
use crate::config::AgentConfig;
use crate::locker::PhoneCustodian;
use crate::paths::Paths;
use crate::secret_memory::SecretBuffer;
use crate::transport::{Transport, TransportAvailability, TransportRegistry};
use phone_auth_protocol::ssh;

use crate::ssh_client::PhoneSsh;
use crate::vault::{PhoneVault, VaultError};

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

    #[cfg(test)]
    pub(crate) fn broadcast_for_test(&mut self, event: Event) {
        self.broadcast(event);
    }

    #[cfg(test)]
    pub(crate) fn subscriber_count_for_test(&self) -> usize {
        self.subscribers.len()
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
        // The listener authenticates inbound connections from its own copy of
        // the paired devices. Without this it keeps accepting the phone that
        // was just forgotten, until some other change happens to republish or
        // the agent restarts.
        self.publish_known_peers();
        if let Some(network) = &self.network {
            network.discard_sessions(device_id);
        }
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

        // Arming a fresh code retires whatever the last attempt left behind.
        // `arm_pairing` clears the transport's copy; without this the held one
        // survived, and a refused attempt could be confirmed against the new
        // code that had just replaced it.
        self.discard_held_proposal();
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
        // Clearing only the transport left an already-collected proposal here,
        // so the next `pair.pending` answered with the cancelled attempt.
        self.discard_held_proposal();
    }

    fn discard_held_proposal(&self) {
        *self.held_proposal.lock().expect("proposal mutex") = None;
    }

    /// Reports a pairing that completed its handshake and is awaiting
    /// confirmation.
    /// Asking is not consuming: the same proposal is returned until the user
    /// answers it.
    ///
    /// This used to take from the transport and hold the result without ever
    /// reading it back, so a second poll answered `None`. One lost IPC reply —
    /// a reopened window, a renderer reload — and the code on screen became
    /// unrecoverable even though the phone was still waiting.
    pub fn pending_pairing(&self) -> Option<PairingProposalSummary> {
        if let Some(held) = self.held_proposal.lock().expect("proposal mutex").as_ref() {
            return Some(PairingProposalSummary::from_proposal(held));
        }
        let network = self.network.as_ref()?;
        let proposal = network.take_proposal()?;
        let summary = PairingProposalSummary::from_proposal(&proposal);
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
    /// [`attempt_id`] is what the UI was shown. When it is given and does not
    /// match, the answer belongs to an attempt that has since been replaced and
    /// is refused without consuming the current one.
    pub fn confirm_pairing(
        &mut self,
        expected_code: &str,
        attempt_id: Option<&str>,
    ) -> Result<(), ServiceError> {
        {
            let held = self.held_proposal.lock().expect("proposal mutex");
            let current = held.as_ref().map(|proposal| proposal.attempt_id.as_str());
            match (attempt_id, current) {
                (Some(quoted), Some(current)) if quoted != current => {
                    return Err(ServiceError::new(
                        "stale-attempt",
                        "that pairing attempt has been replaced; read the new code",
                    ))
                }
                _ => {}
            }
        }

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
        if params.request_id.is_empty()
            || params.request_id.len() > 64
            || !params
                .request_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
            || !matches!(params.operation.as_str(), "create" | "get")
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

        let request_id = &params.request_id;
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
            let deadline = Instant::now() + RECEIVE_TIMEOUT;
            loop {
                if crate::ipc::take_webauthn_cancellation(request_id) {
                    let cancel = webauthn_frame(&serde_json::json!({
                        "version": 1,
                        "type": "webauthn.cancel",
                        "requestId": request_id,
                    }))?;
                    let _ = session.send(&cancel);
                    return Err(ServiceError::new(
                        "cancelled",
                        "WebAuthn request was cancelled",
                    ));
                }
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    let cancel = webauthn_frame(&serde_json::json!({
                        "version": 1,
                        "type": "webauthn.cancel",
                        "requestId": request_id,
                    }))?;
                    let _ = session.send(&cancel);
                    return Err(ServiceError::new("timeout", "WebAuthn request timed out"));
                };
                match session.receive(remaining.min(Duration::from_millis(250))) {
                    Ok(response) => break decode_webauthn_response(&response, request_id),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(error) => {
                        return Err(ServiceError::new("transport-failed", error.to_string()))
                    }
                }
            }
        })();
        crate::ipc::take_webauthn_cancellation(request_id);
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
        let purpose = CredentialPurpose::for_service(&params.service);

        if let Some(requested) = &params.credential_id {
            let (device, _) = store.find_credential(requested).ok_or_else(|| {
                ServiceError::new("unknown-credential", format!("no credential `{requested}`"))
            })?;
            return Ok((device.device_id.clone(), requested.clone()));
        }

        let mut candidates: Vec<(String, String)> = Vec::new();
        for device in store.devices() {
            for credential in &device.credentials {
                if credential.purpose == purpose
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

    /// Locks a file, with the phone wrapping the container's data key.
    ///
    /// The plaintext is removed last, after the container has been written and
    /// verified *and* the recovery code has been written where the caller
    /// asked. Losing the code and the original in the same step is exactly the
    /// failure this ordering exists to prevent.
    pub fn locker_lock(
        &mut self,
        params: &LockerLockParams,
    ) -> Result<LockerLockResult, ServiceError> {
        let source = absolute_path(&params.path)?;
        // Asked before the phone is: this agent deletes the plaintext itself,
        // so it owes the same refusal the engine would have made if it were
        // the one doing the deleting.
        phone_auth_locker::ensure_sole_regular_file(&source, !params.keep_original)
            .map_err(locker_error)?;
        let recovery_path = absolute_path(&params.recovery_code_path)?;
        // Claimed up front: finding out the code has nowhere to go after the
        // container exists would be finding out too late.
        let recovery_slot = claim_recovery_file(&recovery_path)?;

        let (device_id, credential_id) =
            self.select_locker_credential(params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        // Never `remove_original` here: this call returns before the recovery
        // code has been stored, and the engine would already have deleted it.
        let plan = LockPlan {
            destination: None,
            remove_original: false,
        };
        let outcome = {
            let mut custodian = PhoneCustodian::new(
                &mut session,
                self.config.verifier_name.clone(),
                credential_id.clone(),
            );
            phone_auth_locker::lock_file(&source, &plan, &mut custodian)
        };
        let _ = session.close();

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                let error = locker_error(error);
                self.record_locker(&source, "lock", &device_name, development, Err(&error));
                return Err(error);
            }
        };
        recovery_slot.write(&outcome.recovery_code)?;

        let original_removed = !params.keep_original && {
            std::fs::remove_file(&source)
                .map_err(|error| ServiceError::new("io-failed", error.to_string()))?;
            true
        };
        self.record_locker(&source, "lock", &device_name, development, Ok(()));

        Ok(LockerLockResult {
            container: outcome.container.to_string_lossy().into_owned(),
            recovery_code_path: recovery_path.to_string_lossy().into_owned(),
            plaintext_len: outcome.plaintext_len,
            original_removed,
            device_name,
            development,
        })
    }

    /// Unlocks a container with the phone. The offline recovery path does not
    /// come through here: it runs in the caller's own process, with no agent
    /// and no session, which is the whole point of having it.
    pub fn locker_unlock(
        &mut self,
        params: &LockerUnlockParams,
    ) -> Result<LockerUnlockResult, ServiceError> {
        let container = absolute_path(&params.path)?;
        let destination = params
            .destination_dir
            .as_deref()
            .map(absolute_path)
            .transpose()?;

        let (device_id, credential_id) =
            self.select_locker_credential(params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let outcome = {
            let mut custodian = PhoneCustodian::new(
                &mut session,
                self.config.verifier_name.clone(),
                credential_id,
            );
            phone_auth_locker::unlock_file(
                &container,
                destination.as_deref(),
                !params.keep_container,
                UnlockKey::Phone(&mut custodian),
            )
        };
        let _ = session.close();

        match outcome {
            Ok(outcome) => {
                self.record_locker(&container, "unlock", &device_name, development, Ok(()));
                Ok(LockerUnlockResult {
                    restored: outcome.restored.to_string_lossy().into_owned(),
                    plaintext_len: outcome.plaintext_len,
                    container_removed: outcome.container_removed,
                    device_name,
                    development,
                })
            }
            Err(error) => {
                let error = locker_error(error);
                self.record_locker(&container, "unlock", &device_name, development, Err(&error));
                Err(error)
            }
        }
    }

    /// Binds an existing container to this phone's current key, optionally
    /// issuing a new recovery code.
    pub fn locker_rekey(
        &mut self,
        params: &LockerRekeyParams,
    ) -> Result<LockerRekeyResult, ServiceError> {
        let container = absolute_path(&params.path)?;
        let recovery_slot = match (params.new_recovery_code, &params.recovery_code_path) {
            (true, Some(path)) => Some(claim_recovery_file(&absolute_path(path)?)?),
            (true, None) => {
                return Err(ServiceError::new(
                    "bad-request",
                    "a new recovery code needs a path to be written to",
                ))
            }
            (false, _) => None,
        };

        let (device_id, credential_id) =
            self.select_locker_credential(params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let outcome = {
            let mut custodian = PhoneCustodian::new(
                &mut session,
                self.config.verifier_name.clone(),
                credential_id,
            )
            .rekeying();
            phone_auth_locker::rekey_file(
                &container,
                &mut custodian,
                None,
                params.new_recovery_code,
            )
        };
        let _ = session.close();

        let code = match outcome {
            Ok(code) => code,
            Err(error) => {
                let error = locker_error(error);
                self.record_locker(&container, "rekey", &device_name, development, Err(&error));
                return Err(error);
            }
        };
        let recovery_code_path = match (recovery_slot, code) {
            (Some(slot), Some(code)) => {
                let path = slot.path().to_string_lossy().into_owned();
                slot.write(&code)?;
                Some(path)
            }
            _ => None,
        };
        self.record_locker(&container, "rekey", &device_name, development, Ok(()));

        Ok(LockerRekeyResult {
            container: container.to_string_lossy().into_owned(),
            recovery_code_path,
            device_name,
            development,
        })
    }

    /// Reads the vault's metadata from the phone.
    ///
    /// Costs no biometric prompt, because it releases no secret. The rows it
    /// returns are what the tray needs to draw a list; the value behind any of
    /// them costs a separate [`vault_copy`](Self::vault_copy).
    pub fn vault_list(
        &mut self,
        params: &VaultListParams,
    ) -> Result<VaultListResult, ServiceError> {
        let (device_id, _credential_id) =
            self.select_vault_credential(params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let listed = PhoneVault::new(&mut session, self.config.verifier_name.clone()).list();
        let _ = session.close();

        match listed {
            Ok(items) => {
                self.record_vault("", "list", &device_name, development, Ok(()));
                Ok(VaultListResult {
                    items: items.into_iter().map(vault_item).collect(),
                    device_name,
                    development,
                })
            }
            Err(error) => {
                let error = vault_error(error);
                self.record_vault("", "list", &device_name, development, Err(&error));
                Err(error)
            }
        }
    }

    /// The SSH public keys this machine can offer, one per paired credential
    /// whose purpose is `Ssh`.
    ///
    /// Costs no session and no prompt: a paired credential's public key is
    /// already on this disk, and an agent that woke the phone every time a
    /// shell started would be an agent people uninstall.
    pub fn ssh_identities(&self) -> Vec<(Vec<u8>, String)> {
        self.verifier
            .store()
            .devices()
            .flat_map(|device| {
                device.credentials.iter().filter_map(move |credential| {
                    if credential.purpose != CredentialPurpose::Ssh {
                        return None;
                    }
                    // A credential whose key is not a P-256 point is not one
                    // SSH can use. Skipped rather than reported: it is not an
                    // error, it is a credential for something else.
                    let point = ssh::point_from_spki(&credential.public_key).ok()?;
                    let blob = ssh::encode_public_key(&point).ok()?;
                    Some((
                        blob,
                        format!("{} ({})", device.display_name, credential.credential_id),
                    ))
                })
            })
            .collect()
    }

    /// Asks the phone to sign one SSH authentication request.
    ///
    /// The blob travels as-is, because a server accepts a signature over
    /// exactly those bytes. The phone re-parses it and refuses anything that
    /// is not a `publickey` userauth request — this side cannot be the only
    /// thing standing between a compromised desktop and an arbitrary
    /// signature.
    pub fn ssh_sign(&mut self, params: &SshSignParams) -> Result<SshSignResult, ServiceError> {
        let (device_id, _credential_id) =
            self.select_service_credential("ssh", "SSH", params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let signed = PhoneSsh::new(&mut session, self.config.verifier_name.clone())
            .sign(&params.data, &params.destination);
        let _ = session.close();

        match signed {
            Ok(signature) => {
                self.record_application(
                    "ssh",
                    "sign",
                    params.destination.clone(),
                    &device_name,
                    development,
                    Ok(()),
                );
                Ok(SshSignResult { signature })
            }
            Err(error) => {
                let error = vault_error(error);
                self.record_application(
                    "ssh",
                    "sign",
                    params.destination.clone(),
                    &device_name,
                    development,
                    Err(&error),
                );
                Err(error)
            }
        }
    }

    /// Hands one site's password to the browser, for autofill.
    ///
    /// The exception to the rule the rest of this file keeps: the secret is in
    /// the reply. Filling a form field is handing the page's process the
    /// plaintext, so there is no version of autofill where it is not, and
    /// `VLT-09` accepts that. What is controllable is the size of the opening.
    ///
    /// Matching is exact on the host. No widening to the registrable domain —
    /// `login.bank.example` and `blog.bank.example` share one and are not the
    /// same place to type a password, and that widening is the single most
    /// common way autofill hands over the wrong credential.
    ///
    /// Two matches refuse rather than choose. Signing somebody into the wrong
    /// one of their own accounts is silent, and the tray's Copy button is a
    /// working path that shows them the list.
    pub fn vault_fill(
        &mut self,
        params: &VaultFillParams,
    ) -> Result<VaultFillResult, ServiceError> {
        let host = origin_host(&params.origin)
            .ok_or_else(|| ServiceError::new("bad-params", "origin is not an https origin"))?;

        let (device_id, _credential_id) =
            self.select_vault_credential(params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let mut vault = PhoneVault::new(&mut session, self.config.verifier_name.clone());
        let listed = vault.list();
        let matched = match listed {
            Ok(items) => items
                .into_iter()
                .filter(|item| {
                    matches!(item.kind, phone_auth_protocol::vault::ItemKind::Login)
                        && origin_host(&item.uri).as_deref() == Some(host.as_str())
                })
                .collect::<Vec<_>>(),
            Err(error) => {
                let _ = session.close();
                let error = vault_error(error);
                self.record_vault("", "fill", &device_name, development, Err(&error));
                return Err(error);
            }
        };

        // Nothing for this site and several for it are one answer to the
        // browser, which is `not-found` either way at the host. Here they are
        // told apart only because "copy it from the tray" is advice the second
        // case can act on.
        let item = match matched.as_slice() {
            [only] => only.clone(),
            [] => {
                let _ = session.close();
                let error = ServiceError::new("not-found", "no vault item for this site");
                self.record_vault("", "fill", &device_name, development, Err(&error));
                return Err(error);
            }
            several => {
                let _ = session.close();
                let error = ServiceError::new(
                    "ambiguous",
                    format!(
                        "{} accounts for this site; copy the one you want from the tray",
                        several.len()
                    ),
                );
                self.record_vault("", "fill", &device_name, development, Err(&error));
                return Err(error);
            }
        };

        let fetched =
            PhoneVault::new(&mut session, self.config.verifier_name.clone()).fetch(&item.id);
        let _ = session.close();

        match fetched {
            Ok(fetched) => {
                self.record_vault(&item.id, "fill", &device_name, development, Ok(()));
                Ok(VaultFillResult {
                    password: fetched.secret.clone(),
                    username: item.username,
                })
            }
            Err(error) => {
                let error = vault_error(error);
                self.record_vault(&item.id, "fill", &device_name, development, Err(&error));
                Err(error)
            }
        }
    }

    /// Puts one stored secret on the clipboard, after the user approves it on
    /// the phone.
    ///
    /// The secret's whole life on this side is inside this function: it arrives
    /// in a [`FetchResponse`](phone_auth_protocol::vault::FetchResponse) that
    /// wipes itself on drop, moves into locked pages, and goes to the
    /// clipboard. It reaches no return value, no event and no audit entry —
    /// [`VaultCopyResult`] has no field that could carry it.
    pub fn vault_copy(
        &mut self,
        params: &VaultCopyParams,
    ) -> Result<VaultCopyResult, ServiceError> {
        // Checked before the phone is asked. A timeout this refuses would
        // otherwise be discovered after the user had already approved the
        // prompt, with the secret in hand and nowhere to put it.
        let ttl = params
            .clear_after_ms
            .map_or(clipboard::DEFAULT_TTL, Duration::from_millis);
        if ttl < clipboard::MIN_TTL || ttl > clipboard::MAX_TTL {
            return Err(ServiceError::new(
                "bad-params",
                format!(
                    "clearAfterMs must be between {}ms and {}ms",
                    clipboard::MIN_TTL.as_millis(),
                    clipboard::MAX_TTL.as_millis()
                ),
            ));
        }

        let (device_id, _credential_id) =
            self.select_vault_credential(params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let fetched =
            PhoneVault::new(&mut session, self.config.verifier_name.clone()).fetch(&params.item_id);
        let _ = session.close();

        let fetched = match fetched {
            Ok(fetched) => fetched,
            Err(error) => {
                let error = vault_error(error);
                self.record_vault(
                    &params.item_id,
                    "copy",
                    &device_name,
                    development,
                    Err(&error),
                );
                return Err(error);
            }
        };

        // The caller named the revision of the row the user clicked. A
        // different one means the item was edited somewhere else in between,
        // and pasting it would hand over a value the user never looked at.
        if fetched.revision != params.expected_revision {
            let error = ServiceError::new(
                "revision-conflict",
                "the item changed on the phone; refresh the list and copy again",
            );
            self.record_vault(
                &params.item_id,
                "copy",
                &device_name,
                development,
                Err(&error),
            );
            return Err(error);
        }

        let secret = SecretBuffer::from_slice(fetched.secret.as_bytes());
        // Held no longer than the move above needs. Dropping it here wipes the
        // plaintext `String` while the clipboard call is still ahead of us.
        drop(fetched);

        let outcome = clipboard::copy_secret(&secret, ttl);
        let result = match outcome {
            Ok(outcome) => {
                self.record_vault(&params.item_id, "copy", &device_name, development, Ok(()));
                VaultCopyResult {
                    length: secret.len(),
                    clears_at_ms: outcome.clears_at_ms,
                    history_excluded: outcome.history_excluded,
                    cloud_excluded: outcome.cloud_excluded,
                    memory_locked: secret.is_locked(),
                }
            }
            Err(error) => {
                let error = clipboard_error(error);
                self.record_vault(
                    &params.item_id,
                    "copy",
                    &device_name,
                    development,
                    Err(&error),
                );
                return Err(error);
            }
        };
        Ok(result)
    }

    /// Picks the credential that may wrap locker keys.
    ///
    /// A named credential still has to hold the `FileLocker` purpose: an IPC
    /// caller must not be able to point the locker at the credential that
    /// authorizes `sudo`.
    fn select_locker_credential(
        &self,
        credential_id: Option<&str>,
    ) -> Result<(String, String), ServiceError> {
        self.select_service_credential("locker", "file locker", credential_id)
    }

    /// Picks the credential that may release vault secrets.
    ///
    /// Same rule as the locker: the vault purpose is separate from the one that
    /// authorizes `sudo`, and naming a credential does not let a caller borrow
    /// authority from another service.
    fn select_vault_credential(
        &self,
        credential_id: Option<&str>,
    ) -> Result<(String, String), ServiceError> {
        self.select_service_credential("vault", "personal vault", credential_id)
    }

    /// Resolves one enrolled credential for `service`, by name or by being the
    /// only candidate.
    ///
    /// `label` names the service in the messages a person reads.
    fn select_service_credential(
        &self,
        service: &str,
        label: &str,
        credential_id: Option<&str>,
    ) -> Result<(String, String), ServiceError> {
        let store = self.verifier.store();
        let purpose = CredentialPurpose::for_service(service);

        if let Some(requested) = credential_id {
            let (device, credential) = store.find_credential(requested).ok_or_else(|| {
                ServiceError::new("unknown-credential", format!("no credential `{requested}`"))
            })?;
            if credential.purpose != purpose {
                return Err(ServiceError::new(
                    "policy-denied",
                    format!("credential `{requested}` is not a {label} credential"),
                ));
            }
            return Ok((device.device_id.clone(), requested.to_owned()));
        }

        let mut candidates: Vec<(String, String)> = Vec::new();
        for device in store.devices() {
            for credential in &device.credentials {
                if credential.purpose == purpose {
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
                format!("no paired credential is enrolled for the {label}"),
            )),
            1 => Ok(candidates.remove(0)),
            _ => Err(ServiceError::new(
                "ambiguous-credential",
                format!(
                    "{} credentials could open this; pass credentialId to choose",
                    candidates.len()
                ),
            )),
        }
    }

    fn device_name(&self, device_id: &str) -> String {
        self.verifier
            .store()
            .device(device_id)
            .map(|device| device.display_name.clone())
            .unwrap_or_else(|| device_id.to_owned())
    }

    /// Records that a locker operation happened.
    ///
    /// The file's name is recorded, never its contents, its key, or the path
    /// of a recovery code.
    fn record_locker(
        &mut self,
        path: &Path,
        action: &str,
        device_name: &str,
        development: bool,
        result: Result<(), &ServiceError>,
    ) {
        let resource = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.record_application("locker", action, resource, device_name, development, result);
    }

    /// Records that a vault operation happened.
    ///
    /// The item's ID is opaque by design (`DEC-06`), so it is safe to write
    /// down and is the only thing worth writing down: the secret, the item's
    /// name and the user it belongs to never reach this log. A listing has no
    /// single item, and passes an empty resource.
    fn record_vault(
        &mut self,
        item_id: &str,
        action: &str,
        device_name: &str,
        development: bool,
        result: Result<(), &ServiceError>,
    ) {
        self.record_application(
            "vault",
            action,
            item_id.to_owned(),
            device_name,
            development,
            result,
        );
    }

    fn record_application(
        &mut self,
        service: &str,
        action: &str,
        resource: String,
        device_name: &str,
        development: bool,
        result: Result<(), &ServiceError>,
    ) {
        let entry = AuditEntry {
            at_ms: now_ms(),
            outcome: match result {
                Ok(()) => Outcome::Granted,
                Err(error) if error.code == "declined" => Outcome::Denied,
                Err(_) => Outcome::Failed,
            },
            request_id: random::request_id(),
            service: service.into(),
            action: action.into(),
            resource,
            user: String::new(),
            device_name: device_name.to_owned(),
            origin: String::new(),
            detail: result.err().map(|error| error.message.clone()),
            development,
        };
        if let Err(error) = self.audit.append(&entry) {
            eprintln!("phone-auth-agent: could not write audit entry: {error}");
        }
    }
}

/// Rejects a relative path rather than resolving it against the agent's own
/// working directory, which is not the caller's and has no reason to be.
fn absolute_path(path: &str) -> Result<PathBuf, ServiceError> {
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(ServiceError::new(
            "bad-request",
            "locker paths must be absolute",
        ));
    }
    Ok(path)
}

/// A recovery-code file claimed before the work starts.
///
/// Created empty and exclusively, so the name is taken and the directory is
/// known to be writable before there is a container whose only other key lives
/// on a phone.
struct RecoverySlot {
    path: PathBuf,
    written: bool,
}

impl RecoverySlot {
    fn path(&self) -> &Path {
        &self.path
    }

    fn write(mut self, code: &str) -> Result<(), ServiceError> {
        std::fs::write(&self.path, format!("{code}\n"))
            .map_err(|error| ServiceError::new("io-failed", error.to_string()))?;
        self.written = true;
        Ok(())
    }
}

impl Drop for RecoverySlot {
    fn drop(&mut self) {
        if !self.written {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn claim_recovery_file(path: &Path) -> Result<RecoverySlot, ServiceError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ServiceError::new(
                    "recovery-file-exists",
                    "that recovery code file already exists; choose another path",
                )
            } else {
                ServiceError::new("io-failed", error.to_string())
            }
        })?;
    restrict_to_owner(&file);
    Ok(RecoverySlot {
        path: path.to_path_buf(),
        written: false,
    })
}

/// A recovery code is a key. On Unix that means 0600; on Windows the file
/// inherits the directory's ACL, and the CLI tells the user to move it
/// somewhere that is not this computer.
#[cfg(unix)]
fn restrict_to_owner(file: &std::fs::File) {
    use std::os::unix::fs::PermissionsExt;
    let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_to_owner(_file: &std::fs::File) {}

/// Maps an engine error to a stable IPC code, without repeating anything the
/// engine deliberately refused to say.
fn locker_error(error: phone_auth_locker::LockerError) -> ServiceError {
    use phone_auth_locker::LockerError as Error;
    let code = match &error {
        Error::Denied(_) => "declined",
        Error::Corrupt => "corrupt-container",
        Error::NotAContainer | Error::UnsupportedVersion(_) | Error::Malformed(_) => {
            "not-a-container"
        }
        Error::TooLarge { .. } => "container-too-large",
        Error::NoWrapper(_) => "no-wrapper",
        Error::BadRecoveryCode => "bad-recovery-code",
        Error::UnsafeName => "unsafe-name",
        // Distinct codes because the two have different fixes: one path is not
        // a file the locker will touch, the other is a file whose contents
        // would survive under a name this operation is not removing.
        Error::NotARegularFile(_) => "not-a-regular-file",
        Error::SharedOriginal => "shared-original",
        Error::DestinationExists(_) => "destination-exists",
        Error::InputChanged => "input-changed",
        Error::Io(_) => "io-failed",
    };
    ServiceError::new(code, error.to_string())
}

/// Maps a vault refusal to the code the tray sees.
///
/// The coarseness is the feature. A missing item, a stale revision and a
/// biometric the user dismissed all arrive here as
/// [`Declined`](VaultError::Declined) and all leave as `declined`, so a caller
/// that is not entitled to a secret cannot use the error to learn which item
/// IDs exist.
/// The host of an https origin or URI, lowercased, or None.
///
/// Written by hand rather than pulled from a URL crate because the rules
/// wanted here are narrower than a general parser's: only `https`, a
/// scheme-less string is not an origin, a port is not part of a host, and
/// userinfo — the classic way to make a host read as one thing and resolve as
/// another — is discarded rather than parsed.
fn origin_host(value: &str) -> Option<String> {
    let rest = value.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default();
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn vault_error(error: VaultError) -> ServiceError {
    let code = match &error {
        VaultError::Declined => "declined",
        VaultError::Unavailable => "vault-unavailable",
        VaultError::Protocol(_) => "protocol-error",
    };
    ServiceError::new(code, error.to_string())
}

/// Maps a clipboard failure to the code the tray sees.
///
/// A timeout outside the accepted range is the caller's mistake, not a broken
/// clipboard, and gets a code that says so — reporting it as unavailable would
/// send the user looking for a problem on their machine.
pub(crate) fn clipboard_error(error: clipboard::ClipboardError) -> ServiceError {
    let code = match &error {
        clipboard::ClipboardError::TtlOutOfRange { .. } => "bad-params",
        clipboard::ClipboardError::NotText => "protocol-error",
        clipboard::ClipboardError::Unavailable(_) | clipboard::ClipboardError::Unsupported => {
            "clipboard-unavailable"
        }
    };
    ServiceError::new(code, error.to_string())
}

/// Widens one protocol summary into the row the IPC surface serialises.
fn vault_item(summary: phone_auth_protocol::vault::ItemSummary) -> VaultItem {
    use phone_auth_protocol::vault::ItemKind;
    VaultItem {
        id: summary.id,
        revision: summary.revision,
        kind: match summary.kind {
            ItemKind::Login => "login".into(),
            ItemKind::Note => "note".into(),
            ItemKind::Totp => "totp".into(),
        },
        name: summary.name,
        username: summary.username,
        uri: summary.uri,
        updated_at_ms: summary.updated_at_ms,
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
            attempt_id: proposal.attempt_id.clone(),
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
        phone_auth_protocol::CredentialPurpose::Vault => CredentialPurpose::Vault,
        phone_auth_protocol::CredentialPurpose::FileLocker => CredentialPurpose::FileLocker,
        phone_auth_protocol::CredentialPurpose::Ssh => CredentialPurpose::Ssh,
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
mod pairing_state_tests {
    use super::*;
    use crate::qr_network::PairingProposal;

    pub(super) fn service(name: &str) -> Service {
        let root = std::env::temp_dir().join(format!(
            "phone-auth-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let paths = Paths::resolve(Some(root));
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        std::fs::create_dir_all(&paths.data_dir).expect("data dir");
        let config = AgentConfig::load_or_create(&paths.config_file()).expect("config");
        // No network: these cover the state the service itself holds, which is
        // where the proposal was being lost.
        Service::new(config, paths, None, Vec::new(), false).expect("service")
    }

    fn proposal(code: &str) -> PairingProposal {
        attempt("attempt-1", code)
    }

    fn attempt(attempt_id: &str, code: &str) -> PairingProposal {
        PairingProposal {
            attempt_id: attempt_id.into(),
            device_id: "phone-1".into(),
            device_name: "Phone".into(),
            session_identity_spki: vec![1; 91],
            credential_id: "cred-1".into(),
            algorithm: phone_auth_protocol::PUBLIC_KEY_EC_P256_SPKI.into(),
            credential_public_key: vec![2; 91],
            key_kind: phone_auth_protocol::KeyKind::StrongBox,
            purpose: phone_auth_protocol::CredentialPurpose::Authorization,
            verification_code: code.into(),
        }
    }

    /// Polling must not consume: one lost IPC reply used to make the code on
    /// screen unrecoverable while the phone was still waiting on it.
    #[test]
    fn asking_twice_returns_the_same_proposal() {
        let service = service("pending-twice");
        service.hold_proposal(proposal("123456"));

        let first = service.pending_pairing().expect("first poll");
        let second = service.pending_pairing().expect("second poll");

        assert_eq!(first.verification_code, "123456");
        assert_eq!(second.verification_code, first.verification_code);
        assert_eq!(second.device_id, first.device_id);
    }

    #[test]
    fn cancelling_clears_a_proposal_the_service_already_took() {
        let service = service("pending-cancel");
        service.hold_proposal(proposal("123456"));

        service.cancel_pairing();

        assert!(
            service.pending_pairing().is_none(),
            "a cancelled attempt must not still be confirmable"
        );
    }

    #[test]
    fn confirming_a_cancelled_attempt_is_refused() {
        let mut service = service("pending-confirm");
        service.hold_proposal(proposal("123456"));
        service.cancel_pairing();

        let error = service
            .confirm_pairing("123456", None)
            .expect_err("must refuse");
        assert_eq!(error.code, "no-pairing");
    }

    #[test]
    fn a_wrong_code_does_not_pair() {
        let mut service = service("pending-mismatch");
        service.hold_proposal(proposal("123456"));

        let error = service
            .confirm_pairing("654321", None)
            .expect_err("must refuse");
        assert_eq!(error.code, "code-mismatch");
    }

    /// Invariant ten: an answer to a replaced attempt must not confirm the one
    /// that replaced it, even when six digits happen to agree.
    #[test]
    fn an_answer_to_a_replaced_attempt_is_refused() {
        let mut service = service("pending-stale");
        service.hold_proposal(attempt("attempt-old", "123456"));
        // The user cancelled and started again; the phone reconnected and the
        // new attempt drew the same six digits.
        service.hold_proposal(attempt("attempt-new", "123456"));

        let error = service
            .confirm_pairing("123456", Some("attempt-old"))
            .expect_err("the stale answer must not land");
        assert_eq!(error.code, "stale-attempt");

        // And the current attempt survives it, so the user can still confirm.
        assert!(
            service.pending_pairing().is_some(),
            "refusing a stale answer must not consume the live attempt"
        );
    }

    #[test]
    fn quoting_the_current_attempt_confirms_it() {
        let service = service("pending-current");
        service.hold_proposal(attempt("attempt-1", "123456"));

        let summary = service.pending_pairing().expect("pending");
        assert_eq!(summary.attempt_id, "attempt-1");
    }
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

#[cfg(test)]
mod subscriber_tests {
    use super::pairing_state_tests::service;
    use super::*;

    /// The tray reconnects on every restart, so a client that went away must
    /// lose its slot. Holding the sender forever would grow the list without
    /// bound and make every later broadcast pay for a receiver nobody reads.
    #[test]
    fn broadcasting_drops_subscribers_that_went_away() {
        let mut service = service("subscriber-prune");
        let live = service.subscribe();
        let gone = service.subscribe();
        assert_eq!(service.subscriber_count_for_test(), 2);

        drop(gone);
        service.broadcast_for_test(Event::DevicesChanged);

        assert_eq!(service.subscriber_count_for_test(), 1);
        assert!(matches!(live.try_recv(), Ok(Event::DevicesChanged)));
    }

    /// Every live client sees the same event: the tray and the CLI can both be
    /// subscribed, and one must not consume the other's copy.
    #[test]
    fn every_live_subscriber_receives_the_event() {
        let mut service = service("subscriber-fanout");
        let first = service.subscribe();
        let second = service.subscribe();

        service.broadcast_for_test(Event::RequestFinished {
            request_id: "request-1".into(),
            granted: true,
            reason: None,
        });

        for received in [first.try_recv(), second.try_recv()] {
            match received.expect("event delivered") {
                Event::RequestFinished {
                    request_id,
                    granted,
                    ..
                } => {
                    assert_eq!(request_id, "request-1");
                    assert!(granted);
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert_eq!(service.subscriber_count_for_test(), 2);
    }

    /// The exact-host rule that decides which password autofill may release.
    ///
    /// `login.bank.example` and `blog.bank.example` share a registrable domain
    /// and are not the same place to type a password into. Widening to eTLD+1
    /// is the single most common way autofill hands over the wrong credential,
    /// so the comparison is on the whole host and nothing else.
    #[test]
    fn an_origin_matches_only_its_own_host() {
        assert_eq!(
            origin_host("https://login.bank.example"),
            Some("login.bank.example".to_owned())
        );
        assert_ne!(
            origin_host("https://blog.bank.example"),
            origin_host("https://login.bank.example")
        );
        // A stored URI with a path and a port still resolves to the same host
        // the browser reports, or an ordinary saved login would never match.
        assert_eq!(
            origin_host("https://bank.example:8443/login?next=/"),
            Some("bank.example".to_owned())
        );
        assert_eq!(
            origin_host("https://BANK.example/"),
            Some("bank.example".to_owned())
        );
    }

    /// Userinfo is the classic way to make a host read as one thing and
    /// resolve as another. `https://bank.example@evil.example` is a page on
    /// `evil.example`, and it must match the vault item for `evil.example`.
    #[test]
    fn userinfo_never_disguises_the_host() {
        assert_eq!(
            origin_host("https://bank.example@evil.example/"),
            Some("evil.example".to_owned())
        );
    }

    /// Only https. A password typed over plain HTTP is a password on the wire,
    /// and filling one automatically would make that this agent's doing.
    #[test]
    fn a_non_https_origin_has_no_host_to_match() {
        assert_eq!(origin_host("http://bank.example"), None);
        assert_eq!(origin_host("file:///etc/passwd"), None);
        assert_eq!(origin_host("bank.example"), None);
        assert_eq!(origin_host("https://"), None);
        assert_eq!(origin_host(""), None);
    }
}
