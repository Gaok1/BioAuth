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
    LuksEnrollParams, LuksEnrollResult, PairingBootstrap, PermissionSummary, SshSignParams,
    SshSignResult, StatusPayload, SyncPermissionsResult, VaultCopyParams, VaultCopyResult,
    VaultCreateParams, VaultCreateResult, VaultFillParams, VaultFillResult, VaultItem,
    VaultListParams, VaultListResult, WebAuthnParams, WebAuthnResult,
};
use crate::audit::{AuditEntry, AuditLog, Outcome};
use crate::clipboard;
use crate::config::AgentConfig;
use crate::locker::PhoneCustodian;
use crate::paths::Paths;
use crate::secret_memory::SecretBuffer;
use crate::transport::{Transport, TransportAvailability, TransportRegistry};
use phone_auth_protocol::permissions::SyncRequest;
use phone_auth_protocol::ssh;

use crate::password::{self, Policy};
use crate::permissions::{from_wire, to_wire, PhonePermissions};
use crate::ssh_client::PhoneSsh;
use crate::vault::{self, NewItem, PhoneVault, VaultError};
use phone_auth_protocol::vault::ItemKind;

/// How long a pairing bootstrap stays scannable.
const PAIRING_WINDOW_MS: i64 = 120_000;

/// How long to wait for a phone to answer a WebAuthn ceremony.
///
/// A flat number here, unlike everywhere else, because the relay envelope
/// carries no `expires_at_ms` for the wait to be measured against. The
/// authorization exchange below uses the request's own deadline.
const WEBAUTHN_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    /// Stable code the CLI turns into an exit status.
    pub code: &'static str,
    pub message: String,
}

impl ServiceError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
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
    subscribers: Vec<(u64, Sender<Event>)>,
    next_subscriber_id: u64,
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
            next_subscriber_id: 0,
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

    /// Registers a client for event pushes, and names the registration.
    ///
    /// The id is what lets a connection take its own subscription back when it
    /// ends. Without one the only way a subscriber left was a broadcast
    /// failing to reach it, so a client that hung up kept its entry, and the
    /// thread pumping events to it stayed blocked on the channel holding that
    /// socket open, until something somewhere raised an event.
    pub fn subscribe(&mut self) -> (u64, Receiver<Event>) {
        let (sender, receiver) = mpsc::channel();
        let id = self.next_subscriber_id;
        self.next_subscriber_id += 1;
        self.subscribers.push((id, sender));
        (id, receiver)
    }

    /// Drops these registrations, whether or not anything is being broadcast.
    ///
    /// Dropping the sender ends the `for event in receiver` in the pump thread,
    /// which is what closes the socket and reclaims the thread.
    pub fn unsubscribe(&mut self, ids: &[u64]) {
        self.subscribers.retain(|(id, _)| !ids.contains(id));
    }

    /// Sends an event to every live subscriber, dropping closed ones.
    fn broadcast(&mut self, event: Event) {
        self.subscribers
            .retain(|(_, subscriber)| subscriber.send(event.clone()).is_ok());
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
                        permissions_revision: credential.permissions_revision,
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

        let next: Vec<Permission> = permissions
            .into_iter()
            .map(|permission| Permission {
                service: permission.service,
                action: permission.action,
                resource: permission.resource,
                user: permission.user,
            })
            .collect();

        // Refused here so it is not refused later, by something nobody is
        // looking at. The wire bounds a set -- sixty-four grants, no empty
        // field, a payload that fits -- and this is the only place a person
        // can write one that exceeds them. A set stored past those bounds is
        // one the phone can never be told about: every settlement from then on
        // dials the phone, wakes it, and fails on an edit made long before,
        // while the desktop goes on enforcing grants the phone does not know
        // it has.
        SyncRequest {
            verifier_name: self.config.verifier_name.clone(),
            revision: 0,
            permissions: next.iter().map(to_wire).collect(),
        }
        .validate()
        .map_err(|error| ServiceError::new("invalid-permissions", error.to_string()))?;

        credential.permissions = next;
        // Every local edit climbs, so the next sync can tell this set from the
        // phone's without either side having seen the other. Saturating rather
        // than wrapping: a counter that rolls over to zero is a set that loses
        // to everything, and this one is the record of what a person decided.
        credential.permissions_revision = credential.permissions_revision.saturating_add(1);

        self.verifier
            .store_mut()
            .insert(device)
            .map_err(|error| ServiceError::new("store-write-failed", error.to_string()))?;
        self.broadcast(Event::DevicesChanged);
        Ok(())
    }

    /// Reconciles one credential's permissions with the phone's copy.
    ///
    /// Both sides can be edited and neither can see the other between
    /// sessions, so this is not a read or a write but a settlement: the
    /// desktop offers what it believes, the phone answers with what stands,
    /// and the answer is stored whole.
    ///
    /// Stored whole on purpose. A diff would mean this side deciding what the
    /// other meant, and getting that wrong leaves a pairing with powers nobody
    /// granted. A reply that fails to decode is a call that failed, which is a
    /// state a person can retry from.
    pub fn sync_permissions(
        &mut self,
        device_id: &str,
        credential_id: &str,
    ) -> Result<SyncPermissionsResult, ServiceError> {
        let device = self
            .verifier
            .store()
            .device(device_id)
            .cloned()
            .ok_or_else(|| {
                ServiceError::new("unknown-device", format!("no device `{device_id}`"))
            })?;
        let credential = device
            .credential(credential_id)
            .ok_or_else(|| {
                ServiceError::new(
                    "unknown-credential",
                    format!("no credential `{credential_id}` on `{device_id}`"),
                )
            })?
            .clone();

        let mut session = self
            .transports
            .connect(device_id, credential_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(device_id);
        let development = session.security().is_development;

        let answered = PhonePermissions::new(&mut session, self.config.verifier_name.clone())
            .sync(credential.permissions_revision, &credential.permissions);
        let _ = session.close();

        let answered = match answered {
            Ok(answered) => answered,
            Err(error) => {
                let error = vault_error(error);
                self.record_application(
                    "permissions",
                    "sync",
                    credential_id.to_owned(),
                    &device_name,
                    development,
                    Err(&error),
                );
                return Err(error);
            }
        };

        // Compared field by field, not by count. Trading `sudo` for `ssh` is
        // the same length and is the change most worth reporting.
        let settled: Vec<Permission> = answered.permissions.iter().map(from_wire).collect();
        let adopted = answered.revision != credential.permissions_revision
            || settled != credential.permissions;
        let mut device = device;
        if let Some(stored) = device
            .credentials
            .iter_mut()
            .find(|stored| stored.credential_id == credential_id)
        {
            stored.permissions = settled.clone();
            stored.permissions_revision = answered.revision;
        }
        let count = answered.permissions.len();

        self.verifier
            .store_mut()
            .insert(device)
            .map_err(|error| ServiceError::new("store-write-failed", error.to_string()))?;
        self.record_application(
            "permissions",
            "sync",
            credential_id.to_owned(),
            &device_name,
            development,
            Ok(()),
        );
        self.broadcast(Event::DevicesChanged);

        Ok(SyncPermissionsResult {
            revision: answered.revision,
            granted: count,
            changed: adopted,
        })
    }

    /// Puts a pairing code on screen and arms the listener to accept it.
    ///
    /// The code commits to this agent's handshake identity, which is what lets
    /// the phone tell this desktop from a relay on first contact. It carries no
    /// secret: losing the picture lets someone attempt a pairing, not complete
    /// one, because the user still has to confirm the verification code.
    pub fn begin_pairing(&mut self) -> Result<PairingBootstrap, ServiceError> {
        self.begin_pairing_for("authorization")
    }

    /// Puts a pairing code on screen for one specific kind of credential.
    ///
    /// The purpose has to travel in the code because it is decided here and
    /// the phone cannot infer it: a scan is the same gesture whether the key
    /// being enrolled will approve a `sudo` or sign an SSH login, and enrolling
    /// one as the other is exactly the credential reuse the purposes exist to
    /// prevent.
    pub fn begin_pairing_for(&mut self, service: &str) -> Result<PairingBootstrap, ServiceError> {
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

        let bootstrap = ServerBootstrap::for_purpose(
            random::session_id(),
            self.config.verifier_id.clone(),
            endpoint,
            network.identity(),
            now_ms(),
            PAIRING_WINDOW_MS,
            wire_purpose(CredentialPurpose::for_service(service)),
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
            service: service.to_owned(),
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
                permissions_revision: 0,
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
            .connect(&device_id, &credential_id)
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

        let (device_id, credential_id) = self.select_service_credential(
            "webauthn",
            "passkey relay",
            params.credential_id.as_deref(),
        )?;
        let mut session = self
            .transports
            .connect(&device_id, &credential_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        if !session.security().suitable_for_authorization() {
            let _ = session.close();
            return Err(ServiceError::new(
                "channel-unsuitable",
                "desktop passkeys require an authenticated confidential session",
            ));
        }
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

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
            let deadline = Instant::now() + WEBAUTHN_TIMEOUT;
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

        // Written down here and nowhere else. The phone says exactly why it
        // refused and that sentence is worth keeping -- it is the only account
        // of what happened, and losing it is why a passkey that will not work
        // is so hard to tell apart from one that was declined. It belongs in
        // the log the person can read, on their own machine.
        //
        // It does not belong in the answer to the page. WebAuthn gives relying
        // parties one undifferentiated failure on purpose, and a site that can
        // tell "no credential for you" from "the fingerprint did not take" has
        // learnt something about the person from an authenticator that is
        // supposed to tell it nothing.
        match result {
            Ok(response) => {
                self.record_application(
                    "webauthn",
                    &params.operation,
                    params.origin.clone(),
                    &device_name,
                    development,
                    Ok(()),
                );
                Ok(WebAuthnResult { response })
            }
            Err(error) => {
                self.record_application(
                    "webauthn",
                    &params.operation,
                    params.origin.clone(),
                    &device_name,
                    development,
                    Err(&error),
                );
                Err(browser_facing(error))
            }
        }
    }

    /// Sends the request and checks the answer.
    fn exchange(
        &mut self,
        session: &mut Box<dyn phone_auth_verifier::SecureSession + Send>,
        pending: phone_auth_verifier::PendingAuthorization,
    ) -> Result<phone_auth_verifier::Grant, ServiceError> {
        // Read before the frame is sent, because `accept` takes `pending` and
        // this is the only number that says how long the answer is worth
        // waiting for. `request_validity_ms` is the operator's to set, up to
        // the protocol's two-minute ceiling, so a flat wait here was a wait
        // that could be shorter than the window this machine had granted.
        let expires_at_ms = pending.request().expires_at_ms;
        session
            .send(&pending.frame())
            .map_err(|error| ServiceError::new("transport-failed", error.to_string()))?;

        let remaining = u64::try_from(expires_at_ms.saturating_sub(now_ms())).unwrap_or(0);
        let response = session
            .receive(Duration::from_millis(remaining).saturating_add(crate::ANSWER_TRAVEL_MARGIN))
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
        let session = self
            .transports
            .connect(&device_id, &credential_id)
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
            let mut custodian = self.phone_custodian(session, &device_id, &credential_id);
            phone_auth_locker::lock_file(&source, &plan, &mut custodian)
        };

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
        let session = self
            .transports
            .connect(&device_id, &credential_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let outcome = {
            let mut custodian = self.phone_custodian(session, &device_id, &credential_id);
            phone_auth_locker::unlock_file(
                &container,
                destination.as_deref(),
                !params.keep_container,
                UnlockKey::Phone(&mut custodian),
            )
        };

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
        let session = self
            .transports
            .connect(&device_id, &credential_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let outcome = {
            let mut custodian = self
                .phone_custodian(session, &device_id, &credential_id)
                .rekeying();
            phone_auth_locker::rekey_file(
                &container,
                &mut custodian,
                None,
                params.new_recovery_code,
            )
        };

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

    /// Enrolls a new volume key with a paired phone, for unlocking at boot.
    ///
    /// Returns paths and never key material. The volume key is written to
    /// `key_path`, owner-only, for `cryptsetup luksAddKey` to read and the
    /// caller to delete as soon as it has; the wrapper is written to
    /// `wrapped_key_path`, which is public and belongs in the initrd.
    ///
    /// Nothing here touches the volume. Adding the keyslot is the caller's job
    /// because this agent must not be able to write to a block device: it runs
    /// as root to guard `sudo`, and the less it can reach, the less a bug in it
    /// can do.
    pub fn luks_enroll(
        &mut self,
        params: &LuksEnrollParams,
    ) -> Result<LuksEnrollResult, ServiceError> {
        if params.volume.trim().is_empty() {
            return Err(ServiceError::new(
                "bad-params",
                "the volume needs a name; it is what the phone shows the user",
            ));
        }
        let wrapped_path = absolute_path(&params.wrapped_key_path)?;
        let key_path = absolute_path(&params.key_path)?;
        // Claimed before the phone is asked. Finding out that the key has
        // nowhere to go after a fingerprint has been spent is finding out too
        // late, and the second attempt would ask for another one.
        let key_slot = claim_key_file(&key_path)?;

        let (device_id, credential_id) = self.select_boot_credential(&params.credential_id)?;
        let session = self
            .transports
            .connect(&device_id, &credential_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;
        let mut session = session;

        let enrolled =
            crate::luks::enroll(session.as_mut(), &self.config.verifier_name, &params.volume);
        let enrolled = match enrolled {
            Ok(enrolled) => enrolled,
            Err(message) => {
                let error = ServiceError::new("declined", message);
                self.record_application(
                    "luks",
                    "enroll",
                    params.volume.clone(),
                    &device_name,
                    development,
                    Err(&error),
                );
                return Err(error);
            }
        };

        // The phone wraps with the credential the session was opened for. A
        // different one coming back means the initrd would later look for a
        // wrapper that credential cannot open, and would fall back to the
        // passphrase for a reason nobody could see.
        if enrolled.wrapped.credential_id != credential_id {
            let error = ServiceError::new(
                "response-mismatch",
                "the phone wrapped the key with a different credential",
            );
            self.record_application(
                "luks",
                "enroll",
                params.volume.clone(),
                &device_name,
                development,
                Err(&error),
            );
            return Err(error);
        }

        key_slot.write_bytes(enrolled.disk_key.expose())?;
        std::fs::write(&wrapped_path, enrolled.wrapped.encode())
            .map_err(|error| ServiceError::new("io-failed", error.to_string()))?;
        self.record_application(
            "luks",
            "enroll",
            params.volume.clone(),
            &device_name,
            development,
            Ok(()),
        );

        Ok(LuksEnrollResult {
            volume: params.volume.clone(),
            credential_id,
            wrapped_key_path: wrapped_path.to_string_lossy().into_owned(),
            key_path: key_path.to_string_lossy().into_owned(),
            device_name,
            development,
        })
    }

    /// Picks the credential that may wrap a volume key, and refuses a software
    /// one.
    ///
    /// The initrd will only ever use a hardware-backed disk-unlock credential:
    /// at boot there is no session to revoke and no way to notice a compromise.
    /// Enrolling a software key here would produce a keyslot that nothing can
    /// open, discovered at the worst possible moment.
    fn select_boot_credential(
        &self,
        credential_id: &Option<String>,
    ) -> Result<(String, String), ServiceError> {
        let (device_id, credential_id) =
            self.select_service_credential("luks", "disk unlock", credential_id.as_deref())?;
        let store = self.verifier.store();
        let usable = store
            .find_credential(&credential_id)
            .is_some_and(|(_, credential)| credential.key_kind.allowed_at_boot());
        if !usable {
            return Err(ServiceError::new(
                "policy-denied",
                format!(
                    "credential `{credential_id}` is not hardware-backed, and boot unlock only \
                     accepts a hardware key"
                ),
            ));
        }
        Ok((device_id, credential_id))
    }

    /// A custodian that dials the phone once for every request it makes.
    ///
    /// Spends `first` on the opening one, so an operation that needs a single
    /// exchange still costs a single dial. A rekey needs two -- unwrap the old
    /// key, wrap the new one -- and the phone closes a session as soon as it
    /// has answered on it.
    fn phone_custodian<'a>(
        &'a self,
        first: Box<dyn phone_auth_verifier::SecureSession + Send>,
        device_id: &'a str,
        credential_id: &'a str,
    ) -> PhoneCustodian<'a> {
        let mut first = Some(first);
        let transports = &self.transports;
        PhoneCustodian::new(
            move || match first.take() {
                Some(session) => Ok(session),
                None => transports
                    .connect(device_id, credential_id)
                    .map_err(phone_auth_locker::LockerError::Denied),
            },
            self.config.verifier_name.clone(),
            credential_id,
        )
    }

    /// Every item's metadata, spending `first` on the opening page and dialling
    /// again for each one after it.
    ///
    /// The phone closes a session once it has answered on it -- one session,
    /// one request -- and it holds the snapshot a walk started from for thirty
    /// seconds so that the pages of one walk still agree with each other. The
    /// caller hands over the session it already opened rather than throwing it
    /// away, so a vault that fits in one page still costs exactly one dial.
    fn walk_vault(
        &self,
        first: Box<dyn phone_auth_verifier::SecureSession + Send>,
        device_id: &str,
        credential_id: &str,
    ) -> Result<Vec<phone_auth_protocol::vault::ItemSummary>, VaultError> {
        let mut first = Some(first);
        let transports = &self.transports;
        vault::list_all(&self.config.verifier_name, || match first.take() {
            Some(session) => Ok(session),
            // Losing the phone partway through a walk is the same answer as
            // never reaching it: worth retrying, not worth explaining.
            None => transports
                .connect(device_id, credential_id)
                .map_err(|_| VaultError::Unavailable),
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
        let (device_id, credential_id) =
            self.select_vault_credential(params.credential_id.as_deref())?;
        let session = self
            .transports
            .connect(&device_id, &credential_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let listed = self.walk_vault(session, &device_id, &credential_id);

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
        let (device_id, credential_id) =
            self.select_service_credential("ssh", "SSH", params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id, &credential_id)
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
            .ok_or_else(|| ServiceError::new("bad-params", "origin is not a fillable origin"))?;

        let (device_id, credential_id) =
            self.select_vault_credential(params.credential_id.as_deref())?;
        let session = self
            .transports
            .connect(&device_id, &credential_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;

        let listed = self.walk_vault(session, &device_id, &credential_id);
        let matched = match listed {
            Ok(items) => items
                .into_iter()
                .filter(|item| {
                    matches!(item.kind, phone_auth_protocol::vault::ItemKind::Login)
                        && item_host(&item.uri).as_deref() == Some(host.as_str())
                })
                .collect::<Vec<_>>(),
            Err(error) => {
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
                let error = ServiceError::new("not-found", "no vault item for this site");
                self.record_vault("", "fill", &device_name, development, Err(&error));
                return Err(error);
            }
            several => {
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

        // A session of its own, because the listing spent the ones it opened:
        // the phone closes a session once it has answered on it.
        let mut session = self
            .transports
            .connect(&device_id, &credential_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
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

    /// Generates a password, stores it on the phone, and forgets it.
    ///
    /// The secret exists on this computer for the length of one call and never
    /// leaves this function: it is generated into a `Zeroizing<String>`, moved
    /// into the request that wipes it, and never returned, logged or named in
    /// the audit entry. The reply says what was made, not what it is.
    ///
    /// Generated here rather than accepted as a parameter. Taking one would
    /// have meant a password in the Electron process and on the IPC socket to
    /// buy nothing: the reason to make it on the desktop is that this is where
    /// the entropy is, not that this is somewhere to keep it.
    pub fn vault_create(
        &mut self,
        params: &VaultCreateParams,
    ) -> Result<VaultCreateResult, ServiceError> {
        // Refused before the phone is asked, the way `vault_copy` checks its
        // clipboard window first: a policy this rejects would otherwise be
        // found after the person had approved the sheet.
        let mut policy = Policy::default();
        if let Some(length) = params.length {
            policy.length = length;
        }
        if let Some(symbols) = params.symbols {
            policy.symbols = symbols;
        }
        let secret = password::generate(policy)
            .map_err(|error| ServiceError::new("bad-params", error.to_string()))?;

        let (device_id, credential_id) =
            self.select_vault_credential(params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id, &credential_id)
            .map_err(|error| ServiceError::new("no-transport", error))?;
        let device_name = self.device_name(&device_id);
        let development = session.security().is_development;
        let length = secret.chars().count();

        let written =
            PhoneVault::new(&mut session, self.config.verifier_name.clone()).create(NewItem {
                kind: ItemKind::Login,
                name: params.name.clone(),
                username: params.username.clone(),
                uri: params.uri.clone(),
                // The last copy on this side. `NewItem` hands it straight to a
                // request that wipes on drop, and `Zeroizing` clears the one
                // it was cloned from when this function returns.
                secret: secret.to_string(),
            });
        let _ = session.close();

        let written = match written {
            Ok(written) => written,
            Err(error) => {
                let error = vault_error(error);
                self.record_vault("", "create", &device_name, development, Err(&error));
                return Err(error);
            }
        };

        self.record_vault(
            &written.item_id,
            "create",
            &device_name,
            development,
            Ok(()),
        );
        Ok(VaultCreateResult {
            item_id: written.item_id,
            revision: written.revision,
            length,
        })
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
        let ttl = clipboard_ttl(params.clear_after_ms)?;

        let (device_id, credential_id) =
            self.select_vault_credential(params.credential_id.as_deref())?;
        let mut session = self
            .transports
            .connect(&device_id, &credential_id)
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

    /// Records a password generated straight to the clipboard.
    ///
    /// The one vault operation with nothing on the other end of it: no item, no
    /// phone, no approval sheet, no second factor. That is exactly why it
    /// belongs in the log. Every other route a secret takes to this machine's
    /// clipboard is written down, and this one -- one click and a password is
    /// on it -- was the only one that left no trace, so a log read back
    /// afterwards said the clipboard had never held anything.
    ///
    /// Nothing about the password is passed in, and there is nothing worth
    /// passing: the resource is empty for the same reason a listing's is, and
    /// the length stays out because it is a fact about the secret. There is no
    /// device either, since no phone took part; `development` is false because
    /// no pairing was trusted to make this happen, not because one was checked.
    pub fn record_generated_copy(&mut self, result: Result<(), &ServiceError>) {
        self.record_vault("", "generate", "", false, result);
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
    /// Writes key material rather than a code somebody retypes: no trailing
    /// newline, because `cryptsetup` reads the whole file as the key.
    fn write_bytes(mut self, bytes: &[u8]) -> Result<(), ServiceError> {
        std::fs::write(&self.path, bytes)
            .map_err(|error| ServiceError::new("io-failed", error.to_string()))?;
        self.written = true;
        Ok(())
    }

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
    claim_private_file(
        path,
        "recovery-file-exists",
        "that recovery code file already exists; choose another path",
    )
}

/// Where a volume key is put down on its way to `cryptsetup`.
///
/// Refusing a path that already exists is what stops an enrollment from
/// overwriting the key of a volume that is still using it.
fn claim_key_file(path: &Path) -> Result<RecoverySlot, ServiceError> {
    claim_private_file(
        path,
        "key-file-exists",
        "that key file already exists; choose another path",
    )
}

fn claim_private_file(
    path: &Path,
    code: &'static str,
    message: &'static str,
) -> Result<RecoverySlot, ServiceError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ServiceError::new(code, message)
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
/// The host of a fillable origin, lowercased, or None.
///
/// Written by hand rather than pulled from a URL crate because the rules
/// wanted here are narrower than a general parser's: two schemes, a
/// scheme-less string is not an origin, a port is not part of a host, and
/// userinfo — the classic way to make a host read as one thing and resolve as
/// another — is discarded rather than parsed.
///
/// `https` anywhere, and `http` only on this machine. The https rule is that a
/// password typed over plain HTTP is a password on the wire; a request to
/// localhost never reaches one, which is why browsers count it as a secure
/// context too. The extension draws the same line, and has to: a page it will
/// not inject into cannot ask, and an origin it does ask with has to be one
/// this side will accept.
pub fn origin_host(value: &str) -> Option<String> {
    if let Some(rest) = value.strip_prefix("https://") {
        return authority_host(rest);
    }
    let host = authority_host(value.strip_prefix("http://")?)?;
    is_loopback_host(&host).then_some(host)
}

/// Whether a host names this machine and nothing else.
///
/// `localhost` and everything under it are reserved for loopback by RFC 6761,
/// and the literal address is the rest of it. Nothing is resolved: a name that
/// points at 127.0.0.1 today can point elsewhere tomorrow, and resolving would
/// hand this decision to whoever answers the lookup.
fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1"
}

/// The host in the address field of a stored item.
///
/// Looser than [`origin_host`], and only on the side the user types. Somebody
/// filling in "Address" writes `github.com`; `https://` is not part of what
/// they think they are saying. The fill compared that field against a parsed
/// origin, so an item saved the natural way matched nothing and autofill
/// answered "no vault item for this site" -- which was not true, and was the
/// only thing the person had to go on.
///
/// This widens nothing about which site a password can reach. The page's own
/// origin is still parsed strictly by [`origin_host`], and the two are compared
/// by exact host equality: a scheme that never belonged to a browser tab cannot
/// produce a host that matches one.
fn item_host(value: &str) -> Option<String> {
    let value = value.trim();
    authority_host(match value.split_once("://") {
        Some((_, rest)) => rest,
        None => value,
    })
}

/// The host in `authority[/path]`, lowercased, with userinfo and port removed.
///
/// Userinfo is the classic way to make a host read as one thing and resolve as
/// another, so it is taken from the right of the last `@` rather than the left.
fn authority_host(rest: &str) -> Option<String> {
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
/// The clipboard lifetime a caller asked for, refused early if it is impossible.
///
/// `copy_secret` checks this too and is the real gate; this exists so the two
/// methods that offer `clearAfterMs` refuse it in the same words and at the
/// same point. They did neither. `vault.copy` checked here and named the
/// parameter; `vault.generate-copy` let the clipboard raise it and reported
/// `clear timeout must be between ...`, which is the same limit under a name
/// that appears in no API. Adjacent methods, one field, two answers.
///
/// Early also means before the work: `vault.generate-copy` drew a password and
/// moved it into locked pages before finding out the request could not be
/// satisfied. Nothing leaked -- the buffer is wiped when it drops -- but a
/// value that was never going to be used is not worth generating.
pub(crate) fn clipboard_ttl(clear_after_ms: Option<u64>) -> Result<Duration, ServiceError> {
    let ttl = clear_after_ms.map_or(clipboard::DEFAULT_TTL, Duration::from_millis);
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
    Ok(ttl)
}

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

/// What a relying party is allowed to hear about a refusal.
///
/// One sentence for every way the phone can say no. WebAuthn hands relying
/// parties a single undifferentiated failure by design, and the reasons here
/// are exactly the ones that design is about: whether a credential exists,
/// whether a fingerprint was accepted, whether the person pressed Cancel.
/// A site learns none of it.
///
/// Only refusals. A transport that broke or a request the agent would not
/// parse is this machine's own failure, says nothing about the person, and is
/// the kind of thing someone is going to have to debug.
fn browser_facing(error: ServiceError) -> ServiceError {
    if error.code == "declined" {
        ServiceError::new("declined", "passkey operation was cancelled or rejected")
    } else {
        error
    }
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
        // The phone's own account of the refusal, which this used to delete.
        //
        // The frame carries `error` precisely so the browser can be told what
        // happened, and every word of it was replaced here with a guess that
        // the person had cancelled. The phone knows the difference between a
        // passkey that no longer exists, an origin that does not match the
        // relying party, a fingerprint that never arrived, and someone
        // pressing Cancel; all four arrived at the website as the fourth one.
        //
        // Bounded and stripped of control characters, because it ends up in a
        // `DOMException` on a page: this is a device the desktop is already
        // trusting to sign, not an untrusted source, but a message is not a
        // reason to hand a page arbitrary length or arbitrary bytes.
        let reported = value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map(|reason| {
                reason
                    .chars()
                    .filter(|character| !character.is_control())
                    .take(160)
                    .collect::<String>()
            })
            .filter(|reason| !reason.trim().is_empty());
        return Err(ServiceError::new(
            "declined",
            reported.unwrap_or_else(|| "passkey operation was cancelled or rejected".to_owned()),
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

/// The same mapping the other way, for the pairing code.
fn wire_purpose(purpose: CredentialPurpose) -> phone_auth_protocol::CredentialPurpose {
    match purpose {
        CredentialPurpose::Authorization => phone_auth_protocol::CredentialPurpose::Authorization,
        CredentialPurpose::DiskUnlock => phone_auth_protocol::CredentialPurpose::DiskUnlock,
        CredentialPurpose::WebAuthn => phone_auth_protocol::CredentialPurpose::WebAuthn,
        CredentialPurpose::Vault => phone_auth_protocol::CredentialPurpose::Vault,
        CredentialPurpose::FileLocker => phone_auth_protocol::CredentialPurpose::FileLocker,
        CredentialPurpose::Ssh => phone_auth_protocol::CredentialPurpose::Ssh,
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

    fn paired(service: &mut Service) {
        let device = PairedDevice {
            device_id: "phone-1".into(),
            display_name: "Phone".into(),
            paired_at_ms: 1_700_000_000_000,
            session_identity_public_key: vec![1; 91],
            credentials: vec![phone_auth_verifier::PairedCredential {
                credential_id: "cred-1".into(),
                algorithm: phone_auth_protocol::PUBLIC_KEY_EC_P256_SPKI.into(),
                public_key: vec![2; 91],
                key_kind: phone_auth_verifier::KeyKind::StrongBox,
                purpose: CredentialPurpose::Authorization,
                permissions: Vec::new(),
                permissions_revision: 0,
            }],
        };
        service.verifier.store_mut().insert(device).expect("store");
    }

    fn revision(service: &Service) -> u64 {
        service
            .verifier
            .store()
            .device("phone-1")
            .expect("device")
            .credential("cred-1")
            .expect("credential")
            .permissions_revision
    }

    fn grant(service: &str) -> PermissionSummary {
        PermissionSummary {
            service: service.into(),
            action: policy::WILDCARD.into(),
            resource: policy::WILDCARD.into(),
            user: policy::WILDCARD.into(),
        }
    }

    /// The phone can edit the same set, so which of the two copies is newer has
    /// to be a number rather than a guess, and every local edit has to move it.
    ///
    /// A revocation most of all. Taking a grant away leaves a *smaller* set at
    /// the same revision, so a revocation that did not climb would lose the
    /// next reconciliation to the phone's older, wider copy -- and the powers
    /// the user just removed would come back on their own, from the device they
    /// were removed from.
    #[test]
    fn every_local_edit_moves_the_revision_including_taking_one_away() {
        let mut service = service("permission-revision");
        paired(&mut service);
        assert_eq!(revision(&service), 0, "an untouched pairing starts at zero");

        service
            .set_permissions("phone-1", "cred-1", vec![grant("sudo")])
            .expect("granting");
        assert_eq!(revision(&service), 1);

        service
            .set_permissions("phone-1", "cred-1", Vec::new())
            .expect("revoking");
        assert_eq!(
            revision(&service),
            2,
            "a revocation left the revision where the wider set could win it back"
        );
        assert!(service
            .verifier
            .store()
            .device("phone-1")
            .expect("device")
            .credential("cred-1")
            .expect("credential")
            .permissions
            .is_empty());
    }

    /// A set the desktop can store but the sync can never carry is a pairing
    /// that quietly stops settling.
    ///
    /// The wire bounds a set and this write path did not, so a grant with an
    /// empty field -- or the sixty-fifth grant -- was accepted locally and then
    /// refused by every settlement afterwards. Nothing tells the user: the
    /// desktop goes on enforcing what it stored, the phone is never told, and
    /// the failure surfaces on a later sync rather than on the edit that caused
    /// it. So the bound belongs on the edit.
    #[test]
    fn an_edit_the_sync_could_never_carry_is_refused_where_it_is_made() {
        let mut service = service("permission-bounds");
        paired(&mut service);

        service
            .set_permissions("phone-1", "cred-1", vec![grant("sudo")])
            .expect("a set within the bounds");

        let empty_field = PermissionSummary {
            service: "sudo".into(),
            action: String::new(),
            resource: policy::WILDCARD.into(),
            user: policy::WILDCARD.into(),
        };
        let error = service
            .set_permissions("phone-1", "cred-1", vec![empty_field])
            .expect_err("an empty field is not a wildcard, and the wire refuses it");
        assert_eq!(error.code, "invalid-permissions");

        let too_many: Vec<PermissionSummary> = (0..65).map(|n| grant(&format!("s{n}"))).collect();
        let error = service
            .set_permissions("phone-1", "cred-1", too_many)
            .expect_err("more grants than the wire carries");
        assert_eq!(error.code, "invalid-permissions");

        // Refused means unchanged: neither the set nor the revision moved, so
        // a rejected edit cannot win a later tie against the phone either.
        assert_eq!(
            revision(&service),
            1,
            "a refused edit moved the revision it was refused for"
        );
        let stored = service
            .verifier
            .store()
            .device("phone-1")
            .expect("device")
            .credential("cred-1")
            .expect("credential")
            .permissions
            .clone();
        assert_eq!(stored, vec![Permission::service("sudo")]);
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

        // The phone's words survive this far, and no further. They used to be
        // dropped right here, which kept them from the page and from the
        // person equally: the audit entry is written from this message, so
        // deleting it early left the log saying a passkey was denied and
        // nothing about why. The wall belongs one step later.
        assert!(error.message.contains("secret detail"));
        assert!(!browser_facing(error).message.contains("secret detail"));
    }

    #[test]
    fn a_broken_transport_is_not_dressed_up_as_a_refusal() {
        // Only refusals are made uniform. A failure of this machine's own says
        // nothing about the person and is the kind of thing someone has to
        // debug, so it keeps its words.
        let broken = ServiceError::new("transport-failed", "connection reset by peer");
        assert_eq!(browser_facing(broken).message, "connection reset by peer");
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
        let (_, live) = service.subscribe();
        let (_, gone) = service.subscribe();
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
        let (_, first) = service.subscribe();
        let (_, second) = service.subscribe();

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

    /// The address a person typed into the item, which is not an origin and
    /// was never going to be one.
    ///
    /// `github.com` is what someone writes in a field labelled "Address", and
    /// requiring `https://` there meant every item saved that way matched no
    /// site at all -- reported as "no vault item for this site", which reads as
    /// the vault being empty rather than as the address being spelled a way the
    /// agent would not read.
    #[test]
    fn an_item_address_may_be_written_the_way_a_person_writes_it() {
        for written in [
            "github.com",
            "https://github.com",
            "http://github.com/login",
            "  github.com/login?next=/  ",
            "github.com:8443",
            "GitHub.com",
        ] {
            assert_eq!(
                item_host(written),
                Some("github.com".to_owned()),
                "{written}"
            );
        }
    }

    /// Looser on the address does not mean looser on the match.
    #[test]
    fn a_lenient_address_still_matches_only_its_own_host() {
        // Userinfo disguises nothing here either.
        assert_eq!(
            item_host("bank.example@evil.example/"),
            Some("evil.example".to_owned())
        );
        // A sibling subdomain is still a different place to type a password.
        assert_ne!(
            item_host("blog.bank.example"),
            item_host("login.bank.example")
        );
        // And a field holding something that is not an address at all matches
        // nothing rather than matching loosely.
        assert_eq!(item_host("minha senha do banco"), None);
        assert_eq!(item_host(""), None);
        assert_eq!(item_host("https://"), None);
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

    /// The exception, and only for names that cannot leave this machine. A
    /// password sent to `http://localhost:3000` never reaches a wire; one sent
    /// to `http://bank.example` does, which is what the test above pins.
    #[test]
    fn plain_http_is_fillable_only_on_loopback() {
        assert_eq!(
            origin_host("http://localhost:3000"),
            Some("localhost".into())
        );
        assert_eq!(
            origin_host("http://127.0.0.1:8080/"),
            Some("127.0.0.1".into())
        );
        assert_eq!(
            origin_host("http://app.localhost/login"),
            Some("app.localhost".into())
        );
        assert_eq!(origin_host("http://LOCALHOST"), Some("localhost".into()));
    }

    /// A host that merely reads as loopback is not loopback. `localhost.evil`
    /// is a name evil owns, `notlocalhost` is somebody else's machine, and
    /// userinfo is the classic way to make the left of an `@` look like the
    /// host -- all of them resolve off this machine and none may be filled
    /// over plain http.
    #[test]
    fn a_host_that_only_looks_like_loopback_is_not_fillable_over_http() {
        assert_eq!(origin_host("http://localhost.evil.example"), None);
        assert_eq!(origin_host("http://notlocalhost"), None);
        assert_eq!(origin_host("http://localhost@evil.example/"), None);
        assert_eq!(origin_host("http://127.0.0.1.evil.example"), None);
        assert_eq!(origin_host("http://127.0.0.2"), None);
    }
}
