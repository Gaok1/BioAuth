//! Issuing authorization requests and deciding whether an answer grants them.

use std::time::{SystemTime, UNIX_EPOCH};

use phone_auth_protocol::{
    AuthRequest, AuthResponse, Decision, ProtocolError, MAX_VALIDITY_MS, PROTOCOL_VERSION,
};

use crate::pairing::{CredentialPurpose, PairingStore};
use crate::policy;
use crate::random;
use crate::replay::ReplayGuard;
use crate::session::SecureSession;
use crate::signature::{self, SignatureError};

/// Current wall-clock time in milliseconds since the Unix epoch.
///
/// The protocol never trusts time alone — freshness comes from the challenge
/// and the single-use request id — so a clock that is merely wrong delays or
/// rejects authorizations rather than granting them.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// This machine's identity as seen by a phone.
#[derive(Debug, Clone)]
pub struct VerifierIdentity {
    /// Stable identifier, generated once at first run.
    pub verifier_id: String,
    /// Name shown in the biometric prompt. The user picks this, and it is the
    /// main cue that lets them notice a request from a machine that is not
    /// theirs.
    pub verifier_name: String,
}

/// What the caller wants authorized.
#[derive(Debug, Clone)]
pub struct RequestSpec {
    pub credential_id: String,
    pub service: String,
    pub action: String,
    pub resource: String,
    pub user: String,
    /// How long the phone has to answer, clamped to the protocol maximum.
    pub validity_ms: i64,
}

impl RequestSpec {
    pub fn new(
        credential_id: impl Into<String>,
        service: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        user: impl Into<String>,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            service: service.into(),
            action: action.into(),
            resource: resource.into(),
            user: user.into(),
            validity_ms: 60_000,
        }
    }

    pub fn with_validity_ms(mut self, validity_ms: i64) -> Self {
        self.validity_ms = validity_ms;
        self
    }
}

/// A request that has been issued and is awaiting an answer.
///
/// Consumed by value in [`Verifier::accept`]: one issued request can produce
/// at most one grant, enforced by the type system rather than by remembering
/// to check a flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthorization {
    request: AuthRequest,
    origin: String,
    session_binding: [u8; 32],
}

impl PendingAuthorization {
    pub fn request(&self) -> &AuthRequest {
        &self.request
    }

    /// The bytes to put on the wire.
    pub fn frame(&self) -> Vec<u8> {
        self.request.encode()
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// A completed, verified authorization.
///
/// Holding one of these means: a paired phone, over a confidential
/// peer-authenticated session, signed exactly this request with a key that
/// requires strong biometrics per use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub request_id: String,
    pub device_id: String,
    pub device_name: String,
    pub credential_id: String,
    pub service: String,
    pub action: String,
    pub resource: String,
    pub user: String,
    pub origin: String,
    pub granted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    /// The channel was not confidential and peer-authenticated.
    ChannelUnsuitable {
        transport: String,
    },
    /// No paired credential with that id.
    UnknownCredential(String),
    /// The credential exists but is registered for a different purpose.
    PurposeMismatch {
        credential_id: String,
        registered: CredentialPurpose,
        requested: CredentialPurpose,
    },
    /// A software-backed key was offered for a boot-time flow.
    KeyKindUnsuitableForBoot {
        credential_id: String,
    },
    /// A development transport was offered for a boot-time flow.
    DevelopmentTransportRefused {
        transport: String,
    },
    /// Local policy does not cover this request.
    PolicyDenied,
    /// The response did not answer the request that was issued.
    ResponseMismatch {
        field: &'static str,
    },
    /// The session changed between issuing and accepting.
    SessionBindingMismatch,
    /// The user declined on the phone.
    Declined,
    Expired,
    Replayed,
    Protocol(ProtocolError),
    Signature(SignatureError),
    /// The request this verifier built was itself invalid.
    Malformed(ProtocolError),
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelUnsuitable { transport } => write!(
                f,
                "transport `{transport}` is not confidential and peer-authenticated"
            ),
            Self::UnknownCredential(id) => write!(f, "no paired credential `{id}`"),
            Self::PurposeMismatch {
                credential_id,
                registered,
                requested,
            } => write!(
                f,
                "credential `{credential_id}` is registered for {registered:?}, not {requested:?}"
            ),
            Self::KeyKindUnsuitableForBoot { credential_id } => write!(
                f,
                "credential `{credential_id}` is not hardware-backed and cannot be used at boot"
            ),
            Self::DevelopmentTransportRefused { transport } => write!(
                f,
                "`{transport}` is a development transport and cannot be used at boot"
            ),
            Self::PolicyDenied => f.write_str("local policy does not allow this request"),
            Self::ResponseMismatch { field } => {
                write!(f, "response `{field}` did not match the request")
            }
            Self::SessionBindingMismatch => {
                f.write_str("session binding changed between request and response")
            }
            Self::Declined => f.write_str("authorization was declined on the phone"),
            Self::Expired => f.write_str("the request expired before it was answered"),
            Self::Replayed => f.write_str("this request was already answered"),
            Self::Protocol(error) => write!(f, "protocol error: {error}"),
            Self::Signature(error) => write!(f, "signature check failed: {error}"),
            Self::Malformed(error) => write!(f, "built an invalid request: {error}"),
        }
    }
}

impl std::error::Error for AuthorizationError {}

impl From<SignatureError> for AuthorizationError {
    fn from(error: SignatureError) -> Self {
        Self::Signature(error)
    }
}

/// The verifier: pairing records, replay state and the decision procedure.
#[derive(Debug)]
pub struct Verifier {
    identity: VerifierIdentity,
    store: PairingStore,
    replay: ReplayGuard,
}

impl Verifier {
    pub fn new(identity: VerifierIdentity, store: PairingStore) -> Self {
        Self {
            identity,
            store,
            replay: ReplayGuard::default(),
        }
    }

    pub fn identity(&self) -> &VerifierIdentity {
        &self.identity
    }

    pub fn store(&self) -> &PairingStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut PairingStore {
        &mut self.store
    }

    /// Builds and validates a fresh request.
    ///
    /// Everything that can be checked without the user is checked here, so a
    /// phone is never made to buzz for a request this machine would refuse to
    /// accept anyway.
    pub fn issue(
        &mut self,
        spec: &RequestSpec,
        session: &dyn SecureSession,
        now_ms: i64,
    ) -> Result<PendingAuthorization, AuthorizationError> {
        let security = session.security();
        if !security.suitable_for_authorization() {
            return Err(AuthorizationError::ChannelUnsuitable {
                transport: security.transport_name.clone(),
            });
        }

        let (_, credential) = self
            .store
            .find_credential(&spec.credential_id)
            .ok_or_else(|| AuthorizationError::UnknownCredential(spec.credential_id.clone()))?;

        let purpose = CredentialPurpose::for_service(&spec.service);
        if credential.purpose != purpose {
            return Err(AuthorizationError::PurposeMismatch {
                credential_id: spec.credential_id.clone(),
                registered: credential.purpose,
                requested: purpose,
            });
        }
        if purpose == CredentialPurpose::DiskUnlock {
            // Boot-time unlock has no fallback path and no logged-in user to
            // notice something is wrong, so both the key and the transport
            // have to be the real thing.
            if !credential.key_kind.allowed_at_boot() {
                return Err(AuthorizationError::KeyKindUnsuitableForBoot {
                    credential_id: spec.credential_id.clone(),
                });
            }
            if security.is_development {
                return Err(AuthorizationError::DevelopmentTransportRefused {
                    transport: security.transport_name.clone(),
                });
            }
        }

        let validity = spec.validity_ms.clamp(1, MAX_VALIDITY_MS);
        let request = AuthRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: random::request_id(),
            verifier_id: self.identity.verifier_id.clone(),
            verifier_name: self.identity.verifier_name.clone(),
            credential_id: spec.credential_id.clone(),
            challenge: random::bytes::<32>(),
            service: spec.service.clone(),
            action: spec.action.clone(),
            resource: spec.resource.clone(),
            user: spec.user.clone(),
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(validity),
            session_binding: session.session_binding(),
        };
        request.validate().map_err(AuthorizationError::Malformed)?;

        if !policy::permits(&credential.permissions, &request) {
            return Err(AuthorizationError::PolicyDenied);
        }

        Ok(PendingAuthorization {
            request,
            origin: session.origin_label().to_owned(),
            session_binding: session.session_binding(),
        })
    }

    /// Checks an answer and, if everything holds, produces a [`Grant`].
    ///
    /// The pairing lookup and the policy check are repeated here rather than
    /// trusted from `issue`: a device may have been unpaired, or its
    /// permissions narrowed, while the phone was being tapped.
    pub fn accept(
        &mut self,
        pending: PendingAuthorization,
        response_frame: &[u8],
        session: &dyn SecureSession,
        now_ms: i64,
    ) -> Result<Grant, AuthorizationError> {
        let security = session.security();
        if !security.suitable_for_authorization() {
            return Err(AuthorizationError::ChannelUnsuitable {
                transport: security.transport_name.clone(),
            });
        }
        if session.session_binding() != pending.session_binding {
            return Err(AuthorizationError::SessionBindingMismatch);
        }

        let request = pending.request;
        let response =
            AuthResponse::decode(response_frame).map_err(AuthorizationError::Protocol)?;

        if response.request_id != request.request_id {
            return Err(AuthorizationError::ResponseMismatch { field: "requestId" });
        }
        if response.verifier_id != request.verifier_id {
            return Err(AuthorizationError::ResponseMismatch {
                field: "verifierId",
            });
        }
        if response.credential_id != request.credential_id {
            return Err(AuthorizationError::ResponseMismatch {
                field: "credentialId",
            });
        }
        if response.protocol_version != request.protocol_version {
            return Err(AuthorizationError::ResponseMismatch {
                field: "protocolVersion",
            });
        }

        // Burn the request id before doing any crypto. A request is single-use
        // whatever the outcome, so a failed attempt must not leave an id that
        // a second answer could still use.
        if !self.replay.consume(&request.request_id) {
            return Err(AuthorizationError::Replayed);
        }
        if request.is_expired_at(now_ms) {
            return Err(AuthorizationError::Expired);
        }
        if response.decision == Decision::Denied {
            return Err(AuthorizationError::Declined);
        }

        let (device, credential) = self
            .store
            .find_credential(&request.credential_id)
            .ok_or_else(|| AuthorizationError::UnknownCredential(request.credential_id.clone()))?;

        if !policy::permits(&credential.permissions, &request) {
            return Err(AuthorizationError::PolicyDenied);
        }

        signature::verify_authorization(
            &credential.algorithm,
            &credential.public_key,
            &response.algorithm,
            &request.signing_payload(),
            &response.signature,
        )?;

        Ok(Grant {
            request_id: request.request_id,
            device_id: device.device_id.clone(),
            device_name: device.display_name.clone(),
            credential_id: request.credential_id,
            service: request.service,
            action: request.action,
            resource: request.resource,
            user: request.user,
            origin: pending.origin,
            granted_at_ms: now_ms,
        })
    }
}
