//! The IPC wire types shared by the agent, the tray UI and the CLI.
//!
//! One JSON object per line in each direction. Requests carry a token; replies
//! echo the request id. Unsolicited event lines have no id, which is how a
//! client tells them apart from replies.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::transport::TransportStatus;

/// A client-to-agent call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Call {
    pub id: u64,
    /// Shared secret from the endpoint file. Proves the caller can read a file
    /// only this user account can read.
    pub token: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// An agent-to-client reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl Reply {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, code: &str, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(ApiError {
                code: code.to_owned(),
                message: message.into(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable machine-readable code. The CLI maps these to exit codes, so
    /// they are part of the interface and should not be renamed casually.
    pub code: String,
    pub message: String,
}

/// Pushed to subscribed clients.
///
/// The tray UI renders these directly, which is why they carry display
/// context and never protocol material.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    /// A request is now waiting on the phone.
    RequestStarted {
        request_id: String,
        service: String,
        action: String,
        resource: String,
        user: String,
        device_name: String,
        origin: String,
        expires_at_ms: i64,
        development: bool,
    },
    /// A request reached a verdict.
    RequestFinished {
        request_id: String,
        granted: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// The paired device list changed.
    DevicesChanged,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusPayload {
    pub verifier_id: String,
    pub verifier_name: String,
    /// True when the agent was started with `--dev-simulator`. The UI shows a
    /// persistent banner while this holds.
    pub development_mode: bool,
    pub paired_devices: Vec<DeviceSummary>,
    pub transports: Vec<TransportStatus>,
    /// False when no transport can currently reach a phone.
    pub can_authorize: bool,
    /// Human-readable list of what is still missing, for the UI to show.
    pub blocked_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSummary {
    pub device_id: String,
    pub display_name: String,
    pub paired_at_ms: i64,
    pub credentials: Vec<CredentialSummary>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSummary {
    pub credential_id: String,
    pub key_kind: String,
    pub purpose: String,
    pub permissions: Vec<PermissionSummary>,
    /// Whether this credential may be used for boot-time unlock.
    pub usable_at_boot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSummary {
    pub service: String,
    pub action: String,
    pub resource: String,
    pub user: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeParams {
    pub service: String,
    pub action: String,
    pub resource: String,
    pub user: String,
    /// Optional; required only when more than one paired credential could
    /// serve the request, so that the agent never silently picks one.
    #[serde(default)]
    pub credential_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeResult {
    pub granted: bool,
    pub request_id: String,
    pub device_name: String,
    pub origin: String,
    pub development: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnParams {
    pub operation: String,
    pub origin: String,
    pub options: Value,
    #[serde(default)]
    pub credential_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnResult {
    pub response: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgetParams {
    pub device_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPermissionsParams {
    pub device_id: String,
    pub credential_id: String,
    pub permissions: Vec<PermissionSummary>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

/// The desktop's half of a pairing bootstrap.
///
/// Carries no permanent secret: a session id, a fresh nonce and an expiry. The
/// phone treats it as a hint about where to connect, and identity is
/// established by the handshake that follows, not by possession of this.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingBootstrap {
    pub protocol_version: u64,
    pub verifier_id: String,
    pub verifier_name: String,
    pub session_id: String,
    /// 32 fresh bytes, base64url.
    pub nonce: String,
    pub expires_at_ms: i64,
    /// Where the phone should connect. Empty until a transport can publish an
    /// endpoint.
    pub endpoint: String,
    /// The scannable string.
    pub qr_payload: String,
    /// Set when the exchange cannot actually be completed yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_on: Option<String>,
}

/// A pairing handshake that completed and is awaiting the user's confirmation.
///
/// Nothing here is trusted yet. The handshake proved the peer holds *a* key;
/// only the user comparing [`Self::verification_code`] against the phone's
/// screen establishes that it is the phone in their hand.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingProposalSummary {
    /// Names this attempt. Confirming quotes it back, so an answer meant for
    /// an attempt that has since been cancelled or replaced cannot land on the
    /// one that took its place — six digits alone cannot say which is which.
    pub attempt_id: String,
    pub device_id: String,
    pub device_name: String,
    pub credential_id: String,
    pub key_kind: String,
    pub purpose: String,
    /// Six digits. The user checks this matches the phone before confirming.
    pub verification_code: String,
    /// Whether this credential could ever be used for boot-time unlock.
    pub usable_at_boot: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmPairingParams {
    /// Echoed back by the UI, so a stale screen cannot confirm a pairing the
    /// user never looked at.
    pub verification_code: String,
    /// The attempt the UI was showing. Optional so an older tray still works;
    /// when present it must match, and it is the only thing that distinguishes
    /// two attempts whose codes happen to agree.
    #[serde(default)]
    pub attempt_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_omits_the_branch_it_did_not_take() {
        let ok = serde_json::to_string(&Reply::ok(1, serde_json::json!({"a": 1}))).unwrap();
        assert!(ok.contains("\"result\""));
        assert!(!ok.contains("\"error\""));

        let err = serde_json::to_string(&Reply::err(2, "denied", "nope")).unwrap();
        assert!(err.contains("\"error\""));
        assert!(!err.contains("\"result\""));
    }

    #[test]
    fn events_are_tagged_so_a_client_can_dispatch_on_them() {
        let event = Event::RequestFinished {
            request_id: "r-1".into(),
            granted: true,
            reason: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"request-finished\""), "{json}");
        assert!(!json.contains("reason"), "absent reason is omitted");
    }

    #[test]
    fn an_event_line_has_no_id_field_to_confuse_it_with_a_reply() {
        let json = serde_json::to_string(&Event::DevicesChanged).unwrap();
        assert!(!json.contains("\"id\""), "{json}");
    }

    #[test]
    fn authorize_params_accept_an_absent_credential() {
        let parsed: AuthorizeParams = serde_json::from_str(
            r#"{"service":"sudo","action":"ls","resource":"host","user":"alice"}"#,
        )
        .expect("parse");
        assert_eq!(parsed.credential_id, None);
    }
}
