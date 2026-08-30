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
    pub request_id: String,
    pub operation: String,
    pub origin: String,
    pub options: Value,
    #[serde(default)]
    pub credential_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelWebAuthnParams {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnResult {
    pub response: Value,
}

/// Lock a file into a container.
///
/// `recovery_code_path` is where the agent writes the one-time recovery code.
/// It is a required field, and the reply carries only the path: no client —
/// least of all the Electron tray — ever receives the code over IPC.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockerLockParams {
    pub path: String,
    pub recovery_code_path: String,
    /// Keep the plaintext where it is. The default removes it once the
    /// container has been written and verified.
    #[serde(default)]
    pub keep_original: bool,
    #[serde(default)]
    pub credential_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockerLockResult {
    pub container: String,
    /// Where the recovery code was written. Never the code itself.
    pub recovery_code_path: String,
    pub plaintext_len: u64,
    pub original_removed: bool,
    pub device_name: String,
    pub development: bool,
}

/// Enrolling a volume key for boot unlock.
///
/// Both paths are named by the caller and neither is optional: the agent hands
/// back where it put things, never what it put there.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LuksEnrollParams {
    /// What the phone shows the user. The volume being opened, in words.
    pub volume: String,
    /// Where the public wrapper goes: the file the initrd reads.
    pub wrapped_key_path: String,
    /// Where the new volume key goes, owner-only, for `cryptsetup luksAddKey`
    /// to read and the caller to delete immediately after.
    pub key_path: String,
    #[serde(default)]
    pub credential_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LuksEnrollResult {
    pub volume: String,
    pub credential_id: String,
    pub wrapped_key_path: String,
    /// Where the volume key was written. Never the key itself.
    pub key_path: String,
    pub device_name: String,
    pub development: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockerUnlockParams {
    pub path: String,
    #[serde(default)]
    pub keep_container: bool,
    #[serde(default)]
    pub credential_id: Option<String>,
    /// Where to restore. Defaults to the container's own directory.
    #[serde(default)]
    pub destination_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockerUnlockResult {
    pub restored: String,
    pub plaintext_len: u64,
    pub container_removed: bool,
    pub device_name: String,
    pub development: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockerRekeyParams {
    pub path: String,
    #[serde(default)]
    pub credential_id: Option<String>,
    /// Also issue a fresh recovery code, invalidating the previous one. When
    /// set, `recovery_code_path` says where to write it.
    #[serde(default)]
    pub new_recovery_code: bool,
    #[serde(default)]
    pub recovery_code_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockerRekeyResult {
    pub container: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_code_path: Option<String>,
    pub device_name: String,
    pub development: bool,
}

/// Ask the paired phone for the vault's metadata.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultListParams {
    /// Which vault credential to use. Omitted when exactly one is enrolled.
    #[serde(default)]
    pub credential_id: Option<String>,
}

/// One row of the desktop's vault list. Carries no secret.
///
/// This is the metadata the phone already agreed to hand over without a
/// prompt. The secret for any of these rows costs a separate `vault.copy`,
/// which the user approves on the device.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultItem {
    /// Opaque and stable. The tray echoes it back and derives nothing from it.
    pub id: String,
    pub revision: u64,
    /// `login` or `note`.
    pub kind: String,
    pub name: String,
    pub username: String,
    pub uri: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultListResult {
    pub items: Vec<VaultItem>,
    pub device_name: String,
    pub development: bool,
}

/// Copy one stored secret to the clipboard, without it crossing IPC.
///
/// `expected_revision` is the revision of the row the user clicked. If the
/// phone answers with a different one the copy is refused: the value would
/// belong to a version edited elsewhere, and the user would be pasting
/// something they never saw.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultCopyParams {
    pub item_id: String,
    pub expected_revision: u64,
    #[serde(default)]
    pub credential_id: Option<String>,
    /// How long the clipboard entry lives before it is removed.
    #[serde(default)]
    pub clear_after_ms: Option<u64>,
}

/// Release one site's password to the browser, for autofill.
///
/// The one call in this surface that answers with a secret. Everything else
/// exists so that a password reaches the clipboard without passing through a
/// renderer; autofill cannot work that way, because filling a field *is*
/// handing the page's process the plaintext. `VLT-09` accepts that, so what is
/// left is to make the opening as small as it can be:
///
/// - one origin in, and it comes from the browser rather than from the page;
/// - at most one secret out, and only when exactly one item matches;
/// - the phone still approves it, with the sheet that names the site.
///
/// Not on the tray's allow-list. The tray has a Copy button and no business
/// with this.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultFillParams {
    /// The page's origin, exactly as the browser reported it.
    pub origin: String,
    #[serde(default)]
    pub credential_id: Option<String>,
}

/// The secret being handed to a browser, and the account it belongs to.
///
/// Unlike [`VaultCopyResult`], this type has the field. That is the whole
/// difference between the two paths and the reason they are separate types
/// rather than one with an option.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultFillResult {
    pub password: String,
    pub username: String,
}

/// Ask the phone to sign one SSH authentication request.
///
/// `data` is the blob RFC 4252 defines, passed through unchanged: a server
/// accepts a signature over exactly those bytes and nothing else.
///
/// Reachable only from the SSH agent, and not from the tray. The tray has no
/// use for a signature and every method it can reach is a method a renderer
/// can be talked into calling.
///
/// `Serialize` as well as `Deserialize` so the SSH agent binary builds this
/// type instead of hand-rolling the same base64 a third time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshSignParams {
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    /// What this computer believes the connection is going to, for the phone
    /// to display. A claim, not a fact — the phone cannot check it.
    #[serde(default)]
    pub destination: String,
    #[serde(default)]
    pub credential_id: Option<String>,
}

/// The raw `r || s` pair. The SSH encoding happens in the agent, so the
/// `mpint` rule has one implementation rather than two.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshSignResult {
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

/// Bytes over a JSON channel. Base64 rather than an array of numbers: a
/// two-kilobyte blob as `[1,2,3,...]` is eight kilobytes of JSON.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let triple = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
            out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(triple >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[triple as usize & 63] as char
            } else {
                '='
            });
        }
        serializer.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut out = Vec::new();
        let mut accumulator = 0u32;
        let mut bits = 0u32;
        for byte in text.bytes().filter(|byte| *byte != b'=') {
            let index = ALPHABET
                .iter()
                .position(|candidate| *candidate == byte)
                .ok_or_else(|| serde::de::Error::custom("not base64"))?
                as u32;
            accumulator = (accumulator << 6) | index;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((accumulator >> bits) as u8);
            }
        }
        Ok(out)
    }
}

/// Generate a password and put it straight on the clipboard.
///
/// Every field is optional and falls back to the generator's own default, so a
/// caller that has no opinion sends `{}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultGenerateCopyParams {
    #[serde(default)]
    pub length: Option<usize>,
    #[serde(default)]
    pub lowercase: Option<bool>,
    #[serde(default)]
    pub uppercase: Option<bool>,
    #[serde(default)]
    pub digits: Option<bool>,
    #[serde(default)]
    pub symbols: Option<bool>,
    /// How long the clipboard entry lives before it is removed.
    #[serde(default)]
    pub clear_after_ms: Option<u64>,
}

/// What a copy did — never what it copied.
///
/// There is deliberately no field carrying the password and no sibling method
/// that returns one. The tray is an Electron process: a password that reaches
/// it has entered a renderer, a V8 heap that may be dumped, and whatever
/// devtools happens to be attached. Doing the copy in the agent is only worth
/// anything if the plaintext never makes that trip, so the type that crosses
/// IPC cannot express it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultCopyResult {
    /// How many bytes were copied. Not which ones.
    pub length: usize,
    pub clears_at_ms: i64,
    /// The entry was marked to stay out of clipboard history.
    pub history_excluded: bool,
    /// The entry was marked to stay off the cloud clipboard.
    pub cloud_excluded: bool,
    /// Whether the plaintext sat in pages the OS agreed to keep out of the
    /// pagefile. False is a report the UI should be able to show, not a
    /// failure: quotas make it an ordinary outcome.
    pub memory_locked: bool,
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
    /// What the credential this pairing enrols will be for, as a service name.
    ///
    /// Echoed back so the person at the keyboard can see that `--service ssh`
    /// was understood before they scan: the difference is invisible in the
    /// picture, and a code for the wrong purpose enrols the wrong key.
    pub service: String,
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
