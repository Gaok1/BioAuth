//! The ssh-agent protocol, without a socket.
//!
//! `SYS-02`. Parsing and building only: what to do about a request belongs to
//! the caller, where a user can be asked. Keeping the two apart is what makes
//! the interesting half testable at all — an agent that could only be
//! exercised by running `ssh` would be an agent nobody exercised.
//!
//! # What a signature here actually authorizes
//!
//! An SSH signature is not like the rest of this project's approvals. A `sudo`
//! grant is spent immediately and a vault copy releases one secret; an SSH
//! signature logs somebody in, and the session it opens outlives the approval
//! by as long as the user leaves the terminal open. That asymmetry is why the
//! confirmation has to name the destination, and why an agent that says only
//! "sign something?" is not enough.
//!
//! # What the request does and does not say
//!
//! RFC 4252 §7 defines the blob a client asks to have signed. Inside it are
//! the **user name** and the **service**, so those can be shown. The hostname
//! is *not* in it — the session identifier binds the server's host key
//! cryptographically but is not a name anyone can read.
//!
//! OpenSSH 8.9 and newer close that gap with `session-bind@openssh.com`, which
//! hands the agent the server's host key before any signing. Where it arrives,
//! the destination can be named and pinned. Where it does not — an older
//! client — this agent knows what it does not know, and says so rather than
//! inventing a hostname.

use phone_auth_protocol::ssh::{SshReader, SshWriter};

/// Numbers from OpenSSH's `PROTOCOL.agent`.
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_EXTENSION: u8 = 27;

/// The extension that tells an agent which host a connection is to.
pub const SESSION_BIND: &str = "session-bind@openssh.com";

/// The byte that opens a `SSH_MSG_USERAUTH_REQUEST`, per RFC 4252.
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// A cap on one agent message.
///
/// OpenSSH uses 256 KiB. The length is a number the client chose, and this is
/// a socket any process running as this user can connect to.
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// What a client asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// "What keys do you have?"
    Identities,
    Sign(SignRequest),
    /// A `session-bind@openssh.com`, naming the host this connection is to.
    SessionBind(SessionBind),
    /// Understood as a message, not as something this agent does. Answered
    /// with a failure rather than ignored, because a client waiting on a reply
    /// that never comes hangs the terminal.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    /// Which key the client wants used, as the blob the identity list gave it.
    pub key_blob: Vec<u8>,
    /// The bytes to sign. Structured, and [`SignRequest::describe`] reads it.
    pub data: Vec<u8>,
    pub flags: u32,
}

/// Who and what a sign request is for, as far as the request itself says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignContext {
    pub user: String,
    pub service: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBind {
    /// The server's host key blob. Its fingerprint is what names a
    /// destination, and it is what a per-host rule is written against.
    pub host_key: Vec<u8>,
    /// True when this agent is reached through a forwarded connection rather
    /// than from the local machine.
    ///
    /// A forwarded agent is one a remote host can ask to sign things. That is
    /// a legitimate feature and a well-known way to lose a key, so it is
    /// surfaced rather than buried.
    pub forwarding: bool,
}

impl SignRequest {
    /// The user and service the client is authenticating for.
    ///
    /// Returns `None` when the blob is not the shape RFC 4252 defines — which
    /// is not necessarily an attack, but is a request this agent cannot
    /// describe to a human, and there is no signing anything undescribed.
    pub fn describe(&self) -> Option<SignContext> {
        let mut reader = SshReader::new(&self.data);
        let _session_id = reader.string().ok()?;
        if reader.u8().ok()? != SSH_MSG_USERAUTH_REQUEST {
            return None;
        }
        let user = reader.text().ok()?.to_owned();
        let service = reader.text().ok()?.to_owned();
        let method = reader.text().ok()?;
        if method != "publickey" {
            return None;
        }
        Some(SignContext { user, service })
    }
}

/// Reads one agent message body — the bytes after the length prefix.
pub fn parse(body: &[u8]) -> Request {
    let Some((&kind, rest)) = body.split_first() else {
        return Request::Unsupported;
    };
    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES if rest.is_empty() => Request::Identities,
        SSH_AGENTC_SIGN_REQUEST => {
            let mut reader = SshReader::new(rest);
            let Ok(key_blob) = reader.string() else {
                return Request::Unsupported;
            };
            let Ok(data) = reader.string() else {
                return Request::Unsupported;
            };
            let Ok(flags) = reader.u32() else {
                return Request::Unsupported;
            };
            if reader.finish().is_err() {
                return Request::Unsupported;
            }
            Request::Sign(SignRequest {
                key_blob: key_blob.to_vec(),
                data: data.to_vec(),
                flags,
            })
        }
        SSH_AGENTC_EXTENSION => {
            let mut reader = SshReader::new(rest);
            let Ok(name) = reader.text() else {
                return Request::Unsupported;
            };
            if name != SESSION_BIND {
                return Request::Unsupported;
            }
            let Ok(host_key) = reader.string() else {
                return Request::Unsupported;
            };
            // The session identifier and the signature over it prove the
            // client is really talking to that host. They are read to keep the
            // parse honest about the message's shape; verifying them needs the
            // host key's algorithm and is the caller's decision to make.
            if reader.string().is_err() || reader.string().is_err() {
                return Request::Unsupported;
            }
            let Ok(forwarding) = reader.u8() else {
                return Request::Unsupported;
            };
            if reader.finish().is_err() {
                return Request::Unsupported;
            }
            Request::SessionBind(SessionBind {
                host_key: host_key.to_vec(),
                forwarding: forwarding != 0,
            })
        }
        _ => Request::Unsupported,
    }
}

/// The identity list answer.
pub fn identities_answer(keys: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut writer = SshWriter::new();
    writer
        .u8(SSH_AGENT_IDENTITIES_ANSWER)
        .u32(keys.len() as u32);
    for (blob, comment) in keys {
        writer.string(blob).text(comment);
    }
    framed(writer.into_bytes())
}

/// The signature answer.
pub fn sign_response(signature_blob: &[u8]) -> Vec<u8> {
    let mut writer = SshWriter::new();
    writer.u8(SSH_AGENT_SIGN_RESPONSE).string(signature_blob);
    framed(writer.into_bytes())
}

/// The one answer to everything this agent will not do.
///
/// Deliberately identical for a refused signature, an unknown key and a
/// malformed request. A client that could tell those apart could ask the agent
/// which keys it holds without asking for the list — and the list is the thing
/// the user consented to publishing.
pub fn failure() -> Vec<u8> {
    framed(vec![SSH_AGENT_FAILURE])
}

pub fn success() -> Vec<u8> {
    framed(vec![SSH_AGENT_SUCCESS])
}

/// Puts the 32-bit length in front, which is the framing every message uses.
fn framed(body: Vec<u8>) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend(body);
    out
}

/// The length a client announced, checked before anything is allocated.
///
/// Returns `None` when the prefix is incomplete, and an error when the length
/// is one this agent will not honour.
pub fn announced_length(prefix: &[u8]) -> Result<Option<usize>, &'static str> {
    if prefix.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes(prefix[..4].try_into().expect("four bytes")) as usize;
    if length == 0 {
        return Err("empty agent message");
    }
    if length > MAX_MESSAGE_BYTES {
        return Err("agent message over the size limit");
    }
    Ok(Some(length))
}
