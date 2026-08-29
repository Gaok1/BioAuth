//! One ssh-agent connection, without owning the socket.
//!
//! `SYS-02`. The transport differs per platform — a Unix domain socket on
//! Linux and macOS, a named pipe on Windows — and none of that changes what an
//! agent does with a message. Keeping the decision loop here means it can be
//! driven from a test with two byte vectors, which is the only way the
//! interesting paths get exercised at all: an agent testable only by running
//! `ssh` against it is an agent whose refusals nobody checks.

use crate::ssh_agent::{
    announced_length, failure, identities_answer, parse, sign_response, Request, SessionBind,
};
use crate::ssh_policy::{fingerprint, Decision, Prompt, SshPolicy};

/// What the session can ask of the world outside it.
///
/// A trait rather than a closure because two of these have to be mocked
/// together, and a signature that returns without a prompt having happened is
/// the bug worth being able to write a test for.
pub trait SshBackend {
    /// The keys to advertise: an SSH public key blob and a comment each.
    ///
    /// Metadata only. Listing identities costs no approval — it releases
    /// nothing, and a prompt on every `ssh` invocation would train the user to
    /// approve without reading.
    fn identities(&mut self) -> Vec<(Vec<u8>, String)>;

    /// Asks the phone to sign, showing `prompt`.
    ///
    /// Returns the raw 64-byte signature, or `None` for any refusal. The
    /// reason is deliberately not returned: every refusal reaches the client
    /// as the same five bytes.
    fn sign(&mut self, key_blob: &[u8], data: &[u8], prompt: &Prompt) -> Option<Vec<u8>>;
}

/// One connection.
///
/// A session, not a server: `session-bind` applies to the connection it
/// arrived on, so a per-connection value is the only place it can live without
/// one `ssh` leaking its destination into another's approval.
pub struct SshSession<B: SshBackend> {
    backend: B,
    policy: SshPolicy,
    bind: Option<SessionBind>,
}

impl<B: SshBackend> SshSession<B> {
    pub fn new(backend: B, policy: SshPolicy) -> Self {
        Self {
            backend,
            policy,
            bind: None,
        }
    }

    /// Handles one message body and returns the framed reply.
    pub fn handle(&mut self, body: &[u8]) -> Vec<u8> {
        match parse(body) {
            Request::Identities => identities_answer(&self.backend.identities()),

            Request::SessionBind(bind) => {
                // Recorded, not answered with a signature. A client sends this
                // before signing and expects a plain success.
                self.bind = Some(bind);
                crate::ssh_agent::success()
            }

            Request::Sign(request) => {
                let context = request.describe();
                let Decision::Ask(prompt) =
                    self.policy.decide(context.as_ref(), self.bind.as_ref())
                else {
                    return failure();
                };

                // The key has to be one this agent advertised. Signing with
                // anything else would mean a client naming a key it was never
                // offered and getting it used.
                if !self
                    .backend
                    .identities()
                    .iter()
                    .any(|(blob, _)| blob == &request.key_blob)
                {
                    return failure();
                }

                let Some(raw) = self.backend.sign(&request.key_blob, &request.data, &prompt) else {
                    return failure();
                };
                let Ok(blob) = phone_auth_protocol::ssh::encode_signature(&raw) else {
                    return failure();
                };

                // Remembered only after a signature actually happened, so a
                // refused destination never becomes a familiar one.
                if let Some(destination) = prompt.destination {
                    self.policy.remember(destination);
                }
                sign_response(&blob)
            }

            Request::Unsupported => failure(),
        }
    }

    /// The fingerprint of the destination this connection named, if any.
    pub fn destination(&self) -> Option<String> {
        self.bind.as_ref().map(|bind| fingerprint(&bind.host_key))
    }
}

/// Splits a stream of bytes into agent message bodies.
///
/// Kept separate from the session because framing errors and protocol errors
/// are different failures: a bad frame ends the connection, and a bad request
/// is answered and the connection continues.
#[derive(Default)]
pub struct SshFraming {
    pending: Vec<u8>,
}

impl SshFraming {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes and returns whatever complete messages they finished.
    ///
    /// An error means the peer announced a length this agent will not honour,
    /// and the caller should close: there is no resynchronising a stream whose
    /// framing is wrong.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            let Some(length) = announced_length(&self.pending)? else {
                return Ok(out);
            };
            if self.pending.len() < 4 + length {
                return Ok(out);
            }
            out.push(self.pending[4..4 + length].to_vec());
            self.pending.drain(..4 + length);
        }
    }
}
