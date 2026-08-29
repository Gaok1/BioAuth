//! Whether to ask the phone to sign an SSH login, and what to say when asking.
//!
//! `SYS-02` asks for contextual confirmation and limits on destination and
//! command. Two of those three are achievable here and one is not, and saying
//! which is which is the point of this module existing separately from the
//! protocol.
//!
//! **Destination: yes, when the client is new enough.** OpenSSH 8.9+ sends
//! `session-bind@openssh.com` before signing, which carries the server's host
//! key. Its fingerprint is a durable name for a destination and is what a
//! per-host rule is written against. An older client sends nothing, and this
//! module then knows it does not know the destination — which is a reason to
//! ask, not a reason to guess.
//!
//! **Command: no, and not here.** An SSH signature covers the *authentication*
//! request, not the command that follows it. The agent never sees `rm -rf`; by
//! the time a command exists the session is already open. Restricting commands
//! is `authorized_keys`' `command=` on the server, and pretending an agent can
//! do it would be a checkbox that protects nothing.
//!
//! **Forwarding: refused by default.** A forwarded agent is one the remote
//! host can ask to sign things, for as long as the connection lasts. It is a
//! real feature and a well-known way to lose a key, so it is opt-in per host
//! rather than on.

use std::collections::BTreeSet;

use crate::ssh_agent::{SessionBind, SignContext};

/// What the agent should do with a sign request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Ask the phone, showing this.
    Ask(Prompt),
    /// Refuse without asking. The reason is for the agent's own log, never for
    /// the client: every refusal looks the same on the wire.
    Refuse(&'static str),
}

/// What the phone shows before signing.
///
/// Every field is something the user can check against what they just typed.
/// A prompt that said only "sign?" would be a prompt that gets approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    /// The account being logged into.
    pub user: String,
    /// The host key fingerprint, or `None` when the client did not say.
    pub destination: Option<String>,
    /// True when this agent was reached through a forwarded connection.
    pub forwarded: bool,
    /// True when the destination is one this machine has signed into before.
    ///
    /// A first-time destination is not refused — that would make the feature
    /// unusable — but it is worth saying, because it is the case where a
    /// mistake is most likely.
    pub first_time: bool,
}

/// The hosts this agent will sign for, and how.
#[derive(Debug, Clone, Default)]
pub struct SshPolicy {
    /// Fingerprints seen before. Not an allow-list: a name for "you have done
    /// this before", which is the difference between a routine approval and
    /// one worth reading.
    known: BTreeSet<String>,
    /// Fingerprints allowed to be reached through a forwarded agent.
    forwardable: BTreeSet<String>,
    /// When set, the only destinations that may be signed for at all.
    ///
    /// Empty means no restriction, which is the default: an allow-list that
    /// has to be populated before the first login is an allow-list nobody
    /// populates.
    restricted_to: BTreeSet<String>,
}

impl SshPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts signing to these destinations and no others.
    pub fn restrict_to(&mut self, fingerprints: impl IntoIterator<Item = String>) -> &mut Self {
        self.restricted_to = fingerprints.into_iter().collect();
        self
    }

    pub fn allow_forwarding_to(&mut self, fingerprint: impl Into<String>) -> &mut Self {
        self.forwardable.insert(fingerprint.into());
        self
    }

    /// Records that a signature was made for this destination.
    pub fn remember(&mut self, fingerprint: impl Into<String>) {
        self.known.insert(fingerprint.into());
    }

    /// Decides what to do about one request.
    ///
    /// `bind` is what the client said about the destination, if anything.
    pub fn decide(&self, context: Option<&SignContext>, bind: Option<&SessionBind>) -> Decision {
        // A request this agent cannot describe is a request the user cannot be
        // shown. There is no approving something nobody can read.
        let Some(context) = context else {
            return Decision::Refuse("the sign request is not a readable login");
        };
        if context.user.is_empty() {
            return Decision::Refuse("the sign request names no account");
        }

        let destination = bind.map(|bind| fingerprint(&bind.host_key));
        let forwarded = bind.is_some_and(|bind| bind.forwarding);

        if let Some(fingerprint) = &destination {
            if !self.restricted_to.is_empty() && !self.restricted_to.contains(fingerprint) {
                return Decision::Refuse("this destination is not in the allow-list");
            }
            if forwarded && !self.forwardable.contains(fingerprint) {
                return Decision::Refuse("agent forwarding is not allowed to this host");
            }
        } else {
            // No destination and a restriction to enforce is a request that
            // cannot be checked against the restriction. Refusing is the only
            // answer that keeps the restriction meaning anything.
            if !self.restricted_to.is_empty() {
                return Decision::Refuse("the client did not name a destination");
            }
            if forwarded {
                return Decision::Refuse("agent forwarding is not allowed");
            }
        }

        Decision::Ask(Prompt {
            user: context.user.clone(),
            first_time: destination
                .as_ref()
                .is_none_or(|fingerprint| !self.known.contains(fingerprint)),
            destination,
            forwarded,
        })
    }
}

/// OpenSSH's `SHA256:` fingerprint of a host key blob.
///
/// The same string `ssh` prints when it asks about an unknown host, so a user
/// comparing the two is comparing like with like — which is the only way the
/// destination line on the phone is worth anything.
pub fn fingerprint(host_key: &[u8]) -> String {
    format!("SHA256:{}", base64_unpadded(&sha256(host_key)))
}

fn base64_unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(ALPHABET[(accumulator >> bits) as usize & 63] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[(accumulator << (6 - bits)) as usize & 63] as char);
    }
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}
