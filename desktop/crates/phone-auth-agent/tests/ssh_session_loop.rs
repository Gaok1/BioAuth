//! One agent connection, driven with byte vectors.
//!
//! These are the paths that decide whether a key gets used: which requests
//! reach the phone at all, what the phone is shown, and what a refusal looks
//! like from the client's side. An agent testable only by running `ssh`
//! against it is an agent whose refusals nobody checks.

use phone_auth_agent::ssh_agent::{
    SESSION_BIND, SSH_AGENTC_EXTENSION, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
    SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE, SSH_AGENT_SUCCESS,
};
use phone_auth_agent::ssh_policy::{fingerprint, Prompt, SshPolicy};
use phone_auth_agent::ssh_session::{SshBackend, SshFraming, SshSession};
use phone_auth_protocol::ssh::{decode_signature, encode_public_key, SshWriter};
use std::cell::RefCell;
use std::rc::Rc;

fn point() -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend(std::iter::repeat_n(0x11, 64));
    point
}

fn key_blob() -> Vec<u8> {
    encode_public_key(&point()).expect("a valid point")
}

fn userauth_blob(user: &str, method: &str) -> Vec<u8> {
    let mut writer = SshWriter::new();
    writer
        .string(b"session-identifier")
        .u8(50)
        .text(user)
        .text("ssh-connection")
        .text(method)
        .u8(1)
        .text("ecdsa-sha2-nistp256")
        .string(b"key-blob");
    writer.into_bytes()
}

fn sign_body(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut writer = SshWriter::new();
    writer
        .u8(SSH_AGENTC_SIGN_REQUEST)
        .string(key)
        .string(data)
        .u32(0);
    writer.into_bytes()
}

fn bind_body(host_key: &[u8], forwarding: bool) -> Vec<u8> {
    let mut writer = SshWriter::new();
    writer
        .u8(SSH_AGENTC_EXTENSION)
        .text(SESSION_BIND)
        .string(host_key)
        .string(b"session-id")
        .string(b"signature")
        .u8(u8::from(forwarding));
    writer.into_bytes()
}

/// What the phone was shown, kept outside the session so a test can read it.
///
/// The session owns its backend, and asserting on the prompt through a second
/// request would only prove the second request was refused too — which is not
/// the same claim.
type Seen = Rc<RefCell<Vec<Prompt>>>;

/// A phone that says yes, and records what it was shown.
struct Phone {
    seen: Seen,
    refuse: bool,
}

impl Phone {
    fn new() -> (Self, Seen) {
        let seen: Seen = Rc::new(RefCell::new(Vec::new()));
        (
            Self {
                seen: Rc::clone(&seen),
                refuse: false,
            },
            seen,
        )
    }

    fn refusing() -> (Self, Seen) {
        let (mut phone, seen) = Self::new();
        phone.refuse = true;
        (phone, seen)
    }
}

impl SshBackend for Phone {
    fn identities(&mut self) -> Vec<(Vec<u8>, String)> {
        vec![(key_blob(), "phone".to_owned())]
    }

    fn sign(&mut self, _key_blob: &[u8], _data: &[u8], prompt: &Prompt) -> Option<Vec<u8>> {
        self.seen.borrow_mut().push(prompt.clone());
        if self.refuse {
            return None;
        }
        Some((0..64).map(|byte| byte as u8).collect())
    }
}

fn session(phone: Phone, policy: SshPolicy) -> SshSession<Phone> {
    SshSession::new(phone, policy)
}

#[test]
fn an_identity_request_lists_the_key_without_asking_the_phone() {
    let mut session = session(Phone::new().0, SshPolicy::new());

    let reply = session.handle(&[SSH_AGENTC_REQUEST_IDENTITIES]);

    assert_eq!(reply[4], SSH_AGENT_IDENTITIES_ANSWER);
}

#[test]
fn a_session_bind_is_acknowledged_and_remembered() {
    let mut session = session(Phone::new().0, SshPolicy::new());

    let reply = session.handle(&bind_body(b"host-key", false));

    assert_eq!(reply[4], SSH_AGENT_SUCCESS);
    assert_eq!(session.destination(), Some(fingerprint(b"host-key")));
}

#[test]
fn a_signature_reaches_the_client_in_ssh_encoding() {
    let mut session = session(Phone::new().0, SshPolicy::new());
    session.handle(&bind_body(b"host-key", false));

    let reply = session.handle(&sign_body(
        &key_blob(),
        &userauth_blob("alice", "publickey"),
    ));

    assert_eq!(reply[4], SSH_AGENT_SIGN_RESPONSE);
    // The blob the client receives has to decode back to the raw pair the
    // phone produced, or no server accepts it.
    let mut reader = phone_auth_protocol::ssh::SshReader::new(&reply[5..]);
    let blob = reader.string().expect("signature blob");
    let raw = decode_signature(blob).expect("a valid signature blob");
    assert_eq!(raw, (0..64).map(|byte| byte as u8).collect::<Vec<u8>>());
}

/// The prompt is what the user reads before a key that opens a session gets
/// used. If it does not carry the account and the destination, it is a prompt
/// that gets approved without being read.
#[test]
fn the_phone_is_shown_the_account_and_the_destination() {
    let (phone, seen) = Phone::new();
    let mut session = session(phone, SshPolicy::new());
    session.handle(&bind_body(b"host-key", false));

    session.handle(&sign_body(
        &key_blob(),
        &userauth_blob("deploy", "publickey"),
    ));

    let prompt = seen.borrow().first().cloned().expect("the phone was asked");
    assert_eq!(prompt.user, "deploy");
    assert_eq!(prompt.destination, Some(fingerprint(b"host-key")));
    assert!(!prompt.forwarded);
    assert!(prompt.first_time, "a first visit was not flagged");
}

/// The second login to the same host in one session is no longer a first
/// visit. Flagging every one would make the flag mean nothing.
#[test]
fn a_second_login_to_the_same_host_is_not_flagged_as_new() {
    let (phone, seen) = Phone::new();
    let mut session = session(phone, SshPolicy::new());
    session.handle(&bind_body(b"host-key", false));

    session.handle(&sign_body(
        &key_blob(),
        &userauth_blob("alice", "publickey"),
    ));
    session.handle(&sign_body(
        &key_blob(),
        &userauth_blob("alice", "publickey"),
    ));

    let prompts = seen.borrow();
    assert!(prompts[0].first_time);
    assert!(!prompts[1].first_time, "the second visit was still flagged");
}

/// A client too old to send `session-bind` gets a prompt that says the
/// destination is unknown, rather than one with a blank where a host goes.
#[test]
fn an_unnamed_destination_reaches_the_phone_as_unnamed() {
    let (phone, seen) = Phone::new();
    let mut session = session(phone, SshPolicy::new());

    session.handle(&sign_body(
        &key_blob(),
        &userauth_blob("alice", "publickey"),
    ));

    assert_eq!(seen.borrow()[0].destination, None);
}

/// A key the agent never advertised must not be usable. Otherwise a client can
/// name any blob and have it signed.
#[test]
fn a_key_this_agent_never_offered_is_refused() {
    let mut session = session(Phone::new().0, SshPolicy::new());
    session.handle(&bind_body(b"host-key", false));

    let mut other = vec![0x04];
    other.extend(std::iter::repeat_n(0x99, 64));
    let reply = session.handle(&sign_body(
        &encode_public_key(&other).expect("encode"),
        &userauth_blob("alice", "publickey"),
    ));

    assert_eq!(reply[4], SSH_AGENT_FAILURE);
}

/// A blob that is not a publickey userauth request never reaches the phone.
/// There is no approving what nobody can read.
#[test]
fn an_undescribable_request_never_reaches_the_phone() {
    let mut session = session(Phone::new().0, SshPolicy::new());
    session.handle(&bind_body(b"host-key", false));

    let reply = session.handle(&sign_body(&key_blob(), b"arbitrary bytes"));

    assert_eq!(reply[4], SSH_AGENT_FAILURE);
}

#[test]
fn a_forwarded_connection_is_refused_by_default() {
    let mut session = session(Phone::new().0, SshPolicy::new());
    session.handle(&bind_body(b"host-key", true));

    let reply = session.handle(&sign_body(
        &key_blob(),
        &userauth_blob("alice", "publickey"),
    ));

    assert_eq!(reply[4], SSH_AGENT_FAILURE);
}

/// A destination becomes familiar only once a signature actually happened. A
/// refused host that counted as familiar would drop the warning on the retry,
/// which is exactly when it matters.
#[test]
fn a_refused_destination_never_becomes_familiar() {
    let (phone, _) = Phone::refusing();
    let mut refusing = session(phone, SshPolicy::new());
    refusing.handle(&bind_body(b"host-key", false));
    refusing.handle(&sign_body(
        &key_blob(),
        &userauth_blob("alice", "publickey"),
    ));

    // A fresh session over the same policy state: the refusal must not have
    // been recorded, so this one is still a first visit.
    let mut accepting = session(Phone::new().0, SshPolicy::new());
    accepting.handle(&bind_body(b"host-key", false));
    let reply = accepting.handle(&sign_body(
        &key_blob(),
        &userauth_blob("alice", "publickey"),
    ));

    assert_eq!(reply[4], SSH_AGENT_SIGN_RESPONSE);
}

/// Everything this agent will not do reaches the client identically. A client
/// that could tell a refused signature from an unknown key could enumerate the
/// agent's keys without ever asking for the list.
#[test]
fn every_refusal_looks_the_same_from_the_client() {
    let (refusing, _) = Phone::refusing();

    let refused = session(refusing, SshPolicy::new()).handle(&sign_body(
        &key_blob(),
        &userauth_blob("alice", "publickey"),
    ));
    let unknown_key = session(Phone::new().0, SshPolicy::new()).handle(&sign_body(
        b"not-a-key",
        &userauth_blob("alice", "publickey"),
    ));
    let malformed = session(Phone::new().0, SshPolicy::new()).handle(&[0xff]);

    assert_eq!(refused, unknown_key);
    assert_eq!(refused, malformed);
}

// --- framing ---------------------------------------------------------------

#[test]
fn framing_reassembles_messages_split_across_reads() {
    let body = sign_body(&key_blob(), &userauth_blob("alice", "publickey"));
    let mut stream = (body.len() as u32).to_be_bytes().to_vec();
    stream.extend(&body);

    let mut framing = SshFraming::new();
    let mut out = Vec::new();
    // One byte at a time, which is what a slow socket looks like.
    for byte in &stream {
        out.extend(framing.push(&[*byte]).expect("valid framing"));
    }

    assert_eq!(out, vec![body]);
}

#[test]
fn framing_returns_several_messages_from_one_read() {
    let first = vec![SSH_AGENTC_REQUEST_IDENTITIES];
    let second = bind_body(b"host", false);
    let mut stream = Vec::new();
    for body in [&first, &second] {
        stream.extend((body.len() as u32).to_be_bytes());
        stream.extend(body);
    }

    let mut framing = SshFraming::new();

    assert_eq!(
        framing.push(&stream).expect("valid framing"),
        vec![first, second]
    );
}

/// A length header is a number the peer chose, and this socket is reachable by
/// anything running as this user.
#[test]
fn framing_refuses_a_length_it_will_not_honour() {
    let mut framing = SshFraming::new();

    assert!(framing.push(&u32::MAX.to_be_bytes()).is_err());
    assert!(
        SshFraming::new().push(&[0, 0, 0, 0]).is_err(),
        "empty message"
    );
}

#[test]
fn framing_holds_an_incomplete_message_rather_than_guessing() {
    let mut framing = SshFraming::new();

    assert!(framing.push(&[0, 0, 0, 8, 1, 2]).expect("valid").is_empty());
    assert_eq!(
        framing.push(&[3, 4, 5, 6, 7, 8]).expect("valid"),
        vec![vec![1, 2, 3, 4, 5, 6, 7, 8]]
    );
}
