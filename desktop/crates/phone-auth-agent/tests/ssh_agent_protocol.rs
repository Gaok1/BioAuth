//! The ssh-agent protocol, parsed and built.
//!
//! An agent gets its messages from whatever process can reach its socket, so
//! every one of these inputs is attacker-chosen. What is asserted is that
//! nothing malformed becomes a signature, that a request this agent cannot
//! *describe* is a request it will not sign, and that refusals are all the
//! same refusal.

use phone_auth_agent::ssh_agent::{
    announced_length, failure, identities_answer, parse, sign_response, Request, SignRequest,
    MAX_MESSAGE_BYTES, SESSION_BIND, SSH_AGENTC_EXTENSION, SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_SIGN_REQUEST, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_SIGN_RESPONSE,
};
use phone_auth_protocol::ssh::{SshReader, SshWriter};

/// The blob RFC 4252 §7 defines, which is what a real client asks to sign.
fn userauth_blob(user: &str, service: &str, method: &str) -> Vec<u8> {
    let mut writer = SshWriter::new();
    writer
        .string(b"session-identifier-bytes")
        .u8(50) // SSH_MSG_USERAUTH_REQUEST
        .text(user)
        .text(service)
        .text(method)
        .u8(1)
        .text("ecdsa-sha2-nistp256")
        .string(b"key-blob");
    writer.into_bytes()
}

fn sign_body(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut writer = SshWriter::new();
    writer
        .u8(SSH_AGENTC_SIGN_REQUEST)
        .string(key_blob)
        .string(data)
        .u32(flags);
    writer.into_bytes()
}

#[test]
fn an_identity_request_is_recognised() {
    assert_eq!(parse(&[SSH_AGENTC_REQUEST_IDENTITIES]), Request::Identities);
}

/// A request with a payload where none belongs is not the request it claims to
/// be. Accepting it would mean this agent and OpenSSH disagree about what a
/// message is, which is where framing confusions start.
#[test]
fn an_identity_request_with_trailing_bytes_is_refused() {
    assert_eq!(
        parse(&[SSH_AGENTC_REQUEST_IDENTITIES, 0]),
        Request::Unsupported
    );
}

#[test]
fn a_sign_request_carries_its_key_data_and_flags() {
    let body = sign_body(b"the-key", b"the-data", 4);

    let Request::Sign(request) = parse(&body) else {
        panic!("not parsed as a sign request");
    };
    assert_eq!(request.key_blob, b"the-key");
    assert_eq!(request.data, b"the-data");
    assert_eq!(request.flags, 4);
}

/// The user and the service are the only things a plain sign request says
/// about its purpose, and they are what a confirmation can show.
#[test]
fn a_sign_request_describes_who_it_logs_in_as() {
    let request = SignRequest {
        key_blob: b"key".to_vec(),
        data: userauth_blob("alice", "ssh-connection", "publickey"),
        flags: 0,
    };

    let context = request.describe().expect("a well-formed blob");

    assert_eq!(context.user, "alice");
    assert_eq!(context.service, "ssh-connection");
}

/// A blob this agent cannot read is a blob it cannot describe, and there is no
/// signing anything a user cannot be shown. The caller relies on `None` here
/// meaning exactly that.
#[test]
fn a_blob_that_is_not_a_userauth_request_describes_as_nothing() {
    for data in [
        vec![],
        b"not structured at all".to_vec(),
        // Right shape, wrong message type.
        {
            let mut writer = SshWriter::new();
            writer.string(b"session").u8(51).text("alice");
            writer.into_bytes()
        },
        // Right message type, a method that is not publickey — which would be
        // a signature over something else entirely.
        userauth_blob("alice", "ssh-connection", "hostbased"),
    ] {
        let request = SignRequest {
            key_blob: b"key".to_vec(),
            data,
            flags: 0,
        };
        assert!(
            request.describe().is_none(),
            "described something it should not"
        );
    }
}

/// The extension that names the destination. Without it the agent knows a user
/// and a service and no host, which is the honest state for an older client.
#[test]
fn a_session_bind_names_the_host_and_says_whether_it_is_forwarded() {
    let mut writer = SshWriter::new();
    writer
        .u8(SSH_AGENTC_EXTENSION)
        .text(SESSION_BIND)
        .string(b"host-key-blob")
        .string(b"session-id")
        .string(b"signature")
        .u8(1);

    let Request::SessionBind(bind) = parse(&writer.into_bytes()) else {
        panic!("not parsed as a session bind");
    };
    assert_eq!(bind.host_key, b"host-key-blob");
    assert!(bind.forwarding, "a forwarded connection read as local");
}

#[test]
fn an_extension_this_agent_does_not_implement_is_refused_not_ignored() {
    let mut writer = SshWriter::new();
    writer.u8(SSH_AGENTC_EXTENSION).text("query");

    assert_eq!(parse(&writer.into_bytes()), Request::Unsupported);
}

/// Truncation at any point is a refusal, never a partially-read request. A
/// sign request missing its flags must not be signed with flags of zero.
#[test]
fn a_truncated_request_is_never_partially_accepted() {
    let whole = sign_body(b"the-key", b"the-data", 4);

    for cut in 1..whole.len() {
        assert_eq!(
            parse(&whole[..cut]),
            Request::Unsupported,
            "a request truncated to {cut} bytes was accepted"
        );
    }
}

#[test]
fn arbitrary_bytes_never_become_a_signature_request() {
    // Deterministic rather than random: a parser bug that only shows up on one
    // seed is a parser bug that comes back.
    let mut state = 0x12345678u32;
    for _ in 0..2000 {
        let mut bytes = Vec::new();
        for _ in 0..(state as usize % 64) {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            bytes.push((state >> 16) as u8);
        }
        // Reaching the end is the assertion: a panic here is a process any
        // local user can crash by writing to a socket.
        let _ = parse(&bytes);
    }
}

#[test]
fn an_identities_answer_lists_what_it_was_given() {
    let keys = vec![
        (b"blob-one".to_vec(), "phone one".to_owned()),
        (b"blob-two".to_vec(), "phone two".to_owned()),
    ];

    let framed = identities_answer(&keys);

    let length = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
    assert_eq!(
        length,
        framed.len() - 4,
        "length prefix disagrees with body"
    );
    assert_eq!(framed[4], SSH_AGENT_IDENTITIES_ANSWER);

    let mut reader = SshReader::new(&framed[5..]);
    assert_eq!(reader.u32().expect("count"), 2);
    assert_eq!(reader.string().expect("blob"), b"blob-one");
    assert_eq!(reader.text().expect("comment"), "phone one");
    assert_eq!(reader.string().expect("blob"), b"blob-two");
    assert_eq!(reader.text().expect("comment"), "phone two");
    reader.finish().expect("nothing trailing");
}

#[test]
fn an_empty_identity_list_is_a_valid_answer() {
    let framed = identities_answer(&[]);

    assert_eq!(framed[4], SSH_AGENT_IDENTITIES_ANSWER);
    let mut reader = SshReader::new(&framed[5..]);
    assert_eq!(reader.u32().expect("count"), 0);
    reader.finish().expect("nothing trailing");
}

#[test]
fn a_sign_response_carries_the_blob_and_nothing_else() {
    let framed = sign_response(b"signature-blob");

    assert_eq!(framed[4], SSH_AGENT_SIGN_RESPONSE);
    let mut reader = SshReader::new(&framed[5..]);
    assert_eq!(reader.string().expect("blob"), b"signature-blob");
    reader.finish().expect("nothing trailing");
}

/// One refusal for everything. A client that could tell a refused signature
/// from an unknown key could enumerate which keys the agent holds without ever
/// asking for the list — and the list is what the user consented to publish.
#[test]
fn every_refusal_is_the_same_five_bytes() {
    assert_eq!(failure(), vec![0, 0, 0, 1, SSH_AGENT_FAILURE]);
}

/// A length header is a number the client chose, and this socket is reachable
/// by anything running as this user.
#[test]
fn an_announced_length_is_checked_before_anything_is_allocated() {
    assert_eq!(announced_length(&[0, 0, 0, 5]), Ok(Some(5)));
    assert_eq!(
        announced_length(&[0, 0]),
        Ok(None),
        "an incomplete prefix waits"
    );
    assert!(announced_length(&[0, 0, 0, 0]).is_err(), "empty accepted");
    assert!(
        announced_length(&u32::MAX.to_be_bytes()).is_err(),
        "four gigabytes accepted"
    );
    assert!(
        announced_length(&((MAX_MESSAGE_BYTES as u32 + 1).to_be_bytes())).is_err(),
        "one byte over the cap accepted"
    );
    assert!(announced_length(&(MAX_MESSAGE_BYTES as u32).to_be_bytes()).is_ok());
}
