//! The `ssh.sign` payloads.
//!
//! This is the most powerful operation in the protocol: a request to sign
//! bytes the desktop chose, with a key the desktop cannot otherwise reach.
//! What keeps it from being a blind signing oracle is that the phone reads the
//! blob itself and refuses anything that is not a `publickey` userauth
//! request. These tests are that rule.

use phone_auth_protocol::ssh::{
    account_in_request, SignRequest, SignResponse, MAX_SIGN_DATA_BYTES, SIGNATURE_LEN,
};
use phone_auth_protocol::ssh::{SshWriter, OPERATION_SIGN};
use phone_auth_protocol::ApplicationFrame;

fn userauth_blob(user: &str, service: &str, method: &str) -> Vec<u8> {
    let mut writer = SshWriter::new();
    writer
        .string(b"session-identifier")
        .u8(50)
        .text(user)
        .text(service)
        .text(method)
        .u8(1)
        .text("ecdsa-sha2-nistp256")
        .string(b"key-blob");
    writer.into_bytes()
}

fn request() -> SignRequest {
    SignRequest {
        verifier_name: "Meu computador".into(),
        destination: "SHA256:abcdef".into(),
        data: userauth_blob("alice", "ssh-connection", "publickey"),
    }
}

#[test]
fn a_sign_request_round_trips() {
    let payload = request().encode();

    let decoded = SignRequest::decode(&payload).expect("our own encoding");

    assert_eq!(decoded, request());
    assert_eq!(decoded.encode(), payload);
}

#[test]
fn a_sign_response_round_trips() {
    let response = SignResponse {
        signature: vec![0x7f; SIGNATURE_LEN],
    };

    let decoded = SignResponse::decode(&response.encode()).expect("our own encoding");

    assert_eq!(decoded, response);
}

/// A signature of any other length is a different curve or a truncated read,
/// and wrapping it would produce a login failure nobody can diagnose.
#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    for length in [0usize, 63, 65, 128] {
        let response = SignResponse {
            signature: vec![0x01; length],
        };
        assert!(
            SignResponse::decode(&response.encode()).is_err(),
            "{length} bytes accepted"
        );
    }
}

#[test]
fn an_empty_or_oversized_blob_is_refused() {
    for data in [vec![], vec![0x01; MAX_SIGN_DATA_BYTES + 1]] {
        let request = SignRequest { data, ..request() };
        assert!(SignRequest::decode(&request.encode()).is_err());
    }
}

/// Trailing bytes are refused for the reason every payload here refuses them:
/// two byte strings that mean the same thing would be two requests one
/// approval covers.
#[test]
fn a_non_canonical_payload_is_refused() {
    let mut payload = request().encode();
    payload.push(0);

    assert!(SignRequest::decode(&payload).is_err());
}

#[test]
fn truncation_is_always_refused() {
    let payload = request().encode();

    for cut in 0..payload.len() {
        assert!(
            SignRequest::decode(&payload[..cut]).is_err(),
            "truncated to {cut} bytes was accepted"
        );
    }
}

/// The check that stops this being a blind signing oracle. A compromised
/// desktop can put anything in `data`; the phone runs this on it and signs
/// nothing it cannot name an account for.
#[test]
fn only_a_publickey_userauth_request_has_an_account() {
    let (user, service) =
        account_in_request(&userauth_blob("alice", "ssh-connection", "publickey"))
            .expect("a well-formed request");
    assert_eq!(user, "alice");
    assert_eq!(service, "ssh-connection");

    for blob in [
        vec![],
        b"arbitrary bytes somebody wants signed".to_vec(),
        // A different authentication method signs something else entirely.
        userauth_blob("alice", "ssh-connection", "hostbased"),
        userauth_blob("alice", "ssh-connection", "password"),
        // The right method inside the wrong message.
        {
            let mut writer = SshWriter::new();
            writer
                .string(b"session")
                .u8(51)
                .text("alice")
                .text("ssh-connection")
                .text("publickey");
            writer.into_bytes()
        },
    ] {
        assert!(
            account_in_request(&blob).is_none(),
            "an account was read out of something that is not a publickey request"
        );
    }
}

/// Arbitrary bytes must never produce an account, and must never panic —
/// this runs on the phone, on data the desktop chose.
#[test]
fn arbitrary_bytes_never_yield_an_account() {
    let mut state = 0xC0FFEEu32;
    for _ in 0..4000 {
        let mut bytes = Vec::new();
        for _ in 0..(state as usize % 96) {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            bytes.push((state >> 16) as u8);
        }
        // Reaching the end is the assertion. A panic here is a phone that
        // crashes on a frame a desktop sent it.
        let _ = account_in_request(&bytes);
    }
}

/// The operation name has to be one the frame validator accepts, or the
/// payloads above are unreachable.
#[test]
fn the_operation_is_carried_by_an_application_frame() {
    let frame = ApplicationFrame {
        protocol_version: 1,
        kind: phone_auth_protocol::ApplicationFrameKind::Request,
        request_id: "request-1".into(),
        session_binding: [7u8; 32],
        operation: OPERATION_SIGN.into(),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_030_000,
        payload: request().encode(),
    };

    let encoded = frame.encode();
    let decoded = ApplicationFrame::decode(&encoded).expect("a valid ssh frame");

    assert_eq!(decoded.operation, OPERATION_SIGN);
    assert_eq!(
        SignRequest::decode(&decoded.payload).expect("payload"),
        request()
    );
}

/// Pins the bytes the Dart side has to reproduce.
///
/// A change here is a protocol change and must move `mobile/` in the same
/// commit. Two encoders that drift apart produce a phone that refuses every
/// request from its own desktop, with a message about a malformed payload.
#[test]
fn a_sign_request_pins_its_bytes() {
    let request = SignRequest {
        verifier_name: "Desktop".into(),
        destination: "SHA256:aaaa".into(),
        data: vec![0x01, 0x02, 0x03],
    };

    assert_eq!(hex(&request.encode()), SIGN_REQUEST_VECTOR);
}

#[test]
fn a_sign_response_pins_its_bytes() {
    let response = SignResponse {
        signature: (0..64).map(|byte| byte as u8).collect(),
    };

    assert_eq!(hex(&response.encode()), SIGN_RESPONSE_VECTOR);
}

/// Shared with `mobile/test/ssh_payloads_test.dart`. Changing either without
/// the other is the bug these exist to catch.
const SIGN_REQUEST_VECTOR: &str = "8401674465736b746f706b5348413235363a6161616143010203";
const SIGN_RESPONSE_VECTOR: &str = concat!(
    "82015840000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d",
    "1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
