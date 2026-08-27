//! Cross-language wire format lock.
//!
//! The hex below was produced by an encoder written independently from
//! `src/cbor.rs`, straight from RFC 8949, so a shared bug in the Rust writer
//! and reader cannot make this test pass on its own.
//!
//! This is the contract with the Dart authenticator. `mobile/test/
//! protocol_golden_vector_test.dart` asserts the same bytes from the other
//! side. If a change here forces an edit to the constant, the phone will stop
//! verifying until the Dart side is changed to match, and every already-paired
//! device would need re-pairing.

use phone_auth_protocol::{AuthRequest, Decision};

/// Canonical encoding of the shared fixture request.
const REQUEST_FRAME_HEX: &str = concat!(
    "8e0101",
    "69",
    "726571756573742d31", // "request-1"
    "69",
    "6465736b746f702d31", // "desktop-1"
    "6c",
    "4465736b746f702d43617361", // "Desktop-Casa"
    "71",
    "6465736b746f702d312d7375646f2d7631", // "desktop-1-sudo-v1"
    "5820",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "64",
    "7375646f", // "sudo"
    "74",
    "6e69786f732d72656275696c6420737769746368", // "nixos-rebuild switch"
    "6d",
    "4465736b746f702d4e69784f53", // "Desktop-NixOS"
    "65",
    "616c696365", // "alice"
    "1b",
    "000001a03df10200", // issuedAt  1787745600000
    "1b",
    "000001a03df1ec60", // expiresAt 1787745660000
    "5820",
    "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
);

fn fixture() -> AuthRequest {
    let issued_at_ms = 1_787_745_600_000;
    AuthRequest {
        protocol_version: 1,
        request_id: "request-1".into(),
        verifier_id: "desktop-1".into(),
        verifier_name: "Desktop-Casa".into(),
        credential_id: "desktop-1-sudo-v1".into(),
        challenge: core::array::from_fn(|i| i as u8),
        service: "sudo".into(),
        action: "nixos-rebuild switch".into(),
        resource: "Desktop-NixOS".into(),
        user: "alice".into(),
        issued_at_ms,
        expires_at_ms: issued_at_ms + 60_000,
        session_binding: core::array::from_fn(|i| 255 - i as u8),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn request_encoding_matches_the_golden_vector() {
    let expected = from_hex(REQUEST_FRAME_HEX);
    assert_eq!(expected.len(), 186, "golden vector length");
    assert_eq!(to_hex(&fixture().encode()), to_hex(&expected));
}

#[test]
fn golden_vector_decodes_back_to_the_fixture() {
    let decoded = AuthRequest::decode(&from_hex(REQUEST_FRAME_HEX)).expect("golden frame decodes");
    assert_eq!(decoded, fixture());
}

#[test]
fn every_single_byte_mutation_of_the_golden_frame_is_rejected_or_changes_the_request() {
    // A verifier must never accept a frame that differs from what was signed
    // while still decoding to the same request. Either the mutation is
    // rejected outright, or it produces a visibly different request.
    let original = from_hex(REQUEST_FRAME_HEX);
    let baseline = fixture();

    for index in 0..original.len() {
        for bit in 0..8 {
            let mut mutated = original.clone();
            mutated[index] ^= 1 << bit;
            if let Ok(decoded) = AuthRequest::decode(&mutated) {
                assert_ne!(
                    decoded, baseline,
                    "byte {index} bit {bit} decoded to the original request"
                );
            }
        }
    }
}

#[test]
fn decision_wire_values_are_pinned() {
    // These indices come from the Dart enum's declaration order. Reordering
    // the enum would silently turn a denial into an authorization.
    assert_eq!(Decision::Authorized as u64, 0);
    assert_eq!(Decision::Denied as u64, 1);
}
