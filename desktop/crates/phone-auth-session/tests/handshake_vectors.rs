//! Cross-language lock for every deterministic part of the handshake.
//!
//! The constants below were produced by a reference written from the spec
//! against Node's crypto primitives, independently of `phone-auth-session`.
//! Agreement is therefore evidence that the derivations are right, not a
//! restatement of what the Rust happens to compute.
//!
//! `docs/protocol-handshake.md` carries the same values. The mobile
//! implementation should assert against them before attempting a live
//! handshake: every one of these failing produces the same symptom on the
//! wire — a decryption error with no explanation — so checking them in
//! isolation is the difference between a five-minute fix and a long hunt.
//!
//! The handshake as a whole is not deterministic, because both ephemeral keys
//! are fresh per session. What is pinned here is everything downstream of
//! them.

use phone_auth_session::keys::{
    session_binding, verification_code, KeySchedule, SessionBindingInputs,
};

const SESSION_ID: &str = "session-1";
const TRANSPORT: &str = "QrNetworkTransport";

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The shared secret an X25519 exchange would produce, fixed for the vector.
fn shared_secret() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}

/// SHA-256 over both length-prefixed hello bodies.
const TRANSCRIPT_HEX: &str = "76b72c40a881574d332adada02a0960e39c3236f4a14b6bd53c42c565e01860d";

const CLIENT_TO_SERVER_HEX: &str =
    "8dfa481719332738c6ba26756da8c2b30fa5dde7fb300c343aee6553cf655539";
const SERVER_TO_CLIENT_HEX: &str =
    "7ebbd0e4c9f0c0b1129ecb14324eeadafcf53483e85752ee6205a139f865b43c";
const EXPORTER_HEX: &str = "eb2501574690d2f829f0f625cf1789e5c3203b8d402d2e6fe6fee9d911cc5522";
const SESSION_BINDING_HEX: &str =
    "e8435f560ac83635c296802cfb1b07c01aba8c47efead3b880dcc3bbed024017";
const VERIFICATION_CODE: &str = "420017";

fn schedule() -> KeySchedule {
    let transcript: [u8; 32] = from_hex(TRANSCRIPT_HEX)
        .try_into()
        .expect("32-byte transcript");
    KeySchedule::derive(&shared_secret(), &transcript).expect("derive")
}

#[test]
fn the_key_schedule_matches_the_reference() {
    let schedule = schedule();
    assert_eq!(to_hex(&schedule.client_to_server), CLIENT_TO_SERVER_HEX);
    assert_eq!(to_hex(&schedule.server_to_client), SERVER_TO_CLIENT_HEX);
    assert_eq!(to_hex(&schedule.exporter), EXPORTER_HEX);
}

#[test]
fn the_key_schedule_splits_hkdf_output_in_the_documented_order() {
    // Reversing two of these would still produce a working pair of channels
    // as long as both sides made the same mistake — and would then fail
    // against a phone that read the spec.
    let schedule = schedule();
    let joined = format!(
        "{}{}{}",
        to_hex(&schedule.client_to_server),
        to_hex(&schedule.server_to_client),
        to_hex(&schedule.exporter)
    );
    assert_eq!(
        joined,
        format!("{CLIENT_TO_SERVER_HEX}{SERVER_TO_CLIENT_HEX}{EXPORTER_HEX}"),
        "the 96 bytes of HKDF output are split in this order and no other"
    );
}

#[test]
fn the_session_binding_matches_the_reference() {
    let exporter = from_hex(EXPORTER_HEX);
    let binding = session_binding(&SessionBindingInputs {
        transport_name: TRANSPORT,
        session_id: SESSION_ID,
        server_ephemeral: &[0x11; 32],
        client_ephemeral: &[0x22; 32],
        exporter: &exporter,
    });
    assert_eq!(to_hex(&binding), SESSION_BINDING_HEX);
}

#[test]
fn the_verification_code_matches_the_reference() {
    assert_eq!(
        verification_code(&from_hex(EXPORTER_HEX)),
        VERIFICATION_CODE
    );
}

#[test]
fn the_binding_is_what_the_two_ends_must_agree_on() {
    // Restating the dependency the mobile side has to reproduce: everything
    // in the inputs changes the answer, so a mismatch in any one of them
    // fails every request rather than degrading quietly.
    let exporter = from_hex(EXPORTER_HEX);
    let reference = from_hex(SESSION_BINDING_HEX);

    let mut inputs = SessionBindingInputs {
        transport_name: TRANSPORT,
        session_id: SESSION_ID,
        server_ephemeral: &[0x11; 32],
        client_ephemeral: &[0x22; 32],
        exporter: &exporter,
    };
    assert_eq!(session_binding(&inputs).to_vec(), reference);

    inputs.transport_name = "BleTransport";
    assert_ne!(session_binding(&inputs).to_vec(), reference);
}
