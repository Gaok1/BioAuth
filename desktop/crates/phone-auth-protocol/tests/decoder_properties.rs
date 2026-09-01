//! Property tests over every decoder in this crate.
//!
//! These decoders are the only code in the project that reads bytes chosen by
//! somebody else before anything has been authenticated. The unit tests cover
//! the shapes we thought of; this covers the ones we did not.
//!
//! Four properties, applied to every payload type:
//!
//! 1. **Arbitrary bytes never panic.** A decoder that panics on a hostile
//!    frame is a remote crash, and in a `panic = "abort"` release profile it
//!    is the agent going down.
//! 2. **Arbitrary bytes never allocate without bound.** A length header is a
//!    number an attacker picks; a decoder that trusts it is an out-of-memory
//!    waiting to be sent one packet.
//! 3. **Encoding round-trips.** Anything this crate produces, it reads back.
//! 4. **Only the canonical encoding is accepted.** Two byte strings that mean
//!    the same thing would be two frames with one signature, so every decoder
//!    re-encodes what it read and compares.
//!
//! `PROPTEST_CASES` bounds the run. Left at proptest's default here so the
//! suite stays inside a normal `cargo test`; CI raises it, and
//! `docs/review-brief.md` asks a reviewer to raise it further still.
//!
//! Which is why [`decoder_config`] exists: raising the case count on its own
//! was not enough to run this suite.

use phone_auth_protocol::cbor::{Reader, Writer};
use phone_auth_protocol::locker;
use phone_auth_protocol::vault;
use phone_auth_protocol::{
    ApplicationFrame, ApplicationFrameKind, AuthRequest, AuthResponse, Enrolment, MAX_VALIDITY_MS,
};
use proptest::prelude::*;

/// The case count from the environment, with the reject ceilings raised to
/// match it.
///
/// Several strategies below build a value, encode it and keep only the ones
/// that decode inside the protocol's bounds. Every discard is counted, so the
/// discards grow in step with `cases` -- and proptest's ceilings on them do
/// not: they are fixed at 65536 local and 1024 global no matter how many cases
/// are asked for. At the 65536 cases `docs/review-brief.md` tells a reviewer to
/// run, three of these tests stopped with `Test aborted: Too many local
/// rejects` after tens of thousands of successful cases and nothing falsified.
/// That message reads exactly like a failure, in the one document written to be
/// handed to somebody who has never seen this code.
///
/// Tied to `cases` rather than set to a large constant, so a strategy that
/// starts rejecting nearly everything still trips the ceiling and says so. The
/// `max` keeps an explicitly-set `PROPTEST_MAX_*_REJECTS`, and the default case
/// count, from ever lowering it.
fn decoder_config() -> ProptestConfig {
    let base = ProptestConfig::default();
    ProptestConfig {
        max_local_rejects: base.cases.saturating_mul(32).max(base.max_local_rejects),
        max_global_rejects: base.cases.saturating_mul(2).max(base.max_global_rejects),
        ..base
    }
}

/// Bytes that look enough like a frame to get past the first few checks.
///
/// Purely random bytes almost always die on the first header, which exercises
/// one branch very thoroughly and the rest not at all. Building from CBOR
/// pieces reaches the field decoders, which is where the interesting failures
/// would be.
fn plausible_cbor() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop_oneof![
            any::<u64>().prop_map(|value| {
                let mut writer = Writer::new();
                writer.uint(value);
                writer.into_bytes()
            }),
            any::<i64>().prop_map(|value| {
                let mut writer = Writer::new();
                writer.int(value);
                writer.into_bytes()
            }),
            ".{0,64}".prop_map(|text: String| {
                let mut writer = Writer::new();
                writer.text(&text);
                writer.into_bytes()
            }),
            prop::collection::vec(any::<u8>(), 0..64).prop_map(|bytes| {
                let mut writer = Writer::new();
                writer.bytes(&bytes);
                writer.into_bytes()
            }),
            (0u64..40).prop_map(|len| {
                let mut writer = Writer::new();
                writer.array(len);
                writer.into_bytes()
            }),
        ],
        0..12,
    )
    .prop_map(|pieces| pieces.concat())
}

/// Every entry point that turns bytes from the wire into a value.
///
/// Named so a failure says which decoder, and returning a bool rather than the
/// value so one list can hold decoders of different types.
type Decoder = (&'static str, fn(&[u8]) -> bool);

const DECODERS: &[Decoder] = &[
    ("AuthRequest", |bytes| AuthRequest::decode(bytes).is_ok()),
    ("AuthResponse", |bytes| AuthResponse::decode(bytes).is_ok()),
    ("Enrolment", |bytes| Enrolment::decode(bytes).is_ok()),
    ("ApplicationFrame", |bytes| {
        ApplicationFrame::decode(bytes).is_ok()
    }),
    ("vault::ListRequest", |bytes| {
        vault::ListRequest::decode(bytes).is_ok()
    }),
    ("vault::ListResponse", |bytes| {
        vault::ListResponse::decode(bytes).is_ok()
    }),
    ("vault::FetchRequest", |bytes| {
        vault::FetchRequest::decode(bytes).is_ok()
    }),
    ("vault::FetchResponse", |bytes| {
        vault::FetchResponse::decode(bytes).is_ok()
    }),
    ("vault::CreateRequest", |bytes| {
        vault::CreateRequest::decode(bytes).is_ok()
    }),
    ("vault::UpdateRequest", |bytes| {
        vault::UpdateRequest::decode(bytes).is_ok()
    }),
    ("vault::WriteResponse", |bytes| {
        vault::WriteResponse::decode(bytes).is_ok()
    }),
    ("vault::DeleteRequest", |bytes| {
        vault::DeleteRequest::decode(bytes).is_ok()
    }),
    ("vault::DeleteResponse", |bytes| {
        vault::DeleteResponse::decode(bytes).is_ok()
    }),
];

proptest! {
    #![proptest_config(decoder_config())]

    /// Random bytes into every decoder. Reaching the end of this test is the
    /// assertion: a panic anywhere in the list fails it.
    #[test]
    fn no_decoder_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        for (name, decode) in DECODERS {
            let _ = std::panic::catch_unwind(|| decode(&bytes))
                .map_err(|_| format!("{name} panicked"))
                .unwrap();
        }
    }

    #[test]
    fn no_decoder_panics_on_plausible_frames(bytes in plausible_cbor()) {
        for (name, decode) in DECODERS {
            let _ = std::panic::catch_unwind(|| decode(&bytes))
                .map_err(|_| format!("{name} panicked"))
                .unwrap();
        }
    }

    /// A length header is a number the sender picked. Decoding a four-byte
    /// input that claims four gigabytes must fail on the input being short,
    /// not by trying to reserve four gigabytes first.
    #[test]
    fn a_huge_declared_length_does_not_allocate(
        major in 2u8..5,
        declared in (u32::MAX as u64 / 2)..u64::MAX,
    ) {
        // major 2 = byte string, 3 = text, 4 = array.
        let mut frame = vec![(major << 5) | 27];
        frame.extend_from_slice(&declared.to_be_bytes());

        for (name, decode) in DECODERS {
            prop_assert!(!decode(&frame), "{name} accepted a truncated giant");
        }

        let mut reader = Reader::new(&frame);
        prop_assert!(reader.bytes().is_err() || major != 2);
        let mut reader = Reader::new(&frame);
        prop_assert!(reader.text().is_err() || major != 3);
    }

    /// A trailing byte changes the bytes without changing the meaning, which
    /// is exactly the ambiguity `finish()` exists to refuse: two frames, one
    /// signature.
    #[test]
    fn trailing_bytes_are_refused(
        mut frame in auth_request_bytes(),
        trailing in prop::collection::vec(any::<u8>(), 1..8),
    ) {
        prop_assert!(AuthRequest::decode(&frame).is_ok());
        frame.extend_from_slice(&trailing);
        prop_assert!(AuthRequest::decode(&frame).is_err(), "trailing bytes accepted");
    }

    /// Truncation at any point must be a refusal, never a partial value and
    /// never a hang.
    #[test]
    fn truncation_is_always_refused(frame in auth_request_bytes(), cut in 0usize..400) {
        let cut = cut.min(frame.len().saturating_sub(1));
        prop_assert!(AuthRequest::decode(&frame[..cut]).is_err());
    }

    #[test]
    fn an_auth_request_round_trips(frame in auth_request_bytes()) {
        let decoded = AuthRequest::decode(&frame).expect("our own encoding must decode");
        prop_assert_eq!(decoded.encode(), frame, "re-encoding differs");
    }

    #[test]
    fn an_application_frame_round_trips(bytes in application_frame_bytes()) {
        let decoded = ApplicationFrame::decode(&bytes).expect("our own encoding must decode");
        prop_assert_eq!(decoded.encode(), bytes);
    }

    /// Flipping one bit of a valid frame must either be refused or produce a
    /// value that encodes back to those exact bytes. What must never happen is
    /// a frame that decodes to something whose canonical form is different —
    /// that is one signature covering two meanings.
    #[test]
    fn one_flipped_bit_never_creates_a_second_meaning(
        mut bytes in application_frame_bytes(),
        index in 0usize..4096,
        bit in 0u8..8,
    ) {
        let index = index % bytes.len();
        bytes[index] ^= 1 << bit;

        if let Ok(decoded) = ApplicationFrame::decode(&bytes) {
            prop_assert_eq!(decoded.encode(), bytes, "a non-canonical frame decoded");
        }
    }

    /// The same property for the frame that carries a signature. Here it is
    /// not a nicety: two byte strings one signature covers is the definition
    /// of a replay the verifier cannot see.
    #[test]
    fn a_flipped_bit_in_a_request_never_creates_a_second_meaning(
        mut bytes in auth_request_bytes(),
        index in 0usize..4096,
        bit in 0u8..8,
    ) {
        let index = index % bytes.len();
        bytes[index] ^= 1 << bit;

        if let Ok(decoded) = AuthRequest::decode(&bytes) {
            prop_assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn a_vault_list_response_round_trips(items in prop::collection::vec(item_summary(), 0..8)) {
        let response = vault::ListResponse { items, next_cursor: String::new() };
        // Some generated lists are refused by `validate` — duplicate ids, for
        // instance. Those are not round-trip failures; skip them rather than
        // narrowing the generator until it can only produce what already works.
        prop_assume!(response.validate().is_ok());

        let payload = response.encode();
        let decoded = vault::ListResponse::decode(&payload).expect("our own encoding");
        prop_assert_eq!(decoded.encode(), payload);
    }

    #[test]
    fn a_locker_wrap_request_round_trips(payload in locker_wrap_bytes()) {
        let decoded = locker::WrapRequest::decode(&payload).expect("our own encoding");
        prop_assert_eq!(decoded.encode(), payload);
    }
}

// --- generators -------------------------------------------------------------

/// Text within the protocol's own bounds. Field limits are enforced by
/// `validate`, and a generator that ignored them would only ever test the
/// rejection path.
fn short_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ._@:/-]{1,32}"
}

/// Valid `AuthRequest` frames, as bytes.
///
/// Bytes rather than the struct so that a shrunk counterexample proptest
/// prints is a frame, not a field dump — and because `ApplicationFrame` below
/// deliberately has no `Debug`, its payload being a place secrets live. The
/// generators agree on that rather than making an exception for tests.
fn auth_request_bytes() -> impl Strategy<Value = Vec<u8>> {
    (
        short_text(),
        short_text(),
        short_text(),
        short_text(),
        short_text(),
        short_text(),
        short_text(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        0i64..4_000_000_000_000,
        // Within the protocol's own ceiling. Beyond it the frame is refused,
        // and spending most of the budget building frames that get filtered
        // out means the property explores far less than the case count says.
        1i64..=MAX_VALIDITY_MS,
    )
        .prop_map(
            |(
                request_id,
                verifier_id,
                verifier_name,
                credential_id,
                service,
                action,
                user,
                challenge,
                session_binding,
                issued_at_ms,
                validity_ms,
            )| {
                AuthRequest {
                    protocol_version: 1,
                    request_id,
                    verifier_id,
                    verifier_name,
                    credential_id,
                    challenge,
                    service,
                    action,
                    resource: "host".into(),
                    user,
                    issued_at_ms,
                    expires_at_ms: issued_at_ms + validity_ms,
                    session_binding,
                }
                .encode()
            },
        )
        .prop_filter("within protocol bounds", |frame| {
            AuthRequest::decode(frame).is_ok()
        })
}

fn application_frame_bytes() -> impl Strategy<Value = Vec<u8>> {
    (
        short_text(),
        // `valid_operation` accepts only `vault.`/`locker.` prefixes with a
        // lowercase suffix. Generating outside that would test the rejection
        // path, which the arbitrary-bytes properties already cover.
        "(vault|locker)\\.[a-z][a-z0-9-]{0,16}",
        any::<[u8; 32]>(),
        prop::collection::vec(any::<u8>(), 0..64),
        0i64..4_000_000_000_000,
        1i64..300_000,
        0usize..4,
    )
        .prop_map(
            |(request_id, operation, session_binding, payload, issued, validity, kind)| {
                ApplicationFrame {
                    protocol_version: 1,
                    kind: [
                        ApplicationFrameKind::Request,
                        ApplicationFrameKind::Response,
                        ApplicationFrameKind::Cancel,
                        ApplicationFrameKind::Error,
                    ][kind],
                    request_id,
                    session_binding,
                    operation,
                    issued_at_ms: issued,
                    expires_at_ms: issued + validity,
                    payload,
                }
                .encode()
            },
        )
        .prop_filter("within protocol bounds", |bytes| {
            ApplicationFrame::decode(bytes).is_ok()
        })
}

fn item_summary() -> impl Strategy<Value = vault::ItemSummary> {
    (
        short_text(),
        1u64..1000,
        short_text(),
        short_text(),
        any::<bool>(),
    )
        .prop_map(|(id, revision, name, username, login)| vault::ItemSummary {
            id,
            revision,
            kind: if login {
                vault::ItemKind::Login
            } else {
                vault::ItemKind::Note
            },
            name,
            username,
            uri: String::new(),
            updated_at_ms: 0,
        })
}

fn locker_wrap_bytes() -> impl Strategy<Value = Vec<u8>> {
    (
        short_text(),
        short_text(),
        any::<u32>(),
        any::<[u8; 32]>(),
        // Exactly the one accepted length. Drawing 1..64 and filtering the rest
        // away left 1 case in 63 usable, which at the budget CI runs is not a
        // slow test but an impossible one: proptest gives up after 65536
        // rejections, long before 4096 frames have been built.
        prop::collection::vec(any::<u8>(), locker::DATA_KEY_LEN),
    )
        .prop_map(
            |(verifier_name, file_name, plaintext_len, container_binding, data_key)| {
                locker::WrapRequest {
                    verifier_name,
                    file_name,
                    plaintext_len: plaintext_len.into(),
                    container_binding,
                    data_key,
                }
                .encode()
            },
        )
        .prop_filter("within protocol bounds", |payload| {
            locker::WrapRequest::decode(payload).is_ok()
        })
}
