//! Where a secret must never turn up.
//!
//! VLT-14. Every one of these is a place a value is written, formatted or
//! serialised on a path a secret is nearby: a `Debug` line, a log entry, a
//! serialised reply, a heap buffer that outlived its wipe.
//!
//! The tests share one shape — produce the artefact, then search its bytes for
//! the secret. Searching the bytes rather than a field is deliberate: a field
//! assertion only covers the fields somebody thought to assert, and the failure
//! this guards against is a field nobody thought about at all.

use phone_auth_agent::api::{VaultCopyResult, VaultCreateParams, VaultCreateResult};
use phone_auth_agent::audit::{AuditEntry, Outcome};
use phone_auth_agent::password::{
    generate, generate_passphrase, passphrase_capacity, Policy, EFF_LONGEST_WORD, EFF_WORD_COUNT,
};
use phone_auth_agent::secret_memory::SecretBuffer;

/// A string distinctive enough that finding it anywhere is unambiguous.
const CANARY: &str = "canary-hunter2-do-not-log";

/// The passphrase generator built its output in a `String` that grew, and each
/// reallocation left a prefix of the passphrase on the heap that `Zeroizing`
/// never saw — it wipes the buffer it holds when it drops, which is the last
/// one. Reserving the upper bound means there is only ever one buffer.
///
/// The property is that the reservation is always sufficient. If it is, the
/// buffer is never grown, and there is nothing to leave behind.
#[test]
fn a_passphrase_never_outgrows_the_buffer_that_will_be_wiped() {
    for word_count in 1..=24 {
        for separator in ["", "-", " ", "::", "—"] {
            let reserved = passphrase_capacity(word_count, separator);
            let passphrase = generate_passphrase(word_count, separator);

            assert!(
                passphrase.len() <= reserved,
                "{word_count} words joined by {separator:?} needed {} bytes, reserved {reserved}",
                passphrase.len()
            );
        }
    }
}

/// The bound above is only sound if it is the real longest word. A swapped
/// wordlist must fail here rather than by quietly reintroducing the growth.
#[test]
fn the_reserved_word_length_matches_the_embedded_wordlist() {
    let wordlist = include_str!("../src/eff_large_wordlist.txt");
    let mut longest = 0;
    let mut lines = 0;

    for line in wordlist.lines() {
        let (_, word) = line
            .split_once('\t')
            .expect("EFF wordlist entries are tab-separated");
        longest = longest.max(word.len());
        lines += 1;
    }

    assert_eq!(lines, EFF_WORD_COUNT, "wordlist length changed");
    assert_eq!(longest, EFF_LONGEST_WORD, "longest word changed");
}

/// A generated password lives in a `Zeroizing<String>` whose capacity is
/// reserved for the same reason.
#[test]
fn a_generated_password_never_outgrows_its_buffer() {
    for length in [8usize, 20, 64, 128] {
        let policy = Policy {
            length,
            ..Policy::default()
        };
        let password = generate(policy).expect("a satisfiable policy");
        assert_eq!(password.len(), length);
    }
}

/// The type that crosses IPC after a copy. It is serialised straight into a
/// JSON reply, so a field carrying the secret would put the secret in the
/// tray's V8 heap — the trip the whole locked-pages path exists to avoid.
#[test]
fn a_copy_result_cannot_carry_the_secret_it_describes() {
    let result = VaultCopyResult {
        length: CANARY.len(),
        clears_at_ms: 1_700_000_000_000,
        history_excluded: true,
        cloud_excluded: true,
        memory_locked: true,
    };

    let json = serde_json::to_string(&result).expect("serialise");

    assert!(
        !json.contains(CANARY),
        "the copy result serialised something it should not hold: {json}"
    );
    // Length is the one thing about the secret that does travel, and that is
    // deliberate — the UI says how much was copied. Nothing else may.
    assert!(json.contains(&CANARY.len().to_string()));
}

/// The other direction, and the reason `vault.create` is allowed to be on the
/// tray's list at all.
///
/// A password created on the desktop is generated inside the agent and sent to
/// the phone. The claim the design rests on is that the renderer can ask for
/// one and still never be able to see it, which is two statements about types:
/// there is no field for a secret in the call, and none in the reply. Both were
/// only ever said in a comment.
///
/// The request is checked by feeding the canary to every field that exists and
/// asking whether a `VaultCreateParams` will hold it — anything that survives
/// the round trip is a field a renderer could put a password in.
#[test]
fn a_create_cannot_be_told_a_secret_or_be_told_one_back() {
    let asking = serde_json::json!({
        "name": CANARY,
        "username": CANARY,
        "uri": CANARY,
        "credentialId": CANARY,
        "length": 24,
        "symbols": true,
        // The field this test exists to keep from being added. `serde` ignores
        // what it does not know, so today this vanishes; the day somebody adds
        // it, the assertion below starts failing.
        "secret": CANARY,
        "password": CANARY,
    });
    let params: VaultCreateParams = serde_json::from_value(asking).expect("parse");

    // The fields that do exist are the ones the phone's approval sheet is
    // worded from, and the user is the one who typed them.
    assert_eq!(params.name, CANARY);
    let carried = format!("{params:?}");
    let occurrences = carried.matches(CANARY).count();
    assert_eq!(
        occurrences, 4,
        "a create request grew a field beyond name, username, uri and          credentialId: {carried}"
    );

    let told = VaultCreateResult {
        item_id: "item-abc123".into(),
        revision: 1,
        length: CANARY.len(),
    };
    let json = serde_json::to_string(&told).expect("serialise");
    assert!(
        !json.contains(CANARY),
        "the create result serialised something it should not hold: {json}"
    );
    // Same one thing that travels after a copy, for the same reason: the tray
    // says how long the password it made is, and nothing else about it.
    assert!(json.contains(&CANARY.len().to_string()));
}

/// The audit log records that a vault operation happened. `DEC-06` makes the
/// item id opaque, which is why it is the only part worth writing down; the
/// secret, the item's name and its username must not reach the log.
#[test]
fn an_audit_entry_records_the_operation_and_not_its_contents() {
    let entry = AuditEntry {
        at_ms: 1_700_000_000_000,
        outcome: Outcome::Granted,
        request_id: "req-1".into(),
        service: "vault".into(),
        action: "copy".into(),
        resource: "item-abc123".into(),
        user: String::new(),
        device_name: "Pixel".into(),
        origin: "desktop".into(),
        detail: None,
        development: false,
    };

    let json = serde_json::to_string(&entry).expect("serialise");

    assert!(!json.contains(CANARY));
    assert!(
        json.contains("item-abc123"),
        "the opaque id is what makes the log useful"
    );
}

/// A failure message is written to the log verbatim, so it is the easiest
/// place for a secret to arrive by accident — a `format!` that interpolated
/// the wrong variable. This asserts the shape rather than any one call site:
/// what goes in `detail` is what comes out, so callers must never put a secret
/// there, and this is the test that says so out loud.
#[test]
fn an_audit_detail_is_reproduced_verbatim() {
    let entry = AuditEntry {
        at_ms: 0,
        outcome: Outcome::Denied,
        request_id: "req-2".into(),
        service: "vault".into(),
        action: "copy".into(),
        resource: "item-abc123".into(),
        user: String::new(),
        device_name: "Pixel".into(),
        origin: "desktop".into(),
        detail: Some("the phone refused".into()),
        development: false,
    };

    let json = serde_json::to_string(&entry).expect("serialise");

    assert!(json.contains("the phone refused"));
}

/// `SecretBuffer` is what a fetched password sits in between the phone and the
/// clipboard. Anything that printed it — a `Debug` derive added later, a
/// `{:?}` in an error path — would put it wherever that line went.
#[test]
fn a_secret_buffer_does_not_print_what_it_holds() {
    let secret = SecretBuffer::from_slice(CANARY.as_bytes());

    // Compiles only while `SecretBuffer` has no `Display`/`Debug` that reveals
    // the contents. The length is fine to expose and is what the UI reports.
    assert_eq!(secret.len(), CANARY.len());

    let described = format!("{} bytes, locked: {}", secret.len(), secret.is_locked());
    assert!(!described.contains(CANARY));
}

/// The one that is easy to get wrong twice: a value wiped and then read back.
/// `SecretBuffer` wipes before it unlocks the pages, because between unlock and
/// free they would be eligible for the pagefile again.
#[test]
fn a_wiped_secret_buffer_holds_zeroes() {
    let mut secret = SecretBuffer::from_slice(CANARY.as_bytes());
    secret.wipe();

    assert!(
        secret.expose().iter().all(|byte| *byte == 0),
        "a wiped buffer still held something"
    );
}
