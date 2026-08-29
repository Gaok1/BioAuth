//! What the SSH agent will and will not ask the phone to sign.
//!
//! An SSH signature is not spent the way the rest of this project's approvals
//! are: it opens a session that outlives the approval by as long as the
//! terminal stays open. So the refusals here matter more than the approvals,
//! and each test names the way a key gets lost if the rule is missing.

use std::process::Command;

use phone_auth_agent::ssh_agent::{SessionBind, SignContext};
use phone_auth_agent::ssh_policy::{fingerprint, Decision, SshPolicy};

fn context(user: &str) -> SignContext {
    SignContext {
        user: user.to_owned(),
        service: "ssh-connection".to_owned(),
    }
}

fn bind(host_key: &[u8], forwarding: bool) -> SessionBind {
    SessionBind {
        host_key: host_key.to_vec(),
        forwarding,
    }
}

/// A request nobody can read is a request nobody can approve. `describe`
/// returning `None` has to end here rather than in a prompt saying "sign?".
#[test]
fn an_undescribable_request_is_refused_without_asking() {
    let policy = SshPolicy::new();

    assert!(matches!(
        policy.decide(None, Some(&bind(b"host", false))),
        Decision::Refuse(_)
    ));
}

#[test]
fn a_request_naming_no_account_is_refused() {
    let policy = SshPolicy::new();

    assert!(matches!(
        policy.decide(Some(&context("")), None),
        Decision::Refuse(_)
    ));
}

/// A forwarded agent is one the remote host can ask to sign things for as long
/// as the connection lasts. It is a real feature and the classic way to lose a
/// key, so it is off unless turned on for that host.
#[test]
fn forwarding_is_refused_unless_it_was_allowed_for_that_host() {
    let host = b"host-key";
    let mut policy = SshPolicy::new();

    assert!(
        matches!(
            policy.decide(Some(&context("alice")), Some(&bind(host, true))),
            Decision::Refuse(_)
        ),
        "a forwarded request was allowed by default"
    );

    policy.allow_forwarding_to(fingerprint(host));

    assert!(matches!(
        policy.decide(Some(&context("alice")), Some(&bind(host, true))),
        Decision::Ask(_)
    ));
}

/// Allowing forwarding to one host must not allow it to another. Otherwise the
/// setting is a global switch wearing a per-host label.
#[test]
fn allowing_forwarding_to_one_host_does_not_allow_it_to_another() {
    let mut policy = SshPolicy::new();
    policy.allow_forwarding_to(fingerprint(b"trusted"));

    assert!(matches!(
        policy.decide(Some(&context("alice")), Some(&bind(b"other", true))),
        Decision::Refuse(_)
    ));
}

/// A client too old to send `session-bind` says nothing about where it is
/// going. That is a reason to ask rather than to guess, and the prompt must
/// say the destination is unknown rather than leave it blank.
#[test]
fn an_unnamed_destination_still_asks_but_says_it_is_unnamed() {
    let policy = SshPolicy::new();

    let Decision::Ask(prompt) = policy.decide(Some(&context("alice")), None) else {
        panic!("refused a request an older client would send");
    };
    assert_eq!(prompt.destination, None);
    assert!(
        prompt.first_time,
        "an unknown destination is never familiar"
    );
}

/// With an allow-list in force, a request that names no destination cannot be
/// checked against it. Approving it anyway would make the allow-list mean
/// nothing to any client old enough not to send a bind.
#[test]
fn an_unnamed_destination_is_refused_when_a_restriction_exists() {
    let mut policy = SshPolicy::new();
    policy.restrict_to([fingerprint(b"only-this-host")]);

    assert!(matches!(
        policy.decide(Some(&context("alice")), None),
        Decision::Refuse(_)
    ));
}

#[test]
fn a_restriction_admits_its_host_and_refuses_the_rest() {
    let allowed = b"allowed-host";
    let mut policy = SshPolicy::new();
    policy.restrict_to([fingerprint(allowed)]);

    assert!(matches!(
        policy.decide(Some(&context("alice")), Some(&bind(allowed, false))),
        Decision::Ask(_)
    ));
    assert!(matches!(
        policy.decide(Some(&context("alice")), Some(&bind(b"other-host", false))),
        Decision::Refuse(_)
    ));
}

/// An empty restriction is no restriction. An allow-list that has to be filled
/// in before the first login is an allow-list nobody fills in.
#[test]
fn no_restriction_means_no_restriction() {
    let policy = SshPolicy::new();

    assert!(matches!(
        policy.decide(Some(&context("alice")), Some(&bind(b"anywhere", false))),
        Decision::Ask(_)
    ));
}

/// A first login somewhere is the moment a mistake is most likely, and the
/// prompt says so. It is not refused — that would make the feature unusable.
#[test]
fn a_familiar_destination_stops_being_flagged_as_new() {
    let host = b"host-key";
    let mut policy = SshPolicy::new();

    let Decision::Ask(first) = policy.decide(Some(&context("alice")), Some(&bind(host, false)))
    else {
        panic!("refused");
    };
    assert!(first.first_time);

    policy.remember(fingerprint(host));

    let Decision::Ask(second) = policy.decide(Some(&context("alice")), Some(&bind(host, false)))
    else {
        panic!("refused");
    };
    assert!(!second.first_time);
}

/// The prompt carries the account, because it is the one thing the user can
/// check against what they just typed.
#[test]
fn the_prompt_names_the_account_being_logged_into() {
    let policy = SshPolicy::new();

    let Decision::Ask(prompt) = policy.decide(Some(&context("deploy")), None) else {
        panic!("refused");
    };
    assert_eq!(prompt.user, "deploy");
}

/// The fingerprint on the phone must be the exact string `ssh` prints when it
/// asks about an unknown host. If it is not, a user comparing the two is not
/// comparing anything, and the destination line is decoration.
#[test]
fn the_fingerprint_is_the_one_openssh_prints() {
    let available = Command::new("ssh-keygen")
        .arg("-?")
        .output()
        .map(|out| !out.stderr.is_empty() || out.status.success())
        .unwrap_or(false);
    if !available {
        eprintln!("skipping: ssh-keygen is not on PATH");
        return;
    }

    let dir = std::env::temp_dir().join(format!("phoneauth-fp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    let key = dir.join("host_ecdsa");

    let generated = Command::new("ssh-keygen")
        .args(["-t", "ecdsa", "-b", "256", "-N", "", "-C", "host", "-f"])
        .arg(&key)
        .output()
        .expect("ssh-keygen");
    assert!(generated.status.success());

    let line = std::fs::read_to_string(key.with_extension("pub")).expect("pub");
    let blob = base64_decode(line.split(' ').nth(1).expect("blob field"));

    let printed = Command::new("ssh-keygen")
        .arg("-l")
        .arg("-f")
        .arg(key.with_extension("pub"))
        .output()
        .expect("ssh-keygen -l");
    let theirs = String::from_utf8_lossy(&printed.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();

    assert_eq!(fingerprint(&blob), theirs, "our fingerprint differs");

    std::fs::remove_dir_all(&dir).ok();
}

fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in text.trim().bytes().filter(|byte| *byte != b'=') {
        let index = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .expect("standard base64") as u32;
        accumulator = (accumulator << 6) | index;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    out
}
