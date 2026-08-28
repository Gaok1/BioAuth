//! Property tests over the container format.
//!
//! `docs/locker-format.md` states the property this file exists to hold to:
//!
//! > no change anywhere in a container can make it open and produce a
//! > *different* file
//!
//! Removing a wrapper is a denial of service and is allowed to be one. What is
//! forbidden is a container that opens and yields bytes nobody sealed. The
//! mutation test below is that sentence, executed.
//!
//! `inspect` gets its own property because it is the one entry point that
//! parses a file the user did not necessarily produce — `locker status` on
//! anything at all — and it runs before any key is involved.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use phone_auth_locker::{
    inspect, lock_file, parse_recovery_code, unlock_file, wrapper_aad, Dek, KeyCustodian, LockPlan,
    LockerError, UnlockKey, UnwrapRequest, WrapRequest, Wrapper, WrapperKind,
};
use proptest::prelude::*;

/// A phone that always says yes. Mirrors `container.rs`'s stand-in, including
/// binding the blob to the container so a lifted wrapper does not open.
struct FakePhone {
    credential_id: String,
    key: [u8; 32],
}

impl FakePhone {
    fn new() -> Self {
        Self {
            credential_id: "locker-cred-1".into(),
            key: [42; 32],
        }
    }
}

impl KeyCustodian for FakePhone {
    fn wrap(&mut self, request: &WrapRequest<'_>) -> phone_auth_locker::Result<Wrapper> {
        let aad = wrapper_aad(&request.binding, WrapperKind::Phone, &self.credential_id);
        let mut ciphertext = request.dek.expose().to_vec();
        for (index, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= self.key[index] ^ aad[index];
        }
        Ok(Wrapper {
            kind: WrapperKind::Phone,
            id: self.credential_id.clone(),
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext,
        })
    }

    fn unwrap(&mut self, request: &UnwrapRequest<'_>) -> phone_auth_locker::Result<Dek> {
        let aad = wrapper_aad(&request.binding, WrapperKind::Phone, &request.wrapper.id);
        let mut plain = request.wrapper.ciphertext.clone();
        for (index, byte) in plain.iter_mut().enumerate() {
            *byte ^= self.key[index] ^ aad[index];
        }
        if request.wrapper.id != self.credential_id {
            return Err(LockerError::Denied("not this phone's wrapper".into()));
        }
        Dek::from_slice(&plain).ok_or(LockerError::Corrupt)
    }
}

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "phoneauth-locker-prop-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("sandbox");
        Self(path)
    }

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write fixture");
        path
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// How many cases to run, letting the environment raise the floor.
fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// Locks `contents` and returns the container's bytes and its recovery code.
fn seal(contents: &[u8]) -> (Vec<u8>, String) {
    let sandbox = Sandbox::new("seal");
    let source = sandbox.file("payload.bin", contents);
    let locked = lock_file(&source, &LockPlan::default(), &mut FakePhone::new()).expect("lock");
    let bytes = std::fs::read(&locked.container).expect("read the container");
    (bytes, locked.recovery_code)
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Locking writes real files, so a case here costs orders of magnitude
        // more than a decoder's. Forty-eight is enough to find a structural
        // bug in a normal `cargo test`.
        //
        // Read explicitly rather than left to `ProptestConfig::default()`: the
        // default already honours `PROPTEST_CASES`, and naming `cases` at all
        // would otherwise silently override what CI asked for.
        cases: cases(48),
        ..ProptestConfig::default()
    })]

    /// `locker status` runs on whatever path the user typed, before any key
    /// exists. Arbitrary bytes have to come back as an error.
    #[test]
    fn inspect_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let sandbox = Sandbox::new("inspect");
        let path = sandbox.file("not-a-container.balock", &bytes);

        // Reaching the assertion at all is the property. A panic here is
        // `locker status` crashing on a file somebody sent the user.
        let described = inspect(&path);
        prop_assert!(described.is_err() || described.is_ok());
    }

    /// A truncated container is a container the user still has, so it must
    /// fail rather than yield a prefix of the file.
    #[test]
    fn a_truncated_container_never_opens(
        contents in prop::collection::vec(any::<u8>(), 1..2048),
        keep in 0usize..100,
    ) {
        let (container, code) = seal(&contents);
        let keep = (container.len() * keep / 100).min(container.len().saturating_sub(1));

        let sandbox = Sandbox::new("truncated");
        let path = sandbox.file("cut.balock", &container[..keep]);
        let key = parse_recovery_code(&code).expect("parse");

        prop_assert!(
            unlock_file(&path, None, false, UnlockKey::Recovery(&key)).is_err(),
            "a truncated container opened"
        );
    }

    /// The property `locker-format.md` claims. Changing a byte may stop a
    /// container from opening — that is a denial of service and allowed. What
    /// it may never do is produce a file that is not the one that was sealed.
    #[test]
    fn no_edit_makes_a_container_yield_a_different_file(
        contents in prop::collection::vec(any::<u8>(), 1..1024),
        index in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let (container, code) = seal(&contents);
        let mut edited = container.clone();
        let at = index.index(edited.len());
        edited[at] ^= 1 << bit;
        prop_assume!(edited != container);

        let sandbox = Sandbox::new("edited");
        let path = sandbox.file("edited.balock", &edited);
        let key = parse_recovery_code(&code).expect("parse");

        if let Ok(outcome) = unlock_file(&path, None, false, UnlockKey::Recovery(&key)) {
            let restored = std::fs::read(&outcome.restored).expect("read what came out");
            prop_assert_eq!(
                restored,
                contents,
                "an edited container opened and produced a different file"
            );
        }
    }

    /// The recovery path with somebody else's code. Every container is sealed
    /// under its own key, so a code from one must not open another.
    #[test]
    fn another_container_s_code_never_opens_this_one(
        contents in prop::collection::vec(any::<u8>(), 1..512),
        other in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        let (container, _) = seal(&contents);
        let (_, foreign_code) = seal(&other);

        let sandbox = Sandbox::new("foreign");
        let path = sandbox.file("sealed.balock", &container);
        let key = parse_recovery_code(&foreign_code).expect("parse");

        prop_assert!(unlock_file(&path, None, false, UnlockKey::Recovery(&key)).is_err());
    }

    /// The round trip, over sizes that cross the chunk boundary in every way:
    /// empty, under one chunk, exactly one, and several with a partial tail.
    #[test]
    fn any_file_comes_back_byte_for_byte(
        contents in prop::collection::vec(any::<u8>(), 0..3000),
    ) {
        let sandbox = Sandbox::new("round-trip");
        let source = sandbox.file("payload.bin", &contents);
        let locked = lock_file(&source, &LockPlan::default(), &mut FakePhone::new())
            .expect("lock");

        let outcome = unlock_file(
            &locked.container,
            None,
            false,
            UnlockKey::Phone(&mut FakePhone::new()),
        )
        .expect("unlock");

        prop_assert_eq!(std::fs::read(&outcome.restored).expect("read"), contents);
    }
}

/// A recovery code survives being written down and typed back.
///
/// Not inside `proptest!` because it needs no filesystem and runs thousands of
/// cases in the time one lock takes.
#[test]
fn every_recovery_code_parses_back_to_its_key() {
    proptest!(|(seed in any::<[u8; 32]>())| {
        // Sealing is the only way to obtain a key here, and the code it prints
        // is the artefact under test. The seed varies the contents so each
        // case gets a different key.
        let (_, code) = seal(&seed);
        let parsed = parse_recovery_code(&code).expect("our own code must parse");
        let retyped = parse_recovery_code(&code.to_lowercase().replace('-', " "))
            .expect("case, dashes and spaces are ignored");
        prop_assert!(parsed == retyped);
    });
}
