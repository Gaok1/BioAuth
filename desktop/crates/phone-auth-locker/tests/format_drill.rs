//! The drill that keeps a locked file openable.
//!
//! REL-10. `container.rs` proves today's engine can open what today's engine
//! wrote, which is the property that stays true while the format changes
//! underneath it. This opens a container sealed once and checked in, with a
//! recovery code checked in beside it.
//!
//! When this fails, every file any user has ever locked stopped opening — and
//! it fails in a pull request rather than on the day somebody needs one back.
//!
//! **Never regenerate the fixture to make this pass.** A change that cannot
//! read `container-v1.balock` needs a version 2 and a reader for version 1.
//! `PHONEAUTH_WRITE_FIXTURE=1` exists for adding a version, and refuses to
//! overwrite one that is already there.

use std::path::{Path, PathBuf};

use phone_auth_locker::{
    inspect, lock_file, parse_recovery_code, unlock_file, wrapper_aad, Dek, KeyCustodian, LockPlan,
    LockerError, UnlockKey, UnwrapRequest, WrapRequest, Wrapper, WrapperKind,
};

/// A stand-in phone, needed only to *write* a container.
///
/// Every assertion below goes through the recovery code, which needs no phone
/// at all — that is the whole reason the recovery wrapper exists, and it is
/// also what lets this drill outlive any change to how a phone wraps.
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

/// The plaintext the fixture holds. Non-ASCII and a byte over one chunk would
/// be better still, but the fixture must stay small enough to review.
const CONTENTS: &[u8] = "o conteúdo — não perca\n".as_bytes();

const FIXTURE: &str = "tests/fixtures/container-v1.balock";
const CODE_FILE: &str = "tests/fixtures/container-v1.code";

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(name)
}

/// Copies the fixture somewhere writable, because unlocking writes beside it.
fn staged(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("phoneauth-drill-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    let container = dir.join("container-v1.balock");
    std::fs::copy(fixture_path(FIXTURE), &container).expect("stage the fixture");
    (dir, container)
}

#[test]
fn a_version_1_container_still_opens_with_its_recovery_code() {
    let (dir, container) = staged("recovery");
    let code = std::fs::read_to_string(fixture_path(CODE_FILE)).expect("read the code");
    let key = parse_recovery_code(&code).expect("the checked-in code must still parse");

    let outcome = unlock_file(&container, None, false, UnlockKey::Recovery(&key))
        .expect("a version 1 container must still open");

    assert_eq!(
        std::fs::read(&outcome.restored).expect("read"),
        CONTENTS,
        "the file came back different from what was sealed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `locker status` reads a container without any key, and a header change that
/// broke it would leave users unable to see what a file even is.
#[test]
fn a_version_1_container_still_describes_itself() {
    let described = inspect(&fixture_path(FIXTURE)).expect("inspect");

    assert_eq!(described.container_version, 1);
    assert_eq!(described.plaintext_len, CONTENTS.len() as u64);
    assert_eq!(
        described.wrappers.len(),
        2,
        "a phone wrapper and a recovery wrapper"
    );
}

/// The fixture has to be bytes rather than a re-run of the engine, or the
/// drill tests the encoder against itself the moment somebody regenerates it.
#[test]
fn the_fixture_is_not_reproduced_by_locking_again() {
    let dir = std::env::temp_dir().join(format!("phoneauth-drill-{}-fresh", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    let source = dir.join("payload.bin");
    std::fs::write(&source, CONTENTS).expect("write");

    let locked = lock_file(&source, &LockPlan::default(), &mut FakePhone::new()).expect("lock");
    let fresh = std::fs::read(&locked.container).expect("read");
    let fixture = std::fs::read(fixture_path(FIXTURE)).expect("read");

    assert_ne!(fresh, fixture, "the fixture would be circular");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Writes the fixture. Not a test of anything: a generator that lives here so
/// it shares the stand-in phone, gated so an ordinary run never touches it.
///
///   PHONEAUTH_WRITE_FIXTURE=1 cargo test -p phone-auth-locker --test format_drill
#[test]
fn write_the_fixture_when_asked() {
    if std::env::var_os("PHONEAUTH_WRITE_FIXTURE").is_none() {
        return;
    }
    let target = fixture_path(FIXTURE);
    assert!(
        !target.exists(),
        "{} already exists. A change that cannot read it needs a version 2 and \
         a reader for version 1, not a new fixture.",
        target.display()
    );
    std::fs::create_dir_all(target.parent().expect("parent")).expect("fixtures dir");

    let dir = std::env::temp_dir().join(format!("phoneauth-mkfixture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    let source = dir.join("container-v1");
    std::fs::write(&source, CONTENTS).expect("write");

    let locked = lock_file(&source, &LockPlan::default(), &mut FakePhone::new()).expect("lock");
    std::fs::copy(&locked.container, &target).expect("copy the container");
    std::fs::write(fixture_path(CODE_FILE), &locked.recovery_code).expect("write the code");
    let _ = std::fs::remove_dir_all(&dir);
}
