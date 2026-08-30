//! What the File Locker promises about files, end to end.
//!
//! The phone is a stand-in here: a custodian that wraps with a fixed key and
//! can be told to refuse. That is exactly the seam a real phone sits behind,
//! so everything about the container, the atomicity and the recovery path is
//! exercised without a device in the room.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use phone_auth_locker::{
    inspect, lock_file, parse_recovery_code, rekey_file, unlock_file, wrapper_aad, Dek,
    KeyCustodian, LockPlan, LockerError, UnlockKey, UnwrapRequest, WrapRequest, Wrapper,
    WrapperKind,
};

/// A phone that always says yes, wrapping with a key it keeps in memory.
///
/// It mimics the real contract in the one way that matters: the blob is bound
/// to the container, so a wrapper lifted into another container will not open.
struct FakePhone {
    credential_id: String,
    key: [u8; 32],
    refuse: bool,
    wraps: usize,
}

impl FakePhone {
    fn new() -> Self {
        Self {
            credential_id: "locker-cred-1".into(),
            key: [42; 32],
            refuse: false,
            wraps: 0,
        }
    }
}

impl KeyCustodian for FakePhone {
    fn wrap(&mut self, request: &WrapRequest<'_>) -> phone_auth_locker::Result<Wrapper> {
        if self.refuse {
            return Err(LockerError::Denied("the user declined".into()));
        }
        self.wraps += 1;
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
        if self.refuse {
            return Err(LockerError::Denied("the user declined".into()));
        }
        // A real phone recomputes the additional data from the binding it was
        // sent and the credential id it holds, so a container whose wrapper id
        // was edited does not open.
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

/// A directory that cleans up after itself.
struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "phoneauth-locker-{}-{name}-{}",
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

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    #[cfg(unix)]
    fn root(&self) -> &Path {
        &self.0
    }

    fn entries(&self) -> usize {
        std::fs::read_dir(&self.0).expect("list").count()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn container_of(source: &Path) -> PathBuf {
    let mut path = source.as_os_str().to_owned();
    path.push(".balock");
    PathBuf::from(path)
}

#[test]
fn a_locked_file_comes_back_byte_for_byte() {
    let sandbox = Sandbox::new("round-trip");
    let contents = b"the only copy of anything that matters".repeat(7);
    let source = sandbox.file("notes.txt", &contents);
    let mut phone = FakePhone::new();

    let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
    assert_eq!(locked.container, container_of(&source));
    assert!(locked.original_removed);
    assert!(!source.exists(), "the plaintext is gone once it is locked");

    let unlocked =
        unlock_file(&locked.container, None, true, UnlockKey::Phone(&mut phone)).expect("unlock");
    assert_eq!(unlocked.restored, source);
    assert_eq!(std::fs::read(&source).expect("read back"), contents);
    assert!(!locked.container.exists(), "the container is consumed");
}

#[test]
fn an_empty_file_and_a_multi_chunk_file_both_survive() {
    let sandbox = Sandbox::new("sizes");
    let mut phone = FakePhone::new();

    // 64 KiB is one chunk, so these cover empty, exactly-one-chunk, and a tail
    // that is shorter than a chunk.
    for (name, size) in [("empty", 0usize), ("exact", 65_536), ("ragged", 200_003)] {
        let contents: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
        let source = sandbox.file(name, &contents);
        let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
        let info = inspect(&locked.container).expect("inspect");
        assert_eq!(info.plaintext_len, size as u64);
        assert_eq!(info.chunk_count, (size as u64).div_ceil(65_536).max(1));

        unlock_file(&locked.container, None, true, UnlockKey::Phone(&mut phone)).expect("unlock");
        assert_eq!(std::fs::read(&source).expect("read back"), contents);
    }
}

#[test]
fn the_recovery_code_opens_a_container_with_no_phone_at_all() {
    let sandbox = Sandbox::new("recovery");
    let source = sandbox.file("deed.pdf", b"a document worth keeping");
    let mut phone = FakePhone::new();
    let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");

    // The drill: the phone is gone. Nothing below touches it.
    let key = parse_recovery_code(&locked.recovery_code).expect("parse the code");
    let unlocked = unlock_file(&locked.container, None, false, UnlockKey::Recovery(&key))
        .expect("unlock with the recovery code");
    assert_eq!(
        std::fs::read(&unlocked.restored).expect("read back"),
        b"a document worth keeping"
    );

    // And a code from some other container does not open this one.
    let other = sandbox.file("other.pdf", b"something else");
    let other_locked = lock_file(&other, &LockPlan::default(), &mut phone).expect("lock");
    let other_key = parse_recovery_code(&other_locked.recovery_code).expect("parse");
    std::fs::remove_file(&unlocked.restored).expect("clear the way");
    assert!(matches!(
        unlock_file(
            &locked.container,
            None,
            false,
            UnlockKey::Recovery(&other_key)
        ),
        Err(LockerError::Corrupt)
    ));
}

#[test]
fn no_change_to_a_container_can_publish_a_different_file() {
    let sandbox = Sandbox::new("corruption");
    let contents = vec![7u8; 1000];
    let source = sandbox.file("payload.bin", &contents);
    let mut phone = FakePhone::new();
    let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
    let recovery = parse_recovery_code(&locked.recovery_code).expect("parse");
    let original = std::fs::read(&locked.container).expect("read container");

    // The wrapper section holds one entry per way in. Damaging the wrapper a
    // given unlock does not consult is invisible to it — that is what having
    // two independent ways in means — so the sections are asserted apart.
    let core_len = u32::from_be_bytes(original[8..12].try_into().unwrap()) as usize;
    let wrappers_at = 12 + core_len + 4;
    let wrappers_end = wrappers_at
        + u32::from_be_bytes(original[wrappers_at - 4..wrappers_at].try_into().unwrap()) as usize;

    // Sampled rather than exhaustive so the test stays quick, but it covers
    // the magic, the header, both wrappers, the metadata and the chunk body.
    for offset in (0..original.len()).step_by(7) {
        let mut damaged = original.clone();
        damaged[offset] ^= 0x01;
        std::fs::write(&locked.container, &damaged).expect("write damaged");
        let shared = !(wrappers_at..wrappers_end).contains(&offset);

        for attempt in 0..2 {
            let key = if attempt == 0 {
                UnlockKey::Phone(&mut phone)
            } else {
                UnlockKey::Recovery(&recovery)
            };
            match unlock_file(&locked.container, None, false, key) {
                Err(_) => assert!(
                    !source.exists(),
                    "byte {offset}: a failed unlock published a file anyway"
                ),
                Ok(outcome) => {
                    assert!(
                        !shared,
                        "byte {offset} is outside the wrappers and still opened"
                    );
                    // A damaged wrapper the other path owns changes nothing
                    // about what this one is allowed to produce.
                    assert_eq!(
                        std::fs::read(&outcome.restored).expect("read"),
                        contents,
                        "byte {offset}: the file that came out was not the file that went in"
                    );
                    std::fs::remove_file(&outcome.restored).expect("clear the way");
                }
            }
        }
    }

    std::fs::write(&locked.container, &original).expect("restore");
    unlock_file(&locked.container, None, false, UnlockKey::Phone(&mut phone)).expect("unlock");
    assert_eq!(std::fs::read(&source).expect("read"), contents);
}

#[test]
fn truncation_and_trailing_bytes_are_both_refused() {
    let sandbox = Sandbox::new("length");
    let source = sandbox.file("long.bin", &vec![3u8; 150_000]);
    let mut phone = FakePhone::new();
    let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
    let original = std::fs::read(&locked.container).expect("read");

    // Cutting the last chunk off would decrypt to a shorter, plausible file if
    // the final chunk were not flagged.
    for keep in [8, 200, original.len() - 1, original.len() - 65_552] {
        std::fs::write(&locked.container, &original[..keep]).expect("truncate");
        assert!(
            unlock_file(&locked.container, None, false, UnlockKey::Phone(&mut phone)).is_err(),
            "a container cut to {keep} bytes must not open"
        );
        assert!(!source.exists());
    }

    let mut extended = original.clone();
    extended.extend_from_slice(b"appended");
    std::fs::write(&locked.container, &extended).expect("extend");
    assert!(matches!(
        unlock_file(&locked.container, None, false, UnlockKey::Phone(&mut phone)),
        Err(LockerError::Corrupt)
    ));
}

#[test]
fn chunks_cannot_be_reordered_or_moved_between_containers() {
    let sandbox = Sandbox::new("splice");
    let mut phone = FakePhone::new();
    let first = sandbox.file("first.bin", &vec![1u8; 150_000]);
    let second = sandbox.file("second.bin", &vec![2u8; 150_000]);
    let first_locked = lock_file(&first, &LockPlan::default(), &mut phone).expect("lock");
    let second_locked = lock_file(&second, &LockPlan::default(), &mut phone).expect("lock");

    let bytes = std::fs::read(&first_locked.container).expect("read");
    let head = bytes.len() - 150_000 - 3 * 16;
    let chunk = 65_536 + 16;

    // Swap the first two chunks of one container.
    let mut swapped = bytes.clone();
    swapped[head..head + chunk].copy_from_slice(&bytes[head + chunk..head + 2 * chunk]);
    swapped[head + chunk..head + 2 * chunk].copy_from_slice(&bytes[head..head + chunk]);
    std::fs::write(&first_locked.container, &swapped).expect("write");
    assert!(matches!(
        unlock_file(
            &first_locked.container,
            None,
            false,
            UnlockKey::Phone(&mut phone)
        ),
        Err(LockerError::Corrupt)
    ));

    // Paste a chunk in from the other container, which has a different binding.
    let donor = std::fs::read(&second_locked.container).expect("read");
    let mut spliced = bytes.clone();
    spliced[head..head + chunk].copy_from_slice(&donor[head..head + chunk]);
    std::fs::write(&first_locked.container, &spliced).expect("write");
    assert!(matches!(
        unlock_file(
            &first_locked.container,
            None,
            false,
            UnlockKey::Phone(&mut phone)
        ),
        Err(LockerError::Corrupt)
    ));
}

#[test]
fn a_refusal_anywhere_leaves_the_original_and_no_debris() {
    let sandbox = Sandbox::new("refusal");
    let source = sandbox.file("keepme.txt", b"still here");
    let mut phone = FakePhone::new();
    phone.refuse = true;

    assert!(matches!(
        lock_file(&source, &LockPlan::default(), &mut phone),
        Err(LockerError::Denied(_))
    ));
    assert_eq!(std::fs::read(&source).expect("read"), b"still here");
    assert_eq!(
        sandbox.entries(),
        1,
        "a refused lock leaves no container and no temporary file"
    );

    // The same on the way back: a phone that declines must not consume the
    // container or leave a half-written plaintext.
    phone.refuse = false;
    let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
    phone.refuse = true;
    assert!(unlock_file(&locked.container, None, true, UnlockKey::Phone(&mut phone)).is_err());
    assert!(locked.container.exists());
    assert!(!source.exists());
    assert_eq!(sandbox.entries(), 1);
}

#[test]
fn nothing_is_ever_written_over() {
    let sandbox = Sandbox::new("overwrite");
    let source = sandbox.file("report.doc", b"original");
    let mut phone = FakePhone::new();

    let occupied = sandbox.file("report.doc.balock", b"someone else's file");
    assert!(matches!(
        lock_file(&source, &LockPlan::default(), &mut phone),
        Err(LockerError::DestinationExists(_))
    ));
    assert_eq!(
        std::fs::read(&occupied).expect("read"),
        b"someone else's file"
    );
    std::fs::remove_file(&occupied).expect("clear");

    let plan = LockPlan {
        remove_original: false,
        ..LockPlan::default()
    };
    let locked = lock_file(&source, &plan, &mut phone).expect("lock");
    assert!(!locked.original_removed);
    assert!(
        source.exists(),
        "the original stays when it is not to be removed"
    );

    // Unlocking would land on the file that is still there.
    assert!(matches!(
        unlock_file(&locked.container, None, false, UnlockKey::Phone(&mut phone)),
        Err(LockerError::DestinationExists(_))
    ));
    assert_eq!(std::fs::read(&source).expect("read"), b"original");
}

#[test]
fn a_rekey_changes_the_phone_wrapper_and_keeps_the_contents() {
    let sandbox = Sandbox::new("rekey");
    let source = sandbox.file("archive.zip", &vec![9u8; 90_000]);
    let mut phone = FakePhone::new();
    let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
    let before = std::fs::read(&locked.container).expect("read");

    let mut replacement = FakePhone {
        credential_id: "locker-cred-2".into(),
        key: [77; 32],
        refuse: false,
        wraps: 0,
    };
    let key = parse_recovery_code(&locked.recovery_code).expect("parse");
    let code = rekey_file(&locked.container, &mut replacement, Some(&key), false).expect("rekey");
    assert!(code.is_none(), "the existing recovery code still works");

    let info = inspect(&locked.container).expect("inspect");
    assert_eq!(info.wrappers.len(), 2);
    assert_eq!(info.wrappers[0].id, "locker-cred-2");

    // The old phone is locked out, the new one is in, and the file is intact.
    assert!(unlock_file(&locked.container, None, false, UnlockKey::Phone(&mut phone)).is_err());
    let unlocked = unlock_file(
        &locked.container,
        None,
        false,
        UnlockKey::Phone(&mut replacement),
    )
    .expect("unlock with the new phone");
    assert_eq!(
        std::fs::read(&unlocked.restored).expect("read"),
        vec![9u8; 90_000]
    );

    // The recovery code the user wrote down before the rekey still works.
    std::fs::remove_file(&unlocked.restored).expect("clear the way");
    unlock_file(&locked.container, None, false, UnlockKey::Recovery(&key))
        .expect("the old recovery code still opens it");
    std::fs::remove_file(&unlocked.restored).expect("clear the way");

    // A rekey rewrites the wrappers and nothing else.
    let after = std::fs::read(&locked.container).expect("read");
    assert_eq!(before.len(), after.len());
    assert_eq!(
        before[before.len() - 90_000..],
        after[after.len() - 90_000..]
    );
    assert!(!sandbox.path("archive.zip.balock.rekey-new").exists());
    assert!(!sandbox.path("archive.zip.balock.rekey-old").exists());
}

#[test]
fn a_rekey_can_also_issue_a_new_recovery_code() {
    let sandbox = Sandbox::new("rekey-recovery");
    let source = sandbox.file("keys.txt", b"secrets");
    let mut phone = FakePhone::new();
    let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
    let old = parse_recovery_code(&locked.recovery_code).expect("parse");

    let code = rekey_file(&locked.container, &mut phone, None, true)
        .expect("rekey")
        .expect("a new code");
    let new = parse_recovery_code(&code).expect("parse");
    assert_ne!(code, locked.recovery_code);

    assert!(matches!(
        unlock_file(&locked.container, None, false, UnlockKey::Recovery(&old)),
        Err(LockerError::Corrupt)
    ));
    unlock_file(&locked.container, None, false, UnlockKey::Recovery(&new)).expect("new code opens");
}

#[test]
fn a_container_that_is_not_one_is_refused_before_anything_else() {
    let sandbox = Sandbox::new("not-a-container");
    let mut phone = FakePhone::new();
    let plain = sandbox.file("random.bin", b"this is not a locker container at all");
    assert!(matches!(inspect(&plain), Err(LockerError::NotAContainer)));

    let source = sandbox.file("real.txt", b"real");
    let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
    let mut bytes = std::fs::read(&locked.container).expect("read");
    bytes[7] = 9;
    std::fs::write(&locked.container, &bytes).expect("write");
    assert!(matches!(
        inspect(&locked.container),
        Err(LockerError::UnsupportedVersion(9))
    ));
}

#[test]
fn a_directory_is_not_a_file_the_locker_will_pretend_to_encrypt() {
    let sandbox = Sandbox::new("directory");
    let mut phone = FakePhone::new();
    let directory = sandbox.path("folder");
    std::fs::create_dir(&directory).expect("mkdir");
    assert!(matches!(
        lock_file(&directory, &LockPlan::default(), &mut phone),
        Err(LockerError::NotARegularFile(_))
    ));
}

/// Four gigabytes and three bytes: the size where the arithmetic stops being
/// boring.
///
/// The plaintext length no longer fits in a `u32`, the chunk index passes
/// 65536, and the file ends in a three-byte tail. Every one of those is a place
/// where a narrowing cast or an off-by-one would produce a container that locks
/// fine and comes back wrong.
///
/// Ignored by default: it moves something like 28 GiB past the disk and needs
/// about 8 GiB of free space. Run it deliberately, and in release, because the
/// debug build of an AEAD is slow enough to make it look broken:
///
/// ```text
/// cargo test -p phone-auth-locker --release -- --ignored --nocapture
/// ```
#[test]
#[ignore = "4 GiB round trip: needs ~8 GiB free and minutes of disk; run it deliberately"]
fn a_file_past_the_four_gigabyte_boundary_survives_the_round_trip() {
    const SIZE: u64 = (4 << 30) + 3;
    let sandbox = Sandbox::new("multi-gigabyte");
    let source = sandbox.path("archive.bin");
    let digest = write_pattern(&source, SIZE);
    let mut phone = FakePhone::new();

    let locked = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
    let info = inspect(&locked.container).expect("inspect");
    assert_eq!(info.plaintext_len, SIZE);
    assert_eq!(
        info.chunk_count, 65_537,
        "the chunk index has to pass 65536"
    );

    let unlocked =
        unlock_file(&locked.container, None, true, UnlockKey::Phone(&mut phone)).expect("unlock");
    assert_eq!(unlocked.plaintext_len, SIZE);
    assert_eq!(digest_of(&unlocked.restored), (SIZE, digest));
}

/// Writes `size` bytes of a pattern that never repeats and returns their hash.
///
/// Streamed on both sides on purpose: a test that held the file in memory to
/// check it would not be a test of a streaming engine.
fn write_pattern(path: &Path, size: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut block: Vec<u8> = (0..1u32 << 20).map(|index| (index % 251) as u8).collect();
    let mut file = std::io::BufWriter::new(std::fs::File::create(path).expect("create"));
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    while written < size {
        // The offset goes into every block, so two blocks are never the same
        // and a chunk moved from elsewhere in the file changes the hash.
        block[..8].copy_from_slice(&written.to_be_bytes());
        let take = (size - written).min(block.len() as u64) as usize;
        file.write_all(&block[..take]).expect("write");
        hasher.update(&block[..take]);
        written += take as u64;
    }
    file.flush().expect("flush");
    hasher.finalize().into()
}

fn digest_of(path: &Path) -> (u64, [u8; 32]) {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::io::BufReader::new(std::fs::File::open(path).expect("open"));
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer).expect("read");
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += read as u64;
    }
    (total, hasher.finalize().into())
}

/// Links, where a name and the bytes behind it stop being the same thing.
///
/// Every locker operation that reports something as gone works by removing or
/// renaming a *name*. Through a link that name is not the only way back to the
/// contents, so the report would be false and the file would still be sitting
/// there in plaintext. The symlink cases are Unix-only because creating one on
/// Windows needs a privilege a test runner does not have. Hard links are
/// exercised separately on both supported desktop platforms.
#[cfg(unix)]
mod links {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn a_symlink_is_never_the_thing_that_gets_locked() {
        let sandbox = Sandbox::new("symlink-source");
        let secret = sandbox.file("secret.txt", b"the actual contents");
        let link = sandbox.path("shortcut.txt");
        symlink(&secret, &link).expect("symlink");
        let mut phone = FakePhone::new();

        // Following it would encrypt the target and then delete the link:
        // "locked and original removed", with the plaintext still on disk.
        assert!(matches!(
            lock_file(&link, &LockPlan::default(), &mut phone),
            Err(LockerError::NotARegularFile(_))
        ));
        assert_eq!(
            std::fs::read(&secret).expect("target survives"),
            b"the actual contents"
        );
        assert!(!container_of(&link).exists());
        assert!(!container_of(&secret).exists());
    }

    #[test]
    fn a_container_reached_through_a_link_is_read_but_never_consumed() {
        let sandbox = Sandbox::new("symlink-container");
        let source = sandbox.file("report.pdf", &[7u8; 5000]);
        let mut phone = FakePhone::new();
        let outcome = lock_file(&source, &LockPlan::default(), &mut phone).expect("lock");
        let link = sandbox.path("report.link");
        symlink(&outcome.container, &link).expect("symlink");

        // Deleting the link would leave the container; renaming it away during
        // a rekey would leave the old wrappers able to open the file, which is
        // the one thing a rekey exists to prevent.
        assert!(matches!(
            unlock_file(
                &link,
                Some(sandbox.root()),
                true,
                UnlockKey::Phone(&mut phone)
            ),
            Err(LockerError::NotARegularFile(_))
        ));
        assert!(matches!(
            rekey_file(&link, &mut phone, None, false),
            Err(LockerError::NotARegularFile(_))
        ));
        assert!(outcome.container.exists());

        // Reading through it is harmless, so it stays allowed.
        let restored = unlock_file(&link, None, false, UnlockKey::Phone(&mut phone))
            .expect("unlock through the link");
        assert_eq!(
            std::fs::read(&restored.restored).expect("read"),
            [7u8; 5000]
        );
    }

    #[test]
    fn a_dangling_symlink_at_the_destination_is_not_written_over() {
        let sandbox = Sandbox::new("dangling-destination");
        let source = sandbox.file("payslip.pdf", b"salary");
        let destination = sandbox.path("payslip.balock");
        symlink(sandbox.path("nowhere"), &destination).expect("symlink");
        let mut phone = FakePhone::new();

        // `Path::exists` follows the link and answers "nothing there", which is
        // how a rename quietly eats something that was already on disk.
        assert!(matches!(
            lock_file(
                &source,
                &LockPlan {
                    destination: Some(destination.clone()),
                    remove_original: true,
                },
                &mut phone,
            ),
            Err(LockerError::DestinationExists(_))
        ));
        assert!(std::fs::symlink_metadata(&destination).is_ok());
        assert!(source.exists());
    }
}

#[cfg(any(unix, windows))]
#[test]
fn a_file_with_a_second_name_is_locked_only_when_nothing_is_deleted() {
    let sandbox = Sandbox::new("hard-link");
    let source = sandbox.file("notes.txt", b"one file, two names");
    let second = sandbox.path("also-notes.txt");
    std::fs::hard_link(&source, &second).expect("hard link");
    let mut phone = FakePhone::new();

    // Removing one name leaves the contents readable under the other, so the
    // destructive plan is refused outright.
    assert!(matches!(
        lock_file(&source, &LockPlan::default(), &mut phone),
        Err(LockerError::SharedOriginal)
    ));
    assert!(!container_of(&source).exists());

    // Keeping the plaintext is the honest version of the same request, and it
    // is allowed: nothing is claimed to have disappeared.
    let outcome = lock_file(
        &source,
        &LockPlan {
            destination: None,
            remove_original: false,
        },
        &mut phone,
    )
    .expect("lock without removing");
    assert!(!outcome.original_removed);
    assert!(source.exists() && second.exists());
}

#[test]
fn a_file_that_grows_while_it_is_read_fails_instead_of_being_half_locked() {
    let sandbox = Sandbox::new("growing");
    let source = sandbox.file("log.txt", &[1u8; 10]);
    let mut phone = FakePhone::new();

    // The header commits to a length before the read starts; a source that no
    // longer matches it must not produce a container of the old file.
    struct Grower<'a> {
        inner: &'a mut FakePhone,
        source: PathBuf,
    }
    impl KeyCustodian for Grower<'_> {
        fn wrap(&mut self, request: &WrapRequest<'_>) -> phone_auth_locker::Result<Wrapper> {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&self.source)
                .expect("append");
            file.write_all(&[2u8; 5000]).expect("grow");
            self.inner.wrap(request)
        }
        fn unwrap(&mut self, request: &UnwrapRequest<'_>) -> phone_auth_locker::Result<Dek> {
            self.inner.unwrap(request)
        }
    }

    let mut grower = Grower {
        inner: &mut phone,
        source: source.clone(),
    };
    assert!(matches!(
        lock_file(&source, &LockPlan::default(), &mut grower),
        Err(LockerError::InputChanged)
    ));
    assert!(
        !container_of(&source).exists(),
        "no container was published"
    );
    assert_eq!(std::fs::read(&source).expect("read").len(), 5010);
}
