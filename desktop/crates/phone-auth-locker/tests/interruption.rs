//! A real process interruption, not a returned error.
//!
//! The parent kills a child while the child is writing the hidden sibling of a
//! container. This proves the invariant that matters after power loss or an
//! uncatchable signal: the plaintext name still exists and no partial
//! container was published under the destination name.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use phone_auth_locker::{
    lock_file, wrapper_aad, Dek, KeyCustodian, LockPlan, LockerError, UnwrapRequest, WrapRequest,
    Wrapper, WrapperKind,
};

const CHILD_SOURCE: &str = "PHONEAUTH_LOCKER_INTERRUPTION_SOURCE";

struct Phone;

impl KeyCustodian for Phone {
    fn wrap(&mut self, request: &WrapRequest<'_>) -> phone_auth_locker::Result<Wrapper> {
        let aad = wrapper_aad(&request.binding, WrapperKind::Phone, "test-phone");
        let mut ciphertext = request.dek.expose().to_vec();
        for (byte, mask) in ciphertext.iter_mut().zip(aad) {
            *byte ^= mask;
        }
        Ok(Wrapper {
            kind: WrapperKind::Phone,
            id: "test-phone".to_owned(),
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext,
        })
    }

    fn unwrap(&mut self, _request: &UnwrapRequest<'_>) -> phone_auth_locker::Result<Dek> {
        Err(LockerError::Denied("not used".to_owned()))
    }
}

#[test]
fn kill_helper_process() {
    let Some(source) = std::env::var_os(CHILD_SOURCE) else {
        return;
    };
    lock_file(Path::new(&source), &LockPlan::default(), &mut Phone)
        .expect("parent should kill this process before locking finishes");
}

#[test]
fn killing_a_lock_mid_write_keeps_the_original_and_publishes_no_container() {
    let directory =
        std::env::temp_dir().join(format!("phoneauth-locker-kill-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("sandbox");
    let source = directory.join("archive.bin");
    let destination = directory.join("archive.bin.balock");
    let mut file = std::fs::File::create(&source).expect("source");
    file.write_all(b"still-the-original").expect("sentinel");
    file.set_len(1024 * 1024 * 1024).expect("sparse source");
    drop(file);

    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "kill_helper_process", "--nocapture"])
        .env(CHILD_SOURCE, &source)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn helper");

    let deadline = Instant::now() + Duration::from_secs(15);
    let partial = loop {
        if let Some(path) = partial_container(&directory) {
            if std::fs::metadata(&path)
                .map(|metadata| metadata.len())
                .unwrap_or(0)
                > 1024 * 1024
            {
                break path;
            }
        }
        if child.try_wait().expect("child status").is_some() {
            panic!("helper finished before it could be interrupted");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("helper did not start writing within 15 seconds");
        }
        std::thread::sleep(Duration::from_millis(2));
    };

    child.kill().expect("kill helper");
    let status = child.wait().expect("reap helper");
    assert!(!status.success(), "the child was actually interrupted");
    assert!(partial.exists(), "the kill landed after writing began");
    assert!(source.exists(), "the original name survives");
    assert_eq!(
        std::fs::metadata(&source).expect("original metadata").len(),
        1024 * 1024 * 1024
    );
    let mut sentinel = [0u8; 18];
    std::fs::File::open(&source)
        .expect("original")
        .read_exact(&mut sentinel)
        .expect("sentinel");
    assert_eq!(&sentinel, b"still-the-original");
    assert!(!destination.exists(), "no partial container is published");

    std::fs::remove_dir_all(directory).expect("cleanup");
}

fn partial_container(directory: &Path) -> Option<PathBuf> {
    std::fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(".archive.bin.balock.") && name.ends_with(".balock-tmp")
                })
        })
}
