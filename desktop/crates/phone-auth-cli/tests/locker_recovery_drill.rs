//! The recovery drill, run through the shipped binary.
//!
//! `DEC-03` and `FLK-06` both say the same thing: losing the phone must not
//! lose the files. This test is what makes that claim testable — it never
//! starts an agent, never opens a session, and calls the real `phone-auth`
//! executable exactly as a person would on the day it matters.

use std::path::PathBuf;
use std::process::Command;

use phone_auth_locker::{
    lock_file, wrapper_aad, Dek, KeyCustodian, LockPlan, LockerError, UnwrapRequest, WrapRequest,
    Wrapper, WrapperKind,
};

/// Stands in for the phone that will be gone by the time recovery matters.
struct FakePhone;

impl KeyCustodian for FakePhone {
    fn wrap(&mut self, request: &WrapRequest<'_>) -> phone_auth_locker::Result<Wrapper> {
        let aad = wrapper_aad(&request.binding, WrapperKind::Phone, "drill-cred");
        let ciphertext = request
            .dek
            .expose()
            .iter()
            .zip(aad.iter())
            .map(|(key, mask)| key ^ mask)
            .collect();
        Ok(Wrapper {
            kind: WrapperKind::Phone,
            id: "drill-cred".into(),
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext,
        })
    }

    fn unwrap(&mut self, _request: &UnwrapRequest<'_>) -> phone_auth_locker::Result<Dek> {
        Err(LockerError::Denied("the phone is gone".into()))
    }
}

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("phoneauth-drill-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("sandbox");
        Self(path)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn phone_auth(args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_phone-auth"))
        .args(args)
        .output()
        .expect("run phone-auth");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(-1), text)
}

#[test]
fn a_recovery_code_opens_a_container_with_no_agent_and_no_phone() {
    let sandbox = Sandbox::new("recovery");
    let source = sandbox.0.join("statement.pdf");
    let contents = b"the file the drill is about".repeat(40);
    std::fs::write(&source, &contents).expect("write fixture");

    let locked = lock_file(&source, &LockPlan::default(), &mut FakePhone).expect("lock");
    let container = locked.container.to_string_lossy().into_owned();
    let code_file = sandbox.0.join("recovery-code.txt");
    std::fs::write(&code_file, &locked.recovery_code).expect("write the code");
    assert!(!source.exists(), "the plaintext is gone");

    // Reading a container needs no key, no agent and no phone.
    let (status, text) = phone_auth(&["locker", "status", &container]);
    assert_eq!(status, 0, "{text}");
    assert!(text.contains("recovery"), "{text}");
    assert!(text.contains("drill-cred"), "{text}");
    assert!(
        !text.contains(&locked.recovery_code),
        "status must never print the recovery code"
    );

    // A wrong code is a refusal, and it publishes nothing.
    let wrong = sandbox.0.join("wrong-code.txt");
    std::fs::write(
        &wrong,
        "BAL1-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA",
    )
    .expect("write");
    let (status, _) = phone_auth(&[
        "locker",
        "unlock",
        &container,
        "--recovery-file",
        &wrong.to_string_lossy(),
    ]);
    assert_ne!(status, 0, "a wrong recovery code must not unlock");
    assert!(!source.exists(), "a failed unlock published a file anyway");

    // The drill itself.
    let (status, text) = phone_auth(&[
        "locker",
        "unlock",
        &container,
        "--recovery-file",
        &code_file.to_string_lossy(),
    ]);
    assert_eq!(status, 0, "{text}");
    assert_eq!(std::fs::read(&source).expect("read back"), contents);
    assert!(
        !PathBuf::from(&container).exists(),
        "the container is consumed once the file is back"
    );
}

#[test]
fn a_file_that_is_not_a_container_is_reported_and_not_opened() {
    let sandbox = Sandbox::new("not-a-container");
    let plain = sandbox.0.join("ordinary.txt");
    std::fs::write(&plain, b"just a file").expect("write");

    let (status, text) = phone_auth(&["locker", "status", &plain.to_string_lossy()]);
    assert_ne!(status, 0);
    assert!(text.contains("not a locker container"), "{text}");
}
