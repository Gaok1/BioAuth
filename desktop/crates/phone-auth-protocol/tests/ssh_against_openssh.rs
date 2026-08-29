//! The encodings, checked against OpenSSH itself.
//!
//! `ssh_encoding.rs` asserts the layout this project believes in.
//! That belief is exactly what needs an outside opinion: a blob that satisfies
//! our own reader and not `ssh-keygen` is a key no server will ever accept,
//! and the failure arrives as a login that does not work rather than as an
//! error anyone can act on.
//!
//! So this generates a real P-256 key with `ssh-keygen`, takes the point out
//! of it, re-encodes that point with our code, and requires the two lines to
//! match byte for byte. If they ever disagree, this project is wrong.
//!
//! Skipped when `ssh-keygen` is absent rather than failing: not every machine
//! that builds this has OpenSSH, and a test that fails for that reason teaches
//! people to ignore it. CI has it.

use std::path::Path;
use std::process::Command;

use phone_auth_protocol::ssh::{authorized_keys_line, decode_public_key, encode_public_key};

fn ssh_keygen_available() -> bool {
    Command::new("ssh-keygen")
        .arg("-?")
        .output()
        .map(|out| !out.stderr.is_empty() || out.status.success())
        .unwrap_or(false)
}

/// A scratch directory that cleans up after itself.
struct Sandbox(std::path::PathBuf);

impl Sandbox {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("phoneauth-ssh-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("sandbox");
        Self(path)
    }

    fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Generates a P-256 key and returns its public line.
fn generate(dir: &Path) -> Option<String> {
    let key = dir.join("id_ecdsa");
    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ecdsa",
            "-b",
            "256",
            "-N",
            "",
            "-C",
            "phoneauth-test",
            "-f",
        ])
        .arg(&key)
        .output()
        .ok()?;
    if !status.status.success() {
        return None;
    }
    std::fs::read_to_string(key.with_extension("pub")).ok()
}

fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes().filter(|byte| *byte != b'=') {
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

/// The whole point of the module: a point taken out of a real OpenSSH key and
/// re-encoded by us has to produce the identical line.
#[test]
fn our_encoding_reproduces_an_openssh_key_line() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen is not on PATH");
        return;
    }
    let sandbox = Sandbox::new("roundtrip");
    let Some(line) = generate(&sandbox.0) else {
        eprintln!("skipping: ssh-keygen could not generate a P-256 key");
        return;
    };

    let fields: Vec<&str> = line.trim().split(' ').collect();
    assert_eq!(fields[0], "ecdsa-sha2-nistp256", "line: {line}");

    // OpenSSH's own blob, read by our decoder. If this fails, our reader is
    // wrong about a key that demonstrably works.
    let theirs = base64_decode(fields[1]);
    let point = decode_public_key(&theirs).expect("openssh's own blob must decode");

    // And back out again. Byte-identical, or a server would see a different
    // key than the one the user pasted.
    let ours = encode_public_key(&point).expect("re-encode");
    assert_eq!(ours, theirs, "our blob differs from OpenSSH's");

    let our_line = authorized_keys_line(&ours, fields[2]);
    assert_eq!(our_line, line.trim(), "our authorized_keys line differs");
}

/// And the line we produce is one `ssh-keygen` will read back, which is the
/// operation a server performs when it loads `authorized_keys`.
#[test]
fn openssh_accepts_a_line_we_wrote() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen is not on PATH");
        return;
    }
    let sandbox = Sandbox::new("accepts");
    let Some(line) = generate(&sandbox.0) else {
        eprintln!("skipping: ssh-keygen could not generate a P-256 key");
        return;
    };
    let fields: Vec<&str> = line.trim().split(' ').collect();
    let point = decode_public_key(&base64_decode(fields[1])).expect("decode");

    let ours = authorized_keys_line(&encode_public_key(&point).expect("encode"), "phone@laptop");
    let path = sandbox.join("ours.pub");
    std::fs::write(&path, format!("{ours}\n")).expect("write");

    // `-l` prints the fingerprint of a public key file, which requires
    // parsing it the way a server would.
    let output = Command::new("ssh-keygen")
        .arg("-l")
        .arg("-f")
        .arg(&path)
        .output()
        .expect("ssh-keygen -l");

    assert!(
        output.status.success(),
        "ssh-keygen refused our line: {}\n{}",
        ours,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("ECDSA"),
        "ssh-keygen did not read it as ECDSA: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// The fingerprint OpenSSH computes for its key and for ours must match. It is
/// computed over the blob, so an equal fingerprint is the strongest available
/// statement that the two blobs are the same key.
#[test]
fn the_fingerprints_agree() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen is not on PATH");
        return;
    }
    let sandbox = Sandbox::new("fingerprint");
    let Some(line) = generate(&sandbox.0) else {
        eprintln!("skipping: ssh-keygen could not generate a P-256 key");
        return;
    };
    let fields: Vec<&str> = line.trim().split(' ').collect();
    let point = decode_public_key(&base64_decode(fields[1])).expect("decode");

    let ours = sandbox.join("ours.pub");
    std::fs::write(
        &ours,
        format!(
            "{}\n",
            authorized_keys_line(&encode_public_key(&point).expect("encode"), "ours")
        ),
    )
    .expect("write");

    let fingerprint = |path: &Path| {
        let output = Command::new("ssh-keygen")
            .arg("-l")
            .arg("-f")
            .arg(path)
            .output()
            .expect("ssh-keygen -l");
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned()
    };

    assert_eq!(
        fingerprint(&sandbox.join("id_ecdsa.pub")),
        fingerprint(&ours),
        "the two keys fingerprint differently"
    );
}
