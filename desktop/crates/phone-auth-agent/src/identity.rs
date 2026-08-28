//! The agent's handshake identity, persisted across restarts.
//!
//! This is the one private key the desktop holds. Losing it means every phone
//! must re-pair, because a paired phone recognises this desktop by it; leaking
//! it lets someone impersonate this desktop to a paired phone, which is enough
//! to make the user approve a request they think came from their own machine.
//!
//! It is *not* an authorization key. It cannot approve anything; it only
//! proves which desktop is asking.

use std::fs;
use std::io;
use std::path::Path;

use phone_auth_session::IdentityKey;

/// Loads the identity, creating one on first run.
pub fn load_or_create(path: &Path) -> io::Result<IdentityKey> {
    match fs::read(path) {
        Ok(bytes) => IdentityKey::from_pkcs8_der(&bytes).map_err(|error| {
            // Do not silently regenerate: a corrupt file that quietly became a
            // new identity would unpair every phone with no explanation.
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is not a valid identity key ({error}); \
                     move it aside and re-pair to start over",
                    path.display()
                ),
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create(path),
        Err(error) => Err(error),
    }
}

fn create(path: &Path) -> io::Result<IdentityKey> {
    let identity = IdentityKey::generate();
    let encoded = identity
        .to_pkcs8_der()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;

    // Restricted before a byte is written, then renamed into place. Creating
    // the final file first would leave a private key readable for as long as
    // it took to tighten it, and that window is the whole attack.
    //
    // The old version of this did the same thing on Unix and nothing at all on
    // Windows, where a private key was left at whatever the parent directory's
    // ACL happened to be.
    crate::private_files::write_private(path, &encoded)?;

    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "phoneauth-identity-{}-{name}.pkcs8",
            std::process::id()
        ))
    }

    #[test]
    fn first_run_creates_a_key_and_later_runs_reuse_it() {
        let path = temp_path("stable");
        let _ = fs::remove_file(&path);

        let first = load_or_create(&path).expect("create");
        let second = load_or_create(&path).expect("reload");
        assert_eq!(
            first.public_key_spki().expect("spki"),
            second.public_key_spki().expect("spki"),
            "a restart must not unpair every phone"
        );

        fs::remove_file(&path).ok();
    }

    #[test]
    fn two_agents_do_not_share_an_identity() {
        let (a, b) = (temp_path("a"), temp_path("b"));
        let _ = fs::remove_file(&a);
        let _ = fs::remove_file(&b);

        assert_ne!(
            load_or_create(&a)
                .expect("a")
                .public_key_spki()
                .expect("spki"),
            load_or_create(&b)
                .expect("b")
                .public_key_spki()
                .expect("spki")
        );

        fs::remove_file(&a).ok();
        fs::remove_file(&b).ok();
    }

    #[test]
    fn a_corrupt_key_file_is_reported_rather_than_replaced() {
        let path = temp_path("corrupt");
        fs::write(&path, b"this is not a key").expect("write");

        // `IdentityKey` has no `Debug` on purpose, so unwrap by hand rather
        // than through `expect_err`.
        let error = match load_or_create(&path) {
            Ok(_) => panic!("a corrupt key file must not load"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("re-pair"),
            "the message must say what to do: {error}"
        );
        assert_eq!(
            fs::read(&path).expect("read"),
            b"this is not a key",
            "the file must be left alone, not silently replaced"
        );

        fs::remove_file(&path).ok();
    }

    #[test]
    fn no_temporary_file_survives_a_successful_create() {
        let path = temp_path("clean");
        let _ = fs::remove_file(&path);
        load_or_create(&path).expect("create");

        assert!(!path.with_extension("pkcs8.tmp").exists());
        fs::remove_file(&path).ok();
    }
}
