//! Where the agent keeps its files.
//!
//! Three separate locations, because they have different lifetimes and
//! different exposure: configuration the user edits, pairing data that must
//! survive reboots, and runtime data that must *not*.

use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

/// Resolved locations for one agent instance.
#[derive(Debug, Clone)]
pub struct Paths {
    /// User-editable settings.
    pub config_dir: PathBuf,
    /// Pairing store and audit log.
    pub data_dir: PathBuf,
    /// IPC endpoint description. Deleted on shutdown; must not outlive the
    /// process, or a stale file will point a client at a port someone else
    /// now owns.
    pub runtime_dir: PathBuf,
}

impl Paths {
    /// Resolves platform-appropriate directories, honouring an explicit
    /// override so that tests and multiple instances do not collide.
    pub fn resolve(override_root: Option<PathBuf>) -> Self {
        if let Some(root) = override_root {
            return Self {
                config_dir: root.join("config"),
                data_dir: root.join("data"),
                runtime_dir: root.join("run"),
            };
        }
        platform_paths()
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("agent.json")
    }

    pub fn pairing_file(&self) -> PathBuf {
        self.data_dir.join("devices.json")
    }

    pub fn audit_file(&self) -> PathBuf {
        self.data_dir.join("audit.jsonl")
    }

    /// The agent's handshake identity, PKCS#8 DER.
    ///
    /// The only private key on this side. It lives with the pairing data
    /// rather than the config because it is state, not settings: a user who
    /// edits their config should never be editing a key.
    pub fn identity_file(&self) -> PathBuf {
        self.data_dir.join("identity.pkcs8")
    }

    /// Describes the live IPC endpoint: port and connection token.
    pub fn endpoint_file(&self) -> PathBuf {
        self.runtime_dir.join("agent-endpoint.json")
    }

    /// Creates the three directories and narrows them to this user.
    ///
    /// Narrowing the *directory* rather than each file is what makes this one
    /// call enough: the pairing store and the audit log are written by plain
    /// `fs::write` in code that has no reason to know about permissions, and
    /// a directory nobody else can enter covers them.
    ///
    /// On Windows the entry is inheritable, so files created later get it too.
    /// On Unix `0o700` denies traversal, which has the same effect without
    /// touching the files at all.
    pub fn create_all(&self) -> io::Result<()> {
        for dir in [&self.config_dir, &self.data_dir, &self.runtime_dir] {
            fs::create_dir_all(dir)?;
            crate::private_files::restrict_dir(dir)?;
        }
        Ok(())
    }
}

#[cfg(windows)]
fn platform_paths() -> Paths {
    // Windows has no runtime-directory concept; LocalAppData is user-scoped
    // and already excluded from roaming profiles, which is what matters for
    // a file describing a live local socket.
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
        .join("PhoneAuth");
    Paths {
        config_dir: base.join("config"),
        data_dir: base.join("data"),
        runtime_dir: base.join("run"),
    }
}

#[cfg(target_os = "macos")]
fn platform_paths() -> Paths {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    let base = home.join("Library/Application Support/PhoneAuth");
    Paths {
        config_dir: base.join("config"),
        data_dir: base.join("data"),
        runtime_dir: env::temp_dir().join("phone-auth"),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_paths() -> Paths {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    let config_home = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let data_home = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    // XDG_RUNTIME_DIR is cleaned on logout, which is exactly the lifetime the
    // endpoint file needs. Falling back to /tmp is worse but still workable.
    let runtime_home = env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);

    Paths {
        config_dir: config_home.join("phone-auth"),
        data_dir: data_home.join("phone-auth"),
        runtime_dir: runtime_home.join("phone-auth"),
    }
}

/// Best-effort machine name, used as the default verifier display name.
///
/// This is what the user reads on the phone before approving, so an
/// unhelpful default is a usability problem rather than a cosmetic one.
pub fn hostname() -> String {
    if let Some(name) = env::var_os("COMPUTERNAME").or_else(|| env::var_os("HOSTNAME")) {
        if let Some(name) = name.to_str().map(str::trim).filter(|n| !n.is_empty()) {
            return name.to_owned();
        }
    }
    if let Ok(contents) = fs::read_to_string("/etc/hostname") {
        let name = contents.trim();
        if !name.is_empty() {
            return name.to_owned();
        }
    }
    "This computer".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_root_keeps_the_three_areas_separate() {
        let paths = Paths::resolve(Some(PathBuf::from("/tmp/instance")));
        assert_ne!(paths.config_dir, paths.data_dir);
        assert_ne!(paths.data_dir, paths.runtime_dir);
        assert!(paths.pairing_file().starts_with(&paths.data_dir));
        assert!(paths.endpoint_file().starts_with(&paths.runtime_dir));
        assert!(paths.config_file().starts_with(&paths.config_dir));
    }

    #[test]
    fn platform_paths_are_absolute_and_distinct() {
        let paths = Paths::resolve(None);
        assert!(paths.config_dir.is_absolute(), "{:?}", paths.config_dir);
        assert!(paths.data_dir.is_absolute());
        assert!(paths.runtime_dir.is_absolute());
    }

    #[test]
    fn hostname_is_never_blank() {
        assert!(!hostname().trim().is_empty());
    }
}
