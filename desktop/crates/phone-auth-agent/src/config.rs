//! Agent configuration, created on first run and then owned by the user.

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use phone_auth_verifier::encoding::to_hex;
use phone_auth_verifier::random;

use crate::paths::hostname;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfig {
    /// Stable identity of this machine, generated once and then never changed.
    ///
    /// Changing it invalidates every pairing, because the phone's permissions
    /// are recorded against this id.
    pub verifier_id: String,

    /// Name shown on the phone. Safe to edit; it is display only and is
    /// covered by the signature, so a phone always sees the name the verifier
    /// actually claimed.
    pub verifier_name: String,

    /// Loopback port for the IPC listener. Zero asks the OS for a free port,
    /// which is the default so that two user sessions do not fight over one.
    #[serde(default)]
    pub ipc_port: u16,

    /// How long a phone has to answer, in milliseconds.
    #[serde(default = "default_validity_ms")]
    pub request_validity_ms: i64,

    /// Port phones connect to. Zero asks the OS for a free one.
    ///
    /// Ephemeral on first run, because a fixed well-known port is one more
    /// thing to collide or to scan for -- and then written back here, because
    /// the pairing code publishes the port and a paired phone dials the one it
    /// was given. Left at zero, the OS handed out a different port on every
    /// start and every phone already paired went on dialling the old one: the
    /// desktop stopped being reachable after a reboot, and pairing again was
    /// the only thing that appeared to fix it.
    #[serde(default)]
    pub listen_port: u16,
}

fn default_validity_ms() -> i64 {
    60_000
}

impl AgentConfig {
    /// Loads the config, writing a fresh one on first run.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let config = Self::fresh();
                config.save(path)?;
                Ok(config)
            }
            Err(error) => Err(error),
        }
    }

    fn fresh() -> Self {
        Self {
            // 128 random bits rather than the hostname: two machines with the
            // same name must not share an identity, and renaming a machine
            // must not silently unpair it.
            verifier_id: to_hex(&random::bytes::<16>()),
            verifier_name: hostname(),
            ipc_port: 0,
            request_validity_ms: default_validity_ms(),
            listen_port: 0,
        }
    }

    /// Records the port the listener actually got, if it is news.
    ///
    /// Called after binding rather than before, because zero means "any" and
    /// only the OS knows which one that turned out to be.
    pub fn remember_listen_port(&mut self, port: u16, path: &Path) -> io::Result<()> {
        if self.listen_port == port {
            return Ok(());
        }
        self.listen_port = port;
        self.save(path)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        fs::write(path, json)
    }

    /// Rejects a config that would produce invalid requests, so the failure
    /// happens at startup rather than at the moment someone needs to log in.
    pub fn validate(&self) -> Result<(), String> {
        if self.verifier_id.trim().is_empty() || self.verifier_id.len() > 64 {
            return Err("verifierId must be 1-64 characters".into());
        }
        // Counted the way the wire counts it. `AuthRequest` bounds this field
        // at 128 UTF-16 units and this check used to bound it at 128 `char`s,
        // which are not the same thing: anything outside the basic plane --
        // an emoji in a machine name -- is one `char` and two units. Sixty-five
        // of them passed here and then failed `AuthRequest::validate`, so the
        // config was accepted at startup and every authorization built from it
        // was refused as malformed. This function exists to make that
        // impossible, so it has to measure what the wire measures.
        if self.verifier_name.trim().is_empty() || self.verifier_name.encode_utf16().count() > 128 {
            return Err("verifierName must be 1-128 UTF-16 units".into());
        }
        if self.request_validity_ms <= 0
            || self.request_validity_ms > phone_auth_protocol::MAX_VALIDITY_MS
        {
            return Err(format!(
                "requestValidityMs must be between 1 and {}",
                phone_auth_protocol::MAX_VALIDITY_MS
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("phoneauth-cfg-{}-{name}.json", std::process::id()))
    }

    /// A phone dials the port it was handed in the pairing code, so the port
    /// the OS picked has to be the port the agent asks for next time. It used
    /// to be forgotten, which is why a paired desktop stopped answering after
    /// a reboot.
    #[test]
    fn the_port_the_os_chose_survives_a_restart() {
        let path = temp_path("listen-port");
        let _ = fs::remove_file(&path);

        let mut config = AgentConfig::load_or_create(&path).expect("create");
        assert_eq!(config.listen_port, 0, "the first run asks for any port");
        config
            .remember_listen_port(49_732, &path)
            .expect("the port is written down");

        let reloaded = AgentConfig::load_or_create(&path).expect("reload");
        assert_eq!(reloaded.listen_port, 49_732);

        fs::remove_file(&path).ok();
    }

    /// Saving on every start would rewrite the file for nothing, and the file
    /// is the one the user edits.
    #[test]
    fn a_port_that_did_not_change_is_not_rewritten() {
        let path = temp_path("listen-port-unchanged");
        let _ = fs::remove_file(&path);

        let mut config = AgentConfig::load_or_create(&path).expect("create");
        config.remember_listen_port(49_733, &path).expect("write");
        let written = fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime");

        config
            .remember_listen_port(49_733, &path)
            .expect("nothing to do");

        assert_eq!(
            fs::metadata(&path)
                .expect("stat")
                .modified()
                .expect("mtime"),
            written
        );

        fs::remove_file(&path).ok();
    }

    #[test]
    fn first_run_creates_a_usable_config() {
        let path = temp_path("first-run");
        let _ = fs::remove_file(&path);

        let config = AgentConfig::load_or_create(&path).expect("create");
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(config.verifier_id.len(), 32);
        assert!(!config.verifier_name.trim().is_empty());
        assert_eq!(config.ipc_port, 0, "an ephemeral port is the default");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn identity_is_stable_across_restarts() {
        let path = temp_path("stable");
        let _ = fs::remove_file(&path);

        let first = AgentConfig::load_or_create(&path).expect("create");
        let second = AgentConfig::load_or_create(&path).expect("reload");
        assert_eq!(
            first.verifier_id, second.verifier_id,
            "a restart must not unpair every phone"
        );

        fs::remove_file(&path).ok();
    }

    #[test]
    fn two_machines_do_not_share_an_identity() {
        let (a, b) = (temp_path("a"), temp_path("b"));
        let _ = fs::remove_file(&a);
        let _ = fs::remove_file(&b);

        assert_ne!(
            AgentConfig::load_or_create(&a).expect("a").verifier_id,
            AgentConfig::load_or_create(&b).expect("b").verifier_id
        );

        fs::remove_file(&a).ok();
        fs::remove_file(&b).ok();
    }

    #[test]
    fn validation_rejects_out_of_range_values() {
        let mut config = AgentConfig::fresh();

        config.request_validity_ms = 0;
        assert!(config.validate().is_err());

        config.request_validity_ms = phone_auth_protocol::MAX_VALIDITY_MS + 1;
        assert!(config.validate().is_err());

        config.request_validity_ms = 60_000;
        config.verifier_name = "  ".into();
        assert!(config.validate().is_err());
    }

    /// The bound here has to be the bound the wire applies, or this function
    /// waves through a config that cannot authorize anything.
    ///
    /// A name of sixty-five desktop-computer emoji is sixty-five `char`s and a
    /// hundred and thirty UTF-16 units. Measured in `char`s it passed startup
    /// and then failed inside `AuthRequest::validate` on every single request
    /// -- the exact failure this validation was written to move to startup.
    #[test]
    fn a_name_the_wire_will_not_carry_is_refused_at_startup() {
        let mut config = AgentConfig::fresh();
        config.verifier_name = "\u{1f5a5}".repeat(65);
        assert_eq!(config.verifier_name.chars().count(), 65);

        assert!(
            config.validate().is_err(),
            "a name that no request can carry was accepted as a config"
        );

        // And what the wire does carry still passes: the bound narrowed for
        // astral characters, not for names.
        config.verifier_name = "D".repeat(128);
        config
            .validate()
            .expect("128 units is the bound, not one under it");
    }

    #[test]
    fn a_minimal_config_file_fills_in_defaults() {
        let parsed: AgentConfig =
            serde_json::from_str(r#"{"verifierId":"abc","verifierName":"Desk"}"#)
                .expect("minimal config parses");
        assert_eq!(parsed.request_validity_ms, 60_000);
        assert_eq!(parsed.ipc_port, 0);
    }
}
