//! Append-only record of what was asked and what was decided.
//!
//! # What is deliberately absent
//!
//! No challenge, no session binding, no signature, no public key, no frame
//! bytes, no key material of any kind. The audit log answers "who approved
//! what, from where, and when"; anything beyond that turns a readable history
//! into a file that has to be protected like a secret.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use phone_auth_verifier::Grant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Granted,
    Denied,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub at_ms: i64,
    pub outcome: Outcome,
    pub request_id: String,
    pub service: String,
    pub action: String,
    pub resource: String,
    pub user: String,
    pub device_name: String,
    pub origin: String,
    /// Why it failed, when it did. Carries no protocol material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// True when the answer came from a development transport.
    pub development: bool,
}

impl AuditEntry {
    pub fn granted(grant: &Grant, development: bool) -> Self {
        Self {
            at_ms: grant.granted_at_ms,
            outcome: Outcome::Granted,
            request_id: grant.request_id.clone(),
            service: grant.service.clone(),
            action: grant.action.clone(),
            resource: grant.resource.clone(),
            user: grant.user.clone(),
            device_name: grant.device_name.clone(),
            origin: grant.origin.clone(),
            detail: None,
            development,
        }
    }
}

/// A bounded, append-only JSON-lines log.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    /// Entries kept when the file is trimmed.
    retain: usize,
    /// File size above which a trim is considered.
    trim_threshold_bytes: u64,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            retain: 500,
            // Roughly 500 entries at a few hundred bytes each, with room to
            // spare so trimming is rare rather than constant.
            trim_threshold_bytes: 512 * 1024,
        }
    }

    /// Smaller limits so trimming can be exercised without writing megabytes.
    #[cfg(test)]
    fn with_limits(path: impl Into<PathBuf>, retain: usize, trim_threshold_bytes: u64) -> Self {
        Self {
            path: path.into(),
            retain,
            trim_threshold_bytes,
        }
    }

    /// Appends an entry.
    ///
    /// Failure to write is reported but never blocks the decision that was
    /// already made: losing an audit line is bad, refusing a login because the
    /// disk is full is worse.
    pub fn append(&self, entry: &AuditEntry) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_vec(entry)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        line.push(b'\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&line)?;

        self.trim_if_needed()?;
        Ok(())
    }

    /// Most recent entries, newest first.
    pub fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        let mut entries = self.read_all();
        entries.reverse();
        entries.truncate(limit);
        entries
    }

    fn read_all(&self) -> Vec<AuditEntry> {
        let Ok(file) = fs::File::open(&self.path) else {
            return Vec::new();
        };
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            // A corrupt line is skipped rather than fatal; a truncated write
            // from a previous crash must not make the history unreadable.
            .filter_map(|line| serde_json::from_str(&line).ok())
            .collect()
    }

    /// Keeps the file bounded so a request flood cannot fill the disk.
    ///
    /// Gated on the file's size rather than on parsing it, because this runs
    /// after every append: re-reading the whole log each time would make
    /// authorization cost grow with the length of the history.
    fn trim_if_needed(&self) -> io::Result<()> {
        let size = fs::metadata(&self.path)?.len();
        if size <= self.trim_threshold_bytes {
            return Ok(());
        }
        let entries = self.read_all();
        if entries.len() <= self.retain {
            return Ok(());
        }
        let kept = &entries[entries.len() - self.retain..];
        let mut buffer = Vec::new();
        for entry in kept {
            serde_json::to_writer(&mut buffer, entry)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            buffer.push(b'\n');
        }
        let temp = self.path.with_extension("jsonl.tmp");
        fs::write(&temp, &buffer)?;
        fs::rename(&temp, &self.path)
    }

    /// The backing file. Used by tests; the agent addresses the log through
    /// this type rather than by path.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> AuditLog {
        let path = std::env::temp_dir().join(format!(
            "phoneauth-audit-{}-{name}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        AuditLog::new(path)
    }

    fn entry(request_id: &str, at_ms: i64) -> AuditEntry {
        AuditEntry {
            at_ms,
            outcome: Outcome::Granted,
            request_id: request_id.into(),
            service: "sudo".into(),
            action: "nixos-rebuild switch".into(),
            resource: "Desktop-NixOS".into(),
            user: "alice".into(),
            device_name: "Pixel".into(),
            origin: "BleTransport • paired phone".into(),
            detail: None,
            development: false,
        }
    }

    #[test]
    fn entries_round_trip_newest_first() {
        let log = temp_log("order");
        log.append(&entry("r-1", 1)).expect("append");
        log.append(&entry("r-2", 2)).expect("append");

        let recent = log.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].request_id, "r-2", "newest entry comes first");
        assert_eq!(recent[1].request_id, "r-1");

        fs::remove_file(log.path()).ok();
    }

    #[test]
    fn the_log_never_carries_protocol_secrets() {
        // The serialized shape is the contract. If a field carrying challenge
        // or signature material is ever added, this fails.
        let json = serde_json::to_string(&entry("r-1", 1)).expect("serialize");
        for forbidden in [
            "challenge",
            "signature",
            "sessionBinding",
            "publicKey",
            "payload",
        ] {
            assert!(
                !json.contains(forbidden),
                "audit entry must not contain `{forbidden}`: {json}"
            );
        }
    }

    #[test]
    fn a_corrupt_line_does_not_hide_the_rest() {
        let log = temp_log("corrupt");
        log.append(&entry("r-1", 1)).expect("append");
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(log.path())
                .expect("open");
            file.write_all(b"{ this is not json\n").expect("write");
        }
        log.append(&entry("r-2", 2)).expect("append");

        let recent = log.recent(10);
        assert_eq!(recent.len(), 2, "readable entries survive a bad line");

        fs::remove_file(log.path()).ok();
    }

    #[test]
    fn the_file_stays_bounded_under_a_flood() {
        let path = std::env::temp_dir().join(format!(
            "phoneauth-audit-{}-flood.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let log = AuditLog::with_limits(&path, 50, 8 * 1024);

        // Enough appends to cross the trim threshold several times over.
        // Each one reopens the file, so this is kept small deliberately.
        for index in 0..300 {
            log.append(&entry(&format!("r-{index}"), index as i64))
                .expect("append");
        }

        let all = log.read_all();
        assert!(
            all.len() <= 200,
            "log grew unbounded to {} entries",
            all.len()
        );
        assert_eq!(
            log.recent(1)[0].request_id,
            "r-299",
            "trimming keeps the newest entries"
        );

        fs::remove_file(&path).ok();
    }

    #[test]
    fn reading_a_missing_log_is_empty_not_an_error() {
        let log = AuditLog::new(std::env::temp_dir().join("phoneauth-audit-does-not-exist.jsonl"));
        assert!(log.recent(10).is_empty());
    }
}
