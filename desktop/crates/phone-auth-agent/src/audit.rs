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

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        // The log names every service, resource and account this machine has
        // authorized. That is not a secret, but it is a map of what the user
        // does and it has no business being world-readable — which is what an
        // ordinary `create` at the default umask makes it.
        //
        // Set at creation rather than afterwards: tightening a file that
        // already exists leaves the window that `private_files` exists to
        // close, and the mode is ignored when the file is already there.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path)?;
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

        // Newest first, bounded by the count *and* by the bytes.
        //
        // The count alone was the whole rule, and it holds only while `retain`
        // entries fit inside the threshold -- an invariant nothing stated and
        // nothing checked. Entries are bounded by the protocol, not small: the
        // request fields alone allow 64 + 128 + 256 + 128 UTF-16 units before the
        // device name, the origin and a failure detail. Past roughly a kilobyte
        // each, five hundred of them no longer fit in 512 KiB, and both halves of
        // this function break at once.
        //
        // `entries.len() <= self.retain` returned early, so the file was never
        // trimmed and grew without bound. Then, once there were more than
        // `retain` of them, every append trimmed -- reading and rewriting the
        // whole log -- because the result was still over the threshold. That is
        // exactly the cost the comment above says this design avoids.
        //
        // Half the threshold, so a trim leaves room for the appends that follow
        // it rather than for one.
        let budget = (self.trim_threshold_bytes / 2) as usize;
        let mut lines: Vec<Vec<u8>> = Vec::new();
        let mut bytes = 0usize;
        for entry in entries.iter().rev().take(self.retain) {
            let mut line = serde_json::to_vec(entry)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            line.push(b'\n');
            // Never empty. One entry larger than the whole budget is still the
            // most recent thing that happened, and a log answering "nothing has
            // ever been authorized" is worse than one that is too big.
            if !lines.is_empty() && bytes + line.len() > budget {
                break;
            }
            bytes += line.len();
            lines.push(line);
        }
        if lines.len() >= entries.len() {
            return Ok(());
        }
        let mut buffer = Vec::with_capacity(bytes);
        for line in lines.iter().rev() {
            buffer.extend_from_slice(line);
        }
        // Rotation rewrites the whole log, so the replacement has to be as
        // narrow as the file it replaces: a plain `fs::write` would hand the
        // history back to the default umask on every trim.
        //
        // Not `private_files::write_private`, which rewrites an explicit DACL
        // each time. That is right for a file written once at startup and
        // wrong here — trimming happens on every append past the limit, and on
        // Windows the DACL call costs enough to turn a flood of authorizations
        // into ten minutes of security descriptors. The directory's ACL
        // already covers this file; what rotation has to preserve is the mode,
        // and that comes free at open.
        let temp = self.path.with_extension("jsonl.tmp");
        let mut options = OpenOptions::new();
        options.write(true).truncate(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(&buffer)?;
        drop(file);
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

    /// The log names every service, resource and account this machine has
    /// authorized. Not a secret, but a map of what the user does, and an
    /// ordinary `create` at the default umask makes it world-readable.
    #[cfg(unix)]
    #[test]
    fn the_log_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("phoneauth-audit-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("sandbox");
        // A tiny threshold so a handful of appends forces a rotation.
        let log = AuditLog::with_limits(dir.join("audit.jsonl"), 2, 64);

        log.append(&entry("first", 1)).expect("append");
        let created = fs::metadata(log.path()).expect("stat").permissions().mode() & 0o777;

        // Past both limits, so the next appends rotate the file and the
        // replacement has to be as narrow as what it replaced.
        for index in 0..8 {
            log.append(&entry("flood", index)).expect("append");
        }
        let rotated = fs::metadata(log.path()).expect("stat").permissions().mode() & 0o777;

        assert_eq!(created, 0o600, "created world-readable");
        assert_eq!(rotated, 0o600, "rotation widened the log");

        fs::remove_dir_all(&dir).ok();
    }

    /// `retain` entries have to fit inside the threshold, and nothing said so.
    ///
    /// Fifty entries of about 224 bytes is 11 KiB against a 2 KiB threshold.
    /// Under the count rule alone this never trimmed at all: the file crossed
    /// the threshold at ten entries, `entries.len() <= self.retain` returned
    /// early, and it went on doing that for as long as the agent kept
    /// authorizing things. The real limits are 500 and 512 KiB, which is the
    /// same shape as soon as an entry averages over a kilobyte -- and the
    /// protocol allows 64 + 128 + 256 + 128 UTF-16 units of request fields
    /// before the device name, the origin and a failure detail.
    #[test]
    fn a_log_whose_entries_do_not_fit_the_count_is_still_bounded() {
        let path =
            std::env::temp_dir().join(format!("phoneauth-audit-{}-wide.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        let log = AuditLog::with_limits(&path, 50, 2048);

        for index in 0..40 {
            log.append(&entry(&format!("r-{index}"), index as i64))
                .expect("append");
        }

        let size = fs::metadata(&path).expect("stat").len();
        assert!(
            size <= 2048,
            "the log grew to {size} bytes, past the threshold it trims at"
        );
        assert_eq!(
            log.recent(1)[0].request_id,
            "r-39",
            "trimming keeps the newest entries"
        );

        fs::remove_file(&path).ok();
    }

    /// A crashed rotation leaves the temp file behind. The next trim has to
    /// replace it rather than fail, or one interrupted write would stop the
    /// log from ever being trimmed again.
    #[test]
    fn a_leftover_rotation_temp_does_not_wedge_the_log() {
        let dir = std::env::temp_dir().join(format!("phoneauth-audit-temp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("sandbox");
        let path = dir.join("audit.jsonl");
        let log = AuditLog::with_limits(path.clone(), 2, 64);

        fs::write(path.with_extension("jsonl.tmp"), b"left over from a crash").expect("plant");
        for index in 0..6 {
            log.append(&entry("entry", index)).expect("append");
        }

        // One, not `retain`. At a 64-byte threshold the byte budget binds long
        // before the count does -- a single entry serialises to about 224 --
        // and the floor keeps the newest one rather than emptying the log.
        // What this test is about is that trimming happened at all with the
        // temp file in the way: untrimmed, six appends are six entries.
        assert_eq!(log.recent(10).len(), 1, "the log kept trimming");

        fs::remove_dir_all(&dir).ok();
    }
}
