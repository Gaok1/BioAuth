//! Proof, on a date, that the volume still opens without the phone.
//!
//! Enrolment already proves it once: `cryptsetup luksAddKey` will not add the
//! phone's keyslot for anybody who cannot already open the volume. What it
//! cannot prove is anything about next year. A passphrase nobody types is a
//! passphrase that may have been changed, forgotten, or only ever written on a
//! note that is gone — and the day that matters is the day the phone is at the
//! bottom of a river, which is the worst possible day to find out.
//!
//! So the drill is recorded. `luks drill` runs `cryptsetup --test-passphrase`,
//! which opens nothing and only answers whether what was typed works, and
//! stamps the volume with the date. `luks drill --check` reads the stamps
//! without asking anything of anybody, which is what lets a timer run it: it
//! cannot verify a passphrase, so it verifies that somebody did, recently.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// What is known about one volume's second way in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DrillRecord {
    /// The keyslot the phone was given, when cryptsetup named it. Kept so a
    /// drill can refuse to count the phone's own slot as a passphrase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_slot: Option<u32>,
    pub enrolled_at_ms: i64,
    /// When a passphrase was last typed and accepted. Starts at the enrolment,
    /// because `luksAddKey` asked for one and got it.
    pub last_drill_at_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_drill_slot: Option<u32>,
}

/// Every enrolled volume on this machine, by the name the phone shows.
pub type DrillLog = BTreeMap<String, DrillRecord>;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as i64)
        .unwrap_or_default()
}

/// Reads the log, treating "no file yet" as "nothing enrolled".
///
/// A file that exists but does not parse is an error, never an empty log: a
/// silent reset here would answer "no volume is overdue" forever.
pub fn read(path: &Path) -> Result<DrillLog, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| format!("{} is not a drill log: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DrillLog::new()),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

pub fn write(path: &Path, log: &DrillLog) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(log).map_err(|error| error.to_string())?;
    std::fs::write(path, json).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// Volumes whose last drill is older than `max_age_days`, oldest first.
///
/// Dates in the future are not treated as fresh. A clock that jumped forward
/// once would otherwise silence the check until the drill really was overdue
/// by however far it jumped.
pub fn overdue(log: &DrillLog, max_age_days: u32, now_ms: i64) -> Vec<(String, i64)> {
    let max_age = i64::from(max_age_days) * 86_400_000;
    let mut stale: Vec<(String, i64)> = log
        .iter()
        .map(|(volume, record)| (volume.clone(), now_ms - record.last_drill_at_ms))
        .filter(|(_, age)| *age > max_age || *age < 0)
        .collect();
    stale.sort_by_key(|(_, age)| -*age);
    stale
}

/// An age a person reads, from milliseconds.
pub fn describe_age(age_ms: i64) -> String {
    if age_ms < 0 {
        return "dated in the future".to_owned();
    }
    let days = age_ms / 86_400_000;
    match days {
        0 => "today".to_owned(),
        1 => "1 day ago".to_owned(),
        _ => format!("{days} days ago"),
    }
}

/// The keyslot cryptsetup says it unlocked, from its verbose output.
///
/// Absent is a normal answer, not a failure: the wording is cryptsetup's, not
/// an interface, and the drill's real result is the exit status.
pub fn parse_unlocked_slot(output: &str) -> Option<u32> {
    for line in output.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("Key slot ") else {
            continue;
        };
        let (number, tail) = rest.split_once(' ')?;
        if tail.starts_with("unlocked") {
            return number.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(last_drill_at_ms: i64) -> DrillRecord {
        DrillRecord {
            phone_slot: Some(1),
            enrolled_at_ms: 0,
            last_drill_at_ms,
            last_drill_slot: None,
        }
    }

    const DAY: i64 = 86_400_000;

    #[test]
    fn a_volume_drilled_within_the_window_is_not_reported() {
        let mut log = DrillLog::new();
        log.insert("cryptroot".to_owned(), record(80 * DAY));
        assert!(overdue(&log, 90, 100 * DAY).is_empty());
    }

    #[test]
    fn the_oldest_overdue_volume_is_named_first() {
        let mut log = DrillLog::new();
        log.insert("cryptroot".to_owned(), record(100 * DAY));
        log.insert("crypthome".to_owned(), record(10 * DAY));
        let stale = overdue(&log, 90, 200 * DAY);
        assert_eq!(stale.len(), 2);
        assert_eq!(stale[0].0, "crypthome");
        assert_eq!(describe_age(stale[0].1), "190 days ago");
    }

    #[test]
    fn a_drill_dated_in_the_future_is_not_read_as_fresh() {
        // A clock that jumped forward and back would otherwise buy silence
        // for as long as the jump lasted.
        let mut log = DrillLog::new();
        log.insert("cryptroot".to_owned(), record(400 * DAY));
        let stale = overdue(&log, 90, 100 * DAY);
        assert_eq!(stale.len(), 1);
        assert_eq!(describe_age(stale[0].1), "dated in the future");
    }

    #[test]
    fn a_log_that_does_not_parse_is_an_error_not_an_empty_log() {
        let dir = std::env::temp_dir().join("phone-auth-drill-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("broken.json");
        std::fs::write(&path, b"{ not json").expect("write");
        assert!(read(&path).is_err());
        std::fs::remove_file(&path).ok();
        assert_eq!(
            read(&path).expect("a missing log is empty"),
            DrillLog::new()
        );
    }

    #[test]
    fn the_slot_cryptsetup_unlocked_is_read_when_it_says_so() {
        assert_eq!(parse_unlocked_slot("Key slot 0 unlocked.\n"), Some(0));
        assert_eq!(
            parse_unlocked_slot("Command successful.\n"),
            None,
            "silence is not slot zero"
        );
    }
}
