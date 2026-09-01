//! Copying a secret to the clipboard, and taking it back.
//!
//! The clipboard is the leak this module exists to close. On Windows it is
//! global to the session, so any running program can read it without asking;
//! `Win+V` records a history that outlives the paste; and cloud clipboard
//! synchronises the entry to the user's Microsoft account, which takes the
//! secret off the machine entirely. A password manager that calls
//! `SetClipboardData` and stops there has published the password.
//!
//! Three things follow from that, and all three are implemented here:
//!
//! 1. the entry is removed on a timer rather than left until something else
//!    replaces it;
//! 2. the entry is marked so history and cloud sync skip it;
//! 3. the removal only fires if the clipboard still holds *our* entry, checked
//!    through the sequence number. Clearing unconditionally would delete
//!    whatever the user copied in the meantime, which is a data-loss bug
//!    wearing a security feature's clothes.
//!
//! What cannot be fixed from here: while the entry is live the operating system
//! holds a plaintext copy in memory this process does not own, so
//! [`crate::secret_memory`] protects our copy and not that one. That is inherent
//! to there being a clipboard at all.
//!
//! X11 and Wayland offer different guarantees, and [`CopyOutcome`] reports what
//! was actually achieved instead of showing a padlock that is not there.

use std::time::Duration;

use crate::secret_memory::SecretBuffer;

/// Shortest lifetime worth offering.
pub const MIN_TTL: Duration = Duration::from_secs(5);

/// Longest lifetime this will accept.
///
/// Past a few minutes the timer stops being a mitigation and starts being a
/// promise the user relies on while the secret sits there.
pub const MAX_TTL: Duration = Duration::from_secs(600);

/// What the user gets if they express no preference.
pub const DEFAULT_TTL: Duration = Duration::from_secs(45);

/// What the copy actually achieved.
///
/// The booleans are the honesty mechanism. On Wayland neither exclusion is
/// available, and a UI that renders an unconditional padlock would be lying;
/// with these it can say "cleared in 45s" without also claiming "and no history
/// kept it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyOutcome {
    /// Epoch milliseconds at which the entry is scheduled to be removed.
    pub clears_at_ms: i64,
    /// The entry was marked to stay out of clipboard history (`Win+V`).
    pub history_excluded: bool,
    /// The entry was marked to stay off the user's cloud clipboard.
    pub cloud_excluded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    /// The clipboard could not be opened. On Windows another process holds it
    /// open; this is transient and the caller may retry.
    Unavailable(String),
    /// The secret was not valid UTF-8, so it is not text and does not belong on
    /// a text clipboard.
    NotText,
    /// Outside [`MIN_TTL`]..=[`MAX_TTL`]. Refused rather than clamped: a caller
    /// asking for an hour has misunderstood the feature, and silently giving
    /// them ten minutes hides that.
    TtlOutOfRange { min_ms: u64, max_ms: u64 },
    /// No clipboard integration exists for this platform.
    Unsupported,
}

impl std::fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(why) => write!(f, "clipboard unavailable: {why}"),
            Self::NotText => f.write_str("secret is not valid UTF-8 text"),
            Self::TtlOutOfRange { min_ms, max_ms } => {
                write!(f, "clear timeout must be between {min_ms}ms and {max_ms}ms")
            }
            Self::Unsupported => f.write_str("no clipboard integration on this platform"),
        }
    }
}

impl std::error::Error for ClipboardError {}

/// Puts `secret` on the clipboard and schedules its removal.
///
/// The secret must be UTF-8 text. Returns as soon as the entry is live; the
/// removal happens on a background thread that holds the sequence number and
/// nothing else — deliberately, so a secret is never captured by the closure
/// that outlives the copy.
pub fn copy_secret(secret: &SecretBuffer, ttl: Duration) -> Result<CopyOutcome, ClipboardError> {
    if ttl < MIN_TTL || ttl > MAX_TTL {
        return Err(ClipboardError::TtlOutOfRange {
            min_ms: MIN_TTL.as_millis() as u64,
            max_ms: MAX_TTL.as_millis() as u64,
        });
    }
    let text = std::str::from_utf8(secret.expose()).map_err(|_| ClipboardError::NotText)?;

    let excluded = platform::set_text(text)?;
    // One reading of the clipboard's generation, handed to both the people who
    // need it: the timer that will expire this entry, and a person pressing
    // clear. They used to take a reading each, a few instructions apart, and
    // two readings of a counter the rest of the machine is also moving are two
    // different answers to "is the entry still ours". Disagreeing, they made
    // between them the two failures this module is here to avoid: a clear that
    // deletes what the user copied, and a timer that fires and leaves the
    // secret sitting there.
    let ours = platform::claim();
    platform::schedule_clear(ttl, ours);

    Ok(CopyOutcome {
        clears_at_ms: epoch_ms() + ttl.as_millis() as i64,
        history_excluded: excluded.history,
        cloud_excluded: excluded.cloud,
    })
}

/// Removes the entry now, if it is still ours.
///
/// Where the platform can tell. Windows has a clipboard generation counter and
/// the check is real there; X11 and Wayland have none, so this replaces the
/// selection with nothing and says so rather than pretending otherwise.
pub fn clear_now() -> Result<(), ClipboardError> {
    platform::clear()
}

/// Reads the clipboard back, for tests in other modules of this crate.
///
/// Production code never needs this: the agent puts things on the clipboard and
/// takes them off, and never has a reason to ask what is there.
#[cfg(all(test, windows))]
pub(crate) fn read_for_test() -> Option<String> {
    platform::testing::read_text()
}

/// Serialises every test in this crate that touches the clipboard.
///
/// There is one clipboard per session, so two tests running side by side
/// overwrite each other's entry and the failure looks like a bug in whichever
/// one lost the race. The lock lives here rather than in a test module because
/// `ipc` needs it too.
#[cfg(all(test, windows))]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static CLIPBOARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    CLIPBOARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Which exclusions the platform granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Exclusions {
    history: bool,
    cloud: bool,
}

fn epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(windows)]
mod platform {
    use super::{ClipboardError, Exclusions};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
        RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };

    /// `CF_UNICODETEXT`. Spelled out rather than imported so the clipboard code
    /// does not depend on an OLE feature it otherwise has no use for.
    const CF_UNICODETEXT: u32 = 13;

    /// How many times an expiry will try before giving up.
    ///
    /// [`open`] already retries for about half a second, and that is enough for
    /// the ordinary case of a clipboard manager holding the board while the
    /// user copies. It is not enough for one that holds it longer, and a
    /// swallowed failure there leaves the secret on the clipboard for good --
    /// after the copy told the user, to the second, when it would be gone.
    const CLEAR_ATTEMPTS: u32 = 8;

    /// Between those attempts. Eight of these spans about half a minute.
    const CLEAR_RETRY_DELAY: Duration = Duration::from_millis(4000);

    /// The clipboard generation this module last wrote, or zero for none.
    ///
    /// A clear happens in two situations -- a timer firing, and a person asking
    /// -- and only the timer knew which entry it was allowed to remove, because
    /// it captured the generation itself. This is how the other one knows too:
    /// pressing clear after copying something else must empty nothing.
    static OURS: AtomicU32 = AtomicU32::new(0);

    /// Records the entry just placed as this module's, and says which it is.
    ///
    /// The one place the counter is read after a copy. The caller passes the
    /// answer on to [`schedule_clear`] rather than letting it read again.
    pub(super) fn claim() -> u32 {
        let ours = sequence();
        OURS.store(ours, Ordering::Relaxed);
        ours
    }

    /// Set to a `DWORD` 0 to keep the entry out of `Win+V` history.
    const FORMAT_HISTORY: &str = "CanIncludeInClipboardHistory";
    /// Set to a `DWORD` 0 to keep the entry off the cloud clipboard.
    const FORMAT_CLOUD: &str = "CanUploadToCloudClipboard";
    /// Asks clipboard managers and monitors not to process the entry. Advisory:
    /// a monitor that ignores it is not prevented from reading, which is why
    /// this one is not reported as a guarantee in `CopyOutcome`.
    const FORMAT_NO_MONITOR: &str = "ExcludeClipboardContentFromMonitorProcessing";

    /// Opens the clipboard, retrying briefly.
    ///
    /// Another process holding it open is ordinary rather than exceptional —
    /// every clipboard manager does it — so a single failed attempt is not a
    /// reason to fail the user's copy.
    fn open() -> Result<(), ClipboardError> {
        for attempt in 0..10 {
            // SAFETY: a null owner window is documented as valid; it makes the
            // current task the owner.
            if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10 * (attempt + 1)));
        }
        Err(ClipboardError::Unavailable(
            "another process held the clipboard open".to_owned(),
        ))
    }

    fn close() {
        // SAFETY: only called after a successful `open`.
        unsafe { CloseClipboard() };
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Places a `DWORD` 0 under `name`, returning whether it took.
    fn set_marker(name: &str) -> bool {
        let name = wide(name);
        // SAFETY: `name` is a NUL-terminated UTF-16 string.
        let format = unsafe { RegisterClipboardFormatW(name.as_ptr()) };
        if format == 0 {
            return false;
        }

        // SAFETY: a four byte moveable block.
        let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, 4) };
        if handle.is_null() {
            return false;
        }
        // SAFETY: `handle` came from `GlobalAlloc` and is not yet locked.
        let cell = unsafe { GlobalLock(handle) }.cast::<u32>();
        if cell.is_null() {
            // SAFETY: ownership has not been transferred, so this is ours to free.
            unsafe { GlobalFree(handle) };
            return false;
        }
        // SAFETY: `cell` addresses four writable bytes.
        unsafe { cell.write(0) };
        // SAFETY: balances the lock above.
        unsafe { GlobalUnlock(handle) };

        // SAFETY: on success the system takes ownership of `handle`.
        if unsafe { SetClipboardData(format, handle) }.is_null() {
            // SAFETY: ownership was not transferred.
            unsafe { GlobalFree(handle) };
            return false;
        }
        true
    }

    pub(super) fn set_text(text: &str) -> Result<Exclusions, ClipboardError> {
        // Encoded straight into the block the system will own, so the plaintext
        // exists in one place here rather than in an intermediate `Vec` this
        // module would then have to remember to wipe.
        let units = text.encode_utf16().count() + 1;
        let bytes = units.checked_mul(2).ok_or(ClipboardError::NotText)?;

        open()?;

        // SAFETY: opened above.
        unsafe { EmptyClipboard() };

        // SAFETY: `bytes` is non-zero.
        let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
        if handle.is_null() {
            close();
            return Err(ClipboardError::Unavailable(
                "could not allocate clipboard memory".to_owned(),
            ));
        }
        // SAFETY: freshly allocated, not yet locked.
        let dest = unsafe { GlobalLock(handle) }.cast::<u16>();
        if dest.is_null() {
            // SAFETY: still ours.
            unsafe { GlobalFree(handle) };
            close();
            return Err(ClipboardError::Unavailable(
                "could not lock clipboard memory".to_owned(),
            ));
        }
        for (index, unit) in text.encode_utf16().enumerate() {
            // SAFETY: `index` < `units - 1` and the block holds `units` u16s.
            unsafe { dest.add(index).write(unit) };
        }
        // SAFETY: the final slot, reserved by the `+ 1` above.
        unsafe { dest.add(units - 1).write(0) };
        // SAFETY: balances the lock.
        unsafe { GlobalUnlock(handle) };

        // Markers first: they must be present on the same clipboard generation
        // as the text, and setting them after would leave a window in which the
        // text is live and unmarked.
        let exclusions = Exclusions {
            history: set_marker(FORMAT_HISTORY),
            cloud: set_marker(FORMAT_CLOUD),
        };
        set_marker(FORMAT_NO_MONITOR);

        // SAFETY: on success the system owns `handle`.
        let placed = unsafe { SetClipboardData(CF_UNICODETEXT, handle) };
        if placed.is_null() {
            // SAFETY: ownership was not transferred.
            unsafe { GlobalFree(handle) };
            close();
            return Err(ClipboardError::Unavailable(
                "the clipboard refused the entry".to_owned(),
            ));
        }

        close();
        Ok(exclusions)
    }

    /// The clipboard's generation counter.
    ///
    /// This is what makes expiry safe: if it moved, someone else owns the
    /// clipboard now and clearing would destroy their content.
    fn sequence() -> u32 {
        // SAFETY: no arguments, no pointers.
        unsafe { GetClipboardSequenceNumber() }
    }

    pub(super) fn schedule_clear(ttl: Duration, ours: u32) {
        // Captures a `u32`, never the secret: this closure outlives the copy,
        // and anything it held would outlive it too.
        std::thread::spawn(move || {
            std::thread::sleep(ttl);
            for _ in 0..CLEAR_ATTEMPTS {
                // Asked again every time round, so a copy the user makes while
                // this is retrying ends the retries rather than being deleted
                // by one of them.
                if sequence() != ours {
                    return;
                }
                if clear().is_ok() {
                    return;
                }
                std::thread::sleep(CLEAR_RETRY_DELAY);
            }
        });
    }

    pub(super) fn clear() -> Result<(), ClipboardError> {
        let ours = OURS.load(Ordering::Relaxed);
        // Nothing of ours is out there, or the user has copied since. Emptying
        // now would destroy their content, which is the data-loss bug this
        // module's header refuses to trade for a security feature.
        if ours == 0 || ours != sequence() {
            return Ok(());
        }
        open()?;
        // SAFETY: opened above.
        unsafe { EmptyClipboard() };
        close();
        OURS.store(0, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(test)]
    pub(super) mod testing {
        use super::*;
        use windows_sys::Win32::System::DataExchange::{
            GetClipboardData, IsClipboardFormatAvailable,
        };

        /// Reads the clipboard back as text. Test-only: production never needs
        /// to know what is on the clipboard, only to put things there.
        pub fn read_text() -> Option<String> {
            open().ok()?;
            // SAFETY: opened above.
            let handle = unsafe { GetClipboardData(CF_UNICODETEXT) };
            if handle.is_null() {
                close();
                return None;
            }
            // SAFETY: a clipboard text handle is a global memory block.
            let ptr = unsafe { GlobalLock(handle) }.cast::<u16>();
            if ptr.is_null() {
                close();
                return None;
            }
            let mut units = Vec::new();
            let mut index = 0;
            loop {
                // SAFETY: the block is NUL-terminated by contract.
                let unit = unsafe { *ptr.add(index) };
                if unit == 0 {
                    break;
                }
                units.push(unit);
                index += 1;
            }
            // SAFETY: balances the lock.
            unsafe { GlobalUnlock(handle) };
            close();
            Some(String::from_utf16_lossy(&units))
        }

        pub fn marker_present(name: &str) -> bool {
            let name = wide(name);
            // SAFETY: NUL-terminated UTF-16.
            let format = unsafe { RegisterClipboardFormatW(name.as_ptr()) };
            // SAFETY: no pointers; queries availability without opening.
            format != 0 && unsafe { IsClipboardFormatAvailable(format) } != 0
        }

        pub const HISTORY: &str = FORMAT_HISTORY;
        pub const CLOUD: &str = FORMAT_CLOUD;
        pub const NO_MONITOR: &str = FORMAT_NO_MONITOR;
    }
}

#[cfg(unix)]
mod platform {
    use super::{ClipboardError, Exclusions};
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    /// The helper that owns the selection on this session.
    ///
    /// X11 requires a live process to hold the selection and answer conversion
    /// requests, so there is no "set it and return" call the way Windows has.
    /// Shelling out to the session's own helper is the honest option; the
    /// alternative is an X11 client and event loop inside the agent.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Tool {
        /// Wayland.
        WlCopy,
        /// X11.
        Xclip,
    }

    impl Tool {
        fn program(self) -> &'static str {
            match self {
                Self::WlCopy => "wl-copy",
                Self::Xclip => "xclip",
            }
        }

        fn args(self) -> &'static [&'static str] {
            match self {
                // `--foreground` is deliberately absent: the helper must
                // survive this call to keep owning the selection.
                Self::WlCopy => &[],
                Self::Xclip => &["-selection", "clipboard"],
            }
        }
    }

    /// Picks the helper from the session's environment.
    ///
    /// Wayland first: a Wayland session commonly also exports `DISPLAY` for
    /// XWayland, so testing `DISPLAY` first would send a native Wayland session
    /// down the X11 path.
    pub(super) fn detect(wayland_display: Option<&str>, x_display: Option<&str>) -> Option<Tool> {
        if wayland_display.is_some_and(|value| !value.is_empty()) {
            return Some(Tool::WlCopy);
        }
        if x_display.is_some_and(|value| !value.is_empty()) {
            return Some(Tool::Xclip);
        }
        None
    }

    fn detect_from_env() -> Option<Tool> {
        detect(
            std::env::var("WAYLAND_DISPLAY").ok().as_deref(),
            std::env::var("DISPLAY").ok().as_deref(),
        )
    }

    pub(super) fn set_text(text: &str) -> Result<Exclusions, ClipboardError> {
        let tool = detect_from_env().ok_or(ClipboardError::Unsupported)?;

        // Through stdin, never as an argument: a command line is visible to
        // every user on the machine through `/proc`, so passing a password as
        // `argv` would publish it more thoroughly than the clipboard does.
        let mut child = Command::new(tool.program())
            .args(tool.args())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                ClipboardError::Unavailable(format!("{} : {error}", tool.program()))
            })?;

        child
            .stdin
            .take()
            .ok_or_else(|| ClipboardError::Unavailable("no stdin pipe".to_owned()))?
            .write_all(text.as_bytes())
            .map_err(|error| ClipboardError::Unavailable(error.to_string()))?;

        // Neither exclusion exists here. X11 and Wayland have no history or
        // cloud sync of their own; a clipboard manager may keep one and will
        // not be asked politely by any flag.
        Ok(Exclusions::default())
    }

    /// Nothing to remember: neither tool exposes a generation counter, so
    /// ownership is not a question this platform can answer. See [`clear`].
    pub(super) fn claim() -> u32 {
        0
    }

    pub(super) fn schedule_clear(ttl: Duration, _ours: u32) {
        std::thread::spawn(move || {
            std::thread::sleep(ttl);
            // Once, deliberately. Retrying without an ownership check would
            // widen the window in which this deletes something the user copied
            // in the meantime, which is the worse of the two failures.
            let _ = clear();
        });
    }

    pub(super) fn clear() -> Result<(), ClipboardError> {
        let tool = detect_from_env().ok_or(ClipboardError::Unsupported)?;
        match tool {
            Tool::WlCopy => Command::new("wl-copy")
                .arg("--clear")
                .status()
                .map(|_| ())
                .map_err(|error| ClipboardError::Unavailable(error.to_string())),
            // No sequence number to compare against, so this replaces the
            // selection with nothing rather than verifying it is still ours.
            Tool::Xclip => set_text("").map(|_| ()),
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    use super::{ClipboardError, Exclusions};
    use std::time::Duration;

    pub(super) fn claim() -> u32 {
        0
    }

    pub(super) fn set_text(_text: &str) -> Result<Exclusions, ClipboardError> {
        Err(ClipboardError::Unsupported)
    }

    pub(super) fn schedule_clear(_ttl: Duration, _ours: u32) {}

    pub(super) fn clear() -> Result<(), ClipboardError> {
        Err(ClipboardError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests clobber whatever the developer had copied, which is noted
    /// in `docs/handoff/T1.md`. They serialise through `clipboard::test_lock`.
    #[test]
    fn a_ttl_outside_the_range_is_refused_rather_than_clamped() {
        let secret = SecretBuffer::from_slice(b"hunter2");

        let too_short = copy_secret(&secret, Duration::from_secs(1));
        assert!(matches!(
            too_short,
            Err(ClipboardError::TtlOutOfRange { .. })
        ));

        let too_long = copy_secret(&secret, Duration::from_secs(3600));
        assert!(matches!(
            too_long,
            Err(ClipboardError::TtlOutOfRange { .. })
        ));
    }

    #[test]
    fn a_secret_that_is_not_text_is_refused() {
        let secret = SecretBuffer::from_slice(&[0xFF, 0xFE, 0xFD]);
        assert_eq!(
            copy_secret(&secret, DEFAULT_TTL),
            Err(ClipboardError::NotText)
        );
    }

    /// The reason the module exists: the entry must be marked so `Win+V` and
    /// cloud sync skip it. Asserting the outcome booleans alone would pass on a
    /// build that set them without setting the formats, so this asks the
    /// clipboard itself.
    #[cfg(windows)]
    #[test]
    fn a_copied_secret_is_present_and_marked_against_history_and_cloud() {
        let _guard = test_lock();
        let secret = SecretBuffer::from_slice(b"correct horse battery staple");

        let outcome = copy_secret(&secret, MIN_TTL).expect("copy");

        assert_eq!(
            platform::testing::read_text().as_deref(),
            Some("correct horse battery staple")
        );
        assert!(platform::testing::marker_present(
            platform::testing::HISTORY
        ));
        assert!(platform::testing::marker_present(platform::testing::CLOUD));
        assert!(platform::testing::marker_present(
            platform::testing::NO_MONITOR
        ));
        assert!(outcome.history_excluded);
        assert!(outcome.cloud_excluded);
        assert!(outcome.clears_at_ms > 0);

        clear_now().expect("clear");
    }

    #[cfg(windows)]
    #[test]
    fn clearing_removes_the_secret() {
        let _guard = test_lock();
        let secret = SecretBuffer::from_slice(b"ephemeral");

        copy_secret(&secret, MIN_TTL).expect("copy");
        assert_eq!(platform::testing::read_text().as_deref(), Some("ephemeral"));

        clear_now().expect("clear");

        assert_ne!(platform::testing::read_text().as_deref(), Some("ephemeral"));
    }

    /// Expiry must not destroy what the user copied afterwards. Without the
    /// sequence-number check this test finds "" instead, which is a data-loss
    /// bug that looks like a working security feature.
    #[cfg(windows)]
    #[test]
    fn expiry_leaves_a_later_copy_alone() {
        let _guard = test_lock();
        let secret = SecretBuffer::from_slice(b"expires-soon");

        copy_secret(&secret, MIN_TTL).expect("copy");
        // The user copies something of their own before the timer fires.
        platform::set_text("the user's own text").expect("user copy");

        std::thread::sleep(MIN_TTL + Duration::from_millis(750));

        assert_eq!(
            platform::testing::read_text().as_deref(),
            Some("the user's own text"),
            "the expiry timer cleared a clipboard entry that was not ours"
        );
    }

    /// The timer expires the generation it was handed, not the one it finds.
    ///
    /// Arming the timer used to read the clipboard's generation counter a
    /// second time, a few instructions after the reading that told the
    /// clear-by-hand path which entry was ours. Two readings of a counter the
    /// whole session moves are two answers, and between them they made both of
    /// the failures this module refuses. Read the higher one and the timer had
    /// adopted a stranger's entry, and deleted it on schedule. Read the lower
    /// and the timer fired on a generation `clear` disagreed with, returned
    /// `Ok` without emptying anything, and left the secret on the board past
    /// the second the user was promised it would be gone -- silently, because
    /// a refusal to clear someone else's entry is the correct answer to the
    /// only question `clear` was asked.
    ///
    /// One reading now, taken by `claim` and handed on.
    #[cfg(windows)]
    #[test]
    fn the_timer_expires_only_the_generation_it_was_given() {
        let _guard = test_lock();

        platform::set_text("only-this-generation").expect("copy");
        let ours = platform::claim();

        // Armed with a generation that is not the one on the board -- which is
        // what the second reading amounted to whenever anything at all had
        // copied in between.
        platform::schedule_clear(MIN_TTL, ours.wrapping_sub(1));
        std::thread::sleep(MIN_TTL + Duration::from_millis(750));

        assert_eq!(
            platform::testing::read_text().as_deref(),
            Some("only-this-generation"),
            "the timer emptied a generation it was never given"
        );

        clear_now().expect("clear");
    }

    /// Pressing clear after copying something else must empty nothing.
    ///
    /// The timer has always known which entry it was allowed to remove; this
    /// path did not, and `EmptyClipboard` does not ask.
    #[cfg(windows)]
    #[test]
    fn clearing_by_hand_leaves_a_later_copy_alone() {
        let _guard = test_lock();
        let secret = SecretBuffer::from_slice(b"already-pasted");

        copy_secret(&secret, MIN_TTL).expect("copy");
        // Not through `copy_secret`: this stands for the user copying with
        // Ctrl+C, which is the case the check exists for.
        platform::set_text("the user's own text").expect("user copy");

        clear_now().expect("clear");

        assert_eq!(
            platform::testing::read_text().as_deref(),
            Some("the user's own text"),
            "clearing by hand destroyed a clipboard entry that was not ours"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wayland_wins_over_the_x_display_it_also_exports() {
        use platform::Tool;

        assert_eq!(
            platform::detect(Some("wayland-0"), Some(":0")),
            Some(Tool::WlCopy)
        );
        assert_eq!(platform::detect(None, Some(":0")), Some(Tool::Xclip));
        assert_eq!(platform::detect(None, None), None);
        // An exported-but-empty variable means no session, not a session named
        // "".
        assert_eq!(platform::detect(Some(""), Some("")), None);
    }
}
