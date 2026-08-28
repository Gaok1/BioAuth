//! Memory that does not leave the process.
//!
//! A vault secret sits in the agent while the user goes to paste it, which is a
//! much longer window than the locker's data key gets. Over that window the
//! realistic ways a plaintext reaches disk are the pagefile and a crash dump,
//! and both have an operating system call that says "not this page".
//!
//! What this buys, stated plainly so nobody over-claims it later:
//!
//! - `VirtualLock`/`mlock` keeps the page out of the pagefile;
//! - `WerRegisterExcludedMemoryBlock`/`MADV_DONTDUMP` keeps it out of crash and
//!   core dumps.
//!
//! What it does not buy: hibernation writes all of RAM to disk and ignores the
//! lock, and none of this stops a process that can already read this one's
//! memory. Full-disk encryption is the answer to both, and `docs/dependencies.md`
//! records that trade rather than leaving it implied.
//!
//! Encrypting the buffer in place was considered and rejected. The key would
//! live in this same address space, so any dump that captured the ciphertext
//! would capture the key beside it. The goal is to stop bytes leaving the
//! process, not to re-encrypt them inside it.

use std::alloc::{self, Layout};
use std::ptr::NonNull;

/// A fixed-size byte buffer that is wiped on drop and, where the platform
/// allows, kept out of the pagefile and out of crash dumps.
///
/// There is deliberately no `Debug`, no `Display` and no `Serialize`: the
/// codebase treats "has no `Debug`" as the proof that a type cannot reach a log
/// through the usual accidents, and a redacting `Debug` would weaken that rule
/// for every reviewer who relies on it.
///
/// The allocation is page-aligned and rounded up to whole pages. That is not
/// tidiness: `madvise` refuses an unaligned address outright, and locking a
/// sub-page range would silently rope in whichever unrelated allocation shared
/// the page.
pub struct SecretBuffer {
    ptr: NonNull<u8>,
    /// What the caller asked for. The allocation behind it is larger.
    len: usize,
    layout: Layout,
    locked: bool,
}

// The buffer owns its allocation exclusively and hands out references only
// through `&self`/`&mut self`, so moving it between threads is no different
// from moving a `Box<[u8]>`. The clipboard's expiry path needs this.
unsafe impl Send for SecretBuffer {}

impl SecretBuffer {
    /// A zeroed buffer of `len` bytes.
    ///
    /// Zero length still takes a page: an empty secret is a caller bug rather
    /// than a case worth a branch, and a null pointer here would turn that bug
    /// into unsafety.
    pub fn new(len: usize) -> Self {
        let page = page_size();
        let size = len.max(1).next_multiple_of(page);
        let layout = Layout::from_size_align(size, page).expect("page-aligned layout");

        // SAFETY: `layout` has non-zero size, checked above by `max(1)`.
        let raw = unsafe { alloc::alloc_zeroed(layout) };
        let Some(ptr) = NonNull::new(raw) else {
            alloc::handle_alloc_error(layout);
        };

        // SAFETY: the allocation is exactly `size` bytes at `ptr`, and `size`
        // is a whole number of pages starting on a page boundary.
        let locked = unsafe { lock_pages(ptr.as_ptr(), size) };

        Self {
            ptr,
            len,
            layout,
            locked,
        }
    }

    /// A buffer holding a copy of `bytes`.
    ///
    /// The source is the caller's problem to wipe. This exists because the
    /// secret usually arrives inside something the caller does not control,
    /// and the copy is the first moment it can be protected.
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut buffer = Self::new(bytes.len());
        buffer.expose_mut().copy_from_slice(bytes);
        buffer
    }

    pub fn expose(&self) -> &[u8] {
        // SAFETY: `len` is within the allocation and the memory was zeroed at
        // allocation time, so every byte is initialised.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `expose`, and `&mut self` rules out aliasing.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the operating system actually pinned the pages.
    ///
    /// This is not decoration. `VirtualLock` fails once the process reaches its
    /// working-set quota and `mlock` fails against `RLIMIT_MEMLOCK`, both of
    /// which are ordinary conditions rather than bugs. A caller that shows the
    /// user a padlock is entitled to know the lock did not happen, and the
    /// alternative — failing the whole copy because a hardening measure was
    /// unavailable — would trade a real feature for a partial one.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Overwrites the contents now rather than at drop.
    ///
    /// Drop calls exactly this, which is what makes the wipe testable: reading
    /// the buffer after it has been dropped would be undefined behaviour, so
    /// the observable half is tested here and the destructor is one line.
    pub fn wipe(&mut self) {
        wipe_bytes(self.expose_mut());
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        // Wipe before unlocking. Between the unlock and the deallocation the
        // pages are ordinary memory again and the plaintext would be eligible
        // for the pagefile, which is the exact thing this type exists to avoid.
        let size = self.layout.size();
        // SAFETY: the whole allocation is ours and initialised.
        wipe_bytes(unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), size) });

        if self.locked {
            // SAFETY: same address and size that were locked.
            unsafe { unlock_pages(self.ptr.as_ptr(), size) };
        }

        // SAFETY: allocated by `alloc_zeroed` with this exact layout.
        unsafe { alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

/// Overwrites `buffer` with zeroes in a way the optimiser may not remove.
///
/// A plain loop or `fill(0)` is a dead store to a compiler that can see the
/// memory is never read again, and "never read again" is precisely the
/// situation at drop.
fn wipe_bytes(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, writable `u8`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(windows)]
fn page_size() -> usize {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

    let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid, writable `SYSTEM_INFO`.
    unsafe { GetSystemInfo(&mut info) };
    info.dwPageSize as usize
}

#[cfg(unix)]
fn page_size() -> usize {
    // SAFETY: `sysconf` takes a name and returns a long; no pointers involved.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as usize
    } else {
        4096
    }
}

#[cfg(not(any(windows, unix)))]
fn page_size() -> usize {
    4096
}

/// Pins `size` bytes at `ptr` and excludes them from dumps.
///
/// Returns whether the pinning succeeded. Dump exclusion is best-effort and
/// deliberately does not affect the return value: it is the weaker of the two
/// guarantees, and reporting "not locked" because a dump registration failed
/// would misdescribe what happened.
///
/// # Safety
///
/// `ptr` must point at a live allocation of at least `size` bytes, beginning on
/// a page boundary, with `size` a whole number of pages.
#[cfg(windows)]
unsafe fn lock_pages(ptr: *mut u8, size: usize) -> bool {
    use windows_sys::Win32::System::ErrorReporting::WerRegisterExcludedMemoryBlock;
    use windows_sys::Win32::System::Memory::VirtualLock;

    let locked = unsafe { VirtualLock(ptr.cast(), size) } != 0;

    if let Ok(size) = u32::try_from(size) {
        // Best-effort: this API arrived in Windows 10 1709 and returns a
        // failing HRESULT on older builds rather than trapping. The pagefile is
        // the bigger exposure and `VirtualLock` already covered it.
        let _ = unsafe { WerRegisterExcludedMemoryBlock(ptr.cast(), size) };
    }

    locked
}

/// See the Windows implementation for the contract.
///
/// # Safety
///
/// As the Windows implementation.
#[cfg(unix)]
unsafe fn lock_pages(ptr: *mut u8, size: usize) -> bool {
    let locked = unsafe { libc::mlock(ptr.cast(), size) } == 0;

    // `MADV_DONTDUMP` is Linux-only; other unixes keep the lock and lose the
    // dump exclusion rather than failing the allocation.
    #[cfg(target_os = "linux")]
    // SAFETY: page-aligned address and whole-page length, as required.
    let _ = unsafe { libc::madvise(ptr.cast(), size, libc::MADV_DONTDUMP) };

    locked
}

#[cfg(not(any(windows, unix)))]
unsafe fn lock_pages(_ptr: *mut u8, _size: usize) -> bool {
    false
}

/// # Safety
///
/// `ptr` and `size` must be the values passed to a successful [`lock_pages`].
#[cfg(windows)]
unsafe fn unlock_pages(ptr: *mut u8, size: usize) {
    use windows_sys::Win32::System::ErrorReporting::WerUnregisterExcludedMemoryBlock;
    use windows_sys::Win32::System::Memory::VirtualUnlock;

    let _ = unsafe { WerUnregisterExcludedMemoryBlock(ptr.cast()) };
    let _ = unsafe { VirtualUnlock(ptr.cast(), size) };
}

/// # Safety
///
/// As the Windows implementation.
#[cfg(unix)]
unsafe fn unlock_pages(ptr: *mut u8, size: usize) {
    #[cfg(target_os = "linux")]
    // SAFETY: reverses the advice given in `lock_pages`.
    let _ = unsafe { libc::madvise(ptr.cast(), size, libc::MADV_DODUMP) };

    let _ = unsafe { libc::munlock(ptr.cast(), size) };
}

#[cfg(not(any(windows, unix)))]
unsafe fn unlock_pages(_ptr: *mut u8, _size: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_buffer_is_zeroed_and_the_requested_length() {
        let buffer = SecretBuffer::new(20);
        assert_eq!(buffer.len(), 20);
        assert_eq!(buffer.expose(), &[0u8; 20]);
    }

    #[test]
    fn a_copy_holds_what_it_was_given() {
        let buffer = SecretBuffer::from_slice(b"correct horse battery staple");
        assert_eq!(buffer.expose(), b"correct horse battery staple");
        assert_eq!(buffer.len(), 28);
    }

    /// The destructor calls exactly this, so testing it here is what makes the
    /// wipe covered at all: reading the buffer after drop would be undefined
    /// behaviour, and a test that does it proves nothing about a release build.
    #[test]
    fn wiping_replaces_every_byte() {
        let mut buffer = SecretBuffer::from_slice(b"hunter2");
        assert_eq!(buffer.expose(), b"hunter2");

        buffer.wipe();

        assert_eq!(buffer.expose(), &[0u8; 7]);
    }

    /// A secret larger than one page must still be wiped and locked in full.
    /// The rounding is where an off-by-one page would leave a tail unprotected.
    #[test]
    fn a_multi_page_secret_is_handled_whole() {
        let len = page_size() * 2 + 17;
        let mut buffer = SecretBuffer::new(len);
        buffer.expose_mut().fill(0xAB);
        assert_eq!(buffer.expose().len(), len);
        assert!(buffer.expose().iter().all(|byte| *byte == 0xAB));

        buffer.wipe();

        assert!(buffer.expose().iter().all(|byte| *byte == 0));
    }

    /// Zero length is a caller bug, but it must not be an unsafe one: the
    /// allocation still has to be valid so drop has something real to free.
    #[test]
    fn an_empty_buffer_is_valid_rather_than_null() {
        let buffer = SecretBuffer::new(0);
        assert!(buffer.is_empty());
        assert_eq!(buffer.expose(), b"");
    }

    /// Locking is allowed to fail — quotas are ordinary — but on a developer
    /// machine with a small buffer it should succeed, and if it never succeeds
    /// anywhere then the platform code is wired up wrong and every caller is
    /// quietly getting nothing.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn a_small_buffer_locks_on_a_normal_machine() {
        let buffer = SecretBuffer::new(64);
        assert!(
            buffer.is_locked(),
            "VirtualLock/mlock failed for one page; if this is a quota-limited \
             environment the report is correct, but check the wiring first"
        );
    }

    #[test]
    fn buffers_can_move_between_threads() {
        let buffer = SecretBuffer::from_slice(b"moved");
        let handle = std::thread::spawn(move || buffer.expose().to_vec());
        assert_eq!(handle.join().expect("thread"), b"moved");
    }
}
