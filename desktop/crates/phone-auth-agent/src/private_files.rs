//! Files only this user may read, on every platform that has an opinion.
//!
//! The agent writes four things worth protecting: its own handshake private
//! key, the pairing store, the audit log and the endpoint file that carries
//! the IPC token. Until this module existed only the last of those was
//! restricted, and only on Unix — which left a private key at whatever the
//! process umask happened to be, and left Windows relying entirely on the
//! default ACL of `%LOCALAPPDATA%`.
//!
//! Two properties, and they are different problems:
//!
//! - **Nobody else reads it.** `0o600` on Unix; an explicit DACL granting the
//!   owning user alone on Windows, with inheritance switched off so a
//!   permissive parent directory cannot widen it back.
//! - **Nobody reads it half-written.** Writes go to a temporary file in the
//!   same directory and are renamed into place, so a reader either sees the
//!   previous contents or the new ones. A client that read a truncated
//!   endpoint file would look for the agent on port zero.
//!
//! Multiple user sessions on one machine are the case all of this is for: two
//! people logged into the same Windows box get one `%LOCALAPPDATA%` each, but
//! a machine-wide temp directory fallback does not, and the fallback is the
//! path that gets exercised when something else has gone wrong.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Writes `contents` so that only this user can read it, atomically.
///
/// The temporary file is created in the destination's own directory, because
/// a rename across filesystems is a copy and stops being atomic. It is
/// restricted before anything is written into it: creating it world-readable
/// and tightening afterwards leaves a window, and the window is the whole
/// attack.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    fs::create_dir_all(parent)?;
    restrict_dir(parent)?;

    let temporary = temporary_beside(path);
    // Fails if it already exists, rather than following a symlink somebody
    // left in place of it. `create_new` is the whole defence here.
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        restrict_handle(&file, &temporary)?;
        write_all(file, contents)?;
        fs::rename(&temporary, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    // The rename inherits the temporary file's permissions, so the destination
    // is already restricted. Doing it again covers a destination that existed
    // with wider permissions on a platform where rename keeps the target's.
    result.and_then(|()| restrict_file(path))
}

fn write_all(mut file: fs::File, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    file.write_all(contents)?;
    // The rename is atomic with respect to readers, not with respect to power
    // loss. Flushing first means a crash leaves the old file, not an empty
    // new one.
    file.sync_all()
}

/// A name beside `path` that no other process is likely to pick.
///
/// Process id and a counter rather than randomness: this only has to avoid a
/// collision with the agent's own concurrent writes and with a second agent,
/// and `create_new` turns any remaining collision into an error rather than
/// into a shared file.
fn temporary_beside(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("f");
    path.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(unix)]
pub fn restrict_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(unix)]
pub fn restrict_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(unix)]
fn restrict_handle(file: &fs::File, _path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
pub fn restrict_file(path: &Path) -> io::Result<()> {
    windows_acl::restrict(path, windows_acl::Inherit::No)
}

/// Restricts a directory *and* everything later written into it.
///
/// The inheritable entry is what makes this worth calling once rather than at
/// every write: the pairing store and the audit log are written by other
/// crates through plain `fs::write`, and a directory whose ACL children
/// inherit covers them without every writer having to know.
#[cfg(windows)]
pub fn restrict_dir(path: &Path) -> io::Result<()> {
    windows_acl::restrict(path, windows_acl::Inherit::Children)
}

#[cfg(windows)]
fn restrict_handle(_file: &fs::File, path: &Path) -> io::Result<()> {
    windows_acl::restrict(path, windows_acl::Inherit::No)
}

#[cfg(not(any(unix, windows)))]
pub fn restrict_file(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn restrict_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn restrict_handle(_file: &fs::File, _path: &Path) -> io::Result<()> {
    Ok(())
}

/// An explicit owner-only DACL, with inheritance switched off.
///
/// Windows has no mode bits, and the default a file gets is inherited from its
/// directory. `%LOCALAPPDATA%` is per-user and usually fine, but "usually
/// fine, inherited from somewhere else" is not a statement anybody can check
/// — and the temp-directory fallback in `paths.rs` is not per-user at all.
///
/// Setting `PROTECTED_DACL_SECURITY_INFORMATION` is what makes this stick: it
/// stops inherited entries from being merged back in, so a permissive parent
/// cannot widen a file that was deliberately narrowed.
#[cfg(windows)]
mod windows_acl {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        SetNamedSecurityInfoW, SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    };
    use windows_sys::Win32::Security::Authorization::{EXPLICIT_ACCESS_W, TRUSTEE_W};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
        NO_INHERITANCE, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::Security::{ACL, PSID};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Whether children created later inherit this entry.
    pub enum Inherit {
        No,
        Children,
    }

    pub fn restrict(path: &Path, inherit: Inherit) -> io::Result<()> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);

        let sid_buffer = current_user_sid()?;
        // The SID lives inside this buffer, so the buffer has to outlive every
        // use of the pointer below.
        let sid = unsafe { (*(sid_buffer.as_ptr() as *const TOKEN_USER)).User.Sid };

        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS | FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            grfAccessMode: SET_ACCESS,
            grfInheritance: match inherit {
                Inherit::No => NO_INHERITANCE,
                Inherit::Children => CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            },
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: sid as *mut u16,
            },
        };

        let mut acl: *mut ACL = std::ptr::null_mut();
        let status = unsafe {
            windows_sys::Win32::Security::Authorization::SetEntriesInAclW(
                1,
                &access,
                std::ptr::null_mut(),
                &mut acl,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        unsafe { LocalFree(acl as *mut _) };

        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    /// The SID of the user this process runs as, in a buffer the caller keeps.
    fn current_user_sid() -> io::Result<Vec<u8>> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut needed = 0u32;
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        let mut buffer = vec![0u8; needed as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr() as *mut _,
                needed,
                &mut needed,
            )
        };
        unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let _ = PSID::default;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sandbox(name: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "phoneauth-private-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("sandbox");
        path
    }

    #[test]
    fn a_private_write_lands_and_reads_back() {
        let dir = sandbox("round-trip");
        let path = dir.join("secret.bin");

        write_private(&path, b"token").expect("write");

        assert_eq!(fs::read(&path).expect("read"), b"token");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The endpoint file is rewritten on every agent start. A second write
    /// must replace the first rather than fail on the destination existing.
    #[test]
    fn a_second_write_replaces_the_first() {
        let dir = sandbox("replace");
        let path = dir.join("endpoint.json");

        write_private(&path, b"first").expect("first");
        write_private(&path, b"second").expect("second");

        assert_eq!(fs::read(&path).expect("read"), b"second");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A reader sees the old contents or the new ones, never a prefix. What
    /// this can check without racing is the consequence: nothing is left
    /// behind for a reader to find.
    #[test]
    fn no_temporary_file_survives() {
        let dir = sandbox("no-litter");
        let path = dir.join("endpoint.json");

        write_private(&path, b"contents").expect("write");

        let entries: Vec<_> = fs::read_dir(&dir)
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(entries.len(), 1, "left something behind: {entries:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The parent directory is created and narrowed on the way, so the first
    /// write on a fresh machine does not depend on anything else having run.
    #[test]
    fn a_missing_directory_is_created_and_restricted() {
        let dir = sandbox("nested");
        let path = dir.join("deeper").join("secret.bin");

        write_private(&path, b"x").expect("write");

        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn nobody_else_can_read_it() {
        use std::os::unix::fs::PermissionsExt;

        let dir = sandbox("modes");
        let path = dir.join("identity.pkcs8");
        write_private(&path, b"key").expect("write");

        let file = fs::metadata(&path).expect("stat").permissions().mode();
        let parent = fs::metadata(&dir).expect("stat").permissions().mode();

        assert_eq!(file & 0o077, 0, "group or other can reach the file");
        assert_eq!(parent & 0o077, 0, "group or other can enter the directory");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Symlinks are the reason the temporary file is opened with `create_new`.
    /// A pre-existing temporary that is a link elsewhere must make the write
    /// fail rather than follow it.
    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_not_followed() {
        let dir = sandbox("symlink");
        let elsewhere = dir.join("elsewhere");
        fs::write(&elsewhere, b"do not overwrite me").expect("write");

        // The name `write_private` will pick for its temporary is derived from
        // the pid and a counter, so this cannot target it directly. What it can
        // prove is that the destination itself being a link does not cause a
        // write through it.
        let link = dir.join("linked.json");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");
        write_private(&link, b"new contents").expect("write");

        assert_eq!(
            fs::read(&elsewhere).expect("read"),
            b"do not overwrite me",
            "the write followed a symlink out of its directory"
        );
        assert_eq!(fs::read(&link).expect("read"), b"new contents");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn a_restricted_file_is_still_ours_to_read_and_replace() {
        // The DACL grants this user everything and nobody else anything.
        // Asserting the negative half needs a second account, which a unit
        // test does not have; what it can prove is that protecting the file
        // did not lock the agent out of its own state.
        let dir = sandbox("acl");
        let path = dir.join("identity.pkcs8");

        write_private(&path, b"key").expect("write");
        restrict_file(&path).expect("restrict again");
        write_private(&path, b"rotated").expect("rewrite");

        assert_eq!(fs::read(&path).expect("read"), b"rotated");
        let _ = fs::remove_dir_all(&dir);
    }
}
