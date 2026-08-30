//! Locking, unlocking, re-keying and looking at a container.
//!
//! Two rules shape all of it. Nothing is ever written over: every operation
//! builds a complete replacement in a temporary file beside its destination,
//! flushes it, renames it, verifies it, and only then removes what it replaced.
//! And no plaintext is published before every tag over it has been checked, so
//! a container that was tampered with fails while the output is still a
//! temporary file nobody has been handed.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::format::{
    binding_of, decode_wrappers, encode_wrappers, magic, CoreHeader, Metadata, Wrapper,
    WrapperKind, LOCKER_EXTENSION, MAGIC_PREFIX, MAX_CORE_BYTES, MAX_METADATA_BYTES, MAX_WRAPPERS,
    MAX_WRAPPER_BYTES, TAG_LEN,
};
use crate::recovery::{self, RecoveryKey};
use crate::secret::Dek;
use crate::stream::ContainerCipher;
use crate::{LockerError, Result};

/// What the phone is asked to look at before it wraps a key.
///
/// The name and the size are shown to the user, and the binding is what the
/// phone's own tag covers, so an approval for one container cannot be replayed
/// into another.
pub struct WrapRequest<'a> {
    pub binding: [u8; 32],
    pub dek: &'a Dek,
    pub file_name: String,
    pub plaintext_len: u64,
}

/// What the phone is asked to unwrap.
pub struct UnwrapRequest<'a> {
    pub binding: [u8; 32],
    pub wrapper: &'a Wrapper,
    pub container_name: String,
    pub plaintext_len: u64,
}

/// The phone's half of a locker operation.
///
/// The engine never talks to a transport. Everything that involves asking a
/// human to approve something lives behind this trait, which is also how the
/// tests exercise the format without a phone in the room.
pub trait KeyCustodian {
    fn wrap(&mut self, request: &WrapRequest<'_>) -> Result<Wrapper>;
    fn unwrap(&mut self, request: &UnwrapRequest<'_>) -> Result<Dek>;
}

/// Which key opens a container.
///
/// The recovery arm deliberately borrows nothing but a key: it must work with
/// no agent running and no phone reachable.
pub enum UnlockKey<'a> {
    Phone(&'a mut dyn KeyCustodian),
    Recovery(&'a RecoveryKey),
}

/// How a lock should behave, beyond producing a container.
pub struct LockPlan {
    /// Where to write. Defaults to the source with `.balock` appended.
    pub destination: Option<PathBuf>,
    /// Delete the plaintext once the container is written and verified.
    pub remove_original: bool,
}

impl Default for LockPlan {
    fn default() -> Self {
        Self {
            destination: None,
            // Leaving the plaintext next to the container would make the whole
            // operation decorative, so removing it is the default and keeping
            // it is the explicit choice.
            remove_original: true,
        }
    }
}

pub struct LockOutcome {
    pub container: PathBuf,
    /// Shown once and never stored. Losing it and the phone loses the file.
    pub recovery_code: String,
    pub plaintext_len: u64,
    pub original_removed: bool,
}

pub struct UnlockOutcome {
    pub restored: PathBuf,
    pub plaintext_len: u64,
    pub container_removed: bool,
}

/// What can be learned about a container without any key at all.
pub struct LockerInfo {
    pub container_version: u8,
    pub plaintext_len: u64,
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub wrappers: Vec<WrapperInfo>,
}

pub struct WrapperInfo {
    pub kind: WrapperKind,
    pub id: String,
}

/// Encrypts `source` into a new container.
pub fn lock_file(
    source: &Path,
    plan: &LockPlan,
    custodian: &mut dyn KeyCustodian,
) -> Result<LockOutcome> {
    let file_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(LockerError::UnsafeName)?
        .to_owned();
    // Checked against the name the caller gave, not against whatever it points
    // at, and checked as strictly as the plan is destructive.
    let metadata = sole_regular_file(source, plan.remove_original)?;
    let plaintext_len = metadata.len();

    let destination = plan.destination.clone().unwrap_or_else(|| {
        let mut path = source.as_os_str().to_owned();
        path.push(format!(".{LOCKER_EXTENSION}"));
        PathBuf::from(path)
    });

    let header = CoreHeader::fresh(plaintext_len);
    header.validate()?;
    let core = header.encode();
    let binding = binding_of(&core);
    let dek = Dek::random();

    let phone = custodian.wrap(&WrapRequest {
        binding,
        dek: &dek,
        file_name: file_name.clone(),
        plaintext_len,
    })?;
    if phone.kind != WrapperKind::Phone {
        return Err(LockerError::Malformed("phone returned a foreign wrapper"));
    }
    let (recovery_wrapper, recovery_key) = recovery::wrap(&dek, &binding);
    let wrappers = vec![phone, recovery_wrapper];

    let cipher = ContainerCipher::new(&dek, &header, binding);
    let metadata_block = cipher.seal_metadata(
        &Metadata {
            original_name: file_name,
            mode: mode_of(&metadata),
            modified_at_ms: modified_at_ms(&metadata),
            original_len: plaintext_len,
        }
        .encode()?,
    );

    let mut target = AtomicFile::create(&destination)?;
    {
        let mut writer = BufWriter::new(target.file());
        writer.write_all(&magic())?;
        write_section(&mut writer, &core)?;
        write_section(&mut writer, &encode_wrappers(&wrappers)?)?;
        write_section(&mut writer, &metadata_block)?;

        let mut reader = BufReader::new(File::open(source)?);
        encrypt_chunks(&mut reader, &mut writer, &header, &cipher)?;
        writer.flush()?;
    }
    target.commit()?;

    // Read the finished container back and check every tag before the only
    // other copy of the file is deleted. A container that does not open is a
    // bug or a bad disk, and either way the plaintext must survive it.
    verify(&destination, &dek)?;

    let original_removed = plan.remove_original && {
        std::fs::remove_file(source)?;
        true
    };

    Ok(LockOutcome {
        container: destination,
        recovery_code: recovery::format_recovery_code(&recovery_key),
        plaintext_len,
        original_removed,
    })
}

/// Decrypts a container back into the file it was made from.
pub fn unlock_file(
    container: &Path,
    destination_dir: Option<&Path>,
    remove_container: bool,
    key: UnlockKey<'_>,
) -> Result<UnlockOutcome> {
    // Reading through a link harms nothing, but deleting one does: it would
    // remove the name and leave the container itself where it was.
    sole_regular_file(container, remove_container)?;
    let mut reader = BufReader::new(File::open(container)?);
    let head = ContainerHead::read(&mut reader)?;
    let container_name = container
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();

    let dek = match key {
        UnlockKey::Phone(custodian) => {
            let wrapper = head.wrapper(WrapperKind::Phone)?;
            custodian.unwrap(&UnwrapRequest {
                binding: head.binding,
                wrapper,
                container_name,
                plaintext_len: head.header.plaintext_len,
            })?
        }
        UnlockKey::Recovery(recovery_key) => recovery::unwrap(
            head.wrapper(WrapperKind::Recovery)?,
            recovery_key,
            &head.binding,
        )?,
    };

    let cipher = ContainerCipher::new(&dek, &head.header, head.binding);
    let metadata = Metadata::decode(&cipher.open_metadata(&head.metadata)?)?;
    if metadata.original_len != head.header.plaintext_len {
        return Err(LockerError::Malformed("metadata contradicts the header"));
    }

    let directory = destination_dir
        .map(Path::to_path_buf)
        .or_else(|| container.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let restored = directory.join(metadata.safe_file_name()?);

    let mut target = AtomicFile::create(&restored)?;
    {
        let mut writer = BufWriter::new(target.file());
        decrypt_chunks(&mut reader, &mut writer, &head.header, &cipher)?;
        writer.flush()?;
    }
    target.commit()?;
    restore_attributes(&restored, &metadata);

    let container_removed = remove_container && {
        std::fs::remove_file(container)?;
        true
    };

    Ok(UnlockOutcome {
        restored,
        plaintext_len: head.header.plaintext_len,
        container_removed,
    })
}

/// Replaces a container's wrappers without re-encrypting its contents.
///
/// The ciphertext is copied verbatim into a new container, so a rekey costs one
/// pass over the file and cannot leave the old and new wrappers half-applied.
pub fn rekey_file(
    container: &Path,
    custodian: &mut dyn KeyCustodian,
    current_recovery: Option<&RecoveryKey>,
    new_recovery: bool,
) -> Result<Option<String>> {
    // A rekey exists to stop the old wrapper from opening the file, and it
    // works by renaming the container away. Through a link, or with a second
    // link on the container, the old wrappers would survive under the other
    // name and the revocation would be imaginary.
    sole_regular_file(container, true)?;
    let mut reader = BufReader::new(File::open(container)?);
    let head = ContainerHead::read(&mut reader)?;
    let container_name = container
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();

    // One custodian does both halves of a rekey, so the current key comes from
    // the recovery code when there is one and from the phone otherwise. That
    // is also the case that matters: a phone being replaced cannot open the
    // wrapper it is replacing.
    let dek = match current_recovery {
        Some(recovery_key) => recovery::unwrap(
            head.wrapper(WrapperKind::Recovery)?,
            recovery_key,
            &head.binding,
        )?,
        None => {
            let wrapper = head.wrapper(WrapperKind::Phone)?;
            custodian.unwrap(&UnwrapRequest {
                binding: head.binding,
                wrapper,
                container_name: container_name.clone(),
                plaintext_len: head.header.plaintext_len,
            })?
        }
    };

    let phone = custodian.wrap(&WrapRequest {
        binding: head.binding,
        dek: &dek,
        file_name: container_name,
        plaintext_len: head.header.plaintext_len,
    })?;
    if phone.kind != WrapperKind::Phone {
        return Err(LockerError::Malformed("phone returned a foreign wrapper"));
    }

    let mut wrappers = vec![phone];
    let code = if new_recovery {
        let (wrapper, key) = recovery::wrap(&dek, &head.binding);
        wrappers.push(wrapper);
        Some(recovery::format_recovery_code(&key))
    } else {
        // Keeping the existing recovery wrapper means a rekey does not
        // invalidate a code the user already wrote down.
        wrappers.extend(
            head.wrappers
                .iter()
                .filter(|wrapper| wrapper.kind == WrapperKind::Recovery)
                .cloned(),
        );
        None
    };
    if wrappers.len() > MAX_WRAPPERS {
        return Err(LockerError::Malformed("wrapper count"));
    }

    let replacement = suffixed(container, "rekey-new")?;
    let superseded = suffixed(container, "rekey-old")?;
    let mut target = AtomicFile::create(&replacement)?;
    {
        let mut writer = BufWriter::new(target.file());
        writer.write_all(&magic())?;
        write_section(&mut writer, &head.core)?;
        write_section(&mut writer, &encode_wrappers(&wrappers)?)?;
        write_section(&mut writer, &head.metadata)?;
        // The chunks are unchanged: a rekey replaces wrappers, not content, so
        // the ciphertext is copied through exactly as it was authenticated.
        std::io::copy(&mut reader, &mut writer)?;
        writer.flush()?;
    }
    target.commit()?;
    drop(reader);

    verify(&replacement, &dek)?;
    // Two renames rather than a delete and a rename: at every instant at least
    // one complete container exists, and both names say what they are if a
    // crash lands between them.
    std::fs::rename(container, &superseded)?;
    std::fs::rename(&replacement, container)?;
    let _ = std::fs::remove_file(&superseded);
    Ok(code)
}

/// Reads what a container will admit to without a key.
pub fn inspect(container: &Path) -> Result<LockerInfo> {
    let mut reader = BufReader::new(File::open(container)?);
    let head = ContainerHead::read(&mut reader)?;
    Ok(LockerInfo {
        container_version: head.header.container_version,
        plaintext_len: head.header.plaintext_len,
        chunk_size: head.header.chunk_size,
        chunk_count: head.header.chunk_count(),
        wrappers: head
            .wrappers
            .iter()
            .map(|wrapper| WrapperInfo {
                kind: wrapper.kind,
                id: wrapper.id.clone(),
            })
            .collect(),
    })
}

/// Decrypts a container into nothing, purely to check it.
fn verify(container: &Path, dek: &Dek) -> Result<()> {
    let mut reader = BufReader::new(File::open(container)?);
    let head = ContainerHead::read(&mut reader)?;
    let cipher = ContainerCipher::new(dek, &head.header, head.binding);
    Metadata::decode(&cipher.open_metadata(&head.metadata)?)?;
    decrypt_chunks(&mut reader, &mut std::io::sink(), &head.header, &cipher)
}

/// The parsed front of a container.
struct ContainerHead {
    core: Vec<u8>,
    header: CoreHeader,
    binding: [u8; 32],
    wrappers: Vec<Wrapper>,
    metadata: Vec<u8>,
}

impl ContainerHead {
    fn read(reader: &mut impl Read) -> Result<Self> {
        let mut magic_bytes = [0u8; 8];
        reader
            .read_exact(&mut magic_bytes)
            .map_err(|_| LockerError::NotAContainer)?;
        if &magic_bytes[..MAGIC_PREFIX.len()] != MAGIC_PREFIX {
            return Err(LockerError::NotAContainer);
        }
        if magic_bytes[7] != crate::format::CONTAINER_VERSION {
            return Err(LockerError::UnsupportedVersion(magic_bytes[7]));
        }

        let core = read_section(reader, "header", MAX_CORE_BYTES)?;
        let header = CoreHeader::decode(&core)?;
        let binding = binding_of(&core);
        let wrappers = decode_wrappers(&read_section(reader, "wrappers", MAX_WRAPPER_BYTES)?)?;
        let metadata = read_section(reader, "metadata", MAX_METADATA_BYTES)?;
        if metadata.len() <= TAG_LEN {
            return Err(LockerError::Malformed("metadata"));
        }
        Ok(Self {
            core,
            header,
            binding,
            wrappers,
            metadata,
        })
    }

    fn wrapper(&self, kind: WrapperKind) -> Result<&Wrapper> {
        self.wrappers
            .iter()
            .find(|wrapper| wrapper.kind == kind)
            .ok_or(LockerError::NoWrapper(kind))
    }
}

fn write_section(writer: &mut impl Write, section: &[u8]) -> Result<()> {
    let length = u32::try_from(section.len()).map_err(|_| LockerError::TooLarge {
        section: "section",
        limit: u32::MAX as usize,
    })?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(section)?;
    Ok(())
}

fn read_section(reader: &mut impl Read, name: &'static str, limit: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| LockerError::Malformed("truncated container"))?;
    let length = u32::from_be_bytes(length) as usize;
    // Checked before allocating, so a header claiming four gigabytes costs
    // nothing but an error.
    if length > limit {
        return Err(LockerError::TooLarge {
            section: name,
            limit,
        });
    }
    let mut section = vec![0u8; length];
    reader
        .read_exact(&mut section)
        .map_err(|_| LockerError::Malformed("truncated container"))?;
    Ok(section)
}

fn encrypt_chunks(
    reader: &mut impl Read,
    writer: &mut impl Write,
    header: &CoreHeader,
    cipher: &ContainerCipher,
) -> Result<()> {
    let chunk_size = header.chunk_size as usize;
    let chunks = header.chunk_count();
    let mut buffer = Vec::with_capacity(chunk_size + TAG_LEN);
    let mut remaining = header.plaintext_len;

    for index in 0..chunks {
        let take = remaining.min(chunk_size as u64) as usize;
        buffer.clear();
        buffer.resize(take, 0);
        reader
            .read_exact(&mut buffer)
            .map_err(|_| LockerError::InputChanged)?;
        remaining -= take as u64;
        cipher.seal_chunk(index, index + 1 == chunks, &mut buffer);
        writer.write_all(&buffer)?;
    }

    // The length in the header is authenticated by every chunk, so a source
    // that grew while it was being read has to fail rather than silently
    // produce a container of the file as it used to be.
    let mut extra = [0u8; 1];
    match reader.read(&mut extra) {
        Ok(0) => Ok(()),
        Ok(_) => Err(LockerError::InputChanged),
        Err(error) => Err(LockerError::Io(error)),
    }
}

fn decrypt_chunks(
    reader: &mut impl Read,
    writer: &mut impl Write,
    header: &CoreHeader,
    cipher: &ContainerCipher,
) -> Result<()> {
    let chunk_size = header.chunk_size as usize;
    let chunks = header.chunk_count();
    let mut buffer = Vec::with_capacity(chunk_size + TAG_LEN);
    let mut remaining = header.plaintext_len;

    for index in 0..chunks {
        let take = remaining.min(chunk_size as u64) as usize;
        buffer.clear();
        buffer.resize(take + TAG_LEN, 0);
        reader.read_exact(&mut buffer).map_err(|error| {
            // A short read here is a truncated container, not a disk problem
            // worth a different message.
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                LockerError::Corrupt
            } else {
                LockerError::Io(error)
            }
        })?;
        remaining -= take as u64;
        cipher.open_chunk(index, index + 1 == chunks, &mut buffer)?;
        writer.write_all(&buffer)?;
    }

    let mut extra = [0u8; 1];
    match reader.read(&mut extra) {
        Ok(0) => Ok(()),
        // Bytes after the last chunk are not part of anything authenticated,
        // so they are refused rather than ignored.
        Ok(_) => Err(LockerError::Corrupt),
        Err(error) => Err(LockerError::Io(error)),
    }
}

/// The same check `lock_file` makes, for a caller that removes the original
/// itself.
///
/// The agent cannot let the engine delete the plaintext — it has to store the
/// recovery code first — so it takes that responsibility and therefore has to
/// take this check with it. Running it up front also means a file that will be
/// refused is refused before the phone is asked for a fingerprint.
pub fn ensure_sole_regular_file(path: &Path, will_be_removed: bool) -> Result<()> {
    sole_regular_file(path, will_be_removed).map(|_| ())
}

/// Checks that a path is a plain file, and optionally that it is the only name
/// for its contents.
///
/// `sole_name` is set by every caller that is about to delete or rename the
/// path away. A symbolic link and a second hard link are the same problem in
/// two shapes: the name being removed is not the only way to reach the bytes,
/// so the operation would report a file as locked, revoked or consumed while
/// leaving it exactly where it was under the other name. Refusing is the only
/// answer that cannot be silently wrong; following the link and deleting the
/// target would be a locker that deletes files nobody named.
fn sole_regular_file(path: &Path, sole_name: bool) -> Result<std::fs::Metadata> {
    // `symlink_metadata` describes the link itself, which is what the checks
    // below need whenever the link is the thing being acted on.
    let mut metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        // Gated on `sole_name` for the same reason the hard-link check below
        // is, and the paragraph above says why: the danger is removing or
        // renaming a name that is not the only way to reach the bytes.
        if sole_name {
            return Err(LockerError::NotARegularFile("a symbolic link"));
        }
        // An operation that only reads takes no name away, so here the link is
        // just another way to spell the path and what matters is what it
        // points at. Describing the target is the whole point of following it:
        // judging the link itself would reject every one of them at the
        // `is_file` check below, which is a refusal wearing a different
        // message rather than a different decision.
        metadata = std::fs::metadata(path)?;
    }
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        return Err(LockerError::NotARegularFile("a directory"));
    }
    if !file_type.is_file() {
        return Err(LockerError::NotARegularFile("not a regular file"));
    }
    if sole_name && hard_links(path, &metadata)? > 1 {
        return Err(LockerError::SharedOriginal);
    }
    Ok(metadata)
}

#[cfg(unix)]
fn hard_links(_path: &Path, metadata: &std::fs::Metadata) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(metadata.nlink())
}

#[cfg(windows)]
fn hard_links(path: &Path, _metadata: &std::fs::Metadata) -> Result<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let file = File::open(path)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a valid handle for the duration of the call and
    // `information` points to writable storage of the exact structure the API
    // expects.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(LockerError::Io(std::io::Error::last_os_error()));
    }
    Ok(information.nNumberOfLinks.into())
}

#[cfg(not(any(unix, windows)))]
fn hard_links(_path: &Path, _metadata: &std::fs::Metadata) -> Result<u64> {
    Ok(1)
}

/// Whether anything at all occupies a path.
///
/// Deliberately not `Path::exists`, which follows links and so answers `false`
/// for a dangling symlink — the one case where a rename would quietly consume
/// something that was already there.
fn occupied(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// A file that appears at its destination complete or not at all.
struct AtomicFile {
    temporary: PathBuf,
    destination: PathBuf,
    file: Option<File>,
    committed: bool,
}

impl AtomicFile {
    fn create(destination: &Path) -> Result<Self> {
        if occupied(destination) {
            return Err(LockerError::DestinationExists(destination.to_path_buf()));
        }
        let temporary = temporary_sibling(destination)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        Ok(Self {
            temporary,
            destination: destination.to_path_buf(),
            file: Some(file),
            committed: false,
        })
    }

    fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("file is open until commit")
    }

    fn commit(mut self) -> Result<()> {
        let file = self.file.take().expect("file is open until commit");
        file.sync_all()?;
        drop(file);
        // Windows will not rename onto an existing file, and on Unix this
        // check is what stops one from being replaced between the check in
        // `create` and here. Either way the loser of that race gets an error,
        // not a lost file.
        if occupied(&self.destination) {
            return Err(LockerError::DestinationExists(self.destination.clone()));
        }
        std::fs::rename(&self.temporary, &self.destination)?;
        self.committed = true;
        sync_directory(&self.destination);
        Ok(())
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if !self.committed {
            // A failed or abandoned operation leaves the destination untouched
            // and takes its scratch file with it.
            self.file.take();
            let _ = std::fs::remove_file(&self.temporary);
        }
    }
}

fn temporary_sibling(destination: &Path) -> Result<PathBuf> {
    let directory = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(LockerError::UnsafeName)?;
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix).expect("operating system CSPRNG is unavailable");
    // Same directory, so the rename that follows stays on one filesystem and
    // is therefore atomic.
    Ok(directory.join(format!(
        ".{name}.{}.balock-tmp",
        phone_auth_protocol::encoding::to_hex(&suffix)
    )))
}

/// Best effort: a renamed file is durable once its directory entry is on disk,
/// and Windows has no equivalent handle to flush.
#[cfg(unix)]
fn sync_directory(destination: &Path) {
    if let Some(parent) = destination.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn sync_directory(_destination: &Path) {}

#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(_metadata: &std::fs::Metadata) -> u32 {
    0
}

fn modified_at_ms(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|since| i64::try_from(since.as_millis()).ok())
        .unwrap_or(0)
}

/// Restores what the platform supports, and quietly skips what it does not.
///
/// A restored file that is readable with the wrong timestamp is better than a
/// failed unlock, so none of this is fatal.
fn restore_attributes(path: &Path, metadata: &Metadata) {
    if metadata.modified_at_ms > 0 {
        if let Ok(file) = OpenOptions::new().write(true).open(path) {
            let when = std::time::UNIX_EPOCH
                + std::time::Duration::from_millis(metadata.modified_at_ms as u64);
            let _ = file.set_modified(when);
        }
    }
    #[cfg(unix)]
    if metadata.mode != 0 {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(metadata.mode));
    }
}

/// `path` with one more extension on the end.
fn suffixed(path: &Path, suffix: &str) -> Result<PathBuf> {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{suffix}"));
    Ok(PathBuf::from(name))
}
