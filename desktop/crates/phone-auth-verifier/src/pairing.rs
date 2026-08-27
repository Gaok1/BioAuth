//! Paired devices and the public credentials they authorize with.
//!
//! Pairing here is PhoneAuth cryptographic pairing: the verifier retains the
//! phone's public key and the permissions granted to it. It is unrelated to
//! Bluetooth pairing, and a Bluetooth-paired phone gets no authority from that
//! fact alone.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::encoding::{from_base64url, to_base64url};
use crate::policy::Permission;

/// Where a credential's private key lives on the phone.
///
/// This is reported by the phone at pairing time and is not something the
/// verifier can prove on its own. It is used to *withhold* authority — a
/// software key is never enough for disk unlock — never to grant extra
/// authority beyond what the paired public key already establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyKind {
    /// Dedicated secure element (Android StrongBox, iOS Secure Enclave).
    StrongBox,
    /// TEE-backed keystore without a discrete secure element.
    Hardware,
    /// Not hardware-backed. Development fixtures only.
    Software,
}

impl KeyKind {
    /// Whether this key may be used for boot-time and disk-unlock flows,
    /// where a stolen key cannot be remediated by revoking a pairing on a
    /// machine that will not boot.
    pub fn allowed_at_boot(self) -> bool {
        matches!(self, Self::StrongBox | Self::Hardware)
    }
}

/// What a credential is allowed to be used for.
///
/// The architecture requires key separation by purpose: the MVP authorization
/// credential must not later be reused to wrap a LUKS volume. Recording the
/// purpose on the pairing record is what lets the verifier enforce that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialPurpose {
    /// Interactive authorization: login, sudo, unlocking an app.
    Authorization,
    /// Boot-time volume unwrapping. Requires a hardware-backed key.
    DiskUnlock,
    /// WebAuthn assertions. Uses per-RP keys held only by the phone.
    WebAuthn,
}

/// One public credential belonging to a paired device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedCredential {
    /// Matches `credentialId` on the wire.
    pub credential_id: String,
    /// Public key encoding identifier, e.g. `EC_P256_SPKI`.
    pub algorithm: String,
    /// The public key itself, stored as unpadded base64url of the DER bytes.
    #[serde(with = "base64url_bytes")]
    pub public_key: Vec<u8>,
    pub key_kind: KeyKind,
    pub purpose: CredentialPurpose,
    /// What this credential may authorize. Empty means it may authorize
    /// nothing, which is the state a freshly paired credential starts in.
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

/// A phone this verifier trusts, and the credentials it may present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedDevice {
    pub device_id: String,
    pub display_name: String,
    pub paired_at_ms: i64,
    /// P-256 SPKI used only to authenticate secure-session handshakes.
    #[serde(default, with = "base64url_bytes")]
    pub session_identity_public_key: Vec<u8>,
    pub credentials: Vec<PairedCredential>,
}

impl PairedDevice {
    pub fn credential(&self, credential_id: &str) -> Option<&PairedCredential> {
        self.credentials
            .iter()
            .find(|credential| credential.credential_id == credential_id)
    }
}

/// Serde adapter keeping keys readable in the on-disk JSON.
mod base64url_bytes {
    use super::{from_base64url, to_base64url};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&to_base64url(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        from_base64url(&text).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug)]
pub enum PairingError {
    Io(io::Error),
    Corrupt(serde_json::Error),
    /// A credential id was offered that is already bound to another key.
    CredentialConflict(String),
    UnknownDevice(String),
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "pairing store I/O failed: {error}"),
            Self::Corrupt(error) => write!(f, "pairing store is corrupt: {error}"),
            Self::CredentialConflict(id) => {
                write!(f, "credential `{id}` is already paired to a different key")
            }
            Self::UnknownDevice(id) => write!(f, "unknown device `{id}`"),
        }
    }
}

impl std::error::Error for PairingError {}

impl From<io::Error> for PairingError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    devices: Vec<PairedDevice>,
}

/// The set of paired devices, persisted as JSON.
///
/// The file holds only public keys and permissions. Losing it means every
/// phone must re-pair; leaking it does not disclose anything that can
/// authorize on its own.
#[derive(Debug)]
pub struct PairingStore {
    path: PathBuf,
    devices: BTreeMap<String, PairedDevice>,
}

impl PairingStore {
    /// Loads the store, treating a missing file as an empty store so a first
    /// run needs no setup step.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, PairingError> {
        let path = path.into();
        let devices = match fs::read(&path) {
            Ok(bytes) => {
                let file: StoreFile =
                    serde_json::from_slice(&bytes).map_err(PairingError::Corrupt)?;
                file.devices
                    .into_iter()
                    .map(|device| (device.device_id.clone(), device))
                    .collect()
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self { path, devices })
    }

    /// In-memory store for tests and for the request-only initrd path.
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            devices: BTreeMap::new(),
        }
    }

    pub fn devices(&self) -> impl Iterator<Item = &PairedDevice> {
        self.devices.values()
    }

    pub fn device(&self, device_id: &str) -> Option<&PairedDevice> {
        self.devices.get(device_id)
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Finds the device holding a credential id.
    ///
    /// Credential ids are unique across devices, enforced by [`Self::insert`],
    /// so a request naming a credential identifies exactly one phone.
    pub fn find_credential(
        &self,
        credential_id: &str,
    ) -> Option<(&PairedDevice, &PairedCredential)> {
        self.devices.values().find_map(|device| {
            device
                .credential(credential_id)
                .map(|credential| (device, credential))
        })
    }

    /// Adds or replaces a device.
    ///
    /// Rejects a credential id already bound to a different public key on
    /// another device, so that pairing a second phone cannot silently take
    /// over an existing credential's identity.
    pub fn insert(&mut self, device: PairedDevice) -> Result<(), PairingError> {
        for credential in &device.credentials {
            if let Some((owner, existing)) = self.find_credential(&credential.credential_id) {
                if owner.device_id != device.device_id
                    || existing.public_key != credential.public_key
                {
                    return Err(PairingError::CredentialConflict(
                        credential.credential_id.clone(),
                    ));
                }
            }
        }
        self.devices.insert(device.device_id.clone(), device);
        self.persist()
    }

    pub fn remove(&mut self, device_id: &str) -> Result<PairedDevice, PairingError> {
        let device = self
            .devices
            .remove(device_id)
            .ok_or_else(|| PairingError::UnknownDevice(device_id.to_owned()))?;
        self.persist()?;
        Ok(device)
    }

    /// Writes to a temporary file and renames over the original, so an
    /// interrupted write cannot leave a half-written store that would strand
    /// the user with no paired device.
    fn persist(&self) -> Result<(), PairingError> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = StoreFile {
            version: 1,
            devices: self.devices.values().cloned().collect(),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(PairingError::Corrupt)?;

        let temp = self.path.with_extension("json.tmp");
        fs::write(&temp, &json)?;
        restrict_permissions(&temp)?;
        fs::rename(&temp, &self.path)?;
        Ok(())
    }
}

/// Narrows a file to the current user.
///
/// The store holds no secrets, but a writable pairing store is an authority
/// grant: anyone who can add a device can add their own phone.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// On Windows the containing directory's ACL is what protects the store;
/// per-file mode bits have no equivalent. The agent creates the store under
/// the user's local app data, which is already user-scoped.
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(id: &str, key: u8) -> PairedCredential {
        PairedCredential {
            credential_id: id.into(),
            algorithm: phone_auth_protocol::PUBLIC_KEY_EC_P256_SPKI.into(),
            public_key: vec![key; 91],
            key_kind: KeyKind::StrongBox,
            purpose: CredentialPurpose::Authorization,
            permissions: vec![Permission::service("sudo")],
        }
    }

    fn device(id: &str, credential_id: &str, key: u8) -> PairedDevice {
        PairedDevice {
            device_id: id.into(),
            display_name: format!("Phone {id}"),
            paired_at_ms: 1_787_745_600_000,
            // Distinct from the credential key: these tests exist partly to
            // catch the two being conflated.
            session_identity_public_key: vec![key ^ 0xff; 91],
            credentials: vec![credential(credential_id, key)],
        }
    }

    #[test]
    fn round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("phoneauth-store-{}", std::process::id()));
        let path = dir.join("devices.json");
        let _ = fs::remove_dir_all(&dir);

        let mut store = PairingStore::load(&path).expect("empty store loads");
        assert!(store.is_empty());
        store
            .insert(device("phone-1", "cred-1", 0xab))
            .expect("insert");

        let reloaded = PairingStore::load(&path).expect("reload");
        let (found_device, found_credential) = reloaded
            .find_credential("cred-1")
            .expect("credential present");
        assert_eq!(found_device.device_id, "phone-1");
        assert_eq!(found_credential.public_key, vec![0xab; 91]);
        assert_eq!(found_credential.key_kind, KeyKind::StrongBox);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_a_credential_claimed_by_another_device() {
        let mut store = PairingStore::in_memory();
        store
            .insert(device("phone-1", "cred-1", 0xab))
            .expect("first device");

        let conflict = store.insert(device("phone-2", "cred-1", 0xcd));
        assert!(
            matches!(conflict, Err(PairingError::CredentialConflict(id)) if id == "cred-1"),
            "a second phone must not take over an existing credential id"
        );
    }

    #[test]
    fn allows_re_pairing_the_same_device_with_the_same_key() {
        let mut store = PairingStore::in_memory();
        store
            .insert(device("phone-1", "cred-1", 0xab))
            .expect("first");
        store
            .insert(device("phone-1", "cred-1", 0xab))
            .expect("re-pairing the same device must be idempotent");
    }

    #[test]
    fn software_keys_are_refused_at_boot() {
        assert!(!KeyKind::Software.allowed_at_boot());
        assert!(KeyKind::Hardware.allowed_at_boot());
        assert!(KeyKind::StrongBox.allowed_at_boot());
    }

    #[test]
    fn public_keys_survive_json_as_base64url() {
        let original = device("phone-1", "cred-1", 0xff);
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(json.contains("\"publicKey\""), "field is camelCase on disk");
        let parsed: PairedDevice = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
    }
}
