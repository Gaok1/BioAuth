//! `phone-auth-initrd` — unlock an encrypted volume from a paired phone.
//!
//! Runs inside the initrd, before the root filesystem exists. It is a separate
//! binary from `phone-auth-agent` on purpose: the agent's IPC listener, tray
//! protocol and audit log are all things that must not exist in an early-boot
//! environment where there is no user session to protect them and no way to
//! update them short of regenerating the initrd.
//!
//! # Contract with the boot scripts
//!
//! On success it writes the unlock key to stdout and exits 0, so it can be
//! piped straight into `cryptsetup open --key-file=-`. Every other outcome
//! exits non-zero and writes nothing to stdout. Diagnostics go to stderr, so
//! a boot log never captures key material.
//!
//! # Recovery is mandatory
//!
//! The volume must always carry a second, offline keyslot. A phone that is
//! lost, flat or broken must never mean an unbootable machine, and this binary
//! deliberately does nothing to make itself the only way in.
//!
//! # Status
//!
//! Credential selection and a minimal authenticated wired transport are
//! complete. What is missing is the dedicated LUKS wrapping exchange.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use phone_auth_session::IdentityKey;
use phone_auth_verifier::pairing::{CredentialPurpose, PairingStore};

mod network;

// The exit codes are the interface the boot script is written against, so all
// four are defined here even though the two success-path codes are unreachable
// until the LUKS wrapping exchange exists.
#[allow(dead_code)]
/// Unlocked; the key is on stdout.
const EXIT_UNLOCKED: u8 = 0;
#[allow(dead_code)]
/// Refused, declined or expired.
const EXIT_DENIED: u8 = 1;
const EXIT_USAGE: u8 = 2;
/// Could not even ask. The boot script should fall back to the passphrase
/// prompt on this, exactly as it should on a denial.
const EXIT_UNAVAILABLE: u8 = 3;

const USAGE: &str = "\
phone-auth-initrd — unlock a volume with a paired phone

USAGE:
    phone-auth-initrd --volume <NAME> [OPTIONS]

OPTIONS:
    --volume <NAME>      Volume being unlocked, e.g. nvme0n1p2
    --store <PATH>       Pairing store baked into the initrd
                         [default: /etc/phone-auth/devices.json]
    --identity <PATH>    Runtime-provided desktop handshake key
                         [default: /etc/phone-auth/identity.pkcs8]
    --verifier-id <ID>   Desktop id stored by the paired phone
    --credential <ID>    Which disk-unlock credential to use
    --port <PORT>        Fixed wired TCP port [default: 8765]
    --timeout <SECONDS>  How long to wait for the phone [default: 60]
    -h, --help           Show this message

EXIT CODES:
    0  unlocked; the key is on stdout
    1  denied, declined or expired
    2  usage error
    3  could not ask; fall back to the recovery passphrase
";

struct Args {
    volume: Option<String>,
    store: PathBuf,
    identity: PathBuf,
    verifier_id: Option<String>,
    credential: Option<String>,
    port: u16,
    timeout_secs: u64,
    help: bool,
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        volume: None,
        store: PathBuf::from("/etc/phone-auth/devices.json"),
        identity: PathBuf::from("/etc/phone-auth/identity.pkcs8"),
        verifier_id: None,
        credential: None,
        port: 8765,
        timeout_secs: 60,
        help: false,
    };
    let mut raw = std::env::args().skip(1);

    while let Some(flag) = raw.next() {
        let mut value = || raw.next().ok_or(format!("`{flag}` needs a value"));
        match flag.as_str() {
            "--volume" => args.volume = Some(value()?),
            "--store" => args.store = PathBuf::from(value()?),
            "--identity" => args.identity = PathBuf::from(value()?),
            "--verifier-id" => args.verifier_id = Some(value()?),
            "--credential" => args.credential = Some(value()?),
            "--port" => {
                args.port = value()?
                    .parse()
                    .map_err(|_| "--port must be an integer from 1 to 65535".to_owned())?;
                if args.port == 0 {
                    return Err("--port must be an integer from 1 to 65535".to_owned());
                }
            }
            "--timeout" => {
                args.timeout_secs = value()?
                    .parse()
                    .map_err(|_| "--timeout must be from 1 to 300 seconds".to_owned())?;
                if !(1..=300).contains(&args.timeout_secs) {
                    return Err("--timeout must be from 1 to 300 seconds".to_owned());
                }
            }
            "-h" | "--help" => args.help = true,
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("phone-auth-initrd: {error}\n\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if args.help {
        eprintln!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    ExitCode::from(run(args))
}

fn run(args: Args) -> u8 {
    let Some(_volume) = args.volume else {
        eprintln!("phone-auth-initrd: --volume is required\n\n{USAGE}");
        return EXIT_USAGE;
    };
    let Some(verifier_id) = args.verifier_id else {
        eprintln!("phone-auth-initrd: --verifier-id is required\n\n{USAGE}");
        return EXIT_USAGE;
    };
    if verifier_id.is_empty() || verifier_id.len() > 64 {
        eprintln!("phone-auth-initrd: --verifier-id must contain 1 to 64 bytes");
        return EXIT_USAGE;
    }

    let store = match PairingStore::load(&args.store) {
        Ok(store) => store,
        Err(error) => {
            eprintln!(
                "phone-auth-initrd: cannot read {}: {error}",
                args.store.display()
            );
            return EXIT_UNAVAILABLE;
        }
    };

    // Pick the credential enrolled for disk unlock. Key separation is the
    // point: the credential used for sudo must not be able to unwrap a volume.
    let credential = match select_credential(&store, args.credential.as_deref()) {
        Ok(credential) => credential,
        Err(message) => {
            eprintln!("phone-auth-initrd: {message}");
            return EXIT_UNAVAILABLE;
        }
    };

    let identity = match fs::read(&args.identity)
        .map_err(|error| error.to_string())
        .and_then(|bytes| IdentityKey::from_pkcs8_der(&bytes).map_err(|error| error.to_string()))
    {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!(
                "phone-auth-initrd: cannot load handshake identity {}: {error}",
                args.identity.display()
            );
            return EXIT_UNAVAILABLE;
        }
    };
    let listener = match network::WiredListener::bind(args.port) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "phone-auth-initrd: cannot bind wired port {}: {error}",
                args.port
            );
            return EXIT_UNAVAILABLE;
        }
    };
    let _session = match listener.accept(
        &identity,
        &verifier_id,
        &credential.phone_device_id,
        &credential.phone_identity_spki,
        Duration::from_secs(args.timeout_secs),
    ) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("phone-auth-initrd: paired phone unavailable: {error}");
            return EXIT_UNAVAILABLE;
        }
    };

    eprintln!(
        "phone-auth-initrd: authenticated wired session established, but LUKS key wrapping is not implemented yet.\n\
         \n\
         blocked on:\n\
         \x20 - a dedicated LUKS wrapping credential, separate from the\n\
         \x20   authorization credential\n\
         \n\
         Falling back to the recovery keyslot. This is the expected path today."
    );
    let _ = std::io::stdout().flush();
    EXIT_UNAVAILABLE
}

/// A disk-unlock credential resolved from the pairing store.
#[derive(Debug)]
struct BootCredential {
    _credential_id: String,
    phone_device_id: String,
    phone_identity_spki: Vec<u8>,
}

/// Finds the credential enrolled for disk unlock.
///
/// Refuses to guess when several exist: at boot there is nobody to ask, and
/// picking one by iteration order would make which phone can unlock the
/// machine an accident of file layout.
fn select_credential(
    store: &PairingStore,
    requested: Option<&str>,
) -> Result<BootCredential, String> {
    let mut candidates = Vec::new();

    for device in store.devices() {
        for credential in &device.credentials {
            if credential.purpose != CredentialPurpose::DiskUnlock {
                continue;
            }
            // A software key is not acceptable here. At boot there is no way to
            // notice a compromise and no session to revoke.
            if !credential.key_kind.allowed_at_boot() {
                continue;
            }
            if device.session_identity_public_key.is_empty() {
                continue;
            }
            if let Some(requested) = requested {
                if credential.credential_id != requested {
                    continue;
                }
            }
            candidates.push(BootCredential {
                _credential_id: credential.credential_id.clone(),
                phone_device_id: device.device_id.clone(),
                phone_identity_spki: device.session_identity_public_key.clone(),
            });
        }
    }

    match candidates.len() {
        0 => Err(
            "no hardware-backed disk-unlock credential is enrolled; use the recovery passphrase"
                .to_owned(),
        ),
        1 => Ok(candidates.remove(0)),
        count => Err(format!(
            "{count} disk-unlock credentials are enrolled; pass --credential to choose"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phone_auth_verifier::pairing::{KeyKind, PairedCredential, PairedDevice};
    use phone_auth_verifier::policy::Permission;

    fn device(
        id: &str,
        credential_id: &str,
        purpose: CredentialPurpose,
        kind: KeyKind,
    ) -> PairedDevice {
        PairedDevice {
            device_id: id.into(),
            display_name: format!("Phone {id}"),
            paired_at_ms: 0,
            session_identity_public_key: vec![2; 91],
            credentials: vec![PairedCredential {
                credential_id: credential_id.into(),
                algorithm: phone_auth_protocol::PUBLIC_KEY_EC_P256_SPKI.into(),
                public_key: vec![1; 91],
                key_kind: kind,
                purpose,
                permissions: vec![Permission::service("luks")],
            }],
        }
    }

    #[test]
    fn an_empty_store_sends_the_user_to_recovery() {
        let store = PairingStore::in_memory();
        let error = select_credential(&store, None).expect_err("must refuse");
        assert!(error.contains("recovery passphrase"), "{error}");
    }

    #[test]
    fn an_authorization_credential_is_not_a_boot_credential() {
        let mut store = PairingStore::in_memory();
        store
            .insert(device(
                "phone-1",
                "sudo-v1",
                CredentialPurpose::Authorization,
                KeyKind::StrongBox,
            ))
            .expect("insert");

        assert!(
            select_credential(&store, None).is_err(),
            "the sudo credential must not be able to unwrap a volume"
        );
    }

    #[test]
    fn a_software_key_is_never_a_boot_credential() {
        let mut store = PairingStore::in_memory();
        store
            .insert(device(
                "phone-1",
                "luks-v1",
                CredentialPurpose::DiskUnlock,
                KeyKind::Software,
            ))
            .expect("insert");

        assert!(select_credential(&store, None).is_err());
    }

    #[test]
    fn a_hardware_disk_unlock_credential_is_selected() {
        let mut store = PairingStore::in_memory();
        store
            .insert(device(
                "phone-1",
                "luks-v1",
                CredentialPurpose::DiskUnlock,
                KeyKind::StrongBox,
            ))
            .expect("insert");

        let credential = select_credential(&store, None).expect("selected");
        assert_eq!(credential._credential_id, "luks-v1");
    }

    #[test]
    fn several_boot_credentials_require_an_explicit_choice() {
        let mut store = PairingStore::in_memory();
        store
            .insert(device(
                "phone-1",
                "luks-v1",
                CredentialPurpose::DiskUnlock,
                KeyKind::StrongBox,
            ))
            .expect("insert");
        store
            .insert(device(
                "phone-2",
                "luks-v2",
                CredentialPurpose::DiskUnlock,
                KeyKind::Hardware,
            ))
            .expect("insert");

        let error = select_credential(&store, None).expect_err("ambiguous");
        assert!(error.contains("--credential"), "{error}");

        let chosen = select_credential(&store, Some("luks-v2")).expect("explicit choice");
        assert_eq!(chosen._credential_id, "luks-v2");
    }
}
