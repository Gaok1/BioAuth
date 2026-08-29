//! Pairing for a purpose, over a real socket.
//!
//! The purpose travels from the desktop's own decision into the QR, through
//! the handshake, back in the enrolment and into the store — four hops, each
//! in a different crate, and a break anywhere in the chain shows up as a
//! credential that works but is filed under the wrong key. That is the failure
//! this whole mechanism exists to prevent, and the only place it can be
//! watched end to end is here.
//!
//! Uses the simulated phone, which is the only phone available without
//! hardware. It reads the purpose from the bootstrap the way a real phone
//! reads it from the scan.

#![cfg(feature = "dev-simulator")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use phone_auth_agent::config::AgentConfig;
use phone_auth_agent::paths::Paths;
use phone_auth_agent::qr_network::QrNetworkTransport;
use phone_auth_agent::service::Service;
use phone_auth_agent::simulator::{self, SimulatedPhone};
use phone_auth_protocol::CredentialPurpose;
use phone_auth_session::{IdentityKey, ServerBootstrap};

/// A service with a listener on a loopback-reachable port.
fn service(name: &str) -> Service {
    let root = std::env::temp_dir().join(format!(
        "phone-auth-purpose-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let paths = Paths::resolve(Some(root));
    std::fs::create_dir_all(&paths.config_dir).expect("config dir");
    std::fs::create_dir_all(&paths.data_dir).expect("data dir");

    let config = AgentConfig::load_or_create(&paths.config_file()).expect("config");
    let network =
        QrNetworkTransport::bind(IdentityKey::generate(), config.verifier_id.clone(), 0, true)
            .expect("bind");

    Service::new(config, paths, Some(Arc::new(network)), Vec::new(), false).expect("service")
}

/// Runs one pairing to the point where the desktop holds a proposal.
fn pair(service: &mut Service, purpose: CredentialPurpose) -> Result<(), String> {
    let bootstrap = service
        .begin_pairing_for(service_name(purpose))
        .map_err(|error| error.message)?;

    let scanned = ServerBootstrap::from_uri(&bootstrap.qr_payload)
        .map_err(|error| format!("unscannable code: {error}"))?;
    assert_eq!(scanned.purpose, purpose, "the code lost the purpose");

    let phone = SimulatedPhone::new();
    let now = phone_auth_verifier::verifier::now_ms();
    std::thread::spawn(move || {
        let _ = phone.pair(&scanned, now);
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(proposal) = service.pending_pairing() {
            return service
                .confirm_pairing(&proposal.verification_code, Some(&proposal.attempt_id))
                .map_err(|error| error.message);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("the phone never reached the confirmation stage".into())
}

fn service_name(purpose: CredentialPurpose) -> &'static str {
    match purpose {
        CredentialPurpose::Authorization => "authorization",
        CredentialPurpose::DiskUnlock => "luks",
        CredentialPurpose::WebAuthn => "webauthn",
        CredentialPurpose::Vault => "vault",
        CredentialPurpose::FileLocker => "locker",
        CredentialPurpose::Ssh => "ssh",
    }
}

#[test]
fn a_vault_pairing_is_stored_as_a_vault_credential() {
    let mut service = service("vault");

    pair(&mut service, CredentialPurpose::Vault).expect("pairing");

    let devices = service.devices();
    let device = devices.first().expect("a paired device");
    let credential = device.credentials.first().expect("a credential");
    // The summary spells purposes the way the tray shows them.
    assert_eq!(credential.purpose, "Vault");
    // And it authorizes nothing yet: pairing is not permission.
    assert!(credential.permissions.is_empty());
}

/// The point of the whole mechanism. Two pairings with one phone are two
/// credentials, and the second must not evict the first — that eviction was
/// invisible from the phone, which still listed the desktop.
#[test]
fn a_second_purpose_joins_the_same_phone() {
    let mut service = service("two");

    pair(&mut service, CredentialPurpose::Authorization).expect("first pairing");
    pair(&mut service, CredentialPurpose::Ssh).expect("second pairing");

    let devices = service.devices();
    assert_eq!(devices.len(), 1, "one phone, one device row");

    let mut purposes: Vec<&str> = devices[0]
        .credentials
        .iter()
        .map(|credential| credential.purpose.as_str())
        .collect();
    purposes.sort_unstable();
    assert_eq!(purposes, ["Authorization", "Ssh"]);
}

/// The desktop asked for one thing and the phone answered with another. This
/// is the check that keeps someone who ran `pair --service ssh` from ending up
/// holding an authorization key, with nothing in the list to show it.
#[test]
fn an_enrolment_for_the_wrong_purpose_never_becomes_a_pairing() {
    let mut service = service("mismatch");

    let bootstrap = service.begin_pairing_for("ssh").expect("code");
    let scanned = ServerBootstrap::from_uri(&bootstrap.qr_payload).expect("scan");

    // A phone that ignores the purpose in the code: what an older build did,
    // and what a hostile one would do.
    let phone = SimulatedPhone::new();
    let enrolment = phone.enrolment_for(CredentialPurpose::Authorization);
    let now = phone_auth_verifier::verifier::now_ms();
    std::thread::spawn(move || {
        let _ = phone.pair_offering(&scanned, &enrolment, now);
    });

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        assert!(
            service.pending_pairing().is_none(),
            "a mismatched enrolment reached the confirmation stage"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(service.devices().is_empty());
}

/// Each purpose is a separate credential id, so nothing can collide by name.
#[test]
fn every_purpose_reaches_the_store_under_its_own_id() {
    let mut service = service("all");

    for purpose in [
        CredentialPurpose::Authorization,
        CredentialPurpose::Vault,
        CredentialPurpose::FileLocker,
        CredentialPurpose::Ssh,
    ] {
        pair(&mut service, purpose).expect("pairing");
    }

    let devices = service.devices();
    let ids: std::collections::BTreeSet<&str> = devices[0]
        .credentials
        .iter()
        .map(|credential| credential.credential_id.as_str())
        .collect();

    assert_eq!(ids.len(), 4, "credential ids collided: {ids:?}");
    assert!(ids.contains(simulator::CREDENTIAL_ID));
}
