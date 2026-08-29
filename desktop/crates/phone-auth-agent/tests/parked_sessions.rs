//! One phone, several credentials, several sessions — over a real socket.
//!
//! A paired phone runs one connection loop per credential, because the
//! credential a session was opened with decides which key signs on it. So a
//! desktop that holds both a login credential and a vault credential for the
//! same phone has two live sessions from one device, not one.
//!
//! The pool that holds those sessions used to be keyed by device alone, which
//! made the second arrival overwrite the first. The overwritten session's
//! socket closed, its loop on the phone reported a failure and dialled again,
//! and the two loops took turns evicting each other for as long as the app was
//! open. Nothing in the desktop suite could see it: the simulated phone keeps
//! exactly one connection and signs whatever credential a request names, so it
//! is a more forgiving peer than the real one.

#![cfg(feature = "dev-simulator")]

use std::collections::HashMap;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use phone_auth_agent::qr_network::{client, QrNetworkTransport};
use phone_auth_agent::transport::Transport;
use phone_auth_session::{IdentityKey, SecureChannel};

const DEVICE: &str = "phone-1";
const LOGIN: &str = "verifier-1-authorization-v1";
const VAULT: &str = "verifier-1-vault-v1";

/// A transport listening on a loopback port, with `DEVICE` already paired.
fn listening(phone: &IdentityKey) -> QrNetworkTransport {
    let transport = QrNetworkTransport::bind(IdentityKey::generate(), "verifier-1".into(), 0, true)
        .expect("bind");
    transport.set_known_peers(HashMap::from([(
        DEVICE.to_owned(),
        phone.public_key_spki().expect("phone spki"),
    )]));
    transport
}

/// What one of the phone's loops does: dial, say which credential it carries,
/// and wait to be asked something.
fn dial(
    transport: &QrNetworkTransport,
    phone: &IdentityKey,
    credential_id: &str,
) -> (SecureChannel, TcpStream) {
    let endpoint = format!("127.0.0.1:{}", transport.port());
    let verifier = transport
        .identity()
        .public_key_spki()
        .expect("verifier spki");
    client::connect(
        &endpoint,
        &verifier,
        DEVICE,
        phone,
        credential_id,
        phone_auth_verifier::verifier::now_ms(),
    )
    .expect("the phone connects")
}

/// Blocks until the desktop has parked `count` sessions for `DEVICE`.
///
/// The phone's side of a dial returns as soon as it has written; the desktop
/// parks a moment later, on another thread. Asserting without waiting would be
/// asserting on that gap.
fn parked(transport: &QrNetworkTransport, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if transport.parked_credentials(DEVICE).len() >= count {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "only {:?} parked, wanted {count}",
        transport.parked_credentials(DEVICE)
    );
}

#[test]
fn two_credentials_of_one_phone_are_two_sessions() {
    let phone = IdentityKey::generate();
    let transport = listening(&phone);

    // Held for the length of the test. Dropping either would close its socket,
    // which is the very thing being ruled out.
    let _login = dial(&transport, &phone, LOGIN);
    let _vault = dial(&transport, &phone, VAULT);
    parked(&transport, 2);

    // Each credential finds its own session. Before, the second dial replaced
    // the first and this second call waited out the reconnect window and then
    // reported the phone as not connected.
    transport
        .connect(DEVICE, LOGIN)
        .expect("the login session is still parked");
    transport
        .connect(DEVICE, VAULT)
        .expect("the vault session is still parked");
}

#[test]
fn a_credential_with_no_session_is_not_served_by_another_credentials() {
    let phone = IdentityKey::generate();
    let transport = listening(&phone);
    let _vault = dial(&transport, &phone, VAULT);
    parked(&transport, 1);

    // The phone refuses a request naming a credential its session was not
    // opened with, so handing the vault's session to a login request would
    // spend the reconnect window to produce a denial the user never made.
    // Saying the credential is not connected is the honest answer.
    assert!(
        transport.connect(DEVICE, LOGIN).is_err(),
        "a vault session must not stand in for a login credential"
    );
}
