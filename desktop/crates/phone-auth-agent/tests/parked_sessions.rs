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
use std::io::Read;
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

/// The idle window has to happen on its own, not when something else asks.
///
/// `discard_stale` ran on the way past: on another connection arriving, or on
/// the desktop reaching for a session to use. In the steady state the phone's
/// own reconnect drives it -- its idle timeout is deliberately shorter than
/// this one -- but a phone that stops reconnecting is exactly what the window
/// is for. Backgrounded, out of range, killed: its last session stayed parked,
/// holding a `SecureChannel` with live keys and an open socket, until some
/// other phone connected or some other request was made. On a desktop with one
/// paired phone and no `sudo` to run, that is forever.
///
/// Observed from the phone's socket rather than through `parked_credentials`,
/// because that call sweeps as it reads: asking it would be doing the very
/// thing this is checking nobody has to do.
#[test]
fn a_session_nobody_touches_is_dropped_when_its_window_runs_out() {
    let phone = IdentityKey::generate();
    let transport = QrNetworkTransport::bind_with_idle_timeout(
        IdentityKey::generate(),
        "verifier-1".into(),
        0,
        true,
        Duration::from_millis(300),
    )
    .expect("bind");
    transport.set_known_peers(HashMap::from([(
        DEVICE.to_owned(),
        phone.public_key_spki().expect("phone spki"),
    )]));

    let (_channel, mut stream) = dial(&transport, &phone, LOGIN);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");

    // The desktop dropping the parked session closes its end, which the phone
    // sees as EOF. Nothing else in this test touches the transport, so the
    // only thing that can produce it is the window running out by itself.
    let mut byte = [0u8; 1];
    let read = stream.read(&mut byte);
    assert!(
        matches!(read, Ok(0)),
        "the phone's socket should have been closed from the desktop side, got {read:?}"
    );
}

/// A stranger on the port must not take the desktop off the air.
///
/// The listener answers the whole LAN, so anything can reach it: a port
/// scanner, a phone that was forgotten here, a phone whose Wi-Fi roamed
/// mid-handshake. Each of those ends the connection in an error, and that
/// error used to be written to the same field the transport reports as its
/// availability. `TransportRegistry::connect` only considers ready
/// transports, so one stray connection was enough to make a desktop with a
/// phone parked in it answer "no transport can reach a phone yet" -- until
/// some later connection happened to succeed and cleared the field.
#[test]
fn a_failed_connection_does_not_take_the_transport_off_the_air() {
    let phone = IdentityKey::generate();
    let transport = listening(&phone);
    let held = dial(&transport, &phone, LOGIN);
    parked(&transport, 1);

    // Connects, is sent a hello, and hangs up without answering it.
    let stranger = TcpStream::connect(format!("127.0.0.1:{}", transport.port()))
        .expect("the listener answers anyone");
    drop(stranger);

    // The failure is recorded on the connection's own thread, so wait for it
    // rather than race it -- asserting before it lands would pass for the
    // wrong reason.
    let deadline = Instant::now() + Duration::from_secs(10);
    while transport.last_connection_error().is_none() {
        assert!(Instant::now() < deadline, "the failure was never recorded");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(
        transport.availability().is_ready(),
        "a stranger on the port is not a broken listener"
    );
    assert!(
        transport.connect(DEVICE, LOGIN).is_ok(),
        "the phone was parked the whole time"
    );
    drop(held);
}
