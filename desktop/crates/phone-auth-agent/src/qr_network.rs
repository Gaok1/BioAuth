//! QR bootstrap onto a local-network link.
//!
//! The desktop listens; the phone connects. That is the opposite of the pull
//! shape `Transport::connect` suggests, so the listener runs on its own thread
//! and parks each completed session until the verifier asks for it.
//!
//! # Trust
//!
//! Confidentiality and peer authentication come from the PhoneAuth handshake
//! in `phone-auth-session`, not from the network. The IP address a phone
//! connects from is a routing detail and is never treated as identity — a
//! session is only usable once the peer has proved possession of a paired key.
//!
//! # One connection per authorization
//!
//! A session is removed from the pool when the verifier takes it, and closed
//! when the exchange ends. The phone reconnects for the next request. Holding
//! a channel open across requests would mean a phone that walked out of range
//! looked available until the first timeout.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use phone_auth_protocol::{Enrolment, SESSION_BINDING_LEN};
use phone_auth_session::{
    ClientHandshake, IdentityKey, PeerExpectation, PendingServerHandshake, SecureChannel,
    ServerBootstrap, VerifierExpectation,
};
use phone_auth_verifier::session::{SecureSession, TransportSecurity};

use crate::framing::{read_frame, write_frame};
use crate::transport::{Transport, TransportAvailability};

pub const TRANSPORT_NAME: &str = "QrNetworkTransport";

/// How long a phone has to complete a handshake once it connects.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a parked session stays usable before it is discarded.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// What a completed pairing handshake offers, pending user confirmation.
///
/// Not a paired device: nothing here is trusted until the user confirms the
/// verification code matches what the phone shows.
#[derive(Debug, Clone)]
pub struct PairingProposal {
    pub device_id: String,
    pub device_name: String,
    pub session_identity_spki: Vec<u8>,
    pub credential_id: String,
    pub algorithm: String,
    pub credential_public_key: Vec<u8>,
    pub key_kind: phone_auth_protocol::KeyKind,
    pub purpose: phone_auth_protocol::CredentialPurpose,
    /// Shown on both screens. The user confirms they match.
    pub verification_code: String,
}

/// A handshake that completed and is waiting for the verifier.
struct ParkedSession {
    channel: SecureChannel,
    stream: TcpStream,
    origin: String,
    parked_at: Instant,
}

#[derive(Default)]
struct State {
    /// Idle authenticated sessions, by device id.
    sessions: HashMap<String, ParkedSession>,
    /// Session identity keys of paired devices, mirrored from the store so the
    /// listener never has to lock the verifier to answer a connection.
    known_peers: HashMap<String, Vec<u8>>,
    /// Set while the user has a pairing code on screen.
    armed_pairing: Option<ServerBootstrap>,
    /// A pairing that completed and awaits confirmation.
    proposal: Option<PairingProposal>,
    /// Most recent listener failure, surfaced in the transport's status.
    last_error: Option<String>,
}

struct Shared {
    identity: IdentityKey,
    verifier_id: String,
    is_development: bool,
    state: Mutex<State>,
    /// Signalled whenever a session is parked or a proposal arrives.
    signal: Condvar,
}

pub struct QrNetworkTransport {
    shared: Arc<Shared>,
    local_addr: SocketAddr,
}

/// This machine's address on the network the phone is expected to be on.
///
/// The listener binds to every interface, but a pairing code has to name one
/// address the phone can dial, and `0.0.0.0` is not one: it is a bind address.
/// A phone that dials it is dialling itself, and the only reason that ever
/// looked like it worked is that the development simulator runs on this same
/// machine, where the connection loops back and succeeds.
///
/// Connecting a UDP socket sends no packet — it only fixes a route — and the
/// local address that falls out is the interface this machine would use to
/// reach the outside world, which on a home network is the one the phone can
/// reach back on. Resolved per pairing rather than at startup, because a laptop
/// that moved from Ethernet to Wi-Fi since boot would otherwise hand out an
/// address it no longer answers on.
pub fn advertised_address() -> io::Result<Ipv4Addr> {
    let probe = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    probe.connect(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)))?;

    let local = match probe.local_addr()? {
        SocketAddr::V4(local) => *local.ip(),
        SocketAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no IPv4 route to the local network",
            ))
        }
    };

    // Either of these would produce a code that cannot be scanned from another
    // device, which is the whole point of the code.
    if local.is_unspecified() || local.is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no usable address for this machine (got {local})"),
        ));
    }

    Ok(local)
}

impl QrNetworkTransport {
    /// Binds a listener and starts accepting.
    ///
    /// Binds to all interfaces because the phone is on the LAN, not on this
    /// machine. That is a real exposure: the handshake is what makes it safe,
    /// and an unauthenticated peer gets no further than a rejected hello.
    pub fn bind(
        identity: IdentityKey,
        verifier_id: String,
        port: u16,
        is_development: bool,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
        let local_addr = listener.local_addr()?;

        let shared = Arc::new(Shared {
            identity,
            verifier_id,
            is_development,
            state: Mutex::new(State::default()),
            signal: Condvar::new(),
        });

        let accept_shared = Arc::clone(&shared);
        thread::spawn(move || accept_loop(listener, accept_shared));

        Ok(Self { shared, local_addr })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The address to advertise in a bootstrap.
    ///
    /// Reports the port on every interface; picking one interface here would
    /// guess wrong on a machine with both Wi-Fi and Ethernet. Choosing the
    /// address the phone should dial is the caller's job.
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Mirrors the paired devices the listener should accept.
    pub fn set_known_peers(&self, peers: HashMap<String, Vec<u8>>) {
        self.shared.state.lock().expect("state mutex").known_peers = peers;
    }

    /// Puts a pairing code on the wire. Replaces any code already armed.
    pub fn arm_pairing(&self, bootstrap: ServerBootstrap) {
        let mut state = self.shared.state.lock().expect("state mutex");
        state.proposal = None;
        state.armed_pairing = Some(bootstrap);
    }

    pub fn cancel_pairing(&self) {
        let mut state = self.shared.state.lock().expect("state mutex");
        state.armed_pairing = None;
        state.proposal = None;
    }

    /// Takes a completed pairing proposal, if one has arrived.
    pub fn take_proposal(&self) -> Option<PairingProposal> {
        self.shared
            .state
            .lock()
            .expect("state mutex")
            .proposal
            .take()
    }

    /// Waits for a pairing to complete.
    pub fn await_proposal(&self, timeout: Duration) -> Option<PairingProposal> {
        let mut state = self.shared.state.lock().expect("state mutex");
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(proposal) = state.proposal.take() {
                return Some(proposal);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, _) = self
                .shared
                .signal
                .wait_timeout(state, remaining)
                .expect("state mutex");
            state = next;
        }
    }

    /// Identity key hash, for building a bootstrap that commits to this agent.
    pub fn identity(&self) -> &IdentityKey {
        &self.shared.identity
    }

    /// Waits up to `timeout` for a session to this device.
    fn take_session(&self, device_id: &str, timeout: Duration) -> Option<ParkedSession> {
        let mut state = self.shared.state.lock().expect("state mutex");
        let deadline = Instant::now() + timeout;
        loop {
            discard_stale(&mut state);
            if let Some(session) = state.sessions.remove(device_id) {
                return Some(session);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, _) = self
                .shared
                .signal
                .wait_timeout(state, remaining)
                .expect("state mutex");
            state = next;
        }
    }
}

fn discard_stale(state: &mut State) {
    state
        .sessions
        .retain(|_, session| session.parked_at.elapsed() < SESSION_IDLE_TIMEOUT);
}

impl Transport for QrNetworkTransport {
    fn name(&self) -> &str {
        TRANSPORT_NAME
    }

    fn description(&self) -> &str {
        "QR bootstrap onto an authenticated link over the local network"
    }

    fn availability(&self) -> TransportAvailability {
        let state = self.shared.state.lock().expect("state mutex");
        if let Some(error) = &state.last_error {
            return TransportAvailability::Unavailable {
                reason: error.clone(),
            };
        }
        TransportAvailability::Ready
    }

    fn connect(&self, device_id: &str) -> Result<Box<dyn SecureSession + Send>, String> {
        // A short wait rather than an immediate answer: the phone may be
        // reconnecting right now, and failing instantly would turn a normal
        // reconnect into a visible error.
        let session = self
            .take_session(device_id, Duration::from_secs(10))
            .ok_or_else(|| {
                format!("`{device_id}` is not connected; open PhoneAuth on the phone")
            })?;

        Ok(Box::new(NetworkSession {
            channel: session.channel,
            stream: session.stream,
            origin: session.origin,
            security: TransportSecurity {
                transport_name: TRANSPORT_NAME.into(),
                confidential: true,
                peer_authenticated: true,
                requires_network: true,
                // Being on the same network is not proximity, and even if it
                // were, proximity is never authorization.
                proximity_signal: false,
                is_development: self.shared.is_development,
            },
            closed: false,
        }))
    }
}

/// A [`SecureSession`] backed by a TCP connection and a [`SecureChannel`].
struct NetworkSession {
    channel: SecureChannel,
    stream: TcpStream,
    origin: String,
    security: TransportSecurity,
    closed: bool,
}

impl SecureSession for NetworkSession {
    fn origin_label(&self) -> &str {
        &self.origin
    }

    fn session_binding(&self) -> [u8; SESSION_BINDING_LEN] {
        self.channel.session_binding()
    }

    fn security(&self) -> &TransportSecurity {
        &self.security
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        let record = self
            .channel
            .seal(frame)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        write_frame(&mut self.stream, &record)
    }

    fn receive(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        self.stream.set_read_timeout(Some(timeout))?;
        let record = read_frame(&mut self.stream)?;
        self.channel
            .open(&record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
    }

    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let shared = Arc::clone(&shared);
                // One thread per connection. A phone that connects and then
                // says nothing must not block every other phone.
                thread::spawn(move || {
                    if let Err(error) = serve_connection(stream, &shared) {
                        // Expected constantly: port scanners, stale phones,
                        // wrong networks. Recorded, not escalated.
                        let mut state = shared.state.lock().expect("state mutex");
                        state.last_error = Some(error.clone());
                    }
                });
            }
            Err(error) => {
                let mut state = shared.state.lock().expect("state mutex");
                state.last_error = Some(format!("accept failed: {error}"));
            }
        }
    }
}

/// Runs the handshake for one inbound connection and parks the result.
fn serve_connection(mut stream: TcpStream, shared: &Arc<Shared>) -> Result<(), String> {
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| error.to_string())?;
    let origin = format!(
        "{TRANSPORT_NAME} • {}",
        stream
            .peer_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown peer".into())
    );

    // Decide up front whether this connection may pair, and with what.
    let armed = shared
        .state
        .lock()
        .expect("state mutex")
        .armed_pairing
        .clone();

    let bootstrap = match &armed {
        Some(bootstrap) => bootstrap.clone(),
        None => {
            // No code on screen, so this must be an already-paired phone. It
            // still needs a fresh session id and nonce, which it will accept
            // because the hello is signed by the key it stored at pairing.
            ServerBootstrap::new(
                phone_auth_verifier::random::session_id(),
                shared.verifier_id.clone(),
                String::new(),
                &shared.identity,
                phone_auth_verifier::verifier::now_ms(),
                phone_auth_session::DEFAULT_LIFETIME_MS,
            )
            .map_err(|error| error.to_string())?
        }
    };

    let (pending, hello) = PendingServerHandshake::begin(bootstrap, &shared.identity)
        .map_err(|error| error.to_string())?;
    write_frame(&mut stream, &hello).map_err(|error| error.to_string())?;

    let client_frame = read_frame(&mut stream).map_err(|error| error.to_string())?;

    // Peek at the device id so a paired phone is matched against its stored
    // key rather than accepted as a stranger.
    let claimed = peek_device_id(&client_frame)?;
    let known = shared
        .state
        .lock()
        .expect("state mutex")
        .known_peers
        .get(&claimed)
        .cloned();

    let outcome = match (&known, &armed) {
        (Some(identity_spki), _) => pending
            .finish(
                &client_frame,
                PeerExpectation::Paired {
                    device_id: &claimed,
                    identity_spki,
                },
                TRANSPORT_NAME,
            )
            .map_err(|error| error.to_string())?,
        (None, Some(_)) => pending
            .finish(&client_frame, PeerExpectation::Pairing, TRANSPORT_NAME)
            .map_err(|error| error.to_string())?,
        (None, None) => {
            return Err(format!(
                "`{claimed}` is not paired and no pairing code is active"
            ))
        }
    };

    let mut channel = outcome.channel;

    if outcome.was_pairing {
        // A pairing session exists only to carry the enrolment. It is never
        // parked for authorization: nothing about it is trusted until the user
        // has compared the verification code.
        let record = read_frame(&mut stream).map_err(|error| error.to_string())?;
        let frame = channel.open(&record).map_err(|error| error.to_string())?;
        let enrolment = Enrolment::decode(&frame).map_err(|error| error.to_string())?;

        let mut state = shared.state.lock().expect("state mutex");
        state.armed_pairing = None;
        state.proposal = Some(PairingProposal {
            device_id: outcome.peer_device_id,
            device_name: enrolment.device_name,
            session_identity_spki: outcome.peer_identity_spki,
            credential_id: enrolment.credential_id,
            algorithm: enrolment.algorithm,
            credential_public_key: enrolment.public_key,
            key_kind: enrolment.key_kind,
            purpose: enrolment.purpose,
            verification_code: outcome.verification_code,
        });
        state.last_error = None;
        shared.signal.notify_all();
        return Ok(());
    }

    let mut state = shared.state.lock().expect("state mutex");
    discard_stale(&mut state);
    state.sessions.insert(
        outcome.peer_device_id,
        ParkedSession {
            channel,
            stream,
            origin,
            parked_at: Instant::now(),
        },
    );
    state.last_error = None;
    shared.signal.notify_all();
    Ok(())
}

/// Reads the device id out of a client hello without verifying it.
///
/// Only used to choose which stored key to check the hello against. Nothing is
/// trusted on the strength of this: an unpaired id falls through to the
/// pairing path, and a paired one still has to produce a valid signature.
fn peek_device_id(client_frame: &[u8]) -> Result<String, String> {
    use phone_auth_protocol::cbor::Reader;

    let mut reader = Reader::new(client_frame);
    reader.array().map_err(|error| error.to_string())?;
    let unsigned = reader.bytes().map_err(|error| error.to_string())?;

    let mut inner = Reader::new(unsigned);
    inner.array().map_err(|error| error.to_string())?;
    for _ in 0..2 {
        inner.uint().map_err(|error| error.to_string())?;
    }
    inner.text().map_err(|error| error.to_string())?; // session id
    inner.bytes().map_err(|error| error.to_string())?; // nonce
    inner.text().map_err(|error| error.to_string())?; // verifier id
    inner.int().map_err(|error| error.to_string())?; // expiry
    inner
        .text()
        .map(str::to_owned)
        .map_err(|error| error.to_string())
}

/// Drives the phone side of this transport.
///
/// Lives here rather than in a test module because the development simulator
/// uses it to be a real client over a real socket, and because it is the
/// reference the mobile implementation is written against.
pub mod client {
    use super::*;

    /// Connects, pairs, and sends an enrolment.
    pub fn pair(
        endpoint: &str,
        bootstrap: &ServerBootstrap,
        device_id: &str,
        identity: &IdentityKey,
        enrolment: &Enrolment,
        now_ms: i64,
    ) -> Result<(SecureChannel, TcpStream, String), String> {
        let mut stream = TcpStream::connect(endpoint).map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| error.to_string())?;

        let hello = read_frame(&mut stream).map_err(|error| error.to_string())?;
        let (client_frame, outcome) = ClientHandshake::respond(
            &hello,
            VerifierExpectation::Scanned { bootstrap },
            device_id,
            identity,
            TRANSPORT_NAME,
            now_ms,
        )
        .map_err(|error| error.to_string())?;
        write_frame(&mut stream, &client_frame).map_err(|error| error.to_string())?;

        let mut channel = outcome.channel;
        let record = channel
            .seal(&enrolment.encode())
            .map_err(|error| error.to_string())?;
        write_frame(&mut stream, &record).map_err(|error| error.to_string())?;

        Ok((channel, stream, outcome.verification_code))
    }

    /// Connects as an already-paired device.
    pub fn connect(
        endpoint: &str,
        verifier_identity_spki: &[u8],
        device_id: &str,
        identity: &IdentityKey,
        now_ms: i64,
    ) -> Result<(SecureChannel, TcpStream), String> {
        let mut stream = TcpStream::connect(endpoint).map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| error.to_string())?;

        let hello = read_frame(&mut stream).map_err(|error| error.to_string())?;
        let (client_frame, outcome) = ClientHandshake::respond(
            &hello,
            VerifierExpectation::Paired {
                identity_spki: verifier_identity_spki,
            },
            device_id,
            identity,
            TRANSPORT_NAME,
            now_ms,
        )
        .map_err(|error| error.to_string())?;
        write_frame(&mut stream, &client_frame).map_err(|error| error.to_string())?;

        Ok((outcome.channel, stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_advertised_address_is_dialable_from_another_device() {
        // The regression this guards. A pairing code used to carry the bind
        // address, `0.0.0.0`, which a phone resolves to itself. It survived
        // every local run because the development simulator connects from this
        // same machine, where it loops back and succeeds.
        //
        // A machine with no network is a legitimate outcome, so the assertion
        // is on the value when there is one, not on there being one.
        if let Ok(address) = advertised_address() {
            assert!(
                !address.is_unspecified(),
                "0.0.0.0 is a bind address; a phone dialling it dials itself"
            );
            assert!(
                !address.is_loopback(),
                "{address} is reachable only from this machine"
            );
            assert!(!address.is_broadcast(), "{address} is not a host");
        }
    }

    #[test]
    fn the_advertisement_is_resolved_fresh_each_time() {
        // Two calls must agree while the network has not changed. The point of
        // resolving per pairing is that the answer may change between
        // pairings, not that it is unstable within one.
        if let (Ok(first), Ok(second)) = (advertised_address(), advertised_address()) {
            assert_eq!(first, second);
        }
    }
}
