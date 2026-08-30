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
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use phone_auth_protocol::{Enrolment, SessionAttach, SESSION_BINDING_LEN};
use phone_auth_session::{
    ClientHandshake, IdentityKey, PairingIntent, PeerExpectation, PendingServerHandshake,
    SecureChannel, ServerBootstrap, VerifierExpectation,
};
use phone_auth_verifier::session::{SecureSession, TransportSecurity};

use crate::framing::{read_frame, write_frame};
use crate::transport::{Transport, TransportAvailability};

pub const TRANSPORT_NAME: &str = "QrNetworkTransport";

/// How long a phone has to complete a handshake once it connects.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a parked session stays usable before it is discarded.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long the client half waits for a socket to open.
///
/// The same ten seconds the mobile transport gives its own dial. Without one,
/// an endpoint that is routable but silent -- a desktop that moved networks and
/// left its address behind a firewall that drops rather than refuses -- is not
/// a failed connection, it is the operating system's SYN retry schedule, which
/// is minutes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the reaper looks, as a fraction of the timeout it enforces.
///
/// A tenth, so a session outlives its window by at most ten percent of it.
const STALE_SWEEP_DIVISOR: u32 = 10;

/// What a completed pairing handshake offers, pending user confirmation.
///
/// Not a paired device: nothing here is trusted until the user confirms the
/// verification code matches what the phone shows.
#[derive(Debug, Clone)]
pub struct PairingProposal {
    /// Names this attempt for the rest of its short life.
    ///
    /// The verification code cannot do this job: it is six digits, and two
    /// attempts may legitimately produce the same six.
    pub attempt_id: String,
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
    /// Idle authenticated sessions, by device and credential.
    ///
    /// Keyed by both because a phone runs one connection per credential: a
    /// desktop holding a login credential and a vault credential for the same
    /// phone has two live sessions from one device. Keyed by device alone, the
    /// second arrival replaced the first, its socket closed, that loop on the
    /// phone reported a failure and dialled again — and the two took turns
    /// evicting each other for as long as the app was open.
    ///
    /// Within one credential a second arrival still replaces the first, which
    /// is right: a phone has one loop per credential, so the new session *is*
    /// that loop, and the old one is a socket its end has already closed.
    sessions: HashMap<SessionKey, ParkedSession>,
    /// Session identity keys of paired devices, mirrored from the store so the
    /// listener never has to lock the verifier to answer a connection.
    known_peers: HashMap<String, Vec<u8>>,
    /// Set while the user has a pairing code on screen.
    armed_pairing: Option<ServerBootstrap>,
    /// A pairing that completed and awaits confirmation.
    proposal: Option<PairingProposal>,
    /// Most recent failure of the listening socket itself, surfaced in the
    /// transport's status. Only this decides whether the transport is usable.
    listener_error: Option<String>,
    /// Why the most recent inbound connection did not become a session.
    ///
    /// Diagnostic, and deliberately separate. It used to share a field with
    /// the listener failure, and since availability reports that field, one
    /// port scan -- or one phone whose handshake failed, or one that dropped
    /// mid-handshake when the Wi-Fi roamed -- left the transport reporting
    /// `Unavailable`. `connect` only considers ready transports, so a desktop
    /// with a working listener and a phone parked in it answered "no transport
    /// can reach a phone yet" until some other connection happened to succeed.
    last_connection_error: Option<String>,
}

struct Shared {
    identity: IdentityKey,
    verifier_id: String,
    is_development: bool,
    state: Mutex<State>,
    /// Signalled whenever a session is parked or a proposal arrives.
    signal: Condvar,
    /// How long a parked session may sit unused.
    ///
    /// Held rather than read from the constant so a test can set a window it
    /// can afford to wait out. Production always passes [`SESSION_IDLE_TIMEOUT`].
    idle_timeout: Duration,
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

/// Binds the remembered port, and any port at all if that one is taken.
///
/// The port is not decoration: it is half of the address a phone was given
/// when it scanned the pairing code, and nothing tells the phone a new one.
/// So the agent asks for the same port every start. It can still lose it to
/// whatever claimed it while the agent was not running, and refusing to start
/// over a port number would make the machine unreachable rather than merely
/// re-pairable -- so losing it costs a pairing, not the agent.
fn bind_listener(port: u16) -> io::Result<TcpListener> {
    let wanted = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
    match wanted {
        Err(error) if port != 0 && error.kind() == io::ErrorKind::AddrInUse => {
            TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        }
        other => other,
    }
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
        Self::bind_with_idle_timeout(
            identity,
            verifier_id,
            port,
            is_development,
            SESSION_IDLE_TIMEOUT,
        )
    }

    /// As [`Self::bind`], with the parked-session window named explicitly.
    ///
    /// Exists for tests, which cannot afford to wait out five minutes to watch
    /// a stale session be dropped. Production uses [`Self::bind`].
    pub fn bind_with_idle_timeout(
        identity: IdentityKey,
        verifier_id: String,
        port: u16,
        is_development: bool,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        let listener = bind_listener(port)?;
        let local_addr = listener.local_addr()?;

        let shared = Arc::new(Shared {
            identity,
            verifier_id,
            is_development,
            state: Mutex::new(State::default()),
            signal: Condvar::new(),
            idle_timeout,
        });

        let accept_shared = Arc::clone(&shared);
        thread::spawn(move || accept_loop(listener, accept_shared));

        let reap_shared = Arc::clone(&shared);
        thread::spawn(move || reap_loop(reap_shared));

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

    /// Drops any parked session belonging to a device.
    ///
    /// Forgetting a phone has to reach the sessions already sitting here, not
    /// only the peer table, or the next authorization would run over a channel
    /// opened while the pairing still existed.
    pub fn discard_sessions(&self, device_id: &str) {
        self.shared
            .state
            .lock()
            .expect("state mutex")
            .sessions
            // Every credential of that phone. Forgetting a device is not
            // "except for the vault".
            .retain(|(parked, _), _| parked != device_id);
    }

    /// Why the last inbound connection did not become a session, if one
    /// failed since the last one that succeeded.
    ///
    /// Diagnostic. Deliberately not part of [`Self::availability`]: a stranger
    /// on the port says nothing about whether this desktop can reach a phone.
    pub fn last_connection_error(&self) -> Option<String> {
        self.shared
            .state
            .lock()
            .expect("state mutex")
            .last_connection_error
            .clone()
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

    /// Which of a device's credentials currently have a session parked.
    ///
    /// Exists for tests, which otherwise have to guess when an inbound
    /// connection is ready: the phone's side of `connect` returns as soon as
    /// it has written, and the desktop parks some microseconds later. `None`
    /// is a phone that did not name its credential.
    pub fn parked_credentials(&self, device_id: &str) -> Vec<Option<String>> {
        let mut state = self.shared.state.lock().expect("state mutex");
        discard_stale(&mut state, self.shared.idle_timeout);
        state
            .sessions
            .keys()
            .filter(|(parked, _)| parked == device_id)
            .map(|(_, credential)| credential.clone())
            .collect()
    }

    /// Waits up to `timeout` for this device's session for `credential_id`.
    fn take_session(
        &self,
        device_id: &str,
        credential_id: &str,
        timeout: Duration,
    ) -> Option<ParkedSession> {
        let mut state = self.shared.state.lock().expect("state mutex");
        let deadline = Instant::now() + timeout;
        loop {
            discard_stale(&mut state, self.shared.idle_timeout);
            if let Some(session) = take_matching(&mut state, device_id, credential_id) {
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

/// A parked session's address: which phone, and which of its credentials.
///
/// `None` is a phone from before the attach frame, which cannot say. It is
/// served to any credential, because that is exactly what the desktop did for
/// every phone before this existed — a fallback, never a match.
type SessionKey = (String, Option<String>);

fn discard_stale(state: &mut State, idle_timeout: Duration) {
    state
        .sessions
        .retain(|_, session| session.parked_at.elapsed() < idle_timeout);
}

/// Enforces the idle window instead of only consulting it.
///
/// [`discard_stale`] ran on the way past: when another connection arrived, or
/// when the desktop reached for a session to use. In the steady state the
/// phone's own reconnect drives it -- that is why its idle timeout is shorter
/// than this one -- but a phone that stops reconnecting is precisely the case
/// the window exists for. Backgrounded, out of range, killed: its last session
/// stayed parked, holding a `SecureChannel` with live keys and an open socket,
/// for as long as it took some other phone to connect or some other request to
/// be made. On a desktop with one paired phone and no `sudo` to run, that is
/// forever.
fn reap_loop(shared: Arc<Shared>) {
    let interval = shared.idle_timeout / STALE_SWEEP_DIVISOR;
    loop {
        thread::sleep(interval);
        let mut state = shared.state.lock().expect("state mutex");
        discard_stale(&mut state, shared.idle_timeout);
    }
}

/// The session that phone opened for that credential, or a phone that predates
/// the attach frame and therefore answers for anything.
fn take_matching(state: &mut State, device_id: &str, credential_id: &str) -> Option<ParkedSession> {
    let exact = (device_id.to_owned(), Some(credential_id.to_owned()));
    if let Some(session) = state.sessions.remove(&exact) {
        return Some(session);
    }
    state.sessions.remove(&(device_id.to_owned(), None))
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
        if let Some(error) = &state.listener_error {
            return TransportAvailability::Unavailable {
                reason: error.clone(),
            };
        }
        TransportAvailability::Ready
    }

    fn set_known_peers(&self, peers: HashMap<String, Vec<u8>>) {
        QrNetworkTransport::set_known_peers(self, peers);
    }

    fn connect(
        &self,
        device_id: &str,
        credential_id: &str,
    ) -> Result<Box<dyn SecureSession + Send>, String> {
        // A short wait rather than an immediate answer: the phone may be
        // reconnecting right now, and failing instantly would turn a normal
        // reconnect into a visible error.
        let session = self
            .take_session(device_id, credential_id, Duration::from_secs(10))
            .ok_or_else(|| {
                // The last inbound failure belongs here rather than in
                // availability: it explains why this phone is not parked,
                // which is the question being asked, and it says nothing at
                // all when the answer is "it is parked".
                let state = self.shared.state.lock().expect("state mutex");
                match &state.last_connection_error {
                    Some(reason) => format!(
                        "`{device_id}` is not connected; open PhoneAuth on the phone (the last connection to this desktop failed: {reason})"
                    ),
                    None => {
                        format!("`{device_id}` is not connected; open PhoneAuth on the phone")
                    }
                }
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
            pending_record: Vec::new(),
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
    pending_record: Vec<u8>,
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
        let record =
            crate::framing::read_frame_resumable(&mut self.stream, &mut self.pending_record)?;
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

/// How long the accept loop pauses after a failed accept.
///
/// Short enough that a phone dialling during the pause only waits for its
/// retry, long enough that a persistent failure costs no more than ten wakeups
/// a second.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Accepting proves the listener works, whatever it did last.
                shared.state.lock().expect("state mutex").listener_error = None;
                let shared = Arc::clone(&shared);
                // One thread per connection. A phone that connects and then
                // says nothing must not block every other phone.
                thread::spawn(move || {
                    if let Err(error) = serve_connection(stream, &shared) {
                        // Expected constantly: port scanners, stale phones,
                        // wrong networks. Recorded, not escalated.
                        let mut state = shared.state.lock().expect("state mutex");
                        state.last_connection_error = Some(error.clone());
                    }
                });
            }
            Err(error) => {
                shared.state.lock().expect("state mutex").listener_error =
                    Some(format!("accept failed: {error}"));
                // A failing accept usually fails again immediately -- the
                // process is out of descriptors, the kernel is out of buffers
                // -- and `incoming()` never ends, so recording and retrying at
                // once is a loop that pegs a core. Which is also what makes
                // the condition last: nothing else on this machine gets the
                // scheduling it needs to release whatever ran out.
                thread::sleep(ACCEPT_RETRY_DELAY);
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

    // A pairing session exists only to carry the enrolment. It is never parked
    // for authorization: nothing about it is trusted until the user has
    // compared the verification code.
    let enrolment = if outcome.was_pairing {
        let record = read_frame(&mut stream).map_err(|error| error.to_string())?;
        let frame = channel.open(&record).map_err(|error| error.to_string())?;
        Some(Enrolment::decode(&frame).map_err(|error| error.to_string())?)
    } else if armed.is_some() {
        // A phone this computer already knows can still be pairing afresh.
        // Revoking on the phone does not change its session identity, so the
        // handshake above verifies exactly as a reconnect would, and the
        // desktop used to park the session and sit on the QR forever while the
        // phone showed a code nobody could confirm.
        match outcome.intent {
            // It said so, inside the signed hello. Nothing to infer.
            Some(PairingIntent::Pair) => {
                let record = read_frame(&mut stream).map_err(|error| error.to_string())?;
                let frame = channel.open(&record).map_err(|error| error.to_string())?;
                Some(Enrolment::decode(&frame).map_err(|error| error.to_string())?)
            }
            Some(PairingIntent::Resume) => None,
            // A phone from before intents. Fall back to who speaks first: a
            // pairing phone sends its enrolment straight away, a reconnecting
            // one waits to be asked. Only while a code is armed, and it does
            // mean a slow link can be misread as a reconnect — which is the
            // guesswork the intent exists to remove.
            None => peek_enrolment(&mut stream, &mut channel)?,
        }
    } else {
        None
    };

    if let Some(enrolment) = enrolment {
        // The code said what this pairing is for. A phone that answers with a
        // credential for something else is enrolling a key the user did not
        // ask for — the user who ran `pair --service ssh` would end up with an
        // authorization key and no way to see the difference in the list.
        if let Some(armed) = &armed {
            if enrolment.purpose != armed.purpose {
                return Err(format!(
                    "the phone offered a {:?} credential for a {:?} pairing",
                    enrolment.purpose, armed.purpose
                ));
            }
        }

        let mut state = shared.state.lock().expect("state mutex");
        state.armed_pairing = None;
        state.proposal = Some(PairingProposal {
            attempt_id: phone_auth_verifier::random::request_id(),
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
        state.last_connection_error = None;
        shared.signal.notify_all();
        return Ok(());
    }

    // Which of this phone's credentials the session is for. A phone that does
    // not say is parked as an answer to anything, which is what every phone got
    // before the frame existed.
    let credential_id = read_attach(&mut stream, &mut channel)?;

    let mut state = shared.state.lock().expect("state mutex");
    discard_stale(&mut state, shared.idle_timeout);
    state.sessions.insert(
        (outcome.peer_device_id, credential_id),
        ParkedSession {
            channel,
            stream,
            origin,
            parked_at: Instant::now(),
        },
    );
    state.last_connection_error = None;
    shared.signal.notify_all();
    Ok(())
}

/// How long a phone gets to say which credential its session carries.
///
/// Spent in full only by a phone too old to send the frame, and only once per
/// reconnect. A phone that does send it costs nothing: the frame is already in
/// flight when the handshake completes.
const ATTACH_WINDOW: Duration = Duration::from_secs(2);

/// How long a known phone gets to declare itself as re-pairing.
///
/// Only spent while a pairing code is armed, and only before parking a session
/// that would otherwise sit idle anyway.
const RE_ENROLMENT_WINDOW: Duration = Duration::from_secs(2);

/// Looks for an enrolment from a phone that already has a stored key.
///
/// Silence is the ordinary answer and means this is a reconnect. Only a phone
/// that scanned the armed code sends anything here, because in a paired
/// session the desktop always speaks first.
/// Reads the phone's declaration of which credential this session carries.
///
/// A real phone sends it the instant the channel is up, so the wait is spent
/// only on a phone too old to send one — and on that phone the answer is
/// `None`, which parks the session exactly as it was parked before this frame
/// existed. Nothing here grants authority: a phone that names a credential it
/// does not hold has only arranged to be sent requests it will refuse.
fn read_attach(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
) -> Result<Option<String>, String> {
    stream
        .set_read_timeout(Some(ATTACH_WINDOW))
        .map_err(|error| error.to_string())?;
    let record = read_frame(stream);
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| error.to_string())?;

    let record = match record {
        Ok(record) => record,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error.to_string()),
    };

    let frame = channel.open(&record).map_err(|error| error.to_string())?;
    // Anything else arriving here is a phone speaking out of turn: the desktop
    // is the side that asks. Refusing beats parking a session whose first
    // frame has already been read and discarded.
    if !SessionAttach::recognizes(&frame) {
        return Err("the phone sent something other than a session attach".to_owned());
    }
    SessionAttach::decode(&frame)
        .map(|attach| Some(attach.credential_id))
        .map_err(|error| error.to_string())
}

fn peek_enrolment(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
) -> Result<Option<Enrolment>, String> {
    stream
        .set_read_timeout(Some(RE_ENROLMENT_WINDOW))
        .map_err(|error| error.to_string())?;
    let record = read_frame(stream);
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| error.to_string())?;

    let record = match record {
        Ok(record) => record,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error.to_string()),
    };

    let frame = channel.open(&record).map_err(|error| error.to_string())?;
    Enrolment::decode(&frame)
        .map(Some)
        .map_err(|error| error.to_string())
}

/// Reads the device id out of a client hello without verifying it.
///
/// Only used to choose which stored key to check the hello against. Nothing is
/// trusted on the strength of this: an unpaired id falls through to the
/// pairing path, and a paired one still has to produce a valid signature.
pub(crate) fn peek_device_id(client_frame: &[u8]) -> Result<String, String> {
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

    /// Opens a socket to `endpoint`, bounded in every direction it can block.
    ///
    /// `serve_connection` sets both timeouts on the sockets it accepts. This
    /// side set only the read one, which leaves the same handshake, over the
    /// same socket, bounded on one end and not the other: a peer that stops
    /// reading holds `write_frame` for as long as it likes, and dialling
    /// happened on whatever schedule the kernel felt like. Being the reference
    /// the mobile implementation is written against is the reason to get this
    /// right here rather than only there.
    ///
    /// Resolution is not bounded, and does not need to be: an endpoint is the
    /// `host:port` from a scanned code or a pairing record, so it is a literal
    /// address and there is nothing to look up.
    pub(super) fn dial(endpoint: &str) -> Result<TcpStream, String> {
        let address = endpoint
            .to_socket_addrs()
            .map_err(|error| error.to_string())?
            .next()
            .ok_or_else(|| format!("endpoint `{endpoint}` resolved to no address"))?;
        let stream =
            TcpStream::connect_timeout(&address, CONNECT_TIMEOUT).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| error.to_string())?;
        stream
            .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| error.to_string())?;
        Ok(stream)
    }

    /// Connects, pairs, and sends an enrolment.
    pub fn pair(
        endpoint: &str,
        bootstrap: &ServerBootstrap,
        device_id: &str,
        identity: &IdentityKey,
        enrolment: &Enrolment,
        now_ms: i64,
    ) -> Result<(SecureChannel, TcpStream, String), String> {
        let mut stream = dial(endpoint)?;

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

    /// Connects as an already-paired device, for one of its credentials.
    ///
    /// The credential is declared straight away rather than left for the first
    /// request to reveal: the desktop parks this session and later has to pick
    /// the one belonging to the credential it wants to use, and a phone runs a
    /// separate connection for each of them.
    pub fn connect(
        endpoint: &str,
        verifier_identity_spki: &[u8],
        device_id: &str,
        identity: &IdentityKey,
        credential_id: &str,
        now_ms: i64,
    ) -> Result<(SecureChannel, TcpStream), String> {
        let mut stream = dial(endpoint)?;

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

        let mut channel = outcome.channel;
        let record = channel
            .seal(&SessionAttach::new(credential_id).encode())
            .map_err(|error| error.to_string())?;
        write_frame(&mut stream, &record).map_err(|error| error.to_string())?;

        Ok((channel, stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every socket this side opens is bounded in both directions.
    ///
    /// The read timeout was set here and the write one was not -- on the same
    /// socket, carrying the same handshake, that `serve_connection` bounds both
    /// ways from the other end. A peer that stops reading held `write_frame`
    /// for as long as it liked.
    #[test]
    fn the_client_socket_is_bounded_in_both_directions() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let endpoint = listener.local_addr().expect("local addr").to_string();

        let stream = client::dial(&endpoint).expect("dial");

        assert_eq!(
            stream.read_timeout().expect("read timeout"),
            Some(HANDSHAKE_TIMEOUT)
        );
        assert_eq!(
            stream.write_timeout().expect("write timeout"),
            Some(HANDSHAKE_TIMEOUT),
            "a write with no deadline is the half that was missing"
        );
    }

    /// The port is half the address a phone was given, so the agent asks for
    /// the same one every start.
    #[test]
    fn the_remembered_port_is_the_one_bound() {
        let first = bind_listener(0).expect("any port");
        let port = first.local_addr().expect("addr").port();
        drop(first);

        let again = bind_listener(port).expect("the same port again");

        assert_eq!(again.local_addr().expect("addr").port(), port);
    }

    /// And losing it costs a pairing, not the agent: a machine that refuses to
    /// start because something took its port is a machine no phone can reach
    /// at all.
    #[test]
    fn a_port_taken_by_something_else_does_not_stop_the_listener() {
        let holder = bind_listener(0).expect("any port");
        let taken = holder.local_addr().expect("addr").port();

        let listener = bind_listener(taken).expect("some other port");

        assert_ne!(listener.local_addr().expect("addr").port(), taken);
        assert_ne!(listener.local_addr().expect("addr").port(), 0);
    }

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
