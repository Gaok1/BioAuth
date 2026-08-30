//! Linux Bluetooth LE peripheral transport.
//!
//! BlueZ exposes the desktop as a GATT server. Android writes framed protocol
//! records to the request characteristic and receives records as notifications
//! from the response characteristic. The PhoneAuth handshake, not Bluetooth
//! addresses or pairing, supplies confidentiality and peer authentication.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bluer::adv::{Advertisement, Type as AdvertisementType};
use bluer::gatt::local::{
    Application, Characteristic, CharacteristicNotifier, CharacteristicNotify,
    CharacteristicNotifyMethod, CharacteristicWrite, CharacteristicWriteMethod, ReqError, Service,
};
use futures::{future, FutureExt};
use phone_auth_protocol::{SessionAttach, SESSION_BINDING_LEN};
use phone_auth_session::{
    IdentityKey, PeerExpectation, PendingServerHandshake, SecureChannel, ServerBootstrap,
};
use phone_auth_verifier::session::{SecureSession, TransportSecurity};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::time::timeout;
use uuid::Uuid;

use crate::ble_framing::{BleFrameDecoder, BleFrameEncoder};
use crate::qr_network::peek_device_id;
use crate::transport::{Transport, TransportAvailability};

pub const TRANSPORT_NAME: &str = "BleTransport";

const SERVICE_UUID: Uuid = Uuid::from_u128(0x7e57a001_b5a3_4d2f_9f55_41f0dd2f4e41);
const REQUEST_UUID: Uuid = Uuid::from_u128(0x7e57a002_b5a3_4d2f_9f55_41f0dd2f4e41);
const RESPONSE_UUID: Uuid = Uuid::from_u128(0x7e57a003_b5a3_4d2f_9f55_41f0dd2f4e41);

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How often the reaper looks, as a fraction of the timeout it enforces.
///
/// A tenth, so a session outlives its window by at most ten percent of it.
/// Mirrors `qr_network`.
const STALE_SWEEP_DIVISOR: u32 = 10;

/// How long a phone gets to say which credential its session carries.
///
/// Spent in full only by a phone too old to send the frame. One that does send
/// it has the frame in flight before the handshake finishes.
const ATTACH_WINDOW: Duration = Duration::from_secs(2);
// The minimum ATT MTU is 23, leaving 20 bytes for a characteristic value.
// Notifications stay at that portable floor; negotiated larger writes are
// still accepted and reassembled.
const NOTIFICATION_BYTES: usize = 20;

struct ParkedSession {
    channel: SecureChannel,
    outgoing: tokio_mpsc::UnboundedSender<Vec<u8>>,
    incoming: Receiver<Vec<u8>>,
    origin: String,
    parked_at: Instant,
}

#[derive(Default)]
struct State {
    /// By device *and* credential, for the reason set out in `qr_network`: a
    /// phone runs one connection per credential, and keyed by device alone the
    /// second one evicts the first.
    sessions: HashMap<(String, Option<String>), ParkedSession>,
    known_peers: HashMap<String, Vec<u8>>,
    /// Why the adapter itself is unusable: no runtime, no peripheral role, no
    /// adapter. Only this decides whether the transport is usable.
    runtime_error: Option<String>,
    /// Why the most recent link to a phone ended badly.
    ///
    /// Diagnostic, and separate for the reason set out in `qr_network`: a link
    /// that dropped is not an adapter that is gone, and reporting it as
    /// availability took the transport out of `TransportRegistry::connect`
    /// until some later phone happened to connect cleanly.
    last_link_error: Option<String>,
}

fn discard_stale(state: &mut State) {
    state
        .sessions
        .retain(|_, session| session.parked_at.elapsed() < SESSION_IDLE_TIMEOUT);
}

/// Enforces the idle window instead of only consulting it.
///
/// The same defect `qr_network` had, one step further along: there the sweep at
/// least ran whenever a session was parked, and here it ran in exactly one
/// place -- `take_session`, reached only when the desktop wants a session for
/// that same phone. So a phone that connected once and went away left its
/// session parked, holding a `SecureChannel` with live keys and its end of the
/// GATT link, until somebody asked that phone for something. If nobody ever
/// did, forever.
///
/// Not covered by a test on this transport: reaching the park path needs BlueZ
/// and a peer, and a `ParkedSession` cannot be fabricated from this crate
/// because `SecureChannel::new` is crate-private to `phone-auth-session`. The
/// equivalent on `qr_network` is tested over a real socket.
fn reap_loop(shared: Arc<Shared>) {
    let interval = SESSION_IDLE_TIMEOUT / STALE_SWEEP_DIVISOR;
    loop {
        thread::sleep(interval);
        let mut state = shared.state.lock().expect("BLE state mutex");
        discard_stale(&mut state);
    }
}

struct Shared {
    identity: IdentityKey,
    verifier_id: String,
    is_development: bool,
    state: Mutex<State>,
    signal: Condvar,
}

/// Routes characteristic writes to the one active notification subscription.
///
/// Note: BlueZ offers no peer address to the notification callback, so the
/// first phone owns the GATT exchange; add per-device routing if concurrent
/// phone authorization becomes a measured requirement.
#[derive(Default)]
struct LinkHub {
    next_id: AtomicU64,
    active: Mutex<Option<ActiveLink>>,
}

struct ActiveLink {
    id: u64,
    incoming: tokio_mpsc::UnboundedSender<Vec<u8>>,
}

impl LinkHub {
    fn begin(&self) -> Option<(u64, tokio_mpsc::UnboundedReceiver<Vec<u8>>)> {
        let mut active = self.active.lock().expect("BLE link mutex");
        if active.is_some() {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (incoming, receiver) = tokio_mpsc::unbounded_channel();
        *active = Some(ActiveLink { id, incoming });
        Some((id, receiver))
    }

    fn write(&self, value: Vec<u8>) -> Result<(), ReqError> {
        let active = self.active.lock().expect("BLE link mutex");
        active
            .as_ref()
            .ok_or(ReqError::NotPermitted)?
            .incoming
            .send(value)
            .map_err(|_| ReqError::Failed)
    }

    fn finish(&self, id: u64) {
        let mut active = self.active.lock().expect("BLE link mutex");
        if active.as_ref().is_some_and(|link| link.id == id) {
            *active = None;
        }
    }
}

pub struct BleTransport {
    shared: Arc<Shared>,
}

impl BleTransport {
    /// Starts the BlueZ GATT application on its own current-thread runtime.
    pub fn start(
        identity: IdentityKey,
        verifier_id: String,
        verifier_name: String,
        is_development: bool,
    ) -> Result<Self, String> {
        let shared = Arc::new(Shared {
            identity,
            verifier_id,
            is_development,
            state: Mutex::new(State::default()),
            signal: Condvar::new(),
        });
        let server_shared = Arc::clone(&shared);
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("phone-auth-ble".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let result = match runtime {
                    Ok(runtime) => runtime.block_on(run_server(
                        server_shared.clone(),
                        verifier_name,
                        started_tx,
                    )),
                    Err(error) => {
                        let message = format!("could not start BLE runtime: {error}");
                        let _ = started_tx.send(Err(message.clone()));
                        Err(message)
                    }
                };
                if let Err(error) = result {
                    server_shared
                        .state
                        .lock()
                        .expect("BLE state mutex")
                        .runtime_error = Some(error);
                    server_shared.signal.notify_all();
                }
            })
            .map_err(|error| format!("could not start BLE thread: {error}"))?;

        started_rx
            .recv()
            .map_err(|_| "BLE server stopped during startup".to_owned())??;

        let reap_shared = Arc::clone(&shared);
        thread::spawn(move || reap_loop(reap_shared));

        Ok(Self { shared })
    }

    pub fn set_known_peers(&self, peers: HashMap<String, Vec<u8>>) {
        self.shared
            .state
            .lock()
            .expect("BLE state mutex")
            .known_peers = peers;
    }

    fn take_session(
        &self,
        device_id: &str,
        credential_id: &str,
        wait: Duration,
    ) -> Option<ParkedSession> {
        let mut state = self.shared.state.lock().expect("BLE state mutex");
        let deadline = Instant::now() + wait;
        loop {
            discard_stale(&mut state);
            let exact = (device_id.to_owned(), Some(credential_id.to_owned()));
            if let Some(session) = state
                .sessions
                .remove(&exact)
                // A phone too old to name its credential answers for anything,
                // which is what every phone did before it could.
                .or_else(|| state.sessions.remove(&(device_id.to_owned(), None)))
            {
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
                .expect("BLE state mutex");
            state = next;
        }
    }
}

impl Transport for BleTransport {
    fn name(&self) -> &str {
        TRANSPORT_NAME
    }

    fn description(&self) -> &str {
        "Bluetooth Low Energy link to a paired phone"
    }

    fn availability(&self) -> TransportAvailability {
        match &self
            .shared
            .state
            .lock()
            .expect("BLE state mutex")
            .runtime_error
        {
            Some(error) => TransportAvailability::Unavailable {
                reason: error.clone(),
            },
            None => TransportAvailability::Ready,
        }
    }

    fn set_known_peers(&self, peers: HashMap<String, Vec<u8>>) {
        BleTransport::set_known_peers(self, peers);
    }

    fn connect(
        &self,
        device_id: &str,
        credential_id: &str,
    ) -> Result<Box<dyn SecureSession + Send>, String> {
        let session = self
            .take_session(device_id, credential_id, Duration::from_secs(10))
            .ok_or_else(|| {
                // Why this phone is not here belongs in the answer to "where
                // is this phone", not in whether Bluetooth works at all.
                let state = self.shared.state.lock().expect("BLE state mutex");
                match &state.last_link_error {
                    Some(reason) => format!(
                        "`{device_id}` is not connected over Bluetooth (the last link ended: {reason})"
                    ),
                    None => format!("`{device_id}` is not connected over Bluetooth"),
                }
            })?;
        Ok(Box::new(BleSession {
            channel: session.channel,
            outgoing: Some(session.outgoing),
            incoming: session.incoming,
            origin: session.origin,
            security: TransportSecurity {
                transport_name: TRANSPORT_NAME.into(),
                confidential: true,
                peer_authenticated: true,
                requires_network: false,
                proximity_signal: true,
                is_development: self.shared.is_development,
            },
            closed: false,
        }))
    }
}

struct BleSession {
    channel: SecureChannel,
    outgoing: Option<tokio_mpsc::UnboundedSender<Vec<u8>>>,
    incoming: Receiver<Vec<u8>>,
    origin: String,
    security: TransportSecurity,
    closed: bool,
}

impl SecureSession for BleSession {
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
        self.outgoing
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "BLE link closed"))?
            .send(record)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "BLE link closed"))
    }

    fn receive(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        let record = match self.incoming.recv_timeout(timeout) {
            Ok(record) => record,
            Err(RecvTimeoutError::Timeout) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "BLE receive timed out",
                ))
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "BLE link closed"))
            }
        };
        self.channel
            .open(&record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
    }

    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        self.outgoing = None;
        Ok(())
    }
}

async fn run_server(
    shared: Arc<Shared>,
    verifier_name: String,
    started: mpsc::SyncSender<Result<(), String>>,
) -> Result<(), String> {
    let setup = async {
        let session = bluer::Session::new()
            .await
            .map_err(|error| error.to_string())?;
        let adapter = session
            .default_adapter()
            .await
            .map_err(|error| error.to_string())?;
        adapter
            .set_powered(true)
            .await
            .map_err(|error| error.to_string())?;

        let hub = Arc::new(LinkHub::default());
        let write_hub = Arc::clone(&hub);
        let notify_hub = Arc::clone(&hub);
        let notify_shared = Arc::clone(&shared);
        let app = Application {
            services: vec![Service {
                uuid: SERVICE_UUID,
                primary: true,
                characteristics: vec![
                    Characteristic {
                        uuid: REQUEST_UUID,
                        write: Some(CharacteristicWrite {
                            write: true,
                            method: CharacteristicWriteMethod::Fun(Box::new(
                                move |value, request| {
                                    let hub = Arc::clone(&write_hub);
                                    async move {
                                        if request.offset != 0 {
                                            return Err(ReqError::InvalidOffset);
                                        }
                                        hub.write(value)
                                    }
                                    .boxed()
                                },
                            )),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: RESPONSE_UUID,
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            method: CharacteristicNotifyMethod::Fun(Box::new(move |notifier| {
                                let hub = Arc::clone(&notify_hub);
                                let shared = Arc::clone(&notify_shared);
                                async move {
                                    let Some((id, incoming)) = hub.begin() else {
                                        return;
                                    };
                                    tokio::spawn(async move {
                                        if let Err(error) =
                                            serve_link(notifier, incoming, Arc::clone(&shared))
                                                .await
                                        {
                                            shared
                                                .state
                                                .lock()
                                                .expect("BLE state mutex")
                                                .last_link_error = Some(error);
                                        }
                                        hub.finish(id);
                                    });
                                }
                                .boxed()
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let app_handle = adapter
            .serve_gatt_application(app)
            .await
            .map_err(|error| error.to_string())?;
        let advertisement = Advertisement {
            advertisement_type: AdvertisementType::Peripheral,
            service_uuids: [SERVICE_UUID].into_iter().collect(),
            discoverable: Some(true),
            local_name: Some(verifier_name),
            ..Default::default()
        };
        let advertisement_handle = adapter
            .advertise(advertisement)
            .await
            .map_err(|error| error.to_string())?;
        Ok::<_, String>((session, adapter, app_handle, advertisement_handle))
    }
    .await;

    match setup {
        Ok(handles) => {
            let _ = started.send(Ok(()));
            let _handles = handles;
            future::pending::<()>().await;
            Ok(())
        }
        Err(error) => {
            let _ = started.send(Err(error.clone()));
            Err(error)
        }
    }
}

async fn serve_link(
    mut notifier: CharacteristicNotifier,
    mut raw_incoming: tokio_mpsc::UnboundedReceiver<Vec<u8>>,
    shared: Arc<Shared>,
) -> Result<(), String> {
    let bootstrap = ServerBootstrap::new(
        phone_auth_verifier::random::session_id(),
        shared.verifier_id.clone(),
        String::new(),
        &shared.identity,
        phone_auth_verifier::verifier::now_ms(),
        phone_auth_session::DEFAULT_LIFETIME_MS,
    )
    .map_err(|error| error.to_string())?;
    let (pending, hello) = PendingServerHandshake::begin(bootstrap, &shared.identity)
        .map_err(|error| error.to_string())?;
    let mut encoder = BleFrameEncoder::new();
    notify_frame(&mut notifier, &mut encoder, &hello).await?;

    let mut decoder = BleFrameDecoder::default();
    let client_frame = timeout(
        HANDSHAKE_TIMEOUT,
        receive_frame(&mut raw_incoming, &mut decoder),
    )
    .await
    .map_err(|_| "BLE handshake timed out".to_owned())??;
    let claimed = peek_device_id(&client_frame)?;
    let identity_spki = shared
        .state
        .lock()
        .expect("BLE state mutex")
        .known_peers
        .get(&claimed)
        .cloned()
        .ok_or_else(|| format!("`{claimed}` is not paired"))?;
    let outcome = pending
        .finish(
            &client_frame,
            PeerExpectation::Paired {
                device_id: &claimed,
                identity_spki: &identity_spki,
            },
            TRANSPORT_NAME,
        )
        .map_err(|error| error.to_string())?;

    // Which of the phone's credentials this session carries, read before the
    // session is parked because the loop below is what would otherwise deliver
    // it — and by then the desktop may already have picked the wrong session.
    let mut channel = outcome.channel;
    let credential_id = match timeout(
        ATTACH_WINDOW,
        receive_frame(&mut raw_incoming, &mut decoder),
    )
    .await
    {
        Ok(record) => {
            let frame = channel.open(&record?).map_err(|error| error.to_string())?;
            // Anything else is a phone speaking out of turn: the desktop is the
            // side that asks. Refusing beats parking a session whose first
            // frame has already been read and discarded.
            if !SessionAttach::recognizes(&frame) {
                return Err("the phone sent something other than a session attach".to_owned());
            }
            Some(
                SessionAttach::decode(&frame)
                    .map_err(|error| error.to_string())?
                    .credential_id,
            )
        }
        // A phone too old to send one.
        Err(_) => None,
    };

    let (outgoing, mut outgoing_rx) = tokio_mpsc::unbounded_channel();
    let (incoming_tx, incoming) = mpsc::channel();
    {
        let mut state = shared.state.lock().expect("BLE state mutex");
        discard_stale(&mut state);
        state.sessions.insert(
            (outcome.peer_device_id, credential_id),
            ParkedSession {
                channel,
                outgoing,
                incoming,
                origin: format!("{TRANSPORT_NAME} • authenticated nearby phone"),
                parked_at: Instant::now(),
            },
        );
        state.last_link_error = None;
        shared.signal.notify_all();
    }

    loop {
        tokio::select! {
            chunk = raw_incoming.recv() => match chunk {
                Some(chunk) => {
                    if let Some(frame) = decoder.add_chunk(&chunk).map_err(|error| error.to_string())? {
                        if incoming_tx.send(frame).is_err() {
                            break;
                        }
                    }
                }
                None => break,
            },
            frame = outgoing_rx.recv() => match frame {
                Some(frame) => notify_frame(&mut notifier, &mut encoder, &frame).await?,
                None => break,
            },
        }
    }
    Ok(())
}

async fn receive_frame(
    incoming: &mut tokio_mpsc::UnboundedReceiver<Vec<u8>>,
    decoder: &mut BleFrameDecoder,
) -> Result<Vec<u8>, String> {
    while let Some(chunk) = incoming.recv().await {
        if let Some(frame) = decoder
            .add_chunk(&chunk)
            .map_err(|error| error.to_string())?
        {
            return Ok(frame);
        }
    }
    Err("BLE link closed during handshake".into())
}

async fn notify_frame(
    notifier: &mut CharacteristicNotifier,
    encoder: &mut BleFrameEncoder,
    frame: &[u8],
) -> Result<(), String> {
    for chunk in encoder
        .encode(frame, NOTIFICATION_BYTES)
        .map_err(|error| error.to_string())?
    {
        notifier
            .notify(chunk)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
