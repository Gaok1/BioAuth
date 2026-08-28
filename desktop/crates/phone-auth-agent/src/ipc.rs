//! Local IPC surface.
//!
//! A loopback TCP listener carrying one JSON object per line. The port is
//! ephemeral and published, together with a random token, in a file only this
//! user account can read. Possession of the token is the whole authorisation
//! check: it proves the caller could read that file.
//!
//! Loopback TCP rather than a Unix socket or a named pipe because it behaves
//! identically on Linux, macOS and Windows, and the agent has to run on all
//! three without a platform abstraction layer for one small channel.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::json;

use phone_auth_verifier::encoding::to_hex;
use phone_auth_verifier::random;

use crate::api::{
    AuthorizeParams, Call, CancelWebAuthnParams, ConfirmPairingParams, Event, ForgetParams,
    LockerLockParams, LockerRekeyParams, LockerUnlockParams, RecentParams, Reply,
    SetPermissionsParams, VaultCopyParams, VaultCopyResult, VaultGenerateCopyParams,
    VaultListParams, WebAuthnParams,
};
use crate::clipboard;
use crate::password::{self, Policy};
use crate::paths::Paths;
use crate::secret_memory::SecretBuffer;
use crate::service::Service;

static WEBAUTHN_CANCELLATIONS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn webauthn_cancellations() -> &'static Mutex<HashMap<String, Instant>> {
    WEBAUTHN_CANCELLATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn take_webauthn_cancellation(request_id: &str) -> bool {
    webauthn_cancellations()
        .lock()
        .expect("cancellation mutex")
        .remove(request_id)
        .is_some()
}

fn cancel_webauthn(request_id: &str) -> bool {
    let mut cancellations = webauthn_cancellations().lock().expect("cancellation mutex");
    cancellations.retain(|_, created| created.elapsed() < Duration::from_secs(300));
    if cancellations.len() >= 128 {
        if let Some(oldest) = cancellations
            .iter()
            .min_by_key(|(_, created)| *created)
            .map(|(request_id, _)| request_id.clone())
        {
            cancellations.remove(&oldest);
        }
    }
    cancellations.insert(request_id.to_owned(), Instant::now());
    true
}

/// Contents of the endpoint file the UI and CLI read to find the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
    pub pid: u32,
    /// Identifies which agent run wrote this, so a client can notice a stale
    /// file left by a process that did not shut down cleanly.
    pub verifier_id: String,
}

impl Endpoint {
    pub fn read(paths: &Paths) -> io::Result<Self> {
        let bytes = std::fs::read(paths.endpoint_file())?;
        serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    fn write(&self, paths: &Paths) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        // Atomic as well as private. This file carries the IPC token, and a
        // client that read it half-written would look for the agent on port
        // zero rather than retry.
        crate::private_files::write_private(&paths.endpoint_file(), &json)
    }
}

/// Compares two tokens without an early exit on the first differing byte.
fn tokens_match(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Starts the listener and serves connections until the process ends.
pub fn serve(service: Arc<Mutex<Service>>, requested_port: u16) -> io::Result<()> {
    let token = to_hex(&random::bytes::<32>());
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, requested_port)))?;
    let port = listener.local_addr()?.port();

    let (paths, verifier_id) = {
        let service = service.lock().expect("service mutex");
        (service.paths().clone(), service.status().verifier_id)
    };

    let endpoint = Endpoint {
        port,
        token: token.clone(),
        pid: std::process::id(),
        verifier_id,
    };
    endpoint.write(&paths)?;

    println!("phone-auth-agent: listening on 127.0.0.1:{port}");
    println!(
        "phone-auth-agent: endpoint file {}",
        paths.endpoint_file().display()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let service = Arc::clone(&service);
                let token = token.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, service, &token) {
                        // A client hanging up mid-request is routine, so this
                        // is informational rather than an error path.
                        eprintln!("phone-auth-agent: connection ended: {error}");
                    }
                });
            }
            Err(error) => eprintln!("phone-auth-agent: accept failed: {error}"),
        }
    }
    Ok(())
}

/// Removes the endpoint file. Best effort: a stale file is survivable because
/// its token will not match a later run's.
pub fn clear_endpoint(paths: &Paths) {
    let _ = std::fs::remove_file(paths.endpoint_file());
}

fn handle_connection(
    stream: TcpStream,
    service: Arc<Mutex<Service>>,
    token: &str,
) -> io::Result<()> {
    let reader = BufReader::new(stream.try_clone()?);
    // Both the reply path and the event pump write to this socket, so writes
    // are serialised through one lock.
    let writer = Arc::new(Mutex::new(stream));

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let call: Call = match serde_json::from_str(&line) {
            Ok(call) => call,
            Err(error) => {
                write_line(&writer, &Reply::err(0, "bad-request", error.to_string()))?;
                continue;
            }
        };

        if !tokens_match(&call.token, token) {
            write_line(
                &writer,
                &Reply::err(call.id, "unauthorized", "invalid agent token"),
            )?;
            // A wrong token means the peer is not who the endpoint file was
            // written for. Do not keep the connection open for more attempts.
            return Ok(());
        }

        let reply = dispatch(&call, &service, &writer);
        write_line(&writer, &reply)?;
    }
    Ok(())
}

fn dispatch(call: &Call, service: &Arc<Mutex<Service>>, writer: &Arc<Mutex<TcpStream>>) -> Reply {
    let id = call.id;
    match call.method.as_str() {
        "status" => {
            let payload = service.lock().expect("service mutex").status();
            to_reply(id, &payload)
        }

        "devices.list" => {
            let devices = service.lock().expect("service mutex").devices();
            to_reply(id, &json!({ "devices": devices }))
        }

        "devices.forget" => match parse::<ForgetParams>(call) {
            Ok(params) => match service
                .lock()
                .expect("service mutex")
                .forget(&params.device_id)
            {
                Ok(()) => Reply::ok(id, json!({ "forgotten": params.device_id })),
                Err(error) => Reply::err(id, error.code, error.message),
            },
            Err(reply) => reply(id),
        },

        "devices.setPermissions" => match parse::<SetPermissionsParams>(call) {
            Ok(params) => {
                let result = service.lock().expect("service mutex").set_permissions(
                    &params.device_id,
                    &params.credential_id,
                    params.permissions,
                );
                match result {
                    Ok(()) => Reply::ok(id, json!({ "updated": true })),
                    Err(error) => Reply::err(id, error.code, error.message),
                }
            }
            Err(reply) => reply(id),
        },

        "pair.begin" => match service.lock().expect("service mutex").begin_pairing() {
            Ok(bootstrap) => to_reply(id, &bootstrap),
            Err(error) => Reply::err(id, error.code, error.message),
        },

        "pair.cancel" => {
            service.lock().expect("service mutex").cancel_pairing();
            Reply::ok(id, json!({ "cancelled": true }))
        }

        // Polled by the tray while a code is on screen. Returns null until a
        // phone has completed its handshake.
        "pair.pending" => {
            let pending = service.lock().expect("service mutex").pending_pairing();
            to_reply(id, &pending)
        }

        "pair.confirm" => match parse::<ConfirmPairingParams>(call) {
            Ok(params) => {
                let result = service
                    .lock()
                    .expect("service mutex")
                    .confirm_pairing(&params.verification_code, params.attempt_id.as_deref());
                match result {
                    Ok(()) => Reply::ok(id, json!({ "paired": true })),
                    Err(error) => Reply::err(id, error.code, error.message),
                }
            }
            Err(reply) => reply(id),
        },

        "audit.recent" => match parse::<RecentParams>(call) {
            Ok(params) => {
                let entries = service
                    .lock()
                    .expect("service mutex")
                    .audit_recent(params.limit);
                to_reply(id, &json!({ "entries": entries }))
            }
            Err(reply) => reply(id),
        },

        "authorize" => match parse::<AuthorizeParams>(call) {
            Ok(params) => {
                // The lock is held across the exchange so that the replay
                // guard and the pairing store cannot change underneath it.
                let result = service.lock().expect("service mutex").authorize(&params);
                match result {
                    Ok(result) => to_reply(id, &result),
                    Err(error) => Reply::err(id, error.code, error.message),
                }
            }
            Err(reply) => reply(id),
        },

        "webauthn.perform" => match parse::<WebAuthnParams>(call) {
            Ok(params) => {
                let result = service
                    .lock()
                    .expect("service mutex")
                    .perform_webauthn(&params);
                match result {
                    Ok(result) => to_reply(id, &result),
                    Err(error) => Reply::err(id, error.code, error.message),
                }
            }
            Err(reply) => reply(id),
        },

        // Deliberately does not acquire the service mutex: `webauthn.perform`
        // holds it while waiting for the phone, and cancellation must be able
        // to interrupt that wait from a second native-host connection.
        "webauthn.cancel" => match parse::<CancelWebAuthnParams>(call) {
            Ok(params) if !params.request_id.is_empty() && params.request_id.len() <= 64 => {
                Reply::ok(
                    id,
                    json!({ "cancelled": cancel_webauthn(&params.request_id) }),
                )
            }
            Ok(_) => Reply::err(id, "bad-request", "invalid WebAuthn request id"),
            Err(reply) => reply(id),
        },

        // The locker methods hold the service lock for the length of a file
        // operation. That is deliberate: two concurrent locks of the same file
        // would race over the same destination, and the phone can only answer
        // one prompt at a time anyway.
        "locker.lock" => match parse::<LockerLockParams>(call) {
            Ok(params) => {
                let result = service.lock().expect("service mutex").locker_lock(&params);
                match result {
                    Ok(result) => to_reply(id, &result),
                    Err(error) => Reply::err(id, error.code, error.message),
                }
            }
            Err(reply) => reply(id),
        },

        "locker.unlock" => match parse::<LockerUnlockParams>(call) {
            Ok(params) => {
                let result = service
                    .lock()
                    .expect("service mutex")
                    .locker_unlock(&params);
                match result {
                    Ok(result) => to_reply(id, &result),
                    Err(error) => Reply::err(id, error.code, error.message),
                }
            }
            Err(reply) => reply(id),
        },

        "locker.rekey" => match parse::<LockerRekeyParams>(call) {
            Ok(params) => {
                let result = service.lock().expect("service mutex").locker_rekey(&params);
                match result {
                    Ok(result) => to_reply(id, &result),
                    Err(error) => Reply::err(id, error.code, error.message),
                }
            }
            Err(reply) => reply(id),
        },

        "vault.list" => match parse::<VaultListParams>(call) {
            Ok(params) => {
                let result = service.lock().expect("service mutex").vault_list(&params);
                match result {
                    Ok(result) => to_reply(id, &result),
                    Err(error) => Reply::err(id, error.code, error.message),
                }
            }
            Err(reply) => reply(id),
        },

        // The secret goes from the phone into locked pages and then onto the
        // clipboard. It never becomes part of this reply: `VaultCopyResult`
        // has no field it could travel in.
        "vault.copy" => match parse::<VaultCopyParams>(call) {
            Ok(params) => {
                let result = service.lock().expect("service mutex").vault_copy(&params);
                match result {
                    Ok(result) => to_reply(id, &result),
                    Err(error) => Reply::err(id, error.code, error.message),
                }
            }
            Err(reply) => reply(id),
        },

        // Copies a password the agent just generated, for the case where there
        // is nothing stored yet. The clipboard path below is the same one
        // `vault.copy` uses for a fetched secret.
        "vault.generate-copy" => match parse::<VaultGenerateCopyParams>(call) {
            Ok(params) => vault_generate_copy(id, &params),
            Err(reply) => reply(id),
        },

        "subscribe" => {
            let receiver = service.lock().expect("service mutex").subscribe();
            let writer = Arc::clone(writer);
            thread::spawn(move || {
                for event in receiver {
                    if write_event(&writer, &event).is_err() {
                        break;
                    }
                }
            });
            Reply::ok(id, json!({ "subscribed": true }))
        }

        other => Reply::err(id, "unknown-method", format!("unknown method `{other}`")),
    }
}

/// Generates a password and copies it, without the plaintext crossing IPC.
///
/// The generated password lives in a `Zeroizing<String>` for exactly as long as
/// it takes to copy it into locked pages, and both are wiped when this function
/// returns. What goes back to the caller describes the copy.
fn vault_generate_copy(id: u64, params: &VaultGenerateCopyParams) -> Reply {
    let defaults = Policy::default();
    let policy = Policy {
        length: params.length.unwrap_or(defaults.length),
        lowercase: params.lowercase.unwrap_or(defaults.lowercase),
        uppercase: params.uppercase.unwrap_or(defaults.uppercase),
        digits: params.digits.unwrap_or(defaults.digits),
        symbols: params.symbols.unwrap_or(defaults.symbols),
    };

    let generated = match password::generate(policy) {
        Ok(generated) => generated,
        Err(error) => return Reply::err(id, "bad-params", error.to_string()),
    };
    let secret = SecretBuffer::from_slice(generated.as_bytes());
    drop(generated);

    let ttl = params
        .clear_after_ms
        .map_or(clipboard::DEFAULT_TTL, Duration::from_millis);

    match clipboard::copy_secret(&secret, ttl) {
        Ok(outcome) => to_reply(
            id,
            &VaultCopyResult {
                length: secret.len(),
                clears_at_ms: outcome.clears_at_ms,
                history_excluded: outcome.history_excluded,
                cloud_excluded: outcome.cloud_excluded,
                memory_locked: secret.is_locked(),
            },
        ),
        // Mapped exactly as `vault.copy` maps it. A timeout outside the
        // accepted range is the caller's mistake, and calling it
        // `clipboard-unavailable` here and `bad-params` there would leave two
        // adjacent methods disagreeing about the same failure.
        Err(error) => {
            let error = crate::service::clipboard_error(error);
            Reply::err(id, error.code, error.message)
        }
    }
}

/// Parses params, returning a closure that builds the error reply so the call
/// site keeps its `id` in one place.
fn parse<T: serde::de::DeserializeOwned>(call: &Call) -> Result<T, impl Fn(u64) -> Reply> {
    serde_json::from_value::<T>(call.params.clone()).map_err(|error| {
        let message = error.to_string();
        move |id| Reply::err(id, "bad-params", message.clone())
    })
}

fn to_reply<T: Serialize>(id: u64, payload: &T) -> Reply {
    match serde_json::to_value(payload) {
        Ok(value) => Reply::ok(id, value),
        Err(error) => Reply::err(id, "internal", error.to_string()),
    }
}

fn write_line<T: Serialize>(writer: &Arc<Mutex<TcpStream>>, message: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(message)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    line.push(b'\n');
    let mut stream = writer.lock().expect("writer mutex");
    stream.write_all(&line)?;
    stream.flush()
}

fn write_event(writer: &Arc<Mutex<TcpStream>>, event: &Event) -> io::Result<()> {
    write_line(writer, event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_match_only_when_identical() {
        assert!(tokens_match("abc123", "abc123"));
        assert!(!tokens_match("abc123", "abc124"));
        assert!(!tokens_match("abc123", "abc12"));
        assert!(!tokens_match("", "a"));
        assert!(tokens_match("", ""));
    }

    #[test]
    fn an_endpoint_round_trips_through_json() {
        let endpoint = Endpoint {
            port: 51234,
            token: "deadbeef".into(),
            pid: 42,
            verifier_id: "abc".into(),
        };
        let json = serde_json::to_string(&endpoint).expect("serialize");
        let parsed: Endpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.port, endpoint.port);
        assert_eq!(parsed.token, endpoint.token);
        assert_eq!(parsed.verifier_id, endpoint.verifier_id);
    }

    #[test]
    fn webauthn_cancellation_is_bounded_and_consumed_once() {
        let request_id = format!("cancel-test-{}", std::process::id());
        assert!(cancel_webauthn(&request_id));
        assert!(take_webauthn_cancellation(&request_id));
        assert!(!take_webauthn_cancellation(&request_id));
    }
}

/// Two clients on one agent, which is the normal case: the tray sits
/// subscribed for the whole session while the CLI connects, asks one thing and
/// leaves.
///
/// These drive a real listener over loopback rather than calling `dispatch`
/// directly. The bugs this is looking for — a reply going to the wrong socket,
/// an event line being mistaken for a reply, one client's disconnect taking the
/// other down — all live in the socket and threading layer that a direct
/// `dispatch` call skips entirely.
#[cfg(test)]
mod concurrent_client_tests {
    use super::*;
    use crate::client::AgentClient;
    use crate::config::AgentConfig;

    /// Serves `service` on an ephemeral port and returns once the endpoint file
    /// is readable, so a client can connect without racing the listener.
    ///
    /// The serving thread is deliberately left running: `serve` only returns on
    /// listener failure, and the test process exiting is what stops it.
    fn start_agent(name: &str) -> (Arc<Mutex<Service>>, Paths) {
        let root = std::env::temp_dir().join(format!(
            "phone-auth-ipc-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let paths = Paths::resolve(Some(root));
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        std::fs::create_dir_all(&paths.data_dir).expect("data dir");
        clear_endpoint(&paths);

        let config = AgentConfig::load_or_create(&paths.config_file()).expect("config");
        let service = Arc::new(Mutex::new(
            Service::new(config, paths.clone(), None, Vec::new(), false).expect("service"),
        ));

        let served = Arc::clone(&service);
        thread::spawn(move || {
            let _ = serve(served, 0);
        });

        wait_until("the agent to publish its endpoint", || {
            Endpoint::read(&paths).is_ok()
        });
        (service, paths)
    }

    /// Polls rather than sleeping a fixed amount: the listener usually comes up
    /// in microseconds, and a fixed sleep would be either flaky or slow.
    fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if ready() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("timed out waiting for {what}");
    }

    fn subscriber_count(service: &Arc<Mutex<Service>>) -> usize {
        service
            .lock()
            .expect("service mutex")
            .subscriber_count_for_test()
    }

    fn broadcast(service: &Arc<Mutex<Service>>) {
        service
            .lock()
            .expect("service mutex")
            .broadcast_for_test(Event::DevicesChanged);
    }

    #[test]
    fn two_clients_each_get_their_own_reply() {
        let (service, paths) = start_agent("two-clients");
        let mut tray = AgentClient::connect(&paths).expect("tray connects");
        let mut cli = AgentClient::connect(&paths).expect("cli connects");

        let from_tray = tray.call("status", json!({})).expect("tray status");
        let from_cli = cli.call("devices.list", json!({})).expect("cli devices");

        // Interleaved on one service, so the answers must still be the ones
        // each client asked for and not each other's.
        assert!(from_tray.get("verifierId").is_some());
        assert!(from_tray.get("devices").is_none());
        assert!(from_cli.get("devices").is_some());

        let expected = service.lock().expect("service mutex").status().verifier_id;
        assert_eq!(from_tray["verifierId"], serde_json::json!(expected));
    }

    #[test]
    fn an_event_reaches_every_subscribed_client() {
        let (service, paths) = start_agent("fanout");
        let mut tray = AgentClient::connect(&paths).expect("tray connects");
        let mut second = AgentClient::connect(&paths).expect("second connects");

        tray.call("subscribe", json!({})).expect("tray subscribes");
        second
            .call("subscribe", json!({}))
            .expect("second subscribes");
        wait_until("both subscriptions to register", || {
            subscriber_count(&service) == 2
        });

        broadcast(&service);

        // A call issued after the event forces each client to read past the
        // event line to find its reply. If the pushes had gone to one socket
        // only, or been miscounted as replies, this is where it shows.
        assert!(tray.call("status", json!({})).is_ok());
        assert!(second.call("status", json!({})).is_ok());
        assert_eq!(subscriber_count(&service), 2);
    }

    /// The reason `read_reply` skips lines without a matching id. A subscribed
    /// client has events arriving whenever the agent feels like it, including
    /// in the middle of a request it is waiting on.
    #[test]
    fn events_arriving_mid_request_do_not_become_the_reply() {
        let (service, paths) = start_agent("interleaved");
        let mut client = AgentClient::connect(&paths).expect("connects");
        client.call("subscribe", json!({})).expect("subscribes");
        wait_until("the subscription to register", || {
            subscriber_count(&service) == 1
        });

        for _ in 0..16 {
            broadcast(&service);
        }

        // Each reply must be the one for the call just made, in order, with a
        // backlog of event lines sitting in the socket ahead of it.
        for _ in 0..4 {
            let status = client.call("status", json!({})).expect("status");
            assert!(status.get("verifierId").is_some());
            broadcast(&service);
        }
    }

    #[test]
    fn one_client_leaving_does_not_disturb_the_other() {
        let (service, paths) = start_agent("disconnect");
        let mut staying = AgentClient::connect(&paths).expect("staying connects");
        let mut leaving = AgentClient::connect(&paths).expect("leaving connects");

        staying.call("subscribe", json!({})).expect("subscribe");
        leaving.call("subscribe", json!({})).expect("subscribe");
        wait_until("both subscriptions to register", || {
            subscriber_count(&service) == 2
        });

        drop(leaving);

        // The pump only notices the closed socket when it tries to write, so
        // the drop alone proves nothing: it takes a broadcast to prune.
        wait_until("the departed client to be pruned", || {
            broadcast(&service);
            subscriber_count(&service) == 1
        });

        assert!(staying.call("status", json!({})).is_ok());
    }

    /// A wrong token must not merely fail the call: the connection is with
    /// someone who could not read the endpoint file, so it ends.
    #[test]
    fn a_client_with_the_wrong_token_is_disconnected_without_disturbing_the_others() {
        let (_service, paths) = start_agent("bad-token");
        let mut honest = AgentClient::connect(&paths).expect("honest connects");
        let endpoint = Endpoint::read(&paths).expect("endpoint");

        let mut impostor =
            AgentClient::connect_to(endpoint.port, "not-the-token").expect("impostor connects");
        let refused = impostor.call("status", json!({})).expect_err("must refuse");
        assert_eq!(refused.code(), "unauthorized");

        // Second call on the same connection: the agent hung up after the
        // first, so this fails as a dead socket rather than as another reply.
        assert!(impostor.call("status", json!({})).is_err());

        assert!(honest.call("status", json!({})).is_ok());
    }

    /// The claim the whole module rests on: the password reaches the clipboard
    /// without reaching the caller.
    ///
    /// Asserting on the shape of `VaultCopyResult` would only prove the struct
    /// has no password field. This goes through the real socket, reads back
    /// what actually landed on the clipboard, and looks for it in the raw reply
    /// bytes — so adding a field, a debug echo or a stray error message
    /// carrying the plaintext fails here.
    #[cfg(windows)]
    #[test]
    fn a_generated_password_reaches_the_clipboard_but_not_the_caller() {
        let _guard = crate::clipboard::test_lock();
        let (_service, paths) = start_agent("vault-copy");
        let mut client = AgentClient::connect(&paths).expect("client");

        let result = client
            .call("vault.generate-copy", json!({ "clearAfterMs": 5000 }))
            .expect("generate-copy");

        let copied = crate::clipboard::read_for_test().expect("clipboard holds the password");
        assert_eq!(copied.chars().count(), 20, "default policy length");
        assert_eq!(
            result["length"].as_u64(),
            Some(20),
            "the reply reports the length"
        );
        assert!(result["clearsAtMs"].as_i64().unwrap_or(0) > 0);
        assert_eq!(result["historyExcluded"].as_bool(), Some(true));
        assert_eq!(result["cloudExcluded"].as_bool(), Some(true));

        let serialised = serde_json::to_string(&result).expect("serialise reply");
        assert!(
            !serialised.contains(&copied),
            "the generated password crossed the IPC boundary"
        );

        crate::clipboard::clear_now().expect("clear");
    }

    /// A policy no password can satisfy must come back as a refusal, not as an
    /// agent that loops forever holding the service mutex.
    #[test]
    fn an_impossible_password_policy_is_refused_over_ipc() {
        let (_service, paths) = start_agent("vault-copy-policy");
        let mut client = AgentClient::connect(&paths).expect("client");

        let refused = client.call(
            "vault.generate-copy",
            json!({ "lowercase": false, "uppercase": false, "digits": false, "symbols": false }),
        );

        assert!(refused.is_err(), "an empty alphabet must be refused");
    }

    /// With no phone paired there is no vault, and both methods have to say so.
    ///
    /// This is thin on purpose — the exchange itself is covered in
    /// `vault::tests` against a scripted session. What it does prove is that
    /// the two methods are reachable over the real socket and answer with a
    /// refusal, rather than being unknown methods or an empty success.
    #[test]
    fn the_vault_methods_refuse_when_no_phone_is_paired() {
        let (_service, paths) = start_agent("vault-unpaired");
        let mut client = AgentClient::connect(&paths).expect("client");

        for (method, params) in [
            ("vault.list", json!({})),
            (
                "vault.copy",
                json!({ "itemId": "item-1", "expectedRevision": 1 }),
            ),
        ] {
            let refused = client.call(method, params).expect_err("must refuse");
            assert_eq!(refused.code(), "not-paired", "{method}");
        }
    }

    /// `vault.copy` names the revision it believes it is copying, so leaving it
    /// out is a bad request rather than a copy of whatever the phone has.
    #[test]
    fn a_copy_without_an_expected_revision_is_refused() {
        let (_service, paths) = start_agent("vault-copy-revision");
        let mut client = AgentClient::connect(&paths).expect("client");

        // `bad-params`, not `not-paired`: the field is missing, so this is
        // refused while parsing, before any credential is looked up. Asserting
        // only `is_err()` would pass even if the field became optional.
        let refused = client
            .call("vault.copy", json!({ "itemId": "item-1" }))
            .expect_err("a copy with no revision must be refused");
        assert_eq!(refused.code(), "bad-params");
    }
}
