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

use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde::{Deserialize, Serialize};
use serde_json::json;

use phone_auth_verifier::encoding::to_hex;
use phone_auth_verifier::random;

use crate::api::{
    AuthorizeParams, Call, ConfirmPairingParams, Event, ForgetParams, RecentParams, Reply,
    SetPermissionsParams, WebAuthnParams,
};
use crate::paths::Paths;
use crate::service::Service;

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
        std::fs::create_dir_all(&paths.runtime_dir)?;
        let path = paths.endpoint_file();
        let json = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        std::fs::write(&path, json)?;
        restrict(&path)
    }
}

#[cfg(unix)]
fn restrict(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) -> io::Result<()> {
    Ok(())
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
}
