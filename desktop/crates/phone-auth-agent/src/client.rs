//! Blocking client for the agent's IPC surface.
//!
//! Used by the CLI, and by anything else that needs an authorization decision
//! without holding the pairing store itself.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::Value;

use phone_auth_protocol::vault::MAX_PAGE_ITEMS;

use crate::api::{ApiError, Call, Reply};
use crate::ipc::Endpoint;
use crate::paths::Paths;
use crate::vault::MAX_ITEMS;

/// How long to wait for the agent to answer.
///
/// Longer than the protocol's two-minute request ceiling, so a slow human
/// reaching for their phone is never mistaken for a dead agent.
const READ_TIMEOUT: Duration = Duration::from_secs(150);

/// The same, for a call that walks the vault a page at a time.
///
/// [`READ_TIMEOUT`] is justified by the ceiling on *one* request, and a
/// listing stopped being one request when the walk became one session per
/// page: the phone answers a frame and closes, so the agent dials, shakes
/// hands and hangs up once for every thirty-two items. Over BLE a dial is
/// seconds rather than milliseconds, and a large vault ran past a hundred and
/// fifty of them -- reporting an agent that was in fact working, on the one
/// operation that raises no prompt for the phone's owner to have seen.
///
/// Derived from what the protocol allows rather than picked: the most pages a
/// vault can have, times a budget for each. That per-page budget is a guess
/// until somebody measures a real handset over BLE; it is the number to revise
/// first if a big listing still gives up early.
const WALK_TIMEOUT: Duration = {
    let pages = MAX_ITEMS.div_ceil(MAX_PAGE_ITEMS) as u64;
    Duration::from_secs(pages * PER_PAGE_BUDGET.as_secs())
};

/// Dial, handshake, one page, hang up. Unmeasured; see [`WALK_TIMEOUT`].
const PER_PAGE_BUDGET: Duration = Duration::from_secs(4);

#[derive(Debug)]
pub enum ClientError {
    /// No endpoint file: the agent is probably not running.
    NotRunning(io::Error),
    Io(io::Error),
    Protocol(String),
    /// The agent answered with a failure. `code` is stable; see
    /// [`crate::service`] for the vocabulary.
    Agent(ApiError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunning(error) => {
                write!(f, "the agent does not appear to be running ({error})")
            }
            Self::Io(error) => write!(f, "agent connection failed: {error}"),
            Self::Protocol(message) => write!(f, "unexpected agent reply: {message}"),
            Self::Agent(error) => write!(f, "{}", error.message),
        }
    }
}

impl std::error::Error for ClientError {}

impl ClientError {
    /// The agent's stable error code, when the failure came from the agent.
    pub fn code(&self) -> &str {
        match self {
            Self::NotRunning(_) => "not-running",
            Self::Io(_) => "io",
            Self::Protocol(_) => "protocol",
            Self::Agent(error) => &error.code,
        }
    }
}

pub struct AgentClient {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    token: String,
    next_id: u64,
}

/// Whether this method pages through the vault instead of asking once.
///
/// `vault.fill` walks and then fetches, so it is a walk plus one request.
fn walks_the_vault(method: &str) -> bool {
    matches!(method, "vault.list" | "vault.fill")
}

impl AgentClient {
    /// Connects using the endpoint file under `paths`.
    pub fn connect(paths: &Paths) -> Result<Self, ClientError> {
        let endpoint = Endpoint::read(paths).map_err(ClientError::NotRunning)?;
        Self::connect_to(endpoint.port, &endpoint.token)
    }

    pub fn connect_to(port: u16, token: &str) -> Result<Self, ClientError> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let stream = TcpStream::connect(address).map_err(ClientError::NotRunning)?;
        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(ClientError::Io)?;
        let reader = BufReader::new(stream.try_clone().map_err(ClientError::Io)?);

        Ok(Self {
            stream,
            reader,
            token: token.to_owned(),
            next_id: 1,
        })
    }

    /// Issues one call and returns its result payload.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;

        let call = Call {
            id,
            token: self.token.clone(),
            method: method.to_owned(),
            params,
        };
        let mut line =
            serde_json::to_vec(&call).map_err(|error| ClientError::Protocol(error.to_string()))?;
        line.push(b'\n');

        self.stream.write_all(&line).map_err(ClientError::Io)?;
        self.stream.flush().map_err(ClientError::Io)?;

        // Set per call, not once at connect: what the wait has to outlast
        // depends on whether this method talks to the phone once or once per
        // page. Restored afterwards so one listing does not leave every later
        // call on this connection waiting ten minutes on a dead agent.
        let wait = if walks_the_vault(method) {
            WALK_TIMEOUT
        } else {
            READ_TIMEOUT
        };
        self.stream
            .set_read_timeout(Some(wait))
            .map_err(ClientError::Io)?;
        let answered = self.read_reply(id);
        let _ = self.stream.set_read_timeout(Some(READ_TIMEOUT));
        answered
    }

    /// Reads lines until the reply to `id` arrives, skipping event pushes.
    fn read_reply(&mut self, id: u64) -> Result<Value, ClientError> {
        loop {
            let mut line = String::new();
            let read = self.reader.read_line(&mut line).map_err(ClientError::Io)?;
            if read == 0 {
                return Err(ClientError::Protocol(
                    "the agent closed the connection".into(),
                ));
            }
            if line.trim().is_empty() {
                continue;
            }

            let value: Value = serde_json::from_str(&line)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            // Event lines carry no `id`; skip anything that is not our reply.
            if value.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }

            let reply: Reply = serde_json::from_value(value)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            return match (reply.ok, reply.result, reply.error) {
                (true, Some(result), _) => Ok(result),
                (_, _, Some(error)) => Err(ClientError::Agent(error)),
                _ => Err(ClientError::Protocol("reply had no result".into())),
            };
        }
    }

    /// Issues a call and deserializes the result.
    pub fn call_typed<T: DeserializeOwned>(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<T, ClientError> {
        let value = self.call(method, params)?;
        serde_json::from_value(value).map_err(|error| ClientError::Protocol(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ordering the walk timeout exists for.
    ///
    /// A listing is a session per page, so waiting on it with the ceiling for
    /// one request gave up on a large vault while the agent was still working.
    #[test]
    fn a_walk_is_waited_on_longer_than_one_request() {
        assert!(WALK_TIMEOUT > READ_TIMEOUT);
        assert!(walks_the_vault("vault.list"));
        assert!(walks_the_vault("vault.fill"));
        assert!(
            !walks_the_vault("vault.copy"),
            "copy is one request and must not wait like a walk"
        );
    }
}
