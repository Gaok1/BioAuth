//! Blocking client for the agent's IPC surface.
//!
//! Used by the CLI, and by anything else that needs an authorization decision
//! without holding the pairing store itself.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::api::{ApiError, Call, Reply};
use crate::ipc::Endpoint;
use crate::paths::Paths;

/// How long to wait for the agent to answer.
///
/// Longer than the protocol's two-minute request ceiling, so a slow human
/// reaching for their phone is never mistaken for a dead agent.
const READ_TIMEOUT: Duration = Duration::from_secs(150);

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

        self.read_reply(id)
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
