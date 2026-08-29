//! `phone-auth-ssh-agent` — an ssh-agent whose keys live on a phone.
//!
//! `SYS-02`. `ssh` talks to this over `SSH_AUTH_SOCK`; this talks to the
//! background agent over its IPC; the background agent talks to the phone.
//! Every signature costs an approval on the phone naming the account and,
//! where the client says, the destination.
//!
//! # Why a separate process
//!
//! The background agent has no business owning a socket that `ssh` connects
//! to. That socket is reachable by anything running as this user, which makes
//! it the most exposed surface in the project, and keeping it here means a
//! crash is a failed login rather than a phone that stops answering `sudo`.
//!
//! # Unix only, for now
//!
//! Windows OpenSSH uses a named pipe with its own security-descriptor rules.
//! Getting that wrong exposes the pipe to every process on the machine, so
//! this refuses to run there rather than half-implementing it.

fn main() -> std::process::ExitCode {
    let mut socket = None;
    let mut root = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--socket" => socket = args.next(),
            "--root" => root = args.next().map(std::path::PathBuf::from),
            "-h" | "--help" => {
                println!("{USAGE}");
                return std::process::ExitCode::SUCCESS;
            }
            other => {
                eprintln!("phone-auth-ssh-agent: unknown option `{other}`\n\n{USAGE}");
                return std::process::ExitCode::from(2);
            }
        }
    }

    let Some(socket) = socket else {
        eprintln!("phone-auth-ssh-agent: --socket <PATH> is required\n\n{USAGE}");
        return std::process::ExitCode::from(2);
    };

    match serve(&socket, root) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("phone-auth-ssh-agent: {error}");
            std::process::ExitCode::from(3)
        }
    }
}

const USAGE: &str = "\
phone-auth-ssh-agent — an ssh-agent whose keys live on your phone

USAGE:
    phone-auth-ssh-agent --socket <PATH> [--root <DIR>]

Then point ssh at it:

    export SSH_AUTH_SOCK=<PATH>
    ssh you@host

Every signature asks the phone, naming the account and — where your ssh is new
enough to send it — the host. Agent forwarding is refused unless it has been
allowed for that specific host.
";

#[cfg(unix)]
fn serve(socket: &str, root: Option<std::path::PathBuf>) -> std::io::Result<()> {
    unix::listen(socket, &phone_auth_agent::paths::Paths::resolve(root))
}

/// Refused rather than half-implemented. See the module header.
#[cfg(not(unix))]
fn serve(_socket: &str, _root: Option<std::path::PathBuf>) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows OpenSSH uses a named pipe with its own security-descriptor \
         rules; implementing it badly would expose the pipe to every process \
         on the machine, so it is refused rather than half-done",
    ))
}

/// Everything that exists only where there is a Unix domain socket.
///
/// Grouped rather than sprinkled with `cfg` attributes, so the platform split
/// is one boundary instead of nine and a Windows build compiles no dead code
/// rather than warning about it.
#[cfg(unix)]
mod unix {
    use std::io::{Read, Write};

    use phone_auth_agent::api::{SshSignParams, SshSignResult};
    use phone_auth_agent::client::AgentClient;
    use phone_auth_agent::paths::Paths;
    use phone_auth_agent::ssh_policy::{Prompt, SshPolicy};
    use phone_auth_agent::ssh_session::{SshBackend, SshFraming, SshSession};
    use phone_auth_protocol::encoding::from_hex;

    /// Talks to the background agent, which talks to the phone.
    struct IpcBackend {
        client: AgentClient,
    }

    impl SshBackend for IpcBackend {
        fn identities(&mut self) -> Vec<(Vec<u8>, String)> {
            // An empty list is what an unreachable agent looks like to `ssh`,
            // and that is the right answer: it falls through to its other keys
            // rather than failing the connection outright.
            let Ok(value) = self.client.call("ssh.identities", serde_json::json!({})) else {
                return Vec::new();
            };
            value["identities"]
                .as_array()
                .map(|identities| {
                    identities
                        .iter()
                        .filter_map(|identity| {
                            Some((
                                from_hex(identity["blob"].as_str()?).ok()?,
                                identity["comment"].as_str().unwrap_or_default().to_owned(),
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default()
        }

        fn sign(&mut self, _key_blob: &[u8], data: &[u8], prompt: &Prompt) -> Option<Vec<u8>> {
            // Printed here as well as shown on the phone. A prompt that appears
            // only on the phone is one people approve while looking at the
            // screen they typed into.
            eprintln!(
                "phone-auth-ssh-agent: approve on your phone — sign in as {} to {}{}",
                prompt.user,
                prompt
                    .destination
                    .as_deref()
                    .unwrap_or("a host this client did not name"),
                if prompt.first_time {
                    " (first time)"
                } else {
                    ""
                }
            );

            // Built as the IPC type rather than as loose JSON, so the base64
            // lives in one place. A second copy of that encoder is a second
            // chance to get its padding wrong.
            let params = serde_json::to_value(SshSignParams {
                data: data.to_vec(),
                destination: prompt.destination.clone().unwrap_or_default(),
                credential_id: None,
            })
            .ok()?;
            let response = self.client.call("ssh.sign", params).ok()?;
            Some(
                serde_json::from_value::<SshSignResult>(response)
                    .ok()?
                    .signature,
            )
        }
    }

    pub fn listen(socket: &str, paths: &Paths) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        // A stale socket from a crashed run would make binding fail and leave
        // the user deleting files by hand.
        let _ = std::fs::remove_file(socket);
        let listener = UnixListener::bind(socket)?;
        // The socket is the authority: anything that can connect can ask for a
        // signature. Narrowed before it is announced, because the window
        // between binding and tightening is the whole attack.
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;

        println!("phone-auth-ssh-agent: listening on {socket}");
        println!("phone-auth-ssh-agent: export SSH_AUTH_SOCK={socket}");

        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(client) = AgentClient::connect(paths) else {
                eprintln!("phone-auth-ssh-agent: the background agent is not running");
                continue;
            };
            // One session per connection. `session-bind` names the host for
            // the connection it arrived on, and sharing it across connections
            // would let one `ssh` approve against another's destination.
            let mut session = SshSession::new(IpcBackend { client }, SshPolicy::new());
            let mut framing = SshFraming::new();
            let mut buffer = [0u8; 4096];

            'connection: loop {
                let read = match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                // Framing failure is not recoverable: there is no
                // resynchronising a stream whose lengths are wrong.
                let Ok(messages) = framing.push(&buffer[..read]) else {
                    break;
                };
                for message in messages {
                    if stream.write_all(&session.handle(&message)).is_err() {
                        break 'connection;
                    }
                }
            }
        }
        Ok(())
    }
}
