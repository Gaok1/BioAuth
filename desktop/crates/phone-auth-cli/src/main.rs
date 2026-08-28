//! `phone-auth` — the command line face of the agent.
//!
//! Its most important job is `phone-auth authorize`, which PAM runs through
//! `pam_exec`. That makes the exit status a security interface: PAM treats
//! any zero exit as success, so every path that is not a verified grant must
//! return non-zero. There is no "unknown" exit code that could be read as a
//! pass.

use std::process::ExitCode;

use serde_json::{json, Value};

use phone_auth_agent::client::AgentClient;
use phone_auth_agent::paths::Paths;

/// Verified grant.
const EXIT_GRANTED: u8 = 0;
/// The user declined, policy refused, or the request expired. An ordinary,
/// expected "no".
const EXIT_DENIED: u8 = 1;
/// The agent could not be reached, or something failed before a decision.
/// Distinct from a denial so that PAM stacks and scripts can tell an outage
/// from a refusal.
const EXIT_UNAVAILABLE: u8 = 3;
/// The command line itself was wrong.
const EXIT_USAGE: u8 = 2;

const USAGE: &str = "\
phone-auth — ask a paired phone to authorize something

USAGE:
    phone-auth <COMMAND> [OPTIONS]

COMMANDS:
    status                     Show the agent, paired phones and transports
    devices                    List paired phones and their permissions
    forget --device <ID>       Remove a pairing
    pair                       Print a pairing bootstrap for the phone to scan
    history [--limit <N>]      Show recent authorization decisions
    authorize --service <S> --action <A> --resource <R> --user <U>
                               Ask for an authorization and exit 0 only if it
                               was granted

    locker lock <FILE> --recovery-out <FILE>
                               Encrypt a file. The phone wraps the key; the
                               recovery code is written to --recovery-out and
                               shown nowhere else. The plaintext is removed
                               once the container is written and verified.
    locker unlock <FILE>       Decrypt a container with the phone
    locker unlock <FILE> --recovery-file <FILE>
                               Decrypt with the offline recovery code. Runs
                               here, without the agent and without a phone.
    locker status <FILE>       Describe a container. Needs no key and no agent.
    locker rekey <FILE>        Bind a container to this phone's current key

OPTIONS:
    --root <DIR>               Override the agent's config/data/runtime root
    --credential <ID>          Choose which paired credential to use
    --recovery-out <FILE>      Where to write a new recovery code
    --recovery-file <FILE>     Read a recovery code from this file
    --into <DIR>               Where to restore an unlocked file
    --keep-original            Leave the plaintext in place after locking
    --keep-container           Leave the container in place after unlocking
    --new-recovery-code        Issue a new recovery code, retiring the old one
    --json                     Emit raw JSON instead of formatted text
    -h, --help                 Show this message

EXIT CODES:
    0  granted
    1  denied, declined, expired or refused by policy
    2  usage error
    3  agent unreachable or failed before deciding
";

struct Cli {
    command: String,
    /// Positional arguments after the command, in order. Only the locker
    /// subcommands use them: `locker unlock <FILE>` is two of these.
    args: Vec<String>,
    root: Option<std::path::PathBuf>,
    service: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    user: Option<String>,
    credential: Option<String>,
    device: Option<String>,
    limit: Option<usize>,
    recovery_out: Option<String>,
    recovery_file: Option<String>,
    into: Option<String>,
    keep_original: bool,
    keep_container: bool,
    new_recovery_code: bool,
    json: bool,
    help: bool,
}

fn parse() -> Result<Cli, String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_owned());
    let mut cli = Cli {
        command,
        args: Vec::new(),
        root: None,
        service: None,
        action: None,
        resource: None,
        user: None,
        credential: None,
        device: None,
        limit: None,
        recovery_out: None,
        recovery_file: None,
        into: None,
        keep_original: false,
        keep_container: false,
        new_recovery_code: false,
        json: false,
        help: false,
    };

    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or(format!("`{flag}` needs a value"));
        match flag.as_str() {
            "--root" => cli.root = Some(std::path::PathBuf::from(value()?)),
            "--service" => cli.service = Some(value()?),
            "--action" => cli.action = Some(value()?),
            "--resource" => cli.resource = Some(value()?),
            "--user" => cli.user = Some(value()?),
            "--credential" => cli.credential = Some(value()?),
            "--device" => cli.device = Some(value()?),
            "--limit" => {
                cli.limit = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--limit must be a number".to_owned())?,
                )
            }
            "--recovery-out" => cli.recovery_out = Some(value()?),
            "--recovery-file" => cli.recovery_file = Some(value()?),
            "--into" => cli.into = Some(value()?),
            "--keep-original" => cli.keep_original = true,
            "--keep-container" => cli.keep_container = true,
            "--new-recovery-code" => cli.new_recovery_code = true,
            "--json" => cli.json = true,
            "-h" | "--help" => cli.help = true,
            other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
            positional => cli.args.push(positional.to_owned()),
        }
    }
    Ok(cli)
}

fn main() -> ExitCode {
    let cli = match parse() {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("phone-auth: {error}\n\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if cli.help || cli.command == "help" || cli.command == "--help" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    ExitCode::from(run(cli))
}

fn run(cli: Cli) -> u8 {
    // Two locker commands deliberately never touch the agent. Reading a
    // container's header needs no key, and unlocking with a recovery code must
    // work on a machine where the agent is not running and the phone is gone —
    // that is the entire reason the recovery code exists.
    if cli.command == "locker" {
        if let Some(exit) = locker_without_the_agent(&cli) {
            return exit;
        }
    }

    let paths = Paths::resolve(cli.root.clone());
    let mut client = match AgentClient::connect(&paths) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("phone-auth: {error}");
            eprintln!("phone-auth: start it with `phone-auth-agent`");
            return EXIT_UNAVAILABLE;
        }
    };

    match cli.command.as_str() {
        "status" => simple(&mut client, "status", json!({}), cli.json, print_status),
        "devices" => simple(
            &mut client,
            "devices.list",
            json!({}),
            cli.json,
            print_devices,
        ),
        "pair" => simple(
            &mut client,
            "pair.begin",
            json!({}),
            cli.json,
            print_pairing,
        ),
        "history" => {
            let params = json!({ "limit": cli.limit.unwrap_or(20) });
            simple(&mut client, "audit.recent", params, cli.json, print_history)
        }
        "forget" => match cli.device {
            Some(device) => simple(
                &mut client,
                "devices.forget",
                json!({ "deviceId": device }),
                cli.json,
                |value| println!("forgot {}", value["forgotten"].as_str().unwrap_or("?")),
            ),
            None => {
                eprintln!("phone-auth: forget needs --device <ID>");
                EXIT_USAGE
            }
        },
        "authorize" => authorize(&mut client, &cli),
        "locker" => locker(&mut client, &cli),
        other => {
            eprintln!("phone-auth: unknown command `{other}`\n\n{USAGE}");
            EXIT_USAGE
        }
    }
}

/// Runs a read-only command.
fn simple(
    client: &mut AgentClient,
    method: &str,
    params: Value,
    as_json: bool,
    print: impl Fn(&Value),
) -> u8 {
    match client.call(method, params) {
        Ok(value) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
            } else {
                print(&value);
            }
            EXIT_GRANTED
        }
        Err(error) => {
            eprintln!("phone-auth: {error}");
            EXIT_UNAVAILABLE
        }
    }
}

fn authorize(client: &mut AgentClient, cli: &Cli) -> u8 {
    let (Some(service), Some(action), Some(resource), Some(user)) = (
        cli.service.as_ref(),
        cli.action.as_ref(),
        cli.resource.as_ref(),
        cli.user.as_ref(),
    ) else {
        eprintln!("phone-auth: authorize needs --service, --action, --resource and --user");
        return EXIT_USAGE;
    };

    let mut params = json!({
        "service": service,
        "action": action,
        "resource": resource,
        "user": user,
    });
    if let Some(credential) = &cli.credential {
        params["credentialId"] = json!(credential);
    }

    match client.call("authorize", params) {
        Ok(value) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
            } else {
                let device = value["deviceName"].as_str().unwrap_or("phone");
                println!("granted by {device}");
                if value["development"].as_bool().unwrap_or(false) {
                    eprintln!(
                        "phone-auth: WARNING — this was signed by the development simulator, \
                         not by a phone"
                    );
                }
            }
            // Trust the agent's own verdict rather than the presence of a
            // reply: a malformed success payload must not become an exit 0.
            if value["granted"].as_bool() == Some(true) {
                EXIT_GRANTED
            } else {
                EXIT_DENIED
            }
        }
        Err(error) => {
            eprintln!("phone-auth: {error}");
            match error.code() {
                // A real "no" from the user or from policy.
                "declined" | "policy-denied" | "expired" | "not-paired" | "replayed"
                | "bad-signature" | "response-mismatch" | "session-mismatch" => EXIT_DENIED,
                _ => EXIT_UNAVAILABLE,
            }
        }
    }
}

/// Handles the locker subcommands that must work with no agent at all.
///
/// Returns `None` when the command needs the phone after all, so the caller
/// goes on to connect.
fn locker_without_the_agent(cli: &Cli) -> Option<u8> {
    let action = cli.args.first().map(String::as_str)?;
    let target = cli.args.get(1).map(std::path::PathBuf::from);

    match (action, target) {
        ("status", Some(path)) => Some(locker_status(&path, cli.json)),
        ("unlock", Some(path)) if cli.recovery_file.is_some() => Some(locker_recover(&path, cli)),
        _ => None,
    }
}

fn locker_status(path: &std::path::Path, as_json: bool) -> u8 {
    let info = match phone_auth_locker::inspect(path) {
        Ok(info) => info,
        Err(error) => {
            eprintln!("phone-auth: {error}");
            return EXIT_UNAVAILABLE;
        }
    };
    let wrappers: Vec<Value> = info
        .wrappers
        .iter()
        .map(|wrapper| json!({ "kind": wrapper.kind.label(), "id": wrapper.id }))
        .collect();

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "containerVersion": info.container_version,
                "plaintextLen": info.plaintext_len,
                "chunkSize": info.chunk_size,
                "chunkCount": info.chunk_count,
                "wrappers": wrappers,
            }))
            .unwrap_or_default()
        );
        return EXIT_GRANTED;
    }

    println!("container  version {}", info.container_version);
    println!(
        "contents   {} bytes in {} chunks",
        info.plaintext_len, info.chunk_count
    );
    println!("\nways in");
    for wrapper in &info.wrappers {
        match wrapper.kind {
            phone_auth_locker::WrapperKind::Phone => {
                println!("  phone      credential {}", wrapper.id)
            }
            phone_auth_locker::WrapperKind::Recovery => println!("  recovery   offline code"),
        }
    }
    if !info
        .wrappers
        .iter()
        .any(|wrapper| wrapper.kind == phone_auth_locker::WrapperKind::Recovery)
    {
        println!("\nWARNING — this container has no recovery wrapper. Losing the phone loses it.");
    }
    EXIT_GRANTED
}

/// Unlocks with the offline recovery code, in this process.
fn locker_recover(path: &std::path::Path, cli: &Cli) -> u8 {
    let code_file = cli.recovery_file.as_ref().expect("checked by the caller");
    let code = match std::fs::read_to_string(code_file) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("phone-auth: cannot read {code_file}: {error}");
            return EXIT_UNAVAILABLE;
        }
    };
    let key = match phone_auth_locker::parse_recovery_code(&code) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("phone-auth: {error}");
            return EXIT_DENIED;
        }
    };

    let into = cli.into.as_ref().map(std::path::PathBuf::from);
    match phone_auth_locker::unlock_file(
        path,
        into.as_deref(),
        !cli.keep_container,
        phone_auth_locker::UnlockKey::Recovery(&key),
    ) {
        Ok(outcome) => {
            println!(
                "restored {} ({} bytes)",
                outcome.restored.display(),
                outcome.plaintext_len
            );
            EXIT_GRANTED
        }
        Err(error) => {
            eprintln!("phone-auth: {error}");
            EXIT_UNAVAILABLE
        }
    }
}

/// The locker subcommands that need the phone.
fn locker(client: &mut AgentClient, cli: &Cli) -> u8 {
    let (Some(action), Some(target)) = (cli.args.first(), cli.args.get(1)) else {
        eprintln!("phone-auth: locker needs an action and a file, e.g. `locker lock notes.txt`");
        return EXIT_USAGE;
    };
    let path = match absolute(target) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("phone-auth: {error}");
            return EXIT_USAGE;
        }
    };

    let (method, params) = match action.as_str() {
        "lock" => {
            let Some(recovery_out) = &cli.recovery_out else {
                eprintln!(
                    "phone-auth: locker lock needs --recovery-out <FILE>.\n\
                     phone-auth: the recovery code is the only way back in without the phone, \
                     and it is shown nowhere else."
                );
                return EXIT_USAGE;
            };
            let recovery_out = match absolute(recovery_out) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("phone-auth: {error}");
                    return EXIT_USAGE;
                }
            };
            (
                "locker.lock",
                json!({
                    "path": path,
                    "recoveryCodePath": recovery_out,
                    "keepOriginal": cli.keep_original,
                    "credentialId": cli.credential,
                }),
            )
        }
        "unlock" => (
            "locker.unlock",
            json!({
                "path": path,
                "keepContainer": cli.keep_container,
                "credentialId": cli.credential,
                "destinationDir": cli.into.as_deref().map(absolute).transpose().ok().flatten(),
            }),
        ),
        "rekey" => {
            let recovery_out = match cli.recovery_out.as_deref().map(absolute).transpose() {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("phone-auth: {error}");
                    return EXIT_USAGE;
                }
            };
            if cli.new_recovery_code && recovery_out.is_none() {
                eprintln!("phone-auth: --new-recovery-code needs --recovery-out <FILE>");
                return EXIT_USAGE;
            }
            (
                "locker.rekey",
                json!({
                    "path": path,
                    "credentialId": cli.credential,
                    "newRecoveryCode": cli.new_recovery_code,
                    "recoveryCodePath": recovery_out,
                }),
            )
        }
        other => {
            eprintln!("phone-auth: unknown locker action `{other}`\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };

    match client.call(method, params) {
        Ok(value) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
            } else {
                print_locker(action, &value);
            }
            EXIT_GRANTED
        }
        Err(error) => {
            eprintln!("phone-auth: {error}");
            match error.code() {
                "declined" | "policy-denied" | "not-paired" | "bad-recovery-code" => EXIT_DENIED,
                _ => EXIT_UNAVAILABLE,
            }
        }
    }
}

fn print_locker(action: &str, value: &Value) {
    match action {
        "lock" => {
            println!("locked   {}", value["container"].as_str().unwrap_or("?"));
            println!(
                "original {}",
                if value["originalRemoved"].as_bool().unwrap_or(false) {
                    "removed"
                } else {
                    "kept in place — the plaintext is still on this disk"
                }
            );
            println!(
                "\nrecovery code written to {}",
                value["recoveryCodePath"].as_str().unwrap_or("?")
            );
            println!(
                "MOVE IT OFF THIS COMPUTER. It is the only way into this file without the phone,\n\
                 and next to the container it protects nothing."
            );
        }
        "unlock" => {
            println!("restored {}", value["restored"].as_str().unwrap_or("?"));
            if !value["containerRemoved"].as_bool().unwrap_or(false) {
                println!("container kept in place");
            }
        }
        "rekey" => {
            println!("rekeyed  {}", value["container"].as_str().unwrap_or("?"));
            if let Some(path) = value["recoveryCodePath"].as_str() {
                println!("\nnew recovery code written to {path}");
                println!("The previous recovery code no longer opens this container.");
            }
        }
        _ => {}
    }
    if value["development"].as_bool().unwrap_or(false) {
        eprintln!(
            "phone-auth: WARNING — this was authorized by the development simulator, \
             not by a phone"
        );
    }
}

/// Makes a path absolute without touching the filesystem, so the agent — which
/// has its own working directory — resolves the same file the user meant.
fn absolute(path: &str) -> Result<String, String> {
    std::path::absolute(path)
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| format!("cannot resolve `{path}`: {error}"))
}

fn print_status(value: &Value) {
    println!(
        "verifier   {} ({})",
        value["verifierName"].as_str().unwrap_or("?"),
        value["verifierId"].as_str().unwrap_or("?")
    );
    if value["developmentMode"].as_bool().unwrap_or(false) {
        println!("mode       DEVELOPMENT — a simulated phone is attached, not a real one");
    }
    println!(
        "ready      {}",
        if value["canAuthorize"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        }
    );

    println!("\ntransports");
    for transport in value["transports"].as_array().into_iter().flatten() {
        let state = transport["state"].as_str().unwrap_or("?");
        println!(
            "  {:<20} {:<15} {}",
            transport["name"].as_str().unwrap_or("?"),
            state,
            transport["blockedOn"]
                .as_str()
                .unwrap_or_else(|| transport["description"].as_str().unwrap_or(""))
        );
    }

    let blockers = value["blockedOn"].as_array().cloned().unwrap_or_default();
    if !blockers.is_empty() {
        println!("\nwaiting on");
        for blocker in blockers {
            println!("  - {}", blocker.as_str().unwrap_or("?"));
        }
    }

    print_devices(value);
}

fn print_devices(value: &Value) {
    let devices = value["pairedDevices"]
        .as_array()
        .or_else(|| value["devices"].as_array())
        .cloned()
        .unwrap_or_default();

    println!("\npaired phones");
    if devices.is_empty() {
        println!("  (none)");
        return;
    }
    for device in devices {
        println!(
            "  {} [{}]",
            device["displayName"].as_str().unwrap_or("?"),
            device["deviceId"].as_str().unwrap_or("?")
        );
        for credential in device["credentials"].as_array().into_iter().flatten() {
            println!(
                "    {} — {} key, purpose {}{}",
                credential["credentialId"].as_str().unwrap_or("?"),
                credential["keyKind"].as_str().unwrap_or("?"),
                credential["purpose"].as_str().unwrap_or("?"),
                if credential["usableAtBoot"].as_bool().unwrap_or(false) {
                    ", usable at boot"
                } else {
                    ""
                }
            );
            for permission in credential["permissions"].as_array().into_iter().flatten() {
                println!(
                    "      allow {} / {} on {} as {}",
                    permission["service"].as_str().unwrap_or("?"),
                    permission["action"].as_str().unwrap_or("*"),
                    permission["resource"].as_str().unwrap_or("*"),
                    permission["user"].as_str().unwrap_or("*")
                );
            }
        }
    }
}

fn print_pairing(value: &Value) {
    println!("scan this on the phone:\n");
    println!("  {}", value["qrPayload"].as_str().unwrap_or("?"));
    println!(
        "\nexpires at {} (epoch ms)",
        value["expiresAtMs"].as_i64().unwrap_or(0)
    );
    if let Some(blocked) = value["blockedOn"].as_str() {
        println!("\nNOT YET USABLE\n  {blocked}");
    }
}

fn print_history(value: &Value) {
    let entries = value["entries"].as_array().cloned().unwrap_or_default();
    if entries.is_empty() {
        println!("no authorizations recorded yet");
        return;
    }
    for entry in entries {
        println!(
            "{:<8} {:<10} {} / {} on {} as {}{}",
            entry["outcome"].as_str().unwrap_or("?"),
            entry["atMs"].as_i64().unwrap_or(0) % 1_000_000,
            entry["service"].as_str().unwrap_or("?"),
            entry["action"].as_str().unwrap_or("?"),
            entry["resource"].as_str().unwrap_or("?"),
            entry["user"].as_str().unwrap_or("?"),
            if entry["development"].as_bool().unwrap_or(false) {
                "  [dev]"
            } else {
                ""
            }
        );
        if let Some(detail) = entry["detail"].as_str() {
            println!("         {detail}");
        }
    }
}
