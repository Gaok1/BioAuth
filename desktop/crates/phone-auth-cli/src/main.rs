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

OPTIONS:
    --root <DIR>               Override the agent's config/data/runtime root
    --credential <ID>          Choose which paired credential to use
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
    root: Option<std::path::PathBuf>,
    service: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    user: Option<String>,
    credential: Option<String>,
    device: Option<String>,
    limit: Option<usize>,
    json: bool,
    help: bool,
}

fn parse() -> Result<Cli, String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_owned());
    let mut cli = Cli {
        command,
        root: None,
        service: None,
        action: None,
        resource: None,
        user: None,
        credential: None,
        device: None,
        limit: None,
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
            "--json" => cli.json = true,
            "-h" | "--help" => cli.help = true,
            other => return Err(format!("unknown option `{other}`")),
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
