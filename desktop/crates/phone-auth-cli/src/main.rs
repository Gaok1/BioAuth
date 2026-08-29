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
    pair [--service <S>]       Print a pairing bootstrap for the phone to scan.
                               `--service ssh` (or vault, locker, luks,
                               webauthn) enrols a credential for that use
                               instead of for ordinary authorization
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
    locker <ACTION> <FILE>... --batch
                               Act on several files. Prints how many and how
                               large before the first prompt, and each file
                               still needs its own approval on the phone. For
                               `lock`, --recovery-out names a directory.

    vault list                 List what the phone's vault holds. Metadata
                               only: no secret leaves the phone and no prompt
                               appears on it.
    vault copy <ITEM>          Copy one stored secret to the clipboard. <ITEM>
                               is an id, a name, or a unique part of one. The
                               phone asks for biometrics; the secret never
                               crosses IPC and is never printed here.
    vault generate             Generate a password straight to the clipboard

    ssh authorized-key         Print the `authorized_keys` line for each SSH
                               credential this phone holds. Paste it into a
                               server; the private half never leaves the phone.

OPTIONS:
    --root <DIR>               Override the agent's config/data/runtime root
    --credential <ID>          Choose which paired credential to use
    --recovery-out <FILE>      Where to write a new recovery code
    --recovery-file <FILE>     Read a recovery code from this file
    --into <DIR>               Where to restore an unlocked file
    --keep-original            Leave the plaintext in place after locking
    --keep-container           Leave the container in place after unlocking
    --new-recovery-code        Issue a new recovery code, retiring the old one
    --revision <N>             Copy only while the item is still at this
                               revision, from a listing you already read
    --clear-after <MS>         How long the clipboard entry lives
    --length <N>               Length of a generated password
    --no-symbols               Leave symbols out of a generated password
    --batch                    Required to act on more than one file at once
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
    revision: Option<u64>,
    clear_after: Option<u64>,
    length: Option<usize>,
    no_symbols: bool,
    batch: bool,
    recovery_out: Option<String>,
    recovery_file: Option<String>,
    into: Option<String>,
    keep_original: bool,
    keep_container: bool,
    new_recovery_code: bool,
    json: bool,
    help: bool,
}

/// A `Cli` with nothing set, before any flag is read.
///
/// Shared with the tests so they exercise the same defaults the real parser
/// starts from rather than a second copy that can drift.
fn blank_cli(command: String) -> Cli {
    Cli {
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
        revision: None,
        clear_after: None,
        length: None,
        no_symbols: false,
        batch: false,
        recovery_out: None,
        recovery_file: None,
        into: None,
        keep_original: false,
        keep_container: false,
        new_recovery_code: false,
        json: false,
        help: false,
    }
}

fn parse() -> Result<Cli, String> {
    let mut args = std::env::args().skip(1);
    let mut cli = blank_cli(args.next().unwrap_or_else(|| "help".to_owned()));

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
            "--revision" => {
                cli.revision = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--revision must be a number".to_owned())?,
                )
            }
            "--clear-after" => {
                cli.clear_after = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--clear-after must be a number of milliseconds".to_owned())?,
                )
            }
            "--length" => {
                cli.length = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--length must be a number".to_owned())?,
                )
            }
            "--no-symbols" => cli.no_symbols = true,
            "--batch" => cli.batch = true,
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
    // Only for a single target: `status` and a recovery unlock each address
    // one container, and a batch of them still has to go through the batch
    // path so the caps and the summary apply.
    if cli.command == "locker" {
        // Only for a single target: `status` and a recovery unlock each
        // address one container, and a batch of them still goes through the
        // batch path so the caps and the summary apply.
        if cli.args.len() == 2 {
            if let Some(exit) = locker_without_the_agent(&cli) {
                return exit;
            }
        }
        if let Err(exit) = locker_batch_plan(&cli) {
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
        "pair" => {
            // Which credential this pairing enrols. Absent is an ordinary
            // authorization pairing; `--service ssh` enrols an SSH key, which
            // has to be decided here because the phone cannot guess it from a
            // scan.
            let params = match cli.service.as_deref() {
                Some(service) => json!({ "service": service }),
                None => json!({}),
            };
            simple(&mut client, "pair.begin", params, cli.json, print_pairing)
        }
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
        "vault" => vault(&mut client, &cli),
        "ssh" => ssh(&mut client, &cli),
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

/// How many files one batch may touch.
///
/// Not a performance limit. A shell glob is the normal way somebody ends up
/// naming more files than they meant to, and the difference between locking
/// twelve files and locking a home directory is one character of typing.
const MAX_BATCH_FILES: usize = 256;

/// How many bytes one batch may touch, across all its files.
const MAX_BATCH_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The locker subcommands that need the phone.
fn locker(client: &mut AgentClient, cli: &Cli) -> u8 {
    let Some(action) = cli.args.first() else {
        eprintln!("phone-auth: locker needs an action and a file, e.g. `locker lock notes.txt`");
        return EXIT_USAGE;
    };
    let targets = &cli.args[1..];
    if targets.is_empty() {
        eprintln!("phone-auth: locker needs an action and a file, e.g. `locker lock notes.txt`");
        return EXIT_USAGE;
    }
    if let Some(warning) = locker_attribute_warning(cli, action) {
        eprintln!("{warning}");
    }
    if targets.len() > 1 {
        return locker_batch(client, cli, action, targets);
    }
    locker_one(client, cli, action, &targets[0])
}

fn locker_attribute_warning(cli: &Cli, action: &str) -> Option<&'static str> {
    (action == "lock" && !cli.keep_original).then_some(
        "WARNING: removing the original does not preserve ACLs, alternate data streams, \
         extended attributes, ownership or creation time. Use --keep-original if these matter.\n",
    )
}

/// Checks a batch and describes it, before anything connects or prompts.
///
/// Everything here is a usage error, and usage errors have to come first: a
/// user told "the agent is not running" would go and start the agent, then
/// discover the real problem was a glob that matched four hundred files.
fn locker_batch_plan(cli: &Cli) -> Result<(), u8> {
    if cli.args.len() <= 2 {
        return Ok(());
    }
    let targets = &cli.args[1..];
    let action = cli.args.first().map(String::as_str).unwrap_or("act on");

    if !cli.batch {
        eprintln!(
            "phone-auth: {} files named. Pass --batch to act on more than one.\n\
             phone-auth: a glob that matched more than you meant is the reason this asks.",
            targets.len()
        );
        return Err(EXIT_USAGE);
    }
    if targets.len() > MAX_BATCH_FILES {
        eprintln!(
            "phone-auth: {} files is over the batch limit of {MAX_BATCH_FILES}",
            targets.len()
        );
        return Err(EXIT_USAGE);
    }

    // Sizes are read before anything happens, so the summary describes the
    // batch as it stands rather than as it looked after half of it ran.
    let mut total = 0u64;
    for target in targets {
        match std::fs::metadata(target) {
            Ok(meta) => total = total.saturating_add(meta.len()),
            Err(error) => {
                eprintln!("phone-auth: cannot read {target}: {error}");
                return Err(EXIT_USAGE);
            }
        }
    }
    if total > MAX_BATCH_BYTES {
        eprintln!(
            "phone-auth: {} across {} files is over the batch limit of {} GiB",
            human_bytes(total),
            targets.len(),
            MAX_BATCH_BYTES / (1024 * 1024 * 1024)
        );
        return Err(EXIT_USAGE);
    }

    eprintln!(
        "phone-auth: {action} {} files, {} in total, from {}",
        targets.len(),
        human_bytes(total),
        common_parent(targets)
    );
    eprintln!("phone-auth: each one needs its own approval on the phone.\n");
    Ok(())
}

/// Runs one action over many files, after saying what that means.
///
/// Every file still costs its own approval on the phone: the wrap request
/// names one file and one size, so there is no honest way to ask once for
/// twenty. What a batch adds is the part that was missing — the user is told
/// how many files and how many bytes *before* the first prompt, rather than
/// discovering it twenty fingerprints later.
fn locker_batch(client: &mut AgentClient, cli: &Cli, action: &str, targets: &[String]) -> u8 {
    let mut failed = 0usize;
    for (index, target) in targets.iter().enumerate() {
        eprintln!("[{}/{}] {target}", index + 1, targets.len());
        let exit = locker_one(client, cli, action, target);
        if exit == EXIT_GRANTED {
            continue;
        }
        failed += 1;
        // A refusal is the user saying no, and carrying on would ask them
        // again for the next file. Every other failure is about that one
        // file, so the rest of the batch still deserves to run.
        if exit == EXIT_DENIED {
            eprintln!(
                "\nphone-auth: stopped after a refusal. {} of {} done.",
                index + 1 - failed,
                targets.len()
            );
            return EXIT_DENIED;
        }
    }

    eprintln!(
        "\nphone-auth: {} of {} succeeded",
        targets.len() - failed,
        targets.len()
    );
    if failed == 0 {
        EXIT_GRANTED
    } else {
        EXIT_UNAVAILABLE
    }
}

/// Where a batch's files come from, for the line the user reads before
/// approving anything. Their common directory, or a count of directories when
/// there is no single one — either way it answers "these files, from where?"
fn common_parent(targets: &[String]) -> String {
    let mut parents: Vec<String> = targets
        .iter()
        .map(|target| {
            std::path::Path::new(target)
                .parent()
                .map(|parent| parent.to_string_lossy().into_owned())
                .filter(|parent| !parent.is_empty())
                .unwrap_or_else(|| ".".to_owned())
        })
        .collect();
    parents.sort();
    parents.dedup();
    match parents.as_slice() {
        [only] => only.clone(),
        several => format!("{} different directories", several.len()),
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn locker_one(client: &mut AgentClient, cli: &Cli, action: &str, target: &str) -> u8 {
    let path = match absolute(target) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("phone-auth: {error}");
            return EXIT_USAGE;
        }
    };

    let (method, params) = match action {
        "lock" => {
            let Some(recovery_out) = &cli.recovery_out else {
                eprintln!(
                    "phone-auth: locker lock needs --recovery-out <FILE>.\n\
                     phone-auth: the recovery code is the only way back in without the phone, \
                     and it is shown nowhere else."
                );
                return EXIT_USAGE;
            };
            // In a batch `--recovery-out` names a directory: one recovery code
            // per container, because a code is the only way into the file it
            // belongs to and one file cannot hold twenty of them without the
            // user having to work out which line opens which container.
            let recovery_out = if cli.batch {
                let stem = std::path::Path::new(target)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "container".to_owned());
                let per_file = std::path::Path::new(recovery_out)
                    .join(format!("{stem}.recovery"))
                    .to_string_lossy()
                    .into_owned();
                absolute(&per_file)
            } else {
                absolute(recovery_out)
            };
            let recovery_out = match recovery_out {
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

/// The SSH subcommands.
///
/// Reading only. There is nothing here that signs: signing belongs to
/// `phone-auth-ssh-agent`, where `ssh` connects and where a user can be asked.
fn ssh(client: &mut AgentClient, cli: &Cli) -> u8 {
    match cli.args.first().map(String::as_str) {
        // The one step between having this installed and being able to log in.
        // Without it a user has to work out how to derive the line themselves,
        // which is where people give up and generate an ordinary key —
        // defeating the point of the phone holding it.
        Some("authorized-key") => match client.call("ssh.identities", json!({})) {
            Ok(value) => {
                let identities = value["identities"].as_array().cloned().unwrap_or_default();
                if identities.is_empty() {
                    eprintln!(
                        "phone-auth: no SSH credential is paired.\n\
                         phone-auth: pair a phone and enrol a credential for \
                         `ssh`."
                    );
                    return EXIT_DENIED;
                }
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&value).unwrap_or_default()
                    );
                    return EXIT_GRANTED;
                }
                for identity in identities {
                    let Some(blob) = identity["blob"].as_str() else {
                        continue;
                    };
                    let Ok(blob) = phone_auth_protocol::encoding::from_hex(blob) else {
                        continue;
                    };
                    println!(
                        "{}",
                        phone_auth_protocol::ssh::authorized_keys_line(
                            &blob,
                            identity["comment"].as_str().unwrap_or("phoneauth"),
                        )
                    );
                }
                eprintln!(
                    "\nphone-auth: append a line to ~/.ssh/authorized_keys on \
                     the server.\n\
                     phone-auth: the private half stays on the phone, and \
                     every login asks it."
                );
                EXIT_GRANTED
            }
            Err(error) => {
                eprintln!("phone-auth: {error}");
                EXIT_UNAVAILABLE
            }
        },
        _ => {
            eprintln!("phone-auth: ssh needs `authorized-key`");
            EXIT_USAGE
        }
    }
}

/// The vault subcommands.
///
/// Reading only. `vault.create`, `vault.update` and `vault.delete` are served
/// by the phone, but nothing here calls them: a write from the computer needs
/// an approval screen that names the item, and until that screen exists the
/// phone is the only place a vault item is edited. Listing costs no prompt,
/// and copying costs one — which is the whole shape of what the desktop is
/// allowed to do with somebody else's vault.
fn vault(client: &mut AgentClient, cli: &Cli) -> u8 {
    match cli.args.first().map(String::as_str) {
        Some("list") => vault_call(
            client,
            "vault.list",
            vault_params(cli),
            cli,
            print_vault_list,
        ),
        Some("copy") => vault_copy(client, cli),
        Some("generate") => vault_generate(client, cli),
        _ => {
            eprintln!("phone-auth: vault needs `list`, `copy <ITEM>` or `generate`");
            EXIT_USAGE
        }
    }
}

/// Runs one vault method, printing the reply and splitting the failure the way
/// every vault command splits it.
///
/// `simple` cannot serve here: it reports every failure as an outage, which
/// would leave `vault list` exiting 3 and `vault copy` exiting 1 on a computer
/// with no vault credential enrolled — the same refusal, two answers.
fn vault_call(
    client: &mut AgentClient,
    method: &str,
    params: Value,
    cli: &Cli,
    print: impl Fn(&Value),
) -> u8 {
    match client.call(method, params) {
        Ok(value) => {
            if cli.json {
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
            vault_exit(error.code())
        }
    }
}

fn vault_params(cli: &Cli) -> Value {
    let mut params = json!({});
    if let Some(credential) = &cli.credential {
        params["credentialId"] = json!(credential);
    }
    params
}

/// Copies one stored secret, naming the revision it believes it is copying.
fn vault_copy(client: &mut AgentClient, cli: &Cli) -> u8 {
    let Some(wanted) = cli.args.get(1) else {
        eprintln!("phone-auth: vault copy needs an item, e.g. `vault copy github`");
        return EXIT_USAGE;
    };

    // Listing first is not only how a name becomes an id: it is also where
    // `expectedRevision` comes from. The agent refuses a copy that does not
    // name one, and a person typing a command has no way to know it. This is
    // the same thing the tray does when the user clicks a row.
    let mut params = vault_params(cli);
    let listed = match client.call("vault.list", params.clone()) {
        Ok(listed) => listed,
        Err(error) => {
            eprintln!("phone-auth: {error}");
            return vault_exit(error.code());
        }
    };

    let found = match resolve_item(&listed, wanted) {
        Ok(found) => found,
        Err(message) => {
            eprintln!("{message}");
            return EXIT_USAGE;
        }
    };

    params["itemId"] = json!(found.id);
    // `--revision` pins a revision the caller read earlier, which is the
    // stronger check: without it the revision comes from the listing a moment
    // ago, and only an edit between that listing and the fetch is caught.
    params["expectedRevision"] = json!(cli.revision.unwrap_or(found.revision));
    if let Some(ms) = cli.clear_after {
        params["clearAfterMs"] = json!(ms);
    }

    vault_call(client, "vault.copy", params, cli, |value| {
        print_copy(Some(&found.name), value)
    })
}

/// Generates a password and copies it, for the case where nothing is stored
/// yet. Needs no phone: the agent generates it locally.
fn vault_generate(client: &mut AgentClient, cli: &Cli) -> u8 {
    let mut params = json!({});
    if let Some(length) = cli.length {
        params["length"] = json!(length);
    }
    if cli.no_symbols {
        params["symbols"] = json!(false);
    }
    if let Some(ms) = cli.clear_after {
        params["clearAfterMs"] = json!(ms);
    }

    vault_call(client, "vault.generate-copy", params, cli, |value| {
        print_copy(None, value)
    })
}

#[derive(Debug)]
struct VaultRow {
    id: String,
    name: String,
    revision: u64,
}

/// Turns what the user typed into the row they meant.
///
/// Ambiguity is refused rather than guessed: copying the wrong secret is
/// silent, because nothing that follows ever shows what was copied.
fn resolve_item(listed: &Value, wanted: &str) -> Result<VaultRow, String> {
    let items = listed["items"].as_array().cloned().unwrap_or_default();
    let row = |item: &Value| VaultRow {
        id: item["id"].as_str().unwrap_or_default().to_owned(),
        name: item["name"].as_str().unwrap_or("?").to_owned(),
        revision: item["revision"].as_u64().unwrap_or_default(),
    };

    // An id is unambiguous by construction, so it wins outright. A vault
    // holding an item *named* after another item's id must not redirect the
    // copy to the one that was merely named.
    if let Some(item) = items
        .iter()
        .find(|item| item["id"].as_str() == Some(wanted))
    {
        return Ok(row(item));
    }

    let needle = wanted.to_lowercase();
    let name_of = |item: &Value| item["name"].as_str().unwrap_or_default().to_lowercase();
    let mut candidates: Vec<&Value> = items
        .iter()
        .filter(|item| name_of(item) == needle)
        .collect();
    if candidates.is_empty() {
        candidates = items
            .iter()
            .filter(|item| {
                name_of(item).contains(&needle)
                    || item["uri"]
                        .as_str()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(&needle)
            })
            .collect();
    }

    match candidates.as_slice() {
        [] => Err(format!(
            "phone-auth: no vault item matches `{wanted}` — try `phone-auth vault list`"
        )),
        [only] => Ok(row(only)),
        several => {
            let mut message = format!("phone-auth: `{wanted}` matches {} items:", several.len());
            for item in several {
                message.push_str(&format!(
                    "\n  {}  [{}]",
                    item["name"].as_str().unwrap_or("?"),
                    item["id"].as_str().unwrap_or("?")
                ));
            }
            message.push_str("\nCopy one by its id.");
            Err(message)
        }
    }
}

/// Splits vault failures the way `authorize` splits them: a refusal the user,
/// the phone or the policy made is a "no"; everything else is an outage.
fn vault_exit(code: &str) -> u8 {
    match code {
        "declined" | "policy-denied" | "not-paired" | "unknown-credential"
        | "revision-conflict" | "vault-unavailable" => EXIT_DENIED,
        // Every parameter these commands send comes from the command line, so
        // the agent rejecting one is the user's typo — `--clear-after 1` — and
        // not a vault that would not answer.
        "bad-params" => EXIT_USAGE,
        _ => EXIT_UNAVAILABLE,
    }
}

fn print_vault_list(value: &Value) {
    println!(
        "vault on {}",
        value["deviceName"].as_str().unwrap_or("phone")
    );
    let items = value["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("  (empty — add items on the phone)");
    }
    for item in &items {
        println!(
            "  {:<28} {:<6} rev {:<5} {}",
            item["name"].as_str().unwrap_or("?"),
            item["kind"].as_str().unwrap_or("?"),
            item["revision"].as_u64().unwrap_or(0),
            item["username"].as_str().unwrap_or("")
        );
        if let Some(uri) = item["uri"].as_str().filter(|uri| !uri.is_empty()) {
            println!("  {:<28} {uri}", "");
        }
    }
    print_development(value);
}

/// Reports a copy. There is nothing here that could print the secret: the
/// reply it reads has no field carrying one.
fn print_copy(name: Option<&str>, value: &Value) {
    let length = value["length"].as_u64().unwrap_or(0);
    let what = name.unwrap_or("a generated password");
    match seconds_until(value["clearsAtMs"].as_i64().unwrap_or(0)) {
        Some(seconds) => println!("copied {what} — {length} characters, clears in {seconds}s"),
        None => println!("copied {what} — {length} characters"),
    }

    if !value["memoryLocked"].as_bool().unwrap_or(false) {
        eprintln!(
            "phone-auth: WARNING — the secret was not held in locked pages; it may have \
             reached the pagefile"
        );
    }
    if !value["historyExcluded"].as_bool().unwrap_or(false) {
        eprintln!("phone-auth: WARNING — this system's clipboard history may have kept a copy");
    }
    if !value["cloudExcluded"].as_bool().unwrap_or(false) {
        eprintln!("phone-auth: WARNING — the clipboard entry may have been synced to the cloud");
    }
    print_development(value);
}

/// How long the clipboard entry has left, or `None` when the agent's clock and
/// this one disagree enough that the answer would mislead.
fn seconds_until(epoch_ms: i64) -> Option<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as i64;
    let remaining = (epoch_ms - now) / 1000;
    (remaining > 0).then_some(remaining)
}

fn print_development(value: &Value) {
    if value["development"].as_bool().unwrap_or(false) {
        eprintln!(
            "phone-auth: WARNING — this came from the development simulator, not from a phone"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_lock_warns_about_attributes_the_container_does_not_store() {
        let mut cli = blank_cli("locker".to_owned());
        let warning = locker_attribute_warning(&cli, "lock").expect("destructive lock warns");
        assert!(warning.contains("ACLs"));
        assert!(warning.contains("--keep-original"));

        cli.keep_original = true;
        assert!(locker_attribute_warning(&cli, "lock").is_none());
        assert!(locker_attribute_warning(&cli, "unlock").is_none());
    }

    fn listing(items: Value) -> Value {
        json!({ "items": items, "deviceName": "phone", "development": false })
    }

    fn item(id: &str, name: &str, revision: u64, uri: &str) -> Value {
        json!({
            "id": id,
            "name": name,
            "revision": revision,
            "kind": "login",
            "username": "someone",
            "uri": uri,
            "updatedAtMs": 0,
        })
    }

    /// The id the user typed wins over an item that merely carries it as a
    /// name. Guessing the other way would copy a secret the user never named,
    /// and nothing downstream ever shows which one it was.
    #[test]
    fn an_id_beats_an_item_named_after_it() {
        let listed = listing(json!([
            item("abc-123", "Bank", 4, ""),
            item("def-456", "abc-123", 9, ""),
        ]));

        let found = resolve_item(&listed, "abc-123").expect("the id must resolve");

        assert_eq!(found.id, "abc-123");
        assert_eq!(found.revision, 4, "the revision travels with the row");
    }

    /// An exact name is not made ambiguous by a longer name containing it.
    #[test]
    fn an_exact_name_beats_a_longer_one_containing_it() {
        let listed = listing(json!([
            item("1", "Mail", 1, ""),
            item("2", "Webmail", 1, ""),
        ]));

        let found = resolve_item(&listed, "mail").expect("the exact name must win");

        assert_eq!(found.id, "1");
    }

    /// Two partial matches are refused, and the refusal carries the ids that
    /// would resolve it — otherwise the user has no way forward.
    #[test]
    fn an_ambiguous_fragment_is_refused_with_its_candidates() {
        let listed = listing(json!([
            item("1", "Bank of A", 1, ""),
            item("2", "Bank of B", 1, ""),
        ]));

        let message = resolve_item(&listed, "bank").expect_err("must not guess");

        assert!(message.contains("[1]"), "{message}");
        assert!(message.contains("[2]"), "{message}");
    }

    #[test]
    fn a_fragment_of_the_uri_resolves() {
        let listed = listing(json!([item("1", "Bank", 7, "https://example.com/login")]));

        let found = resolve_item(&listed, "EXAMPLE.com").expect("uri match");

        assert_eq!(found.revision, 7);
    }

    #[test]
    fn nothing_matching_is_refused() {
        let listed = listing(json!([item("1", "Bank", 1, "")]));

        assert!(resolve_item(&listed, "github").is_err());
    }

    /// A refusal has to exit 1, not 3: a script that treats an outage and a
    /// declined biometric alike cannot retry the one and stop on the other.
    #[test]
    fn refusals_and_outages_get_different_exit_codes() {
        for code in [
            "declined",
            "revision-conflict",
            "not-paired",
            "policy-denied",
        ] {
            assert_eq!(vault_exit(code), EXIT_DENIED, "{code}");
        }
        for code in ["clipboard-unavailable", "no-transport", "protocol-error"] {
            assert_eq!(vault_exit(code), EXIT_UNAVAILABLE, "{code}");
        }
        assert_eq!(
            vault_exit("bad-params"),
            EXIT_USAGE,
            "a rejected --clear-after is a typo, not an outage"
        );
    }

    /// Builds a `Cli` naming `files`, the way the argument parser would.
    fn batch_cli(files: Vec<String>, batch: bool) -> Cli {
        let mut cli = blank_cli("locker".to_owned());
        cli.args = std::iter::once("lock".to_owned()).chain(files).collect();
        cli.batch = batch;
        cli
    }

    /// A glob that matched more than the user meant is the normal way a batch
    /// gets out of hand: the difference between twelve files and a home
    /// directory is one character of typing.
    #[test]
    fn more_than_one_file_needs_the_batch_flag() {
        let files = vec!["a.txt".to_owned(), "b.txt".to_owned()];

        assert_eq!(locker_batch_plan(&batch_cli(files, false)), Err(EXIT_USAGE));
    }

    /// One file is the ordinary case and must not need a flag.
    #[test]
    fn a_single_file_is_not_a_batch() {
        assert_eq!(
            locker_batch_plan(&batch_cli(vec!["a.txt".to_owned()], false)),
            Ok(())
        );
    }

    #[test]
    fn a_batch_over_the_file_limit_is_refused() {
        let files = (0..=MAX_BATCH_FILES).map(|i| format!("f{i}.txt")).collect();

        assert_eq!(locker_batch_plan(&batch_cli(files, true)), Err(EXIT_USAGE));
    }

    /// A file that is not there is refused before the phone is asked for
    /// anything, rather than half way through a batch.
    #[test]
    fn a_batch_naming_a_missing_file_is_refused_up_front() {
        let dir = std::env::temp_dir().join(format!("phoneauth-batch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("sandbox");
        let present = dir.join("here.txt");
        std::fs::write(&present, b"x").expect("write");

        let files = vec![
            present.to_string_lossy().into_owned(),
            dir.join("gone.txt").to_string_lossy().into_owned(),
        ];

        assert_eq!(locker_batch_plan(&batch_cli(files, true)), Err(EXIT_USAGE));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_batch_within_its_limits_is_allowed() {
        let dir = std::env::temp_dir().join(format!("phoneauth-batch-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("sandbox");
        let files = (0..3)
            .map(|index| {
                let path = dir.join(format!("f{index}.txt"));
                std::fs::write(&path, vec![b'x'; 16]).expect("write");
                path.to_string_lossy().into_owned()
            })
            .collect();

        assert_eq!(locker_batch_plan(&batch_cli(files, true)), Ok(()));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The summary the user reads before the first prompt has to answer
    /// "these files, from where?" — one directory when there is one, and an
    /// honest count when there is not.
    #[test]
    fn a_batch_says_where_its_files_came_from() {
        let same = [
            format!("{0}docs{0}a.txt", std::path::MAIN_SEPARATOR),
            format!("{0}docs{0}b.txt", std::path::MAIN_SEPARATOR),
        ];
        assert_eq!(
            common_parent(&same),
            format!("{0}docs", std::path::MAIN_SEPARATOR)
        );

        let spread = [
            format!("{0}docs{0}a.txt", std::path::MAIN_SEPARATOR),
            format!("{0}photos{0}b.txt", std::path::MAIN_SEPARATOR),
            format!("{0}music{0}c.txt", std::path::MAIN_SEPARATOR),
        ];
        assert_eq!(common_parent(&spread), "3 different directories");
    }

    /// A bare filename has no directory, and the summary must still say
    /// something rather than an empty string.
    #[test]
    fn a_batch_of_bare_names_still_names_a_place() {
        assert_eq!(
            common_parent(&["a.txt".to_owned(), "b.txt".to_owned()]),
            "."
        );
    }

    /// The size in the summary is what the user weighs the batch by, so the
    /// units have to be the ones they think in.
    #[test]
    fn sizes_are_reported_in_units_a_person_reads() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(3 * 1024 * 1024), "3.0 MiB");
        assert_eq!(human_bytes(2 * 1024 * 1024 * 1024), "2.0 GiB");
        // Past the largest unit it keeps counting rather than wrapping.
        assert_eq!(human_bytes(10 * 1024 * 1024 * 1024), "10.0 GiB");
    }
}
