//! The PhoneAuth background agent.
//!
//! Long-lived, idle almost all the time, and the only process that holds the
//! pairing store and the replay guard. The tray UI and the CLI are clients:
//! they can ask for an authorization but cannot mint one, so a compromised UI
//! cannot forge a grant.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use phone_auth_agent::config::AgentConfig;
use phone_auth_agent::ipc;
use phone_auth_agent::paths::Paths;
use phone_auth_agent::qr_network::{self, QrNetworkTransport};
use phone_auth_agent::service::Service;
#[cfg(feature = "dev-simulator")]
use phone_auth_agent::simulator;
use phone_auth_agent::transport::Transport;
use phone_auth_session::IdentityKey;

const USAGE: &str = "\
phone-auth-agent — background PhoneAuth verifier

USAGE:
    phone-auth-agent [OPTIONS]

OPTIONS:
    --root <DIR>          Override the config/data/runtime root (for testing)
    --port <PORT>         Bind the IPC listener to a fixed loopback port
    --listen-port <PORT>  Accept phone connections on a fixed port
    --dev-simulator    Pair and answer with an in-process software
                       authenticator. Development only: it has no biometrics,
                       and it cannot satisfy a boot-time unlock.
    -h, --help         Show this message
";

struct Args {
    root: Option<PathBuf>,
    port: Option<u16>,
    listen_port: Option<u16>,
    dev_simulator: bool,
    help: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        root: None,
        port: None,
        listen_port: None,
        dev_simulator: false,
        help: false,
    };
    let mut raw = std::env::args().skip(1);

    while let Some(flag) = raw.next() {
        match flag.as_str() {
            "--root" => {
                args.root = Some(PathBuf::from(raw.next().ok_or("--root needs a directory")?));
            }
            "--port" => {
                args.port = Some(
                    raw.next()
                        .ok_or("--port needs a number")?
                        .parse()
                        .map_err(|_| "--port must be a number between 0 and 65535")?,
                );
            }
            "--listen-port" => {
                args.listen_port = Some(
                    raw.next()
                        .ok_or("--listen-port needs a number")?
                        .parse()
                        .map_err(|_| "--listen-port must be a number between 0 and 65535")?,
                );
            }
            "--dev-simulator" => args.dev_simulator = true,
            "-h" | "--help" => args.help = true,
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("phone-auth-agent: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if args.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("phone-auth-agent: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    let paths = Paths::resolve(args.root);
    paths
        .create_all()
        .map_err(|error| format!("could not create {}: {error}", paths.data_dir.display()))?;

    let mut config = AgentConfig::load_or_create(&paths.config_file())
        .map_err(|error| format!("could not read {}: {error}", paths.config_file().display()))?;
    config
        .validate()
        .map_err(|error| format!("{} is invalid: {error}", paths.config_file().display()))?;

    refuse_simulator_without_the_feature(args.dev_simulator)?;

    // The one private key the desktop holds. A phone recognises this machine
    // by it, so it is created once and then never regenerated silently.
    let identity = phone_auth_agent::identity::load_or_create(&paths.identity_file())
        .map_err(|error| format!("could not load the identity key: {error}"))?;
    let identity_spki = identity
        .public_key_spki()
        .map_err(|error| format!("could not read the identity key: {error}"))?;
    let additional_transports = start_additional_transports(
        &identity,
        &config.verifier_id,
        &config.verifier_name,
        args.dev_simulator,
    );

    let network = QrNetworkTransport::bind(
        identity,
        config.verifier_id.clone(),
        args.listen_port.unwrap_or(config.listen_port),
        args.dev_simulator,
    )
    .map_err(|error| format!("could not listen for phones: {error}"))?;
    // The bind address, which is every interface. The address a phone should
    // dial is a different question and is answered per pairing, in
    // `Service::begin_pairing`, because it changes when this machine changes
    // network.
    println!(
        "phone-auth-agent: listening for phones on 0.0.0.0:{}",
        network.port()
    );
    // Written down now that the OS has chosen, so the phones that were handed
    // this port in a pairing code still reach this machine after a restart.
    // Not when the port came from the command line: that is one run's choice,
    // not the machine's.
    if args.listen_port.is_none() {
        if let Err(error) = config.remember_listen_port(network.port(), &paths.config_file()) {
            eprintln!(
                "phone-auth-agent: could not record the listening port ({error});                  paired phones may have to be paired again after a restart"
            );
        }
    }
    match qr_network::advertised_address() {
        Ok(address) => println!("phone-auth-agent: phones should reach this machine at {address}"),
        Err(error) => eprintln!(
            "phone-auth-agent: no usable address on the local network ({error}); \
             pairing codes cannot be produced until that is fixed"
        ),
    }

    let network = Arc::new(network);
    let port = args.port.unwrap_or(config.ipc_port);

    let service = Service::new(
        config,
        paths.clone(),
        Some(Arc::clone(&network)),
        additional_transports,
        args.dev_simulator,
    )
    .map_err(|error| error.to_string())?;

    let mut service = service;
    if args.dev_simulator {
        pair_simulator_if_needed(&mut service)?;
        // Loopback, explicitly: the simulator is in this process. It used to be
        // handed the bind address, which connects back here anyway — which is
        // precisely why an unusable pairing address survived every local run.
        let simulator_endpoint = format!("127.0.0.1:{}", network.port());
        start_simulator(&simulator_endpoint, &identity_spki);
    }
    print_banner(&service);

    let service = Arc::new(Mutex::new(service));
    let result = ipc::serve(Arc::clone(&service), port).map_err(|error| error.to_string());

    ipc::clear_endpoint(&paths);
    result
}

fn start_additional_transports(
    identity: &IdentityKey,
    verifier_id: &str,
    verifier_name: &str,
    is_development: bool,
) -> Vec<Arc<dyn Transport>> {
    #[cfg(target_os = "linux")]
    {
        use phone_auth_agent::ble::BleTransport;

        let ble = identity
            .to_pkcs8_der()
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                IdentityKey::from_pkcs8_der(&bytes).map_err(|error| error.to_string())
            })
            .and_then(|identity| {
                BleTransport::start(
                    identity,
                    verifier_id.to_owned(),
                    verifier_name.to_owned(),
                    is_development,
                )
            });
        match ble {
            Ok(transport) => {
                println!("phone-auth-agent: advertising Bluetooth LE");
                vec![Arc::new(transport)]
            }
            Err(error) => {
                eprintln!("phone-auth-agent: Bluetooth LE unavailable ({error})");
                Vec::new()
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (identity, verifier_id, verifier_name, is_development);
        Vec::new()
    }
}

/// A build without the feature must not silently ignore `--dev-simulator` and
/// come up looking like a production agent that simply cannot see any phone.
#[cfg(feature = "dev-simulator")]
fn refuse_simulator_without_the_feature(_enabled: bool) -> Result<(), String> {
    Ok(())
}

#[cfg(not(feature = "dev-simulator"))]
fn refuse_simulator_without_the_feature(enabled: bool) -> Result<(), String> {
    if enabled {
        return Err(
            "this build has no simulator; rebuild with `--features dev-simulator`".to_owned(),
        );
    }
    Ok(())
}

/// Starts the simulated phone, which connects over the real transport.
#[cfg(feature = "dev-simulator")]
fn start_simulator(endpoint: &str, identity_spki: &[u8]) {
    simulator::SimulatedPhone::new().run_in_background(endpoint.to_owned(), identity_spki.to_vec());
}

#[cfg(not(feature = "dev-simulator"))]
fn start_simulator(_endpoint: &str, _identity_spki: &[u8]) {}

/// Pairs the simulated phone on first run.
///
/// Drives the real pairing path — arm a code, scan it, handshake, enrol,
/// compare the verification code — rather than writing a record into the
/// store. A shortcut here would leave the one flow this is meant to exercise
/// untested, and would let the store hold a device no handshake ever produced.
#[cfg(feature = "dev-simulator")]
fn pair_simulator_if_needed(service: &mut Service) -> Result<(), String> {
    use std::thread;
    use std::time::{Duration, Instant};

    if service
        .devices()
        .iter()
        .any(|device| device.device_id == simulator::DEVICE_ID)
    {
        return Ok(());
    }

    let bootstrap = service.begin_pairing().map_err(|error| error.to_string())?;
    let uri = bootstrap.qr_payload.clone();

    let scanned = phone_auth_session::ServerBootstrap::from_uri(&uri)
        .map_err(|error| format!("the agent produced an unscannable code: {error}"))?;

    thread::spawn(move || {
        let now = phone_auth_verifier::verifier::now_ms();
        if let Err(error) = simulator::SimulatedPhone::new().pair(&scanned, now) {
            eprintln!("phone-auth-agent: simulator could not pair: {error}");
        }
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(proposal) = service.pending_pairing() {
            service
                .confirm_pairing(&proposal.verification_code, Some(&proposal.attempt_id))
                .map_err(|error| error.to_string())?;
            println!(
                "phone-auth-agent: paired the simulator (code {})",
                proposal.verification_code
            );
            // A freshly paired credential authorizes nothing, which is correct
            // for a real phone and useless for a development run.
            return grant_simulator_permissions(service);
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("the simulator did not complete pairing".to_owned())
}

/// Gives the simulated phone the permissions a user would grant by hand.
#[cfg(feature = "dev-simulator")]
fn grant_simulator_permissions(service: &mut Service) -> Result<(), String> {
    use phone_auth_agent::api::PermissionSummary;

    let permissions = ["sudo", "login"]
        .into_iter()
        .map(|service_name| PermissionSummary {
            service: service_name.to_owned(),
            action: "*".to_owned(),
            resource: "*".to_owned(),
            user: "*".to_owned(),
        })
        .collect();

    service
        .set_permissions(simulator::DEVICE_ID, simulator::CREDENTIAL_ID, permissions)
        .map_err(|error| error.to_string())
}

#[cfg(not(feature = "dev-simulator"))]
fn pair_simulator_if_needed(_service: &mut Service) -> Result<(), String> {
    Ok(())
}

fn print_banner(service: &Service) {
    let status = service.status();
    println!(
        "phone-auth-agent: verifier `{}` ({})",
        status.verifier_name, status.verifier_id
    );

    if status.development_mode {
        eprintln!("+-----------------------------------------------------------+");
        eprintln!("|  DEVELOPMENT MODE — a simulated phone is attached. It      |");
        eprintln!("|  signs with a software key and approves everything it is   |");
        eprintln!("|  asked. No biometrics, no phone, no security.              |");
        eprintln!("+-----------------------------------------------------------+");
    }

    if status.paired_devices.is_empty() {
        println!("phone-auth-agent: no phone paired yet");
    } else {
        for device in &status.paired_devices {
            println!(
                "phone-auth-agent: paired `{}` ({} credential(s))",
                device.display_name,
                device.credentials.len()
            );
        }
    }

    for blocker in &status.blocked_on {
        println!("phone-auth-agent: unavailable — {blocker}");
    }
}
