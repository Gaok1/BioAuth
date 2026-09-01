'use strict';

// Starts the bundled agent when nothing is already serving.
//
// The tray is a view onto the agent, so on a packaged install — where the user
// never opens a terminal — something has to start the daemon. On NixOS that is
// the systemd unit in `nixos/module.nix` and this supervisor stays out of the
// way; on Windows and on a plain Linux desktop there is no unit, and without
// this the app would sit at "agent offline" forever.
//
// # Why the path is fixed
//
// The binary is resolved from the install directory only, never from `PATH`.
// The agent is the process that decides whether a login is authorized, so
// letting a shadowing binary earlier in `PATH` take that role would hand the
// decision to whoever could write a directory.

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const BINARY = process.platform === 'win32' ? 'phone-auth-agent.exe' : 'phone-auth-agent';

/** How long to wait after an exit before starting the agent again. */
const RESTART_DELAY_MS = 3000;

/** Give up after this many consecutive failed starts. */
const MAX_ATTEMPTS = 3;

/**
 * Where the agent binary lives for this build.
 *
 * Packaged: alongside the app's resources, put there by electron-builder.
 * Development: the cargo target directory, so `npm start` works from a checkout.
 */
function agentBinaryPath() {
  const candidates = process.resourcesPath
    ? [path.join(process.resourcesPath, 'bin', BINARY)]
    : [];

  candidates.push(
    path.join(__dirname, '..', '..', 'target', 'release', BINARY),
    path.join(__dirname, '..', '..', 'target', 'debug', BINARY)
  );

  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

class AgentSupervisor {
  constructor({ onLog } = {}) {
    this.child = null;
    this.attempts = 0;
    this.stopped = false;
    this.timer = null;
    this.onLog = onLog || (() => {});
  }

  /**
   * Starts the agent unless one is already running.
   *
   * `alreadyRunning` is the tray's own view of the endpoint file. A system
   * that starts the agent as a service — the NixOS module, or a user who runs
   * it by hand — must not get a second one: two agents would race over the
   * endpoint file and the pairing store.
   */
  ensureRunning(alreadyRunning) {
    if (this.stopped || this.child || alreadyRunning) return;
    if (this.attempts >= MAX_ATTEMPTS) return;

    const binary = agentBinaryPath();
    if (!binary) {
      this.attempts = MAX_ATTEMPTS;
      this.onLog('no bundled agent binary found; start phone-auth-agent yourself');
      return;
    }

    this.attempts += 1;
    this.onLog(`starting agent: ${binary}`);

    // Detached and silent: this is a background daemon, and a console window
    // appearing behind a tray app on Windows reads as something having crashed.
    const child = spawn(binary, [], {
      detached: process.platform !== 'win32',
      windowsHide: true,
      stdio: 'ignore',
    });

    child.on('error', (error) => {
      this.child = null;
      this.onLog(`agent failed to start: ${error.message}`);
    });

    child.on('exit', (code) => {
      this.child = null;
      if (this.stopped) return;
      this.onLog(`agent exited with ${code}`);
      // Actually retry. This timer used to clear itself and do nothing, so
      // RESTART_DELAY_MS described a restart that never happened.
      this.timer = setTimeout(() => {
        this.timer = null;
        this.ensureRunning(false);
      }, RESTART_DELAY_MS);
    });

    this.child = child;
  }

  /** Resets the attempt budget once the agent is confirmed up. */
  markHealthy() {
    this.attempts = 0;
    // And drops a restart that is no longer owed. The `exit` handler queues one
    // three seconds out, and it fires with a hardcoded `false` for
    // `alreadyRunning` -- the single question `ensureRunning` exists to be told
    // the truth about. Three seconds is long enough for a service-managed agent
    // to take over, and taking over is often *why* the one this process started
    // exited. Starting a rival to it is the harm this class is written around:
    // the agent has no single-instance lock, so two of them race over the
    // endpoint file and the pairing store. Being confirmed up answers the
    // question, and the answer arrives here.
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  /**
   * Stops only an agent this process started.
   *
   * A service-managed agent, or one the user launched in a terminal, outlives
   * the tray: quitting a window must not take the authenticator down with it.
   */
  stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    if (this.child) {
      this.child.kill();
      this.child = null;
    }
  }
}

module.exports = { AgentSupervisor, agentBinaryPath };
