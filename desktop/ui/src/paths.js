'use strict';

// Mirrors `crates/phone-auth-agent/src/paths.rs`.
//
// The two must agree on where the endpoint file lives, or the tray silently
// reports the agent as not running while it is in fact up. Any change here
// needs the same change there.

const os = require('os');
const path = require('path');

/** Resolves the agent's runtime directory for this platform. */
function runtimeDir() {
  // Honoured first so a developer can run an agent with `--root` and point the
  // tray at the same instance.
  const override = process.env.PHONEAUTH_ROOT;
  if (override) return path.join(override, 'run');

  if (process.platform === 'win32') {
    const base = process.env.LOCALAPPDATA || os.tmpdir();
    return path.join(base, 'PhoneAuth', 'run');
  }
  if (process.platform === 'darwin') {
    return path.join(os.tmpdir(), 'phone-auth');
  }
  const runtime = process.env.XDG_RUNTIME_DIR || os.tmpdir();
  return path.join(runtime, 'phone-auth');
}

function endpointFile() {
  return path.join(runtimeDir(), 'agent-endpoint.json');
}

module.exports = { runtimeDir, endpointFile };
