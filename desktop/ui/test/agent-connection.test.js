'use strict';

// The tray's half of the agent connection.
//
// These run on `node --test` with nothing installed: the Electron main process
// modules under test deliberately require only Node built-ins, and the one that
// decides whether the daemon ever starts is worth being able to test without a
// display, a socket, or a packaged app.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// `paths.js` reads this at call time, so pointing it at an empty directory is
// enough to make the endpoint file missing without touching the real one.
process.env.PHONEAUTH_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'phoneauth-test-'));

const { AgentConnection } = require('../src/agent-connection');

test('reports disconnected on the first failure, having never connected', () => {
  // The regression this file exists for. `fail()` used to emit `status` only
  // when the connection had previously been up, so on a fresh install the
  // supervisor — which starts the agent from that event — was never told the
  // agent was missing. The agent never started, and restarting the app landed
  // in exactly the same state, because that state was the initial one.
  const agent = new AgentConnection();
  const seen = [];
  agent.on('status', (status) => seen.push(status));

  agent.start();
  agent.stop();

  assert.equal(seen.length, 1, 'a first failure must still be announced');
  assert.equal(seen[0].connected, false);
  assert.match(seen[0].reason, /agent not running/);
});

test('a call with no socket rejects instead of throwing', async () => {
  // `subscribe` used to skip this guard and reach `socket.write` on null.
  const agent = new AgentConnection();
  await assert.rejects(agent.call('subscribe'), /agent not connected/);
  await assert.rejects(agent.call('status'), /agent not connected/);
  agent.stop();
});

test('isConnected is false before anything succeeds', () => {
  const agent = new AgentConnection();
  assert.equal(agent.isConnected(), false);
  agent.stop();
});
