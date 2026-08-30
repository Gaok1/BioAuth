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

const net = require('node:net');

const { AgentConnection } = require('../src/agent-connection');
const { endpointFile } = require('../src/paths');

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

test('stopping settles the calls that were still in flight', async () => {
  // "Reconnect to agent" in the tray menu is `stop()` then `start()`. `stop()`
  // dropped the socket and left every pending call in the map, so a call
  // issued a moment earlier -- the vault panel loading its list, say -- could
  // never settle, and the panel stayed loading for as long as the app was
  // open. `fail()` had always rejected them; `stop()` had not.
  //
  // The accepted sockets are kept so the teardown can drop them itself. The
  // client destroying its end does not reliably close the server's, and
  // `server.close` waits for every connection: without this the test hung
  // after having already proved what it came to prove.
  const accepted = [];
  const server = net.createServer((socket) => accepted.push(socket));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  fs.mkdirSync(path.dirname(endpointFile()), { recursive: true });
  fs.writeFileSync(
    endpointFile(),
    JSON.stringify({ port: server.address().port, token: 'test-token' })
  );

  const agent = new AgentConnection();
  try {
    const connected = new Promise((resolve) => {
      agent.on('status', (status) => {
        if (status.connected) resolve();
      });
    });
    agent.start();
    await connected;

    // The server accepts and never answers, which is the case that matters.
    const inFlight = agent.call('status');
    agent.stop();

    await assert.rejects(inFlight, /agent connection stopped/);
  } finally {
    agent.stop();
    fs.rmSync(endpointFile(), { force: true });
    for (const socket of accepted) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
});
