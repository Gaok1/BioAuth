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

test('a missing agent is reported as nothing serving', () => {
  // No endpoint file at all: the supervisor must start the daemon.
  const agent = new AgentConnection();
  const seen = [];
  agent.on('status', (status) => seen.push(status));
  try {
    agent.start();
    assert.equal(seen[0].reachable, false);
  } finally {
    agent.stop();
  }
});

// The deadline is part of the assertion. This test, and the two below, prove
// their fix by *waiting* on something -- a promise that only ever settles
// because the fix is there. Without a deadline a regression does not fail the
// suite, it wedges it: no red test, just a run that never ends, on CI where
// nobody is watching the clock. Sized to be unreachable on a loopback socket,
// so it can only fire for the reason it exists.
const HANGS_WITHOUT_THE_FIX = { timeout: 10_000 };

/**
 * A server standing in for the agent, with its teardown already registered.
 *
 * The teardown is on the test context and not in a `finally`, because a
 * `finally` only runs if the body reaches it -- and the body is exactly what
 * stops running when the deadline above fires. Registered this way it runs
 * either way. The handles are unreferenced as well, so that even a teardown
 * that somehow does not run cannot hold the event loop open: between the two,
 * a regression here fails the suite instead of hanging it, which is the whole
 * point of the deadline.
 *
 * The accepted sockets are kept because the teardown has to drop them itself.
 * The client destroying its end does not reliably close the server's, and
 * `server.close` waits for every connection.
 */
async function fakeAgent(t, { onConnection, ...options } = {}) {
  const accepted = [];
  const server = net.createServer((socket) => {
    socket.unref();
    accepted.push(socket);
    // Absent, the server accepts and then says nothing, which is the case most
    // of these tests are about.
    if (onConnection) onConnection(socket);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  server.unref();

  fs.mkdirSync(path.dirname(endpointFile()), { recursive: true });
  fs.writeFileSync(
    endpointFile(),
    JSON.stringify({ port: server.address().port, token: 'test-token' })
  );

  const agent = new AgentConnection(options);
  t.after(async () => {
    agent.stop();
    fs.rmSync(endpointFile(), { force: true });
    for (const socket of accepted) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return agent;
}

/** Resolves once the agent reports a status matching `predicate`. */
function statusMatching(agent, predicate) {
  return new Promise((resolve) => {
    agent.on('status', (status) => {
      if (predicate(status)) resolve(status);
    });
  });
}

test('an agent that closes the connection still counts as serving', HANGS_WITHOUT_THE_FIX, async (t) => {
  // The agent closes on a token it does not recognise and on a malformed line,
  // so from the outside that is indistinguishable from the agent having died --
  // unless it is recorded that the socket was accepted. It matters because the
  // supervisor starts the daemon from this event and the agent has no
  // single-instance lock: a second one overwrites the endpoint file, so the
  // tray would start a rival to a perfectly healthy service-managed agent.
  const agent = await fakeAgent(t, { onConnection: (socket) => socket.destroy() });

  const dropped = statusMatching(agent, (s) => !s.connected && s.reachable);
  agent.start();

  assert.equal((await dropped).reachable, true);
});

test('a malformed endpoint file is reported, not thrown', () => {
  // Valid JSON, no usable port -- a half-written file, or one from a build that
  // spelled the field differently. `net.createConnection` throws synchronously
  // on that, and `start()` runs from a retry timer where nothing catches it, so
  // this used to take the whole tray down rather than report an agent that is
  // not up yet.
  fs.mkdirSync(path.dirname(endpointFile()), { recursive: true });
  fs.writeFileSync(endpointFile(), JSON.stringify({ token: 'test-token' }));

  const agent = new AgentConnection();
  const seen = [];
  agent.on('status', (status) => seen.push(status));
  try {
    assert.doesNotThrow(() => agent.start());
    assert.equal(seen.length, 1);
    assert.equal(seen[0].connected, false);
    assert.match(seen[0].reason, /malformed/);
  } finally {
    agent.stop();
    fs.rmSync(endpointFile(), { force: true });
  }
});

test('a call the agent never answers gives up on its own', HANGS_WITHOUT_THE_FIX, async (t) => {
  // The socket stays up and the reply never comes: the agent's IPC is serial
  // per connection behind a process-wide lock, so a call waiting on a phone
  // that is not answering holds every later call on a healthy connection.
  // `discard` rejects what is in flight, but only when the socket is lost --
  // which this is not. `client.rs` has always bounded its reads; this side had
  // no bound at all, and the vault panel stayed loading for as long as the app
  // was open.
  const agent = await fakeAgent(t, { readTimeoutMs: 40, walkTimeoutMs: 40 });

  const connected = statusMatching(agent, (s) => s.connected);
  agent.start();
  await connected;

  await assert.rejects(agent.call('status'), /did not answer status/);
  // The socket is untouched: giving up on one call is not losing the agent.
  assert.equal(agent.isConnected(), true);
});

test('stopping settles the calls that were still in flight', HANGS_WITHOUT_THE_FIX, async (t) => {
  // "Reconnect to agent" in the tray menu is `stop()` then `start()`. `stop()`
  // dropped the socket and left every pending call in the map, so a call
  // issued a moment earlier -- the vault panel loading its list, say -- could
  // never settle, and the panel stayed loading for as long as the app was
  // open. `fail()` had always rejected them; `stop()` had not.
  const agent = await fakeAgent(t);

  const connected = statusMatching(agent, (s) => s.connected);
  agent.start();
  await connected;

  // The server accepts and never answers, which is the case that matters.
  const inFlight = agent.call('status');
  agent.stop();

  await assert.rejects(inFlight, /agent connection stopped/);
});
