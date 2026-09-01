'use strict';

// Client for the agent's line protocol, mirroring `client.rs`.
//
// Lives in the main process only. The renderer never opens a socket and never
// sees the agent token: it can ask for things through the preload bridge, and
// nothing more.

const fs = require('fs');
const net = require('net');
const { EventEmitter } = require('events');
const { StringDecoder } = require('string_decoder');

const { endpointFile } = require('./paths');

/** Reconnect backoff, in milliseconds. */
const RETRY_MS = 2000;

/**
 * The most an unterminated reply may hold before the connection is dropped.
 *
 * A reply ends at a newline, so until one arrives every byte has to be kept.
 * Nothing bounded that: a peer that writes and never terminates a line grew
 * this buffer for as long as it kept writing, in the process that owns the
 * tray. Every other boundary in this product already refuses rather than
 * accumulates -- the native host rejects a frame over 128 KiB before
 * allocating for it, the agent caps relayed WebAuthn options at 6000 bytes --
 * and this one was reading from a socket with no ceiling at all.
 *
 * A megabyte is far above any legitimate line. The widest is a vault page,
 * which the protocol caps at thirty-two items whose fields are themselves
 * bounded, so tens of kilobytes is the real ceiling; this leaves an order of
 * magnitude of room. Over it, the connection is dropped and retried, which is
 * the same path a malformed line already takes.
 */
const MAX_UNTERMINATED_CHARS = 1_048_576;

/// How long to wait for the agent to answer one call, in milliseconds.
//
// Mirrors `READ_TIMEOUT` in `client.rs`, and for the same reason: longer than
// the protocol's two-minute request ceiling, so a slow human reaching for their
// phone is never mistaken for a dead agent.
const READ_TIMEOUT_MS = 150_000;

// The most items a vault may hold, and the most one page may carry. Kept here
// only to derive the walk budget; `vault.rs` is the source of truth.
const MAX_ITEMS = 4096;
const MAX_PAGE_ITEMS = 32;

// Dial, handshake, one page, hang up. A guess until somebody measures a real
// handset over BLE; the number to revise first if a big listing gives up early.
const PER_PAGE_BUDGET_MS = 4000;

/**
 * The same, for a call that walks the vault a page at a time.
 *
 * A listing stopped being one request when the walk became one session per
 * page: the phone answers a frame and closes, so the agent dials, shakes hands
 * and hangs up once for every thirty-two items. Derived from what the protocol
 * allows rather than picked.
 */
const WALK_TIMEOUT_MS = Math.ceil(MAX_ITEMS / MAX_PAGE_ITEMS) * PER_PAGE_BUDGET_MS;

/** The calls that walk, matching `walks_the_vault` in `client.rs`. */
function walksTheVault(method) {
  return method === 'vault.list' || method === 'vault.fill';
}

/**
 * A reconnecting connection to the agent.
 *
 * Emits `status` (connected / disconnected) and `agent-event` (pushes from the
 * agent, forwarded verbatim).
 */
class AgentConnection extends EventEmitter {
  // The two windows are held rather than read from the constants so a test can
  // set one it can afford to wait out.
  constructor({ readTimeoutMs = READ_TIMEOUT_MS, walkTimeoutMs = WALK_TIMEOUT_MS } = {}) {
    super();
    this.readTimeoutMs = readTimeoutMs;
    this.walkTimeoutMs = walkTimeoutMs;
    this.socket = null;
    this.token = null;
    this.buffer = '';
    // Not `chunk.toString('utf8')`. TCP splits wherever it likes, including
    // between the two bytes of a `ç`, and decoding each chunk on its own turns
    // whichever character straddles the boundary into replacement characters.
    // The line still parses as JSON, so nothing fails: it is the item's *name*
    // that comes back wrong, in an app whose every string is Portuguese, and
    // only for answers big enough to be split -- which a vault listing is.
    // `client.rs` never had this because `read_line` collects bytes to the
    // newline and validates the whole line at once. This decoder is the same
    // guarantee: it holds an incomplete sequence back until the rest arrives.
    this.decoder = new StringDecoder('utf8');
    this.nextId = 1;
    this.pending = new Map();
    this.connected = false;
    this.retryTimer = null;
    this.lastError = null;
    // Whether this attempt got as far as an accepted socket. Not the same
    // question as `connected`: the agent closes the connection on a token it
    // does not recognise and on a malformed line, so "the socket went away" and
    // "nothing is serving" look identical from the outside unless this is kept.
    this.reachedAgent = false;
  }

  isConnected() {
    return this.connected;
  }

  /** Opens the connection, retrying until the agent appears. */
  start() {
    this.stopRetry();
    this.reachedAgent = false;

    let endpoint;
    try {
      endpoint = JSON.parse(fs.readFileSync(endpointFile(), 'utf8'));
    } catch (error) {
      this.fail(`agent not running (${error.code || error.message})`);
      return;
    }

    // Checked rather than trusted. The agent writes this file at startup, so a
    // torn or half-written read is reachable, and `createConnection` throws
    // *synchronously* on a port that is not a number -- from a retry timer,
    // where there is nobody to catch it. A malformed file would have taken the
    // tray down instead of being reported as an agent that is not up yet.
    const port = Number(endpoint.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      this.fail('agent endpoint file is malformed');
      return;
    }

    this.token = endpoint.token;
    let socket;
    try {
      socket = net.createConnection({ host: '127.0.0.1', port });
    } catch (error) {
      this.fail(`agent not reachable (${error.code || error.message})`);
      return;
    }
    this.socket = socket;

    socket.on('connect', () => {
      this.connected = true;
      this.reachedAgent = true;
      this.lastError = null;
      this.emit('status', { connected: true });
      // Subscribing here rather than on demand: the tray has to reflect a
      // request that some other client (PAM, the CLI) started.
      this.call('subscribe', {}).catch(() => {});
    });

    socket.on('data', (chunk) => this.consume(chunk));
    socket.on('error', (error) => this.fail(error.message));
    socket.on('close', () => this.fail('agent connection closed'));
  }

  consume(chunk) {
    this.buffer += this.decoder.write(chunk);
    let newline;
    while ((newline = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (!line) continue;

      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }

      // Event lines carry no `id`; replies always do.
      if (message.id === undefined) {
        this.emit('agent-event', message);
        continue;
      }
      const waiter = this.pending.get(message.id);
      if (!waiter) continue;
      this.pending.delete(message.id);
      clearTimeout(waiter.timer);
      if (message.ok) waiter.resolve(message.result);
      else waiter.reject(new Error(message.error ? message.error.message : 'agent error'));
    }

    // Checked on what is left, not on what arrived: complete replies have just
    // been taken out of the buffer above, so only a line still waiting for its
    // newline can trip this. A large answer that does terminate is served.
    if (this.buffer.length > MAX_UNTERMINATED_CHARS) {
      this.fail('agent sent an oversized line');
    }
  }

  /**
   * Drops the socket and settles everything that was waiting on it.
   *
   * Every in-flight call is unanswerable once the socket is gone; rejecting is
   * what keeps the UI from spinning on a promise that can never settle. Shared
   * with `stop`, which used to leave those promises pending -- so "Reconnect to
   * agent", pressed while the vault panel was loading, left that panel loading
   * for as long as the app stayed open.
   */
  discard(reason) {
    this.connected = false;
    if (this.socket) {
      this.socket.removeAllListeners();
      this.socket.destroy();
      this.socket = null;
    }
    for (const waiter of this.pending.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error(reason));
    }
    this.pending.clear();
    this.buffer = '';
    // Replaced rather than kept: a decoder holding half a character from the
    // socket that just died would prepend it to the first line of the next
    // connection, which is the one line that has to parse.
    this.decoder = new StringDecoder('utf8');
  }

  fail(reason) {
    this.lastError = reason;
    this.discard(reason);

    // Emitted on every failure, including the first. This used to fire only
    // when the connection had previously been up, which deadlocked a fresh
    // install: the supervisor starts the agent from this event, so an agent
    // that had never run could never be started, and restarting the app landed
    // in the same state. Silence is not a safe default for a signal something
    // else acts on.
    // `reachable` says whether anything answered on that port during this
    // attempt. The supervisor starts the daemon from this event, and starting a
    // second one next to a service-managed agent is the harm it exists to
    // avoid: two agents race over the endpoint file and the pairing store.
    this.emit('status', { connected: false, reason, reachable: this.reachedAgent });
    this.scheduleRetry();
  }

  scheduleRetry() {
    if (this.retryTimer) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.start();
    }, RETRY_MS);
  }

  stopRetry() {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  /** Issues one call. Rejects if the agent is not reachable. */
  call(method, params = {}) {
    return new Promise((resolve, reject) => {
      // `subscribe` used to be exempt from this guard, which let it reach
      // `this.socket.write` on a null socket. It is only ever issued from the
      // `connect` handler, where the socket exists and `connected` is already
      // true, so the exemption bought nothing and could only throw.
      if (!this.socket || !this.connected) {
        reject(new Error(this.lastError || 'agent not connected'));
        return;
      }
      const id = this.nextId++;
      // A socket that stays up while the answer never comes was the one way a
      // call could not settle. `discard` rejects everything in flight -- that
      // is what keeps the UI from spinning on a promise that can never settle
      // -- but it only ever runs when the socket is lost, and the agent's IPC
      // is serial per connection behind a process-wide lock, so one call
      // waiting on a phone that is not answering holds up every later one on a
      // connection that is perfectly healthy. `client.rs` has bounded this
      // since it was written; the tray, speaking the same protocol to the same
      // agent, had no bound at all, and the vault panel simply stayed loading.
      const wait = walksTheVault(method) ? this.walkTimeoutMs : this.readTimeoutMs;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`agent did not answer ${method}`));
      }, wait);
      // Nothing here should keep the process alive on its own.
      if (typeof timer.unref === 'function') timer.unref();
      this.pending.set(id, { resolve, reject, timer });
      this.socket.write(`${JSON.stringify({ id, token: this.token, method, params })}\n`);
    });
  }

  stop() {
    this.stopRetry();
    this.discard('agent connection stopped');
  }
}

module.exports = { AgentConnection };
