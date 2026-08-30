'use strict';

// Client for the agent's line protocol, mirroring `client.rs`.
//
// Lives in the main process only. The renderer never opens a socket and never
// sees the agent token: it can ask for things through the preload bridge, and
// nothing more.

const fs = require('fs');
const net = require('net');
const { EventEmitter } = require('events');

const { endpointFile } = require('./paths');

/** Reconnect backoff, in milliseconds. */
const RETRY_MS = 2000;

/**
 * A reconnecting connection to the agent.
 *
 * Emits `status` (connected / disconnected) and `agent-event` (pushes from the
 * agent, forwarded verbatim).
 */
class AgentConnection extends EventEmitter {
  constructor() {
    super();
    this.socket = null;
    this.token = null;
    this.buffer = '';
    this.nextId = 1;
    this.pending = new Map();
    this.connected = false;
    this.retryTimer = null;
    this.lastError = null;
  }

  isConnected() {
    return this.connected;
  }

  /** Opens the connection, retrying until the agent appears. */
  start() {
    this.stopRetry();

    let endpoint;
    try {
      endpoint = JSON.parse(fs.readFileSync(endpointFile(), 'utf8'));
    } catch (error) {
      this.fail(`agent not running (${error.code || error.message})`);
      return;
    }

    this.token = endpoint.token;
    const socket = net.createConnection({ host: '127.0.0.1', port: endpoint.port });
    this.socket = socket;

    socket.on('connect', () => {
      this.connected = true;
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
    this.buffer += chunk.toString('utf8');
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
      if (message.ok) waiter.resolve(message.result);
      else waiter.reject(new Error(message.error ? message.error.message : 'agent error'));
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
    for (const waiter of this.pending.values()) waiter.reject(new Error(reason));
    this.pending.clear();
    this.buffer = '';
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
    this.emit('status', { connected: false, reason });
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
      this.pending.set(id, { resolve, reject });
      this.socket.write(`${JSON.stringify({ id, token: this.token, method, params })}\n`);
    });
  }

  stop() {
    this.stopRetry();
    this.discard('agent connection stopped');
  }
}

module.exports = { AgentConnection };
