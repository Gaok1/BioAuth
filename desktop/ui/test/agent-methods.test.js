'use strict';

// The tray's allow-list, and the one rule that governs it.
//
// The renderer is an Electron page: its strings are immutable and
// garbage-collected, so a password that reaches it cannot be wiped. That is why
// `vault.copy` writes the clipboard from inside the agent and replies with a
// description instead of the secret, and why `vault.create` generates the
// password in the agent and has no field for one in either direction.
//
// `vault.fill` is the one IPC method whose reply carries a password. It exists
// for the browser extension's native host, which is a different process with a
// different reason to hold one. Nothing but a hand-kept `Set` was keeping it
// off this list -- and this list grows every time the vault panel does.

const test = require('node:test');
const assert = require('node:assert');

const { ALLOWED_METHODS, SECRET_BEARING_METHODS } = require('../src/agent-methods');

test('no method that answers with a secret is reachable from the tray', () => {
  for (const method of SECRET_BEARING_METHODS) {
    assert.equal(
      ALLOWED_METHODS.has(method),
      false,
      `\`${method}\` answers with a password and must not be callable from the renderer`
    );
  }
});

test('authorising a login is not something a window can start', () => {
  // Authorisations are started by whatever needs them -- PAM, sudo, the CLI --
  // and never by a click in a tray. A window that could call this could approve
  // a login nobody asked for.
  for (const method of ['authorize', 'webauthn.perform', 'ssh.sign']) {
    assert.equal(ALLOWED_METHODS.has(method), false, method);
  }
});

test('the list is exactly what the panels call, and every entry is namespaced', () => {
  // A whole-list assertion rather than spot checks: the failure this guards
  // against is an entry nobody meant to add, and a spot check only sees the
  // entries somebody thought of.
  assert.deepEqual([...ALLOWED_METHODS].sort(), [
    'audit.recent',
    'devices.forget',
    'devices.list',
    'devices.setPermissions',
    'pair.begin',
    'pair.cancel',
    'pair.confirm',
    'pair.pending',
    'status',
    'vault.copy',
    'vault.create',
    'vault.generate-copy',
    'vault.list',
  ]);
});
