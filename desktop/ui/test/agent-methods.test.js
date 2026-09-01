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
const fs = require('fs');
const path = require('path');

const { ALLOWED_METHODS, SECRET_BEARING_METHODS } = require('../src/agent-methods');

/**
 * Every method the renderer actually asks for, read out of its source.
 *
 * A regex over a file is a blunt instrument, and it is the right one here:
 * the question is what this list is allowed to contain, and the honest answer
 * is "whatever the page calls". Reading the page is the only way to ask that
 * without a person remembering correctly. Every call site is a literal today
 * -- `api.call('vault.list', {})` and twelve like it -- and if one ever stops
 * being a literal the count below drops and this file says so, which is the
 * point at which somebody should decide what an allow-list means for a call
 * whose name is computed.
 */
function methodsTheRendererCalls() {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'renderer', 'renderer.js'),
    'utf8'
  );
  const called = new Set();
  for (const match of source.matchAll(/api\.call\(\s*'([^']+)'/g)) {
    called.add(match[1]);
  }
  return called;
}

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

test('the list is exactly what the panels call', () => {
  // A whole-list assertion rather than spot checks: the failure this guards
  // against is an entry nobody meant to add, and a spot check only sees the
  // entries somebody thought of.
  assert.deepEqual([...ALLOWED_METHODS].sort(), [
    'audit.recent',
    'devices.forget',
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

test('nothing is allowed that no panel calls', () => {
  // The list held `devices.list` and `devices.setPermissions` from the first
  // commit and no panel ever called either. Unused surface is still surface:
  // `devices.setPermissions` rewrites what a paired phone may authorize, and
  // it was reachable from a window that offered no way to ask for it.
  //
  // Stated as a derived expectation rather than a second hand-kept list -- a
  // list checked against a copy of itself only proves someone typed twice.
  const called = methodsTheRendererCalls();
  assert.ok(called.size > 0, 'no api.call(...) literals found; the regex has gone stale');

  const unused = [...ALLOWED_METHODS].filter((method) => !called.has(method)).sort();
  assert.deepEqual(
    unused,
    [],
    `allowed but never called by the renderer: ${unused.join(', ')}`
  );
});

test('every method a panel calls is allowed, and is namespaced', () => {
  // The other direction. This one fails as a broken feature rather than as
  // loose surface: `main.js` refuses anything off the list, so a panel calling
  // a method nobody added here gets an error dialog instead of an answer.
  for (const method of methodsTheRendererCalls()) {
    assert.ok(ALLOWED_METHODS.has(method), `renderer calls \`${method}\`, which is not allowed`);
    assert.ok(
      method === 'status' || method.includes('.'),
      `\`${method}\` is not namespaced`
    );
  }
});
