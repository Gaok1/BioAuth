'use strict';

// What the tray's renderer may ask the agent to do.
//
// Its own file so it can be read as a list rather than found in the middle of
// window plumbing, and so the one rule that governs it can be tested: **no
// method here may return a secret.** The renderer is an Electron page, its
// strings are immutable and garbage-collected, and a password that reaches it
// cannot be wiped -- which is the whole reason `vault.copy` hands the phone's
// answer to the clipboard from inside the agent instead of replying with it.
//
// `vault.fill` is the counter-example and the reason this list is now checked
// by a test. It is the one IPC method whose reply carries a password, it
// exists for the browser extension's native host, and nothing but a hand-kept
// `Set` was keeping it out of here.
//
// The second rule, added after this list was found holding two methods no
// panel had ever called: **an entry is added when its caller is, and removed
// when its caller goes.** A list of what a window may do that outgrows what
// the window does is not describing the tray any more, and the entries it
// keeps are reachable by anything that ends up running in that page. The
// tests read `renderer/renderer.js` to check both directions, so the answer
// comes from the calls rather than from someone's memory of them.

/** Methods the renderer may invoke. Anything not listed is refused. */
const ALLOWED_METHODS = new Set([
  'status',
  // No `devices.list`: the device panel reads `status.pairedDevices`, which
  // the tray already polls. No `devices.setPermissions` either -- it changes
  // what a paired phone is allowed to authorize, which is the most
  // consequential thing in the `devices` namespace, and no panel has ever
  // offered it. Both sat here from the first commit. The agent still serves
  // both: `devices.list` is what `phone-auth devices` calls, and
  // `devices.setPermissions` has no client at all in this repo -- which is a
  // reason to leave it out of a window's reach, not a reason to keep it in.
  'devices.forget',
  'pair.begin',
  'pair.cancel',
  'pair.pending',
  'pair.confirm',
  'audit.recent',
  // The vault panel. `vault.copy` mutates nothing and reveals nothing to this
  // process: the secret goes from the phone into locked pages in the agent and
  // then to the clipboard, and the reply describes the copy without carrying
  // it. Unlike `authorize`, a copy is exactly the kind of thing a person means
  // to start by clicking, and the phone still shows what was asked before it
  // releases anything.
  'vault.list',
  'vault.copy',
  'vault.generate-copy',
  // The other direction, and the one the rule about never storing a password
  // here makes easy to allow: `vault.create` generates the secret inside the
  // agent and sends it to the phone. There is no field for one in the call and
  // none in the reply, so a renderer can ask for a login to be created and
  // still never be able to see it. The phone raises its own approval sheet,
  // worded from the request.
  'vault.create',
]);

/**
 * Methods that answer with a secret, and so may never be on the list above.
 *
 * Named rather than implied. A list of what is allowed says nothing about why
 * something is missing, and "we forgot" and "we decided" look identical in it.
 */
const SECRET_BEARING_METHODS = new Set(['vault.fill']);

module.exports = { ALLOWED_METHODS, SECRET_BEARING_METHODS };
