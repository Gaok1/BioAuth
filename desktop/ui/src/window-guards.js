'use strict';

// What the tray window is allowed to become, and where a link may go.
//
// `preload.js` attaches `window.phoneAuth` to whatever document the window
// loads — that is how Electron works, and the preload says so itself: it is
// "reachable by any script that runs in the window". Today only the bundled
// page ever loads there, but nothing was keeping it that way, and the bridge
// is a capability: a remote origin holding it could call `vault.copy` and put
// a password on the clipboard.
//
// These are pure so they can be tested without an Electron window; `main.js`
// wires them to `will-navigate` and to the window-open handler.

/**
 * Schemes `shell.openExternal` may be handed.
 *
 * Anything else goes to the OS as a protocol to resolve, and on Windows that
 * includes `file:` and every registered handler an installed program left
 * behind. A tray app whose renderer has no links at all does not need to be
 * the thing that reaches those.
 */
const EXTERNAL_SCHEMES = new Set(['http:', 'https:']);

/** Everything before the fragment: a `#` jump is not a navigation. */
function withoutFragment(url) {
  const hash = url.indexOf('#');
  return hash === -1 ? url : url.slice(0, hash);
}

/**
 * Whether the window may navigate from `fromUrl` to `toUrl`.
 *
 * Only the page it already is. That covers a reload and an in-page anchor and
 * refuses everything else, including a `file:` walk to another path on disk.
 */
function allowsNavigation(fromUrl, toUrl) {
  if (typeof fromUrl !== 'string' || typeof toUrl !== 'string') return false;
  return withoutFragment(fromUrl) === withoutFragment(toUrl);
}

/**
 * The URL to open in the real browser, or null to drop the request.
 *
 * Parsing rather than prefix-matching: `https:/\/\evil` and friends are only
 * a scheme once something has actually parsed them.
 */
function externalTarget(url) {
  if (typeof url !== 'string') return null;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  return EXTERNAL_SCHEMES.has(parsed.protocol) ? parsed.toString() : null;
}

module.exports = { allowsNavigation, externalTarget, EXTERNAL_SCHEMES };
