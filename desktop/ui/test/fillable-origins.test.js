// The browser's three halves of the shared origin table.
//
// See `desktop/fillable-origins.json` for why the table exists. The rule is
// decided by the agent, by the service worker, by the content script and again
// by the manifest, which decides a page's fate before any of the code runs by
// choosing where the content script is injected. The agent's half is pinned in
// `crates/phone-auth-agent/tests/fillable_origins.rs`; these are the rest.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const extension = path.resolve(__dirname, '../../browser-extension');
const table = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../../fillable-origins.json'), 'utf8')
);
const cases = table.cases;
const manifest = JSON.parse(fs.readFileSync(path.join(extension, 'manifest.json'), 'utf8'));

// A table nobody reads is four tests that pass by looping over nothing.
assert.ok(cases.length > 0, 'the shared table has cases in it');

/// The service worker, run alone the way `browser-extension.test.js` runs it.
function bootWorker() {
  const context = vm.createContext({
    URL,
    setTimeout,
    // Only enough of the API for the file to finish loading. Nothing here is
    // called: what this test wants is the predicate the listeners are built on.
    chrome: { runtime: { onMessage: { addListener: () => {} } } },
  });
  context.globalThis = context;
  vm.runInContext(fs.readFileSync(path.join(extension, 'service-worker.js'), 'utf8'), context);
  // The worker is a plain script, so its top-level `const` declarations live in
  // the context's lexical scope rather than on its global object -- reading
  // `context.fillableUrl` finds nothing. A second script in the same context
  // sees them, which is what this is.
  return { fillableUrl: vm.runInContext('fillableUrl', context) };
}

/// The content script's namespace.
function bootContentScript() {
  const context = vm.createContext({
    Array,
    Promise,
    console,
    chrome: { runtime: {} },
    globalThis: {},
    window: {},
    document: {},
  });
  vm.runInContext(fs.readFileSync(path.join(extension, 'autofill-bridge.js'), 'utf8'), context);
  return context.globalThis.bioauthAutofill;
}

/// Whether a Chrome match pattern covers a URL.
///
/// Ports are deliberately absent: match patterns have no notion of one, so
/// `http://localhost/*` covers `http://localhost:3000/` and a test that
/// compared ports would disagree with the browser.
function patternMatches(pattern, url) {
  const [scheme, rest] = pattern.split('://');
  const host = rest.slice(0, rest.indexOf('/'));
  if (`${scheme}:` !== url.protocol) return false;
  if (host === '*') return true;
  if (host.startsWith('*.')) return url.hostname.endsWith(host.slice(1));
  return url.hostname === host;
}

test('the service worker decides every shared case the way the table says', () => {
  const { fillableUrl } = bootWorker();

  for (const { origin, fillable, why } of cases) {
    assert.equal(fillableUrl(origin), fillable, `${origin}: ${why}`);
  }
});

test('the content script decides every shared case the way the table says', () => {
  const { fillableOrigin } = bootContentScript();

  for (const { origin, fillable, why } of cases) {
    // A content script is handed a real `location`, never a string, so the
    // cases are parsed here rather than passed through as text.
    const url = new URL(origin);
    const answer = fillableOrigin({
      protocol: url.protocol,
      hostname: url.hostname,
      origin: url.origin,
    });
    assert.equal(answer !== null, fillable, `${origin}: ${why}`);
  }
});

/// The gate that runs before any of the code does.
///
/// An origin the agent would fill is worth nothing if the content script is
/// never injected into the page: the fill reports that nobody answered, which
/// reads as "no field is focused" and sends the person looking in the wrong
/// place. This is the same disagreement the native host had, one level up.
test('the manifest injects the content script wherever a fill is allowed', () => {
  const entry = manifest.content_scripts.find((script) =>
    script.js.includes('autofill-bridge.js')
  );
  assert.ok(entry, 'the autofill content script is declared');

  for (const { origin, fillable, why } of cases) {
    const url = new URL(origin);
    const covered = entry.matches.some((pattern) => patternMatches(pattern, url));
    if (fillable) {
      assert.ok(covered, `${origin} is fillable but matches no pattern: ${why}`);
    } else {
      assert.ok(!covered, `${origin} is not fillable but is injected into: ${why}`);
    }
  }
});

/// The passkey bridges replace `navigator.credentials`, and the agent refuses a
/// WebAuthn origin that is not https. Injecting them on localhost would take
/// away the browser's own implementation, which works there, and leave nothing
/// behind it.
test('the passkey bridges stay on https alone', () => {
  for (const entry of manifest.content_scripts) {
    if (entry.js.includes('autofill-bridge.js')) continue;
    assert.deepEqual(entry.matches, ['https://*/*'], entry.js.join(', '));
  }
});
