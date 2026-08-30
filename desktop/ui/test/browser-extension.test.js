const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const extension = path.resolve(__dirname, '../../browser-extension');

class CustomEvent extends Event {
  constructor(type, options = {}) {
    super(type);
    this.detail = options.detail;
  }
}

function page({ topLevel = true, permits = true, setTimeout = global.setTimeout, capabilities } = {}) {
  const document = new EventTarget();
  document.permissionsPolicy = { allowsFeature: () => permits };
  const native = {
    create: async (options) => ({ native: 'create', options }),
    get: async (options) => ({ native: 'get', options }),
  };
  const credentials = { ...native };
  const window = {};
  // The engine's own answers, which the bridge has to leave standing wherever
  // it does not speak for the capability itself. `getClientCapabilities` is
  // only defined when the caller asks for it: engines older than Chrome 133 do
  // not have it, and the bridge must not invent it for them.
  class PublicKeyCredential {}
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => false;
  if (capabilities) PublicKeyCredential.getClientCapabilities = async () => ({ ...capabilities });
  window.top = topLevel ? window : {};
  const context = vm.createContext({
    ArrayBuffer,
    atob,
    btoa,
    clearTimeout,
    crypto,
    CustomEvent,
    document,
    DOMException,
    Event,
    location: { hostname: 'login.example.com' },
    navigator: { credentials },
    PublicKeyCredential,
    AuthenticatorAttestationResponse: class AuthenticatorAttestationResponse {},
    AuthenticatorAssertionResponse: class AuthenticatorAssertionResponse {},
    setTimeout,
    structuredClone,
    Uint8Array,
    window,
  });
  context.globalThis = context;
  vm.runInContext(fs.readFileSync(path.join(extension, 'page-bridge.js'), 'utf8'), context);
  return { credentials, document, native, PublicKeyCredential };
}

test('page bridge serializes BufferSource and rebuilds a WebAuthn response', async () => {
  const { credentials, document } = page();
  document.addEventListener('bioauth-webauthn-request', (event) => {
    const request = JSON.parse(event.detail);
    assert.equal(request.options.challenge, 'AQID');
    assert.equal(request.options.user.id, 'BAU');
    assert.equal(request.options.rp.id, 'login.example.com');
    document.dispatchEvent(new CustomEvent('bioauth-webauthn-response', {
      detail: JSON.stringify({
        id: request.id,
        ok: true,
        response: {
          id: 'credential',
          rawId: 'Bgc',
          response: {
            clientDataJSON: 'CA',
            attestationObject: 'CQ',
            publicKey: 'Cg',
            publicKeyAlgorithm: -7,
            transports: ['internal'],
          },
          clientExtensionResults: { credProps: { rk: true } },
        },
      }),
    }));
  }, { once: true });

  const credential = await credentials.create({
    publicKey: { challenge: Uint8Array.of(1, 2, 3), user: { id: Uint8Array.of(4, 5) }, rp: {} },
  });
  assert.equal(credential.id, 'credential');
  assert.deepEqual([...new Uint8Array(credential.rawId)], [6, 7]);
  assert.deepEqual(Array.from(credential.response.getTransports()), ['internal']);
  assert.equal(credential.response.getPublicKeyAlgorithm(), -7);
  assert.equal(JSON.stringify(credential.getClientExtensionResults()), '{"credProps":{"rk":true}}');
});

test('page bridge handles abort, timeout, iframe policy, and native fallback', async () => {
  const aborting = page();
  let cancelled;
  aborting.document.addEventListener('bioauth-webauthn-cancel', (event) => {
    cancelled = JSON.parse(event.detail).id;
  });
  const controller = new AbortController();
  const aborted = aborting.credentials.get({
    publicKey: { challenge: Uint8Array.of(1) },
    signal: controller.signal,
  });
  controller.abort();
  await assert.rejects(aborted, { name: 'AbortError' });
  assert.equal(typeof cancelled, 'string');

  const timingOut = page({ setTimeout: (callback) => queueMicrotask(callback) });
  await assert.rejects(
    timingOut.credentials.get({ publicKey: { challenge: Uint8Array.of(1), timeout: 1 } }),
    { name: 'NotAllowedError', message: 'PhoneAuth request timed out' },
  );

  const framed = page({ topLevel: false, permits: false });
  await assert.rejects(
    framed.credentials.create({ publicKey: { challenge: Uint8Array.of(1) } }),
    { name: 'NotAllowedError' },
  );

  const fallback = page();
  assert.equal((await fallback.credentials.create({ password: true })).native, 'create');
  assert.equal((await fallback.credentials.get({ publicKey: {}, mediation: 'conditional' })).native, 'get');
});

test('page bridge answers that a platform authenticator is available', async () => {
  // The bug this covers is a silent one. The bridge takes `create` and `get`
  // over completely and reports `authenticatorAttachment: "platform"`, but the
  // question a relying party asks *before* offering that path was left to the
  // browser, which answers for Windows Hello and knows nothing about PhoneAuth.
  // A site gating "use this device" on it saw false and never offered the
  // option the extension had already taken over -- no error, nothing in the
  // console, just a choice that was not on the page.
  const plain = page();
  assert.equal(
    await plain.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
    true,
  );
  // Absent in the engine, absent afterwards: feature detection has to keep
  // seeing the engine it is really running on.
  assert.equal(plain.PublicKeyCredential.getClientCapabilities, undefined);

  // Newer engines ask for every capability at once. Ours are asserted; the rest
  // stay the browser's to answer -- conditional mediation above all, because
  // `get` hands that case straight back to the browser's own authenticator, so
  // claiming it here would promise something this bridge never handles.
  const modern = page({
    capabilities: {
      userVerifyingPlatformAuthenticator: false,
      passkeyPlatformAuthenticator: false,
      conditionalGet: true,
      hybridTransport: false,
    },
  });
  assert.deepEqual({ ...(await modern.PublicKeyCredential.getClientCapabilities()) }, {
    userVerifyingPlatformAuthenticator: true,
    passkeyPlatformAuthenticator: true,
    conditionalGet: true,
    hybridTransport: false,
  });
});

test('service worker returns native-host errors and rejects invalid origins', async () => {
  // Every registered listener, not just the last one. Chrome runs them all
  // and takes the first that claims the message; keeping one variable made
  // this test pass only while the worker had a single listener.
  const listeners = [];
  const listener = (message, sender, sendResponse) => {
    for (const candidate of listeners) {
      const claimed = candidate(message, sender, sendResponse);
      if (claimed !== undefined) return claimed;
    }
    return undefined;
  };
  const nativeMessages = [];
  const runtime = {
    onMessage: { addListener: (value) => { listeners.push(value); } },
    sendNativeMessage: async (_host, payload) => {
      nativeMessages.push(payload);
      throw new Error('host unavailable');
    },
  };
  const context = vm.createContext({ browser: { runtime }, URL });
  context.globalThis = context;
  vm.runInContext(fs.readFileSync(path.join(extension, 'service-worker.js'), 'utf8'), context);

  const hostError = await new Promise((resolve) => {
    assert.equal(listener(
      { type: 'bioauth-webauthn', requestId: 'request-1', operation: 'get', options: {} },
      { url: 'https://login.example.com/page' },
      resolve,
    ), true);
  });
  assert.equal(JSON.stringify(hostError), '{"ok":false,"error":"host unavailable"}');

  const invalidOrigin = await new Promise((resolve) => {
    assert.equal(listener(
      { type: 'bioauth-webauthn', requestId: 'request-2', operation: 'get', options: {} },
      { url: 'http://login.example.com/' },
      resolve,
    ), true);
  });
  assert.equal(JSON.stringify(invalidOrigin), '{"ok":false,"error":"Invalid browser origin"}');

  const invalidRequest = await new Promise((resolve) => {
    assert.equal(listener(
      { type: 'bioauth-webauthn', requestId: 'request-3', operation: 'delete', options: [] },
      { url: 'https://login.example.com/' },
      resolve,
    ), true);
  });
  assert.equal(JSON.stringify(invalidRequest), '{"ok":false,"error":"Invalid browser request"}');

  await new Promise((resolve) => listener(
    { type: 'bioauth-webauthn-cancel', requestId: 'request-1' },
    { url: 'https://login.example.com/' },
    resolve,
  ));
  assert.equal(JSON.stringify(nativeMessages.at(-1)), '{"operation":"cancel","requestId":"request-1"}');
});

test('the content scripts share one scope and both survive it', async () => {
  // Every content script this extension injects into a frame runs in the same
  // isolated world and shares one global scope with the others. Both isolated
  // scripts declared `const runtime` at the top level, so the second to load --
  // `autofill-bridge.js`, at `document_idle` -- threw `Identifier 'runtime' has
  // already been declared` and never ran. Autofill was not broken, it was
  // absent: no listener, so the service worker's fill message reached nobody
  // and answered "Receiving end does not exist". The only sign was a
  // SyntaxError per frame in a console nobody opens.
  //
  // Loading them one context each, which is what the other tests here do, is
  // exactly the arrangement in which this cannot happen. So load them the way
  // the browser does: same context, manifest order.
  const document = new EventTarget();
  const sent = [];
  const listeners = [];
  const context = vm.createContext({
    Array,
    CustomEvent,
    Event,
    JSON,
    Promise,
    chrome: {
      runtime: {
        sendMessage: async (payload) => {
          sent.push(payload);
          return { ok: true, response: { id: 'credential' } };
        },
        onMessage: { addListener: (listener) => listeners.push(listener) },
      },
    },
    console,
    document,
    window: {},
  });
  context.globalThis = context;
  context.window.top = context.window;

  for (const script of ['content-bridge.js', 'autofill-bridge.js']) {
    assert.doesNotThrow(
      () => vm.runInContext(fs.readFileSync(path.join(extension, script), 'utf8'), context),
      `${script} must load beside the others`,
    );
  }

  // Both are there, and "there" means installed rather than merely parsed.
  assert.equal(listeners.length, 1, 'autofill must register its listener');
  assert.equal(typeof context.globalThis.bioauthAutofill.performFill, 'function');

  document.dispatchEvent(new CustomEvent('bioauth-webauthn-request', {
    detail: JSON.stringify({ id: 'request-1', operation: 'get', options: {} }),
  }));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(sent.length, 1, 'the passkey bridge must still be listening');
  assert.equal(sent[0].type, 'bioauth-webauthn');
});

test('isolated bridge cannot bypass iframe policy with a forged page event', async () => {
  const document = new EventTarget();
  document.permissionsPolicy = { allowsFeature: () => false };
  const window = { top: {} };
  let calls = 0;
  let response;
  document.addEventListener('bioauth-webauthn-response', (event) => {
    response = JSON.parse(event.detail);
  });
  const context = vm.createContext({
    browser: { runtime: { sendMessage: async () => { calls += 1; } } },
    CustomEvent,
    document,
    Event,
    window,
  });
  context.globalThis = context;
  vm.runInContext(fs.readFileSync(path.join(extension, 'content-bridge.js'), 'utf8'), context);
  document.dispatchEvent(new CustomEvent('bioauth-webauthn-request', {
    detail: JSON.stringify({ id: 'forged', operation: 'get', options: {} }),
  }));
  await Promise.resolve();
  assert.equal(calls, 0);
  assert.equal(response.id, 'forged');
  assert.equal(response.ok, false);
});

test('a refused fill says why, where the button is', async () => {
  // The click lands on the toolbar and the refusal used to land nowhere: the
  // answer was never read, so "the vault is locked", "no item for this site"
  // and "two accounts, pick one" were all a button that did nothing. The badge
  // marks it and the title carries the sentence, because those are the only
  // two surfaces an extension with no popup has.
  const boot = ({ answer, sendMessage }) => {
    const action = { title: null, badge: null, colour: null };
    const clicks = [];
    const menus = [];
    const runtime = {
      onMessage: { addListener: () => {} },
      onInstalled: { addListener: () => {} },
      sendNativeMessage: () => {},
      lastError: undefined,
    };
    const context = vm.createContext({
      URL,
      setTimeout,
      chrome: {
        runtime,
        tabs: {
          sendMessage: sendMessage
            ? (...args) => sendMessage(runtime, ...args)
            : ((tabId, message, options, done) => done(answer)),
        },
        action: {
          onClicked: { addListener: (value) => clicks.push(value) },
          setBadgeText: ({ text }) => { action.badge = text; },
          setTitle: ({ title }) => { action.title = title; },
          setBadgeBackgroundColor: ({ color }) => { action.colour = color; },
        },
        contextMenus: {
          create: () => {},
          onClicked: { addListener: (value) => menus.push(value) },
        },
      },
    });
    context.globalThis = context;
    vm.runInContext(fs.readFileSync(path.join(extension, 'service-worker.js'), 'utf8'), context);
    return { action, click: clicks[0], menu: menus[0] };
  };

  const refused = boot({ answer: { ok: false, error: 'o cofre está trancado' } });
  refused.click({ id: 7, url: 'https://bank.example/login' });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(refused.action.badge, '!');
  assert.equal(refused.action.title, 'PhoneAuth: o cofre está trancado');

  // A filled field is not an announcement. The mark comes down and the title
  // goes back to what the button does.
  const filled = boot({ answer: { ok: true } });
  filled.click({ id: 7, url: 'https://bank.example/login' });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(filled.action.badge, '');
  assert.equal(filled.action.title, 'Preencher senha do cofre');

  // Nobody answered, because no frame held a focused field. That silence has
  // its own sentence rather than being left as nothing happening.
  const quiet = boot({
    sendMessage: (runtime, tabId, message, options, done) => {
      // What Chrome actually does when nobody answers: it does not throw, it
      // sets `lastError` and runs the callback anyway. Reading the return
      // value instead of that flag is how this reads as success.
      runtime.lastError = { message: 'Could not establish connection' };
      done(undefined);
      runtime.lastError = undefined;
    },
  });
  quiet.click({ id: 7, url: 'https://bank.example/login' });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(quiet.action.badge, '!');
  assert.equal(quiet.action.title, 'PhoneAuth: selecione o campo de senha primeiro');

  // A page the content scripts were never injected into. Told apart from the
  // silence above by the only thing that can tell them apart: the page's URL.
  let asked = false;
  const insecure = boot({
    sendMessage: () => { asked = true; },
  });

  insecure.click({ id: 7, url: 'http://bank.example/login' });
  assert.equal(asked, false, 'no tab was messaged');
  assert.equal(insecure.action.badge, '!');
  assert.equal(insecure.action.title, 'PhoneAuth: só páginas https podem ser preenchidas');
});
