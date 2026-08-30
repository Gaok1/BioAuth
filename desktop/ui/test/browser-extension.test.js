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
