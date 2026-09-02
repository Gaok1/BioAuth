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

function page({
  topLevel = true,
  permits = true,
  setTimeout = global.setTimeout,
  capabilities,
  conditional,
} = {}) {
  const document = new EventTarget();
  document.permissionsPolicy = { allowsFeature: () => permits };
  // On the prototype, where the browser keeps them, and not on the instance.
  //
  // More than realism. `Object.defineProperty` over an existing *own* property
  // keeps every attribute it is not given; over a fresh one the omitted ones
  // default to false. With `create` and `get` sitting on the object itself,
  // the bridge's descriptors inherited this harness's writability and a
  // non-writable definition was indistinguishable from a writable one.
  class CredentialsContainer {
    async create(options) {
      return { native: 'create', options };
    }

    async get(options) {
      return { native: 'get', options };
    }
  }
  const credentials = new CredentialsContainer();
  const native = CredentialsContainer.prototype;
  const window = {};
  // The engine's own answers, which the bridge has to leave standing wherever
  // it does not speak for the capability itself. `getClientCapabilities` and
  // `isConditionalMediationAvailable` are only defined when the caller asks
  // for them: engines older than Chrome 133 lack the first and engines older
  // than Chrome 108 lack the second, and the bridge must not invent either.
  class PublicKeyCredential {}
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => false;
  if (capabilities) PublicKeyCredential.getClientCapabilities = async () => ({ ...capabilities });
  if (conditional !== undefined) {
    PublicKeyCredential.isConditionalMediationAvailable = async () => conditional;
  }
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
  // The authenticator is a phone on the other end of a link, not something
  // attached to this computer, and a response that omits the field must not be
  // reported as though it were.
  assert.equal(credential.authenticatorAttachment, 'cross-platform');
  assert.equal(credential.response.getPublicKeyAlgorithm(), -7);
  assert.equal(JSON.stringify(credential.getClientExtensionResults()), '{"credProps":{"rk":true}}');
});

test('page bridge processes GitHub AppID migration extensions as the WebAuthn client', async () => {
  const { credentials, document } = page();
  document.addEventListener('bioauth-webauthn-request', (event) => {
    const request = JSON.parse(event.detail);
    assert.deepEqual(request.options.extensions, { credProps: true });
    document.dispatchEvent(new CustomEvent('bioauth-webauthn-response', {
      detail: JSON.stringify({
        id: request.id,
        ok: true,
        response: {
          id: 'github-credential',
          rawId: 'AQ',
          response: { clientDataJSON: 'Ag', attestationObject: 'Aw' },
          clientExtensionResults: { credProps: { rk: true } },
        },
      }),
    }));
  }, { once: true });

  const created = await credentials.create({
    publicKey: {
      challenge: Uint8Array.of(1),
      user: { id: Uint8Array.of(2) },
      rp: {},
      extensions: {
        appidExclude: 'https://github.com/u2f/trusted_facets',
        credProps: true,
        prf: {},
      },
    },
  });
  assert.equal(
    JSON.stringify(created.getClientExtensionResults()),
    '{"credProps":{"rk":true},"appidExclude":false}',
  );
  assert.equal(
    JSON.stringify(created.toJSON().clientExtensionResults),
    '{"credProps":{"rk":true},"appidExclude":false}',
  );

  // What actually broke on github.com, after the phone had already signed:
  // `@github/webauthn-json` shadows `toJSON` by assigning to the credential it
  // was handed. On a real one that is an own property shadowing a prototype
  // method; on ours it hit a property defined without `writable` and threw,
  // and the page reported a failed registration for a credential that exists.
  created.toJSON = () => ({ patched: true });
  assert.deepEqual(created.toJSON(), { patched: true });
  created.response.getPublicKey = () => null;
  assert.equal(created.response.getPublicKey(), null);

  document.addEventListener('bioauth-webauthn-request', (event) => {
    const request = JSON.parse(event.detail);
    assert.equal(request.options.extensions, undefined);
    document.dispatchEvent(new CustomEvent('bioauth-webauthn-response', {
      detail: JSON.stringify({
        id: request.id,
        ok: true,
        response: {
          id: 'github-credential',
          rawId: 'AQ',
          response: {
            clientDataJSON: 'Ag',
            authenticatorData: 'Aw',
            signature: 'BA',
            userHandle: 'BQ',
          },
        },
      }),
    }));
  }, { once: true });
  const asserted = await credentials.get({
    publicKey: {
      challenge: Uint8Array.of(1),
      extensions: { appid: 'https://github.com/u2f/trusted_facets' },
    },
  });
  assert.equal(JSON.stringify(asserted.getClientExtensionResults()), '{"appid":false}');
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

  // Already aborted before the call: the listener the bridge installs would
  // never fire, so without an up-front check the phone was asked to approve a
  // ceremony the page had abandoned. Nothing may reach it, and the rejection
  // carries the signal's own reason.
  const settled = page();
  let reached = false;
  settled.document.addEventListener('bioauth-webauthn-request', () => { reached = true; });
  const already = new AbortController();
  const reason = new DOMException('gone', 'AbortError');
  already.abort(reason);
  await assert.rejects(
    settled.credentials.get({ publicKey: { challenge: Uint8Array.of(1) }, signal: already.signal }),
    (error) => error === reason,
  );
  await assert.rejects(
    settled.credentials.create({ publicKey: { challenge: Uint8Array.of(1) }, signal: already.signal }),
    (error) => error === reason,
  );
  assert.equal(reached, false);

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

/// The bridge's own lesson, one level up.
///
/// `toJSON` on a credential was defined without `writable` once, and
/// `@github/webauthn-json` assigning over it threw -- after the phone had
/// signed. `create` and `get` shadow prototype methods that are writable and
/// configurable, and were defined as neither. A site or a passkey library
/// wrapping `navigator.credentials.get` -- which is what this very file does --
/// got a TypeError under strict mode, at document_start, and lost the script
/// that was doing the wrapping.
test('a page may wrap the bridge the way the bridge wrapped the browser', () => {
  const { credentials } = page();

  // The descriptors themselves, because that is the claim. Asserting through
  // an assignment would depend on whether the code doing it is strict, and
  // the answer that matters is the browser's, not this file's.
  for (const name of ['create', 'get']) {
    const descriptor = Object.getOwnPropertyDescriptor(credentials, name);
    assert.equal(descriptor.writable, true, `${name} cannot be wrapped`);
    assert.equal(descriptor.configurable, true, `${name} cannot be replaced`);
  }

  // And the wrapping works, which is the thing the descriptors are for.
  const ours = credentials.get;
  let sawOptions;
  credentials.get = (options) => {
    sawOptions = options;
    return ours(options);
  };
  credentials.get({ mediation: 'silent' });
  assert.deepEqual(sawOptions, { mediation: 'silent' });
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
  assert.equal(plain.PublicKeyCredential.isConditionalMediationAvailable, undefined);

  // The older, and still far more widely asked, form of the conditional
  // question. A browser that says yes is answering for its own authenticator,
  // and `get` hands conditional calls back to precisely that authenticator --
  // which holds none of this product's passkeys. A site that believes the yes
  // puts its whole passkey flow in autofill, where nothing reaches the phone
  // and nothing raises an error. Answering here and not in
  // `getClientCapabilities` would leave the common path unfixed, so both say
  // no together.
  const autofilling = page({ conditional: true });
  assert.equal(await autofilling.PublicKeyCredential.isConditionalMediationAvailable(), false);

  // Newer engines ask for every capability at once. Ours are asserted; anything
  // this bridge does not speak for stays the browser's to answer -- here,
  // `hybridTransport` passes through untouched.
  //
  // `conditionalGet` is asserted *false*, over a browser that says true. The
  // browser is answering for its own authenticator, and `get` hands conditional
  // calls back to exactly that authenticator -- which holds none of the
  // passkeys this product creates. Letting the true through told sites the
  // autofill path worked, so a site that leads with it (Google's sign-in) put
  // its whole passkey flow there: nothing reached the phone and nothing
  // reported an error, while registration on the same site kept working
  // because `create` has no conditional mode. False sends those sites to the
  // modal path this bridge actually serves.
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
    conditionalGet: false,
    hybridTransport: false,
    'extension:appid': true,
    'extension:appidExclude': true,
    'extension:credProps': true,
    'extension:largeBlob': false,
    'extension:prf': false,
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

  const refused = boot({ answer: { ok: false, error: 'the vault is locked' } });
  refused.click({ id: 7, url: 'https://bank.example/login' });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(refused.action.badge, '!');
  assert.equal(refused.action.title, 'PhoneAuth: the vault is locked');

  // A filled field is not an announcement. The mark comes down and the title
  // goes back to what the button does.
  const filled = boot({ answer: { ok: true } });
  filled.click({ id: 7, url: 'https://bank.example/login' });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(filled.action.badge, '');
  assert.equal(filled.action.title, 'Fill password from vault');

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
  assert.equal(quiet.action.title, 'PhoneAuth: select the password field first');

  // A page the content scripts were never injected into. Told apart from the
  // silence above by the only thing that can tell them apart: the page's URL.
  let asked = false;
  const insecure = boot({
    sendMessage: () => { asked = true; },
  });

  insecure.click({ id: 7, url: 'http://bank.example/login' });
  assert.equal(asked, false, 'no tab was messaged');
  assert.equal(insecure.action.badge, '!');
  assert.equal(insecure.action.title, 'PhoneAuth: only https pages can be filled');
});

test('a bridge that cannot reach the extension says which way it failed', async () => {
  // One sentence used to stand for every way the message did not get through,
  // and they are not one problem. A content script outlives the extension that
  // injected it whenever the extension is reloaded: the script stays in the
  // page, every request from that tab fails for good, and the fix is to reload
  // the page -- which is the one thing the person could have done and the one
  // thing "PhoneAuth bridge failed" never said.
  const answer = async (failure) => {
    const document = new EventTarget();
    let response;
    document.addEventListener('bioauth-webauthn-response', (event) => {
      response = JSON.parse(event.detail);
    });
    const top = {};
    const context = vm.createContext({
      browser: { runtime: { sendMessage: async () => { throw failure; } } },
      CustomEvent,
      document,
      Event,
      window: { top },
    });
    context.window.top = context.window;
    context.globalThis = context;
    vm.runInContext(fs.readFileSync(path.join(extension, 'content-bridge.js'), 'utf8'), context);
    document.dispatchEvent(new CustomEvent('bioauth-webauthn-request', {
      detail: JSON.stringify({ id: 'request-1', operation: 'get', options: {} }),
    }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    return response;
  };

  const orphaned = await answer(new Error('Extension context invalidated.'));
  assert.equal(orphaned.ok, false);
  assert.equal(orphaned.error, 'PhoneAuth was updated — reload this page and try again');

  const absent = await answer(new Error('Could not establish connection. Receiving end does not exist.'));
  assert.match(absent.error, /Receiving end does not exist/);

  // A throw with nothing to say still gets the old sentence rather than an
  // empty one.
  const mute = await answer(new Error(''));
  assert.equal(mute.error, 'PhoneAuth bridge failed');
});
