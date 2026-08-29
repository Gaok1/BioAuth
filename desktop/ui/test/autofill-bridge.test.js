// The autofill content script's rules.
//
// Every one of these is a way a password ends up somewhere it should not:
// an advertisement iframe on a bank's page, a plain-HTTP login form, the
// "confirm your old password" box of a form that mails it somewhere. The
// script exists to refuse those, so this is where the refusals are pinned.
//
// Loaded into a `vm` context the way `browser-extension.test.js` loads the
// passkey bridge, which is also why the script is a plain file with top-level
// declarations rather than a module with test-only exports.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(
  path.resolve(__dirname, '../../browser-extension/autofill-bridge.js'),
  'utf8'
);

class FakeEvent {
  constructor(type, options = {}) {
    this.type = type;
    this.bubbles = options.bubbles ?? false;
  }
}

/// One input, with just enough of the DOM surface the script touches.
function input({ type = 'password', disabled = false, readOnly = false } = {}) {
  return {
    tagName: 'INPUT',
    type,
    disabled,
    readOnly,
    value: '',
    events: [],
    form: null,
    dispatchEvent(event) {
      this.events.push(event.type);
      return true;
    },
  };
}

/// A frame whose parent is another origin: `top` reads, `top.location` throws.
function crossOriginFrame({ protocol = 'https:' } = {}) {
  return {
    location: { protocol, origin: 'https://ads.example' },
    top: {
      get location() {
        throw new Error('blocked by the same-origin policy');
      },
    },
  };
}

/// A login form: a username field, then a password field.
function loginForm() {
  const username = input({ type: 'text' });
  const password = input();
  const form = { elements: [username, password] };
  username.form = form;
  password.form = form;
  return { form, username, password };
}

/// Boots the script and hands back its context.
function boot({ onMessage = null, runtimeMessage = async () => ({}) } = {}) {
  const context = vm.createContext({
    Event: FakeEvent,
    Array,
    Promise,
    console,
    chrome: {
      runtime: {
        sendMessage: runtimeMessage,
        onMessage: onMessage ? { addListener: onMessage } : undefined,
      },
    },
    globalThis: {},
    window: {},
    document: {},
  });
  vm.runInContext(source, context);
  return context;
}

test('a cross-origin iframe is never filled', () => {
  const { frameIsFillable } = boot();

  const top = { location: { origin: 'https://bank.example' } };
  top.top = top;
  assert.equal(frameIsFillable(top), true);

  // A browser lets `window.top` through and throws on its `location`. That is
  // the shape modelled here, because it is the one that actually happens.
  assert.equal(frameIsFillable(crossOriginFrame()), false);

  // And a `top` that throws outright still fails closed, which is why the
  // whole check sits inside the try.
  const hostile = { location: { origin: 'https://ads.example' } };
  Object.defineProperty(hostile, 'top', {
    get() {
      throw new Error('blocked');
    },
  });
  assert.equal(frameIsFillable(hostile), false);
});

test('a same-origin iframe is filled, because the page embedded itself', () => {
  const { frameIsFillable } = boot();

  const top = { location: { origin: 'https://bank.example' } };
  const nested = { top, location: { origin: 'https://bank.example' } };

  assert.equal(frameIsFillable(nested), true);
});

/// A sibling subdomain is one registrable domain and not one place to type a
/// password. The origin is compared whole.
test('the origin sent to the host is exact', () => {
  const { fillableOrigin } = boot();

  assert.equal(
    fillableOrigin({ protocol: 'https:', origin: 'https://login.bank.example' }),
    'https://login.bank.example'
  );
  assert.notEqual(
    fillableOrigin({ protocol: 'https:', origin: 'https://blog.bank.example' }),
    'https://login.bank.example'
  );
});

test('plain http and an opaque origin are refused', () => {
  const { fillableOrigin } = boot();

  assert.equal(fillableOrigin({ protocol: 'http:', origin: 'http://bank.example' }), null);
  assert.equal(fillableOrigin({ protocol: 'https:', origin: 'null' }), null);
  assert.equal(fillableOrigin({ protocol: 'file:', origin: 'null' }), null);
});

/// The focused field, not the first password box on the page. Guessing is how
/// a password lands in a form that was asking for something else.
test('only the focused field is a target', () => {
  const { fillTarget } = boot();

  const focused = input();
  assert.equal(fillTarget({ activeElement: focused }), focused);
  assert.equal(fillTarget({ activeElement: null }), null);
  assert.equal(fillTarget({ activeElement: { tagName: 'DIV' } }), null);
  assert.equal(fillTarget({ activeElement: input({ disabled: true }) }), null);
  assert.equal(fillTarget({ activeElement: input({ readOnly: true }) }), null);
});

test('a fill writes the password and fires what a page listens for', async () => {
  const { performFill } = boot();
  const { password, username } = loginForm();
  const top = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  top.top = top;

  const result = await performFill({
    view: top,
    document: { activeElement: password },
    EventCtor: FakeEvent,
    send: async () => ({ ok: true, password: 'hunter2', username: 'alice' }),
  });

  assert.equal(result.ok, true);
  assert.equal(password.value, 'hunter2');
  assert.equal(username.value, 'alice');
  // Setting `.value` alone leaves a framework showing an empty field and
  // submitting an empty password.
  assert.deepEqual(password.events, ['input', 'change']);
});

test('a cross-origin frame never even asks the host', async () => {
  const { performFill } = boot();
  let asked = false;
  const result = await performFill({
    view: crossOriginFrame({ protocol: 'https:' }),
    document: { activeElement: input() },
    EventCtor: FakeEvent,
    send: async () => {
      asked = true;
      return { ok: true, password: 'hunter2' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(asked, false, 'the vault was asked from a frame that may not fill');
});

test('http never even asks the host', async () => {
  const { performFill } = boot();
  let asked = false;
  const top = { location: { protocol: 'http:', origin: 'http://bank.example' } };
  top.top = top;

  const result = await performFill({
    view: top,
    document: { activeElement: input() },
    EventCtor: FakeEvent,
    send: async () => {
      asked = true;
      return { ok: true, password: 'hunter2' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(asked, false);
});

test('nothing is written when the vault refuses', async () => {
  const { performFill } = boot();
  const { password } = loginForm();
  const top = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  top.top = top;

  const result = await performFill({
    view: top,
    document: { activeElement: password },
    EventCtor: FakeEvent,
    send: async () => ({ ok: false, error: 'o telefone recusou' }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.error, 'o telefone recusou');
  assert.equal(password.value, '');
  assert.deepEqual(password.events, []);
});

/// A host that answered with something other than a string must not have that
/// something coerced into a field.
test('a malformed answer fills nothing', async () => {
  const { performFill } = boot();
  const { password } = loginForm();
  const top = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  top.top = top;

  for (const answer of [{ ok: true }, { ok: true, password: 42 }, null, undefined]) {
    const result = await performFill({
      view: top,
      document: { activeElement: password },
      EventCtor: FakeEvent,
      send: async () => answer,
    });
    assert.equal(result.ok, false);
    assert.equal(password.value, '');
  }
});

/// The username is a convenience and the password is the point. A form whose
/// shape is not the usual one gets the password and no guess.
test('a password field outside a form still gets its password', async () => {
  const { performFill } = boot();
  const lonely = input();
  const top = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  top.top = top;

  const result = await performFill({
    view: top,
    document: { activeElement: lonely },
    EventCtor: FakeEvent,
    send: async () => ({ ok: true, password: 'hunter2', username: 'alice' }),
  });

  assert.equal(result.ok, true);
  assert.equal(lonely.value, 'hunter2');
});

/// Nothing fires on load. Autofill that starts by itself is autofill that
/// starts on a phishing page too, and the listener is the only way in.
test('loading the script registers one listener and fills nothing', () => {
  const registered = [];
  const context = boot({ onMessage: (listener) => registered.push(listener) });

  assert.equal(registered.length, 1);
  assert.equal(typeof context.performFill, 'function');
});

/// The listener answers its own message type and ignores everything else, so a
/// stray message from another part of the extension cannot start a fill.
test('the listener ignores messages that are not its own', () => {
  const registered = [];
  boot({ onMessage: (listener) => registered.push(listener) });
  const listener = registered[0];

  assert.equal(listener({ type: 'bioauth-webauthn' }, {}, () => {}), undefined);
  assert.equal(listener({}, {}, () => {}), undefined);
  assert.equal(listener(null, {}, () => {}), undefined);
});
