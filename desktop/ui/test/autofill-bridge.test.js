// The autofill content script's rules.
//
// Every one of these is a way a password ends up somewhere it should not:
// an advertisement iframe on a bank's page, a plain-HTTP login form, the
// "confirm your old password" box of a form that mails it somewhere. The
// script exists to refuse those, so this is where the refusals are pinned.
//
// Loaded into a `vm` context the way `browser-extension.test.js` loads the
// passkey bridge. The script is a plain file wrapped in a function -- content
// scripts have no module loading, and every one of them shares a global scope
// with the others -- so what it exposes is one namespace, not bare globals.

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
function input({
  type = 'password',
  disabled = false,
  readOnly = false,
  isConnected = true,
} = {}) {
  return {
    tagName: 'INPUT',
    type,
    disabled,
    readOnly,
    // Real elements always have this; the script reads it after the wait to
    // find out whether the page still holds the field it was handed.
    isConnected,
    value: '',
    events: [],
    form: null,
    dispatchEvent(event) {
      this.events.push(event.type);
      return true;
    },
  };
}

/// The ordinary case: a page that is not in a frame at all.
function topFrame() {
  const view = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  view.top = view;
  return view;
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
function boot({
  onMessage = null,
  runtimeMessage = async () => ({}),
  document = {},
  window = {},
} = {}) {
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
    window,
    document,
  });
  vm.runInContext(source, context);
  // The script publishes one namespace rather than a handful of bare globals,
  // because in the browser every content script of this extension shares one
  // global scope -- which is what used to make this file collide with
  // `content-bridge.js` over `runtime` and never run at all.
  return context.globalThis.bioauthAutofill;
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

  assert.equal(
    fillableOrigin({
      protocol: 'http:',
      hostname: 'bank.example',
      origin: 'http://bank.example',
    }),
    null
  );
  assert.equal(fillableOrigin({ protocol: 'https:', origin: 'null' }), null);
  assert.equal(fillableOrigin({ protocol: 'file:', origin: 'null' }), null);
});

/// The exception to the rule above, and the reason it is narrow: a password
/// sent to a loopback name never reaches a wire, which is the whole basis of
/// the https rule. Browsers call localhost a secure context for the same
/// reason.
test('plain http is fillable on a loopback host', () => {
  const { fillableOrigin } = boot();

  for (const [hostname, origin] of [
    ['localhost', 'http://localhost:3000'],
    ['127.0.0.1', 'http://127.0.0.1:8080'],
    ['app.localhost', 'http://app.localhost'],
  ]) {
    assert.equal(fillableOrigin({ protocol: 'http:', hostname, origin }), origin);
  }
});

/// A name that merely reads as loopback belongs to whoever registered it.
/// `localhost.evil.example` resolves wherever evil.example says, and a
/// password filled there is a password on the wire.
test('a host that only looks like loopback is still refused over http', () => {
  const { fillableOrigin } = boot();

  for (const hostname of [
    'localhost.evil.example',
    'notlocalhost',
    '127.0.0.1.evil.example',
    '127.0.0.2',
  ]) {
    assert.equal(
      fillableOrigin({ protocol: 'http:', hostname, origin: `http://${hostname}` }),
      null,
      hostname
    );
  }
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

  // A username box is a field a fill may start from, and half the login forms
  // on the web spell that one `email`.
  const email = input({ type: 'email' });
  assert.equal(fillTarget({ activeElement: email }), email);
  assert.equal(fillTarget({ activeElement: input({ type: 'checkbox' }) }), null);
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

// The host takes as long as a person takes to reach for their phone. These
// three mutate the page inside that wait, which is the only place a fill can
// be checked against a form that is no longer the one it was aimed at.

test('a field that left the page during the wait is not filled', async () => {
  const { performFill } = boot();
  const { password } = loginForm();
  const top = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  top.top = top;

  const result = await performFill({
    view: top,
    document: { activeElement: password },
    EventCtor: FakeEvent,
    send: async () => {
      // The login form re-rendered while the phone was asking. The old node is
      // detached, and writing into it puts the password nowhere at all.
      password.isConnected = false;
      return { ok: true, password: 'hunter2', username: 'alice' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(password.value, '');
  assert.deepEqual(password.events, [], 'a detached field was written and told nobody');
});

test('a box that stopped being a password box during the wait is not filled', async () => {
  const { performFill } = boot();
  const { password } = loginForm();
  const top = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  top.top = top;

  const result = await performFill({
    view: top,
    document: { activeElement: password },
    EventCtor: FakeEvent,
    send: async () => {
      // "The secret only ever reaches an `input[type=password]`" was true when
      // the host was asked. A page that flips the type while the phone is
      // asking gets the password painted on screen -- readable by the page
      // either way, and now by whoever is looking at it.
      password.type = 'text';
      return { ok: true, password: 'hunter2' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(password.value, '');
});

test('a username box that went away does not fail the fill', async () => {
  const { performFill } = boot();
  const { password, username } = loginForm();
  const top = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  top.top = top;

  const result = await performFill({
    view: top,
    document: { activeElement: password },
    EventCtor: FakeEvent,
    send: async () => {
      username.isConnected = false;
      return { ok: true, password: 'hunter2', username: 'alice' };
    },
  });

  // The password is what was asked for and it is in. A username box that went
  // away in the meantime is not a reason to call the fill a failure.
  assert.equal(result.ok, true);
  assert.equal(password.value, 'hunter2');
  assert.equal(username.value, '');
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
  const autofill = boot({ onMessage: (listener) => registered.push(listener) });

  assert.equal(registered.length, 1);
  assert.equal(typeof autofill.performFill, 'function');
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

/// The toolbar button cannot name a frame -- the browser does not say which one
/// has focus -- so the fill message goes to every frame in the tab. A frame
/// that answers is a frame claiming the reply, and only one of them is holding
/// the field the person is typing in.
test('a frame with nothing focused does not answer for the page', async () => {
  const claims = [];
  const boot_ = (document, window = topFrame()) => {
    let listener;
    boot({
      document,
      window,
      runtimeMessage: async () => ({ ok: true, password: 'hunter2' }),
      onMessage: (value) => {
        listener = value;
      },
    });
    return listener;
  };

  const idle = boot_({ activeElement: { tagName: 'BODY' } });
  const answered = await new Promise((resolve) => {
    const claimed = idle({ type: 'bioauth-autofill-fill' }, {}, () => resolve('answered'));
    claims.push(claimed);
    if (claimed === undefined) resolve('silent');
  });
  assert.equal(answered, 'silent');
  assert.equal(claims[0], undefined, 'a quiet frame must not hold the channel open');

  // And the frame that does hold the field answers, or the button would have
  // traded one silence for another.
  const password = input();
  const focused = boot_({ activeElement: password });
  const reply = await new Promise((resolve) => {
    assert.equal(
      focused({ type: 'bioauth-autofill-fill' }, {}, resolve),
      true,
      'the frame with the field claims the reply'
    );
  });
  assert.equal(reply.ok, true, 'the frame that claimed went on to fill');
});

/// Clicking the username line is how people use a password manager, and this
/// script answered it with "Selecione o campo de senha primeiro". The secret
/// still lands only in an `input[type=password]`; what changed is which field
/// the user is allowed to have picked.
test('a fill started from the username box fills both', async () => {
  const { performFill } = boot();
  const { username, password } = loginForm();
  const top = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  top.top = top;

  const result = await performFill({
    view: top,
    document: { activeElement: username },
    EventCtor: FakeEvent,
    send: async () => ({ ok: true, password: 'hunter2', username: 'alice' }),
  });

  assert.equal(result.ok, true);
  assert.equal(password.value, 'hunter2', 'the password went to the password box');
  assert.equal(username.value, 'alice');
});

/// A change-password form holds "current", "new" and "confirm". Choosing
/// between them is the guess this file exists not to make.
test('a form with several password boxes gets none of them', async () => {
  const { performFill } = boot();
  const name = input({ type: 'text' });
  const current = input();
  const fresh = input();
  const confirm = input();
  const form = { elements: [name, current, fresh, confirm] };
  for (const field of form.elements) field.form = form;
  const top = { location: { protocol: 'https:', origin: 'https://bank.example' } };
  top.top = top;

  let asked = false;
  const result = await performFill({
    view: top,
    document: { activeElement: name },
    EventCtor: FakeEvent,
    send: async () => {
      asked = true;
      return { ok: true, password: 'hunter2' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(asked, false, 'the vault was not even asked');
  assert.deepEqual([current.value, fresh.value, confirm.value], ['', '', '']);
});

/// A frame keeps its `activeElement` after focus moves to another frame. The
/// claim used to accept any text input, so a sidebar holding a stale one would
/// answer for the whole page -- with a refusal, while the frame that actually
/// held the password box was still working.
test('a frame whose stale field cannot be filled does not claim the reply', () => {
  const listeners = [];
  const bootFrame = (document, window = topFrame()) => {
    let listener;
    boot({ document, window, onMessage: (value) => { listener = value; } });
    listeners.push(listener);
    return listener;
  };

  // A lone text input, in no form: nothing a password could go into.
  const stale = bootFrame({ activeElement: input({ type: 'text' }) });
  assert.equal(
    stale({ type: 'bioauth-autofill-fill' }, {}, () => {}),
    undefined,
    'a frame that could not fill must leave the channel to the one that can'
  );

  // The same input inside a login form is a field a fill can start from, and
  // that frame does claim.
  const { username } = loginForm();
  const real = bootFrame({ activeElement: username });
  assert.equal(real({ type: 'bioauth-autofill-fill' }, {}, () => {}), true);

  // And a cross-origin frame holding a perfectly good password field does not,
  // however focused it is. It cannot be filled, so claiming the reply only
  // takes it from the frame that can -- which is one embed silencing the
  // toolbar button for a whole page, with a message about a frame the user
  // never knew was there.
  const advert = bootFrame(
    { activeElement: loginForm().password },
    crossOriginFrame()
  );
  assert.equal(
    advert({ type: 'bioauth-autofill-fill' }, {}, () => {}),
    undefined,
    'an advertisement took the reply away from the page it sits in'
  );
});
