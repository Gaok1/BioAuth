// The devices panel: forgetting a phone, and what happens while it is being
// forgotten.
//
// `devices.forget` goes to the agent and the answer takes as long as it takes.
// Meanwhile the status poll rebuilds this whole list every four seconds, from
// scratch, which is the window every assertion here is about. The panel had no
// tests at all; these are its first.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const rendererSource = fs.readFileSync(
  path.resolve(__dirname, '../renderer/renderer.js'),
  'utf8'
);

class FakeElement {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.children = [];
    this.textContent = '';
    this.className = '';
    this.dataset = {};
    this.hidden = false;
    this.disabled = false;
    this.value = '';
    this.listeners = new Map();
    this.classList = { toggle: () => {} };
  }

  focus() {}
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  removeChild(child) {
    this.children = this.children.filter((candidate) => candidate !== child);
    return child;
  }
  get firstChild() {
    return this.children[0] ?? null;
  }
  addEventListener(type, handler) {
    this.listeners.set(type, handler);
  }
  removeAttribute() {}
  emit(type, event = {}) {
    const handler = this.listeners.get(type);
    if (!handler) throw new Error(`no ${type} handler on ${this.tagName}`);
    return handler({ currentTarget: this, ...event });
  }
}

/// Boots the renderer and hands back the pieces these tests drive.
///
/// The agent's push channel is captured rather than dropped: a
/// `devices-changed` event makes the renderer refresh, which is the same code
/// path the four-second poll takes and the only way to re-render this list
/// from a test without a real timer.
function boot({ call }) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement(id));
    return elements.get(id);
  };

  let pushEvent = () => {};
  const document = {
    hidden: false,
    getElementById: element,
    createElement: (tag) => new FakeElement(tag),
    createTextNode: (text) => Object.assign(new FakeElement('#text'), {
      textContent: text,
    }),
    querySelectorAll: () => [],
    addEventListener: () => {},
  };

  const calls = [];
  vm.runInContext(
    rendererSource,
    vm.createContext({
      document,
      window: {
        phoneAuth: {
          call: (method, params) => {
            calls.push({ method, params });
            return call(method, params);
          },
          info: async () => ({ endpointFile: '/tmp/endpoint' }),
          renderQr: async () => 'data:,',
          onStatus: () => () => {},
          onEvent: (handler) => {
            pushEvent = handler;
            return () => {};
          },
        },
      },
      URL,
      Date,
      Math,
      setTimeout: () => 0,
      clearTimeout: () => {},
      // No real polling. `poll()` below stands in for it, through the push
      // channel, which lands in the same `refresh`.
      setInterval: () => 0,
      clearInterval: () => {},
    })
  );

  const settle = () => new Promise((resolve) => setImmediate(resolve));
  return {
    element,
    calls,
    settle,
    /** What the four-second poll does: refresh, and rebuild this list. */
    async poll() {
      pushEvent({ event: 'devices-changed' });
      await settle();
    },
    /** The "esquecer" buttons currently on screen, in order. */
    forgetButtons() {
      return element('devices')
        .children.flatMap((entry) => entry.children)
        .flatMap((row) => row.children)
        .filter((child) => child.tagName === 'button');
    },
  };
}

const device = {
  deviceId: 'phone-1',
  displayName: 'Pixel',
  credentials: [
    { credentialId: 'desktop-1-login', keyKind: 'StrongBox', purpose: 'login' },
  ],
};

function agent({ forget }) {
  return async (method) => {
    if (method === 'status') {
      return { verifierName: 'PhoneAuth', pairedDevices: [device] };
    }
    if (method === 'audit.recent') return { entries: [] };
    if (method === 'devices.forget') return forget();
    return {};
  };
}

test('a forget that fails says why and can be pressed again', async () => {
  // It used to write the message onto the button and stop there. The button
  // stayed disabled, so the one thing the user could do about a failure --
  // try it again -- was the one thing the panel had just taken away.
  const harness = boot({
    call: agent({
      forget: () => {
        throw new Error('o telefone ainda está pareado');
      },
    }),
  });
  await harness.settle();

  const [forget] = harness.forgetButtons();
  await forget.emit('click');
  await harness.settle();

  const [after] = harness.forgetButtons();
  assert.equal(after.textContent, 'o telefone ainda está pareado');
  assert.equal(after.disabled, false, 'a failed forget left a dead button');
});

test('a forget that fails into a dead agent still re-enables its button', async () => {
  // The other half of the same failure. Both paths end in `refresh()`, which
  // is what puts the message on a live row -- but a `refresh` that cannot
  // reach the agent shows the offline banner and never redraws this list. The
  // button on screen is then the one that was pressed, and it is the only one
  // there is to re-enable.
  let listed = 0;
  const harness = boot({
    call: async (method) => {
      if (method === 'status') {
        listed += 1;
        // Up for the initial render, gone by the time the forget fails.
        if (listed > 1) throw new Error('agent not connected');
        return { verifierName: 'PhoneAuth', pairedDevices: [device] };
      }
      if (method === 'audit.recent') return { entries: [] };
      if (method === 'devices.forget') throw new Error('não foi possível');
      return {};
    },
  });
  await harness.settle();

  const [forget] = harness.forgetButtons();
  await forget.emit('click');
  await harness.settle();

  assert.equal(harness.element('offline-banner').hidden, false);
  assert.equal(forget.textContent, 'não foi possível');
  assert.equal(forget.disabled, false, 'the only button on screen stayed dead');
});

test('a forget in flight survives the poll rebuilding the list', async () => {
  const held = [];
  const harness = boot({
    call: agent({ forget: () => new Promise((resolve) => held.push(resolve)) }),
  });
  await harness.settle();

  const [forget] = harness.forgetButtons();
  const forgetting = forget.emit('click');
  await harness.settle();

  await harness.poll();
  const [redrawn] = harness.forgetButtons();
  assert.equal(redrawn.disabled, true, 'the redrawn row invited a second press');

  // Not awaited: a press that gets through starts a forget only the resolvers
  // below can settle, and awaiting it would hang the run rather than fail it.
  redrawn.emit('click');
  await harness.settle();
  assert.equal(
    harness.calls.filter((entry) => entry.method === 'devices.forget').length,
    1,
    'a second press asked the agent to forget the same phone twice'
  );

  for (const resolve of held.splice(0)) resolve({});
  await forgetting;
  await harness.settle();
  assert.equal(harness.forgetButtons()[0].disabled, false);
});
