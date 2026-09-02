// The tray's pairing panel, run against the same DOM stub as the vault panel.
//
// The thing being tested is not presentation. The QR looks identical for every
// purpose, and a credential enrolled for the wrong one is indistinguishable in
// the device list afterwards — so which service the panel *sends* is a
// security property, and so is saying it out loud before the code is scanned.

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
    this.hidden = false;
    this.dataset = {};
    this.value = '';
    this.listeners = new Map();
    this.classList = { toggle: () => {} };
  }

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

function boot({ call }) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement(id));
    return elements.get(id);
  };

  const document = {
    hidden: false,
    getElementById: element,
    createElement: (tag) => new FakeElement(tag),
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
          onEvent: () => () => {},
        },
      },
      URL,
      Date,
      Math,
      setTimeout: () => 0,
      clearTimeout: () => {},
      setInterval: () => 0,
      clearInterval: () => {},
    })
  );
  // The renderer also calls `status` and `audit.recent` while booting; the
  // pairing tests care only about what the button sends.
  const pairCalls = () => calls.filter((entry) => entry.method === 'pair.begin');
  return { element, calls, pairCalls };
}

const bootstrap = (service) => ({
  qrPayload: 'phoneauth://pair/v1?vid=desktop-1',
  expiresAtMs: 1787745600000,
  service,
});

test('the chosen service is what the agent is asked for', async () => {
  const { element, pairCalls } = boot({
    call: async (_method, params) => bootstrap(params.service),
  });

  element('pair-service').value = 'ssh';
  await element('pair').emit('click');

  assert.deepEqual(
    pairCalls().map((entry) => entry.params.service),
    ['ssh']
  );
});

test('the default is an ordinary authorization pairing', async () => {
  const { element, pairCalls } = boot({
    call: async (_method, params) => bootstrap(params.service),
  });

  // Nothing chosen: the select's value is whatever the markup's first option
  // is, and the stub starts empty. What matters is that the panel does not
  // invent a privileged one.
  await element('pair').emit('click');

  assert.notEqual(pairCalls()[0].params.service, 'ssh');
});

test('what the credential will do is said before the code is scanned', async () => {
  const { element } = boot({ call: async () => bootstrap('ssh') });

  await element('pair').emit('click');

  const shown = element('pairing-service').textContent;
  assert.match(shown, /SSH/);
  // And that the pairing is not itself an approval of those logins.
  assert.match(shown, /fingerprint/);
});

// The panel echoes the agent's answer, not its own request: if the agent
// understood something different from what was asked, that difference has to
// be visible rather than papered over by re-rendering the local choice.
test('the note follows the agent reply, not the local selection', async () => {
  const { element } = boot({ call: async () => bootstrap('vault') });

  element('pair-service').value = 'ssh';
  await element('pair').emit('click');

  assert.match(element('pairing-service').textContent, /vault/);
});

test('choosing a service explains it before anything is sent', () => {
  const { element, pairCalls } = boot({ call: async () => bootstrap('vault') });

  element('pair-service').value = 'vault';
  element('pair-service').emit('change');

  assert.match(element('pair-service-note').textContent, /vault/);
  assert.deepEqual(pairCalls(), [], 'explaining a choice must not begin a pairing');
});
