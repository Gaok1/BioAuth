// The tray's vault panel, run against a DOM stub.
//
// Two things here are security properties rather than presentation. The panel
// must send the revision of the row it is showing, because that is what stops
// a copy of a value edited elsewhere. And nothing the agent replies with may
// carry a secret — the reply type has no field for one, and a panel that
// started rendering `result.secret` would be the moment that stopped being
// true.

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

  /** Fires a handler the renderer registered, the way a click would. */
  emit(type, event = {}) {
    const handler = this.listeners.get(type);
    if (!handler) throw new Error(`no ${type} handler on ${this.tagName}`);
    return handler({ currentTarget: this, ...event });
  }

  /** Every rendered node's text, flattened, for asserting on the list. */
  get text() {
    return [this.textContent, ...this.children.map((child) => child.text)]
      .filter(Boolean)
      .join(' ');
  }
}

/// Boots renderer.js against a stub, and hands back the pieces a test drives.
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
    // The renderer walks the tab strip twice; one tab is enough to register
    // the handlers, and the vault panel is the one this file cares about.
    querySelectorAll: () => [Object.assign(new FakeElement('button'), {
      dataset: { panel: 'panel-vault' },
    })],
    addEventListener: () => {},
  };

  const calls = [];
  // Held rather than run, so a panel that schedules work for later can be
  // asked what it scheduled.
  const scheduled = [];
  const context = vm.createContext({
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
    setTimeout: (fn) => {
      scheduled.push(fn);
      return 0;
    },
    clearTimeout: () => {},
    // Polling would fire the status call forever; the tests drive the panel
    // directly instead.
    setInterval: () => 0,
    clearInterval: () => {},
  });

  vm.runInContext(rendererSource, context);

  /** Runs whatever the panel put on a timer, then lets promises settle. */
  async function drainTimers() {
    for (const fn of scheduled.splice(0)) await fn();
    await new Promise((resolve) => setImmediate(resolve));
  }

  return { element, calls, context, drainTimers };
}

const item = {
  id: 'item-1',
  revision: 7,
  kind: 'login',
  name: 'Banco',
  username: 'alice',
  uri: 'https://banco.example.com/login',
  updatedAtMs: 0,
};

/** Runs the panel's load, then hands back its rendered row buttons. */
async function openVault(harness) {
  await harness.element('vault-refresh').emit('click');
  await new Promise((resolve) => setImmediate(resolve));
  return harness
    .element('vault-items')
    .children.flatMap((entry) => entry.children)
    .flatMap((row) => row.children)
    .filter((node) => node.dataset && node.dataset.copy);
}

test('a copy names the revision of the row on screen', async () => {
  const harness = boot({
    call: async (method) => {
      if (method === 'vault.list') {
        return { items: [item], deviceName: 'Pixel', development: false };
      }
      if (method === 'vault.copy') {
        return {
          length: 18,
          clearsAtMs: Date.now() + 45000,
          historyExcluded: true,
          cloudExcluded: true,
          memoryLocked: true,
        };
      }
      return {};
    },
  });

  const [copy] = await openVault(harness);
  await copy.emit('click');

  // Field by field, and then the key set: the params object is built inside
  // the vm's realm, so a structural compare fails on the prototype alone.
  const request = harness.calls.find((entry) => entry.method === 'vault.copy');
  assert.equal(request.params.itemId, 'item-1');
  assert.equal(request.params.expectedRevision, 7);
  assert.deepEqual(Object.keys(request.params).sort(), [
    'expectedRevision',
    'itemId',
  ]);
  assert.match(harness.element('vault-note').textContent, /limpa em \d+s/);
});

test('a copy does not send the phone back for a whole new listing', async () => {
  // A listing is not free on the phone. The metadata lives inside the
  // encrypted blob and the key is auth-per-use, so re-listing raises a
  // Keystore prompt -- and listing raises no sheet to explain it. This used to
  // run a second after every copy, so approving one copy bought the owner a
  // second fingerprint prompt for something they had not asked for.
  const harness = boot({
    call: async (method) => {
      if (method === 'vault.list') {
        return { items: [item], deviceName: 'Pixel', development: false };
      }
      return {
        length: 18,
        clearsAtMs: Date.now() + 45000,
        historyExcluded: true,
        cloudExcluded: true,
        memoryLocked: true,
      };
    },
  });

  const [copy] = await openVault(harness);
  const listed = () => harness.calls.filter((c) => c.method === 'vault.list').length;
  const before = listed();

  await copy.emit('click');
  await harness.drainTimers();

  assert.equal(listed(), before, 'a copy must not cost an unexplained prompt');
});

test('a clipboard the OS would not protect is reported, not hidden', async () => {
  const harness = boot({
    call: async (method) => {
      if (method === 'vault.list') {
        return { items: [item], deviceName: 'Pixel', development: false };
      }
      return {
        length: 18,
        clearsAtMs: Date.now() + 45000,
        historyExcluded: false,
        cloudExcluded: true,
        memoryLocked: false,
      };
    },
  });

  const [copy] = await openVault(harness);
  await copy.emit('click');

  const note = harness.element('vault-note').textContent;
  assert.match(note, /pagefile/);
  assert.match(note, /hist[óo]rico/);
});

test('a refusal from the phone is shown as it arrived, not guessed at', async () => {
  const harness = boot({
    call: async (method) => {
      if (method === 'vault.list') {
        return { items: [item], deviceName: 'Pixel', development: false };
      }
      throw new Error('o telefone recusou');
    },
  });

  const [copy] = await openVault(harness);
  await copy.emit('click');

  assert.equal(harness.element('vault-note').textContent, 'o telefone recusou');
  assert.equal(harness.element('vault-note').className, 'muted note--bad');
  assert.equal(copy.disabled, false, 'the row stays usable after a refusal');
});

test('search filters what is already listed, without asking the phone again', async () => {
  const second = { ...item, id: 'item-2', name: 'Email', uri: 'https://mail.example.org' };
  const harness = boot({
    call: async () => ({
      items: [item, second],
      deviceName: 'Pixel',
      development: false,
    }),
  });

  await openVault(harness);
  const listCallsBefore = harness.calls.filter((c) => c.method === 'vault.list').length;

  harness.element('vault-search').value = 'mail.example';
  harness.element('vault-search').emit('input');

  const listed = harness.element('vault-items').text;
  assert.match(listed, /Email/);
  assert.doesNotMatch(listed, /Banco/);
  assert.equal(
    harness.calls.filter((c) => c.method === 'vault.list').length,
    listCallsBefore,
    'filtering must not wake the phone'
  );
});

test('a list from the simulator says so', async () => {
  const harness = boot({
    call: async () => ({ items: [], deviceName: 'sim', development: true }),
  });

  await openVault(harness);

  assert.match(harness.element('vault-note').textContent, /simulador/);
});
