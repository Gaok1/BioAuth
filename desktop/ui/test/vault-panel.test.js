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
    // Recorded rather than ignored: sending the cursor back to the field that
    // has to be filled in is behaviour worth being able to assert.
    this.focused = false;
  }

  focus() {
    this.focused = true;
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

test('storing a login sends no secret and is given none back', async () => {
  // The direction that puts a password on the phone. The security property is
  // the same one the copy tests defend from the other side: nothing about the
  // secret is on this side of the call. The panel sends a name, a user and an
  // address; the agent generates, sends and forgets. A panel that started
  // sending a `secret` field, or rendering one from the reply, is the moment
  // that stops being true.
  const harness = boot({
    call: async (method) => {
      if (method === 'vault.create') {
        return { itemId: 'item-9', revision: 1, length: 20 };
      }
      return { items: [item], deviceName: 'Pixel' };
    },
  });

  harness.element('vault-new-name').value = 'Banco';
  harness.element('vault-new-username').value = 'alice';
  harness.element('vault-new-uri').value = 'https://banco.example.com';
  await harness.element('vault-store').emit('click');
  await new Promise((resolve) => setImmediate(resolve));

  const created = harness.calls.find((entry) => entry.method === 'vault.create');
  assert.equal(created.params.name, 'Banco');
  assert.equal(created.params.username, 'alice');
  assert.equal(created.params.uri, 'https://banco.example.com');
  // The property this test exists for: the call has three fields and none of
  // them is the password. Asserted on the keys rather than on one name, so a
  // field added later has to be looked at.
  assert.deepEqual(Object.keys(created.params).sort(), ['name', 'uri', 'username']);
  assert.match(harness.element('vault-note').textContent, /20 characters/);
  // Written, so the list this panel is holding is behind by exactly the item
  // the person just made -- and it is the one they will want to copy.
  assert.ok(harness.calls.some((entry) => entry.method === 'vault.list'));
  assert.equal(harness.element('vault-new-name').value, '');
});

test('a store whose re-listing fails still says the item was stored', async () => {
  // The write and the listing are two trips to the phone, and the second
  // raises its own Keystore prompt with no approval sheet to explain it.
  // Declining it does not undo the first. The panel used to write "guardado"
  // over the listing's error and leave an empty list underneath, so the one
  // action available -- press Atualizar -- was the one thing not said.
  const harness = boot({
    call: async (method) => {
      if (method === 'vault.create') {
        return { itemId: 'item-9', revision: 1, length: 20 };
      }
      throw new Error('o telefone recusou');
    },
  });

  harness.element('vault-new-name').value = 'Banco';
  await harness.element('vault-store').emit('click');
  await new Promise((resolve) => setImmediate(resolve));

  const note = harness.element('vault-note');
  assert.match(note.textContent, /20 characters/, 'the write happened');
  assert.match(note.textContent, /o telefone recusou/, 'the listing did not');
  assert.match(note.className, /note--bad/);
  // Still cleared: the item is on the phone, and leaving the fields filled
  // invites a second copy of it.
  assert.equal(harness.element('vault-new-name').value, '');
});

test('a store that fails keeps what was typed', async () => {
  // Clearing the fields on the way out would lose the person's typing every
  // time the phone declined or the write failed -- which is precisely when
  // they are about to try again.
  const harness = boot({
    call: async (method) => {
      if (method === 'vault.create') throw new Error('recusado no telefone');
      return { items: [], deviceName: 'Pixel' };
    },
  });

  harness.element('vault-new-name').value = 'Banco';
  await harness.element('vault-store').emit('click');
  await new Promise((resolve) => setImmediate(resolve));

  assert.match(harness.element('vault-note').textContent, /recusado no telefone/);
  assert.equal(harness.element('vault-new-name').value, 'Banco');
  assert.equal(harness.element('vault-store').disabled, false);
});

test('an unnamed item never reaches the phone', async () => {
  // The name is what the approval sheet is worded from, because the item does
  // not exist on the phone yet. Sending a blank one costs a prompt on the
  // person's phone to be told something this side already knew.
  const harness = boot({ call: async () => ({ items: [], deviceName: 'Pixel' }) });

  await harness.element('vault-store').emit('click');
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(harness.calls.some((entry) => entry.method === 'vault.create'), false);
  assert.match(harness.element('vault-note').textContent, /name/i);
  assert.equal(harness.element('vault-new-name').focused, true);
});

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
  assert.match(harness.element('vault-note').textContent, /clears in \d+s/);
});

test('a copy still in flight survives the list being re-rendered', async () => {
  // The wait is however long someone takes to approve on their phone, and a
  // keystroke in the search box rebuilds every row from `vaultItems`. The
  // button that was disabled and reading "on the phone…" was a detached node
  // after that, and the row on screen was a fresh one: enabled, and inviting
  // a second press for a copy already under way.
  // Every copy is held, not just the first. A second one getting through is
  // the regression this test is for, and a fake that could only answer one
  // would hang on it instead of failing.
  const held = [];
  const release = () => {
    for (const resolve of held.splice(0)) {
      resolve({
        length: 18,
        clearsAtMs: Date.now() + 45000,
        historyExcluded: true,
        cloudExcluded: true,
        memoryLocked: true,
      });
    }
  };
  const harness = boot({
    call: async (method) => {
      if (method === 'vault.list') {
        return { items: [item], deviceName: 'Pixel', development: false };
      }
      if (method === 'vault.copy') {
        return new Promise((resolve) => held.push(resolve));
      }
      return {};
    },
  });

  const [copy] = await openVault(harness);
  const copying = copy.emit('click');
  await new Promise((resolve) => setImmediate(resolve));

  // Anything that re-renders. A search is the cheapest one a person does.
  harness.element('vault-search').emit('input');
  const [redrawn] = harness
    .element('vault-items')
    .children.flatMap((entry) => entry.children)
    .flatMap((row) => row.children)
    .filter((node) => node.dataset && node.dataset.copy);

  assert.equal(redrawn.disabled, true, 'the redrawn row invited a second press');
  assert.equal(redrawn.textContent, 'on the phone…');

  // And pressing it anyway asks the phone nothing further. Not awaited: a
  // press that does get through starts a copy that only `release` below can
  // settle, and awaiting it here would deadlock the test rather than fail it.
  redrawn.emit('click');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(
    harness.calls.filter((entry) => entry.method === 'vault.copy').length,
    1,
    'a second press raised a second approval sheet for one copy'
  );

  release();
  await copying;
  const [settled] = harness
    .element('vault-items')
    .children.flatMap((entry) => entry.children)
    .flatMap((row) => row.children)
    .filter((node) => node.dataset && node.dataset.copy);
  assert.equal(settled.disabled, false);
  assert.equal(settled.textContent, 'copied');
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
  assert.match(note, /clipboard history/);
});

/// The same clipboard, the same reply type, and for a while only one of the
/// two paths read the honest half of it.
///
/// "Generate and copy" is the quicker way to make a password and the one with no
/// item behind it to fall back on, so a copy of it sitting in `Win+V` history
/// -- or synced to a Microsoft account, off this machine entirely -- is the
/// case the user most needs told about.
test('a generated password reports the same clipboard warnings as a stored one', async () => {
  const harness = boot({
    call: async (method) => {
      if (method === 'vault.list') {
        return { items: [item], deviceName: 'Pixel', development: false };
      }
      assert.equal(method, 'vault.generate-copy');
      return {
        length: 20,
        clearsAtMs: Date.now() + 45000,
        historyExcluded: false,
        cloudExcluded: false,
        memoryLocked: true,
      };
    },
  });

  await harness.element('vault-generate').emit('click');

  const note = harness.element('vault-note').textContent;
  assert.match(note, /20 characters/);
  assert.match(note, /clears in \d+s/);
  assert.match(note, /clipboard history/);
  assert.match(note, /synced to the cloud/);
});

test('a clean generated copy says only what it did', async () => {
  const harness = boot({
    call: async () => ({
      length: 20,
      clearsAtMs: Date.now() + 45000,
      historyExcluded: true,
      cloudExcluded: true,
      memoryLocked: true,
    }),
  });

  await harness.element('vault-generate').emit('click');

  const note = harness.element('vault-note').textContent;
  assert.match(note, /clears in \d+s/);
  assert.doesNotMatch(note, /ATEN/, 'nothing failed, so nothing is warned about');
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

  assert.match(harness.element('vault-note').textContent, /simulator/);
});
