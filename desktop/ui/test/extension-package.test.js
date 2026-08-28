// Covers `tools/package-extension.js`.
//
// The archive is read back with the small parser below rather than trusted from
// the writer's own bookkeeping: a store package that says it contains four
// files and actually contains five is exactly the failure worth catching.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const zlib = require('node:zlib');

const packager = require('../tools/package-extension.js');

const EXTENSION = path.resolve(__dirname, '../../browser-extension');

function scratch() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'bioauth-extension-'));
}

// Reads a ZIP through its central directory, which is what an unpacker uses.
// Walking the local headers instead would miss an entry that was written but
// never indexed, and a browser would never see such a file.
function entries(file) {
  const buffer = fs.readFileSync(file);
  const end = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.notEqual(end, -1, 'no end-of-central-directory record');
  const count = buffer.readUInt16LE(end + 10);
  let offset = buffer.readUInt32LE(end + 16);

  const found = new Map();
  for (let index = 0; index < count; index++) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, 'bad central directory signature');
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString('utf8');

    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const start = localOffset + 30 + localNameLength + localExtraLength;
    const raw = buffer.subarray(start, start + compressedSize);
    found.set(name, method === 8 ? zlib.inflateRawSync(raw) : raw);

    offset += 46 + nameLength + extraLength + commentLength;
  }
  return found;
}

async function pack(engine, extension = EXTENSION) {
  const { file } = await packager.build(engine, scratch(), extension);
  return entries(file);
}

test('the store package never carries the native host installers', async () => {
  for (const engine of Object.keys(packager.ENGINES)) {
    const names = [...(await pack(engine)).keys()];
    assert.deepEqual(
      names.sort(),
      ['content-bridge.js', 'manifest.json', 'page-bridge.js', 'service-worker.js'],
      `${engine} package has unexpected contents`,
    );
    // The installers live inside the extension folder, so their absence is the
    // whole reason the payload is an explicit list rather than a directory walk.
    assert.equal(names.some((name) => name.includes('native-host')), false);
    assert.equal(names.some((name) => name.endsWith('.ps1') || name.endsWith('.sh')), false);
  }
});

test('each engine gets the background spelling it accepts', async () => {
  const chromium = JSON.parse((await pack('chromium')).get('manifest.json').toString('utf8'));
  assert.equal(chromium.background.service_worker, 'service-worker.js');
  assert.equal('scripts' in chromium.background, false);
  // Chrome has no use for the Gecko block and a reviewer reads it as sloppiness.
  assert.equal('browser_specific_settings' in chromium, false);

  const firefox = JSON.parse((await pack('firefox')).get('manifest.json').toString('utf8'));
  assert.deepEqual(firefox.background.scripts, ['service-worker.js']);
  assert.equal('service_worker' in firefox.background, false);
  // AMO signs against this ID, and the native host allowlists it by name.
  assert.equal(firefox.browser_specific_settings.gecko.id, 'webauthn@bioauth.local');
});

test('the packaged scripts are the ones in the repository', async () => {
  const packaged = await pack('chromium');
  for (const name of packager.PAYLOAD) {
    assert.deepEqual(
      packaged.get(name),
      fs.readFileSync(path.join(EXTENSION, name)),
      `${name} was altered on the way into the package`,
    );
  }
});

test('the same commit always produces the same bytes', async () => {
  const first = scratch();
  const second = scratch();
  for (const engine of Object.keys(packager.ENGINES)) {
    const a = await packager.build(engine, first);
    const b = await packager.build(engine, second);
    assert.equal(a.digest, b.digest, `${engine} package is not reproducible`);
    assert.deepEqual(fs.readFileSync(a.file), fs.readFileSync(b.file));
  }
});

test('a version that disagrees with the workspace is refused', async () => {
  const tampered = scratch();
  fs.cpSync(EXTENSION, tampered, { recursive: true });
  const manifestPath = path.join(tampered, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.version = '9.9.9';
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  await assert.rejects(
    () => packager.build('chromium', scratch(), tampered),
    /declares '9\.9\.9'/,
    'packaging accepted a manifest version the workspace does not claim',
  );
});

test('the checked-in manifest already agrees with the workspace', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(EXTENSION, 'manifest.json'), 'utf8'));
  assert.equal(manifest.version, packager.canonicalVersion());
});
