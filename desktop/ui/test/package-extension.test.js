// The store packaging step.
//
// Lives here because this is the directory `node --test` already runs in CI,
// the same reason `browser-extension.test.js` reaches out of it.
//
// Two things are worth testing. The zip has to be a real zip — a writer this
// short is easy to get subtly wrong, and a corrupt upload is discovered by a
// store reviewer days later. And the per-store manifests have to differ in
// exactly the ways each store requires, because a rejection costs a review
// cycle rather than a build.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { execFileSync } = require('node:child_process');
const zlib = require('node:zlib');

const tool = require('../../../tools/package-extension.js');

function sandbox() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'phoneauth-ext-'));
}

/// Reads a zip back through its central directory, the way a consumer does.
///
/// Walking the local headers instead would pass on a file whose directory is
/// wrong, which is exactly the corruption a hand-written writer produces.
function readZip(buffer) {
  const end = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.notEqual(end, -1, 'no end-of-central-directory record');

  const count = buffer.readUInt16LE(end + 10);
  let offset = buffer.readUInt32LE(end + 16);
  const entries = new Map();

  for (let index = 0; index < count; index++) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, 'bad directory header');
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString('utf8', offset + 46, offset + 46 + nameLength);

    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const extraLength = buffer.readUInt16LE(localOffset + 28);
    const dataAt = localOffset + 30 + localNameLength + extraLength;
    const inflated = zlib.inflateRawSync(
      buffer.subarray(dataAt, dataAt + compressedSize)
    );

    assert.equal(inflated.length, uncompressedSize, `${name} size mismatch`);
    assert.equal(tool.crc32(inflated), buffer.readUInt32LE(offset + 16), `${name} crc`);
    entries.set(name, inflated);
    offset += 46 + nameLength + buffer.readUInt16LE(offset + 30) + buffer.readUInt16LE(offset + 32);
  }
  return entries;
}

test('every store gets a readable zip with only the extension in it', () => {
  const out = sandbox();
  const built = tool.build(out);

  assert.equal(built.length, 3);
  for (const { file } of built) {
    const entries = readZip(fs.readFileSync(file));
    assert.deepEqual([...entries.keys()].sort(), [...tool.INCLUDED].sort());

    // Installer scripts and example native-host manifests belong on the
    // user's disk, not inside a signed extension. A reviewer who finds shell
    // scripts in an upload rejects it.
    for (const name of entries.keys()) {
      assert.doesNotMatch(name, /native-host|install\.|\.example$/);
    }
  }
});

test('the chrome build drops what chrome refuses', () => {
  const out = sandbox();
  const file = tool
    .build(out)
    .map(({ file }) => file)
    .find((name) => name.includes('chrome'));

  const manifest = JSON.parse(readZip(fs.readFileSync(file)).get('manifest.json'));

  assert.equal(manifest.browser_specific_settings, undefined);
  assert.equal(manifest.background.scripts, undefined);
  assert.equal(manifest.background.service_worker, 'service-worker.js');
});

test('the firefox build keeps the gecko block it is the only consumer of', () => {
  const out = sandbox();
  const file = tool
    .build(out)
    .map(({ file }) => file)
    .find((name) => name.includes('firefox'));

  const manifest = JSON.parse(readZip(fs.readFileSync(file)).get('manifest.json'));

  assert.equal(manifest.browser_specific_settings.gecko.id, 'webauthn@bioauth.local');
  assert.deepEqual(manifest.background.scripts, ['service-worker.js']);
  assert.equal(manifest.background.service_worker, undefined);
});

/// A zip whose bytes change because the clock moved cannot be checked against
/// a published checksum, so the timestamps are fixed.
test('the same source produces the same bytes', () => {
  const first = tool.build(sandbox())[0].file;
  const second = tool.build(sandbox())[0].file;

  assert.deepEqual(fs.readFileSync(first), fs.readFileSync(second));
});

/// The version in the packaged manifest is the one the release gate checks
/// across the four manifests. A packager that rewrote it would put a build in
/// a store under a version no tag matches.
test('the packaged version is the source version', () => {
  const source = JSON.parse(
    fs.readFileSync(
      path.resolve(__dirname, '../../browser-extension/manifest.json'),
      'utf8'
    )
  );
  const out = sandbox();

  for (const { file } of tool.build(out)) {
    const manifest = JSON.parse(readZip(fs.readFileSync(file)).get('manifest.json'));
    assert.equal(manifest.version, source.version);
    assert.match(path.basename(file), new RegExp(`-${source.version}\\.zip$`));
  }
});

/// The point of the writer being hand-rolled is that the packaging step pulls
/// no code from the network. This is the test that says so: if it ever needs a
/// dependency, this fails first.
test('packaging runs with no installed modules', () => {
  const out = sandbox();
  execFileSync(
    process.execPath,
    [path.resolve(__dirname, '../../../tools/package-extension.js'), '--out', out],
    { stdio: 'pipe' }
  );

  assert.equal(fs.readdirSync(out).length, 3);
});

/// What the desktop installer ships, and the reason it is generated at all.
///
/// `extraResources` used to copy `desktop/browser-extension/` verbatim. That
/// directory holds both engines' shapes on purpose so a developer can point
/// either browser at the source, which makes it the one thing that must never
/// be shipped: Chrome got a Gecko block and an MV2 `background.scripts`,
/// Firefox got a `service_worker` it does not run. And it was not an obscure
/// path -- it was the path the native-host allowlist is registered against, so
/// it is exactly what a user following the instructions loads.
/// Every file under a directory, as paths relative to it, with forward slashes.
function tree(dir, prefix = '') {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? tree(path.join(dir, entry.name), `${prefix}${entry.name}/`)
      : [`${prefix}${entry.name}`]
  );
}

test('the shipped directories are per-browser, not the developer source', () => {
  const out = sandbox();
  const built = tool.buildUnpacked(out);

  assert.deepEqual(
    built.map(({ dir }) => path.basename(dir)).sort(),
    ['chrome', 'edge', 'firefox']
  );

  for (const { dir } of built) {
    // Walked rather than listed: `_locales/<lang>/messages.json` is nested, and
    // a top-level listing would compare a directory name against a file path
    // and pass on anything inside it.
    assert.deepEqual(tree(dir).sort(), [...tool.INCLUDED].sort());

    const manifest = JSON.parse(
      fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8')
    );
    const gecko = path.basename(dir) === 'firefox';

    // The two keys that make the source directory unloadable, each present in
    // exactly one of the three.
    assert.equal(
      manifest.browser_specific_settings !== undefined,
      gecko,
      `${path.basename(dir)} manifest carries the wrong engine's settings block`
    );
    assert.equal(
      manifest.background.scripts !== undefined,
      gecko,
      `${path.basename(dir)} manifest carries the wrong background shape`
    );
    assert.equal(manifest.background.service_worker !== undefined, !gecko);
  }
});

/// A file dropped from `INCLUDED` has to leave a directory that already
/// exists. Merging into it leaves a script the browser still loads, from a
/// version of the extension nobody built.
test('rebuilding a shipped directory removes what no longer belongs', () => {
  const out = sandbox();
  tool.buildUnpacked(out);

  const stale = path.join(out, 'chrome', 'left-behind.js');
  fs.writeFileSync(stale, '// from an older build\n');
  tool.buildUnpacked(out);

  assert.equal(fs.existsSync(stale), false);
});

/// The hook is what makes the two above true of every package, including a
/// `npm run dist` on a laptop. Wired into the build config rather than into
/// the release workflow, because a step only CI runs is a step the local build
/// skips without saying so.
test('the packager runs the generation before every pack', () => {
  const config = JSON.parse(
    fs.readFileSync(path.resolve(__dirname, '..', 'package.json'), 'utf8')
  ).build;

  assert.equal(config.beforePack, 'build/before-pack.js');

  const shipped = config.extraResources.find(
    ({ to }) => to === 'browser-extension'
  );
  assert.equal(shipped.from, '../browser-extension-dist/');

  const hook = require('../build/before-pack.js');
  assert.equal(path.basename(hook.OUTPUT), 'browser-extension-dist');
});
