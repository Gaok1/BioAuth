// Builds store-ready packages of the browser extension.
//
//     npm run package:extension            (from desktop/ui)
//     node desktop/ui/tools/package-extension.js [--out DIR]
//
// It lives under `desktop/ui` rather than the repo's root `tools/` because that
// is where the only npm project is, and this script has a dependency. Node
// resolves modules upward from the file that requires them, so a script at the
// root could not see `desktop/ui/node_modules`.
//
// Produces one archive per engine, because the two disagree about how a
// background script is declared and Chrome rejects the Firefox spelling:
//
//     phone-auth-passkeys-<version>-chromium.zip   Chrome Web Store, Edge Add-ons
//     phone-auth-passkeys-<version>-firefox.zip    Firefox AMO (upload as .xpi)
//
// The checked-in `manifest.json` carries both spellings on purpose so that
// "load unpacked" works in either engine during development. A store package
// may not: Chrome MV3 wants `background.service_worker` and treats
// `background.scripts` as invalid, while Firefox uses `scripts` and needs the
// `browser_specific_settings.gecko.id` that Chrome has no use for. This script
// is where that split is made explicit instead of living in someone's memory.
//
// Output is byte-for-byte reproducible: entries are written in a fixed order
// with a fixed timestamp, so the same commit always produces the same archive
// and the same SHA-256. That is what lets you check that what a store is
// serving is what this repository built.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const yazl = require('yazl');

const ROOT = path.join(__dirname, '..', '..', '..');
const EXTENSION = path.join(ROOT, 'desktop', 'browser-extension');

// An explicit list, never a directory walk. `native-host/` lives inside the
// extension folder and holds the desktop installer scripts; a walk would
// quietly ship them to a store, and a reviewer would be right to reject that.
// Adding a file to the extension has to be a deliberate edit here.
const PAYLOAD = [
  'content-bridge.js',
  'page-bridge.js',
  'service-worker.js',
];

const ENGINES = {
  chromium: (manifest) => {
    const packaged = { ...manifest };
    packaged.background = { service_worker: 'service-worker.js' };
    delete packaged.browser_specific_settings;
    return packaged;
  },
  firefox: (manifest) => {
    const packaged = { ...manifest };
    packaged.background = { scripts: ['service-worker.js'] };
    return packaged;
  },
};

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

// `desktop/Cargo.toml` is the canonical version for the whole product; the
// release workflow checks the other manifests against it. The extension is
// checked here too, so packaging fails on drift even if it is invoked outside
// that workflow. A store listing that claims a version the build does not is
// not a cosmetic problem: it is the number a user reports a bug against.
function canonicalVersion() {
  const cargo = fs.readFileSync(path.join(ROOT, 'desktop', 'Cargo.toml'), 'utf8');
  const workspace = cargo.split(/^\[/m).find((section) => section.startsWith('workspace.package]'));
  const version = workspace && workspace.match(/^version = "(.*)"$/m);
  if (!version) throw new Error('no [workspace.package] version in desktop/Cargo.toml');
  return version[1];
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

// A fixed instant, so the archive never depends on when it was built. The DOS
// timestamp a ZIP carries cannot express anything before 1980, and yazl clamps
// to that floor.
const EPOCH = new Date(Date.UTC(1980, 0, 1, 0, 0, 0));

function zip(entries) {
  return new Promise((resolve, reject) => {
    const archive = new yazl.ZipFile();
    for (const { name, data } of entries) {
      // A fixed mode too: whatever umask built this must not end up describing
      // the file a browser unpacks.
      archive.addBuffer(data, name, { mtime: EPOCH, mode: 0o100644, compress: true });
    }
    archive.end();

    const chunks = [];
    archive.outputStream.on('data', (chunk) => chunks.push(chunk));
    archive.outputStream.on('error', reject);
    archive.outputStream.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

// ---------------------------------------------------------------------------
// Packaging
// ---------------------------------------------------------------------------

async function build(engine, outputDirectory, extension = EXTENSION) {
  const version = canonicalVersion();
  const source = JSON.parse(fs.readFileSync(path.join(extension, 'manifest.json'), 'utf8'));
  if (source.version !== version) {
    throw new Error(
      `desktop/browser-extension/manifest.json declares '${source.version}', ` +
        `desktop/Cargo.toml says '${version}'`,
    );
  }

  const manifest = ENGINES[engine](source);
  const entries = [
    { name: 'manifest.json', data: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8') },
    // Sorted, so entry order never depends on how the filesystem enumerates.
    ...[...PAYLOAD].sort().map((name) => ({
      name,
      data: fs.readFileSync(path.join(extension, name)),
    })),
  ];

  const archive = await zip(entries);
  const file = path.join(outputDirectory, `phone-auth-passkeys-${version}-${engine}.zip`);
  fs.mkdirSync(outputDirectory, { recursive: true });
  fs.writeFileSync(file, archive);
  return { file, digest: crypto.createHash('sha256').update(archive).digest('hex') };
}

async function main(argv) {
  const flag = argv.indexOf('--out');
  const outputDirectory = flag === -1
    ? path.join(ROOT, 'desktop', 'dist', 'extension')
    : path.resolve(argv[flag + 1]);

  for (const engine of Object.keys(ENGINES)) {
    const { file, digest } = await build(engine, outputDirectory);
    process.stdout.write(`${digest}  ${path.relative(ROOT, file)}\n`);
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { build, canonicalVersion, ENGINES, PAYLOAD };
