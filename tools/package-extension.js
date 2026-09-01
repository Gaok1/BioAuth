#!/usr/bin/env node
'use strict';

// Builds the store upload for the browser extension.
//
// Three stores want three slightly different things from the same source, and
// none of them wants `native-host/` — those are installer scripts and example
// manifests that belong on the user's disk, not inside a signed extension. A
// reviewer who finds shell scripts in an upload is a reviewer who rejects it.
//
// What this does NOT do is sign anything. Chrome Web Store, Edge Add-ons and
// AMO all sign on their side, after a submission made with an account this
// script has no business holding. The zips are the input to that.
//
//   node tools/package-extension.js [--out dist/extension]
//   node tools/package-extension.js --unpacked <dir>    # loadable directories
//
// Deliberately dependency-free: it runs in the release workflow before any
// `npm install`, and a packaging step that can itself pull code from the
// network is a supply-chain step nobody reviewed.

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const root = path.resolve(__dirname, '..');
const source = path.join(root, 'desktop', 'browser-extension');

/** Files that go into every upload. */
const INCLUDED = [
  'manifest.json',
  'service-worker.js',
  'content-bridge.js',
  'page-bridge.js',
  'autofill-bridge.js',
];

/**
 * Per-store manifest edits.
 *
 * Chrome refuses `browser_specific_settings`; Firefox refuses MV3
 * `background.scripts` alongside `service_worker` in some versions and wants
 * the Gecko block it is the only consumer of. One source manifest carries
 * both because loading unpacked has to keep working in either browser, and
 * this is where that convenience is paid for.
 */
const TARGETS = {
  chrome: (manifest) => {
    delete manifest.browser_specific_settings;
    delete manifest.background.scripts;
    return manifest;
  },
  edge: (manifest) => {
    delete manifest.browser_specific_settings;
    delete manifest.background.scripts;
    return manifest;
  },
  firefox: (manifest) => {
    delete manifest.background.service_worker;
    return manifest;
  },
};

/** A minimal store-format zip writer. */
function zip(entries) {
  const chunks = [];
  const central = [];
  let offset = 0;

  for (const [name, contents] of entries) {
    const nameBytes = Buffer.from(name, 'utf8');
    const deflated = zlib.deflateRawSync(contents, { level: 9 });
    const crc = crc32(contents);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(8, 8); // deflate
    // A fixed timestamp, so the same source produces the same bytes. A zip
    // whose hash changes because the clock moved cannot be checked against a
    // published checksum.
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0x0021, 12); // 1980-01-01
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(deflated.length, 18);
    local.writeUInt32LE(contents.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);

    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(0, 8);
    header.writeUInt16LE(8, 10);
    header.writeUInt16LE(0, 12);
    header.writeUInt16LE(0x0021, 14);
    header.writeUInt32LE(crc, 16);
    header.writeUInt32LE(deflated.length, 20);
    header.writeUInt32LE(contents.length, 24);
    header.writeUInt16LE(nameBytes.length, 28);
    header.writeUInt32LE(offset, 42);

    chunks.push(local, nameBytes, deflated);
    central.push(Buffer.concat([header, nameBytes]));
    offset += local.length + nameBytes.length + deflated.length;
  }

  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);

  return Buffer.concat([...chunks, directory, end]);
}

let crcTable = null;
function crc32(buffer) {
  if (!crcTable) {
    crcTable = new Int32Array(256);
    for (let index = 0; index < 256; index++) {
      let value = index;
      for (let bit = 0; bit < 8; bit++) {
        value = value & 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
      }
      crcTable[index] = value;
    }
  }
  let crc = -1;
  for (const byte of buffer) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff];
  return (crc ^ -1) >>> 0;
}

function readManifest() {
  return JSON.parse(fs.readFileSync(path.join(source, 'manifest.json'), 'utf8'));
}

/** The file set one browser gets, manifest already adjusted for it. */
function filesFor(target, manifestSource) {
  const manifest = TARGETS[target](JSON.parse(JSON.stringify(manifestSource)));
  return [
    ['manifest.json', Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8')],
    ...INCLUDED.filter((name) => name !== 'manifest.json').map((name) => [
      name,
      fs.readFileSync(path.join(source, name)),
    ]),
  ];
}

function build(outDir) {
  const manifestSource = readManifest();
  fs.mkdirSync(outDir, { recursive: true });

  const built = [];
  for (const target of Object.keys(TARGETS)) {
    const file = path.join(
      outDir,
      `phoneauth-passkeys-${target}-${manifestSource.version}.zip`
    );
    fs.writeFileSync(file, zip(filesFor(target, manifestSource)));
    built.push({ file, version: manifestSource.version });
  }
  return built;
}

/**
 * The same per-browser file sets, as directories rather than zips.
 *
 * This is what the desktop installer ships. It used to copy
 * `desktop/browser-extension/` verbatim, and that directory is deliberately
 * not loadable: it carries both engines' shapes at once -- MV2
 * `background.scripts` next to an MV3 `service_worker`, and a Gecko block
 * Chrome does not know -- so a developer can point either browser at the
 * source while working. Shipping it meant the one path the native-host
 * allowlist was registered for was also the one path that hands each browser
 * half a manifest written for the other.
 *
 * A zip is no answer here: nothing unpacks it, and an unpacked extension's ID
 * on Chromium is a hash of the directory it was loaded from. Unzipping to
 * Downloads is how a person ends up with an ID the allowlist has never heard
 * of -- a native host that hangs up, with nothing in the browser to say why.
 */
function buildUnpacked(outDir) {
  const manifestSource = readManifest();
  const built = [];
  for (const target of Object.keys(TARGETS)) {
    const dir = path.join(outDir, target);
    // Rebuilt rather than merged into: a file dropped from `INCLUDED` has to
    // leave the shipped directory too, and a stale script in an extension is
    // one the browser still loads.
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true });
    for (const [name, contents] of filesFor(target, manifestSource)) {
      fs.writeFileSync(path.join(dir, name), contents);
    }
    built.push({ dir, version: manifestSource.version });
  }
  return built;
}

module.exports = { build, buildUnpacked, zip, crc32, TARGETS, INCLUDED };

if (require.main === module) {
  const unpacked = process.argv.indexOf('--unpacked');
  if (unpacked !== -1) {
    const outDir = path.resolve(root, process.argv[unpacked + 1]);
    for (const { dir } of buildUnpacked(outDir)) {
      console.log(path.relative(root, dir));
    }
  } else {
    const flag = process.argv.indexOf('--out');
    const outDir = path.resolve(
      root,
      flag === -1 ? 'dist/extension' : process.argv[flag + 1]
    );
    for (const { file } of build(outDir)) {
      console.log(path.relative(root, file));
    }
  }
}
