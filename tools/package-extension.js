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

function build(outDir) {
  const manifestSource = JSON.parse(
    fs.readFileSync(path.join(source, 'manifest.json'), 'utf8')
  );
  fs.mkdirSync(outDir, { recursive: true });

  const built = [];
  for (const [target, adjust] of Object.entries(TARGETS)) {
    const manifest = adjust(JSON.parse(JSON.stringify(manifestSource)));
    const entries = [
      ['manifest.json', Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8')],
      ...INCLUDED.filter((name) => name !== 'manifest.json').map((name) => [
        name,
        fs.readFileSync(path.join(source, name)),
      ]),
    ];

    const file = path.join(
      outDir,
      `phoneauth-passkeys-${target}-${manifestSource.version}.zip`
    );
    fs.writeFileSync(file, zip(entries));
    built.push({ file, version: manifestSource.version });
  }
  return built;
}

module.exports = { build, zip, crc32, TARGETS, INCLUDED };

if (require.main === module) {
  const flag = process.argv.indexOf('--out');
  const outDir = path.resolve(
    root,
    flag === -1 ? 'dist/extension' : process.argv[flag + 1]
  );
  for (const { file } of build(outDir)) {
    console.log(path.relative(root, file));
  }
}
