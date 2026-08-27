// Generates the tray and window icons.
//
// Written by hand with zlib rather than pulled from an image library: these
// are two flat shapes, and the alternative is a build-time dependency that
// ships nothing but a PNG encoder.
//
// Run with `node tools/make-icons.js` after changing the palette below.

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function crc32(buf) {
  let c;
  const table = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  let crc = 0xffffffff;
  for (const byte of buf) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

/** Builds an RGBA PNG from a pixel callback. */
function png(size, pixel) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  let offset = 0;
  for (let y = 0; y < size; y++) {
    raw[offset++] = 0; // filter: none
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = pixel(x, y, size);
      raw[offset++] = r;
      raw[offset++] = g;
      raw[offset++] = b;
      raw[offset++] = a;
    }
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // colour type: RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** A rounded square with a keyhole cut out of it. */
function icon(accent) {
  return (x, y, size) => {
    const unit = size / 32;
    const cx = size / 2;

    // Rounded-square body.
    const inset = 3 * unit;
    const radius = 8 * unit;
    const dx = Math.max(inset + radius - x, 0, x - (size - inset - radius));
    const dy = Math.max(inset + radius - y, 0, y - (size - inset - radius));
    const outside =
      x < inset || y < inset || x > size - inset || y > size - inset
        ? true
        : Math.hypot(dx, dy) > radius;
    if (outside) return [0, 0, 0, 0];

    // Keyhole: a circle over a tapering stem.
    const holeR = 4 * unit;
    const holeY = 12.5 * unit;
    const inCircle = Math.hypot(x - cx, y - holeY) <= holeR;
    const stemHalf = 2.2 * unit - ((y - holeY) / (10 * unit)) * 0.9 * unit;
    const inStem = y >= holeY && y <= 23 * unit && Math.abs(x - cx) <= stemHalf;
    if (inCircle || inStem) return [0, 0, 0, 0];

    return accent;
  };
}

const assets = path.join(__dirname, '..', 'assets');
fs.mkdirSync(assets, { recursive: true });

// Tray icons are drawn at small sizes on both light and dark menu bars, so a
// mid-tone accent stays legible on either.
const accent = [86, 130, 246, 255];
fs.writeFileSync(path.join(assets, 'tray.png'), png(32, icon(accent)));
fs.writeFileSync(path.join(assets, 'tray@2x.png'), png(64, icon(accent)));
fs.writeFileSync(path.join(assets, 'icon.png'), png(256, icon(accent)));

console.log('wrote tray.png, tray@2x.png and icon.png to', assets);
