// Derives every app icon in the repo from `assets/bioauth-logo-flat.png`.
//
// Run from the repo root after changing the logo:
//
//     node tools/make-icons.js
//
// The outputs are committed, so this is a manual step rather than part of a
// build — no CI job needs an image toolchain, and a logo change shows up as a
// reviewable diff instead of appearing silently in a release.
//
// PNG decoding, resampling and encoding are written out below rather than
// pulled from an image library. That is a deliberate trade: the alternative is
// a native dependency (`sharp`) or a slow pure-JS one (`jimp`) carried by every
// contributor and every CI runner to run a script perhaps twice a year.

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.join(__dirname, '..');
const SOURCE = path.join(ROOT, 'assets', 'bioauth-logo-flat.png');

// ---------------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------------

function crc32(buf) {
  if (!crc32.table) {
    crc32.table = [];
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crc32.table[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (const byte of buf) crc = crc32.table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
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

/** Decodes 8-bit RGBA, non-interlaced PNG — which is what the logo is. */
function decodePng(file) {
  const buf = fs.readFileSync(file);
  let offset = 8;
  const idat = [];
  let width = 0;
  let height = 0;
  let depth = 0;
  let colorType = 0;
  let interlace = 0;

  while (offset < buf.length) {
    const length = buf.readUInt32BE(offset);
    const type = buf.toString('ascii', offset + 4, offset + 8);
    const data = buf.subarray(offset + 8, offset + 8 + length);
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      depth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === 'IDAT') {
      idat.push(data);
    } else if (type === 'IEND') {
      break;
    }
    offset += 12 + length;
  }

  if (depth !== 8 || colorType !== 6 || interlace !== 0) {
    throw new Error(
      `${file}: expected an 8-bit RGBA non-interlaced PNG, got ` +
        `depth=${depth} colorType=${colorType} interlace=${interlace}`,
    );
  }

  const raw = zlib.inflateSync(Buffer.concat(idat));
  const bpp = 4;
  const stride = width * bpp;
  const data = Buffer.alloc(width * height * bpp);
  let previous = Buffer.alloc(stride);
  let read = 0;

  for (let y = 0; y < height; y++) {
    const filter = raw[read++];
    const line = raw.subarray(read, read + stride);
    read += stride;
    const current = Buffer.alloc(stride);

    for (let i = 0; i < stride; i++) {
      const left = i >= bpp ? current[i - bpp] : 0;
      const up = previous[i];
      const upLeft = i >= bpp ? previous[i - bpp] : 0;
      let value = line[i];
      switch (filter) {
        case 0:
          break;
        case 1:
          value += left;
          break;
        case 2:
          value += up;
          break;
        case 3:
          value += (left + up) >> 1;
          break;
        case 4: {
          const estimate = left + up - upLeft;
          const dl = Math.abs(estimate - left);
          const du = Math.abs(estimate - up);
          const dul = Math.abs(estimate - upLeft);
          value += dl <= du && dl <= dul ? left : du <= dul ? up : upLeft;
          break;
        }
        default:
          throw new Error(`${file}: unknown row filter ${filter}`);
      }
      current[i] = value & 0xff;
    }

    current.copy(data, y * stride);
    previous = current;
  }

  return { width, height, data };
}

/**
 * Encodes RGBA, or RGB when `opaque` is set.
 *
 * iOS rejects an app icon that carries an alpha channel at all — even a fully
 * opaque one — so those targets need the channel dropped, not just filled.
 */
function encodePng(image, { opaque = false } = {}) {
  const { width, height, data } = image;
  const channels = opaque ? 3 : 4;
  const stride = width * channels;
  const raw = Buffer.alloc(height * (stride + 1));
  let write = 0;

  for (let y = 0; y < height; y++) {
    raw[write++] = 0; // filter: none
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4;
      raw[write++] = data[i];
      raw[write++] = data[i + 1];
      raw[write++] = data[i + 2];
      if (!opaque) raw[write++] = data[i + 3];
    }
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = opaque ? 2 : 6;

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ---------------------------------------------------------------------------
// Pixels
// ---------------------------------------------------------------------------

/**
 * Area-averaged downscale.
 *
 * Every target is smaller than the 1254px source, so averaging the source
 * pixels each destination pixel covers is both correct and the best available
 * filter — no separate anti-aliasing pass is needed.
 *
 * Colour is averaged premultiplied by alpha. Skipping that step lets the fully
 * transparent pixels outside the mark — which are transparent *black* — drag
 * the edges toward a dark fringe.
 */
function resample(source, rect, size) {
  const out = Buffer.alloc(size * size * 4);
  const scaleX = rect.width / size;
  const scaleY = rect.height / size;

  for (let y = 0; y < size; y++) {
    const y0 = rect.y + y * scaleY;
    const y1 = y0 + scaleY;
    const fromY = Math.floor(y0);
    const toY = Math.max(fromY + 1, Math.ceil(y1));

    for (let x = 0; x < size; x++) {
      const x0 = rect.x + x * scaleX;
      const x1 = x0 + scaleX;
      const fromX = Math.floor(x0);
      const toX = Math.max(fromX + 1, Math.ceil(x1));

      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      let n = 0;

      for (let sy = fromY; sy < toY; sy++) {
        if (sy < 0 || sy >= source.height) continue;
        for (let sx = fromX; sx < toX; sx++) {
          if (sx < 0 || sx >= source.width) continue;
          const i = (sy * source.width + sx) * 4;
          const alpha = source.data[i + 3];
          r += source.data[i] * alpha;
          g += source.data[i + 1] * alpha;
          b += source.data[i + 2] * alpha;
          a += alpha;
          n++;
        }
      }

      const o = (y * size + x) * 4;
      if (n === 0 || a === 0) continue;
      out[o] = Math.round(r / a);
      out[o + 1] = Math.round(g / a);
      out[o + 2] = Math.round(b / a);
      out[o + 3] = Math.round(a / n);
    }
  }

  return { width: size, height: size, data: out };
}

/** Centres `image` on a transparent square of `size`, scaled to `coverage`. */
function place(source, rect, size, coverage) {
  const inner = Math.round(size * coverage);
  // Preserve the aspect ratio: the mark is not quite square.
  const scale = inner / Math.max(rect.width, rect.height);
  const width = Math.max(1, Math.round(rect.width * scale));
  const height = Math.max(1, Math.round(rect.height * scale));

  // `resample` is square-only, so scale on the longer axis and letterbox the
  // shorter one by widening the source rect symmetrically.
  const side = Math.max(width, height);
  const padX = (side - width) * (rect.width / Math.max(1, width));
  const padY = (side - height) * (rect.height / Math.max(1, height));
  const padded = {
    x: rect.x - padX / 2,
    y: rect.y - padY / 2,
    width: rect.width + padX,
    height: rect.height + padY,
  };

  const scaled = resample(source, padded, side);
  const canvas = { width: size, height: size, data: Buffer.alloc(size * size * 4) };
  const offset = Math.round((size - side) / 2);

  for (let y = 0; y < side; y++) {
    const ty = y + offset;
    if (ty < 0 || ty >= size) continue;
    for (let x = 0; x < side; x++) {
      const tx = x + offset;
      if (tx < 0 || tx >= size) continue;
      scaled.data.copy(canvas.data, (ty * size + tx) * 4, (y * side + x) * 4, (y * side + x) * 4 + 4);
    }
  }

  return canvas;
}

/** Composites over an opaque background. */
function flatten(image, [br, bg, bb]) {
  const data = Buffer.from(image.data);
  for (let i = 0; i < data.length; i += 4) {
    const a = data[i + 3];
    data[i] = Math.round((data[i] * a + br * (255 - a)) / 255);
    data[i + 1] = Math.round((data[i + 1] * a + bg * (255 - a)) / 255);
    data[i + 2] = Math.round((data[i + 2] * a + bb * (255 - a)) / 255);
    data[i + 3] = 255;
  }
  return { ...image, data };
}

// ---------------------------------------------------------------------------
// Reading the logo's geometry
// ---------------------------------------------------------------------------

/**
 * Splits the lockup into the fingerprint mark and the "BioAuth" wordmark.
 *
 * Both are found by scanning for ink rather than hardcoded, so re-exporting the
 * logo at another size or with different margins does not silently shift every
 * icon.
 */
function measure(image) {
  const { width, height, data } = image;
  const rows = new Array(height).fill(0);
  const columns = new Array(width).fill(0);

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (data[(y * width + x) * 4 + 3] >= 32) {
        rows[y]++;
        columns[x]++;
      }
    }
  }

  const inkTop = rows.findIndex((n) => n > 0);
  const inkBottom = height - 1 - [...rows].reverse().findIndex((n) => n > 0);
  if (inkTop < 0) throw new Error('the logo has no visible pixels');

  // The widest fully empty band inside the ink is the gap between the mark and
  // the wordmark.
  let widest = null;
  let start = -1;
  for (let y = inkTop; y <= inkBottom; y++) {
    if (rows[y] === 0) {
      if (start < 0) start = y;
    } else if (start >= 0) {
      if (!widest || y - start > widest.end - widest.start) widest = { start, end: y };
      start = -1;
    }
  }
  if (!widest) throw new Error('could not find the gap between the mark and the wordmark');

  const boundsIn = (top, bottom) => {
    let left = width;
    let right = -1;
    for (let y = top; y <= bottom; y++) {
      for (let x = 0; x < width; x++) {
        if (data[(y * width + x) * 4 + 3] >= 32) {
          if (x < left) left = x;
          if (x > right) right = x;
        }
      }
    }
    return { x: left, y: top, width: right - left + 1, height: bottom - top + 1 };
  };

  return {
    mark: boundsIn(inkTop, widest.start - 1),
    lockup: boundsIn(inkTop, inkBottom),
  };
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

const written = [];

function write(relative, buffer) {
  const target = path.join(ROOT, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, buffer);
  written.push(`${relative} (${(buffer.length / 1024).toFixed(1)} kB)`);
}

const logo = decodePng(SOURCE);
const { mark, lockup } = measure(logo);
console.log(
  `source ${logo.width}x${logo.height}; ` +
    `mark ${mark.width}x${mark.height} at ${mark.x},${mark.y}; ` +
    `lockup ${lockup.width}x${lockup.height}`,
);

// The wordmark is dropped from every launcher and tray icon. At 48 px the word
// "BioAuth" is about six pixels tall and resolves to a grey smudge that reads
// as dirt on the mark rather than as text. It is kept only where the image is
// shown large, which is the README.
const icon = (size, coverage) => encodePng(place(logo, mark, size, coverage));

// -- Desktop (Electron) -----------------------------------------------------
// `icon.png` feeds electron-builder, which derives the Windows .ico and the
// Linux hicolor set from it. 512 is the largest size it asks for.
write('desktop/ui/assets/icon.png', icon(512, 0.86));

// The tray sits on a 16-24 px strip, so the mark is given nearly the whole
// canvas — the platform supplies its own padding, and any we add here is lost
// as blank pixels the user cannot see.
write('desktop/ui/assets/tray.png', icon(32, 0.96));
write('desktop/ui/assets/tray@2x.png', icon(64, 0.96));

// -- Android ----------------------------------------------------------------
const DENSITIES = [
  ['mdpi', 1],
  ['hdpi', 1.5],
  ['xhdpi', 2],
  ['xxhdpi', 3],
  ['xxxhdpi', 4],
];

for (const [density, scale] of DENSITIES) {
  // Legacy launcher icon: pre-Android 8 and anywhere the adaptive icon is not
  // used. 48 dp.
  write(
    `mobile/android/app/src/main/res/mipmap-${density}/ic_launcher.png`,
    icon(Math.round(48 * scale), 0.92),
  );

  // Adaptive foreground: a 108 dp canvas of which only the centre 72 dp is
  // guaranteed visible — the launcher masks the rest to whatever shape it
  // likes and parallaxes the layer. Anything outside that circle gets clipped
  // on some devices and not others, so the mark stays well inside it.
  write(
    `mobile/android/app/src/main/res/mipmap-${density}/ic_launcher_foreground.png`,
    icon(Math.round(108 * scale), 0.56),
  );
}

// No `ic_launcher_round`: that is the API 25 mechanism, and it is superseded
// here — an adaptive icon is masked to whatever shape the launcher wants,
// round included. Declaring `android:roundIcon` would also oblige us to ship a
// round bitmap for every pre-26 density, which nothing would ever read.
write(
  'mobile/android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml',
  Buffer.from(`<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@mipmap/ic_launcher_foreground" />
    <monochrome android:drawable="@mipmap/ic_launcher_foreground" />
</adaptive-icon>
`),
);

// The mark is a cyan-to-violet gradient drawn for a light ground; on the brand
// navy its right-hand end loses most of its contrast. White is what the logo
// was designed against.
write(
  'mobile/android/app/src/main/res/values/ic_launcher_background.xml',
  Buffer.from(`<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="ic_launcher_background">#FFFFFFFF</color>
</resources>
`),
);

// -- iOS --------------------------------------------------------------------
// Sizes are taken from the generated AppIcon.appiconset; each is opaque white
// because iOS both rejects alpha and applies its own rounded-rect mask.
const IOS = [
  ['Icon-App-20x20@1x.png', 20],
  ['Icon-App-20x20@2x.png', 40],
  ['Icon-App-20x20@3x.png', 60],
  ['Icon-App-29x29@1x.png', 29],
  ['Icon-App-29x29@2x.png', 58],
  ['Icon-App-29x29@3x.png', 87],
  ['Icon-App-40x40@1x.png', 40],
  ['Icon-App-40x40@2x.png', 80],
  ['Icon-App-40x40@3x.png', 120],
  ['Icon-App-60x60@2x.png', 120],
  ['Icon-App-60x60@3x.png', 180],
  ['Icon-App-76x76@1x.png', 76],
  ['Icon-App-76x76@2x.png', 152],
  ['Icon-App-83.5x83.5@2x.png', 167],
  ['Icon-App-1024x1024@1x.png', 1024],
];

for (const [name, size] of IOS) {
  const composed = flatten(place(logo, mark, size, 0.78), [255, 255, 255]);
  write(`mobile/ios/Runner/Assets.xcassets/AppIcon.appiconset/${name}`, encodePng(composed, { opaque: true }));
}

// -- Docs -------------------------------------------------------------------
// The full lockup, for anywhere the brand is shown large enough for the
// wordmark to be legible.
write('docs/media/logo.png', encodePng(place(logo, lockup, 480, 0.98)));
// The mark alone, for the README header, which already carries the product
// name as a heading directly underneath.
write('docs/media/mark.png', icon(128, 1));

console.log(`\nwrote ${written.length} files:`);
for (const line of written) console.log(`  ${line}`);
