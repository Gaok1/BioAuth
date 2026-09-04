// The extension's two message packs, and the fallbacks written beside them.
//
// `_locales/` is the browser's own mechanism, so there is no code to test in
// how a message is chosen -- the browser chooses. What can go wrong is what the
// files hold: a key in one language and not the other, a key the code asks for
// that neither has, and the fallback English written into every `t()` call
// drifting away from the English in the pack. The fallback is not decoration:
// it is what a browser without `i18n` shows, and what `node --test` sees.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const extension = path.resolve(__dirname, '../../browser-extension');
const locales = path.join(extension, '_locales');

const packs = Object.fromEntries(
  fs
    .readdirSync(locales)
    .map((language) => [
      language,
      JSON.parse(fs.readFileSync(path.join(locales, language, 'messages.json'), 'utf8')),
    ])
);

/// Every `t("key", "fallback")` in the extension's own scripts.
const calls = fs
  .readdirSync(extension)
  .filter((name) => name.endsWith('.js'))
  .flatMap((name) => {
    const source = fs.readFileSync(path.join(extension, name), 'utf8');
    return [...source.matchAll(/\bt\(\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\)/g)].map(
      ([, key, fallback]) => ({ name, key, fallback })
    );
  });

const defaultLocale = JSON.parse(
  fs.readFileSync(path.join(extension, 'manifest.json'), 'utf8')
).default_locale;

test('the manifest names a pack that is actually shipped', () => {
  assert.ok(defaultLocale, 'the manifest declares a default locale');
  assert.ok(packs[defaultLocale], `\`${defaultLocale}\` is not in _locales/`);
});

test('every pack holds the same keys', () => {
  const expected = Object.keys(packs[defaultLocale]).sort();
  assert.ok(expected.length > 0, 'the default pack has messages in it');

  for (const [language, pack] of Object.entries(packs)) {
    assert.deepEqual(Object.keys(pack).sort(), expected, `\`${language}\``);
  }
});

test('every key the code asks for is in every pack', () => {
  assert.ok(calls.length > 0, 'the scripts ask for messages');

  for (const { name, key } of calls) {
    for (const [language, pack] of Object.entries(packs)) {
      assert.ok(pack[key], `${name} asks for \`${key}\`, missing from \`${language}\``);
    }
  }
});

/// The fallback is what a browser with no `i18n` shows and what the test
/// harness sees, so a fallback that has drifted from the pack is a second
/// wording of the same sentence that nobody is maintaining.
test('every fallback is the message the default pack holds', () => {
  for (const { name, key, fallback } of calls) {
    assert.equal(
      fallback,
      packs[defaultLocale][key]?.message,
      `${name}: the fallback for \`${key}\` is not what \`${defaultLocale}\` says`
    );
  }
});

/// A message nothing asks for is a sentence being translated for nobody.
test('every message in the packs is asked for somewhere', () => {
  const asked = new Set(calls.map((call) => call.key));

  for (const key of Object.keys(packs[defaultLocale])) {
    assert.ok(asked.has(key), `\`${key}\` is in the packs and nothing asks for it`);
  }
});
