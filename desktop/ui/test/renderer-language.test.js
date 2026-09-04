// The tray window's language packs, and the markup that reads them.
//
// The phone gets this from the compiler: `AppStrings` is an abstract class, so
// a string that exists in one language and not the other does not build. The
// window's packs are two object literals, and nothing there fails -- a missing
// key silently falls back to English, and a key the markup asks for that no
// pack has renders as `undefined`. These are the checks that stand in for the
// compiler the window does not have.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const renderer = path.resolve(__dirname, '../renderer');
const markup = fs.readFileSync(path.join(renderer, 'index.html'), 'utf8');

/// The packs, read out of the window rather than parsed out of the file.
function packs() {
  const element = () => ({
    dataset: {},
    style: {},
    classList: { toggle: () => {} },
    appendChild(child) {
      return child;
    },
    addEventListener: () => {},
    textContent: '',
    value: '',
    hidden: false,
  });
  const context = vm.createContext({
    document: {
      hidden: false,
      getElementById: element,
      createElement: element,
      querySelectorAll: () => [],
      addEventListener: () => {},
      documentElement: {},
    },
    window: {
      phoneAuth: {
        info: async () => ({}),
        onStatus: () => () => {},
        onEvent: () => () => {},
      },
    },
    URL,
    Date,
    Math,
    setTimeout: () => 0,
    clearTimeout: () => {},
    setInterval: () => 0,
    clearInterval: () => {},
    console,
  });
  context.globalThis = context;
  vm.runInContext(fs.readFileSync(path.join(renderer, 'renderer.js'), 'utf8'), context);
  // `STRINGS` is a top-level `const`, so it lives in the context's lexical
  // scope rather than on its global object. A second script in the same
  // context can see it.
  return vm.runInContext('STRINGS', context);
}

/// Every key the markup asks a pack for.
function keysInMarkup() {
  const keys = new Set();
  for (const [, key] of markup.matchAll(/data-i18n="([^"]+)"/g)) keys.add(key);
  for (const [, pair] of markup.matchAll(/data-i18n-attr="([^"]+)"/g)) {
    keys.add(pair.split(':')[1]);
  }
  return keys;
}

test('the packs hold the same keys', () => {
  const STRINGS = packs();
  const languages = Object.keys(STRINGS);
  assert.ok(languages.length >= 2, 'there is more than one pack to compare');

  const [first, ...rest] = languages;
  for (const language of rest) {
    assert.deepEqual(
      Object.keys(STRINGS[language]).sort(),
      Object.keys(STRINGS[first]).sort(),
      `\`${language}\` and \`${first}\` do not hold the same keys`
    );
  }
});

/// A key that is a sentence in one language and a function taking arguments in
/// the other is worse than a missing one: `t()` returns the string, the caller
/// passes arguments nobody reads, and the number lands nowhere.
test('a key is the same kind of thing in every pack', () => {
  const STRINGS = packs();
  const [first, ...rest] = Object.keys(STRINGS);

  for (const language of rest) {
    for (const key of Object.keys(STRINGS[first])) {
      assert.equal(
        typeof STRINGS[language][key],
        typeof STRINGS[first][key],
        `\`${key}\` is a ${typeof STRINGS[first][key]} in ${first} and a ` +
          `${typeof STRINGS[language][key]} in ${language}`
      );
    }
  }
});

/// A key the markup asks for that no pack has renders as the word `undefined`
/// in the window, which is the one failure a person would report as "it broke".
test('every key the markup asks for exists in every pack', () => {
  const STRINGS = packs();

  for (const key of keysInMarkup()) {
    for (const [language, pack] of Object.entries(STRINGS)) {
      assert.ok(key in pack, `\`${key}\` is asked for in the markup, missing from \`${language}\``);
    }
  }
});

/// Words the window says in every language.
///
/// The product's own name, and nothing else. An entry here is a promise that
/// the string reads the same to a Portuguese speaker as to an English one.
const SAME_IN_EVERY_LANGUAGE = new Set(['PhoneAuth']);

/// Text written into the markup is text no pack can reach.
///
/// `applyLanguage` rewrites the content of elements carrying `data-i18n` and
/// nothing else, so a sentence typed straight between two tags is a sentence
/// the language picker cannot touch. It looks right in English, which is how it
/// survives review, and it stays English on a phone -- and on a window -- set
/// to anything else.
test('no text in the markup is left where a pack cannot reach it', () => {
  const body = markup.slice(markup.indexOf('<body'), markup.lastIndexOf('</body>'));
  const stripped = body
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<script[\s\S]*?<\/script>/g, '')
    .replace(/<style[\s\S]*?<\/style>/g, '');

  const offenders = [];
  const stack = [];
  const token = /<(\/?)([a-zA-Z0-9-]+)([^>]*)>|([^<]+)/g;

  for (const [, closing, name, attributes, text] of stripped.matchAll(token)) {
    if (text !== undefined) {
      const trimmed = text.trim();
      if (!trimmed || SAME_IN_EVERY_LANGUAGE.has(trimmed)) continue;
      if (!stack.some((frame) => frame.translated)) offenders.push(trimmed);
      continue;
    }
    if (closing) {
      const index = stack.map((frame) => frame.name).lastIndexOf(name);
      if (index >= 0) stack.length = index;
      continue;
    }
    // A void element holds no text, and neither does a self-closed one.
    if (/\/\s*$/.test(attributes) || /^(br|hr|img|input|meta|link)$/i.test(name)) continue;
    stack.push({ name, translated: /data-i18n=/.test(attributes) });
  }

  assert.deepEqual(
    offenders,
    [],
    'Give each of these a `data-i18n` key, or let the renderer write it:\n' +
      offenders.join('\n')
  );
});
