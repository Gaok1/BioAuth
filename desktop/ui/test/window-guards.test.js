'use strict';

// The tray window is a view onto a local socket, and `preload.js` attaches the
// agent bridge to whatever document lives in it. So "where may this window go"
// and "who may hold `vault.copy`" are the same question, and the answer has to
// be the page it loaded and nothing else.

const test = require('node:test');
const assert = require('node:assert');

const { allowsNavigation, externalTarget } = require('../src/window-guards');

const PAGE = 'file:///C:/Program%20Files/PhoneAuth/renderer/index.html';

test('the window may reload itself and jump within its own page', () => {
  assert.equal(allowsNavigation(PAGE, PAGE), true);
  assert.equal(allowsNavigation(PAGE, `${PAGE}#devices`), true);
  assert.equal(allowsNavigation(`${PAGE}#devices`, `${PAGE}#vault`), true);
});

test('the window may not become a remote origin', () => {
  // The one that matters: a page served from anywhere else would come up
  // holding `window.phoneAuth`, and `vault.copy` puts a password on the
  // clipboard without this process ever seeing it -- which is exactly the
  // property that makes it safe from the renderer and dangerous from a site.
  assert.equal(allowsNavigation(PAGE, 'https://example.com/'), false);
  assert.equal(allowsNavigation(PAGE, 'http://127.0.0.1:8080/'), false);
});

test('the window may not walk to another file on disk', () => {
  assert.equal(
    allowsNavigation(PAGE, 'file:///C:/Users/someone/Downloads/page.html'),
    false
  );
  assert.equal(allowsNavigation(PAGE, 'about:blank'), false);
});

test('a missing or malformed URL is not a navigation anyone may make', () => {
  assert.equal(allowsNavigation(PAGE, undefined), false);
  assert.equal(allowsNavigation(undefined, PAGE), false);
  assert.equal(allowsNavigation(PAGE, ''), false);
});

test('web links reach the browser', () => {
  assert.equal(externalTarget('https://example.com/docs'), 'https://example.com/docs');
  assert.equal(externalTarget('http://example.com/'), 'http://example.com/');
});

test('everything else is dropped rather than handed to the OS', () => {
  // `shell.openExternal` resolves whatever it is given through the system, so
  // on Windows these are a file the shell will open, a script the page wrote,
  // and whatever program registered a handler.
  assert.equal(externalTarget('file:///C:/Windows/System32/calc.exe'), null);
  assert.equal(externalTarget('javascript:alert(1)'), null);
  assert.equal(externalTarget('ms-settings:windowsupdate'), null);
  assert.equal(externalTarget('smb://198.51.100.1/share'), null);
  assert.equal(externalTarget('not a url'), null);
  assert.equal(externalTarget(null), null);
});

test('what reaches the browser is what the browser would resolve', () => {
  // Parsed, not prefix-matched, so the string handed to `shell.openExternal`
  // is already normalised: the backslashes below are a real https URL and go
  // out as one, and a scheme dressed up with leading space or odd case is not
  // a scheme at all.
  assert.equal(externalTarget('https:/\/\evil.example'), 'https://evil.example/');
  assert.equal(externalTarget(' javascript:alert(1)'), null);
  assert.equal(externalTarget('JaVaScRiPt:alert(1)'), null);
});
