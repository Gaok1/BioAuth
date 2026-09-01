'use strict';

// Builds the per-browser extension directories that the installer ships.
//
// A `beforePack` hook rather than a line in the release workflow, because the
// thing it prevents is a shipped extension nobody could load, and that has to
// be impossible from `npm run dist` on a laptop as well as from CI. A step
// that only exists in the workflow is a step the local build silently skips.
//
// What is generated, and why it is not just a copy: `desktop/browser-extension`
// carries both engines' shapes at once -- an MV2 `background.scripts` beside
// the MV3 `service_worker`, and a `browser_specific_settings` block only Gecko
// reads -- so that a developer can load the source directly in either browser.
// It is a development convenience and not a package. The installer used to
// copy it verbatim, which handed every user a manifest half-written for the
// other browser.
//
// The output goes next to the source rather than into `dist/`, because
// electron-builder resolves `extraResources` relative to the app directory and
// a path climbing out of `dist` is one nobody can read at a glance.

const path = require('node:path');
const { buildUnpacked } = require('../../../tools/package-extension.js');

/** Where the generated directories live. Git-ignored; see `.gitignore`. */
const OUTPUT = path.resolve(__dirname, '..', '..', 'browser-extension-dist');

exports.default = async function beforePack() {
  for (const { dir } of buildUnpacked(OUTPUT)) {
    console.log(`  • extension  ${path.relative(process.cwd(), dir)}`);
  }
};

exports.OUTPUT = OUTPUT;
