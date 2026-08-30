// Runs Mozilla's own add-on validator over the packaged extension.
//
// This is the one check here that knows the stores' current rules rather than
// what someone believed them to be when the manifest was written. It already
// earned its place: it is what caught that AMO now requires
// `data_collection_permissions` on new submissions, which no amount of reading
// our own code would have surfaced.
//
// It lints what the release actually uploads, so it calls the packager the
// release workflow calls -- `tools/package-extension.js` at the repository
// root, which stays dependency-free because it runs before any `npm install`.
// A second packager living here would be a second answer to the same question,
// and only one of them would be the one that shipped.
//
// Errors fail the build. Warnings do not — today there are two, both saying
// that `strict_min_version: 128` predates the Firefox 142 that introduced the
// data-collection key, so the declaration is ignored on 128 through 141.
// Raising the floor to 142 would silence them by dropping support for those
// versions, which is a product decision and not the linter's to make.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const linter = require('addons-linter');
const packager = require('../../../tools/package-extension.js');

test("the Firefox package passes Mozilla's validator", { timeout: 120_000 }, async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'bioauth-extension-lint-'));
  const built = packager.build(out);
  const firefox = built.find(({ file }) => path.basename(file).includes('firefox'));
  assert.ok(firefox, 'the packager produced no Firefox upload');

  const instance = linter.createInstance({
    config: {
      _: [firefox.file],
      logLevel: 'fatal',
      stack: false,
      pretty: false,
      boring: true,
      output: 'none',
      metadata: false,
      shouldScanFile: () => true,
    },
    runAsBinary: false,
  });

  const result = await instance.run();
  assert.equal(
    result.summary.errors,
    0,
    `addons-linter rejected the package: ${JSON.stringify(result.errors, null, 2)}`,
  );
});
