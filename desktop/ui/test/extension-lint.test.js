// Runs Mozilla's own add-on validator over the packaged extension.
//
// This is the one check here that knows the stores' current rules rather than
// what someone believed them to be when the manifest was written. It already
// earned its place: it is what caught that AMO now requires
// `data_collection_permissions` on new submissions, which no amount of reading
// our own code would have surfaced.
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
const packager = require('../tools/package-extension.js');

test('the Firefox package passes Mozilla\'s validator', { timeout: 120_000 }, async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'bioauth-extension-lint-'));
  const { file } = await packager.build('firefox', out);

  const instance = linter.createInstance({
    config: {
      _: [file],
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
