'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('Windows packaging signs before verifying every shipped executable', () => {
  const workflow = fs.readFileSync(
    path.join(__dirname, '..', '..', '..', '.github', 'workflows', 'release.yml'),
    'utf8'
  );
  const prepare = workflow.indexOf('name: Prepare Authenticode signing');
  const packageTray = workflow.indexOf('name: Package tray', prepare);
  const verify = workflow.indexOf('name: Verify Authenticode on app, helpers and installer');

  assert.ok(prepare >= 0 && prepare < packageTray && packageTray < verify);
  assert.match(workflow.slice(prepare, packageTray), /WIN_CSC_LINK=/);
  assert.match(workflow.slice(packageTray, verify), /WIN_CSC_KEY_PASSWORD/);
  assert.match(workflow.slice(verify), /find desktop\/dist\/win-unpacked/);
  assert.match(workflow.slice(verify), /-iname '\*\.exe'/);
  assert.match(workflow.slice(verify), /PhoneAuth-Setup-\*\.exe/);

  const manifest = require('../package.json');
  assert.ok(manifest.build.extraResources.some(
    (resource) => resource.from === 'src/verify-authenticode.ps1' &&
      resource.to === 'verify-authenticode.ps1'
  ));
});
