'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  SecureUpdater,
  compareVersions,
  installerName,
  parseVersion,
  releaseAsset,
} = require('../src/secure-updater');

function release(version) {
  return {
    tag_name: `v${version}`,
    draft: false,
    prerelease: false,
    assets: [{
      name: installerName(version),
      size: 20 * 1024 * 1024,
      browser_download_url:
        `https://github.com/Gaok1/BioAuth/releases/download/v${version}/${installerName(version)}`,
    }],
  };
}

test('versions are canonical and never offer a downgrade', () => {
  assert.deepEqual(parseVersion('v1.2.3'), [1, 2, 3]);
  assert.equal(parseVersion('1.02.3'), null);
  assert.equal(parseVersion('1.2.3-beta'), null);
  assert.equal(compareVersions('1.2.3', '1.2.4'), -1);
  assert.equal(compareVersions('2.0.0', '1.99.99'), 1);
});

test('release metadata names one bounded stable GitHub installer', () => {
  assert.equal(releaseAsset(release('1.2.3'), '1.2.3').name, installerName('1.2.3'));
  assert.throws(() => releaseAsset({ ...release('1.2.3'), prerelease: true }, '1.2.3'));
  const duplicate = release('1.2.3');
  duplicate.assets.push(duplicate.assets[0]);
  assert.throws(() => releaseAsset(duplicate, '1.2.3'));
  const foreign = release('1.2.3');
  foreign.assets[0].browser_download_url = 'https://example.com/update.exe';
  assert.throws(() => releaseAsset(foreign, '1.2.3'));
});

test('a signed update stages a separately signed rollback installer', async (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'phoneauth-update-'));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const executable = path.join(directory, 'PhoneAuth.exe');
  fs.writeFileSync(executable, 'installed');
  const downloads = [];
  const launches = [];
  const updater = new SecureUpdater({
    platform: 'win32',
    packaged: true,
    currentVersion: '1.2.3',
    currentExecutable: executable,
    directory,
    fetchJson: async (route) => route === 'releases/latest' ? release('1.2.4') : release('1.2.3'),
    downloadFile: async (_url, destination, size) => {
      downloads.push(destination);
      fs.closeSync(fs.openSync(destination, 'w'));
      fs.truncateSync(destination, size);
    },
    verify: async (file) => ({
      valid: true,
      publicKey: 'publisher-key',
      fileVersion: file.includes('1.2.4') ? '1.2.4' : '1.2.3',
    }),
    launch: (file) => launches.push(file),
  });

  assert.deepEqual(await updater.check(), { available: true, version: '1.2.4' });
  assert.equal(downloads.length, 2);
  await updater.install();
  assert.match(launches[0], /PhoneAuth-Setup-1\.2\.4-x64\.exe$/);

  const nextBuild = new SecureUpdater({
    platform: 'win32',
    packaged: true,
    currentVersion: '1.2.4',
    currentExecutable: executable,
    directory,
    verify: async (file) => ({
      valid: true,
      publicKey: 'publisher-key',
      fileVersion: file === executable ? '1.2.4' : '1.2.3',
    }),
    launch: (file) => launches.push(file),
  });
  assert.equal((await nextBuild.rollbackInfo()).version, '1.2.3');
  await nextBuild.rollback();
  assert.match(launches[1], /rollback-PhoneAuth-Setup-1\.2\.3-x64\.exe$/);
});

test('a substituted installer is deleted and never becomes ready', async (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'phoneauth-update-'));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const executable = path.join(directory, 'PhoneAuth.exe');
  fs.writeFileSync(executable, 'installed');
  let checks = 0;
  const updater = new SecureUpdater({
    platform: 'win32',
    packaged: true,
    currentVersion: '1.2.3',
    currentExecutable: executable,
    directory,
    fetchJson: async () => release('1.2.4'),
    downloadFile: async (_url, destination, size) => {
      fs.closeSync(fs.openSync(destination, 'w'));
      fs.truncateSync(destination, size);
    },
    verify: async (file) => ({
      valid: true,
      publicKey: checks++ === 0 ? 'installed-key' : 'attacker-key',
      fileVersion: file === executable ? '1.2.3' : '1.2.4',
    }),
  });

  await assert.rejects(updater.check(), /identity does not match/);
  assert.equal(fs.existsSync(path.join(directory, installerName('1.2.4'))), false);
  await assert.rejects(updater.install(), /no verified update/);
});

test('the staged installer is verified again immediately before launch', async (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'phoneauth-update-'));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const executable = path.join(directory, 'PhoneAuth.exe');
  fs.writeFileSync(executable, 'installed');
  let stagedValid = true;
  let launched = false;
  const updater = new SecureUpdater({
    platform: 'win32',
    packaged: true,
    currentVersion: '1.2.3',
    currentExecutable: executable,
    directory,
    fetchJson: async (route) => route === 'releases/latest' ? release('1.2.4') : release('1.2.3'),
    downloadFile: async (_url, destination, size) => {
      fs.closeSync(fs.openSync(destination, 'w'));
      fs.truncateSync(destination, size);
    },
    verify: async (file) => ({
      valid: !file.includes('PhoneAuth-Setup-1.2.4') || stagedValid,
      publicKey: 'publisher-key',
      fileVersion: file.includes('PhoneAuth-Setup-1.2.4') ? '1.2.4' : '1.2.3',
    }),
    launch: () => { launched = true; },
  });

  await updater.check();
  stagedValid = false;
  await assert.rejects(updater.install(), /identity does not match/);
  assert.equal(launched, false);
  assert.equal(fs.existsSync(path.join(directory, installerName('1.2.4'))), false);
});

test('development and unsigned installs never download', async () => {
  let fetched = false;
  const unsupported = new SecureUpdater({
    platform: 'linux', packaged: true, currentVersion: '1.0.0', directory: '.',
    fetchJson: async () => { fetched = true; },
  });
  assert.deepEqual(await unsupported.check(), { available: false, reason: 'unsupported' });
  assert.equal(fetched, false);

  const unsigned = new SecureUpdater({
    platform: 'win32', packaged: true, currentVersion: '1.0.0', directory: '.',
    verify: async () => ({ valid: false, publicKey: '', fileVersion: '' }),
    fetchJson: async () => { fetched = true; },
  });
  assert.deepEqual(
    await unsigned.check(),
    { available: false, reason: 'installed-build-is-not-signed' }
  );
  assert.equal(fetched, false);
});
