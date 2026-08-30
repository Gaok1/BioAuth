'use strict';

const fs = require('fs');
const https = require('https');
const path = require('path');
const { spawn } = require('child_process');

const REPOSITORY = 'Gaok1/BioAuth';
const MAX_INSTALLER_BYTES = 512 * 1024 * 1024;
const MIN_INSTALLER_BYTES = 1024 * 1024;
const ALLOWED_DOWNLOAD_HOSTS = new Set([
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
]);

function parseVersion(value) {
  const match = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value || '');
  return match ? match.slice(1).map(Number) : null;
}

function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) throw new Error('release version is not canonical semver');
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
  }
  return 0;
}

function installerName(version) {
  if (!parseVersion(version)) throw new Error('invalid installer version');
  return `PhoneAuth-Setup-${version}-x64.exe`;
}

function githubJson(route) {
  return new Promise((resolve, reject) => {
    const request = https.get(
      `https://api.github.com/repos/${REPOSITORY}/${route}`,
      {
        headers: {
          Accept: 'application/vnd.github+json',
          'User-Agent': 'PhoneAuth-secure-updater',
          'X-GitHub-Api-Version': '2022-11-28',
        },
        timeout: 15000,
      },
      (response) => {
        const chunks = [];
        let length = 0;
        response.on('data', (chunk) => {
          length += chunk.length;
          if (length > 1024 * 1024) {
            response.destroy(new Error('release metadata is too large'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('error', reject);
        response.on('end', () => {
          if (response.statusCode !== 200) {
            reject(new Error(`GitHub release metadata returned ${response.statusCode}`));
            return;
          }
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            reject(new Error('GitHub release metadata is not JSON'));
          }
        });
      }
    );
    request.on('timeout', () => request.destroy(new Error('release metadata timed out')));
    request.on('error', reject);
  });
}

function download(url, destination, expectedSize, redirects = 0) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || !ALLOWED_DOWNLOAD_HOSTS.has(parsed.hostname)) {
      reject(new Error('release download left the GitHub HTTPS boundary'));
      return;
    }
    if (redirects > 5) {
      reject(new Error('too many release download redirects'));
      return;
    }
    const request = https.get(parsed, { timeout: 30000 }, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        response.resume();
        if (!response.headers.location) {
          reject(new Error('release redirect has no destination'));
          return;
        }
        download(
          new URL(response.headers.location, parsed).toString(),
          destination,
          expectedSize,
          redirects + 1
        )
          .then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`release download returned ${response.statusCode}`));
        return;
      }
      const declared = Number(response.headers['content-length'] || 0);
      if (declared && (declared < MIN_INSTALLER_BYTES || declared > MAX_INSTALLER_BYTES)) {
        response.resume();
        reject(new Error('release installer has an invalid declared size'));
        return;
      }
      if (declared && declared !== expectedSize) {
        response.resume();
        reject(new Error('release installer size does not match its metadata'));
        return;
      }
      const temporary = `${destination}.part`;
      const stream = fs.createWriteStream(temporary, { flags: 'wx', mode: 0o600 });
      let received = 0;
      response.on('data', (chunk) => {
        received += chunk.length;
        if (received > MAX_INSTALLER_BYTES) {
          response.destroy(new Error('release installer is too large'));
        }
      });
      response.on('error', (error) => stream.destroy(error));
      stream.on('error', (error) => {
        fs.rmSync(temporary, { force: true });
        reject(error);
      });
      stream.on('finish', () => {
        stream.close(() => {
          if (received !== expectedSize) {
            fs.rmSync(temporary, { force: true });
            reject(new Error('release installer size does not match its metadata'));
            return;
          }
          fs.renameSync(temporary, destination);
          resolve(destination);
        });
      });
      response.pipe(stream);
    });
    request.on('timeout', () => request.destroy(new Error('release download timed out')));
    request.on('error', reject);
  });
}

function verifyAuthenticode(
  file,
  script = process.resourcesPath
    ? path.join(process.resourcesPath, 'verify-authenticode.ps1')
    : path.join(__dirname, 'verify-authenticode.ps1')
) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, '-Path', file],
      { windowsHide: true }
    );
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`Authenticode verification failed: ${Buffer.concat(stderr)}`));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(stdout).toString('utf8')));
      } catch {
        reject(new Error('Authenticode verifier returned an invalid result'));
      }
    });
  });
}

function releaseAsset(release, version) {
  if (!release || release.draft || release.prerelease || release.tag_name !== `v${version}`) {
    throw new Error('release metadata is not a stable canonical release');
  }
  const expected = installerName(version);
  const matches = (release.assets || []).filter((asset) => asset.name === expected);
  if (matches.length !== 1) throw new Error(`release must carry exactly one ${expected}`);
  const asset = matches[0];
  if (!Number.isSafeInteger(asset.size) || asset.size < MIN_INSTALLER_BYTES ||
      asset.size > MAX_INSTALLER_BYTES) {
    throw new Error('release installer size is outside the accepted bounds');
  }
  const parsed = new URL(asset.browser_download_url);
  const expectedPath = `/${REPOSITORY}/releases/download/v${version}/${expected}`;
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'github.com' ||
      parsed.pathname !== expectedPath || parsed.search || parsed.hash) {
    throw new Error('release installer URL is not GitHub HTTPS');
  }
  return asset;
}

function atomicJson(file, value) {
  const temporary = `${file}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(temporary, file);
}

class SecureUpdater {
  constructor({
    platform = process.platform,
    packaged,
    currentVersion,
    currentExecutable = process.execPath,
    directory,
    fetchJson = githubJson,
    downloadFile = download,
    verify = verifyAuthenticode,
    launch = (file) => spawn(file, [], { detached: true, stdio: 'ignore', windowsHide: false }).unref(),
  }) {
    this.platform = platform;
    this.packaged = packaged;
    this.currentVersion = currentVersion;
    this.currentExecutable = currentExecutable;
    this.directory = directory;
    this.fetchJson = fetchJson;
    this.downloadFile = downloadFile;
    this.verify = verify;
    this.launch = launch;
    this.ready = null;
  }

  get enabled() {
    return this.platform === 'win32' && this.packaged === true;
  }

  async check() {
    if (!this.enabled) return { available: false, reason: 'unsupported' };
    const installed = await this.verify(this.currentExecutable);
    if (!installed.valid || !installed.publicKey ||
        installed.fileVersion !== this.currentVersion) {
      return { available: false, reason: 'installed-build-is-not-signed' };
    }

    const latest = await this.fetchJson('releases/latest');
    const latestVersion = (latest.tag_name || '').replace(/^v/, '');
    if (!parseVersion(latestVersion) || compareVersions(latestVersion, this.currentVersion) <= 0) {
      return { available: false, reason: 'current' };
    }
    const latestAsset = releaseAsset(latest, latestVersion);
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    const pending = path.join(this.directory, latestAsset.name);
    await this.#downloadAndVerify(latestAsset, pending, installed.publicKey, latestVersion);

    const currentRelease = await this.fetchJson(`releases/tags/v${this.currentVersion}`);
    const currentAsset = releaseAsset(currentRelease, this.currentVersion);
    const rollback = path.join(this.directory, `rollback-${installerName(this.currentVersion)}`);
    await this.#downloadAndVerify(
      currentAsset,
      rollback,
      installed.publicKey,
      this.currentVersion
    );

    this.ready = {
      version: latestVersion,
      installer: pending,
      signerPublicKey: installed.publicKey,
    };
    atomicJson(path.join(this.directory, 'rollback.json'), {
      version: this.currentVersion,
      installer: rollback,
      signerPublicKey: installed.publicKey,
    });
    return { available: true, version: latestVersion };
  }

  async rollbackInfo() {
    if (!this.enabled) return null;
    try {
      const metadata = JSON.parse(
        fs.readFileSync(path.join(this.directory, 'rollback.json'), 'utf8')
      );
      if (!parseVersion(metadata.version) || !path.isAbsolute(metadata.installer) ||
          path.dirname(metadata.installer) !== path.resolve(this.directory) ||
          compareVersions(metadata.version, this.currentVersion) >= 0) return null;
      const installed = await this.verify(this.currentExecutable);
      if (!installed.valid || installed.publicKey !== metadata.signerPublicKey ||
          installed.fileVersion !== this.currentVersion) return null;
      await this.#sameSigner(metadata.installer, installed.publicKey, metadata.version);
      return { version: metadata.version, installer: metadata.installer };
    } catch {
      return null;
    }
  }

  async install() {
    if (!this.ready) throw new Error('no verified update is ready');
    await this.#sameSigner(
      this.ready.installer,
      this.ready.signerPublicKey,
      this.ready.version
    );
    this.launch(this.ready.installer);
  }

  async rollback() {
    const info = await this.rollbackInfo();
    if (!info) throw new Error('no verified rollback is available');
    this.launch(info.installer);
  }

  async #downloadAndVerify(asset, destination, publicKey, version) {
    fs.rmSync(`${destination}.part`, { force: true });
    if (fs.existsSync(destination) && fs.statSync(destination).size !== asset.size) {
      fs.rmSync(destination, { force: true });
    }
    if (!fs.existsSync(destination)) {
      await this.downloadFile(asset.browser_download_url, destination, asset.size);
    }
    if (fs.statSync(destination).size !== asset.size) {
      fs.rmSync(destination, { force: true });
      throw new Error('release installer size does not match its metadata');
    }
    await this.#sameSigner(destination, publicKey, version);
  }

  async #sameSigner(file, publicKey, version) {
    const signature = await this.verify(file);
    if (!signature.valid || signature.publicKey !== publicKey ||
        signature.fileVersion !== version) {
      fs.rmSync(file, { force: true });
      throw new Error('release Authenticode identity does not match the expected build');
    }
  }
}

module.exports = {
  SecureUpdater,
  compareVersions,
  installerName,
  parseVersion,
  releaseAsset,
};
