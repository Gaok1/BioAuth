'use strict';

// PhoneAuth tray application.
//
// Deliberately small. The window is hidden by default, holds no state the
// agent does not already have, and performs no cryptography: it is a view onto
// the agent plus two buttons. Closing it hides it rather than quitting, since
// the point of the app is to be there when a request arrives.

const path = require('path');
const { app, BrowserWindow, Menu, Tray, ipcMain, nativeImage, shell } = require('electron');
const QRCode = require('qrcode');

const { AgentConnection } = require('./agent-connection');
const { AgentSupervisor } = require('./agent-supervisor');
const { endpointFile } = require('./paths');
const { SecureUpdater } = require('./secure-updater');
const { allowsNavigation, externalTarget } = require('./window-guards');
const { ALLOWED_METHODS } = require('./agent-methods');

/**
 * Renders a pairing code.
 *
 * Runs here rather than in the renderer because the QR library is a Node
 * module with no browser bundle, and because it keeps the renderer free of
 * any script beyond its own — the page's CSP allows no third-party code.
 *
 * Always dark-on-white, even in a dark theme: inverted codes defeat some
 * scanners, and a code that will not scan is the only failure that matters
 * here.
 */
function renderPairingCode(text) {
  return QRCode.toDataURL(text, {
    errorCorrectionLevel: 'M',
    margin: 2,
    scale: 6,
    color: { dark: '#000000ff', light: '#ffffffff' },
  });
}

let tray = null;
let window = null;
let agent = null;
let supervisor = null;
let updater = null;
let updateTimer = null;
let updateState = { checking: false, available: null, rollback: null };
let quitting = false;

function createWindow() {
  window = new BrowserWindow({
    width: 400,
    height: 600,
    show: false,
    resizable: false,
    fullscreenable: false,
    maximizable: false,
    skipTaskbar: true,
    title: 'PhoneAuth',
    icon: nativeImage.createFromPath(path.join(__dirname, '..', 'assets', 'icon.png')),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      // The renderer is a view. It gets no Node, no direct access to the
      // agent socket, and no ability to reach into the main process beyond
      // the narrow bridge in preload.js.
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webviewTag: false,
    },
  });

  window.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  // Closing hides. A background agent's UI that quits on close would stop
  // showing requests the moment the user tidied their desktop.
  window.on('close', (event) => {
    if (quitting) return;
    event.preventDefault();
    window.hide();
  });

  // The window stays the page it loaded.
  //
  // `preload.js` attaches the agent bridge to whatever document lives here, so
  // a navigation is not a change of view: it is a change of who holds
  // `vault.copy`. Nothing in the renderer navigates, which is why this never
  // fired -- and why letting it stay unguarded cost nothing to fix.
  window.webContents.on('will-navigate', (event, url) => {
    if (allowsNavigation(window.webContents.getURL(), url)) return;
    event.preventDefault();
    console.log(`phone-auth-tray: refused navigation to ${url}`);
  });

  // External links open in the real browser, never inside the app window --
  // and only if they are web links. `shell.openExternal` hands anything else
  // to the OS to resolve, which on Windows means `file:` and every protocol
  // handler an installed program registered.
  window.webContents.setWindowOpenHandler(({ url }) => {
    const target = externalTarget(url);
    if (target) shell.openExternal(target);
    else console.log(`phone-auth-tray: refused to open ${url}`);
    return { action: 'deny' };
  });

  // A view onto a local socket needs no camera, no microphone, no location and
  // no notifications. Electron grants these to a `file:` page without asking.
  const permissions = window.webContents.session;
  permissions.setPermissionRequestHandler((_contents, permission, callback) => {
    console.log(`phone-auth-tray: refused permission ${permission}`);
    callback(false);
  });
  permissions.setPermissionCheckHandler(() => false);
}

function toggleWindow() {
  if (!window) return;
  if (window.isVisible()) {
    window.hide();
  } else {
    window.show();
    window.focus();
  }
}

function createTray() {
  const image = nativeImage.createFromPath(
    path.join(__dirname, '..', 'assets', 'tray.png')
  );
  tray = new Tray(image);
  tray.setToolTip('PhoneAuth');

  rebuildTrayMenu();
  tray.on('click', toggleWindow);
}

function rebuildTrayMenu() {
  if (!tray) return;
  const updateItems = [];
  if (updater && updater.enabled) {
    updateItems.push({
      label: updateState.checking ? 'Checking for updates…' : 'Check for updates',
      enabled: !updateState.checking,
      click: () => checkForUpdates(true),
    });
    if (updateState.available) {
      updateItems.push({
        label: `Install PhoneAuth ${updateState.available}`,
        click: async () => {
          try {
            await updater.install();
            quitting = true;
            app.quit();
          } catch (error) {
            updateState.available = null;
            tray.displayBalloon({
              title: 'PhoneAuth update was not accepted',
              content: 'The staged installer changed or is no longer valid.',
            });
            rebuildTrayMenu();
          }
        },
      });
    }
    if (updateState.rollback) {
      updateItems.push({
        label: `Roll back to PhoneAuth ${updateState.rollback}`,
        click: async () => {
          try {
            await updater.rollback();
            quitting = true;
            app.quit();
          } catch (error) {
            updateState.rollback = null;
            tray.displayBalloon({
              title: 'PhoneAuth rollback was not accepted',
              content: 'The previous installer changed or is no longer valid.',
            });
            rebuildTrayMenu();
          }
        },
      });
    }
  }
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: 'Open PhoneAuth', click: toggleWindow },
      { type: 'separator' },
      {
        label: 'Reconnect to agent',
        click: () => {
          agent.stop();
          agent.start();
        },
      },
      ...(updateItems.length ? [{ type: 'separator' }, ...updateItems] : []),
      { type: 'separator' },
      {
        label: 'Quit',
        click: () => {
          quitting = true;
          app.quit();
        },
      },
    ])
  );
}

async function checkForUpdates(announce = false) {
  if (!updater || !updater.enabled || updateState.checking) return;
  updateState.checking = true;
  rebuildTrayMenu();
  try {
    const result = await updater.check();
    updateState.available = result.available ? result.version : null;
    if (result.available || announce) {
      const unsigned = result.reason === 'installed-build-is-not-signed';
      tray.displayBalloon({
        title: result.available
          ? 'PhoneAuth update verified'
          : unsigned ? 'Automatic updates are disabled' : 'PhoneAuth is up to date',
        content: result.available
          ? `Version ${result.version} is signed and ready to install from the tray menu.`
          : unsigned
            ? 'This installed build has no valid Authenticode signature.'
            : 'No newer signed stable release is available.',
      });
    }
  } catch (error) {
    // A failed check never weakens verification or blocks authentication.
    // eslint-disable-next-line no-console
    console.log(`phone-auth-tray: update check failed: ${error.message}`);
    if (announce) {
      tray.displayBalloon({
        title: 'PhoneAuth update was not accepted',
        content: 'The release could not be verified. The installed version was left unchanged.',
      });
    }
  } finally {
    updateState.checking = false;
    rebuildTrayMenu();
  }
}

async function initializeUpdater() {
  updater = new SecureUpdater({
    packaged: app.isPackaged,
    currentVersion: app.getVersion(),
    directory: path.join(app.getPath('userData'), 'updates'),
  });
  const rollback = await updater.rollbackInfo();
  updateState.rollback = rollback ? rollback.version : null;
  rebuildTrayMenu();
  if (!updater.enabled) return;
  updateTimer = setTimeout(() => {
    checkForUpdates(false);
    updateTimer = setInterval(() => checkForUpdates(false), 6 * 60 * 60 * 1000);
    updateTimer.unref?.();
  }, 60 * 1000);
  updateTimer.unref?.();
}

/** Pushes a message to the renderer, if there is one. */
function send(channel, payload) {
  if (window && !window.isDestroyed()) {
    window.webContents.send(channel, payload);
  }
}

function wireAgent() {
  agent = new AgentConnection();
  supervisor = new AgentSupervisor({
    // eslint-disable-next-line no-console
    onLog: (message) => console.log(`phone-auth-tray: ${message}`),
  });

  agent.on('status', (status) => {
    send('agent:status', status);
    tray.setToolTip(status.connected ? 'PhoneAuth — connected' : 'PhoneAuth — agent offline');

    // On a packaged install nothing else starts the daemon.
    //
    // `reachable` is passed where a hardcoded `false` used to be, which threw
    // away the one guard `ensureRunning` documents -- on the path that runs
    // most often, since a failed connection re-emits this every couple of
    // seconds. The agent has no single-instance lock and a second one
    // overwrites the endpoint file, so a service-managed agent restarting, or
    // simply closing the connection on a token it no longer recognises, had the
    // tray start a rival to it: one of them owns the endpoint file, the phone
    // dials whichever port its pairing record holds, and both write the pairing
    // store. An agent that really did die answers nothing on the next attempt
    // two seconds later, and is started then.
    if (status.connected) {
      supervisor.markHealthy();
    } else {
      supervisor.ensureRunning(status.reachable === true);
    }
  });

  agent.on('agent-event', (event) => {
    send('agent:event', event);

    // A request waiting on the phone is the one moment this app has something
    // urgent to say, so it surfaces itself without being asked.
    if (event.event === 'request-started' && window && !window.isVisible()) {
      window.show();
    }
  });

  // Started here as well as from the `status` handler. Whether the daemon comes
  // up at all is too important to depend on an event having fired: this is the
  // one thing the app exists to do, and on a packaged install nothing else will
  // do it. `ensureRunning` is idempotent, so the two paths cannot race.
  supervisor.ensureRunning(agent.isConnected());
  agent.start();
}

// A second instance would fight over the tray icon and double every event.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', toggleWindow);

  app.whenReady().then(() => {
    createWindow();
    createTray();
    wireAgent();
    initializeUpdater().catch((error) => {
      // eslint-disable-next-line no-console
      console.log(`phone-auth-tray: updater initialization failed: ${error.message}`);
    });

    ipcMain.handle('agent:call', async (_event, method, params) => {
      if (!ALLOWED_METHODS.has(method)) {
        // `authorize` is deliberately absent: authorizations are started by
        // whatever needs them (PAM, sudo, the CLI), not by clicking in a tray.
        throw new Error(`method \`${method}\` is not available from the UI`);
      }
      return agent.call(method, params || {});
    });

    ipcMain.handle('qr:render', async (_event, text) => {
      if (typeof text !== 'string' || text.length === 0 || text.length > 2048) {
        throw new Error('nothing to encode');
      }
      return renderPairingCode(text);
    });

    ipcMain.handle('agent:info', () => ({
      connected: agent.isConnected(),
      lastError: agent.lastError,
      endpointFile: endpointFile(),
    }));

    // The window is hidden at startup: this is a background app, and showing a
    // window on login is exactly what a background app should not do.
    if (process.argv.includes('--show')) window.show();
  });

  app.on('window-all-closed', () => {
    // Keep running with no windows. The tray is the app.
  });

  app.on('before-quit', () => {
    quitting = true;
    if (updateTimer) clearTimeout(updateTimer);
    if (agent) agent.stop();
    // Only stops an agent this process started. One managed by systemd, or
    // launched by hand, outlives the tray.
    if (supervisor) supervisor.stop();
  });
}
