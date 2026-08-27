'use strict';

// View layer. Reads from the agent through the preload bridge and renders.
// It holds no authority: nothing here can approve anything, and the only
// mutating call it can make is forgetting a pairing.

const api = window.phoneAuth;

/** Refresh cadence while the window is visible. */
const POLL_MS = 4000;
let pollTimer = null;

const el = (id) => document.getElementById(id);

/** Builds an element. Text is set via textContent, never innerHTML. */
function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function clear(container) {
  while (container.firstChild) container.removeChild(container.firstChild);
}

// --- tabs -----------------------------------------------------------------

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    for (const other of document.querySelectorAll('.tab')) {
      other.classList.toggle('tab--active', other === tab);
    }
    for (const panel of document.querySelectorAll('.panel')) {
      panel.hidden = panel.id !== tab.dataset.panel;
    }
  });
}

// --- rendering ------------------------------------------------------------

function renderStatus(status) {
  el('verifier-name').textContent = status.verifierName || 'PhoneAuth';
  el('verifier-id').textContent = status.verifierId || '';
  el('dev-banner').hidden = !status.developmentMode;

  const connection = el('connection');
  connection.textContent = status.canAuthorize ? 'pronto' : 'sem transporte';
  connection.className = `pill ${status.canAuthorize ? 'pill--on' : 'pill--off'}`;

  renderDevices(status.pairedDevices || []);
  renderTransports(status.transports || [], status.blockedOn || []);
}

function renderDevices(devices) {
  const container = el('devices');
  clear(container);

  if (devices.length === 0) {
    container.appendChild(
      node('p', 'empty', 'Nenhum telefone pareado com este computador.')
    );
    return;
  }

  for (const device of devices) {
    const entry = node('div', 'entry');
    const row = node('div', 'row');
    row.appendChild(node('h3', null, device.displayName));

    const forget = node('button', 'tag', 'esquecer');
    forget.addEventListener('click', async () => {
      forget.disabled = true;
      try {
        await api.call('devices.forget', { deviceId: device.deviceId });
        await refresh();
      } catch (error) {
        forget.textContent = error.message;
      }
    });
    row.appendChild(forget);
    entry.appendChild(row);

    for (const credential of device.credentials || []) {
      const line = node('p', null, credential.credentialId);
      entry.appendChild(line);

      const tags = node('p');
      const kind = node(
        'span',
        `tag ${credential.keyKind === 'Software' ? 'tag--warn' : 'tag--ok'}`,
        credential.keyKind
      );
      tags.appendChild(kind);
      tags.appendChild(document.createTextNode(' '));
      tags.appendChild(node('span', 'tag', credential.purpose));
      if (credential.usableAtBoot) {
        tags.appendChild(document.createTextNode(' '));
        tags.appendChild(node('span', 'tag tag--ok', 'boot'));
      }
      entry.appendChild(tags);

      const permissions = node('ul');
      for (const permission of credential.permissions || []) {
        permissions.appendChild(
          node(
            'li',
            null,
            `${permission.service} / ${permission.action} em ${permission.resource} como ${permission.user}`
          )
        );
      }
      if ((credential.permissions || []).length === 0) {
        permissions.appendChild(node('li', null, 'sem permissões — não autoriza nada'));
      }
      entry.appendChild(permissions);
    }

    container.appendChild(entry);
  }
}

function renderTransports(transports, blockedOn) {
  const container = el('transports');
  clear(container);

  for (const transport of transports) {
    const entry = node('div', 'entry');
    const row = node('div', 'row');
    row.appendChild(node('h3', null, transport.name));

    const ready = transport.state === 'ready';
    row.appendChild(
      node('span', `tag ${ready ? 'tag--ok' : 'tag--warn'}`, transport.state)
    );
    entry.appendChild(row);
    entry.appendChild(node('p', 'muted', transport.description));

    if (transport.blockedOn) {
      entry.appendChild(node('p', 'muted', `pendente — ${transport.blockedOn}`));
    }
    container.appendChild(entry);
  }

  if (blockedOn.length > 0) {
    const entry = node('div', 'entry');
    entry.appendChild(node('h3', null, 'Pendências'));
    const list = node('ul');
    for (const item of blockedOn) list.appendChild(node('li', null, item));
    entry.appendChild(list);
    container.appendChild(entry);
  }
}

function renderHistory(entries) {
  const container = el('history');
  clear(container);

  if (entries.length === 0) {
    container.appendChild(node('p', 'empty', 'Nenhuma autorização registrada.'));
    return;
  }

  for (const item of entries) {
    const entry = node('div', 'entry');
    const row = node('div', 'row');
    row.appendChild(node('h3', null, item.action));

    const tone =
      item.outcome === 'granted' ? 'tag--ok' : item.outcome === 'denied' ? 'tag--bad' : 'tag--warn';
    row.appendChild(node('span', `tag ${tone}`, item.outcome));
    entry.appendChild(row);

    entry.appendChild(
      node('p', 'muted', `${item.service} · ${item.resource} · ${item.user}`)
    );
    entry.appendChild(
      node('p', 'muted', new Date(item.atMs).toLocaleString())
    );
    if (item.development) {
      entry.appendChild(node('p', null, '')).appendChild(
        node('span', 'tag tag--warn', 'simulador')
      );
    }
    if (item.detail) entry.appendChild(node('p', 'muted', item.detail));
    container.appendChild(entry);
  }
}

function showLiveRequest(event) {
  el('live-action').textContent = event.action;
  el('live-service').textContent = event.service;
  el('live-resource').textContent = event.resource;
  el('live-user').textContent = event.user;
  el('live-origin').textContent = event.origin;
  el('live').hidden = false;
}

// --- data -----------------------------------------------------------------

async function refresh() {
  try {
    const status = await api.call('status', {});
    renderStatus(status);
    el('offline-banner').hidden = true;

    const history = await api.call('audit.recent', { limit: 25 });
    renderHistory(history.entries || []);
  } catch (error) {
    showOffline(error.message);
  }
}

async function showOffline(reason) {
  el('offline-banner').hidden = false;
  el('offline-detail').textContent = reason || 'Não foi possível falar com o agente.';
  const connection = el('connection');
  connection.textContent = 'offline';
  connection.className = 'pill pill--off';

  try {
    const info = await api.info();
    el('offline-endpoint').textContent = info.endpointFile;
  } catch {
    // The bridge itself is unavailable; the banner text is enough.
  }
}

// --- pairing ---------------------------------------------------------------

/** Polls for a phone completing its handshake while a code is on screen. */
let pairingPoll = null;

function stopPairingPoll() {
  if (!pairingPoll) return;
  clearInterval(pairingPoll);
  pairingPoll = null;
}

function hidePairing() {
  stopPairingPoll();
  el('pairing').hidden = true;
  el('confirm').hidden = true;
  el('confirm-error').textContent = '';
}

el('pair').addEventListener('click', async () => {
  el('confirm').hidden = true;
  try {
    const bootstrap = await api.call('pair.begin', {});
    el('pairing-payload').textContent = bootstrap.qrPayload;
    el('pairing-blocked').textContent = bootstrap.blockedOn || '';
    el('pairing-expiry').textContent = `Válido até ${new Date(
      bootstrap.expiresAtMs
    ).toLocaleTimeString()}`;

    try {
      el('pairing-qr').src = await api.renderQr(bootstrap.qrPayload);
    } catch (error) {
      // The payload is still readable below the code, so a rendering failure
      // is a degradation rather than a dead end.
      el('pairing-blocked').textContent = `Não foi possível desenhar o código: ${error.message}`;
    }

    el('pairing').hidden = false;
    stopPairingPoll();
    pairingPoll = setInterval(checkPairing, 700);
  } catch (error) {
    el('pairing-qr').removeAttribute('src');
    el('pairing-payload').textContent = '';
    el('pairing-blocked').textContent = error.message;
    el('pairing').hidden = false;
  }
});

el('pairing-cancel').addEventListener('click', async () => {
  try {
    await api.call('pair.cancel', {});
  } finally {
    hidePairing();
  }
});

async function checkPairing() {
  let proposal;
  try {
    proposal = await api.call('pair.pending', {});
  } catch {
    return;
  }
  if (!proposal) return;

  stopPairingPoll();
  el('pairing').hidden = true;

  el('confirm-code').textContent = proposal.verificationCode;
  el('confirm-device').textContent = `${proposal.deviceName} (${proposal.deviceId})`;
  el('confirm-credential').textContent = proposal.credentialId;
  el('confirm-key').textContent = `${proposal.keyKind} · ${proposal.purpose}`;
  el('confirm').dataset.code = proposal.verificationCode;
  // Quoted back on confirm so this screen answers the attempt it is showing,
  // not whichever one happens to be pending by the time the user clicks.
  el('confirm').dataset.attemptId = proposal.attemptId ?? '';
  el('confirm').hidden = false;
}

el('confirm-yes').addEventListener('click', async () => {
  const code = el('confirm').dataset.code;
  const attemptId = el('confirm').dataset.attemptId || undefined;
  try {
    await api.call('pair.confirm', { verificationCode: code, attemptId });
    hidePairing();
    await refresh();
  } catch (error) {
    el('confirm-error').textContent = error.message;
  }
});

el('confirm-no').addEventListener('click', async () => {
  // Declining discards the proposal: the pairing is simply never stored.
  try {
    await api.call('pair.cancel', {});
  } finally {
    hidePairing();
  }
});

api.onStatus((status) => {
  if (status.connected) refresh();
  else showOffline(status.reason);
});

api.onEvent((event) => {
  if (event.event === 'request-started') {
    showLiveRequest(event);
  } else if (event.event === 'request-finished') {
    el('live').hidden = true;
    refresh();
  } else if (event.event === 'devices-changed') {
    refresh();
  }
});

// Poll only while the window is on screen. A hidden tray app should be idle.
function startPolling() {
  if (pollTimer) return;
  refresh();
  pollTimer = setInterval(refresh, POLL_MS);
}

function stopPolling() {
  if (!pollTimer) return;
  clearInterval(pollTimer);
  pollTimer = null;
}

document.addEventListener('visibilitychange', () => {
  if (document.hidden) stopPolling();
  else startPolling();
});

startPolling();
