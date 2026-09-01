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

// What each pairing gets the phone to do, in the words the phone will use.
// Shown before the code because the picture is identical for all of them, and
// a credential enrolled for the wrong one is invisible in the device list.
const PAIRING_SERVICES = {
  authorization: 'A credencial aprova logins e ações neste computador.',
  vault: 'A credencial libera senhas do cofre do telefone para este computador.',
  locker: 'A credencial abre arquivos trancados guardados aqui.',
  webauthn: 'A credencial responde por chaves de acesso em sites.',
  ssh: 'A credencial assina logins SSH. Cada login ainda pede a digital no telefone.',
};

function describeService() {
  const service = el('pair-service').value;
  el('pair-service-note').textContent = PAIRING_SERVICES[service] || '';
}

el('pair-service').addEventListener('change', describeService);
describeService();

el('pair').addEventListener('click', async () => {
  el('confirm').hidden = true;
  const service = el('pair-service').value;
  try {
    const bootstrap = await api.call('pair.begin', { service });
    el('pairing-service').textContent = PAIRING_SERVICES[bootstrap.service] || '';
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

// --- vault -----------------------------------------------------------------

// Held so that filtering does not go back to the phone. `vault.list` crosses
// the network to a device that may be in a pocket, so it happens when the user
// opens the panel or asks for it, and never on the 4-second poll.
let vaultItems = null;
let vaultLoading = false;

function vaultNote(text, kind) {
  const note = el('vault-note');
  note.textContent = text;
  note.className = kind === 'bad' ? 'muted note--bad' : 'muted';
}

async function loadVault() {
  if (vaultLoading) return;
  vaultLoading = true;
  vaultNote('Perguntando ao telefone…');
  try {
    const listed = await api.call('vault.list', {});
    vaultItems = listed.items || [];
    vaultNote(
      listed.development
        ? 'ATENÇÃO — esta lista veio do simulador de desenvolvimento, não de um telefone.'
        : `${vaultItems.length} itens em ${listed.deviceName || 'telefone'}.`
    );
  } catch (error) {
    vaultItems = null;
    vaultNote(error.message, 'bad');
  } finally {
    vaultLoading = false;
    renderVault();
  }
}

function matchesQuery(item, query) {
  if (!query) return true;
  return [item.name, item.username, item.uri].some(
    (field) => (field || '').toLowerCase().includes(query)
  );
}

function renderVault() {
  const container = el('vault-items');
  clear(container);

  if (vaultItems === null) return;
  const query = el('vault-search').value.trim().toLowerCase();
  const shown = vaultItems.filter((item) => matchesQuery(item, query));

  if (shown.length === 0) {
    container.appendChild(
      node(
        'p',
        'empty',
        vaultItems.length === 0
          ? 'O cofre está vazio. Adicione itens no telefone.'
          : 'Nada corresponde a essa busca.'
      )
    );
    return;
  }

  for (const item of shown) {
    const entry = node('div', 'entry');
    const row = node('div', 'row');
    row.appendChild(node('h3', null, item.name));

    const copy = node('button', 'tag', 'copiar');
    copy.dataset.copy = item.id;
    copy.addEventListener('click', () => copyItem(item, copy));
    row.appendChild(copy);
    entry.appendChild(row);

    const detail = [item.username, hostOf(item.uri)].filter(Boolean).join(' · ');
    if (detail) entry.appendChild(node('p', 'muted', detail));
    container.appendChild(entry);
  }
}

/** The host, for the line a person reads. Falls back to the raw string. */
function hostOf(uri) {
  if (!uri) return '';
  try {
    return new URL(uri).host || uri;
  } catch {
    return uri;
  }
}

/// What the OS did and did not do with the entry, in the words a person reads.
///
/// Shared by both ways a password reaches the clipboard, because it is the same
/// clipboard and the same reply type. `vault.generate-copy` read only the
/// countdown out of it, so a password generated here could be sitting in the
/// `Win+V` history, or synced to a Microsoft account and off this machine
/// entirely, while the panel said nothing -- the same three failures the stored
/// copy has spelled out in capitals all along.
function clipboardNote(result, opening) {
  const seconds = Math.max(0, Math.round((result.clearsAtMs - Date.now()) / 1000));
  const warnings = [];
  if (!result.memoryLocked) warnings.push('a senha pode ter chegado ao pagefile');
  if (!result.historyExcluded) warnings.push('o histórico da área de transferência pode ter guardado uma cópia');
  if (!result.cloudExcluded) warnings.push('a área de transferência pode ter sincronizado com a nuvem');

  return (
    `${opening} A área de transferência se limpa em ${seconds}s.` +
    (warnings.length ? ` ATENÇÃO — ${warnings.join('; ')}.` : '')
  );
}

async function copyItem(item, button) {
  button.disabled = true;
  button.textContent = 'no telefone…';
  vaultNote(`Aprove no telefone: ${item.name}.`);
  try {
    // The revision of the row that is on screen. If the phone answers with a
    // different one the agent refuses the copy — the item was edited somewhere
    // else, and pasting it would hand over a value nobody looked at.
    const result = await api.call('vault.copy', {
      itemId: item.id,
      expectedRevision: item.revision,
    });
    vaultNote(clipboardNote(result, 'Copiado.'));
    button.textContent = 'copiado';
  } catch (error) {
    // A refusal on the phone, a stale revision and a missing item all arrive
    // as the same code. Saying which one it was is not something this window
    // is able to do, so it does not guess.
    vaultNote(error.message, 'bad');
    button.textContent = 'copiar';
  } finally {
    button.disabled = false;
    // No automatic re-listing here. It used to run a second after every copy,
    // to keep each row's revision fresh, on the grounds that a listing cost
    // nothing anybody would notice. That stopped being true: the metadata
    // lives inside the encrypted blob and the phone's key is auth-per-use, so
    // a fresh listing raises a Keystore prompt -- and a listing raises no
    // approval sheet to explain one. The owner approved a copy and then, a
    // second later, got a second fingerprint prompt for nothing they had done.
    //
    // What the re-list was protecting against is already handled: `vault.copy`
    // carries the revision of the row on screen and the agent refuses a copy
    // whose revision has moved on. So a stale row costs one clear failure and
    // a press of Atualizar, rather than an unexplained prompt after every
    // single copy.
  }
}

el('vault-search').addEventListener('input', renderVault);
el('vault-refresh').addEventListener('click', loadVault);

el('vault-generate').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await api.call('vault.generate-copy', {});
    vaultNote(
      clipboardNote(result, `Senha de ${result.length} caracteres copiada.`)
    );
  } catch (error) {
    vaultNote(error.message, 'bad');
  } finally {
    button.disabled = false;
  }
});

// The other direction from `vault.copy`: a password made here and kept there.
//
// Nothing about the secret is on this side of the call. The renderer sends the
// name, the user and the address; the agent generates, sends to the phone and
// forgets, and the reply says how long the password was rather than what it
// was. So this handler cannot show it, and that is deliberate rather than an
// omission -- the place to read it back is the phone, or the Copy button on
// the list above, both of which the phone approves.
el('vault-store').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const name = el('vault-new-name').value.trim();
  // Checked here as well as in the agent. Reaching the phone to be told the
  // name was blank costs a prompt on the person's phone for nothing.
  if (!name) {
    vaultNote('Dê um nome ao item antes de guardar.', 'bad');
    el('vault-new-name').focus();
    return;
  }
  button.disabled = true;
  vaultNote(`Aprove no telefone: ${name}.`);
  try {
    const result = await api.call('vault.create', {
      name,
      username: el('vault-new-username').value.trim(),
      uri: el('vault-new-uri').value.trim(),
    });
    // The fields are cleared only once the phone has actually stored it.
    // Emptying them on the way out would lose what the person typed whenever
    // the write failed or they declined.
    for (const field of ['vault-new-name', 'vault-new-username', 'vault-new-uri']) {
      el(field).value = '';
    }
    // The listing this panel holds is now behind by one item, and it is the
    // one the person just made: refreshing is what lets them copy it.
    vaultItems = null;
    await loadVault();
    vaultNote(`"${name}" guardado com senha de ${result.length} caracteres.`);
  } catch (error) {
    vaultNote(error.message, 'bad');
  } finally {
    button.disabled = false;
  }
});

// Listing is deferred until the panel is actually opened: a tray that dials
// the phone every time it starts would wake the device for nothing.
for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    if (tab.dataset.panel === 'panel-vault' && vaultItems === null) loadVault();
  });
}
