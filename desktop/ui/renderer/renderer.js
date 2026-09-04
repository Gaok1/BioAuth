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

// --- language -------------------------------------------------------------

/// Every word this window says, in each language it ships.
///
/// Kept here rather than in a file of its own because the window is one
/// script, and because the tests run `renderer.js` on its own in a `vm`. A
/// value is either a string or a function of whatever the line needs; adding a
/// language is adding one entry, and a key missing from it falls back to
/// English rather than rendering blank.
///
/// The house rule for the copy: say what a thing is or what a button does. No
/// sentence explains how the app works underneath.
const STRINGS = {
  en: {
    languageName: 'English',
    languageTitle: 'Language',
    connectionTitle: 'Agent state',
    connectionReady: 'ready',
    connectionNoTransport: 'no transport',
    connectionOffline: 'offline',
    devBannerTitle: 'Development mode.',
    devBannerBody:
      'Authorizations are signed here by a software key. No biometrics, no phone.',
    offlineTitle: 'Agent unavailable.',
    offlineDefault: 'Could not reach the agent.',
    liveWaiting: 'Waiting for the phone',
    liveNote: 'Approve or refuse on the phone.',
    fieldService: 'service',
    fieldResource: 'resource',
    fieldUser: 'user',
    fieldOrigin: 'origin',
    fieldPhone: 'phone',
    fieldCredential: 'credential',
    fieldKey: 'key',
    fieldName: 'Name',
    fieldAddress: 'Address',
    tabPhones: 'Phones',
    tabVault: 'Vault',
    tabConnection: 'Connection',
    tabHistory: 'History',
    pairFor: 'Pair for',
    serviceAuthorization: 'Login and `sudo`',
    serviceVault: 'Password vault',
    serviceLocker: 'Locked files',
    serviceWebauthn: 'Passkeys on websites',
    serviceSsh: 'SSH logins',
    pairButton: 'Pair a phone…',
    pairingScan: 'Scan this on the phone',
    pairingQrAlt: 'Pairing code',
    pairingShowPayload: 'Show what the code carries',
    pairingExpiry: (time) => `Valid until ${time}`,
    pairingQrFailed: (reason) => `Could not draw the code: ${reason}`,
    cancel: 'Cancel',
    confirmOnPhone: 'Confirm on the phone',
    confirmNote:
      "This number must match the phone's screen. If it differs, refuse.",
    matches: 'It matches',
    doesNotMatch: 'It does not match',
    noPhones: 'No phone paired with this computer.',
    forget: 'forget',
    grantSudo: 'sudo',
    grantLogin: 'login',
    grantVault: 'vault',
    grantLocker: 'files',
    grantSsh: 'ssh',
    grantLuks: 'disk',
    grantWebauthn: 'passkeys',
    syncing: 'syncing…',
    sync: 'sync',
    grantLine: (service, action, resource, user) =>
      `${service} / ${action} on ${resource} as ${user}`,
    noGrants: 'no permissions — authorizes nothing',
    transportPending: (reason) => `pending — ${reason}`,
    blockedOn: 'Pending',
    noHistory: 'No authorizations recorded.',
    credentialAuthorization:
      'Approves logins and actions on this computer.',
    credentialVault:
      "Releases passwords from the phone's vault to this computer.",
    credentialLocker: 'Opens locked files stored here.',
    credentialWebauthn: 'Answers for passkeys on websites.',
    credentialSsh:
      'Signs SSH logins. Every login still asks for the fingerprint.',
    refresh: 'refresh',
    vaultSearch: 'Search the vault…',
    vaultListNote: 'No passwords here. Each copy is approved on the phone.',
    vaultNewTitle: 'New password',
    vaultNewNote: 'Generated here and copied. Paste it before it clears.',
    vaultGenerate: 'Generate and copy',
    vaultStoreTitle: 'Store on the phone',
    vaultStoreNote:
      'The password goes straight to the phone, which asks before storing it. '
      + 'It is never shown here.',
    vaultStoreButton: 'Generate and store',
    vaultAsking: 'Asking the phone…',
    vaultDevelopment:
      'WARNING — this list came from the development simulator, not a phone.',
    vaultListed: (count, device) => `${count} items on ${device}.`,
    vaultPhone: 'the phone',
    vaultEmpty: 'The vault is empty. Add items on the phone.',
    vaultNoMatch: 'Nothing matches that search.',
    copy: 'copy',
    copyOnPhone: 'on the phone…',
    copied: 'copied',
    approveOnPhone: (name) => `Approve on the phone: ${name}.`,
    copiedOpening: 'Copied.',
    generatedOpening: (length) => `Password of ${length} characters copied.`,
    storedOpening: (name, length) =>
      `"${name}" stored with a password of ${length} characters.`,
    listFailed: (reason) => `The list could not be refreshed: ${reason}`,
    nameRequired: 'Give the item a name before storing it.',
    clipboardClears: (seconds) => `The clipboard clears in ${seconds}s.`,
    clipboardWarning: (warnings) => `WARNING — ${warnings}.`,
    clipboardPagefile: 'the password may have reached the pagefile',
    clipboardHistory: 'the clipboard history may hold a copy',
    clipboardCloud: 'the clipboard may have synced to the cloud',
  },
  pt: {
    languageName: 'Português (Brasil)',
    languageTitle: 'Idioma',
    connectionTitle: 'Estado do agente',
    connectionReady: 'pronto',
    connectionNoTransport: 'sem transporte',
    connectionOffline: 'offline',
    devBannerTitle: 'Modo de desenvolvimento.',
    devBannerBody:
      'As autorizações são assinadas aqui por uma chave de software. Sem '
      + 'biometria, sem telefone.',
    offlineTitle: 'Agente indisponível.',
    offlineDefault: 'Não foi possível falar com o agente.',
    liveWaiting: 'Aguardando o telefone',
    liveNote: 'Aprove ou recuse no telefone.',
    fieldService: 'serviço',
    fieldResource: 'recurso',
    fieldUser: 'usuário',
    fieldOrigin: 'origem',
    fieldPhone: 'telefone',
    fieldCredential: 'credencial',
    fieldKey: 'chave',
    fieldName: 'Nome',
    fieldAddress: 'Endereço',
    tabPhones: 'Telefones',
    tabVault: 'Cofre',
    tabConnection: 'Conexão',
    tabHistory: 'Histórico',
    pairFor: 'Parear para',
    serviceAuthorization: 'Login e `sudo`',
    serviceVault: 'Cofre de senhas',
    serviceLocker: 'Arquivos trancados',
    serviceWebauthn: 'Passkeys em sites',
    serviceSsh: 'Login SSH',
    pairButton: 'Parear um telefone…',
    pairingScan: 'Escaneie no telefone',
    pairingQrAlt: 'Código de pareamento',
    pairingShowPayload: 'Ver o conteúdo do código',
    pairingExpiry: (time) => `Válido até ${time}`,
    pairingQrFailed: (reason) => `Não foi possível desenhar o código: ${reason}`,
    cancel: 'Cancelar',
    confirmOnPhone: 'Confirme no telefone',
    confirmNote:
      'Este número tem de ser igual ao da tela do telefone. Se for diferente, '
      + 'recuse.',
    matches: 'Confere',
    doesNotMatch: 'Não confere',
    noPhones: 'Nenhum telefone pareado com este computador.',
    forget: 'esquecer',
    grantSudo: 'sudo',
    grantLogin: 'login',
    grantVault: 'cofre',
    grantLocker: 'arquivos',
    grantSsh: 'ssh',
    grantLuks: 'disco',
    grantWebauthn: 'passkeys',
    syncing: 'sincronizando…',
    sync: 'sincronizar',
    grantLine: (service, action, resource, user) =>
      `${service} / ${action} em ${resource} como ${user}`,
    noGrants: 'sem permissões — não autoriza nada',
    transportPending: (reason) => `pendente — ${reason}`,
    blockedOn: 'Pendências',
    noHistory: 'Nenhuma autorização registrada.',
    credentialAuthorization:
      'Aprova logins e ações neste computador.',
    credentialVault:
      'Libera senhas do cofre do telefone para este computador.',
    credentialLocker: 'Abre arquivos trancados guardados aqui.',
    credentialWebauthn: 'Responde por passkeys em sites.',
    credentialSsh:
      'Assina logins SSH. Cada login ainda pede a digital no telefone.',
    refresh: 'atualizar',
    vaultSearch: 'Buscar no cofre…',
    vaultListNote: 'Nenhuma senha aqui. Cada cópia é aprovada no telefone.',
    vaultNewTitle: 'Senha nova',
    vaultNewNote: 'Gerada aqui e copiada. Cole antes que ela se apague.',
    vaultGenerate: 'Gerar e copiar',
    vaultStoreTitle: 'Guardar no telefone',
    vaultStoreNote:
      'A senha vai direto para o telefone, que pede aprovação antes de '
      + 'gravar. Ela não aparece aqui.',
    vaultStoreButton: 'Gerar e guardar',
    vaultAsking: 'Perguntando ao telefone…',
    vaultDevelopment:
      'ATENÇÃO — esta lista veio do simulador de desenvolvimento, não de um '
      + 'telefone.',
    vaultListed: (count, device) => `${count} itens em ${device}.`,
    vaultPhone: 'telefone',
    vaultEmpty: 'O cofre está vazio. Adicione itens no telefone.',
    vaultNoMatch: 'Nada corresponde a essa busca.',
    copy: 'copiar',
    copyOnPhone: 'no telefone…',
    copied: 'copiado',
    approveOnPhone: (name) => `Aprove no telefone: ${name}.`,
    copiedOpening: 'Copiado.',
    generatedOpening: (length) => `Senha de ${length} caracteres copiada.`,
    storedOpening: (name, length) =>
      `"${name}" guardado com senha de ${length} caracteres.`,
    listFailed: (reason) => `A lista não pôde ser atualizada: ${reason}`,
    nameRequired: 'Dê um nome ao item antes de guardar.',
    clipboardClears: (seconds) =>
      `A área de transferência se limpa em ${seconds}s.`,
    clipboardWarning: (warnings) => `ATENÇÃO — ${warnings}.`,
    clipboardPagefile: 'a senha pode ter chegado ao pagefile',
    clipboardHistory:
      'o histórico da área de transferência pode ter guardado uma cópia',
    clipboardCloud: 'a área de transferência pode ter sincronizado com a nuvem',
  },
};

const LANGUAGE_KEY = 'phoneauth.language';

/// Follows the machine unless a person picked one here.
///
/// Everything is guarded: this same file runs under the tests in a bare `vm`
/// with no `localStorage` and no `navigator`, and a window that failed to boot
/// over a preference would be a worse trade than one in the wrong language.
function readLanguage() {
  try {
    const stored = globalThis.localStorage?.getItem(LANGUAGE_KEY);
    if (stored && STRINGS[stored]) return stored;
  } catch {
    // Storage unavailable; the machine's own language decides.
  }
  const system = String(globalThis.navigator?.language || 'en')
    .slice(0, 2)
    .toLowerCase();
  return STRINGS[system] ? system : 'en';
}

let language = readLanguage();

/// One word or line, in the current language, falling back to English.
function t(key, ...args) {
  const value = STRINGS[language][key] ?? STRINGS.en[key];
  return typeof value === 'function' ? value(...args) : value;
}

/// Writes every `data-i18n` in the markup, and re-writes them on a switch.
/// The last thing the window drew, ready to be drawn again in another language.
///
/// `applyLanguage` rewrites the elements carrying `data-i18n`, and everything
/// the agent's answers produce is not among them: the connection pill, the
/// device rows, the transports and the history are written by the renderers,
/// from `t()`, at the moment the answer arrives.
///
/// The picker already asks for a fresh `refresh()` after a switch, so this is
/// not what stops that text going stale -- the answer does. What it stops is
/// the wait: the round trip is a visible moment of the old language, and
/// anything else that ever calls `applyLanguage` gets the redraw without having
/// to know it must ask for one.
let repaint = () => {};

function applyLanguage() {
  try {
    document.documentElement.lang = language;
  } catch {
    // No document element under the test harness.
  }
  // The key is read back rather than trusted from the selector: the test
  // harness answers every `querySelectorAll` with the same handful of
  // elements, and a window that threw here would not boot at all.
  for (const element of document.querySelectorAll('[data-i18n]')) {
    if (element.dataset?.i18n) element.textContent = t(element.dataset.i18n);
  }
  for (const element of document.querySelectorAll('[data-i18n-attr]')) {
    if (!element.dataset?.i18nAttr) continue;
    const [attribute, key] = element.dataset.i18nAttr.split(':');
    element.setAttribute?.(attribute, t(key));
  }
  // After the markup, because the markup holds the starting text for elements
  // the renderers take over -- the connection pill among them -- and what the
  // agent last said is more recent than what the file was written with.
  repaint();
}

/// The picker, built from whatever languages the pack holds.
function setUpLanguagePicker() {
  const picker = el('language');
  if (!picker) return;
  for (const code of Object.keys(STRINGS)) {
    const option = document.createElement('option');
    option.value = code;
    // Each language names itself: a list renamed into the language currently
    // showing is one nobody can use to get out of a language they cannot read.
    option.textContent = STRINGS[code].languageName;
    picker.appendChild(option);
  }
  picker.value = language;
  picker.addEventListener('change', () => {
    language = STRINGS[picker.value] ? picker.value : 'en';
    try {
      globalThis.localStorage?.setItem(LANGUAGE_KEY, language);
    } catch {
      // Applied for this session; the next launch follows the machine again.
    }
    applyLanguage();
    describeService();
    refresh();
    if (vaultItems !== null) renderVault();
  });
}

applyLanguage();
setUpLanguagePicker();

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
  connection.textContent = status.canAuthorize
    ? t('connectionReady')
    : t('connectionNoTransport');
  connection.className = `pill ${status.canAuthorize ? 'pill--on' : 'pill--off'}`;

  renderDevices(status.pairedDevices || []);
  renderTransports(status.transports || [], status.blockedOn || []);
}

/// The device waiting on the agent, and the last one that refused to go.
///
/// The same reason the vault panel holds `vaultCopying`: this list is rebuilt
/// from scratch by every status poll, which is every four seconds, and a
/// `devices.forget` is in flight across at least one of them. The button that
/// was disabled was a detached node by then, and the row on screen offered the
/// press again.
///
/// The failure had nowhere to go either. The old handler wrote the error onto
/// the button and never re-enabled it, so a forget that failed left a dead
/// button labelled with a sentence -- and the next poll replaced it with a
/// fresh "forget" that said nothing had happened.
let forgetting = null;
let forgetFailure = null;

/// The services a grant may name, and what to call them on screen.
///
/// A closed list because the enforcing side treats `service` as an exact match
/// against a small vocabulary -- there is no wildcard for it, by design, since
/// a wildcard service is a grant of everything. A free-text box here would
/// mostly produce grants that match nothing.
const GRANTABLE = [
  ['sudo', 'grantSudo'],
  ['login', 'grantLogin'],
  ['vault', 'grantVault'],
  ['locker', 'grantLocker'],
  ['ssh', 'grantSsh'],
  ['luks', 'grantLuks'],
  ['webauthn', 'grantWebauthn'],
];

/// How every field but `service` says "any value". The same string the agent
/// and the phone use; an empty one is a grant that matches nothing.
const ANY = '*';

/// Which credential is mid-write, and the last failure, for the same reason
/// `forgetting` exists: this list is rebuilt by every status poll and the
/// element that was disabled is a detached node by the time the call returns.
let permissionBusy = null;
let permissionFailure = null;

function credentialKey(device, credential) {
  return `${device.deviceId}/${credential.credentialId}`;
}

/// The editor for one credential's grants, plus the button that settles them
/// with the phone.
///
/// Checkboxes rather than a free-text list: `service` is matched exactly
/// against a closed vocabulary, so the useful choice is which of them, and the
/// remaining three fields are `*` unless somebody needs otherwise -- which the
/// CLI still covers.
function permissionEditor(device, credential) {
  const key = credentialKey(device, credential);
  const busy = permissionBusy === key;
  const box = node('div', 'row');
  const granted = new Set(
    (credential.permissions || []).map((permission) => permission.service)
  );

  for (const [service, labelKey] of GRANTABLE) {
    const wrapper = node('label', 'tag');
    const check = document.createElement('input');
    check.type = 'checkbox';
    check.checked = granted.has(service);
    check.disabled = busy;
    check.addEventListener('change', async () => {
      if (permissionBusy) {
        // Put back: the poll that follows the in-flight write is what decides
        // what is true, and a box left ticked in the meantime says the agent
        // agreed when it was never asked.
        check.checked = granted.has(service);
        return;
      }
      const next = new Set(granted);
      if (check.checked) next.add(service);
      else next.delete(service);
      await writePermissions(device, credential, next);
    });
    wrapper.appendChild(check);
    wrapper.appendChild(document.createTextNode(` ${t(labelKey)}`));
    box.appendChild(wrapper);
  }

  const sync = node('button', 'tag', busy ? t('syncing') : t('sync'));
  sync.disabled = busy;
  sync.addEventListener('click', async () => {
    if (permissionBusy) return;
    await runPermissionCall(key, () =>
      api.call('devices.syncPermissions', {
        deviceId: device.deviceId,
        credentialId: credential.credentialId,
      })
    );
  });
  box.appendChild(sync);

  if (permissionFailure && permissionFailure.key === key) {
    box.appendChild(node('span', 'tag tag--warn', permissionFailure.message));
  }
  return box;
}

async function writePermissions(device, credential, services) {
  await runPermissionCall(credentialKey(device, credential), () =>
    api.call('devices.setPermissions', {
      deviceId: device.deviceId,
      credentialId: credential.credentialId,
      permissions: [...services].map((service) => ({
        service,
        action: ANY,
        resource: ANY,
        user: ANY,
      })),
    })
  );
}

/// One at a time, and the list refreshed on both paths.
///
/// A success needs the row redrawn from what the agent now holds; a failure
/// needs the reason on a live row rather than on the detached one the poll
/// already replaced.
async function runPermissionCall(key, call) {
  permissionBusy = key;
  permissionFailure = null;
  try {
    await call();
  } catch (error) {
    permissionFailure = { key, message: error.message };
  } finally {
    permissionBusy = null;
  }
  await refresh();
}

function renderDevices(devices) {
  const container = el('devices');
  clear(container);

  if (devices.length === 0) {
    container.appendChild(
      node('p', 'empty', t('noPhones'))
    );
    return;
  }

  for (const device of devices) {
    const entry = node('div', 'entry');
    const row = node('div', 'row');
    row.appendChild(node('h3', null, device.displayName));

    const forget = node('button', 'tag', t('forget'));
    // Re-applied on every render, so neither state is lost to a poll.
    if (forgetting === device.deviceId) {
      forget.disabled = true;
    } else if (forgetFailure && forgetFailure.deviceId === device.deviceId) {
      forget.textContent = forgetFailure.message;
    }
    forget.addEventListener('click', async () => {
      if (forgetting) return;
      forgetting = device.deviceId;
      forgetFailure = null;
      forget.disabled = true;
      try {
        await api.call('devices.forget', { deviceId: device.deviceId });
      } catch (error) {
        forgetFailure = { deviceId: device.deviceId, message: error.message };
      } finally {
        forgetting = null;
        // Both: this button when it is still the one on screen, and the state
        // above for when a poll has already replaced it. Neither knows which
        // of the two happened.
        forget.disabled = false;
        forget.textContent = forgetFailure ? forgetFailure.message : t('forget');
      }
      // On the way out of both paths. A device that went needs the list
      // without it; one that refused to go needs the reason on the live row.
      await refresh();
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
            t(
              'grantLine',
              permission.service,
              permission.action,
              permission.resource,
              permission.user
            )
          )
        );
      }
      if ((credential.permissions || []).length === 0) {
        permissions.appendChild(node('li', null, t('noGrants')));
      }
      entry.appendChild(permissions);
      entry.appendChild(permissionEditor(device, credential));
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
      entry.appendChild(
        node('p', 'muted', t('transportPending', transport.blockedOn))
      );
    }
    container.appendChild(entry);
  }

  if (blockedOn.length > 0) {
    const entry = node('div', 'entry');
    entry.appendChild(node('h3', null, t('blockedOn')));
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
    container.appendChild(node('p', 'empty', t('noHistory')));
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
    repaint = () => {
      renderStatus(status);
      renderHistory(history.entries || []);
    };
  } catch (error) {
    showOffline(error.message);
  }
}

async function showOffline(reason) {
  repaint = () => showOffline(reason);
  el('offline-banner').hidden = false;
  el('offline-detail').textContent = reason || t('offlineDefault');
  const connection = el('connection');
  connection.textContent = t('connectionOffline');
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
  authorization: 'credentialAuthorization',
  vault: 'credentialVault',
  locker: 'credentialLocker',
  webauthn: 'credentialWebauthn',
  ssh: 'credentialSsh',
};

function describeService() {
  const service = el('pair-service').value;
  el('pair-service-note').textContent = PAIRING_SERVICES[service]
    ? t(PAIRING_SERVICES[service])
    : '';
}

el('pair-service').addEventListener('change', describeService);
describeService();

el('pair').addEventListener('click', async () => {
  el('confirm').hidden = true;
  const service = el('pair-service').value;
  try {
    const bootstrap = await api.call('pair.begin', { service });
    el('pairing-service').textContent = PAIRING_SERVICES[bootstrap.service]
      ? t(PAIRING_SERVICES[bootstrap.service])
      : '';
    el('pairing-payload').textContent = bootstrap.qrPayload;
    el('pairing-blocked').textContent = bootstrap.blockedOn || '';
    el('pairing-expiry').textContent = t(
      'pairingExpiry',
      new Date(bootstrap.expiresAtMs).toLocaleTimeString()
    );

    try {
      el('pairing-qr').src = await api.renderQr(bootstrap.qrPayload);
    } catch (error) {
      // The payload is still readable below the code, so a rendering failure
      // is a degradation rather than a dead end.
      el('pairing-blocked').textContent = t('pairingQrFailed', error.message);
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

/// The row waiting on the phone, and the last row that was copied.
///
/// Held here rather than on the button, because the button does not outlive
/// the wait. A copy takes as long as someone takes to approve on their phone,
/// and anything that re-renders the list in that window -- a keystroke in the
/// search box is enough -- rebuilds every row from `vaultItems`. The button
/// that was disabled and reading "no telefone…" was then a detached node: the
/// row on screen was a fresh one, enabled, inviting a second press for a copy
/// already in flight, which is a second approval sheet on the phone for one
/// press of one button.
let vaultCopying = null;
let vaultCopied = null;

function vaultNote(text, kind) {
  const note = el('vault-note');
  note.textContent = text;
  note.className = kind === 'bad' ? 'muted note--bad' : 'muted';
}

/// Loads the list. Returns null when the panel now shows a current one, or the
/// reason it does not.
///
/// The answer matters to exactly one caller: storing an item re-lists straight
/// afterwards, and used to write its own success line over whatever this left
/// behind. A listing that failed set `vaultItems` to null, so the panel went
/// empty -- and the sentence explaining why was replaced, half a tick later,
/// by "guardado". A person who declined the second Keystore prompt got a
/// success message above an empty vault and nothing anywhere saying to press
/// refresh.
async function loadVault() {
  // Another listing is already on its way and will write the note itself.
  // Not a failure to report: the panel does end up current.
  if (vaultLoading) return null;
  vaultLoading = true;
  vaultNote(t('vaultAsking'));
  let failure = null;
  try {
    const listed = await api.call('vault.list', {});
    vaultItems = listed.items || [];
    vaultNote(
      listed.development
        ? t('vaultDevelopment')
        : t('vaultListed', vaultItems.length, listed.deviceName || t('vaultPhone'))
    );
  } catch (error) {
    vaultItems = null;
    failure = error.message;
    vaultNote(failure, 'bad');
  } finally {
    vaultLoading = false;
    renderVault();
  }
  return failure;
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
        vaultItems.length === 0 ? t('vaultEmpty') : t('vaultNoMatch')
      )
    );
    return;
  }

  for (const item of shown) {
    const entry = node('div', 'entry');
    const row = node('div', 'row');
    row.appendChild(node('h3', null, item.name));

    const copy = node('button', 'tag', t('copy'));
    copy.dataset.copy = item.id;
    // Re-applied on every render, so the state survives one.
    if (vaultCopying === item.id) {
      copy.disabled = true;
      copy.textContent = t('copyOnPhone');
    } else if (vaultCopied === item.id) {
      copy.textContent = t('copied');
    }
    copy.addEventListener('click', () => copyItem(item));
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
  if (!result.memoryLocked) warnings.push(t('clipboardPagefile'));
  if (!result.historyExcluded) warnings.push(t('clipboardHistory'));
  if (!result.cloudExcluded) warnings.push(t('clipboardCloud'));

  return (
    `${opening} ${t('clipboardClears', seconds)}` +
    (warnings.length ? ` ${t('clipboardWarning', warnings.join('; '))}` : '')
  );
}

async function copyItem(item) {
  // One at a time. The agent serialises these anyway, so a second press only
  // ever bought a second sheet on the phone for a copy already under way.
  if (vaultCopying) return;
  vaultCopying = item.id;
  vaultCopied = null;
  renderVault();
  vaultNote(t('approveOnPhone', item.name));
  try {
    // The revision of the row that is on screen. If the phone answers with a
    // different one the agent refuses the copy — the item was edited somewhere
    // else, and pasting it would hand over a value nobody looked at.
    const result = await api.call('vault.copy', {
      itemId: item.id,
      expectedRevision: item.revision,
    });
    vaultCopied = item.id;
    vaultNote(clipboardNote(result, t('copiedOpening')));
  } catch (error) {
    // A refusal on the phone, a stale revision and a missing item all arrive
    // as the same code. Saying which one it was is not something this window
    // is able to do, so it does not guess.
    vaultNote(error.message, 'bad');
  } finally {
    vaultCopying = null;
    renderVault();
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
    // a press of refresh, rather than an unexplained prompt after every
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
    vaultNote(clipboardNote(result, t('generatedOpening', result.length)));
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
    vaultNote(t('nameRequired'), 'bad');
    el('vault-new-name').focus();
    return;
  }
  button.disabled = true;
  vaultNote(t('approveOnPhone', name));
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
    //
    // And it can fail on its own. Listing decrypts the vault, so it raises a
    // second Keystore prompt a moment after the one the person just answered
    // for the write -- with no approval sheet to explain it, which is the
    // reason `copyItem` no longer re-lists at all. Declining that prompt does
    // not undo the write: the item is on the phone, and both halves have to be
    // said, or the panel reads "stored" over a list that is empty for a
    // reason nobody mentioned.
    vaultItems = null;
    const failure = await loadVault();
    const stored = t('storedOpening', name, result.length);
    if (failure) {
      vaultNote(`${stored} ${t('listFailed', failure)}`, 'bad');
    } else {
      vaultNote(stored);
    }
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
