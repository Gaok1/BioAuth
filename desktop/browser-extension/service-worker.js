const runtime = globalThis.browser?.runtime ?? chrome.runtime;

const HOST = "com.bioauth.webauthn";

// The two engines disagree on both halves of this exchange.
//
// Sending: Firefox's `browser.*` API returns a promise and rejects a callback;
// Chrome's `chrome.*` API takes a callback and only returns a promise from 116
// onwards. Branch on the namespace rather than guessing from the return value.
const sendToHost = (payload) => {
  if (globalThis.browser?.runtime) {
    return globalThis.browser.runtime.sendNativeMessage(HOST, payload);
  }
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(HOST, payload, (response) => {
      const failure = chrome.runtime.lastError;
      if (failure) reject(new Error(failure.message));
      else resolve(response);
    });
  });
};

// Replying: Firefox resolves a promise returned from the listener, Chrome
// ignores it and closes the channel — which would leave the page waiting on an
// answer that never arrives. `sendResponse` plus `return true` is the one shape
// both implement.
runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!sender.url) return undefined;
  if (message?.type === "bioauth-webauthn-cancel") {
    if (typeof message.requestId !== "string" || !message.requestId) return undefined;
    sendToHost({ operation: "cancel", requestId: message.requestId }).then(
      (response) => sendResponse(response ?? { ok: false, error: "PhoneAuth host sent no answer" }),
      (error) => sendResponse({ ok: false, error: String(error?.message ?? error) }),
    );
    return true;
  }
  if (message?.type !== "bioauth-webauthn") return undefined;
  if (!["create", "get"].includes(message.operation)
      || typeof message.requestId !== "string"
      || !message.requestId
      || !message.options
      || typeof message.options !== "object"
      || Array.isArray(message.options)) {
    sendResponse({ ok: false, error: "Invalid browser request" });
    return true;
  }

  let origin;
  try {
    const url = new URL(sender.url);
    if (url.protocol !== "https:") throw new Error("HTTPS is required");
    origin = url.origin;
  } catch {
    sendResponse({ ok: false, error: "Invalid browser origin" });
    return true;
  }

  sendToHost({
    operation: message.operation,
    requestId: message.requestId,
    origin,
    options: message.options,
  }).then(
    (response) => sendResponse(response ?? { ok: false, error: "PhoneAuth host sent no answer" }),
    (error) => sendResponse({ ok: false, error: String(error?.message ?? error) }),
  );
  return true;
});

// --- password autofill ------------------------------------------------------
//
// A separate listener, a separate host operation, and a separate entry point.
// The passkey path above relays a signature the page cannot reuse; this one
// hands the page a password it keeps. Keeping them apart is what stops a bug
// in the second from reaching the first.
//
// A fill starts from the extension's own action or context menu — never from
// the page. That is the trusted gesture: a page can synthesise a click, and it
// cannot reach `chrome.action.onClicked`.

const AUTOFILL_MENU = "bioauth-autofill";
const AUTOFILL_TITLE = "Preencher senha do cofre";

// What went wrong, where the person who pressed the button can see it.
//
// A fill has no window of its own: the click happens on the toolbar and the
// answer used to be dropped on the floor, so refusing was indistinguishable
// from a button that does nothing. Every reason the vault has for refusing --
// locked, no item for this site, two accounts and no way to choose -- arrived
// and was discarded one step from the person who needed it.
//
// The badge marks that something was refused and the title carries the
// sentence. Cleared when the next attempt starts rather than on a timer,
// because a service worker can be stopped between the two and a timer that
// dies with it leaves the mark up for good.
const report = (message) => {
  const action = globalThis.chrome?.action;
  if (!action) return;
  action.setBadgeText?.({ text: message ? "!" : "" });
  action.setTitle?.({ title: message ? `PhoneAuth: ${message}` : AUTOFILL_TITLE });
  if (message) action.setBadgeBackgroundColor?.({ color: "#b3261e" });
};

// Firefox answers with a promise, Chrome with a callback. The same split as
// `sendToHost`, for the same reason.
const askFrameToFill = (tabId, frameId) => {
  const message = { type: "bioauth-autofill-fill" };
  // `{}` rather than `undefined`: the options argument sits between the
  // message and the callback, and a hole there is not the same as an absence.
  const options = typeof frameId === "number" ? { frameId } : {};
  if (globalThis.browser?.tabs) {
    return globalThis.browser.tabs.sendMessage(tabId, message, options);
  }
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, options, (response) => {
      const failure = chrome.runtime.lastError;
      if (failure) reject(new Error(failure.message));
      else resolve(response);
    });
  });
};

const startFill = ({ tabId, frameId, pageUrl }) => {
  if (typeof tabId !== "number" || !globalThis.chrome?.tabs) return;
  report(null);
  // Content scripts only match `https://*/*`, so anywhere else there is nobody
  // to answer, and that silence would otherwise be read as "no field is
  // focused". The page's own URL is the only thing that tells those apart.
  if (typeof pageUrl === "string" && !pageUrl.startsWith("https://")) {
    report("só páginas https podem ser preenchidas");
    return;
  }
  // The context menu names the frame the click was in. The toolbar button
  // cannot -- the browser does not say which frame has focus -- so that one
  // goes to every frame, and the content script stays quiet in the frames with
  // nothing focused rather than answering for a page it is not part of.
  askFrameToFill(tabId, frameId).then(
    (response) => {
      if (!response?.ok) report(response?.error ?? "o cofre não respondeu");
    },
    () => report("selecione o campo de senha primeiro"),
  );
};

if (globalThis.chrome?.action?.onClicked) {
  chrome.action.onClicked.addListener((tab) => startFill({
    tabId: tab?.id,
    pageUrl: tab?.url,
  }));
}

if (globalThis.chrome?.contextMenus) {
  chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
      id: AUTOFILL_MENU,
      title: AUTOFILL_TITLE,
      contexts: ["editable"],
      documentUrlPatterns: ["https://*/*"],
    });
  });
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info?.menuItemId !== AUTOFILL_MENU) return;
    startFill({ tabId: tab?.id, frameId: info.frameId, pageUrl: info.pageUrl });
  });
}

// The content script asking the vault for one origin's password.
//
// The origin is taken from `sender.url`, which the browser sets, and never
// from the message body — a compromised content script could put anything in
// the body, and this is the check that keeps one page's fill from being
// another page's password.
runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "bioauth-autofill") return undefined;

  let origin;
  try {
    const url = new URL(sender.url);
    if (url.protocol !== "https:") throw new Error("HTTPS is required");
    origin = url.origin;
  } catch {
    sendResponse({ ok: false, error: "Invalid browser origin" });
    return true;
  }

  sendToHost({ operation: "vault-fill", origin }).then(
    (response) => sendResponse(response ?? { ok: false, error: "PhoneAuth host sent no answer" }),
    (error) => sendResponse({ ok: false, error: String(error?.message ?? error) }),
  );
  return true;
});
