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

const startFill = (tabId, frameId) => {
  if (typeof tabId !== "number") return;
  // Addressed to the frame the user was actually in. Sending to the tab would
  // deliver to every frame, and the one that answered first would win.
  runtime.sendMessage
    ? chrome.tabs.sendMessage(
        tabId,
        { type: "bioauth-autofill-fill" },
        typeof frameId === "number" ? { frameId } : undefined,
      )
    : undefined;
};

if (globalThis.chrome?.action?.onClicked) {
  chrome.action.onClicked.addListener((tab) => startFill(tab?.id));
}

if (globalThis.chrome?.contextMenus) {
  chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
      id: AUTOFILL_MENU,
      title: "Preencher senha do cofre",
      contexts: ["editable"],
      documentUrlPatterns: ["https://*/*"],
    });
  });
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info?.menuItemId !== AUTOFILL_MENU) return;
    startFill(tab?.id, info.frameId);
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
