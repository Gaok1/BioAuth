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
  if (message?.type !== "bioauth-webauthn" || !sender.url) return undefined;

  let origin;
  try {
    const url = new URL(sender.url);
    if (url.protocol !== "https:") throw new Error("HTTPS is required");
    origin = url.origin;
  } catch {
    sendResponse({ ok: false, error: "Invalid browser origin" });
    return true;
  }

  sendToHost({ operation: message.operation, origin, options: message.options }).then(
    (response) => sendResponse(response ?? { ok: false, error: "PhoneAuth host sent no answer" }),
    (error) => sendResponse({ ok: false, error: String(error?.message ?? error) }),
  );
  return true;
});
