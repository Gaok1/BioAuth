const runtime = globalThis.browser?.runtime ?? chrome.runtime;

runtime.onMessage.addListener((message, sender) => {
  if (message?.type !== "bioauth-webauthn" || !sender.url) return undefined;
  let origin;
  try {
    const url = new URL(sender.url);
    if (url.protocol !== "https:") throw new Error("HTTPS is required");
    origin = url.origin;
  } catch {
    return Promise.resolve({ ok: false, error: "Invalid browser origin" });
  }
  return runtime.sendNativeMessage("com.bioauth.webauthn", {
    operation: message.operation,
    origin,
    options: message.options,
  });
});
