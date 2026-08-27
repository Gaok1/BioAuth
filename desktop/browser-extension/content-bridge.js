const runtime = globalThis.browser?.runtime ?? chrome.runtime;

document.addEventListener("bioauth-webauthn-request", async (event) => {
  let request;
  try {
    request = JSON.parse(event.detail);
    if (!request?.id || !["create", "get"].includes(request.operation)) return;
    const response = await runtime.sendMessage({
      type: "bioauth-webauthn",
      operation: request.operation,
      options: request.options,
    });
    document.dispatchEvent(
      new CustomEvent("bioauth-webauthn-response", {
        detail: JSON.stringify({ id: request.id, ...response }),
      }),
    );
  } catch {
    if (!request?.id) return;
    document.dispatchEvent(
      new CustomEvent("bioauth-webauthn-response", {
        detail: JSON.stringify({ id: request.id, ok: false, error: "PhoneAuth bridge failed" }),
      }),
    );
  }
});
