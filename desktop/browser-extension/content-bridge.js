const runtime = globalThis.browser?.runtime ?? chrome.runtime;

const framePermits = (operation) => {
  if (window.top === window) return true;
  const feature = operation === "create"
    ? "publickey-credentials-create"
    : "publickey-credentials-get";
  const policy = document.permissionsPolicy ?? document.featurePolicy;
  try {
    return policy?.allowsFeature?.(feature) === true;
  } catch {
    return false;
  }
};

const reply = (id, response) => document.dispatchEvent(
  new CustomEvent("bioauth-webauthn-response", {
    detail: JSON.stringify({ id, ...response }),
  }),
);

document.addEventListener("bioauth-webauthn-request", async (event) => {
  let request;
  try {
    request = JSON.parse(event.detail);
    if (!request?.id || !["create", "get"].includes(request.operation)) return;
    if (!framePermits(request.operation)) {
      reply(request.id, { ok: false, error: "This frame is not allowed to use PhoneAuth passkeys" });
      return;
    }
    const response = await runtime.sendMessage({
      type: "bioauth-webauthn",
      requestId: request.id,
      operation: request.operation,
      options: request.options,
    });
    reply(request.id, response);
  } catch {
    if (!request?.id) return;
    reply(request.id, { ok: false, error: "PhoneAuth bridge failed" });
  }
});

document.addEventListener("bioauth-webauthn-cancel", (event) => {
  try {
    const request = JSON.parse(event.detail);
    if (!request?.id) return;
    void Promise.resolve(runtime.sendMessage({
      type: "bioauth-webauthn-cancel",
      requestId: request.id,
    })).catch(() => {});
  } catch {
    // A page can forge DOM events; malformed cancellation is simply ignored.
  }
});
