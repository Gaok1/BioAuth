// The isolated half of the passkey relay.
//
// Wrapped, because every content script this extension injects into a frame
// shares one global scope with the others. A top-level `const` here is a
// top-level `const` for all of them, and two files that both wanted `runtime`
// meant the second one threw `Identifier 'runtime' has already been declared`
// and never ran at all -- silently, in a console nobody reads, taking the
// whole autofill feature with it. Nothing of this file belongs in that scope.
(() => {
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
    } catch (failure) {
      if (!request?.id) return;
      // The browser's own words, rather than one sentence standing in for all
      // of them. They are different problems: "Extension context invalidated"
      // means this script outlived the extension that injected it and every
      // request from this tab will fail until the page is reloaded, which is
      // the one failure a person can fix and the one they were not told about.
      // "Receiving end does not exist" means the worker was never there, and
      // "the message port closed" means it went away mid-request.
      const detail = String(failure?.message ?? failure ?? "").slice(0, 200);
      reply(request.id, {
        ok: false,
        error: /context invalidated/i.test(detail)
          ? "PhoneAuth was updated — reload this page and try again"
          : detail
            ? `PhoneAuth bridge failed: ${detail}`
            : "PhoneAuth bridge failed",
      });
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
})();
