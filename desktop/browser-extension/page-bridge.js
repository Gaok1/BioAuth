(() => {
  const credentials = navigator.credentials;
  if (!credentials || credentials.__phoneAuthInstalled) return;

  const nativeCreate = credentials.create.bind(credentials);
  const nativeGet = credentials.get.bind(credentials);
  const pending = new Map();

  const base64url = (bytes) => {
    let binary = "";
    for (const byte of new Uint8Array(bytes.buffer ?? bytes, bytes.byteOffset ?? 0, bytes.byteLength)) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  };

  const fromBase64url = (text) => {
    const normalized = text.replaceAll("-", "+").replaceAll("_", "/");
    const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
  };

  const jsonify = (value) => {
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return base64url(value);
    if (Array.isArray(value)) return value.map(jsonify);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, jsonify(child)]));
    }
    return value;
  };

  const responseObject = (operation, json) => {
    const fields = operation === "create"
      ? ["clientDataJSON", "attestationObject"]
      : ["clientDataJSON", "authenticatorData", "signature", "userHandle"];
    const prototype = operation === "create"
      ? globalThis.AuthenticatorAttestationResponse?.prototype
      : globalThis.AuthenticatorAssertionResponse?.prototype;
    const response = Object.create(prototype ?? Object.prototype);
    for (const field of fields) {
      Object.defineProperty(response, field, {
        value: json.response[field] == null ? null : fromBase64url(json.response[field]),
        enumerable: true,
      });
    }
    if (operation === "create") {
      Object.defineProperties(response, {
        getTransports: { value: () => [...(json.response.transports ?? [])] },
        getPublicKey: { value: () => null },
        getPublicKeyAlgorithm: { value: () => -7 },
      });
    }
    return response;
  };

  const credentialObject = (operation, json) => {
    const credential = Object.create(globalThis.PublicKeyCredential?.prototype ?? Object.prototype);
    Object.defineProperties(credential, {
      id: { value: json.id, enumerable: true },
      rawId: { value: fromBase64url(json.rawId), enumerable: true },
      type: { value: "public-key", enumerable: true },
      authenticatorAttachment: { value: json.authenticatorAttachment ?? "platform", enumerable: true },
      response: { value: responseObject(operation, json), enumerable: true },
      getClientExtensionResults: { value: () => ({ ...(json.clientExtensionResults ?? {}) }) },
      toJSON: { value: () => structuredClone(json) },
    });
    return credential;
  };

  const relay = (operation, options) => {
    const id = crypto.randomUUID();
    const publicKey = jsonify(options.publicKey);
    if (operation === "create") {
      publicKey.rp = { ...publicKey.rp, id: publicKey.rp?.id ?? location.hostname };
    } else {
      publicKey.rpId ??= location.hostname;
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new DOMException("PhoneAuth request timed out", "NotAllowedError"));
      }, 120000);
      pending.set(id, { operation, resolve, reject, timer });
      options.signal?.addEventListener("abort", () => {
        const current = pending.get(id);
        if (!current) return;
        clearTimeout(current.timer);
        pending.delete(id);
        reject(options.signal.reason ?? new DOMException("Aborted", "AbortError"));
      }, { once: true });
      document.dispatchEvent(new CustomEvent("bioauth-webauthn-request", {
        detail: JSON.stringify({ id, operation, options: publicKey }),
      }));
    });
  };

  document.addEventListener("bioauth-webauthn-response", (event) => {
    let message;
    try { message = JSON.parse(event.detail); } catch { return; }
    const request = pending.get(message?.id);
    if (!request) return;
    clearTimeout(request.timer);
    pending.delete(message.id);
    if (!message.ok || !message.response) {
      request.reject(new DOMException(message.error ?? "Passkey request rejected", "NotAllowedError"));
      return;
    }
    try {
      request.resolve(credentialObject(request.operation, message.response));
    } catch {
      request.reject(new DOMException("Invalid PhoneAuth response", "UnknownError"));
    }
  });

  Object.defineProperties(credentials, {
    __phoneAuthInstalled: { value: true },
    create: {
      value: (options = {}) => options.publicKey
        ? relay("create", options)
        : nativeCreate(options),
    },
    get: {
      value: (options = {}) => options.publicKey && options.mediation !== "conditional"
        ? relay("get", options)
        : nativeGet(options),
    },
  });
})();
