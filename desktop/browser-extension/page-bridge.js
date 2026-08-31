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

  // A real credential carries its methods on the prototype, where a library is
  // free to shadow one by assigning to the instance. `@github/webauthn-json`
  // does exactly that with `toJSON`, and it is on the path of every site using
  // it — github.com included. Defining ours without `writable` made that
  // assignment a TypeError, so the ceremony died *after* the phone had already
  // signed: the person approved with a fingerprint and then read "registration
  // failed". Own properties that shadow a prototype method must be as writable
  // as the method they stand in for.
  const method = { writable: true, configurable: true };

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
        configurable: true,
      });
    }
    if (operation === "create") {
      const spki = json.response.publicKey;
      Object.defineProperties(response, {
        getTransports: { ...method, value: () => [...(json.response.transports ?? [])] },
        getPublicKey: { ...method, value: () => (spki == null ? null : fromBase64url(spki)) },
        getPublicKeyAlgorithm: {
          ...method,
          value: () => json.response.publicKeyAlgorithm ?? -7,
        },
      });
    }
    return response;
  };

  const credentialObject = (operation, json, clientExtensionResults = {}) => {
    const credential = Object.create(globalThis.PublicKeyCredential?.prototype ?? Object.prototype);
    Object.defineProperties(credential, {
      id: { value: json.id, enumerable: true, configurable: true },
      rawId: { value: fromBase64url(json.rawId), enumerable: true, configurable: true },
      type: { value: "public-key", enumerable: true, configurable: true },
      authenticatorAttachment: {
        // Every credential this bridge builds came off a phone at the other
        // end of a link, so the fallback for one that arrives without the
        // field is `cross-platform`, not `platform`. Saying `platform` told
        // the site the key lived on the computer it was running on.
        value: json.authenticatorAttachment ?? "cross-platform",
        enumerable: true,
        configurable: true,
      },
      response: { value: responseObject(operation, json), enumerable: true, configurable: true },
      getClientExtensionResults: {
        ...method,
        value: () => ({ ...(json.clientExtensionResults ?? {}), ...clientExtensionResults }),
      },
      toJSON: {
        ...method,
        value: () => structuredClone({
          ...json,
          clientExtensionResults: {
            ...(json.clientExtensionResults ?? {}),
            ...clientExtensionResults,
          },
        }),
      },
    });
    return credential;
  };

  // Overriding `navigator.credentials` also bypasses the browser's own
  // Permissions Policy gate, which is what normally stops a third-party iframe
  // — an ad, an embedded widget — from asking for a passkey. Re-check it here.
  // Firefox exposes no policy object, so a cross-origin frame fails closed
  // there; WebAuthn inside one is rare and always needs an explicit `allow=`.
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

  // The relying party's own deadline, kept inside bounds a person can actually
  // meet: the phone has to wake, show a prompt, and take a fingerprint.
  const deadline = (publicKey) => {
    const requested = Number(publicKey?.timeout);
    if (!Number.isFinite(requested) || requested <= 0) return 120000;
    return Math.min(Math.max(requested, 15000), 300000);
  };

  const relay = (operation, options) => {
    const id = crypto.randomUUID();
    const publicKey = jsonify(options.publicKey);
    const clientExtensionResults = {};
    if (publicKey.extensions) {
      // AppID is processed by the WebAuthn client, not by the authenticator.
      // This bridge has never created U2F credentials, so neither legacy lookup
      // can match. GitHub includes these migration extensions in otherwise
      // ordinary passkey requests; forwarding them to the phone made the phone
      // reject a valid ceremony as an unsupported authenticator extension.
      if (operation === "create" && "appidExclude" in publicKey.extensions) {
        clientExtensionResults.appidExclude = false;
      }
      if (operation === "get" && "appid" in publicKey.extensions) {
        clientExtensionResults.appid = false;
      }
      publicKey.extensions = Object.fromEntries(
        Object.entries(publicKey.extensions).filter(([name]) => name === "credProps"),
      );
      if (!Object.keys(publicKey.extensions).length) delete publicKey.extensions;
    }
    if (operation === "create") {
      publicKey.rp = { ...publicKey.rp, id: publicKey.rp?.id ?? location.hostname };
    } else {
      publicKey.rpId ??= location.hostname;
    }
    return new Promise((resolve, reject) => {
      // A signal that is already aborted never fires `abort` again, so the
      // listener installed below would never run: the request went to the
      // phone anyway and raised a biometric prompt for a ceremony the page had
      // already given up on, and the promise then settled on whatever the
      // person did about it. Both algorithms check this first and reject with
      // the signal's own reason. Sites reach it by reusing one controller
      // across an autofill attempt and the button that replaces it, which is
      // the ordinary shape of a passkey sign-in page.
      if (options.signal?.aborted) {
        reject(options.signal.reason ?? new DOMException("Aborted", "AbortError"));
        return;
      }
      if (!framePermits(operation)) {
        reject(new DOMException(
          "This frame is not allowed to use PhoneAuth passkeys",
          "NotAllowedError",
        ));
        return;
      }
      const timer = setTimeout(() => {
        pending.delete(id);
        document.dispatchEvent(new CustomEvent("bioauth-webauthn-cancel", {
          detail: JSON.stringify({ id }),
        }));
        reject(new DOMException("PhoneAuth request timed out", "NotAllowedError"));
      }, deadline(options.publicKey));
      pending.set(id, { operation, resolve, reject, timer, clientExtensionResults });
      options.signal?.addEventListener("abort", () => {
        const current = pending.get(id);
        if (!current) return;
        clearTimeout(current.timer);
        pending.delete(id);
        document.dispatchEvent(new CustomEvent("bioauth-webauthn-cancel", {
          detail: JSON.stringify({ id }),
        }));
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
      request.resolve(credentialObject(
        request.operation,
        message.response,
        request.clientExtensionResults,
      ));
    } catch {
      request.reject(new DOMException("Invalid PhoneAuth response", "UnknownError"));
    }
  });

  // The page asks whether a platform authenticator exists before it offers the
  // option, and nothing here answered for PhoneAuth. `create` and `get` were
  // taken over completely, while the one question the platform API exposes
  // about availability was left to the browser -- which answers about Windows
  // Hello and has never heard of this extension. A site that gates its
  // "use this device" path on that answer therefore never offered the path this
  // bridge had already taken over, and the failure was silent: no error, just
  // an option that was not there.
  //
  // Unconditionally true, and deliberately not a probe of the agent. The
  // question is whether such an authenticator exists on this machine, not
  // whether it will succeed this second -- Windows Hello answers true with its
  // owner out of the room. When the agent is down `create` rejects with a
  // message saying so, which is a better thing for a person to see than an
  // option that quietly does not appear.
  const platformAuthenticator = globalThis.PublicKeyCredential;
  if (typeof platformAuthenticator === "function") {
    const nativeCapabilities = platformAuthenticator.getClientCapabilities?.bind(
      platformAuthenticator,
    );
    Object.defineProperty(platformAuthenticator, "isUserVerifyingPlatformAuthenticatorAvailable", {
      value: async () => true,
    });
    // Newer engines ask the same thing through one dictionary instead. Merged
    // over the browser's answer rather than replacing it: the capabilities this
    // bridge does not speak for stay the browser's to report -- conditional
    // mediation above all, which `get` deliberately hands back to the browser's
    // own authenticator. Only defined when the engine has it, so that feature
    // detection still sees the engine it is actually running on.
    if (nativeCapabilities) {
      Object.defineProperty(platformAuthenticator, "getClientCapabilities", {
        value: async () => Object.fromEntries(Object.entries({
          ...(await nativeCapabilities().catch(() => ({}))),
          userVerifyingPlatformAuthenticator: true,
          passkeyPlatformAuthenticator: true,
          "extension:appid": true,
          "extension:appidExclude": true,
          "extension:credProps": true,
          "extension:largeBlob": false,
          "extension:prf": false,
        }).sort(([left], [right]) => left.localeCompare(right))),
      });
    }
  }

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
