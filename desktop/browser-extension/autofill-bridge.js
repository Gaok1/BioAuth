// Password autofill, deliberately kept apart from the passkey relay.
//
// A plain script, not a module: MV3 content scripts have no module loading,
// and the test harness runs this file in a `vm` context where top-level
// declarations become properties of that context. So the functions below are
// reachable from a test without a test-only export existing in shipped code.
//
// Separate file, separate message type, separate native-host operation. The
// two features look alike and are not: a passkey assertion is a signature the
// page cannot reuse, and an autofilled password is a string the page keeps
// forever. Sharing a code path would mean a bug in the easier feature reaching
// the harder one.
//
// **The page's process receives the plaintext.** That is not a leak, it is
// what autofill is, and it is why the rules below are what they are. A
// password filled into a field is a password the renderer holds, any script on
// that page can read once it is in the DOM, and an extension cannot take back.
// So it happens only when: the user asked for it with a real gesture, the
// origin matches exactly, and the frame is one the top page vouches for.
//
// Four rules, in the order they are checked:
//
//   1. No automatic anything. Nothing here runs on load, on focus, or on a
//      form appearing. Autofill that fires by itself is autofill that fires on
//      a phishing page too.
//   2. A trusted gesture. The fill is started by the extension's own action or
//      context menu; a page-dispatched event is refused, because a page that
//      can synthesise a click can synthesise consent.
//   3. Exact origin. `login.bank.example` and `blog.bank.example` are one
//      registrable domain and not one place to type a password.
//   4. No unexpected frame. A cross-origin iframe never receives the top
//      page's credentials, and a same-origin one is only filled when it is
//      the frame the user is actually typing in.

const runtime = globalThis.browser?.runtime ?? chrome.runtime;

/// Whether this frame may be filled at all.
///
/// A cross-origin iframe is the whole problem: an advertisement embedded in a
/// bank's page must not be handed the bank's password, and from inside that
/// frame `document.domain` and the visible chrome both look reassuring.
///
/// Same-origin nesting is allowed because the top page chose to embed itself,
/// and refusing it would break ordinary login pages that frame their own form.
function frameIsFillable(view) {
  // The whole check is inside the try, including reading `top`. A browser
  // lets that one through and throws on `location`, but a check that fails
  // open on an unexpected throw is a check that stops being one.
  try {
    if (view.top === view) return true;
    // Reading `origin` across a cross-origin boundary throws, and the throw is
    // the answer. Comparing strings would need the string to be readable.
    return view.top.location.origin === view.location.origin;
  } catch {
    return false;
  }
}

/// The origin sent to the host, or null when there is not one worth sending.
///
/// Only `https:`. A password typed over plain HTTP is a password on the wire,
/// and filling one automatically would make that this extension's doing.
function fillableOrigin(location) {
  if (location.protocol !== "https:") return null;
  const origin = location.origin;
  if (!origin || origin === "null") return null;
  return origin;
}

/// The field a fill would go into, or null.
///
/// The *focused* field, not the first password input on the page. A page can
/// hold several forms, and guessing between them is how a password ends up in
/// the "confirm your old password" box of a form that emails it somewhere.
function fillTarget(document) {
  const active = document.activeElement;
  if (!active || active.tagName !== "INPUT") return null;
  if (active.type !== "password" && active.type !== "text") return null;
  if (active.disabled || active.readOnly) return null;
  return active;
}

/// The username field paired with a password field, if there is an obvious one.
///
/// Obvious means: in the same form, an input the browser itself would call a
/// username. Anything cleverer is guessing, and a wrong guess writes an
/// account name into a field that was not asking for one.
function usernameFieldFor(passwordField) {
  const form = passwordField.form;
  if (!form) return null;
  const candidates = Array.from(form.elements ?? []).filter(
    (element) =>
      element.tagName === "INPUT" &&
      (element.type === "text" || element.type === "email") &&
      !element.disabled &&
      !element.readOnly,
  );
  // The one immediately before the password field, which is the shape every
  // login form has. No match rather than a guess when it is not that shape.
  const index = Array.from(form.elements ?? []).indexOf(passwordField);
  return candidates.reverse().find(
    (element) => Array.from(form.elements ?? []).indexOf(element) < index,
  ) ?? null;
}

/// Writes a value the way a page's own scripts expect to see it happen.
///
/// Setting `.value` alone leaves frameworks that track their own state showing
/// an empty field and submitting an empty password. The events are what make
/// the fill real rather than cosmetic.
function setFieldValue(field, value, EventCtor) {
  field.value = value;
  field.dispatchEvent(new EventCtor("input", { bubbles: true }));
  field.dispatchEvent(new EventCtor("change", { bubbles: true }));
}

/// Performs one fill. Returns what happened, for the extension to report.
///
/// Takes its collaborators rather than reaching for globals so the rules above
/// can be exercised without a browser.
async function performFill({ view, document, send, EventCtor }) {
  if (!frameIsFillable(view)) {
    return { ok: false, error: "Este quadro não pode ser preenchido" };
  }
  const origin = fillableOrigin(view.location);
  if (!origin) {
    return { ok: false, error: "Só páginas https podem ser preenchidas" };
  }
  const password = fillTarget(document);
  if (!password || password.type !== "password") {
    return { ok: false, error: "Selecione o campo de senha primeiro" };
  }

  // The host answers with a secret or with nothing. Everything about which
  // item, and the approval on the phone, happens on the other side of this
  // call — this side only says where it is.
  const response = await send({ type: "bioauth-autofill", origin });
  if (!response?.ok || typeof response.password !== "string") {
    return { ok: false, error: response?.error ?? "O cofre não respondeu" };
  }

  setFieldValue(password, response.password, EventCtor);
  if (typeof response.username === "string" && response.username) {
    const username = usernameFieldFor(password);
    if (username) setFieldValue(username, response.username, EventCtor);
  }
  return { ok: true };
}

// The only entry point, and it is the extension talking, never the page.
//
// `runtime.onMessage` is reachable from the extension's own action and context
// menu and from nowhere else; a page has no way to dispatch into it. That is
// the trusted gesture rule, enforced by which channel this listens on rather
// than by inspecting an event the page could have made.
if (typeof runtime?.onMessage?.addListener === "function") {
  runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== "bioauth-autofill-fill") return undefined;
    performFill({
      view: window,
      document,
      EventCtor: Event,
      send: (payload) => runtime.sendMessage(payload),
    }).then(sendResponse, () =>
      sendResponse({ ok: false, error: "Falha ao preencher" }),
    );
    return true;
  });
}
