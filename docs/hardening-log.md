# Hardening log

The running record of the hardening loop: what each pass changed, and what the
next pass should pick up. Scope is *making what exists solid for real use* —
`implementation-tracker.md` is still the authority on what the product is
supposed to contain.

In English, like the code comments and commit messages. The product tracker
stays in Portuguese; this file is a working log, not a spec.

Rules this log follows:

- A pass ends with a commit that is green, or it does not end.
- Every finding gets an entry, including the ones deliberately left alone —
  a bug ruled out once should not be re-investigated from scratch next pass.
- "Next" is ordered. The top item is what the next pass starts on.

## Done

### Pass 1 — 2026-09-04

- **Unlocking an empty vault asked for nothing.** `VaultStoreChannel.load`
  answered `list`/`listAll` from the `!storage.exists()` branch before any
  authentication ran, so on a fresh install — and on any vault whose contents
  had been discarded — the unlock button opened the vault with no prompt.
  Now it runs `requireCryptoReady()` and authenticates against the key the
  first write would use. Reported by the user, not found by a test.
- **`webAuthnPromptInfo` broke the instrumentation build.** The context
  parameter added with the Android string resources left the test calling the
  three-argument version. `src/androidTest` is compiled by the emulator CI job
  and nothing else, so it passed every local check. Fixed in `725b568`.

### Pass 2 — 2026-09-04

- **The empty-vault unlock now has a test.** `VaultStoreChannelTest` drives the
  channel directly with a storage that reports no file, and asserts that both
  `list` and `listAll` reach `requireCryptoReady` instead of answering. Checked
  the way a regression test has to be: reverted the fix, watched it fail,
  restored it, watched it pass.
- **Mockito could not mock a final class on a current JDK.** Mockito 5.0 ships a
  Byte Buddy that refuses Java 21 outright, so the approach failed locally while
  CI’s JDK was fine. Fixed with `net.bytebuddy.experimental` on the unit test
  task rather than a dependency bump, which would have dragged the trust
  snapshots along with it.

### Pass 3 — 2026-09-04

- **The vault can now fill on localhost.** The extension refused anything that
  was not `https:`, which meant a personal vault could not fill the app you are
  writing on your own machine. The rule behind https is that a password typed
  over plain HTTP is a password on the wire, and a request to a loopback name
  never reaches one — the same reason browsers count localhost as a secure
  context. Widened end to end: `origin_host` in the agent, `fillableOrigin` in
  the content script and the service worker, and the manifest's match patterns.
  Loopback is decided by name (`localhost`, `*.localhost`, `127.0.0.1`) and
  never resolved, because a name that points at 127.0.0.1 today can point
  elsewhere tomorrow.
- **Filling only — and that scoping is the point.** Widening the match patterns
  for all three content scripts would have injected `page-bridge.js` on
  localhost, where it replaces `navigator.credentials` with a relay the agent
  refuses for any non-https origin. Passkeys on localhost work today through
  the browser's own implementation; that change would have taken them away and
  put nothing in their place. Caught before commit, not after.

### Pass 4 — 2026-09-04

- Audited the vault channel for more of pass 1's bug. None found; see
  *Ruled out*.

### Pass 5 — 2026-09-04

- **Pass 3 did not actually work, and this found it.** The native-messaging
  host is a second gate in front of `vault.fill`, and it carried its own copy
  of the https rule: `origin.starts_with("https://")`. So the extension sent a
  loopback origin, the agent would have accepted it, and this binary refused it
  first — the localhost fill was dead before it reached the socket. Shipped
  green because nothing tested that filter.
- **Fixed by deleting the copy, not by updating it.** The host now calls the
  agent's `origin_host`, so there is one definition of a fillable origin and a
  future change to it cannot leave a second gate behind. Tested at the host's
  own boundary, which is what was missing.
- **Passkeys on localhost deferred, with reasons.** It is not the same size of
  job as the fill: the phone binds an origin to an RP ID and requires `https`
  in `requireOriginMatchesRpId`, asset links are fetched over https, and the
  agent and the host each test the origin again. That is the WebAuthn phishing
  binding, and a rushed relaxation of it is the one mistake in this repo that
  would matter. Browsers already do WebAuthn on localhost with their built-in
  authenticator, so nothing is broken today — what is missing is using the
  phone there. Worth a designed pass, not a loop tick.

## Next

1. **A test that the two gates cannot drift apart again.** Pass 5 fixed one
   copy of the origin rule. Nothing stops a third appearing — the extension
   holds its own in JavaScript, necessarily, and it is checked only by its own
   tests. A shared table of cases, or at least a comment at each site pointing
   at the others.
2. **The native-messaging payload has no version field.** Nothing negotiates:
   an extension newer than the installed host sends an operation the host does
   not know and gets `invalid browser request`, which says nothing about the
   real cause. Decide whether a version belongs in the handshake.
3. **Passkeys on localhost**, as scoped above.

## Ruled out

- **The rest of the vault channel does not have pass 1's bug.** Everything in
  `process` runs after a successful decrypt, so it is already behind a prompt.
  The two answers that still come out of the `!storage.exists()` branch without
  one are `export`, which returns no items, and a `restore` that adds nothing,
  which returns an empty listing — neither reveals anything a locked vault was
  holding. `VaultCredentialActivity` fails rather than answers when the vault
  file is missing.
