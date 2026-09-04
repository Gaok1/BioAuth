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

### Pass 6 — 2026-09-04

- **The origin rule now has one table and four gates tested against it.**
  `desktop/fillable-origins.json` holds the cases; the agent checks them in
  `tests/fillable_origins.rs`, and the service worker, the content script and
  the manifest's match patterns check the same cases in
  `desktop/ui/test/fillable-origins.test.js`. The rule cannot live in one place
  — an extension cannot call the agent to ask — so what is shared is the
  answer, not the code.
- **The manifest is a gate too, and now it is treated as one.** It decides a
  page's fate before any of the code runs, by choosing where the content script
  is injected; an origin the agent would fill but the manifest does not cover
  reports that nobody answered, which reads as "no field is focused". Same
  disagreement as pass 5, one level up.
- Checked the guard by breaking the manifest on purpose: dropping one loopback
  pattern fails that test and leaves the other three passing, which is what a
  drift guard has to do.

### Pass 7 — 2026-09-04

- **Version skew now says so.** The native-messaging host answered both "I do
  not know this operation" and "I know it and cannot read this message" with
  `invalid browser request`. They are different problems with different fixes.
  An unknown operation now names the host's version and says to reinstall it;
  a known one with a broken body keeps the old sentence. A message with no
  operation at all is malformed rather than old, and does not send anybody
  reinstalling.
- **No version field, and none needed.** The skew is real — the extension is
  loaded from the repository and changes when it is rebuilt, while the host is
  a copy an installer made — but it shows up as exactly one symptom, an
  operation the host does not have. Naming that costs nothing and negotiates
  nothing. A handshake would be ceremony around a message the host already has
  in hand.
- The operation name is filtered and truncated before it is quoted back: it
  comes from the browser and ends up in a badge tooltip and in logs.

### Pass 8 — 2026-09-04

- **One Portuguese string survived the language pack**, and it was in the worst
  possible place to notice: `XTypeGroup(label: 'Exportação de gerenciador')`,
  inside a `const` list, drawn by the platform's own file dialog. A const list
  is exactly where a string hides from a pack. Moved to `importFileType` and the
  list is no longer const.
- **A guard for the whole class.** `mobile/test/language_pack_test.dart` scans
  `lib/` for quoted literals carrying Portuguese accents, skipping `l10n/` and
  dropping comments with a scan rather than a pattern, since most comments in
  this repository contain quotes. Checked by putting the literal back: it names
  the file, the line and the string.
- Two Kotlin comments still quoted strings that had moved into resources.

### Pass 9 — 2026-09-04

- **The window's packs now have the check the phone gets from its compiler.**
  `AppStrings` is an abstract class, so a string in one language and not the
  other does not build. The window's packs are two object literals and nothing
  fails: a missing key falls back to English, and a key the markup asks for that
  no pack has renders as the word `undefined`. Three tests stand in — the packs
  hold the same keys, a key is the same kind of thing in each (a sentence in one
  and a function in the other is worse than a missing one), and every key the
  markup asks for exists. Checked by deleting a key: all three fail.
- **One string in the markup was never translated.** The connection pill was
  written `>offline<`, which is text no pack can reach; it showed in English
  until the first status answered. Now `data-i18n="connectionOffline"`. A fourth
  test walks the markup for any other text left outside a `data-i18n` element,
  with an allowlist of exactly one entry: the product's name.
- `applyLanguage` redraws what the agent's answers produced, rather than leaving
  it to the round trip the picker asks for. Smaller than it first looked — the
  picker already calls `refresh()`, so the text was never permanently stale.
  What it removes is a visible moment of the old language, and the requirement
  that every future caller of `applyLanguage` remember to refresh.

### Pass 10 — 2026-09-04

- **The extension's packs are now checked too**, which completes the set: the
  phone by its compiler, the window by pass 9, the extension by
  `extension-locales.test.js`. Five checks — the manifest's `default_locale` is
  a pack that ships, every pack holds the same keys, every key the code asks for
  exists, every message is asked for by somebody, and every `t("key",
  "fallback")` fallback is exactly what the default pack says.
- **The fallback check is the one that earns its place.** A fallback is not
  decoration: it is what a browser with no `i18n` shows and what `node --test`
  sees, so a fallback drifting from the pack is a second wording of the same
  sentence that nobody maintains.
- **Writing it surfaced a copy bug.** `fillSelectField` said "select the
  password field first" while `fillSelectFieldCapitalized` said "Select the
  user or password field first". The bridge accepts a username box — it says so
  in `fillTarget` — so the toolbar button was telling people to pick the one
  field when either would have done. Both variants now agree with the code.

### Pass 11 — 2026-09-04

- **The host binary can say which build it is.** `--version` prints and exits.
  Before it, running the host by hand blocked on stdin and looked like a hang,
  and there was no way to ask a machine which build a browser was about to
  launch.
- **Both installers now use it as a "does this run at all" check.** Mode bits
  say a file may be executed, not that it can be: a binary built for another
  architecture, or half-copied, satisfies `-x`, and then every launch the
  browser makes fails silently — which a browser reports as nothing at all.
  The installer refuses it now instead of leaving a manifest pointing at it.
- **Unrecognised arguments stay ignored, and that is the delicate part.**
  Chrome passes the calling extension's origin, Firefox adds the manifest path
  and the extension id. A host that treated an unknown argument as a usage
  error would refuse every launch a browser makes. `tests/host_arguments.rs`
  runs the real binary with four arguments a browser actually sends and
  requires each to succeed.
- Checked the installer guard by removing it: the new case in
  `install.test.sh` fails, saying the installer accepted a host that will not
  run.

### Pass 12 — 2026-09-04

- **Pass 11 broke the Windows job, and this is the fix.** The probe asked the
  host `--version` and required exit 0. `install.test.ps1` stands its host in
  with a copy of `powershell.exe`, which does not answer that flag, so the
  installer refused it and the job went red. Caught by CI, not by me — the
  Linux test passed and I did not run the Windows one.
- **The probe was asking the wrong question.** What matters is whether a
  browser can launch the binary, not whether it parses a flag. Both installers
  now launch it the way a browser does, with nothing on stdin: the host reads
  end-of-stream and stops. That works for the real binary, for a stand-in, and
  fails for a file that cannot be executed — which is the case the check is for.
- **Both platforms now have the negative case**, and both were verified by
  removing the guard and watching the test fail. On Windows the broken host is
  a file with the right name and the wrong contents, which is what half a copy
  looks like.
- `--version` stays. It is still what a person runs to find out which build is
  installed, and `host_arguments.rs` still pins it.

### Pass 13 — 2026-09-04

- **The capitalised message pairs are held together now.** Several messages
  exist twice — once mid-sentence for a badge tooltip, once as a whole sentence
  handed back to the page — and pass 10 found the pair that had drifted. The
  test requires the twin to be the plain message with its first letter
  capitalised, in every language, since a pack can drift on one side alone.
  Checked by restoring the old wording: it fails, and so does the fallback test.
- **The loopback match patterns are valid, confirmed by a real validator.** An
  invalid pattern makes a browser reject the whole extension at load, and
  nothing in this repository parses Chrome's grammar. Mozilla's `addons-linter`
  does, it runs over the packaged extension in CI, and it accepts them.

## Next

1. **Passkeys on localhost**, as scoped in pass 5.
2. **A password saved for `localhost` is offered to every port.** `item_host`
   and `origin_host` compare hosts and drop the port on purpose, which is right
   for the web and loose on loopback, where the port is the only thing telling
   two apps apart. Two saved items refuse rather than choose, and the phone
   shows the origin before releasing anything, so nothing leaks silently — but
   the matching is wider there than it reads. Introduced with the localhost
   fill in pass 3, not before it.
3. **Nothing exercises the phone.** Twelve passes of tests have not run the
   app once; the two real bugs this session found — the vault unlock and the
   dead-on-arrival localhost fill — were both invisible to the suite.

## Ruled out

- **The phone and the agent share no origin rule.** Pass 6's shape does not
  repeat on the WebAuthn side: the agent never looks at an RP ID, it relays.
  Only `RpIdValidator` on the phone binds an origin to one, so there is nothing
  to keep in agreement and no table to share. The earlier queue entry that said
  otherwise was wrong.
- **The rest of the vault channel does not have pass 1's bug.** Everything in
  `process` runs after a successful decrypt, so it is already behind a prompt.
  The two answers that still come out of the `!storage.exists()` branch without
  one are `export`, which returns no items, and a `restore` that adds nothing,
  which returns an empty listing — neither reveals anything a locked vault was
  holding. `VaultCredentialActivity` fails rather than answers when the vault
  file is missing.
