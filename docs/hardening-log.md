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

## Next

1. **Browser extension protocol coverage.** The autofill bridge refuses
   anything that is not `https:`. Decide what else is legitimate — at minimum
   `http://localhost` and `http://127.0.0.1` for local development — and
   whether the native-messaging protocol version is negotiated or assumed.
2. **Audit the rest of the vault channel for the same shape of bug**: an early
   return that answers before `authenticate` runs. `export` on a missing file
   is the other one, and is currently deliberate.

## Ruled out

Nothing yet.
