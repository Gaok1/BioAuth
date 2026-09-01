# External review brief

What to hand a reviewer, and what to ask them.

`REL-04` blocks calling any of this production. This file exists so that
commissioning the review is sending one link rather than explaining a project,
and so that the reviewer spends their time on the parts where a mistake is
unrecoverable instead of rediscovering the layout.

**This is a brief, not a defence.** Where a decision is arguable it is written
here as arguable. A review that only confirms what the authors already believe
has cost money and bought nothing.

## The one-paragraph version

A phone holds hardware-backed private keys and approves things a computer asks
for: logins and `sudo` via PAM, WebAuthn assertions, a password vault, and file
encryption. The computer never holds a key that can authorize on its own. The
phone is the authority for the vault; the desktop reads it over an
authenticated session and can be told no.

## Read in this order

| # | Document | Why it is first |
|---|---|---|
| 1 | `docs/threat-model.md` | What is claimed. Everything else is only interesting relative to this. |
| 2 | `docs/locker-format.md` | Container format. **Head of the queue** — it is the only format that survives on disk indefinitely and can be attacked offline, at leisure, with the file in hand. |
| 3 | `docs/vault-export-format.md` | The other at-rest format. Same construction, different keying. |
| 4 | `docs/protocol-handshake.md` | The session everything else assumes. |
| 5 | `docs/protocol-application.md` | Vault and locker operations, and the approval rules. |
| 6 | `docs/desktop.md` § *Browser autofill* | The one place a plaintext secret is handed to a renderer. |
| 7 | `docs/product-decisions.md`, and the `DEC-` rows in `docs/implementation-tracker.md` | The decisions the code is built on. The prose is in the first and the numbered rows are in the second. Disagreeing with one of these is more useful than finding a bug. |

## The questions that matter

Ordered by how bad it is to be wrong.

1. **Locker container.** Is the claim in `locker-format.md` true — that *no
   change anywhere in a container can make it open and produce a different
   file*? Removing a wrapper is a denial of service and allowed to be one.
   `container_properties.rs` asserts this against random mutations; a proof
   sketch or a counterexample is worth more than either.

2. **Key separation.** Five credential purposes exist and must never be
   interchangeable — the credential that authorizes `sudo` must not open the
   vault or a disk. Is that separation enforced everywhere it is claimed, or
   only where it was remembered?

3. **The approval sheet.** Every vault operation but `list` passes a screen
   naming the computer, the operation and the item. Is that screen actually on
   the only path to a secret, or is there a way to the store that does not
   cross it?

4. **Autofill's opening.** `vault.fill` answers with a plaintext password,
   which is what filling a form field is. Is the narrowing sufficient — origin
   from the browser rather than the page, exact host, https only, one match or
   none, phone approval — or does it leak more than it should?

5. **Canonical encoding.** Every decoder re-encodes what it read and compares,
   so that no byte string decodes to a value whose canonical form differs.
   Without it one signature covers two frames. Is the property actually total?

6. **Recovery.** A locker recovery code and a vault backup code are each the
   whole thing they protect. Are the generation, rendering and parsing sound,
   and is losing them the only unrecoverable path?

## Where we already think we are weak

Naming these is not a request to skip them. It is so the reviewer knows what
will *not* be a surprise, and can spend the surprise budget elsewhere.

- **The TOTP seed sits beside the password.** Two factors on one device. Argued
  in `mobile/lib/core/vault/totp.dart`'s header; we think the alternative
  people actually choose — a screenshot of the QR code — is worse.
- **Autofill hands the browser plaintext.** No version of the feature does not.
- **The phone is trusted as the vault's authority.** A hostile phone is outside
  the model. `vault.copy` checks the revision desktop-side anyway, which helps
  against an edit race and not against a hostile phone.
- **Metadata travels in the clear inside the encrypted channel.** `DEC-06`
  governs at-rest; the session is assumed confidential.
- **BLE has no hardware test.** It compiles in CI and has never met a radio.

## What has not been reviewed by anyone

- The vault and locker application protocol, end to end.
- The container format.
- The autofill boundaries, on both Android and the browser.
- Recovery-code generation and parsing.

## Evidence a reviewer can rerun

```bash
cd desktop && cargo test --workspace
cd desktop && PROPTEST_CASES=65536 cargo test -p phone-auth-protocol --test decoder_properties
cd desktop && PROPTEST_CASES=4096 cargo test -p phone-auth-locker --test container_properties
cd mobile && flutter test
cd mobile && PROPERTY_SEED=12345 PROPERTY_ROUNDS=20000 flutter test test/wire_decoder_properties_test.dart test/vault_import_properties_test.dart
cd desktop/ui && npm test
```

The property suites take their case count from the environment, so a reviewer
can turn them up far past what CI runs and see whether anything falls out.

The two hand-rolled Dart ones take a seed as well, because they are not
proptest and do not draw one: left alone they walk the same sequence of inputs
on every run, which is one sequence covered thoroughly and everything else not
at all. Sweeping seeds is the part of the Rust suites they were missing.

That second line is the one worth running, and it did not work until recently.
Several of those strategies build a value, encode it and keep only the ones
that decode inside the protocol's bounds; proptest counts every discard and
aborts at ceilings that do **not** scale with the case count. At 65536 the run
stopped with `Test aborted: Too many local rejects` after tens of thousands of
successful cases and nothing falsified — a message that reads exactly like a
failure and is not one. `decoder_config` in that file now raises the two
ceilings in step with `cases`, so the command above runs as printed.

## What a useful report looks like

Findings against the questions above, each with the file and the input that
demonstrates it. A finding we cannot reproduce is a finding we will argue with
instead of fixing, and that helps nobody.

Disagreement with a `DEC-` decision is in scope and welcome. Those are the
choices that cannot be fixed later by patching a function.
