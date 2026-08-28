# Security policy

## Supported versions

BioAuth is pre-1.0. Security fixes are provided only for the latest published
release. Older releases and builds from arbitrary commits are unsupported.

## Report a vulnerability

Do not open a public issue with exploit details, credentials, logs, QR codes,
or pairing material. Use GitHub's private vulnerability reporting form:

<https://github.com/Gaok1/BioAuth/security/advisories/new>

If that form is unavailable, open a public issue containing only a request for
private contact. Do not include vulnerability details in that issue.

Include the affected version and platform, impact, reproduction steps, and the
smallest non-secret proof of concept. Remove keys, signatures, challenges,
passwords, file contents, and personal data from every attachment.

The project will acknowledge a report within 7 days, coordinate validation and
a fix privately, and publish an advisory after a release is available. Please
allow 90 days for remediation before public disclosure unless active
exploitation or another urgent risk requires a shorter coordinated timeline.

## Scope

Reports about protocol authentication, Android Keystore use, native messaging,
IPC authorization, pairing, passkey origin/RP validation, release signing, and
secret leakage are in scope. Findings that require the development simulator,
a deliberately debug-signed build, or a device already fully controlled by the
attacker may be closed as out of scope unless they cross a documented boundary.

The current product limitations and incomplete security work are tracked in
[`docs/implementation-tracker.md`](docs/implementation-tracker.md). Reporting a
listed missing feature is not a vulnerability, but a way to bypass an existing
fail-closed behavior is.

## Handling policy

- No production secret or user data belongs in an issue, log, fixture, or crash
  report.
- Security fixes receive a CVE/advisory when appropriate and are released
  before technical details are made public.
- Reporter credit is offered unless anonymity is requested.

