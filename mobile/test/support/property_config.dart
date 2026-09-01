/// How hard the hand-rolled property suites try, and from where.
///
/// The Rust property suites take their case count from `PROPTEST_CASES`, and
/// proptest draws a fresh seed on every run. `docs/review-brief.md` builds on
/// that: it tells a reviewer the suites "take their case count from the
/// environment, so a reviewer can turn them up far past what CI runs and see
/// whether anything falls out", and then lists `cd mobile && flutter test`
/// among the commands.
///
/// These suites could not be turned up at all. Same seed, same number of
/// rounds, every run since they were written — so they cover exactly one
/// sequence of inputs, thoroughly, and everything else not at all.
///
/// The defaults are what CI runs and what those files used before, so nothing
/// about an ordinary `flutter test` changes. The environment can raise either.
library;

import 'dart:io';
import 'dart:math';

/// The seed, so a sweep can walk many of them.
///
/// Still fixed by default. A property test that fails only sometimes is a
/// property test nobody trusts, and a counterexample has to be reproducible
/// from what the failure prints — which is why a sweep names its seed rather
/// than drawing one.
Random propertyRandom(int fallback) =>
    Random(_environmentInt('PROPERTY_SEED') ?? fallback);

/// How many rounds one property runs.
int propertyRounds(int fallback) =>
    _environmentInt('PROPERTY_ROUNDS') ?? fallback;

/// A positive integer from the environment, or null.
///
/// Anything else is ignored rather than raised: a typo in a variable must not
/// turn a green suite into a failure that looks like a bug in the code.
int? _environmentInt(String name) {
  final raw = Platform.environment[name];
  if (raw == null) return null;
  final value = int.tryParse(raw.trim());
  return value != null && value > 0 ? value : null;
}
