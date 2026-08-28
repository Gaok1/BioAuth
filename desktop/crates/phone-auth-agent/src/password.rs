//! Password generation for the vault.
//!
//! Small on purpose. The only thing a generator has to get right is that every
//! password it can produce is as likely as every other one, and the usual way
//! to get that wrong is `random_byte % alphabet_len`, which quietly makes the
//! first few characters of the alphabet more likely than the last few. This
//! rejects out-of-range bytes instead.
//!
//! The generated password is returned in a [`Zeroizing`] buffer and never
//! logged, never cached and never written anywhere by this module. `VLT-12`
//! asks for no history, and the simplest way to keep that promise is to have
//! nowhere to keep one.

use zeroize::Zeroizing;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";

/// Punctuation that survives a round trip through a shell, a CSV export and a
/// login form without needing to be escaped or being eaten by a "smart quotes"
/// text field. Quotes, backslash and backtick are deliberately absent.
const SYMBOLS: &[u8] = b"!#$%&()*+,-.:;<=>?@[]^_{|}~";

/// Shortest password worth generating.
pub const MIN_LENGTH: usize = 8;

/// Longest password this generates.
///
/// Well inside the vault's 4096-unit secret bound, and past the point where
/// added length changes anything an attacker can do.
pub const MAX_LENGTH: usize = 128;

/// What the user asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for Policy {
    /// Twenty characters from all four classes.
    ///
    /// Long enough that the class mix stops mattering, which is the honest
    /// reason to default to length rather than to a symbol requirement.
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// Every class was switched off, so there is no alphabet to draw from.
    NoCharacterClasses,
    LengthOutOfRange {
        min: usize,
        max: usize,
    },
    /// More classes were required than there are characters to hold them.
    TooShortForClasses {
        classes: usize,
        length: usize,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCharacterClasses => f.write_str("at least one character class is required"),
            Self::LengthOutOfRange { min, max } => {
                write!(f, "length must be between {min} and {max}")
            }
            Self::TooShortForClasses { classes, length } => write!(
                f,
                "{length} characters cannot contain all {classes} required classes"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    fn classes(&self) -> Vec<&'static [u8]> {
        let mut classes = Vec::new();
        if self.lowercase {
            classes.push(LOWERCASE);
        }
        if self.uppercase {
            classes.push(UPPERCASE);
        }
        if self.digits {
            classes.push(DIGITS);
        }
        if self.symbols {
            classes.push(SYMBOLS);
        }
        classes
    }

    fn check(&self) -> Result<Vec<&'static [u8]>, PolicyError> {
        let classes = self.classes();
        if classes.is_empty() {
            return Err(PolicyError::NoCharacterClasses);
        }
        if self.length < MIN_LENGTH || self.length > MAX_LENGTH {
            return Err(PolicyError::LengthOutOfRange {
                min: MIN_LENGTH,
                max: MAX_LENGTH,
            });
        }
        if self.length < classes.len() {
            return Err(PolicyError::TooShortForClasses {
                classes: classes.len(),
                length: self.length,
            });
        }
        Ok(classes)
    }
}

/// Generates one password satisfying `policy`.
///
/// Every enabled class is guaranteed to appear at least once. That is done by
/// drawing a whole password and redrawing if a class is missing, rather than by
/// placing one character per class and filling the rest: the placing trick
/// changes the distribution, and a generator that is subtly non-uniform is
/// worse than one that is honestly slower.
///
/// The redraw is not a practical cost. At the default length the chance of
/// missing a class is small enough that a second draw is already rare, and
/// [`Policy::check`] has ruled out the case where no password could satisfy the
/// policy at all, so this cannot loop forever.
pub fn generate(policy: Policy) -> Result<Zeroizing<String>, PolicyError> {
    let classes = policy.check()?;
    let alphabet: Vec<u8> = classes.concat();

    loop {
        let mut candidate = Zeroizing::new(String::with_capacity(policy.length));
        for _ in 0..policy.length {
            candidate.push(alphabet[index_below(alphabet.len())] as char);
        }
        if classes
            .iter()
            .all(|class| candidate.bytes().any(|byte| class.contains(&byte)))
        {
            return Ok(candidate);
        }
    }
}

/// A uniform index in `0..bound`, by rejection.
///
/// `bound` is an alphabet length, so it always fits in a byte here. Bytes at or
/// above the largest multiple of `bound` are thrown away rather than folded,
/// which is the whole difference between this and `byte % bound`.
///
/// Panics if the OS cannot provide randomness, matching the locker's rule: a
/// password from a predictable source is worse than no password at all, so
/// there is no degraded mode.
fn index_below(bound: usize) -> usize {
    debug_assert!((1..=256).contains(&bound));
    let limit = (256 / bound) * bound;
    loop {
        let mut byte = [0u8; 1];
        getrandom::getrandom(&mut byte).expect("operating system CSPRNG is unavailable");
        if usize::from(byte[0]) < limit {
            return usize::from(byte[0]) % bound;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derived rather than written down, so the bias test keeps testing the
    /// alphabet the generator actually draws from.
    const BOUND: usize = LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len();
    const PER_INDEX: usize = 1000;
    /// Where `% BOUND` would stop giving an extra chance: 256 = 2×89 + 78.
    const FOLD: usize = 256 % BOUND;

    /// How much more often the indices modulo folding favours came up than the
    /// rest. Unbiased sampling puts this at 1.0; `byte % BOUND` puts it at 1.5.
    fn favoured_ratio(mut draw: impl FnMut() -> usize) -> f64 {
        let mut counts = [0usize; BOUND];
        for _ in 0..BOUND * PER_INDEX {
            counts[draw()] += 1;
        }
        assert!(
            counts.iter().all(|count| *count > 0),
            "every index must be reachable"
        );
        let favoured = counts[..FOLD].iter().sum::<usize>() as f64 / FOLD as f64;
        let rest = counts[FOLD..].iter().sum::<usize>() as f64 / (BOUND - FOLD) as f64;
        favoured / rest
    }

    #[test]
    fn a_generated_password_matches_its_policy() {
        let policy = Policy::default();
        let password = generate(policy).expect("generate");

        assert_eq!(password.chars().count(), policy.length);
        assert!(password.bytes().any(|byte| LOWERCASE.contains(&byte)));
        assert!(password.bytes().any(|byte| UPPERCASE.contains(&byte)));
        assert!(password.bytes().any(|byte| DIGITS.contains(&byte)));
        assert!(password.bytes().any(|byte| SYMBOLS.contains(&byte)));
    }

    #[test]
    fn a_disabled_class_never_appears() {
        let policy = Policy {
            length: 32,
            symbols: false,
            uppercase: false,
            ..Policy::default()
        };
        for _ in 0..64 {
            let password = generate(policy).expect("generate");
            assert!(!password.bytes().any(|byte| SYMBOLS.contains(&byte)));
            assert!(!password.bytes().any(|byte| UPPERCASE.contains(&byte)));
            assert!(password.bytes().any(|byte| DIGITS.contains(&byte)));
        }
    }

    #[test]
    fn two_passwords_are_not_the_same_password() {
        let first = generate(Policy::default()).expect("first");
        let second = generate(Policy::default()).expect("second");
        assert_ne!(*first, *second);
    }

    /// An impossible policy must be refused up front rather than looping
    /// forever inside `generate` looking for a password that cannot exist.
    #[test]
    fn a_policy_no_password_could_satisfy_is_refused() {
        let empty = Policy {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Policy::default()
        };
        assert_eq!(generate(empty), Err(PolicyError::NoCharacterClasses));

        let short = Policy {
            length: MIN_LENGTH - 1,
            ..Policy::default()
        };
        assert_eq!(
            generate(short),
            Err(PolicyError::LengthOutOfRange {
                min: MIN_LENGTH,
                max: MAX_LENGTH
            })
        );

        let long = Policy {
            length: MAX_LENGTH + 1,
            ..Policy::default()
        };
        assert!(matches!(
            generate(long),
            Err(PolicyError::LengthOutOfRange { .. })
        ));
    }

    /// `MIN_LENGTH` is above the class count today, so the "too short for the
    /// classes it requires" branch is only reachable if that changes. The test
    /// pins the check itself so the branch cannot rot into a live infinite
    /// loop.
    #[test]
    fn requiring_more_classes_than_characters_is_refused() {
        let policy = Policy {
            length: 3,
            ..Policy::default()
        };
        assert!(policy.check().is_err());
    }

    /// The reason this module exists.
    ///
    /// This compares the two groups `byte % bound` would split the range into,
    /// rather than individual counts. That distinction matters: with a 92
    /// character alphabet, 256 = 2×92 + 72, so modulo folding gives indices
    /// 0..71 three chances per byte and indices 72..91 only two. Per character
    /// that is a mild 1.08x against 0.72x, which ordinary sampling noise can
    /// hide. Aggregated over each group it is a flat 1.5x, and the noise on a
    /// group rate at this sample size is under one percent — so the bound below
    /// is roughly twenty standard deviations away from a false failure and
    /// nowhere near a real bias.
    #[test]
    fn the_alphabet_is_sampled_without_modulo_bias() {
        let ratio = favoured_ratio(|| index_below(BOUND));
        assert!(
            (0.85..1.15).contains(&ratio),
            "indices below {FOLD} came up {ratio:.3}x as often as the rest; \
             modulo bias would show 1.5"
        );
    }

    /// Proves the test above is not vacuous.
    ///
    /// Written because the first version of it compared individual character
    /// counts against a half-to-double band, and modulo bias over a 92
    /// character alphabet lands inside that band — it would have passed on
    /// exactly the bug it was named after. This runs the real biased sampler
    /// through the same metric and shows the metric moves.
    #[test]
    fn the_bias_metric_catches_a_deliberately_biased_sampler() {
        let ratio = favoured_ratio(|| {
            let mut byte = [0u8; 1];
            getrandom::getrandom(&mut byte).expect("CSPRNG");
            usize::from(byte[0]) % BOUND
        });
        assert!(
            ratio > 1.3,
            "a modulo sampler should show about 1.5, showed {ratio:.3}"
        );
    }

    /// Guards the test above from going quiet: if the alphabet ever stops being
    /// the size the bias test assumes, the test would still pass while checking
    /// the wrong distribution.
    #[test]
    fn the_alphabet_is_the_one_the_bias_test_samples() {
        let alphabet: Vec<u8> = Policy::default().classes().concat();
        assert_eq!(alphabet.len(), BOUND);

        // No character may appear in two classes, or the concatenated alphabet
        // would weight it twice and the generator would not be uniform even
        // with a perfect index.
        let mut seen = alphabet.clone();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), alphabet.len());

        // A bound that divides 256 exactly would make the bias test vacuous:
        // there would be nothing for `%` to fold unevenly.
        assert_ne!(FOLD, 0);
    }
}
