//! Password and passphrase generator.
//!
//! All randomness comes from the OS CSPRNG. Selection uses rejection sampling
//! ([`uniform_below`]) so there is no modulo bias.

use zeroize::Zeroizing;

use crate::crypto::fill_random;
use crate::error::{Error, Result};

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*";
const SPECIAL: &str = "()-_=+[]{};:,.<>/?~";
const AMBIGUOUS: &str = "0Oo1lI|";
const WORDLIST: &str = include_str!("wordlist.txt");

/// Minimum / maximum supported password length.
pub const MIN_LEN: usize = 4;
/// Maximum supported password length.
pub const MAX_LEN: usize = 128;
/// Maximum passphrase word count.
pub const MAX_WORDS: usize = 20;

/// Password generation options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    /// Number of characters (4..=128).
    pub length: usize,
    /// Include `A-Z`.
    pub uppercase: bool,
    /// Include `a-z`.
    pub lowercase: bool,
    /// Include `0-9`.
    pub numbers: bool,
    /// Include `!@#$%^&*`.
    pub symbols: bool,
    /// Include `()-_=+[]{};:,.<>/?~`.
    pub special: bool,
    /// Drop look-alike characters (`0 O o 1 l I |`).
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            special: false,
            exclude_ambiguous: false,
        }
    }
}

/// Passphrase options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// Number of words (1..=20).
    pub words: usize,
    /// Separator between words.
    pub separator: String,
    /// Capitalize the first letter of each word.
    pub capitalize: bool,
    /// Append a random digit to one random word.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Qualitative strength bucket derived from entropy bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    /// < 40 bits.
    VeryWeak,
    /// 40..60 bits.
    Weak,
    /// 60..80 bits.
    Fair,
    /// 80..100 bits.
    Strong,
    /// >= 100 bits.
    VeryStrong,
}

/// Map entropy bits to a [`Strength`] bucket.
pub fn strength_from_bits(bits: f64) -> Strength {
    match bits {
        b if b < 40.0 => Strength::VeryWeak,
        b if b < 60.0 => Strength::Weak,
        b if b < 80.0 => Strength::Fair,
        b if b < 100.0 => Strength::Strong,
        _ => Strength::VeryStrong,
    }
}

/// Uniform random integer in `0..n` using rejection sampling (no modulo bias).
pub fn uniform_below(n: usize) -> Result<usize> {
    if n == 0 {
        return Err(Error::InvalidParams);
    }
    let n = n as u64;
    // Largest multiple of n that fits in u64; values at or above it are rejected.
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let mut b = [0u8; 8];
        fill_random(&mut b)?;
        let v = u64::from_le_bytes(b);
        if v < zone {
            return Ok((v % n) as usize);
        }
    }
}

fn pick(chars: &[char]) -> Result<char> {
    let i = uniform_below(chars.len())?;
    chars.get(i).copied().ok_or(Error::InvalidParams)
}

/// Character classes enabled by `opts`, with ambiguous characters removed if requested.
fn classes(opts: &PasswordOptions) -> Vec<Vec<char>> {
    [
        (opts.uppercase, UPPER),
        (opts.lowercase, LOWER),
        (opts.numbers, DIGITS),
        (opts.symbols, SYMBOLS),
        (opts.special, SPECIAL),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, set)| {
        set.chars()
            .filter(|c| !(opts.exclude_ambiguous && AMBIGUOUS.contains(*c)))
            .collect::<Vec<_>>()
    })
    .filter(|v| !v.is_empty())
    .collect()
}

/// Size of the character pool for `opts`.
pub fn pool_size(opts: &PasswordOptions) -> usize {
    classes(opts).iter().map(Vec::len).sum()
}

/// Entropy in bits of a password drawn uniformly from the pool (`length * log2(pool)`).
/// The "at least one of each class" guarantee lowers the true value very slightly.
pub fn password_entropy_bits(opts: &PasswordOptions) -> f64 {
    let pool = pool_size(opts);
    if pool < 2 {
        return 0.0;
    }
    opts.length as f64 * (pool as f64).log2()
}

/// Generate a password. Guarantees at least one character from every enabled class.
pub fn generate_password(opts: &PasswordOptions) -> Result<Zeroizing<String>> {
    if !(MIN_LEN..=MAX_LEN).contains(&opts.length) {
        return Err(Error::InvalidParams);
    }
    let classes = classes(opts);
    if classes.is_empty() || classes.len() > opts.length {
        return Err(Error::InvalidParams);
    }
    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    let mut out: Vec<char> = Vec::with_capacity(opts.length);
    for class in &classes {
        out.push(pick(class)?);
    }
    while out.len() < opts.length {
        out.push(pick(&pool)?);
    }
    // Fisher-Yates shuffle so the guaranteed characters are not positionally predictable.
    for i in (1..out.len()).rev() {
        out.swap(i, uniform_below(i + 1)?);
    }
    let s: String = out.iter().collect();
    out.iter_mut().for_each(|c| *c = '\0');
    Ok(Zeroizing::new(s))
}

fn words() -> Vec<&'static str> {
    WORDLIST.lines().filter(|l| !l.is_empty()).collect()
}

/// Entropy in bits of a passphrase: `words * log2(wordlist_size)` (+ number placement).
pub fn passphrase_entropy_bits(opts: &PassphraseOptions) -> f64 {
    let n = words().len();
    let mut bits = opts.words as f64 * (n as f64).log2();
    if opts.include_number && opts.words > 0 {
        bits += (10.0 * opts.words as f64).log2();
    }
    bits
}

/// Generate a passphrase from the 7776-word EFF large list.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if opts.words == 0 || opts.words > MAX_WORDS {
        return Err(Error::InvalidParams);
    }
    let list = words();
    let mut parts: Vec<String> = Vec::with_capacity(opts.words);
    for _ in 0..opts.words {
        let w = list
            .get(uniform_below(list.len())?)
            .copied()
            .ok_or(Error::InvalidParams)?;
        let mut w = w.to_string();
        if opts.capitalize {
            if let Some(first) = w.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
        }
        parts.push(w);
    }
    if opts.include_number {
        let idx = uniform_below(parts.len())?;
        let digit = uniform_below(10)?;
        if let Some(p) = parts.get_mut(idx) {
            p.push_str(&digit.to_string());
        }
    }
    Ok(Zeroizing::new(parts.join(&opts.separator)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(len: usize) -> PasswordOptions {
        PasswordOptions {
            length: len,
            ..Default::default()
        }
    }

    #[test]
    fn length_is_honored_across_range() {
        for len in [MIN_LEN, 8, 20, 64, MAX_LEN] {
            assert_eq!(generate_password(&opts(len)).unwrap().chars().count(), len);
        }
    }

    #[test]
    fn rejects_out_of_range_length_and_empty_pool() {
        assert!(generate_password(&opts(MIN_LEN - 1)).is_err());
        assert!(generate_password(&opts(MAX_LEN + 1)).is_err());
        let none = PasswordOptions {
            uppercase: false,
            lowercase: false,
            numbers: false,
            symbols: false,
            special: false,
            ..Default::default()
        };
        assert!(generate_password(&none).is_err());
    }

    #[test]
    fn every_enabled_class_is_present_even_at_min_length() {
        let o = PasswordOptions {
            length: 5,
            special: true,
            ..Default::default()
        };
        for _ in 0..300 {
            let p = generate_password(&o).unwrap();
            assert!(p.chars().any(|c| UPPER.contains(c)));
            assert!(p.chars().any(|c| LOWER.contains(c)));
            assert!(p.chars().any(|c| DIGITS.contains(c)));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
            assert!(p.chars().any(|c| SPECIAL.contains(c)));
        }
    }

    #[test]
    fn disabled_classes_never_appear() {
        let o = PasswordOptions {
            uppercase: false,
            symbols: false,
            special: false,
            length: 64,
            ..Default::default()
        };
        for _ in 0..50 {
            let p = generate_password(&o).unwrap();
            assert!(p.chars().all(|c| LOWER.contains(c) || DIGITS.contains(c)));
        }
    }

    #[test]
    fn ambiguous_characters_are_excluded_when_requested() {
        let o = PasswordOptions {
            exclude_ambiguous: true,
            special: true,
            length: 128,
            ..Default::default()
        };
        for _ in 0..100 {
            assert!(!generate_password(&o)
                .unwrap()
                .chars()
                .any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn entropy_bits_match_pool_math() {
        let o = PasswordOptions {
            length: 10,
            uppercase: false,
            lowercase: false,
            symbols: false,
            special: false,
            numbers: true,
            exclude_ambiguous: false,
        };
        assert!((password_entropy_bits(&o) - 10.0 * 10f64.log2()).abs() < 1e-9);
        assert_eq!(pool_size(&o), 10);
    }

    #[test]
    fn strength_buckets() {
        assert_eq!(strength_from_bits(10.0), Strength::VeryWeak);
        assert_eq!(strength_from_bits(50.0), Strength::Weak);
        assert_eq!(strength_from_bits(70.0), Strength::Fair);
        assert_eq!(strength_from_bits(90.0), Strength::Strong);
        assert_eq!(strength_from_bits(128.0), Strength::VeryStrong);
    }

    #[test]
    fn uniform_below_has_no_obvious_bias() {
        // Statistical sanity: 6 buckets, 60k draws, each within 10% of expectation.
        let mut counts = [0usize; 6];
        for _ in 0..60_000 {
            counts[uniform_below(6).unwrap()] += 1;
        }
        for c in counts {
            assert!((9_000..=11_000).contains(&c), "bucket count {c}");
        }
        assert!(uniform_below(0).is_err());
        assert_eq!(uniform_below(1).unwrap(), 0);
    }

    #[test]
    fn passphrase_has_requested_word_count_and_separator() {
        let o = PassphraseOptions {
            words: 5,
            separator: ".".into(),
            ..Default::default()
        };
        let p = generate_passphrase(&o).unwrap();
        assert_eq!(p.split('.').count(), 5);
        assert!(generate_passphrase(&PassphraseOptions {
            words: 0,
            ..o.clone()
        })
        .is_err());
        assert!(generate_passphrase(&PassphraseOptions {
            words: MAX_WORDS + 1,
            ..o
        })
        .is_err());
    }

    #[test]
    fn passphrase_options_capitalize_and_number() {
        let o = PassphraseOptions {
            words: 4,
            capitalize: true,
            include_number: true,
            ..Default::default()
        };
        let p = generate_passphrase(&o).unwrap();
        assert!(p
            .split('-')
            .all(|w| w.chars().next().is_some_and(char::is_uppercase)));
        assert_eq!(p.chars().filter(char::is_ascii_digit).count(), 1);
    }

    #[test]
    fn wordlist_is_the_7776_word_eff_list() {
        assert_eq!(words().len(), 7776);
        let bits = passphrase_entropy_bits(&PassphraseOptions {
            words: 6,
            ..Default::default()
        });
        assert!((bits - 77.55).abs() < 0.01);
    }
}
