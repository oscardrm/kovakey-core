//! Password strength estimation for stored credentials (PRD §8.1, §9.2).
//!
//! Heuristic entropy estimate: character-class pool × length, reduced for repeated runs,
//! keyboard/alphabetic sequences, very few distinct characters and well-known passwords.
//! [`Session::password_strengths`](crate::session::Session::password_strengths) additionally
//! caps the level of passwords reused across items. Nothing here logs or returns the password.

use crate::generator::{strength_from_bits, Strength};

/// Result of analysing one password.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StrengthReport {
    /// Estimated entropy in bits after penalties.
    pub bits: f64,
    /// Qualitative bucket for `bits`.
    pub level: Strength,
}

const COMMON: &[&str] = &[
    "password",
    "passw0rd",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwertyuiop",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "111111",
    "000000",
    "contraseña",
    "contrasena",
    "changeme",
    "secret",
];

const SEQUENCES: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiopasdfghjklzxcvbnm",
];

fn pool_size(pw: &str) -> f64 {
    let (mut lo, mut up, mut dg, mut sy) = (false, false, false, false);
    for c in pw.chars() {
        if c.is_ascii_lowercase() {
            lo = true;
        } else if c.is_ascii_uppercase() {
            up = true;
        } else if c.is_ascii_digit() {
            dg = true;
        } else {
            sy = true;
        }
    }
    let n = (lo as u32) * 26 + (up as u32) * 26 + (dg as u32) * 10 + (sy as u32) * 33;
    f64::from(n.max(1))
}

/// Number of characters that continue a repeat (`aaa`) or a 3+ ascending/descending sequence.
fn predictable_chars(chars: &[char]) -> usize {
    let lower: Vec<char> = chars.iter().flat_map(|c| c.to_lowercase()).collect();
    lower
        .windows(3)
        .filter(|w| {
            let repeat = matches!(w, [a, b, c] if a == b && b == c);
            let fwd: String = w.iter().collect();
            let rev: String = w.iter().rev().collect();
            repeat
                || SEQUENCES
                    .iter()
                    .any(|s| s.contains(&fwd) || s.contains(&rev))
        })
        .count()
}

/// Estimate the strength of `password`.
pub fn analyze(password: &str) -> StrengthReport {
    let chars: Vec<char> = password.chars().collect();
    if chars.is_empty() {
        return StrengthReport {
            bits: 0.0,
            level: Strength::VeryWeak,
        };
    }
    let lowered = password.to_lowercase();
    if COMMON.iter().any(|c| lowered == *c) {
        return StrengthReport {
            bits: 8.0,
            level: Strength::VeryWeak,
        };
    }
    let mut distinct = chars.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let effective_len = (chars.len() - predictable_chars(&chars)).max(1);
    let per_char = pool_size(password).log2();
    let mut bits = effective_len as f64 * per_char;
    // Few distinct characters cap the real entropy.
    bits = bits.min(distinct.len() as f64 * per_char * 1.5);
    // A common word with a trivial suffix/prefix is still weak.
    if COMMON.iter().any(|c| lowered.contains(c)) {
        bits = bits.min(30.0);
    }
    StrengthReport {
        bits,
        level: strength_from_bits(bits),
    }
}

/// One more level down, never below `VeryWeak`: applied to reused passwords.
pub fn demote(level: Strength) -> Strength {
    match level {
        Strength::VeryStrong => Strength::Strong,
        Strength::Strong => Strength::Fair,
        Strength::Fair => Strength::Weak,
        Strength::Weak | Strength::VeryWeak => Strength::VeryWeak,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_common_are_very_weak() {
        assert_eq!(analyze("").level, Strength::VeryWeak);
        assert_eq!(analyze("Password").level, Strength::VeryWeak);
        assert_eq!(analyze("password123").level, Strength::VeryWeak);
    }

    #[test]
    fn sequences_and_repeats_are_penalised() {
        assert!(analyze("abcdefgh").bits < analyze("xk3pq9wz").bits);
        assert!(analyze("aaaaaaaa").bits < 20.0);
    }

    #[test]
    fn long_random_is_strong() {
        let r = analyze("vT9#kLq2$Zw8!mXc4Rp7");
        assert!(r.bits >= 100.0, "{}", r.bits);
        assert_eq!(r.level, Strength::VeryStrong);
    }

    #[test]
    fn monotonic_in_length() {
        assert!(analyze("Tq7!kd").bits < analyze("Tq7!kdWm9@").bits);
    }

    #[test]
    fn demote_saturates() {
        assert_eq!(demote(Strength::VeryStrong), Strength::Strong);
        assert_eq!(demote(Strength::VeryWeak), Strength::VeryWeak);
    }
}
