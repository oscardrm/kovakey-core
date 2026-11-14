//! Opt-in Have I Been Pwned check, k-anonymity side only (ADR 0017).
//!
//! This module performs **no network I/O**. The platform sends `GET /range/<prefix>` with the value
//! from [`prefix`] and passes the response body to [`match_count`]. The full SHA-1 and its suffix
//! never leave the core.

use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const PREFIX_LEN: usize = 5;

fn nibble(n: u8) -> char {
    char::from_digit(u32::from(n), 16).map_or('0', |c| c.to_ascii_uppercase())
}

/// Uppercase hex SHA-1 of the password (40 chars), zeroized on drop.
fn sha1_hex(password: &str) -> Zeroizing<String> {
    let mut raw = Sha1::digest(password.as_bytes());
    let mut digest = Zeroizing::new([0u8; 20]);
    digest.copy_from_slice(&raw);
    raw.iter_mut().for_each(|b| *b = 0);
    let mut out = Zeroizing::new(String::with_capacity(40));
    for b in digest.iter() {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

/// The 5-char uppercase SHA-1 prefix to send to the range API. Empty passwords are rejected.
pub fn prefix(password: &str) -> Result<String> {
    if password.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(sha1_hex(password).chars().take(PREFIX_LEN).collect())
}

/// Number of times `password` appears in a range response body (`SUFFIX:COUNT` lines).
///
/// Returns `0` when absent. Padding entries (count `0`) therefore never count as a match.
/// Malformed lines are skipped; a body with no parseable line is still a valid "not found".
pub fn match_count(password: &str, response_body: &str) -> Result<u64> {
    if password.is_empty() {
        return Err(Error::InvalidInput);
    }
    let hash = sha1_hex(password);
    let suffix = hash
        .get(PREFIX_LEN..)
        .ok_or(Error::InvalidInput)?
        .as_bytes();
    let mut found = 0u64;
    for line in response_body.lines() {
        let Some((candidate, count)) = line.trim().split_once(':') else {
            continue;
        };
        let candidate = candidate.trim().as_bytes();
        // Constant-time compare; lengths are public.
        if candidate.len() == suffix.len()
            && bool::from(candidate.to_ascii_uppercase().ct_eq(suffix))
        {
            found = count.trim().parse::<u64>().unwrap_or(0);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    #[test]
    fn prefix_known_answer() {
        assert_eq!(prefix("password").unwrap(), "5BAA6");
        assert_eq!(prefix("abc").unwrap(), "A9993"); // A9993E36...
    }

    #[test]
    fn empty_password_rejected() {
        assert!(prefix("").is_err());
        assert!(match_count("", "").is_err());
    }

    #[test]
    fn finds_suffix_and_count() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n\
                    011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n";
        assert_eq!(match_count("password", body).unwrap(), 9_545_824);
    }

    #[test]
    fn case_insensitive_suffix() {
        let body = "1e4c9b93f3f0682250b6cf8331b7ee68fd8:42";
        assert_eq!(match_count("password", body).unwrap(), 42);
    }

    #[test]
    fn absent_padding_and_garbage_are_zero() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\nnot-a-line\n\n:\n";
        assert_eq!(match_count("password", body).unwrap(), 0);
        // padding entry for our own suffix has count 0
        let padded = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:0";
        assert_eq!(match_count("password", padded).unwrap(), 0);
    }

    #[test]
    fn partial_suffix_does_not_match() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD:5";
        assert_eq!(match_count("password", body).unwrap(), 0);
    }
}
