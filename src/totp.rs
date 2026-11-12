//! RFC 6238 TOTP (HMAC-SHA1/256/512) with Base32 secrets and `otpauth://` URI parsing.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// HMAC hash used for code generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC-SHA1 (default for most services).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

/// TOTP configuration. The secret is zeroized on drop and never printed by `Debug`.
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    /// Hash algorithm.
    pub algorithm: Algorithm,
    /// Number of digits (6..=8).
    pub digits: u32,
    /// Time step in seconds.
    pub period: u64,
}

impl core::fmt::Debug for Totp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Totp(<redacted>)")
    }
}

fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut m = <M as Mac>::new_from_slice(key).map_err(|_| Error::InvalidParams)?;
    m.update(msg);
    Ok(m.finalize().into_bytes().to_vec())
}

impl Totp {
    /// Build from a Base32 secret (spaces/dashes/case/padding tolerated).
    pub fn from_base32(
        secret: &str,
        algorithm: Algorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self> {
        if !(6..=8).contains(&digits) || period == 0 {
            return Err(Error::InvalidParams);
        }
        let cleaned: Zeroizing<String> = Zeroizing::new(
            secret
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let bytes = data_encoding::BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| Error::Corrupted)?;
        if bytes.is_empty() {
            return Err(Error::Corrupted);
        }
        Ok(Self {
            secret: Zeroizing::new(bytes),
            algorithm,
            digits,
            period,
        })
    }

    /// Parse an `otpauth://totp/...?secret=...&algorithm=&digits=&period=` URI (QR payload).
    pub fn from_uri(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("otpauth://totp/")
            .ok_or(Error::Corrupted)?;
        let query = rest
            .split_once('?')
            .map(|(_, q)| q)
            .ok_or(Error::Corrupted)?;
        let (mut secret, mut algo, mut digits, mut period) = (None, Algorithm::Sha1, 6u32, 30u64);
        for pair in query.split('&') {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            match k {
                "secret" => secret = Some(v),
                "algorithm" => {
                    algo = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(Error::InvalidParams),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| Error::InvalidParams)?,
                "period" => period = v.parse().map_err(|_| Error::InvalidParams)?,
                _ => {}
            }
        }
        Self::from_base32(secret.ok_or(Error::Corrupted)?, algo, digits, period)
    }

    /// Code for the given Unix time (seconds), zero-padded to `digits`.
    pub fn code_at(&self, unix_secs: u64) -> Result<String> {
        let counter = (unix_secs / self.period).to_be_bytes();
        let h = match self.algorithm {
            Algorithm::Sha1 => mac::<Hmac<Sha1>>(&self.secret, &counter)?,
            Algorithm::Sha256 => mac::<Hmac<Sha256>>(&self.secret, &counter)?,
            Algorithm::Sha512 => mac::<Hmac<Sha512>>(&self.secret, &counter)?,
        };
        let offset = (h.last().copied().ok_or(Error::Corrupted)? & 0x0f) as usize;
        let chunk: [u8; 4] = h
            .get(offset..offset + 4)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Corrupted)?;
        let bin = u32::from_be_bytes(chunk) & 0x7fff_ffff;
        let code = bin % 10u32.pow(self.digits);
        Ok(format!("{code:0width$}", width = self.digits as usize))
    }

    /// Seconds remaining until the current code expires.
    pub fn seconds_remaining(&self, unix_secs: u64) -> u64 {
        self.period - (unix_secs % self.period)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B secrets (ASCII "1234567890..." repeated), Base32-encoded.
    fn b32(ascii: &[u8]) -> String {
        data_encoding::BASE32_NOPAD.encode(ascii)
    }

    #[test]
    fn rfc6238_vectors_for_all_algorithms() {
        let cases: [(Algorithm, &[u8], u64, &str); 9] = [
            (Algorithm::Sha1, b"12345678901234567890", 59, "94287082"),
            (
                Algorithm::Sha1,
                b"12345678901234567890",
                1111111109,
                "07081804",
            ),
            (
                Algorithm::Sha1,
                b"12345678901234567890",
                20000000000,
                "65353130",
            ),
            (
                Algorithm::Sha256,
                b"12345678901234567890123456789012",
                59,
                "46119246",
            ),
            (
                Algorithm::Sha256,
                b"12345678901234567890123456789012",
                1111111109,
                "68084774",
            ),
            (
                Algorithm::Sha256,
                b"12345678901234567890123456789012",
                20000000000,
                "77737706",
            ),
            (
                Algorithm::Sha512,
                b"1234567890123456789012345678901234567890123456789012345678901234",
                59,
                "90693936",
            ),
            (
                Algorithm::Sha512,
                b"1234567890123456789012345678901234567890123456789012345678901234",
                1111111109,
                "25091201",
            ),
            (
                Algorithm::Sha512,
                b"1234567890123456789012345678901234567890123456789012345678901234",
                20000000000,
                "47863826",
            ),
        ];
        for (algo, secret, t, expected) in cases {
            let totp = Totp::from_base32(&b32(secret), algo, 8, 30).unwrap();
            assert_eq!(totp.code_at(t).unwrap(), expected, "{algo:?} t={t}");
        }
    }

    #[test]
    fn six_digit_codes_are_zero_padded() {
        let t = Totp::from_base32(&b32(b"12345678901234567890"), Algorithm::Sha1, 6, 30).unwrap();
        assert_eq!(t.code_at(59).unwrap(), "287082");
        assert_eq!(t.code_at(59).unwrap().len(), 6);
    }

    #[test]
    fn uri_parsing_reads_parameters() {
        let uri = format!(
            "otpauth://totp/Fake:me?secret={}&algorithm=SHA256&digits=8&period=60&issuer=Fake",
            b32(b"12345678901234567890123456789012")
        );
        let t = Totp::from_uri(&uri).unwrap();
        assert_eq!(
            (t.algorithm, t.digits, t.period),
            (Algorithm::Sha256, 8, 60)
        );
        assert!(Totp::from_uri("https://example.com").is_err());
        assert!(Totp::from_uri("otpauth://totp/x?issuer=y").is_err());
    }

    #[test]
    fn secret_formatting_is_tolerated_and_invalid_rejected() {
        let a = Totp::from_base32("gezd gnbv-gy3t qojq", Algorithm::Sha1, 6, 30).unwrap();
        let b = Totp::from_base32("GEZDGNBVGY3TQOJQ", Algorithm::Sha1, 6, 30).unwrap();
        assert_eq!(a.code_at(100).unwrap(), b.code_at(100).unwrap());
        assert!(Totp::from_base32("!!!", Algorithm::Sha1, 6, 30).is_err());
        assert!(Totp::from_base32("GEZDGNBV", Algorithm::Sha1, 5, 30).is_err());
        assert!(Totp::from_base32("GEZDGNBV", Algorithm::Sha1, 6, 0).is_err());
    }

    #[test]
    fn remaining_seconds_and_redacted_debug() {
        let t = Totp::from_base32("GEZDGNBVGY3TQOJQ", Algorithm::Sha1, 6, 30).unwrap();
        assert_eq!(t.seconds_remaining(59), 1);
        assert_eq!(t.seconds_remaining(60), 30);
        assert_eq!(format!("{t:?}"), "Totp(<redacted>)");
    }
}
