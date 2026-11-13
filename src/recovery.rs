//! Recovery Key: 128-bit CSPRNG secret + 32-bit checksum, shown as Base32 groups
//! (`XXXX-XXXX-...`). It independently wraps the vault data key; it is never stored
//! in the vault. Because it is high-entropy, HKDF (not Argon2) derives its wrapping key.

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{fill_random, SecretKey};
use crate::error::{Error, Result};

const SECRET_LEN: usize = 16;
const CHECK_LEN: usize = 4;
const GROUP: usize = 4;
const KEK_LABEL: &[u8] = b"vault/recovery-kek/v1";

/// A user-facing Recovery Key. Zeroized on drop, redacted `Debug`, not `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; SECRET_LEN]);

impl core::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

fn checksum(secret: &[u8; SECRET_LEN]) -> [u8; CHECK_LEN] {
    let digest = Sha256::digest([b"vault/recovery-check/v1".as_slice(), secret].concat());
    let mut out = [0u8; CHECK_LEN];
    out.copy_from_slice(digest.get(..CHECK_LEN).unwrap_or(&[0; CHECK_LEN]));
    out
}

impl RecoveryKey {
    /// Generate a new random Recovery Key.
    pub fn generate() -> Result<Self> {
        let mut b = [0u8; SECRET_LEN];
        fill_random(&mut b)?;
        Ok(Self(b))
    }

    /// Human-friendly representation, e.g. `ABCD-EFGH-...` (8 groups of 4).
    pub fn to_display_string(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new(Vec::with_capacity(SECRET_LEN + CHECK_LEN));
        raw.extend_from_slice(&self.0);
        raw.extend_from_slice(&checksum(&self.0));
        let enc = Zeroizing::new(BASE32_NOPAD.encode(&raw));
        let mut out = String::with_capacity(enc.len() + enc.len() / GROUP);
        for (i, c) in enc.chars().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(c);
        }
        Zeroizing::new(out)
    }

    /// Parse user input: case-insensitive, ignores dashes and whitespace, verifies checksum.
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let raw = Zeroizing::new(
            BASE32_NOPAD
                .decode(cleaned.as_bytes())
                .map_err(|_| Error::Corrupted)?,
        );
        if raw.len() != SECRET_LEN + CHECK_LEN {
            return Err(Error::Corrupted);
        }
        let (s, c) = raw.split_at(SECRET_LEN);
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(s);
        if !bool::from(checksum(&secret).as_slice().ct_eq(c)) {
            secret.zeroize();
            return Err(Error::Corrupted);
        }
        Ok(Self(secret))
    }

    /// Derive the key that wraps the vault data key.
    pub fn derive_kek(&self) -> Result<SecretKey> {
        let mut padded = [0u8; 32];
        // Expand the 128-bit secret into a 256-bit IKM via HKDF inside `derive_subkey`.
        padded[..SECRET_LEN].copy_from_slice(&self.0);
        let ikm = SecretKey::from_bytes(padded);
        padded.zeroize();
        ikm.derive_subkey(KEK_LABEL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_parse_round_trip() {
        let k = RecoveryKey::generate().unwrap();
        let s = k.to_display_string();
        assert_eq!(s.len(), 32 + 7);
        let back = RecoveryKey::parse(&s).unwrap();
        assert_eq!(
            back.derive_kek().unwrap().expose(),
            k.derive_kek().unwrap().expose()
        );
    }

    #[test]
    fn parse_accepts_lowercase_and_spaces() {
        let k = RecoveryKey::generate().unwrap();
        let s = k.to_display_string().to_lowercase().replace('-', " ");
        assert!(RecoveryKey::parse(&s).is_ok());
    }

    #[test]
    fn checksum_rejects_every_single_character_typo() {
        let k = RecoveryKey::generate().unwrap();
        let s = k.to_display_string().to_string();
        for i in (0..s.len()).filter(|i| s.as_bytes()[*i] != b'-') {
            let mut b = s.clone().into_bytes();
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            assert!(
                RecoveryKey::parse(&String::from_utf8(b).unwrap()).is_err(),
                "pos {i}"
            );
        }
    }

    #[test]
    fn parse_rejects_wrong_length_and_garbage() {
        assert!(RecoveryKey::parse("").is_err());
        assert!(RecoveryKey::parse("AAAA-AAAA").is_err());
        assert!(RecoveryKey::parse("!!!!").is_err());
    }

    #[test]
    fn keys_are_unique_and_debug_is_redacted() {
        let a = RecoveryKey::generate().unwrap();
        let b = RecoveryKey::generate().unwrap();
        assert_ne!(a.0, b.0);
        assert_eq!(format!("{a:?}"), "RecoveryKey(<redacted>)");
    }
}
