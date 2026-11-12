//! AES-256-GCM authenticated encryption and HKDF subkey derivation.
//!
//! Wire format of a sealed blob: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
//! A fresh random 96-bit nonce is drawn from the OS CSPRNG for every encryption.
//! Context (vault id, item id, format version, purpose) is bound through AAD.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;
/// GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// A 256-bit secret key. Zeroized on drop; `Debug` is redacted; not `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Wrap raw key bytes (the input array is consumed by value; callers should zeroize copies).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random key from the OS CSPRNG.
    pub fn random() -> Result<Self> {
        let mut b = [0u8; KEY_LEN];
        fill_random(&mut b)?;
        Ok(Self(b))
    }

    /// Borrow the raw bytes. Handle with care.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive an independent 256-bit subkey via HKDF-SHA256 with a domain-separation label.
    /// `self` must already be high-entropy key material (not a password).
    pub fn derive_subkey(&self, label: &[u8]) -> Result<SecretKey> {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; KEY_LEN];
        hk.expand(label, &mut out)
            .map_err(|_| Error::InvalidParams)?;
        let key = SecretKey(out);
        out.zeroize();
        Ok(key)
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Fill `buf` with bytes from the OS CSPRNG.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Rng)
}

/// Encrypt `plaintext` under `key`, binding `aad`. Returns `nonce || ciphertext || tag`.
pub fn seal(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::InvalidParams)?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decryption)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob produced by [`seal`]. Any failure (wrong key, wrong AAD, tampering)
/// yields the same [`Error::Decryption`]; truncated input yields [`Error::Corrupted`].
pub fn open(key: &SecretKey, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Corrupted);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::InvalidParams)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SecretKey {
        SecretKey::from_bytes([b; KEY_LEN])
    }

    #[test]
    fn round_trip_returns_original_plaintext() {
        let k = key(1);
        let sealed = seal(&k, b"fake-secret", b"ctx").unwrap();
        assert_eq!(&**open(&k, &sealed, b"ctx").unwrap(), b"fake-secret");
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let sealed = seal(&key(1), b"x", b"").unwrap();
        assert_eq!(open(&key(2), &sealed, b"").unwrap_err(), Error::Decryption);
    }

    #[test]
    fn decrypt_fails_with_wrong_aad() {
        let sealed = seal(&key(1), b"x", b"a").unwrap();
        assert_eq!(open(&key(1), &sealed, b"b").unwrap_err(), Error::Decryption);
    }

    #[test]
    fn decrypt_fails_when_any_byte_is_tampered() {
        let k = key(1);
        let sealed = seal(&k, b"fake-secret", b"ctx").unwrap();
        for i in 0..sealed.len() {
            let mut t = sealed.clone();
            t[i] ^= 0x01;
            assert_eq!(
                open(&k, &t, b"ctx").unwrap_err(),
                Error::Decryption,
                "byte {i}"
            );
        }
    }

    #[test]
    fn decrypt_fails_when_truncated() {
        let k = key(1);
        let sealed = seal(&k, b"fake-secret", b"").unwrap();
        assert!(open(&k, &sealed[..NONCE_LEN + TAG_LEN - 1], b"").is_err());
        assert!(open(&k, &sealed[..sealed.len() - 1], b"").is_err());
        assert_eq!(open(&k, &[], b"").unwrap_err(), Error::Corrupted);
    }

    #[test]
    fn nonces_are_unique_across_many_encryptions() {
        let k = key(1);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            let s = seal(&k, b"x", b"").unwrap();
            assert!(seen.insert(s[..NONCE_LEN].to_vec()));
        }
    }

    // NIST GCM test case 16 (AES-256, 96-bit IV, with AAD), cross-checked against the primitive.
    #[test]
    fn aes_gcm_known_answer_vector() {
        let key_bytes = data_encoding::HEXLOWER
            .decode(b"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .unwrap();
        let iv = data_encoding::HEXLOWER
            .decode(b"cafebabefacedbaddecaf888")
            .unwrap();
        let pt = data_encoding::HEXLOWER
            .decode(b"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
            .unwrap();
        let aad = data_encoding::HEXLOWER
            .decode(b"feedfacedeadbeeffeedfacedeadbeefabaddad2")
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .unwrap();
        // Tag from NIST test case 16.
        assert_eq!(
            data_encoding::HEXLOWER.encode(&ct[ct.len() - 16..]),
            "76fc6ece0f4e1768cddf8853bb2d551b"
        );
    }

    #[test]
    fn subkeys_are_label_separated_and_deterministic() {
        let k = key(7);
        let a1 = k.derive_subkey(b"a").unwrap();
        let a2 = k.derive_subkey(b"a").unwrap();
        let b = k.derive_subkey(b"b").unwrap();
        assert_eq!(a1.expose(), a2.expose());
        assert_ne!(a1.expose(), b.expose());
    }

    #[test]
    fn debug_output_is_redacted() {
        assert!(!format!("{:?}", key(0xAB)).contains("171"));
        assert_eq!(format!("{:?}", key(1)), "SecretKey(<redacted>)");
    }
}
