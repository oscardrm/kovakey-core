//! Content-addressed, separately encrypted side blobs for large note images (ADR 0001).

use data_encoding::HEXLOWER;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{Error, Result};
use crate::keys::VaultKeys;

type HmacSha256 = Hmac<Sha256>;

/// Images strictly larger than this many bytes are stored as side blobs.
pub const SIDE_BLOB_THRESHOLD: usize = 64 * 1024;

const MAGIC: &[u8; 4] = b"TVSB";
/// Side blob format version (bound into the AAD).
const BLOB_VERSION: u8 = 1;
const SEAL_LABEL: &[u8] = b"truevault/side-blob/v1";
const NAME_LABEL: &[u8] = b"truevault/side-blob-name/v1";
const HASH_LEN: usize = 32;

/// An encrypted side blob and its storage name.
///
/// Identity is the plaintext SHA-256 (content addressing, so identical images are stored once),
/// but the *storage name* is an HMAC of that hash under a vault-derived key. The provider thus
/// cannot confirm that a known file is in the vault by hashing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SideBlob {
    /// Storage name (64 lowercase hex chars), deterministic per vault + content.
    pub name: String,
    /// `nonce || ciphertext || tag`.
    pub sealed: Vec<u8>,
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(data))
}

/// Whether an image of `len` bytes goes to a side blob (strictly above the threshold).
pub fn is_external(len: usize) -> bool {
    len > SIDE_BLOB_THRESHOLD
}

fn parse_hash(hex: &str) -> Result<[u8; HASH_LEN]> {
    HEXLOWER
        .decode(hex.as_bytes())
        .map_err(|_| Error::Corrupted)?
        .try_into()
        .map_err(|_| Error::Corrupted)
}

/// Storage name for content with the given plaintext SHA-256.
pub fn blob_name(keys: &VaultKeys, sha256_hex: &str) -> Result<String> {
    let hash = parse_hash(sha256_hex)?;
    let name_key = keys.data_key().derive_subkey(NAME_LABEL)?;
    let mut mac =
        HmacSha256::new_from_slice(name_key.expose()).map_err(|_| Error::InvalidParams)?;
    mac.update(&hash);
    Ok(HEXLOWER.encode(&mac.finalize().into_bytes()))
}

fn aad(vault_id: &[u8; 16], hash: &[u8; HASH_LEN]) -> Vec<u8> {
    [MAGIC.as_slice(), &[BLOB_VERSION], vault_id, hash].concat()
}

/// Encrypt `data` as a side blob for `vault_id`. The AAD binds the format version, the vault id
/// and the plaintext hash, so a blob cannot be moved to another vault or served for another hash.
pub fn seal_side_blob(keys: &VaultKeys, vault_id: &[u8; 16], data: &[u8]) -> Result<SideBlob> {
    let hex = sha256_hex(data);
    let hash = parse_hash(&hex)?;
    let key = keys.data_key().derive_subkey(SEAL_LABEL)?;
    Ok(SideBlob {
        name: blob_name(keys, &hex)?,
        sealed: crypto::seal(&key, data, &aad(vault_id, &hash))?,
    })
}

/// Decrypt a side blob, then verify the plaintext against the expected hash and size.
pub fn open_side_blob(
    keys: &VaultKeys,
    vault_id: &[u8; 16],
    sha256_hex_expected: &str,
    size: u64,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let hash = parse_hash(sha256_hex_expected)?;
    let key = keys.data_key().derive_subkey(SEAL_LABEL)?;
    let plain = crypto::open(&key, sealed, &aad(vault_id, &hash))?;
    if plain.len() as u64 != size || sha256_hex(&plain) != sha256_hex_expected {
        return Err(Error::Corrupted);
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfParams;
    use crate::keys::VaultHeader;

    const VID: [u8; 16] = [9; 16];

    fn keys() -> VaultKeys {
        VaultHeader::create_with(b"fake-pass-1", KdfParams::for_tests())
            .unwrap()
            .1
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn sha256_hex_matches_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn threshold_is_strictly_greater_than_64_kib() {
        assert!(!is_external(0));
        assert!(!is_external(65_536));
        assert!(is_external(65_537));
    }

    #[test]
    fn round_trip_returns_original_bytes() {
        let k = keys();
        let d = data(70_000);
        let b = seal_side_blob(&k, &VID, &d).unwrap();
        let out = open_side_blob(&k, &VID, &sha256_hex(&d), d.len() as u64, &b.sealed).unwrap();
        assert_eq!(&**out, &d);
    }

    #[test]
    fn name_is_deterministic_keyed_and_not_the_plain_hash() {
        let k = keys();
        let d = data(100);
        let h = sha256_hex(&d);
        let n1 = seal_side_blob(&k, &VID, &d).unwrap().name;
        let n2 = seal_side_blob(&k, &VID, &d).unwrap().name;
        assert_eq!(n1, n2);
        assert_eq!(n1, blob_name(&k, &h).unwrap());
        assert_eq!(n1.len(), 64);
        assert_ne!(n1, h, "provider must not learn the plaintext hash");
        assert_ne!(
            n1,
            blob_name(&keys(), &h).unwrap(),
            "name depends on the vault key"
        );
    }

    #[test]
    fn same_content_seals_to_different_ciphertext() {
        let k = keys();
        let a = seal_side_blob(&k, &VID, b"x").unwrap();
        let b = seal_side_blob(&k, &VID, b"x").unwrap();
        assert_ne!(a.sealed, b.sealed);
    }

    #[test]
    fn open_fails_with_wrong_key_or_wrong_vault() {
        let k = keys();
        let d = data(10);
        let h = sha256_hex(&d);
        let b = seal_side_blob(&k, &VID, &d).unwrap();
        assert_eq!(
            open_side_blob(&keys(), &VID, &h, 10, &b.sealed).unwrap_err(),
            Error::Decryption
        );
        assert_eq!(
            open_side_blob(&k, &[1; 16], &h, 10, &b.sealed).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn every_tampered_byte_is_rejected() {
        let k = keys();
        let d = data(64);
        let h = sha256_hex(&d);
        let b = seal_side_blob(&k, &VID, &d).unwrap();
        for i in 0..b.sealed.len() {
            let mut t = b.sealed.clone();
            t[i] ^= 1;
            assert!(open_side_blob(&k, &VID, &h, 64, &t).is_err(), "byte {i}");
        }
    }

    #[test]
    fn blob_cannot_be_served_under_a_different_hash() {
        let k = keys();
        let a = data(10);
        let other = sha256_hex(b"other");
        let b = seal_side_blob(&k, &VID, &a).unwrap();
        assert_eq!(
            open_side_blob(&k, &VID, &other, 10, &b.sealed).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn size_mismatch_is_rejected_as_corrupted() {
        let k = keys();
        let d = data(10);
        let b = seal_side_blob(&k, &VID, &d).unwrap();
        assert_eq!(
            open_side_blob(&k, &VID, &sha256_hex(&d), 11, &b.sealed).unwrap_err(),
            Error::Corrupted
        );
    }

    #[test]
    fn malformed_hash_is_rejected() {
        let k = keys();
        assert!(blob_name(&k, "zz").is_err());
        assert!(open_side_blob(&k, &VID, "abcd", 1, &[0; 40]).is_err());
    }
}
