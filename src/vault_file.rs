//! `.vault` file codec: header + wrapped keys + AES-256-GCM encrypted postcard payload.
//! File layout:
//!
//! ```text
//! header (HEADER_LEN bytes, see keys.rs) | snapshot_format_version u8 | nonce[12] | ciphertext | tag[16]
//! ```
//!
//! The ciphertext is the postcard snapshot sealed with AES-256-GCM under a subkey of the vault
//! data key. The AAD is `"TVPL" || header bytes exactly as stored || snapshot_format_version`, so
//! the whole header (vault id, KDF params, both wrapped keys) and the payload version are
//! authenticated: a payload cannot be re-attached to another vault's header, to a stale header
//! (e.g. from before a password change) or to a different declared version.
//! Anything that changes the header (password change) requires re-sealing the payload.

use std::collections::HashSet;

use zeroize::Zeroizing;

use crate::codec;
use crate::crypto;
use crate::error::{Error, Result};
use crate::keys::{VaultHeader, VaultKeys, HEADER_LEN};
use crate::models::Snapshot;
use crate::side_blob::{self, SideBlob};

const PAYLOAD_LABEL: &[u8] = b"vault/snapshot/v1";
const PAYLOAD_PURPOSE: &[u8] = b"TVPL";

/// Output of [`seal_vault`].
#[derive(Debug)]
pub struct SealedVault {
    /// The `.vault` file bytes.
    pub file: Vec<u8>,
    /// Side blobs the file refers to (deduplicated by name). Upload each that the provider lacks.
    pub side_blobs: Vec<SideBlob>,
}

fn payload_aad(header_bytes: &[u8], version: u8) -> Vec<u8> {
    [PAYLOAD_PURPOSE, header_bytes, &[version]].concat()
}

/// Parse the header at the start of a `.vault` file (needed to unlock before opening).
pub fn read_header(file: &[u8]) -> Result<VaultHeader> {
    let (header, _) = file.split_at_checked(HEADER_LEN).ok_or(Error::Corrupted)?;
    VaultHeader::from_bytes(header)
}

/// Encrypt `snapshot` into a `.vault` file.
///
/// `keys` must be the data key wrapped by `header`; a mismatch is only detected when opening.
/// Images above the side-blob threshold are returned separately in [`SealedVault::side_blobs`].
pub fn seal_vault(
    header: &VaultHeader,
    keys: &VaultKeys,
    snapshot: &Snapshot,
) -> Result<SealedVault> {
    let encoded = codec::encode_snapshot(snapshot)?;
    let header_bytes = header.to_bytes();
    let key = keys.data_key().derive_subkey(PAYLOAD_LABEL)?;
    let sealed = crypto::seal(
        &key,
        &encoded.payload,
        &payload_aad(&header_bytes, encoded.version),
    )?;
    let file = [&header_bytes[..], &[encoded.version], &sealed].concat();

    let mut seen = HashSet::new();
    let mut side_blobs = Vec::new();
    for blob in &encoded.external {
        if seen.insert(blob.sha256) {
            side_blobs.push(side_blob::seal_side_blob(
                keys,
                header.vault_id(),
                blob.data,
            )?);
        }
    }
    Ok(SealedVault { file, side_blobs })
}

/// Storage names of the side blobs a `.vault` file refers to (deduplicated, sorted), so a sync
/// client can download exactly those before [`open_vault`]. Same errors as [`open_vault`]
/// except that missing blobs are not an error here.
pub fn required_side_blobs(file: &[u8], keys: &VaultKeys) -> Result<Vec<String>> {
    let (header_bytes, rest) = file.split_at_checked(HEADER_LEN).ok_or(Error::Corrupted)?;
    VaultHeader::from_bytes(header_bytes)?;
    let (version, sealed) = rest.split_first().ok_or(Error::Corrupted)?;
    if !codec::is_supported_version(*version) {
        return Err(Error::UnsupportedVersion);
    }
    let key = keys.data_key().derive_subkey(PAYLOAD_LABEL)?;
    let payload: Zeroizing<Vec<u8>> =
        crypto::open(&key, sealed, &payload_aad(header_bytes, *version))?;
    let names: std::collections::BTreeSet<String> = codec::external_image_refs(*version, &payload)?
        .iter()
        .map(|(sha, _)| side_blob::blob_name(keys, sha))
        .collect::<Result<_>>()?;
    Ok(names.into_iter().collect())
}

/// Decrypt a `.vault` file. `side_blob` looks up sealed side blobs by storage name.
///
/// Errors: wrong key or any tampering of header/payload/side blobs is [`Error::Decryption`];
/// truncated or malformed input is [`Error::Corrupted`]; a newer payload version is
/// [`Error::UnsupportedVersion`]; a referenced side blob that is not provided is
/// [`Error::NotFound`].
pub fn open_vault(
    file: &[u8],
    keys: &VaultKeys,
    side_blob: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Result<Snapshot> {
    let (header_bytes, rest) = file.split_at_checked(HEADER_LEN).ok_or(Error::Corrupted)?;
    let header = VaultHeader::from_bytes(header_bytes)?;
    let (version, sealed) = rest.split_first().ok_or(Error::Corrupted)?;
    if !codec::is_supported_version(*version) {
        return Err(Error::UnsupportedVersion);
    }
    let key = keys.data_key().derive_subkey(PAYLOAD_LABEL)?;
    let payload: Zeroizing<Vec<u8>> =
        crypto::open(&key, sealed, &payload_aad(header_bytes, *version))?;
    let vault_id = *header.vault_id();
    codec::decode_snapshot(*version, &payload, &mut |sha, size| {
        let name = side_blob::blob_name(keys, sha)?;
        let sealed = side_blob(&name).ok_or(Error::NotFound)?;
        side_blob::open_side_blob(keys, &vault_id, sha, size, &sealed)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::fixtures::{image, pattern, sample};
    use crate::kdf::KdfParams;
    use crate::keys::HEADER_LEN;
    use std::collections::HashMap;

    const PW: &[u8] = b"fake-pass-for-tests";

    fn vault() -> (VaultHeader, VaultKeys) {
        let (h, k, _) = VaultHeader::create_with(PW, KdfParams::for_tests()).unwrap();
        (h, k)
    }

    fn store(s: &SealedVault) -> HashMap<String, Vec<u8>> {
        s.side_blobs
            .iter()
            .map(|b| (b.name.clone(), b.sealed.clone()))
            .collect()
    }

    fn open(file: &[u8], k: &VaultKeys, m: &HashMap<String, Vec<u8>>) -> Result<Snapshot> {
        open_vault(file, k, &|n| m.get(n).cloned())
    }

    #[test]
    fn round_trip_without_side_blobs() {
        let (h, k) = vault();
        let snap = sample(false);
        let sealed = seal_vault(&h, &k, &snap).unwrap();
        assert!(sealed.side_blobs.is_empty());
        assert_eq!(open(&sealed.file, &k, &HashMap::new()).unwrap(), snap);
    }

    #[test]
    fn file_starts_with_the_header_and_unlocks_with_password() {
        let (h, k) = vault();
        let sealed = seal_vault(&h, &k, &sample(false)).unwrap();
        assert_eq!(&sealed.file[..HEADER_LEN], h.to_bytes().as_slice());
        let parsed = read_header(&sealed.file).unwrap();
        assert_eq!(parsed, h);
        let k2 = parsed.unlock(PW).unwrap();
        assert!(open(&sealed.file, &k2, &HashMap::new()).is_ok());
    }

    #[test]
    fn unlock_with_recovery_key_opens_the_file() {
        let (h, k, r) = VaultHeader::create_with(PW, KdfParams::for_tests()).unwrap();
        let sealed = seal_vault(&h, &k, &sample(false)).unwrap();
        let k2 = read_header(&sealed.file)
            .unwrap()
            .unlock_with_recovery(&r)
            .unwrap();
        assert_eq!(
            open(&sealed.file, &k2, &HashMap::new()).unwrap(),
            sample(false)
        );
    }

    #[test]
    fn large_images_become_side_blobs_and_round_trip() {
        let (h, k) = vault();
        let snap = sample(true);
        let sealed = seal_vault(&h, &k, &snap).unwrap();
        assert_eq!(sealed.side_blobs.len(), 1);
        assert!(sealed.file.len() < 5_000, "file is {}", sealed.file.len());
        assert_eq!(open(&sealed.file, &k, &store(&sealed)).unwrap(), snap);
    }

    #[test]
    fn identical_large_images_share_one_side_blob() {
        let (h, k) = vault();
        let mut snap = Snapshot::default();
        snap.note_images.push(image("a", pattern(70_000)));
        snap.note_images.push(image("b", pattern(70_000)));
        let sealed = seal_vault(&h, &k, &snap).unwrap();
        assert_eq!(sealed.side_blobs.len(), 1);
        assert_eq!(open(&sealed.file, &k, &store(&sealed)).unwrap(), snap);
    }

    #[test]
    fn file_does_not_contain_plaintext() {
        let (h, k) = vault();
        let sealed = seal_vault(&h, &k, &sample(false)).unwrap();
        for needle in [&b"fake-secret-value"[..], b"old-fake-pass-1", b"Example"] {
            assert!(!sealed.file.windows(needle.len()).any(|w| w == needle));
        }
    }

    #[test]
    fn sealing_twice_gives_different_files() {
        let (h, k) = vault();
        let a = seal_vault(&h, &k, &sample(false)).unwrap();
        let b = seal_vault(&h, &k, &sample(false)).unwrap();
        assert_ne!(a.file, b.file);
    }

    #[test]
    fn wrong_key_fails_with_decryption() {
        let (h, k) = vault();
        let (_, other) = vault();
        let sealed = seal_vault(&h, &k, &sample(false)).unwrap();
        assert_eq!(
            open(&sealed.file, &other, &HashMap::new()).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn every_tampered_byte_of_the_file_is_rejected() {
        let (h, k) = vault();
        let sealed = seal_vault(&h, &k, &sample(false)).unwrap();
        for i in 0..sealed.file.len() {
            let mut t = sealed.file.clone();
            t[i] ^= 0x01;
            assert!(
                open(&t, &k, &HashMap::new()).is_err(),
                "byte {i} (header {})",
                i < HEADER_LEN
            );
        }
    }

    #[test]
    fn payload_swapped_under_another_vaults_header_is_rejected() {
        let (h1, k1) = vault();
        let (h2, _k2) = vault();
        let s1 = seal_vault(&h1, &k1, &sample(false)).unwrap();
        let mut forged = h2.to_bytes();
        forged.extend_from_slice(&s1.file[HEADER_LEN..]);
        assert!(open(&forged, &k1, &HashMap::new()).is_err());
    }

    #[test]
    fn stale_header_after_password_change_cannot_be_replayed() {
        let (h, k) = vault();
        let s_old = seal_vault(&h, &k, &sample(false)).unwrap();
        let h_new = h.change_password(&k, b"another-fake-pass").unwrap();
        let mut spliced = h_new.to_bytes();
        spliced.extend_from_slice(&s_old.file[HEADER_LEN..]);
        assert_eq!(
            open(&spliced, &k, &HashMap::new()).unwrap_err(),
            Error::Decryption
        );
        let s_new = seal_vault(&h_new, &k, &sample(false)).unwrap();
        assert!(open(&s_new.file, &k, &HashMap::new()).is_ok());
    }

    #[test]
    fn truncation_at_every_length_is_rejected() {
        let (h, k) = vault();
        let sealed = seal_vault(&h, &k, &sample(false)).unwrap();
        for n in 0..sealed.file.len() {
            assert!(
                open(&sealed.file[..n], &k, &HashMap::new()).is_err(),
                "len {n}"
            );
        }
        let mut longer = sealed.file.clone();
        longer.push(0);
        assert!(open(&longer, &k, &HashMap::new()).is_err());
    }

    #[test]
    fn unknown_snapshot_version_is_unsupported() {
        let (h, k) = vault();
        let mut f = seal_vault(&h, &k, &sample(false)).unwrap().file;
        f[HEADER_LEN] = 6;
        assert_eq!(
            open(&f, &k, &HashMap::new()).unwrap_err(),
            Error::UnsupportedVersion
        );
    }

    #[test]
    fn missing_side_blob_is_not_found() {
        let (h, k) = vault();
        let sealed = seal_vault(&h, &k, &sample(true)).unwrap();
        assert_eq!(
            open(&sealed.file, &k, &HashMap::new()).unwrap_err(),
            Error::NotFound
        );
    }

    #[test]
    fn tampered_side_blob_is_rejected() {
        let (h, k) = vault();
        let sealed = seal_vault(&h, &k, &sample(true)).unwrap();
        let mut m = store(&sealed);
        for v in m.values_mut() {
            let mid = v.len() / 2;
            v[mid] ^= 1;
        }
        assert_eq!(open(&sealed.file, &k, &m).unwrap_err(), Error::Decryption);
    }

    #[test]
    fn side_blob_from_another_image_cannot_be_substituted() {
        let (h, k) = vault();
        let mut a = Snapshot::default();
        a.note_images.push(image("a", pattern(70_000)));
        let mut b = Snapshot::default();
        b.note_images.push(image("b", pattern(80_000)));
        let sa = seal_vault(&h, &k, &a).unwrap();
        let sb = seal_vault(&h, &k, &b).unwrap();
        // Serve B's ciphertext under A's name.
        let mut m = HashMap::new();
        m.insert(
            sa.side_blobs[0].name.clone(),
            sb.side_blobs[0].sealed.clone(),
        );
        assert!(open(&sa.file, &k, &m).is_err());
    }

    #[test]
    fn side_blob_from_another_vault_is_rejected() {
        let (h1, k1) = vault();
        let (h2, _) = vault();
        let snap = sample(true);
        let s1 = seal_vault(&h1, &k1, &snap).unwrap();
        // Same data key for both, so only the vault-id in the AAD differs.
        let s2 = seal_vault(&h2, &k1, &snap).unwrap();
        let mut m = store(&s1);
        m.insert(
            s1.side_blobs[0].name.clone(),
            s2.side_blobs[0].sealed.clone(),
        );
        assert_eq!(open(&s1.file, &k1, &m).unwrap_err(), Error::Decryption);
    }

    #[test]
    fn oversized_image_with_wrong_declared_hash_is_rejected_on_seal() {
        let (h, k) = vault();
        let mut snap = Snapshot::default();
        let mut img = image("a", pattern(70_000));
        img.sha256 = crate::side_blob::sha256_hex(b"nope");
        snap.note_images.push(img);
        assert_eq!(seal_vault(&h, &k, &snap).unwrap_err(), Error::InvalidInput);
    }

    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/golden_v1.vault"
    );

    /// `TV_REGEN_GOLDEN=1 cargo test -p vault-core regenerate_vault_golden -- --ignored`
    #[test]
    #[ignore]
    fn regenerate_vault_golden() {
        if std::env::var("TV_REGEN_GOLDEN").is_err() {
            return;
        }
        let (h, k) = vault();
        let sealed = seal_vault(&h, &k, &sample(false)).unwrap();
        std::fs::write(GOLDEN, sealed.file).unwrap();
    }

    #[test]
    fn golden_v1_vault_file_still_opens_with_the_password() {
        let file = std::fs::read(GOLDEN).unwrap();
        let keys = read_header(&file).unwrap().unlock(PW).unwrap();
        assert_eq!(
            open(&file, &keys, &HashMap::new()).unwrap(),
            crate::codec::fixtures::v1_view(sample(false))
        );
    }
}
