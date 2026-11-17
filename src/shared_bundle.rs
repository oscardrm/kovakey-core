//! Shared-vault bundle: a `.vault` plus its sealed side blobs in one Drive file (ADR 0033).
//!
//! Members of a shared vault can read only the one file they were given, so attachments and large
//! note images (side blobs) travel inside it. Layout, big-endian:
//!
//! ```text
//! "TVSH" | version u8 = 1 | vault_len u32 | vault bytes | count u32 | count × (name[64] | sealed_len u32 | sealed)
//! ```
//!
//! No new cryptography: the vault payload and every blob are already AES-256-GCM sealed, so a
//! tampered part fails to decrypt and tampered framing is `Corrupted`. A file without the magic is a
//! legacy plain `.vault` and passes through unchanged, so vaults that never use side blobs stay
//! byte-identical and readable by older clients.

use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::side_blob::SideBlob;

/// Magic bytes that start a bundle (a plain `.vault` starts with its own header instead).
pub const MAGIC: &[u8; 4] = b"TVSH";
/// Bundle format version.
pub const VERSION: u8 = 1;
/// Upper bound for the sealed side blobs of one shared vault (ADR 0033 §4).
pub const MAX_BLOB_BYTES: usize = 25 * 1024 * 1024;
/// Upper bound for the number of side blobs in one bundle.
pub const MAX_BLOBS: usize = 4096;
const NAME_LEN: usize = 64;

/// The two parts of a shared file once opened.
#[derive(Debug, PartialEq, Eq)]
pub struct Unpacked {
    /// The `.vault` bytes.
    pub file: Vec<u8>,
    /// Sealed side blobs that came with it (empty for a legacy plain file).
    pub side_blobs: Vec<SideBlob>,
}

fn valid_name(name: &str) -> bool {
    name.len() == NAME_LEN && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn len_u32(n: usize) -> Result<[u8; 4]> {
    Ok(u32::try_from(n)
        .map_err(|_| Error::InvalidInput)?
        .to_be_bytes())
}

/// Build the Drive file for a shared vault. With no side blobs this is exactly `file` (plain
/// `.vault`). Errors with [`Error::InvalidInput`] above [`MAX_BLOB_BYTES`] / [`MAX_BLOBS`] or for a
/// malformed or duplicate blob name.
pub fn pack(file: &[u8], side_blobs: &[SideBlob]) -> Result<Vec<u8>> {
    if side_blobs.is_empty() {
        return Ok(file.to_vec());
    }
    if side_blobs.len() > MAX_BLOBS {
        return Err(Error::InvalidInput);
    }
    let mut total = 0usize;
    let mut seen = HashSet::new();
    for b in side_blobs {
        if !valid_name(&b.name) || !seen.insert(b.name.as_str()) {
            return Err(Error::InvalidInput);
        }
        total = total
            .checked_add(b.sealed.len())
            .ok_or(Error::InvalidInput)?;
    }
    if total > MAX_BLOB_BYTES {
        return Err(Error::InvalidInput);
    }
    let mut out = Vec::with_capacity(file.len() + total + 64 * side_blobs.len() + 16);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&len_u32(file.len())?);
    out.extend_from_slice(file);
    out.extend_from_slice(&len_u32(side_blobs.len())?);
    for b in side_blobs {
        out.extend_from_slice(b.name.as_bytes());
        out.extend_from_slice(&len_u32(b.sealed.len())?);
        out.extend_from_slice(&b.sealed);
    }
    Ok(out)
}

/// Forward-only reader over untrusted bytes.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(Error::Corrupted)?;
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<usize> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::Corrupted)?;
        usize::try_from(u32::from_be_bytes(b)).map_err(|_| Error::Corrupted)
    }
}

/// Split a shared Drive file into the `.vault` and its side blobs. Bytes without the bundle magic are
/// a legacy plain `.vault` and come back unchanged. Errors: [`Error::UnsupportedVersion`] for a newer
/// bundle, [`Error::Corrupted`] for any malformed, truncated, oversized or duplicated content.
pub fn unpack(bytes: &[u8]) -> Result<Unpacked> {
    let Some(rest) = bytes.strip_prefix(MAGIC.as_slice()) else {
        return Ok(Unpacked {
            file: bytes.to_vec(),
            side_blobs: Vec::new(),
        });
    };
    let mut c = Cursor(rest);
    if c.take(1)? != [VERSION] {
        return Err(Error::UnsupportedVersion);
    }
    let vault_len = c.u32()?;
    let file = c.take(vault_len)?.to_vec();
    let count = c.u32()?;
    if count > MAX_BLOBS {
        return Err(Error::Corrupted);
    }
    let mut total = 0usize;
    let mut seen = HashSet::new();
    let mut side_blobs = Vec::new();
    for _ in 0..count {
        let name = std::str::from_utf8(c.take(NAME_LEN)?).map_err(|_| Error::Corrupted)?;
        if !valid_name(name) || !seen.insert(name.to_owned()) {
            return Err(Error::Corrupted);
        }
        let len = c.u32()?;
        total = total.checked_add(len).ok_or(Error::Corrupted)?;
        if total > MAX_BLOB_BYTES {
            return Err(Error::Corrupted);
        }
        side_blobs.push(SideBlob {
            name: name.to_owned(),
            sealed: c.take(len)?.to_vec(),
        });
    }
    if !c.0.is_empty() {
        return Err(Error::Corrupted);
    }
    Ok(Unpacked { file, side_blobs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::fixtures::sample;
    use crate::kdf::KdfParams;
    use crate::keys::VaultHeader;
    use crate::vault_file::{open_vault, seal_vault};
    use std::collections::HashMap;

    fn blob(c: char, len: usize) -> SideBlob {
        SideBlob {
            name: c.to_string().repeat(NAME_LEN),
            sealed: (0..len).map(|i| (i % 251) as u8).collect(),
        }
    }

    #[test]
    fn no_blobs_is_the_plain_vault_in_both_directions() {
        let file = vec![1, 2, 3, 4, 5, 6];
        assert_eq!(pack(&file, &[]).unwrap(), file);
        let u = unpack(&file).unwrap();
        assert_eq!(u.file, file);
        assert!(u.side_blobs.is_empty());
    }

    #[test]
    fn round_trips_a_vault_with_blobs() {
        let file = b"vault-bytes".to_vec();
        let blobs = vec![blob('a', 10), blob('b', 0), blob('c', 5_000)];
        let packed = pack(&file, &blobs).unwrap();
        assert!(packed.starts_with(MAGIC));
        let u = unpack(&packed).unwrap();
        assert_eq!(u.file, file);
        assert_eq!(u.side_blobs, blobs);
    }

    #[test]
    fn a_real_vault_with_a_large_image_survives_the_bundle() {
        let (h, k, _) =
            VaultHeader::create_with(b"fake-pass-for-tests", KdfParams::for_tests()).unwrap();
        let snap = sample(true);
        let sealed = seal_vault(&h, &k, &snap).unwrap();
        assert_eq!(sealed.side_blobs.len(), 1);
        let u = unpack(&pack(&sealed.file, &sealed.side_blobs).unwrap()).unwrap();
        let store: HashMap<_, _> = u
            .side_blobs
            .iter()
            .map(|b| (b.name.clone(), b.sealed.clone()))
            .collect();
        assert_eq!(
            open_vault(&u.file, &k, &|n| store.get(n).cloned()).unwrap(),
            snap
        );
    }

    #[test]
    fn every_truncation_is_corrupted_and_never_panics() {
        let packed = pack(b"vault", &[blob('a', 40), blob('b', 7)]).unwrap();
        for cut in 0..packed.len() {
            let r = unpack(&packed[..cut]);
            if cut < MAGIC.len() {
                // Too short to carry the magic: treated as a (tiny, invalid) plain file.
                assert!(r.is_ok());
            } else {
                assert_eq!(r.unwrap_err(), Error::Corrupted, "cut at {cut}");
            }
        }
    }

    #[test]
    fn trailing_bytes_are_corrupted() {
        let mut packed = pack(b"vault", &[blob('a', 4)]).unwrap();
        packed.push(0);
        assert_eq!(unpack(&packed).unwrap_err(), Error::Corrupted);
    }

    #[test]
    fn unknown_version_is_unsupported() {
        let mut packed = pack(b"vault", &[blob('a', 4)]).unwrap();
        packed[MAGIC.len()] = VERSION + 1;
        assert_eq!(unpack(&packed).unwrap_err(), Error::UnsupportedVersion);
    }

    #[test]
    fn malformed_and_duplicate_names_are_rejected() {
        let mut bad = blob('a', 1);
        bad.name = "A".repeat(NAME_LEN);
        assert_eq!(pack(b"v", &[bad]).unwrap_err(), Error::InvalidInput);
        assert_eq!(
            pack(b"v", &[blob('a', 1), blob('a', 2)]).unwrap_err(),
            Error::InvalidInput
        );
        // A bundle carrying a bad name on the wire.
        let mut packed = pack(b"v", &[blob('a', 1)]).unwrap();
        let at = MAGIC.len() + 1 + 4 + 1 + 4;
        packed[at] = b'Z';
        assert_eq!(unpack(&packed).unwrap_err(), Error::Corrupted);
    }

    #[test]
    fn the_size_cap_is_enforced_when_packing_and_when_reading() {
        let ok = vec![SideBlob {
            sealed: vec![0; MAX_BLOB_BYTES],
            ..blob('a', 0)
        }];
        let packed = pack(b"v", &ok).unwrap();
        assert!(unpack(&packed).is_ok());
        let over = vec![SideBlob {
            sealed: vec![0; MAX_BLOB_BYTES + 1],
            ..blob('a', 0)
        }];
        assert_eq!(pack(b"v", &over).unwrap_err(), Error::InvalidInput);
        // Forge a bundle that declares a blob above the cap: reading refuses it before allocating.
        let mut forged = pack(b"v", &[blob('a', 0)]).unwrap();
        let len_at = MAGIC.len() + 1 + 4 + 1 + 4 + NAME_LEN;
        forged[len_at..len_at + 4].copy_from_slice(&((MAX_BLOB_BYTES as u32) + 1).to_be_bytes());
        assert_eq!(unpack(&forged).unwrap_err(), Error::Corrupted);
    }

    #[test]
    fn a_huge_declared_count_is_refused_without_allocating() {
        let mut forged = pack(b"v", &[blob('a', 0)]).unwrap();
        let count_at = MAGIC.len() + 1 + 4 + 1;
        forged[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(unpack(&forged).unwrap_err(), Error::Corrupted);
    }
}
