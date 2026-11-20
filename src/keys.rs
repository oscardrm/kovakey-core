//! Vault key hierarchy and header.
//!
//! ```text
//! Master Password --Argon2id--> KEK_pw  --wraps--\
//!                                                  >--> random 256-bit data key
//! Recovery Key    --HKDF------> KEK_rk  --wraps--/        |-- HKDF --> DB key (SQLCipher raw key)
//! ```
//!
//! Optional **device wrap** (quick unlock, ADR 0003): a random per-device [`DeviceKey`] wraps the
//! data key into a 60-byte blob that is stored *device-locally* (never in the header or the synced
//! `.vault`). The host keeps the `DeviceKey` in hardware-protected storage (Keychain/Keystore,
//! biometric-gated). The data key itself never leaves this crate.
//!
//! Two header kinds share the magic and differ by version byte:
//!
//! - **Password header** (format version 1, fixed 169 bytes):
//!   `magic "TVLT" | 1 | vault_id[16] | kdf_params[28] | wrapped_by_pw[60] | wrapped_by_rk[60]`.
//!   Each wrap is AES-256-GCM with AAD binding magic, version, vault id, purpose (and KDF params
//!   for the password wrap), so header tampering or downgrade makes unwrapping fail.
//! - **Member header** (format version 2, fixed 25 bytes): `magic "TVLT" | 2 | vault_id[16] | epoch u32 BE`.
//!   The data key is not stored in the header at all: it is wrapped separately for each member's
//!   public key (see [`crate::member_keys`]). The epoch increases on every re-key. Readers that
//!   only know version 1 reject it with [`Error::UnsupportedVersion`].
//!
//! The whole header is part of the payload AAD (see `vault_file`), so a payload cannot be moved
//! to another header kind, vault or epoch.

use crate::crypto::{self, SecretKey, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::kdf::{KdfParams, PARAMS_LEN};
use crate::recovery::RecoveryKey;

const MAGIC: &[u8; 4] = b"TVLT";
/// Format version of the password header.
pub const FORMAT_VERSION: u8 = 1;
/// Format version of the member header (data key wrapped per member, no password).
pub const MEMBER_FORMAT_VERSION: u8 = 2;
const ID_LEN: usize = 16;
const WRAPPED_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
/// Serialized size of a password header.
pub const HEADER_LEN: usize = 4 + 1 + ID_LEN + PARAMS_LEN + WRAPPED_LEN * 2;
/// Serialized size of a member header.
pub const MEMBER_HEADER_LEN: usize = 4 + 1 + ID_LEN + 4;

/// Size of the header at the start of `bytes`, read from its version byte. Unknown versions are
/// [`Error::UnsupportedVersion`]; bad magic or too few bytes are [`Error::Corrupted`].
pub fn header_len(bytes: &[u8]) -> Result<usize> {
    let magic = bytes.get(..4).ok_or(Error::Corrupted)?;
    if magic != MAGIC {
        return Err(Error::Corrupted);
    }
    match *bytes.get(4).ok_or(Error::Corrupted)? {
        FORMAT_VERSION => Ok(HEADER_LEN),
        MEMBER_FORMAT_VERSION => Ok(MEMBER_HEADER_LEN),
        _ => Err(Error::UnsupportedVersion),
    }
}
const DB_KEY_LABEL: &[u8] = b"vault/db-key/v1";

/// A random per-device key that unwraps the data key from a device-local wrap blob.
/// Zeroized on drop; `Debug` is redacted; not `Clone`.
pub struct DeviceKey(SecretKey);

impl DeviceKey {
    /// Generate a fresh random device key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self(SecretKey::random()?))
    }

    /// Rebuild from the bytes previously handed to the host. Wrong length is an error.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::Decryption)?;
        Ok(Self(SecretKey::from_bytes(arr)))
    }

    /// Borrow the raw bytes (for handing to the host's secure storage exactly once).
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose()
    }
}

impl core::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DeviceKey(<redacted>)")
    }
}

/// Result of device enrollment: the key for secure storage and the device-local wrap blob.
#[derive(Debug)]
pub struct DeviceEnrollment {
    /// Store in hardware-protected, biometric-gated storage; never sync, never log.
    pub device_key: DeviceKey,
    /// Opaque wrap (`nonce || ciphertext || tag`, [`WRAPPED_LEN`] bytes). Not secret on its own;
    /// store device-locally next to the header.
    pub wrapped: Vec<u8>,
}

/// The password slots of a version-1 header.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PasswordSlots {
    kdf: KdfParams,
    wrapped_by_password: [u8; WRAPPED_LEN],
    wrapped_by_recovery: [u8; WRAPPED_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HeaderKind {
    /// Master Password + Recovery Key wrap the data key (format version 1).
    Password(PasswordSlots),
    /// The data key is wrapped per member outside the header (format version 2).
    Members { epoch: u32 },
}

/// Parsed vault header (contains no plaintext secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultHeader {
    vault_id: [u8; ID_LEN],
    kind: HeaderKind,
}

/// The unlocked vault data key. Zeroized on drop; dropping it is "locking".
#[derive(Debug)]
pub struct VaultKeys {
    data_key: SecretKey,
}

impl VaultKeys {
    /// Key for the SQLCipher database (independent subkey of the data key).
    pub fn db_key(&self) -> Result<SecretKey> {
        self.data_key.derive_subkey(DB_KEY_LABEL)
    }

    /// Key for encrypting individual payloads/blobs outside the database.
    pub fn data_key(&self) -> &SecretKey {
        &self.data_key
    }

    pub(crate) fn from_data_key(data_key: SecretKey) -> Self {
        Self { data_key }
    }
}

fn aad(header_id: &[u8; ID_LEN], purpose: &[u8], extra: &[u8]) -> Vec<u8> {
    [
        MAGIC.as_slice(),
        &[FORMAT_VERSION],
        header_id,
        purpose,
        extra,
    ]
    .concat()
}

fn wrap(kek: &SecretKey, dk: &SecretKey, aad: &[u8]) -> Result<[u8; WRAPPED_LEN]> {
    let sealed = crypto::seal(kek, dk.expose(), aad)?;
    sealed.try_into().map_err(|_| Error::Corrupted)
}

fn unwrap_key(kek: &SecretKey, wrapped: &[u8], aad: &[u8]) -> Result<VaultKeys> {
    let pt = crypto::open(kek, wrapped, aad)?;
    let bytes: [u8; KEY_LEN] = pt.as_slice().try_into().map_err(|_| Error::Corrupted)?;
    Ok(VaultKeys {
        data_key: SecretKey::from_bytes(bytes),
    })
}

impl VaultHeader {
    /// Create a brand-new vault: returns the header, unlocked keys and the Recovery Key
    /// (which the caller must show to the user exactly once).
    pub fn create(password: &[u8]) -> Result<(Self, VaultKeys, RecoveryKey)> {
        Self::create_with(password, KdfParams::generate()?)
    }

    pub(crate) fn create_with(
        password: &[u8],
        kdf: KdfParams,
    ) -> Result<(Self, VaultKeys, RecoveryKey)> {
        let id = *uuid::Uuid::now_v7().as_bytes();
        let data_key = SecretKey::random()?;
        let recovery = RecoveryKey::generate()?;
        let kek_pw = kdf.derive_kek(password)?;
        let kek_rk = recovery.derive_kek()?;
        let slots = PasswordSlots {
            wrapped_by_password: wrap(&kek_pw, &data_key, &aad(&id, b"pw", &kdf.to_bytes()))?,
            wrapped_by_recovery: wrap(&kek_rk, &data_key, &aad(&id, b"rk", &[]))?,
            kdf,
        };
        let header = Self {
            vault_id: id,
            kind: HeaderKind::Password(slots),
        };
        Ok((header, VaultKeys { data_key }, recovery))
    }

    /// Create a brand-new member vault (no password, no Recovery Key): a fresh vault id, epoch 0
    /// and a random data key. The caller wraps the key for each member with
    /// [`crate::member_keys::wrap_data_key`].
    pub fn create_member() -> Result<(Self, VaultKeys)> {
        let header = Self {
            vault_id: *uuid::Uuid::now_v7().as_bytes(),
            kind: HeaderKind::Members { epoch: 0 },
        };
        Ok((header, VaultKeys::from_data_key(SecretKey::random()?)))
    }

    /// Re-key a member vault: same vault id, the next epoch and a fresh random data key. Every
    /// member needs a new wrap afterwards; wraps of the old epoch no longer open. A password
    /// vault (or an exhausted epoch counter) is [`Error::InvalidInput`].
    pub fn rekey_members(&self) -> Result<(Self, VaultKeys)> {
        let epoch = self.member_epoch()?;
        let next = epoch.checked_add(1).ok_or(Error::InvalidInput)?;
        let header = Self {
            vault_id: self.vault_id,
            kind: HeaderKind::Members { epoch: next },
        };
        Ok((header, VaultKeys::from_data_key(SecretKey::random()?)))
    }

    /// `true` for a member header (format version 2).
    pub fn is_member(&self) -> bool {
        matches!(self.kind, HeaderKind::Members { .. })
    }

    /// Key epoch of a member header; a password header is [`Error::InvalidInput`].
    pub fn member_epoch(&self) -> Result<u32> {
        match self.kind {
            HeaderKind::Members { epoch } => Ok(epoch),
            HeaderKind::Password(_) => Err(Error::InvalidInput),
        }
    }

    /// The password slots; a member header has none ([`Error::InvalidInput`]).
    fn slots(&self) -> Result<&PasswordSlots> {
        match &self.kind {
            HeaderKind::Password(s) => Ok(s),
            HeaderKind::Members { .. } => Err(Error::InvalidInput),
        }
    }

    /// Unlock with the Master Password. Wrong password and tampering are indistinguishable.
    pub fn unlock(&self, password: &[u8]) -> Result<VaultKeys> {
        let s = self.slots()?;
        let kek = s.kdf.derive_kek(password)?;
        unwrap_key(
            &kek,
            &s.wrapped_by_password,
            &aad(&self.vault_id, b"pw", &s.kdf.to_bytes()),
        )
    }

    /// Unlock with the Recovery Key.
    pub fn unlock_with_recovery(&self, recovery: &RecoveryKey) -> Result<VaultKeys> {
        let s = self.slots()?;
        let kek = recovery.derive_kek()?;
        unwrap_key(
            &kek,
            &s.wrapped_by_recovery,
            &aad(&self.vault_id, b"rk", &[]),
        )
    }

    /// Enroll this device for quick unlock: generate a [`DeviceKey`] and wrap the data key with it.
    /// The AAD binds magic, format version, vault id and the purpose `"dev"` (not the device id,
    /// so the wrap survives a device-id change). Callers must authenticate the user first.
    /// Member vaults do not support quick unlock ([`Error::InvalidInput`]).
    pub fn enroll_device(&self, keys: &VaultKeys) -> Result<DeviceEnrollment> {
        self.slots()?;
        let device_key = DeviceKey::generate()?;
        let wrapped = wrap(
            &device_key.0,
            &keys.data_key,
            &aad(&self.vault_id, b"dev", &[]),
        )?;
        Ok(DeviceEnrollment {
            device_key,
            wrapped: wrapped.to_vec(),
        })
    }

    /// Unlock with a device key and its wrap blob. Every failure (wrong key, tampering, wrong
    /// vault, bad length, member vault) is the same [`Error::Decryption`].
    pub fn unlock_with_device_key(
        &self,
        device_key: &DeviceKey,
        wrapped: &[u8],
    ) -> Result<VaultKeys> {
        if wrapped.len() != WRAPPED_LEN || self.is_member() {
            return Err(Error::Decryption);
        }
        unwrap_key(&device_key.0, wrapped, &aad(&self.vault_id, b"dev", &[]))
            .map_err(|_| Error::Decryption)
    }

    /// Forgotten-password flow: prove possession of the Recovery Key and set a new Master
    /// Password. Returns an updated header (new salt); the data key and Recovery Key are unchanged.
    pub fn reset_password(&self, recovery: &RecoveryKey, new_password: &[u8]) -> Result<Self> {
        let keys = self.unlock_with_recovery(recovery)?;
        self.rewrap_password(&keys, new_password, KdfParams::generate()?)
    }

    /// Change the Master Password while unlocked.
    pub fn change_password(&self, keys: &VaultKeys, new_password: &[u8]) -> Result<Self> {
        self.rewrap_password(keys, new_password, KdfParams::generate()?)
    }

    pub(crate) fn rewrap_password(
        &self,
        keys: &VaultKeys,
        new_password: &[u8],
        kdf: KdfParams,
    ) -> Result<Self> {
        let s = self.slots()?;
        let kek = kdf.derive_kek(new_password)?;
        let wrapped = wrap(
            &kek,
            &keys.data_key,
            &aad(&self.vault_id, b"pw", &kdf.to_bytes()),
        )?;
        Ok(Self {
            vault_id: self.vault_id,
            kind: HeaderKind::Password(PasswordSlots {
                kdf,
                wrapped_by_password: wrapped,
                wrapped_by_recovery: s.wrapped_by_recovery,
            }),
        })
    }

    /// Replace the Recovery Key: generate a new one and re-wrap the data key with it. The old
    /// Recovery Key stops working once the returned header is persisted. The data key and the
    /// password wrap are unchanged, so device wraps and sealed blobs stay valid.
    pub fn rotate_recovery(&self, keys: &VaultKeys) -> Result<(Self, RecoveryKey)> {
        let s = self.slots()?;
        let recovery = RecoveryKey::generate()?;
        let kek = recovery.derive_kek()?;
        let wrapped = wrap(&kek, &keys.data_key, &aad(&self.vault_id, b"rk", &[]))?;
        Ok((
            Self {
                vault_id: self.vault_id,
                kind: HeaderKind::Password(PasswordSlots {
                    wrapped_by_recovery: wrapped,
                    ..s.clone()
                }),
            },
            recovery,
        ))
    }

    /// Vault id (UUIDv7 bytes).
    pub fn vault_id(&self) -> &[u8; ID_LEN] {
        &self.vault_id
    }

    /// Serialize to the on-disk header format.
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.kind {
            HeaderKind::Password(s) => [
                MAGIC.as_slice(),
                &[FORMAT_VERSION],
                &self.vault_id,
                &s.kdf.to_bytes(),
                &s.wrapped_by_password,
                &s.wrapped_by_recovery,
            ]
            .concat(),
            HeaderKind::Members { epoch } => [
                MAGIC.as_slice(),
                &[MEMBER_FORMAT_VERSION],
                &self.vault_id,
                &epoch.to_be_bytes(),
            ]
            .concat(),
        }
    }

    /// Parse a header. Rejects bad magic, unknown versions (incl. downgrades) and bad lengths.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != header_len(bytes)? {
            return Err(Error::Corrupted);
        }
        let rest = bytes.get(5..).ok_or(Error::Corrupted)?;
        let (id, rest) = rest.split_at_checked(ID_LEN).ok_or(Error::Corrupted)?;
        let vault_id: [u8; ID_LEN] = id.try_into().map_err(|_| Error::Corrupted)?;
        if bytes.get(4) == Some(&MEMBER_FORMAT_VERSION) {
            let epoch: [u8; 4] = rest.try_into().map_err(|_| Error::Corrupted)?;
            return Ok(Self {
                vault_id,
                kind: HeaderKind::Members {
                    epoch: u32::from_be_bytes(epoch),
                },
            });
        }
        let (kdf, rest) = rest.split_at_checked(PARAMS_LEN).ok_or(Error::Corrupted)?;
        let (wp, wr) = rest.split_at_checked(WRAPPED_LEN).ok_or(Error::Corrupted)?;
        Ok(Self {
            vault_id,
            kind: HeaderKind::Password(PasswordSlots {
                kdf: KdfParams::from_bytes(kdf)?,
                wrapped_by_password: wp.try_into().map_err(|_| Error::Corrupted)?,
                wrapped_by_recovery: wr.try_into().map_err(|_| Error::Corrupted)?,
            }),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const PW: &[u8] = b"correct-horse-test";

    fn new_vault() -> (VaultHeader, VaultKeys, RecoveryKey) {
        VaultHeader::create_with(PW, KdfParams::for_tests()).unwrap()
    }

    #[test]
    fn unlock_with_password_returns_same_data_key() {
        let (h, k, _) = new_vault();
        assert_eq!(
            h.unlock(PW).unwrap().data_key().expose(),
            k.data_key().expose()
        );
    }

    #[test]
    fn unlock_fails_with_wrong_password() {
        let (h, _, _) = new_vault();
        assert_eq!(h.unlock(b"wrong-fake-pass").unwrap_err(), Error::Decryption);
    }

    #[test]
    fn unlock_with_recovery_key_returns_same_data_key() {
        let (h, k, r) = new_vault();
        assert_eq!(
            h.unlock_with_recovery(&r).unwrap().data_key().expose(),
            k.data_key().expose()
        );
    }

    #[test]
    fn recovery_key_from_other_vault_fails() {
        let (h, _, _) = new_vault();
        let (_, _, other) = new_vault();
        assert!(h.unlock_with_recovery(&other).is_err());
    }

    #[test]
    fn reset_password_end_to_end() {
        let (h, k, r) = new_vault();
        let parsed = RecoveryKey::parse(&r.to_display_string()).unwrap();
        let h2 = h.reset_password(&parsed, b"new-fake-pass").unwrap();
        assert!(h2.unlock(PW).is_err());
        assert_eq!(
            h2.unlock(b"new-fake-pass").unwrap().data_key().expose(),
            k.data_key().expose()
        );
        assert!(h2.unlock_with_recovery(&r).is_ok());
        assert_ne!(h2.slots().unwrap().kdf, h.slots().unwrap().kdf);
    }

    #[test]
    fn rotate_recovery_replaces_the_key_and_keeps_password_and_data_key() {
        let (h, k, old) = new_vault();
        let (h2, new) = h.rotate_recovery(&k).unwrap();
        assert!(h2.unlock_with_recovery(&old).is_err());
        assert_eq!(
            h2.unlock_with_recovery(&new).unwrap().data_key().expose(),
            k.data_key().expose()
        );
        assert!(h2.unlock(PW).is_ok());
        assert_eq!(h2.vault_id, h.vault_id);
        assert_eq!(
            h2.slots().unwrap().wrapped_by_password,
            h.slots().unwrap().wrapped_by_password
        );
        assert_ne!(
            h2.slots().unwrap().wrapped_by_recovery,
            h.slots().unwrap().wrapped_by_recovery
        );
        // Survives serialization.
        let parsed = VaultHeader::from_bytes(&h2.to_bytes()).unwrap();
        assert!(parsed.unlock_with_recovery(&new).is_ok());
    }

    #[test]
    fn device_wrap_round_trips_to_the_same_data_key() {
        let (h, k, _) = new_vault();
        let e = h.enroll_device(&k).unwrap();
        assert_eq!(e.wrapped.len(), WRAPPED_LEN);
        let keys = h.unlock_with_device_key(&e.device_key, &e.wrapped).unwrap();
        assert_eq!(keys.data_key().expose(), k.data_key().expose());
    }

    #[test]
    fn device_wrap_does_not_contain_the_data_key() {
        let (h, k, _) = new_vault();
        let e = h.enroll_device(&k).unwrap();
        let dk = k.data_key().expose();
        assert!(!e.wrapped.windows(dk.len()).any(|w| w == dk));
        assert!(!e
            .wrapped
            .windows(KEY_LEN)
            .any(|w| w == e.device_key.expose()));
    }

    #[test]
    fn each_enrollment_uses_a_fresh_key_and_nonce() {
        let (h, k, _) = new_vault();
        let (a, b) = (h.enroll_device(&k).unwrap(), h.enroll_device(&k).unwrap());
        assert_ne!(a.device_key.expose(), b.device_key.expose());
        assert_ne!(a.wrapped, b.wrapped);
        // A wrap only opens with its own key.
        assert!(h.unlock_with_device_key(&a.device_key, &b.wrapped).is_err());
    }

    #[test]
    fn wrong_device_key_fails() {
        let (h, k, _) = new_vault();
        let e = h.enroll_device(&k).unwrap();
        let other = DeviceKey::generate().unwrap();
        assert_eq!(
            h.unlock_with_device_key(&other, &e.wrapped).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn tampering_with_any_wrap_byte_fails() {
        let (h, k, _) = new_vault();
        let e = h.enroll_device(&k).unwrap();
        for i in 0..e.wrapped.len() {
            let mut t = e.wrapped.clone();
            t[i] ^= 0x01;
            assert_eq!(
                h.unlock_with_device_key(&e.device_key, &t).unwrap_err(),
                Error::Decryption,
                "byte {i}"
            );
        }
    }

    #[test]
    fn truncated_or_extended_wrap_fails() {
        let (h, k, _) = new_vault();
        let e = h.enroll_device(&k).unwrap();
        for len in [0, 1, WRAPPED_LEN - 1] {
            assert!(h
                .unlock_with_device_key(&e.device_key, &e.wrapped[..len])
                .is_err());
        }
        let mut longer = e.wrapped.clone();
        longer.push(0);
        assert!(h.unlock_with_device_key(&e.device_key, &longer).is_err());
    }

    #[test]
    fn wrap_from_another_vault_is_rejected_even_with_its_device_key() {
        let (h_a, k_a, _) = new_vault();
        let (h_b, _, _) = new_vault();
        let e = h_a.enroll_device(&k_a).unwrap();
        // Same key + blob presented to a different vault: the vault id in the AAD must not match.
        assert!(h_b
            .unlock_with_device_key(&e.device_key, &e.wrapped)
            .is_err());
    }

    #[test]
    fn password_wrap_cannot_be_replayed_as_a_device_wrap() {
        // Purpose binding: the "pw" wrap under some key must not open as a "dev" wrap.
        let (h, k, _) = new_vault();
        let kek = h.slots().unwrap().kdf.derive_kek(PW).unwrap();
        let as_device = DeviceKey::from_slice(kek.expose()).unwrap();
        assert!(h
            .unlock_with_device_key(&as_device, &h.slots().unwrap().wrapped_by_password)
            .is_err());
        let _ = k;
    }

    #[test]
    fn device_wrap_survives_password_change_and_reset() {
        let (h, k, r) = new_vault();
        let e = h.enroll_device(&k).unwrap();
        let h2 = h.change_password(&k, b"new-fake-pass").unwrap();
        assert!(h2.unlock_with_device_key(&e.device_key, &e.wrapped).is_ok());
        let h3 = h2.reset_password(&r, b"newer-fake-pass").unwrap();
        assert!(h3.unlock_with_device_key(&e.device_key, &e.wrapped).is_ok());
    }

    #[test]
    fn device_key_debug_is_redacted_and_length_is_checked() {
        let k = DeviceKey::generate().unwrap();
        assert_eq!(format!("{k:?}"), "DeviceKey(<redacted>)");
        assert!(DeviceKey::from_slice(&[0u8; 31]).is_err());
        assert!(DeviceKey::from_slice(&[0u8; 33]).is_err());
        assert!(DeviceKey::from_slice(&[]).is_err());
    }

    #[test]
    fn header_round_trips() {
        let (h, _, _) = new_vault();
        let b = h.to_bytes();
        assert_eq!(b.len(), HEADER_LEN);
        assert_eq!(VaultHeader::from_bytes(&b).unwrap(), h);
    }

    #[test]
    fn tampering_with_any_header_byte_prevents_unlock_or_parse() {
        let (h, _, r) = new_vault();
        let bytes = h.to_bytes();
        // Offsets of the m/t/p u32 fields inside the header. Flipping a *high* byte of these
        // only yields a different (possibly very expensive) KDF cost, which the bounds check
        // in `KdfParams::from_bytes` covers separately, so only the low byte is flipped here.
        let kdf_start = 4 + 1 + ID_LEN;
        let high_bytes: Vec<usize> = (0..3)
            .flat_map(|f| (1..4).map(move |b| kdf_start + f * 4 + b))
            .collect();
        for i in (0..bytes.len()).filter(|i| !high_bytes.contains(i)) {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            // Every byte is authenticated by at least one wrap (or rejected at parse time), so
            // no single flip may leave both unlock paths working.
            let both_ok = VaultHeader::from_bytes(&t)
                .map(|h| h.unlock(PW).is_ok() && h.unlock_with_recovery(&r).is_ok())
                .unwrap_or(false);
            assert!(!both_ok, "byte {i} tamper went unnoticed");
        }
    }

    #[test]
    fn tampering_with_recovery_wrap_prevents_recovery_unlock() {
        let (h, _, r) = new_vault();
        let bytes = h.to_bytes();
        let start = HEADER_LEN - WRAPPED_LEN;
        for i in start..HEADER_LEN {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            let h = VaultHeader::from_bytes(&t).unwrap();
            assert!(h.unlock_with_recovery(&r).is_err(), "byte {i}");
        }
    }

    #[test]
    fn oversized_kdf_cost_in_header_is_rejected_without_deriving() {
        let (h, _, _) = new_vault();
        let mut t = h.to_bytes();
        t[4 + 1 + ID_LEN + 3] ^= 0x01; // high byte of memory cost -> huge allocation request
        assert_eq!(
            VaultHeader::from_bytes(&t).unwrap_err(),
            Error::InvalidParams
        );
    }

    #[test]
    fn truncated_or_unknown_version_headers_are_rejected() {
        let (h, _, _) = new_vault();
        let b = h.to_bytes();
        assert_eq!(
            VaultHeader::from_bytes(&b[..b.len() - 1]).unwrap_err(),
            Error::Corrupted
        );
        let mut v = b.clone();
        v[4] = 3;
        assert_eq!(
            VaultHeader::from_bytes(&v).unwrap_err(),
            Error::UnsupportedVersion
        );
        v[4] = 0;
        assert_eq!(
            VaultHeader::from_bytes(&v).unwrap_err(),
            Error::UnsupportedVersion
        );
    }

    #[test]
    fn db_key_differs_from_data_key() {
        let (_, k, _) = new_vault();
        assert_ne!(k.db_key().unwrap().expose(), k.data_key().expose());
    }
}
