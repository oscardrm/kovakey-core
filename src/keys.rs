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
//! Header layout (fixed 169 bytes, format version 1):
//! `magic "TVLT" | version u8 | vault_id[16] | kdf_params[28] | wrapped_by_pw[60] | wrapped_by_rk[60]`.
//! Each wrap is AES-256-GCM with AAD binding magic, version, vault id, purpose (and KDF params
//! for the password wrap), so header tampering or downgrade makes unwrapping fail.

use crate::crypto::{self, SecretKey, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::kdf::{KdfParams, PARAMS_LEN};
use crate::recovery::RecoveryKey;

const MAGIC: &[u8; 4] = b"TVLT";
/// Current vault header format version.
pub const FORMAT_VERSION: u8 = 1;
const ID_LEN: usize = 16;
const WRAPPED_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
/// Total serialized header size.
pub const HEADER_LEN: usize = 4 + 1 + ID_LEN + PARAMS_LEN + WRAPPED_LEN * 2;
const DB_KEY_LABEL: &[u8] = b"truevault/db-key/v1";

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

/// Parsed vault header (contains no plaintext secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultHeader {
    vault_id: [u8; ID_LEN],
    kdf: KdfParams,
    wrapped_by_password: [u8; WRAPPED_LEN],
    wrapped_by_recovery: [u8; WRAPPED_LEN],
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
        let header = Self {
            vault_id: id,
            wrapped_by_password: wrap(&kek_pw, &data_key, &aad(&id, b"pw", &kdf.to_bytes()))?,
            wrapped_by_recovery: wrap(&kek_rk, &data_key, &aad(&id, b"rk", &[]))?,
            kdf,
        };
        Ok((header, VaultKeys { data_key }, recovery))
    }

    /// Unlock with the Master Password. Wrong password and tampering are indistinguishable.
    pub fn unlock(&self, password: &[u8]) -> Result<VaultKeys> {
        let kek = self.kdf.derive_kek(password)?;
        unwrap_key(
            &kek,
            &self.wrapped_by_password,
            &aad(&self.vault_id, b"pw", &self.kdf.to_bytes()),
        )
    }

    /// Unlock with the Recovery Key.
    pub fn unlock_with_recovery(&self, recovery: &RecoveryKey) -> Result<VaultKeys> {
        let kek = recovery.derive_kek()?;
        unwrap_key(
            &kek,
            &self.wrapped_by_recovery,
            &aad(&self.vault_id, b"rk", &[]),
        )
    }

    /// Enroll this device for quick unlock: generate a [`DeviceKey`] and wrap the data key with it.
    /// The AAD binds magic, format version, vault id and the purpose `"dev"` (not the device id,
    /// so the wrap survives a device-id change). Callers must authenticate the user first.
    pub fn enroll_device(&self, keys: &VaultKeys) -> Result<DeviceEnrollment> {
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
    /// vault, bad length) is the same [`Error::Decryption`].
    pub fn unlock_with_device_key(
        &self,
        device_key: &DeviceKey,
        wrapped: &[u8],
    ) -> Result<VaultKeys> {
        if wrapped.len() != WRAPPED_LEN {
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
        let kek = kdf.derive_kek(new_password)?;
        let wrapped = wrap(
            &kek,
            &keys.data_key,
            &aad(&self.vault_id, b"pw", &kdf.to_bytes()),
        )?;
        Ok(Self {
            kdf,
            wrapped_by_password: wrapped,
            ..self.clone()
        })
    }

    /// Replace the Recovery Key: generate a new one and re-wrap the data key with it. The old
    /// Recovery Key stops working once the returned header is persisted. The data key and the
    /// password wrap are unchanged, so device wraps and sealed blobs stay valid.
    pub fn rotate_recovery(&self, keys: &VaultKeys) -> Result<(Self, RecoveryKey)> {
        let recovery = RecoveryKey::generate()?;
        let kek = recovery.derive_kek()?;
        let wrapped = wrap(&kek, &keys.data_key, &aad(&self.vault_id, b"rk", &[]))?;
        Ok((
            Self {
                wrapped_by_recovery: wrapped,
                ..self.clone()
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
        [
            MAGIC.as_slice(),
            &[FORMAT_VERSION],
            &self.vault_id,
            &self.kdf.to_bytes(),
            &self.wrapped_by_password,
            &self.wrapped_by_recovery,
        ]
        .concat()
    }

    /// Parse a header. Rejects bad magic, unknown versions (incl. downgrades) and bad lengths.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(Error::Corrupted);
        }
        let (magic, rest) = bytes.split_at(4);
        if magic != MAGIC {
            return Err(Error::Corrupted);
        }
        let (ver, rest) = rest.split_at(1);
        if ver != [FORMAT_VERSION] {
            return Err(Error::UnsupportedVersion);
        }
        let (id, rest) = rest.split_at(ID_LEN);
        let (kdf, rest) = rest.split_at(PARAMS_LEN);
        let (wp, wr) = rest.split_at(WRAPPED_LEN);
        Ok(Self {
            vault_id: id.try_into().map_err(|_| Error::Corrupted)?,
            kdf: KdfParams::from_bytes(kdf)?,
            wrapped_by_password: wp.try_into().map_err(|_| Error::Corrupted)?,
            wrapped_by_recovery: wr.try_into().map_err(|_| Error::Corrupted)?,
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
        assert_ne!(h2.kdf, h.kdf);
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
        assert_eq!(h2.wrapped_by_password, h.wrapped_by_password);
        assert_ne!(h2.wrapped_by_recovery, h.wrapped_by_recovery);
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
        let kek = h.kdf.derive_kek(PW).unwrap();
        let as_device = DeviceKey::from_slice(kek.expose()).unwrap();
        assert!(h
            .unlock_with_device_key(&as_device, &h.wrapped_by_password)
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
        v[4] = 2;
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
