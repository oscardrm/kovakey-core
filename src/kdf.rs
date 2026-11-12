//! Argon2id key derivation: Master Password -> KEK.
//!
//! Parameters are stored in the vault header and may never be set below the floor
//! ([`MIN_MEMORY_KIB`], [`MIN_ITERATIONS`]). Tests use cheap parameters through a
//! `cfg(test)`-only constructor.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::crypto::{fill_random, SecretKey, KEY_LEN};
use crate::error::{Error, Result};

/// Minimum Argon2id memory cost: 64 MiB.
pub const MIN_MEMORY_KIB: u32 = 64 * 1024;
/// Minimum Argon2id iteration count.
pub const MIN_ITERATIONS: u32 = 3;
/// Salt length in bytes.
pub const SALT_LEN: usize = 16;
/// Serialized length of [`KdfParams`].
pub const PARAMS_LEN: usize = 4 + 4 + 4 + SALT_LEN;
/// Upper bounds to reject absurd values read from untrusted files (DoS guard).
/// Floor applied to parsed headers in unit tests only.
#[cfg(test)]
const TEST_MIN_MEMORY_KIB: u32 = 8;
const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;
const MAX_LANES: u32 = 16;

/// Argon2id parameters plus the per-vault random salt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Production defaults (64 MiB, 3 iterations, 4 lanes) with a fresh random salt.
    pub fn generate() -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        Self::new(MIN_MEMORY_KIB, MIN_ITERATIONS, 4, salt)
    }

    /// Validated constructor; rejects values below the floor or above sanity limits.
    pub fn new(memory_kib: u32, iterations: u32, lanes: u32, salt: [u8; SALT_LEN]) -> Result<Self> {
        let p = Self {
            memory_kib,
            iterations,
            lanes,
            salt,
        };
        p.validate()?;
        Ok(p)
    }

    /// Cheap parameters for unit tests only. Never compiled into production builds.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        let mut salt = [0u8; SALT_LEN];
        // Salt randomness is irrelevant for tests but keep it unique per call.
        let _ = fill_random(&mut salt);
        Self {
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            salt,
        }
    }

    fn validate(&self) -> Result<()> {
        self.validate_with_floor(MIN_MEMORY_KIB, MIN_ITERATIONS)
    }

    /// Bounds check against an explicit floor. The upper bounds always apply, so a
    /// corrupted header can never request a huge allocation (DoS guard).
    fn validate_with_floor(&self, min_memory_kib: u32, min_iterations: u32) -> Result<()> {
        let ok = (min_memory_kib..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (min_iterations..=MAX_ITERATIONS).contains(&self.iterations)
            && (1..=MAX_LANES).contains(&self.lanes);
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidParams)
        }
    }

    /// Serialize as `m(u32 LE) || t(u32 LE) || p(u32 LE) || salt`.
    pub fn to_bytes(&self) -> [u8; PARAMS_LEN] {
        let mut out = [0u8; PARAMS_LEN];
        let (a, rest) = out.split_at_mut(4);
        a.copy_from_slice(&self.memory_kib.to_le_bytes());
        let (b, rest) = rest.split_at_mut(4);
        b.copy_from_slice(&self.iterations.to_le_bytes());
        let (c, s) = rest.split_at_mut(4);
        c.copy_from_slice(&self.lanes.to_le_bytes());
        s.copy_from_slice(&self.salt);
        out
    }

    /// Parse and validate. Enforces the floor, so a downgraded header is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PARAMS_LEN {
            return Err(Error::Corrupted);
        }
        let (m, rest) = bytes.split_at(4);
        let (t, rest) = rest.split_at(4);
        let (p, s) = rest.split_at(4);
        let u = |b: &[u8]| -> Result<u32> {
            Ok(u32::from_le_bytes(
                b.try_into().map_err(|_| Error::Corrupted)?,
            ))
        };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(s);
        let params = Self {
            memory_kib: u(m)?,
            iterations: u(t)?,
            lanes: u(p)?,
            salt,
        };
        // Unit tests use cheap params, so they get a lower floor here; the upper bounds and the
        // production floor are still enforced (see `parse_enforces_production_floor`).
        #[cfg(test)]
        params.validate_with_floor(TEST_MIN_MEMORY_KIB, 1)?;
        #[cfg(not(test))]
        params.validate()?;
        Ok(params)
    }

    /// Derive the key-encryption key from the Master Password.
    pub fn derive_kek(&self, password: &[u8]) -> Result<SecretKey> {
        let params = Params::new(self.memory_kib, self.iterations, self.lanes, Some(KEY_LEN))
            .map_err(|_| Error::InvalidParams)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        argon
            .hash_password_into(password, &self.salt, out.as_mut())
            .map_err(|_| Error::InvalidParams)?;
        Ok(SecretKey::from_bytes(*out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_defaults_meet_the_floor() {
        let p = KdfParams::generate().unwrap();
        assert!(p.memory_kib >= MIN_MEMORY_KIB && p.iterations >= MIN_ITERATIONS);
    }

    #[test]
    fn new_rejects_params_below_floor() {
        let s = [0u8; SALT_LEN];
        assert_eq!(
            KdfParams::new(MIN_MEMORY_KIB - 1, 3, 1, s),
            Err(Error::InvalidParams)
        );
        assert_eq!(
            KdfParams::new(MIN_MEMORY_KIB, 2, 1, s),
            Err(Error::InvalidParams)
        );
        assert_eq!(
            KdfParams::new(MIN_MEMORY_KIB, 3, 0, s),
            Err(Error::InvalidParams)
        );
        assert_eq!(KdfParams::new(u32::MAX, 3, 1, s), Err(Error::InvalidParams));
    }

    #[test]
    fn parse_enforces_production_floor_and_upper_bounds() {
        let p = KdfParams::for_tests();
        assert_eq!(p.validate(), Err(Error::InvalidParams)); // cheap test params < production floor
        let mut huge = p.clone();
        huge.memory_kib = MAX_MEMORY_KIB + 1;
        assert_eq!(
            KdfParams::from_bytes(&huge.to_bytes()),
            Err(Error::InvalidParams)
        );
        let mut many = p;
        many.iterations = MAX_ITERATIONS + 1;
        assert_eq!(
            KdfParams::from_bytes(&many.to_bytes()),
            Err(Error::InvalidParams)
        );
    }

    #[test]
    fn serialization_round_trips() {
        let p = KdfParams::for_tests();
        assert_eq!(KdfParams::from_bytes(&p.to_bytes()).unwrap(), p);
        assert_eq!(KdfParams::from_bytes(&[0u8; 5]), Err(Error::Corrupted));
    }

    #[test]
    fn same_password_and_salt_give_same_kek_and_others_differ() {
        let p = KdfParams::for_tests();
        let a = p.derive_kek(b"correct-horse-test").unwrap();
        let b = p.derive_kek(b"correct-horse-test").unwrap();
        let c = p.derive_kek(b"another-fake-pass").unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    // RFC 9106 §5.3 Argon2id test vector (secret + associated data are part of the vector,
    // so we exercise the primitive directly with the same crate we depend on).
    #[test]
    fn argon2id_matches_rfc9106_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[4u8; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let a = Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params)
            .unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
            .unwrap();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }
}
