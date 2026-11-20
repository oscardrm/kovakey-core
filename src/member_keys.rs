//! Per-member wrapping of a shared vault's data key (no shared password).
//!
//! Each person has an X25519 [`IdentityKey`]. Hosts keep the private key inside the person's own
//! (password-protected) vault and publish the [`MemberPublicKey`] wherever the shared vault
//! syncs. A member vault (see [`VaultHeader::create_member`]) has no password slots: its random
//! data key is sealed separately for every member public key with HPKE base mode (RFC 9180,
//! DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM).
//!
//! Wrap layout (81 bytes): `version u8 = 1 | encapsulated key[32] | ciphertext[32] | tag[16]`.
//! The HPKE `info` binds a domain label, the vault id and the key epoch; the AEAD `aad` binds the
//! recipient's key id. So a wrap only opens for its own member key, vault and epoch: after
//! [`VaultHeader::rekey_members`] every old wrap stops working.
//!
//! Every failure to open a wrap (wrong key, other vault, old epoch, tampering, bad length) is the
//! same [`Error::Decryption`].

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, SecretKey, KEY_LEN};
use crate::error::{Error, Result};
use crate::keys::{VaultHeader, VaultKeys};
use crate::models::Snapshot;
use crate::vault_file::{self, SealedVault};

type Suite = X25519HkdfSha256;
type PrivateKey = <Suite as Kem>::PrivateKey;
type PublicKey = <Suite as Kem>::PublicKey;
type EncappedKey = <Suite as Kem>::EncappedKey;

/// Length of a serialized identity private key or member public key.
pub const MEMBER_KEY_LEN: usize = 32;
const ENC_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WRAP_VERSION: u8 = 1;
/// Length of a member wrap.
pub const WRAP_LEN: usize = 1 + ENC_LEN + KEY_LEN + TAG_LEN;
const KEY_ID_LEN: usize = 16;
const INFO_LABEL: &[u8] = b"kovakey/member-wrap/v1";
const KEY_ID_LABEL: &[u8] = b"kovakey/member-key/v1";

/// A person's private identity key. Zeroized on drop; `Debug` is redacted; not `Clone`.
pub struct IdentityKey {
    sk: PrivateKey,
    pk: PublicKey,
}

impl IdentityKey {
    /// Generate a fresh identity key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut ikm = Zeroizing::new([0u8; KEY_LEN]);
        crypto::fill_random(ikm.as_mut())?;
        let (sk, pk) = Suite::derive_keypair(ikm.as_ref());
        Ok(Self { sk, pk })
    }

    /// Rebuild from the bytes returned by [`IdentityKey::to_bytes`]. Wrong length or an invalid
    /// key is [`Error::Corrupted`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MEMBER_KEY_LEN {
            return Err(Error::Corrupted);
        }
        let sk = PrivateKey::from_bytes(bytes).map_err(|_| Error::Corrupted)?;
        let pk = Suite::sk_to_pk(&sk);
        Ok(Self { sk, pk })
    }

    /// The private key bytes, for storing inside the owner's own encrypted vault only.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut raw = self.sk.to_bytes();
        let out = Zeroizing::new(raw.to_vec());
        raw.as_mut_slice().zeroize();
        out
    }

    /// The matching public key, safe to publish.
    pub fn public_key(&self) -> MemberPublicKey {
        MemberPublicKey(self.pk.clone())
    }
}

impl core::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentityKey(<redacted>)")
    }
}

/// A member's public key (not secret).
#[derive(Clone)]
pub struct MemberPublicKey(PublicKey);

impl MemberPublicKey {
    /// Parse a published public key. Wrong length is [`Error::Corrupted`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MEMBER_KEY_LEN {
            return Err(Error::Corrupted);
        }
        PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::Corrupted)
    }

    /// Serialized public key ([`MEMBER_KEY_LEN`] bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Stable, non-secret id of this key: the first 16 bytes of
    /// SHA-256("kovakey/member-key/v1" || public key), lowercase hex (32 chars).
    pub fn key_id(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.key_id_bytes())
    }

    fn key_id_bytes(&self) -> [u8; KEY_ID_LEN] {
        let digest = Sha256::new()
            .chain_update(KEY_ID_LABEL)
            .chain_update(self.0.to_bytes())
            .finalize();
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(digest.get(..KEY_ID_LEN).unwrap_or(&[0u8; KEY_ID_LEN]));
        id
    }
}

impl core::fmt::Debug for MemberPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MemberPublicKey({})", self.key_id())
    }
}

impl PartialEq for MemberPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for MemberPublicKey {}

fn info(header: &VaultHeader) -> Result<Vec<u8>> {
    let epoch = header.member_epoch()?;
    Ok([INFO_LABEL, header.vault_id(), &epoch.to_be_bytes()].concat())
}

/// The OS CSPRNG behind the `rand_core` traits HPKE needs. `fill_bytes` cannot fail by
/// signature, so a failure zeroes the output and is reported through [`SealRng::failed`]; the
/// caller then discards everything that was produced.
struct SealRng {
    failed: bool,
}

impl RngCore for SealRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        if crypto::fill_random(dst).is_err() {
            dst.zeroize();
            self.failed = true;
        }
    }
}

impl CryptoRng for SealRng {}

/// Seal `keys` (the data key of the member vault `header`) for `member`. Returns a
/// [`WRAP_LEN`]-byte wrap to publish next to the vault. A password vault is
/// [`Error::InvalidInput`]; an invalid (e.g. low-order) public key is [`Error::Corrupted`].
pub fn wrap_data_key(
    header: &VaultHeader,
    keys: &VaultKeys,
    member: &MemberPublicKey,
) -> Result<Vec<u8>> {
    let info = info(header)?;
    let mut rng = SealRng { failed: false };
    let sealed = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Suite, _>(
        &OpModeS::Base,
        &member.0,
        &info,
        keys.data_key().expose(),
        &member.key_id_bytes(),
        &mut rng,
    );
    if rng.failed {
        return Err(Error::Rng);
    }
    let (enc, ct) = sealed.map_err(|_| Error::Corrupted)?;
    let wrap = [&[WRAP_VERSION][..], enc.to_bytes().as_slice(), &ct].concat();
    if wrap.len() == WRAP_LEN {
        Ok(wrap)
    } else {
        Err(Error::Corrupted)
    }
}

/// Open a wrap made by [`wrap_data_key`] with the member's own identity key. Every failure is
/// [`Error::Decryption`].
pub fn unwrap_data_key(
    header: &VaultHeader,
    identity: &IdentityKey,
    wrap: &[u8],
) -> Result<VaultKeys> {
    let info = info(header).map_err(|_| Error::Decryption)?;
    if wrap.len() != WRAP_LEN || wrap.first() != Some(&WRAP_VERSION) {
        return Err(Error::Decryption);
    }
    let enc_bytes = wrap.get(1..1 + ENC_LEN).ok_or(Error::Decryption)?;
    let ct = wrap.get(1 + ENC_LEN..).ok_or(Error::Decryption)?;
    let enc = EncappedKey::from_bytes(enc_bytes).map_err(|_| Error::Decryption)?;
    let pt = Zeroizing::new(
        hpke::single_shot_open::<AesGcm256, HkdfSha256, Suite>(
            &OpModeR::Base,
            &identity.sk,
            &enc,
            &info,
            ct,
            &identity.public_key().key_id_bytes(),
        )
        .map_err(|_| Error::Decryption)?,
    );
    let bytes: [u8; KEY_LEN] = pt.as_slice().try_into().map_err(|_| Error::Decryption)?;
    Ok(VaultKeys::from_data_key(SecretKey::from_bytes(bytes)))
}

/// A re-keyed member vault: the new file (and side blobs) under the next epoch, plus a fresh wrap
/// for every member key that keeps access, in the order given.
#[derive(Debug)]
pub struct Rekeyed {
    /// The new header (next epoch). Old wraps no longer open it.
    pub header: VaultHeader,
    /// The `.vault` file sealed under the new data key.
    pub sealed: SealedVault,
    /// One wrap per member key passed in, same order.
    pub wraps: Vec<Vec<u8>>,
}

/// Re-key a member vault holding `snapshot` (used after removing a member): a fresh data key,
/// the next epoch, the snapshot sealed under it and new wraps for `members` only.
pub fn rekey(
    header: &VaultHeader,
    snapshot: &Snapshot,
    members: &[MemberPublicKey],
) -> Result<Rekeyed> {
    let (header, keys) = header.rekey_members()?;
    let sealed = vault_file::seal_vault(&header, &keys, snapshot)?;
    let wraps = members
        .iter()
        .map(|m| wrap_data_key(&header, &keys, m))
        .collect::<Result<_>>()?;
    Ok(Rekeyed {
        header,
        sealed,
        wraps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::fixtures::sample;
    use crate::kdf::KdfParams;

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    /// RFC 9180 test vector for mode Base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
    /// AES-256-GCM (kem 0x20, kdf 1, aead 2), first encryption.
    #[test]
    fn hpke_suite_matches_rfc9180_known_answer() {
        let (sk, pk) = Suite::derive_keypair(&hex(
            "dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee",
        ));
        assert_eq!(
            sk.to_bytes().to_vec(),
            hex("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d")
        );
        assert_eq!(
            pk.to_bytes().to_vec(),
            hex("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c")
        );
        let enc = EncappedKey::from_bytes(&hex(
            "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
        ))
        .unwrap();
        let pt = hpke::single_shot_open::<AesGcm256, HkdfSha256, Suite>(
            &OpModeR::Base,
            &sk,
            &enc,
            &hex("4f6465206f6e2061204772656369616e2055726e"),
            &hex("e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a"),
            &hex("436f756e742d30"),
        )
        .unwrap();
        assert_eq!(
            pt,
            hex("4265617574792069732074727574682c20747275746820626561757479")
        );
    }

    fn member_vault() -> (VaultHeader, VaultKeys) {
        VaultHeader::create_member().unwrap()
    }

    #[test]
    fn wrap_round_trips_to_the_same_data_key() {
        let (h, k) = member_vault();
        let id = IdentityKey::generate().unwrap();
        let w = wrap_data_key(&h, &k, &id.public_key()).unwrap();
        assert_eq!(w.len(), WRAP_LEN);
        let got = unwrap_data_key(&h, &id, &w).unwrap();
        assert_eq!(got.data_key().expose(), k.data_key().expose());
    }

    #[test]
    fn wrap_does_not_contain_the_data_key_and_is_fresh_each_time() {
        let (h, k) = member_vault();
        let id = IdentityKey::generate().unwrap();
        let (a, b) = (
            wrap_data_key(&h, &k, &id.public_key()).unwrap(),
            wrap_data_key(&h, &k, &id.public_key()).unwrap(),
        );
        assert_ne!(a, b);
        let dk = k.data_key().expose();
        assert!(!a.windows(dk.len()).any(|w| w == dk));
    }

    #[test]
    fn a_wrap_only_opens_for_its_own_member() {
        let (h, k) = member_vault();
        let (alice, bob) = (
            IdentityKey::generate().unwrap(),
            IdentityKey::generate().unwrap(),
        );
        let w = wrap_data_key(&h, &k, &alice.public_key()).unwrap();
        assert_eq!(
            unwrap_data_key(&h, &bob, &w).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn a_wrap_does_not_open_for_another_vault_or_epoch() {
        let (h, k) = member_vault();
        let (other, _) = member_vault();
        let id = IdentityKey::generate().unwrap();
        let w = wrap_data_key(&h, &k, &id.public_key()).unwrap();
        assert_eq!(
            unwrap_data_key(&other, &id, &w).unwrap_err(),
            Error::Decryption
        );
        let (next, _) = h.rekey_members().unwrap();
        assert_eq!(
            unwrap_data_key(&next, &id, &w).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn tampering_with_any_wrap_byte_or_length_fails() {
        let (h, k) = member_vault();
        let id = IdentityKey::generate().unwrap();
        let w = wrap_data_key(&h, &k, &id.public_key()).unwrap();
        for i in 0..w.len() {
            let mut t = w.clone();
            t[i] ^= 0x01;
            assert_eq!(
                unwrap_data_key(&h, &id, &t).unwrap_err(),
                Error::Decryption,
                "byte {i}"
            );
        }
        for len in [0, 1, WRAP_LEN - 1] {
            assert_eq!(
                unwrap_data_key(&h, &id, &w[..len]).unwrap_err(),
                Error::Decryption
            );
        }
        let mut longer = w.clone();
        longer.push(0);
        assert_eq!(
            unwrap_data_key(&h, &id, &longer).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn password_vaults_have_no_member_wraps() {
        let (h, k, _) =
            VaultHeader::create_with(b"fake-pass-for-tests", KdfParams::for_tests()).unwrap();
        let id = IdentityKey::generate().unwrap();
        assert_eq!(
            wrap_data_key(&h, &k, &id.public_key()).unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(
            unwrap_data_key(&h, &id, &[0u8; WRAP_LEN]).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn identity_key_round_trips_and_is_redacted() {
        let id = IdentityKey::generate().unwrap();
        let again = IdentityKey::from_bytes(&id.to_bytes()).unwrap();
        assert_eq!(again.public_key(), id.public_key());
        assert_eq!(format!("{id:?}"), "IdentityKey(<redacted>)");
        assert!(IdentityKey::from_bytes(&[1u8; 31]).is_err());
        assert!(IdentityKey::from_bytes(&[1u8; 33]).is_err());
    }

    #[test]
    fn public_key_parses_and_has_a_stable_key_id() {
        let id = IdentityKey::generate().unwrap();
        let pk = id.public_key();
        let parsed = MemberPublicKey::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(parsed, pk);
        assert_eq!(parsed.key_id(), pk.key_id());
        assert_eq!(pk.key_id().len(), 32);
        assert_ne!(
            pk.key_id(),
            IdentityKey::generate().unwrap().public_key().key_id()
        );
        assert!(MemberPublicKey::from_bytes(&[1u8; 31]).is_err());
    }

    #[test]
    fn low_order_public_key_cannot_receive_a_wrap() {
        let (h, k) = member_vault();
        // The all-zero point is low order: the DH output is zero and HPKE must refuse it.
        let zero = MemberPublicKey::from_bytes(&[0u8; MEMBER_KEY_LEN]).unwrap();
        assert!(wrap_data_key(&h, &k, &zero).is_err());
    }

    #[test]
    fn member_vault_file_opens_through_a_wrap() {
        let (h, k) = member_vault();
        let id = IdentityKey::generate().unwrap();
        let snap = sample(true);
        let sealed = vault_file::seal_vault(&h, &k, &snap).unwrap();
        let w = wrap_data_key(&h, &k, &id.public_key()).unwrap();
        let header = vault_file::read_header(&sealed.file).unwrap();
        assert!(header.is_member());
        let keys = unwrap_data_key(&header, &id, &w).unwrap();
        let blobs: std::collections::HashMap<_, _> = sealed
            .side_blobs
            .iter()
            .map(|b| (b.name.clone(), b.sealed.clone()))
            .collect();
        let opened =
            vault_file::open_vault(&sealed.file, &keys, &|n| blobs.get(n).cloned()).unwrap();
        assert_eq!(opened, snap);
    }

    #[test]
    fn rekey_locks_out_removed_members_and_old_keys() {
        let (h, k) = member_vault();
        let (alice, bob) = (
            IdentityKey::generate().unwrap(),
            IdentityKey::generate().unwrap(),
        );
        let snap = sample(true);
        let old_bob_wrap = wrap_data_key(&h, &k, &bob.public_key()).unwrap();

        let r = rekey(&h, &snap, &[alice.public_key()]).unwrap();
        assert_eq!(r.header.vault_id(), h.vault_id());
        assert_eq!(r.header.member_epoch().unwrap(), 1);
        assert_eq!(r.wraps.len(), 1);

        let header = vault_file::read_header(&r.sealed.file).unwrap();
        let keys = unwrap_data_key(&header, &alice, &r.wraps[0]).unwrap();
        assert_ne!(keys.data_key().expose(), k.data_key().expose());
        let blobs: std::collections::HashMap<_, _> = r
            .sealed
            .side_blobs
            .iter()
            .map(|b| (b.name.clone(), b.sealed.clone()))
            .collect();
        assert_eq!(
            vault_file::open_vault(&r.sealed.file, &keys, &|n| blobs.get(n).cloned()).unwrap(),
            snap
        );
        // Bob's old wrap and the old data key no longer open the new file.
        assert_eq!(
            unwrap_data_key(&header, &bob, &old_bob_wrap).unwrap_err(),
            Error::Decryption
        );
        assert!(vault_file::open_vault(&r.sealed.file, &k, &|n| blobs.get(n).cloned()).is_err());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]
        /// Any data key wrapped for any member opens to the same key, and only for that member.
        #[test]
        fn wrap_unwrap_is_identity_for_any_key(dk in proptest::array::uniform32(proptest::num::u8::ANY)) {
            let (h, _) = member_vault();
            let keys = VaultKeys::from_data_key(SecretKey::from_bytes(dk));
            let (id, other) = (IdentityKey::generate().unwrap(), IdentityKey::generate().unwrap());
            let w = wrap_data_key(&h, &keys, &id.public_key()).unwrap();
            let opened = unwrap_data_key(&h, &id, &w).unwrap();
            proptest::prop_assert_eq!(opened.data_key().expose(), &dk);
            proptest::prop_assert!(unwrap_data_key(&h, &other, &w).is_err());
        }
    }

    #[test]
    fn member_header_round_trips_and_rejects_tampering() {
        let (h, _) = member_vault();
        let b = h.to_bytes();
        assert_eq!(b.len(), crate::keys::MEMBER_HEADER_LEN);
        assert_eq!(VaultHeader::from_bytes(&b).unwrap(), h);
        assert!(VaultHeader::from_bytes(&b[..b.len() - 1]).is_err());
        let mut v = b.clone();
        v[4] = 9;
        assert_eq!(
            VaultHeader::from_bytes(&v).unwrap_err(),
            Error::UnsupportedVersion
        );
        // A member header has no password, Recovery Key or device unlock.
        assert_eq!(h.unlock(b"anything").unwrap_err(), Error::InvalidInput);
        let (_, k) = member_vault();
        assert_eq!(h.enroll_device(&k).unwrap_err(), Error::InvalidInput);
    }

    #[test]
    fn payload_cannot_move_to_another_epoch_header() {
        let (h, k) = member_vault();
        let sealed = vault_file::seal_vault(&h, &k, &sample(true)).unwrap();
        let (next, _) = h.rekey_members().unwrap();
        // Same data key, but the stored header differs: the payload AAD must not match.
        let mut forged = next.to_bytes();
        forged.extend_from_slice(&sealed.file[crate::keys::MEMBER_HEADER_LEN..]);
        assert_eq!(
            vault_file::open_vault(&forged, &k, &|_| None).unwrap_err(),
            Error::Decryption
        );
    }
}
