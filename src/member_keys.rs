//! Per-member wrapping of a shared vault's data key (no shared password).
//!
//! Each person has an X25519 [`IdentityKey`]. Hosts keep the private key inside the person's own
//! (password-protected) vault and publish the [`MemberPublicKey`] wherever the shared vault
//! syncs. A member vault (see [`VaultHeader::create_member`]) has no password slots: its random
//! data key is sealed separately for every member public key with HPKE **Auth** mode (RFC 9180,
//! DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM), so every wrap is also authenticated
//! by the identity key of the member who made it.
//!
//! Wrap layout (97 bytes): `version u8 = 2 | sender key id[16] | encapsulated key[32] |
//! ciphertext[32] | tag[16]`. The HPKE `info` binds a domain label, the vault id and the key
//! epoch; the AEAD `aad` binds the recipient's and the sender's key ids. A wrap only opens for its
//! own recipient, vault and epoch, and only when its sender is one of the member keys the host
//! trusts: someone who can write to the sync store but holds no trusted identity key cannot forge
//! a wrap (or a re-keyed vault) that members would adopt. After [`VaultHeader::rekey_members`]
//! every old wrap stops working.
//!
//! Every failure to open a wrap (wrong key, untrusted sender, other vault, old epoch, tampering,
//! bad length) is the same [`Error::Decryption`].
//!
//! Limits: like any static-key Auth mode, it is open to key-compromise impersonation: whoever
//! steals a member's private key can make wraps *to that member* that look as if a trusted sender
//! made them (the key is in that member's password-protected vault, so this needs the vault
//! already). Wrap v1 (base mode) was never published by a release, so v1 wraps are not read.

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
const WRAP_VERSION: u8 = 2;
const KEY_ID_LEN: usize = 16;
/// Length of a member wrap.
pub const WRAP_LEN: usize = 1 + KEY_ID_LEN + ENC_LEN + KEY_LEN + TAG_LEN;
const INFO_LABEL: &[u8] = b"kovakey/member-wrap/v2";
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

fn wrap_aad(recipient: &MemberPublicKey, sender_id: &[u8; KEY_ID_LEN]) -> Vec<u8> {
    [recipient.key_id_bytes().as_slice(), sender_id].concat()
}

/// The OS CSPRNG behind the `rand_core` traits HPKE needs. `fill_bytes` cannot fail by
/// signature, so a failure zeroes the output and is reported through [`SealRng::failed`]; the
/// caller then discards everything that was produced.
struct SealRng {
    failed: bool,
    fill: fn(&mut [u8]) -> Result<()>,
}

impl SealRng {
    fn os() -> Self {
        Self {
            failed: false,
            fill: crypto::fill_random,
        }
    }
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
        if (self.fill)(dst).is_err() {
            dst.zeroize();
            self.failed = true;
        }
    }
}

impl CryptoRng for SealRng {}

/// Seal `keys` (the data key of the member vault `header`) for `member`, authenticated by the
/// `sender`'s identity key. Returns a [`WRAP_LEN`]-byte wrap to publish next to the vault. A
/// password vault is [`Error::InvalidInput`]; an invalid (e.g. low-order) public key is
/// [`Error::Corrupted`].
pub fn wrap_data_key(
    header: &VaultHeader,
    keys: &VaultKeys,
    sender: &IdentityKey,
    member: &MemberPublicKey,
) -> Result<Vec<u8>> {
    wrap_with(header, keys, sender, member, &mut SealRng::os())
}

fn wrap_with(
    header: &VaultHeader,
    keys: &VaultKeys,
    sender: &IdentityKey,
    member: &MemberPublicKey,
    rng: &mut SealRng,
) -> Result<Vec<u8>> {
    let info = info(header)?;
    let sender_id = sender.public_key().key_id_bytes();
    let sealed = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Suite, _>(
        &OpModeS::Auth((sender.sk.clone(), sender.pk.clone())),
        &member.0,
        &info,
        keys.data_key().expose(),
        &wrap_aad(member, &sender_id),
        rng,
    );
    if rng.failed {
        return Err(Error::Rng);
    }
    let (enc, ct) = sealed.map_err(|_| Error::Corrupted)?;
    let wrap = [
        &[WRAP_VERSION][..],
        &sender_id,
        enc.to_bytes().as_slice(),
        &ct,
    ]
    .concat();
    if wrap.len() == WRAP_LEN {
        Ok(wrap)
    } else {
        Err(Error::Corrupted)
    }
}

/// Key id of the member who made `wrap` (lowercase hex), so a host can tell whom it came from
/// before trusting it. A malformed wrap is [`Error::Decryption`].
pub fn wrap_sender_key_id(wrap: &[u8]) -> Result<String> {
    if wrap.len() != WRAP_LEN || wrap.first() != Some(&WRAP_VERSION) {
        return Err(Error::Decryption);
    }
    let id = wrap.get(1..1 + KEY_ID_LEN).ok_or(Error::Decryption)?;
    Ok(data_encoding::HEXLOWER.encode(id))
}

/// Open a wrap made by [`wrap_data_key`] with the member's own identity key. The wrap's sender
/// must be one of `trusted_senders` (the member keys the host accepts for this vault, which
/// should include this member's own key). Every failure is [`Error::Decryption`].
pub fn unwrap_data_key(
    header: &VaultHeader,
    identity: &IdentityKey,
    wrap: &[u8],
    trusted_senders: &[MemberPublicKey],
) -> Result<VaultKeys> {
    let info = info(header).map_err(|_| Error::Decryption)?;
    if wrap.len() != WRAP_LEN || wrap.first() != Some(&WRAP_VERSION) {
        return Err(Error::Decryption);
    }
    let sender_id: [u8; KEY_ID_LEN] = wrap
        .get(1..1 + KEY_ID_LEN)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Decryption)?;
    let sender = trusted_senders
        .iter()
        .find(|k| k.key_id_bytes() == sender_id)
        .ok_or(Error::Decryption)?;
    let enc_start = 1 + KEY_ID_LEN;
    let enc_bytes = wrap
        .get(enc_start..enc_start + ENC_LEN)
        .ok_or(Error::Decryption)?;
    let ct = wrap.get(enc_start + ENC_LEN..).ok_or(Error::Decryption)?;
    let enc = EncappedKey::from_bytes(enc_bytes).map_err(|_| Error::Decryption)?;
    let pt = Zeroizing::new(
        hpke::single_shot_open::<AesGcm256, HkdfSha256, Suite>(
            &OpModeR::Auth(sender.0.clone()),
            &identity.sk,
            &enc,
            &info,
            ct,
            &wrap_aad(&identity.public_key(), &sender_id),
        )
        .map_err(|_| Error::Decryption)?,
    );
    let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
    if pt.len() != KEY_LEN {
        return Err(Error::Decryption);
    }
    bytes.copy_from_slice(&pt);
    Ok(VaultKeys::from_data_key(SecretKey::from_bytes(*bytes)))
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
/// the next epoch, the snapshot sealed under it and new wraps (made by `sender`) for `members`
/// only.
pub fn rekey(
    header: &VaultHeader,
    snapshot: &Snapshot,
    sender: &IdentityKey,
    members: &[MemberPublicKey],
) -> Result<Rekeyed> {
    let (header, keys) = header.rekey_members()?;
    let sealed = vault_file::seal_vault(&header, &keys, snapshot)?;
    let wraps = members
        .iter()
        .map(|m| wrap_data_key(&header, &keys, sender, m))
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
    use std::collections::HashMap;

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    /// RFC 9180 test vector for mode Base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
    /// AES-256-GCM (kem 0x20, kdf 1, aead 2), first encryption.
    #[test]
    fn hpke_base_suite_matches_rfc9180_known_answer() {
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

    /// RFC 9180 test vector for mode Auth (mode 2) of the same suite: the mode the wraps use.
    #[test]
    fn hpke_auth_suite_matches_rfc9180_known_answer() {
        let (sk_r, _) = Suite::derive_keypair(&hex(
            "f59761a1e479c2a291b91a5af2b35dd2cace1b2042b570f88a16b226f6f30774",
        ));
        assert_eq!(
            sk_r.to_bytes().to_vec(),
            hex("47f1eee3670dfaaf27c30a83d06ee9f257af174727c17b35328ef730dfc1cd81")
        );
        let (_, pk_s) = Suite::derive_keypair(&hex(
            "87137373fe6b28a72534f38048b9467a614d3566fb3a16a50fcaf11c76051392",
        ));
        assert_eq!(
            pk_s.to_bytes().to_vec(),
            hex("4a91c3d0893433f5e31a79fc520f885527a1bc60bf2b0c72693dd7f0b2e41a5a")
        );
        let enc = EncappedKey::from_bytes(&hex(
            "9e59f4b1fa5c876f684765290c34e51145894cc4f244342b9fb1a4bdfd8bb426",
        ))
        .unwrap();
        let pt = hpke::single_shot_open::<AesGcm256, HkdfSha256, Suite>(
            &OpModeR::Auth(pk_s),
            &sk_r,
            &enc,
            &hex("4f6465206f6e2061204772656369616e2055726e"),
            &hex("10b964283ac2cc0bdc4c85ab617291b446bf3832e9359b2c3a0facc50ea75a3c1afd08aeaacd6041d02eb560ec"),
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

    fn id() -> IdentityKey {
        IdentityKey::generate().unwrap()
    }

    fn blobs(s: &SealedVault) -> HashMap<String, Vec<u8>> {
        s.side_blobs
            .iter()
            .map(|b| (b.name.clone(), b.sealed.clone()))
            .collect()
    }

    #[test]
    fn wrap_round_trips_to_the_same_data_key() {
        let (h, k) = member_vault();
        let (owner, bob) = (id(), id());
        let w = wrap_data_key(&h, &k, &owner, &bob.public_key()).unwrap();
        assert_eq!(w.len(), WRAP_LEN);
        assert_eq!(wrap_sender_key_id(&w).unwrap(), owner.public_key().key_id());
        let got = unwrap_data_key(&h, &bob, &w, &[owner.public_key()]).unwrap();
        assert_eq!(got.data_key().expose(), k.data_key().expose());
        // A self-wrap: the member is also the sender.
        let mine = wrap_data_key(&h, &k, &owner, &owner.public_key()).unwrap();
        assert!(unwrap_data_key(&h, &owner, &mine, &[owner.public_key()]).is_ok());
    }

    #[test]
    fn wrap_does_not_contain_the_data_key_and_is_fresh_each_time() {
        let (h, k) = member_vault();
        let (owner, bob) = (id(), id());
        let a = wrap_data_key(&h, &k, &owner, &bob.public_key()).unwrap();
        let b = wrap_data_key(&h, &k, &owner, &bob.public_key()).unwrap();
        assert_ne!(a, b);
        let dk = k.data_key().expose();
        assert!(!a.windows(dk.len()).any(|w| w == dk));
    }

    #[test]
    fn a_wrap_only_opens_for_its_own_member() {
        let (h, k) = member_vault();
        let (owner, alice, bob) = (id(), id(), id());
        let w = wrap_data_key(&h, &k, &owner, &alice.public_key()).unwrap();
        assert_eq!(
            unwrap_data_key(&h, &bob, &w, &[owner.public_key()]).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn a_wrap_from_an_untrusted_sender_does_not_open() {
        // Someone who can write to the sync store but holds no trusted identity key forges a
        // vault key for a member: the member refuses it.
        let (h, k) = member_vault();
        let (owner, mallory, bob) = (id(), id(), id());
        let forged = wrap_data_key(&h, &k, &mallory, &bob.public_key()).unwrap();
        assert_eq!(
            unwrap_data_key(&h, &bob, &forged, &[owner.public_key(), bob.public_key()])
                .unwrap_err(),
            Error::Decryption
        );
        // Relabelling the forged wrap with a trusted sender's id does not help: the HPKE
        // authentication (and the AAD) still bind Mallory's key.
        let mut relabelled = forged.clone();
        relabelled[1..1 + KEY_ID_LEN].copy_from_slice(&owner.public_key().key_id_bytes());
        assert_eq!(
            unwrap_data_key(&h, &bob, &relabelled, &[owner.public_key()]).unwrap_err(),
            Error::Decryption
        );
        // An empty trust list opens nothing.
        let real = wrap_data_key(&h, &k, &owner, &bob.public_key()).unwrap();
        assert_eq!(
            unwrap_data_key(&h, &bob, &real, &[]).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn a_wrap_does_not_open_for_another_vault_or_epoch() {
        let (h, k) = member_vault();
        let (other, _) = member_vault();
        let (owner, bob) = (id(), id());
        let trust = [owner.public_key()];
        let w = wrap_data_key(&h, &k, &owner, &bob.public_key()).unwrap();
        assert_eq!(
            unwrap_data_key(&other, &bob, &w, &trust).unwrap_err(),
            Error::Decryption
        );
        let (next, _) = h.rekey_members().unwrap();
        assert_eq!(
            unwrap_data_key(&next, &bob, &w, &trust).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn tampering_with_any_wrap_byte_or_length_fails() {
        let (h, k) = member_vault();
        let (owner, bob) = (id(), id());
        let trust = [owner.public_key()];
        let w = wrap_data_key(&h, &k, &owner, &bob.public_key()).unwrap();
        for i in 0..w.len() {
            let mut t = w.clone();
            t[i] ^= 0x01;
            assert_eq!(
                unwrap_data_key(&h, &bob, &t, &trust).unwrap_err(),
                Error::Decryption,
                "byte {i}"
            );
        }
        for len in [0, 1, WRAP_LEN - 1] {
            assert_eq!(
                unwrap_data_key(&h, &bob, &w[..len], &trust).unwrap_err(),
                Error::Decryption
            );
        }
        let mut longer = w.clone();
        longer.push(0);
        assert_eq!(
            unwrap_data_key(&h, &bob, &longer, &trust).unwrap_err(),
            Error::Decryption
        );
        assert_eq!(wrap_sender_key_id(&longer).unwrap_err(), Error::Decryption);
    }

    #[test]
    fn rng_failure_discards_the_wrap() {
        let (h, k) = member_vault();
        let (owner, bob) = (id(), id());
        let mut broken = SealRng {
            failed: false,
            fill: |_| Err(Error::Rng),
        };
        assert_eq!(
            wrap_with(&h, &k, &owner, &bob.public_key(), &mut broken).unwrap_err(),
            Error::Rng
        );
    }

    #[test]
    fn password_vaults_have_no_member_wraps() {
        let (h, k, _) =
            VaultHeader::create_with(b"fake-pass-for-tests", KdfParams::for_tests()).unwrap();
        let (owner, bob) = (id(), id());
        assert_eq!(
            wrap_data_key(&h, &k, &owner, &bob.public_key()).unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(
            unwrap_data_key(&h, &bob, &[0u8; WRAP_LEN], &[owner.public_key()]).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn identity_key_round_trips_and_is_redacted() {
        let k = id();
        let again = IdentityKey::from_bytes(&k.to_bytes()).unwrap();
        assert_eq!(again.public_key(), k.public_key());
        assert_eq!(format!("{k:?}"), "IdentityKey(<redacted>)");
        assert!(IdentityKey::from_bytes(&[1u8; 31]).is_err());
        assert!(IdentityKey::from_bytes(&[1u8; 33]).is_err());
    }

    #[test]
    fn public_key_parses_and_has_a_stable_key_id() {
        let pk = id().public_key();
        let parsed = MemberPublicKey::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(parsed, pk);
        assert_eq!(parsed.key_id(), pk.key_id());
        assert_eq!(pk.key_id().len(), 32);
        assert_ne!(pk.key_id(), id().public_key().key_id());
        assert!(MemberPublicKey::from_bytes(&[1u8; 31]).is_err());
    }

    #[test]
    fn low_order_public_key_cannot_receive_a_wrap() {
        let (h, k) = member_vault();
        // The all-zero point is low order: the DH output is zero and HPKE must refuse it.
        let zero = MemberPublicKey::from_bytes(&[0u8; MEMBER_KEY_LEN]).unwrap();
        assert!(wrap_data_key(&h, &k, &id(), &zero).is_err());
    }

    #[test]
    fn member_vault_file_opens_through_a_wrap() {
        let (h, k) = member_vault();
        let (owner, bob) = (id(), id());
        let snap = sample(true);
        let sealed = vault_file::seal_vault(&h, &k, &snap).unwrap();
        let w = wrap_data_key(&h, &k, &owner, &bob.public_key()).unwrap();
        let header = vault_file::read_header(&sealed.file).unwrap();
        assert!(header.is_member());
        let keys = unwrap_data_key(&header, &bob, &w, &[owner.public_key()]).unwrap();
        let b = blobs(&sealed);
        let opened = vault_file::open_vault(&sealed.file, &keys, &|n| b.get(n).cloned()).unwrap();
        assert_eq!(opened, snap);
    }

    #[test]
    fn rekey_locks_out_removed_members_and_old_keys() {
        let (h, k) = member_vault();
        let (alice, bob) = (id(), id());
        let trust = [alice.public_key(), bob.public_key()];
        let snap = sample(true);
        let old_bob_wrap = wrap_data_key(&h, &k, &alice, &bob.public_key()).unwrap();

        let r = rekey(&h, &snap, &alice, &[alice.public_key()]).unwrap();
        assert_eq!(r.header.vault_id(), h.vault_id());
        assert_eq!(r.header.member_epoch().unwrap(), 1);
        assert_eq!(r.wraps.len(), 1);

        let header = vault_file::read_header(&r.sealed.file).unwrap();
        let keys = unwrap_data_key(&header, &alice, &r.wraps[0], &trust).unwrap();
        assert_ne!(keys.data_key().expose(), k.data_key().expose());
        let b = blobs(&r.sealed);
        assert_eq!(
            vault_file::open_vault(&r.sealed.file, &keys, &|n| b.get(n).cloned()).unwrap(),
            snap
        );
        // Bob's old wrap and the old data key no longer open the new file.
        assert_eq!(
            unwrap_data_key(&header, &bob, &old_bob_wrap, &trust).unwrap_err(),
            Error::Decryption
        );
        assert!(vault_file::open_vault(&r.sealed.file, &k, &|n| b.get(n).cloned()).is_err());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]
        /// Any data key wrapped for any member opens to the same key, and only for that member.
        #[test]
        fn wrap_unwrap_is_identity_for_any_key(dk in proptest::array::uniform32(proptest::num::u8::ANY)) {
            let (h, _) = member_vault();
            let keys = VaultKeys::from_data_key(SecretKey::from_bytes(dk));
            let (owner, member, other) = (id(), id(), id());
            let trust = [owner.public_key()];
            let w = wrap_data_key(&h, &keys, &owner, &member.public_key()).unwrap();
            let opened = unwrap_data_key(&h, &member, &w, &trust).unwrap();
            proptest::prop_assert_eq!(opened.data_key().expose(), &dk);
            proptest::prop_assert!(unwrap_data_key(&h, &other, &w, &trust).is_err());
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
