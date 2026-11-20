//! An unlockable vault session: the single object UIs talk to through FFI / wasm.
//!
//! The data key lives only inside the session. Nothing here returns it, and nothing derived from
//! it except sealed blobs (`.vault` files, side blobs) and the *wrapped* header. [`Session::lock`]
//! drops the keys and the store (zeroizing both; for SQLCipher this closes the connection);
//! afterwards every operation fails with [`Error::Locked`].
//!
//! Storage is pluggable ([`VaultStore`]): SQLCipher on native targets, [`crate::mem_store::MemStore`]
//! everywhere. Time is injected per call (`now_ms`), never read here.

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::{DeviceEnrollment, DeviceKey, VaultHeader, VaultKeys};
use crate::member_keys::{self, IdentityKey, MemberPublicKey};
use crate::ops::{non_empty, VaultStore, WriteCtx};
use crate::recovery::RecoveryKey;
use crate::search::{
    filter_items, group_by_category, matches_global, split_terms, ItemFilter, SearchGroup,
};
use crate::totp::Totp;
use crate::vault_file::{self, SealedVault};

/// A current TOTP code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    /// The zero-padded code.
    pub code: String,
    /// Seconds until it expires.
    pub seconds_remaining: u64,
    /// Time step in seconds.
    pub period: u64,
}

/// Local Security Audit result (PRD §9.2). Ids only; no password material.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditReport {
    /// Items whose primary password is `VeryWeak` or `Weak` by entropy (before any reuse demotion).
    pub weak: Vec<String>,
    /// Groups of items sharing the same primary password.
    pub reused: Vec<Vec<String>>,
    /// Items with a password not modified for at least the requested number of days
    /// (`updated_at` is the proxy for "password last changed").
    pub old: Vec<String>,
    /// Credential items with a password and a URL but no `totp` field.
    pub missing_2fa: Vec<String>,
}

/// Strength of one item's password. See [`Session::password_strengths`].
#[derive(Clone, Debug, PartialEq)]
pub struct PasswordStrength {
    /// Item id.
    pub item_id: String,
    /// Estimated entropy in bits (before the reuse demotion).
    pub bits: f64,
    /// Level, demoted one step when `reused`.
    pub level: crate::generator::Strength,
    /// The same password is used by another item.
    pub reused: bool,
    key: String,
}

struct Unlocked<S> {
    keys: VaultKeys,
    store: S,
}

/// A vault session. See the module docs.
pub struct Session<S: VaultStore> {
    device_id: String,
    header: VaultHeader,
    /// Unlocked with the Recovery Key: the user may set a new password without knowing the old.
    via_recovery: bool,
    state: Option<Unlocked<S>>,
}

impl<S: VaultStore> Session<S> {
    fn new(
        device_id: &str,
        header: VaultHeader,
        keys: VaultKeys,
        via_recovery: bool,
        make_store: impl FnOnce(&VaultKeys) -> Result<S>,
    ) -> Result<Self> {
        non_empty(device_id)?;
        let store = make_store(&keys)?;
        Ok(Self {
            device_id: device_id.to_string(),
            header,
            via_recovery,
            state: Some(Unlocked { keys, store }),
        })
    }

    /// Create a brand-new vault. Returns the unlocked session and the Recovery Key, which the
    /// caller must show exactly once. `make_store` builds the empty store from the fresh keys.
    pub fn create(
        master_password: &str,
        device_id: &str,
        make_store: impl FnOnce(&VaultKeys) -> Result<S>,
    ) -> Result<(Self, Zeroizing<String>)> {
        non_empty(master_password)?;
        let (header, keys, recovery) = VaultHeader::create(master_password.as_bytes())?;
        let session = Self::new(device_id, header, keys, false, make_store)?;
        Ok((session, recovery.to_display_string()))
    }

    /// Create a brand-new member vault: no password and no Recovery Key. Give access with
    /// [`Session::wrap_for_member`] (starting with the creator's own public key).
    pub fn create_member(
        device_id: &str,
        make_store: impl FnOnce(&VaultKeys) -> Result<S>,
    ) -> Result<Self> {
        let (header, keys) = VaultHeader::create_member()?;
        Self::new(device_id, header, keys, false, make_store)
    }

    /// This account's newest identity key (personal sessions only), the sender of every wrap.
    fn sender_identity(&self) -> Result<IdentityKey> {
        if self.header.is_member() {
            return Err(Error::InvalidInput);
        }
        let keys = self.store()?.live_identity_keys()?;
        let newest = keys.last().ok_or(Error::NotFound)?;
        IdentityKey::from_bytes(&newest.private_key)
    }

    /// From the personal session: seal the open member vault `shared`'s data key for `member`,
    /// authenticated by this account's identity key (see [`crate::member_keys`]). Create the
    /// identity first with [`Session::member_public_key`]; without one this is
    /// [`Error::NotFound`].
    pub fn wrap_member_vault<S2: VaultStore>(
        &self,
        shared: &Session<S2>,
        member: &MemberPublicKey,
    ) -> Result<Vec<u8>> {
        let sender = self.sender_identity()?;
        let st = shared.state.as_ref().ok_or(Error::Locked)?;
        member_keys::wrap_data_key(&shared.header, &st.keys, &sender, member)
    }

    /// From the personal session: re-key the open member vault `shared` (after removing someone).
    /// Its current contents are sealed under a fresh data key and the next epoch, with new wraps
    /// (made by this account) for `members` only. `shared` is then **locked**, so it can no longer
    /// produce files under the old key; hosts upload the result and reopen from it.
    pub fn rekey_member_vault<S2: VaultStore>(
        &self,
        shared: &mut Session<S2>,
        members: &[MemberPublicKey],
    ) -> Result<member_keys::Rekeyed> {
        let sender = self.sender_identity()?;
        let snapshot = shared
            .state
            .as_ref()
            .ok_or(Error::Locked)?
            .store
            .snapshot()?;
        let rekeyed = member_keys::rekey(&shared.header, &snapshot, &sender, members)?;
        shared.lock();
        Ok(rekeyed)
    }

    /// This account's public key for shared member vaults. The identity key is created on first
    /// use and stored inside this (personal, password) vault, so it syncs to the person's other
    /// devices and the Recovery Key restores it. The private key never leaves the core. On a
    /// member vault this is [`Error::InvalidInput`].
    pub fn member_public_key(&mut self, now_ms: i64) -> Result<MemberPublicKey> {
        if self.header.is_member() {
            return Err(Error::InvalidInput);
        }
        if let Some(newest) = self.store()?.live_identity_public_keys()?.last() {
            return MemberPublicKey::from_bytes(newest);
        }
        let identity = IdentityKey::generate()?;
        let public = identity.public_key();
        let secret = identity.to_bytes();
        self.write(now_ms, |st, ctx| {
            st.add_identity_key(ctx, &secret, &public.to_bytes())
        })?;
        Ok(public)
    }

    /// Key ids of every live identity key of this account (another device may have created one
    /// at the same time, so a member vault may hold wraps for any of them).
    pub fn member_key_ids(&self) -> Result<Vec<String>> {
        self.store()?
            .live_identity_public_keys()?
            .iter()
            .map(|k| MemberPublicKey::from_bytes(k).map(|p| p.key_id()))
            .collect()
    }

    /// Open a member vault `file` with this account's identity key `key_id` and the `wrap` made
    /// for it, into a new session built by `make_store`. The wrap's sender must be one of
    /// `trusted_senders`: hosts take them from data they keep inside the personal vault (never
    /// straight from the sync store) and drop removed members. The file's key epoch must be at
    /// least `min_epoch`, the highest epoch this vault was **successfully opened** at, so an old
    /// file a removed member can still read is refused. Hosts raise `min_epoch` only after this
    /// call succeeds, never from [`vault_file::read_header`] or [`Error::Rekeyed`] alone: both
    /// come from the unauthenticated header, and trusting them would let anyone with write access
    /// push the minimum out of reach. Only on a personal (password) session; an unknown key id is [`Error::NotFound`]
    /// and anything else that does not open is [`Error::Decryption`].
    #[allow(clippy::too_many_arguments)]
    pub fn open_member_vault<S2: VaultStore>(
        &self,
        file: &[u8],
        key_id: &str,
        wrap: &[u8],
        trusted_senders: &[MemberPublicKey],
        min_epoch: u32,
        device_id: &str,
        side_blob: &dyn Fn(&str) -> Option<Vec<u8>>,
        make_store: impl FnOnce(&VaultKeys) -> Result<S2>,
    ) -> Result<Session<S2>> {
        if self.header.is_member() {
            return Err(Error::InvalidInput);
        }
        let record = self
            .store()?
            .live_identity_keys()?
            .into_iter()
            .find(|k| {
                MemberPublicKey::from_bytes(&k.public_key).is_ok_and(|p| p.key_id() == key_id)
            })
            .ok_or(Error::NotFound)?;
        let identity = IdentityKey::from_bytes(&record.private_key)?;
        Session::<S2>::from_vault_file(
            file,
            UnlockSecret::MemberWrap {
                identity: &identity,
                wrap,
                trusted_senders,
                min_epoch,
            },
            device_id,
            side_blob,
            make_store,
        )
    }

    /// Unlock with the Master Password. Wrong password and tampering are indistinguishable.
    pub fn unlock(
        header: &VaultHeader,
        master_password: &str,
        device_id: &str,
        make_store: impl FnOnce(&VaultKeys) -> Result<S>,
    ) -> Result<Self> {
        let keys = header.unlock(master_password.as_bytes())?;
        Self::new(device_id, header.clone(), keys, false, make_store)
    }

    /// Unlock with the Recovery Key.
    pub fn unlock_with_recovery(
        header: &VaultHeader,
        recovery_key: &str,
        device_id: &str,
        make_store: impl FnOnce(&VaultKeys) -> Result<S>,
    ) -> Result<Self> {
        let keys = header.unlock_with_recovery(&RecoveryKey::parse(recovery_key)?)?;
        Self::new(device_id, header.clone(), keys, true, make_store)
    }

    /// Unlock with a device key and its device-local wrap (quick unlock, ADR 0003).
    /// Any failure is [`Error::Decryption`]; the host should then disable quick unlock and fall
    /// back to the Master Password.
    pub fn unlock_with_device_key(
        header: &VaultHeader,
        device_key: &DeviceKey,
        wrapped: &[u8],
        device_id: &str,
        make_store: impl FnOnce(&VaultKeys) -> Result<S>,
    ) -> Result<Self> {
        let keys = header.unlock_with_device_key(device_key, wrapped)?;
        Self::new(device_id, header.clone(), keys, false, make_store)
    }

    /// Enroll this device for quick unlock. Re-verifies the Master Password (skipped when the
    /// session was unlocked with the Recovery Key, like [`Session::change_password`]) so a
    /// session left unlocked cannot silently enable biometric access. Returns the device key
    /// (for hardware-protected storage) and the wrap blob (device-local file).
    pub fn enroll_device_unlock(&self, current_password: &str) -> Result<DeviceEnrollment> {
        let st = self.state.as_ref().ok_or(Error::Locked)?;
        if !self.via_recovery {
            self.header.unlock(current_password.as_bytes())?;
        }
        self.header.enroll_device(&st.keys)
    }

    /// `true` once [`Session::lock`] has been called.
    pub fn is_locked(&self) -> bool {
        self.state.is_none()
    }

    /// Lock: drop (zeroize) the keys and the store. Idempotent.
    pub fn lock(&mut self) {
        self.state = None;
    }

    /// The (wrapped, non-secret) header to persist next to the local store. Changes after
    /// [`Session::change_password`].
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Change the Master Password and return the new header, which the caller must persist.
    /// The current password is re-verified unless the session was unlocked with the Recovery Key.
    /// The data key (and so every sealed blob and the local store key) is unchanged.
    pub fn change_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> Result<VaultHeader> {
        non_empty(new_password)?;
        let st = self.state.as_ref().ok_or(Error::Locked)?;
        if !self.via_recovery {
            self.header.unlock(current_password.as_bytes())?;
        }
        let header = self
            .header
            .change_password(&st.keys, new_password.as_bytes())?;
        self.header = header.clone();
        self.via_recovery = false;
        Ok(header)
    }

    /// `true` while this session was unlocked with the Recovery Key and the Master Password has
    /// not been changed yet: hosts must then require the user to set a new password.
    pub fn requires_password_reset(&self) -> bool {
        self.via_recovery
    }

    /// Replace the Recovery Key and return the new header (persist it) and the new key in display
    /// form (show it exactly once). The current password is re-verified unless the session was
    /// unlocked with the Recovery Key. The old Recovery Key stops working.
    pub fn rotate_recovery_key(
        &mut self,
        current_password: &str,
    ) -> Result<(VaultHeader, Zeroizing<String>)> {
        let st = self.state.as_ref().ok_or(Error::Locked)?;
        if !self.via_recovery {
            self.header.unlock(current_password.as_bytes())?;
        }
        let (header, recovery) = self.header.rotate_recovery(&st.keys)?;
        self.header = header.clone();
        Ok((header, recovery.to_display_string()))
    }

    /// Read-only access to the store.
    pub fn store(&self) -> Result<&S> {
        self.state.as_ref().map(|u| &u.store).ok_or(Error::Locked)
    }

    /// Run a write against the store with a [`WriteCtx`] for `now_ms` and this device.
    pub fn write<R>(
        &mut self,
        now_ms: i64,
        f: impl FnOnce(&mut S, &WriteCtx<'_>) -> Result<R>,
    ) -> Result<R> {
        let st = self.state.as_mut().ok_or(Error::Locked)?;
        let ctx = WriteCtx {
            now_ms,
            device_id: &self.device_id,
        };
        f(&mut st.store, &ctx)
    }

    /// Search, filter and sort live items (non-secret fields only).
    pub fn search(&self, filter: &ItemFilter) -> Result<Vec<crate::ops::ItemSummary>> {
        Ok(filter_items(self.store()?.list_items()?, filter))
    }

    /// Global search across the whole vault: every term must occur in an item's title, URL, tag
    /// or **non-secret** field value (e.g. a username or email). Hits are grouped by category in
    /// category display order, uncategorized last. A blank query returns no groups. `vault_id`
    /// limits the search to one vault (`None` = every vault).
    pub fn search_grouped(&self, query: &str, vault_id: Option<&str>) -> Result<Vec<SearchGroup>> {
        let terms = split_terms(query);
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        let store = self.store()?;
        let mut hits = Vec::new();
        for summary in store.list_items()? {
            if vault_id.is_some_and(|v| summary.vault_id != v) {
                continue;
            }
            let values: Vec<String> = store
                .get_item(&summary.id)?
                .fields
                .into_iter()
                .filter_map(|f| f.value)
                .collect();
            if matches_global(&summary, &values, &terms) {
                hits.push(summary);
            }
        }
        let order: Vec<String> = store.list_categories()?.into_iter().map(|c| c.id).collect();
        Ok(group_by_category(hits, &order))
    }

    /// Strength of every live item's primary password (first `password` field), computed locally.
    /// Passwords shared by several items are marked `reused` and demoted one level. The result
    /// holds no password material.
    pub fn password_strengths(&self) -> Result<Vec<PasswordStrength>> {
        let store = self.store()?;
        let mut out: Vec<PasswordStrength> = Vec::new();
        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for summary in store.list_items()? {
            let detail = store.get_item(&summary.id)?;
            let Some(field) = detail.fields.iter().find(|f| f.kind == "password") else {
                continue;
            };
            let pw = store.reveal_field(&summary.id, &field.id)?;
            if pw.is_empty() {
                continue;
            }
            let report = crate::strength::analyze(&pw);
            *seen.entry(pw.to_string()).or_default() += 1;
            out.push(PasswordStrength {
                item_id: summary.id,
                bits: report.bits,
                level: report.level,
                reused: false,
                key: pw.to_string(),
            });
        }
        for p in &mut out {
            if seen.get(&p.key).copied().unwrap_or(0) > 1 {
                p.reused = true;
                p.level = crate::strength::demote(p.level);
            }
            p.key.zeroize();
        }
        Ok(out)
    }

    /// `(item_id, hibp_prefix)` for every live item's primary password, for the opt-in HIBP check
    /// (ADR 0017). Only the 5-char SHA-1 prefix is returned; passwords stay inside the core.
    pub fn breach_prefixes(&self) -> Result<Vec<(String, String)>> {
        let store = self.store()?;
        let mut out = Vec::new();
        for summary in store.list_items()? {
            let detail = store.get_item(&summary.id)?;
            let Some(field) = detail.fields.iter().find(|f| f.kind == "password") else {
                continue;
            };
            let pw = store.reveal_field(&summary.id, &field.id)?;
            if pw.is_empty() {
                continue;
            }
            out.push((summary.id, crate::breach::prefix(&pw)?));
        }
        Ok(out)
    }

    /// Breach count of the item's primary password in a HIBP range response body (`0` if absent
    /// or the item has no password). The caller fetched the body for this item's prefix.
    pub fn breach_match(&self, item_id: &str, response_body: &str) -> Result<u64> {
        let store = self.store()?;
        let detail = store.get_item(item_id)?;
        let Some(field) = detail.fields.iter().find(|f| f.kind == "password") else {
            return Ok(0);
        };
        let pw = store.reveal_field(item_id, &field.id)?;
        if pw.is_empty() {
            return Ok(0);
        }
        crate::breach::match_count(&pw, response_body)
    }

    /// Local Security Audit: weak, reused, old and missing-2FA items, computed in memory with no
    /// network access. `old_after_days` is the age threshold for `old`; `now_ms` is Unix ms UTC.
    pub fn security_audit(&self, now_ms: i64, old_after_days: u32) -> Result<AuditReport> {
        use crate::generator::Strength;
        let strengths = self.password_strengths()?;
        let with_password: std::collections::HashSet<&str> =
            strengths.iter().map(|p| p.item_id.as_str()).collect();
        let mut report = AuditReport {
            weak: strengths
                .iter()
                .filter(|p| {
                    matches!(
                        crate::generator::strength_from_bits(p.bits),
                        Strength::VeryWeak | Strength::Weak
                    )
                })
                .map(|p| p.item_id.clone())
                .collect(),
            reused: self.password_reuse_groups()?,
            ..AuditReport::default()
        };
        let cutoff = now_ms.saturating_sub(i64::from(old_after_days).saturating_mul(86_400_000));
        let store = self.store()?;
        for summary in store.list_items()? {
            if !with_password.contains(summary.id.as_str()) {
                continue;
            }
            if summary.updated_at <= cutoff {
                report.old.push(summary.id.clone());
            }
            if summary.item_type == crate::models::ItemType::Credential
                && summary.url.as_deref().is_some_and(|u| !u.trim().is_empty())
                && !store
                    .get_item(&summary.id)?
                    .fields
                    .iter()
                    .any(|f| f.kind == "totp")
            {
                report.missing_2fa.push(summary.id);
            }
        }
        Ok(report)
    }

    /// Groups of live items whose primary password (first `password` field) is identical.
    /// Only groups of two or more items are returned, each sorted by item id and the groups
    /// ordered by their first id. The result holds item ids only, never password material.
    pub fn password_reuse_groups(&self) -> Result<Vec<Vec<String>>> {
        let store = self.store()?;
        let mut by_pw: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for summary in store.list_items()? {
            let detail = store.get_item(&summary.id)?;
            let Some(field) = detail.fields.iter().find(|f| f.kind == "password") else {
                continue;
            };
            let pw = store.reveal_field(&summary.id, &field.id)?;
            if pw.is_empty() {
                continue;
            }
            by_pw.entry(pw.to_string()).or_default().push(summary.id);
        }
        let mut groups: Vec<Vec<String>> = Vec::new();
        for (mut key, mut ids) in by_pw {
            key.zeroize();
            if ids.len() > 1 {
                ids.sort();
                groups.push(ids);
            }
        }
        groups.sort();
        Ok(groups)
    }

    /// Current TOTP code of a `totp` field. The field holds a Base32 secret or an `otpauth://`
    /// URI; the secret itself never leaves the session.
    pub fn totp_code(&self, item_id: &str, field_id: &str, unix_secs: u64) -> Result<TotpCode> {
        let value = self.store()?.reveal_field(item_id, field_id)?;
        let value = value.trim();
        let (totp, _) = Totp::parse_input(value)?;
        Ok(TotpCode {
            code: totp.code_at(unix_secs)?,
            seconds_remaining: totp.seconds_remaining(unix_secs),
            period: totp.period,
        })
    }

    /// Seal the current vault into a `.vault` file plus the side blobs it refers to. Upload the
    /// file and every side blob the provider does not already have (names are stable).
    pub fn export_vault(&self) -> Result<SealedVault> {
        let st = self.state.as_ref().ok_or(Error::Locked)?;
        vault_file::seal_vault(&self.header, &st.keys, &st.store.snapshot()?)
    }

    /// Encrypted KovaKey export sealed under `export_password` (ADR 0016). The password is chosen
    /// for the file and need not match the Master Password.
    pub fn export_encrypted(&self, export_password: &str) -> Result<Vec<u8>> {
        let st = self.state.as_ref().ok_or(Error::Locked)?;
        crate::export::export_encrypted(&st.store, export_password)
    }

    /// Plaintext JSON export. Re-verifies the Master Password (skipped after a Recovery Key
    /// unlock, like [`Session::change_password`]) so an unattended unlocked session cannot dump
    /// the vault. The UI must also show the plaintext warning and get confirmation.
    pub fn export_plain_json(&self, current_password: &str) -> Result<Zeroizing<Vec<u8>>> {
        let st = self.verified_state(current_password)?;
        crate::export::export_plain_json(&st.store)
    }

    /// Plaintext CSV export; same re-verification and warning rules as
    /// [`Session::export_plain_json`].
    pub fn export_plain_csv(&self, current_password: &str) -> Result<Zeroizing<Vec<u8>>> {
        let st = self.verified_state(current_password)?;
        crate::export::export_plain_csv(&st.store)
    }

    fn verified_state(&self, current_password: &str) -> Result<&Unlocked<S>> {
        let st = self.state.as_ref().ok_or(Error::Locked)?;
        if !self.via_recovery {
            self.header.unlock(current_password.as_bytes())?;
        }
        Ok(st)
    }

    /// Side-blob storage names a downloaded `.vault` file needs. Fetch those, then call
    /// [`Session::merge_remote_vault`].
    pub fn required_side_blobs(&self, file: &[u8]) -> Result<Vec<String>> {
        let st = self.state.as_ref().ok_or(Error::Locked)?;
        self.check_same_vault(file)?;
        vault_file::required_side_blobs(file, &st.keys)
    }

    /// Decrypt a downloaded `.vault` file of **this** vault and merge it into the local store
    /// (item-level last-writer-wins, atomic). `side_blob` looks up sealed side blobs by name.
    ///
    /// The remote header is *not* adopted: if the password was changed on another device, this
    /// device keeps its own header until the user re-syncs (see ADR 0001, "open questions").
    pub fn merge_remote_vault(
        &mut self,
        file: &[u8],
        side_blob: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<()> {
        self.check_same_vault(file)?;
        let member = self.header.is_member();
        let st = self.state.as_mut().ok_or(Error::Locked)?;
        let mut remote = vault_file::open_vault(file, &st.keys, side_blob)?;
        if member {
            // Identity keys belong to personal vaults only; never keep one sent into a shared vault.
            remote.identity_keys.clear();
        }
        st.store.merge_remote(&remote)
    }

    /// Same vault, and for a member vault the same key epoch: a newer epoch is
    /// [`Error::Rekeyed`] (fetch the new wrap and reopen); an older one is refused as
    /// [`Error::Decryption`] (it may be a rollback to a key a removed member still knows).
    fn check_same_vault(&self, file: &[u8]) -> Result<()> {
        let remote = vault_file::read_header(file)?;
        if remote.vault_id() != self.header.vault_id()
            || remote.is_member() != self.header.is_member()
        {
            return Err(Error::InvalidInput);
        }
        if let (Ok(theirs), Ok(ours)) = (remote.member_epoch(), self.header.member_epoch()) {
            if theirs > ours {
                return Err(Error::Rekeyed);
            }
            if theirs < ours {
                return Err(Error::Decryption);
            }
        }
        Ok(())
    }
}

impl<S: VaultStore> Session<S> {
    /// Open an existing `.vault` file (first run on a new device, or restore) into an empty store
    /// built by `make_store`, which receives the unlocked keys.
    pub fn from_vault_file(
        file: &[u8],
        secret: UnlockSecret<'_>,
        device_id: &str,
        side_blob: &dyn Fn(&str) -> Option<Vec<u8>>,
        make_store: impl FnOnce(&VaultKeys) -> Result<S>,
    ) -> Result<Self> {
        let header = vault_file::read_header(file)?;
        let (keys, via_recovery) = match secret {
            UnlockSecret::Password(p) => (header.unlock(p.as_bytes())?, false),
            UnlockSecret::RecoveryKey(r) => {
                (header.unlock_with_recovery(&RecoveryKey::parse(r)?)?, true)
            }
            UnlockSecret::MemberWrap {
                identity,
                wrap,
                trusted_senders,
                min_epoch,
            } => {
                if header.member_epoch().map_err(|_| Error::Decryption)? < min_epoch {
                    return Err(Error::Decryption);
                }
                (
                    member_keys::unwrap_data_key(&header, identity, wrap, trusted_senders)?,
                    false,
                )
            }
        };
        let snapshot = vault_file::open_vault(file, &keys, side_blob)?;
        let mut session = Self::new(device_id, header, keys, via_recovery, make_store)?;
        // Merging into the fresh, empty store adopts the snapshot (and validates its references).
        session
            .state
            .as_mut()
            .ok_or(Error::Locked)?
            .store
            .merge_remote(&snapshot)?;
        Ok(session)
    }
}

/// What unlocks a vault.
#[derive(Clone, Copy)]
pub enum UnlockSecret<'a> {
    /// The Master Password.
    Password(&'a str),
    /// The Recovery Key (display form).
    RecoveryKey(&'a str),
    /// A member vault: this person's identity key and the wrap made for its public key.
    MemberWrap {
        /// The member's private identity key.
        identity: &'a IdentityKey,
        /// The wrap of the vault's data key for that identity's public key.
        wrap: &'a [u8],
        /// Member keys whose wraps are accepted (the wrap's sender must be one of them).
        trusted_senders: &'a [MemberPublicKey],
        /// Lowest key epoch accepted; an older file is refused.
        min_epoch: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::kdf::KdfParams;
    use crate::mem_store::MemStore;
    use crate::models::ItemType;
    use crate::ops::{FieldInput, NewItem};
    use crate::search::SortOrder;
    use std::collections::HashMap;

    const PW: &str = "fake-pass-for-tests";

    /// Fresh vault with cheap KDF parameters. Returns the session and the Recovery Key.
    fn new_mem() -> (Session<MemStore>, String) {
        let (header, keys, recovery) =
            VaultHeader::create_with(PW.as_bytes(), KdfParams::for_tests()).unwrap();
        let s = Session::new("dev-a", header, keys, false, |_| Ok(MemStore::new())).unwrap();
        (s, recovery.to_display_string().to_string())
    }

    fn add_login<S: VaultStore>(s: &mut Session<S>, now: i64, title: &str, pw: &str) -> String {
        s.write(now, |st, ctx| {
            let mut n = NewItem::new(ItemType::Credential, title);
            n.fields = vec![FieldInput::new("password", "password", pw, true)];
            st.create_item(ctx, &n)
        })
        .unwrap()
    }

    fn blobs(v: &SealedVault) -> HashMap<String, Vec<u8>> {
        v.side_blobs
            .iter()
            .map(|b| (b.name.clone(), b.sealed.clone()))
            .collect()
    }

    /// Alice and Bob each have a personal vault (and so an identity key).
    fn two_people() -> (
        Session<MemStore>,
        Session<MemStore>,
        MemberPublicKey,
        MemberPublicKey,
    ) {
        let (mut alice, _) = new_mem();
        let (mut bob, _) = new_mem();
        let (pa, pb) = (
            alice.member_public_key(1).unwrap(),
            bob.member_public_key(2).unwrap(),
        );
        (alice, bob, pa, pb)
    }

    fn open_as(
        who: &Session<MemStore>,
        sealed: &SealedVault,
        key: &MemberPublicKey,
        wrap: &[u8],
        trusted: &[MemberPublicKey],
        min_epoch: u32,
    ) -> Result<Session<MemStore>> {
        let b = blobs(sealed);
        who.open_member_vault(
            &sealed.file,
            &key.key_id(),
            wrap,
            trusted,
            min_epoch,
            "dev-x",
            &|n| b.get(n).cloned(),
            |_| Ok(MemStore::new()),
        )
    }

    #[test]
    fn member_vault_is_shared_through_wraps_merged_and_rekeyed() {
        let (alice, bob, pa, pb) = two_people();
        let trusted = [pa.clone(), pb.clone()];
        let mut shared = Session::create_member("dev-a", |_| Ok(MemStore::new())).unwrap();
        assert!(shared.header().is_member());
        add_login(&mut shared, 10, "Wi-Fi", "fake-wifi");
        let wrap_a = alice.wrap_member_vault(&shared, &pa).unwrap();
        let wrap_b = alice.wrap_member_vault(&shared, &pb).unwrap();
        let sealed = shared.export_vault().unwrap();

        // Bob opens it with his own key; no password exists.
        let mut b = open_as(&bob, &sealed, &pb, &wrap_b, &trusted, 0).unwrap();
        assert_eq!(b.store().unwrap().list_items().unwrap().len(), 1);
        // Bob's key does not open Alice's wrap; untrusted senders and password paths are refused.
        assert_eq!(
            open_as(&bob, &sealed, &pb, &wrap_a, &trusted, 0).err(),
            Some(Error::Decryption)
        );
        assert_eq!(
            open_as(&bob, &sealed, &pb, &wrap_b, std::slice::from_ref(&pb), 0).err(),
            Some(Error::Decryption),
            "Alice is not trusted"
        );
        assert_eq!(
            b.change_password("x", "new-fake-pass").unwrap_err(),
            Error::InvalidInput
        );
        assert!(b.enroll_device_unlock("x").is_err());
        assert_eq!(b.member_public_key(3).unwrap_err(), Error::InvalidInput);

        // Edits merge both ways.
        add_login(&mut b, 20, "Bank", "fake-bank");
        let sb = b.export_vault().unwrap();
        let bb = blobs(&sb);
        shared
            .merge_remote_vault(&sb.file, &|n| bb.get(n).cloned())
            .unwrap();
        assert_eq!(shared.store().unwrap().list_items().unwrap().len(), 2);

        // Removing Bob: Alice re-keys for herself only, and the old session is locked.
        let r = alice
            .rekey_member_vault(&mut shared, std::slice::from_ref(&pa))
            .unwrap();
        assert!(shared.is_locked(), "no more files under the old key");
        assert_eq!(r.header.member_epoch().unwrap(), 1);
        let mut reopened = open_as(&alice, &r.sealed, &pa, &r.wraps[0], &trusted, 1).unwrap();
        assert_eq!(reopened.store().unwrap().list_items().unwrap().len(), 2);
        assert_eq!(
            open_as(&bob, &r.sealed, &pb, &wrap_b, &trusted, 1).err(),
            Some(Error::Decryption)
        );

        // Rollback: once the host has seen epoch 1, the old file (still readable by Bob) is refused.
        assert_eq!(
            open_as(&alice, &sealed, &pa, &wrap_a, &trusted, 1).err(),
            Some(Error::Decryption)
        );
        // Bob's still-open epoch-0 session sees the re-key distinctly when merging.
        let rb = blobs(&r.sealed);
        assert_eq!(
            b.merge_remote_vault(&r.sealed.file, &|n| rb.get(n).cloned())
                .unwrap_err(),
            Error::Rekeyed
        );
        // And the re-keyed session refuses the older epoch.
        assert_eq!(
            reopened
                .merge_remote_vault(&sb.file, &|n| bb.get(n).cloned())
                .unwrap_err(),
            Error::Decryption
        );

        // A password vault cannot be wrapped or re-keyed per member.
        let (mut p, _) = new_mem();
        assert_eq!(
            alice.wrap_member_vault(&p, &pa).unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(
            alice
                .rekey_member_vault(&mut p, std::slice::from_ref(&pa))
                .unwrap_err(),
            Error::InvalidInput
        );
    }

    #[test]
    fn identity_keys_sent_into_a_member_vault_are_dropped() {
        let mut shared = Session::create_member("dev-a", |_| Ok(MemStore::new())).unwrap();
        // A tampering member injects an identity record into the shared vault's snapshot.
        let mut snap = shared.store().unwrap().snapshot().unwrap();
        let fake = IdentityKey::generate().unwrap();
        snap.identity_keys.push(crate::models::IdentityKeyRecord {
            id: "x".into(),
            private_key: fake.to_bytes().to_vec(),
            public_key: fake.public_key().to_bytes(),
            created_at: 1,
            updated_at: 1,
            updated_by: "m".into(),
            deleted_at: None,
        });
        let injected = {
            let st = shared.state.as_ref().unwrap();
            vault_file::seal_vault(&shared.header, &st.keys, &snap).unwrap()
        };
        shared
            .merge_remote_vault(&injected.file, &|_| None)
            .unwrap();
        assert!(shared
            .store()
            .unwrap()
            .snapshot()
            .unwrap()
            .identity_keys
            .is_empty());
    }

    #[test]
    fn identity_key_is_created_once_synced_and_opens_member_vaults() {
        // Alice's personal vault on two devices (A1 in memory, A2 on SQLCipher from A1's file).
        let (mut a1, _) = new_mem();
        let pk = a1.member_public_key(10).unwrap();
        assert_eq!(a1.member_public_key(11).unwrap(), pk, "created only once");
        assert_eq!(a1.member_key_ids().unwrap(), [pk.key_id()]);
        let personal = a1.export_vault().unwrap();
        let a2 = Session::<Database>::from_vault_file(
            &personal.file,
            UnlockSecret::Password(PW),
            "dev-a2",
            &|n| blobs(&personal).get(n).cloned(),
            |k| Database::open_in_memory(&k.db_key()?),
        )
        .unwrap();
        assert_eq!(a2.member_key_ids().unwrap(), [pk.key_id()]);

        // A shared member vault wrapped by Alice's first device opens on her second device.
        let mut shared = Session::create_member("dev-x", |_| Ok(MemStore::new())).unwrap();
        add_login(&mut shared, 20, "Wi-Fi", "fake-wifi");
        let wrap = a1.wrap_member_vault(&shared, &pk).unwrap();
        let sealed = shared.export_vault().unwrap();
        let sb = blobs(&sealed);
        let opened = a2
            .open_member_vault(
                &sealed.file,
                &pk.key_id(),
                &wrap,
                std::slice::from_ref(&pk),
                0,
                "dev-a2",
                &|n| sb.get(n).cloned(),
                |_| Ok(MemStore::new()),
            )
            .unwrap();
        assert_eq!(opened.store().unwrap().list_items().unwrap().len(), 1);

        // Unknown key id, and a personal vault without an identity cannot wrap.
        assert_eq!(
            a2.open_member_vault(
                &sealed.file,
                "00",
                &wrap,
                std::slice::from_ref(&pk),
                0,
                "d",
                &|_| None,
                |_| Ok(MemStore::new())
            )
            .err(),
            Some(Error::NotFound)
        );
        let (fresh, _) = new_mem();
        assert_eq!(
            fresh.wrap_member_vault(&shared, &pk).unwrap_err(),
            Error::NotFound
        );
        // The private key is never printed.
        let snap = a1.store().unwrap().snapshot().unwrap();
        assert!(format!("{:?}", snap.identity_keys).contains("<redacted>"));
    }
    #[test]
    fn identity_keys_created_on_two_devices_at_once_are_both_kept_after_merge() {
        let (mut a, _) = new_mem();
        let file = a.export_vault().unwrap();
        let mut b = Session::<MemStore>::from_vault_file(
            &file.file,
            UnlockSecret::Password(PW),
            "dev-b",
            &|_| None,
            |_| Ok(MemStore::new()),
        )
        .unwrap();
        let (ka, kb) = (
            a.member_public_key(10).unwrap(),
            b.member_public_key(11).unwrap(),
        );
        assert_ne!(ka, kb);
        let (sa, sb) = (a.export_vault().unwrap(), b.export_vault().unwrap());
        a.merge_remote_vault(&sb.file, &|_| None).unwrap();
        b.merge_remote_vault(&sa.file, &|_| None).unwrap();
        let mut ids_a = a.member_key_ids().unwrap();
        let mut ids_b = b.member_key_ids().unwrap();
        ids_a.sort();
        ids_b.sort();
        assert_eq!(ids_a.len(), 2);
        assert_eq!(ids_a, ids_b);
        // Both devices then publish the same (newest) key.
        assert_eq!(
            a.member_public_key(20).unwrap(),
            b.member_public_key(21).unwrap()
        );
    }

    #[test]
    fn device_unlock_round_trip_preserves_data_and_requires_password_to_enroll() {
        let (header, keys, _) =
            VaultHeader::create_with(PW.as_bytes(), KdfParams::for_tests()).unwrap();
        let mut s = Session::new(
            "dev-a",
            header.clone(),
            keys,
            false,
            |_| Ok(MemStore::new()),
        )
        .unwrap();
        // Wrong or empty password cannot enroll.
        assert_eq!(
            s.enroll_device_unlock("wrong").err(),
            Some(Error::Decryption)
        );
        assert_eq!(s.enroll_device_unlock("").err(), Some(Error::Decryption));
        let e = s.enroll_device_unlock(PW).unwrap();
        assert_eq!(e.wrapped.len(), 60);
        add_login(&mut s, 10, "Mail", "fake-secret");
        s.lock();

        // Unlock without the password; the store is rebuilt by the host from the same keys.
        let s2 =
            Session::unlock_with_device_key(&header, &e.device_key, &e.wrapped, "dev-a", |k| {
                // MemStore is not persistent; a successful key unwrap + store build is what we assert.
                assert!(k.db_key().is_ok());
                Ok(MemStore::new())
            })
            .unwrap();
        assert!(!s2.is_locked());
        // A device-unlocked session is not "via recovery": enrolling again needs the password.
        assert_eq!(
            s2.enroll_device_unlock("wrong").err(),
            Some(Error::Decryption)
        );
    }

    #[test]
    fn device_unlock_with_bad_key_or_wrap_fails_with_decryption() {
        let (header, keys, _) =
            VaultHeader::create_with(PW.as_bytes(), KdfParams::for_tests()).unwrap();
        let s = Session::new(
            "dev-a",
            header.clone(),
            keys,
            false,
            |_| Ok(MemStore::new()),
        )
        .unwrap();
        let e = s.enroll_device_unlock(PW).unwrap();
        let bad = DeviceKey::generate().unwrap();
        let r = Session::<MemStore>::unlock_with_device_key(&header, &bad, &e.wrapped, "d", |_| {
            Ok(MemStore::new())
        });
        assert_eq!(r.err(), Some(Error::Decryption));
    }

    #[test]
    fn enrolling_requires_an_unlocked_session() {
        let (mut s, _) = new_mem();
        s.lock();
        assert_eq!(s.enroll_device_unlock(PW).err(), Some(Error::Locked));
    }

    #[test]
    fn recovery_unlocked_session_can_enroll_without_the_old_password() {
        let (header, keys, recovery) =
            VaultHeader::create_with(PW.as_bytes(), KdfParams::for_tests()).unwrap();
        drop(keys);
        let s =
            Session::unlock_with_recovery(&header, &recovery.to_display_string(), "dev-a", |_| {
                Ok(MemStore::new())
            })
            .unwrap();
        assert!(s.enroll_device_unlock("").is_ok());
    }

    #[test]
    fn plain_exports_require_the_master_password_and_locked_sessions_export_nothing() {
        let (mut s, _) = new_mem();
        add_login(&mut s, 10, "Mail", "fake-secret");
        assert_eq!(s.export_plain_json("wrong").err(), Some(Error::Decryption));
        assert_eq!(s.export_plain_csv("wrong").err(), Some(Error::Decryption));
        let json = s.export_plain_json(PW).unwrap();
        assert!(String::from_utf8_lossy(&json).contains("fake-secret"));
        assert!(s.export_plain_csv(PW).is_ok());
        // The encrypted export does not need the Master Password and hides the secret.
        let enc = s.export_encrypted("fake-export-pass").unwrap();
        assert!(!enc.windows(11).any(|w| w == b"fake-secret"));
        s.lock();
        assert_eq!(s.export_plain_json(PW).err(), Some(Error::Locked));
        assert_eq!(s.export_encrypted("x").err(), Some(Error::Locked));
    }

    #[test]
    fn lock_wipes_the_session_and_every_operation_then_reports_locked() {
        let (mut s, _) = new_mem();
        add_login(&mut s, 10, "Mail", "fake-secret");
        s.lock();
        s.lock(); // idempotent
        assert!(s.is_locked());
        assert_eq!(s.store().err(), Some(Error::Locked));
        assert_eq!(s.search(&ItemFilter::default()).err(), Some(Error::Locked));
        assert_eq!(s.export_vault().err(), Some(Error::Locked));
        assert_eq!(s.write(1, |_, _| Ok(())).err(), Some(Error::Locked));
        assert_eq!(s.change_password(PW, "x").err(), Some(Error::Locked));
    }

    #[test]
    fn unlock_with_password_and_with_recovery_key_and_wrong_secrets_fail() {
        let (s, recovery) = new_mem();
        let h = s.header().clone();
        assert!(Session::<MemStore>::unlock(&h, PW, "d", |_| Ok(MemStore::new())).is_ok());
        assert_eq!(
            Session::<MemStore>::unlock(&h, "wrong-fake-pass", "d", |_| Ok(MemStore::new())).err(),
            Some(Error::Decryption)
        );
        assert!(
            Session::<MemStore>::unlock_with_recovery(&h, &recovery, "d", |_| Ok(MemStore::new()))
                .is_ok()
        );
        assert_eq!(
            Session::<MemStore>::unlock_with_recovery(
                &h,
                "not-a-key",
                "d",
                |_| Ok(MemStore::new())
            )
            .err(),
            Some(Error::Corrupted)
        );
        assert_eq!(
            Session::<MemStore>::unlock(&h, PW, "", |_| Ok(MemStore::new())).err(),
            Some(Error::InvalidInput)
        );
    }

    // Uses production Argon2 parameters for the new password: the one slow test here.
    #[test]
    fn change_password_requires_the_current_one_and_keeps_the_data_readable() {
        let (mut s, recovery) = new_mem();
        add_login(&mut s, 10, "Mail", "fake-secret");
        assert_eq!(
            s.change_password("wrong-fake-pass", "new-fake-pass").err(),
            Some(Error::Decryption)
        );
        assert_eq!(s.change_password(PW, "  ").err(), Some(Error::InvalidInput));
        let h = s.change_password(PW, "new-fake-pass").unwrap();
        assert_eq!(&h, s.header());
        assert!(h.unlock(PW.as_bytes()).is_err());
        assert!(h.unlock(b"new-fake-pass").is_ok());
        // The sealed file written after the change opens with the new header only.
        let sealed = s.export_vault().unwrap();
        let t = Session::<MemStore>::from_vault_file(
            &sealed.file,
            UnlockSecret::Password("new-fake-pass"),
            "dev-b",
            &|n| blobs(&sealed).get(n).cloned(),
            |_| Ok(MemStore::new()),
        )
        .unwrap();
        assert_eq!(t.store().unwrap().list_items().unwrap().len(), 1);
        // The Recovery Key still works after a password change.
        assert!(
            Session::<MemStore>::unlock_with_recovery(&h, &recovery, "d", |_| Ok(MemStore::new()))
                .is_ok()
        );
    }

    #[test]
    fn rotating_the_recovery_key_requires_the_password_and_invalidates_the_old_key() {
        let (mut s, old) = new_mem();
        assert!(!s.requires_password_reset());
        assert_eq!(
            s.rotate_recovery_key("wrong-fake-pass").err(),
            Some(Error::Decryption)
        );
        let (h, new) = s.rotate_recovery_key(PW).unwrap();
        assert_eq!(&h, s.header());
        let open = |h: &VaultHeader, k: &str| {
            Session::<MemStore>::unlock_with_recovery(h, k, "d", |_| Ok(MemStore::new()))
        };
        assert!(open(&h, &old).is_err());
        assert!(open(&h, &new).is_ok());
        assert!(h.unlock(PW.as_bytes()).is_ok());
        let mut locked = s;
        locked.lock();
        assert_eq!(locked.rotate_recovery_key(PW).err(), Some(Error::Locked));
    }

    #[test]
    fn recovery_unlock_requires_a_password_reset_until_the_password_changes() {
        let (s, recovery) = new_mem();
        let mut r = Session::<MemStore>::unlock_with_recovery(s.header(), &recovery, "d", |_| {
            Ok(MemStore::new())
        })
        .unwrap();
        assert!(r.requires_password_reset());
        // Rotation after a recovery unlock needs no password (the old key was just exposed).
        let (h, new) = r.rotate_recovery_key("").unwrap();
        assert!(
            Session::<MemStore>::unlock_with_recovery(&h, &recovery, "d", |_| Ok(MemStore::new()))
                .is_err()
        );
        assert!(
            Session::<MemStore>::unlock_with_recovery(&h, &new, "d", |_| Ok(MemStore::new()))
                .is_ok()
        );
        assert!(r.requires_password_reset());
        r.change_password("", "new-fake-pass").unwrap();
        assert!(!r.requires_password_reset());
    }

    #[test]
    fn a_recovery_unlocked_session_may_set_a_new_password_without_the_old_one() {
        let (s, recovery) = new_mem();
        let mut r = Session::<MemStore>::unlock_with_recovery(s.header(), &recovery, "d", |_| {
            Ok(MemStore::new())
        })
        .unwrap();
        let h = r.change_password("", "new-fake-pass").unwrap();
        assert!(h.unlock(b"new-fake-pass").is_ok());
        // Afterwards the normal rule applies again.
        assert_eq!(
            r.change_password("", "another-fake").err(),
            Some(Error::Decryption)
        );
    }

    #[test]
    fn attachments_travel_as_encrypted_side_blobs_between_devices() {
        let (mut a, _) = new_mem();
        let mail = add_login(&mut a, 10, "Mail", "fake-secret");
        let file = b"%PDF-1.7 fake attachment bytes".to_vec();
        let att = a
            .write(11, |st, ctx| {
                st.add_attachment(ctx, &mail, "scan.pdf", "application/pdf", &file)
            })
            .unwrap();
        let sealed = a.export_vault().unwrap();
        // The provider-visible pieces never contain the bytes or the name.
        assert_eq!(sealed.side_blobs.len(), 1);
        for piece in [&sealed.file, &sealed.side_blobs[0].sealed] {
            assert!(!piece.windows(file.len()).any(|w| w == &file[..]));
            assert!(!piece.windows(8).any(|w| w == b"scan.pdf"));
        }
        assert_eq!(
            a.required_side_blobs(&sealed.file).unwrap(),
            [sealed.side_blobs[0].name.clone()]
        );

        // Missing blob is reported, not silently dropped.
        let none = Session::<Database>::from_vault_file(
            &sealed.file,
            UnlockSecret::Password(PW),
            "dev-b",
            &|_| None,
            |k| Database::open_in_memory(&k.db_key()?),
        );
        assert_eq!(none.err(), Some(Error::NotFound));

        // Device B (SQLCipher) restores the attachment from the file plus the blob.
        let mut b = Session::<Database>::from_vault_file(
            &sealed.file,
            UnlockSecret::Password(PW),
            "dev-b",
            &|n| blobs(&sealed).get(n).cloned(),
            |k| Database::open_in_memory(&k.db_key()?),
        )
        .unwrap();
        let (info, bytes) = b.store().unwrap().read_attachment(&att).unwrap();
        assert_eq!(info.file_name, "scan.pdf");
        assert_eq!(bytes.as_slice(), &file[..]);

        // Deleting on B propagates a tombstone (no blob) back to A.
        b.write(20, |st, ctx| st.delete_attachment(ctx, &att))
            .unwrap();
        let back = b.export_vault().unwrap();
        assert!(back.side_blobs.is_empty());
        a.merge_remote_vault(&back.file, &|_| None).unwrap();
        assert!(a
            .store()
            .unwrap()
            .list_attachments(&mail)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn passkeys_sync_inside_the_encrypted_vault_and_sign_on_the_other_device() {
        let (mut a, _) = new_mem();
        let cdh = [0x24u8; 32];
        let reg = a
            .write(11, |st, ctx| {
                st.register_passkey(ctx, None, "example.com", "ana", &[3; 8], &cdh)
            })
            .unwrap();
        let key = a
            .store()
            .unwrap()
            .passkey_secret(&reg.passkey_id)
            .unwrap()
            .1;
        let sealed = a.export_vault().unwrap();
        // v6 payload, no side blobs, and the key never appears in what the provider sees.
        assert_eq!(sealed.file.get(crate::keys::HEADER_LEN), Some(&6));
        assert!(sealed.side_blobs.is_empty());
        assert!(!sealed.file.windows(32).any(|w| w == key.as_slice()));

        let b = Session::<Database>::from_vault_file(
            &sealed.file,
            UnlockSecret::Password(PW),
            "dev-b",
            &|_| None,
            |k| Database::open_in_memory(&k.db_key()?),
        )
        .unwrap();
        let on_a = a
            .store()
            .unwrap()
            .assert_passkey(&reg.passkey_id, &cdh)
            .unwrap();
        let on_b = b
            .store()
            .unwrap()
            .assert_passkey(&reg.passkey_id, &cdh)
            .unwrap();
        // Same key, deterministic nonces: both devices produce the same signature.
        assert_eq!(on_a, on_b);
    }

    #[test]
    fn two_devices_converge_through_exported_vault_files_across_backends() {
        let (mut a, _) = new_mem();
        let mail = add_login(&mut a, 10, "Mail", "fake-secret");
        let big = vec![7u8; 100 * 1024]; // above the side-blob threshold
        a.write(11, |st, ctx| st.add_note_image(ctx, "image/png", &big))
            .unwrap();
        let sealed = a.export_vault().unwrap();
        assert_eq!(sealed.side_blobs.len(), 1);

        // Device B: SQLCipher backend, bootstrapped from A's file.
        let names = a.required_side_blobs(&sealed.file).unwrap();
        assert_eq!(names, [sealed.side_blobs[0].name.clone()]);
        let mut b = Session::<Database>::from_vault_file(
            &sealed.file,
            UnlockSecret::Password(PW),
            "dev-b",
            &|n| blobs(&sealed).get(n).cloned(),
            |k| Database::open_in_memory(&k.db_key()?),
        )
        .unwrap();
        assert_eq!(b.store().unwrap().list_items().unwrap().len(), 1);

        // Concurrent edits on both devices.
        b.write(20, |st, ctx| st.record_use(ctx, &mail)).unwrap();
        let docs = add_login(&mut b, 30, "Docs", "fake-docs");
        a.write(40, |st, ctx| st.delete_item(ctx, &mail)).unwrap();
        let sa = a.export_vault().unwrap();
        let sb = b.export_vault().unwrap();

        let (ba, bb) = (blobs(&sa), blobs(&sb));
        a.merge_remote_vault(&sb.file, &|n| bb.get(n).cloned())
            .unwrap();
        b.merge_remote_vault(&sa.file, &|n| ba.get(n).cloned())
            .unwrap();
        let titles = |s: &dyn Fn() -> Vec<String>| s();
        let ta = titles(&|| {
            a.store()
                .unwrap()
                .list_items()
                .unwrap()
                .into_iter()
                .map(|i| i.title)
                .collect()
        });
        let tb = titles(&|| {
            b.store()
                .unwrap()
                .list_items()
                .unwrap()
                .into_iter()
                .map(|i| i.title)
                .collect()
        });
        assert_eq!(ta, ["Docs"]);
        assert_eq!(ta, tb);
        assert!(a.store().unwrap().get_item(&docs).is_ok());
        assert_eq!(
            a.store().unwrap().snapshot().unwrap(),
            b.store().unwrap().snapshot().unwrap()
        );
    }

    #[test]
    fn merging_a_file_from_another_vault_or_a_tampered_file_is_rejected_and_changes_nothing() {
        let (mut a, _) = new_mem();
        add_login(&mut a, 10, "Mail", "fake-secret");
        let (mut other, _) = new_mem();
        add_login(&mut other, 10, "Other", "fake-other");
        let foreign = other.export_vault().unwrap();
        let before = a.store().unwrap().snapshot().unwrap();
        assert_eq!(
            a.merge_remote_vault(&foreign.file, &|_| None).err(),
            Some(Error::InvalidInput)
        );
        let mut mine = a.export_vault().unwrap().file;
        let last = mine.len() - 1;
        mine[last] ^= 1;
        assert_eq!(
            a.merge_remote_vault(&mine, &|_| None).err(),
            Some(Error::Decryption)
        );
        assert_eq!(a.store().unwrap().snapshot().unwrap(), before);
    }

    #[test]
    fn totp_code_comes_from_a_stored_field_without_revealing_the_secret() {
        let (mut s, _) = new_mem();
        let id = s
            .write(10, |st, ctx| {
                let mut n = NewItem::new(ItemType::Credential, "Mail");
                n.fields = vec![
                    FieldInput::new("2fa", "totp", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", true),
                    FieldInput::new(
                        "2fa-uri",
                        "totp",
                        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
                        true,
                    ),
                    FieldInput::new("bad", "totp", "!!!", true),
                ];
                st.create_item(ctx, &n)
            })
            .unwrap();
        let fields = s.store().unwrap().get_item(&id).unwrap().fields;
        let c = s.totp_code(&id, &fields[0].id, 59).unwrap();
        assert_eq!(c.code, "287082");
        assert_eq!((c.seconds_remaining, c.period), (1, 30));
        assert_eq!(
            s.totp_code(&id, &fields[1].id, 59).unwrap().code,
            "94287082"
        );
        assert!(s.totp_code(&id, &fields[2].id, 59).is_err());
        assert_eq!(s.totp_code(&id, "nope", 59).err(), Some(Error::NotFound));
    }

    #[test]
    fn password_strengths_flag_reuse_and_weakness() {
        let (mut s, _) = new_mem();
        let a = add_login(&mut s, 10, "A", "123456");
        let b = add_login(&mut s, 20, "B", "vT9#kLq2$Zw8!mXc4Rp7");
        let c = add_login(&mut s, 30, "C", "vT9#kLq2$Zw8!mXc4Rp7");
        let r = s.password_strengths().unwrap();
        let get = |id: &str| r.iter().find(|p| p.item_id == id).unwrap();
        assert_eq!(get(&a).level, crate::generator::Strength::VeryWeak);
        assert!(!get(&a).reused);
        assert!(get(&b).reused && get(&c).reused);
        assert_eq!(get(&b).level, crate::generator::Strength::Strong);
        assert!(r.iter().all(|p| p.key.is_empty()));
    }

    #[test]
    fn breach_prefixes_and_match_keep_passwords_in_core() {
        let (mut s, _) = new_mem();
        let a = add_login(&mut s, 10, "A", "password");
        let _ = add_login(&mut s, 20, "B", "");
        let p = s.breach_prefixes().unwrap();
        assert_eq!(p, vec![(a.clone(), "5BAA6".to_string())]);
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:77\r\n";
        assert_eq!(s.breach_match(&a, body).unwrap(), 77);
        assert_eq!(s.breach_match(&a, "ABC:1").unwrap(), 0);
    }

    #[test]
    fn password_reuse_groups_lists_only_shared_passwords() {
        let (mut s, _) = new_mem();
        let a = add_login(&mut s, 10, "A", "123456");
        let b = add_login(&mut s, 20, "B", "vT9#kLq2$Zw8!mXc4Rp7");
        let c = add_login(&mut s, 30, "C", "vT9#kLq2$Zw8!mXc4Rp7");
        let d = add_login(&mut s, 40, "D", "vT9#kLq2$Zw8!mXc4Rp7");
        let e = add_login(&mut s, 50, "E", "123456");
        let mut g = s.password_reuse_groups().unwrap();
        for grp in &mut g {
            grp.sort();
        }
        let mut want_1 = vec![a, e];
        want_1.sort();
        let mut want_2 = vec![b, c, d];
        want_2.sort();
        assert_eq!(g.len(), 2);
        assert!(g.contains(&want_1) && g.contains(&want_2));
    }

    #[test]
    fn security_audit_reports_weak_reused_old_and_missing_2fa() {
        let (mut s, _) = new_mem();
        let day = 86_400_000i64;
        let weak = add_login(&mut s, 0, "Weak", "123456");
        let strong = add_login(&mut s, 100 * day, "Strong", "vT9#kLq2$Zw8!mXc4Rp7");
        let dup = add_login(&mut s, 100 * day, "Dup", "vT9#kLq2$Zw8!mXc4Rp7");
        let with_2fa = s
            .write(100 * day, |st, ctx| {
                let mut n = NewItem::new(ItemType::Credential, "Bank");
                n.url = Some("https://bank.example".into());
                n.fields = vec![
                    FieldInput::new("password", "password", "q8#Zr!pL2$vN7&xKd4Wm", true),
                    FieldInput::new("2FA", "totp", "JBSWY3DPEHPK3PXP", true),
                ];
                st.create_item(ctx, &n)
            })
            .unwrap();
        let no_2fa = s
            .write(100 * day, |st, ctx| {
                let mut n = NewItem::new(ItemType::Credential, "Shop");
                n.url = Some("https://shop.example".into());
                n.fields = vec![FieldInput::new(
                    "password",
                    "password",
                    "m4$Tz!qW9#bXr2&Lc7Pn",
                    true,
                )];
                st.create_item(ctx, &n)
            })
            .unwrap();
        let r = s.security_audit(100 * day, 90).unwrap();
        assert_eq!(r.weak, vec![weak.clone()]);
        assert_eq!(r.old, vec![weak]);
        assert_eq!(r.reused.len(), 1);
        assert!(r.reused[0].contains(&strong) && r.reused[0].contains(&dup));
        assert_eq!(r.missing_2fa, vec![no_2fa]);
        assert!(!r.missing_2fa.contains(&with_2fa));
    }

    #[test]
    fn password_reuse_groups_empty_without_reuse() {
        let (mut s, _) = new_mem();
        add_login(&mut s, 10, "A", "123456");
        add_login(&mut s, 20, "B", "vT9#kLq2$Zw8!mXc4Rp7");
        assert!(s.password_reuse_groups().unwrap().is_empty());
    }

    #[test]
    fn search_grouped_matches_non_secret_values_but_never_secrets() {
        let (mut s, _) = new_mem();
        let id = s
            .write(10, |st, ctx| {
                st.create_item(
                    ctx,
                    &NewItem {
                        item_type: ItemType::Credential,
                        title: "Mail".into(),
                        url: None,
                        vault_id: None,
                        category_id: None,
                        color: None,
                        favorite: false,
                        fields: vec![
                            FieldInput::new("Username", "email", "me@example.org", false),
                            FieldInput::new("Password", "password", "hunter2-secret", true),
                        ],
                        blocks: vec![],
                    },
                )
            })
            .unwrap();
        let g = s.search_grouped("me@example", None).unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].items[0].id, id);
        assert!(s.search_grouped("hunter2", None).unwrap().is_empty());
        assert!(s.search_grouped("  ", None).unwrap().is_empty());
    }

    #[test]
    fn search_filters_and_sorts_through_the_session() {
        let (mut s, _) = new_mem();
        let a = add_login(&mut s, 10, "GitHub", "fake-1");
        add_login(&mut s, 20, "Bank", "fake-2");
        s.write(30, |st, ctx| st.record_use(ctx, &a)).unwrap();
        let hits = s
            .search(&ItemFilter {
                query: "git".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        let used = s
            .search(&ItemFilter {
                sort: SortOrder::MostUsed,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(used[0].title, "GitHub");
    }
}
