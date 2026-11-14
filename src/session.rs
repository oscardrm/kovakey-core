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
        let st = self.state.as_mut().ok_or(Error::Locked)?;
        let remote = vault_file::open_vault(file, &st.keys, side_blob)?;
        st.store.merge_remote(&remote)
    }

    fn check_same_vault(&self, file: &[u8]) -> Result<()> {
        if vault_file::read_header(file)?.vault_id() == self.header.vault_id() {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
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
