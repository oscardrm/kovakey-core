//! An unlockable vault session: the single object UIs talk to through FFI / wasm.
//!
//! The data key lives only inside the session. Nothing here returns it, and nothing derived from
//! it except sealed blobs (`.vault` files, side blobs) and the *wrapped* header. [`Session::lock`]
//! drops the keys and the store (zeroizing both; for SQLCipher this closes the connection);
//! afterwards every operation fails with [`Error::Locked`].
//!
//! Storage is pluggable ([`VaultStore`]): SQLCipher on native targets, [`crate::mem_store::MemStore`]
//! everywhere. Time is injected per call (`now_ms`), never read here.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::{VaultHeader, VaultKeys};
use crate::ops::{non_empty, VaultStore, WriteCtx};
use crate::recovery::RecoveryKey;
use crate::search::{filter_items, ItemFilter};
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

    /// Current TOTP code of a `totp` field. The field holds a Base32 secret or an `otpauth://`
    /// URI; the secret itself never leaves the session.
    pub fn totp_code(&self, item_id: &str, field_id: &str, unix_secs: u64) -> Result<TotpCode> {
        let value = self.store()?.reveal_field(item_id, field_id)?;
        let value = value.trim();
        let totp = if value.starts_with("otpauth://") {
            Totp::from_uri(value)?
        } else {
            Totp::from_base32(value, crate::totp::Algorithm::Sha1, 6, 30)?
        };
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
