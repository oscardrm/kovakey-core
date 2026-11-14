//! Backend-independent write context, inputs and read views of the CRUD layer, plus the
//! [`VaultStore`] trait implemented by the SQLCipher `Database` (native) and by
//! [`crate::mem_store::MemStore`] (portable, wasm).
//!
//! Invariants every backend upholds (ADR 0001):
//! * A failed call changes nothing.
//! * Deletes are tombstones. Deleting an item tombstones its fields, note blocks and tag links and
//!   **scrubs** secret payloads (field values, note bodies). Password history is retained.
//! * Changing a `password` field writes the old value to the password history, only if it changed.
//! * The auto-tagger runs on create/update and never re-adds a tag the user removed or deleted.
//! * Callers inject time and device id ([`WriteCtx`]); core never reads the wall clock. A record's
//!   `updated_at` is always strictly greater than its previous value, even if the clock moves back.
//! * List/get return non-secret views; secrets come only from `reveal_*`.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::models::{
    BlockKind, Category, CategoryField, HistoryEntry, InputKind, ItemType, NoteBlock, Snapshot,
    Tag, VaultMeta,
};

/// Time and writer identity for a write. Injected so core stays free of wall-clock access.
#[derive(Clone, Copy, Debug)]
pub struct WriteCtx<'a> {
    /// Current time, Unix ms UTC.
    pub now_ms: i64,
    /// Stable id of this device (merge tie-break). Must not be empty.
    pub device_id: &'a str,
}

/// New category.
#[derive(Clone, Debug)]
pub struct NewCategory {
    /// Name (non-empty).
    pub name: String,
    /// Category color.
    pub color: String,
    /// Icon identifier.
    pub icon: String,
    /// Icon color (independent from `color`).
    pub icon_color: String,
    /// Extra inputs of the category form (all ids must be `None`; never core).
    pub fields: Vec<CategoryFieldInput>,
}

/// Input for one category field. `id: None` creates a (non-core) field; `Some` targets that
/// existing field.
#[derive(Clone, Debug)]
pub struct CategoryFieldInput {
    /// Existing field id, or `None` for a new field.
    pub id: Option<String>,
    /// Display name (non-empty).
    pub name: String,
    /// Input type: an [`InputKind`] storage identifier.
    pub kind: String,
    /// Whether values are secret. Ignored for core fields (fixed).
    pub is_secret: bool,
}

impl CategoryFieldInput {
    /// New field of `kind`, secret by the kind's default.
    pub fn new(name: &str, kind: InputKind) -> Self {
        Self {
            id: None,
            name: name.to_string(),
            kind: kind.as_str().to_string(),
            is_secret: kind.secret_by_default(),
        }
    }
}

/// Input for one item field. `id: None` creates a field; `Some` updates that existing field.
#[derive(Clone)]
pub struct FieldInput {
    /// Existing field id, or `None` for a new field.
    pub id: Option<String>,
    /// Display name (non-empty).
    pub name: String,
    /// Kind: `text`, `password`, `totp`, `url`, ...
    pub kind: String,
    /// Value.
    pub value: String,
    /// Whether the value is secret.
    pub is_secret: bool,
}

impl FieldInput {
    /// New field.
    pub fn new(name: &str, kind: &str, value: &str, is_secret: bool) -> Self {
        Self {
            id: None,
            name: name.to_string(),
            kind: kind.to_string(),
            value: value.to_string(),
            is_secret,
        }
    }

    /// Target an existing field id.
    pub fn with_id(mut self, id: &str) -> Self {
        self.id = Some(id.to_string());
        self
    }
}

impl fmt::Debug for FieldInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldInput")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for FieldInput {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Input for one note block. `id: None` creates a block; `Some` updates that existing block.
/// Block order is the order in the list. Code blocks without a language get one detected.
#[derive(Clone)]
pub struct BlockInput {
    /// Existing block id, or `None`.
    pub id: Option<String>,
    /// Block kind.
    pub kind: BlockKind,
    /// Code language id.
    pub language: Option<String>,
    /// Body.
    pub content: String,
    /// Image reference for image blocks (see `VaultStore::add_note_image`).
    pub image_id: Option<String>,
}

impl fmt::Debug for BlockInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockInput")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("content", &"<redacted>")
            .finish()
    }
}

impl Drop for BlockInput {
    fn drop(&mut self) {
        self.content.zeroize();
    }
}

/// New item.
#[derive(Clone, Debug)]
pub struct NewItem {
    /// Item type.
    pub item_type: ItemType,
    /// Title (non-empty).
    pub title: String,
    /// URL.
    pub url: Option<String>,
    /// Vault to create the item in (must be live). `None` = the default vault.
    pub vault_id: Option<String>,
    /// Category (must be live).
    pub category_id: Option<String>,
    /// Accent color.
    pub color: Option<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Fields (all ids must be `None`).
    pub fields: Vec<FieldInput>,
    /// Note blocks (all ids must be `None`).
    pub blocks: Vec<BlockInput>,
}

impl NewItem {
    /// Item with a type and title and nothing else.
    pub fn new(item_type: ItemType, title: &str) -> Self {
        Self {
            item_type,
            title: title.to_string(),
            url: None,
            vault_id: None,
            category_id: None,
            color: None,
            favorite: false,
            fields: Vec::new(),
            blocks: Vec::new(),
        }
    }
}

/// Partial item update. `None` leaves a value unchanged; for nullable values `Some(None)` clears
/// it. `fields` / `blocks`: `Some(list)` is the complete new set; existing entries missing from
/// the list are tombstoned and scrubbed.
#[derive(Clone, Debug, Default)]
pub struct ItemUpdate {
    /// New title.
    pub title: Option<String>,
    /// New URL.
    pub url: Option<Option<String>>,
    /// Move the item to this vault (must be live).
    pub vault_id: Option<String>,
    /// New category.
    pub category_id: Option<Option<String>>,
    /// New accent color.
    pub color: Option<Option<String>>,
    /// New favorite flag.
    pub favorite: Option<bool>,
    /// Complete new field set.
    pub fields: Option<Vec<FieldInput>>,
    /// Complete new note block set.
    pub blocks: Option<Vec<BlockInput>>,
}

/// Vault changes (`None` = unchanged; `badge: Some(None)` clears the badge).
#[derive(Clone, Debug, Default)]
pub struct VaultUpdate {
    /// New name.
    pub name: Option<String>,
    /// New color (`#RRGGBB`).
    pub color: Option<String>,
    /// New badge.
    pub badge: Option<Option<String>>,
}

const MAX_VAULT_NAME_CHARS: usize = 64;
const MAX_VAULT_BADGE_CHARS: usize = 4;

/// Trimmed, validated vault name (non-empty, ≤ 64 chars, no control characters).
pub(crate) fn clean_vault_name(name: &str) -> Result<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_VAULT_NAME_CHARS || n.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    Ok(n.to_string())
}

/// Validated `#RRGGBB` color.
pub(crate) fn check_vault_color(color: &str) -> Result<()> {
    let ok = color.len() == 7
        && color.starts_with('#')
        && color.chars().skip(1).all(|c| c.is_ascii_hexdigit());
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Trimmed badge (≤ 4 chars, no control characters); empty means "no badge".
pub(crate) fn clean_vault_badge(badge: &str) -> Result<Option<String>> {
    let b = badge.trim();
    if b.chars().count() > MAX_VAULT_BADGE_CHARS || b.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    Ok((!b.is_empty()).then(|| b.to_string()))
}

/// Upper bound of live vaults per account.
pub(crate) const MAX_VAULTS: usize = 64;

/// Category changes (`None` = unchanged).
#[derive(Clone, Debug, Default)]
pub struct CategoryUpdate {
    /// New name.
    pub name: Option<String>,
    /// New color.
    pub color: Option<String>,
    /// New icon.
    pub icon: Option<String>,
    /// New icon color.
    pub icon_color: Option<String>,
    /// Complete new field template. Live fields missing from the list are tombstoned, except
    /// core fields: omitting one fails with [`Error::InvalidInput`] and changes nothing.
    pub fields: Option<Vec<CategoryFieldInput>>,
}

/// Non-secret list row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemSummary {
    /// Item id.
    pub id: String,
    /// Item type.
    pub item_type: ItemType,
    /// Title.
    pub title: String,
    /// URL.
    pub url: Option<String>,
    /// Vault the item lives in.
    pub vault_id: String,
    /// Live category, `None` if unset or the category was deleted.
    pub category_id: Option<String>,
    /// Accent color.
    pub color: Option<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Usage counter.
    pub use_count: i64,
    /// Last use time.
    pub last_used_at: Option<i64>,
    /// Last modification time.
    pub updated_at: i64,
    /// Names of live tags.
    pub tags: Vec<String>,
    /// When the item was moved to the Trash (`None` for items outside the Trash).
    pub trashed_at: Option<i64>,
}

/// Field as shown by [`Database::get_item`]: secret values are withheld.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldView {
    /// Field id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: String,
    /// Whether the value is secret.
    pub is_secret: bool,
    /// Value; `None` for secret fields (use `VaultStore::reveal_field`).
    pub value: Option<String>,
}

/// Item with fields and note blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemDetail {
    /// Summary row.
    pub summary: ItemSummary,
    /// Live fields in display order.
    pub fields: Vec<FieldView>,
    /// Live note blocks in order.
    pub blocks: Vec<NoteBlock>,
}

/// `max(now, prev + 1)`: a record's timestamp never goes backwards or repeats.
pub(crate) fn bump(prev: i64, now: i64) -> i64 {
    now.max(prev.saturating_add(1))
}

pub(crate) fn new_id(ctx: &WriteCtx<'_>) -> Result<String> {
    let ms = u64::try_from(ctx.now_ms).map_err(|_| Error::InvalidInput)?;
    let nanos = u32::try_from((ms % 1000) * 1_000_000).map_err(|_| Error::InvalidInput)?;
    let ts = uuid::Timestamp::from_unix(uuid::NoContext, ms / 1000, nanos);
    Ok(uuid::Uuid::new_v7(ts).to_string())
}

pub(crate) fn non_empty(s: &str) -> Result<()> {
    if s.trim().is_empty() {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

const DAY_MS: i64 = 86_400_000;

/// Permanently delete every trashed item (tombstone + content wipe). Returns how many were purged.
pub fn empty_trash<S: VaultStore>(store: &mut S, ctx: &WriteCtx<'_>) -> Result<u32> {
    let mut purged = 0;
    for item in store.list_trashed_items()? {
        store.delete_item(ctx, &item.id)?;
        purged += 1;
    }
    Ok(purged)
}

/// Permanently delete trashed items that have been in the Trash for at least `retention_days`
/// (PRD §9.3, default 30 in the apps). `retention_days == 0` keeps trashed items forever.
/// Returns how many were purged.
pub fn purge_expired_trash<S: VaultStore>(
    store: &mut S,
    ctx: &WriteCtx<'_>,
    retention_days: u32,
) -> Result<u32> {
    if retention_days == 0 {
        return Ok(0);
    }
    let cutoff = ctx
        .now_ms
        .saturating_sub(i64::from(retention_days).saturating_mul(DAY_MS));
    let mut purged = 0;
    for item in store.list_trashed_items()? {
        if item.trashed_at.is_some_and(|t| t <= cutoff) {
            store.delete_item(ctx, &item.id)?;
            purged += 1;
        }
    }
    Ok(purged)
}

/// Storage backend of an unlocked vault: the full CRUD surface plus snapshot access.
///
/// Implemented by the SQLCipher `Database` (native) and by [`crate::mem_store::MemStore`]
/// (portable). `tests/store_conformance.rs` runs the same scenarios against both so behaviour
/// cannot drift.
pub trait VaultStore {
    /// Create an item with its fields and note blocks, then run the auto-tagger. Returns its id.
    fn create_item(&mut self, ctx: &WriteCtx<'_>, new: &NewItem) -> Result<String>;
    /// Update an item; writes nothing if no value changes.
    fn update_item(&mut self, ctx: &WriteCtx<'_>, id: &str, upd: &ItemUpdate) -> Result<()>;
    /// Permanently delete an item (live or trashed): tombstone it with its children and scrub
    /// secret payloads. Use [`VaultStore::trash_item`] for the recoverable delete.
    fn delete_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
    /// Move a live item to the Trash. Its content is kept; it disappears from
    /// [`VaultStore::list_items`], search and autofill. Trashing a trashed item is a no-op.
    fn trash_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
    /// Take an item out of the Trash. Restoring an item that is not trashed is a no-op;
    /// a permanently deleted item is `NotFound`.
    fn restore_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
    /// Summaries of trashed items, most recently trashed first.
    fn list_trashed_items(&self) -> Result<Vec<ItemSummary>>;
    /// Live vaults, default first (ordered by creation time, then id).
    fn list_vaults(&self) -> Result<Vec<VaultMeta>>;
    /// Create a vault. Names are unique (case-insensitive) among live vaults.
    fn create_vault(
        &mut self,
        ctx: &WriteCtx<'_>,
        name: &str,
        color: &str,
        badge: Option<&str>,
    ) -> Result<VaultMeta>;
    /// Rename / recolor / re-badge a live vault.
    fn update_vault(
        &mut self,
        ctx: &WriteCtx<'_>,
        id: &str,
        upd: &VaultUpdate,
    ) -> Result<VaultMeta>;
    /// Delete a vault: every item in it (including trashed ones) moves to the live vault
    /// `move_items_to`, then the vault is tombstoned. Fails if `id == move_items_to`.
    fn delete_vault(&mut self, ctx: &WriteCtx<'_>, id: &str, move_items_to: &str) -> Result<()>;
    /// Create the default vault if the store has never had one (never resurrects a deleted one).
    fn ensure_default_vault(&mut self, ctx: &WriteCtx<'_>) -> Result<()>;
    /// Record one use (copy/autofill).
    fn record_use(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
    /// Non-secret summaries of all live items outside the Trash, sorted by title.
    fn list_items(&self) -> Result<Vec<ItemSummary>>;
    /// A live item with fields (secrets withheld) and note blocks.
    fn get_item(&self, id: &str) -> Result<ItemDetail>;
    /// Value of one live field (the only way to read secret field values).
    fn reveal_field(&self, item_id: &str, field_id: &str) -> Result<Zeroizing<String>>;
    /// Password history of an item, newest first.
    fn reveal_password_history(&self, item_id: &str) -> Result<Vec<HistoryEntry>>;
    /// Create a tag, or return the live tag with the same name.
    fn create_tag(&mut self, ctx: &WriteCtx<'_>, name: &str, color: &str) -> Result<Tag>;
    /// Live tags sorted by name.
    fn list_tags(&self) -> Result<Vec<Tag>>;
    /// Rename and/or recolor a live tag. Fails with `InvalidInput` if the new name is empty or used
    /// by another live tag, and `NotFound` if the tag does not exist or is deleted.
    fn update_tag(
        &mut self,
        ctx: &WriteCtx<'_>,
        tag_id: &str,
        name: Option<&str>,
        color: Option<&str>,
    ) -> Result<Tag>;
    /// Delete a tag and its links.
    fn delete_tag(&mut self, ctx: &WriteCtx<'_>, tag_id: &str) -> Result<()>;
    /// Attach a tag to an item (user choice).
    fn add_tag(&mut self, ctx: &WriteCtx<'_>, item_id: &str, tag_id: &str) -> Result<()>;
    /// Remove a tag from an item.
    fn remove_tag(&mut self, ctx: &WriteCtx<'_>, item_id: &str, tag_id: &str) -> Result<()>;
    /// Create a category, appended after the existing ones.
    fn create_category(&mut self, ctx: &WriteCtx<'_>, new: &NewCategory) -> Result<Category>;
    /// Update a live category.
    fn update_category(&mut self, ctx: &WriteCtx<'_>, id: &str, upd: &CategoryUpdate)
        -> Result<()>;
    /// Set the display order of live categories.
    fn reorder_categories(&mut self, ctx: &WriteCtx<'_>, ordered_ids: &[String]) -> Result<()>;
    /// Tombstone a category.
    fn delete_category(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
    /// Live categories in display order.
    fn list_categories(&self) -> Result<Vec<Category>>;
    /// Live inputs of a live category in display order.
    fn list_category_fields(&self, category_id: &str) -> Result<Vec<CategoryField>>;
    /// Create the built-in preset categories that do not exist yet (tombstoned ones are not
    /// re-created). Idempotent; call after creating or unlocking a vault.
    fn seed_default_categories(&mut self, ctx: &WriteCtx<'_>) -> Result<()>;
    /// Store an immutable note image; returns its id.
    fn add_note_image(
        &mut self,
        ctx: &WriteCtx<'_>,
        mime_type: &str,
        data: &[u8],
    ) -> Result<String>;
    /// MIME type and bytes of a stored note image.
    fn note_image(&self, id: &str) -> Result<(String, Zeroizing<Vec<u8>>)>;
    /// Attach a file to a live item; returns the attachment id. The name is sanitized, the MIME
    /// type validated and the per-file / per-vault limits enforced (ADR 0019).
    fn add_attachment(
        &mut self,
        ctx: &WriteCtx<'_>,
        item_id: &str,
        file_name: &str,
        mime_type: &str,
        data: &[u8],
    ) -> Result<String>;
    /// Live attachments of an item (metadata only), oldest first.
    fn list_attachments(&self, item_id: &str) -> Result<Vec<AttachmentInfo>>;
    /// Metadata and bytes of a live attachment.
    fn read_attachment(&self, id: &str) -> Result<(AttachmentInfo, Zeroizing<Vec<u8>>)>;
    /// Rename a live attachment (sanitized).
    fn rename_attachment(&mut self, ctx: &WriteCtx<'_>, id: &str, file_name: &str) -> Result<()>;
    /// Tombstone an attachment and scrub its bytes.
    fn delete_attachment(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
    /// Store a passkey on a live, non-trashed item; returns its record id. A live passkey of the same
    /// relying party and user handle is replaced (tombstoned, key scrubbed) in the same transaction,
    /// as WebAuthn requires. Inputs must already be validated (see [`VaultStore::register_passkey`]).
    fn add_passkey(
        &mut self,
        ctx: &WriteCtx<'_>,
        item_id: &str,
        new: &NewPasskey,
    ) -> Result<String>;
    /// Live passkeys of an item (metadata only), oldest first.
    fn list_passkeys(&self, item_id: &str) -> Result<Vec<PasskeyInfo>>;
    /// Live passkeys for a relying party on items that are not trashed (metadata only), newest
    /// first. `rp_id` is normalized first; an invalid one yields an empty list.
    fn passkeys_for_rp(&self, rp_id: &str) -> Result<Vec<PasskeyInfo>>;
    /// Metadata and private key of a live passkey on a non-trashed item. **Core-internal**: never
    /// expose it through FFI/wasm; bindings call [`VaultStore::assert_passkey`] instead.
    fn passkey_secret(&self, id: &str) -> Result<(PasskeyInfo, Zeroizing<Vec<u8>>)>;
    /// Tombstone a passkey and scrub its key.
    fn delete_passkey(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;

    /// Create a passkey (ADR 0020): validates the untrusted inputs, generates an ES256 key, stores it
    /// on `item_id` (or on a new Credential item for the site when `None`) and returns the
    /// registration response. The private key never leaves the core.
    fn register_passkey(
        &mut self,
        ctx: &WriteCtx<'_>,
        item_id: Option<&str>,
        rp_id: &str,
        user_name: &str,
        user_handle: &[u8],
        client_data_hash: &[u8],
    ) -> Result<PasskeyRegistration> {
        let rp_id = crate::passkey::normalize_rp_id(rp_id)?;
        let user_name = crate::passkey::clean_user_name(user_name);
        crate::passkey::check_user_handle(user_handle)?;
        crate::passkey::check_client_data_hash(client_data_hash)?;
        let private_key = crate::passkey::generate_private_key()?;
        let credential_id = crate::passkey::new_credential_id()?;
        let cose = crate::passkey::cose_public_key(&private_key)?;
        let auth_data = crate::passkey::authenticator_data(
            &rp_id,
            crate::passkey::REGISTRATION_FLAGS,
            Some((&credential_id, &cose)),
        )?;
        let attestation_object = crate::passkey::attestation_object(&auth_data)?;
        // Validation and key generation are done; only storage can fail from here on.
        let item_id = match item_id {
            Some(id) => id.to_string(),
            None => {
                let mut item = NewItem::new(ItemType::Credential, &rp_id);
                item.url = Some(format!("https://{rp_id}"));
                if !user_name.is_empty() {
                    item.fields = vec![FieldInput::new("Username", "text", &user_name, false)];
                }
                self.create_item(ctx, &item)?
            }
        };
        let new = NewPasskey {
            credential_id: credential_id.clone(),
            rp_id,
            user_name,
            user_handle: user_handle.to_vec(),
            private_key,
        };
        let passkey_id = self.add_passkey(ctx, &item_id, &new)?;
        Ok(PasskeyRegistration {
            passkey_id,
            item_id,
            credential_id,
            authenticator_data: auth_data,
            attestation_object,
        })
    }

    /// Sign a WebAuthn assertion with a stored passkey (ADR 0020). Read-only: the sign count stays 0.
    fn assert_passkey(&self, id: &str, client_data_hash: &[u8]) -> Result<PasskeyAssertion> {
        crate::passkey::check_client_data_hash(client_data_hash)?;
        let (info, key) = self.passkey_secret(id)?;
        let auth_data =
            crate::passkey::authenticator_data(&info.rp_id, crate::passkey::ASSERTION_FLAGS, None)?;
        let signature = crate::passkey::sign_assertion(&key, &auth_data, client_data_hash)?;
        Ok(PasskeyAssertion {
            rp_id: info.rp_id.clone(),
            credential_id: info.credential_id.clone(),
            user_handle: info.user_handle.clone(),
            authenticator_data: auth_data,
            signature,
        })
    }
    /// The whole vault as a merge snapshot.
    fn snapshot(&self) -> Result<Snapshot>;
    /// Merge a decrypted remote snapshot atomically.
    fn merge_remote(&mut self, remote: &Snapshot) -> Result<()>;
}

/// Non-secret view of an attachment (ADR 0019); the bytes come from `read_attachment`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentInfo {
    /// Attachment id.
    pub id: String,
    /// Owning item.
    pub item_id: String,
    /// Sanitized file name.
    pub file_name: String,
    /// MIME type as declared when it was added.
    pub mime_type: String,
    /// Size in bytes.
    pub size: u64,
    /// Creation time, Unix ms UTC.
    pub created_at: i64,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
}

/// A validated passkey to store (built by [`VaultStore::register_passkey`]).
pub struct NewPasskey {
    /// WebAuthn credential id.
    pub credential_id: Vec<u8>,
    /// Normalized relying-party id.
    pub rp_id: String,
    /// Cleaned user name.
    pub user_name: String,
    /// User handle (1–64 bytes).
    pub user_handle: Vec<u8>,
    /// P-256 private scalar.
    pub private_key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for NewPasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewPasskey(<redacted>)")
    }
}

/// Non-secret view of a passkey (ADR 0020). `rp_id`, `user_name` and `user_handle` are untrusted
/// site data; show them as plain text only.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyInfo {
    /// Record id.
    pub id: String,
    /// Owning item.
    pub item_id: String,
    /// WebAuthn credential id.
    pub credential_id: Vec<u8>,
    /// Relying-party id.
    pub rp_id: String,
    /// Account name.
    pub user_name: String,
    /// User handle.
    pub user_handle: Vec<u8>,
    /// Creation time, Unix ms UTC.
    pub created_at: i64,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
}

impl fmt::Debug for PasskeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyInfo")
            .field("id", &self.id)
            .field("item_id", &self.item_id)
            .finish_non_exhaustive()
    }
}

/// Registration response handed to the platform.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyRegistration {
    /// Stored record id.
    pub passkey_id: String,
    /// Item that holds the passkey (new when none was given).
    pub item_id: String,
    /// WebAuthn credential id.
    pub credential_id: Vec<u8>,
    /// Authenticator data (with attested credential data).
    pub authenticator_data: Vec<u8>,
    /// CBOR attestation object (`fmt: "none"`).
    pub attestation_object: Vec<u8>,
}

impl fmt::Debug for PasskeyRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyRegistration")
            .field("passkey_id", &self.passkey_id)
            .field("item_id", &self.item_id)
            .finish_non_exhaustive()
    }
}

/// Assertion response handed to the platform.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyAssertion {
    /// Relying-party id.
    pub rp_id: String,
    /// WebAuthn credential id.
    pub credential_id: Vec<u8>,
    /// User handle.
    pub user_handle: Vec<u8>,
    /// Authenticator data (no attested data).
    pub authenticator_data: Vec<u8>,
    /// DER ECDSA signature over `authenticator_data ‖ client_data_hash`.
    pub signature: Vec<u8>,
}

impl fmt::Debug for PasskeyAssertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasskeyAssertion(<redacted>)")
    }
}

/// Longest stored file name, in bytes.
pub const MAX_FILE_NAME_BYTES: usize = 255;

/// Turn an externally supplied file name into a safe display name: keeps only the last path
/// component, drops control characters and bidirectional overrides (which can disguise an
/// extension), trims surrounding spaces and dots, and caps the length. An empty result is
/// [`Error::InvalidInput`]. The name is never used to build a path inside the core.
pub fn sanitize_file_name(raw: &str) -> Result<String> {
    let last = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = last
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c: char| c == '.' || c.is_whitespace());
    let mut out = String::new();
    for c in trimmed.chars() {
        if out.len() + c.len_utf8() > MAX_FILE_NAME_BYTES {
            break;
        }
        out.push(c);
    }
    if out.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(out)
}

/// Accept only a plain `type/subtype` MIME string (ASCII graphic, at most 127 bytes). It is stored
/// for display and export hints; the core never picks behavior from it.
pub fn check_mime_type(mime: &str) -> Result<()> {
    let ok = !mime.is_empty()
        && mime.len() <= 127
        && mime.bytes().all(|b| b.is_ascii_graphic())
        && mime.matches('/').count() == 1
        && !mime.starts_with('/')
        && !mime.ends_with('/');
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Enforce the per-file and per-vault attachment limits (ADR 0019). `live_total` is the number of
/// bytes already held by live attachments.
pub fn check_attachment_size(len: usize, live_total: u64) -> Result<()> {
    if len == 0 || len > crate::models::MAX_ATTACHMENT_BYTES {
        return Err(Error::InvalidInput);
    }
    if live_total.saturating_add(len as u64) > crate::models::MAX_VAULT_ATTACHMENT_BYTES {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Validate a category field input and turn it into a record body.
fn check_input(i: &CategoryFieldInput) -> Result<InputKind> {
    non_empty(&i.name)?;
    InputKind::parse(&i.kind)
}

/// Records to upsert for a category's new complete field template.
///
/// `existing` are all stored fields of the category (tombstones included). Returns only records
/// that actually change; core fields keep their kind and secrecy and cannot be omitted.
pub(crate) fn plan_field_update(
    ctx: &WriteCtx<'_>,
    category_id: &str,
    existing: &[CategoryField],
    inputs: &[CategoryFieldInput],
) -> Result<Vec<CategoryField>> {
    let mut out: Vec<CategoryField> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for (pos, input) in inputs.iter().enumerate() {
        let kind = check_input(input)?;
        let order = i64::try_from(pos).map_err(|_| Error::InvalidInput)?;
        match &input.id {
            None => out.push(CategoryField {
                id: new_id(ctx)?,
                category_id: category_id.to_string(),
                name: input.name.trim().to_string(),
                kind: kind.as_str().to_string(),
                is_secret: input.is_secret,
                is_core: false,
                sort_order: order,
                updated_at: ctx.now_ms,
                updated_by: ctx.device_id.to_string(),
                deleted_at: None,
            }),
            Some(id) => {
                if seen.contains(&id.as_str()) {
                    return Err(Error::InvalidInput);
                }
                seen.push(id);
                let cur = existing
                    .iter()
                    .find(|f| &f.id == id && f.deleted_at.is_none())
                    .ok_or(Error::NotFound)?;
                let (kind_s, secret) = if cur.is_core {
                    if kind.as_str() != cur.kind {
                        return Err(Error::InvalidInput);
                    }
                    (cur.kind.clone(), cur.is_secret)
                } else {
                    (kind.as_str().to_string(), input.is_secret)
                };
                let name = input.name.trim().to_string();
                if (&name, &kind_s, secret, cur.sort_order)
                    != (&cur.name, &cur.kind, cur.is_secret, order)
                {
                    let mut f = cur.clone();
                    f.name = name;
                    f.kind = kind_s;
                    f.is_secret = secret;
                    f.sort_order = order;
                    f.updated_at = bump(cur.updated_at, ctx.now_ms);
                    f.updated_by = ctx.device_id.to_string();
                    out.push(f);
                }
            }
        }
    }
    for cur in existing.iter().filter(|f| f.deleted_at.is_none()) {
        if seen.contains(&cur.id.as_str()) {
            continue;
        }
        if cur.is_core {
            return Err(Error::InvalidInput);
        }
        let mut f = cur.clone();
        let t = bump(cur.updated_at, ctx.now_ms);
        f.deleted_at = Some(t);
        f.updated_at = t;
        f.updated_by = ctx.device_id.to_string();
        out.push(f);
    }
    Ok(out)
}
