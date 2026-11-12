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
    BlockKind, Category, CategoryField, HistoryEntry, InputKind, ItemType, NoteBlock, Snapshot, Tag,
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
    /// Tombstone an item with its children and scrub secret payloads.
    fn delete_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
    /// Record one use (copy/autofill).
    fn record_use(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
    /// Non-secret summaries of all live items, sorted by title.
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
    /// The whole vault as a merge snapshot.
    fn snapshot(&self) -> Result<Snapshot>;
    /// Merge a decrypted remote snapshot atomically.
    fn merge_remote(&mut self, remote: &Snapshot) -> Result<()>;
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
