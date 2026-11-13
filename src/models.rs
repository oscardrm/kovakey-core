//! Plain data records exchanged between the database and the merge engine. They mirror every
//! synced column of the schema, so a [`Snapshot`] round-trips the vault without loss
//! (ADR 0001). Secret payloads (`password`, field `value`, note `content`, image `data`) are
//! wiped on drop and never printed by `Debug`.
//!
//! Every versioned record carries `(updated_at, updated_by, deleted_at)`; deletes are tombstones.

use std::collections::BTreeSet;
use std::fmt;

use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Marker printed instead of secret content.
const REDACTED: &str = "<redacted>";

/// One entry of an item's password history (append-only, unioned on merge).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HistoryEntry {
    /// Entry id (UUIDv7).
    pub id: String,
    /// Field the password belonged to, when known.
    pub field_id: Option<String>,
    /// Previous password value.
    pub password: String,
    /// Change time, Unix ms UTC.
    pub changed_at: i64,
}

impl fmt::Debug for HistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryEntry")
            .field("id", &self.id)
            .field("field_id", &self.field_id)
            .field("password", &REDACTED)
            .field("changed_at", &self.changed_at)
            .finish()
    }
}

impl Drop for HistoryEntry {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Kind of vault item. Mirrors the `items.item_type` CHECK constraint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItemType {
    /// Website / app login.
    Credential,
    /// Payment card.
    Card,
    /// Identity document / personal data.
    Identity,
    /// Travel document.
    Travel,
    /// Database connection.
    Database,
    /// Developer secret (API key, token, SSH key, ...).
    DevSecret,
    /// Rich note.
    Note,
}

impl ItemType {
    /// Stable storage identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Card => "card",
            Self::Identity => "identity",
            Self::Travel => "travel",
            Self::Database => "database",
            Self::DevSecret => "dev_secret",
            Self::Note => "note",
        }
    }

    /// Parse a storage identifier.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "credential" => Self::Credential,
            "card" => Self::Card,
            "identity" => Self::Identity,
            "travel" => Self::Travel,
            "database" => Self::Database,
            "dev_secret" => Self::DevSecret,
            "note" => Self::Note,
            _ => return Err(Error::Corrupted),
        })
    }
}

/// A vault item (without its fields, tags and note blocks, which are separate records).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Item {
    /// Item id (UUIDv7).
    pub id: String,
    /// Owning category.
    pub category_id: Option<String>,
    /// Item type.
    pub item_type: ItemType,
    /// Title.
    pub title: String,
    /// Associated URL.
    pub url: Option<String>,
    /// Optional accent color.
    pub color: Option<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Creation time, Unix ms UTC.
    pub created_at: i64,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer (deterministic tie-break).
    pub updated_by: String,
    /// Tombstone time; `Some` means permanently deleted (content wiped).
    pub deleted_at: Option<i64>,
    /// Time the item was moved to the Trash (PRD §9.3), Unix ms UTC. A trashed item keeps its
    /// content, is hidden from lists/search/autofill and can be restored until it is purged
    /// (tombstoned). Travels with the item row, so it merges last-writer-wins like any edit.
    pub trashed_at: Option<i64>,
    // The three fields below are *absorbed* on merge (max / max / union) rather than chosen by
    // last-writer-wins. They must stay last: the derived `Ord` is the final merge tie-break and
    // must not depend on values that `absorb` rewrites.
    /// Usage counter (merged as max, see [`crate::merge`]).
    pub use_count: i64,
    /// Last use time (merged as max).
    pub last_used_at: Option<i64>,
    /// Password history (append-only, unioned on merge).
    pub history: BTreeSet<HistoryEntry>,
}

/// A typed field of an item (username, password, TOTP secret, ...).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ItemField {
    /// Field id.
    pub id: String,
    /// Owning item.
    pub item_id: String,
    /// Display name.
    pub name: String,
    /// Kind: `text`, `password`, `totp`, `url`, ...
    pub kind: String,
    /// Value. Blank once tombstoned.
    pub value: String,
    /// Whether the value is secret (hidden by default).
    pub is_secret: bool,
    /// Display order.
    pub sort_order: i64,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer.
    pub updated_by: String,
    /// Tombstone time.
    pub deleted_at: Option<i64>,
}

impl fmt::Debug for ItemField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemField")
            .field("id", &self.id)
            .field("item_id", &self.item_id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &REDACTED)
            .field("is_secret", &self.is_secret)
            .field("updated_at", &self.updated_at)
            .field("deleted_at", &self.deleted_at)
            .finish()
    }
}

impl Drop for ItemField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Category record (independent category color and icon color).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Category {
    /// Category id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Category color.
    pub color: String,
    /// Icon identifier.
    pub icon: String,
    /// Icon color, independent from `color`.
    pub icon_color: String,
    /// Stable key of the built-in preset this category was seeded from (e.g. `card`), if any.
    /// Presets are ordinary, fully editable categories; the key only lets the app recognise them
    /// (item behaviour, localized default names). `None` for user-created categories.
    pub preset: Option<String>,
    /// Display order.
    pub sort_order: i64,
    /// Creation time, Unix ms UTC.
    pub created_at: i64,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer.
    pub updated_by: String,
    /// Tombstone time.
    pub deleted_at: Option<i64>,
}

/// Input type of a category field (what kind of value the input holds). Stored as the `kind`
/// string of both [`CategoryField`] and the [`ItemField`]s created from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InputKind {
    /// Single-line text.
    Text,
    /// Password (changes are recorded in the password history).
    Password,
    /// Multi-line secret note.
    SecureNote,
    /// TOTP secret.
    Totp,
    /// URL.
    Url,
    /// E-mail address.
    Email,
    /// Phone number.
    Phone,
    /// Number.
    Number,
    /// Calendar date.
    Date,
    /// Payment card number.
    CardNumber,
    /// Expiration date (MM/YY).
    Expiry,
    /// Card verification value.
    Cvv,
    /// PIN.
    Pin,
    /// Hash / checksum.
    Hash,
    /// Key material (API key, SSH key, ...).
    Key,
    /// `.env`-style variables.
    Env,
}

impl InputKind {
    /// Every input type a user can choose, in display order.
    pub const ALL: [InputKind; 16] = [
        Self::Text,
        Self::Password,
        Self::SecureNote,
        Self::Totp,
        Self::Url,
        Self::Email,
        Self::Phone,
        Self::Number,
        Self::Date,
        Self::CardNumber,
        Self::Expiry,
        Self::Cvv,
        Self::Pin,
        Self::Hash,
        Self::Key,
        Self::Env,
    ];

    /// Stable storage identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Password => "password",
            Self::SecureNote => "secure_note",
            Self::Totp => "totp",
            Self::Url => "url",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Number => "number",
            Self::Date => "date",
            Self::CardNumber => "card_number",
            Self::Expiry => "expiry",
            Self::Cvv => "cvv",
            Self::Pin => "pin",
            Self::Hash => "hash",
            Self::Key => "key",
            Self::Env => "env",
        }
    }

    /// Parse a storage identifier; unknown identifiers are [`Error::InvalidInput`].
    pub fn parse(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or(Error::InvalidInput)
    }

    /// Whether values of this type are secret (hidden by default) unless overridden.
    pub fn secret_by_default(self) -> bool {
        matches!(
            self,
            Self::Password
                | Self::SecureNote
                | Self::Totp
                | Self::CardNumber
                | Self::Cvv
                | Self::Pin
                | Self::Hash
                | Self::Key
                | Self::Env
        )
    }
}

/// One input of a category's form template. Items created in the category start with one
/// [`ItemField`] per live category field.
///
/// `is_core` inputs are required by the category's logic (e.g. a card's number, expiry and CVV):
/// they can be renamed or reordered but never deleted, and their `kind` and secrecy are fixed.
/// Users can add any number of extra (non-core) inputs to any category.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CategoryField {
    /// Field id. Preset fields use deterministic ids (`preset:<preset>:<key>`) so devices that
    /// seed independently converge on the same records.
    pub id: String,
    /// Owning category.
    pub category_id: String,
    /// Display name.
    pub name: String,
    /// Input type, an [`InputKind`] storage identifier.
    pub kind: String,
    /// Whether values are secret (hidden by default).
    pub is_secret: bool,
    /// Protected core input: cannot be deleted.
    pub is_core: bool,
    /// Display order.
    pub sort_order: i64,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer.
    pub updated_by: String,
    /// Tombstone time.
    pub deleted_at: Option<i64>,
}

/// Tag record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tag {
    /// Tag id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Color.
    pub color: String,
    /// Creation time, Unix ms UTC.
    pub created_at: i64,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer.
    pub updated_by: String,
    /// Tombstone time.
    pub deleted_at: Option<i64>,
}

/// Link between an item and a tag. A tombstoned link on an auto tag records that the user
/// rejected it, so the auto-tagger must not re-add it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ItemTag {
    /// Item id.
    pub item_id: String,
    /// Tag id.
    pub tag_id: String,
    /// `true` if suggested by the auto-tagger.
    pub auto: bool,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer.
    pub updated_by: String,
    /// Tombstone time.
    pub deleted_at: Option<i64>,
}

/// Kind of a note block. Mirrors the `note_blocks.kind` CHECK constraint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlockKind {
    /// Rich text.
    RichText,
    /// Code with a language.
    Code,
    /// Table (JSON content).
    Table,
    /// Embedded image (see `image_id`).
    Image,
}

impl BlockKind {
    /// Stable storage identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RichText => "rich_text",
            Self::Code => "code",
            Self::Table => "table",
            Self::Image => "image",
        }
    }

    /// Parse a storage identifier.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "rich_text" => Self::RichText,
            "code" => Self::Code,
            "table" => Self::Table,
            "image" => Self::Image,
            _ => return Err(Error::Corrupted),
        })
    }
}

/// One block of a rich note.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoteBlock {
    /// Block id.
    pub id: String,
    /// Owning item.
    pub item_id: String,
    /// Position within the note.
    pub position: i64,
    /// Block kind.
    pub kind: BlockKind,
    /// Code language id.
    pub language: Option<String>,
    /// Block body. Blank once tombstoned.
    pub content: String,
    /// Referenced image for image blocks.
    pub image_id: Option<String>,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer.
    pub updated_by: String,
    /// Tombstone time.
    pub deleted_at: Option<i64>,
}

impl fmt::Debug for NoteBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteBlock")
            .field("id", &self.id)
            .field("item_id", &self.item_id)
            .field("position", &self.position)
            .field("kind", &self.kind)
            .field("content", &REDACTED)
            .field("updated_at", &self.updated_at)
            .field("deleted_at", &self.deleted_at)
            .finish()
    }
}

impl Drop for NoteBlock {
    fn drop(&mut self) {
        self.content.zeroize();
    }
}

/// Immutable embedded image. Merged as a union by id (content never changes).
///
/// `sha256` and `size` are what a future blob codec references when it moves images above the
/// size threshold into content-addressed side blobs (ADR 0001).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoteImage {
    /// Image id.
    pub id: String,
    /// MIME type.
    pub mime_type: String,
    /// Lowercase hex SHA-256 of `data`.
    pub sha256: String,
    /// Length of `data` in bytes.
    pub size: u64,
    /// Image bytes.
    pub data: Vec<u8>,
    /// Creation time, Unix ms UTC.
    pub created_at: i64,
}

impl fmt::Debug for NoteImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteImage")
            .field("id", &self.id)
            .field("mime_type", &self.mime_type)
            .field("sha256", &self.sha256)
            .field("size", &self.size)
            .finish()
    }
}

impl Drop for NoteImage {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Vault metadata (name, color, badge).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VaultMeta {
    /// Vault id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Color.
    pub color: String,
    /// Optional badge.
    pub badge: Option<String>,
    /// Creation time, Unix ms UTC.
    pub created_at: i64,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer.
    pub updated_by: String,
}

/// Everything that is merged between two copies of one vault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Vault metadata.
    pub vault_meta: Vec<VaultMeta>,
    /// Categories.
    pub categories: Vec<Category>,
    /// Category form templates (inputs).
    pub category_fields: Vec<CategoryField>,
    /// Tags.
    pub tags: Vec<Tag>,
    /// Items (with password history).
    pub items: Vec<Item>,
    /// Item fields.
    pub item_fields: Vec<ItemField>,
    /// Item-tag links.
    pub item_tags: Vec<ItemTag>,
    /// Note blocks.
    pub note_blocks: Vec<NoteBlock>,
    /// Note images.
    pub note_images: Vec<NoteImage>,
}
