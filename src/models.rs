//! Plain data records used by the merge engine. They mirror the DB schema's sync-relevant
//! columns (id, timestamps, device id, tombstone). Secret payloads stay in the encrypted DB;
//! merge operates on in-memory snapshots decrypted from both vault files.

use std::collections::BTreeSet;

/// One entry of an item's password history (append-only, unioned on merge).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HistoryEntry {
    /// Entry id (UUIDv7).
    pub id: String,
    /// Previous password value.
    pub password: String,
    /// Change time, Unix ms UTC.
    pub changed_at: i64,
}

/// A vault item as seen by the merge engine.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Item {
    /// Item id (UUIDv7).
    pub id: String,
    /// Title.
    pub title: String,
    /// Serialized field payload.
    pub body: String,
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer (deterministic tie-break).
    pub updated_by: String,
    /// Tombstone time; `Some` means deleted.
    pub deleted_at: Option<i64>,
    /// Password history.
    pub history: BTreeSet<HistoryEntry>,
}

/// Category record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Category {
    /// Category id.
    pub id: String,
    /// Name.
    pub name: String,
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
    /// Last modification time, Unix ms UTC.
    pub updated_at: i64,
    /// Device id of the last writer.
    pub updated_by: String,
    /// Tombstone time.
    pub deleted_at: Option<i64>,
}

/// Everything that is merged between two copies of one vault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Items.
    pub items: Vec<Item>,
    /// Categories.
    pub categories: Vec<Category>,
    /// Tags.
    pub tags: Vec<Tag>,
}
