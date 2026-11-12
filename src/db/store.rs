//! CRUD over the encrypted database.
//!
//! Invariants (ADR 0001):
//! * Every write is one `IMMEDIATE` transaction; a failed call changes nothing.
//! * Deletes are tombstones. Deleting an item tombstones its fields, note blocks and tag links in
//!   the same transaction and **scrubs** secret payloads (field values, note bodies). Password
//!   history is retained (append-only, unioned by merge).
//! * Changing a `password` field writes the old value to `password_history` in the same
//!   transaction, and only when the value actually changed.
//! * The auto-tagger runs on create/update. It never re-adds a tag whose link the user removed
//!   (a tombstoned `item_tags` row), nor a tag the user deleted.
//! * Callers inject time and device id ([`WriteCtx`]); core never reads the wall clock. A record's
//!   `updated_at` is always strictly greater than its previous value, even if the clock moves back.
//! * List/get APIs return non-secret views; secrets come from [`Database::reveal_field`] and
//!   [`Database::reveal_password_history`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use zeroize::{Zeroize, Zeroizing};

use super::snapshot::sha256_hex;
use super::{db_err, Database};
use crate::error::{Error, Result};
use crate::models::{BlockKind, Category, HistoryEntry, ItemType, NoteBlock, Tag};
use crate::notes::detect_language;
use crate::tagger::suggest_tags;

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
    /// Image reference for image blocks (see [`Database::add_note_image`]).
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
    /// Value; `None` for secret fields (use [`Database::reveal_field`]).
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
fn bump(prev: i64, now: i64) -> i64 {
    now.max(prev.saturating_add(1))
}

fn new_id(ctx: &WriteCtx<'_>) -> Result<String> {
    let ms = u64::try_from(ctx.now_ms).map_err(|_| Error::InvalidInput)?;
    let nanos = u32::try_from((ms % 1000) * 1_000_000).map_err(|_| Error::InvalidInput)?;
    let ts = uuid::Timestamp::from_unix(uuid::NoContext, ms / 1000, nanos);
    Ok(uuid::Uuid::new_v7(ts).to_string())
}

fn non_empty(s: &str) -> Result<()> {
    if s.trim().is_empty() {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

struct ItemRow {
    item_type: ItemType,
    title: String,
    url: Option<String>,
    category_id: Option<String>,
    color: Option<String>,
    favorite: bool,
    updated_at: i64,
}

fn live_item(conn: &Connection, id: &str) -> Result<ItemRow> {
    conn.query_row(
        "SELECT item_type,title,url,category_id,color,favorite,updated_at
         FROM items WHERE id=?1 AND deleted_at IS NULL",
        [id],
        |r| {
            let ty: String = r.get(0)?;
            Ok((
                ty,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
            ))
        },
    )
    .optional()
    .map_err(db_err)?
    .map(|(ty, title, url, category_id, color, fav, updated_at)| {
        Ok(ItemRow {
            item_type: ItemType::parse(&ty)?,
            title,
            url,
            category_id,
            color,
            favorite: fav != 0,
            updated_at,
        })
    })
    .unwrap_or(Err(Error::NotFound))
}

fn require_live_category(conn: &Connection, id: &str) -> Result<()> {
    conn.query_row(
        "SELECT 1 FROM categories WHERE id=?1 AND deleted_at IS NULL",
        [id],
        |_| Ok(()),
    )
    .optional()
    .map_err(db_err)?
    .ok_or(Error::NotFound)
}

fn require_image(conn: &Connection, id: &str) -> Result<()> {
    conn.query_row("SELECT 1 FROM note_images WHERE id=?1", [id], |_| Ok(()))
        .optional()
        .map_err(db_err)?
        .ok_or(Error::NotFound)
}

struct FieldRow {
    id: String,
    name: String,
    kind: String,
    value: Zeroizing<String>,
    is_secret: bool,
    sort_order: i64,
    updated_at: i64,
}

fn live_fields(conn: &Connection, item_id: &str) -> Result<Vec<FieldRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id,name,kind,value,is_secret,sort_order,updated_at FROM item_fields
             WHERE item_id=?1 AND deleted_at IS NULL ORDER BY sort_order,id",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map([item_id], |r| {
            Ok(FieldRow {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                value: Zeroizing::new(r.get(3)?),
                is_secret: r.get::<_, i64>(4)? != 0,
                sort_order: r.get(5)?,
                updated_at: r.get(6)?,
            })
        })
        .map_err(db_err)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
}

/// Make the live fields of `item_id` equal to `inputs`. Returns whether anything changed.
fn sync_fields(
    conn: &Connection,
    ctx: &WriteCtx<'_>,
    item_id: &str,
    inputs: &[FieldInput],
) -> Result<bool> {
    let existing = live_fields(conn, item_id)?;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut changed = false;
    for (idx, inp) in inputs.iter().enumerate() {
        non_empty(&inp.name)?;
        non_empty(&inp.kind)?;
        let order = i64::try_from(idx).map_err(|_| Error::InvalidInput)?;
        match inp.id.as_deref() {
            Some(id) => {
                let cur = existing
                    .iter()
                    .find(|f| f.id == id)
                    .ok_or(Error::NotFound)?;
                if !seen.insert(id) {
                    return Err(Error::InvalidInput);
                }
                if cur.kind == "password"
                    && !cur.value.is_empty()
                    && cur.value.as_str() != inp.value
                {
                    conn.execute(
                        "INSERT INTO password_history(id,item_id,field_id,password,changed_at)
                         VALUES(?1,?2,?3,?4,?5)",
                        params![
                            new_id(ctx)?,
                            item_id,
                            cur.id,
                            cur.value.as_str(),
                            ctx.now_ms
                        ],
                    )
                    .map_err(db_err)?;
                }
                let same = cur.name == inp.name
                    && cur.kind == inp.kind
                    && cur.value.as_str() == inp.value
                    && cur.is_secret == inp.is_secret
                    && cur.sort_order == order;
                if !same {
                    conn.execute(
                        "UPDATE item_fields SET name=?2,kind=?3,value=?4,is_secret=?5,sort_order=?6,
                                updated_at=?7,updated_by=?8 WHERE id=?1",
                        params![
                            id,
                            inp.name,
                            inp.kind,
                            inp.value,
                            i64::from(inp.is_secret),
                            order,
                            bump(cur.updated_at, ctx.now_ms),
                            ctx.device_id
                        ],
                    )
                    .map_err(db_err)?;
                    changed = true;
                }
            }
            None => {
                conn.execute(
                    "INSERT INTO item_fields(id,item_id,name,kind,value,is_secret,sort_order,updated_at,updated_by)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    params![
                        new_id(ctx)?,
                        item_id,
                        inp.name,
                        inp.kind,
                        inp.value,
                        i64::from(inp.is_secret),
                        order,
                        ctx.now_ms,
                        ctx.device_id
                    ],
                )
                .map_err(db_err)?;
                changed = true;
            }
        }
    }
    for f in existing.iter().filter(|f| !seen.contains(f.id.as_str())) {
        tombstone_field(conn, ctx, f)?;
        changed = true;
    }
    Ok(changed)
}

/// Tombstone a field and scrub its value.
fn tombstone_field(conn: &Connection, ctx: &WriteCtx<'_>, f: &FieldRow) -> Result<()> {
    let t = bump(f.updated_at, ctx.now_ms);
    conn.execute(
        "UPDATE item_fields SET value='',deleted_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
        params![f.id, t, ctx.device_id],
    )
    .map_err(db_err)?;
    Ok(())
}

struct BlockRow {
    id: String,
    position: i64,
    kind: BlockKind,
    language: Option<String>,
    content: Zeroizing<String>,
    image_id: Option<String>,
    updated_at: i64,
}

fn live_blocks(conn: &Connection, item_id: &str) -> Result<Vec<BlockRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id,position,kind,language,content,image_id,updated_at FROM note_blocks
             WHERE item_id=?1 AND deleted_at IS NULL ORDER BY position,id",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map([item_id], |r| {
            let kind: String = r.get(2)?;
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                kind,
                r.get::<_, Option<String>>(3)?,
                Zeroizing::new(r.get::<_, String>(4)?),
                r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })
        .map_err(db_err)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, position, kind, language, content, image_id, updated_at) = row.map_err(db_err)?;
        out.push(BlockRow {
            id,
            position,
            kind: BlockKind::parse(&kind)?,
            language,
            content,
            image_id,
            updated_at,
        });
    }
    Ok(out)
}

fn resolved_language(inp: &BlockInput) -> Option<String> {
    match (&inp.language, inp.kind) {
        (Some(l), _) => Some(l.clone()),
        (None, BlockKind::Code) => Some(detect_language(&inp.content).id().to_string()),
        (None, _) => None,
    }
}

/// Make the live note blocks of `item_id` equal to `inputs`. Returns whether anything changed.
fn sync_blocks(
    conn: &Connection,
    ctx: &WriteCtx<'_>,
    item_id: &str,
    inputs: &[BlockInput],
) -> Result<bool> {
    let existing = live_blocks(conn, item_id)?;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut changed = false;
    for (idx, inp) in inputs.iter().enumerate() {
        let position = i64::try_from(idx).map_err(|_| Error::InvalidInput)?;
        match (inp.kind, &inp.image_id) {
            (BlockKind::Image, None) => return Err(Error::InvalidInput),
            (BlockKind::Image, Some(img)) => require_image(conn, img)?,
            (_, Some(_)) => return Err(Error::InvalidInput),
            (_, None) => {}
        }
        let language = resolved_language(inp);
        match inp.id.as_deref() {
            Some(id) => {
                let cur = existing
                    .iter()
                    .find(|b| b.id == id)
                    .ok_or(Error::NotFound)?;
                if !seen.insert(id) {
                    return Err(Error::InvalidInput);
                }
                let same = cur.position == position
                    && cur.kind == inp.kind
                    && cur.language == language
                    && cur.content.as_str() == inp.content
                    && cur.image_id == inp.image_id;
                if !same {
                    conn.execute(
                        "UPDATE note_blocks SET position=?2,kind=?3,language=?4,content=?5,image_id=?6,
                                updated_at=?7,updated_by=?8 WHERE id=?1",
                        params![
                            id,
                            position,
                            inp.kind.as_str(),
                            language,
                            inp.content,
                            inp.image_id,
                            bump(cur.updated_at, ctx.now_ms),
                            ctx.device_id
                        ],
                    )
                    .map_err(db_err)?;
                    changed = true;
                }
            }
            None => {
                conn.execute(
                    "INSERT INTO note_blocks(id,item_id,position,kind,language,content,image_id,updated_at,updated_by)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    params![
                        new_id(ctx)?,
                        item_id,
                        position,
                        inp.kind.as_str(),
                        language,
                        inp.content,
                        inp.image_id,
                        ctx.now_ms,
                        ctx.device_id
                    ],
                )
                .map_err(db_err)?;
                changed = true;
            }
        }
    }
    for b in existing.iter().filter(|b| !seen.contains(b.id.as_str())) {
        tombstone_block(conn, ctx, b)?;
        changed = true;
    }
    Ok(changed)
}

/// Tombstone a note block and scrub its body.
fn tombstone_block(conn: &Connection, ctx: &WriteCtx<'_>, b: &BlockRow) -> Result<()> {
    conn.execute(
        "UPDATE note_blocks SET content='',deleted_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
        params![b.id, bump(b.updated_at, ctx.now_ms), ctx.device_id],
    )
    .map_err(db_err)?;
    Ok(())
}

/// Tombstone a live link (keeps `auto`, so a rejected auto tag stays rejected).
fn tombstone_link(
    conn: &Connection,
    ctx: &WriteCtx<'_>,
    item_id: &str,
    tag_id: &str,
    prev: i64,
) -> Result<()> {
    let t = bump(prev, ctx.now_ms);
    conn.execute(
        "UPDATE item_tags SET deleted_at=?3,updated_at=?3,updated_by=?4 WHERE item_id=?1 AND tag_id=?2",
        params![item_id, tag_id, t, ctx.device_id],
    )
    .map_err(db_err)?;
    Ok(())
}

/// Apply auto-tagger suggestions to an item.
fn apply_auto_tags(conn: &Connection, ctx: &WriteCtx<'_>, item_id: &str) -> Result<()> {
    let item = live_item(conn, item_id)?;
    let fields = live_fields(conn, item_id)?;
    let kinds: Vec<&str> = fields.iter().map(|f| f.kind.as_str()).collect();
    for s in suggest_tags(
        &item.title,
        item.url.as_deref(),
        item.item_type.as_str(),
        &kinds,
    ) {
        let live: Option<String> = conn
            .query_row(
                "SELECT id FROM tags WHERE name=?1 AND deleted_at IS NULL ORDER BY id LIMIT 1",
                [s.name],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        let tag_id = match live {
            Some(id) => id,
            None => {
                let deleted: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM tags WHERE name=?1 AND deleted_at IS NOT NULL)",
                        [s.name],
                        |r| r.get(0),
                    )
                    .map_err(db_err)?;
                if deleted {
                    continue; // the user deleted this tag; do not resurrect it
                }
                create_tag_row(conn, ctx, s.name, s.color)?
            }
        };
        let link: Option<Option<i64>> = conn
            .query_row(
                "SELECT deleted_at FROM item_tags WHERE item_id=?1 AND tag_id=?2",
                params![item_id, tag_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        if link.is_none() {
            conn.execute(
                "INSERT INTO item_tags(item_id,tag_id,auto,updated_at,updated_by) VALUES(?1,?2,1,?3,?4)",
                params![item_id, tag_id, ctx.now_ms, ctx.device_id],
            )
            .map_err(db_err)?;
        }
        // Existing link (live, or tombstoned = user rejection): leave as is.
    }
    Ok(())
}

fn create_tag_row(
    conn: &Connection,
    ctx: &WriteCtx<'_>,
    name: &str,
    color: &str,
) -> Result<String> {
    let id = new_id(ctx)?;
    conn.execute(
        "INSERT INTO tags(id,name,color,created_at,updated_at,updated_by) VALUES(?1,?2,?3,?4,?4,?5)",
        params![id, name, color, ctx.now_ms, ctx.device_id],
    )
    .map_err(db_err)?;
    Ok(id)
}

fn summaries(conn: &Connection, only: Option<&str>) -> Result<Vec<ItemSummary>> {
    let mut tags: BTreeMap<String, Vec<String>> = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT it.item_id,t.name FROM item_tags it JOIN tags t ON t.id=it.tag_id
                 WHERE it.deleted_at IS NULL AND t.deleted_at IS NULL ORDER BY t.name,t.id",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(db_err)?;
        for row in rows {
            let (item, name) = row.map_err(db_err)?;
            tags.entry(item).or_default().push(name);
        }
    }
    let mut stmt = conn
        .prepare(
            "SELECT i.id,i.item_type,i.title,i.url,
                    CASE WHEN c.deleted_at IS NULL THEN i.category_id END,
                    i.color,i.favorite,i.use_count,i.last_used_at,i.updated_at
             FROM items i LEFT JOIN categories c ON c.id=i.category_id
             WHERE i.deleted_at IS NULL AND (?1 IS NULL OR i.id=?1)
             ORDER BY i.title COLLATE NOCASE,i.id",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map([only], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, Option<i64>>(8)?,
                r.get::<_, i64>(9)?,
            ))
        })
        .map_err(db_err)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, ty, title, url, category_id, color, fav, use_count, last_used_at, updated_at) =
            row.map_err(db_err)?;
        out.push(ItemSummary {
            item_type: ItemType::parse(&ty)?,
            tags: tags.remove(&id).unwrap_or_default(),
            id,
            title,
            url,
            category_id,
            color,
            favorite: fav != 0,
            use_count,
            last_used_at,
            updated_at,
        });
    }
    Ok(out)
}

impl Database {
    /// Validate the context and open an `IMMEDIATE` write transaction.
    fn begin(&mut self, ctx: &WriteCtx<'_>) -> Result<Transaction<'_>> {
        non_empty(ctx.device_id)?;
        if ctx.now_ms < 0 {
            return Err(Error::InvalidInput);
        }
        self.conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_err)
    }

    // ---- items -------------------------------------------------------------------------

    /// Create an item with its fields and note blocks, then run the auto-tagger. Returns its id.
    pub fn create_item(&mut self, ctx: &WriteCtx<'_>, new: &NewItem) -> Result<String> {
        non_empty(&new.title)?;
        if new.fields.iter().any(|f| f.id.is_some()) || new.blocks.iter().any(|b| b.id.is_some()) {
            return Err(Error::InvalidInput);
        }
        let tx = self.begin(ctx)?;
        if let Some(c) = &new.category_id {
            require_live_category(&tx, c)?;
        }
        let id = new_id(ctx)?;
        tx.execute(
            "INSERT INTO items(id,category_id,item_type,title,url,color,favorite,created_at,updated_at,updated_by)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8,?9)",
            params![
                id,
                new.category_id,
                new.item_type.as_str(),
                new.title,
                new.url,
                new.color,
                i64::from(new.favorite),
                ctx.now_ms,
                ctx.device_id
            ],
        )
        .map_err(db_err)?;
        sync_fields(&tx, ctx, &id, &new.fields)?;
        sync_blocks(&tx, ctx, &id, &new.blocks)?;
        apply_auto_tags(&tx, ctx, &id)?;
        tx.commit().map_err(db_err)?;
        Ok(id)
    }

    /// Update an item. Writes nothing (and keeps `updated_at`) if no value actually changes.
    /// Changing a password field records the old value in the password history.
    pub fn update_item(&mut self, ctx: &WriteCtx<'_>, id: &str, upd: &ItemUpdate) -> Result<()> {
        if let Some(t) = &upd.title {
            non_empty(t)?;
        }
        let tx = self.begin(ctx)?;
        let cur = live_item(&tx, id)?;
        if let Some(Some(c)) = &upd.category_id {
            require_live_category(&tx, c)?;
        }
        let title = upd.title.clone().unwrap_or_else(|| cur.title.clone());
        let url = upd.url.clone().unwrap_or_else(|| cur.url.clone());
        let category_id = upd
            .category_id
            .clone()
            .unwrap_or_else(|| cur.category_id.clone());
        let color = upd.color.clone().unwrap_or_else(|| cur.color.clone());
        let favorite = upd.favorite.unwrap_or(cur.favorite);
        let scalars_changed = title != cur.title
            || url != cur.url
            || category_id != cur.category_id
            || color != cur.color
            || favorite != cur.favorite;
        let fields_changed = match &upd.fields {
            Some(f) => sync_fields(&tx, ctx, id, f)?,
            None => false,
        };
        let blocks_changed = match &upd.blocks {
            Some(b) => sync_blocks(&tx, ctx, id, b)?,
            None => false,
        };
        if scalars_changed || fields_changed || blocks_changed {
            tx.execute(
                "UPDATE items SET title=?2,url=?3,category_id=?4,color=?5,favorite=?6,
                        updated_at=?7,updated_by=?8 WHERE id=?1",
                params![
                    id,
                    title,
                    url,
                    category_id,
                    color,
                    i64::from(favorite),
                    bump(cur.updated_at, ctx.now_ms),
                    ctx.device_id
                ],
            )
            .map_err(db_err)?;
            apply_auto_tags(&tx, ctx, id)?;
        }
        tx.commit().map_err(db_err)
    }

    /// Delete an item: tombstone it, its fields, note blocks and tag links, and scrub secret
    /// payloads. Password history is kept.
    pub fn delete_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        let cur = live_item(&tx, id)?;
        let t = bump(cur.updated_at, ctx.now_ms);
        // Children use the same logical time so every table converges on one tombstone time.
        for f in live_fields(&tx, id)? {
            tx.execute(
                "UPDATE item_fields SET value='',deleted_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
                params![f.id, bump(f.updated_at, t), ctx.device_id],
            )
            .map_err(db_err)?;
        }
        for b in live_blocks(&tx, id)? {
            tx.execute(
                "UPDATE note_blocks SET content='',deleted_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
                params![b.id, bump(b.updated_at, t), ctx.device_id],
            )
            .map_err(db_err)?;
        }
        tx.execute(
            "UPDATE item_tags SET deleted_at=max(?2,updated_at+1),updated_at=max(?2,updated_at+1),updated_by=?3
             WHERE item_id=?1 AND deleted_at IS NULL",
            params![id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.execute(
            "UPDATE items SET deleted_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
            params![id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Record one use (copy/autofill). Monotone counters; does not touch `updated_at`, so a
    /// usage bump never wins a merge against a real edit (merge keeps the max of both sides).
    pub fn record_use(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        live_item(&tx, id)?;
        tx.execute(
            "UPDATE items SET use_count=use_count+1,last_used_at=max(coalesce(last_used_at,0),?2) WHERE id=?1",
            params![id, ctx.now_ms],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Non-secret summaries of all live items, sorted by title.
    pub fn list_items(&self) -> Result<Vec<ItemSummary>> {
        summaries(self.conn(), None)
    }

    /// A live item with its live fields (secret values withheld) and note blocks.
    pub fn get_item(&self, id: &str) -> Result<ItemDetail> {
        let summary = summaries(self.conn(), Some(id))?
            .into_iter()
            .next()
            .ok_or(Error::NotFound)?;
        let fields = live_fields(self.conn(), id)?
            .into_iter()
            .map(|f| FieldView {
                value: (!f.is_secret).then(|| f.value.to_string()),
                id: f.id,
                name: f.name,
                kind: f.kind,
                is_secret: f.is_secret,
            })
            .collect();
        let blocks = live_blocks(self.conn(), id)?
            .into_iter()
            .map(|b| NoteBlock {
                id: b.id,
                item_id: id.to_string(),
                position: b.position,
                kind: b.kind,
                language: b.language,
                content: b.content.to_string(),
                image_id: b.image_id,
                updated_at: b.updated_at,
                updated_by: String::new(),
                deleted_at: None,
            })
            .collect();
        Ok(ItemDetail {
            summary,
            fields,
            blocks,
        })
    }

    /// The value of one live field of a live item (the only way to read secret values).
    pub fn reveal_field(&self, item_id: &str, field_id: &str) -> Result<Zeroizing<String>> {
        live_item(self.conn(), item_id)?;
        live_fields(self.conn(), item_id)?
            .into_iter()
            .find(|f| f.id == field_id)
            .map(|f| f.value)
            .ok_or(Error::NotFound)
    }

    /// Password history of an item (secret), newest first. Also available for deleted items.
    pub fn reveal_password_history(&self, item_id: &str) -> Result<Vec<HistoryEntry>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id,field_id,password,changed_at FROM password_history
                 WHERE item_id=?1 ORDER BY changed_at DESC,id DESC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([item_id], |r| {
                Ok(HistoryEntry {
                    id: r.get(0)?,
                    field_id: r.get(1)?,
                    password: r.get(2)?,
                    changed_at: r.get(3)?,
                })
            })
            .map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    // ---- tags --------------------------------------------------------------------------

    /// Create a tag, or return the existing live tag with the same name.
    pub fn create_tag(&mut self, ctx: &WriteCtx<'_>, name: &str, color: &str) -> Result<Tag> {
        non_empty(name)?;
        let tx = self.begin(ctx)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM tags WHERE name=?1 AND deleted_at IS NULL ORDER BY id LIMIT 1",
                [name],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        let id = match existing {
            Some(id) => id,
            None => create_tag_row(&tx, ctx, name, color)?,
        };
        let tag = read_tag(&tx, &id)?;
        tx.commit().map_err(db_err)?;
        Ok(tag)
    }

    /// Live tags sorted by name.
    pub fn list_tags(&self) -> Result<Vec<Tag>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT id FROM tags WHERE deleted_at IS NULL ORDER BY name,id")
            .map_err(db_err)?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(db_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db_err)?;
        ids.iter().map(|id| read_tag(self.conn(), id)).collect()
    }

    /// Delete a tag and all its links (tombstones).
    pub fn delete_tag(&mut self, ctx: &WriteCtx<'_>, tag_id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        let tag = read_tag(&tx, tag_id)?;
        if tag.deleted_at.is_some() {
            return Err(Error::NotFound);
        }
        let t = bump(tag.updated_at, ctx.now_ms);
        tx.execute(
            "UPDATE item_tags SET deleted_at=max(?2,updated_at+1),updated_at=max(?2,updated_at+1),updated_by=?3
             WHERE tag_id=?1 AND deleted_at IS NULL",
            params![tag_id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.execute(
            "UPDATE tags SET deleted_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
            params![tag_id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Attach a tag to an item as a user choice (`auto = 0`). Revives a removed link.
    pub fn add_tag(&mut self, ctx: &WriteCtx<'_>, item_id: &str, tag_id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        live_item(&tx, item_id)?;
        if read_tag(&tx, tag_id)?.deleted_at.is_some() {
            return Err(Error::NotFound);
        }
        let prev: Option<i64> = tx
            .query_row(
                "SELECT updated_at FROM item_tags WHERE item_id=?1 AND tag_id=?2",
                params![item_id, tag_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        match prev {
            None => tx.execute(
                "INSERT INTO item_tags(item_id,tag_id,auto,updated_at,updated_by) VALUES(?1,?2,0,?3,?4)",
                params![item_id, tag_id, ctx.now_ms, ctx.device_id],
            ),
            Some(p) => tx.execute(
                "UPDATE item_tags SET auto=0,deleted_at=NULL,updated_at=?3,updated_by=?4
                 WHERE item_id=?1 AND tag_id=?2",
                params![item_id, tag_id, bump(p, ctx.now_ms), ctx.device_id],
            ),
        }
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Remove a tag from an item. For an auto tag this is a rejection the tagger will respect.
    pub fn remove_tag(&mut self, ctx: &WriteCtx<'_>, item_id: &str, tag_id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        let prev: Option<i64> = tx
            .query_row(
                "SELECT updated_at FROM item_tags WHERE item_id=?1 AND tag_id=?2 AND deleted_at IS NULL",
                params![item_id, tag_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        tombstone_link(&tx, ctx, item_id, tag_id, prev.ok_or(Error::NotFound)?)?;
        tx.commit().map_err(db_err)
    }

    // ---- categories --------------------------------------------------------------------

    /// Create a category, appended after the existing ones.
    pub fn create_category(&mut self, ctx: &WriteCtx<'_>, new: &NewCategory) -> Result<Category> {
        non_empty(&new.name)?;
        let tx = self.begin(ctx)?;
        let id = new_id(ctx)?;
        tx.execute(
            "INSERT INTO categories(id,name,color,icon,icon_color,sort_order,created_at,updated_at,updated_by)
             VALUES(?1,?2,?3,?4,?5,
                    (SELECT coalesce(max(sort_order)+1,0) FROM categories WHERE deleted_at IS NULL),
                    ?6,?6,?7)",
            params![id, new.name, new.color, new.icon, new.icon_color, ctx.now_ms, ctx.device_id],
        )
        .map_err(db_err)?;
        let c = read_category(&tx, &id)?;
        tx.commit().map_err(db_err)?;
        Ok(c)
    }

    /// Update a live category.
    pub fn update_category(
        &mut self,
        ctx: &WriteCtx<'_>,
        id: &str,
        upd: &CategoryUpdate,
    ) -> Result<()> {
        if let Some(n) = &upd.name {
            non_empty(n)?;
        }
        let tx = self.begin(ctx)?;
        let c = read_category(&tx, id)?;
        if c.deleted_at.is_some() {
            return Err(Error::NotFound);
        }
        let name = upd.name.clone().unwrap_or_else(|| c.name.clone());
        let color = upd.color.clone().unwrap_or_else(|| c.color.clone());
        let icon = upd.icon.clone().unwrap_or_else(|| c.icon.clone());
        let icon_color = upd
            .icon_color
            .clone()
            .unwrap_or_else(|| c.icon_color.clone());
        if (&name, &color, &icon, &icon_color) != (&c.name, &c.color, &c.icon, &c.icon_color) {
            tx.execute(
                "UPDATE categories SET name=?2,color=?3,icon=?4,icon_color=?5,updated_at=?6,updated_by=?7 WHERE id=?1",
                params![id, name, color, icon, icon_color, bump(c.updated_at, ctx.now_ms), ctx.device_id],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    /// Set the display order (drag-and-drop). `ordered_ids` are live categories; their position
    /// in the list becomes `sort_order`.
    pub fn reorder_categories(&mut self, ctx: &WriteCtx<'_>, ordered_ids: &[String]) -> Result<()> {
        let tx = self.begin(ctx)?;
        for (idx, id) in ordered_ids.iter().enumerate() {
            let order = i64::try_from(idx).map_err(|_| Error::InvalidInput)?;
            let c = read_category(&tx, id)?;
            if c.deleted_at.is_some() {
                return Err(Error::NotFound);
            }
            if c.sort_order != order {
                tx.execute(
                    "UPDATE categories SET sort_order=?2,updated_at=?3,updated_by=?4 WHERE id=?1",
                    params![id, order, bump(c.updated_at, ctx.now_ms), ctx.device_id],
                )
                .map_err(db_err)?;
            }
        }
        tx.commit().map_err(db_err)
    }

    /// Delete a category (tombstone). Items keep their reference but report no category.
    pub fn delete_category(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        let c = read_category(&tx, id)?;
        if c.deleted_at.is_some() {
            return Err(Error::NotFound);
        }
        let t = bump(c.updated_at, ctx.now_ms);
        tx.execute(
            "UPDATE categories SET deleted_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
            params![id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Live categories in display order.
    pub fn list_categories(&self) -> Result<Vec<Category>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT id FROM categories WHERE deleted_at IS NULL ORDER BY sort_order,id")
            .map_err(db_err)?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(db_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db_err)?;
        ids.iter()
            .map(|id| read_category(self.conn(), id))
            .collect()
    }

    // ---- note images -------------------------------------------------------------------

    /// Store an immutable image for use by an image block. Returns its id.
    pub fn add_note_image(
        &mut self,
        ctx: &WriteCtx<'_>,
        mime_type: &str,
        data: &[u8],
    ) -> Result<String> {
        non_empty(mime_type)?;
        if data.is_empty() {
            return Err(Error::InvalidInput);
        }
        let tx = self.begin(ctx)?;
        let id = new_id(ctx)?;
        tx.execute(
            "INSERT INTO note_images(id,mime_type,data,created_at) VALUES(?1,?2,?3,?4)",
            params![id, mime_type, data, ctx.now_ms],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(id)
    }

    /// SHA-256 (hex) of a stored image, for content-addressing by the blob codec.
    pub fn note_image_sha256(&self, id: &str) -> Result<String> {
        let data: Vec<u8> = self
            .conn()
            .query_row("SELECT data FROM note_images WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_err)?
            .ok_or(Error::NotFound)?;
        Ok(sha256_hex(&data))
    }
}

fn read_tag(conn: &Connection, id: &str) -> Result<Tag> {
    conn.query_row(
        "SELECT id,name,color,created_at,updated_at,updated_by,deleted_at FROM tags WHERE id=?1",
        [id],
        |r| {
            Ok(Tag {
                id: r.get(0)?,
                name: r.get(1)?,
                color: r.get(2)?,
                created_at: r.get(3)?,
                updated_at: r.get(4)?,
                updated_by: r.get(5)?,
                deleted_at: r.get(6)?,
            })
        },
    )
    .optional()
    .map_err(db_err)?
    .ok_or(Error::NotFound)
}

fn read_category(conn: &Connection, id: &str) -> Result<Category> {
    conn.query_row(
        "SELECT id,name,color,icon,icon_color,sort_order,created_at,updated_at,updated_by,deleted_at
         FROM categories WHERE id=?1",
        [id],
        |r| {
            Ok(Category {
                id: r.get(0)?,
                name: r.get(1)?,
                color: r.get(2)?,
                icon: r.get(3)?,
                icon_color: r.get(4)?,
                sort_order: r.get(5)?,
                created_at: r.get(6)?,
                updated_at: r.get(7)?,
                updated_by: r.get(8)?,
                deleted_at: r.get(9)?,
            })
        },
    )
    .optional()
    .map_err(db_err)?
    .ok_or(Error::NotFound)
}
