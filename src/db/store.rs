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

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

use super::{db_err, Database};
use crate::error::{Error, Result};
use crate::models::{
    BlockKind, Category, CategoryField, HistoryEntry, ItemType, NoteBlock, Snapshot, Tag,
    VaultMeta, DEFAULT_VAULT_ID,
};
use crate::notes::detect_language;
use crate::ops::{
    bump, check_attachment_size, check_mime_type, check_vault_color, clean_vault_badge,
    clean_vault_name, new_id, non_empty, plan_field_update, sanitize_file_name, AttachmentInfo,
    BlockInput, CategoryUpdate, FieldInput, FieldView, ItemDetail, ItemSummary, ItemUpdate,
    NewCategory, NewItem, NewPasskey, PasskeyInfo, VaultStore, VaultUpdate, WriteCtx, MAX_VAULTS,
};
use crate::presets::seed_records;
use crate::side_blob::sha256_hex;
use crate::tagger::suggest_tags;

struct ItemRow {
    vault_id: String,
    item_type: ItemType,
    title: String,
    url: Option<String>,
    category_id: Option<String>,
    color: Option<String>,
    favorite: bool,
    updated_at: i64,
}

/// Fails with `InvalidInput` when the (live) item is in the Trash: trashed items are read-only.
fn ensure_not_trashed(conn: &Connection, id: &str) -> Result<()> {
    match trashed_at(conn, id)? {
        Some(_) => Err(Error::InvalidInput),
        None => Ok(()),
    }
}

/// `trashed_at` of a live item (`NotFound` for missing or permanently deleted items).
fn trashed_at(conn: &Connection, id: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT trashed_at FROM items WHERE id=?1 AND deleted_at IS NULL",
        [id],
        |r| r.get(0),
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Error::NotFound,
        other => db_err(other),
    })
}

fn live_item(conn: &Connection, id: &str) -> Result<ItemRow> {
    conn.query_row(
        "SELECT item_type,title,url,category_id,color,favorite,updated_at,vault_id
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
                r.get::<_, String>(7)?,
            ))
        },
    )
    .optional()
    .map_err(db_err)?
    .map(
        |(ty, title, url, category_id, color, fav, updated_at, vault_id)| {
            Ok(ItemRow {
                vault_id,
                item_type: ItemType::parse(&ty)?,
                title,
                url,
                category_id,
                color,
                favorite: fav != 0,
                updated_at,
            })
        },
    )
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

fn vault_is_live(conn: &Connection, id: &str) -> Result<bool> {
    conn.query_row(
        "SELECT 1 FROM vault_meta WHERE id=?1 AND deleted_at IS NULL",
        [id],
        |_| Ok(()),
    )
    .optional()
    .map(|o| o.is_some())
    .map_err(db_err)
}

/// Live vaults ordered by (creation time, id): the default vault (created at 0) comes first.
fn live_vaults(conn: &Connection) -> Result<Vec<VaultMeta>> {
    let mut stmt = conn
        .prepare(
            "SELECT id,name,color,badge,created_at,updated_at,updated_by,deleted_at
             FROM vault_meta WHERE deleted_at IS NULL ORDER BY created_at,id",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(VaultMeta {
                id: r.get(0)?,
                name: r.get(1)?,
                color: r.get(2)?,
                badge: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                updated_by: r.get(6)?,
                deleted_at: r.get(7)?,
            })
        })
        .map_err(db_err)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
}

/// Vault for a new item: the requested one (must be live) or the first live vault.
fn resolve_vault(conn: &Connection, requested: Option<&str>) -> Result<String> {
    match requested {
        Some(id) if vault_is_live(conn, id)? => Ok(id.to_string()),
        Some(_) => Err(Error::NotFound),
        None => live_vaults(conn)?
            .into_iter()
            .next()
            .map(|v| v.id)
            .ok_or(Error::NotFound),
    }
}

fn vault_name_taken(conn: &Connection, name: &str, except: Option<&str>) -> Result<bool> {
    Ok(live_vaults(conn)?
        .iter()
        .any(|v| Some(v.id.as_str()) != except && v.name.to_lowercase() == name.to_lowercase()))
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
                    i.color,i.favorite,i.use_count,i.last_used_at,i.updated_at,i.trashed_at,i.vault_id
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
                r.get::<_, Option<i64>>(10)?,
                r.get::<_, String>(11)?,
            ))
        })
        .map_err(db_err)?;
    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            ty,
            title,
            url,
            category_id,
            color,
            fav,
            use_count,
            last_used_at,
            updated_at,
            trashed_at,
            vault_id,
        ) = row.map_err(db_err)?;
        out.push(ItemSummary {
            vault_id,
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
            trashed_at,
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
        let vault_id = resolve_vault(&tx, new.vault_id.as_deref())?;
        let id = new_id(ctx)?;
        tx.execute(
            "INSERT INTO items(id,category_id,item_type,title,url,color,favorite,created_at,updated_at,updated_by,vault_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8,?9,?10)",
            params![
                id,
                new.category_id,
                new.item_type.as_str(),
                new.title,
                new.url,
                new.color,
                i64::from(new.favorite),
                ctx.now_ms,
                ctx.device_id,
                vault_id
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
        ensure_not_trashed(&tx, id)?;
        let cur = live_item(&tx, id)?;
        if let Some(Some(c)) = &upd.category_id {
            require_live_category(&tx, c)?;
        }
        if let Some(v) = &upd.vault_id {
            resolve_vault(&tx, Some(v))?;
        }
        let vault_id = upd.vault_id.clone().unwrap_or_else(|| cur.vault_id.clone());
        let title = upd.title.clone().unwrap_or_else(|| cur.title.clone());
        let url = upd.url.clone().unwrap_or_else(|| cur.url.clone());
        let category_id = upd
            .category_id
            .clone()
            .unwrap_or_else(|| cur.category_id.clone());
        let color = upd.color.clone().unwrap_or_else(|| cur.color.clone());
        let favorite = upd.favorite.unwrap_or(cur.favorite);
        let scalars_changed = vault_id != cur.vault_id
            || title != cur.title
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
                        updated_at=?7,updated_by=?8,vault_id=?9 WHERE id=?1",
                params![
                    id,
                    title,
                    url,
                    category_id,
                    color,
                    i64::from(favorite),
                    bump(cur.updated_at, ctx.now_ms),
                    ctx.device_id,
                    vault_id
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
        // Passkeys: tombstone and scrub the private key (ADR 0020).
        tx.execute(
            "UPDATE passkeys SET private_key=x'',deleted_at=max(?2,updated_at+1),
               updated_at=max(?2,updated_at+1),updated_by=?3
             WHERE item_id=?1 AND deleted_at IS NULL",
            params![id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        // Attachments: tombstone and scrub the bytes (ADR 0019).
        tx.execute(
            "UPDATE attachments SET data=x'',size=0,deleted_at=max(?2,updated_at+1),
               updated_at=max(?2,updated_at+1),updated_by=?3
             WHERE item_id=?1 AND deleted_at IS NULL",
            params![id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.execute(
            "UPDATE item_tags SET deleted_at=max(?2,updated_at+1),updated_at=max(?2,updated_at+1),updated_by=?3
             WHERE item_id=?1 AND deleted_at IS NULL",
            params![id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.execute(
            "UPDATE items SET deleted_at=?2,trashed_at=NULL,updated_at=?2,updated_by=?3 WHERE id=?1",
            params![id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Move a live item to the Trash, keeping its content. No-op if it is already trashed.
    pub fn trash_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        if trashed_at(&tx, id)?.is_none() {
            let cur = live_item(&tx, id)?;
            let t = bump(cur.updated_at, ctx.now_ms);
            tx.execute(
                "UPDATE items SET trashed_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
                params![id, t, ctx.device_id],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    /// Take an item out of the Trash. No-op if it is not trashed.
    pub fn restore_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        if trashed_at(&tx, id)?.is_some() {
            let cur = live_item(&tx, id)?;
            let t = bump(cur.updated_at, ctx.now_ms);
            tx.execute(
                "UPDATE items SET trashed_at=NULL,updated_at=?2,updated_by=?3 WHERE id=?1",
                params![id, t, ctx.device_id],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    /// Summaries of trashed items, most recently trashed first.
    pub fn list_trashed_items(&self) -> Result<Vec<ItemSummary>> {
        let mut out: Vec<ItemSummary> = summaries(self.conn(), None)?
            .into_iter()
            .filter(|i| i.trashed_at.is_some())
            .collect();
        out.sort_by(|a, b| (b.trashed_at, &a.id).cmp(&(a.trashed_at, &b.id)));
        Ok(out)
    }

    // ---- vaults ------------------------------------------------------------------------

    /// Live vaults, default first.
    pub fn list_vaults(&self) -> Result<Vec<VaultMeta>> {
        live_vaults(self.conn())
    }

    /// Create a vault; names are unique (case-insensitive) among live vaults.
    pub fn create_vault(
        &mut self,
        ctx: &WriteCtx<'_>,
        name: &str,
        color: &str,
        badge: Option<&str>,
    ) -> Result<VaultMeta> {
        let name = clean_vault_name(name)?;
        check_vault_color(color)?;
        let badge = badge.map(clean_vault_badge).transpose()?.flatten();
        let tx = self.begin(ctx)?;
        if live_vaults(&tx)?.len() >= MAX_VAULTS || vault_name_taken(&tx, &name, None)? {
            return Err(Error::InvalidInput);
        }
        let v = VaultMeta {
            id: new_id(ctx)?,
            name,
            color: color.to_string(),
            badge,
            created_at: ctx.now_ms,
            updated_at: ctx.now_ms,
            updated_by: ctx.device_id.to_string(),
            deleted_at: None,
        };
        tx.execute(
            "INSERT INTO vault_meta(id,name,color,badge,created_at,updated_at,updated_by)
             VALUES(?1,?2,?3,?4,?5,?5,?6)",
            params![v.id, v.name, v.color, v.badge, v.created_at, v.updated_by],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(v)
    }

    /// Rename / recolor / re-badge a live vault. Writes nothing if no value changes.
    pub fn update_vault(
        &mut self,
        ctx: &WriteCtx<'_>,
        id: &str,
        upd: &VaultUpdate,
    ) -> Result<VaultMeta> {
        let name = upd.name.as_deref().map(clean_vault_name).transpose()?;
        if let Some(c) = &upd.color {
            check_vault_color(c)?;
        }
        let badge = match &upd.badge {
            Some(Some(b)) => Some(clean_vault_badge(b)?),
            Some(None) => Some(None),
            None => None,
        };
        let tx = self.begin(ctx)?;
        let mut cur = live_vaults(&tx)?
            .into_iter()
            .find(|v| v.id == id)
            .ok_or(Error::NotFound)?;
        if let Some(n) = &name {
            if vault_name_taken(&tx, n, Some(id))? {
                return Err(Error::InvalidInput);
            }
        }
        let changed = name.as_ref().is_some_and(|n| *n != cur.name)
            || upd.color.as_ref().is_some_and(|c| *c != cur.color)
            || badge.as_ref().is_some_and(|b| *b != cur.badge);
        if changed {
            if let Some(n) = name {
                cur.name = n;
            }
            if let Some(c) = &upd.color {
                cur.color = c.clone();
            }
            if let Some(b) = badge {
                cur.badge = b;
            }
            cur.updated_at = bump(cur.updated_at, ctx.now_ms);
            cur.updated_by = ctx.device_id.to_string();
            tx.execute(
                "UPDATE vault_meta SET name=?2,color=?3,badge=?4,updated_at=?5,updated_by=?6 WHERE id=?1",
                params![id, cur.name, cur.color, cur.badge, cur.updated_at, cur.updated_by],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)?;
        Ok(cur)
    }

    /// Delete a vault: its items (trashed ones included) move to `move_items_to`, then the vault
    /// is tombstoned.
    pub fn delete_vault(
        &mut self,
        ctx: &WriteCtx<'_>,
        id: &str,
        move_items_to: &str,
    ) -> Result<()> {
        if id == move_items_to {
            return Err(Error::InvalidInput);
        }
        let tx = self.begin(ctx)?;
        if !vault_is_live(&tx, id)? || !vault_is_live(&tx, move_items_to)? {
            return Err(Error::NotFound);
        }
        tx.execute(
            "UPDATE items SET vault_id=?2,updated_at=max(?3,updated_at+1),updated_by=?4
             WHERE vault_id=?1 AND deleted_at IS NULL",
            params![id, move_items_to, ctx.now_ms, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.execute(
            "UPDATE vault_meta SET deleted_at=max(?2,updated_at+1),updated_at=max(?2,updated_at+1),updated_by=?3
             WHERE id=?1",
            params![id, ctx.now_ms, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Create the default vault if the store has never had one.
    pub fn ensure_default_vault(&mut self, ctx: &WriteCtx<'_>) -> Result<()> {
        let tx = self.begin(ctx)?;
        tx.execute(
            "INSERT OR IGNORE INTO vault_meta(id,name,color,badge,created_at,updated_at,updated_by)
             VALUES(?1,'Personal','#2563EB',NULL,0,0,'')",
            [DEFAULT_VAULT_ID],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Record one use (copy/autofill). Monotone counters; does not touch `updated_at`, so a
    /// usage bump never wins a merge against a real edit (merge keeps the max of both sides).
    pub fn record_use(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        ensure_not_trashed(&tx, id)?;
        tx.execute(
            "UPDATE items SET use_count=use_count+1,last_used_at=max(coalesce(last_used_at,0),?2) WHERE id=?1",
            params![id, ctx.now_ms],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Non-secret summaries of all live items, sorted by title.
    pub fn list_items(&self) -> Result<Vec<ItemSummary>> {
        let mut out = summaries(self.conn(), None)?;
        out.retain(|i| i.trashed_at.is_none());
        Ok(out)
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

    /// Rename and/or recolor a live tag; item links are untouched.
    pub fn update_tag(
        &mut self,
        ctx: &WriteCtx<'_>,
        tag_id: &str,
        name: Option<&str>,
        color: Option<&str>,
    ) -> Result<Tag> {
        if let Some(n) = name {
            non_empty(n)?;
        }
        let tx = self.begin(ctx)?;
        let tag = read_tag(&tx, tag_id)?;
        if tag.deleted_at.is_some() {
            return Err(Error::NotFound);
        }
        let new_name = name.unwrap_or(&tag.name);
        let clash: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tags WHERE name=?1 AND id<>?2 AND deleted_at IS NULL)",
                params![new_name, tag_id],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        if clash {
            return Err(Error::InvalidInput);
        }
        let new_color = color.unwrap_or(&tag.color);
        let t = bump(tag.updated_at, ctx.now_ms);
        tx.execute(
            "UPDATE tags SET name=?2,color=?3,updated_at=?4,updated_by=?5 WHERE id=?1",
            params![tag_id, new_name, new_color, t, ctx.device_id],
        )
        .map_err(db_err)?;
        let updated = read_tag(&tx, tag_id)?;
        tx.commit().map_err(db_err)?;
        Ok(updated)
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
        if new.fields.iter().any(|f| f.id.is_some()) {
            return Err(Error::InvalidInput);
        }
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
        let planned = plan_field_update(ctx, &id, &[], &new.fields)?;
        write_category_fields(&tx, &planned)?;
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
        if let Some(inputs) = &upd.fields {
            let existing = read_category_fields(&tx, id, true)?;
            let planned = plan_field_update(ctx, id, &existing, inputs)?;
            write_category_fields(&tx, &planned)?;
        }
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

    /// Live inputs of a live category in display order.
    pub fn list_category_fields(&self, category_id: &str) -> Result<Vec<CategoryField>> {
        let c = read_category(self.conn(), category_id)?;
        if c.deleted_at.is_some() {
            return Err(Error::NotFound);
        }
        read_category_fields(self.conn(), category_id, false)
    }

    /// Create the preset categories that do not exist yet. Idempotent.
    pub fn seed_default_categories(&mut self, ctx: &WriteCtx<'_>) -> Result<()> {
        let tx = self.begin(ctx)?;
        let existing: Vec<Category> = {
            let mut stmt = tx.prepare("SELECT id FROM categories").map_err(db_err)?;
            let ids = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(db_err)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_err)?;
            ids.iter()
                .map(|id| read_category(&tx, id))
                .collect::<Result<_>>()?
        };
        let mut existing_fields = Vec::new();
        for c in &existing {
            existing_fields.extend(read_category_fields(&tx, &c.id, true)?);
        }
        let first: i64 = tx
            .query_row(
                "SELECT coalesce(max(sort_order)+1,0) FROM categories WHERE deleted_at IS NULL",
                [],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        let (cats, fields) = seed_records(ctx, &existing, &existing_fields, first);
        for c in &cats {
            tx.execute(
                "INSERT INTO categories(id,name,color,icon,icon_color,preset,sort_order,created_at,updated_at,updated_by)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    c.id, c.name, c.color, c.icon, c.icon_color, c.preset, c.sort_order,
                    c.created_at, c.updated_at, c.updated_by
                ],
            )
            .map_err(db_err)?;
        }
        write_category_fields(&tx, &fields)?;
        tx.commit().map_err(db_err)
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

    /// Attach a file to a live item (ADR 0019).
    pub fn add_attachment(
        &mut self,
        ctx: &WriteCtx<'_>,
        item_id: &str,
        file_name: &str,
        mime_type: &str,
        data: &[u8],
    ) -> Result<String> {
        let name = sanitize_file_name(file_name)?;
        check_mime_type(mime_type)?;
        let tx = self.begin(ctx)?;
        live_item(&tx, item_id)?;
        let live_total: i64 = tx
            .query_row(
                "SELECT COALESCE(SUM(size),0) FROM attachments WHERE deleted_at IS NULL",
                [],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        check_attachment_size(data.len(), u64::try_from(live_total).unwrap_or(u64::MAX))?;
        let id = new_id(ctx)?;
        tx.execute(
            "INSERT INTO attachments(id,item_id,file_name,mime_type,sha256,size,data,created_at,updated_at,updated_by)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8,?9)",
            params![
                id,
                item_id,
                name,
                mime_type,
                sha256_hex(data),
                data.len() as i64,
                data,
                ctx.now_ms,
                ctx.device_id
            ],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(id)
    }

    /// Live attachments of an item, oldest first (metadata only).
    pub fn list_attachments(&self, item_id: &str) -> Result<Vec<AttachmentInfo>> {
        live_item(self.conn(), item_id)?;
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id,item_id,file_name,mime_type,size,created_at,updated_at FROM attachments
                 WHERE item_id=?1 AND deleted_at IS NULL ORDER BY created_at,id",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([item_id], read_attachment_info)
            .map_err(db_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)
    }

    /// Metadata and bytes of a live attachment.
    pub fn read_attachment(&self, id: &str) -> Result<(AttachmentInfo, Zeroizing<Vec<u8>>)> {
        let (info, data) = self
            .conn()
            .query_row(
                "SELECT a.id,a.item_id,a.file_name,a.mime_type,a.size,a.created_at,a.updated_at,a.data
                 FROM attachments a JOIN items i ON i.id=a.item_id
                 WHERE a.id=?1 AND a.deleted_at IS NULL AND i.deleted_at IS NULL",
                [id],
                |r| Ok((read_attachment_info(r)?, r.get::<_, Vec<u8>>(7)?)),
            )
            .optional()
            .map_err(db_err)?
            .ok_or(Error::NotFound)?;
        Ok((info, Zeroizing::new(data)))
    }

    /// Rename a live attachment.
    pub fn rename_attachment(
        &mut self,
        ctx: &WriteCtx<'_>,
        id: &str,
        file_name: &str,
    ) -> Result<()> {
        let name = sanitize_file_name(file_name)?;
        let tx = self.begin(ctx)?;
        let prev: i64 = tx
            .query_row(
                "SELECT updated_at FROM attachments WHERE id=?1 AND deleted_at IS NULL",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?
            .ok_or(Error::NotFound)?;
        tx.execute(
            "UPDATE attachments SET file_name=?2,updated_at=?3,updated_by=?4 WHERE id=?1",
            params![id, name, bump(prev, ctx.now_ms), ctx.device_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Tombstone an attachment and scrub its bytes.
    pub fn delete_attachment(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        let prev: i64 = tx
            .query_row(
                "SELECT updated_at FROM attachments WHERE id=?1 AND deleted_at IS NULL",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?
            .ok_or(Error::NotFound)?;
        let t = bump(prev, ctx.now_ms);
        tx.execute(
            "UPDATE attachments SET data=x'',size=0,deleted_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
            params![id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
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

impl Database {
    /// Store a passkey on a live, non-trashed item (ADR 0020).
    pub fn add_passkey(
        &mut self,
        ctx: &WriteCtx<'_>,
        item_id: &str,
        new: &NewPasskey,
    ) -> Result<String> {
        let tx = self.begin(ctx)?;
        live_item(&tx, item_id)?;
        ensure_not_trashed(&tx, item_id)?;
        // WebAuthn: a new credential for the same account replaces the old one.
        tx.execute(
            "UPDATE passkeys SET private_key=x'',deleted_at=max(?3,updated_at+1),
               updated_at=max(?3,updated_at+1),updated_by=?4
             WHERE rp_id=?1 AND user_handle=?2 AND deleted_at IS NULL",
            params![new.rp_id, new.user_handle, ctx.now_ms, ctx.device_id],
        )
        .map_err(db_err)?;
        let id = new_id(ctx)?;
        tx.execute(
            "INSERT INTO passkeys(id,item_id,credential_id,rp_id,user_name,user_handle,private_key,created_at,updated_at,updated_by)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8,?9)",
            params![
                id,
                item_id,
                new.credential_id,
                new.rp_id,
                new.user_name,
                new.user_handle,
                new.private_key.as_slice(),
                ctx.now_ms,
                ctx.device_id
            ],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(id)
    }

    /// Live passkeys of an item, oldest first (metadata only).
    pub fn list_passkeys(&self, item_id: &str) -> Result<Vec<PasskeyInfo>> {
        live_item(self.conn(), item_id)?;
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id,item_id,credential_id,rp_id,user_name,user_handle,created_at,updated_at
                 FROM passkeys WHERE item_id=?1 AND deleted_at IS NULL ORDER BY created_at,id",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([item_id], read_passkey_info)
            .map_err(db_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)
    }

    /// Live passkeys for a relying party on non-trashed items, newest first.
    pub fn passkeys_for_rp(&self, rp_id: &str) -> Result<Vec<PasskeyInfo>> {
        let Ok(rp_id) = crate::passkey::normalize_rp_id(rp_id) else {
            return Ok(Vec::new());
        };
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT p.id,p.item_id,p.credential_id,p.rp_id,p.user_name,p.user_handle,p.created_at,p.updated_at
                 FROM passkeys p JOIN items i ON i.id=p.item_id
                 WHERE p.rp_id=?1 AND p.deleted_at IS NULL AND i.deleted_at IS NULL AND i.trashed_at IS NULL
                 ORDER BY p.created_at DESC,p.id DESC",
            )
            .map_err(db_err)?;
        let rows = stmt.query_map([rp_id], read_passkey_info).map_err(db_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)
    }

    /// Metadata and private key of a usable passkey (core-internal).
    pub fn passkey_secret(&self, id: &str) -> Result<(PasskeyInfo, Zeroizing<Vec<u8>>)> {
        let (info, key) = self
            .conn()
            .query_row(
                "SELECT p.id,p.item_id,p.credential_id,p.rp_id,p.user_name,p.user_handle,p.created_at,p.updated_at,p.private_key
                 FROM passkeys p JOIN items i ON i.id=p.item_id
                 WHERE p.id=?1 AND p.deleted_at IS NULL AND i.deleted_at IS NULL AND i.trashed_at IS NULL",
                [id],
                |r| Ok((read_passkey_info(r)?, Zeroizing::new(r.get::<_, Vec<u8>>(8)?))),
            )
            .optional()
            .map_err(db_err)?
            .ok_or(Error::NotFound)?;
        Ok((info, key))
    }

    /// Tombstone a passkey and scrub its key.
    pub fn delete_passkey(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        let tx = self.begin(ctx)?;
        let prev: i64 = tx
            .query_row(
                "SELECT updated_at FROM passkeys WHERE id=?1 AND deleted_at IS NULL",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?
            .ok_or(Error::NotFound)?;
        let t = bump(prev, ctx.now_ms);
        tx.execute(
            "UPDATE passkeys SET private_key=x'',deleted_at=?2,updated_at=?2,updated_by=?3 WHERE id=?1",
            params![id, t, ctx.device_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }
}

fn read_passkey_info(r: &rusqlite::Row<'_>) -> rusqlite::Result<PasskeyInfo> {
    Ok(PasskeyInfo {
        id: r.get(0)?,
        item_id: r.get(1)?,
        credential_id: r.get(2)?,
        rp_id: r.get(3)?,
        user_name: r.get(4)?,
        user_handle: r.get(5)?,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
    })
}

fn read_attachment_info(r: &rusqlite::Row<'_>) -> rusqlite::Result<AttachmentInfo> {
    Ok(AttachmentInfo {
        id: r.get(0)?,
        item_id: r.get(1)?,
        file_name: r.get(2)?,
        mime_type: r.get(3)?,
        size: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
        created_at: r.get(5)?,
        updated_at: r.get(6)?,
    })
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

/// Fields of a category in display order; `with_deleted` includes tombstones.
fn read_category_fields(
    conn: &Connection,
    category_id: &str,
    with_deleted: bool,
) -> Result<Vec<CategoryField>> {
    let mut stmt = conn
        .prepare(
            "SELECT id,category_id,name,kind,is_secret,is_core,sort_order,updated_at,updated_by,deleted_at
             FROM category_fields WHERE category_id=?1 AND (?2 OR deleted_at IS NULL)
             ORDER BY sort_order,id",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map(params![category_id, with_deleted], |r| {
            Ok(CategoryField {
                id: r.get(0)?,
                category_id: r.get(1)?,
                name: r.get(2)?,
                kind: r.get(3)?,
                is_secret: r.get(4)?,
                is_core: r.get(5)?,
                sort_order: r.get(6)?,
                updated_at: r.get(7)?,
                updated_by: r.get(8)?,
                deleted_at: r.get(9)?,
            })
        })
        .map_err(db_err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_err)?;
    Ok(rows)
}

fn write_category_fields(conn: &Connection, fields: &[CategoryField]) -> Result<()> {
    for f in fields {
        conn.execute(
            "INSERT INTO category_fields(id,category_id,name,kind,is_secret,is_core,sort_order,updated_at,updated_by,deleted_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,
               is_secret=excluded.is_secret,is_core=excluded.is_core,
               sort_order=excluded.sort_order,updated_at=excluded.updated_at,updated_by=excluded.updated_by,
               deleted_at=excluded.deleted_at",
            params![
                f.id, f.category_id, f.name, f.kind, f.is_secret, f.is_core, f.sort_order,
                f.updated_at, f.updated_by, f.deleted_at
            ],
        )
        .map_err(db_err)?;
    }
    Ok(())
}

fn read_category(conn: &Connection, id: &str) -> Result<Category> {
    conn.query_row(
        "SELECT id,name,color,icon,icon_color,sort_order,created_at,updated_at,updated_by,deleted_at,preset
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
                preset: r.get(10)?,
            })
        },
    )
    .optional()
    .map_err(db_err)?
    .ok_or(Error::NotFound)
}

impl Database {
    /// MIME type and bytes of a stored note image.
    pub fn note_image(&self, id: &str) -> Result<(String, Zeroizing<Vec<u8>>)> {
        self.conn()
            .query_row(
                "SELECT mime_type,data FROM note_images WHERE id=?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        Zeroizing::new(r.get::<_, Vec<u8>>(1)?),
                    ))
                },
            )
            .optional()
            .map_err(db_err)?
            .ok_or(Error::NotFound)
    }
}

macro_rules! delegate {
    ($( fn $name:ident($recv:ty $(, $a:ident : $t:ty)*) -> $ret:ty; )*) => {$(
        fn $name(self: $recv $(, $a: $t)*) -> $ret {
            Database::$name(self $(, $a)*)
        }
    )*};
}

impl VaultStore for Database {
    delegate! {
        fn create_item(&mut Self, ctx: &WriteCtx<'_>, new: &NewItem) -> Result<String>;
        fn update_item(&mut Self, ctx: &WriteCtx<'_>, id: &str, upd: &ItemUpdate) -> Result<()>;
        fn delete_item(&mut Self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
        fn trash_item(&mut Self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
        fn restore_item(&mut Self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
        fn list_trashed_items(&Self) -> Result<Vec<ItemSummary>>;
        fn list_vaults(&Self) -> Result<Vec<VaultMeta>>;
        fn create_vault(&mut Self, ctx: &WriteCtx<'_>, name: &str, color: &str, badge: Option<&str>) -> Result<VaultMeta>;
        fn update_vault(&mut Self, ctx: &WriteCtx<'_>, id: &str, upd: &VaultUpdate) -> Result<VaultMeta>;
        fn delete_vault(&mut Self, ctx: &WriteCtx<'_>, id: &str, move_items_to: &str) -> Result<()>;
        fn ensure_default_vault(&mut Self, ctx: &WriteCtx<'_>) -> Result<()>;
        fn record_use(&mut Self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
        fn list_items(&Self) -> Result<Vec<ItemSummary>>;
        fn get_item(&Self, id: &str) -> Result<ItemDetail>;
        fn reveal_field(&Self, item_id: &str, field_id: &str) -> Result<Zeroizing<String>>;
        fn reveal_password_history(&Self, item_id: &str) -> Result<Vec<HistoryEntry>>;
        fn create_tag(&mut Self, ctx: &WriteCtx<'_>, name: &str, color: &str) -> Result<Tag>;
        fn list_tags(&Self) -> Result<Vec<Tag>>;
        fn update_tag(&mut Self, ctx: &WriteCtx<'_>, tag_id: &str, name: Option<&str>, color: Option<&str>) -> Result<Tag>;
        fn delete_tag(&mut Self, ctx: &WriteCtx<'_>, tag_id: &str) -> Result<()>;
        fn add_tag(&mut Self, ctx: &WriteCtx<'_>, item_id: &str, tag_id: &str) -> Result<()>;
        fn remove_tag(&mut Self, ctx: &WriteCtx<'_>, item_id: &str, tag_id: &str) -> Result<()>;
        fn create_category(&mut Self, ctx: &WriteCtx<'_>, new: &NewCategory) -> Result<Category>;
        fn update_category(&mut Self, ctx: &WriteCtx<'_>, id: &str, upd: &CategoryUpdate) -> Result<()>;
        fn reorder_categories(&mut Self, ctx: &WriteCtx<'_>, ordered_ids: &[String]) -> Result<()>;
        fn delete_category(&mut Self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
        fn list_categories(&Self) -> Result<Vec<Category>>;
        fn list_category_fields(&Self, category_id: &str) -> Result<Vec<CategoryField>>;
        fn seed_default_categories(&mut Self, ctx: &WriteCtx<'_>) -> Result<()>;
        fn add_note_image(&mut Self, ctx: &WriteCtx<'_>, mime_type: &str, data: &[u8]) -> Result<String>;
        fn note_image(&Self, id: &str) -> Result<(String, Zeroizing<Vec<u8>>)>;
        fn add_attachment(&mut Self, ctx: &WriteCtx<'_>, item_id: &str, file_name: &str, mime_type: &str, data: &[u8]) -> Result<String>;
        fn list_attachments(&Self, item_id: &str) -> Result<Vec<AttachmentInfo>>;
        fn read_attachment(&Self, id: &str) -> Result<(AttachmentInfo, Zeroizing<Vec<u8>>)>;
        fn rename_attachment(&mut Self, ctx: &WriteCtx<'_>, id: &str, file_name: &str) -> Result<()>;
        fn delete_attachment(&mut Self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
        fn add_passkey(&mut Self, ctx: &WriteCtx<'_>, item_id: &str, new: &NewPasskey) -> Result<String>;
        fn list_passkeys(&Self, item_id: &str) -> Result<Vec<PasskeyInfo>>;
        fn passkeys_for_rp(&Self, rp_id: &str) -> Result<Vec<PasskeyInfo>>;
        fn passkey_secret(&Self, id: &str) -> Result<(PasskeyInfo, Zeroizing<Vec<u8>>)>;
        fn delete_passkey(&mut Self, ctx: &WriteCtx<'_>, id: &str) -> Result<()>;
        fn merge_remote(&mut Self, remote: &Snapshot) -> Result<()>;
    }

    fn snapshot(&self) -> Result<Snapshot> {
        self.load_snapshot()
    }
}
