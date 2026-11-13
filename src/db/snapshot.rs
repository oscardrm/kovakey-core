//! Conversion between the encrypted database and the merge [`Snapshot`] (ADR 0001).
//!
//! * `load_snapshot` reads every synced table in one read transaction.
//! * `save_snapshot` writes a snapshot in one `IMMEDIATE` transaction. It is **upsert-only**
//!   (tombstones are rows; nothing is ever hard-deleted) and **LWW-guarded**: a row whose
//!   `(updated_at, updated_by)` is older than the stored row is left untouched, so a stale
//!   snapshot cannot overwrite newer local edits. Foreign keys are checked at commit, so the
//!   write order is irrelevant and an inconsistent snapshot rolls back as a whole.
//! * `merge_remote` loads, merges and saves inside a single transaction, which makes it safe
//!   against a concurrent local write between load and save.

use std::collections::{BTreeMap, BTreeSet};

use crate::side_blob::sha256_hex;
use rusqlite::{params, Connection, TransactionBehavior};

use super::{db_err, Database};
use crate::error::{Error, Result};
use crate::merge::merge;
use crate::models::{
    BlockKind, Category, CategoryField, HistoryEntry, Item, ItemField, ItemTag, ItemType,
    NoteBlock, NoteImage, Snapshot, Tag, VaultMeta,
};

fn corrupt(idx: usize, e: Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
}

fn query<T>(
    conn: &Connection,
    sql: &str,
    map: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut stmt = conn.prepare(sql).map_err(db_err)?;
    let rows = stmt.query_map([], map).map_err(db_err)?;
    rows.collect::<rusqlite::Result<Vec<T>>>().map_err(db_err)
}

/// Read every synced table. Output is sorted by key for determinism.
fn read_all(conn: &Connection) -> Result<Snapshot> {
    let vault_meta = query(
        conn,
        "SELECT id,name,color,badge,created_at,updated_at,updated_by,deleted_at FROM vault_meta ORDER BY id",
        |r| {
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
        },
    )?;
    let categories = query(
        conn,
        "SELECT id,name,color,icon,icon_color,sort_order,created_at,updated_at,updated_by,deleted_at,preset
         FROM categories ORDER BY id",
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
    )?;
    let category_fields = query(
        conn,
        "SELECT id,category_id,name,kind,is_secret,is_core,sort_order,updated_at,updated_by,deleted_at
         FROM category_fields ORDER BY id",
        |r| {
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
        },
    )?;
    let tags = query(
        conn,
        "SELECT id,name,color,created_at,updated_at,updated_by,deleted_at FROM tags ORDER BY id",
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
    )?;
    let mut items = query(
        conn,
        "SELECT id,category_id,item_type,title,url,color,favorite,use_count,last_used_at,
                created_at,updated_at,updated_by,deleted_at,trashed_at,vault_id
         FROM items ORDER BY id",
        |r| {
            let ty: String = r.get(2)?;
            Ok(Item {
                id: r.get(0)?,
                vault_id: r.get(14)?,
                category_id: r.get(1)?,
                item_type: ItemType::parse(&ty).map_err(|e| corrupt(2, e))?,
                title: r.get(3)?,
                url: r.get(4)?,
                color: r.get(5)?,
                favorite: r.get::<_, i64>(6)? != 0,
                use_count: r.get(7)?,
                last_used_at: r.get(8)?,
                created_at: r.get(9)?,
                updated_at: r.get(10)?,
                updated_by: r.get(11)?,
                deleted_at: r.get(12)?,
                trashed_at: r.get(13)?,
                history: BTreeSet::new(),
            })
        },
    )?;
    let history = query(
        conn,
        "SELECT id,item_id,field_id,password,changed_at FROM password_history ORDER BY id",
        |r| {
            Ok((
                r.get::<_, String>(1)?,
                HistoryEntry {
                    id: r.get(0)?,
                    field_id: r.get(2)?,
                    password: r.get(3)?,
                    changed_at: r.get(4)?,
                },
            ))
        },
    )?;
    let mut by_item: BTreeMap<String, BTreeSet<HistoryEntry>> = BTreeMap::new();
    for (item_id, entry) in history {
        by_item.entry(item_id).or_default().insert(entry);
    }
    for item in &mut items {
        if let Some(h) = by_item.remove(&item.id) {
            item.history = h;
        }
    }
    let item_fields = query(
        conn,
        "SELECT id,item_id,name,kind,value,is_secret,sort_order,updated_at,updated_by,deleted_at
         FROM item_fields ORDER BY id",
        |r| {
            Ok(ItemField {
                id: r.get(0)?,
                item_id: r.get(1)?,
                name: r.get(2)?,
                kind: r.get(3)?,
                value: r.get(4)?,
                is_secret: r.get::<_, i64>(5)? != 0,
                sort_order: r.get(6)?,
                updated_at: r.get(7)?,
                updated_by: r.get(8)?,
                deleted_at: r.get(9)?,
            })
        },
    )?;
    let item_tags = query(
        conn,
        "SELECT item_id,tag_id,auto,updated_at,updated_by,deleted_at FROM item_tags
         ORDER BY item_id,tag_id",
        |r| {
            Ok(ItemTag {
                item_id: r.get(0)?,
                tag_id: r.get(1)?,
                auto: r.get::<_, i64>(2)? != 0,
                updated_at: r.get(3)?,
                updated_by: r.get(4)?,
                deleted_at: r.get(5)?,
            })
        },
    )?;
    let note_blocks = query(
        conn,
        "SELECT id,item_id,position,kind,language,content,image_id,updated_at,updated_by,deleted_at
         FROM note_blocks ORDER BY id",
        |r| {
            let kind: String = r.get(3)?;
            Ok(NoteBlock {
                id: r.get(0)?,
                item_id: r.get(1)?,
                position: r.get(2)?,
                kind: BlockKind::parse(&kind).map_err(|e| corrupt(3, e))?,
                language: r.get(4)?,
                content: r.get(5)?,
                image_id: r.get(6)?,
                updated_at: r.get(7)?,
                updated_by: r.get(8)?,
                deleted_at: r.get(9)?,
            })
        },
    )?;
    let note_images = query(
        conn,
        "SELECT id,mime_type,data,created_at FROM note_images ORDER BY id",
        |r| {
            let data: Vec<u8> = r.get(2)?;
            Ok(NoteImage {
                id: r.get(0)?,
                mime_type: r.get(1)?,
                sha256: sha256_hex(&data),
                size: data.len() as u64,
                data,
                created_at: r.get(3)?,
            })
        },
    )?;
    Ok(Snapshot {
        vault_meta,
        categories,
        category_fields,
        tags,
        items,
        item_fields,
        item_tags,
        note_blocks,
        note_images,
    })
}

/// Write `snap` using upserts. Must run inside a transaction.
fn write_all(conn: &Connection, snap: &Snapshot) -> Result<()> {
    // Check foreign keys at COMMIT rather than per statement: write order is then irrelevant.
    conn.execute_batch("PRAGMA defer_foreign_keys = ON;")
        .map_err(db_err)?;

    // Images first (immutable, insert-only). Hash/size are derived, never trusted.
    for i in &snap.note_images {
        conn.execute(
            "INSERT OR IGNORE INTO note_images(id,mime_type,data,created_at) VALUES(?1,?2,?3,?4)",
            params![i.id, i.mime_type, i.data, i.created_at],
        )
        .map_err(db_err)?;
    }
    for v in &snap.vault_meta {
        conn.execute(
            "INSERT INTO vault_meta(id,name,color,badge,created_at,updated_at,updated_by,deleted_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name,color=excluded.color,
               badge=excluded.badge,created_at=excluded.created_at,
               updated_at=excluded.updated_at,updated_by=excluded.updated_by,
               deleted_at=excluded.deleted_at
             WHERE (excluded.updated_at,excluded.updated_by) >= (vault_meta.updated_at,vault_meta.updated_by)",
            params![
                v.id,
                v.name,
                v.color,
                v.badge,
                v.created_at,
                v.updated_at,
                v.updated_by,
                v.deleted_at
            ],
        )
        .map_err(db_err)?;
    }
    for c in &snap.categories {
        conn.execute(
            "INSERT INTO categories(id,name,color,icon,icon_color,sort_order,created_at,updated_at,updated_by,deleted_at,preset)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name,color=excluded.color,
               icon=excluded.icon,icon_color=excluded.icon_color,sort_order=excluded.sort_order,
               preset=excluded.preset,
               created_at=excluded.created_at,updated_at=excluded.updated_at,
               updated_by=excluded.updated_by,deleted_at=excluded.deleted_at
             WHERE (excluded.updated_at,excluded.updated_by) >= (categories.updated_at,categories.updated_by)",
            params![
                c.id, c.name, c.color, c.icon, c.icon_color, c.sort_order, c.created_at,
                c.updated_at, c.updated_by, c.deleted_at, c.preset
            ],
        )
        .map_err(db_err)?;
    }
    for f in &snap.category_fields {
        conn.execute(
            "INSERT INTO category_fields(id,category_id,name,kind,is_secret,is_core,sort_order,updated_at,updated_by,deleted_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(id) DO UPDATE SET category_id=excluded.category_id,name=excluded.name,
               kind=excluded.kind,is_secret=excluded.is_secret,is_core=excluded.is_core,
               sort_order=excluded.sort_order,updated_at=excluded.updated_at,
               updated_by=excluded.updated_by,deleted_at=excluded.deleted_at
             WHERE (excluded.updated_at,excluded.updated_by) >= (category_fields.updated_at,category_fields.updated_by)",
            params![
                f.id, f.category_id, f.name, f.kind, f.is_secret, f.is_core, f.sort_order,
                f.updated_at, f.updated_by, f.deleted_at
            ],
        )
        .map_err(db_err)?;
    }
    for t in &snap.tags {
        conn.execute(
            "INSERT INTO tags(id,name,color,created_at,updated_at,updated_by,deleted_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name,color=excluded.color,
               created_at=excluded.created_at,updated_at=excluded.updated_at,
               updated_by=excluded.updated_by,deleted_at=excluded.deleted_at
             WHERE (excluded.updated_at,excluded.updated_by) >= (tags.updated_at,tags.updated_by)",
            params![
                t.id,
                t.name,
                t.color,
                t.created_at,
                t.updated_at,
                t.updated_by,
                t.deleted_at
            ],
        )
        .map_err(db_err)?;
    }
    for i in &snap.items {
        // Usage counters are monotone: keep the max of stored and incoming values.
        conn.execute(
            "INSERT INTO items(id,category_id,item_type,title,url,color,favorite,use_count,last_used_at,
                               created_at,updated_at,updated_by,deleted_at,trashed_at,vault_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
             ON CONFLICT(id) DO UPDATE SET category_id=excluded.category_id,vault_id=excluded.vault_id,
               item_type=excluded.item_type,title=excluded.title,url=excluded.url,
               color=excluded.color,favorite=excluded.favorite,
               use_count=max(items.use_count,excluded.use_count),
               last_used_at=CASE WHEN items.last_used_at IS NULL THEN excluded.last_used_at
                                 WHEN excluded.last_used_at IS NULL THEN items.last_used_at
                                 ELSE max(items.last_used_at,excluded.last_used_at) END,
               created_at=excluded.created_at,updated_at=excluded.updated_at,
               updated_by=excluded.updated_by,deleted_at=excluded.deleted_at,
               trashed_at=excluded.trashed_at
             WHERE (excluded.updated_at,excluded.updated_by) >= (items.updated_at,items.updated_by)",
            params![
                i.id,
                i.category_id,
                i.item_type.as_str(),
                i.title,
                i.url,
                i.color,
                i64::from(i.favorite),
                i.use_count,
                i.last_used_at,
                i.created_at,
                i.updated_at,
                i.updated_by,
                i.deleted_at,
                i.trashed_at,
                i.vault_id
            ],
        )
        .map_err(db_err)?;
        for h in &i.history {
            conn.execute(
                "INSERT OR IGNORE INTO password_history(id,item_id,field_id,password,changed_at)
                 VALUES(?1,?2,?3,?4,?5)",
                params![h.id, i.id, h.field_id, h.password, h.changed_at],
            )
            .map_err(db_err)?;
        }
    }
    for f in &snap.item_fields {
        conn.execute(
            "INSERT INTO item_fields(id,item_id,name,kind,value,is_secret,sort_order,updated_at,updated_by,deleted_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(id) DO UPDATE SET item_id=excluded.item_id,name=excluded.name,
               kind=excluded.kind,value=excluded.value,is_secret=excluded.is_secret,
               sort_order=excluded.sort_order,updated_at=excluded.updated_at,
               updated_by=excluded.updated_by,deleted_at=excluded.deleted_at
             WHERE (excluded.updated_at,excluded.updated_by) >= (item_fields.updated_at,item_fields.updated_by)",
            params![
                f.id,
                f.item_id,
                f.name,
                f.kind,
                f.value,
                i64::from(f.is_secret),
                f.sort_order,
                f.updated_at,
                f.updated_by,
                f.deleted_at
            ],
        )
        .map_err(db_err)?;
    }
    for l in &snap.item_tags {
        conn.execute(
            "INSERT INTO item_tags(item_id,tag_id,auto,updated_at,updated_by,deleted_at)
             VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(item_id,tag_id) DO UPDATE SET auto=excluded.auto,
               updated_at=excluded.updated_at,updated_by=excluded.updated_by,
               deleted_at=excluded.deleted_at
             WHERE (excluded.updated_at,excluded.updated_by) >= (item_tags.updated_at,item_tags.updated_by)",
            params![
                l.item_id,
                l.tag_id,
                i64::from(l.auto),
                l.updated_at,
                l.updated_by,
                l.deleted_at
            ],
        )
        .map_err(db_err)?;
    }
    for b in &snap.note_blocks {
        conn.execute(
            "INSERT INTO note_blocks(id,item_id,position,kind,language,content,image_id,updated_at,updated_by,deleted_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(id) DO UPDATE SET item_id=excluded.item_id,position=excluded.position,
               kind=excluded.kind,language=excluded.language,content=excluded.content,
               image_id=excluded.image_id,updated_at=excluded.updated_at,
               updated_by=excluded.updated_by,deleted_at=excluded.deleted_at
             WHERE (excluded.updated_at,excluded.updated_by) >= (note_blocks.updated_at,note_blocks.updated_by)",
            params![
                b.id,
                b.item_id,
                b.position,
                b.kind.as_str(),
                b.language,
                b.content,
                b.image_id,
                b.updated_at,
                b.updated_by,
                b.deleted_at
            ],
        )
        .map_err(db_err)?;
    }
    Ok(())
}

impl Database {
    /// Read the whole vault into a [`Snapshot`] (one consistent read transaction).
    pub fn load_snapshot(&self) -> Result<Snapshot> {
        let tx = self.conn().unchecked_transaction().map_err(db_err)?;
        let snap = read_all(&tx)?;
        tx.commit().map_err(db_err)?;
        Ok(snap)
    }

    /// Write a (merged) snapshot in a single transaction. Upsert-only and LWW-guarded; on any
    /// error (including a dangling foreign key) nothing is written.
    pub fn save_snapshot(&mut self, snap: &Snapshot) -> Result<()> {
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_err)?;
        write_all(&tx, snap)?;
        tx.commit().map_err(db_err)
    }

    /// Merge a decrypted remote snapshot into this database atomically: load, merge, save in
    /// one `IMMEDIATE` transaction. Nothing is persisted if any step fails.
    pub fn merge_remote(&mut self, remote: &Snapshot) -> Result<()> {
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_err)?;
        let local = read_all(&tx)?;
        write_all(&tx, &merge(&local, remote))?;
        tx.commit().map_err(db_err)
    }
}
