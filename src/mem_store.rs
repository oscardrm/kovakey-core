//! Portable in-memory [`VaultStore`] over a decrypted [`Snapshot`] (no SQLCipher, so it builds for
//! `wasm32-unknown-unknown`). It upholds the same invariants as the SQLCipher backend (see
//! [`crate::ops`]); `tests/store_conformance.rs` runs identical scenarios against both.
//!
//! Every write runs on a working copy that replaces the live data only on success, so a failed
//! call changes nothing. The copy excludes note images (moved in and out, never cloned), and every
//! record wipes its secret payload on drop. The whole structure is plaintext in memory:
//! dropping a `MemStore` is the "lock" for portable clients.

use std::collections::BTreeSet;
use std::mem;

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::merge::merge;
use crate::models::{
    Attachment, BlockKind, Category, CategoryField, HistoryEntry, Item, ItemField, ItemTag,
    NoteBlock, NoteImage, Passkey, Snapshot, Tag, VaultMeta, DEFAULT_VAULT_ID,
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

/// In-memory vault store.
#[derive(Debug)]
pub struct MemStore {
    snap: Snapshot,
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Guarantee at least one live vault (a new item needs somewhere to live): create the default
/// vault, or revive it if it is the tombstoned one.
fn ensure_live_vault(s: &mut Snapshot) {
    if s.vault_meta.iter().any(|v| v.deleted_at.is_none()) {
        return;
    }
    if let Some(v) = s.vault_meta.iter_mut().find(|v| v.id == DEFAULT_VAULT_ID) {
        v.deleted_at = None;
    } else {
        s.vault_meta.push(VaultMeta {
            id: DEFAULT_VAULT_ID.to_string(),
            name: "Personal".to_string(),
            color: "#2563EB".to_string(),
            badge: None,
            created_at: 0,
            updated_at: 0,
            updated_by: String::new(),
            deleted_at: None,
        });
    }
}

/// Check the foreign-key relations the SQL schema enforces, so a malformed remote cannot slip in.
fn check_integrity(s: &Snapshot) -> Result<()> {
    let items: BTreeSet<&str> = s.items.iter().map(|i| i.id.as_str()).collect();
    let tags: BTreeSet<&str> = s.tags.iter().map(|t| t.id.as_str()).collect();
    let cats: BTreeSet<&str> = s.categories.iter().map(|c| c.id.as_str()).collect();
    let imgs: BTreeSet<&str> = s.note_images.iter().map(|i| i.id.as_str()).collect();
    let ok = s
        .items
        .iter()
        .all(|i| i.category_id.as_deref().map_or(true, |c| cats.contains(c)))
        && s.category_fields
            .iter()
            .all(|f| cats.contains(f.category_id.as_str()))
        && s.attachments
            .iter()
            .all(|a| items.contains(a.item_id.as_str()))
        && s.passkeys
            .iter()
            .all(|p| items.contains(p.item_id.as_str()))
        && s.item_fields
            .iter()
            .all(|f| items.contains(f.item_id.as_str()))
        && s.item_tags
            .iter()
            .all(|l| items.contains(l.item_id.as_str()) && tags.contains(l.tag_id.as_str()))
        && s.note_blocks.iter().all(|b| {
            items.contains(b.item_id.as_str())
                && b.image_id.as_deref().map_or(true, |i| imgs.contains(i))
        });
    if ok {
        Ok(())
    } else {
        Err(Error::Corrupted)
    }
}

fn passkey_info(p: &Passkey) -> PasskeyInfo {
    PasskeyInfo {
        id: p.id.clone(),
        item_id: p.item_id.clone(),
        credential_id: p.credential_id.clone(),
        rp_id: p.rp_id.clone(),
        user_name: p.user_name.clone(),
        user_handle: p.user_handle.clone(),
        created_at: p.created_at,
        updated_at: p.updated_at,
    }
}

/// Tombstone a passkey at `t` and scrub its key.
fn tombstone_passkey(p: &mut Passkey, t: i64, device_id: &str) {
    p.private_key.zeroize();
    p.private_key.clear();
    p.deleted_at = Some(t);
    p.updated_at = t;
    p.updated_by = device_id.to_string();
}

fn attachment_info(a: &Attachment) -> AttachmentInfo {
    AttachmentInfo {
        id: a.id.clone(),
        item_id: a.item_id.clone(),
        file_name: a.file_name.clone(),
        mime_type: a.mime_type.clone(),
        size: a.size,
        created_at: a.created_at,
        updated_at: a.updated_at,
    }
}

fn begin(ctx: &WriteCtx<'_>) -> Result<()> {
    non_empty(ctx.device_id)?;
    if ctx.now_ms < 0 {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn live_item<'a>(s: &'a mut Snapshot, id: &str) -> Result<&'a mut Item> {
    s.items
        .iter_mut()
        .find(|i| i.id == id && i.deleted_at.is_none())
        .ok_or(Error::NotFound)
}

/// A live item that is not in the Trash (the only kind that can be edited or used).
fn active_item<'a>(s: &'a mut Snapshot, id: &str) -> Result<&'a mut Item> {
    let it = live_item(s, id)?;
    if it.trashed_at.is_some() {
        return Err(Error::InvalidInput);
    }
    Ok(it)
}

/// Live vaults ordered by (creation time, id): the default vault (created at 0) comes first.
fn live_vaults(s: &Snapshot) -> Vec<&VaultMeta> {
    let mut v: Vec<&VaultMeta> = s
        .vault_meta
        .iter()
        .filter(|v| v.deleted_at.is_none())
        .collect();
    v.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    v
}

fn vault_is_live(s: &Snapshot, id: &str) -> bool {
    s.vault_meta
        .iter()
        .any(|v| v.id == id && v.deleted_at.is_none())
}

/// Vault for a new item: the requested one (must be live) or the first live vault.
fn resolve_vault(s: &Snapshot, requested: Option<&str>) -> Result<String> {
    match requested {
        Some(id) if vault_is_live(s, id) => Ok(id.to_string()),
        Some(_) => Err(Error::NotFound),
        None => live_vaults(s)
            .first()
            .map(|v| v.id.clone())
            .ok_or(Error::NotFound),
    }
}

fn vault_name_taken(s: &Snapshot, name: &str, except: Option<&str>) -> bool {
    live_vaults(s)
        .iter()
        .any(|v| Some(v.id.as_str()) != except && v.name.to_lowercase() == name.to_lowercase())
}

fn require_live_category(s: &Snapshot, id: &str) -> Result<()> {
    s.categories
        .iter()
        .any(|c| c.id == id && c.deleted_at.is_none())
        .then_some(())
        .ok_or(Error::NotFound)
}

/// Insert or replace category fields by id.
fn upsert_category_fields(s: &mut Snapshot, planned: Vec<CategoryField>) {
    for f in planned {
        match s.category_fields.iter_mut().find(|e| e.id == f.id) {
            Some(slot) => *slot = f,
            None => s.category_fields.push(f),
        }
    }
}

fn live_tag_by_name<'a>(s: &'a Snapshot, name: &str) -> Option<&'a Tag> {
    s.tags
        .iter()
        .filter(|t| t.name == name && t.deleted_at.is_none())
        .min_by(|a, b| a.id.cmp(&b.id))
}

/// Indexes of the live fields of an item in display order.
fn live_field_idx(s: &Snapshot, item_id: &str) -> Vec<usize> {
    let mut v: Vec<usize> = (0..s.item_fields.len())
        .filter(|&i| {
            s.item_fields
                .get(i)
                .is_some_and(|f| f.item_id == item_id && f.deleted_at.is_none())
        })
        .collect();
    v.sort_by(|&a, &b| {
        let (x, y) = (s.item_fields.get(a), s.item_fields.get(b));
        x.map(|f| (f.sort_order, &f.id))
            .cmp(&y.map(|f| (f.sort_order, &f.id)))
    });
    v
}

fn live_block_idx(s: &Snapshot, item_id: &str) -> Vec<usize> {
    let mut v: Vec<usize> = (0..s.note_blocks.len())
        .filter(|&i| {
            s.note_blocks
                .get(i)
                .is_some_and(|b| b.item_id == item_id && b.deleted_at.is_none())
        })
        .collect();
    v.sort_by(|&a, &b| {
        let (x, y) = (s.note_blocks.get(a), s.note_blocks.get(b));
        x.map(|f| (f.position, &f.id))
            .cmp(&y.map(|f| (f.position, &f.id)))
    });
    v
}

fn resolved_language(inp: &BlockInput) -> Option<String> {
    match (&inp.language, inp.kind) {
        (Some(l), _) => Some(l.clone()),
        (None, BlockKind::Code) => Some(detect_language(&inp.content).id().to_string()),
        (None, _) => None,
    }
}

/// Make the live fields of `item_id` equal to `inputs`. Returns whether anything changed.
fn sync_fields(
    s: &mut Snapshot,
    ctx: &WriteCtx<'_>,
    item_id: &str,
    inputs: &[FieldInput],
) -> Result<bool> {
    let existing: Vec<String> = live_field_idx(s, item_id)
        .into_iter()
        .filter_map(|i| s.item_fields.get(i).map(|f| f.id.clone()))
        .collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut changed = false;
    for (idx, inp) in inputs.iter().enumerate() {
        non_empty(&inp.name)?;
        non_empty(&inp.kind)?;
        let order = i64::try_from(idx).map_err(|_| Error::InvalidInput)?;
        match inp.id.as_deref() {
            Some(id) => {
                if !existing.iter().any(|e| e == id) {
                    return Err(Error::NotFound);
                }
                if !seen.insert(id) {
                    return Err(Error::InvalidInput);
                }
                let history_id = new_id(ctx)?;
                let f = s
                    .item_fields
                    .iter_mut()
                    .find(|f| f.id == id)
                    .ok_or(Error::NotFound)?;
                let old_pw = (f.kind == "password" && !f.value.is_empty() && f.value != inp.value)
                    .then(|| f.value.clone());
                let same = f.name == inp.name
                    && f.kind == inp.kind
                    && f.value == inp.value
                    && f.is_secret == inp.is_secret
                    && f.sort_order == order;
                if !same {
                    f.name.clone_from(&inp.name);
                    f.kind.clone_from(&inp.kind);
                    f.value.zeroize();
                    f.value.clone_from(&inp.value);
                    f.is_secret = inp.is_secret;
                    f.sort_order = order;
                    f.updated_at = bump(f.updated_at, ctx.now_ms);
                    f.updated_by = ctx.device_id.to_string();
                    changed = true;
                }
                let field_id = f.id.clone();
                if let Some(password) = old_pw {
                    live_item(s, item_id)?.history.insert(HistoryEntry {
                        id: history_id,
                        field_id: Some(field_id),
                        password,
                        changed_at: ctx.now_ms,
                    });
                }
            }
            None => {
                s.item_fields.push(ItemField {
                    id: new_id(ctx)?,
                    item_id: item_id.to_string(),
                    name: inp.name.clone(),
                    kind: inp.kind.clone(),
                    value: inp.value.clone(),
                    is_secret: inp.is_secret,
                    sort_order: order,
                    updated_at: ctx.now_ms,
                    updated_by: ctx.device_id.to_string(),
                    deleted_at: None,
                });
                changed = true;
            }
        }
    }
    for f in s
        .item_fields
        .iter_mut()
        .filter(|f| existing.contains(&f.id) && !seen.contains(f.id.as_str()))
    {
        let t = bump(f.updated_at, ctx.now_ms);
        f.value.zeroize();
        f.value.clear();
        f.deleted_at = Some(t);
        f.updated_at = t;
        f.updated_by = ctx.device_id.to_string();
        changed = true;
    }
    Ok(changed)
}

/// Make the live note blocks of `item_id` equal to `inputs`. Returns whether anything changed.
fn sync_blocks(
    s: &mut Snapshot,
    ctx: &WriteCtx<'_>,
    item_id: &str,
    inputs: &[BlockInput],
) -> Result<bool> {
    let existing: Vec<String> = live_block_idx(s, item_id)
        .into_iter()
        .filter_map(|i| s.note_blocks.get(i).map(|b| b.id.clone()))
        .collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut changed = false;
    for (idx, inp) in inputs.iter().enumerate() {
        let position = i64::try_from(idx).map_err(|_| Error::InvalidInput)?;
        match (inp.kind, &inp.image_id) {
            (BlockKind::Image, None)
            | (BlockKind::RichText | BlockKind::Code | BlockKind::Table, Some(_)) => {
                return Err(Error::InvalidInput)
            }
            (BlockKind::Image, Some(img)) if !s.note_images.iter().any(|i| &i.id == img) => {
                return Err(Error::NotFound)
            }
            _ => {}
        }
        let language = resolved_language(inp);
        match inp.id.as_deref() {
            Some(id) => {
                if !existing.iter().any(|e| e == id) {
                    return Err(Error::NotFound);
                }
                if !seen.insert(id) {
                    return Err(Error::InvalidInput);
                }
                let b = s
                    .note_blocks
                    .iter_mut()
                    .find(|b| b.id == id)
                    .ok_or(Error::NotFound)?;
                let same = b.position == position
                    && b.kind == inp.kind
                    && b.language == language
                    && b.content == inp.content
                    && b.image_id == inp.image_id;
                if !same {
                    b.position = position;
                    b.kind = inp.kind;
                    b.language = language;
                    b.content.zeroize();
                    b.content.clone_from(&inp.content);
                    b.image_id.clone_from(&inp.image_id);
                    b.updated_at = bump(b.updated_at, ctx.now_ms);
                    b.updated_by = ctx.device_id.to_string();
                    changed = true;
                }
            }
            None => {
                s.note_blocks.push(NoteBlock {
                    id: new_id(ctx)?,
                    item_id: item_id.to_string(),
                    position,
                    kind: inp.kind,
                    language,
                    content: inp.content.clone(),
                    image_id: inp.image_id.clone(),
                    updated_at: ctx.now_ms,
                    updated_by: ctx.device_id.to_string(),
                    deleted_at: None,
                });
                changed = true;
            }
        }
    }
    for b in s
        .note_blocks
        .iter_mut()
        .filter(|b| existing.contains(&b.id) && !seen.contains(b.id.as_str()))
    {
        let t = bump(b.updated_at, ctx.now_ms);
        b.content.zeroize();
        b.content.clear();
        b.deleted_at = Some(t);
        b.updated_at = t;
        b.updated_by = ctx.device_id.to_string();
        changed = true;
    }
    Ok(changed)
}

/// Apply auto-tagger suggestions to an item.
fn apply_auto_tags(s: &mut Snapshot, ctx: &WriteCtx<'_>, item_id: &str) -> Result<()> {
    let item = live_item(s, item_id).map(|i| i.clone())?;
    let kinds: Vec<String> = live_field_idx(s, item_id)
        .into_iter()
        .filter_map(|i| s.item_fields.get(i).map(|f| f.kind.clone()))
        .collect();
    let kinds: Vec<&str> = kinds.iter().map(String::as_str).collect();
    for sug in suggest_tags(
        &item.title,
        item.url.as_deref(),
        item.item_type.as_str(),
        &kinds,
    ) {
        let tag_id = match live_tag_by_name(s, sug.name) {
            Some(t) => t.id.clone(),
            None => {
                if s.tags.iter().any(|t| t.name == sug.name) {
                    continue; // the user deleted this tag; do not resurrect it
                }
                let id = new_id(ctx)?;
                s.tags.push(Tag {
                    id: id.clone(),
                    name: sug.name.to_string(),
                    color: sug.color.to_string(),
                    created_at: ctx.now_ms,
                    updated_at: ctx.now_ms,
                    updated_by: ctx.device_id.to_string(),
                    deleted_at: None,
                });
                id
            }
        };
        // Existing link (live, or tombstoned = user rejection): leave as is.
        if !s
            .item_tags
            .iter()
            .any(|l| l.item_id == item_id && l.tag_id == tag_id)
        {
            s.item_tags.push(ItemTag {
                item_id: item_id.to_string(),
                tag_id,
                auto: true,
                updated_at: ctx.now_ms,
                updated_by: ctx.device_id.to_string(),
                deleted_at: None,
            });
        }
    }
    Ok(())
}

fn summarize(s: &Snapshot, i: &Item) -> ItemSummary {
    let mut tags: Vec<(&str, &str)> = s
        .item_tags
        .iter()
        .filter(|l| l.item_id == i.id && l.deleted_at.is_none())
        .filter_map(|l| {
            s.tags
                .iter()
                .find(|t| t.id == l.tag_id && t.deleted_at.is_none())
        })
        .map(|t| (t.name.as_str(), t.id.as_str()))
        .collect();
    tags.sort_unstable();
    ItemSummary {
        id: i.id.clone(),
        item_type: i.item_type,
        title: i.title.clone(),
        url: i.url.clone(),
        vault_id: i.vault_id.clone(),
        category_id: i.category_id.clone().filter(|c| {
            s.categories
                .iter()
                .any(|x| &x.id == c && x.deleted_at.is_none())
        }),
        color: i.color.clone(),
        favorite: i.favorite,
        use_count: i.use_count,
        last_used_at: i.last_used_at,
        updated_at: i.updated_at,
        tags: tags.into_iter().map(|(n, _)| n.to_string()).collect(),
        trashed_at: i.trashed_at,
    }
}

impl MemStore {
    /// Empty store (with the default vault).
    pub fn new() -> Self {
        let mut snap = Snapshot::default();
        ensure_live_vault(&mut snap);
        Self { snap }
    }

    /// Adopt a decrypted snapshot (e.g. from [`crate::vault_file::open_vault`]). Rejects
    /// snapshots whose references dangle.
    pub fn from_snapshot(snap: Snapshot) -> Result<Self> {
        check_integrity(&snap)?;
        let mut snap = snap;
        ensure_live_vault(&mut snap);
        Ok(Self { snap })
    }

    /// Run `f` on a working copy; commit it only on success.
    fn tx<R>(
        &mut self,
        ctx: &WriteCtx<'_>,
        f: impl FnOnce(&mut Snapshot) -> Result<R>,
    ) -> Result<R> {
        begin(ctx)?;
        // Large byte payloads are moved, not cloned, into the working copy. Writers validate
        // before they mutate, so an error never leaves a half-applied change behind.
        let images = mem::take(&mut self.snap.note_images);
        let attachments = mem::take(&mut self.snap.attachments);
        let mut work = Snapshot {
            note_images: Vec::new(),
            attachments: Vec::new(),
            ..self.snap.clone()
        };
        work.note_images = images;
        work.attachments = attachments;
        match f(&mut work) {
            Ok(r) => {
                self.snap = work;
                Ok(r)
            }
            Err(e) => {
                self.snap.note_images = mem::take(&mut work.note_images);
                self.snap.attachments = mem::take(&mut work.attachments);
                Err(e)
            }
        }
    }

    /// Whether `item_id` is a live item outside the Trash.
    fn usable(&self, item_id: &str) -> bool {
        self.snap
            .items
            .iter()
            .any(|i| i.id == item_id && i.deleted_at.is_none() && i.trashed_at.is_none())
    }

    fn item(&self, id: &str) -> Result<&Item> {
        self.snap
            .items
            .iter()
            .find(|i| i.id == id && i.deleted_at.is_none())
            .ok_or(Error::NotFound)
    }
}

impl VaultStore for MemStore {
    fn create_item(&mut self, ctx: &WriteCtx<'_>, new: &NewItem) -> Result<String> {
        non_empty(&new.title)?;
        if new.fields.iter().any(|f| f.id.is_some()) || new.blocks.iter().any(|b| b.id.is_some()) {
            return Err(Error::InvalidInput);
        }
        self.tx(ctx, |s| {
            if let Some(c) = &new.category_id {
                require_live_category(s, c)?;
            }
            let vault_id = resolve_vault(s, new.vault_id.as_deref())?;
            let id = new_id(ctx)?;
            s.items.push(Item {
                id: id.clone(),
                vault_id,
                category_id: new.category_id.clone(),
                item_type: new.item_type,
                title: new.title.clone(),
                url: new.url.clone(),
                color: new.color.clone(),
                favorite: new.favorite,
                created_at: ctx.now_ms,
                updated_at: ctx.now_ms,
                updated_by: ctx.device_id.to_string(),
                deleted_at: None,
                trashed_at: None,
                use_count: 0,
                last_used_at: None,
                history: BTreeSet::new(),
            });
            sync_fields(s, ctx, &id, &new.fields)?;
            sync_blocks(s, ctx, &id, &new.blocks)?;
            apply_auto_tags(s, ctx, &id)?;
            Ok(id)
        })
    }

    fn update_item(&mut self, ctx: &WriteCtx<'_>, id: &str, upd: &ItemUpdate) -> Result<()> {
        if let Some(t) = &upd.title {
            non_empty(t)?;
        }
        self.tx(ctx, |s| {
            let cur = active_item(s, id)?.clone();
            if let Some(Some(c)) = &upd.category_id {
                require_live_category(s, c)?;
            }
            if let Some(v) = &upd.vault_id {
                resolve_vault(s, Some(v))?;
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
                Some(f) => sync_fields(s, ctx, id, f)?,
                None => false,
            };
            let blocks_changed = match &upd.blocks {
                Some(b) => sync_blocks(s, ctx, id, b)?,
                None => false,
            };
            if scalars_changed || fields_changed || blocks_changed {
                let it = live_item(s, id)?;
                it.vault_id = vault_id;
                it.title = title;
                it.url = url;
                it.category_id = category_id;
                it.color = color;
                it.favorite = favorite;
                it.updated_at = bump(cur.updated_at, ctx.now_ms);
                it.updated_by = ctx.device_id.to_string();
                apply_auto_tags(s, ctx, id)?;
            }
            Ok(())
        })
    }

    fn delete_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            let t = bump(live_item(s, id)?.updated_at, ctx.now_ms);
            // Children use the same logical time so every table converges on one tombstone time.
            for f in s
                .item_fields
                .iter_mut()
                .filter(|f| f.item_id == id && f.deleted_at.is_none())
            {
                let ft = bump(f.updated_at, t);
                f.value.zeroize();
                f.value.clear();
                f.deleted_at = Some(ft);
                f.updated_at = ft;
                f.updated_by = ctx.device_id.to_string();
            }
            for b in s
                .note_blocks
                .iter_mut()
                .filter(|b| b.item_id == id && b.deleted_at.is_none())
            {
                let bt = bump(b.updated_at, t);
                b.content.zeroize();
                b.content.clear();
                b.deleted_at = Some(bt);
                b.updated_at = bt;
                b.updated_by = ctx.device_id.to_string();
            }
            for l in s
                .item_tags
                .iter_mut()
                .filter(|l| l.item_id == id && l.deleted_at.is_none())
            {
                let lt = t.max(l.updated_at.saturating_add(1));
                l.deleted_at = Some(lt);
                l.updated_at = lt;
                l.updated_by = ctx.device_id.to_string();
            }
            for p in s
                .passkeys
                .iter_mut()
                .filter(|p| p.item_id == id && p.deleted_at.is_none())
            {
                let pt = t.max(p.updated_at.saturating_add(1));
                tombstone_passkey(p, pt, ctx.device_id);
            }
            for a in s
                .attachments
                .iter_mut()
                .filter(|a| a.item_id == id && a.deleted_at.is_none())
            {
                let at = t.max(a.updated_at.saturating_add(1));
                a.data.zeroize();
                a.data.clear();
                a.size = 0;
                a.sha256 = sha256_hex(&[]);
                a.deleted_at = Some(at);
                a.updated_at = at;
                a.updated_by = ctx.device_id.to_string();
            }
            let it = live_item(s, id)?;
            it.deleted_at = Some(t);
            it.trashed_at = None;
            it.updated_at = t;
            it.updated_by = ctx.device_id.to_string();
            Ok(())
        })
    }

    fn trash_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            let it = live_item(s, id)?;
            if it.trashed_at.is_none() {
                let t = bump(it.updated_at, ctx.now_ms);
                it.trashed_at = Some(t);
                it.updated_at = t;
                it.updated_by = ctx.device_id.to_string();
            }
            Ok(())
        })
    }

    fn restore_item(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            let it = live_item(s, id)?;
            if it.trashed_at.is_some() {
                it.trashed_at = None;
                it.updated_at = bump(it.updated_at, ctx.now_ms);
                it.updated_by = ctx.device_id.to_string();
            }
            Ok(())
        })
    }

    fn list_trashed_items(&self) -> Result<Vec<ItemSummary>> {
        let mut out: Vec<ItemSummary> = self
            .snap
            .items
            .iter()
            .filter(|i| i.deleted_at.is_none() && i.trashed_at.is_some())
            .map(|i| summarize(&self.snap, i))
            .collect();
        out.sort_by(|a, b| (b.trashed_at, &a.id).cmp(&(a.trashed_at, &b.id)));
        Ok(out)
    }

    fn list_vaults(&self) -> Result<Vec<VaultMeta>> {
        Ok(live_vaults(&self.snap).into_iter().cloned().collect())
    }

    fn create_vault(
        &mut self,
        ctx: &WriteCtx<'_>,
        name: &str,
        color: &str,
        badge: Option<&str>,
    ) -> Result<VaultMeta> {
        let name = clean_vault_name(name)?;
        check_vault_color(color)?;
        let badge = badge.map(clean_vault_badge).transpose()?.flatten();
        self.tx(ctx, |s| {
            if live_vaults(s).len() >= MAX_VAULTS || vault_name_taken(s, &name, None) {
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
            s.vault_meta.push(v.clone());
            Ok(v)
        })
    }

    fn update_vault(
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
        self.tx(ctx, |s| {
            if let Some(n) = &name {
                if vault_name_taken(s, n, Some(id)) {
                    return Err(Error::InvalidInput);
                }
            }
            let v = s
                .vault_meta
                .iter_mut()
                .find(|v| v.id == id && v.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            let changed = name.as_ref().is_some_and(|n| *n != v.name)
                || upd.color.as_ref().is_some_and(|c| *c != v.color)
                || badge.as_ref().is_some_and(|b| *b != v.badge);
            if changed {
                if let Some(n) = name {
                    v.name = n;
                }
                if let Some(c) = &upd.color {
                    v.color = c.clone();
                }
                if let Some(b) = badge {
                    v.badge = b;
                }
                v.updated_at = bump(v.updated_at, ctx.now_ms);
                v.updated_by = ctx.device_id.to_string();
            }
            Ok(v.clone())
        })
    }

    fn delete_vault(&mut self, ctx: &WriteCtx<'_>, id: &str, move_items_to: &str) -> Result<()> {
        if id == move_items_to {
            return Err(Error::InvalidInput);
        }
        self.tx(ctx, |s| {
            if !vault_is_live(s, id) || !vault_is_live(s, move_items_to) {
                return Err(Error::NotFound);
            }
            for it in s
                .items
                .iter_mut()
                .filter(|i| i.vault_id == id && i.deleted_at.is_none())
            {
                it.vault_id = move_items_to.to_string();
                it.updated_at = bump(it.updated_at, ctx.now_ms);
                it.updated_by = ctx.device_id.to_string();
            }
            let v = s
                .vault_meta
                .iter_mut()
                .find(|v| v.id == id)
                .ok_or(Error::NotFound)?;
            let t = bump(v.updated_at, ctx.now_ms);
            v.deleted_at = Some(t);
            v.updated_at = t;
            v.updated_by = ctx.device_id.to_string();
            Ok(())
        })
    }

    fn ensure_default_vault(&mut self, ctx: &WriteCtx<'_>) -> Result<()> {
        self.tx(ctx, |s| {
            if !s.vault_meta.iter().any(|v| v.id == DEFAULT_VAULT_ID) {
                s.vault_meta.push(VaultMeta {
                    id: DEFAULT_VAULT_ID.to_string(),
                    name: "Personal".to_string(),
                    color: "#2563EB".to_string(),
                    badge: None,
                    created_at: 0,
                    updated_at: 0,
                    updated_by: String::new(),
                    deleted_at: None,
                });
            }
            Ok(())
        })
    }

    fn record_use(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            let it = active_item(s, id)?;
            it.use_count = it.use_count.saturating_add(1);
            it.last_used_at = Some(it.last_used_at.unwrap_or(0).max(ctx.now_ms));
            Ok(())
        })
    }

    fn list_items(&self) -> Result<Vec<ItemSummary>> {
        let mut out: Vec<ItemSummary> = self
            .snap
            .items
            .iter()
            .filter(|i| i.deleted_at.is_none() && i.trashed_at.is_none())
            .map(|i| summarize(&self.snap, i))
            .collect();
        // Same order as the SQL backend: `COLLATE NOCASE` folds ASCII only.
        out.sort_by(|a, b| {
            (a.title.to_ascii_lowercase(), &a.id).cmp(&(b.title.to_ascii_lowercase(), &b.id))
        });
        Ok(out)
    }

    fn get_item(&self, id: &str) -> Result<ItemDetail> {
        let summary = summarize(&self.snap, self.item(id)?);
        let fields = live_field_idx(&self.snap, id)
            .into_iter()
            .filter_map(|i| self.snap.item_fields.get(i))
            .map(|f| FieldView {
                id: f.id.clone(),
                name: f.name.clone(),
                kind: f.kind.clone(),
                is_secret: f.is_secret,
                value: (!f.is_secret).then(|| f.value.clone()),
            })
            .collect();
        let blocks = live_block_idx(&self.snap, id)
            .into_iter()
            .filter_map(|i| self.snap.note_blocks.get(i))
            .map(|b| NoteBlock {
                id: b.id.clone(),
                item_id: id.to_string(),
                position: b.position,
                kind: b.kind,
                language: b.language.clone(),
                content: b.content.clone(),
                image_id: b.image_id.clone(),
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

    fn reveal_field(&self, item_id: &str, field_id: &str) -> Result<Zeroizing<String>> {
        self.item(item_id)?;
        self.snap
            .item_fields
            .iter()
            .find(|f| f.id == field_id && f.item_id == item_id && f.deleted_at.is_none())
            .map(|f| Zeroizing::new(f.value.clone()))
            .ok_or(Error::NotFound)
    }

    fn reveal_password_history(&self, item_id: &str) -> Result<Vec<HistoryEntry>> {
        let mut v: Vec<HistoryEntry> = self
            .snap
            .items
            .iter()
            .find(|i| i.id == item_id)
            .map(|i| i.history.iter().cloned().collect())
            .unwrap_or_default();
        v.sort_by(|a, b| (b.changed_at, &b.id).cmp(&(a.changed_at, &a.id)));
        Ok(v)
    }

    fn create_tag(&mut self, ctx: &WriteCtx<'_>, name: &str, color: &str) -> Result<Tag> {
        non_empty(name)?;
        self.tx(ctx, |s| {
            if let Some(t) = live_tag_by_name(s, name) {
                return Ok(t.clone());
            }
            let tag = Tag {
                id: new_id(ctx)?,
                name: name.to_string(),
                color: color.to_string(),
                created_at: ctx.now_ms,
                updated_at: ctx.now_ms,
                updated_by: ctx.device_id.to_string(),
                deleted_at: None,
            };
            s.tags.push(tag.clone());
            Ok(tag)
        })
    }

    fn list_tags(&self) -> Result<Vec<Tag>> {
        let mut v: Vec<Tag> = self
            .snap
            .tags
            .iter()
            .filter(|t| t.deleted_at.is_none())
            .cloned()
            .collect();
        v.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        Ok(v)
    }

    fn update_tag(
        &mut self,
        ctx: &WriteCtx<'_>,
        tag_id: &str,
        name: Option<&str>,
        color: Option<&str>,
    ) -> Result<Tag> {
        if let Some(n) = name {
            non_empty(n)?;
        }
        self.tx(ctx, |s| {
            if let Some(n) = name {
                if s.tags
                    .iter()
                    .any(|t| t.id != tag_id && t.deleted_at.is_none() && t.name == n)
                {
                    return Err(Error::InvalidInput);
                }
            }
            let tag = s
                .tags
                .iter_mut()
                .find(|t| t.id == tag_id && t.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            if let Some(n) = name {
                tag.name = n.to_string();
            }
            if let Some(c) = color {
                tag.color = c.to_string();
            }
            tag.updated_at = bump(tag.updated_at, ctx.now_ms);
            tag.updated_by = ctx.device_id.to_string();
            Ok(tag.clone())
        })
    }

    fn delete_tag(&mut self, ctx: &WriteCtx<'_>, tag_id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            let tag = s
                .tags
                .iter_mut()
                .find(|t| t.id == tag_id && t.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            let t = bump(tag.updated_at, ctx.now_ms);
            tag.deleted_at = Some(t);
            tag.updated_at = t;
            tag.updated_by = ctx.device_id.to_string();
            for l in s
                .item_tags
                .iter_mut()
                .filter(|l| l.tag_id == tag_id && l.deleted_at.is_none())
            {
                let lt = t.max(l.updated_at.saturating_add(1));
                l.deleted_at = Some(lt);
                l.updated_at = lt;
                l.updated_by = ctx.device_id.to_string();
            }
            Ok(())
        })
    }

    fn add_tag(&mut self, ctx: &WriteCtx<'_>, item_id: &str, tag_id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            live_item(s, item_id)?;
            if !s
                .tags
                .iter()
                .any(|t| t.id == tag_id && t.deleted_at.is_none())
            {
                return Err(Error::NotFound);
            }
            match s
                .item_tags
                .iter_mut()
                .find(|l| l.item_id == item_id && l.tag_id == tag_id)
            {
                Some(l) => {
                    l.auto = false;
                    l.deleted_at = None;
                    l.updated_at = bump(l.updated_at, ctx.now_ms);
                    l.updated_by = ctx.device_id.to_string();
                }
                None => s.item_tags.push(ItemTag {
                    item_id: item_id.to_string(),
                    tag_id: tag_id.to_string(),
                    auto: false,
                    updated_at: ctx.now_ms,
                    updated_by: ctx.device_id.to_string(),
                    deleted_at: None,
                }),
            }
            Ok(())
        })
    }

    fn remove_tag(&mut self, ctx: &WriteCtx<'_>, item_id: &str, tag_id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            let l = s
                .item_tags
                .iter_mut()
                .find(|l| l.item_id == item_id && l.tag_id == tag_id && l.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            let t = bump(l.updated_at, ctx.now_ms);
            l.deleted_at = Some(t);
            l.updated_at = t;
            l.updated_by = ctx.device_id.to_string();
            Ok(())
        })
    }

    fn create_category(&mut self, ctx: &WriteCtx<'_>, new: &NewCategory) -> Result<Category> {
        non_empty(&new.name)?;
        if new.fields.iter().any(|f| f.id.is_some()) {
            return Err(Error::InvalidInput);
        }
        self.tx(ctx, |s| {
            let sort_order = s
                .categories
                .iter()
                .filter(|c| c.deleted_at.is_none())
                .map(|c| c.sort_order.saturating_add(1))
                .max()
                .unwrap_or(0);
            let c = Category {
                id: new_id(ctx)?,
                name: new.name.clone(),
                color: new.color.clone(),
                icon: new.icon.clone(),
                icon_color: new.icon_color.clone(),
                preset: None,
                sort_order,
                created_at: ctx.now_ms,
                updated_at: ctx.now_ms,
                updated_by: ctx.device_id.to_string(),
                deleted_at: None,
            };
            let planned = plan_field_update(ctx, &c.id, &[], &new.fields)?;
            s.categories.push(c.clone());
            upsert_category_fields(s, planned);
            Ok(c)
        })
    }

    fn update_category(
        &mut self,
        ctx: &WriteCtx<'_>,
        id: &str,
        upd: &CategoryUpdate,
    ) -> Result<()> {
        if let Some(n) = &upd.name {
            non_empty(n)?;
        }
        self.tx(ctx, |s| {
            let c = s
                .categories
                .iter_mut()
                .find(|c| c.id == id && c.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            let name = upd.name.clone().unwrap_or_else(|| c.name.clone());
            let color = upd.color.clone().unwrap_or_else(|| c.color.clone());
            let icon = upd.icon.clone().unwrap_or_else(|| c.icon.clone());
            let icon_color = upd
                .icon_color
                .clone()
                .unwrap_or_else(|| c.icon_color.clone());
            let cat_id = c.id.clone();
            if let Some(inputs) = &upd.fields {
                let existing: Vec<CategoryField> = s
                    .category_fields
                    .iter()
                    .filter(|f| f.category_id == cat_id)
                    .cloned()
                    .collect();
                let planned = plan_field_update(ctx, &cat_id, &existing, inputs)?;
                upsert_category_fields(s, planned);
            }
            let c = s
                .categories
                .iter_mut()
                .find(|c| c.id == id && c.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            if (&name, &color, &icon, &icon_color) != (&c.name, &c.color, &c.icon, &c.icon_color) {
                c.name = name;
                c.color = color;
                c.icon = icon;
                c.icon_color = icon_color;
                c.updated_at = bump(c.updated_at, ctx.now_ms);
                c.updated_by = ctx.device_id.to_string();
            }
            Ok(())
        })
    }

    fn reorder_categories(&mut self, ctx: &WriteCtx<'_>, ordered_ids: &[String]) -> Result<()> {
        self.tx(ctx, |s| {
            for (idx, id) in ordered_ids.iter().enumerate() {
                let order = i64::try_from(idx).map_err(|_| Error::InvalidInput)?;
                let c = s
                    .categories
                    .iter_mut()
                    .find(|c| &c.id == id && c.deleted_at.is_none())
                    .ok_or(Error::NotFound)?;
                if c.sort_order != order {
                    c.sort_order = order;
                    c.updated_at = bump(c.updated_at, ctx.now_ms);
                    c.updated_by = ctx.device_id.to_string();
                }
            }
            Ok(())
        })
    }

    fn delete_category(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            let c = s
                .categories
                .iter_mut()
                .find(|c| c.id == id && c.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            let t = bump(c.updated_at, ctx.now_ms);
            c.deleted_at = Some(t);
            c.updated_at = t;
            c.updated_by = ctx.device_id.to_string();
            Ok(())
        })
    }

    fn list_categories(&self) -> Result<Vec<Category>> {
        let mut v: Vec<Category> = self
            .snap
            .categories
            .iter()
            .filter(|c| c.deleted_at.is_none())
            .cloned()
            .collect();
        v.sort_by(|a, b| (a.sort_order, &a.id).cmp(&(b.sort_order, &b.id)));
        Ok(v)
    }

    fn list_category_fields(&self, category_id: &str) -> Result<Vec<CategoryField>> {
        require_live_category(&self.snap, category_id)?;
        let mut v: Vec<CategoryField> = self
            .snap
            .category_fields
            .iter()
            .filter(|f| f.category_id == category_id && f.deleted_at.is_none())
            .cloned()
            .collect();
        v.sort_by(|a, b| (a.sort_order, &a.id).cmp(&(b.sort_order, &b.id)));
        Ok(v)
    }

    fn seed_default_categories(&mut self, ctx: &WriteCtx<'_>) -> Result<()> {
        self.tx(ctx, |s| {
            let first = s
                .categories
                .iter()
                .filter(|c| c.deleted_at.is_none())
                .map(|c| c.sort_order.saturating_add(1))
                .max()
                .unwrap_or(0);
            let (cats, fields) = seed_records(ctx, &s.categories, &s.category_fields, first);
            s.categories.extend(cats);
            upsert_category_fields(s, fields);
            // A fresh in-memory store has no default vault yet (SQLCipher gets it from the migration).
            if !s.vault_meta.iter().any(|v| v.id == DEFAULT_VAULT_ID) {
                s.vault_meta.push(VaultMeta {
                    id: DEFAULT_VAULT_ID.to_string(),
                    name: "Personal".to_string(),
                    color: "#2563EB".to_string(),
                    badge: None,
                    created_at: 0,
                    updated_at: 0,
                    updated_by: String::new(),
                    deleted_at: None,
                });
            }
            Ok(())
        })
    }

    fn add_note_image(
        &mut self,
        ctx: &WriteCtx<'_>,
        mime_type: &str,
        data: &[u8],
    ) -> Result<String> {
        non_empty(mime_type)?;
        if data.is_empty() {
            return Err(Error::InvalidInput);
        }
        self.tx(ctx, |s| {
            let id = new_id(ctx)?;
            s.note_images.push(NoteImage {
                id: id.clone(),
                mime_type: mime_type.to_string(),
                sha256: sha256_hex(data),
                size: data.len() as u64,
                data: data.to_vec(),
                created_at: ctx.now_ms,
            });
            Ok(id)
        })
    }

    fn note_image(&self, id: &str) -> Result<(String, Zeroizing<Vec<u8>>)> {
        self.snap
            .note_images
            .iter()
            .find(|i| i.id == id)
            .map(|i| (i.mime_type.clone(), Zeroizing::new(i.data.clone())))
            .ok_or(Error::NotFound)
    }

    fn add_attachment(
        &mut self,
        ctx: &WriteCtx<'_>,
        item_id: &str,
        file_name: &str,
        mime_type: &str,
        data: &[u8],
    ) -> Result<String> {
        let name = sanitize_file_name(file_name)?;
        check_mime_type(mime_type)?;
        self.tx(ctx, |s| {
            live_item(s, item_id)?;
            let live_total: u64 = s
                .attachments
                .iter()
                .filter(|a| a.deleted_at.is_none())
                .map(|a| a.size)
                .sum();
            check_attachment_size(data.len(), live_total)?;
            let id = new_id(ctx)?;
            s.attachments.push(Attachment {
                id: id.clone(),
                item_id: item_id.to_string(),
                file_name: name,
                mime_type: mime_type.to_string(),
                sha256: sha256_hex(data),
                size: data.len() as u64,
                data: data.to_vec(),
                created_at: ctx.now_ms,
                updated_at: ctx.now_ms,
                updated_by: ctx.device_id.to_string(),
                deleted_at: None,
            });
            Ok(id)
        })
    }

    fn list_attachments(&self, item_id: &str) -> Result<Vec<AttachmentInfo>> {
        self.item(item_id)?;
        let mut out: Vec<AttachmentInfo> = self
            .snap
            .attachments
            .iter()
            .filter(|a| a.item_id == item_id && a.deleted_at.is_none())
            .map(attachment_info)
            .collect();
        out.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(out)
    }

    fn read_attachment(&self, id: &str) -> Result<(AttachmentInfo, Zeroizing<Vec<u8>>)> {
        let a = self
            .snap
            .attachments
            .iter()
            .find(|a| a.id == id && a.deleted_at.is_none())
            .ok_or(Error::NotFound)?;
        self.item(&a.item_id)?;
        Ok((attachment_info(a), Zeroizing::new(a.data.clone())))
    }

    fn rename_attachment(&mut self, ctx: &WriteCtx<'_>, id: &str, file_name: &str) -> Result<()> {
        let name = sanitize_file_name(file_name)?;
        self.tx(ctx, |s| {
            let a = s
                .attachments
                .iter_mut()
                .find(|a| a.id == id && a.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            a.file_name = name;
            a.updated_at = bump(a.updated_at, ctx.now_ms);
            a.updated_by = ctx.device_id.to_string();
            Ok(())
        })
    }

    fn delete_attachment(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            let a = s
                .attachments
                .iter_mut()
                .find(|a| a.id == id && a.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            let t = bump(a.updated_at, ctx.now_ms);
            a.data.zeroize();
            a.data.clear();
            a.size = 0;
            a.sha256 = sha256_hex(&[]);
            a.deleted_at = Some(t);
            a.updated_at = t;
            a.updated_by = ctx.device_id.to_string();
            Ok(())
        })
    }

    fn add_passkey(
        &mut self,
        ctx: &WriteCtx<'_>,
        item_id: &str,
        new: &NewPasskey,
    ) -> Result<String> {
        self.tx(ctx, |s| {
            active_item(s, item_id)?;
            // WebAuthn: a new credential for the same account replaces the old one.
            for p in s.passkeys.iter_mut().filter(|p| {
                p.deleted_at.is_none() && p.rp_id == new.rp_id && p.user_handle == new.user_handle
            }) {
                let t = ctx.now_ms.max(p.updated_at.saturating_add(1));
                tombstone_passkey(p, t, ctx.device_id);
            }
            let id = new_id(ctx)?;
            s.passkeys.push(Passkey {
                id: id.clone(),
                item_id: item_id.to_string(),
                credential_id: new.credential_id.clone(),
                rp_id: new.rp_id.clone(),
                user_name: new.user_name.clone(),
                user_handle: new.user_handle.clone(),
                private_key: new.private_key.to_vec(),
                created_at: ctx.now_ms,
                updated_at: ctx.now_ms,
                updated_by: ctx.device_id.to_string(),
                deleted_at: None,
            });
            Ok(id)
        })
    }

    fn list_passkeys(&self, item_id: &str) -> Result<Vec<PasskeyInfo>> {
        self.item(item_id)?;
        let mut out: Vec<PasskeyInfo> = self
            .snap
            .passkeys
            .iter()
            .filter(|p| p.item_id == item_id && p.deleted_at.is_none())
            .map(passkey_info)
            .collect();
        out.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(out)
    }

    fn passkeys_for_rp(&self, rp_id: &str) -> Result<Vec<PasskeyInfo>> {
        let Ok(rp_id) = crate::passkey::normalize_rp_id(rp_id) else {
            return Ok(Vec::new());
        };
        let mut out: Vec<PasskeyInfo> = self
            .snap
            .passkeys
            .iter()
            .filter(|p| p.rp_id == rp_id && p.deleted_at.is_none() && self.usable(&p.item_id))
            .map(passkey_info)
            .collect();
        out.sort_by(|a, b| (b.created_at, &b.id).cmp(&(a.created_at, &a.id)));
        Ok(out)
    }

    fn passkey_secret(&self, id: &str) -> Result<(PasskeyInfo, Zeroizing<Vec<u8>>)> {
        let p = self
            .snap
            .passkeys
            .iter()
            .find(|p| p.id == id && p.deleted_at.is_none() && self.usable(&p.item_id))
            .ok_or(Error::NotFound)?;
        Ok((passkey_info(p), Zeroizing::new(p.private_key.clone())))
    }

    fn delete_passkey(&mut self, ctx: &WriteCtx<'_>, id: &str) -> Result<()> {
        self.tx(ctx, |s| {
            let p = s
                .passkeys
                .iter_mut()
                .find(|p| p.id == id && p.deleted_at.is_none())
                .ok_or(Error::NotFound)?;
            let t = bump(p.updated_at, ctx.now_ms);
            tombstone_passkey(p, t, ctx.device_id);
            Ok(())
        })
    }

    fn snapshot(&self) -> Result<Snapshot> {
        Ok(self.snap.clone())
    }

    fn merge_remote(&mut self, remote: &Snapshot) -> Result<()> {
        let merged = merge(&self.snap, remote);
        check_integrity(&merged)?;
        self.snap = merged;
        Ok(())
    }
}
