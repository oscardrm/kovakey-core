//! Importers for other password managers (ADR 0005). Parsing and mapping live here so every UI
//! shares them; UIs only pick a file, show the [`ImportPreview`] and call [`import_items`].
//!
//! Supported today: Enpass JSON ([`enpass::parse_json`]). Values are never logged: every type
//! holding imported secrets redacts its `Debug` output and is wiped on drop.

pub mod enpass;
pub mod kovakey;

use std::collections::HashSet;
use std::fmt;

use zeroize::Zeroize;

use crate::error::Result;
use crate::models::{BlockKind, ItemType};
use crate::ops::{BlockInput, FieldInput, ItemUpdate, NewItem, VaultStore, WriteCtx};

/// Largest input accepted (bytes). Bigger files are rejected before parsing.
pub const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;

/// Tag color for tags created from imported folders.
const IMPORT_TAG_COLOR: &str = "#64748B";

/// One item ready to be written to the vault.
#[derive(Clone)]
pub struct ImportItem {
    /// Item type.
    pub item_type: ItemType,
    /// Key of the built-in preset category to file the item under (e.g. `credential`).
    pub preset_key: String,
    /// Title (never empty).
    pub title: String,
    /// Main URL.
    pub url: Option<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Fields in display order (empty values already dropped).
    pub fields: Vec<FieldInput>,
    /// Free-text note, if any.
    pub note: String,
    /// Names of tags to assign (created when missing).
    pub tags: Vec<String>,
    /// Previous values of the main password, oldest first (excludes the current value).
    pub password_history: Vec<String>,
}

impl fmt::Debug for ImportItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportItem")
            .field("item_type", &self.item_type)
            .field("title", &self.title)
            .field("fields", &self.fields.len())
            .field("note", &"<redacted>")
            .field("password_history", &self.password_history.len())
            .finish()
    }
}

impl Drop for ImportItem {
    fn drop(&mut self) {
        self.note.zeroize();
        for p in &mut self.password_history {
            p.zeroize();
        }
    }
}

impl ImportItem {
    /// Identity used to detect duplicates: lower-cased title, URL and first plain
    /// username / e-mail value. Secrets are never part of it.
    pub fn duplicate_key(&self) -> DuplicateKey {
        let user = self
            .fields
            .iter()
            .find(|f| !f.is_secret && (f.kind == "text" || f.kind == "email"))
            .map(|f| f.value.as_str());
        DuplicateKey::new(&self.title, self.url.as_deref(), user)
    }
}

/// Normalized `(title, url, username)` triple. See [`ImportItem::duplicate_key`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DuplicateKey(String, String, String);

impl DuplicateKey {
    fn new(title: &str, url: Option<&str>, user: Option<&str>) -> Self {
        let n = |s: &str| s.trim().to_lowercase();
        Self(n(title), n(url.unwrap_or("")), n(user.unwrap_or("")))
    }
}

/// Result of parsing a file: nothing has been written yet.
#[derive(Debug, Default)]
pub struct ImportPreview {
    /// Items that can be imported.
    pub items: Vec<ImportItem>,
    /// Entries skipped because they were in the source app's trash.
    pub skipped_trashed: u32,
    /// Entries skipped because they had no usable content.
    pub skipped_invalid: u32,
}

/// Outcome of [`import_items`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Items written.
    pub imported: u32,
    /// Items skipped because the vault (or the file itself) already had the same one.
    pub skipped_duplicates: u32,
    /// Items that failed to write.
    pub failed: u32,
    /// Tags created.
    pub tags_created: u32,
}

/// Indices (into `items`) of items that already exist in the vault or repeat an earlier entry.
pub fn find_duplicates<S: VaultStore>(store: &S, items: &[ImportItem]) -> Result<Vec<usize>> {
    let mut seen = existing_keys(store)?;
    let mut dup = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if !seen.insert(item.duplicate_key()) {
            dup.push(i);
        }
    }
    Ok(dup)
}

fn existing_keys<S: VaultStore>(store: &S) -> Result<HashSet<DuplicateKey>> {
    let mut keys = HashSet::new();
    for s in store.list_items()? {
        let d = store.get_item(&s.id)?;
        let user = d
            .fields
            .iter()
            .find(|f| !f.is_secret && (f.kind == "text" || f.kind == "email"))
            .and_then(|f| f.value.as_deref());
        keys.insert(DuplicateKey::new(&s.title, s.url.as_deref(), user));
    }
    Ok(keys)
}

/// Write `items` into the vault. With `skip_duplicates`, items matching an existing one (or an
/// earlier item of the list) are left out. A failing item is counted and does not abort the rest.
/// `vault_id` is the vault the items go to (`None` = the default vault).
pub fn import_items<S: VaultStore>(
    store: &mut S,
    ctx: &WriteCtx<'_>,
    items: &[ImportItem],
    skip_duplicates: bool,
    vault_id: Option<&str>,
) -> Result<ImportReport> {
    let mut report = ImportReport::default();
    let mut seen = if skip_duplicates {
        existing_keys(store)?
    } else {
        HashSet::new()
    };
    let categories = store.list_categories()?;
    let mut tags = store.list_tags()?;

    for item in items {
        if skip_duplicates && !seen.insert(item.duplicate_key()) {
            report.skipped_duplicates += 1;
            continue;
        }
        let category_id = categories
            .iter()
            .find(|c| c.preset.as_deref() == Some(item.preset_key.as_str()))
            .map(|c| c.id.clone());
        match write_item(
            store,
            ctx,
            item,
            category_id,
            vault_id,
            &mut tags,
            &mut report,
        ) {
            Ok(()) => report.imported += 1,
            Err(_) => report.failed += 1,
        }
    }
    Ok(report)
}

fn write_item<S: VaultStore>(
    store: &mut S,
    ctx: &WriteCtx<'_>,
    item: &ImportItem,
    category_id: Option<String>,
    vault_id: Option<&str>,
    tags: &mut Vec<crate::models::Tag>,
    report: &mut ImportReport,
) -> Result<()> {
    let mut new = NewItem::new(item.item_type, &item.title);
    new.url = item.url.clone();
    new.category_id = category_id;
    new.vault_id = vault_id.map(str::to_string);
    new.favorite = item.favorite;
    new.fields = item.fields.clone();
    if !item.note.trim().is_empty() {
        new.blocks = vec![BlockInput {
            id: None,
            kind: BlockKind::RichText,
            language: None,
            content: item.note.clone(),
            image_id: None,
        }];
    }

    // Replay the password history: create with the oldest value, then update through the rest so
    // the store records every earlier value as history (oldest first).
    let pw_index = item.fields.iter().position(|f| f.kind == "password");
    let mut chain: Vec<String> = Vec::new();
    if let Some(i) = pw_index {
        chain.extend(item.password_history.iter().cloned());
        if let Some(f) = item.fields.get(i) {
            chain.push(f.value.clone());
        }
        chain.dedup();
        if chain.len() > 1 {
            if let (Some(first), Some(slot)) = (chain.first(), new.fields.get_mut(i)) {
                slot.value = first.clone();
            }
        }
    }

    let id = store.create_item(ctx, &new)?;

    if chain.len() > 1 {
        let detail = store.get_item(&id)?;
        let pw_field = detail.fields.iter().find(|f| f.kind == "password");
        if let Some(pw_field) = pw_field {
            for value in chain.iter().skip(1) {
                let mut fields = Vec::with_capacity(detail.fields.len());
                for f in &detail.fields {
                    if f.id == pw_field.id {
                        fields.push(
                            FieldInput::new(&f.name, &f.kind, value, f.is_secret).with_id(&f.id),
                        );
                    } else {
                        let current = match &f.value {
                            Some(v) => v.clone(),
                            None => store.reveal_field(&id, &f.id)?.to_string(),
                        };
                        fields.push(
                            FieldInput::new(&f.name, &f.kind, &current, f.is_secret).with_id(&f.id),
                        );
                    }
                }
                store.update_item(
                    ctx,
                    &id,
                    &ItemUpdate {
                        fields: Some(fields),
                        ..Default::default()
                    },
                )?;
            }
        }
    }

    for name in &item.tags {
        let tag = match tags.iter().find(|t| t.name.eq_ignore_ascii_case(name)) {
            Some(t) => t.clone(),
            None => {
                let t = store.create_tag(ctx, name, IMPORT_TAG_COLOR)?;
                report.tags_created += 1;
                tags.push(t.clone());
                t
            }
        };
        store.add_tag(ctx, &id, &tag.id)?;
    }
    Ok(())
}
