//! Enpass JSON export (`Export > JSON`) parser.
//!
//! Mapping: `login`/`password` -> credential, `creditcard` -> card, `identity` -> identity,
//! `travel` -> travel, `note` -> note; any other Enpass category becomes a credential that keeps
//! all its fields. Items in the Enpass trash are skipped. Enpass folders become tags. Original
//! timestamps are not preserved (the vault stamps imported items with the import time).

use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;
use zeroize::Zeroize;

use super::{ImportItem, ImportPreview, MAX_IMPORT_BYTES};
use crate::error::{Error, Result};
use crate::models::{InputKind, ItemType};
use crate::ops::FieldInput;

/// A 0/1 integer or boolean flag.
#[derive(Clone, Copy, Debug, Default)]
struct Flag(bool);

impl<'de> Deserialize<'de> for Flag {
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Flag;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a boolean or integer flag")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> core::result::Result<Flag, E> {
                Ok(Flag(v))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> core::result::Result<Flag, E> {
                Ok(Flag(v != 0))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> core::result::Result<Flag, E> {
                Ok(Flag(v != 0))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Deserialize, Default)]
struct Export {
    #[serde(default)]
    folders: Vec<RawFolder>,
    #[serde(default)]
    items: Vec<RawItem>,
}

#[derive(Deserialize, Default)]
struct RawFolder {
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    title: String,
}

#[derive(Deserialize, Default)]
struct RawItem {
    #[serde(default)]
    category: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    subtitle: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    favorite: Flag,
    #[serde(default)]
    trashed: Flag,
    #[serde(default)]
    folders: Vec<String>,
    #[serde(default)]
    fields: Vec<RawField>,
}

impl Drop for RawItem {
    fn drop(&mut self) {
        self.note.zeroize();
    }
}

#[derive(Deserialize, Default)]
struct RawField {
    #[serde(default)]
    label: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    sensitive: Flag,
    #[serde(default)]
    deleted: Flag,
    #[serde(default)]
    history: Vec<RawHistory>,
}

impl Drop for RawField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Deserialize, Default)]
struct RawHistory {
    #[serde(default)]
    value: String,
    #[serde(default)]
    updated_at: i64,
}

impl Drop for RawHistory {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Parse an Enpass JSON export. Nothing is written; the result feeds [`super::import_items`].
pub fn parse_json(bytes: &[u8]) -> Result<ImportPreview> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(Error::InvalidInput);
    }
    let mut export: Export = serde_json::from_slice(bytes).map_err(|_| Error::Corrupted)?;
    let mut preview = ImportPreview::default();
    let raw_items = core::mem::take(&mut export.items);
    for mut raw in raw_items {
        if raw.trashed.0 {
            preview.skipped_trashed += 1;
            continue;
        }
        match convert(&mut raw, &export.folders) {
            Some(item) => preview.items.push(item),
            None => preview.skipped_invalid += 1,
        }
    }
    Ok(preview)
}

fn category(raw: &str) -> (ItemType, &'static str) {
    match raw {
        "creditcard" => (ItemType::Card, "card"),
        "identity" => (ItemType::Identity, "identity"),
        "travel" => (ItemType::Travel, "travel"),
        "note" => (ItemType::Note, "note"),
        _ => (ItemType::Credential, "credential"),
    }
}

fn input_kind(enpass_type: &str, sensitive: bool) -> InputKind {
    match enpass_type {
        "password" => InputKind::Password,
        "totp" => InputKind::Totp,
        "email" => InputKind::Email,
        "url" => InputKind::Url,
        "phone" => InputKind::Phone,
        "date" => InputKind::Date,
        "numeric" => InputKind::Number,
        "pin" | "ccPin" => InputKind::Pin,
        "ccNumber" => InputKind::CardNumber,
        "ccExpiry" => InputKind::Expiry,
        "ccCvc" => InputKind::Cvv,
        "multiline" if sensitive => InputKind::SecureNote,
        _ => InputKind::Text,
    }
}

fn convert(raw: &mut RawItem, folders: &[RawFolder]) -> Option<ImportItem> {
    let (item_type, preset_key) = category(&raw.category);

    let mut url: Option<String> = None;
    let mut fields: Vec<FieldInput> = Vec::new();
    let mut password_history: Vec<String> = Vec::new();

    let raw_fields = core::mem::take(&mut raw.fields);
    for f in raw_fields {
        if f.deleted.0 || f.kind == "section" || f.value.trim().is_empty() {
            continue;
        }
        let kind = input_kind(&f.kind, f.sensitive.0);
        if kind == InputKind::Url && url.is_none() {
            url = Some(f.value.trim().to_string());
            continue;
        }
        if kind == InputKind::Password && password_history.is_empty() {
            let mut hist: Vec<(i64, String)> = f
                .history
                .iter()
                .filter(|h| !h.value.is_empty())
                .map(|h| (h.updated_at, h.value.clone()))
                .collect();
            hist.sort_by_key(|(t, _)| *t);
            password_history = hist.into_iter().map(|(_, v)| v).collect();
        }
        let name = if f.label.trim().is_empty() {
            f.kind.as_str()
        } else {
            f.label.as_str()
        };
        let secret = f.sensitive.0 || kind.secret_by_default();
        fields.push(FieldInput::new(name, kind.as_str(), &f.value, secret));
    }

    let title = [raw.title.trim(), raw.subtitle.trim()]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or("Untitled")
        .to_string();

    let note = core::mem::take(&mut raw.note);
    let has_content = !fields.is_empty() || !note.trim().is_empty() || url.is_some();
    if !has_content && raw.title.trim().is_empty() {
        return None;
    }

    let mut tags: Vec<String> = Vec::new();
    for id in &raw.folders {
        if let Some(name) = folders
            .iter()
            .find(|f| &f.uuid == id)
            .map(|f| f.title.trim())
            .filter(|n| !n.is_empty())
        {
            if !tags.iter().any(|t| t.eq_ignore_ascii_case(name)) {
                tags.push(name.to_string());
            }
        }
    }

    Some(ImportItem {
        item_type,
        preset_key: preset_key.to_string(),
        title,
        url,
        favorite: raw.favorite.0,
        fields,
        note,
        tags,
        password_history,
    })
}
