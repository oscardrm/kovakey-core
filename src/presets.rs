//! Built-in category presets ("Credit Card", "Travel", ...).
//!
//! Presets are **not** a separate kind of thing: seeding turns each into an ordinary, fully
//! editable [`Category`] plus its [`CategoryField`] template. Preset records use deterministic
//! ids (`preset:<key>`, `preset:<key>:<field>`) and `updated_at = 0`, so devices that seed
//! independently converge on the same rows and any later user edit wins the merge. A preset the
//! user deleted stays deleted: seeding skips ids that already exist, tombstones included.

use crate::models::{Category, CategoryField, InputKind};
use crate::ops::WriteCtx;

/// One input of a preset.
pub struct PresetField {
    /// Stable key, used in the deterministic field id.
    pub key: &'static str,
    /// Default (English) display name.
    pub name: &'static str,
    /// Input type.
    pub kind: InputKind,
    /// Core inputs cannot be deleted by the user.
    pub core: bool,
}

/// A built-in category.
pub struct Preset {
    /// Stable key. Matches the legacy item-type storage ids, so the app can map a category to
    /// item behaviour (autofill, auto-tags).
    pub key: &'static str,
    /// Default (English) name.
    pub name: &'static str,
    /// Icon identifier.
    pub icon: &'static str,
    /// Category color.
    pub color: &'static str,
    /// Icon color.
    pub icon_color: &'static str,
    /// Template inputs in display order.
    pub fields: &'static [PresetField],
}

const fn f(key: &'static str, name: &'static str, kind: InputKind, core: bool) -> PresetField {
    PresetField {
        key,
        name,
        kind,
        core,
    }
}

/// All presets, in default display order.
pub const PRESETS: &[Preset] = &[
    Preset {
        key: "credential",
        name: "Login",
        icon: "key",
        color: "#3B82F6",
        icon_color: "#FFFFFF",
        fields: &[
            f("username", "Username", InputKind::Text, true),
            f("password", "Password", InputKind::Password, true),
            f("totp", "One-time code", InputKind::Totp, false),
        ],
    },
    Preset {
        key: "card",
        name: "Credit Card",
        icon: "creditcard",
        color: "#10B981",
        icon_color: "#FFFFFF",
        fields: &[
            f("holder", "Cardholder", InputKind::Text, true),
            f("number", "Card number", InputKind::CardNumber, true),
            f("expiry", "Expiry", InputKind::Expiry, true),
            f("cvv", "CVV", InputKind::Cvv, true),
            f("pin", "PIN", InputKind::Pin, false),
            f("bank", "Bank", InputKind::Text, false),
        ],
    },
    Preset {
        key: "identity",
        name: "Identity",
        icon: "person.text.rectangle",
        color: "#F59E0B",
        icon_color: "#FFFFFF",
        fields: &[
            f("full_name", "Full name", InputKind::Text, false),
            f("national_id", "National ID", InputKind::Key, false),
            f("document", "Document number", InputKind::Key, false),
            f("expiry", "Expiry", InputKind::Date, false),
        ],
    },
    Preset {
        key: "travel",
        name: "Travel",
        icon: "airplane",
        color: "#06B6D4",
        icon_color: "#FFFFFF",
        fields: &[
            f(
                "frequent_flyer",
                "Frequent flyer number",
                InputKind::Text,
                false,
            ),
            f("booking", "Booking reference", InputKind::Text, false),
            f("insurance", "Insurance policy", InputKind::Text, false),
        ],
    },
    Preset {
        key: "database",
        name: "Database",
        icon: "server.rack",
        color: "#8B5CF6",
        icon_color: "#FFFFFF",
        fields: &[
            f("host", "Host", InputKind::Text, false),
            f("port", "Port", InputKind::Number, false),
            f("database", "Database", InputKind::Text, false),
            f("username", "Username", InputKind::Text, false),
            f("password", "Password", InputKind::Password, false),
            f("connection", "Connection string", InputKind::Key, false),
        ],
    },
    Preset {
        key: "dev_secret",
        name: "Developer Secret",
        icon: "terminal",
        color: "#EF4444",
        icon_color: "#FFFFFF",
        fields: &[
            f("api_key", "API key", InputKind::Key, false),
            f("ssh_key", "SSH key", InputKind::Key, false),
            f("hash", "Hash", InputKind::Hash, false),
            f("env", ".env", InputKind::Env, false),
        ],
    },
    Preset {
        key: "wifi",
        name: "Wi-Fi",
        icon: "wifi",
        color: "#0EA5E9",
        icon_color: "#FFFFFF",
        // Order matters for the QR export (see `crate::wifi`): network name = first text input,
        // security = second text input, password = first password input.
        fields: &[
            f("ssid", "Network name", InputKind::Text, true),
            f("password", "Password", InputKind::Password, true),
            f("security", "Security", InputKind::Text, false),
        ],
    },
    Preset {
        key: "software_license",
        name: "Software License",
        icon: "key.horizontal",
        color: "#EC4899",
        icon_color: "#FFFFFF",
        fields: &[
            f("product", "Product", InputKind::Text, false),
            f("license_key", "License key", InputKind::Key, false),
            f("licensed_to", "Licensed to", InputKind::Text, false),
            f("purchase_date", "Purchase date", InputKind::Date, false),
            f("expiry", "Expiry", InputKind::Date, false),
        ],
    },
    Preset {
        key: "note",
        name: "Notes",
        icon: "note.text",
        color: "#64748B",
        icon_color: "#FFFFFF",
        fields: &[],
    },
];

/// Deterministic category id of a preset.
pub fn preset_category_id(key: &str) -> String {
    format!("preset:{key}")
}

/// Records for every preset not yet present in `existing` (tombstoned ones count as present).
/// `first_sort_order` is where the new categories start in the display order.
///
/// Also repairs core inputs of presets that already exist: if a core input of a live preset
/// category is missing, tombstoned or not flagged core (vaults seeded by an older build), it is
/// restored with `is_core = true`.
pub(crate) fn seed_records(
    ctx: &WriteCtx<'_>,
    existing: &[Category],
    existing_fields: &[CategoryField],
    first_sort_order: i64,
) -> (Vec<Category>, Vec<CategoryField>) {
    let mut cats = Vec::new();
    let mut fields = Vec::new();
    let mut order = first_sort_order;
    for p in PRESETS {
        let id = preset_category_id(p.key);
        if let Some(cat) = existing.iter().find(|c| c.id == id) {
            if cat.deleted_at.is_some() {
                continue;
            }
            for (i, pf) in p.fields.iter().enumerate().filter(|(_, pf)| pf.core) {
                let fid = format!("{id}:{}", pf.key);
                let live_core = existing_fields
                    .iter()
                    .any(|f| f.id == fid && f.is_core && f.deleted_at.is_none());
                if live_core {
                    continue;
                }
                let mut f = existing_fields
                    .iter()
                    .find(|f| f.id == fid)
                    .cloned()
                    .unwrap_or_else(|| CategoryField {
                        id: fid.clone(),
                        category_id: id.clone(),
                        name: pf.name.to_string(),
                        kind: pf.kind.as_str().to_string(),
                        is_secret: pf.kind.secret_by_default(),
                        is_core: true,
                        sort_order: i64::try_from(i).unwrap_or(i64::MAX),
                        updated_at: 0,
                        updated_by: ctx.device_id.to_string(),
                        deleted_at: None,
                    });
                f.kind = pf.kind.as_str().to_string();
                f.is_core = true;
                f.deleted_at = None;
                f.updated_at = f.updated_at.saturating_add(1).max(ctx.now_ms);
                f.updated_by = ctx.device_id.to_string();
                fields.push(f);
            }
            continue;
        }
        cats.push(Category {
            id: id.clone(),
            name: p.name.to_string(),
            color: p.color.to_string(),
            icon: p.icon.to_string(),
            icon_color: p.icon_color.to_string(),
            preset: Some(p.key.to_string()),
            sort_order: order,
            created_at: ctx.now_ms,
            updated_at: 0,
            updated_by: ctx.device_id.to_string(),
            deleted_at: None,
        });
        order = order.saturating_add(1);
        for (i, pf) in p.fields.iter().enumerate() {
            fields.push(CategoryField {
                id: format!("{id}:{}", pf.key),
                category_id: id.clone(),
                name: pf.name.to_string(),
                kind: pf.kind.as_str().to_string(),
                is_secret: pf.kind.secret_by_default(),
                is_core: pf.core,
                sort_order: i64::try_from(i).unwrap_or(i64::MAX),
                updated_at: 0,
                updated_by: ctx.device_id.to_string(),
                deleted_at: None,
            });
        }
    }
    (cats, fields)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn ctx() -> WriteCtx<'static> {
        WriteCtx {
            now_ms: 1_000,
            device_id: "dev",
        }
    }

    #[test]
    fn cardholder_is_a_core_input() {
        let (_, fields) = seed_records(&ctx(), &[], &[], 0);
        let holder = fields
            .iter()
            .find(|f| f.id == "preset:card:holder")
            .unwrap();
        assert!(holder.is_core);
    }

    #[test]
    fn reseeding_repairs_core_flags_and_restores_deleted_core_inputs() {
        let (cats, mut fields) = seed_records(&ctx(), &[], &[], 0);
        // Vault seeded by an older build: holder was not core and the user had deleted it.
        for f in &mut fields {
            if f.id == "preset:card:holder" {
                f.is_core = false;
                f.deleted_at = Some(5);
                f.updated_at = 5;
            }
        }
        let (new_cats, repaired) = seed_records(&ctx(), &cats, &fields, 0);
        assert!(new_cats.is_empty());
        assert_eq!(repaired.len(), 1);
        let h = &repaired[0];
        assert_eq!(h.id, "preset:card:holder");
        assert!(h.is_core && h.deleted_at.is_none() && h.updated_at > 5);
        // Already healthy: nothing to do.
        let healthy: Vec<_> = fields
            .iter()
            .cloned()
            .map(|f| if f.id == h.id { h.clone() } else { f })
            .collect();
        assert!(seed_records(&ctx(), &cats, &healthy, 0).1.is_empty());
    }

    #[test]
    fn a_deleted_preset_category_is_not_repaired() {
        let (mut cats, fields) = seed_records(&ctx(), &[], &[], 0);
        for c in &mut cats {
            c.deleted_at = Some(9);
        }
        let (c, f) = seed_records(&ctx(), &cats, &[], 0);
        assert!(c.is_empty() && f.is_empty());
        let _ = fields;
    }
}
