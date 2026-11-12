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
            f("holder", "Cardholder", InputKind::Text, false),
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

/// Records for every preset not yet present in `existing_category_ids` (tombstoned ones count as
/// present). `first_sort_order` is where the new categories start in the display order.
pub(crate) fn seed_records(
    ctx: &WriteCtx<'_>,
    existing_category_ids: &[&str],
    first_sort_order: i64,
) -> (Vec<Category>, Vec<CategoryField>) {
    let mut cats = Vec::new();
    let mut fields = Vec::new();
    let mut order = first_sort_order;
    for p in PRESETS {
        let id = preset_category_id(p.key);
        if existing_category_ids.contains(&id.as_str()) {
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
