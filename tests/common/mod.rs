//! Shared helpers for integration tests. Fake data only.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use vault_core::crypto::SecretKey;
use vault_core::db::{Database, FieldInput, NewItem, WriteCtx};
use vault_core::models::ItemType;

pub fn key() -> SecretKey {
    SecretKey::from_bytes([7; 32])
}

pub fn db() -> Database {
    Database::open_in_memory(&key()).unwrap()
}

pub fn ctx(device: &str, now_ms: i64) -> WriteCtx<'_> {
    WriteCtx {
        now_ms,
        device_id: device,
    }
}

/// Login item with a (fake) password field. Returns `(item_id)`.
pub fn login(db: &mut Database, device: &str, now: i64, title: &str, password: &str) -> String {
    let mut item = NewItem::new(ItemType::Credential, title);
    item.fields = vec![
        FieldInput::new("username", "text", "user@example.test", false),
        FieldInput::new("password", "password", password, true),
    ];
    db.create_item(&ctx(device, now), &item).unwrap()
}
