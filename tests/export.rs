//! Export -> import round trip across both store backends, with production Argon2id params.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::ctx;
use vault_core::export::{export_encrypted, export_plain_json};
use vault_core::import::{import_items, kovakey};
use vault_core::models::ItemType;
use vault_core::ops::{FieldInput, NewItem, VaultStore};

fn source<S: VaultStore>(mut s: S) -> S {
    s.seed_default_categories(&ctx("dev-a", 1)).unwrap();
    let mut n = NewItem::new(ItemType::Credential, "Bank");
    n.fields = vec![
        FieldInput::new("Username", "text", "bob", false),
        FieldInput::new("Password", "password", "fake-pw-9", true),
        FieldInput::new("2FA", "totp", "JBSWY3DPEHPK3PXP", true),
    ];
    let id = s.create_item(&ctx("dev-a", 10), &n).unwrap();
    let tag = s.create_tag(&ctx("dev-a", 11), "Money", "#FF0000").unwrap();
    s.add_tag(&ctx("dev-a", 12), &id, &tag.id).unwrap();
    s
}

fn check_round_trip<S: VaultStore>(src: S, mut dst: S) {
    let src = source(src);
    dst.seed_default_categories(&ctx("dev-b", 1)).unwrap();
    let file = export_encrypted(&src, "fake-export-pass").unwrap();
    let preview = kovakey::parse_encrypted(&file, "fake-export-pass").unwrap();
    let r = import_items(&mut dst, &ctx("dev-b", 100), &preview.items, true, None).unwrap();
    assert_eq!((r.imported, r.failed), (1, 0));

    let item = dst.list_items().unwrap().remove(0);
    assert_eq!(item.title, "Bank");
    // The auto-tagger may add its own tags (#bank, #2fa); the user tag must travel.
    assert!(item.tags.contains(&"Money".to_string()));
    assert_eq!(item.category_id.as_deref(), Some("preset:credential"));
    let d = dst.get_item(&item.id).unwrap();
    let totp = d.fields.iter().find(|f| f.kind == "totp").unwrap();
    assert_eq!(
        &*dst.reveal_field(&item.id, &totp.id).unwrap(),
        "JBSWY3DPEHPK3PXP"
    );
    // Re-importing the same export is flagged as duplicate.
    let again = import_items(&mut dst, &ctx("dev-b", 200), &preview.items, true, None).unwrap();
    assert_eq!(again.skipped_duplicates, 1);

    let plain = export_plain_json(&src).unwrap();
    assert!(kovakey::parse_json(&plain).is_ok());
}

#[test]
fn encrypted_export_round_trips_between_sqlcipher_stores() {
    check_round_trip(common::db(), common::db());
}

#[test]
fn encrypted_export_round_trips_between_memory_stores() {
    check_round_trip(
        vault_core::mem_store::MemStore::new(),
        vault_core::mem_store::MemStore::new(),
    );
}
