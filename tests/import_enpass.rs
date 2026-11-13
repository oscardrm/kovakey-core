//! Enpass JSON import: parsing, mapping, duplicates, password history. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use vault_core::import::{enpass, find_duplicates, import_items};

const EXPORT: &str = r#"{
  "folders": [{"uuid": "f1", "title": "Work"}],
  "items": [
    {"category": "login", "title": "Mail", "favorite": 1, "folders": ["f1"], "note": "my note",
     "fields": [
       {"type": "username", "label": "Username", "value": "alice", "sensitive": 0},
       {"type": "email", "label": "E-mail", "value": "alice@example.test", "sensitive": 0},
       {"type": "password", "label": "Password", "value": "fake-pw-3", "sensitive": 1,
        "history": [{"value": "fake-pw-2", "updated_at": 20}, {"value": "fake-pw-1", "updated_at": 10}]},
       {"type": "url", "label": "Website", "value": "https://mail.example.test/"},
       {"type": "url", "label": "Other", "value": "https://other.example.test/"},
       {"type": "section", "label": "EXTRA", "value": ""},
       {"type": "totp", "label": "One-time code", "value": "JBSWY3DPEHPK3PXP", "sensitive": 1},
       {"type": "text", "label": "Empty", "value": ""},
       {"type": "text", "label": "Gone", "value": "x", "deleted": 1}
     ]},
    {"category": "creditcard", "title": "Visa",
     "fields": [
       {"type": "ccNumber", "label": "Number", "value": "4111111111111111"},
       {"type": "ccCvc", "label": "CVC", "value": "123"}
     ]},
    {"category": "note", "title": "Memo", "note": "just text", "fields": []},
    {"category": "login", "title": "Old", "trashed": 1, "fields": []},
    {"category": "login", "title": "", "fields": []}
  ]
}"#;

#[test]
fn parse_maps_types_and_skips_trash_and_empties() {
    let p = enpass::parse_json(EXPORT.as_bytes()).unwrap();
    assert_eq!(p.items.len(), 3);
    assert_eq!(p.skipped_trashed, 1);
    assert_eq!(p.skipped_invalid, 1);

    let mail = &p.items[0];
    assert_eq!(mail.preset_key, "credential");
    assert_eq!(mail.url.as_deref(), Some("https://mail.example.test/"));
    assert!(mail.favorite);
    assert!(mail.tags.contains(&"Work".to_string()));
    assert_eq!(mail.note, "my note");
    assert_eq!(mail.password_history, vec!["fake-pw-1", "fake-pw-2"]);
    let kinds: Vec<_> = mail.fields.iter().map(|f| f.kind.as_str()).collect();
    assert_eq!(kinds, ["text", "email", "password", "url", "totp"]);
    assert!(
        mail.fields
            .iter()
            .find(|f| f.kind == "totp")
            .unwrap()
            .is_secret
    );

    assert_eq!(p.items[1].preset_key, "card");
    assert_eq!(p.items[2].preset_key, "note");
}

#[test]
fn parse_rejects_garbage_and_debug_never_prints_values() {
    assert!(enpass::parse_json(b"not json").is_err());
    assert!(enpass::parse_json(b"{}").unwrap().items.is_empty());
    let p = enpass::parse_json(EXPORT.as_bytes()).unwrap();
    let dbg = format!("{p:?}");
    for secret in [
        "fake-pw-3",
        "fake-pw-1",
        "4111111111111111",
        "my note",
        "JBSWY3DPEHPK3PXP",
    ] {
        assert!(!dbg.contains(secret), "{secret} leaked");
    }
}

macro_rules! store_tests {
    ($mod:ident, $new:expr) => {
        mod $mod {
            use super::*;
            use common::ctx;
            use vault_core::ops::VaultStore;

            fn seeded() -> impl VaultStore {
                let mut d = $new;
                d.seed_default_categories(&ctx("dev-a", 1)).unwrap();
                d
            }

            #[test]
            fn import_writes_items_tags_category_and_history() {
                let mut d = seeded();
                let p = enpass::parse_json(EXPORT.as_bytes()).unwrap();
                let r = import_items(&mut d, &ctx("dev-a", 1_000), &p.items, true, None).unwrap();
                assert_eq!((r.imported, r.skipped_duplicates, r.failed), (3, 0, 0));
                assert_eq!(r.tags_created, 1);

                let items = d.list_items().unwrap();
                assert_eq!(items.len(), 3);
                let mail = items.iter().find(|i| i.title == "Mail").unwrap();
                assert!(mail.favorite);
                assert!(mail.tags.contains(&"Work".to_string()));
                assert_eq!(mail.category_id.as_deref(), Some("preset:credential"));

                let detail = d.get_item(&mail.id).unwrap();
                let pw = detail.fields.iter().find(|f| f.kind == "password").unwrap();
                assert_eq!(&*d.reveal_field(&mail.id, &pw.id).unwrap(), "fake-pw-3");
                let hist: Vec<String> = d
                    .reveal_password_history(&mail.id)
                    .unwrap()
                    .iter()
                    .map(|h| h.password.clone())
                    .collect();
                assert_eq!(hist.len(), 2);
                assert!(hist.contains(&"fake-pw-1".to_string()));
                assert!(hist.contains(&"fake-pw-2".to_string()));
                assert_eq!(detail.blocks.len(), 1);
            }

            #[test]
            fn second_import_skips_duplicates_unless_told_otherwise() {
                let mut d = seeded();
                let p = enpass::parse_json(EXPORT.as_bytes()).unwrap();
                import_items(&mut d, &ctx("dev-a", 1_000), &p.items, true, None).unwrap();
                assert_eq!(find_duplicates(&d, &p.items).unwrap(), vec![0, 1, 2]);

                let r = import_items(&mut d, &ctx("dev-a", 2_000), &p.items, true, None).unwrap();
                assert_eq!((r.imported, r.skipped_duplicates), (0, 3));
                assert_eq!(d.list_items().unwrap().len(), 3);

                let r = import_items(&mut d, &ctx("dev-a", 3_000), &p.items, false, None).unwrap();
                assert_eq!(r.imported, 3);
                assert_eq!(d.list_items().unwrap().len(), 6);
            }

            #[test]
            fn duplicates_inside_one_file_are_detected() {
                let mut d = seeded();
                let one = r#"{"items":[{"category":"login","title":"A","fields":[{"type":"password","label":"P","value":"x","sensitive":1}]}]}"#;
                let mut p = enpass::parse_json(one.as_bytes()).unwrap();
                p.items.push(p.items[0].clone());
                let r = import_items(&mut d, &ctx("dev-a", 1_000), &p.items, true, None).unwrap();
                assert_eq!((r.imported, r.skipped_duplicates), (1, 1));
            }
        }
    };
}

store_tests!(sqlcipher, common::db());
store_tests!(memory, vault_core::mem_store::MemStore::new());
