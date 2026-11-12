use super::common::{ctx, login};
use vault_core::db::{
    BlockInput, CategoryFieldInput, CategoryUpdate, FieldInput, ItemUpdate, NewCategory, NewItem, VaultStore,
};
use vault_core::models::{BlockKind, InputKind, ItemType};
use vault_core::Error;

// Included twice by `crud.rs`: once per `VaultStore` backend. `Store` and `db()` are defined there.
fn field_id(d: &Store, item: &str, kind: &str) -> String {
    d.get_item(item)
        .unwrap()
        .fields
        .into_iter()
        .find(|f| f.kind == kind)
        .unwrap()
        .id
}

fn set_password(d: &mut Store, item: &str, now: i64, pw: &str) -> vault_core::Result<()> {
    let user = field_id(d, item, "text");
    let pass = field_id(d, item, "password");
    d.update_item(
        &ctx("dev-a", now),
        item,
        &ItemUpdate {
            fields: Some(vec![
                FieldInput::new("username", "text", "user@example.test", false).with_id(&user),
                FieldInput::new("password", "password", pw, true).with_id(&pass),
            ]),
            ..Default::default()
        },
    )
}

fn tags_of(d: &Store, item: &str) -> Vec<String> {
    d.get_item(item).unwrap().summary.tags
}

// ---- reads / secrets --------------------------------------------------------------------

#[test]
fn get_item_withholds_secret_values_and_reveal_returns_them() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-secret-1");
    let detail = d.get_item(&id).unwrap();
    let pw = detail.fields.iter().find(|f| f.kind == "password").unwrap();
    assert_eq!(pw.value, None);
    let user = detail.fields.iter().find(|f| f.kind == "text").unwrap();
    assert_eq!(user.value.as_deref(), Some("user@example.test"));
    assert_eq!(
        d.reveal_field(&id, &pw.id).unwrap().as_str(),
        "fake-secret-1"
    );
    assert!(!format!("{detail:?}").contains("fake-secret-1"));
}

#[test]
fn list_items_is_sorted_by_title_and_excludes_deleted() {
    let mut d = db();
    let b = login(&mut d, "dev-a", 100, "banana", "fake");
    login(&mut d, "dev-a", 101, "Apple", "fake");
    d.delete_item(&ctx("dev-a", 200), &b).unwrap();
    let titles: Vec<_> = d
        .list_items()
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert_eq!(titles, ["Apple"]);
}

// ---- password history -------------------------------------------------------------------

#[test]
fn changing_a_password_records_the_old_value_in_history() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-v1");
    set_password(&mut d, &id, 200, "fake-v2").unwrap();
    set_password(&mut d, &id, 300, "fake-v3").unwrap();
    let hist = d.reveal_password_history(&id).unwrap();
    let values: Vec<_> = hist.iter().map(|h| h.password.as_str()).collect();
    assert_eq!(values, ["fake-v2", "fake-v1"], "newest first");
    assert!(hist.iter().all(|h| h.field_id.is_some()));
    let pass = field_id(&d, &id, "password");
    assert_eq!(d.reveal_field(&id, &pass).unwrap().as_str(), "fake-v3");
}

#[test]
fn rewriting_the_same_password_adds_no_history_and_keeps_updated_at() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-v1");
    let before = d.get_item(&id).unwrap().summary.updated_at;
    set_password(&mut d, &id, 200, "fake-v1").unwrap();
    assert!(d.reveal_password_history(&id).unwrap().is_empty());
    assert_eq!(d.get_item(&id).unwrap().summary.updated_at, before);
}

#[test]
fn changing_a_non_password_field_adds_no_history() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-v1");
    let user = field_id(&d, &id, "text");
    let pass = field_id(&d, &id, "password");
    d.update_item(
        &ctx("dev-a", 200),
        &id,
        &ItemUpdate {
            fields: Some(vec![
                FieldInput::new("username", "text", "other@example.test", false).with_id(&user),
                FieldInput::new("password", "password", "fake-v1", true).with_id(&pass),
            ]),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(d.reveal_password_history(&id).unwrap().is_empty());
}

#[test]
fn failed_update_rolls_back_history_and_field_changes() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-v1");
    let pass = field_id(&d, &id, "password");
    let snapshot = d.snapshot().unwrap();
    let res = d.update_item(
        &ctx("dev-a", 200),
        &id,
        &ItemUpdate {
            fields: Some(vec![
                FieldInput::new("password", "password", "fake-v2", true).with_id(&pass),
                FieldInput::new("bogus", "text", "x", false).with_id("no-such-field"),
            ]),
            ..Default::default()
        },
    );
    assert_eq!(res, Err(Error::NotFound));
    assert_eq!(d.snapshot().unwrap(), snapshot);
    assert!(d.reveal_password_history(&id).unwrap().is_empty());
}

// ---- tombstones -------------------------------------------------------------------------

#[test]
fn delete_item_tombstones_children_scrubs_secrets_and_keeps_history() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "My Bank", "fake-v1");
    set_password(&mut d, &id, 150, "fake-v2").unwrap();
    d.delete_item(&ctx("dev-a", 200), &id).unwrap();

    let snap = d.snapshot().unwrap();
    let item = snap.items.iter().find(|i| i.id == id).unwrap();
    assert!(item.deleted_at.is_some());
    assert_eq!(item.history.len(), 1, "history survives deletion");
    assert!(!snap.item_fields.is_empty());
    assert!(snap
        .item_fields
        .iter()
        .all(|f| f.deleted_at.is_some() && f.value.is_empty()));
    assert!(
        snap.item_tags.iter().all(|l| l.deleted_at.is_some()),
        "tag links tombstoned"
    );
    assert_eq!(d.get_item(&id), Err(Error::NotFound));
    assert!(d.list_items().unwrap().is_empty());
    assert_eq!(d.delete_item(&ctx("dev-a", 300), &id), Err(Error::NotFound));
}

#[test]
fn removing_a_field_or_block_tombstones_and_scrubs_it() {
    let mut d = db();
    let mut n = NewItem::new(ItemType::Note, "Notes");
    n.fields = vec![FieldInput::new("pin", "text", "fake-1234", true)];
    n.blocks = vec![BlockInput {
        id: None,
        kind: BlockKind::RichText,
        language: None,
        content: "fake-note-body".into(),
        image_id: None,
    }];
    let id = d.create_item(&ctx("dev-a", 100), &n).unwrap();
    d.update_item(
        &ctx("dev-a", 200),
        &id,
        &ItemUpdate {
            fields: Some(vec![]),
            blocks: Some(vec![]),
            ..Default::default()
        },
    )
    .unwrap();
    let snap = d.snapshot().unwrap();
    assert!(snap.item_fields[0].value.is_empty() && snap.item_fields[0].deleted_at.is_some());
    assert!(snap.note_blocks[0].content.is_empty() && snap.note_blocks[0].deleted_at.is_some());
    let detail = d.get_item(&id).unwrap();
    assert!(detail.fields.is_empty() && detail.blocks.is_empty());
}

#[test]
fn updated_at_strictly_increases_even_if_the_clock_moves_backwards() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 1_000, "Mail", "fake");
    for (now, title) in [(500, "one"), (500, "two")] {
        let before = d.get_item(&id).unwrap().summary.updated_at;
        d.update_item(
            &ctx("dev-a", now),
            &id,
            &ItemUpdate {
                title: Some(title.into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(d.get_item(&id).unwrap().summary.updated_at > before);
    }
}

// ---- auto-tagger ------------------------------------------------------------------------

#[test]
fn create_item_applies_auto_tags_flagged_auto() {
    let mut d = db();
    let mut n = NewItem::new(ItemType::Credential, "My Bank");
    n.fields = vec![FieldInput::new("otp", "totp", "JBSWY3DPEHPK3PXP", true)];
    let id = d.create_item(&ctx("dev-a", 100), &n).unwrap();
    let tags = tags_of(&d, &id);
    assert!(tags.contains(&"#bank".to_string()), "{tags:?}");
    assert!(tags.contains(&"#2fa".to_string()), "{tags:?}");
    let snap = d.snapshot().unwrap();
    assert!(snap.item_tags.iter().all(|l| l.auto));
}

#[test]
fn update_reapplies_tagger_for_new_title() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Misc", "fake");
    assert!(!tags_of(&d, &id).contains(&"#bank".to_string()));
    d.update_item(
        &ctx("dev-a", 200),
        &id,
        &ItemUpdate {
            title: Some("PayPal".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(tags_of(&d, &id).contains(&"#bank".to_string()));
}

#[test]
fn a_tag_the_user_removed_is_not_readded_by_the_tagger() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "My Bank", "fake");
    let bank = d
        .list_tags()
        .unwrap()
        .into_iter()
        .find(|t| t.name == "#bank")
        .unwrap();
    d.remove_tag(&ctx("dev-a", 200), &id, &bank.id).unwrap();
    assert!(!tags_of(&d, &id).contains(&"#bank".to_string()));

    d.update_item(
        &ctx("dev-a", 300),
        &id,
        &ItemUpdate {
            title: Some("My Bank (new)".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        !tags_of(&d, &id).contains(&"#bank".to_string()),
        "rejection respected"
    );
}

#[test]
fn explicitly_adding_a_removed_tag_revives_it_as_a_user_choice() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "My Bank", "fake");
    let bank = d
        .list_tags()
        .unwrap()
        .into_iter()
        .find(|t| t.name == "#bank")
        .unwrap();
    d.remove_tag(&ctx("dev-a", 200), &id, &bank.id).unwrap();
    d.add_tag(&ctx("dev-a", 300), &id, &bank.id).unwrap();
    assert!(tags_of(&d, &id).contains(&"#bank".to_string()));
    let snap = d.snapshot().unwrap();
    assert!(snap.item_tags.iter().all(|l| !l.auto));
}

#[test]
fn a_deleted_tag_is_not_recreated_by_the_tagger_for_other_items() {
    let mut d = db();
    let first = login(&mut d, "dev-a", 100, "My Bank", "fake");
    let bank = d
        .list_tags()
        .unwrap()
        .into_iter()
        .find(|t| t.name == "#bank")
        .unwrap();
    d.delete_tag(&ctx("dev-a", 200), &bank.id).unwrap();
    assert!(!tags_of(&d, &first).contains(&"#bank".to_string()));

    let second = login(&mut d, "dev-a", 300, "Other Bank", "fake");
    assert!(!tags_of(&d, &second).contains(&"#bank".to_string()));
    assert!(d.list_tags().unwrap().iter().all(|t| t.name != "#bank"));
}

#[test]
fn create_tag_returns_the_existing_live_tag_with_the_same_name() {
    let mut d = db();
    let a = d
        .create_tag(&ctx("dev-a", 100), "#work", "#111111")
        .unwrap();
    let b = d
        .create_tag(&ctx("dev-a", 200), "#work", "#999999")
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(d.list_tags().unwrap().len(), 1);
}

// ---- usage counters ---------------------------------------------------------------------

#[test]
fn record_use_increments_counters_without_touching_updated_at() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake");
    let before = d.get_item(&id).unwrap().summary;
    d.record_use(&ctx("dev-a", 500), &id).unwrap();
    d.record_use(&ctx("dev-a", 600), &id).unwrap();
    let after = d.get_item(&id).unwrap().summary;
    assert_eq!((after.use_count, after.last_used_at), (2, Some(600)));
    assert_eq!(after.updated_at, before.updated_at);
}

// ---- categories -------------------------------------------------------------------------

fn new_cat(name: &str) -> NewCategory {
    NewCategory {
        name: name.into(),
        color: "#101010".into(),
        icon: "folder".into(),
        icon_color: "#f0f0f0".into(),
        fields: vec![],
    }
}

#[test]
fn categories_keep_independent_icon_color_and_support_reordering() {
    let mut d = db();
    let a = d
        .create_category(&ctx("dev-a", 100), &new_cat("A"))
        .unwrap();
    let b = d
        .create_category(&ctx("dev-a", 101), &new_cat("B"))
        .unwrap();
    assert_eq!((a.sort_order, b.sort_order), (0, 1));
    assert_ne!(a.color, a.icon_color);

    d.reorder_categories(&ctx("dev-a", 200), &[b.id.clone(), a.id.clone()])
        .unwrap();
    let names: Vec<_> = d
        .list_categories()
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, ["B", "A"]);

    d.update_category(
        &ctx("dev-a", 300),
        &a.id,
        &CategoryUpdate {
            icon_color: Some("#abcdef".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let a2 = d
        .list_categories()
        .unwrap()
        .into_iter()
        .find(|c| c.id == a.id)
        .unwrap();
    assert_eq!(
        (a2.color.as_str(), a2.icon_color.as_str()),
        ("#101010", "#abcdef")
    );
}

#[test]
fn deleting_a_category_hides_it_from_items_and_rejects_new_assignments() {
    let mut d = db();
    let cat = d
        .create_category(&ctx("dev-a", 100), &new_cat("Work"))
        .unwrap();
    let mut n = NewItem::new(ItemType::Credential, "Intranet");
    n.category_id = Some(cat.id.clone());
    let id = d.create_item(&ctx("dev-a", 110), &n).unwrap();
    assert_eq!(
        d.get_item(&id).unwrap().summary.category_id,
        Some(cat.id.clone())
    );

    d.delete_category(&ctx("dev-a", 200), &cat.id).unwrap();
    assert_eq!(d.get_item(&id).unwrap().summary.category_id, None);
    assert!(d.list_categories().unwrap().is_empty());
    assert_eq!(d.create_item(&ctx("dev-a", 300), &n), Err(Error::NotFound));
}

// ---- notes ------------------------------------------------------------------------------

#[test]
fn code_blocks_get_a_detected_language_and_image_blocks_need_a_real_image() {
    let mut d = db();
    let mut n = NewItem::new(ItemType::Note, "Snippets");
    n.blocks = vec![BlockInput {
        id: None,
        kind: BlockKind::Code,
        language: None,
        content: "{\"a\": 1}".into(),
        image_id: None,
    }];
    let id = d.create_item(&ctx("dev-a", 100), &n).unwrap();
    assert_eq!(
        d.get_item(&id).unwrap().blocks[0].language.as_deref(),
        Some("json")
    );

    n.blocks = vec![BlockInput {
        id: None,
        kind: BlockKind::Image,
        language: None,
        content: String::new(),
        image_id: Some("missing".into()),
    }];
    assert_eq!(d.create_item(&ctx("dev-a", 200), &n), Err(Error::NotFound));
    let img = d
        .add_note_image(&ctx("dev-a", 210), "image/png", &[9, 9, 9])
        .unwrap();
    n.blocks[0].image_id = Some(img.clone());
    assert!(d.create_item(&ctx("dev-a", 220), &n).is_ok());
    assert_eq!(d.note_image(&img).unwrap().1.as_slice(), &[9, 9, 9]);
}

// ---- validation -------------------------------------------------------------------------

#[test]
fn invalid_input_is_rejected_without_side_effects() {
    let mut d = db();
    assert_eq!(
        d.create_item(&ctx("dev-a", 100), &NewItem::new(ItemType::Note, "  ")),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        d.create_item(&ctx("", 100), &NewItem::new(ItemType::Note, "x")),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        d.create_item(&ctx("dev-a", -1), &NewItem::new(ItemType::Note, "x")),
        Err(Error::InvalidInput)
    );
    let mut n = NewItem::new(ItemType::Note, "x");
    n.fields = vec![FieldInput::new("a", "text", "v", false).with_id("preset")];
    assert_eq!(
        d.create_item(&ctx("dev-a", 100), &n),
        Err(Error::InvalidInput)
    );
    assert!(d.list_items().unwrap().is_empty());
    assert_eq!(d.snapshot().unwrap(), Default::default());
}

#[test]
fn field_input_debug_never_prints_the_value() {
    let f = FieldInput::new("password", "password", "fake-do-not-print", true);
    assert!(!format!("{f:?}").contains("fake-do-not-print"));
}

// ---- preset categories and their editable field templates ---------------------------------

fn card(d: &Store) -> vault_core::models::Category {
    d.list_categories()
        .unwrap()
        .into_iter()
        .find(|c| c.preset.as_deref() == Some("card"))
        .unwrap()
}

/// The category's template as inputs targeting the existing fields (an unchanged edit).
fn template(d: &Store, cat: &str) -> Vec<CategoryFieldInput> {
    d.list_category_fields(cat)
        .unwrap()
        .into_iter()
        .map(|f| CategoryFieldInput {
            id: Some(f.id),
            name: f.name,
            kind: f.kind,
            is_secret: f.is_secret,
        })
        .collect()
}

#[test]
fn seeding_creates_editable_preset_categories_once() {
    let mut d = db();
    d.seed_default_categories(&ctx("dev-a", 100)).unwrap();
    let n = d.list_categories().unwrap().len();
    assert!(n >= 7);
    d.seed_default_categories(&ctx("dev-b", 200)).unwrap();
    assert_eq!(d.list_categories().unwrap().len(), n);

    let c = card(&d);
    let fields = d.list_category_fields(&c.id).unwrap();
    let core: Vec<_> = fields.iter().filter(|f| f.is_core).map(|f| f.kind.as_str()).collect();
    assert_eq!(core, ["text", "card_number", "expiry", "cvv"]);

    // Fully editable like any category.
    d.update_category(
        &ctx("dev-a", 300),
        &c.id,
        &CategoryUpdate {
            name: Some("Cards".into()),
            icon: Some("star".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(card(&d).name, "Cards");

    // A deleted preset stays deleted.
    d.delete_category(&ctx("dev-a", 400), &c.id).unwrap();
    d.seed_default_categories(&ctx("dev-a", 500)).unwrap();
    assert!(d.list_categories().unwrap().iter().all(|x| x.id != c.id));
}

#[test]
fn core_inputs_cannot_be_deleted_but_extras_can_be_added_and_removed() {
    let mut d = db();
    d.seed_default_categories(&ctx("dev-a", 100)).unwrap();
    let c = card(&d);
    let base = template(&d, &c.id);

    // Omitting a core input fails and changes nothing.
    let mut without_core = base.clone();
    without_core.retain(|f| f.kind != "cvv");
    let r = d.update_category(
        &ctx("dev-a", 200),
        &c.id,
        &CategoryUpdate { fields: Some(without_core), ..Default::default() },
    );
    assert_eq!(r, Err(Error::InvalidInput));
    assert_eq!(d.list_category_fields(&c.id).unwrap().len(), base.len());

    // Core kind is fixed.
    let mut retyped = base.clone();
    for f in &mut retyped {
        if f.kind == "cvv" {
            f.kind = "text".into();
        }
    }
    let r = d.update_category(
        &ctx("dev-a", 210),
        &c.id,
        &CategoryUpdate { fields: Some(retyped), ..Default::default() },
    );
    assert_eq!(r, Err(Error::InvalidInput));

    // Extras: add one (with a chosen input type) ...
    let mut with_extra = base.clone();
    with_extra.push(CategoryFieldInput::new("Billing address", InputKind::SecureNote));
    d.update_category(
        &ctx("dev-a", 300),
        &c.id,
        &CategoryUpdate { fields: Some(with_extra), ..Default::default() },
    )
    .unwrap();
    let fields = d.list_category_fields(&c.id).unwrap();
    assert_eq!(fields.len(), base.len() + 1);
    let extra = fields.last().unwrap();
    assert_eq!((extra.kind.as_str(), extra.is_core, extra.is_secret), ("secure_note", false, true));

    // ... rename a core input (allowed) and remove the extra again.
    let mut edited = template(&d, &c.id);
    edited.pop();
    for f in &mut edited {
        if f.kind == "cvv" {
            f.name = "Security code".into();
        }
    }
    d.update_category(
        &ctx("dev-a", 400),
        &c.id,
        &CategoryUpdate { fields: Some(edited), ..Default::default() },
    )
    .unwrap();
    let fields = d.list_category_fields(&c.id).unwrap();
    assert_eq!(fields.len(), base.len());
    assert!(fields.iter().any(|f| f.name == "Security code" && f.is_core));
}

#[test]
fn custom_categories_take_extra_inputs_on_create_and_reject_bad_kinds() {
    let mut d = db();
    let mut new = new_cat("Wi-Fi");
    new.fields = vec![
        CategoryFieldInput::new("Network", InputKind::Text),
        CategoryFieldInput::new("Password", InputKind::Password),
    ];
    let c = d.create_category(&ctx("dev-a", 100), &new).unwrap();
    assert!(c.preset.is_none());
    let fields = d.list_category_fields(&c.id).unwrap();
    assert_eq!(fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["Network", "Password"]);
    assert!(fields.iter().all(|f| !f.is_core));

    let mut bad = new_cat("Bad");
    bad.fields = vec![CategoryFieldInput {
        id: None,
        name: "x".into(),
        kind: "bogus".into(),
        is_secret: false,
    }];
    assert_eq!(d.create_category(&ctx("dev-a", 200), &bad).err(), Some(Error::InvalidInput));
    assert_eq!(d.list_categories().unwrap().len(), 1);

    // Extras are deletable on custom categories.
    d.update_category(
        &ctx("dev-a", 300),
        &c.id,
        &CategoryUpdate { fields: Some(vec![]), ..Default::default() },
    )
    .unwrap();
    assert!(d.list_category_fields(&c.id).unwrap().is_empty());
}

#[test]
fn category_templates_survive_snapshot_merge() {
    let mut a = db();
    a.seed_default_categories(&ctx("dev-a", 100)).unwrap();
    let c = card(&a);
    let mut inputs = template(&a, &c.id);
    inputs.push(CategoryFieldInput::new("Notes", InputKind::Text));
    a.update_category(
        &ctx("dev-a", 200),
        &c.id,
        &CategoryUpdate { fields: Some(inputs), ..Default::default() },
    )
    .unwrap();
    let mut b = db();
    b.seed_default_categories(&ctx("dev-b", 300)).unwrap();
    b.merge_remote(&a.snapshot().unwrap()).unwrap();
    // Same preset ids on both devices: no duplicates, and A's later edit wins over B's seed.
    assert_eq!(b.list_categories().unwrap().len(), a.list_categories().unwrap().len());
    assert_eq!(
        b.list_category_fields(&c.id).unwrap().len(),
        a.list_category_fields(&c.id).unwrap().len()
    );
}
