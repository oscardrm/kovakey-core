use super::common::{ctx, login};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use vault_core::{db::VaultStore, Error};

// Included twice by `passkeys.rs`: once per `VaultStore` backend. `Store` and `db()` come from there.

const CDH: [u8; 32] = [0x42; 32];

fn register(d: &mut Store, item: Option<&str>, now: i64, handle: &[u8]) -> vault_core::ops::PasskeyRegistration {
    d.register_passkey(&ctx("dev-a", now), item, "Example.com", "ana@example.test", handle, &CDH)
        .unwrap()
}

/// Public key from the COSE key inside the registration's authenticator data.
fn public_key(reg: &vault_core::ops::PasskeyRegistration) -> VerifyingKey {
    let a = &reg.authenticator_data;
    let cred_len = u16::from_be_bytes([a[53], a[54]]) as usize;
    let cose = &a[55 + cred_len..];
    assert_eq!(cose.len(), 77);
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&cose[10..42]);
    sec1.extend_from_slice(&cose[45..77]);
    VerifyingKey::from_sec1_bytes(&sec1).unwrap()
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` -> fixed 64-byte form.
fn der_to_sig(der: &[u8]) -> Signature {
    let mut i = 2;
    let mut raw = Vec::new();
    for _ in 0..2 {
        let len = der[i + 1] as usize;
        let int: Vec<u8> = der[i + 2..i + 2 + len].iter().skip_while(|&&b| b == 0).copied().collect();
        raw.extend(vec![0u8; 32 - int.len()]);
        raw.extend(int);
        i += 2 + len;
    }
    Signature::from_slice(&raw).unwrap()
}

#[test]
fn registration_creates_a_login_item_and_a_valid_attestation() {
    let mut d = db();
    let reg = register(&mut d, None, 100, &[9; 16]);
    let item = d.get_item(&reg.item_id).unwrap();
    assert_eq!(item.summary.title, "example.com");
    assert_eq!(item.summary.url.as_deref(), Some("https://example.com"));
    assert_eq!(reg.credential_id.len(), 16);

    let a = &reg.authenticator_data;
    assert_eq!(&a[..32], Sha256::digest(b"example.com").as_slice());
    assert_eq!(a[32], 0x5d, "UP|UV|BE|BS|AT");
    assert_eq!(&a[33..37], &[0, 0, 0, 0], "sign count 0");
    assert_eq!(&a[55..71], reg.credential_id.as_slice());
    // The attestation object ends with the authenticator data.
    assert!(reg.attestation_object.ends_with(a));
    assert!(reg.attestation_object.starts_with(b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData"));

    let list = d.list_passkeys(&reg.item_id).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, reg.passkey_id);
    assert_eq!(list[0].rp_id, "example.com");
    assert_eq!(list[0].user_name, "ana@example.test");
    assert_eq!(list[0].user_handle, vec![9; 16]);
}

#[test]
fn assertion_signs_auth_data_and_client_data_hash_with_the_registered_key() {
    let mut d = db();
    let reg = register(&mut d, None, 100, &[9; 16]);
    let vk = public_key(&reg);
    let got = d.assert_passkey(&reg.passkey_id, &CDH).unwrap();
    assert_eq!(got.rp_id, "example.com");
    assert_eq!(got.credential_id, reg.credential_id);
    assert_eq!(got.user_handle, vec![9; 16]);
    assert_eq!(got.authenticator_data.len(), 37);
    assert_eq!(got.authenticator_data[32], 0x1d, "UP|UV|BE|BS");
    let msg = [got.authenticator_data.as_slice(), &CDH].concat();
    assert!(vk.verify(&msg, &der_to_sig(&got.signature)).is_ok());
    // Read-only: asserting twice changes nothing in the store.
    let before = d.snapshot().unwrap();
    d.assert_passkey(&reg.passkey_id, &CDH).unwrap();
    assert_eq!(d.snapshot().unwrap(), before);
}

#[test]
fn registration_on_an_existing_item_and_lookup_by_rp() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Example", "fake-1");
    let reg = register(&mut d, Some(&item), 200, &[1]);
    assert_eq!(reg.item_id, item);
    let other = d
        .register_passkey(&ctx("dev-a", 300), None, "other.test", "bo", &[2], &CDH)
        .unwrap();
    let found = d.passkeys_for_rp("EXAMPLE.com.").unwrap();
    assert_eq!(found.iter().map(|p| p.id.clone()).collect::<Vec<_>>(), [reg.passkey_id]);
    assert_eq!(d.passkeys_for_rp("other.test").unwrap()[0].id, other.passkey_id);
    assert!(d.passkeys_for_rp("nothing.test").unwrap().is_empty());
    assert!(d.passkeys_for_rp("not a domain").unwrap().is_empty());
}

#[test]
fn same_account_replaces_the_previous_passkey() {
    let mut d = db();
    let first = register(&mut d, None, 100, &[5; 8]);
    let second = register(&mut d, Some(&first.item_id), 200, &[5; 8]);
    let ids: Vec<_> = d.passkeys_for_rp("example.com").unwrap().into_iter().map(|p| p.id).collect();
    assert_eq!(ids, std::slice::from_ref(&second.passkey_id));
    assert_eq!(d.assert_passkey(&first.passkey_id, &CDH).err(), Some(Error::NotFound));
    let snap = d.snapshot().unwrap();
    let old = snap.passkeys.iter().find(|p| p.id == first.passkey_id).unwrap();
    assert!(old.deleted_at.is_some() && old.private_key.is_empty());
    // A different user handle is a different account: both stay.
    register(&mut d, Some(&first.item_id), 300, &[6; 8]);
    assert_eq!(d.passkeys_for_rp("example.com").unwrap().len(), 2);
}

#[test]
fn invalid_inputs_are_rejected_and_change_nothing() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-1");
    let before = d.snapshot().unwrap();
    let c = ctx("dev-a", 200);
    let bad: Vec<(&str, &[u8], &[u8])> = vec![
        ("not a domain", &[1], &CDH),
        ("https://example.com", &[1], &CDH),
        ("example.com", &[], &CDH),
        ("example.com", &[0; 65], &CDH),
        ("example.com", &[1], &[0; 16]),
    ];
    for (rp, handle, cdh) in bad {
        let r = d.register_passkey(&c, Some(&item), rp, "ana", handle, cdh);
        assert_eq!(r.err(), Some(Error::InvalidInput), "{rp:?}");
    }
    assert_eq!(
        d.register_passkey(&c, Some("ghost"), "example.com", "ana", &[1], &CDH).err(),
        Some(Error::NotFound)
    );
    assert_eq!(d.snapshot().unwrap(), before);
    let reg = register(&mut d, Some(&item), 300, &[1]);
    assert_eq!(d.assert_passkey(&reg.passkey_id, &[0; 31]).err(), Some(Error::InvalidInput));
    assert_eq!(d.assert_passkey("ghost", &CDH).err(), Some(Error::NotFound));
}

#[test]
fn trashed_items_hide_their_passkeys_until_restored() {
    let mut d = db();
    let reg = register(&mut d, None, 100, &[1]);
    d.trash_item(&ctx("dev-a", 200), &reg.item_id).unwrap();
    assert!(d.passkeys_for_rp("example.com").unwrap().is_empty());
    assert_eq!(d.assert_passkey(&reg.passkey_id, &CDH).err(), Some(Error::NotFound));
    // A trashed item is read-only: no new passkey on it.
    let r = d.register_passkey(&ctx("dev-a", 250), Some(&reg.item_id), "example.com", "x", &[2], &CDH);
    assert_eq!(r.err(), Some(Error::InvalidInput));
    d.restore_item(&ctx("dev-a", 300), &reg.item_id).unwrap();
    assert!(d.assert_passkey(&reg.passkey_id, &CDH).is_ok());
}

#[test]
fn delete_and_item_purge_tombstone_and_scrub_the_key() {
    let mut d = db();
    let reg = register(&mut d, None, 100, &[1]);
    d.delete_passkey(&ctx("dev-a", 200), &reg.passkey_id).unwrap();
    assert!(d.list_passkeys(&reg.item_id).unwrap().is_empty());
    assert_eq!(d.delete_passkey(&ctx("dev-a", 210), &reg.passkey_id).err(), Some(Error::NotFound));

    let other = register(&mut d, None, 300, &[2]);
    d.delete_item(&ctx("dev-a", 400), &other.item_id).unwrap();
    let snap = d.snapshot().unwrap();
    for p in &snap.passkeys {
        assert!(p.deleted_at.is_some() && p.private_key.is_empty(), "{p:?}");
    }
}

#[test]
fn debug_output_never_shows_key_or_account() {
    let mut d = db();
    register(&mut d, None, 100, &[1]);
    let snap = d.snapshot().unwrap();
    let key = format!("{:?}", snap.passkeys[0].private_key);
    let out = format!("{:?}", snap.passkeys);
    assert!(!out.contains("ana@example.test") && !out.contains("example.com"));
    assert!(!out.contains(key.trim_matches(['[', ']'])));
    let out = format!("{:?}", d.passkeys_for_rp("example.com").unwrap());
    assert!(!out.contains("ana@example.test") && !out.contains("example.com"));
    let reg = register(&mut d, None, 200, &[2]);
    let out = format!("{reg:?} {:?}", d.assert_passkey(&reg.passkey_id, &CDH).unwrap());
    assert!(!out.contains("example.com"));
}

#[test]
fn merge_carries_passkeys_and_lww_resolves_delete() {
    let mut a = db();
    let mut b = db();
    let reg = register(&mut a, None, 100, &[1]);
    b.merge_remote(&a.snapshot().unwrap()).unwrap();
    // B signs with the key that A created.
    let vk = public_key(&reg);
    let got = b.assert_passkey(&reg.passkey_id, &CDH).unwrap();
    let msg = [got.authenticator_data.as_slice(), &CDH].concat();
    assert!(vk.verify(&msg, &der_to_sig(&got.signature)).is_ok());

    b.delete_passkey(&ctx("dev-b", 400), &reg.passkey_id).unwrap();
    let (sa, sb) = (a.snapshot().unwrap(), b.snapshot().unwrap());
    a.merge_remote(&sb).unwrap();
    b.merge_remote(&sa).unwrap();
    for d in [&a, &b] {
        assert_eq!(d.assert_passkey(&reg.passkey_id, &CDH).err(), Some(Error::NotFound));
    }
    assert_eq!(a.snapshot().unwrap().passkeys, b.snapshot().unwrap().passkeys);
}

#[test]
fn merge_rejects_a_passkey_of_an_unknown_item() {
    let mut a = db();
    register(&mut a, None, 100, &[1]);
    let mut snap = a.snapshot().unwrap();
    snap.passkeys[0].item_id = "ghost".into();
    let mut b = db();
    assert!(b.merge_remote(&snap).is_err());
    assert!(b.snapshot().unwrap().passkeys.is_empty());
}
