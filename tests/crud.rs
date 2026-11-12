//! Integration tests: CRUD layer, tagger wiring, password history and tombstones.
//!
//! The same scenarios (`suites/crud.rs`) run against both `VaultStore` backends, so the SQLCipher
//! database and the portable in-memory store cannot drift apart.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

mod sqlcipher {
    use super::common;
    use vault_core::db::Database as Store;

    fn db() -> Store {
        common::db()
    }

    include!("suites/crud.rs");
}

mod memory {
    use vault_core::mem_store::MemStore as Store;

    fn db() -> Store {
        Store::new()
    }

    include!("suites/crud.rs");
}
