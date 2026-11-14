//! Attachment behavior (ADR 0019), run against both `VaultStore` backends.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

mod sqlcipher {
    use super::common;
    use vault_core::db::Database as Store;

    fn db() -> Store {
        common::db()
    }

    include!("suites/attachments.rs");
}

mod memory {
    use vault_core::mem_store::MemStore as Store;

    fn db() -> Store {
        Store::new()
    }

    include!("suites/attachments.rs");
}
