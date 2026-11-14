-- Schema v6: encrypted file attachments (ADR 0019). Metadata merges last-writer-wins like any child
-- record; `data` is blanked when the row is tombstoned. Everything lives inside the SQLCipher file.

CREATE TABLE attachments (
    id          TEXT PRIMARY KEY,
    item_id     TEXT NOT NULL REFERENCES items(id),
    file_name   TEXT NOT NULL,
    mime_type   TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size        INTEGER NOT NULL,
    data        BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT NOT NULL DEFAULT '',
    deleted_at  INTEGER
) STRICT;
CREATE INDEX idx_attachments_item ON attachments(item_id) WHERE deleted_at IS NULL;
