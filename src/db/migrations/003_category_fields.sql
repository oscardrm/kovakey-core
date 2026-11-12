-- Schema v3: categories absorb the former rigid item types. A category may carry the key of the
-- built-in preset it was seeded from, and owns an editable form template (category_fields).
-- Core fields (is_core = 1) are required by the category's logic and cannot be deleted.

ALTER TABLE categories ADD COLUMN preset TEXT;

CREATE TABLE category_fields (
    id           TEXT PRIMARY KEY,
    category_id  TEXT NOT NULL REFERENCES categories(id),
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL,           -- an InputKind storage id
    is_secret    INTEGER NOT NULL DEFAULT 0 CHECK (is_secret IN (0,1)),
    is_core      INTEGER NOT NULL DEFAULT 0 CHECK (is_core IN (0,1)),
    sort_order   INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL,
    updated_by   TEXT NOT NULL DEFAULT '',
    deleted_at   INTEGER
) STRICT;
CREATE INDEX idx_category_fields_category ON category_fields(category_id);
