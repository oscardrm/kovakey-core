-- Schema v2: every syncable record carries its last writer (`updated_by`) and a tombstone, so
-- the whole vault round-trips through a merge `Snapshot` without loss (ADR 0001).
-- Legacy v1 rows get an empty device id, which sorts below any real device id.

ALTER TABLE vault_meta  ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE categories  ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE tags        ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE item_tags   ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE item_fields ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE item_fields ADD COLUMN deleted_at INTEGER;
ALTER TABLE note_blocks ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';

-- Two devices can create a tag with the same name concurrently; both rows must be storable after
-- a merge. Uniqueness for new tags is enforced by the CRUD layer instead.
DROP INDEX idx_tags_name;
CREATE INDEX idx_tags_name ON tags(name) WHERE deleted_at IS NULL;
