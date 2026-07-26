-- Plan 2b. Sync needs one monotonic sequence shared by every syncable row.
--
-- A per-table counter cannot work: a shared collection's items are visible to
-- several users at once, so "what changed since I last synced" has to be a
-- single ordering across the whole database, not per user and not per table.
-- SQLite tolerates one writer, so a single-row counter advanced inside each
-- write transaction is exactly as concurrent as the database already is.
CREATE TABLE revision_sequence (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL
);

INSERT INTO revision_sequence (id, value)
VALUES (1, (
    SELECT COALESCE(MAX(revision), 0)
    FROM (SELECT revision FROM items UNION ALL SELECT revision FROM folders)
));

-- items.folder_id is removed for the same reason `type` never became a column:
-- a plaintext column recording which items are grouped together tells the
-- server something the encrypted body already carries. folderId lives inside
-- the encrypted item body and the client reads it after decrypting.
--
-- This is a table rebuild rather than ALTER TABLE ... DROP COLUMN because
-- SQLite refuses to drop a column named in a FOREIGN KEY clause, and
-- folder_id is one. Nothing references items, so the drop-and-rename is safe.
CREATE TABLE items_new (
    id               TEXT PRIMARY KEY,
    owner_user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    collection_id    TEXT REFERENCES collections(id) ON DELETE CASCADE,
    ciphertext       TEXT NOT NULL,
    wrapped_item_key TEXT NOT NULL,
    revision         INTEGER NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    deleted_at       TEXT
);

INSERT INTO items_new (id, owner_user_id, collection_id, ciphertext,
                       wrapped_item_key, revision, created_at, updated_at, deleted_at)
SELECT id, owner_user_id, collection_id, ciphertext,
       wrapped_item_key, revision, created_at, updated_at, deleted_at
FROM items;

DROP TABLE items;
ALTER TABLE items_new RENAME TO items;

-- Both sync paths: personal items are found by owner, collection items by
-- collection, and both are filtered on revision > since.
CREATE INDEX items_owner_revision ON items (owner_user_id, revision);
CREATE INDEX items_collection_revision ON items (collection_id, revision);
CREATE INDEX folders_user_revision ON folders (user_id, revision);

-- A pending grant has to record which role it will confer. Without this the
-- fulfilling client has to guess, and every grant silently becomes a member.
ALTER TABLE pending_grants ADD COLUMN role TEXT NOT NULL DEFAULT 'member';
