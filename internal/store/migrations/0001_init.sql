-- Keyhole initial schema. See spec section 4.2.
--
-- Every column holding client-produced key material stores an opaque string
-- exactly as received. The server never parses these.

CREATE TABLE users (
    id                          TEXT PRIMARY KEY,
    email                       TEXT NOT NULL,
    name                        TEXT NOT NULL,
    role                        TEXT NOT NULL CHECK (role IN ('admin','user')),
    status                      TEXT NOT NULL CHECK (status IN ('pending','active','disabled')),

    -- Populated at enrollment. NULL while the account is pending.
    kdf_salt                    TEXT,
    kdf_params                  TEXT,
    auth_hash                   TEXT,
    protected_user_key          TEXT,
    recovery_protected_user_key TEXT,
    recovery_salt               TEXT,
    recovery_kdf_params         TEXT,
    public_key                  TEXT,
    encrypted_private_key       TEXT,

    revision                    INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT NOT NULL,
    updated_at                  TEXT NOT NULL
);

-- Case-insensitive uniqueness: a user considers Person@example.com and
-- person@example.com the same address, so the database must too.
--
-- classifyUserInsertError in internal/store/users.go maps SQLITE_CONSTRAINT_UNIQUE
-- from a users insert straight to ErrEmailTaken, which is only sound while this
-- is the sole UNIQUE constraint on the table. Adding a second one means teaching
-- that function to tell them apart first.
CREATE UNIQUE INDEX users_email_unique ON users (lower(email));

CREATE TABLE invites (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
);

CREATE INDEX invites_user ON invites (user_id);

CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    refresh_hash TEXT NOT NULL UNIQUE,
    device_label TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    revoked_at   TEXT
);

CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE collections (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE TABLE collection_memberships (
    collection_id         TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sealed_collection_key TEXT NOT NULL,
    role                  TEXT NOT NULL CHECK (role IN ('member','manager')),
    granted_by            TEXT NOT NULL REFERENCES users(id),
    granted_at            TEXT NOT NULL,
    PRIMARY KEY (collection_id, user_id)
);

CREATE INDEX collection_memberships_user ON collection_memberships (user_id);

CREATE TABLE pending_grants (
    collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_by  TEXT NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL,
    PRIMARY KEY (collection_id, user_id)
);

CREATE TABLE folders (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_name TEXT NOT NULL,
    revision       INTEGER NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    deleted_at     TEXT
);

CREATE INDEX folders_user ON folders (user_id);

-- No `type` column: it lives inside the encrypted body so the server cannot
-- tell a login from a note, or count how many of each a user holds.
CREATE TABLE items (
    id               TEXT PRIMARY KEY,
    owner_user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    collection_id    TEXT REFERENCES collections(id) ON DELETE CASCADE,
    folder_id        TEXT REFERENCES folders(id) ON DELETE SET NULL,
    ciphertext       TEXT NOT NULL,
    wrapped_item_key TEXT NOT NULL,
    revision         INTEGER NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    deleted_at       TEXT
);

CREATE INDEX items_owner_revision ON items (owner_user_id, revision);
CREATE INDEX items_collection ON items (collection_id);

CREATE TABLE audit_log (
    id             TEXT PRIMARY KEY,
    actor_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
    action         TEXT NOT NULL,
    target         TEXT NOT NULL,
    metadata       TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);

CREATE INDEX audit_log_created ON audit_log (created_at);

CREATE TABLE server_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
