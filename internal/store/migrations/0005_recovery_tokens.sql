-- A recovery token is minted when a caller proves possession of a recovery
-- code, and spent when they upload the new credentials it authorizes. It is
-- the invites table's shape on purpose: hashed at rest, single use, expiring.
-- One mechanism for "a bearer string that works once, briefly" is enough.
CREATE TABLE recovery_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
);

CREATE INDEX recovery_tokens_user ON recovery_tokens (user_id);
