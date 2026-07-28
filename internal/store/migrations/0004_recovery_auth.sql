-- A recovery blob created before this migration was wrapped under the
-- undifferentiated recovery key, with no auth hash to check, so it cannot be
-- redeemed remotely. NULL marks exactly those, and the redeem endpoints treat
-- a NULL here identically to an unknown address.
ALTER TABLE users ADD COLUMN recovery_auth_hash TEXT;
