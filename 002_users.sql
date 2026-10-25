-- Adds user-management columns. Additive and repeatable: existing users, passwords and roles are untouched.
ALTER TABLE users ADD COLUMN IF NOT EXISTS name          TEXT        NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS active        BOOLEAN     NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER     NOT NULL DEFAULT 0;   -- bump to sign a user out everywhere
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login    TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at    TIMESTAMPTZ NOT NULL DEFAULT now();
