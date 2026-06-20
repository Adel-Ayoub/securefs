-- SecureFS baseline schema (V1). Idempotent so it both creates a fresh database
-- and adopts one previously initialized by the legacy init_db path. Runtime,
-- secret-keyed backfills (path_digest / parent_digest) and seed data (the admin
-- account and the /home root) are applied in Rust after migrations run, since
-- they depend on the live DB_PASS.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS fnode (
    id BIGSERIAL PRIMARY KEY,
    name BYTEA,
    path BYTEA,
    owner BYTEA,
    hash VARCHAR,
    parent VARCHAR,
    dir BOOLEAN,
    u VARCHAR,
    g VARCHAR,
    o VARCHAR,
    children VARCHAR[],
    encrypted_name VARCHAR,
    file_group VARCHAR,
    size_bytes BIGINT DEFAULT 0,
    created_at BIGINT DEFAULT 0,
    modified_at BIGINT DEFAULT 0,
    link_target VARCHAR,
    path_digest BYTEA,
    parent_digest BYTEA
);

CREATE TABLE IF NOT EXISTS groups (
    id BIGSERIAL PRIMARY KEY,
    users VARCHAR[],
    g_name VARCHAR UNIQUE
);

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    user_name VARCHAR,
    group_name VARCHAR,
    key VARCHAR,
    salt VARCHAR,
    is_admin BOOLEAN,
    totp_secret VARCHAR DEFAULT NULL,
    totp_last_step BIGINT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts BIGINT NOT NULL,
    event VARCHAR(64) NOT NULL,
    username VARCHAR(64) NOT NULL,
    resource VARCHAR(512) NOT NULL,
    result VARCHAR(256) NOT NULL,
    ip VARCHAR(45)
);

-- Adopt databases created by an older schema that lacked these columns.
ALTER TABLE fnode ADD COLUMN IF NOT EXISTS size_bytes BIGINT DEFAULT 0;
ALTER TABLE fnode ADD COLUMN IF NOT EXISTS created_at BIGINT DEFAULT 0;
ALTER TABLE fnode ADD COLUMN IF NOT EXISTS modified_at BIGINT DEFAULT 0;
ALTER TABLE fnode ADD COLUMN IF NOT EXISTS link_target VARCHAR;
ALTER TABLE fnode ADD COLUMN IF NOT EXISTS path_digest BYTEA;
ALTER TABLE fnode ADD COLUMN IF NOT EXISTS parent_digest BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR DEFAULT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT;

-- Identity columns must never be null.
ALTER TABLE users ALTER COLUMN user_name SET NOT NULL;
ALTER TABLE groups ALTER COLUMN g_name SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_fnode_path_digest ON fnode(path_digest);
CREATE INDEX IF NOT EXISTS idx_fnode_parent_digest ON fnode(parent_digest);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_user_name ON users(user_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts DESC);

-- user -> group reference: a rename propagates; deleting a group nulls its
-- members' group_name rather than cascading into user deletion.
DO $$ BEGIN
    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_group_name_fkey;
    ALTER TABLE users ADD CONSTRAINT users_group_name_fkey
        FOREIGN KEY (group_name) REFERENCES groups(g_name)
        ON UPDATE CASCADE ON DELETE SET NULL;
END $$;
