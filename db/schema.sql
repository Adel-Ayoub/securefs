-- Base table definitions. All seed data and migrations (added columns,
-- indexes, the admin account, the /home root) are owned by init_db so there is
-- a single source of truth applied on every boot.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE if not exists fnode  (
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
    path_digest BYTEA
);

CREATE TABLE groups (
    id BIGSERIAL PRIMARY KEY,
    users VARCHAR[],
    g_name VARCHAR UNIQUE
);

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    user_name VARCHAR,
    group_name VARCHAR REFERENCES groups(g_name),
    key VARCHAR,
    salt VARCHAR,
    is_admin BOOLEAN
);
