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
    link_target VARCHAR
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

INSERT INTO groups (users, g_name) VALUES (ARRAY[]::VARCHAR[], 'admin_group');

INSERT INTO fnode (name, path, owner, hash, parent, dir, u, g, o, children, encrypted_name) VALUES (
    pgp_sym_encrypt('home', 'TEMP'),
    pgp_sym_encrypt('/home', 'TEMP'),
    pgp_sym_encrypt('admin', 'TEMP'),
    '',
    pgp_sym_encrypt('/', 'TEMP'),
    true,
    '7', '5', '5',
    ARRAY[]::VARCHAR[],
    'home'
);
