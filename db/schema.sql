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
    encrypted_name VARCHAR
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
INSERT INTO users (id, user_name, key, salt, is_admin) VALUES (
    0,
    'admin',
    pgp_sym_encrypt('[200,87,79,201,112,11,113,60,116,203,21,239,45,147,162,69,17,97,14,36,219,66,33,153,97,215,153,50,84,47,97,184]', 'TEMP'),
    '$argon2id$v=19$m=19456,t=2,p=1$2x+D890DlNldiUEFWj6osA$xCXFoO12ImKyfo9B9VNcMx+fJcexMcvQ7Z4f7BmF5do',
    true
);

INSERT INTO fnode (name, path, owner, hash, parent, dir, u, g, o, children, encrypted_name) VALUES (
    pgp_sym_encrypt('home', 'TEMP'),
    pgp_sym_encrypt('/home', 'TEMP'),
    pgp_sym_encrypt('admin', 'TEMP'),
    '',
    '/',
    true,
    '7', '5', '5',
    ARRAY[]::VARCHAR[],
    'home'
);
