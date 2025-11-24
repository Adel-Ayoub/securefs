-- SecureFS Database Schema
-- PostgreSQL setup with required extensions

-- Enable pgcrypto extension for encryption functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Enable uuid-ossp extension for UUID generation (if needed)
-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- TABLE STRUCTURE PLANNING
-- =====================================================

-- Users table: Authentication and user management
-- - id: Unique identifier
-- - username: Unique username
-- - password_hash: Argon2 password hash
-- - salt: Salt used for password hashing
-- - is_admin: Administrative privileges flag
-- - created_at: Account creation timestamp
-- - last_login: Last login timestamp

-- Groups table: Group management and membership
-- - id: Unique identifier
-- - name: Unique group name
-- - owner_id: User ID of group creator/owner
-- - members: Array of user IDs in the group
-- - created_at: Group creation timestamp

-- Users table: Authentication and user management
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE
);

-- Create index on username for fast lookups during authentication
CREATE INDEX idx_users_username ON users(username);

-- fnode table: File/directory metadata
-- - id: Unique identifier
-- - name: Encrypted file/directory name
-- - path: Encrypted full path
-- - is_directory: Directory flag
-- - size: File size in bytes (0 for directories)
-- - owner_id: User ID of owner
-- - group_id: Group ID of owner
-- - permissions: Unix-style permissions (octal)
-- - created_at: Creation timestamp
-- - modified_at: Last modification timestamp
-- - parent_id: Parent directory ID (NULL for root)

-- Groups table: Group management and membership
CREATE TABLE groups (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    members BIGINT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create index on group name for fast lookups
CREATE INDEX idx_groups_name ON groups(name);

-- Create index on owner_id for group ownership queries
CREATE INDEX idx_groups_owner_id ON groups(owner_id);

-- fnode table: File/directory metadata storage
CREATE TABLE fnode (
    id BIGSERIAL PRIMARY KEY,
    encrypted_name BYTEA NOT NULL,        -- Encrypted file/directory name
    encrypted_path BYTEA NOT NULL,        -- Encrypted full path
    is_directory BOOLEAN NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,       -- File size in bytes (0 for directories)
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    permissions INTEGER NOT NULL,          -- Unix-style permissions (octal, e.g., 0755)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    parent_id BIGINT REFERENCES fnode(id) ON DELETE CASCADE
);

-- Create indexes for efficient file system operations
CREATE INDEX idx_fnode_encrypted_path ON fnode(encrypted_path);
CREATE INDEX idx_fnode_parent_id ON fnode(parent_id);
CREATE INDEX idx_fnode_owner_id ON fnode(owner_id);
CREATE INDEX idx_fnode_group_id ON fnode(group_id);
CREATE INDEX idx_fnode_is_directory ON fnode(is_directory);

-- Add constraint to ensure root has no parent
ALTER TABLE fnode ADD CONSTRAINT chk_root_no_parent
    CHECK (parent_id IS NOT NULL OR encrypted_path = '\x2f'); -- '/' in hex
