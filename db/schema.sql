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

-- Schema will be implemented in subsequent commits
