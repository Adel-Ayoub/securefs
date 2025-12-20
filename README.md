# SecureFS

A secure distributed file system implemented in Rust with client-server architecture.

## Installation

```sh
# Clone
git clone https://github.com/Adel-Ayoub/securefs.git
cd securefs

# Start database
docker-compose up -d

# Build
cargo build --release

# Run server
cargo run --bin securefs-server

# Run client (in new terminal)
cargo run --bin securefs
```

---

## Requirements

- Rust 1.70+
- PostgreSQL 13+
- Docker and Docker Compose

---

## Features

### Completed Features

#### Core File System Operations
- **File CRUD**: Create, read, update, delete files and directories
- **Directory Navigation**: cd, pwd, ls commands
- **File Operations**: mkdir, touch, mv, delete, cat, echo
- **Recursive Copy**: Copy files and directories with `cp` command
- **File Search**: Find files by pattern with recursive search

#### Security & Encryption
- **End-to-End Encryption**: AES-256-GCM encryption for all messages
- **Key Exchange**: X25519 ECDH for secure key establishment
- **Password Hashing**: Argon2 for secure password storage
- **Database Encryption**: PostgreSQL pgcrypto for metadata encryption
- **Integrity Checking**: BLAKE3 hash verification with `scan` command

#### Permission System
- **Unix-style Permissions**: Owner/group/other with rwx bits
- **Permission Management**: chmod command support
- **Access Control**: Read/write/execute permission checks

#### User & Group Management
- **User Creation**: Admin can create new users
- **Group Management**: Create and manage groups
- **Admin Tools**: lsusers, lsgroups commands
- **Authentication**: Secure login/logout with session management

### Planned Features
- Group Permission Checks: Group-based access control
- File Metadata: Size and timestamp support
- Large File Streaming: Efficient handling of large files
- Command History: Up/down arrow navigation
- Tab Completion: Path auto-completion

---

## Commands

### File System Operations
| Command | Description |
|---------|-------------|
| `ls` | List directory contents |
| `cd <path>` | Change directory |
| `pwd` | Print working directory |
| `mkdir <name>` | Create directory |
| `touch <name>` | Create empty file |
| `mv <src> <dst>` | Move/rename file or directory |
| `delete <name>` | Delete file or directory |
| `cat <file>` | Display file contents |
| `echo <content> <file>` | Write content to file |
| `cp <src> <dst>` | Copy file or directory (recursive) |
| `find <pattern>` | Search for files by name pattern |

### Permissions & Security
| Command | Description |
|---------|-------------|
| `chmod <mode> <name>` | Change file permissions |
| `scan <file>` | Verify file integrity |

### User Management (Admin)
| Command | Description |
|---------|-------------|
| `newuser <user> <pass> <group>` | Create new user |
| `newgroup <name>` | Create new group |
| `lsusers` | List all users |
| `lsgroups` | List all groups |

### Session
| Command | Description |
|---------|-------------|
| `login <user> <pass>` | Authenticate with server |
| `logout` | End session |

---

## Usage Examples

### Server Setup
```sh
# Start PostgreSQL database
docker-compose up -d

# Initialize schema (automatic on first run)
# Default admin credentials: admin / password

# Start server
cargo run --bin securefs-server
# Server listening on 127.0.0.1:8080
```

### Client Usage
```sh
# Connect to server
cargo run --bin securefs
# Connected to 127.0.0.1:8080

# Login
> login admin password
# Logged in successfully

# Basic operations
> pwd
/home/admin

> ls
drwxrwxrwx admin

> mkdir projects
> cd projects
> touch README.md
> echo "Hello SecureFS" README.md
> cat README.md
Hello SecureFS

# Copy operations
> cp README.md backup.md
> cp -r projects archive

# Search files
> find README
/home/admin/projects/README.md
/home/admin/projects/backup.md

# Check integrity
> scan README.md
Ensured integrity of README.md!

# Permission management
> chmod 750 README.md
> ls
-rwxr-x--- admin README.md

# Logout
> logout
```

---

## Architecture

### System Overview

![Architecture Overview](docs/Architecture.png)

SecureFS implements a client-server architecture with end-to-end encryption, separating the system into **untrusted** (Client, OS) and **trusted** (Server, Database, Docker) environments.

### UML Diagrams

#### Class Diagram

![Class Diagram](docs/class_diagram.png)

Shows the complete system architecture including:
- **Model Package**: Protocol classes (AppMessage, FNode, User, Group, Cmd enum)
- **DAO Layer**: All 23 database operations
- **Database Tables**: PostgreSQL schema (fnode, users, groups)
- **Client & Server**: Communication components

#### Sequence Diagram

![Sequence Diagram](docs/sequence_diagram.png)

Illustrates the high-level communication flow:
- WebSocket connection establishment
- X25519 Diffie-Hellman key exchange
- Encrypted message loop between Client, Server, and Database

#### Use Case Diagram

![Use Case Diagram](docs/usecase_diagram.png)

Documents all system capabilities:
- **File System Operations**: ls, cd, pwd, mkdir, touch, cat, echo, mv, delete, cp, find
- **Security Operations**: chmod, scan, encryption, key exchange
- **User Management**: login, logout, user/group management
- **Permission System**: Read/write/execute checks, access control


---

## Security Features

### Encryption
- **Transport**: All WebSocket messages encrypted with AES-256-GCM
- **Key Exchange**: X25519 Elliptic Curve Diffie-Hellman
- **Session Keys**: Unique per-connection ephemeral keys
- **Database**: Sensitive fields encrypted with pgcrypto

### Authentication
- **Password Storage**: Argon2id with salt
- **Session Management**: Stateful server-side authentication
- **Access Control**: Unix-style permission enforcement

### Integrity
- **File Hashing**: BLAKE3 for content verification
- **Corruption Detection**: `scan` command for integrity checks
- **Audit Trail**: Server-side logging

---

## Configuration

### Environment Variables
```sh
# Server
export SERVER_ADDR=127.0.0.1:8080
export DB_PASS=securefs

# Client
export SERVER_ADDR=127.0.0.1:8080
```

### Database
```sh
# Connection (see docker-compose.yml)
Host: localhost
Port: 5431
Database: securefs
User: securefs_user
Password: securefs_password
```

---

## Testing

### Run All Tests
```sh
cargo test --workspace
```

### Individual Test Suites
```sh
# Authentication roundtrip
cargo test --package securefs-server --test dao_auth

# Recursive copy
cargo test --package securefs-server --test cp_test

# File search
cargo test --package securefs-server --test find_test

# Integrity checking
cargo test --package securefs-server --test scan_test
```
---

## Future Improvements

- [x] Basic file operations (ls, cd, mkdir, etc.)
- [x] Unix-style permissions
- [x] User and group management
- [x] End-to-end encryption
- [x] Recursive copy and search
- [x] Integrity verification
- [x] Integration test suite
- [ ] Group permission checks
- [ ] File metadata (size, timestamps)
- [ ] chown/chgrp commands
- [ ] Large file streaming
- [ ] Command history & tab completion

---

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
