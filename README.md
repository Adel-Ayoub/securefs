# SecureFS

A secure distributed file system implemented in Rust with client-server architecture.

## Overview

SecureFS provides a secure file system with Unix-style permissions, encryption, and WebSocket-based communication between client and server.

## Features

- **Authentication**: Argon2 password hashing and user authentication
- **File Operations**: Create, read, update, delete files and directories
- **Permissions**: Unix-style permission system (owner/group/other)
- **Encryption**: AES-256-GCM encryption for sensitive data
- **WebSocket Protocol**: Real-time communication between client and server
- **PostgreSQL Backend**: Persistent metadata storage with pgcrypto

## Architecture

- **Client**: Interactive CLI for file system operations
- **Server**: WebSocket server handling commands and database operations
- **Model**: Shared data structures and protocol definitions

## Getting Started

### Prerequisites

- Rust 1.70+
- PostgreSQL 13+
- Docker and Docker Compose (optional)

### Database Setup

Start the PostgreSQL database:

```bash
docker-compose up -d
```

Initialize the schema:

```bash
psql -h localhost -p 5431 -U USER -d db -f db/schema.sql
```

### Running the Server

```bash
cargo run --bin securefs-server
```

### Running the Client

```bash
cargo run --bin securefs-client
```

## Commands

- `login <username> <password>` - Authenticate with the server
- `logout` - End the session
- `pwd` - Print current working directory
- `ls` - List directory contents
- `cd <path>` - Change directory
- `mkdir <name>` - Create a directory
- `touch <name>` - Create an empty file
- `mv <src> <dst>` - Rename/move a file or directory
- `delete <name>` - Delete a file or directory
- `cat <file>` - Display file contents
- `echo <content> <file>` - Write content to a file
- `chmod <mode> <name>` - Change file permissions
- `newuser <username> <password> <group>` - Create a new user (admin)
- `newgroup <groupname>` - Create a new group (admin)

## Development

### Running Tests

```bash
cargo test
```

### Building

```bash
cargo build --release
```

## License

Apache-2.0
