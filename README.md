<p align="center">
  <h1 align="center">SecureFS</h1>
  <p align="center">An encrypted file system with client-server architecture, built in Rust.</p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-2021_edition-orange.svg" alt="Rust Edition">
  <img src="https://img.shields.io/badge/postgres-15-336791.svg" alt="PostgreSQL">
</p>

---

## Installation

```sh
git clone https://github.com/Adel-Ayoub/securefs.git
cd securefs

docker-compose up -d                  # start PostgreSQL
cargo build --release

cargo run --bin securefs-server       # server
cargo run --bin securefs              # client (new terminal)
```

---

## Architecture

<p align="center">
  <img src="docs/Architecture.png" alt="Architecture Overview" width="700">
</p>

SecureFS implements a client-server model over encrypted WebSocket channels. The client sends commands through an AES-256-GCM encrypted tunnel established via X25519 key exchange. The server processes file operations against a PostgreSQL database where all metadata is encrypted with pgcrypto.

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Transport | AES-256-GCM over WebSocket | Message confidentiality |
| Key Exchange | X25519 ECDH + HKDF-SHA256 | Ephemeral session keys |
| Authentication | Argon2id | Password hashing with rate limiting |
| Database | pgcrypto | Symmetric encryption for all metadata |
| Integrity | BLAKE3 | File corruption detection |

### Communication Flow

<p align="center">
  <img src="docs/sequence_diagram.png" alt="Communication Flow" width="600">
</p>

The client and server perform an X25519 ECDH handshake to derive a shared AES-256 key, then exchange encrypted messages over a long-lived WebSocket until the client disconnects.

---

## Usage

```sh
> login admin password            # default admin
> mkdir projects
> cd projects
> echo "Hello SecureFS" notes.md
> cat notes.md
> cp notes.md backup.md
> find notes
> scan notes.md                   # BLAKE3 integrity check
> chmod 750 notes.md
> logout
```

---

## Commands

| Category | Commands |
|----------|----------|
| File system | `ls`, `cd`, `pwd`, `mkdir`, `touch`, `cat`, `echo`, `mv`, `delete`, `cp`, `find` |
| Permissions | `chmod`, `chown`, `chgrp`, `scan` |
| User management (admin) | `newuser`, `newgroup`, `lsusers`, `lsgroups`, `add_user_to_group`, `remove_user_from_group` |
| Session | `login`, `logout` |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_ADDR` | `127.0.0.1:8080` | Server bind address |
| `DB_PASS` | `securefs` | Database password |
| `ALLOW_INSECURE` | — | Set to `1` to disable TLS requirement |

Database defaults (see `docker-compose.yml`): host `localhost`, port `5431`, database `securefs`, user `securefs_user`.

---

## Testing

```sh
cargo test --workspace            # requires PostgreSQL running
```

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.
