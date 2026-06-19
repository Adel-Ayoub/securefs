#!/usr/bin/env bash
# Back up SecureFS: the Postgres database plus the storage/ blob tree, into one
# timestamped tarball under BACKUP_DIR. Prints the archive path on success.
#
# Secrets are deliberately NOT in the backup: without DB_PASS (pgcrypto/HMAC key)
# and DATA_KEY (file-content key) the data cannot be decrypted, so keep those
# safe separately. A restore needs the same DB_PASS/DATA_KEY used when the
# backup was taken.
#
# Env (same names the server reads):
#   DB_HOST DB_PORT DB_NAME DB_USER DB_CONN_PASSWORD
#   STORAGE_DIR (default: storage)   BACKUP_DIR (default: backups)
#   PG_BIN  - optional dir holding pg_dump when it is not already on PATH
set -euo pipefail

[ -n "${PG_BIN:-}" ] && export PATH="$PG_BIN:$PATH"

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-securefs}"
DB_USER="${DB_USER:-securefs_user}"
STORAGE_DIR="${STORAGE_DIR:-storage}"
BACKUP_DIR="${BACKUP_DIR:-backups}"
export PGPASSWORD="${DB_CONN_PASSWORD:-${DB_PASS:-}}"

command -v pg_dump >/dev/null 2>&1 || {
  echo "error: pg_dump not found (set PG_BIN to your PostgreSQL bin dir)" >&2
  exit 1
}

ts="$(date -u +%Y%m%dT%H%M%SZ)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pg_dump -Fc -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$work/db.dump"

if [ -d "$STORAGE_DIR" ]; then
  srcdir="$STORAGE_DIR"
else
  mkdir -p "$work/empty"
  srcdir="$work/empty"
fi
tar -cf "$work/storage.tar" -C "$srcdir" .

mkdir -p "$BACKUP_DIR"
out="$BACKUP_DIR/securefs-backup-$ts.tar.gz"
tar -czf "$out" -C "$work" db.dump storage.tar
echo "$out"
