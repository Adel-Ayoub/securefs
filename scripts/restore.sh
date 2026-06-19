#!/usr/bin/env bash
# Restore a SecureFS backup produced by backup.sh: drops and recreates the
# database, restores it, and replaces the storage/ tree.
#
# DESTRUCTIVE. Stop the server first. The restore is only usable with the same
# DB_PASS/DATA_KEY that were in effect when the backup was taken.
#
#   usage: restore.sh <archive.tar.gz>
#   env: DB_HOST DB_PORT DB_NAME DB_USER DB_CONN_PASSWORD STORAGE_DIR PG_BIN
#        FORCE=1  - skip the confirmation prompt
set -euo pipefail

[ -n "${PG_BIN:-}" ] && export PATH="$PG_BIN:$PATH"

archive="${1:-}"
if [ -z "$archive" ] || [ ! -f "$archive" ]; then
  echo "usage: $0 <archive.tar.gz>" >&2
  exit 1
fi

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-securefs}"
DB_USER="${DB_USER:-securefs_user}"
STORAGE_DIR="${STORAGE_DIR:-storage}"
export PGPASSWORD="${DB_CONN_PASSWORD:-${DB_PASS:-}}"

for t in pg_restore dropdb createdb; do
  command -v "$t" >/dev/null 2>&1 || {
    echo "error: $t not found (set PG_BIN to your PostgreSQL bin dir)" >&2
    exit 1
  }
done

if [ "${FORCE:-0}" != 1 ]; then
  printf 'Drop and recreate database "%s" and replace "%s"? [y/N] ' "$DB_NAME" "$STORAGE_DIR"
  read -r ans
  case "$ans" in
    y | Y) ;;
    *)
      echo "aborted"
      exit 1
      ;;
  esac
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work"
[ -f "$work/db.dump" ] || {
  echo "error: archive is missing db.dump" >&2
  exit 1
}

dropdb --if-exists -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME"
createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -O "$DB_USER" "$DB_NAME"
pg_restore -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" "$work/db.dump"

rm -rf "$STORAGE_DIR"
mkdir -p "$STORAGE_DIR"
[ -f "$work/storage.tar" ] && tar -xf "$work/storage.tar" -C "$STORAGE_DIR"

echo "restored database '$DB_NAME' and storage '$STORAGE_DIR' from $archive"
