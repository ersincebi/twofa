#!/bin/sh
# Nightly pull of the encrypted vault onto the Raspberry Pi's backup SSD.
# The backup token can only read ciphertext; it can't decrypt or change anything.
set -eu

URL="${TWOFA_URL:-https://2fa.ersincebi.com}"
DIR="${TWOFA_BACKUP_DIR:-/mnt/backup/twofa}"
TOKEN_FILE="$HOME/.config/twofa/backup-token"

mkdir -p "$DIR"
tmp="$DIR/.vault.tmp"
curl -fsS --max-time 30 -H "Authorization: Bearer $(cat "$TOKEN_FILE")" "$URL/api/backup" -o "$tmp"
mv "$tmp" "$DIR/vault-$(date +%F).json"
chmod 600 "$DIR"/vault-*.json

# Keep 90 days of history.
find "$DIR" -name 'vault-*.json' -mtime +90 -delete
