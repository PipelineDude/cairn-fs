#!/usr/bin/env bash
# the documentation must be EXECUTABLE.
#
# Every cairn invocation below is copy-pasted from README.md / OPERATING.md with
# only paths/passwords substituted. If you change an example in the docs, change
# it here too — this gate exists because the docs once drifted into sequences
# that failed at every step (FINDINGS F-4: flag order, init without password,
# key model pinned at init).
#
# Usage: tests/docs_smoke.sh [path-to-cairn-binary]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
[ -x "$BIN" ] || BIN="$(realpath "$REPO/target/debug/cairn")"
[ -x "$BIN" ] || { echo "[FAIL] cairn binary not found"; exit 1; }
GEN="$(dirname "$BIN")/gen_keys"
[ -x "$GEN" ] || { echo "[FAIL] gen_keys not found next to cairn"; exit 1; }

W="$(mktemp -d /tmp/cairn-docs.XXXXXX)"
trap 'mountpoint -q "$W/mnt" 2>/dev/null && fusermount -u "$W/mnt"; sleep 0.5; rm -rf "$W"' EXIT
export CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"
unset CAIRN_PASSWORD || true

PASSED=0; FAILED=0
ok()   { PASSED=$((PASSED+1)); echo "  [ok] $1"; }
fail() { FAILED=$((FAILED+1)); echo "  [FAIL] $1"; }

cd "$W"
mkdir -p src/docs_data mnt
echo "readme quick start data" > src/docs_data/doc.txt
head -c 20000 /dev/urandom > src/docs_data/big.bin
( "$GEN" >/dev/null 2>&1 )   # → priv.pem, pub.pem  (README step 2)

echo "== README Quick Start (steps 3-7, verbatim shapes) =="
"$BIN" mybackup.db init --password "a-strong-passphrase" --pub-key pub.pem >/dev/null 2>&1 \
    && ok "step 3: init --password --pub-key" || fail "step 3: init"
"$BIN" mybackup.db backup "$W/src/docs_data" /docs --password "a-strong-passphrase" --pub-key pub.pem >/dev/null 2>&1 \
    && ok "step 4: backup with trailing global flags" || fail "step 4: backup"
if command -v fusermount >/dev/null 2>&1; then
    "$BIN" mybackup.db mount "$W/mnt" --password "a-strong-passphrase" --pub-key pub.pem --priv-key priv.pem >/dev/null 2>&1 &
    MNT_PID=$!
    for _ in $(seq 1 30); do mountpoint -q "$W/mnt" && break; sleep 0.5; done
    ls "$W/mnt" >/dev/null 2>&1 && ok "step 5: mount + ls" || fail "step 5: mount + ls"
    fusermount -u "$W/mnt" 2>/dev/null || true
    for _ in $(seq 1 30); do kill -0 "$MNT_PID" 2>/dev/null || break; sleep 0.5; done
else
    echo "  [skip] fusermount not available"
fi
rm -rf "$W/restored"
"$BIN" mybackup.db restore "$W/restored" --password "a-strong-passphrase" --pub-key pub.pem --priv-key priv.pem >/dev/null 2>&1 \
    && cmp -s src/docs_data/doc.txt "$W/restored/docs/doc.txt" \
    && ok "step 6: restore (content byte-exact)" || fail "step 6: restore"
"$BIN" mybackup.db check --password "a-strong-passphrase" --pub-key pub.pem --priv-key priv.pem >/dev/null 2>&1 \
    && ok "step 7: check" || fail "step 7: check"

echo "== README symmetric quick start =="
"$BIN" simple.db init --password "a-strong-passphrase" >/dev/null 2>&1 \
    && ok "symmetric init --password" || fail "symmetric init"
"$BIN" simple.db backup "$W/src/docs_data" /backup --password "a-strong-passphrase" >/dev/null 2>&1 \
    && ok "symmetric backup" || fail "symmetric backup"

echo "== README init combo + --disable-dedup =="
"$BIN" combo.db init --pub-key pub.pem --crypto-algo aes-256-gcm --comp-algo zstd \
    --index-sync-interval 300 --inline-max-size 4096 --password "a-strong-passphrase" >/dev/null 2>&1 \
    && ok "init with algo/interval/inline flags" || fail "init combo"
"$BIN" nodedup.db init --disable-dedup --password "a-strong-passphrase" >/dev/null 2>&1 \
    && ok "init --disable-dedup" || fail "init --disable-dedup"

echo "== README extract shapes (literal --file-path vs --glob) =="
rm -rf "$W/x1" "$W/x2"; mkdir "$W/x1" "$W/x2"
"$BIN" mybackup.db extract "$W/x1" --file-path "/docs/doc.txt" --password "a-strong-passphrase" --pub-key pub.pem --priv-key priv.pem >/dev/null 2>&1 \
    && [ -f "$W/x1/doc.txt" ] && ok "extract --file-path (literal, lands at <dest>/<basename>)" || fail "extract --file-path"
"$BIN" mybackup.db extract "$W/x2" --glob "/docs/*.txt" --password "a-strong-passphrase" --pub-key pub.pem --priv-key priv.pem >/dev/null 2>&1 \
    && [ -f "$W/x2/docs/doc.txt" ] && ok "extract --glob (wildcard)" || fail "extract --glob"

echo "== README snapshots & retention =="
"$BIN" mybackup.db snapshot create "Before system update" --password "a-strong-passphrase" --pub-key pub.pem >/dev/null 2>&1 \
    && ok "snapshot create" || fail "snapshot create"
"$BIN" mybackup.db snapshot ls --password "a-strong-passphrase" --pub-key pub.pem >/dev/null 2>&1 \
    && ok "snapshot ls" || fail "snapshot ls"
"$BIN" mybackup.db snapshot prune --keep-daily 7 --keep-weekly 4 --keep-monthly 12 --password "a-strong-passphrase" --pub-key pub.pem --priv-key priv.pem >/dev/null 2>&1 \
    && ok "snapshot prune --keep-*" || fail "snapshot prune"
"$BIN" mybackup.db gc --grace-period-hours 24 --password "a-strong-passphrase" --pub-key pub.pem --priv-key priv.pem >/dev/null 2>&1 \
    && ok "gc --grace-period-hours" || fail "gc"

echo "== OPERATING runbook (§1-§6 shapes) =="
export CAIRN_PASSWORD='a-strong-index-password'
"$BIN" backup.db init --pub-key pub.pem >/dev/null 2>&1 \
    && ok "§1 init --pub-key (env password)" || fail "§1 init"
"$BIN" backup.db backup "$W/src/docs_data" /data --pub-key pub.pem >/dev/null 2>&1 \
    && ok "§2 backup, exit code authoritative" || fail "§2 backup"
"$BIN" backup.db snapshot create "$(date -I)" --pub-key pub.pem >/dev/null 2>&1 \
    && ok "§2 snapshot create" || fail "§2 snapshot"
"$BIN" backup.db verify --pub-key pub.pem --priv-key priv.pem >/dev/null 2>&1 \
    && ok "§3 verify" || fail "§3 verify"
rm -rf "$W/drill"
"$BIN" backup.db extract "$W/drill" --priv-key priv.pem --pub-key pub.pem >/dev/null 2>&1 \
    && diff -r "$W/src/docs_data" "$W/drill/data" >/dev/null 2>&1 \
    && ok "§4 restore drill + diff -r" || fail "§4 restore drill"
rm -f share_*.bin
( "$GEN" split priv.pem 2 3 >/dev/null 2>&1 ) \
    && ( "$GEN" combine "$W/recovered.pem" share_1.bin share_3.bin >/dev/null 2>&1 ) \
    && ok "§5 gen_keys split/combine" || fail "§5 shamir"
"$BIN" backup.db append-only --pub-key pub.pem >/dev/null 2>&1 \
    && ok "§6 append-only" || fail "§6 append-only"
"$BIN" backup.db status --pub-key pub.pem >/dev/null 2>&1 \
    && ok "§7 status" || fail "§7 status"
unset CAIRN_PASSWORD

echo
echo "docs_smoke: passed $PASSED, failed $FAILED"
if [ "$FAILED" = 0 ]; then echo "DOCS SMOKE: PASS"; exit 0; else echo "DOCS SMOKE: FAIL"; exit 1; fi
