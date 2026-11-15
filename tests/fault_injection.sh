#!/usr/bin/env bash
# Write-failure (fault) injection for Cairn.
#
# The dangerous failure mode for a backup tool is to run out of disk (ENOSPC) or
# hit a permission error mid-backup and SILENTLY claim success while the data was
# never stored. The paramount property: a chunk-store write failure must make
# `backup` FAIL LOUDLY (non-zero exit), never lie; already-committed data must
# survive; the tool must be able to TELL you which files are incomplete (verify);
# and a retry once space/permission is restored must recover.
#
# Root/tmpfs is not required — we make the chunk-store cache directory read-only,
# which triggers the same "chunk write failed" path as ENOSPC.
# Usage: tests/fault_injection.sh [binary]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
[ -x "$BIN" ] || { BIN="$(realpath "${1:-$REPO/target/debug/cairn}")"; }
[ -x "$BIN" ] || { echo "[FAIL] binary not found: $BIN"; exit 1; }
export CAIRN_PASSWORD="fault-test-pass"
export CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"  # test speed: low KDF (throwaway data)

W="$(mktemp -d /tmp/cairn-fault.XXXXXX)"
CACHE="$W/fi.db_cache"
# Restore perms before cleanup or rm -rf can't remove the read-only cache.
trap 'chmod -R u+rwx "$CACHE" 2>/dev/null; rm -rf "$W"' EXIT
PASSED=0; FAILED=0
ok()   { PASSED=$((PASSED+1)); printf '  [ok]   %s\n' "$1"; }
fail() { FAILED=$((FAILED+1)); printf '  [FAIL] %s\n' "$1"; }

db="$W/fi.db"
mkdir -p "$W/src"
# Chunked (incompressible, > inline threshold) so data really goes to the cache
# store, not inline in the DB.
head -c 60000 /dev/urandom | base64 > "$W/src/canary.bin"
CANARY_SUM=$(sha256sum "$W/src/canary.bin" | cut -d' ' -f1)

head -c 60000 /dev/urandom | base64 > "$W/src/newfile.bin"
NEW_SUM=$(sha256sum "$W/src/newfile.bin" | cut -d' ' -f1)
"$BIN" "$db" init >/dev/null 2>&1
# DEST "/" so a single-file source lands at /<basename> (DEST is a directory prefix).
"$BIN" "$db" backup "$W/src/canary.bin" / >/dev/null 2>&1   # succeeds; populates cache

echo "=== 1. cache write failure -> backup fails LOUDLY (no silent success) ==="
chmod -R a-w "$CACHE" 2>/dev/null
"$BIN" "$db" backup "$W/src/newfile.bin" / >/dev/null 2>&1
rc=$?
# Restore write access immediately: a read-only cache dir also blocks cacache
# READS, so every check below must run against a readable cache.
chmod -R u+rwx "$CACHE" 2>/dev/null
[ "$rc" -ne 0 ] && ok "1a: backup exits non-zero on cache write failure (rc=$rc)" \
                || fail "1a: backup exited 0 despite a chunk write failure (SILENT loss)"

echo "=== 2. committed data survives the failed backup ==="
rm -rf "$W/o2"; mkdir "$W/o2"
"$BIN" "$db" extract "$W/o2" --file-path /canary.bin >/dev/null 2>&1
[ "$(sha256sum "$W/o2/canary.bin" 2>/dev/null | cut -d' ' -f1)" = "$CANARY_SUM" ] \
    && ok "2a: previously-committed file still byte-intact" || fail "2a: committed data lost/corrupted"

echo "=== 3. the tool KNOWS the archive is incomplete (does not pretend) ==="
# verify must report a problem (non-zero) — a half-written file must never be
# silently presented as restorable.
"$BIN" "$db" verify >/dev/null 2>&1 && fail "3a: verify reported all-OK despite an unstored file (lying)" \
                                    || ok "3a: verify flags the incomplete file (non-zero)"

echo "=== 4. retry after space/permission is restored recovers ==="
"$BIN" "$db" backup "$W/src/newfile.bin" / >/dev/null 2>&1
rc=$?
[ "$rc" -eq 0 ] && ok "4a: retry backup succeeds once cache is writable (rc=0)" || fail "4a: retry still failed (rc=$rc)"
rm -rf "$W/o4"; mkdir "$W/o4"
"$BIN" "$db" extract "$W/o4" --file-path /newfile.bin >/dev/null 2>&1
[ "$(sha256sum "$W/o4/newfile.bin" 2>/dev/null | cut -d' ' -f1)" = "$NEW_SUM" ] \
    && ok "4b: the file is now fully restorable after retry" || fail "4b: file still not restorable after retry"
"$BIN" "$db" verify >/dev/null 2>&1 && ok "4c: verify passes after retry (archive complete)" || fail "4c: verify still reports problems after retry"

echo "=========================================="
echo "Fault-injection complete. Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAILED"
