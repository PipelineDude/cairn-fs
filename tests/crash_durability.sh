#!/usr/bin/env bash
# Crash-durability tests for Cairn.
#
# For a backup tool the paramount property is: an abrupt crash (kill -9, power
# loss) NEVER corrupts the archive and NEVER destroys already-committed data.
# The in-progress operation may be incomplete, but the archive must still open,
# `check` must pass, and everything backed up BEFORE the crash must remain intact.
#
# This kills `backup`, `snapshot rollback` (which has a documented small
# non-atomic window) and `gc` at random moments and verifies the archive survives.
# CLI-only (no FUSE), so it is deterministic in a sandbox. Needs `dangerously...`
# for the background kill.  Usage: tests/crash_durability.sh [binary]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
[ -x "$BIN" ] || { BIN="$(realpath "${1:-$REPO/target/debug/cairn}")"; }
[ -x "$BIN" ] || { echo "[FAIL] binary not found: $BIN"; exit 1; }
export CAIRN_PASSWORD="crash-test-pass"
# Test speed: low SQLCipher KDF (data is throwaway). ~250x faster DB open. See
# CAIRN_KDF_ITER in the README/main.rs (production default is 256000).
export CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"

W="$(mktemp -d /tmp/cairn-crash.XXXXXX)"
trap 'pkill -x cairn 2>/dev/null; rm -rf "$W"' EXIT
PASSED=0; FAILED=0
ok()   { PASSED=$((PASSED+1)); printf '  [ok]   %s\n' "$1"; }
fail() { FAILED=$((FAILED+1)); printf '  [FAIL] %s\n' "$1"; }

CANARY="CANARY-committed-before-any-crash-$$"

# A known-good archive: one committed file + a snapshot, established BEFORE any
# crash. Every crash iteration must leave THIS intact.
db="$W/crash.db"
echo "$CANARY" > "$W/canary.txt"
"$BIN" "$db" init >/dev/null 2>&1
"$BIN" "$db" backup "$W/canary.txt" / >/dev/null 2>&1
"$BIN" "$db" snapshot create "safe" >/dev/null 2>&1

# Assert the archive is uncorrupted and pre-crash data survived.
check_intact() {
    local tag="$1"
    "$BIN" "$db" check >/dev/null 2>&1 || { fail "$tag: check failed (archive corrupt / won't open)"; return; }
    rm -rf "$W/co"; mkdir "$W/co"
    "$BIN" "$db" extract "$W/co" --file-path /canary.txt >/dev/null 2>&1
    if [ "$(cat "$W/co/canary.txt" 2>/dev/null)" = "$CANARY" ]; then
        ok "$tag: archive intact + committed data survived"
    else
        fail "$tag: committed canary lost/corrupted after crash"
    fi
}

echo "=== 1. kill -9 during backup (10 iterations, varied timing) ==="
mkdir -p "$W/src"
for i in $(seq 1 10); do
    # Fresh multi-MB payload so the backup runs long enough to be killed mid-flight.
    head -c 12000000 /dev/urandom > "$W/src/batch_$i.bin"
    "$BIN" "$db" backup "$W/src/batch_$i.bin" "/crash/$i" >/dev/null 2>&1 &
    pid=$!
    # Kill at a random point in [0.1s, 1.6s]: sometimes before, during, or after.
    sleep "0.$((RANDOM % 15 + 1))"
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    pkill -x cairn 2>/dev/null
    rm -f "$W/src/batch_$i.bin"
done
check_intact "1: after 10 backup kills"

echo "=== 2. kill -9 during snapshot rollback (documented non-atomic window) ==="
# Grow the archive so rollback has work to do, snapshot it, then crash a rollback.
head -c 12000000 /dev/urandom > "$W/src/more.bin"
"$BIN" "$db" backup "$W/src/more.bin" /more >/dev/null 2>&1
"$BIN" "$db" snapshot create "v2" >/dev/null 2>&1
for i in $(seq 1 5); do
    "$BIN" "$db" snapshot rollback 1 --i-accept-non-atomic >/dev/null 2>&1 &
    pid=$!
    sleep "0.$((RANDOM % 8 + 1))"
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    pkill -x cairn 2>/dev/null
done
# After crashed rollbacks the archive must still OPEN and check must pass (a
# consistent state must be recoverable — the pre-rollback auto-snapshot is the
# recovery path). The canary predates every snapshot, so it must be reachable.
check_intact "2: after 5 rollback kills"

echo "=== 3. kill -9 during gc ==="
for i in $(seq 1 5); do
    "$BIN" "$db" gc --grace-period-hours 0 >/dev/null 2>&1 &
    pid=$!
    sleep "0.$((RANDOM % 6 + 1))"
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    pkill -x cairn 2>/dev/null
done
check_intact "3: after 5 gc kills"

echo "=== 4. full verify after all crashes ==="
"$BIN" "$db" verify >/dev/null 2>&1 && ok "4: verify passes on the survived archive" || fail "4: verify reports unrestorable files"

echo "=========================================="
echo "Crash-durability complete. Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAILED"
