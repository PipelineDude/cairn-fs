#!/usr/bin/env bash
# short-lived CLI commands must never die on a signal.
#
# Background: with pool min_idle>0, checking out the only idle connection made
# r2d2 schedule a fire-and-forget background replenish — a SQLCipher KDF inside
# libcrypto on an r2d2-worker thread — which raced process exit and segfaulted
# in OpenSSL's atexit teardown (kernel: "r2d2-worker-1 segfault ... in
# libcrypto.so.3"; soak 2026-07-18 r049). One-shot commands now run min_idle=0.
#
# This gate hammers the exact observed shape (init --password-file) plus status,
# asserting every exit code < 128 (no signal deaths). Rare race → the more
# iterations the better: N defaults to 200 for the suite, override with
# STRESS_ITERS for nightly runs.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
[ -x "$BIN" ] || BIN="$(realpath "$REPO/target/debug/cairn")"
[ -x "$BIN" ] || { echo "[FAIL] cairn binary not found"; exit 1; }

N="${STRESS_ITERS:-200}"
W="$(mktemp -d /tmp/cairn-stress.XXXXXX)"
trap 'rm -rf "$W"' EXIT
export CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"  # fast KDF = more exit-races per second
echo "stress-pass" > "$W/pf.txt"

CRASHES=0
for i in $(seq 1 "$N"); do
    rm -f "$W/s.db" "$W/s.db-wal" "$W/s.db-shm" "$W/s.db.lock"
    env -u CAIRN_PASSWORD "$BIN" --password-file "$W/pf.txt" "$W/s.db" init \
        --inline-max-size 4096 >/dev/null 2>&1
    rc=$?
    [ "$rc" -ge 128 ] && { CRASHES=$((CRASHES+1)); echo "  [signal] init iter $i: exit $rc"; }
    env -u CAIRN_PASSWORD "$BIN" --password-file "$W/pf.txt" "$W/s.db" status >/dev/null 2>&1
    rc=$?
    [ "$rc" -ge 128 ] && { CRASHES=$((CRASHES+1)); echo "  [signal] status iter $i: exit $rc"; }
done

echo "stress_short_cmds: $((N * 2)) runs, $CRASHES signal deaths"
if [ "$CRASHES" -eq 0 ]; then echo "STRESS: PASS"; exit 0; else echo "STRESS: FAIL"; exit 1; fi
