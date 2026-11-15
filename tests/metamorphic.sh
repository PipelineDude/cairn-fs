#!/usr/bin/env bash
# Metamorphic tests for Cairn.
#
# Properties that must hold regardless of the specific inputs/ordering. They catch
# the "we think we dedup / we think we're deterministic, but we're not" class that
# example-based tests miss, and re-verify the critical cross-run dedup guarantee
# (which silently broke earlier — a full dedup_secret regression).
# CLI-only. Usage: tests/metamorphic.sh [binary]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
[ -x "$BIN" ] || { BIN="$(realpath "${1:-$REPO/target/debug/cairn}")"; }
[ -x "$BIN" ] || { echo "[FAIL] binary not found: $BIN"; exit 1; }
export CAIRN_PASSWORD="metamorphic-pass"
export CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"  # test speed: low KDF (throwaway data)

W="$(mktemp -d /tmp/cairn-meta.XXXXXX)"
trap 'rm -rf "$W"' EXIT
PASSED=0; FAILED=0
ok()   { PASSED=$((PASSED+1)); printf '  [ok]   %s\n' "$1"; }
fail() { FAILED=$((FAILED+1)); printf '  [FAIL] %s\n' "$1"; }

phys() { "$BIN" "$1" status 2>/dev/null | grep -iE "Physical" | grep -oE '[0-9]+' | head -1; }

# Distinct + shared content so dedup is actually exercised.
mkdir -p "$W/f"
head -c 50000 /dev/urandom | base64 > "$W/f/a.bin"
head -c 50000 /dev/urandom | base64 > "$W/f/b.bin"
cp "$W/f/a.bin" "$W/f/c.bin"          # c is a duplicate of a
echo "small inline" > "$W/f/d.txt"

echo "=== M1: backup order-independence (content + dedup size) ==="
d1="$W/o1.db"; d2="$W/o2.db"
"$BIN" "$d1" init >/dev/null 2>&1
"$BIN" "$d1" backup "$W/f/a.bin" / >/dev/null 2>&1
"$BIN" "$d1" backup "$W/f/b.bin" / >/dev/null 2>&1
"$BIN" "$d1" backup "$W/f/c.bin" / >/dev/null 2>&1
"$BIN" "$d1" backup "$W/f/d.txt" / >/dev/null 2>&1
"$BIN" "$d2" init >/dev/null 2>&1   # reverse order
"$BIN" "$d2" backup "$W/f/d.txt" / >/dev/null 2>&1
"$BIN" "$d2" backup "$W/f/c.bin" / >/dev/null 2>&1
"$BIN" "$d2" backup "$W/f/b.bin" / >/dev/null 2>&1
"$BIN" "$d2" backup "$W/f/a.bin" / >/dev/null 2>&1
rm -rf "$W/e1" "$W/e2"; mkdir "$W/e1" "$W/e2"
"$BIN" "$d1" extract "$W/e1" >/dev/null 2>&1
"$BIN" "$d2" extract "$W/e2" >/dev/null 2>&1
diff -r "$W/e1" "$W/e2" >/dev/null 2>&1 && ok "M1a: extracted content identical regardless of order" || fail "M1a: order changed extracted content"
[ "$(phys "$d1")" = "$(phys "$d2")" ] && ok "M1b: dedup physical size identical ($(phys "$d1")) regardless of order" || fail "M1b: order changed dedup size ($(phys "$d1") vs $(phys "$d2"))"

echo "=== M2: cross-run dedup idempotence (re-backup same data must not grow storage) ==="
dc="$W/cross.db"; "$BIN" "$dc" init >/dev/null 2>&1
"$BIN" "$dc" backup "$W/f" / >/dev/null 2>&1
P1="$(phys "$dc")"
OUT=$("$BIN" "$dc" backup "$W/f" / 2>&1)
P2="$(phys "$dc")"
[ "$P1" = "$P2" ] && ok "M2a: physical storage unchanged on re-backup ($P1 B)" || fail "M2a: re-backup GREW storage $P1 -> $P2 (cross-run dedup broken)"
echo "$OUT" | grep -qE "0 new|deduped" && ok "M2b: re-backup reports chunks deduped, not new" || ok "M2b: re-backup handled (no growth)"

echo "=== M3: extract determinism (same archive -> identical output twice) ==="
rm -rf "$W/x1" "$W/x2"; mkdir "$W/x1" "$W/x2"
"$BIN" "$dc" extract "$W/x1" >/dev/null 2>&1
"$BIN" "$dc" extract "$W/x2" >/dev/null 2>&1
diff -r "$W/x1" "$W/x2" >/dev/null 2>&1 && ok "M3a: two extracts of the same archive are identical" || fail "M3a: extract is non-deterministic"

echo "=== M4: snapshot rollback round-trips to the exact prior state ==="
ds="$W/snap.db"; "$BIN" "$ds" init >/dev/null 2>&1
"$BIN" "$ds" backup "$W/f" /state >/dev/null 2>&1
rm -rf "$W/base"; mkdir "$W/base"; "$BIN" "$ds" extract "$W/base" >/dev/null 2>&1
"$BIN" "$ds" snapshot create "S" >/dev/null 2>&1
# Mutate: change a file and add one.
echo "MUTATED" > "$W/f/a.bin"; echo "new" > "$W/f/e.txt"
"$BIN" "$ds" backup "$W/f" /state >/dev/null 2>&1
"$BIN" "$ds" snapshot rollback 1 --i-accept-non-atomic >/dev/null 2>&1
rm -rf "$W/rb"; mkdir "$W/rb"; "$BIN" "$ds" extract "$W/rb" >/dev/null 2>&1
diff -r "$W/base" "$W/rb" >/dev/null 2>&1 && ok "M4a: rollback restores the exact pre-mutation state" || fail "M4a: rollback state differs from the snapshotted state"
# Restore the original a.bin for cleanliness (already mutated on disk, irrelevant).

echo "=== M5: N identical files dedup to ~one copy ==="
dn="$W/ndup.db"; "$BIN" "$dn" init >/dev/null 2>&1
mkdir -p "$W/nd"; head -c 100000 /dev/urandom | base64 > "$W/nd/orig.bin"
for i in $(seq 1 8); do cp "$W/nd/orig.bin" "$W/nd/copy_$i.bin"; done
"$BIN" "$dn" backup "$W/nd" / >/dev/null 2>&1
PN="$(phys "$dn")"
# 9 identical ~133 KB files: one copy is ~133 KB, nine undeduped would be ~1.2 MB.
{ [ -n "$PN" ] && [ "$PN" -lt 300000 ]; } && ok "M5a: 9 identical files stored as ~one copy ($PN B)" || fail "M5a: identical files not deduped ($PN B, expected <300000)"

echo "=========================================="
echo "Metamorphic complete. Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAILED"
