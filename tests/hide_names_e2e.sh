#!/usr/bin/env bash
# Cairn hide-names end-to-end — the CLI-level gate that `cargo test` cannot reach.
#
# The engine tests (crates/cairn-core/tests/hide_names_tests.rs) cover the crypto
# and FS surface by constructing a CryptoCtx directly. They do NOT exercise the
# main.rs wiring: the default-on decision, generating + storing name_hash_secret
# under the SQLCipher password, and loading it back into the ctx on open. This
# script drives the real binary through init → backup → extract to prove that path.
#
# Name hiding is ON BY DEFAULT for asymmetric archives with a password (no flag
# needed); --plaintext-names opts out. A symmetric archive or a missing password
# just can't support it — silently, not an error (see docs/DESIGN-NOTES.md#2).
#
# No FUSE required (backup/extract are enough), so it is fast and CI-friendly.
#
# Usage:   tests/hide_names_e2e.sh [path-to-cairn-binary]
# Default: target/debug/cairn (build first: cargo build)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/debug/cairn}")"
GEN="$(dirname "$BIN")/gen_keys"
[ -x "$BIN" ] || { echo "[FAIL] binary not found: $BIN (run: cargo build)"; exit 1; }
[ -x "$GEN" ] || { echo "[FAIL] gen_keys not found next to cairn (cargo build builds both)"; exit 1; }

W="$(mktemp -d /tmp/cairn-hidenames-e2e.XXXXXX)"
FAILED=0; TESTS=0; PASSED=0
say()  { TESTS=$((TESTS+1)); printf '  [ok] %s\n' "$1"; PASSED=$((PASSED+1)); }
fail() { TESTS=$((TESTS+1)); printf '  [FAIL] %s\n' "$1"; FAILED=1; }
die()  { printf '  [FAIL] %s\n' "$1"; exit 1; }
cleanup() { rm -rf "$W"; }
trap cleanup EXIT

cd "$W"
( "$GEN" >/dev/null ) || die "gen_keys failed"
export CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"   # test speed: low KDF (throwaway data)
PW='hide-names-e2e-pw-123'

echo "== default-on decision =="

# 1. asymmetric + password, no flag → hidden by default
env CAIRN_PASSWORD="$PW" "$BIN" hn.db --pub-key pub.pem init >/dev/null 2>&1 \
    && say "init accepted (asymmetric + password, hidden by default)" \
    || fail "init refused a valid asymmetric+password archive"

# 2. symmetric (no --pub-key) → succeeds, but names cannot be hidden (no error)
env CAIRN_PASSWORD="$PW" "$BIN" sym.db init >/dev/null 2>&1 \
    && say "init on a symmetric archive still succeeds (hiding just doesn't apply)" \
    || fail "init on a symmetric archive was refused (should silently skip hiding, not error)"

# 3. asymmetric but NO password → succeeds with a warning, not an error
if env -u CAIRN_PASSWORD "$BIN" np.db --pub-key pub.pem init >"$W/g3.log" 2>&1; then
    grep -qi 'skipped: no password' "$W/g3.log" && say "init without a password warns and skips hiding (no error)" \
        || fail "passwordless asymmetric init succeeded, but without the expected warning"
else
    fail "init without a password was refused (should warn and proceed with plaintext names)"
fi

# 4. explicit opt-out
env CAIRN_PASSWORD="$PW" "$BIN" plain.db --pub-key pub.pem init --plaintext-names >/dev/null 2>&1 \
    && say "init --plaintext-names accepted (explicit opt-out)" \
    || fail "init --plaintext-names was refused"

echo "== backup → extract round-trip (real config path, hidden by default) =="
mkdir -p src/sub
printf 'quarterly numbers 42' > "src/SECRET_report.txt"
printf 'deep secret'          > "src/sub/nested_SECRET.txt"
env CAIRN_PASSWORD="$PW" "$BIN" hn.db --pub-key pub.pem backup "$W/src" / >/dev/null 2>&1 \
    || die "backup into hide-names archive failed"

mkdir -p out
env CAIRN_PASSWORD="$PW" "$BIN" hn.db --pub-key pub.pem --priv-key priv.pem extract "$W/out" >/dev/null 2>&1 \
    || die "extract with the private key failed"
[ -f "$W/out/SECRET_report.txt" ] && [ "$(cat "$W/out/SECRET_report.txt")" = 'quarterly numbers 42' ] \
    && say "extract with priv key restores the real name + content" \
    || fail "extract did not restore SECRET_report.txt correctly"
[ -f "$W/out/sub/nested_SECRET.txt" ] && [ "$(cat "$W/out/sub/nested_SECRET.txt")" = 'deep secret' ] \
    && say "nested-directory name reconstruction works" \
    || fail "nested hidden name not reconstructed"

echo "== untrusted-host view: pub-only extract must NOT recover names =="
mkdir -p out_pubonly
# No --priv-key: content is unreadable (expected non-zero) AND names must be hashes.
env CAIRN_PASSWORD="$PW" "$BIN" hn.db --pub-key pub.pem extract "$W/out_pubonly" >/dev/null 2>&1 || true
if find "$W/out_pubonly" | grep -q 'SECRET'; then
    fail "LEAK: a real name appeared in a pub-only (no private key) extract"
else
    say "pub-only extract yields no real names (hashes only)"
fi

echo "== --plaintext-names archive keeps names in plaintext =="
mkdir -p src_plain out_plain
printf 'visible content' > "src_plain/VISIBLE_name.txt"
env CAIRN_PASSWORD="$PW" "$BIN" plain.db --pub-key pub.pem backup "$W/src_plain" / >/dev/null 2>&1 \
    || die "backup into --plaintext-names archive failed"
env CAIRN_PASSWORD="$PW" "$BIN" plain.db --pub-key pub.pem --priv-key priv.pem extract "$W/out_plain" >/dev/null 2>&1 \
    || die "extract from --plaintext-names archive failed"
[ -f "$W/out_plain/VISIBLE_name.txt" ] \
    && say "--plaintext-names archive: real name visible without a private key" \
    || fail "--plaintext-names archive did not preserve the plaintext name"

echo "== verify runs on a hide-names archive =="
env CAIRN_PASSWORD="$PW" "$BIN" hn.db --pub-key pub.pem --priv-key priv.pem verify >/dev/null 2>&1 \
    && say "verify exits 0 on a healthy hide-names archive" \
    || fail "verify failed on a healthy hide-names archive"

echo
echo "== $PASSED/$TESTS passed =="
[ "$FAILED" = 0 ] || exit 1
