#!/usr/bin/env bash
# Cairn backup→extract FIDELITY probe — black-box. Builds a source tree of the
# tricky cases backup tools routinely get wrong (exotic names, sym/hard links,
# sparse files, fifos, permissions, mtime, empty files, dedup), backs it up,
# extracts it, and checks each property survived. A FAIL is a real fidelity bug.
# Usage: tests/fidelity.sh [path-to-cairn-binary]   (default target/release/cairn)
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
[ -x "$BIN" ] || { echo "[FAIL] binary not found: $BIN"; exit 1; }
W="$(mktemp -d /tmp/cairn-fidelity.XXXXXX)"; trap 'rm -rf "$W"' EXIT
export CAIRN_PASSWORD="fidelity-pass"
export CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"  # test speed: low KDF (throwaway data)
SRC="$W/src"; OUT="$W/out"; mkdir -p "$SRC" "$OUT"
FAILED=0
ok()   { printf '  [ok]   %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; FAILED=1; }

# ── build the source tree ────────────────────────────────────────────────
echo "content-a" > "$SRC/plain.txt"
printf 'русский 日本語 émojis.txt content' > "$SRC/юникод_имя_файл.txt"       # unicode name
echo "spaces" > "$SRC/name with spaces and.dots.txt"                          # spaces + dots
LONGNAME=$(printf 'x%.0s' $(seq 1 250)); echo "long" > "$SRC/$LONGNAME.txt"   # near-255 name
: > "$SRC/empty.txt"                                                           # 0-byte
mkdir -p "$SRC/emptydir"                                                       # empty dir
mkdir -p "$SRC/a/b/c/d"; echo "deep" > "$SRC/a/b/c/d/deep.txt"                 # deep nesting
# symlinks: relative, absolute, dangling
ln -s plain.txt "$SRC/rel_link"
ln -s /etc/hostname "$SRC/abs_link"
ln -s does_not_exist "$SRC/dangling_link"
# hardlink: two names, one inode
echo "hardlinked content" > "$SRC/hardlink_a"
ln "$SRC/hardlink_a" "$SRC/hardlink_b"
# sparse file: 1 MiB hole then 5 bytes
dd if=/dev/zero of="$SRC/sparse.bin" bs=1 count=0 seek=1048576 2>/dev/null
printf 'endcap' >> "$SRC/sparse.bin"
# fifo
mkfifo "$SRC/a_fifo" 2>/dev/null || true
# permissions + mtime
echo "perm755" > "$SRC/exec.sh"; chmod 755 "$SRC/exec.sh"
echo "perm600" > "$SRC/secret"; chmod 600 "$SRC/secret"
touch -d "2020-01-02 03:04:05" "$SRC/plain.txt"
# dedup: two identical large files
head -c 500000 /dev/urandom > "$SRC/dup1.bin"; cp "$SRC/dup1.bin" "$SRC/dup2.bin"
# xattrs (conditional on tools; --preserve will be used for roundtrip)
if command -v setfattr >/dev/null 2>&1; then
  setfattr -n user.fidelity -v "xattr-fidelity-value" "$SRC/plain.txt" 2>/dev/null || true
  setfattr -n user.cairn.test -v "123" "$SRC/secret" 2>/dev/null || true
fi

# More edge content: exact inline boundary (4096), one over, all-zero small, urandom limited
head -c 4096 /dev/zero > "$SRC/inline_exact.bin"
head -c 4097 /dev/zero > "$SRC/inline_plus1.bin"
head -c 100000 /dev/urandom > "$SRC/rand100k.bin"
dd if=/dev/zero of="$SRC/zeros_small.bin" bs=1 count=0 seek=8192 2>/dev/null; printf 'tail' >> "$SRC/zeros_small.bin"

# Weird names via python (control chars where possible, emoji, dots, long, deep).
# SRC must be EXPORTED into python's env — the heredoc is quoted so the shell
# does not expand $SRC, and without the export the files were created in a
# literal "$SRC/weird" directory under cwd and never made it into the backup.
SRC="$SRC" python3 - <<'PY' || echo "  [note] python name gen partial"
import os, subprocess
d = os.path.join(os.environ['SRC'], 'weird')
os.makedirs(d, exist_ok=True)
# emoji and unicode variants
open(os.path.join(d, 'emoji_🚀_cairn.txt'), 'w').write('rocket')
open(os.path.join(d, 'combining_e\u0301.txt'), 'w').write('e-comb')
# special dots and dots only
open(os.path.join(d, 'file..double..dots.txt'), 'w').write('dots')
open(os.path.join(d, '...'), 'w').write('dotdotdot')
# long name close to limit
longn = 'x' * 240 + '.txt'
open(os.path.join(d, longn), 'w').write('long240')
# deep nesting
deep = d
for i in range(25):
    deep = os.path.join(deep, f'lvl{i}')
os.makedirs(deep, exist_ok=True)
open(os.path.join(deep, 'deepfile.txt'), 'w').write('deep25')
# hidden and special looking
open(os.path.join(d, '.hidden_edge'), 'w').write('hidden')
open(os.path.join(d, 'file with\t tab.txt'), 'w').write('tab')  # tab may work
print("weird names created")
PY

# ── backup + extract (with --preserve for perms/mtime/xattrs) ────────────
"$BIN" "$W/a.db" init >/dev/null
"$BIN" "$W/a.db" backup "$SRC" >/dev/null 2>&1
rc=$?
[ $rc -eq 0 ] && ok "backup of the tricky tree exited 0" || bad "backup exited $rc (special file / name rejected the whole run?)"
# Use --preserve with NO fallback: falling back to a non-preserve extract used to
# silently reset every mtime (masking preserve regressions). A preserve failure
# must surface as a failing mtime/xattr check below, not be hidden.
"$BIN" "$W/a.db" extract "$OUT" --preserve >/dev/null 2>&1

# ── checks ───────────────────────────────────────────────────────────────
echo "== names & content =="
cmp -s "$SRC/plain.txt" "$OUT/plain.txt" && ok "plain file content" || bad "plain file content"
cmp -s "$SRC/юникод_имя_файл.txt" "$OUT/юникод_имя_файл.txt" && ok "unicode filename round-trip" || bad "unicode filename lost/corrupted"
cmp -s "$SRC/name with spaces and.dots.txt" "$OUT/name with spaces and.dots.txt" && ok "spaces+dots filename" || bad "spaces/dots filename"
cmp -s "$SRC/$LONGNAME.txt" "$OUT/$LONGNAME.txt" && ok "near-255-byte filename" || bad "long filename"
[ -f "$OUT/empty.txt" ] && [ ! -s "$OUT/empty.txt" ] && ok "empty file (0 bytes)" || bad "empty file"
[ -d "$OUT/emptydir" ] && ok "empty directory" || bad "empty directory lost"
cmp -s "$SRC/a/b/c/d/deep.txt" "$OUT/a/b/c/d/deep.txt" && ok "deep nesting" || bad "deep nesting"

echo "== symlinks =="
[ -L "$OUT/rel_link" ] && [ "$(readlink "$OUT/rel_link")" = "plain.txt" ] && ok "relative symlink target" || bad "relative symlink (is-link=$([ -L "$OUT/rel_link" ] && echo y||echo n) target='$(readlink "$OUT/rel_link" 2>/dev/null)')"
[ -L "$OUT/abs_link" ] && [ "$(readlink "$OUT/abs_link")" = "/etc/hostname" ] && ok "absolute symlink target" || bad "absolute symlink target='$(readlink "$OUT/abs_link" 2>/dev/null)'"
[ -L "$OUT/dangling_link" ] && [ "$(readlink "$OUT/dangling_link")" = "does_not_exist" ] && ok "dangling symlink preserved" || bad "dangling symlink"

echo "== hardlinks =="
# Backup stores a hardlink group ONCE (dedup, via source dev+ino), and extract
# recreates the on-disk link so both names share one inode (see RISKS.md R-B6).
if [ -f "$OUT/hardlink_a" ] && [ -f "$OUT/hardlink_b" ]; then
    cmp -s "$OUT/hardlink_a" "$OUT/hardlink_b" && ok "hardlink content matches (both names restore)" || bad "hardlink content differs"
    ia=$(stat -c%i "$OUT/hardlink_a"); ib=$(stat -c%i "$OUT/hardlink_b")
    [ "$ia" = "$ib" ] && ok "hardlink shared inode recreated on extract" \
        || bad "extract split the hardlink into 2 files (inodes $ia != $ib)"
else
    bad "hardlink files missing"
fi

echo "== sparse file =="
if [ -f "$OUT/sparse.bin" ]; then
    ssz=$(stat -c%s "$OUT/sparse.bin")
    [ "$ssz" = "1048582" ] && ok "sparse file logical size (1MiB+6)" || bad "sparse file size $ssz != 1048582"
    cmp -s "$SRC/sparse.bin" "$OUT/sparse.bin" && ok "sparse file content (hole reads zeros)" || bad "sparse file content mismatch"
else
    bad "sparse file missing"
fi

echo "== special files =="
if [ -p "$SRC/a_fifo" ]; then
    if [ -e "$OUT/a_fifo" ]; then
        [ -p "$OUT/a_fifo" ] && ok "fifo restored as fifo" || bad "fifo restored as $(stat -c%F "$OUT/a_fifo") (wrong type)"
    else
        ok "fifo skipped (acceptable if documented; not silently a regular file)"
    fi
else
    echo "  [skip] mkfifo unavailable"
fi

echo "== permissions & mtime (--preserve) =="
pm=$(stat -c%a "$OUT/exec.sh" 2>/dev/null); [ "$pm" = "755" ] && ok "mode 755 preserved" || bad "mode 755 -> $pm"
ps=$(stat -c%a "$OUT/secret" 2>/dev/null); [ "$ps" = "600" ] && ok "mode 600 preserved" || bad "mode 600 -> $ps"
smt=$(stat -c%Y "$SRC/plain.txt"); omt=$(stat -c%Y "$OUT/plain.txt" 2>/dev/null)
[ "$smt" = "$omt" ] && ok "mtime preserved" || bad "mtime not preserved (src=$smt out=$omt)"

echo "== xattrs (--preserve) =="
# Only assert if the xattr was ACTUALLY set on the source (some filesystems reject
# user xattrs). If the source has it, a faithful backup MUST restore it — the old
# "[note]" here was non-fatal and silently hid a real bug: backup never captured
# source xattrs at all, so they were dropped on restore.
if command -v getfattr >/dev/null 2>&1 \
   && getfattr -n user.fidelity --only-values "$SRC/plain.txt" 2>/dev/null | grep -q 'xattr-fidelity-value'; then
  if getfattr -n user.fidelity --only-values "$OUT/plain.txt" 2>/dev/null | grep -q 'xattr-fidelity-value'; then
    ok "user.fidelity xattr preserved via extract --preserve"
  else
    bad "xattr dropped: source had user.fidelity but restore does not"
  fi
else
  echo "  [skip] xattr not set on source (fs lacks xattr support or getfattr unavailable)"
fi

echo "== dedup =="
phys=$("$BIN" "$W/a.db" status 2>/dev/null | grep -i "Physical" | grep -oE "[0-9]+" | head -1)
# Two identical 500k files: physical (deduped) storage should be ~one copy, not two.
if [ -n "$phys" ]; then
    [ "$phys" -lt 900000 ] && ok "identical files deduped (physical=${phys} < 2 copies)" \
        || bad "no dedup: physical=${phys} (~two copies of 500k stored)"
else
    echo "  [skip] could not read physical size"
fi

echo "== restore into non-empty dir (overwrite must not corrupt) =="
echo "STALE" > "$OUT/plain.txt"
"$BIN" "$W/a.db" extract "$OUT" >/dev/null 2>&1
cmp -s "$SRC/plain.txt" "$OUT/plain.txt" && ok "re-extract over existing restored correct content" || bad "re-extract left stale/corrupt content"

echo "== size boundary files (inline exact +1, rand, sparse zeros) =="
for f in inline_exact.bin inline_plus1.bin rand100k.bin zeros_small.bin; do
  if [ -f "$OUT/$f" ]; then
    cmp -s "$SRC/$f" "$OUT/$f" && ok "$f roundtrip exact" || bad "$f content mismatch"
  else
    bad "$f missing after extract"
  fi
done

echo "== weird names roundtrip (emoji, combining, dots, long, deep, hidden) =="
# Real assertions against the ACTUAL generated names. The old checks used
# `find ... | head -1` — head exits 0 on empty input AND find exits 0 with no
# matches, so they could never fail on a missing file (a false pass), and their
# name patterns didn't even match what the generator creates.
WD="$OUT/weird"
have() { [ "$(find "$WD" -name "$1" -type f 2>/dev/null | wc -l)" -ge 1 ]; }
[ -f "$WD/emoji_🚀_cairn.txt" ]        && ok "emoji name round-trip"        || bad "emoji name lost"
have 'combining_*'                     && ok "combining-char name round-trip" || bad "combining name lost"
have 'xxxxxxxxxx*.txt'                 && ok "~244-byte long name round-trip"  || bad "long name lost"
[ -f "$WD/file..double..dots.txt" ]    && ok "double-dots name round-trip"   || bad "dots name lost"
[ -f "$WD/..." ]                       && ok "'...' name round-trip"          || bad "'...' name lost"
[ "$(find "$WD" -name deepfile.txt -type f 2>/dev/null | wc -l)" -ge 1 ] && ok "25-level deep name restored" || bad "deep nesting lost"
[ -f "$WD/.hidden_edge" ]              && ok "hidden name round-trip"        || bad "hidden name lost"

echo "== non-empty extract merge behavior =="
# Re-do a small non-empty extract test inside fidelity for coverage
NED="$W/ne_dst"; rm -rf "$NED"; mkdir -p "$NED/sub"
echo "STALE_TOP" > "$NED/stale_top.txt"
echo "STALE_SUB" > "$NED/sub/stale_sub.txt"
"$BIN" "$W/a.db" extract "$NED" >/dev/null 2>&1 || true
[ -f "$NED/stale_top.txt" ] && [ "$(cat "$NED/stale_top.txt")" = "STALE_TOP" ] && ok "existing top file survived non-empty extract" || bad "existing top file lost or overwritten wrongly"
[ -f "$NED/sub/stale_sub.txt" ] && [ "$(cat "$NED/sub/stale_sub.txt")" = "STALE_SUB" ] && ok "existing sub file survived" || bad "existing sub lost"
[ -f "$NED/plain.txt" ] && ok "new content from archive added to non-empty" || bad "new files not added to non-empty dst"

echo
[ "$FAILED" = 0 ] && echo "FIDELITY: PASS" || echo "FIDELITY: FAIL"
exit $FAILED
