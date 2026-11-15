#!/usr/bin/env bash
#
# coverage.sh — measure Rust test coverage via cargo-llvm-cov.
#
# Uses LLVM source-based coverage (accurate for async/await and
# spawn_blocking closures, unlike tarpaulin).
#
# Modes:
#   tests/coverage.sh              measure → compare → UPDATE baseline
#   tests/coverage.sh --no-save    measure → compare (read-only)
#   tests/coverage.sh --reset      measure → save as new baseline (no compare)
#   tests/coverage.sh --ci         measure → compare → exit 1 on regression
#
# The --ci mode exits with status 1 if LIB-ONLY dropped ≥0.5 pp from baseline.
# Per-file warnings at ≥3 pp drop are informational (not a hard fail).
#
# CLI binaries (src/main.rs, cairn-keys/src/main.rs) are excluded from the
# LIB-ONLY metric because they are exercised by shell gates (e2e, blackbox,
# fault injection), not by cargo test.  Likewise the FUSE adapter
# (cairn-core/src/vfs.rs) can only be reached through a live FUSE mount.
set -uo pipefail
export LC_NUMERIC=C

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
BASELINE="$REPO/tests/coverage-baseline.txt"
MODE="${1:-}"

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo "cargo-llvm-cov is not installed. Install it with:" >&2
  echo "    cargo install cargo-llvm-cov" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

LCOV="$TMP/lcov.info"

echo "==> running cargo llvm-cov (tests + coverage — this is slow)…"
cargo llvm-cov --workspace --lcov --output-path "$LCOV" 2>&1

# Parse LCOV for per-file stats. Source files only (test files excluded).
declare -A FILE_HIT FILE_TOT
LIB_HIT=0 LIB_TOT=0
if [ -f "$LCOV" ]; then
  while IFS=',' read -r f lh lf; do
    FILE_HIT["$f"]=$lh
    FILE_TOT["$f"]=$lf
    if [[ $f != src/main.rs && $f != crates/cairn-keys/src/main.rs && $f != crates/cairn-core/src/vfs.rs && $f != */tests/* ]]; then
      (( LIB_HIT += lh ))
      (( LIB_TOT += lf ))
    fi
  done < <(
    awk '
      /^SF:/  { f=substr($0,4); sub("'"$REPO"'/","",f) }
      /^LF:/  { lf=substr($0,4) }
      /^LH:/  { lh=substr($0,4) }
      /^end_of_record/ {
        if (f ~ /\.rs$/ && f !~ /\/tests\//) print f "," lh "," lf
      }
    ' "$LCOV"
  )

  LIB_PCT=0; [ "$LIB_TOT" -gt 0 ] && LIB_PCT="$(awk "BEGIN{printf \"%.2f\", 100*$LIB_HIT/$LIB_TOT}")"
  # Compute "with CLI" total (includes all source files, excluding test files)
  ALL_HIT=0 ALL_TOT=0
  for f in "${!FILE_HIT[@]}"; do
    (( ALL_HIT += ${FILE_HIT[$f]} ))
    (( ALL_TOT += ${FILE_TOT[$f]} ))
  done
  ALL_PCT=0; [ "$ALL_TOT" -gt 0 ] && ALL_PCT="$(awk "BEGIN{printf \"%.2f\", 100*$ALL_HIT/$ALL_TOT}")"

  echo
  echo "Per-file, source only:"
  for f in "${!FILE_HIT[@]}"; do
    pct="$(awk "BEGIN{printf \"%.1f\", 100*${FILE_HIT[$f]}/${FILE_TOT[$f]}}")"
    printf "  %-44s %5s/%-5s %6.1f%%\n" "$f" "${FILE_HIT[$f]}" "${FILE_TOT[$f]}" "$pct"
  done | LC_ALL=C sort -t/ -k1,1
  echo
fi

# ---------- baseline compare ----------
DELTA_PP=""
OLD_ALL_PCT=""
OLD_LIB_PCT=""
if [ "$MODE" != "--reset" ] && [ -f "$BASELINE" ]; then
  OLD_ALL_PCT="$(sed -n 's/^ALL: \([0-9.]*\)% .*/\1/p' "$BASELINE" | head -1)"
  OLD_LIB_PCT="$(sed -n 's/^# LIB-ONLY \([0-9.]*\)% .*/\1/p' "$BASELINE" | head -1)"

  if [ -n "$OLD_ALL_PCT" ]; then
    DELTA="$(awk -v a="$OLD_ALL_PCT" -v b="$ALL_PCT" 'BEGIN{printf "%+.2f", b-a}')"
    echo "ALL (with CLI)     before: ${OLD_ALL_PCT}%   after: ${ALL_PCT}%   delta: ${DELTA} pp   (${ALL_HIT}/${ALL_TOT})"
  else
    echo "ALL (with CLI)     after: ${ALL_PCT}%   (${ALL_HIT}/${ALL_TOT})   [no baseline]"
  fi

  if [ -n "$OLD_LIB_PCT" ]; then
    LIB_DELTA="$(awk -v a="$OLD_LIB_PCT" -v b="$LIB_PCT" 'BEGIN{printf "%+.2f", b-a}')"
    echo "LIB-ONLY           before: ${OLD_LIB_PCT}%   after: ${LIB_PCT}%   delta: ${LIB_DELTA} pp   (${LIB_HIT}/${LIB_TOT})"
  else
    echo "LIB-ONLY           after: ${LIB_PCT}%   (${LIB_HIT}/${LIB_TOT})   [no baseline]"
  fi

  # Per-file delta from baseline
  declare -A BASE_HIT BASE_TOT
  while IFS='' read -r line; do
    [ -z "$line" ] && continue
    f="${line%%|*}"
    rest="${line#*|}"
    h="${rest%%/*}"
    t="${rest#*/}"
    BASE_HIT["$f"]=$h
    BASE_TOT["$f"]=$t
  done < <(sed -n '/^# per-file:/,$ p' "$BASELINE" | grep '|' | sed 's/^#  //')

  if [ ${#BASE_HIT[@]} -gt 0 ]; then
    echo "Per-file delta vs baseline:"
    for f in "${!FILE_HIT[@]}"; do
      bh=${BASE_HIT["$f"]:-0}
      bt=${BASE_TOT["$f"]:-0}
      if [ "$bt" -gt 0 ] && [ "${FILE_TOT[$f]}" -gt 0 ]; then
        now_pct="$(awk "BEGIN{printf \"%.1f\", 100*${FILE_HIT[$f]}/${FILE_TOT[$f]}}")"
        pct_calc="BEGIN{printf \"%.1f\", 100*$bh/$bt}"
        old_pct="$(awk "$pct_calc")"
        d="$(awk -v a="$old_pct" -v b="$now_pct" 'BEGIN{printf "%+.1f", b-a}')"
        printf "  %-44s  was %6.1f%% → %6.1f%%  (%s pp)\n" "$f" "$old_pct" "$now_pct" "$d"
      fi
    done | LC_ALL=C sort -t/ -k1,1
  fi
else
  echo "ALL (with CLI)     after: ${ALL_PCT}%   (${ALL_HIT}/${ALL_TOT})   [no baseline]"
  echo "LIB-ONLY           after: ${LIB_PCT}%   (${LIB_HIT}/${LIB_TOT})   [no baseline]"
fi

# ---------- CI gate (--ci mode) ----------
CI_FAIL=0
if [ "$MODE" = "--ci" ] && [ -n "$OLD_LIB_PCT" ]; then
  LIB_DROP="$(awk -v a="$OLD_LIB_PCT" -v b="$LIB_PCT" 'BEGIN{if (b < a) printf "%.2f", a-b; else print "0"}')"
  if awk "BEGIN{exit ($LIB_DROP >= 0.5 ? 0 : 1)}"; then
    echo "!! CI FAIL: LIB-ONLY coverage dropped by ${LIB_DROP} pp (threshold: 0.5 pp)" >&2
    CI_FAIL=1
  fi

  for f in "${!FILE_HIT[@]}"; do
    bh=${BASE_HIT["$f"]:-0}
    bt=${BASE_TOT["$f"]:-0}
    if [ "$bt" -gt 0 ] && [ "${FILE_TOT[$f]}" -gt 0 ]; then
      old_pct="$(awk "BEGIN{printf \"%.1f\", 100*$bh/$bt}")"
      now_pct="$(awk "BEGIN{printf \"%.1f\", 100*${FILE_HIT[$f]}/${FILE_TOT[$f]}}")"
      drop="$(awk -v a="$old_pct" -v b="$now_pct" 'BEGIN{if (b < a) printf "%.1f", a-b; else print "0"}')"
      if awk "BEGIN{exit ($drop >= 3 ? 0 : 1)}"; then
        echo "!! WARN: $f dropped ${drop} pp (${old_pct}% → ${now_pct}%)" >&2
      fi
    fi
  done

  if [ "$CI_FAIL" -eq 1 ]; then
    exit 1
  fi
fi

# ---------- save baseline ----------
if [ "$MODE" != "--no-save" ] && [ "$MODE" != "--ci" ]; then
  {
    echo "ALL: ${ALL_PCT}% (${ALL_HIT}/${ALL_TOT} lines, excl. test files)"
    echo "measured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# LIB-ONLY ${LIB_PCT}% (${LIB_HIT}/${LIB_TOT} lines, excl. test files, CLI binaries, and vfs.rs)"
    echo "# per-file:"
    for f in "${!FILE_HIT[@]}"; do
      echo "#  ${f}|${FILE_HIT[$f]}/${FILE_TOT[$f]}"
    done | LC_ALL=C sort
  } > "$BASELINE"
  echo "==> baseline saved → tests/coverage-baseline.txt"
fi
