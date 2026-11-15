#!/usr/bin/env bash
# Anti-pattern gates, enforced in CI by this script.
#
# These are the two DETERMINISTIC, zero-false-positive gates from the observers'
# pattern review, so they can run in CI and stay green. The clippy-based lints
# (clippy::let_underscore_drop, cast_sign_loss, cast_possible_truncation) are kept
# WARN-only rather than wired in as `-D`, because the codebase has many
# legitimately-acceptable instances (best-effort cleanup, structurally-safe casts)
# that would otherwise need blanket #[allow] annotations.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
FAIL=0

echo "== P-008: no debug_assert! in production code =="
# `debug_assert!` compiles to nothing in --release, so a security/integrity invariant
# guarded by it is silently unprotected in production. Match the MACRO call (with `!`),
# not comment mentions of the word, and skip pure-comment lines.
hits=$(grep -rn 'debug_assert!' crates/*/src/ src/ --include='*.rs' 2>/dev/null \
        | grep -vE ':[0-9]+:[[:space:]]*//' || true)
if [ -n "$hits" ]; then
  echo "  [FAIL] debug_assert! found in production code — use a runtime check (bail!/assert!):"
  echo "$hits" | sed 's/^/    /'
  FAIL=1
else
  echo "  [ok] no debug_assert! in production code"
fi

echo "== P-006: format!-built SQL must carry a // SAFETY justification =="
# SQLite cannot bind identifiers as parameters, so table/pragma names must sometimes be
# interpolated. Any such site must document WHY the interpolated value is safe.
hits=$(grep -rnE 'format!.*(SELECT|INSERT|UPDATE|DELETE|[^_]WHERE)' crates/*/src/ src/ --include='*.rs' 2>/dev/null \
        | grep -vE ':[0-9]+:[[:space:]]*//' \
        | grep -v '// SAFETY' || true)
if [ -n "$hits" ]; then
  echo "  [FAIL] format!-built SQL without a // SAFETY comment on the same line:"
  echo "$hits" | sed 's/^/    /'
  FAIL=1
else
  echo "  [ok] all format!-in-SQL sites carry a // SAFETY justification"
fi

echo
if [ "$FAIL" = 0 ]; then
  echo "PATTERN GATES: PASS"
  exit 0
else
  echo "PATTERN GATES: FAIL"
  exit 1
fi
