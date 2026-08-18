#!/usr/bin/env bash
# Master script to run all tests in the project sequentially.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$REPO/tests"

# Find the binary
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
if [ ! -x "$BIN" ]; then
    BIN="$(realpath "${1:-$REPO/target/debug/cairn}")"
fi
if [ ! -x "$BIN" ]; then
    echo "[FAIL] cairn binary not found. Please build it first: cargo build --release"
    exit 1
fi

echo "=========================================================="
echo "          Cairn Unified Test Suite Runner                 "
echo "=========================================================="
echo "Using binary: $BIN"
echo ""

PASSED=0
FAILED=0
FAILED_TESTS=()

# Fast vs full gate. `soak.sh` is a long-running endurance test (minutes) and is
# never part of the standard runner. `FAST=1` also skips the heaviest suites so a
# per-commit gate stays quick; the full suite (default) runs everything else.
# (Every suite already runs with a low SQLCipher KDF via CAIRN_KDF_ITER, so DB
# opens are ~250x faster than production.)
SKIP_ALWAYS="soak.sh"
SKIP_FAST="e2e_smoke.sh"

# Find all test scripts in the tests directory (excluding this one)
for test_script in "$TESTS_DIR"/*.sh; do
    base="$(basename "$test_script")"
    # Skip the unified runner itself
    if [[ "$base" == "all_tests.sh" ]]; then
        continue
    fi
    if [[ " $SKIP_ALWAYS " == *" $base "* ]]; then
        echo "▷ Skipping $base (endurance test; run it directly)"
        continue
    fi
    if [[ "${FAST:-0}" == "1" && " $SKIP_FAST " == *" $base "* ]]; then
        echo "▷ Skipping $base (FAST mode)"
        continue
    fi

    echo "----------------------------------------------------------"
    echo "▶ Running: $(basename "$test_script")"
    echo "----------------------------------------------------------"
    
    # Run the test script in a subshell/subprocess so its traps/variables don't leak
    if bash "$test_script" "$BIN"; then
        echo -e "\n✅ [SUCCESS] $(basename "$test_script") completed successfully."
        ((PASSED++))
    else
        echo -e "\n❌ [ERROR] $(basename "$test_script") failed."
        ((FAILED++))
        FAILED_TESTS+=("$(basename "$test_script")")
    fi
    echo ""
done

echo "=========================================================="
echo "                    Test Summary                          "
echo "=========================================================="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -gt 0 ]; then
    echo "Failed scripts:"
    for failed_test in "${FAILED_TESTS[@]}"; do
        echo "  - $failed_test"
    done
    exit 1
else
    echo "All tests passed successfully!"
    exit 0
fi
