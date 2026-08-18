#!/usr/bin/env bash
# Cairn soak test — mixed read/write/gc/snapshot load against a live mount for a
# set duration, sampling the daemon's RSS and fd count. A pilot runs the daemon
# for weeks; the smoke only runs it for seconds. This surfaces the failures that
# only appear over time: memory growth, fd leaks, background-loop misbehavior.
#
# Usage:   tests/soak.sh [minutes] [path-to-cairn-binary]
# Default: 30 minutes, target/debug/cairn. For a real pre-pilot gate run 1440+
# (24h). Prints an RSS/fd trend and PASS/FAIL on a growth threshold at the end.
set -uo pipefail

MINUTES="${1:-30}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${2:-$REPO/target/debug/cairn}")"
[ -x "$BIN" ] || { echo "[FAIL] binary not found: $BIN"; exit 1; }

W="$(mktemp -d /tmp/cairn-soak.XXXXXX)"
export CAIRN_PASSWORD="soak-pass"
export CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"  # test speed: low KDF (throwaway data)
DAEMON_PID=""
SAMPLES="$W/samples.tsv"

cleanup() {
    mountpoint -q "$W/mnt" 2>/dev/null && fusermount -u "$W/mnt" 2>/dev/null
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    sleep 1; rm -rf "$W"
}
trap cleanup EXIT

mkdir -p "$W/mnt"; cd "$W"
"$BIN" soak.db init >/dev/null

nohup "$BIN" soak.db mount "$W/mnt" >>"$W/daemon.log" 2>&1 &
DAEMON_PID=$!
disown
for _ in $(seq 1 60); do mountpoint -q "$W/mnt" && break; sleep 0.5; done
mountpoint -q "$W/mnt" || { echo "[FAIL] mount did not come up"; tail "$W/daemon.log"; exit 1; }

sample() { # label
    local rss fd
    rss=$(awk '/VmRSS/{print $2}' "/proc/$DAEMON_PID/status" 2>/dev/null || echo 0)
    fd=$(ls "/proc/$DAEMON_PID/fd" 2>/dev/null | wc -l)
    printf '%s\t%s\t%s\t%s\n' "$(date +%s)" "$1" "$rss" "$fd" >> "$SAMPLES"
    echo "  [$(date +%H:%M:%S)] $1: RSS=${rss}kB fd=${fd}"
}

# A leak detector must hold the ARCHIVE size roughly constant, else RSS grows
# with the index (deleted files' chunks linger until `gc`, page cache tracks it)
# and every run "fails" on expected growth, not a leak. So churn against a FIXED
# corpus that mostly dedups — the write/RMW/read paths run every round but the
# archive reaches steady state. (Confirmed: identical-data churn plateaus RSS
# flat; all-new-data churn grows linearly — that growth is archive size, not a
# leak, and is why a pilot with churn MUST run gc periodically.)
CORPUS="$W/corpus"; mkdir -p "$CORPUS"
for i in $(seq 1 20); do head -c $(( (i % 8 + 1) * 40000 )) /dev/urandom > "$CORPUS/f_$i"; done

echo "== soak: ${MINUTES} min, daemon pid $DAEMON_PID =="
sample start
END=$(( $(date +%s) + MINUTES * 60 ))
round=0
while [ "$(date +%s)" -lt "$END" ]; do
    round=$((round + 1))
    d="$W/mnt/round_$((round % 5))"        # reuse 5 dirs → create+delete churn
    rm -rf "$d" 2>/dev/null; mkdir -p "$d"
    cp "$CORPUS"/* "$d"/                     # re-store the corpus (dedups)
    cat "$d"/* > /dev/null 2>&1              # read back
    for i in 1 2 3; do cp "$CORPUS/f_$i" "$d/f_$i.rmw"; done  # a little RMW/write churn
    sync
    [ $((round % 10)) -eq 0 ] && sample "round_$round"
done
sample end

echo "== trend (ts / label / RSS-kB / fd) =="
column -t "$SAMPLES" 2>/dev/null || cat "$SAMPLES"

# Samples are tab-separated; the label may contain no spaces now, but stay strict.
first=$(awk -F'\t' 'NR==2{print $3}' "$SAMPLES")   # post-warmup baseline
last=$(awk -F'\t' 'END{print $3}' "$SAMPLES")
fd_last=$(awk -F'\t' 'END{print $4}' "$SAMPLES")
echo
echo "RSS: ${first}kB -> ${last}kB ; fd at end: ${fd_last}"
FAILED=0
# Steady-state (dedup corpus) should plateau; >2x from the warmed baseline is a leak.
if [ "${first:-0}" -gt 0 ] && [ "${last:-0}" -gt $(( first * 2 )) ]; then
    echo "SOAK: FAIL (RSS grew >2x over steady-state churn — probable leak)"; FAILED=1
fi
if [ "${fd_last:-0}" -gt 500 ]; then
    echo "SOAK: FAIL (fd count high — probable descriptor leak)"; FAILED=1
fi
[ "$FAILED" = 0 ] && echo "SOAK: PASS" || exit 1
