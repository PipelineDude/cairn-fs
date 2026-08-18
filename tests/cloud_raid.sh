#!/usr/bin/env bash
# Cloud RAID e2e (S3/MinIO) — exercises EVERY RAID mode against K *separate*
# MinIO instances (distinct endpoints = distinct "providers", far more realistic
# than several buckets in one server). For each mode it proves:
#   1. healthy round-trip from cloud (local cache wiped),
#   2. shard/backend loss WITHIN tolerance still fully restores,
#   3. loss BEYOND tolerance FAILS LOUDLY — never silent wrong data (the property
#      that matters most for a backup tool),
#   4. corrupt object is detected (blake3) and, where redundant, reconstructed,
#   5. scrub --auto-heal repopulates a lost backend.
#
# Backend loss is induced two ways: bucket purge (backend up, shard gone) and
# `docker stop` (backend unreachable — the realistic case). The script starts K
# MinIO instances itself on ports away from any running soak (:9000) and stops
# what it started (KEEP_MINIO=1 to keep them).
#
# Not covered here (needs a real network / a fault-injection proxy — deferred):
# timeouts, throttling/503, latency, torn PUTs, degraded WRITE while a backend
# is already down. This file is the local-only slice.
#
# Usage: tests/cloud_raid.sh [path-to-cairn-binary]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
[ -x "$BIN" ] || BIN="$(realpath "$REPO/target/debug/cairn")"
[ -x "$BIN" ] || { echo "[FAIL] cairn binary not found"; exit 1; }

if ! "$BIN" x.db --help 2>/dev/null | grep -q "push"; then
    echo "[skip] binary built without cloud-storage"; exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "[skip] docker not available — cloud RAID e2e needs it to run MinIO"; exit 0
fi

K="${RAID_INSTANCES:-4}"
BASE_PORT="${RAID_BASE_PORT:-9100}"
CREDS="minioadmin:minioadmin"
BUCKET="raid"
PREFIX="cairn-raidmc"

port_of()  { echo $(( BASE_PORT + $1 * 10 )); }
name_of()  { echo "${PREFIX}-$1"; }
uri_of()   { echo "s3://${CREDS}@localhost:$(port_of "$1")/${BUCKET}?region=us-east-1"; }
alive_i()  { curl -s -o /dev/null --max-time 2 "http://localhost:$(port_of "$1")/minio/health/live"; }
mc_i()     { local _i="$1"; shift; docker exec "$(name_of "$_i")" mc "$@" >/dev/null 2>&1; }

STARTED=()
start_instances() {
    # Always start fresh — reusing a possibly-wedged instance from a prior run
    # led to flaky bucket creation. This test owns its instances.
    for i in $(seq 0 $((K-1))); do
        local nm; nm="$(name_of "$i")"; local port; port="$(port_of "$i")"
        docker rm -f "$nm" >/dev/null 2>&1 || true
        docker run -d --name "$nm" -p "${port}:9000" \
            minio/minio server /data >/dev/null 2>&1
        STARTED+=("$nm")
    done
    for i in $(seq 0 $((K-1))); do
        local ok=0 t
        for t in $(seq 1 60); do alive_i "$i" && { ok=1; break; }; sleep 1; done
        [ "$ok" = 1 ] || { echo "[FAIL] MinIO instance $i did not come up"; return 1; }
        # Create the bucket and VERIFY it — a fresh MinIO can pass /health/live
        # yet not be ready for the S3 API for a moment, so `mc mb` flakes. Retry
        # until `mc ls` actually shows the bucket (silent failure here = every
        # upload later dies NoSuchBucket).
        local made=0 t2
        for t2 in $(seq 1 15); do
            docker exec "$(name_of "$i")" mc alias set local "http://localhost:9000" minioadmin minioadmin >/dev/null 2>&1
            mc_i "$i" mb -p "local/${BUCKET}"
            if docker exec "$(name_of "$i")" mc ls "local/${BUCKET}" >/dev/null 2>&1; then made=1; break; fi
            sleep 1
        done
        [ "$made" = 1 ] || { echo "[FAIL] could not create bucket on instance $i"; return 1; }
    done
    return 0
}
W="$(mktemp -d /tmp/cairn-raid.XXXXXX)"
cleanup() {
    rm -rf "${W:-}" 2>/dev/null
    if [ "${KEEP_MINIO:-0}" != 1 ]; then
        for nm in "${STARTED[@]:-}"; do [ -n "$nm" ] && docker rm -f "$nm" >/dev/null 2>&1; done
    fi
}
trap cleanup EXIT

start_instances || exit 1
export CAIRN_PASSWORD="raid-pass" CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"
PASSED=0; FAILED=0
ok()   { PASSED=$((PASSED+1)); echo "    [ok] $1"; }
fail() { FAILED=$((FAILED+1)); echo "    [FAIL] $1"; }

cd "$W"; mkdir -p src
echo "raid inline small file" > src/small.txt
head -c 300000 /dev/urandom > src/big.bin       # multi-chunk, spans backends

# restore into a fresh dir and compare; returns 0 only if BOTH files byte-exact
restore_ok() {  # <db> <outdir>
    local db="$1" out="$2"
    rm -rf "$out"; mkdir -p "$out"
    "$BIN" "$db" extract "$out" >/dev/null 2>&1
    cmp -s src/small.txt "$out/data/small.txt" && cmp -s src/big.bin "$out/data/big.bin"
}
# assert LOUD failure: verify must exit non-zero AND no restored file is silently WRONG
assert_loud_failure() {  # <db> <label>
    local db="$1" label="$2"
    if "$BIN" "$db" verify >/dev/null 2>&1; then
        fail "$label: verify PASSED after loss beyond tolerance (silent data loss!)"; return
    fi
    local out="$W/loudout"; rm -rf "$out"; mkdir -p "$out"
    "$BIN" "$db" extract "$out" >/dev/null 2>&1 || true
    # any file that WAS produced must be correct (never wrong bytes); missing is OK
    local bad=0
    [ -f "$out/data/big.bin" ] && { cmp -s src/big.bin "$out/data/big.bin" || bad=1; }
    [ -f "$out/data/small.txt" ] && { cmp -s src/small.txt "$out/data/small.txt" || bad=1; }
    if [ "$bad" = 0 ]; then ok "$label: loss beyond tolerance fails loudly, no silent corruption"
    else fail "$label: restored WRONG BYTES after loss beyond tolerance (silent corruption!)"; fi
}
restart_all() { for i in $(seq 0 $((K-1))); do alive_i "$i" || docker start "$(name_of "$i")" >/dev/null 2>&1; done
                for i in $(seq 0 $((K-1))); do for _ in $(seq 1 30); do alive_i "$i" && break; sleep 1; done; done; }

# spec: mode | min_backends | recover-purge idx (space list, "-" none) | fail-purge idx
run_mode() {  # <mode> <recover_purge> <fail_purge>
    local mode="$1" recover="$2" failp="$3"
    echo "  === $mode ==="
    restart_all
    for i in $(seq 0 $((K-1))); do mc_i "$i" rm --recursive --force "local/${BUCKET}"; done
    local db="$W/${mode}.db"; rm -f "$db" "$db"-wal "$db"-shm "$db".lock; rm -rf "${db}_cache"
    "$BIN" "$db" init >/dev/null 2>&1
    for i in $(seq 0 $((K-1))); do "$BIN" "$db" raid add "$(uri_of "$i")" >/dev/null 2>&1; done
    "$BIN" "$db" raid set-mode "$mode" >/dev/null 2>&1 && ok "$mode: configured across $K backends" || fail "$mode: set-mode"
    "$BIN" "$db" backup "$W/src" /data >/dev/null 2>&1 || fail "$mode: backup"
    "$BIN" "$db" push >/dev/null 2>&1 || fail "$mode: push"

    rm -rf "${db}_cache"
    restore_ok "$db" "$W/h_out" && ok "$mode: healthy restore-from-cloud byte-exact" \
        || fail "$mode: healthy cloud restore broken"

    if [ "$recover" != "-" ]; then
        rm -rf "${db}_cache"
        for i in $recover; do mc_i "$i" rm --recursive --force "local/${BUCKET}"; done
        restore_ok "$db" "$W/r_out" \
            && ok "$mode: recovers after losing backend(s) [$recover] (within tolerance)" \
            || fail "$mode: could NOT recover within tolerance (lost [$recover])"
        # auto-heal: repopulate a purged backend from surviving redundancy
        local first; first=$(echo "$recover" | awk '{print $1}')
        "$BIN" "$db" scrub --auto-heal >/dev/null 2>&1
        sleep 1
        local n; n=$(docker exec "$(name_of "$first")" mc ls --recursive "local/${BUCKET}" 2>/dev/null | grep -c chunks)
        [ "${n:-0}" -gt 0 ] && ok "$mode: scrub --auto-heal repopulated backend $first ($n objs)" \
            || fail "$mode: auto-heal did not repopulate backend $first"
    fi

    # loss beyond tolerance → must fail loudly (rebuild clean first)
    restart_all
    for i in $(seq 0 $((K-1))); do mc_i "$i" rm --recursive --force "local/${BUCKET}"; done
    rm -f "$db" "$db"-wal "$db"-shm "$db".lock; rm -rf "${db}_cache"
    "$BIN" "$db" init >/dev/null 2>&1
    for i in $(seq 0 $((K-1))); do "$BIN" "$db" raid add "$(uri_of "$i")" >/dev/null 2>&1; done
    "$BIN" "$db" raid set-mode "$mode" >/dev/null 2>&1
    "$BIN" "$db" backup "$W/src" /data >/dev/null 2>&1
    "$BIN" "$db" push >/dev/null 2>&1
    rm -rf "${db}_cache"
    # raid0 stripes each chunk to a single hash-chosen backend, so a fixed index
    # may hold none of THIS file's chunks (purging it would lose nothing and the
    # loud-failure assert would misfire). Purge a backend that demonstrably holds
    # a chunk instead. Other modes place shards/replicas deterministically, so
    # their fixed fail-purge list is fine.
    if [ "$mode" = "raid0" ]; then
        local nonempty=""
        for i in $(seq 0 $((K-1))); do
            [ "$(docker exec "$(name_of "$i")" mc ls --recursive "local/${BUCKET}" 2>/dev/null | grep -c chunks)" -gt 0 ] \
                && { nonempty="$i"; break; }
        done
        failp="${nonempty:-0}"
    fi
    for i in $failp; do mc_i "$i" rm --recursive --force "local/${BUCKET}"; done
    assert_loud_failure "$db" "$mode"
}

echo "== Cloud RAID e2e across $K separate MinIO instances (ports $(port_of 0)..$(port_of $((K-1)))) =="
run_mode raid1  "1 2 3" "0 1 2 3"
run_mode raid5  "1"     "1 2"
run_mode raid6  "1 2"   "1 2 3"
run_mode raid10 "1 3"   "0 1"
run_mode raid0  "-"     "1"

echo
echo "== backend DOWN (docker stop, not just empty bucket) — raid1 realistic outage =="
restart_all
for i in $(seq 0 $((K-1))); do mc_i "$i" rm --recursive --force "local/${BUCKET}"; done
db="$W/down.db"; rm -f "$db"*; rm -rf "${db}_cache"
"$BIN" "$db" init >/dev/null 2>&1
for i in $(seq 0 $((K-1))); do "$BIN" "$db" raid add "$(uri_of "$i")" >/dev/null 2>&1; done
"$BIN" "$db" raid set-mode raid1 >/dev/null 2>&1
"$BIN" "$db" backup "$W/src" /data >/dev/null 2>&1
"$BIN" "$db" push >/dev/null 2>&1
rm -rf "${db}_cache"
docker stop "$(name_of 0)" >/dev/null 2>&1; docker stop "$(name_of 1)" >/dev/null 2>&1
restore_ok "$db" "$W/down_out" \
    && ok "raid1: restores with 2/4 backends STOPPED (connection refused, read from survivors)" \
    || fail "raid1: could not restore with 2 backends down"
restart_all

echo
echo "== corrupt object detection (blake3) + reconstruction (raid6) =="
restart_all
for i in $(seq 0 $((K-1))); do mc_i "$i" rm --recursive --force "local/${BUCKET}"; done
db="$W/corrupt.db"; rm -f "$db"*; rm -rf "${db}_cache"
"$BIN" "$db" init >/dev/null 2>&1
for i in $(seq 0 $((K-1))); do "$BIN" "$db" raid add "$(uri_of "$i")" >/dev/null 2>&1; done
"$BIN" "$db" raid set-mode raid6 >/dev/null 2>&1
"$BIN" "$db" backup "$W/src" /data >/dev/null 2>&1
"$BIN" "$db" push >/dev/null 2>&1
rm -rf "${db}_cache"
# overwrite one backend's shard objects with garbage
obj=$(docker exec "$(name_of 0)" mc ls --recursive "local/${BUCKET}" 2>/dev/null | awk '/chunks/{print $NF; exit}')
if [ -n "$obj" ]; then
    echo "GARBAGE-not-the-real-shard" | docker exec -i "$(name_of 0)" mc pipe "local/${BUCKET}/$obj" >/dev/null 2>&1
    restore_ok "$db" "$W/corr_out" \
        && ok "raid6: corrupt shard on backend 0 detected + reconstructed from parity" \
        || fail "raid6: corrupt shard broke restore (should reconstruct)"
else
    echo "    [skip] corrupt: no shard object found to corrupt"
fi

echo
echo "cloud_raid: passed $PASSED, failed $FAILED"
if [ "$FAILED" = 0 ]; then echo "CLOUD RAID: PASS"; exit 0; else echo "CLOUD RAID: FAIL"; exit 1; fi
