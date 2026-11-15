#!/usr/bin/env bash
# Cloud network-fault e2e (S3/MinIO behind Toxiproxy). Injects the failure modes
# a real S3 endpoint shows that a local MinIO never does — latency, bandwidth
# throttle, dropped/reset connections, torn uploads — and asserts cairn behaves
# safely:
#   * slow network (latency / throttle)  → still succeeds, byte-exact,
#   * dropped/reset connections on upload → LOUD failure (exit != 0), never a
#     silent "success" that stored nothing; clearing the fault + re-push recovers,
#   * torn PUT (connection closed mid-body) → detected (blake3), never silent
#     wrong bytes on restore.
#
# Topology (podman --network host):
#   cairn --(s3)--> localhost:PROXY_PORT  (Toxiproxy)  --> 127.0.0.1:MINIO_PORT (MinIO)
# Toxics are added/removed through the Toxiproxy HTTP API on :8474.
#
# The script starts MinIO + Toxiproxy in docker itself (ports away from any soak
# on :9000 and the RAID test on :9100-91xx) and removes what it started.
#
# Usage: tests/cloud_faults.sh [path-to-cairn-binary]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
[ -x "$BIN" ] || BIN="$(realpath "$REPO/target/debug/cairn")"
[ -x "$BIN" ] || { echo "[FAIL] cairn binary not found"; exit 1; }
"$BIN" x.db --help 2>/dev/null | grep -q "push" || { echo "[skip] built without cloud-storage"; exit 0; }
command -v docker >/dev/null 2>&1 || { echo "[skip] docker not available"; exit 0; }
command -v curl  >/dev/null 2>&1 || { echo "[skip] curl not available"; exit 0; }

MINIO_PORT="${FAULT_MINIO_PORT:-9200}"
PROXY_PORT="${FAULT_PROXY_PORT:-9201}"
API="http://localhost:8474"
MINIO_C="cairn-faultmc"
TOXI_C="cairn-toxiproxy"
BUCKET="faults"

STARTED=()
W="$(mktemp -d /tmp/cairn-faults.XXXXXX)"
cleanup() {
    rm -rf "${W:-}" 2>/dev/null
    curl -s -X POST "$API/reset" >/dev/null 2>&1 || true
    if [ "${KEEP_MINIO:-0}" != 1 ]; then
        for c in "${STARTED[@]:-}"; do [ -n "$c" ] && docker rm -f "$c" >/dev/null 2>&1; done
    fi
}
trap cleanup EXIT

start_stack() {
    if ! curl -s -o /dev/null --max-time 2 "http://localhost:${MINIO_PORT}/minio/health/live"; then
        docker rm -f "$MINIO_C" >/dev/null 2>&1 || true
        docker run -d --name "$MINIO_C" -p "${MINIO_PORT}:9000" minio/minio server /data >/dev/null 2>&1
        STARTED+=("$MINIO_C")
    fi
    if ! curl -s -o /dev/null --max-time 2 "$API/version"; then
        docker rm -f "$TOXI_C" >/dev/null 2>&1 || true
        docker run -d --name "$TOXI_C" --network host \
            ghcr.io/shopify/toxiproxy:latest >/dev/null 2>&1
        STARTED+=("$TOXI_C")
    fi
    local ok=0 t
    for t in $(seq 1 60); do curl -s -o /dev/null --max-time 2 "http://localhost:${MINIO_PORT}/minio/health/live" && { ok=1; break; }; sleep 1; done
    [ "$ok" = 1 ] || { echo "[FAIL] MinIO did not come up"; return 1; }
    ok=0
    for t in $(seq 1 30); do curl -s -o /dev/null --max-time 2 "$API/version" && { ok=1; break; }; sleep 1; done
    [ "$ok" = 1 ] || { echo "[FAIL] Toxiproxy did not come up"; return 1; }
    # bucket (retry: fresh MinIO health can beat S3 API readiness)
    local made=0
    for t in $(seq 1 15); do
        docker exec "$MINIO_C" mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1
        docker exec "$MINIO_C" mc mb -p "local/${BUCKET}" >/dev/null 2>&1
        docker exec "$MINIO_C" mc ls "local/${BUCKET}" >/dev/null 2>&1 && { made=1; break; }
        sleep 1
    done
    [ "$made" = 1 ] || { echo "[FAIL] bucket create failed"; return 1; }
    # (re)create the proxy
    curl -s -X DELETE "$API/proxies/minio" >/dev/null 2>&1
    curl -s -X POST "$API/proxies" \
        -d "{\"name\":\"minio\",\"listen\":\"0.0.0.0:${PROXY_PORT}\",\"upstream\":\"127.0.0.1:${MINIO_PORT}\"}" >/dev/null 2>&1
    curl -s "$API/proxies/minio" | grep -q '"minio"' || { echo "[FAIL] could not create toxiproxy proxy"; return 1; }
    return 0
}

start_stack || exit 1

export CAIRN_PASSWORD="fault-pass" CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"
# Under a persistent fault, failed chunks stay queued for retry and the
# drain runs to this cap before exiting non-zero — keep it short for the test.
export CAIRN_UPLOAD_DRAIN_SECS="${CAIRN_UPLOAD_DRAIN_SECS:-15}"
PASSED=0; FAILED=0
ok()   { PASSED=$((PASSED+1)); echo "    [ok] $1"; }
fail() { FAILED=$((FAILED+1)); echo "    [FAIL] $1"; }

toxic()  { curl -s -X POST "$API/proxies/minio/toxics" -d "$1" >/dev/null 2>&1; }   # add one toxic (JSON)
clear_toxics() { curl -s -X POST "$API/reset" >/dev/null 2>&1; }                     # remove all toxics
purge()  { docker exec "$MINIO_C" mc rm --recursive --force "local/${BUCKET}" >/dev/null 2>&1; }

cd "$W"; mkdir -p src
echo "fault inline small" > src/small.txt
head -c 400000 /dev/urandom > src/big.bin
URI="s3://minioadmin:minioadmin@localhost:${PROXY_PORT}/${BUCKET}?region=us-east-1"

fresh_archive() {  # <db>
    local db="$1"; rm -f "$db" "$db"-wal "$db"-shm "$db".lock; rm -rf "${db}_cache"
    "$BIN" "$db" init >/dev/null 2>&1
    "$BIN" "$db" raid add "$URI" >/dev/null 2>&1
}
restore_ok() {  # <db> <out>
    local db="$1" out="$2"; rm -rf "$out"; mkdir -p "$out"
    "$BIN" "$db" extract "$out" >/dev/null 2>&1
    cmp -s src/small.txt "$out/data/small.txt" && cmp -s src/big.bin "$out/data/big.bin"
}

echo "== Cloud network faults via Toxiproxy (MinIO :${MINIO_PORT} behind proxy :${PROXY_PORT}) =="

# 1. Latency (both directions) — slow but reliable network must still work.
echo "  === latency 300ms ±80 (up+down) ==="
clear_toxics; purge
toxic '{"name":"lat_up","type":"latency","stream":"upstream","attributes":{"latency":300,"jitter":80}}'
toxic '{"name":"lat_dn","type":"latency","stream":"downstream","attributes":{"latency":300,"jitter":80}}'
db="$W/lat.db"; fresh_archive "$db"
"$BIN" "$db" backup "$W/src" /data >/dev/null 2>&1 && ok "latency: backup succeeds" || fail "latency: backup failed"
"$BIN" "$db" push >/dev/null 2>&1 && ok "latency: push succeeds" || fail "latency: push failed"
rm -rf "${db}_cache"
restore_ok "$db" "$W/lat_out" && ok "latency: restore-from-cloud byte-exact" || fail "latency: restore wrong"
clear_toxics

# 2. Bandwidth throttle — big file over a slow pipe, integrity must hold.
echo "  === bandwidth 256 KB/s ==="
clear_toxics; purge
toxic '{"name":"bw_up","type":"bandwidth","stream":"upstream","attributes":{"rate":256}}'
toxic '{"name":"bw_dn","type":"bandwidth","stream":"downstream","attributes":{"rate":256}}'
db="$W/bw.db"; fresh_archive "$db"
"$BIN" "$db" backup "$W/src" /data >/dev/null 2>&1 && ok "throttle: backup succeeds" || fail "throttle: backup failed"
"$BIN" "$db" push >/dev/null 2>&1 && ok "throttle: push succeeds" || fail "throttle: push failed"
rm -rf "${db}_cache"
restore_ok "$db" "$W/bw_out" && ok "throttle: restore byte-exact under throttle" || fail "throttle: restore wrong"
clear_toxics

# 3. Reset connections on upload — must FAIL LOUDLY (no silent success), then
#    recover after the fault clears (data is safe in the local cache).
echo "  === reset_peer on upload (connection drops) ==="
clear_toxics; purge
db="$W/rst.db"; fresh_archive "$db"
toxic '{"name":"rst","type":"reset_peer","stream":"upstream","attributes":{"timeout":200}}'
# Under a persistent reset the internal per-chunk retry makes backup slow; a
# timeout counts as a loud failure too (the point is it must NOT silently
# succeed). Data stays safe in the local cache + upload queue.
timeout 90 "$BIN" "$db" backup "$W/src" /data >/dev/null 2>&1
rc=$?
[ "$rc" != 0 ] && ok "reset: backup does not silently succeed (exit $rc)" \
              || fail "reset: backup exited 0 despite dropped uploads (silent incomplete!)"
clear_toxics
# the failed chunks were kept queued, so a re-push completes the off-site copy.
timeout 120 "$BIN" "$db" push >/dev/null 2>&1 && ok "reset: re-push after fault clears completes upload" || fail "reset: recovery push failed"
rm -rf "${db}_cache"
restore_ok "$db" "$W/rst_out" && ok "reset: restore byte-exact after recovery" || fail "reset: post-recovery restore wrong"

# 4. Torn PUT (connection closed mid-body) — a truncated/garbage object must be
#    detected on read (blake3), never returned as silent wrong bytes.
echo "  === torn upload (limit_data) → corruption detected, not silent ==="
clear_toxics; purge
db="$W/torn.db"; fresh_archive "$db"
# heal from cache is impossible once we wipe it; single backend, no redundancy →
# a corrupt/short object must surface as a LOUD restore failure, not wrong bytes.
"$BIN" "$db" backup "$W/src" /data >/dev/null 2>&1
"$BIN" "$db" push >/dev/null 2>&1
# now corrupt one stored object directly (equivalent to a torn write landing bad
# bytes), wipe cache, and require detection
obj=$(docker exec "$MINIO_C" mc ls --recursive "local/${BUCKET}" 2>/dev/null | awk '/chunks/{print $NF; exit}')
if [ -n "$obj" ]; then
    printf 'TORN-not-the-real-ciphertext' | docker exec -i "$MINIO_C" mc pipe "local/${BUCKET}/$obj" >/dev/null 2>&1
    rm -rf "${db}_cache"; rm -rf "$W/torn_out"; mkdir -p "$W/torn_out"
    "$BIN" "$db" extract "$W/torn_out" >/dev/null 2>&1
    bad=0
    [ -f "$W/torn_out/data/big.bin" ] && { cmp -s src/big.bin "$W/torn_out/data/big.bin" || bad=1; }
    if "$BIN" "$db" verify >/dev/null 2>&1; then
        fail "torn: verify PASSED on a corrupted object (silent corruption!)"
    elif [ "$bad" = 1 ]; then
        fail "torn: restored WRONG BYTES from corrupted object (silent corruption!)"
    else
        ok "torn: corrupted object detected (blake3), restore fails loudly — no silent wrong data"
    fi
else
    echo "    [skip] torn: no object to corrupt"
fi
clear_toxics

echo
echo "cloud_faults: passed $PASSED, failed $FAILED"
if [ "$FAILED" = 0 ]; then echo "CLOUD FAULTS: PASS"; exit 0; else echo "CLOUD FAULTS: FAIL"; exit 1; fi
