#!/usr/bin/env bash
# Cloud-path smoke (S3/MinIO): the first end-to-end exercise of the
# cfg(cloud-storage) code — restore-from-cloud, index pull bootstrap, RAID1
# backend loss + auto-heal. Requires an S3 endpoint (default: local MinIO,
# console-created buckets $BUCKET_A/$BUCKET_B/$BUCKET_C) and the default-feature
# (cloud) build.
#
# Usage: tests/cloud_smoke.sh [path-to-cairn-binary]
# Env:   CAIRN_S3_CREDS_HOST (default minioadmin:minioadmin@localhost:9000)
#        BUCKET_A/B/C        (default cairn-a/b/c)
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$REPO/target/release/cairn}")"
[ -x "$BIN" ] || BIN="$(realpath "$REPO/target/debug/cairn")"
[ -x "$BIN" ] || { echo "[FAIL] cairn binary not found"; exit 1; }

CREDS_HOST="${CAIRN_S3_CREDS_HOST:-minioadmin:minioadmin@localhost:9000}"
BUCKET_A="${BUCKET_A:-cairn-a}"; BUCKET_B="${BUCKET_B:-cairn-b}"; BUCKET_C="${BUCKET_C:-cairn-c}"
S3_HOST="${CREDS_HOST##*@}"
MINIO_CONTAINER="${MINIO_CONTAINER:-minio}"

if ! "$BIN" x.db --help 2>/dev/null | grep -q "push"; then
    echo "[skip] binary built without cloud-storage"; exit 0
fi

s3_alive() {
    curl -s -o /dev/null --max-time 3 "http://${S3_HOST}/minio/health/live" \
        || curl -s -o /dev/null --max-time 3 "http://${S3_HOST}/"
}

# Self-sufficient endpoint: when nothing answers on ${S3_HOST}, start MinIO in
# docker ourselves (reuse a stopped container, else create one). We stop it on
# exit ONLY if we started it here (KEEP_MINIO=1 overrides). A remote/non-local
# endpoint with no docker → clean skip, as before.
STARTED_MINIO=0
if ! s3_alive; then
    if command -v docker >/dev/null 2>&1 && [[ "$S3_HOST" == localhost:* || "$S3_HOST" == 127.0.0.* ]]; then
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$MINIO_CONTAINER"; then
            docker start "$MINIO_CONTAINER" >/dev/null 2>&1
        else
            docker run -d --name "$MINIO_CONTAINER" -p 9000:9000 -p 9001:9001 \
                minio/minio server /data --console-address ":9001" >/dev/null 2>&1
        fi
        STARTED_MINIO=1
        for _ in $(seq 1 60); do s3_alive && break; sleep 1; done
    fi
    if ! s3_alive; then
        echo "[skip] no S3 endpoint at ${S3_HOST} and could not start MinIO — cloud smoke not run"
        exit 0
    fi
fi
stop_minio() {
    [ "$STARTED_MINIO" = 1 ] && [ "${KEEP_MINIO:-0}" != 1 ] \
        && docker stop "$MINIO_CONTAINER" >/dev/null 2>&1
}

# Object-level asserts + bucket bootstrap via the container's own mc (best
# effort; a remote endpoint must have the buckets pre-created).
MC_OK=0
if docker exec "$MINIO_CONTAINER" mc --version >/dev/null 2>&1; then
    docker exec "$MINIO_CONTAINER" mc alias set local "http://localhost:9000" minioadmin minioadmin >/dev/null 2>&1 && MC_OK=1
    docker exec "$MINIO_CONTAINER" mc mb -p "local/$BUCKET_A" "local/$BUCKET_B" "local/$BUCKET_C" >/dev/null 2>&1
fi
bucket_count() {  # <bucket> → object count, or -1 when mc unavailable
    if [ "$MC_OK" = 1 ]; then docker exec minio mc ls --recursive "local/$1" 2>/dev/null | wc -l; else echo -1; fi
}
bucket_purge() { [ "$MC_OK" = 1 ] && docker exec minio mc rm --recursive --force "local/$1" >/dev/null 2>&1; }

W="$(mktemp -d /tmp/cairn-cloud.XXXXXX)"
trap 'rm -rf "$W"; stop_minio' EXIT
export CAIRN_PASSWORD="cloud-smoke-pass" CAIRN_KDF_ITER="${CAIRN_KDF_ITER:-1000}"
PASSED=0; FAILED=0
ok()   { PASSED=$((PASSED+1)); echo "  [ok] $1"; }
fail() { FAILED=$((FAILED+1)); echo "  [FAIL] $1"; }

cd "$W"; mkdir -p src
echo "small inline cloud payload" > src/small.txt
head -c 300000 /dev/urandom > src/big.bin

echo "== A. single S3 backend: backup → push → wipe cache → restore from cloud =="
"$BIN" a.db init >/dev/null 2>&1 || fail "A: init"
"$BIN" a.db raid add "s3://${CREDS_HOST}/${BUCKET_A}?region=us-east-1" >/dev/null 2>&1 \
    && ok "A: raid add s3 backend" || fail "A: raid add"
"$BIN" a.db backup "$W/src" /data >/dev/null 2>&1 && ok "A: backup" || fail "A: backup"
"$BIN" a.db push >/dev/null 2>&1 && ok "A: push exits 0" || fail "A: push"
CNT_A=$(bucket_count "$BUCKET_A")
[ "$CNT_A" = "-1" ] || { [ "$CNT_A" -gt 0 ] && ok "A: bucket has $CNT_A objects" || fail "A: bucket empty after push"; }
rm -rf a.db_cache
rm -rf out; mkdir out
"$BIN" a.db extract "$W/out" >/dev/null 2>&1 || fail "A: extract after cache wipe errored"
cmp -s src/small.txt out/data/small.txt && cmp -s src/big.bin out/data/big.bin \
    && ok "A: RESTORE FROM CLOUD byte-exact (local cache was wiped)" \
    || fail "A: cloud restore corrupted/missing"
rm -rf a.db_cache
"$BIN" a.db verify >/dev/null 2>&1 && ok "A: verify decrypts from cloud" || fail "A: verify from cloud"

# B uses ASYMMETRIC mode: lost-machine recovery brings priv.pem, which unwraps
# the cloud index. Symmetric mode cannot bootstrap from cloud alone — its KEK
# lives only inside the archive DB you are trying to restore (chicken-and-egg),
# by design. A separate bucket keeps B independent of A.
echo "== B. index pull bootstrap (lost machine: only cloud + priv key + password) =="
GEN="$(dirname "$BIN")/gen_keys"
if [ -x "$GEN" ]; then
    bucket_purge "$BUCKET_B"
    ( cd "$W" && "$GEN" >/dev/null 2>&1 )
    "$BIN" b.db init --pub-key "$W/pub.pem" >/dev/null 2>&1
    "$BIN" b.db raid add "s3://${CREDS_HOST}/${BUCKET_B}?region=us-east-1" >/dev/null 2>&1
    "$BIN" b.db backup "$W/src" /data --pub-key "$W/pub.pem" >/dev/null 2>&1
    "$BIN" b.db push --pub-key "$W/pub.pem" >/dev/null 2>&1
    # wipe the machine: only the cloud bucket + keys + password survive
    rm -f b.db b.db-wal b.db-shm b.db.lock; rm -rf b.db_cache
    "$BIN" b.db init --pub-key "$W/pub.pem" >/dev/null 2>&1
    "$BIN" b.db raid add "s3://${CREDS_HOST}/${BUCKET_B}?region=us-east-1" >/dev/null 2>&1
    if "$BIN" b.db pull --pub-key "$W/pub.pem" --priv-key "$W/priv.pem" >/dev/null 2>&1; then
        rm -rf out2; mkdir out2
        "$BIN" b.db extract "$W/out2" --pub-key "$W/pub.pem" --priv-key "$W/priv.pem" >/dev/null 2>&1
        cmp -s src/small.txt out2/data/small.txt && cmp -s src/big.bin out2/data/big.bin \
            && ok "B: pull bootstrap → extract byte-exact (lost-machine recovery)" \
            || fail "B: pull succeeded but extract wrong/missing"
    else
        fail "B: pull errored"
    fi
else
    echo "  [skip] B: gen_keys not next to binary (asymmetric bootstrap needs a keypair)"
fi

echo "== C. RAID1 across two buckets: survive backend loss + auto-heal =="
bucket_purge "$BUCKET_B"; bucket_purge "$BUCKET_C"
"$BIN" r.db init >/dev/null 2>&1
"$BIN" r.db raid add "s3://${CREDS_HOST}/${BUCKET_B}?region=us-east-1" >/dev/null 2>&1
"$BIN" r.db raid add "s3://${CREDS_HOST}/${BUCKET_C}?region=us-east-1" >/dev/null 2>&1
"$BIN" r.db raid set-mode raid1 >/dev/null 2>&1 && ok "C: raid1 configured" || fail "C: set-mode"
"$BIN" r.db backup "$W/src" /data >/dev/null 2>&1 || fail "C: backup"
"$BIN" r.db push >/dev/null 2>&1 || fail "C: push"
CB=$(bucket_count "$BUCKET_B"); CC=$(bucket_count "$BUCKET_C")
if [ "$CB" != "-1" ]; then
    [ "$CB" -gt 0 ] && [ "$CC" -gt 0 ] && ok "C: both mirrors populated (B=$CB C=$CC)" \
        || fail "C: mirror(s) empty after raid1 push (B=$CB C=$CC)"
fi
# Lose bucket B entirely, wipe local cache → reads must come from mirror C.
bucket_purge "$BUCKET_B"
rm -rf r.db_cache
rm -rf rout; mkdir rout
"$BIN" r.db extract "$W/rout" >/dev/null 2>&1
cmp -s src/big.bin rout/data/big.bin \
    && ok "C: RESTORE SURVIVES FULL BACKEND LOSS (read from mirror)" \
    || fail "C: raid1 restore failed after losing one bucket"
# Heal: scrub --auto-heal should re-upload missing chunks to B.
"$BIN" r.db scrub --auto-heal >/dev/null 2>&1 && ok "C: scrub --auto-heal exits 0" || fail "C: scrub --auto-heal"
CB2=$(bucket_count "$BUCKET_B")
if [ "$CB2" != "-1" ]; then
    [ "$CB2" -gt 0 ] && ok "C: auto-heal repopulated lost mirror (B=$CB2)" \
        || fail "C: mirror still empty after auto-heal"
fi

echo
echo "cloud_smoke: passed $PASSED, failed $FAILED"
if [ "$FAILED" = 0 ]; then echo "CLOUD SMOKE: PASS"; exit 0; else echo "CLOUD SMOKE: FAIL"; exit 1; fi
