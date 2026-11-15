//! Cairn chunk storage layer: content-addressed local cache with optional cloud fallback.
//!
//! Owns the shared `CloudOperator` handle (moved here from cairn-cdc — its natural home)
//! and the read path (`fetch_chunk`). The write/upload path currently still lives in
//! `cairn-cdc::Chunker::process_data`; folding it into a `ChunkStore` trait here is a
//! future refinement (see MIGRATION.md).

pub mod shared_dedup;

// Cloud storage handle, shared across the workspace. With the `cloud-storage` feature
// this is a real `opendal::Operator`; without it, a zero-sized `Clone` (not `Copy`)
// placeholder so struct fields / signatures compile unchanged while every network call
// path is cfg-gated out.

/// deterministic hash for RAID placement. Uses blake3 (stable,
/// cryptographically strong) instead of `DefaultHasher` (not guaranteed stable
/// across Rust versions — upgrading the toolchain could silently break RAID
/// placement, causing every chunk to hit the slow all-backend scan fallback).
pub fn stable_hash_index(key: &str, modulus: usize) -> usize {
    let hash = blake3::hash(key.as_bytes());
    let bytes = hash.as_bytes();
    let val = u64::from_le_bytes(bytes[..8].try_into().expect("blake3 output >= 8 bytes"));
    (val as usize) % modulus
}
/// site is `#[cfg]`-gated out.
#[cfg(feature = "cloud-storage")]
pub type CloudOperator = opendal::Operator;
#[cfg(not(feature = "cloud-storage"))]
#[derive(Clone)]
pub struct CloudOperator;

/// how long any single cloud read may block before it is abandoned.
/// The write path already retries with backoff; the read path had NO deadline, so a
/// half-open TCP connection or a black-holed backend could wedge `read`/`extract`/
/// `verify`/`scrub` indefinitely. Env-tunable via `CAIRN_CLOUD_READ_TIMEOUT_SECS`
/// (default 60s; a non-numeric or zero value falls back to the default).
#[cfg(feature = "cloud-storage")]
fn cloud_read_timeout() -> std::time::Duration {
    // an UNSET var silently uses the default (correct for a tuning knob), but a
    // SET-but-invalid value is almost certainly an operator typo — warn rather than
    // silently ignore it, so a mistyped timeout doesn't look like it took effect.
    let secs = match std::env::var("CAIRN_CLOUD_READ_TIMEOUT_SECS") {
        Ok(v) => v.parse::<u64>().ok().filter(|&s| s > 0).unwrap_or_else(|| {
            tracing::warn!("invalid CAIRN_CLOUD_READ_TIMEOUT_SECS='{v}' — using default 60s");
            60
        }),
        Err(_) => 60,
    };
    std::time::Duration::from_secs(secs)
}

/// read one object from a cloud backend under a hard deadline, so a single
/// stalled backend cannot hang the whole read path. Returns the raw bytes, or an
/// error on backend failure OR timeout (the caller falls through to the next backend
/// / RAID reconstruction, exactly as it already does on a normal read error).
#[cfg(feature = "cloud-storage")]
async fn read_op_with_timeout(op: &CloudOperator, path: &str) -> anyhow::Result<Vec<u8>> {
    let dur = cloud_read_timeout();
    match tokio::time::timeout(dur, op.read(path)).await {
        Ok(Ok(buf)) => Ok(buf.to_vec()),
        Ok(Err(e)) => Err(anyhow::anyhow!("cloud read failed for {path}: {e}")),
        Err(_) => Err(anyhow::anyhow!(
            "cloud read timed out after {}s for {path}",
            dur.as_secs()
        )),
    }
}

/// Fetch a chunk's stored blob by content hash: local cacache first, then each cloud
/// operator in turn (stripping the wrapped-key header and warming the local cache on
/// hit). Returns the raw stored ciphertext — decryption is the caller's responsibility.
#[cfg_attr(not(feature = "cloud-storage"), allow(unused_variables))]
pub async fn fetch_chunk_impl(
    cache_dir: &str,
    operators: &[CloudOperator],
    hash_key: &str,
    raid_mode: &str,
    skip_verify: bool,
    auto_heal: bool,
    force_cloud: bool,
) -> anyhow::Result<Vec<u8>> {
    if !force_cloud {
        if let Ok(data) = cacache::read(cache_dir, hash_key).await {
            if skip_verify {
                return Ok(data);
            }
            let hash = blake3::hash(&data).to_hex().to_string();
            if hash == hash_key {
                return Ok(data);
            } else {
                tracing::warn!(
                    "Local cache chunk {} is corrupted, fetching from remote",
                    hash_key
                );
                // log cache removal failures instead of silently
                // discarding. A persistent failure (permissions, FS full) would
                // cause the corrupted entry to be retried on every read.
                if let Err(e) = cacache::remove(cache_dir, hash_key).await {
                    tracing::warn!("Failed to remove corrupt cache entry {hash_key}: {e}");
                }
            }
        }
    }

    #[cfg(not(feature = "cloud-storage"))]
    {
        let _ = operators;
        let _ = raid_mode;
        let _ = skip_verify;
        let _ = auto_heal;
        let _ = force_cloud;
        anyhow::bail!("Chunk missing from local cache and cloud-storage feature is disabled");
    }

    #[cfg(feature = "cloud-storage")]
    {
        let s3_path = format!("chunks/{hash_key}");

        if raid_mode == "raid5" || raid_mode == "raid6" {
            let parity_shards: usize = if raid_mode == "raid5" { 1 } else { 2 };
            // Guard against an under-provisioned topology: `operators.len() -
            // parity_shards` would underflow (usize panic) when there are fewer
            // backends than parity shards. Match the upload path's
            // `saturating_sub().max(1)`, and bail early with a clear error
            // instead of handing ReedSolomon an impossible (data=0) config.
            if operators.len() < parity_shards + 1 {
                anyhow::bail!(
                    "{raid_mode} needs at least {} backends, got {}",
                    parity_shards + 1,
                    operators.len()
                );
            }
            let data_shards = operators.len().saturating_sub(parity_shards).max(1);

            let mut fetches = Vec::new();
            for op in operators {
                // each shard read is bounded by a deadline so one stalled
                // backend cannot block the whole parity fan-out / reconstruction.
                fetches.push(read_op_with_timeout(op, &s3_path));
            }
            let results = futures::future::join_all(fetches).await;
            let shards: Vec<Option<Vec<u8>>> = results
                .into_iter()
                .enumerate()
                .map(|(i, r)| match r {
                    Ok(d) => Some(d),
                    Err(e) => {
                        // log shard read errors instead of
                        // silently discarding. Without this, a total backend
                        // failure (expired creds, network partition) produces no
                        // log output — the operator can't distinguish "no data"
                        // from "backend down".
                        tracing::warn!("RAID shard {i} read error: {e}");
                        None
                    }
                })
                .collect();

            let r = reed_solomon_erasure::galois_8::ReedSolomon::new(data_shards, parity_shards)
                .map_err(|e| anyhow::anyhow!("RS error: {e:?}"))?;

            // the erasure-coded payload is `[exact_len:4][raw ciphertext]`.
            // The 4-byte length prefix is still needed (reed-solomon pads shards
            // to equal size, so we must recover the exact original length), but
            // there is NO wrapped-key header inside — the object is raw ciphertext
            // and `blake3(object) == hash_key`.
            let extract_and_verify = |reconstructed: &[u8], hash_key: &str| -> Option<Vec<u8>> {
                if reconstructed.len() >= 4 {
                    let exact_len = u32::from_le_bytes([
                        reconstructed[0],
                        reconstructed[1],
                        reconstructed[2],
                        reconstructed[3],
                    ]) as usize;
                    if reconstructed.len() >= 4 + exact_len {
                        let payload_slice = &reconstructed[4..4 + exact_len];
                        if skip_verify {
                            return Some(payload_slice.to_vec());
                        }
                        let hash = blake3::hash(payload_slice).to_hex().to_string();
                        if hash == hash_key {
                            return Some(payload_slice.to_vec());
                        }
                    }
                }
                None
            };

            let mut success_payload = None;
            let mut healed_shards = None;
            let mut reconstructed = Vec::new();

            // Try 0 (all available)construct assuming no corruption (only missing shards are None)
            let mut current_shards = shards.clone();
            if r.reconstruct(&mut current_shards).is_ok() {
                reconstructed.clear();
                for s in current_shards.iter().take(data_shards).flatten() {
                    reconstructed.extend_from_slice(s);
                }
                if let Some(payload) = extract_and_verify(&reconstructed, hash_key) {
                    success_payload = Some(payload);
                    if shards.iter().any(std::option::Option::is_none) {
                        tracing::warn!(
                            "RAID missing shards for chunk {}, recovered via parity",
                            hash_key
                        );
                        healed_shards = Some(current_shards);
                    } else {
                        // all shards were present, so the DATA verified —
                        // but a PARITY shard can be silently corrupt (a wrong
                        // value, not a missing one). Re-encode the parity from the
                        // intact data shards and compare; heal any that differ, or
                        // the redundancy is silently degraded and a later lost data
                        // shard becomes unrecoverable.
                        let shard_size = current_shards
                            .first()
                            .and_then(|s| s.as_ref())
                            .map_or(0, Vec::len);
                        let mut check: Vec<Vec<u8>> = Vec::with_capacity(current_shards.len());
                        for s in current_shards.iter().take(data_shards) {
                            check.push(s.clone().unwrap_or_default());
                        }
                        for _ in 0..parity_shards {
                            check.push(vec![0u8; shard_size]);
                        }
                        if r.encode(&mut check).is_ok() {
                            let parity_bad = (data_shards..current_shards.len()).any(|idx| {
                                current_shards[idx].as_deref() != Some(check[idx].as_slice())
                            });
                            if parity_bad {
                                tracing::warn!(
                                    "RAID parity shard(s) corrupt for chunk {}, re-encoding + healing",
                                    hash_key
                                );
                                let mut corrected = current_shards.clone();
                                for idx in data_shards..corrected.len() {
                                    corrected[idx] = Some(std::mem::take(&mut check[idx]));
                                }
                                healed_shards = Some(corrected);
                            }
                        }
                    }
                }
            }

            // Try dropping 1 shard
            if success_payload.is_none() {
                for i in 0..operators.len() {
                    if shards[i].is_some() {
                        let mut test_shards = shards.clone();
                        test_shards[i] = None;
                        let available = test_shards.iter().filter(|s| s.is_some()).count();
                        if available >= data_shards && r.reconstruct(&mut test_shards).is_ok() {
                            reconstructed.clear();
                            for s in test_shards.iter().take(data_shards).flatten() {
                                reconstructed.extend_from_slice(s);
                            }
                            if let Some(payload) = extract_and_verify(&reconstructed, hash_key) {
                                success_payload = Some(payload);
                                tracing::warn!(
                                    "RAID recovery successful: chunk {} was corrupted on backend {}, but recovered via parity",
                                    hash_key,
                                    i
                                );
                                healed_shards = Some(test_shards);
                                break;
                            }
                        }
                    }
                }
            }

            // Try dropping 2 shards (only for raid6)
            if success_payload.is_none() && raid_mode == "raid6" {
                for i in 0..operators.len() {
                    for j in (i + 1)..operators.len() {
                        if shards[i].is_some() && shards[j].is_some() {
                            let mut test_shards = shards.clone();
                            test_shards[i] = None;
                            test_shards[j] = None;
                            let available = test_shards.iter().filter(|s| s.is_some()).count();
                            if available >= data_shards && r.reconstruct(&mut test_shards).is_ok() {
                                reconstructed.clear();
                                for s in test_shards.iter().take(data_shards).flatten() {
                                    reconstructed.extend_from_slice(s);
                                }
                                if let Some(payload) = extract_and_verify(&reconstructed, hash_key)
                                {
                                    success_payload = Some(payload);
                                    tracing::warn!(
                                        "RAID-6 recovery successful: chunk {} was corrupted on backends {} and {}, but recovered via dual parity",
                                        hash_key,
                                        i,
                                        j
                                    );
                                    healed_shards = Some(test_shards);
                                    break;
                                }
                            }
                        }
                    }
                    if success_payload.is_some() {
                        break;
                    }
                }
            }

            if let Some(payload) = success_payload {
                if let Err(e) = cacache::write(cache_dir, hash_key, &payload).await {
                    tracing::warn!("Failed to write local cache entry {hash_key}: {e}");
                }
                if auto_heal {
                    if let Some(repaired) = healed_shards {
                        let s3_path = s3_path.clone();
                        let ops_clone = operators.to_vec();
                        let hash_clone = hash_key.to_string();
                        // wrap the auto-heal body in
                        // `catch_unwind` so a panic (e.g. from a future opendal
                        // change) surfaces as a `tracing::error!` instead of
                        // a silent tokio-runtime warning. The previous
                        // `tokio::spawn` was panic-blind. The rate limiter
                        // for the heal path is not plumbed in here yet
                        // (would require extending `fetch_chunk_impl`'s
                        // signature); the heal is bounded by `auto_heal`'s
                        // call sites, so a flapping backend produces at most
                        // a few tasks per fetch.
                        tokio::spawn(async move {
                            let body = async {
                                for (idx, shard_opt) in repaired.into_iter().enumerate() {
                                    if let Some(shard_data) = shard_opt {
                                        let op = &ops_clone[idx];
                                        if let Err(e) = op.write(&s3_path, shard_data).await {
                                            tracing::error!(
                                                "Auto-heal failed to write shard \
                                                 {} for chunk {}: {}",
                                                idx,
                                                hash_clone,
                                                e
                                            );
                                        } else {
                                            tracing::info!(
                                                "Auto-heal successfully wrote \
                                                 repaired shard {} for chunk {}",
                                                idx,
                                                hash_clone
                                            );
                                        }
                                    }
                                }
                            };
                            use futures::FutureExt;
                            use std::panic::AssertUnwindSafe;
                            if let Err(panic) = AssertUnwindSafe(body).catch_unwind().await {
                                tracing::error!(
                                    "Auto-heal task for chunk {} PANICKED: {:?}",
                                    hash_clone,
                                    panic
                                );
                            }
                        });
                    }
                }
                return Ok(payload);
            }
            anyhow::bail!("Chunk {hash_key} reconstruction failed or corrupt on all combinations");
        } else {
            let target_ops: Vec<usize> = if operators.is_empty() {
                Vec::new()
            } else if raid_mode == "raid10" && operators.len() >= 2 {
                let hash_val = stable_hash_index(hash_key, operators.len());
                let num_pairs = operators.len() / 2;
                let pair_idx = (hash_val / 2) % num_pairs;
                vec![pair_idx * 2, pair_idx * 2 + 1]
            } else if raid_mode == "raid0" {
                let idx = stable_hash_index(hash_key, operators.len());
                vec![idx]
            } else {
                // unknown raid_mode (typo like "rad5") silently
                // falls back to full replication. Log a warning so the operator
                // knows their config isn't being used as expected.
                if !raid_mode.is_empty() {
                    tracing::warn!(
                        "Unknown raid_mode '{raid_mode}', falling back to full replication on all backends"
                    );
                }
                (0..operators.len()).collect()
            };

            let mut found_payload = None;
            let mut found_data_vec = None;
            let mut needs_heal = false;

            // the S3 object is the RAW ciphertext (`blake3(object) ==
            // hash_key`), identical to the local cacache blob. The dominant
            // upload path (backup → enqueue → push → upload_chunk_from_cache)
            // uploads the cache blob verbatim, and the wrapped key is never
            // read from the object (data chunks take it from chunk_index,
            // index chunks from the manifest). An earlier revision assumed a
            // `[wk_len][wrapped_key]` prefix here and stripped it, so every
            // push-uploaded chunk read back as "corrupted"/"missing".
            for &idx in &target_ops {
                let op = &operators[idx];
                // bounded read — a wedged replica falls through to the next.
                if let Ok(data) = read_op_with_timeout(op, &s3_path).await {
                    let data_vec = data;
                    if skip_verify {
                        // --dangerously-skip-verify accepts cloud bytes
                        // unverified. Warn so it is visible in logs (the local
                        // cache path warns on corruption; the cloud path was silent).
                        tracing::warn!(
                            "skip-verify: accepting chunk {} from backend {} WITHOUT blake3 verification",
                            hash_key,
                            idx
                        );
                        found_payload = Some(data_vec.clone());
                        found_data_vec = Some(data_vec);
                        break;
                    }
                    let hash = blake3::hash(&data_vec).to_hex().to_string();
                    if hash == hash_key {
                        found_payload = Some(data_vec.clone());
                        found_data_vec = Some(data_vec);
                        break;
                    }
                    tracing::warn!("RAID replica {} for chunk {} is corrupted", idx, hash_key);
                    needs_heal = true;
                } else {
                    tracing::warn!(
                        "RAID replica {} for chunk {} is missing/unreadable",
                        idx,
                        hash_key
                    );
                    needs_heal = true;
                }
            }

            if found_payload.is_none() {
                // Fallback to searching ALL operators for robustness
                for (i, op) in operators.iter().enumerate() {
                    // bounded read in the all-backend fallback scan too.
                    if let Ok(data) = read_op_with_timeout(op, &s3_path).await {
                        let data_vec = data;
                        let hash = blake3::hash(&data_vec).to_hex().to_string();
                        if hash == hash_key {
                            found_payload = Some(data_vec.clone());
                            found_data_vec = Some(data_vec);
                            needs_heal = true;
                            tracing::warn!(
                                "Chunk {} recovered from unexpected backend {}",
                                hash_key,
                                i
                            );
                            break;
                        }
                    }
                }
            }

            if let Some(payload) = found_payload {
                if let Err(e) = cacache::write(cache_dir, hash_key, &payload).await {
                    tracing::warn!("Failed to write local cache entry {hash_key}: {e}");
                }
                if auto_heal && needs_heal {
                    if let Some(upload_data) = found_data_vec {
                        let s3_path = s3_path.clone();
                        let ops_clone = operators.to_vec();
                        let hash_clone = hash_key.to_string();
                        // wrap in catch_unwind like the raid5/6 heal path so
                        // a panic (e.g. a future opendal change) surfaces as an
                        // error log instead of a silent tokio-runtime warning.
                        tokio::spawn(async move {
                            use futures::FutureExt;
                            use std::panic::AssertUnwindSafe;
                            let body = async {
                                for idx in target_ops {
                                    let op = &ops_clone[idx];
                                    if let Err(e) = op.write(&s3_path, upload_data.clone()).await {
                                        tracing::error!(
                                            "Auto-heal failed to write replica {} for chunk {}: {}",
                                            idx,
                                            hash_clone,
                                            e
                                        );
                                    } else {
                                        tracing::info!(
                                            "Auto-heal successfully wrote replica {} for chunk {}",
                                            idx,
                                            hash_clone
                                        );
                                    }
                                }
                            };
                            if let Err(panic) = AssertUnwindSafe(body).catch_unwind().await {
                                tracing::error!(
                                    "Auto-heal task for chunk {} PANICKED: {:?}",
                                    hash_clone,
                                    panic
                                );
                            }
                        });
                    }
                }
                return Ok(payload);
            }
        }
    }

    #[cfg(feature = "cloud-storage")]
    anyhow::bail!("Chunk missing from S3")
}

#[cfg(feature = "cloud-storage")]
pub async fn upload_chunk_impl(
    upload_data: Vec<u8>,
    hash_key: &str,
    operators: &[CloudOperator],
    raid_mode: &str,
    rate_limiter: &Option<std::sync::Arc<leaky_bucket::RateLimiter>>,
    sleep_secs: &(dyn Fn(u32) -> u64 + Send + Sync),
) -> anyhow::Result<()> {
    if operators.is_empty() {
        return Ok(());
    }
    let s3_path = format!("chunks/{hash_key}");

    // Compute the per-backend payloads ONCE (content-addressed → identical across
    // retries, so rewriting a backend is idempotent). `None` means "this backend
    // holds nothing for this chunk under this RAID mode" (raid0 → one replica;
    // raid10 → the chosen pair); the upload loop only writes `Some(..)` slots.
    let per_backend: Vec<Option<Vec<u8>>> =
        build_raid_shards(&upload_data, operators, raid_mode, hash_key)?;
    if per_backend.len() != operators.len() {
        anyhow::bail!(
            "RAID shard plan length {} != operators {} (internal bug)",
            per_backend.len(),
            operators.len()
        );
    }

    // Retry ONLY the backends that failed (or were skipped), not all of them. A
    // partial failure used to re-upload every backend on the next attempt,
    // leaving shards from different generations side by side; a reconstruct that
    // mixed them could return garbage that passes the length check. Since shards
    // are content-addressed and deterministic, retrying just the missing ones
    // converges to full consistency.
    let mut pending: Vec<usize> = (0..operators.len())
        .filter(|&i| per_backend[i].is_some())
        .collect();
    if pending.is_empty() {
        return Ok(()); // e.g. raid0 with zero operators handled above
    }
    let mut attempt = 0u32;
    loop {
        let mut failed: Vec<usize> = Vec::new();
        let mut write_futures = Vec::with_capacity(pending.len());
        for &idx in &pending {
            let s3_path_clone = s3_path.clone();
            let shard_data = per_backend[idx].clone().ok_or_else(|| {
                anyhow::anyhow!("internal error: missing shard for backend {idx}")
            })?;
            let op_clone = operators[idx].clone();
            let rl_clone = rate_limiter.clone();
            let up_len = upload_data.len();
            write_futures.push(async move {
                if let Some(rl) = rl_clone {
                    rl.acquire(up_len).await;
                }
                (idx, op_clone.write(&s3_path_clone, shard_data).await)
            });
        }
        let results = futures::future::join_all(write_futures).await;
        for (idx, res) in results {
            if let Err(e) = res {
                tracing::warn!("upload: backend {idx} failed for {hash_key}: {e}");
                failed.push(idx);
            }
        }

        if failed.is_empty() {
            if attempt > 0 {
                tracing::info!(
                    "upload: chunk {hash_key} fully consistent after {attempt} retry round(s)"
                );
            } else {
                tracing::debug!("Successfully uploaded chunk {} to {}", hash_key, raid_mode);
            }
            return Ok(());
        }

        attempt += 1;
        if attempt >= 6 {
            return Err(anyhow::anyhow!(
                "S3 upload for chunk {hash_key} incomplete after {attempt} attempts: \
                 backends still failing: {failed:?}. The chunk is NOT fully redundant — \
                 run `scrub`/re-upload to heal."
            ));
        }
        let backoff = std::cmp::min(30u64, 1u64 << attempt);
        tracing::error!(
            "S3 upload partial for chunk {} (round {}/6): {} backend(s) failed {failed:?}; \
             retrying only those in {}s...",
            hash_key,
            attempt,
            failed.len(),
            backoff
        );
        tokio::time::sleep(std::time::Duration::from_secs(sleep_secs(attempt))).await;
        pending = failed;
    }
}

/// Compute the per-backend shard payloads for a chunk under the given RAID mode.
/// Each operator gets exactly one slot; `None` means the operator holds nothing
/// for this chunk (raid0 → one replica; raid10 → the chosen pair). The layout
/// matches the fetch path (raid1/raid10/raid0/fallback = full payload;
/// raid5/6 = Reed-Solomon data+parity shards with a 4-byte little-endian length
/// prefix). Centralizing this lets the upload path retry only failed backends
/// without recomputing the plan each round.
#[cfg(feature = "cloud-storage")]
fn build_raid_shards(
    upload_data: &[u8],
    operators: &[CloudOperator],
    raid_mode: &str,
    hash_key: &str,
) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
    let n = operators.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    if raid_mode == "raid10" && n >= 2 {
        let hash_val = stable_hash_index(hash_key, n);
        let num_pairs = n / 2;
        let pair_idx = (hash_val / 2) % num_pairs;
        let mut plan = vec![None; n];
        let payload = upload_data.to_vec();
        plan[pair_idx * 2] = Some(payload.clone());
        plan[pair_idx * 2 + 1] = Some(payload);
        return Ok(plan);
    }
    if raid_mode == "raid0" {
        let idx = stable_hash_index(hash_key, n);
        let mut plan = vec![None; n];
        plan[idx] = Some(upload_data.to_vec());
        return Ok(plan);
    }
    if raid_mode == "raid5" || raid_mode == "raid6" {
        let parity_shards: usize = if raid_mode == "raid5" { 1 } else { 2 };
        if n < parity_shards + 1 {
            anyhow::bail!(
                "{raid_mode} needs at least {} backends, got {n}",
                parity_shards + 1
            );
        }
        let data_shards = n.saturating_sub(parity_shards).max(1);
        // a chunk larger than u32::MAX would silently
        // truncate `exact_len` and the read-side `extract_and_verify` would
        // short-read, returning the chunk as "unrecoverable" without ever
        // surfacing a real error. The chunker max is 262 KiB today, so this
        // is unreachable in practice; the assert is a tripwire if someone
        // raises the chunker constants past 4 GiB in the future.
        // enforce the u32 manifest bound at RUNTIME, not only under
        // debug_assertions. The chunker maxes at 262 KiB today so this is currently
        // unreachable, but a silent `as u32` truncation in --release would make the
        // read-side short-read and mis-report the chunk as unrecoverable. Fail loudly.
        if upload_data.len() > u32::MAX as usize {
            anyhow::bail!(
                "chunk too large for the u32 manifest: {} bytes (max {})",
                upload_data.len(),
                u32::MAX
            );
        }
        let exact_len = upload_data.len() as u32;
        let data_to_encode_len = upload_data.len() + 4;
        let shard_size = data_to_encode_len.div_ceil(data_shards);

        let mut padded = Vec::with_capacity(shard_size * data_shards);
        padded.extend_from_slice(&exact_len.to_le_bytes());
        padded.extend_from_slice(upload_data);
        padded.resize(shard_size * data_shards, 0);

        let mut shards: Vec<Vec<u8>> = vec![vec![0; shard_size]; n];
        for (i, shard) in shards.iter_mut().enumerate().take(data_shards) {
            let start = i * shard_size;
            shard.copy_from_slice(&padded[start..start + shard_size]);
        }

        let r = reed_solomon_erasure::galois_8::ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| anyhow::anyhow!("RS error: {e:?}"))?;
        r.encode(&mut shards)
            .map_err(|e| anyhow::anyhow!("RS encode error: {e:?}"))?;
        return Ok(shards.into_iter().map(Some).collect());
    }
    // raid1 / fallback: full payload to every backend.
    Ok((0..n).map(|_| Some(upload_data.to_vec())).collect())
}

#[cfg(feature = "cloud-storage")]
pub async fn upload_chunk_from_cache_impl(
    cache_dir: &str,
    hash_key: &str,
    operators: &[CloudOperator],
    raid_mode: &str,
    rate_limiter: &Option<std::sync::Arc<leaky_bucket::RateLimiter>>,
) -> anyhow::Result<()> {
    let data = cacache::read(cache_dir, hash_key).await?;
    // verify the cache blob against its content hash BEFORE propagating to
    // the cloud. A bit-rotted / partially-written cache entry would otherwise be
    // pushed to every backend identically — RAID reconstruction cannot recover
    // from a chunk that is corrupt on all replicas. Fail loud and drop the bad
    // entry so a re-backup re-creates it.
    let computed = blake3::hash(&data).to_hex().to_string();
    if computed != hash_key {
        if let Err(e) = cacache::remove(cache_dir, hash_key).await {
            tracing::warn!("failed to remove corrupt cache entry {hash_key}: {e}");
        }
        anyhow::bail!(
            "local cache corruption: chunk {hash_key} hashes to {computed} — \
             refusing to upload corrupt data to cloud"
        );
    }
    upload_chunk_impl(data, hash_key, operators, raid_mode, rate_limiter, &|n| {
        std::cmp::min(30u64, 1u64 << n)
    })
    .await
}

#[async_trait::async_trait]
pub trait ChunkStore: Send + Sync {
    async fn fetch_chunk(
        &self,
        hash_key: &str,
        raid_mode: &str,
        skip_verify: bool,
        auto_heal: bool,
        force_cloud: bool,
    ) -> anyhow::Result<Vec<u8>>;
    async fn upload_chunk(
        &self,
        upload_data: Vec<u8>,
        hash_key: &str,
        raid_mode: &str,
    ) -> anyhow::Result<()>;
    async fn upload_chunk_from_cache(&self, hash_key: &str, raid_mode: &str) -> anyhow::Result<()>;
}

pub struct CairnStore {
    pub cache_dir: String,
    pub operators: Vec<CloudOperator>,
    pub rate_limiter: Option<std::sync::Arc<leaky_bucket::RateLimiter>>,
}

impl CairnStore {
    #[must_use]
    pub const fn new(
        cache_dir: String,
        operators: Vec<CloudOperator>,
        rate_limiter: Option<std::sync::Arc<leaky_bucket::RateLimiter>>,
    ) -> Self {
        Self {
            cache_dir,
            operators,
            rate_limiter,
        }
    }
}

#[async_trait::async_trait]
impl ChunkStore for CairnStore {
    async fn fetch_chunk(
        &self,
        hash_key: &str,
        raid_mode: &str,
        skip_verify: bool,
        auto_heal: bool,
        force_cloud: bool,
    ) -> anyhow::Result<Vec<u8>> {
        fetch_chunk_impl(
            &self.cache_dir,
            &self.operators,
            hash_key,
            raid_mode,
            skip_verify,
            auto_heal,
            force_cloud,
        )
        .await
    }

    #[cfg(feature = "cloud-storage")]
    async fn upload_chunk(
        &self,
        upload_data: Vec<u8>,
        hash_key: &str,
        raid_mode: &str,
    ) -> anyhow::Result<()> {
        upload_chunk_impl(
            upload_data,
            hash_key,
            &self.operators,
            raid_mode,
            &self.rate_limiter,
            &|n| std::cmp::min(30u64, 1u64 << n),
        )
        .await
    }

    #[cfg(not(feature = "cloud-storage"))]
    async fn upload_chunk(
        &self,
        _upload_data: Vec<u8>,
        _hash_key: &str,
        _raid_mode: &str,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    #[cfg(feature = "cloud-storage")]
    async fn upload_chunk_from_cache(&self, hash_key: &str, raid_mode: &str) -> anyhow::Result<()> {
        upload_chunk_from_cache_impl(
            &self.cache_dir,
            hash_key,
            &self.operators,
            raid_mode,
            &self.rate_limiter,
        )
        .await
    }

    #[cfg(not(feature = "cloud-storage"))]
    async fn upload_chunk_from_cache(
        &self,
        _hash_key: &str,
        _raid_mode: &str,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "cloud-storage")]
    use opendal::services::Memory;
    #[cfg(feature = "cloud-storage")]
    use std::time::Duration;

    fn create_mock_operator() -> CloudOperator {
        #[cfg(feature = "cloud-storage")]
        {
            let builder = Memory::default();
            opendal::Operator::new(builder).unwrap()
        }
        #[cfg(not(feature = "cloud-storage"))]
        {
            CloudOperator
        }
    }

    #[allow(dead_code)]
    fn setup_operators(n: usize) -> Vec<CloudOperator> {
        (0..n).map(|_| create_mock_operator()).collect()
    }

    #[allow(dead_code)]
    // the stored S3 object IS the raw ciphertext (`blake3(object) ==
    // hash_key`), identical to the local cacache blob — there is no
    // wrapped-key header. The test payload is the object verbatim.
    fn make_test_data(payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    #[tokio::test]
    async fn test_store_fetch_local() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let store = CairnStore::new(cache_dir.clone(), vec![], None);

        let payload = b"hello test data".to_vec();
        let hash = blake3::hash(&payload).to_hex().to_string();
        cacache::write(&cache_dir, &hash, &payload).await.unwrap();

        let fetched = store
            .fetch_chunk(&hash, "raid0", false, false, false)
            .await
            .unwrap();
        assert_eq!(fetched, payload);

        let fetched_skip = store
            .fetch_chunk(&hash, "raid0", true, false, false)
            .await
            .unwrap();
        assert_eq!(fetched_skip, payload);
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_local_corrupt_fallback() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(1);
        let store = CairnStore::new(cache_dir.clone(), ops.clone(), None);

        let payload = b"actual data".to_vec();
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();

        store
            .upload_chunk(data.clone(), &hash, "raid0")
            .await
            .unwrap();
        cacache::write(&cache_dir, &hash, b"corrupt").await.unwrap();

        let fetched = store
            .fetch_chunk(&hash, "raid0", false, false, false)
            .await
            .unwrap();
        assert_eq!(fetched, payload);
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_force_cloud() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(1);
        let store = CairnStore::new(cache_dir.clone(), ops, None);

        let payload = b"actual data".to_vec();
        let hash = blake3::hash(&payload).to_hex().to_string();
        cacache::write(&cache_dir, &hash, &payload).await.unwrap();

        let result = store.fetch_chunk(&hash, "raid0", false, false, true).await;
        assert!(result.is_err());
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_raid0() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(3);
        let store = CairnStore::new(cache_dir.clone(), ops, None);

        let payload = b"raid0 data".to_vec();
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();

        store
            .upload_chunk(data.clone(), &hash, "raid0")
            .await
            .unwrap();
        let fetched = store
            .fetch_chunk(&hash, "raid0", false, false, true)
            .await
            .unwrap();
        assert_eq!(fetched, payload);
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_raid1() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(3);
        let store = CairnStore::new(cache_dir.clone(), ops.clone(), None);

        let payload = b"raid1 data".to_vec();
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();

        store
            .upload_chunk(data.clone(), &hash, "raid1")
            .await
            .unwrap();

        let s3_path = format!("chunks/{}", hash);
        ops[0].write(&s3_path, vec![0, 0, 0, 0]).await.unwrap();
        ops[1].delete(&s3_path).await.unwrap();

        let fetched = store
            .fetch_chunk(&hash, "raid1", false, false, true)
            .await
            .unwrap();
        assert_eq!(fetched, payload);
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_raid10() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(4);
        let store = CairnStore::new(cache_dir.clone(), ops.clone(), None);

        let payload = b"raid10 data".to_vec();
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();

        store
            .upload_chunk(data.clone(), &hash, "raid10")
            .await
            .unwrap();

        let fetched = store
            .fetch_chunk(&hash, "raid10", false, false, true)
            .await
            .unwrap();
        assert_eq!(fetched, payload);
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_raid5() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(4);
        let store = CairnStore::new(cache_dir.clone(), ops.clone(), None);

        let payload = vec![42u8; 1024];
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();

        store
            .upload_chunk(data.clone(), &hash, "raid5")
            .await
            .unwrap();

        let fetched = store
            .fetch_chunk(&hash, "raid5", false, false, true)
            .await
            .unwrap();
        assert_eq!(fetched, payload);

        let s3_path = format!("chunks/{}", hash);
        ops[1].delete(&s3_path).await.unwrap();

        let fetched_rec = store
            .fetch_chunk(&hash, "raid5", false, false, true)
            .await
            .unwrap();
        assert_eq!(fetched_rec, payload);
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_raid6() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(5);
        let store = CairnStore::new(cache_dir.clone(), ops.clone(), None);

        let payload = vec![7u8; 500];
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();

        store
            .upload_chunk(data.clone(), &hash, "raid6")
            .await
            .unwrap();

        let s3_path = format!("chunks/{}", hash);
        ops[0].delete(&s3_path).await.unwrap();
        ops[2].delete(&s3_path).await.unwrap();

        let fetched_rec = store
            .fetch_chunk(&hash, "raid6", false, false, true)
            .await
            .unwrap();
        assert_eq!(fetched_rec, payload);

        let fetched_heal = store
            .fetch_chunk(&hash, "raid6", false, true, true)
            .await
            .unwrap();
        assert_eq!(fetched_heal, payload);
        let mut s0_result = None;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Ok(data) = ops[0].read(&s3_path).await {
                s0_result = Some(data);
                break;
            }
        }
        assert!(!s0_result.unwrap().is_empty());
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_upload_chunk_from_cache() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(2);
        let store = CairnStore::new(cache_dir.clone(), ops.clone(), None);

        let payload = b"cache to cloud".to_vec();
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();
        cacache::write(&cache_dir, &hash, &data).await.unwrap();

        store.upload_chunk_from_cache(&hash, "raid1").await.unwrap();

        let fetched = store
            .fetch_chunk(&hash, "raid1", false, false, true)
            .await
            .unwrap();
        assert_eq!(fetched, payload);
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_raid1_auto_heal() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(3);
        let store = CairnStore::new(cache_dir.clone(), ops.clone(), None);

        let payload = b"raid1 heal data".to_vec();
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();

        store
            .upload_chunk(data.clone(), &hash, "raid1")
            .await
            .unwrap();

        let s3_path = format!("chunks/{}", hash);
        ops[0].write(&s3_path, b"bad".to_vec()).await.unwrap();
        ops[1].delete(&s3_path).await.unwrap();

        let fetched = store
            .fetch_chunk(&hash, "raid1", false, true, true)
            .await
            .unwrap();
        assert_eq!(fetched, payload);

        let mut restored1_result = None;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Ok(data) = ops[1].read(&s3_path).await {
                restored1_result = Some(data);
                break;
            }
        }
        assert!(!restored1_result.unwrap().is_empty());
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_no_operators_errors() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let store = CairnStore::new(cache_dir.clone(), vec![], None);

        let payload = b"data".to_vec();
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();

        store
            .upload_chunk(data.clone(), &hash, "raid0")
            .await
            .unwrap();

        let result = store.fetch_chunk(&hash, "raid0", false, false, true).await;
        assert!(result.is_err());
    }

    #[cfg(feature = "cloud-storage")]
    #[tokio::test]
    async fn test_raid5_corruption() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let ops = setup_operators(4);
        let store = CairnStore::new(cache_dir.clone(), ops.clone(), None);

        let payload = vec![42u8; 1024];
        let data = make_test_data(&payload);
        let hash = blake3::hash(&payload).to_hex().to_string();

        store
            .upload_chunk(data.clone(), &hash, "raid5")
            .await
            .unwrap();

        let s3_path = format!("chunks/{}", hash);
        ops[0].write(&s3_path, b"corrupted".to_vec()).await.unwrap();

        let fetched = store
            .fetch_chunk(&hash, "raid5", false, true, true)
            .await
            .unwrap();
        assert_eq!(fetched, payload);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[cfg(not(feature = "cloud-storage"))]
    #[tokio::test]
    async fn test_not_cloud_storage() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let store = CairnStore::new(cache_dir.clone(), vec![], None);

        let payload = b"local only".to_vec();
        let data = vec![0, 0]; // actually mock without cloud storage doesn't care
        let hash = blake3::hash(&payload).to_hex().to_string();
        cacache::write(&cache_dir, &hash, &payload).await.unwrap();

        store
            .upload_chunk(data.clone(), &hash, "raid0")
            .await
            .unwrap();

        let fetched = store
            .fetch_chunk(&hash, "raid0", false, false, false)
            .await
            .unwrap();
        assert_eq!(fetched, payload);
    }
}
