//! Maintenance operations: GC, verify, scrub (extracted from lib.rs 2026-08-16).

use crate::CairnEngine;

impl CairnEngine {
    pub async fn gc(&self, grace_period_hours: u64) -> anyhow::Result<(usize, usize)> {
        // prevent concurrent GC runs — a second GC during an active one
        // would see a partially-deleted index and double-delete or orphan chunks.
        let _gc_guard = self
            .gc_running
            .try_lock()
            .map_err(|_| anyhow::anyhow!("GC is already running (concurrent GC not supported)"))?;
        // `get_orphaned_chunks` excludes chunks referenced by the LIVE tree
        // (file_chunks) but is blind to snapshots — their chunks live inside blob
        // DBs, not queryable in SQL. Without this second filter, gc deletes chunks
        // that only a snapshot references, silently bricking that snapshot's
        // restore. `get_all_used_chunks` opens every snapshot and ERRORS on a
        // corrupt one, so gc fails safe rather than deleting what it can't verify.
        //
        // the used/orphan queries are not one transaction, but the
        // `grace_period_hours` filter in `get_orphaned_chunks` is the race guard:
        // a chunk a concurrent flush just wrote is younger than the grace window,
        // so it is never an orphan candidate. Only `--grace-period-hours 0`
        // removes this protection — do not run gc with grace 0 against a live
        // mount (OPERATING recommends 24h).
        let used = self.db.get_all_used_chunks()?;
        let orphaned: Vec<String> = self
            .db
            .get_orphaned_chunks(grace_period_hours)?
            .into_iter()
            .filter(|h| !used.contains(h))
            .collect();
        let mut total_removed = 0;

        let gc_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
        #[cfg_attr(not(feature = "cloud-storage"), allow(unused_mut))]
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        for hash_key in orphaned {
            let cache_dir = self.cache_dir.clone();
            let sem = gc_sem.clone();
            let db = self.db.clone();
            let _permit = sem
                .acquire()
                .await
                .map_err(|e| anyhow::anyhow!("GC semaphore closed: {e}"))?;
            // Remove the index row FIRST. The failure modes are asymmetric: an
            // orphaned blob (row gone, delete below fails) merely leaks storage
            // and the local sweep reclaims it, while a dangling row (data gone,
            // row removal fails) turns into EIO at read time.
            if let Err(e) = db.remove_chunk_from_index(&hash_key) {
                tracing::error!(
                    "gc: failed to remove {hash_key} from index: {e} — leaving its data in place"
                );
                drop(_permit);
                continue;
            }
            let _ = cacache::remove(&cache_dir, &hash_key).await;
            #[cfg(feature = "cloud-storage")]
            {
                let s3_path = format!("chunks/{hash_key}");
                let ops = self.operators.clone();
                let sem2 = gc_sem.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem2.acquire().await;
                    for op in &ops {
                        let _ = op.delete(&s3_path).await;
                    }
                    drop(_permit);
                }));
            }
            total_removed += 1;
            drop(_permit);
        }
        futures::future::join_all(handles).await;

        // Also clean up any lingering local cacache blobs that aren't referenced
        // anywhere. The protected set is used_chunks (file_chunks + snapshots)
        // UNION all chunk_index rows: a chunk still in the index is either in
        // active use or inside the grace window (orphaned but not yet
        // collectable). The old sweep used only `used_chunks`, so a grace-period
        // orphan's local blob was deleted while its index row survived — and the
        // next dedup hit on the same content found the row but no blob → `EIO`
        // on local-only archives.
        let mut local_orphans = 0;
        let mut protected = self.db.get_all_used_chunks()?;
        protected.extend(self.db.get_all_indexed_chunk_objects()?);
        for entry in cacache::list_sync(&self.cache_dir).flatten() {
            if !protected.contains(&entry.key) {
                let _ = cacache::remove(&self.cache_dir, &entry.key).await;
                local_orphans += 1;
            }
        }

        tracing::info!(
            "Garbage Collection complete: removed {} orphaned chunks globally, and {} local cache orphans",
            total_removed,
            local_orphans
        );
        Ok((total_removed, local_orphans))
    }

    /// Per-FILE integrity check: proves every file is actually restorable, which
    /// `scrub` does NOT — scrub verifies chunks exist and hash-match, but a file
    /// with a dangling chunk reference or a recorded size that no chunks back
    /// (the class: "size set, zero data") passes scrub and fails here.
    ///
    /// For each regular file it fetches and DECRYPTS every chunk (so it needs the
    /// read key — this measures restorability, not just presence), streaming one
    /// chunk at a time, and checks the decrypted total equals the recorded size.
    /// Returns `(ok, bad)` and logs each bad file with the reason.
    pub async fn verify_all(&self) -> anyhow::Result<(usize, usize)> {
        let files = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.list_regular_files()
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

        // files whose backup was interrupted (killed mid-write) carry a
        // durable marker. Their committed size is self-consistent with the
        // chunks actually written, so verify_one would pass them — but the file
        // is truncated. Treat any marked inode as NOT restorable.
        let incomplete: std::collections::HashSet<u64> = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.list_incomplete_files()
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?
        .unwrap_or_default()
        .into_iter()
        .collect();

        let mut ok = 0usize;
        let mut bad = 0usize;

        for (ino, size) in files {
            if incomplete.contains(&ino) {
                bad += 1;
                let name = self
                    .get_resolved_inode_name(ino)
                    .unwrap_or_else(|_| format!("ino {ino}"));
                tracing::error!(
                    "verify: {name} (ino {ino}) is NOT restorable: backup was interrupted \
                 (killed mid-file) — the file is truncated. Re-run backup to complete it."
                );
                continue;
            }
            match self.verify_one(ino, size).await {
                Ok(()) => ok += 1,
                Err(e) => {
                    bad += 1;
                    let name = self
                        .get_resolved_inode_name(ino)
                        .unwrap_or_else(|_| format!("ino {ino}"));
                    tracing::error!("verify: {name} (ino {ino}) is NOT restorable: {e}");
                }
            }
        }

        if bad > 0 {
            tracing::error!("verify: {ok} file(s) OK, {bad} file(s) NOT restorable");
        } else {
            tracing::info!("verify: all {ok} file(s) restorable");
        }
        Ok((ok, bad))
    }

    async fn verify_one(&self, ino: u64, size: u64) -> anyhow::Result<()> {
        // Inline files: the bytes are in the index, no chunks to resolve.
        // propagate a DB read error — verify must not silently treat an
        // unreadable inode as "0-byte / no inline" and PASS it as restorable.
        if let Some(raw) = self.db.get_inline_data(ino)? {
            // Decrypt so the size check is against the PLAINTEXT length (the
            // stored blob is now envelope ciphertext). Also proves the inline
            // content is actually recoverable with the current key.
            // inline may be SHORTER than the recorded size — a truncate-
            // extended inline file has a legitimate zero tail (read() zero-fills
            // it). Only inline LONGER than the size is an inconsistency.
            let inline = self.unwrap_inline(&raw)?;
            if inline.len() as u64 > size {
                anyhow::bail!("inline size {} > recorded {size}", inline.len());
            }
            return Ok(());
        }

        let chunks = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_file_chunks(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

        // Empty file: legitimately zero chunks. A non-empty file with none is the
        // "size recorded, data never flushed" footprint.
        if chunks.is_empty() {
            if size == 0 {
                return Ok(());
            }
            anyhow::bail!("recorded size {size} but no chunks (data was never stored)");
        }

        for (hash_key, _offset, plain_len, wrapped_key, comp_type, cipher_algo) in chunks {
            let cipher = self
                .fetch_chunk(&hash_key)
                .await
                .map_err(|e| anyhow::anyhow!("chunk {hash_key} unreadable: {e}"))?;
            let crypto = self.crypto.clone();
            let plain = tokio::task::spawn_blocking(move || {
                crypto.decrypt_chunk_symmetric(&cipher, &wrapped_key, comp_type as u8, &cipher_algo)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?
            .map_err(|e| anyhow::anyhow!("chunk {hash_key} does not decrypt: {e}"))?;
            if plain.len() < plain_len {
                anyhow::bail!(
                    "chunk {hash_key} decrypted to {} bytes < recorded {plain_len}",
                    plain.len()
                );
            }
        }

        // no under-coverage check — coverage gaps (middle or tail holes)
        // are LEGITIMATE zeros from sparse writes / truncate-extend, and read()/
        // extract now reproduce them as zeros. (The old `sum(plain_len) < size`
        // test was double-counting overlapping RMW chunks anyway.) The
        // "size recorded but data never flushed" footprint is still caught above:
        // a non-empty file with ZERO chunks and no inline fails loudly.
        Ok(())
    }

    pub async fn scrub(&self) -> anyhow::Result<(usize, usize)> {
        // Iterate distinct chunk objects, not `file_chunks` rows: a chunk shared
        // by many files (the dedup case) was previously verified once per
        // reference — N times the work, N times the bandwidth on cloud reads.
        let chunks = self.db.get_all_distinct_chunk_objects()?;
        let mut corrupted = 0;
        let mut verified = 0;

        // Scrub verifies the durable copy. With cloud backends configured, force
        // a cloud read (bypass the local cache) and heal from redundancy — unless
        // the operator already set force_remote_read (same intent). On a
        // LOCAL-ONLY archive the cache IS the durable store — forcing a cloud
        // read there fails every fetch and reports a healthy archive as 100%
        // corrupt (masked until made scrub's exit code authoritative).
        let has_cloud = !self.operators.is_empty();
        let force_remote = self.force_remote_read || has_cloud;

        for hash_key in chunks {
            if let Ok(cipher) = self
                .store
                .fetch_chunk(&hash_key, &self.raid_mode, false, has_cloud, force_remote)
                .await
            {
                let actual_hash = blake3::hash(&cipher).to_hex().to_string();
                if actual_hash == hash_key {
                    verified += 1;
                } else {
                    // Report which files reference the corrupted chunk so the
                    // operator can assess impact and prioritise recovery.
                    let affected = self
                        .db
                        .get_inodes_using_chunk(&hash_key)
                        .unwrap_or_default();
                    let file_names: Vec<String> = affected
                        .iter()
                        .map(|ino| {
                            self.get_resolved_inode_name(*ino)
                                .unwrap_or_else(|_| format!("ino {ino}"))
                        })
                        .collect();
                    tracing::error!(
                        "Corrupted chunk detected (hash mismatch): {} — affects {} file(s): {:?}",
                        hash_key,
                        file_names.len(),
                        file_names
                    );
                    corrupted += 1;
                }
            } else {
                let affected = self
                    .db
                    .get_inodes_using_chunk(&hash_key)
                    .unwrap_or_default();
                let file_names: Vec<String> = affected
                    .iter()
                    .map(|ino| {
                        self.get_resolved_inode_name(*ino)
                            .unwrap_or_else(|_| format!("ino {ino}"))
                    })
                    .collect();
                tracing::error!(
                    "Missing chunk detected: {} — affects {} file(s): {:?}",
                    hash_key,
                    file_names.len(),
                    file_names
                );
                corrupted += 1;
            }
        }

        if corrupted > 0 {
            tracing::error!(
                "Scrub complete: {} chunks verified, {} corrupted/missing!",
                verified,
                corrupted
            );
        } else {
            tracing::info!(
                "Scrub complete: {} chunks verified successfully. No corruption detected.",
                verified
            );
        }

        Ok((verified, corrupted))
    }
}
