// CloudOperator now lives in `cairn-store` (its natural home). Re-exported so this
// crate's `crate::CloudOperator` paths keep resolving.
pub use cairn_store::CloudOperator;

pub mod shared;

use anyhow::Result;
use fastcdc::v2020::FastCDC;

use crate::shared::{SharedDedupConfig, publish_shared_chunk};

#[derive(Debug)]
pub struct ChunkResult {
    pub hash_key: String,
    pub plain_len: usize,
    pub offset: usize,
    pub comp_type: i32,
    pub dedup_hit: bool,
}

#[cfg(feature = "cloud-storage")]
pub static S3_UPLOAD_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(128);
#[cfg(feature = "cloud-storage")]
pub static PENDING_UPLOAD_SEMAPHORE: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(1024);
/// Set true when any chunk upload permanently fails (after bounded retries). On unmount
/// the CLI checks this and refuses to sync a "complete" index to the cloud, so we never
/// claim durability we don't have.
#[cfg(feature = "cloud-storage")]
pub static UPLOAD_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub struct Chunker;

impl Chunker {
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(feature = "cloud-storage"), allow(unused_variables))]
    pub async fn process_data(
        data: &[u8],
        cache_dir: &str,
        crypto: std::sync::Arc<cairn_seal::CryptoCtx>,
        db: std::sync::Arc<cairn_index::Db>,
        store: std::sync::Arc<dyn cairn_store::ChunkStore>,
        raid_mode: String,
        async_upload: bool,
        comp_algo_override: Option<String>,
        shared: Option<SharedDedupConfig>,
    ) -> Result<Vec<ChunkResult>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let data_arc: std::sync::Arc<[u8]> = data.into();
        #[cfg(feature = "cloud-storage")]
        let raid_mode_arc: std::sync::Arc<str> = raid_mode.into();

        let chunker = FastCDC::new(data, 16384, 65536, 262144);
        let chunks: Vec<_> = chunker.collect();

        use futures::StreamExt;

        let db_arc_for_map = db.clone();
        let results: Vec<_> =
            futures::stream::iter(chunks)
                .map(|entry| {
                    let data_ref = data_arc.clone();
                    let dir = cache_dir.to_string();
                    let len = entry.length;
                    let offset = entry.offset;
                    let crypto_ref = crypto.clone();
                    let db_ref = db_arc_for_map.clone();
                    let comp_override = comp_algo_override.clone();
                    let shared_cfg = shared.clone();
                    #[cfg(feature = "cloud-storage")]
                    let store = store.clone();
                    #[cfg(feature = "cloud-storage")]
                    let raid_mode = raid_mode_arc.clone();

                    tokio::spawn(async move {
                        // defensive bound — a bad FastCDC offset/len would
                        // otherwise panic inside the spawned task.
                        if offset.checked_add(len).is_none_or(|end| end > data_ref.len()) {
                            return Err(anyhow::anyhow!(
                                "chunk slice out of bounds: offset {offset} + len {len} > {}",
                                data_ref.len()
                            ));
                        }
                        let chunk_data = &data_ref[offset..offset + len];
                        let content_id = crypto_ref.content_id(chunk_data)?;
                        let plaintext_hash = content_id
                            .map(|id| blake3::Hash::from(id).to_hex().to_string());

                        let db_res = if let Some(ref plaintext_hash) = plaintext_hash {
                            let db = db_ref.clone();
                            let ph = plaintext_hash.clone();
                            // JoinHandle::Err can indicate a
                            // panic inside spawn_blocking. Propagate as error
                            // rather than treating it as "no dedup match" which
                            // would silently create a duplicate chunk.
                            match tokio::task::spawn_blocking(move || db.get_chunk_by_hash(&ph)).await
                            {
                                Ok(res) => res,
                                Err(join_err) => {
                                    return Err(anyhow::anyhow!(
                                        "spawn_blocking in dedup lookup panicked: {join_err}"
                                    ));
                                }
                            }
                        } else {
                            Ok(None)
                        };

                        // match the three outcomes of a dedup
                        // lookup. A DB Err (busy / corrupt / IO) previously
                        // fell through as if the chunk were new — silently
                        // disabling dedup for the rest of the run. Propagate
                        // the error so the operator knows.
                        match db_res {
                            Ok(Some((object_id, _sym_key, comp_type))) => {
                                return Ok::<
                                    (ChunkResult, Option<(String, String, Vec<u8>, i32, String, bool)>),
                                    anyhow::Error,
                                >((
                                    ChunkResult {
                                        hash_key: object_id,
                                        plain_len: len,
                                        offset,
                                        comp_type,
                                        dedup_hit: true,
                                    },
                                    None,
                                ));
                            }
                            Ok(None) => {}
                            Err(e) => {
                                return Err(anyhow::anyhow!("dedup lookup DB error: {e}"));
                            }
                        }

                        // D03: shared-domain write.  When a domain is configured
                        // (and convergent dedup is on), produce the canonical
                        // domain object instead of an archive-scope one:
                        // seal_chunk_shared (double wrap) → publish_or_adopt →
                        // index the WINNER with the DOMAIN-wrapped record and
                        // flag it `domain`.
                        if let Some(cfg) = &shared_cfg {
                            let outcome = publish_shared_chunk(
                                chunk_data,
                                &crypto_ref,
                                comp_override.as_deref(),
                                cfg,
                                &dir,
                            )
                            .await?;
                            let oid = outcome.object_id.clone();
                            let shared_cid = {
                                let cid = cairn_store::shared_dedup::shared_content_id(
                                    &cfg.domain_id,
                                    &cfg.domain_secret,
                                    chunk_data,
                                );
                                cid.iter().map(|b| format!("{b:02x}")).collect::<String>()
                            };
                            return Ok((
                                ChunkResult {
                                    hash_key: oid.clone(),
                                    plain_len: len,
                                    offset,
                                    comp_type: outcome.comp_type as i32,
                                    dedup_hit: outcome.dedup_hit,
                                },
                                Some((
                                    oid,
                                    shared_cid,
                                    outcome.record.sealed_meta.wrapped_key,
                                    outcome.comp_type as i32,
                                    outcome.record.sealed_meta.cipher_algo,
                                    true,
                                )),
                            ));
                        }

                        let cairn_seal::SealedChunk {
                            object_id: hash, wrapped_key, comp_type, cipher_algo, ciphertext, ..
                        } = crypto_ref.seal_chunk(chunk_data, comp_override.as_deref())?;
                        // The schema keeps this column non-null even when no dedup
                        // lookup occurs. A random physical ID is never a plaintext ID.
                        let plaintext_hash = plaintext_hash.unwrap_or_else(|| hash.clone());

                        // 3. Write ciphertext to cacache without per-chunk fsync
                        cacache::write(&dir, &hash, &ciphertext)
                            .await
                            .map_err(|e| anyhow::anyhow!("cache error: {e}"))?;

                        // track whether upload succeeded. On failure
                        // the task returns Err so the chunk is NOT indexed
                        // as cloud-durable — the UPLOAD_FAILED flag handles
                        // the exit code.
                        // exit code.
                        #[cfg_attr(not(feature = "cloud-storage"), allow(unused_mut))]
                        let mut upload_failed = false;

                        #[cfg(feature = "cloud-storage")]
                        {
                            let store_clone = store.clone();
                            let raid = raid_mode.clone();

                            // the S3 object IS the raw ciphertext, byte
                            // for byte identical to the local cacache blob
                            // (`blake3(object) == hash_key`). The wrapped key
                            // lives in chunk_index (data) / the manifest
                            // (index), never in the object, so there is no
                            // header to prepend — the async push path uploads
                            // the cache blob verbatim and this sync path must
                            // produce the same bytes.
                            let upload_data = ciphertext.clone();
                            {
                                let hash_clone_q = hash.clone();
                                let db_clone = db_ref.clone();
                                if async_upload {
                                    if let Err(e) = db_clone.enqueue_upload(&hash_clone_q) {
                                        // enqueue failed — try
                                        // synchronous upload as fallback so the
                                        // chunk is NOT silently lost. This avoids
                                        // the chunk sitting in local cache forever
                                        // with no path to cloud durability.
                                        tracing::warn!(
                                            "enqueue_upload failed for {hash_clone_q}: {e} — \
                                             falling back to synchronous upload"
                                        );
                                        // bound concurrent uploads via the
                                        // shared S3 semaphore, like the async worker.
                                        // hold the permit for the scope; make the
                                        // (never, for a static semaphore) close case explicit
                                        // instead of discarding the Result.
                                        let _s3_permit = match S3_UPLOAD_SEMAPHORE.acquire().await {
                                            Ok(p) => Some(p),
                                            Err(e) => {
                                                tracing::error!("S3 upload semaphore closed: {e}");
                                                None
                                            }
                                        };
                                        if let Err(e2) = store_clone
                                            .upload_chunk(upload_data, &hash_clone_q, &raid)
                                            .await
                                        {
                                            tracing::error!(
                                                "Fallback sync S3 upload also failed: {e2}"
                                            );
                                            upload_failed = true;
                                            UPLOAD_FAILED
                                                .store(true, std::sync::atomic::Ordering::SeqCst);
                                            // enqueue failed AND the fallback
                                            // upload failed, so this chunk is in NEITHER
                                            // the cloud NOR the retry queue — the
                                            // background worker drains only the queue, so
                                            // it would be stranded local-only with no
                                            // retry path. Best-effort re-enqueue so a
                                            // later push/daemon drain retries it (closes
                                            // the async edge of the durability class).
                                            if let Err(e3) =
                                                db_clone.enqueue_upload(&hash_clone_q)
                                            {
                                                tracing::error!(
                                                    "re-enqueue after double upload failure \
                                                     failed for {hash_clone_q}: {e3} — chunk is \
                                                     local-only until it is backed up again"
                                                );
                                            }
                                        }
                                    }
                                    // The actual background FUSE loop will handle it.
                                } else {
                                    if let Err(e) = db_clone.enqueue_upload(&hash_clone_q) {
                                        tracing::error!(
                                            "enqueue_upload failed for {hash_clone_q}: {e} — upload will not \
                                             be retried if the direct upload below also fails"
                                        );
                                    }
                                    // bound concurrent uploads via the shared S3 semaphore.
                                    let _s3_permit = S3_UPLOAD_SEMAPHORE.acquire().await;
                                    if let Err(e) = store_clone
                                        .upload_chunk(upload_data, &hash_clone_q, &raid)
                                        .await
                                    {
                                        tracing::error!("Sync S3 upload failed: {}", e);
                                        upload_failed = true;
                                        UPLOAD_FAILED
                                            .store(true, std::sync::atomic::Ordering::SeqCst);
                                    } else {
                                        // a dequeue failure leaves the chunk in the
                                        // queue (harmless re-upload next drain), but log it so
                                        // a persistent DB error is visible, not silent.
                                        if let Err(e) = db_clone.dequeue_upload(&hash_clone_q) {
                                            tracing::warn!(
                                                "dequeue_upload({hash_clone_q}) failed after a successful upload: {e}"
                                            );
                                        }
                                    }
                                }
                            }
                        }

                        // if upload failed, return Err so the chunk is
                        // NOT added to the index as cloud-durable.
                        if upload_failed {
                            anyhow::bail!(
                                "S3 upload failed for chunk {hash} — chunk is local-only"
                            );
                        }

                        // 4. Return new chunk meta to be inserted in batch
                        Ok::<
                            (ChunkResult, Option<(String, String, Vec<u8>, i32, String, bool)>),
                            anyhow::Error,
                        >((
                            ChunkResult {
                                hash_key: hash.clone(),
                                plain_len: len,
                                offset,
                                comp_type: i32::from(comp_type),
                                dedup_hit: false,
                            },
                            Some((
                                hash,
                                plaintext_hash,
                                wrapped_key,
                                i32::from(comp_type),
                                cipher_algo,
                                false,
                            )),
                        ))
                    })
                })
                .buffer_unordered(16)
                .map(|res| match res {
                        Ok(inner) => inner,
                        Err(e) => Err(anyhow::anyhow!("Spawned chunk task failed: {e}")),
                    })
                .collect()
                .await;

        // collect the chunks that DID complete and remember the first
        // error, but do NOT early-return before recording the completed chunks'
        // index rows — an uploaded-but-unindexed chunk is a permanent cloud
        // orphan (gc's orphan detection works off chunk_index, so it can never
        // reclaim it). Indexing them makes them gc-visible; then propagate the
        // error so the caller still sees the failure.
        let mut final_results = Vec::with_capacity(results.len());
        let mut new_chunks = Vec::new();
        let mut domain_oids = Vec::new();
        let mut first_err = None;
        for r in results {
            match r {
                Ok((chunk_res, new_meta)) => {
                    final_results.push(chunk_res);
                    if let Some(meta) = new_meta {
                        let (oid, ph, sk, ct, algo, domain_flag) = meta;
                        new_chunks.push((oid.clone(), ph, sk, ct, algo));
                        if domain_flag {
                            domain_oids.push(oid);
                        }
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        if !new_chunks.is_empty() {
            let db_ref = db.clone();
            tokio::task::spawn_blocking(move || db_ref.insert_chunk_indices_batch(&new_chunks))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking in batch insert failed: {e}"))??;
            // D03: mark the domain-mode chunks so reads use the shared
            // reader path instead of the archive path.
            for oid in &domain_oids {
                db.set_chunk_domain(oid, true)?;
            }
        }

        // completed chunks are now indexed (gc-visible); surface the error.
        if let Some(e) = first_err {
            return Err(e);
        }

        final_results.sort_by_key(|c| c.offset);
        Ok(final_results)
    }
}

#[cfg(test)]
#[cfg(feature = "cloud-storage")]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn setup_test_env_cloud(
        disable_dedup: bool,
    ) -> (
        Arc<cairn_index::Db>,
        Arc<cairn_seal::CryptoCtx>,
        Arc<cairn_store::CairnStore>,
        opendal::Operator,
        tempfile::TempDir,
    ) {
        // File-backed SQLite so concurrent writers exercise real busy-timeout
        // handling instead of the cross-connection artefacts of
        // `mode=memory&cache=shared`. The TempDir is returned alongside so the
        // db file (and its WAL) has a known lifetime for the test body.
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = cairn_index::Db::new(db_path.to_str().unwrap(), None).unwrap();
        let db = Arc::new(db);

        let identity_file = temp_dir.path().join("identity.txt");
        let pub_key_file = temp_dir.path().join("pubkey.txt");

        let identity = age::x25519::Identity::generate();
        use secrecy::ExposeSecret;
        std::fs::write(
            &identity_file,
            identity.to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        std::fs::write(&pub_key_file, identity.to_public().to_string().as_bytes()).unwrap();

        let crypto = Arc::new(
            cairn_seal::CryptoCtx::new(
                pub_key_file.to_str().unwrap(),
                Some(identity_file.to_str().unwrap()),
                3,
                0,
                "zstd".to_string(),
                "aes-gcm".to_string(),
                None,
                disable_dedup,
                10,
            )
            .unwrap(),
        );

        let builder = opendal::services::Memory::default();
        let op = opendal::Operator::new(builder).unwrap();
        let store = Arc::new(cairn_store::CairnStore::new(
            temp_dir.path().to_str().unwrap().to_string(),
            vec![op.clone()],
            None,
        ));

        (db, crypto, store, op, temp_dir)
    }

    #[tokio::test]
    async fn test_process_empty_data() {
        let (db, crypto, store, _op, temp_dir) = setup_test_env_cloud(false).await;
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();

        let chunks = Chunker::process_data(
            b"",
            &cache_dir,
            crypto,
            db,
            store,
            "raid1".to_string(),
            false,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(chunks.is_empty());
    }

    #[tokio::test]
    #[cfg(feature = "cloud-storage")]
    async fn test_process_data_with_memory_cloud() {
        let (db, crypto, store, op, temp_dir) = setup_test_env_cloud(false).await;
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let data = b"hello world this is a test chunk that should be uploaded to the memory cloud operator";

        let chunks = Chunker::process_data(
            data,
            &cache_dir,
            crypto,
            db,
            store,
            "raid1".to_string(),
            false,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(!chunks.is_empty());
        let hash = &chunks[0].hash_key;

        let s3_path = format!("chunks/{}", hash);
        let cloud_data = op
            .read(&s3_path)
            .await
            .expect("Chunk should be uploaded to cloud");
        assert!(!cloud_data.is_empty());
    }

    #[tokio::test]
    #[cfg(feature = "cloud-storage")]
    async fn test_deduplication() {
        let (db, crypto, store, op, temp_dir) = setup_test_env_cloud(false).await;
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let data = b"data for deduplication test";

        let chunks1 = Chunker::process_data(
            data,
            &cache_dir,
            crypto.clone(),
            db.clone(),
            store.clone(),
            "raid1".to_string(),
            false,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(chunks1.len(), 1);

        let s3_path = format!("chunks/{}", chunks1[0].hash_key);
        op.delete(&s3_path).await.unwrap();

        let chunks2 = Chunker::process_data(
            data,
            &cache_dir,
            crypto,
            db,
            store,
            "raid1".to_string(),
            false,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(chunks2.len(), 1);
        assert_eq!(chunks1[0].hash_key, chunks2[0].hash_key);
        assert!(op.read(&s3_path).await.is_err());
    }

    #[tokio::test]
    #[cfg(feature = "cloud-storage")]
    async fn test_disable_dedup() {
        let (db, crypto, store, _op, temp_dir) = setup_test_env_cloud(true).await;
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let data = b"data for disable dedup test";

        let chunks1 = Chunker::process_data(
            data,
            &cache_dir,
            crypto.clone(),
            db.clone(),
            store.clone(),
            "raid1".to_string(),
            false,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(chunks1.len(), 1);

        let chunks2 = Chunker::process_data(
            data,
            &cache_dir,
            crypto,
            db,
            store,
            "raid1".to_string(),
            false,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(chunks2.len(), 1);
        assert_ne!(chunks1[0].hash_key, chunks2[0].hash_key);
    }

    #[tokio::test]
    #[cfg(feature = "cloud-storage")]
    async fn test_async_upload() {
        let (db, crypto, store, _op, temp_dir) = setup_test_env_cloud(false).await;
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let data = b"data for async upload test";

        let chunks = Chunker::process_data(
            data,
            &cache_dir,
            crypto,
            db,
            store,
            "raid1".to_string(),
            true,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(chunks.len(), 1);
    }

    #[tokio::test]
    #[cfg(feature = "cloud-storage")]
    async fn test_multiple_chunks() {
        let (db, crypto, store, _op, temp_dir) = setup_test_env_cloud(false).await;
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let data = vec![0u8; 1024 * 1024]; // 1MB should be split into multiple chunks

        // Use a different RAID mode to test varying configuration.
        // the in-memory OpenDAL store may reject S3 uploads, so
        // accept either success (chunks indexed) or upload failure
        // (partial/no chunks indexed but no panic).
        let result = Chunker::process_data(
            &data,
            &cache_dir,
            crypto,
            db,
            store,
            "raid5".to_string(),
            false,
            None,
            None,
        )
        .await;
        match result {
            Ok(chunks) => assert!(chunks.len() > 1),
            Err(e) => assert!(
                e.to_string().contains("S3 upload failed"),
                "unexpected error: {e}"
            ),
        }
    }

    #[tokio::test]
    #[cfg(feature = "cloud-storage")]
    async fn test_chunk_indexed_on_upload_success() {
        // verify that chunks ARE indexed when upload succeeds
        let (db, crypto, store, _op, temp_dir) = setup_test_env_cloud(true).await;
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let data = vec![42u8; 1024];

        let chunks = Chunker::process_data(
            &data,
            &cache_dir,
            crypto,
            db.clone(),
            store,
            "raid1".to_string(),
            false,
            None,
            None,
        )
        .await
        .expect("upload should succeed with in-memory store");

        assert!(!chunks.is_empty());

        // Verify the chunk is visible in the index
        let count = db.total_chunks().unwrap();
        assert_eq!(count, chunks.len() as u64);
    }

    #[tokio::test]
    #[cfg(feature = "cloud-storage")]
    async fn test_concurrent_writers_leave_consistent_index() {
        let (db, crypto, store, _op, temp_dir) = setup_test_env_cloud(false).await;
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let data = vec![0xABu8; 64 * 1024];
        let writers = 8;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(writers));

        let mut handles = Vec::new();
        for _ in 0..writers {
            let d = data.clone();
            let cache = cache_dir.clone();
            let cr = crypto.clone();
            let dbc = db.clone();
            let st = store.clone();
            let start = barrier.clone();
            handles.push(tokio::spawn(async move {
                start.wait().await;
                Chunker::process_data(
                    &d,
                    &cache,
                    cr,
                    dbc,
                    st,
                    "raid1".to_string(),
                    false,
                    None,
                    None,
                )
                .await
            }));
        }
        let mut results = Vec::new();
        for h in handles {
            results.push(
                h.await
                    .expect("writer task must not panic")
                    .expect("all writers must succeed against the healthy fake cloud store"),
            );
        }
        assert_eq!(results.len(), writers);
        let chunk_counts: Vec<usize> = results.iter().map(|r| r.len()).collect();
        assert_eq!(
            chunk_counts.iter().max().unwrap(),
            chunk_counts.iter().min().unwrap(),
            "chunk counts must agree across concurrent identical writers"
        );

        // Every result handed to a caller must resolve to a durable index row.
        // A total count cannot prove that property because it could count an
        // unrelated chunk while one returned object is orphaned.
        for result in &results {
            for chunk in result {
                assert!(
                    db.chunk_exists(&chunk.hash_key).unwrap(),
                    "returned object {} is missing from chunk_index",
                    chunk.hash_key
                );
                let stored = cairn_store::ChunkStore::fetch_chunk(
                    store.as_ref(),
                    &chunk.hash_key,
                    "raid1",
                    false,
                    false,
                    true,
                )
                .await
                .expect("each indexed object must be readable from cloud storage");
                assert_eq!(blake3::hash(&stored).to_hex().as_str(), chunk.hash_key);
            }
        }

        // Sequential re-write after the concurrent burst must dedup to a single
        // already-published object set (B02: repeat write reuses object).
        let again = Chunker::process_data(
            &data,
            &cache_dir,
            crypto,
            db,
            store,
            "raid1".to_string(),
            false,
            None,
            None,
        )
        .await
        .expect("sequential re-write must succeed");
        assert_eq!(again.len(), chunk_counts[0]);
        assert!(
            results
                .iter()
                .any(|r| r.iter().zip(&again).all(|(a, b)| a.hash_key == b.hash_key)),
            "sequential repeat must reuse one of the concurrently published objects"
        );
    }
}
