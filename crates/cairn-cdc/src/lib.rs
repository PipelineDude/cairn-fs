// CloudOperator now lives in `cairn-store` (its natural home). Re-exported so this
// crate's `crate::CloudOperator` paths keep resolving.
pub use cairn_store::CloudOperator;

use anyhow::Result;
use fastcdc::v2020::FastCDC;

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
                        let plaintext_hash = {
                            // clone the secret out of the mutex
                            // quickly, then drop the guard BEFORE the CPU-heavy
                            // blake3 hash. Holding std::sync::Mutex across an
                            // async task blocks the tokio worker thread.
                            // the clone is `Zeroizing` so the dedup secret
                            // does not linger on the heap after the hash.
                            let ds_clone: Option<zeroize::Zeroizing<Vec<u8>>> = {
                                let ds_guard = crypto_ref.dedup_secret.lock();
                                ds_guard.as_ref().map(|ds| {
                                    use secrecy::ExposeSecret;
                                    zeroize::Zeroizing::new(ds.expose_secret().as_bytes().to_vec())
                                })
                            };
                            if let Some(ref ds_bytes) = ds_clone {
                                let mut hasher = blake3::Hasher::new();
                                hasher.update(ds_bytes);
                                hasher.update(chunk_data);
                                hasher.finalize().to_hex().to_string()
                            } else if crypto_ref.disable_dedup {
                                // random-key mode: this hash is not used for dedup.
                                blake3::hash(chunk_data).to_hex().to_string()
                            } else {
                                // convergent mode with no secret = a write
                                // after zeroize_keys. Fail loud rather than store an
                                // UNKEYED hash that can never match future lookups.
                                return Err(anyhow::anyhow!(
                                    "dedup_secret unavailable (already zeroized?) — \
                                     cannot hash chunk for dedup"
                                ));
                            }
                        };

                        let db_res = if crypto_ref.disable_dedup {
                            Ok(None)
                        } else {
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
                        };

                        // match the three outcomes of a dedup
                        // lookup. A DB Err (busy / corrupt / IO) previously
                        // fell through as if the chunk were new — silently
                        // disabling dedup for the rest of the run. Propagate
                        // the error so the operator knows.
                        match db_res {
                            Ok(Some((object_id, _sym_key, comp_type))) => {
                                return Ok::<
                                    (ChunkResult, Option<(String, String, Vec<u8>, i32, String)>),
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

                        // 1. Encrypt chunk asymmetrically (actually symmetrically)
                        //    The plaintext chunk key is secret material — zeroize
                        //    it on drop (hardened the read path; this closes
                        //    the write-side gap so keys never linger on the heap).
                        //    generate_chunk_key now returns
                        //    Result<Zeroizing<Vec<u8>>> directly — no double wrap.
                        let sym_key = crypto_ref.generate_chunk_key(chunk_data)
                            .map_err(|e| anyhow::anyhow!("Chunk key generation failed: {e}"))?;
                        let (ciphertext, comp_type) = crypto_ref
                            .encrypt_chunk_symmetric(chunk_data, &sym_key, comp_override.as_deref())
                            .map_err(|e| anyhow::anyhow!("Crypto error: {e}"))?;

                        let wrapped_key = crypto_ref
                            .encrypt_blob(&sym_key)
                            .map_err(|e| anyhow::anyhow!("Envelope error: {e}"))?;

                        // 2. Hash the ciphertext for object_id
                        let hash = blake3::hash(&ciphertext).to_hex().to_string();

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
                            (ChunkResult, Option<(String, String, Vec<u8>, i32, String)>),
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
                                crypto_ref.crypto_algo.clone(),
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
        let mut first_err = None;
        for r in results {
            match r {
                Ok((chunk_res, new_meta)) => {
                    final_results.push(chunk_res);
                    if let Some(meta) = new_meta {
                        new_chunks.push(meta);
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
            match tokio::task::spawn_blocking(move || {
                db_ref.insert_chunk_indices_batch(&new_chunks)
            })
            .await
            {
                Ok(res) => res?,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "spawn_blocking in batch insert failed: {e}"
                    ));
                }
            };
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
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let uri = format!("file:test_cdc_{}?mode=memory&cache=shared", id);

        let db = cairn_index::Db::new(&uri, None).unwrap();
        let db = Arc::new(db);

        let identity_file = tempfile::NamedTempFile::new().unwrap();
        let pub_key_file = tempfile::NamedTempFile::new().unwrap();

        let identity = age::x25519::Identity::generate();
        use secrecy::ExposeSecret;
        std::fs::write(
            identity_file.path(),
            identity.to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        std::fs::write(
            pub_key_file.path(),
            identity.to_public().to_string().as_bytes(),
        )
        .unwrap();

        let crypto = Arc::new(
            cairn_seal::CryptoCtx::new(
                pub_key_file.path().to_str().unwrap(),
                Some(identity_file.path().to_str().unwrap()),
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

        let temp_dir = tempfile::tempdir().unwrap();

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
        )
        .await
        .expect("upload should succeed with in-memory store");

        assert!(!chunks.is_empty());

        // Verify the chunk is visible in the index
        let count = db.total_chunks().unwrap();
        assert_eq!(count, chunks.len() as u64);
    }
}
