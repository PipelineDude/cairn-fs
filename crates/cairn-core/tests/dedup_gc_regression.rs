// Dedup audit 2026-11-17 regression: the gc LOCAL cache sweep must pin
// blobs that are enqueued for upload but not yet indexed (async mode enqueues
// in the chunker task and commits chunk_index rows only afterwards). The
// upload worker reads the blob back from this cache; if the sweep deleted it,
// the queue entry would strand forever and the cloud copy would be lost.

use cairn_core::CairnEngine;
use cairn_core::types::*;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tempfile::TempDir;
use tokio::sync::Mutex;

async fn setup_engine() -> (CairnEngine, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let pub_path = temp_dir.path().join("pub.pem");
    let priv_path = temp_dir.path().join("priv.pem");
    use age::secrecy::ExposeSecret;
    let identity = age::x25519::Identity::generate();
    std::fs::write(&pub_path, identity.to_public().to_string()).unwrap();
    std::fs::write(&priv_path, identity.to_string().expose_secret()).unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db = Arc::new(cairn_index::Db::new(db_path.to_str().unwrap(), None).unwrap());
    let cache_dir = temp_dir.path().join("cache").to_string_lossy().to_string();
    std::fs::create_dir_all(&cache_dir).unwrap();
    let crypto_ctx = cairn_seal::CryptoCtx::new(
        pub_path.to_str().unwrap(),
        Some(priv_path.to_str().unwrap()),
        3,
        10,
        "zstd".to_string(),
        "chacha20".to_string(),
        None,
        true,
        1024,
    )
    .unwrap();
    let store = Arc::new(cairn_store::CairnStore::new(
        cache_dir.clone(),
        vec![],
        None,
    ));
    let engine = CairnEngine {
        db,
        cache_dir,
        crypto: Arc::new(crypto_ctx),
        store,
        op: None,
        operators: vec![],
        raid_mode: "1".to_string(),
        skip_read_verify: false,
        force_remote_read: false,
        async_upload: false,
        auto_heal: false,
        write_buffers: Arc::new(dashmap::DashMap::new()),
        last_index_hash: Default::default(),
        no_comp_ext: vec!["jpg".to_string(), "zip".to_string()],
        write_locks: DashMap::new(),
        decrypted_chunk_cache: Arc::new(Mutex::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(100).unwrap(),
        ))),
        global_write_buffer_bytes: Arc::new(AtomicUsize::new(0)),
        chunk_cache_bytes: Arc::new(AtomicUsize::new(0)),
        write_buffer_inode_max: cairn_core::DEFAULT_WRITE_BUFFER_INODE_MAX,
        write_buffer_global_max: cairn_core::DEFAULT_WRITE_BUFFER_GLOBAL_MAX,
        chunk_cache_max_bytes: cairn_core::DEFAULT_CHUNK_CACHE_MAX_BYTES,
        max_write: cairn_core::DEFAULT_MAX_WRITE,
        max_file_size: cairn_core::DEFAULT_MAX_FILE_SIZE,
        backup_stats: Arc::new(cairn_core::BackupStats::new()),
        meta_cache: Arc::new(dashmap::DashMap::new()),
        gc_running: Arc::new(tokio::sync::Mutex::new(())),
    };
    let req = Request::default();
    engine.init(req).await.unwrap();
    (engine, temp_dir)
}

#[tokio::test]
async fn gc_local_sweep_pins_queued_unindexed_blobs() {
    let (engine, _tmp) = setup_engine().await;
    // A blob in the local cache with an upload_queue entry but NO chunk_index
    // row — exactly the async-mode window (enqueued, batch index insert later).
    let key = "ab".repeat(32);
    cacache::write(&engine.cache_dir, &key, b"queued-but-not-indexed")
        .await
        .unwrap();
    engine.db.enqueue_upload(&key).unwrap();

    let (_glob, local) = engine.gc(0).await.unwrap();
    assert_eq!(local, 0, "queued blob must not count as a local orphan");
    assert!(
        cacache::read(&engine.cache_dir, &key).await.is_ok(),
        "gc swept a blob that the upload worker still needs"
    );

    // Positive control: once the upload completes (dequeue), the sweep — with
    // no index row and no file referencing it — reclaims the blob normally.
    engine.db.dequeue_upload(&key).unwrap();
    let (_glob, local) = engine.gc(0).await.unwrap();
    assert_eq!(local, 1, "dequeued unreferenced blob must be reclaimed");
    assert!(cacache::read(&engine.cache_dir, &key).await.is_err());
}
