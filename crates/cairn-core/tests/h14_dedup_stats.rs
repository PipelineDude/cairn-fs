// H14: deduplication statistics over a known duplicate set (offline engine).
use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use age::secrecy::ExposeSecret;
use cairn_core::types::*;
use cairn_core::{BackupStats, CairnEngine};
use cairn_index::Db;
use dashmap::DashMap;
use lru::LruCache;
use tempfile::TempDir;
use tokio::sync::Mutex;

async fn setup_engine() -> (CairnEngine, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let pub_path = temp_dir.path().join("pub.pem");
    let priv_path = temp_dir.path().join("priv.pem");
    let identity = age::x25519::Identity::generate();
    let priv_key_val = identity.to_string().expose_secret().to_string();
    let pub_key_str = identity.to_public().to_string();
    std::fs::write(&pub_path, pub_key_str).unwrap();
    std::fs::write(&priv_path, priv_key_val).unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db = Arc::new(Db::new(db_path.to_str().unwrap(), None).unwrap());
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
        write_buffers: Arc::new(DashMap::new()),
        last_index_hash: Default::default(),
        no_comp_ext: vec!["jpg".to_string(), "zip".to_string()],
        write_locks: DashMap::new(),
        decrypted_chunk_cache: Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(100).unwrap(),
        ))),
        global_write_buffer_bytes: Arc::new(AtomicUsize::new(0)),
        chunk_cache_bytes: Arc::new(AtomicUsize::new(0)),
        write_buffer_inode_max: cairn_core::DEFAULT_WRITE_BUFFER_INODE_MAX,
        write_buffer_global_max: cairn_core::DEFAULT_WRITE_BUFFER_GLOBAL_MAX,
        chunk_cache_max_bytes: cairn_core::DEFAULT_CHUNK_CACHE_MAX_BYTES,
        max_write: cairn_core::DEFAULT_MAX_WRITE,
        max_file_size: cairn_core::DEFAULT_MAX_FILE_SIZE,
        backup_stats: Arc::new(BackupStats::new()),
        gc_running: Arc::new(Mutex::new(())),
    };
    engine.init(Request::default()).await.unwrap();
    (engine, temp_dir)
}

async fn make_and_write(engine: &CairnEngine, name: &str, payload: &[u8]) {
    let req = Request::default();
    let (entry, fh, _) = engine
        .create(req.clone(), 1, OsStr::new(name), 0o100644, 0)
        .await
        .unwrap();
    engine
        .write(req.clone(), entry.attr.ino, fh, 0, payload, 0, 0)
        .await
        .unwrap();
    engine
        .flush_range(entry.attr.ino, 0, payload)
        .await
        .unwrap();
    engine
        .release(req.clone(), entry.attr.ino, fh, 0, 0, true)
        .await
        .unwrap();
}

#[tokio::test]
async fn dedup_stats_report_savings_on_known_duplicates_and_inline() {
    let (engine, _dir) = setup_engine().await;
    let payload: Vec<u8> = vec![0x5Au8; 60_000]; // highly duplicate content
    make_and_write(&engine, "a.bin", &payload).await;
    make_and_write(&engine, "a-copy.bin", &payload).await; // identical bytes

    let stats = engine.dedup_stats().await.unwrap();
    assert_eq!(
        stats.logical_file_bytes,
        2 * payload.len() as u64,
        "both copies count"
    );
    assert!(stats.unique_object_count > 0);
    assert!(
        stats.unique_object_bytes < stats.logical_file_bytes,
        "dedup must shrink stored bytes: {} < {}",
        stats.unique_object_bytes,
        stats.logical_file_bytes
    );
    assert!(
        stats.savings_percent > 30.0,
        "achieved {:.1}% savings on identical files",
        stats.savings_percent
    );
    assert_eq!(
        stats.compressed_stored_bytes,
        engine.db.total_plain_bytes().unwrap()
    );

    // A small INLINE file adds logical bytes but no pool objects.
    let before_objects = stats.unique_object_bytes;
    make_and_write(&engine, "tiny.txt", &b"inline data".repeat(100)).await;
    let after = engine.dedup_stats().await.unwrap();
    assert_eq!(
        after.inline_logical_bytes,
        (b"inline data".repeat(100).len()) as u64
    );
    assert!(
        after.unique_object_bytes >= before_objects,
        "inline must not remove objects"
    );
    assert!(
        after.savings_percent > 0.0,
        "savings remain positive after adding inline data"
    );
}
