// H13: read-only replication audit across two durable stores.
#![cfg(feature = "cloud-storage")]

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

async fn setup_engine() -> (CairnEngine, TempDir, opendal::Operator, opendal::Operator) {
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
        256,
        "zstd".to_string(),
        "chacha20".to_string(),
        None,
        true,
        256 * 1024,
    )
    .unwrap();
    let op0 = opendal::Operator::new(opendal::services::Memory::default()).unwrap();
    let op1 = opendal::Operator::new(opendal::services::Memory::default()).unwrap();
    let ops = vec![op0.clone(), op1.clone()];
    let store = Arc::new(cairn_store::CairnStore::new(
        cache_dir.clone(),
        ops.clone(),
        None,
    ));
    let engine = CairnEngine {
        db,
        cache_dir,
        crypto: Arc::new(crypto_ctx),
        store,
        op: Some(op0.clone()),
        operators: ops,
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
    (engine, temp_dir, op0, op1)
}

#[tokio::test]
async fn replication_audit_flags_missing_and_corrupt_replicas_per_store() {
    let (engine, _dir, op0, op1) = setup_engine().await;
    let req = Request::default();
    let (entry, fh, _) = engine
        .create(req.clone(), 1, OsStr::new("f.bin"), 0o100644, 0)
        .await
        .unwrap();
    let payload: Vec<u8> = (0..40_000u32).map(|j| (j & 0xff) as u8).collect();
    engine
        .write(req.clone(), entry.attr.ino, fh, 0, &payload, 0, 0)
        .await
        .unwrap();
    engine
        .flush_range(entry.attr.ino, 0, &payload)
        .await
        .unwrap();
    engine
        .release(req.clone(), entry.attr.ino, fh, 0, 0, true)
        .await
        .unwrap();

    // Healthy: both stores carry byte-exact replicas of every object.
    let audit = engine.replication_audit().await.unwrap();
    assert!(audit.missing.is_empty(), "missing: {:?}", audit.missing);
    assert!(audit.corrupt.is_empty(), "corrupt: {:?}", audit.corrupt);

    let object = engine.db.list_all_object_hashes().unwrap().remove(0);
    let path = format!("chunks/{object}");

    // Store #1 loses the replica -> audit must name (<id>, 1) as missing,
    // while store #0 stays verified.
    op1.delete(&path).await.unwrap();
    let audit = engine.replication_audit().await.unwrap();
    assert!(
        audit
            .missing
            .iter()
            .any(|(id, idx)| id == &object && *idx == 1),
        "missing flags store 1: {:?}",
        audit.missing
    );
    assert!(
        audit
            .verified
            .iter()
            .any(|(id, idx)| id == &object && *idx == 0),
        "store 0 remains verified"
    );

    // Store #1 carries WRONG bytes -> corrupt, never "assumed present".
    op1.write(&path, b"wrong bytes".to_vec()).await.unwrap();
    let audit = engine.replication_audit().await.unwrap();
    assert!(
        audit
            .corrupt
            .iter()
            .any(|(id, idx)| id == &object && *idx == 1),
        "corrupt flags store 1: {:?}",
        audit.corrupt
    );
    assert!(op0.stat(&path).await.is_ok());
}
