// B04: index slices and manifest round-trip through the sealed (BF-01)
// format against a Memory operator; restore + corruption rejection covered.
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

async fn setup_engine() -> (CairnEngine, TempDir, opendal::Operator) {
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
    let op = opendal::Operator::new(opendal::services::Memory::default()).unwrap();
    let ops = vec![op.clone()];
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
        op: Some(op.clone()),
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
    (engine, temp_dir, op)
}

async fn make_and_write(engine: &CairnEngine, name: &str, payload: &[u8]) -> u64 {
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
    entry.attr.ino
}

#[tokio::test]
async fn b04_index_sync_and_restore_roundtrip() {
    let (engine, _dir, op) = setup_engine().await;
    let req = Request::default();
    let payload: Vec<u8> = (0..(1024 * 1024)).map(|i| (i * 31) as u8).collect();
    let ino = make_and_write(&engine, "restore.bin", &payload).await;

    for (oid, _off, _len, _wrap, _ct, _algo) in engine.db.get_file_chunks(ino).unwrap() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while op.stat(&format!("chunks/{oid}")).await.is_err()
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(op.stat(&format!("chunks/{oid}")).await.is_ok());
    }

    engine.sync_index_to_cloud().await.unwrap();
    assert!(!op.read("meta/archive.db.enc").await.unwrap().is_empty());

    let fresh = tempfile::tempdir().unwrap();
    let fresh_cache = fresh.path().join("cache").to_string_lossy().to_string();
    let dst_db = fresh
        .path()
        .join("restored.db")
        .to_string_lossy()
        .to_string();
    cairn_core::restore_index_from_cloud(
        &engine.operators,
        &engine.crypto,
        &dst_db,
        &fresh_cache,
        "1",
    )
    .await
    .expect("production restore must succeed");

    let db2 = Db::new(&dst_db, None).unwrap();
    let mut engine2 = engine.new_from_db(db2);
    engine2.cache_dir = fresh_cache;
    engine2.store = {
        let s: std::sync::Arc<dyn cairn_store::ChunkStore> = std::sync::Arc::new(
            cairn_store::CairnStore::new(engine2.cache_dir.clone(), engine.operators.clone(), None),
        );
        s
    };
    let restored_ino = engine2
        .lookup(req.clone(), 1, OsStr::new("restore.bin"))
        .await
        .expect("restored archive must know the file")
        .attr
        .ino;
    let fh2 = engine2.open(req.clone(), restored_ino, 0).await.unwrap().0;
    let restored: Vec<u8> = engine2
        .read(req.clone(), restored_ino, fh2, 0, payload.len() as u32)
        .await
        .map_err(|e| panic!("restored read failed: {e}"))
        .unwrap();
    assert_eq!(
        restored, payload,
        "restored content must equal the original"
    );
}

#[tokio::test]
async fn b04_corrupt_data_chunk_is_rejected_on_read() {
    let (mut engine, _dir, op) = setup_engine().await;
    let payload = vec![0x55u8; 1024 * 1024];
    let ino = make_and_write(&engine, "f.bin", &payload).await;
    let (oid, _off, _len, _wrap, _ct, _algo) = engine
        .db
        .get_file_chunks(ino)
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let path = format!("chunks/{oid}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while op.stat(&path).await.is_err() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut blob = op.read(&path).await.unwrap().to_vec();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    op.write(&path, blob).await.unwrap();

    // Read through a FRESH cache: the source cache still holds the good object
    // and would conceal cloud corruption.
    let fresh = tempfile::tempdir().unwrap();
    let fresh_cache = fresh.path().join("cache").to_string_lossy().to_string();
    std::fs::create_dir_all(&fresh_cache).unwrap();
    let old_store = engine.store.clone();
    engine.store = {
        let s: std::sync::Arc<dyn cairn_store::ChunkStore> = std::sync::Arc::new(
            cairn_store::CairnStore::new(fresh_cache, engine.operators.clone(), None),
        );
        s
    };
    let res = engine.fetch_chunk(&oid).await;
    engine.store = old_store;
    assert!(res.is_err(), "corrupted chunk must be rejected");
}

#[tokio::test]
async fn b04_corrupt_manifest_is_rejected_on_restore() {
    let (engine, _dir, op) = setup_engine().await;
    engine.sync_index_to_cloud().await.unwrap();
    op.write("meta/archive.db.enc", b"not a sealed manifest".to_vec())
        .await
        .unwrap();

    let fresh = tempfile::tempdir().unwrap();
    let db_path = fresh.path().join("x.db").to_string_lossy().to_string();
    let cache_path = fresh.path().join("c").to_string_lossy().to_string();
    let res = cairn_core::restore_index_from_cloud(
        &engine.operators,
        &engine.crypto,
        &db_path,
        &cache_path,
        "1",
    )
    .await;
    assert!(res.is_err(), "corrupt manifest must fail the restore");
}
