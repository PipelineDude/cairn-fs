// H13b: resumable read-write replica repair (object-then-store, verified-only
// sources; no false success when no healthy source exists).
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

async fn make(data: &[u8], engine: &CairnEngine) -> Vec<String> {
    let req = Request::default();
    let (entry, fh, _) = engine
        .create(req.clone(), 1, OsStr::new("f.bin"), 0o100644, 0)
        .await
        .unwrap();
    engine
        .write(req.clone(), entry.attr.ino, fh, 0, data, 0, 0)
        .await
        .unwrap();
    engine.flush_range(entry.attr.ino, 0, data).await.unwrap();
    engine
        .release(req.clone(), entry.attr.ino, fh, 0, 0, true)
        .await
        .unwrap();
    engine.db.list_all_object_hashes().unwrap()
}

#[tokio::test]
async fn repair_fixes_missing_and_corrupt_replicas_and_idles_when_healthy() {
    let (engine, _dir, op0, op1) = setup_engine().await;
    let data: Vec<u8> = (0..40_000u32).map(|j| (j & 0xff) as u8).collect();
    let ids = make(&data, &engine).await;
    let path = |id: &str| format!("chunks/{id}");

    // Healthy: repair writes nothing.
    let r = engine.replicate_repair().await.unwrap();
    assert_eq!(r.repaired, 0, "healthy tree should repair nothing");
    assert_eq!(r.unrepaired.len(), 0);
    assert!(
        r.verified_skipped >= ids.len() * 2,
        "both stores should count as verified"
    );

    // Missing replica on store 1 → repaired from store 0.
    op1.delete(&path(&ids[0])).await.unwrap();
    let r = engine.replicate_repair().await.unwrap();
    assert_eq!(r.repaired, 1, "missing replica must be repaired: {r:?}");
    let audit = engine.replication_audit().await.unwrap();
    assert!(
        audit.missing.is_empty(),
        "audit after repair: {:?}",
        audit.missing
    );

    // Corrupt replica on store 1 → repaired.
    op1.write(&path(&ids[0]), b"wrong".to_vec()).await.unwrap();
    let r = engine.replicate_repair().await.unwrap();
    assert_eq!(r.repaired, 1, "corrupt replica must be repaired: {r:?}");
    let audit = engine.replication_audit().await.unwrap();
    assert!(
        audit.corrupt.is_empty(),
        "audit after repair: {:?}",
        audit.corrupt
    );

    // No verified source anywhere (both stores bad AND cache cleared) →
    // honest unrepaired, never a false "repaired" or a repair from bad bytes.
    let victim = ids[0].clone();
    let p0 = path(&victim);
    let mut bad0 = op0.read(&p0).await.unwrap().to_vec();
    let last = bad0.len() - 1;
    bad0[last] ^= 0x01;
    op0.write(&p0, bad0).await.unwrap();
    op1.delete(&p0).await.unwrap();
    cacache::remove(&engine.cache_dir, &victim).await.unwrap();

    let r = engine.replicate_repair().await.unwrap();
    assert!(
        r.unrepaired
            .iter()
            .any(|(id, idx)| id == &victim && *idx == 0),
        "{r:?}"
    );
    assert!(
        r.unrepaired
            .iter()
            .any(|(id, idx)| id == &victim && *idx == 1),
        "{r:?}"
    );
    let audit = engine.replication_audit().await.unwrap();
    assert!(
        !audit.missing.is_empty() || !audit.corrupt.is_empty(),
        "must stay damaged"
    );
}

#[tokio::test]
async fn repair_and_audit_refuse_non_replica_layouts_before_writing() {
    // BF-04.8: whole-replica repair/audit is only sound for raid1/fallback.
    // raid5/6 store shards (a whole-ciphertext write would corrupt the
    // stripe); raid0/10 legitimately keep only 1/2 of N copies, so the loop
    // would amplify replicas (repair) or report healthy backends as missing
    // (audit).
    for mode in ["raid5", "raid6", "raid0", "raid10"] {
        let (mut engine, _dir, _op0, _op1) = setup_engine().await;
        engine.raid_mode = mode.to_string();

        let err = engine.replicate_repair().await.unwrap_err();
        assert!(
            err.to_string().contains("not layout-aware"),
            "{mode} repair: {err}"
        );

        let audit_res = engine.replication_audit().await;
        assert!(audit_res.is_err(), "{mode} audit unexpectedly succeeded");
        let err = audit_res.err().unwrap();
        assert!(
            err.to_string().contains("not layout-aware"),
            "{mode} audit: {err}"
        );
    }
}
