// H15: trusted checkpoint outside the store — rollback and tampering must be
// detected; loss/corruption of the checkpoint is an explicit refusal.
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

async fn make_file(engine: &CairnEngine, name: &str, payload: &[u8]) {
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
async fn checkpoint_detects_rollback_tampering_and_refuses_corruption() {
    let (engine, _dir) = setup_engine().await;
    make_file(&engine, "a.bin", &vec![0x5Au8; 60_000]).await;
    let cp = _dir.path().join("trusted.checkpoint");

    engine.db.create_snapshot("s1").unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    engine.db.create_snapshot("s2").unwrap();
    let snaps = engine.db.list_snapshots().unwrap();
    let (sid1, _, _) = snaps[0];
    let (sid2, _, _) = snaps[1];
    assert!(sid1 < sid2);

    // The trusted writer checkpoints the newest snapshot.
    engine
        .record_checkpoint(sid2, &cp)
        .await
        .expect("checkpoint newest");
    assert!(cp.exists());

    // The newest passes; an OLDER snapshot is detected as rollback.
    engine
        .verify_snapshot_against_checkpoint(sid2, &cp)
        .await
        .expect("newest must validate");
    let err = engine
        .verify_snapshot_against_checkpoint(sid1, &cp)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("OLDER"),
        "rollback must be caught: {err}"
    );

    // Regression guard: the checkpoint can never move backwards in seq.
    let err = engine.record_checkpoint(sid1, &cp).await.unwrap_err();
    assert!(
        err.to_string().contains("refusing to regress"),
        "regress: {err}"
    );

    // Tampering with the checkpoint root must fail even for the newest snapshot.
    std::fs::write(&cp, format!("seq={}\nroot={}\n", sid2, "11".repeat(32))).unwrap();
    let err = engine
        .verify_snapshot_against_checkpoint(sid2, &cp)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("does not match") || err.to_string().contains("tampered"),
        "tampered root: {err}"
    );

    // A missing/corrupt checkpoint must be an explicit refusal, not a silent pass.
    std::fs::write(&cp, b"garbage").unwrap();
    let err = engine
        .verify_snapshot_against_checkpoint(sid2, &cp)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("missing seq") || err.to_string().contains("root"),
        "{err}"
    );
    std::fs::remove_file(&cp).unwrap();
    let err = engine
        .verify_snapshot_against_checkpoint(sid2, &cp)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("no trusted checkpoint"),
        "absent: {err}"
    );

    // Retention is an explicit, operator-approved rollback: it may re-anchor
    // to an older retained snapshot, unlike normal checkpoint recording.
    engine.recheckpoint_after_prune(sid1, &cp).await.unwrap();
    engine
        .verify_snapshot_against_checkpoint(sid1, &cp)
        .await
        .expect("explicit retention re-anchor must validate the retained snapshot");
}

#[tokio::test]
async fn snapshot_bundle_round_trip_validates_before_cache_import() {
    let (engine, dir) = setup_engine().await;
    make_file(&engine, "bundle.bin", &vec![0x42; 30_000]).await;
    engine.db.create_snapshot("portable").unwrap();
    let id = engine.db.list_snapshots().unwrap()[0].0;
    let bundle = dir.path().join("bundle");
    engine.export_snapshot_bundle(id, &bundle).await.unwrap();
    let imported_cache = dir.path().join("imported-cache");
    assert_eq!(
        CairnEngine::import_snapshot_bundle(&bundle, &imported_cache)
            .await
            .unwrap(),
        id
    );
    for object in engine.db.snapshot_used_objects(id).unwrap() {
        assert!(cacache::read(&imported_cache, object).await.is_ok());
    }
}

// BF-04.4 (audit 2026-09-17): the bundle import must authenticate snapshot.db,
// reject duplicate ids, and refuse manifests that predate the db hash.

#[tokio::test]
async fn snapshot_bundle_rejects_a_tampered_snapshot_db() {
    let (engine, dir) = setup_engine().await;
    make_file(&engine, "db-tamper.bin", &vec![0x51; 30_000]).await;
    engine.db.create_snapshot("portable").unwrap();
    let id = engine.db.list_snapshots().unwrap()[0].0;
    let bundle = dir.path().join("bundle");
    engine.export_snapshot_bundle(id, &bundle).await.unwrap();

    // Flip a byte in the DB copy; the manifest hash must catch it.
    let db_path = bundle.join("snapshot.db");
    let mut bytes = std::fs::read(&db_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&db_path, &bytes).unwrap();

    let err = CairnEngine::import_snapshot_bundle(&bundle, &dir.path().join("c1"))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("snapshot.db hash mismatch"),
        "{err}"
    );
}

#[tokio::test]
async fn snapshot_bundle_rejects_duplicate_object_ids() {
    let (engine, dir) = setup_engine().await;
    make_file(&engine, "dup.bin", &vec![0x52; 30_000]).await;
    engine.db.create_snapshot("portable").unwrap();
    let id = engine.db.list_snapshots().unwrap()[0].0;
    let bundle = dir.path().join("bundle");
    engine.export_snapshot_bundle(id, &bundle).await.unwrap();

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let objects = manifest["objects"].as_array().unwrap();
    assert!(!objects.is_empty(), "bundle must reference objects");
    let first = objects[0].clone();
    manifest["objects"].as_array_mut().unwrap().push(first);
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let err = CairnEngine::import_snapshot_bundle(&bundle, &dir.path().join("c2"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("duplicate object id"), "{err}");
}

#[tokio::test]
async fn snapshot_bundle_rejects_pre_db_hash_manifests() {
    let (engine, dir) = setup_engine().await;
    make_file(&engine, "old.bin", &vec![0x53; 30_000]).await;
    engine.db.create_snapshot("portable").unwrap();
    let id = engine.db.list_snapshots().unwrap()[0].0;
    let bundle = dir.path().join("bundle");
    engine.export_snapshot_bundle(id, &bundle).await.unwrap();

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest.as_object_mut().unwrap().remove("db_hash");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let err = CairnEngine::import_snapshot_bundle(&bundle, &dir.path().join("c3"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no snapshot.db hash"), "{err}");
}

// BF-04.9: concurrent recordings must serialize — the checkpoint can never end
// up at a sequence lower than the maximum that was recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_checkpoints_never_regress_the_sequence() {
    let (engine, dir) = setup_engine().await;
    make_file(&engine, "cp.bin", &vec![0x21; 30_000]).await;
    for i in 0..6 {
        engine.db.create_snapshot(&format!("s{i}")).unwrap();
    }
    let ids: Vec<u64> = engine
        .db
        .list_snapshots()
        .unwrap()
        .into_iter()
        .map(|(id, _, _)| id)
        .collect();
    let max_id = *ids.iter().max().unwrap();
    let engine = Arc::new(engine);
    let cp = dir.path().join("race.checkpoint");

    let mut handles = Vec::new();
    // Spawn in REVERSE order so the first write to land is an older snapshot.
    for id in ids.iter().rev() {
        let e = engine.clone();
        let cp = cp.clone();
        let id = *id;
        handles.push(tokio::spawn(async move {
            let _ = e.record_checkpoint(id, &cp).await;
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    engine
        .verify_snapshot_against_checkpoint(max_id, &cp)
        .await
        .expect("checkpoint must be at the maximum recorded sequence");
}
