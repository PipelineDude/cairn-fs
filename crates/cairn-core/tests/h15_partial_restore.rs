// H15: partial restore — restore ONE file from a snapshot, authenticated by
// the trusted checkpoint (freshness) AND a Merkle inclusion chain (membership
// in the snapshot root), with a read-back digest check before any write.
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
    setup_engine_with(None, 256_000).await
}

/// BF-04.2: same engine, but with an encrypted DB and an explicit kdf_iter, so
/// partial restore must carry the archive's cipher parameters into the
/// extracted snapshot copy.
async fn setup_engine_with(password: Option<&str>, kdf_iter: u32) -> (CairnEngine, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let pub_path = temp_dir.path().join("pub.pem");
    let priv_path = temp_dir.path().join("priv.pem");
    let identity = age::x25519::Identity::generate();
    let priv_key_val = identity.to_string().expose_secret().to_string();
    let pub_key_str = identity.to_public().to_string();
    std::fs::write(&pub_path, pub_key_str).unwrap();
    std::fs::write(&priv_path, priv_key_val).unwrap();
    let db_path = temp_dir.path().join("test.db");
    let secret = password.map(|p| secrecy::SecretString::from(p.to_string()));
    let tuning = cairn_index::DbTuning {
        kdf_iter,
        ..Default::default()
    };
    let db =
        Arc::new(Db::new_with_tuning(db_path.to_str().unwrap(), secret.as_ref(), &tuning).unwrap());
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

async fn write_file(engine: &CairnEngine, parent: u64, name: &str, payload: &[u8]) {
    let req = Request::default();
    let (entry, fh, _) = engine
        .create(req.clone(), parent, OsStr::new(name), 0o100644, 0)
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

async fn make_subdir(engine: &CairnEngine, parent: u64, name: &str) -> u64 {
    let req = Request::default();
    let entry = engine
        .mkdir(req.clone(), parent, OsStr::new(name), 0o040755, 0)
        .await
        .unwrap();
    entry.attr.ino
}

#[tokio::test]
async fn partial_restore_is_fresh_included_and_digest_checked() {
    let (engine, dir) = setup_engine().await;
    let payload_a = vec![0x5Au8; 60_000];
    write_file(&engine, 1, "a.bin", &payload_a).await;
    engine.db.create_snapshot("s1").unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Deeper tree: sub/deep.bin and a second top-level file b.bin.
    let sub = make_subdir(&engine, 1, "sub").await;
    let payload_deep = vec![0xBBu8; 40_000];
    write_file(&engine, sub, "deep.bin", &payload_deep).await;
    engine.db.create_snapshot("s2").unwrap();

    let snaps = engine.db.list_snapshots().unwrap();
    let (sid1, _) = (snaps[0].0, ());
    let (sid2, _) = (snaps[1].0, ());
    let cp = dir.path().join("trusted.checkpoint");
    engine
        .record_checkpoint(sid2, &cp)
        .await
        .expect("checkpoint s2");

    let out = dir.path().join("restore");

    // Happy path: restore a top-level file from the fresh snapshot.
    engine
        .restore_path_from_snapshot(sid2, "/a.bin", &cp, &out.join("a.out"))
        .await
        .expect("restore a.bin");
    assert_eq!(std::fs::read(out.join("a.out")).unwrap(), payload_a);

    // Nested path: the inclusion chain walks BOTH levels up to the root.
    engine
        .restore_path_from_snapshot(sid2, "/sub/deep.bin", &cp, &out.join("deep.out"))
        .await
        .expect("restore deep.bin");
    assert_eq!(std::fs::read(out.join("deep.out")).unwrap(), payload_deep);

    // A path absent from the (fresh) snapshot is an explicit failure.
    let err = engine
        .restore_path_from_snapshot(sid2, "/missing.bin", &cp, &out.join("missing.out"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");

    // ROLLBACK: restoring the OLDER snapshot against the newer checkpoint fails.
    let err = engine
        .restore_path_from_snapshot(sid1, "/a.bin", &cp, &out.join("old.out"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("OLDER"), "{err}");

    // TAMPERED checkpoint: even the fresh snapshot refuses (root mismatch).
    std::fs::write(&cp, format!("seq={}\nroot={}\n", sid2, "11".repeat(32))).unwrap();
    let err = engine
        .restore_path_from_snapshot(sid2, "/a.bin", &cp, &out.join("tampered.out"))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("does not match") || err.to_string().contains("tampered"),
        "{err}"
    );
    assert!(
        !out.join("tampered.out").exists(),
        "no file on tampered path"
    );
}

// BF-04.2: partial restore on an ENCRYPTED archive whose tuning carries a
// non-default kdf_iter. After the BF-04.12 order fix (the kdf pragma must
// follow keying) this is a true discriminator: the archive is really keyed
// with 1 024 iterations, and the restore must carry the archive's parameters
// into the extracted snapshot copy.
#[tokio::test]
async fn partial_restore_works_with_a_non_default_kdf_iter() {
    let (engine, dir) = setup_engine_with(Some("kdf-test-password"), 1_024).await;
    let payload = vec![0x77u8; 70_000];
    write_file(&engine, 1, "kdf.bin", &payload).await;
    engine.db.create_snapshot("s-kdf").unwrap();

    let sid = engine.db.list_snapshots().unwrap()[0].0;
    let cp = dir.path().join("kdf.checkpoint");
    engine
        .record_checkpoint(sid, &cp)
        .await
        .expect("checkpoint");

    let out = dir.path().join("kdf.out");
    engine
        .restore_path_from_snapshot(sid, "/kdf.bin", &cp, &out)
        .await
        .expect("partial restore on a non-default kdf_iter archive");
    assert_eq!(std::fs::read(&out).unwrap(), payload);
}

// BF-04.3: a hardlinked inode appears under several names (even two names in
// ONE directory). The inclusion proof must walk the requested dentry —
// `get_parent_inode`/id-only child lookup used to select an arbitrary sibling
// and fail a healthy file as "tampered".
#[tokio::test]
async fn partial_restore_works_for_hardlinked_names() {
    let (engine, dir) = setup_engine().await;
    let req = Request::default();
    let payload = vec![0x42u8; 50_000];
    write_file(&engine, 1, "a.bin", &payload).await;

    let entry = engine
        .lookup(req.clone(), 1, OsStr::new("a.bin"))
        .await
        .unwrap();
    let ino = entry.attr.ino;
    // Same directory, second name, and a second directory.
    engine
        .link(req.clone(), ino, 1, OsStr::new("z.bin"))
        .await
        .unwrap();
    let sub = make_subdir(&engine, 1, "d2").await;
    engine
        .link(req.clone(), ino, sub, OsStr::new("z.bin"))
        .await
        .unwrap();

    engine.db.create_snapshot("s-link").unwrap();
    let sid = engine.db.list_snapshots().unwrap()[0].0;
    let cp = dir.path().join("link.checkpoint");
    engine
        .record_checkpoint(sid, &cp)
        .await
        .expect("checkpoint");

    for (path, out_name) in [
        ("/a.bin", "a.out"),
        ("/z.bin", "z.out"),
        ("/d2/z.bin", "dz.out"),
    ] {
        let out = dir.path().join(out_name);
        engine
            .restore_path_from_snapshot(sid, path, &cp, &out)
            .await
            .unwrap_or_else(|e| panic!("restore {path}: {e}"));
        assert_eq!(std::fs::read(&out).unwrap(), payload, "restore {path}");
    }
}
