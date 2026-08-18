use cairn_core::CairnEngine;
use cairn_core::types::*;
use dashmap::DashMap;
use lru::LruCache;
use std::ffi::OsString;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tempfile::TempDir;
use tokio::sync::Mutex;

async fn setup_engine() -> (CairnEngine, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();

    let pub_path = temp_dir.path().join("pub.pem");
    let priv_path = temp_dir.path().join("priv.pem");

    // Generate keys
    use age::secrecy::ExposeSecret;
    let identity = age::x25519::Identity::generate();
    let priv_key_val = identity.to_string().expose_secret().to_string();
    let pub_key_str = identity.to_public().to_string();

    std::fs::write(&pub_path, pub_key_str).unwrap();
    std::fs::write(&priv_path, priv_key_val).unwrap();

    // file-backed DB (like production) — a pooled `:memory:` SQLite DB is
    // per-connection, so the r2d2 pool hands out separate empty databases and
    // many-op tests intermittently hit a fresh one (mknod EIO, flaky suite).
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
        backup_stats: std::sync::Arc::new(cairn_core::BackupStats::new()),
        gc_running: std::sync::Arc::new(tokio::sync::Mutex::new(())),
    };

    // Initialize root directory (ino 1)
    let req = Request::default();
    engine.init(req).await.unwrap();

    (engine, temp_dir)
}

#[tokio::test]
async fn test_mkdir_and_readdir() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();

    // Create a directory
    let dir_name = OsString::from("testdir");
    let reply = engine
        .mkdir(req.clone(), 1, &dir_name, 0o755, 0)
        .await
        .unwrap();
    assert_eq!(reply.attr.kind, FileType::Directory);

    // Read root directory
    let entries = engine.readdir(req, 1, 0, 0).await.unwrap();
    let found = entries.iter().find(|e| e.name == dir_name);
    assert!(found.is_some(), "testdir should be in readdir results");
}

#[tokio::test]
async fn test_file_create_write_read_unlink() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();

    // Create file
    let file_name = OsString::from("testfile.txt");
    let reply = engine
        .mknod(req.clone(), 1, &file_name, 0o644, 0)
        .await
        .unwrap();
    let ino = reply.attr.ino;
    assert_eq!(reply.attr.kind, FileType::RegularFile);

    // Write to file
    let data = b"Hello, World!";
    let written = engine
        .write(req.clone(), ino, 0, 0, data, 0, 0)
        .await
        .unwrap();
    assert_eq!(written as usize, data.len());

    // Release (which flushes buffer)
    engine
        .release(req.clone(), ino, 0, libc::O_WRONLY as u32, 0, true)
        .await
        .unwrap();

    // Read from file
    let read_data = engine.read(req.clone(), ino, 0, 0, 100).await.unwrap();
    assert_eq!(read_data, data);

    // Unlink file
    engine.unlink(req.clone(), 1, &file_name).await.unwrap();

    // Try read again (should fail because inode is removed from db index but maybe accessible if we still have inode, but unlink deletes it from parent)
    // Looking up the file should fail
    let lookup_res = engine.lookup(req.clone(), 1, &file_name).await;
    assert!(lookup_res.is_err());
}

/// Regression test for directory-listing pagination. The kernel may start a
/// listing with readdirplus and CONTINUE it with plain readdir passing the last
/// consumed entry's offset (READDIRPLUS_AUTO) — a stateful cursor filled only by
/// readdir broke this: the continuation restarted from the top, so `ls` showed
/// every entry twice (live-reproduced with 150 files → 301 entries).
#[tokio::test]
async fn test_readdir_pagination_stateless() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();

    let dir_reply = engine
        .mkdir(req.clone(), 1, &OsString::from("d"), 0o755, 0)
        .await
        .unwrap();
    let dino = dir_reply.attr.ino;
    for i in 0..10 {
        engine
            .mknod(
                req.clone(),
                dino,
                &OsString::from(format!("f{i:02}")),
                0o644,
                0,
            )
            .await
            .unwrap();
    }

    // First page via readdirplus (the kernel's first call): `.` + `..` + 10 files.
    let plus = engine
        .readdirplus(req.clone(), dino, 0, 0, 0)
        .await
        .unwrap();
    let plus_names: Vec<String> = plus
        .iter()
        .skip(2)
        .map(|e| e.name.to_string_lossy().to_string())
        .collect();
    assert_eq!(plus_names.len(), 10);

    // Continuation via plain readdir at the last consumed offset: MUST be empty.
    let last_off = plus.last().unwrap().offset;
    let cont = engine
        .readdir(req.clone(), dino, 0, last_off)
        .await
        .unwrap();
    assert!(
        cont.is_empty(),
        "readdir continuation after the last entry must be empty, got {} entries (directory re-listed)",
        cont.len()
    );

    // Mid-stream continuation after the 3rd file: exactly the remaining 7, once each.
    let mid_off = plus[2 + 2].offset;
    let cont2 = engine.readdir(req.clone(), dino, 0, mid_off).await.unwrap();
    let cont2_names: Vec<String> = cont2
        .iter()
        .map(|e| e.name.to_string_lossy().to_string())
        .collect();
    assert_eq!(cont2_names, plus_names[3..].to_vec());
}

/// Regression test for the global write-buffer accounting: non-contiguous
/// writes, fsync and release must leave the counter at exactly 0 (an underflow
/// wraps to usize::MAX and locks every writer into permanent backpressure).
#[tokio::test]
async fn test_write_buffer_accounting() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();

    let file_name = OsString::from("counter.bin");
    let reply = engine
        .mknod(req.clone(), 1, &file_name, 0o644, 0)
        .await
        .unwrap();
    let ino = reply.attr.ino;

    // Sequential write, then a non-contiguous one (forces the random-write
    // flush path), then fsync + release.
    let a = vec![0xAAu8; 8192];
    let b = vec![0xBBu8; 4096];
    engine
        .write(req.clone(), ino, 0, 0, &a, 0, 0)
        .await
        .unwrap();
    engine
        .write(req.clone(), ino, 0, 100_000, &b, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    // fsync flushed everything; a second fsync on the empty buffer must not
    // double-decrement the counter.
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    engine
        .release(req.clone(), ino, 0, libc::O_WRONLY as u32, 0, true)
        .await
        .unwrap();

    assert_eq!(
        engine
            .global_write_buffer_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "write-buffer byte counter must return to zero after all data is flushed"
    );
    assert!(
        !engine.write_buffers.contains_key(&ino),
        "release must drop the per-inode buffer entry"
    );
    assert!(
        !engine.write_locks.contains_key(&ino),
        "release must evict the per-inode write-lock entry (one Arc<Mutex> per \
         inode ever touched otherwise — ~0.4 GB RSS per million files)"
    );

    // Both ranges must be readable back intact.
    let read_a = engine.read(req.clone(), ino, 0, 0, 8192).await.unwrap();
    assert_eq!(read_a, a);
    let read_b = engine
        .read(req.clone(), ino, 0, 100_000, 4096)
        .await
        .unwrap();
    assert_eq!(read_b, b);
}

#[tokio::test]
async fn test_rename() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();

    let old_name = OsString::from("old.txt");
    let new_name = OsString::from("new.txt");

    engine
        .mknod(req.clone(), 1, &old_name, 0o644, 0)
        .await
        .unwrap();

    engine
        .rename(req.clone(), 1, &old_name, 1, &new_name)
        .await
        .unwrap();

    assert!(engine.lookup(req.clone(), 1, &old_name).await.is_err());
    assert!(engine.lookup(req.clone(), 1, &new_name).await.is_ok());
}

#[tokio::test]
async fn test_setattr() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();

    let name = OsString::from("attr.txt");
    let reply = engine.mknod(req.clone(), 1, &name, 0o644, 0).await.unwrap();
    let ino = reply.attr.ino;

    let attr = SetAttr {
        size: Some(1024),
        ..Default::default()
    };

    let attr_reply = engine.setattr(req.clone(), ino, None, attr).await.unwrap();
    assert_eq!(attr_reply.size, 1024);
}
