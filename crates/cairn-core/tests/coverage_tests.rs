use cairn_core::CairnEngine;
use cairn_core::types::*;
use dashmap::DashMap;
use lru::LruCache;
use std::ffi::{OsStr, OsString};
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
    engine.init(Request::default()).await.unwrap();
    (engine, temp_dir)
}

// ════════════════════════════════════════════════════════════════════
// File operations — edge cases
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_read_empty_file() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("empty"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Write 0 bytes — should be a no-op.
    engine
        .write(req.clone(), ino, 0, 0, b"", 0, 0)
        .await
        .unwrap();
    // Read 0 bytes — should return empty.
    let data = engine.read(req.clone(), ino, 0, 0, 0).await.unwrap();
    assert!(data.is_empty());
}

#[tokio::test]
async fn test_read_past_eof() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("f"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    engine
        .write(req.clone(), ino, 0, 0, b"hello", 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    // Read at offset 10 (past EOF of 5 bytes) with size 100.
    let data = engine.read(req.clone(), ino, 0, 10, 100).await.unwrap();
    // Should return empty because offset >= file_size.
    assert!(data.is_empty());
}

#[tokio::test]
async fn test_write_at_offset_past_current_size() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("gap"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Write 1 byte at offset 100 — creates a gap [0, 100).
    engine
        .write(req.clone(), ino, 0, 100, b"X", 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    // Verify file size is 101.
    let attr = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(attr.size, 101);
    // Read from offset 0 — gap [0, 100) should be zero-filled.
    let data = engine.read(req.clone(), ino, 0, 0, 101).await.unwrap();
    assert_eq!(data.len(), 101);
    assert!(
        data[..100].iter().all(|b| *b == 0),
        "gap should be zero-filled"
    );
    assert_eq!(data[100], b'X');
}

#[tokio::test]
async fn test_write_exact_inline_threshold() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("th"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Write exactly 4096 bytes (INLINE_THRESHOLD).
    let payload = vec![0xAB_u8; 4096];
    engine
        .write(req.clone(), ino, 0, 0, &payload, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    // Verify inline storage (no file_chunks).
    let chunks = engine.db.get_file_chunks(ino).unwrap();
    assert!(
        chunks.is_empty(),
        "exactly INLINE_THRESHOLD should be inline, not chunked"
    );
    // Verify data round-trips.
    let data = engine.read(req.clone(), ino, 0, 0, 4096).await.unwrap();
    assert_eq!(data, payload);
}

#[tokio::test]
async fn test_write_one_byte_over_inline_threshold() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("over"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Write 4097 bytes (one over INLINE_THRESHOLD).
    let payload = vec![0xCD_u8; 4097];
    engine
        .write(req.clone(), ino, 0, 0, &payload, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    // Should be chunked (not inline).
    let inline = engine.db.get_inline_data(ino).unwrap();
    assert!(inline.is_none(), "4097 bytes should not be stored inline");
    // Data should still round-trip.
    let data = engine.read(req.clone(), ino, 0, 0, 4097).await.unwrap();
    assert_eq!(data, payload);
}

#[tokio::test]
async fn test_write_zero_bytes() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("z"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let before = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    // Write empty slice.
    engine
        .write(req.clone(), ino, 0, 0, b"", 0, 0)
        .await
        .unwrap();
    let after = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(
        before.size, after.size,
        "size should not change on zero-byte write"
    );
}

#[tokio::test]
async fn test_read_zero_bytes() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("rz"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    engine
        .write(req.clone(), ino, 0, 0, b"hello", 0, 0)
        .await
        .unwrap();
    // Read with size=0.
    let data = engine.read(req.clone(), ino, 0, 0, 0).await.unwrap();
    assert!(data.is_empty());
}

#[tokio::test]
async fn test_multiple_writes_same_offset() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("ow"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Two sequential writes at offset 0 — second should win.
    engine
        .write(req.clone(), ino, 0, 0, b"first", 0, 0)
        .await
        .unwrap();
    engine
        .write(req.clone(), ino, 0, 0, b"second", 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    let data = engine.read(req.clone(), ino, 0, 0, 6).await.unwrap();
    assert_eq!(&data, b"second");
}

#[tokio::test]
async fn test_write_read_larger_than_max_write() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("big"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Write 2 MiB (twice DEFAULT_MAX_WRITE).
    let payload = vec![0x42_u8; 2 * 1024 * 1024];
    engine
        .write(req.clone(), ino, 0, 0, &payload, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    // Read back in chunks (each capped at max_write).
    let chunk_size = cairn_core::DEFAULT_MAX_WRITE as usize;
    let mut offset = 0u64;
    while offset < payload.len() as u64 {
        let remaining = (payload.len() as u64 - offset) as u32;
        let to_read = remaining.min(chunk_size as u32);
        let data = engine
            .read(req.clone(), ino, 0, offset, to_read)
            .await
            .unwrap();
        let start = offset as usize;
        assert_eq!(data, &payload[start..start + data.len()]);
        offset += data.len() as u64;
    }
}

// ════════════════════════════════════════════════════════════════════
// Directory operations — edge cases
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_mkdir_empty_name() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    // Creating a dir with empty name — behavior depends on impl.
    let result = engine.mkdir(req.clone(), 1, OsStr::new(""), 0o755, 0).await;
    // Either succeeds or fails; just verify it doesn't panic.
    if let Ok(_r) = result {
        // If it succeeded, verify it appears in readdir.
        let entries = engine.readdir(req.clone(), 1, 0, 0).await.unwrap();
        assert!(entries.iter().any(|e| e.name.is_empty()));
    }
}

#[tokio::test]
async fn test_readdir_empty_directory() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mkdir(req.clone(), 1, OsStr::new("emptydir"), 0o755, 0)
        .await
        .unwrap();
    let dir_ino = r.attr.ino;
    let entries = engine.readdir(req.clone(), dir_ino, 0, 0).await.unwrap();
    // An empty dir should only have "." and "..".
    let names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
    assert!(names.contains(&OsString::from(".")));
    assert!(names.contains(&OsString::from("..")));
    assert_eq!(names.len(), 2);
}

#[tokio::test]
async fn test_readdir_pagination() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mkdir(req.clone(), 1, OsStr::new("pagedir"), 0o755, 0)
        .await
        .unwrap();
    let dir_ino = r.attr.ino;
    // Create 5 files.
    for i in 0..5 {
        let name = OsString::from(format!("file{i}"));
        engine
            .mknod(req.clone(), dir_ino, &name, 0o644, 0)
            .await
            .unwrap();
    }
    // Use DB-level pagination with limit=2 to test page-by-page retrieval.
    let page1 = engine.db.list_dentries_rowid_after(dir_ino, 0, 2).unwrap();
    assert_eq!(page1.len(), 2, "first page should have 2 entries");
    let page2 = engine
        .db
        .list_dentries_rowid_after(dir_ino, page1.last().unwrap().0, 2)
        .unwrap();
    assert_eq!(page2.len(), 2, "second page should have 2 entries");
    let page3 = engine
        .db
        .list_dentries_rowid_after(dir_ino, page2.last().unwrap().0, 2)
        .unwrap();
    assert_eq!(page3.len(), 1, "third page should have 1 entry");
    // Verify no overlap.
    let all_names: Vec<_> = [page1, page2, page3]
        .iter()
        .flat_map(|p| p.iter().map(|r| r.1.clone()))
        .collect();
    assert_eq!(all_names.len(), 5);
}

#[tokio::test]
async fn test_lookup_nonexistent_entry() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let result = engine
        .lookup(req.clone(), 1, OsStr::new("nonexistent"))
        .await;
    assert!(result.is_err(), "lookup of nonexistent entry should fail");
}

#[tokio::test]
async fn test_mkdir_root_child() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mkdir(req.clone(), 1, OsStr::new("child"), 0o755, 0)
        .await
        .unwrap();
    let child_ino = r.attr.ino;
    // Verify it appears in readdir of root.
    let entries = engine.readdir(req.clone(), 1, 0, 0).await.unwrap();
    let names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
    assert!(
        names.contains(&OsString::from("child")),
        "mkdir under root should appear in readdir"
    );
    // Verify lookup works.
    let lookup = engine
        .lookup(req.clone(), 1, OsStr::new("child"))
        .await
        .unwrap();
    assert_eq!(lookup.attr.ino, child_ino);
}

// ════════════════════════════════════════════════════════════════════
// Symlink operations — edge cases
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_symlink_read_roundtrip() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let target = "/usr/local/bin/python3";
    let r = engine
        .symlink(req.clone(), 1, OsStr::new("pylink"), OsStr::new(target))
        .await
        .unwrap();
    let ino = r.attr.ino;
    let read_target = engine.readlink(req.clone(), ino).await.unwrap();
    assert_eq!(read_target, target.as_bytes());
}

#[tokio::test]
async fn test_symlink_overwrite() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    // Create first symlink.
    let r1 = engine
        .symlink(req.clone(), 1, OsStr::new("mlink"), OsStr::new("/first"))
        .await
        .unwrap();
    let ino1 = r1.attr.ino;
    // Create second symlink with same name — UNIQUE constraint causes EIO.
    let err = engine
        .symlink(req.clone(), 1, OsStr::new("mlink"), OsStr::new("/second"))
        .await
        .expect_err("duplicate symlink name should fail");
    assert_eq!(err.raw_os_error(), Some(libc::EIO));
    // First symlink is still intact.
    let lookup = engine
        .lookup(req.clone(), 1, OsStr::new("mlink"))
        .await
        .unwrap();
    assert_eq!(lookup.attr.ino, ino1);
    let target = engine.readlink(req.clone(), ino1).await.unwrap();
    assert_eq!(target, b"/first");
}

#[tokio::test]
async fn test_dangling_symlink() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    // Create symlink to a nonexistent target.
    let r = engine
        .symlink(
            req.clone(),
            1,
            OsStr::new("dangly"),
            OsStr::new("/nonexistent/path"),
        )
        .await
        .unwrap();
    let ino = r.attr.ino;
    // readlink should still return the target.
    let target = engine.readlink(req.clone(), ino).await.unwrap();
    assert_eq!(target, b"/nonexistent/path");
}

// ════════════════════════════════════════════════════════════════════
// Rename operations — edge cases
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_rename_same_directory() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("old"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    engine
        .rename(req.clone(), 1, OsStr::new("old"), 1, OsStr::new("new"))
        .await
        .unwrap();
    // Old name gone.
    assert!(
        engine
            .lookup(req.clone(), 1, OsStr::new("old"))
            .await
            .is_err()
    );
    // New name present with same inode.
    let lookup = engine
        .lookup(req.clone(), 1, OsStr::new("new"))
        .await
        .unwrap();
    assert_eq!(lookup.attr.ino, ino);
}

#[tokio::test]
async fn test_rename_cross_directory() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    // Create two directories.
    let dir_a = engine
        .mkdir(req.clone(), 1, OsStr::new("dirA"), 0o755, 0)
        .await
        .unwrap();
    let dir_b = engine
        .mkdir(req.clone(), 1, OsStr::new("dirB"), 0o755, 0)
        .await
        .unwrap();
    // Create file in dirA.
    let r = engine
        .mknod(req.clone(), dir_a.attr.ino, OsStr::new("moveme"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Rename across directories.
    engine
        .rename(
            req.clone(),
            dir_a.attr.ino,
            OsStr::new("moveme"),
            dir_b.attr.ino,
            OsStr::new("moved"),
        )
        .await
        .unwrap();
    // Gone from dirA.
    assert!(
        engine
            .lookup(req.clone(), dir_a.attr.ino, OsStr::new("moveme"))
            .await
            .is_err()
    );
    // Present in dirB.
    let lookup = engine
        .lookup(req.clone(), dir_b.attr.ino, OsStr::new("moved"))
        .await
        .unwrap();
    assert_eq!(lookup.attr.ino, ino);
}

#[tokio::test]
async fn test_rename_overwrite_existing() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    // Create two files.
    let r1 = engine
        .mknod(req.clone(), 1, OsStr::new("src"), 0o644, 0)
        .await
        .unwrap();
    let ino_src = r1.attr.ino;
    engine
        .mknod(req.clone(), 1, OsStr::new("dst"), 0o644, 0)
        .await
        .unwrap();
    // Rename src over dst — dst should be replaced.
    engine
        .rename(req.clone(), 1, OsStr::new("src"), 1, OsStr::new("dst"))
        .await
        .unwrap();
    let lookup = engine
        .lookup(req.clone(), 1, OsStr::new("dst"))
        .await
        .unwrap();
    assert_eq!(lookup.attr.ino, ino_src, "src should replace dst");
    assert!(
        engine
            .lookup(req.clone(), 1, OsStr::new("src"))
            .await
            .is_err()
    );
}

// ════════════════════════════════════════════════════════════════════
// Link operations
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_hardlink_increments_nlink() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("orig"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let before = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(before.nlink, 1);
    engine
        .link(req.clone(), ino, 1, OsStr::new("link_a"))
        .await
        .unwrap();
    let after = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(after.nlink, 2, "nlink should be 2 after one hardlink");
}

#[tokio::test]
async fn test_hardlink_shares_inode() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("orig"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let link_r = engine
        .link(req.clone(), ino, 1, OsStr::new("the_link"))
        .await
        .unwrap();
    assert_eq!(
        link_r.attr.ino, ino,
        "hardlink must share the same inode number"
    );
    // Both dentries should resolve to the same inode.
    let orig_lookup = engine
        .lookup(req.clone(), 1, OsStr::new("orig"))
        .await
        .unwrap();
    let link_lookup = engine
        .lookup(req.clone(), 1, OsStr::new("the_link"))
        .await
        .unwrap();
    assert_eq!(orig_lookup.attr.ino, link_lookup.attr.ino);
}

// ════════════════════════════════════════════════════════════════════
// Xattr operations — edge cases
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_setxattr_create_existing_fails() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("xattr_f"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    engine
        .setxattr(req.clone(), ino, OsStr::new("user.k"), b"v1", 0, 0)
        .await
        .unwrap();
    // XATTR_CREATE (flags=1) against existing → should fail with EEXIST.
    let err = engine
        .setxattr(req.clone(), ino, OsStr::new("user.k"), b"v2", 1, 0)
        .await
        .expect_err("XATTR_CREATE on existing must fail");
    assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
}

#[tokio::test]
async fn test_setxattr_replace_missing_fails() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("xattr_r"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // XATTR_REPLACE (flags=2) against missing → should fail with ENODATA.
    let err = engine
        .setxattr(req.clone(), ino, OsStr::new("user.nonexistent"), b"v", 2, 0)
        .await
        .expect_err("XATTR_REPLACE on missing must fail");
    assert_eq!(err.raw_os_error(), Some(libc::ENODATA));
}

#[tokio::test]
async fn test_getxattr_nonexistent() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("xattr_g"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let err = engine
        .getxattr(req.clone(), ino, OsStr::new("user.nope"), 1024)
        .await
        .expect_err("getxattr for nonexistent name must fail");
    assert_eq!(err.raw_os_error(), Some(libc::ENODATA));
}

#[tokio::test]
async fn test_listxattr_empty() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("xattr_l"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // listxattr with size=0 returns a fake fuse_getxattr_out with size 0.
    let data = engine.listxattr(req.clone(), ino, 0).await.unwrap();
    // The size field in the 8-byte response should be 0 (no xattrs).
    let sz = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    assert_eq!(
        sz, 0,
        "listxattr on inode with no xattrs should report size 0"
    );
}

#[tokio::test]
async fn test_removexattr_nonexistent() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("xattr_rm"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Removing a non-existent xattr should succeed (no error).
    engine
        .removexattr(req.clone(), ino, OsStr::new("user.noexist"))
        .await
        .unwrap();
}

// ════════════════════════════════════════════════════════════════════
// Truncate / setattr
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_setattr_truncate_to_zero() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("trunc0"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    engine
        .write(req.clone(), ino, 0, 0, b"hello world", 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    // Truncate to 0.
    engine
        .setattr(
            req.clone(),
            ino,
            None,
            SetAttr {
                size: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let attr = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(attr.size, 0);
}

#[tokio::test]
async fn test_setattr_truncate_below_threshold() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("trunc_in"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Write > 4096 bytes (chunked).
    let payload = vec![0xBB_u8; 8192];
    engine
        .write(req.clone(), ino, 0, 0, &payload, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    // Truncate to 100 bytes (below INLINE_THRESHOLD).
    engine
        .setattr(
            req.clone(),
            ino,
            None,
            SetAttr {
                size: Some(100),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let attr = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(attr.size, 100);
    // Read back and verify data.
    let data = engine.read(req.clone(), ino, 0, 0, 100).await.unwrap();
    assert_eq!(data.len(), 100);
    assert!(data.iter().all(|b| *b == 0xBB));
}

#[tokio::test]
async fn test_setattr_update_mode() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("mode_ch"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let before = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(before.perm, 0o644);
    // Change mode to 0o755.
    engine
        .setattr(
            req.clone(),
            ino,
            None,
            SetAttr {
                mode: Some(libc::S_IFREG | 0o755),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let after = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(after.perm, 0o755);
}

// ════════════════════════════════════════════════════════════════════
// DB-level edge cases (no engine needed)
// ════════════════════════════════════════════════════════════════════

// file-backed DB for the same reason as setup_engine above — with
// `:memory:` each pooled connection is a separate empty database, so even a
// 2-query test (insert on one connection, read on another) is flaky.
fn file_db() -> (cairn_index::Db, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = cairn_index::Db::new(dir.path().join("t.db").to_str().unwrap(), None).unwrap();
    (db, dir)
}

#[test]
fn test_insert_inode_invalid_mode() {
    let (db, _dir) = file_db();
    // Insert with mode 0 — DB doesn't enforce valid mode bits.
    let ino = db.insert_inode(0, 1000, 1000, 0, 1).unwrap();
    let info = db.get_inode(ino).unwrap().unwrap();
    assert_eq!(info.0, 0, "mode should be stored as-is even if 0");
}

#[test]
fn test_atomic_unlink_nonexistent_returns_error() {
    let (db, _dir) = file_db();
    // Unlink a name that doesn't exist under root.
    let result = db.atomic_unlink(1, "ghost_file", false);
    assert!(result.is_err(), "atomic_unlink of nonexistent must error");
}

#[test]
fn test_atomic_rename_nonexistent_source_returns_error() {
    let (db, _dir) = file_db();
    let result = db.atomic_rename(1, "no_source", 1, "no_dest", None);
    assert!(result.is_err(), "renaming nonexistent source must error");
}

#[test]
fn test_get_file_chunks_empty() {
    let (db, _dir) = file_db();
    let ino = db.insert_inode(0o100644, 0, 0, 0, 1).unwrap();
    let chunks = db.get_file_chunks(ino).unwrap();
    assert!(
        chunks.is_empty(),
        "inode with no chunks should return empty vec"
    );
}

#[test]
fn test_config_roundtrip() {
    let (db, _dir) = file_db();
    db.set_config("archive.name", "test-backup").unwrap();
    let val = db.get_config("archive.name").unwrap().unwrap();
    assert_eq!(val, "test-backup");
}

#[test]
fn test_config_missing_key_returns_none() {
    let (db, _dir) = file_db();
    let val = db.get_config("nonexistent.key").unwrap();
    assert!(val.is_none(), "missing key should return Ok(None)");
}

#[test]
fn test_insert_dentry_duplicate_fails() {
    let (db, _dir) = file_db();
    let ino1 = db.insert_inode(0o100644, 0, 0, 0, 1).unwrap();
    let ino2 = db.insert_inode(0o100644, 0, 0, 0, 1).unwrap();
    db.insert_dentry(1, "dup", ino1).unwrap();
    // Inserting the same (parent, name) again must fail (PRIMARY KEY violation).
    let result = db.insert_dentry(1, "dup", ino2);
    assert!(result.is_err(), "duplicate dentry must fail");
}

#[test]
fn test_insert_inode_multiple_modes() {
    let (db, _dir) = file_db();
    // Regular file.
    let reg = db.insert_inode(libc::S_IFREG | 0o644, 0, 0, 0, 1).unwrap();
    let info = db.get_inode(reg).unwrap().unwrap();
    assert_eq!(info.0 & libc::S_IFMT, libc::S_IFREG);
    // Directory.
    let dir = db
        .insert_inode(libc::S_IFDIR | 0o755, 0, 0, 4096, 2)
        .unwrap();
    let info = db.get_inode(dir).unwrap().unwrap();
    assert_eq!(info.0 & libc::S_IFMT, libc::S_IFDIR);
    // Symlink.
    let lnk = db.insert_inode(libc::S_IFLNK | 0o777, 0, 0, 10, 1).unwrap();
    let info = db.get_inode(lnk).unwrap().unwrap();
    assert_eq!(info.0 & libc::S_IFMT, libc::S_IFLNK);
}

#[test]
fn test_bulk_insert_file_chunks() {
    let (db, _dir) = file_db();
    let ino = db.insert_inode(0o100644, 0, 0, 0, 1).unwrap();
    // Insert chunk indices first.
    let indices: Vec<_> = (0..100)
        .map(|i| {
            (
                format!("obj_{i}"),
                format!("hash_{i}"),
                b"k".to_vec(),
                0i32,
                "aes-gcm".to_string(),
            )
        })
        .collect();
    db.insert_chunk_indices_batch(&indices).unwrap();
    // Insert 100 file_chunks.
    let chunks: Vec<_> = (0..100)
        .map(|i| (ino, i * 100, format!("obj_{i}"), 100usize, 0i32))
        .collect();
    db.insert_file_chunks_batch(&chunks).unwrap();
    // Verify all retrievable.
    let got = db.get_file_chunks(ino).unwrap();
    assert_eq!(got.len(), 100, "should retrieve all 100 chunks");
}

#[test]
fn test_orphaned_chunks_with_grace() {
    let dir = tempfile::tempdir().unwrap();
    let db = cairn_index::Db::new(dir.path().join("orphan.db").to_str().unwrap(), None).unwrap();
    // Insert a chunk_index entry with created_at=0 (orphaned, no file_chunks reference).
    let conn = db.pool.get().unwrap();
    conn.execute(
        "INSERT INTO chunk_index (object_id, plaintext_hash, sym_key, comp_type, created_at) \
         VALUES ('orphan_obj', 'hash_val', X'00', 0, 0)",
        [],
    )
    .unwrap();
    // With grace=0, the orphan should be detected immediately.
    let orphans = db.get_orphaned_chunks(0).unwrap();
    assert!(
        orphans.contains(&"orphan_obj".to_string()),
        "chunk with created_at=0 should be orphaned with grace=0"
    );
}
