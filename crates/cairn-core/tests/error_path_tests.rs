// Regression tests for engine error paths documented in the audit history.
// These cover the error/edge branches (ENODATA / ENOENT / EEXIST / EFBIG) that
// the happy-path suite does not — each one guards a previously-fixed bug.

use cairn_core::CairnEngine;
use cairn_core::types::*;
use dashmap::DashMap;
use lru::LruCache;
use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tempfile::TempDir;
use tokio::sync::Mutex;

async fn setup_engine(max_file_size: u64) -> (CairnEngine, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    use age::secrecy::ExposeSecret;
    let id = age::x25519::Identity::generate();
    let pubp = temp_dir.path().join("pub.pem");
    let privp = temp_dir.path().join("priv.pem");
    std::fs::write(&pubp, id.to_public().to_string()).unwrap();
    std::fs::write(&privp, id.to_string().expose_secret()).unwrap();

    let db = Arc::new(
        cairn_index::Db::new(temp_dir.path().join("t.db").to_str().unwrap(), None).unwrap(),
    );
    let cache_dir = temp_dir.path().join("cache").to_string_lossy().to_string();
    std::fs::create_dir_all(&cache_dir).unwrap();
    let crypto = cairn_seal::CryptoCtx::new(
        pubp.to_str().unwrap(),
        Some(privp.to_str().unwrap()),
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
        crypto: Arc::new(crypto),
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
        no_comp_ext: vec![],
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
        max_file_size,
        backup_stats: std::sync::Arc::new(cairn_core::BackupStats::new()),
        gc_running: std::sync::Arc::new(tokio::sync::Mutex::new(())),
    };
    engine.init(Request::default()).await.unwrap();
    (engine, temp_dir)
}

fn errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

// getxattr for an attribute the file does not have returns ENODATA
// (distinguished from a real DB error, which is EIO).
#[tokio::test]
async fn test_getxattr_missing_returns_enodata() {
    let (engine, _d) = setup_engine(cairn_core::DEFAULT_MAX_FILE_SIZE).await;
    let req = Request::default();
    let ino = engine
        .mknod(req.clone(), 1, OsStr::new("f"), 0o644, 0)
        .await
        .unwrap()
        .attr
        .ino;
    let err = engine
        .getxattr(req, ino, OsStr::new("user.absent"), 0)
        .await
        .expect_err("missing xattr must error");
    assert_eq!(errno(&err), libc::ENODATA);
}

// setattr on an inode that does not exist returns ENOENT (not a generic EIO).
#[tokio::test]
async fn test_setattr_missing_inode_returns_enoent() {
    let (engine, _d) = setup_engine(cairn_core::DEFAULT_MAX_FILE_SIZE).await;
    let sa = SetAttr {
        mode: Some(0o600),
        uid: None,
        gid: None,
        size: None,
        atime: None,
        mtime: None,
        ctime: None,
        fh: None,
    };
    let err = engine
        .setattr(Request::default(), 987_654, None, sa)
        .await
        .expect_err("setattr on a missing inode must error");
    assert_eq!(errno(&err), libc::ENOENT);
}

// XATTR_CREATE on an existing attribute → EEXIST; XATTR_REPLACE on a
// missing attribute → ENODATA (the flag semantics, not silently applied).
#[tokio::test]
async fn test_setxattr_create_replace_flag_semantics() {
    let (engine, _d) = setup_engine(cairn_core::DEFAULT_MAX_FILE_SIZE).await;
    let req = Request::default();
    let ino = engine
        .mknod(req.clone(), 1, OsStr::new("f"), 0o644, 0)
        .await
        .unwrap()
        .attr
        .ino;

    engine
        .setxattr(req.clone(), ino, OsStr::new("user.a"), b"1", 0, 0)
        .await
        .expect("plain set should succeed");

    let e_exist = engine
        .setxattr(
            req.clone(),
            ino,
            OsStr::new("user.a"),
            b"2",
            libc::XATTR_CREATE as u32,
            0,
        )
        .await
        .expect_err("XATTR_CREATE on an existing attr must fail");
    assert_eq!(errno(&e_exist), libc::EEXIST);

    let e_nodata = engine
        .setxattr(
            req,
            ino,
            OsStr::new("user.absent"),
            b"x",
            libc::XATTR_REPLACE as u32,
            0,
        )
        .await
        .expect_err("XATTR_REPLACE on a missing attr must fail");
    assert_eq!(errno(&e_nodata), libc::ENODATA);
}

// A write whose end offset exceeds the archive's max file size is refused with
// EFBIG, so a runaway file cannot blow past the configured ceiling.
#[tokio::test]
async fn test_write_past_max_file_size_efbig() {
    let (engine, _d) = setup_engine(4096).await; // tiny ceiling
    let req = Request::default();
    let ino = engine
        .mknod(req.clone(), 1, OsStr::new("big"), 0o644, 0)
        .await
        .unwrap()
        .attr
        .ino;
    let err = engine
        .write(req, ino, 0, 8000, b"way past the ceiling", 0, 0)
        .await
        .expect_err("write past max_file_size must fail");
    assert_eq!(errno(&err), libc::EFBIG);
}
