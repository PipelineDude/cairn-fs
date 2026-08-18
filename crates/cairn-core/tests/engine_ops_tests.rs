// Engine-operation tests: fallocate, statfs, create, copy_file_range,
// mode_to_filetype, extract_single_file, new_readonly, gc, scrub.

use cairn_core::CairnEngine;
use cairn_core::types::*;
use dashmap::DashMap;
use lru::LruCache;
use std::ffi::OsStr;
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
        backup_stats: Arc::new(cairn_core::BackupStats::new()),
        gc_running: Arc::new(tokio::sync::Mutex::new(())),
    };
    let req = Request::default();
    engine.init(req).await.unwrap();
    (engine, temp_dir)
}

fn root_ino() -> u64 {
    1
}

#[tokio::test]
async fn test_copy_file_range_returns_enosys() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let err = engine
        .copy_file_range(req, 1, 0, 0, 1, 0, 0, 1024, 0)
        .await
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOSYS));
}

#[tokio::test]
async fn test_statfs_returns_valid_values() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let st = engine.statfs(req).await.unwrap();
    assert_eq!(st.bsize, 4096);
    assert_eq!(st.namelen, 255);
    assert_eq!(st.frsize, 4096);
    // Root directory (ino 1) exists after init
    assert!(st.files >= 1);
}

#[tokio::test]
async fn test_statfs_after_write() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("f.txt"), 0o100644, 0)
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("f.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    let data = vec![0xABu8; 4096];
    let fh = engine.open(req.clone(), ino, 0).await.unwrap().0;
    engine
        .write(req.clone(), ino, fh, 0, &data, 0, 0)
        .await
        .unwrap();
    engine
        .release(req.clone(), ino, fh, 0, 0, true)
        .await
        .unwrap();
    let st = engine.statfs(req).await.unwrap();
    // After write: at least root + f.txt = 2 inodes, at least 1 data block
    assert!(st.files >= 2);
    assert!(st.blocks >= 1);
}

#[tokio::test]
async fn test_create_file() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let (entry, fh, _flags) = engine
        .create(req.clone(), root_ino(), OsStr::new("new.txt"), 0o100644, 0)
        .await
        .unwrap();
    assert!(entry.attr.ino > 1);
    let found = engine
        .lookup(req.clone(), root_ino(), OsStr::new("new.txt"))
        .await
        .unwrap();
    assert_eq!(found.attr.ino, entry.attr.ino);
    engine
        .release(req.clone(), entry.attr.ino, fh, 0, 0, false)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_writes_data() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let (entry, fh, _) = engine
        .create(req.clone(), root_ino(), OsStr::new("data.bin"), 0o100644, 0)
        .await
        .unwrap();
    let payload = b"hello world";
    engine
        .write(req.clone(), entry.attr.ino, fh, 0, payload, 0, 0)
        .await
        .unwrap();
    engine
        .fsync(req.clone(), entry.attr.ino, fh, false)
        .await
        .unwrap();
    let buf = engine
        .read(req.clone(), entry.attr.ino, fh, 0, 64)
        .await
        .unwrap();
    assert_eq!(&buf[..], payload);
    engine
        .release(req.clone(), entry.attr.ino, fh, 0, 0, false)
        .await
        .unwrap();
}

// -- fallocate tests --

#[tokio::test]
async fn test_fallocate_length_zero_is_noop() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("f.txt"), 0o100644, 0)
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("f.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    engine
        .fallocate(req.clone(), ino, 0, 0, 0, 0)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_fallocate_punch_hole_without_keep_size_invalid() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("f.txt"), 0o100644, 0)
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("f.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    let err = engine
        .fallocate(req.clone(), ino, 0, 0, 4096, 0x02)
        .await
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[tokio::test]
async fn test_fallocate_punch_hole_with_keep_size() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("f.txt"), 0o100644, 0)
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("f.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    engine
        .fallocate(req.clone(), ino, 0, 0, 4096, 0x02 | 0x01)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_fallocate_keep_size_only() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("f.txt"), 0o100644, 0)
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("f.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    engine
        .fallocate(req.clone(), ino, 0, 0, 8192, 0x01)
        .await
        .unwrap();
    let st = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(st.size, 0);
}

#[tokio::test]
async fn test_fallocate_default_grows_size() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("f.txt"), 0o100644, 0)
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("f.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    engine
        .fallocate(req.clone(), ino, 0, 0, 16384, 0)
        .await
        .unwrap();
    let st = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(st.size, 16384);
}

#[tokio::test]
async fn test_fallocate_within_current_size_does_not_shrink() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("f.txt"), 0o100644, 0)
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("f.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    let fh = engine.open(req.clone(), ino, 0).await.unwrap().0;
    let data = vec![0xABu8; 4096];
    engine
        .write(req.clone(), ino, fh, 0, &data, 0, 0)
        .await
        .unwrap();
    engine
        .release(req.clone(), ino, fh, 0, 0, false)
        .await
        .unwrap();
    engine
        .fallocate(req.clone(), ino, 0, 0, 2048, 0)
        .await
        .unwrap();
    let st = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(st.size, 4096);
}

#[tokio::test]
async fn test_fallocate_nonexistent_inode() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let err = engine
        .fallocate(req.clone(), 99999, 0, 0, 4096, 0)
        .await
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
}

// -- extract_single_file --

#[tokio::test]
async fn test_extract_single_file_round_trip() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("a.txt"), 0o100644, 0)
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("a.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    let payload = b"extract me";
    let fh = engine.open(req.clone(), ino, 0).await.unwrap().0;
    engine
        .write(req.clone(), ino, fh, 0, payload, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, fh, false).await.unwrap();
    engine
        .release(req.clone(), ino, fh, 0, 0, false)
        .await
        .unwrap();
    let dest = tempfile::tempdir().unwrap();
    engine
        .extract_single_file("a.txt", dest.path().to_str().unwrap(), false)
        .await
        .unwrap();
    let contents = std::fs::read(dest.path().join("a.txt")).unwrap();
    assert_eq!(contents, payload);
}

#[tokio::test]
async fn test_extract_single_file_nested_path() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("dir"), 0o040755, 0)
        .await
        .unwrap();
    let dir_ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("dir"))
        .await
        .unwrap()
        .attr
        .ino;
    engine
        .mknod(req.clone(), dir_ino, OsStr::new("b.txt"), 0o100644, 0)
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), dir_ino, OsStr::new("b.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    let payload = b"nested extract";
    let fh = engine.open(req.clone(), ino, 0).await.unwrap().0;
    engine
        .write(req.clone(), ino, fh, 0, payload, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, fh, false).await.unwrap();
    engine
        .release(req.clone(), ino, fh, 0, 0, false)
        .await
        .unwrap();
    let dest = tempfile::tempdir().unwrap();
    engine
        .extract_single_file("dir/b.txt", dest.path().to_str().unwrap(), false)
        .await
        .unwrap();
    let contents = std::fs::read(dest.path().join("b.txt")).unwrap();
    assert_eq!(contents, payload);
}

#[tokio::test]
async fn test_extract_single_file_missing_path() {
    let (engine, _dir) = setup_engine().await;
    let dest = tempfile::tempdir().unwrap();
    let err = engine
        .extract_single_file("nope.txt", dest.path().to_str().unwrap(), false)
        .await
        .err();
    assert!(err.is_some());
    assert!(err.unwrap().to_string().contains("not found"));
}

// -- mode_to_filetype --

#[test]
fn test_mode_to_filetype_all_variants() {
    assert!(matches!(
        mode_to_filetype(libc::S_IFDIR),
        FileType::Directory
    ));
    assert!(matches!(mode_to_filetype(libc::S_IFLNK), FileType::Symlink));
    assert!(matches!(
        mode_to_filetype(libc::S_IFREG),
        FileType::RegularFile
    ));
    assert!(matches!(
        mode_to_filetype(libc::S_IFIFO),
        FileType::NamedPipe
    ));
    assert!(matches!(
        mode_to_filetype(libc::S_IFCHR),
        FileType::CharDevice
    ));
    assert!(matches!(
        mode_to_filetype(libc::S_IFBLK),
        FileType::BlockDevice
    ));
    assert!(matches!(mode_to_filetype(libc::S_IFSOCK), FileType::Socket));
}

#[test]
fn test_mode_to_filetype_unknown_defaults_to_regular() {
    assert!(matches!(mode_to_filetype(0), FileType::RegularFile));
    assert!(matches!(mode_to_filetype(0o7777), FileType::RegularFile));
}

#[test]
fn test_mode_to_filetype_ignores_permission_bits() {
    assert!(matches!(
        mode_to_filetype(libc::S_IFDIR | 0o755),
        FileType::Directory
    ));
}

// -- new_readonly / new_from_db --

#[tokio::test]
async fn test_new_readonly_engine_works() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(
            req.clone(),
            root_ino(),
            OsStr::new("test_ro.txt"),
            0o100644,
            0,
        )
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("test_ro.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    let payload = b"readonly test";
    let fh = engine.open(req.clone(), ino, 0).await.unwrap().0;
    engine
        .write(req.clone(), ino, fh, 0, payload, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, fh, false).await.unwrap();
    engine
        .release(req.clone(), ino, fh, 0, 0, false)
        .await
        .unwrap();
    let db = cairn_index::Db::new(_dir.path().join("test.db").to_str().unwrap(), None).unwrap();
    let ro = CairnEngine::new_readonly(
        db,
        engine.crypto.clone(),
        engine.cache_dir.clone(),
        vec!["jpg".to_string()],
    );
    let st = ro.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(st.size, payload.len() as u64);
}

#[tokio::test]
async fn test_new_from_db_forks_engine() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(req.clone(), root_ino(), OsStr::new("orig.txt"), 0o100644, 0)
        .await
        .unwrap();
    let db2 = cairn_index::Db::new(_dir.path().join("fork.db").to_str().unwrap(), None).unwrap();
    let forked = engine.new_from_db(db2);
    assert_eq!(forked.cache_dir, engine.cache_dir);
}

// -- gc / scrub smoke tests --

#[tokio::test]
async fn test_gc_on_empty_engine() {
    let (engine, _dir) = setup_engine().await;
    let (freed, total) = engine.gc(24).await.unwrap();
    assert_eq!(freed, 0);
    assert_eq!(total, 0);
}

#[tokio::test]
async fn test_scrub_on_empty_engine() {
    let (engine, _dir) = setup_engine().await;
    let (checked, corrupted) = engine.scrub().await.unwrap();
    assert_eq!(checked, 0);
    assert_eq!(corrupted, 0);
}

#[tokio::test]
async fn test_gc_after_write_and_delete() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(
            req.clone(),
            root_ino(),
            OsStr::new("gc_test.txt"),
            0o100644,
            0,
        )
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("gc_test.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    let fh = engine.open(req.clone(), ino, 0).await.unwrap().0;
    // Write 16KB to ensure chunks are created (above inline threshold)
    engine
        .write(req.clone(), ino, fh, 0, &vec![0xCC; 16384], 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, fh, false).await.unwrap();
    engine
        .release(req.clone(), ino, fh, 0, 0, false)
        .await
        .unwrap();
    engine
        .unlink(req.clone(), root_ino(), OsStr::new("gc_test.txt"))
        .await
        .unwrap();
    // GC with grace=0: should complete without error (may free 0+ chunks
    // depending on timing of index writes vs. orphan detection)
    let (_freed, _total) = engine.gc(0).await.unwrap();
}

#[tokio::test]
async fn test_scrub_after_write() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    engine
        .mknod(
            req.clone(),
            root_ino(),
            OsStr::new("scrub.txt"),
            0o100644,
            0,
        )
        .await
        .unwrap();
    let ino = engine
        .lookup(req.clone(), root_ino(), OsStr::new("scrub.txt"))
        .await
        .unwrap()
        .attr
        .ino;
    let fh = engine.open(req.clone(), ino, 0).await.unwrap().0;
    engine
        .write(req.clone(), ino, fh, 0, &vec![0xDD; 4096], 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, fh, false).await.unwrap();
    engine
        .release(req.clone(), ino, fh, 0, 0, false)
        .await
        .unwrap();
    // Scrub should complete without error
    let (_checked, corrupted) = engine.scrub().await.unwrap();
    assert_eq!(corrupted, 0);
}
