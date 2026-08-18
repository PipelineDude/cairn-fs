// Round-trip tests for the non-FUSE programmatic API (`cairn_core::vfs::Vfs`).
// This is the cross-platform restore/browse path (used by libraries and GUIs
// without a FUSE mount); it was previously exercised by nothing. We build an
// engine, write a small tree through it, wrap it in a Vfs, and assert the Vfs
// facade lists, reads, resolves and extracts that tree byte-for-byte.

use cairn_core::CairnEngine;
use cairn_core::types::*;
use cairn_core::vfs::{Vfs, walk_archive};
use dashmap::DashMap;
use lru::LruCache;
use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tempfile::TempDir;
use tokio::sync::Mutex;

struct Tree {
    file_ino: u64,
    sub_ino: u64,
    inner_ino: u64,
    link_ino: u64,
}

const FILE_DATA: &[u8] = b"hello world from the vfs round-trip";
const INNER_DATA: &[u8] = b"nested file contents";

async fn setup_vfs() -> (Vfs, TempDir, Tree) {
    let temp_dir = tempfile::tempdir().unwrap();

    use age::secrecy::ExposeSecret;
    let identity = age::x25519::Identity::generate();
    let pub_path = temp_dir.path().join("pub.pem");
    let priv_path = temp_dir.path().join("priv.pem");
    std::fs::write(&pub_path, identity.to_public().to_string()).unwrap();
    std::fs::write(&priv_path, identity.to_string().expose_secret()).unwrap();

    let db_path = temp_dir.path().join("test.db");
    let db = Arc::new(cairn_index::Db::new(db_path.to_str().unwrap(), None).unwrap());
    let cache_dir = temp_dir.path().join("cache").to_string_lossy().to_string();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let crypto = cairn_seal::CryptoCtx::new(
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
        no_comp_ext: vec!["jpg".to_string()],
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

    let req = Request::default();
    engine.init(req.clone()).await.unwrap();

    // /file.txt
    let file_ino = engine
        .mknod(req.clone(), 1, OsStr::new("file.txt"), 0o644, 0)
        .await
        .unwrap()
        .attr
        .ino;
    engine
        .write(req.clone(), file_ino, 0, 0, FILE_DATA, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), file_ino, 0, false).await.unwrap();

    // /sub/
    let sub_ino = engine
        .mkdir(req.clone(), 1, &std::ffi::OsString::from("sub"), 0o755, 0)
        .await
        .unwrap()
        .attr
        .ino;
    // /sub/inner.txt
    let inner_ino = engine
        .mknod(req.clone(), sub_ino, OsStr::new("inner.txt"), 0o644, 0)
        .await
        .unwrap()
        .attr
        .ino;
    engine
        .write(req.clone(), inner_ino, 0, 0, INNER_DATA, 0, 0)
        .await
        .unwrap();
    engine
        .fsync(req.clone(), inner_ino, 0, false)
        .await
        .unwrap();

    // /link -> file.txt (relative symlink)
    let link_ino = engine
        .symlink(req.clone(), 1, OsStr::new("link"), OsStr::new("file.txt"))
        .await
        .unwrap()
        .attr
        .ino;

    let vfs = Vfs::from_engine(Arc::new(engine));
    (
        vfs,
        temp_dir,
        Tree {
            file_ino,
            sub_ino,
            inner_ino,
            link_ino,
        },
    )
}

#[tokio::test]
async fn test_vfs_readdir_lists_entries() {
    let (vfs, _d, _t) = setup_vfs().await;
    let names: Vec<String> = vfs
        .readdir(1)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    for want in ["file.txt", "sub", "link"] {
        assert!(
            names.contains(&want.to_string()),
            "readdir(/) missing {want}: {names:?}"
        );
    }
}

#[tokio::test]
async fn test_vfs_getattr_present_and_absent() {
    let (vfs, _d, t) = setup_vfs().await;
    let sub = vfs
        .getattr(t.sub_ino)
        .await
        .unwrap()
        .expect("sub should exist");
    assert_eq!(sub.kind, FileType::Directory);
    let file = vfs
        .getattr(t.file_ino)
        .await
        .unwrap()
        .expect("file should exist");
    assert_eq!(file.kind, FileType::RegularFile);
    assert_eq!(file.size, FILE_DATA.len() as u64);
    assert!(
        vfs.getattr(999_999).await.unwrap().is_none(),
        "absent inode → None"
    );
}

#[tokio::test]
async fn test_vfs_read_file_byte_exact() {
    let (vfs, _d, t) = setup_vfs().await;
    assert_eq!(vfs.read_file(t.file_ino).await.unwrap(), FILE_DATA);
    assert_eq!(vfs.read_file(t.inner_ino).await.unwrap(), INNER_DATA);
}

#[tokio::test]
async fn test_vfs_readlink() {
    let (vfs, _d, t) = setup_vfs().await;
    assert_eq!(vfs.readlink(t.link_ino).await.unwrap(), b"file.txt");
}

#[tokio::test]
async fn test_vfs_resolve_path() {
    let (vfs, _d, t) = setup_vfs().await;
    assert_eq!(
        vfs.resolve_path("/file.txt").await.unwrap(),
        Some(t.file_ino)
    );
    assert_eq!(
        vfs.resolve_path("/sub/inner.txt").await.unwrap(),
        Some(t.inner_ino)
    );
    assert_eq!(vfs.resolve_path("/does/not/exist").await.unwrap(), None);
    assert_eq!(vfs.resolve_path("/").await.unwrap(), Some(1));
}

#[tokio::test]
async fn test_vfs_walk_archive() {
    let (vfs, _d, _t) = setup_vfs().await;
    let paths: Vec<String> = walk_archive(&vfs)
        .await
        .unwrap()
        .into_iter()
        .map(|(p, _)| p.to_string_lossy().to_string())
        .collect();
    for want in ["/file.txt", "/sub", "/sub/inner.txt"] {
        assert!(
            paths.iter().any(|p| p == want),
            "walk_archive missing {want}: {paths:?}"
        );
    }
}

#[tokio::test]
async fn test_vfs_extract_all_round_trip() {
    let (vfs, _d, _t) = setup_vfs().await;
    let out = tempfile::tempdir().unwrap();
    vfs.extract_all(out.path().to_str().unwrap(), false)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(out.path().join("file.txt")).unwrap(),
        FILE_DATA
    );
    assert_eq!(
        std::fs::read(out.path().join("sub/inner.txt")).unwrap(),
        INNER_DATA
    );
}

#[tokio::test]
async fn test_vfs_extract_to_single_file() {
    let (vfs, _d, t) = setup_vfs().await;
    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("restored.bin");
    vfs.extract_to(t.file_ino, &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), FILE_DATA);
}
