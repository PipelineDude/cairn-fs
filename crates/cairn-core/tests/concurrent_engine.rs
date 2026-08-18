// Concurrency tests for the intra-process race surface.
//
// The FUSE mount daemon serves many requests as concurrent tokio tasks against
// ONE engine, exercising the per-inode `write_locks`, the r2d2 connection pool,
// the decrypted-chunk cache, and the global write-buffer atomics. The black-box
// suite only covers concurrent *processes* (gated by the shared advisory flock +
// SQLite busy-timeout); this drives concurrent tasks against a single engine and
// checks the result is consistent -- the natural target to also run under
// ThreadSanitizer later.

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
    // File-backed DB (like production): a pooled `:memory:` DB is per-connection
    // and would hand out separate empty databases under concurrency.
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

/// Concurrent writes to DISTINCT inodes must all round-trip correctly. Stresses
/// the shared r2d2 pool, the decrypted-chunk cache and the global write-buffer
/// atomics under real parallelism, with no per-inode contention.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_distinct_inode_writes() {
    let (engine, _dir) = setup_engine().await;
    let engine = Arc::new(engine);
    let req = Request::default();

    const N: usize = 24;
    let mut inos = Vec::new();
    for i in 0..N {
        let name = format!("f{i}");
        let r = engine
            .mknod(req.clone(), 1, OsStr::new(&name), 0o644, 0)
            .await
            .unwrap();
        inos.push(r.attr.ino);
    }

    let mut handles = Vec::new();
    for (i, &ino) in inos.iter().enumerate() {
        let eng = engine.clone();
        // ~30 KB each -> crosses the inline threshold into real chunks.
        let data: Vec<u8> = (0..30_000u32)
            .map(|j| (j.wrapping_add(i as u32) & 0xff) as u8)
            .collect();
        handles.push(tokio::spawn(async move {
            eng.write(Request::default(), ino, 0, 0, &data, 0, 0)
                .await
                .unwrap();
            eng.fsync(Request::default(), ino, 0, false).await.unwrap();
            (ino, data)
        }));
    }

    for h in handles {
        let (ino, expected) = h.await.unwrap();
        let got = engine
            .read(Request::default(), ino, 0, 0, expected.len() as u32)
            .await
            .unwrap();
        assert_eq!(
            got, expected,
            "distinct-inode concurrent write corrupted inode {ino}"
        );
    }
}

/// Concurrent writes to the SAME inode at NON-overlapping offsets must all land:
/// the per-inode `write_lock` serialises the read-modify-write merges, so the
/// final file is the exact union of the blocks. A broken lock would drop or
/// tear a block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_inode_nonoverlapping_writes() {
    let (engine, _dir) = setup_engine().await;
    let engine = Arc::new(engine);
    let req = Request::default();

    let ino = engine
        .mknod(req.clone(), 1, OsStr::new("shared"), 0o644, 0)
        .await
        .unwrap()
        .attr
        .ino;

    const N: u64 = 16;
    const BLOCK: u64 = 8_000; // crosses inline + chunk boundaries across the file

    let mut handles = Vec::new();
    for i in 0..N {
        let eng = engine.clone();
        handles.push(tokio::spawn(async move {
            let data = vec![(i + 1) as u8; BLOCK as usize];
            eng.write(Request::default(), ino, 0, i * BLOCK, &data, 0, 0)
                .await
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();

    let total = (N * BLOCK) as usize;
    let got = engine
        .read(req.clone(), ino, 0, 0, total as u32)
        .await
        .unwrap();

    let mut expected = vec![0u8; total];
    for i in 0..N {
        let val = (i + 1) as u8;
        let start = (i * BLOCK) as usize;
        expected[start..start + BLOCK as usize].fill(val);
    }
    assert_eq!(
        got.len(),
        total,
        "concurrent same-inode writes changed the file length"
    );
    assert!(
        got == expected,
        "concurrent same-inode non-overlapping writes lost or tore a block"
    );
}
