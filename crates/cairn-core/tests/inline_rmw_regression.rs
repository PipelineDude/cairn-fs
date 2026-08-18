// Deterministic regression tests for the inline->chunked transition, found by the
// 10h soak (proptest r33) as a rare (~1/34000) silent data-corruption case.
//
// Root cause: `flush_range` fetched overlapping *chunks* but never folded existing
// `inline_data` into the read-modify-write merge, and `replace_file_chunks` (and the
// small-data inline fallbacks) clear inline. So a file first stored inline (a small
// write at offset 0) LOST its offset-0 content the moment a later non-contiguous
// write forced it to chunked storage. The read path serves inline EXCLUSIVELY of
// chunks (see `read()`), so the invariant is "inline XOR chunks" — the fix must
// preserve it.
//
// These hard-code the exact op structure so the gate cannot be silently skipped by
// proptest's persistence-path quirks (this integration test can't locate lib.rs/
// main.rs, so proptest disables regression persistence entirely).

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
    // File-backed DB (like production): `:memory:` is per-connection, so the pool
    // would hand out separate empty DBs.
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

fn apply(model: &mut Vec<u8>, off: usize, data: &[u8]) {
    let end = off + data.len();
    if model.len() < end {
        model.resize(end, 0);
    }
    model[off..end].copy_from_slice(data);
}

async fn mk(engine: &CairnEngine, req: &Request) -> u64 {
    engine
        .mknod(req.clone(), 1, OsStr::new("f"), 0o644, 0)
        .await
        .unwrap()
        .attr
        .ino
}

// The exact shrunk repro from soak proptest r33:
//   Write [1] @ 0  ->  file stored INLINE
//   Write [0] @ 2  ->  leaves a zero hole at offset 1
//   Write [8377b] @ 1 -> forces chunked storage; offset-0 byte must survive
// The bug returned result[0]=0 instead of 1. Data content is irrelevant (the
// defect is structural), so a deterministic fill is used.
#[tokio::test(flavor = "multi_thread")]
async fn inline_then_noncontiguous_write_preserves_offset0() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let ino = mk(&engine, &req).await;
    let mut model = Vec::new();

    let d0 = vec![1u8];
    let d1 = vec![0u8];
    let d2: Vec<u8> = (0..8377u32).map(|i| (i % 251) as u8).collect();

    for (off, data) in [(0u64, &d0), (2, &d1), (1, &d2)] {
        engine
            .write(req.clone(), ino, 0, off, data, 0, 0)
            .await
            .unwrap();
        apply(&mut model, off as usize, data);
    }

    let got = engine
        .read(req.clone(), ino, 0, 0, model.len() as u32)
        .await
        .unwrap();
    assert_eq!(got.len(), model.len(), "length mismatch");
    assert_eq!(
        got,
        model,
        "content mismatch: offset 0 read as {} but wrote 1 (inline lost on chunked transition)",
        got.first().copied().unwrap_or(255)
    );
}

// Sibling failure mode the offset-capped proptest cannot reach: a file stored
// inline, then a DISJOINT far write. `inline_data` must not be lost, and the read
// must zero-fill the hole between the inline region and the far chunk. Exercises
// the merge-window bound (folding inline to offset 0 across a 5 MiB gap).
#[tokio::test(flavor = "multi_thread")]
async fn inline_then_far_sparse_write_preserves_both_regions() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let ino = mk(&engine, &req).await;
    let mut model = Vec::new();

    let head = vec![7u8, 8, 9]; // small -> inline at offset 0
    let far_off = 5 * 1024 * 1024u64;
    let far: Vec<u8> = (0..40000u32).map(|i| (i % 253) as u8 + 1).collect();

    engine
        .write(req.clone(), ino, 0, 0, &head, 0, 0)
        .await
        .unwrap();
    apply(&mut model, 0, &head);
    // fsync so the head is durably stored as inline before the far write.
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    engine
        .write(req.clone(), ino, 0, far_off, &far, 0, 0)
        .await
        .unwrap();
    apply(&mut model, far_off as usize, &far);
    // fsync forces the far write to chunked storage — on the buggy code this
    // clears the inline head (data loss). Without the fsync the far write stays
    // buffered and the read overlay hides the bug.
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();

    // Read bounded regions (reading the whole 5 MiB in one call would hit the
    // per-read max_write cap).
    let head_region = engine.read(req.clone(), ino, 0, 0, 4096).await.unwrap();
    assert_eq!(
        &head_region[..3],
        &head[..],
        "inline head region lost after far write"
    );
    assert!(
        head_region[3..].iter().all(|&b| b == 0),
        "hole not zero-filled"
    );

    let far_region = engine
        .read(req.clone(), ino, 0, far_off, far.len() as u32)
        .await
        .unwrap();
    assert_eq!(far_region, far, "far region content wrong");
}

// truncate_inode clears inline_data unconditionally, so truncating an inline file
// (shrink OR extend) lost its content — read returned zeros. Found by the broadened
// proptest (Write[11]@0; Truncate 21132). These pin all three inline-truncate cases.
async fn read_whole(engine: &CairnEngine, req: &Request, ino: u64, len: usize) -> Vec<u8> {
    let mut got = Vec::with_capacity(len);
    while got.len() < len {
        let off = got.len() as u64;
        let want = ((len - got.len()).min(1024 * 1024)) as u32;
        let piece = engine.read(req.clone(), ino, 0, off, want).await.unwrap();
        if piece.is_empty() {
            break;
        }
        got.extend_from_slice(&piece);
    }
    got
}

#[tokio::test(flavor = "multi_thread")]
async fn inline_truncate_shrink_keeps_prefix() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let ino = mk(&engine, &req).await;
    let data: Vec<u8> = (0..200u32).map(|i| (i % 250 + 1) as u8).collect();
    engine
        .write(req.clone(), ino, 0, 0, &data, 0, 0)
        .await
        .unwrap();
    engine
        .setattr(
            req.clone(),
            ino,
            None,
            SetAttr {
                size: Some(40),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let got = read_whole(&engine, &req, ino, 40).await;
    assert_eq!(
        got,
        data[..40],
        "inline shrink lost/altered the kept prefix"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn inline_truncate_extend_within_threshold_zero_fills() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let ino = mk(&engine, &req).await;
    let data = vec![1u8, 2, 3, 4, 5];
    engine
        .write(req.clone(), ino, 0, 0, &data, 0, 0)
        .await
        .unwrap();
    engine
        .setattr(
            req.clone(),
            ino,
            None,
            SetAttr {
                size: Some(2000),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let got = read_whole(&engine, &req, ino, 2000).await;
    let mut want = data.clone();
    want.resize(2000, 0);
    assert_eq!(
        got, want,
        "inline extend within threshold lost content / didn't zero-fill"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn inline_truncate_extend_past_threshold_zero_fills() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let ino = mk(&engine, &req).await;
    let data = vec![9u8, 8, 7, 6, 5, 4, 3, 2, 1, 10, 11];
    engine
        .write(req.clone(), ino, 0, 0, &data, 0, 0)
        .await
        .unwrap();
    engine
        .setattr(
            req.clone(),
            ino,
            None,
            SetAttr {
                size: Some(21132),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let got = read_whole(&engine, &req, ino, 21132).await;
    let mut want = data.clone();
    want.resize(21132, 0);
    assert_eq!(
        got, want,
        "inline extend past threshold lost content / didn't zero-fill"
    );
}
