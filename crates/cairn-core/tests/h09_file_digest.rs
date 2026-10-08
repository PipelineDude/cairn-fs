// H09: whole-file digest is stored in the protected index at finalize and can
// prove a successful restore (content, ORDER and SIZE of individually-correct
// chunks).  Offline engine tests: real file-backed DB + keys, no cloud.
use std::ffi::OsStr;
use std::sync::Arc;

use age::secrecy::ExposeSecret;
use cairn_core::hashing;
use cairn_core::types::*;
use cairn_core::{BackupStats, CairnEngine};
use cairn_index::Db;
use dashmap::DashMap;
use lru::LruCache;
use std::sync::atomic::AtomicUsize;
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

async fn make_and_write(engine: &CairnEngine, name: &str, payload: &[u8]) -> u64 {
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
    entry.attr.ino
}

fn expected_digest(payload: &[u8]) -> [u8; 32] {
    let mut h = hashing::FileHasher::new();
    h.update(payload).unwrap();
    h.finish().hash
}

#[tokio::test]
async fn inline_file_digest_is_stored_and_verified() {
    let (engine, _dir) = setup_engine().await;
    let payload = b"inline small file payload".repeat(60); // ~1.5 KiB < INLINE_THRESHOLD
    let ino = make_and_write(&engine, "inline.bin", &payload).await;

    if let Err(e) = engine.verify_file_digest(ino).await {
        panic!("inline verify: {e}");
    }
    // The protected index now holds the expected digest for a later restore-check.
    let stored = engine.db.get_file_digest(ino).unwrap();
    assert_eq!(stored, Some(expected_digest(&payload)));
    // The file itself still reads correctly.
    let fh = engine.open(Request::default(), ino, 0).await.unwrap().0;
    let read = engine
        .read(Request::default(), ino, fh, 0, payload.len() as u32)
        .await
        .unwrap();
    assert_eq!(read, payload);
}

#[tokio::test]
async fn fsync_refreshes_digest_without_waiting_for_release() {
    let (engine, _dir) = setup_engine().await;
    let ino = make_and_write(&engine, "fsync.bin", b"old payload").await;
    let fh = engine.open(Request::default(), ino, 0).await.unwrap().0;
    engine
        .write(Request::default(), ino, fh, 0, b"new payload", 0, 0)
        .await
        .unwrap();
    engine
        .fsync(Request::default(), ino, fh, false)
        .await
        .unwrap();

    engine.verify_file_digest(ino).await.unwrap();
}

#[tokio::test]
async fn digest_uses_logical_length_after_truncate_inside_chunk() {
    let (engine, _dir) = setup_engine().await;
    let bytes: Vec<u8> = (0..30_000u32).map(|n| (n & 0xff) as u8).collect();
    let ino = make_and_write(&engine, "truncate.bin", &bytes).await;
    engine.db.truncate_inode(ino, 10_000).unwrap();

    let digest = engine.compute_file_digest(ino).await.unwrap();
    assert_eq!(digest.logical_size, 10_000);
    assert_eq!(digest.hash, expected_digest(&bytes[..10_000]));
}

#[tokio::test]
async fn chunked_digest_detects_duplicate_placement_on_verify() {
    let (engine, _dir) = setup_engine().await;
    let payload: Vec<u8> = (0..30_000u32).map(|j| (j & 0xff) as u8).collect();
    let ino = make_and_write(&engine, "chunk.bin", &payload).await;

    engine
        .verify_file_digest(ino)
        .await
        .expect("clean digest must verify");
    assert_eq!(
        engine.db.get_file_digest(ino).unwrap(),
        Some(expected_digest(&payload))
    );

    // Inject a duplicate/overlapping placement: a SECOND chunk reference whose
    // offset falls inside an already-covered span (as a corrupt mapping would).
    let (oid, _off, _len, _wrapped, _ct, _alg) = engine
        .db
        .get_file_chunks(ino)
        .unwrap()
        .first()
        .unwrap()
        .clone();
    engine
        .db
        .insert_file_chunk(ino, 15_000, &oid, 100, 0)
        .unwrap();

    let err = engine.verify_file_digest(ino).await.unwrap_err();
    assert!(
        err.to_string().contains("overlaps") || err.to_string().contains("duplicates"),
        "duplicate placement must be caught, got: {err}"
    );
}

#[tokio::test]
async fn tampered_stored_digest_is_detected() {
    let (engine, _dir) = setup_engine().await;
    let payload: Vec<u8> = (0..30_000u32)
        .map(|j| (j.wrapping_mul(7) & 0xff) as u8)
        .collect();
    let ino = make_and_write(&engine, "tamper.bin", &payload).await;

    let wrong = [0xEEu8; 32];
    engine.db.set_file_digest(ino, &wrong).unwrap();

    let err = engine.verify_file_digest(ino).await.unwrap_err();
    assert!(err.to_string().contains("digest mismatch"), "got: {err}");
    assert!(
        !err.to_string().contains("eeee"),
        "digest must not leak: {err}"
    );
}

#[tokio::test]
async fn chunked_digest_includes_trailing_sparse_hole() {
    let (engine, _dir) = setup_engine().await;
    let payload = vec![0xA5; 30_000];
    let ino = make_and_write(&engine, "sparse.bin", &payload).await;
    let attr = SetAttr {
        size: Some(60_000),
        ..SetAttr::default()
    };
    engine
        .setattr(Request::default(), ino, None, attr)
        .await
        .unwrap();
    engine.store_file_digest(ino).await.unwrap();
    engine.verify_file_digest(ino).await.unwrap();

    let mut expected = hashing::FileHasher::new();
    expected.update(&payload).unwrap();
    expected.update_zeros(30_000).unwrap();
    assert_eq!(
        engine.db.get_file_digest(ino).unwrap(),
        Some(expected.finish().hash)
    );
}

#[tokio::test]
async fn verify_all_reports_healthy_tree_and_detects_one_tampered_file() {
    let (engine, _dir) = setup_engine().await;
    let a: Vec<u8> = (0..30_000u32).map(|j| (j & 0xff) as u8).collect();
    let b = b"second inline file".repeat(20);
    let ino_a = make_and_write(&engine, "a.bin", &a).await;
    make_and_write(&engine, "b.txt", &b).await;

    let report = engine.verify_all_file_digests().await.unwrap();
    assert_eq!(report.verified, 2, "healthy tree must verify: {report:?}");
    assert_eq!(report.missing_digest, 0);
    assert!(
        report.failed.is_empty(),
        "unexpected failures: {:?}",
        report.failed
    );

    // Tamper one file's stored digest -> the whole-tree check must report it.
    engine.db.set_file_digest(ino_a, &[0xEEu8; 32]).unwrap();
    let report = engine.verify_all_file_digests().await.unwrap();
    assert_eq!(report.verified, 1);
    assert!(
        report
            .failed
            .iter()
            .any(|(ino, msg)| *ino == ino_a && msg.contains("digest mismatch"))
    );
}

// ----------------------------------------------------------------------
// BF-04.1 (audit 2026-09-17): every size/content mutation must refresh the
// stored digest, not only release/fsync.  Before this, `tree_root()` and
// `verify_file_digest()` kept binding bytes the file no longer had.
// ----------------------------------------------------------------------

#[tokio::test]
async fn setattr_truncate_refreshes_the_stored_digest() {
    let (engine, _dir) = setup_engine().await;
    let bytes: Vec<u8> = (0..30_000u32).map(|n| (n & 0xff) as u8).collect();
    let ino = make_and_write(&engine, "setattr-trunc.bin", &bytes).await;

    let attr = SetAttr {
        size: Some(10_000),
        ..SetAttr::default()
    };
    engine
        .setattr(Request::default(), ino, None, attr)
        .await
        .unwrap();

    // No manual store_file_digest: setattr itself must have refreshed it.
    assert_eq!(
        engine.db.get_file_digest(ino).unwrap(),
        Some(expected_digest(&bytes[..10_000]))
    );
    engine.verify_file_digest(ino).await.unwrap();
}

#[tokio::test]
async fn open_with_o_trunc_refreshes_the_stored_digest() {
    let (engine, _dir) = setup_engine().await;
    let ino = make_and_write(&engine, "otrunc.bin", b"payload before truncation").await;

    engine
        .open(Request::default(), ino, libc::O_TRUNC as u32)
        .await
        .unwrap();

    assert_eq!(
        engine.db.get_file_digest(ino).unwrap(),
        Some(expected_digest(b"")),
        "O_TRUNC must store the digest of the now-empty file"
    );
    engine.verify_file_digest(ino).await.unwrap();
}

#[tokio::test]
async fn fallocate_grow_refreshes_the_stored_digest() {
    let (engine, _dir) = setup_engine().await;
    let bytes: Vec<u8> = (0..30_000u32).map(|n| (n & 0xff) as u8).collect();
    let ino = make_and_write(&engine, "grow.bin", &bytes).await;

    engine
        .fallocate(Request::default(), ino, 0, 0, 45_000, 0)
        .await
        .unwrap();

    let mut expected = hashing::FileHasher::new();
    expected.update(&bytes).unwrap();
    expected.update_zeros(15_000).unwrap();
    assert_eq!(
        engine.db.get_file_digest(ino).unwrap(),
        Some(expected.finish().hash)
    );
    engine.verify_file_digest(ino).await.unwrap();
}

#[tokio::test]
async fn fallocate_punch_hole_refreshes_the_stored_digest() {
    // Punch a WHOLE middle chunk of a multi-chunk file (600 KiB -> three
    // chunker windows) so the tested path is the digest refresh, not the
    // known partial-chunk limitation tracked as BF-04.11.
    let (engine, _dir) = setup_engine().await;
    let bytes: Vec<u8> = (0..600_000u32).map(|n| (n & 0xff) as u8).collect();
    let ino = make_and_write(&engine, "punch.bin", &bytes).await;

    let mut chunks = engine.db.get_file_chunks(ino).unwrap();
    chunks.sort_by_key(|(_, off, _, _, _, _)| *off);
    assert!(
        chunks.len() >= 3,
        "test needs a multi-chunk file: {chunks:?}"
    );
    let (_, mid_off, mid_len, _, _, _) = chunks[1].clone();

    const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
    const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
    engine
        .fallocate(
            Request::default(),
            ino,
            0,
            mid_off as u64,
            mid_len as u64,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
        )
        .await
        .unwrap();

    let mut expected = hashing::FileHasher::new();
    expected.update(&bytes[..mid_off]).unwrap();
    expected.update_zeros(mid_len as u64).unwrap();
    expected.update(&bytes[mid_off + mid_len..]).unwrap();
    assert_eq!(
        engine.db.get_file_digest(ino).unwrap(),
        Some(expected.finish().hash)
    );
    engine.verify_file_digest(ino).await.unwrap();
}

// BF-04.11: a PUNCH_HOLE range that starts inside a chunk must zero ONLY the
// intersection and preserve the bytes beyond the range (the old drop/shorten
// path erased the chunk tail).
#[tokio::test]
async fn punch_inside_a_chunk_preserves_the_tail_beyond_it() {
    let (engine, _dir) = setup_engine().await;
    let bytes = vec![0xABu8; 30_000];
    let ino = make_and_write(&engine, "punch-tail.bin", &bytes).await;

    const KEEP: u32 = 0x01;
    const PUNCH: u32 = 0x02;
    engine
        .fallocate(Request::default(), ino, 0, 1_000, 1_000, PUNCH | KEEP)
        .await
        .unwrap();

    let fh = engine.open(Request::default(), ino, 0).await.unwrap().0;
    let tail = engine
        .read(Request::default(), ino, fh, 2_000, 1_000)
        .await
        .unwrap();
    assert_eq!(
        tail,
        vec![0xABu8; 1_000],
        "tail beyond the punched range must survive"
    );
}

// BF-04.7: concurrent writers and size mutations must leave a state whose
// stored digest verifies (the flush + mutation now share one per-inode lock).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_write_and_truncate_leave_a_verifiable_state() {
    let (engine, _dir) = setup_engine().await;
    let engine = std::sync::Arc::new(engine);
    let ino = make_and_write(&engine, "race.bin", b"initial").await;

    for round in 0..25u32 {
        let e1 = engine.clone();
        let writer = tokio::spawn(async move {
            let fh = e1.open(Request::default(), ino, 0).await.unwrap().0;
            let payload = vec![round as u8; 8_000];
            e1.write(Request::default(), ino, fh, 0, &payload, 0, 0)
                .await
                .unwrap();
            e1.release(Request::default(), ino, fh, 0, 0, true)
                .await
                .unwrap();
        });
        let e2 = engine.clone();
        let trunc = tokio::spawn(async move {
            let attr = SetAttr {
                size: Some(u64::from(round % 3) * 4_000),
                ..SetAttr::default()
            };
            e2.setattr(Request::default(), ino, None, attr)
                .await
                .unwrap();
        });
        writer.await.unwrap();
        trunc.await.unwrap();

        // Both operations have completed and the lock is free: whatever state
        // they converged on must be digest-verifiable.
        engine
            .verify_file_digest(ino)
            .await
            .unwrap_or_else(|e| panic!("round {round}: {e}"));
    }
}

// BF-04.11: a punch spanning a chunk boundary must zero exactly the requested
// range and keep both sides intact (prefix of the first row, tail of the last).
#[tokio::test]
async fn punch_across_chunk_boundaries_preserves_both_sides() {
    let (engine, _dir) = setup_engine().await;
    let bytes: Vec<u8> = (0..600_000u32).map(|n| (n & 0xff) as u8).collect();
    let ino = make_and_write(&engine, "punch-boundary.bin", &bytes).await;

    let mut chunks = engine.db.get_file_chunks(ino).unwrap();
    chunks.sort_by_key(|(_, off, _, _, _, _)| *off);
    assert!(
        chunks.len() >= 2,
        "test needs a multi-chunk file: {chunks:?}"
    );
    let (_, o0, l0, _, _, _) = chunks[0].clone();
    let (_, o1, _l1, _, _, _) = chunks[1].clone();

    // Start near the end of chunk 0, end 1000 bytes into chunk 1.
    let punch_start = (o0 + l0 - 1_000) as u64;
    let punch_end = (o1 + 1_000) as u64;
    const KEEP: u32 = 0x01;
    const PUNCH: u32 = 0x02;
    engine
        .fallocate(
            Request::default(),
            ino,
            0,
            punch_start,
            punch_end - punch_start,
            PUNCH | KEEP,
        )
        .await
        .unwrap();

    let fh = engine.open(Request::default(), ino, 0).await.unwrap().0;
    let before = engine
        .read(Request::default(), ino, fh, punch_start - 500, 500)
        .await
        .unwrap();
    assert_eq!(
        before,
        bytes[(punch_start - 500) as usize..punch_start as usize]
    );
    let inside = engine
        .read(Request::default(), ino, fh, punch_start, 500)
        .await
        .unwrap();
    assert_eq!(inside, vec![0u8; 500], "punched bytes must read as zeros");
    let after = engine
        .read(Request::default(), ino, fh, punch_end, 500)
        .await
        .unwrap();
    assert_eq!(after, bytes[punch_end as usize..punch_end as usize + 500]);

    let mut expected = hashing::FileHasher::new();
    expected.update(&bytes[..punch_start as usize]).unwrap();
    expected.update_zeros(punch_end - punch_start).unwrap();
    expected.update(&bytes[punch_end as usize..]).unwrap();
    assert_eq!(
        engine.db.get_file_digest(ino).unwrap(),
        Some(expected.finish().hash)
    );
    engine.verify_file_digest(ino).await.unwrap();
}
