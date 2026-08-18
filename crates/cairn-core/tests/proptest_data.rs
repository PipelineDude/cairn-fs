// Property-based tests for the data path (write / truncate / read).
//
// The dominant historical bug class in this codebase is SILENT data corruption on
// specific write/overwrite/truncate patterns (interior pwrite, large->small
// overwrite leaving a stale tail, truncate-extend not zero-filling, multi-chunk
// stitching, read-after-write coherence). Hand-written tests only cover the
// patterns someone thought of; these generate the ones nobody did.
//
// Model: an in-memory `Vec<u8>` is the ground truth for the file's logical
// content. After EVERY operation we read the whole file back through the engine
// (which overlays the pending write buffer, so this also checks read-after-write
// coherence WITHOUT an explicit fsync) and assert it equals the model.

use cairn_core::CairnEngine;
use cairn_core::types::*;
use dashmap::DashMap;
use lru::LruCache;
use proptest::prelude::*;
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
    // Use a FILE-backed DB (like production), not `:memory:`. An in-memory SQLite
    // database is per-connection, so the multi-connection r2d2 pool would hand out
    // separate empty databases — sound only for the 1-2 queries the other test
    // files run, but this proptest does many ops and would intermittently hit a
    // fresh connection (mknod EIO). A file DB makes all pool connections consistent.
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

#[derive(Debug, Clone)]
enum Op {
    // Write `data` at `offset` (may extend the file, leaving a zero gap).
    Write { offset: u64, data: Vec<u8> },
    // Truncate to `size` (shrink drops the tail; grow zero-fills).
    Truncate { size: u64 },
    // Flush pending writes to the chunk store.
    Fsync,
}

// Offsets: weighted toward small (dense interior-overwrite / hole patterns near
// the inline threshold, where the historical corruption lives) but regularly
// reaching multi-MB so far/disjoint sparse writes, big holes, fold-across-a-gap,
// and crossing many CDC chunk boundaries (min 16 KiB, avg 64 KiB, max 256 KiB)
// are all exercised — the ranges the old 0..40_000 cap could never reach.
fn offset_strategy() -> impl Strategy<Value = u64> {
    prop_oneof![
        6 => 0u64..64,          // tiny: interior overwrites of an inline file
        6 => 0u64..40_000,      // inline threshold (4096) + first chunks
        3 => 0u64..300_000,     // several chunks
        2 => 0u64..2_000_000,   // far/sparse: fold-across-gap, large holes
    ]
}

// Write lengths: mostly small (stay inline / sub-chunk), but regularly large
// enough to cross the inline threshold (4096), the CDC min (16384), the avg
// (65536) and produce many chunks — so inline<->chunked transitions and
// multi-chunk stitching are hit.
fn size_strategy() -> impl Strategy<Value = usize> {
    prop_oneof![
        6 => 1usize..64,
        5 => 1usize..12_000,
        3 => 1usize..80_000,
        1 => 1usize..256_000,
    ]
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (offset_strategy(), size_strategy()).prop_flat_map(|(offset, n)| {
            prop::collection::vec(any::<u8>(), n..=n)
                .prop_map(move |data| Op::Write { offset, data })
        }),
        2 => offset_strategy().prop_map(|size| Op::Truncate { size }),
        2 => Just(Op::Fsync), // bumped: force flushes at varied points
    ]
}

fn read_size(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

proptest! {
    // 128 random sequences per run (a few different every CI run — proptest seeds
    // randomly), each up to 18 ops. Hammer harder locally with `PROPTEST_CASES=500`.
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A random sequence of writes/truncates/fsyncs must leave the file's logical
    /// content byte-identical to an in-memory model — checked after EVERY op.
    #[test]
    fn write_truncate_read_matches_reference(ops in prop::collection::vec(op_strategy(), 1..18)) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let outcome: Result<(), TestCaseError> = rt.block_on(async {
            let (engine, _dir) = setup_engine().await;
            let req = Request::default();
            let ino = engine
                .mknod(req.clone(), 1, OsStr::new("f"), 0o644, 0)
                .await
                .map_err(|e| TestCaseError::fail(format!("mknod: {e}")))?
                .attr
                .ino;

            let mut model: Vec<u8> = Vec::new();

            for (i, op) in ops.iter().enumerate() {
                match op {
                    Op::Write { offset, data } => {
                        engine
                            .write(req.clone(), ino, 0, *offset, data, 0, 0)
                            .await
                            .map_err(|e| TestCaseError::fail(format!("write op#{i}: {e}")))?;
                        let off = *offset as usize;
                        let end = off + data.len();
                        if model.len() < end {
                            model.resize(end, 0);
                        }
                        model[off..end].copy_from_slice(data);
                    }
                    Op::Truncate { size } => {
                        engine
                            .setattr(
                                req.clone(),
                                ino,
                                None,
                                SetAttr { size: Some(*size), ..Default::default() },
                            )
                            .await
                            .map_err(|e| TestCaseError::fail(format!("truncate op#{i}: {e}")))?;
                        model.resize(*size as usize, 0);
                    }
                    Op::Fsync => {
                        engine
                            .fsync(req.clone(), ino, 0, false)
                            .await
                            .map_err(|e| TestCaseError::fail(format!("fsync op#{i}: {e}")))?;
                    }
                }

                // Read the whole logical file back and compare with the model.
                // read() serves at most max_write (1 MiB) per call, so stitch the
                // file together in <= max_write pieces — files now reach multiple MB.
                let mut got: Vec<u8> = Vec::with_capacity(model.len());
                while got.len() < model.len() {
                    let off = got.len() as u64;
                    let want = read_size(model.len() - got.len()).min(1024 * 1024);
                    let piece = engine
                        .read(req.clone(), ino, 0, off, want)
                        .await
                        .map_err(|e| TestCaseError::fail(format!("read after op#{i}: {e}")))?;
                    if piece.is_empty() {
                        // Short read before EOF — record it; the length assert below
                        // then fails loudly rather than looping forever.
                        break;
                    }
                    got.extend_from_slice(&piece);
                }
                prop_assert_eq!(
                    got.len(),
                    model.len(),
                    "length mismatch after op#{} {:?}",
                    i,
                    op
                );
                prop_assert!(
                    got == model,
                    "content mismatch after op#{} {:?} (len {})",
                    i,
                    op,
                    model.len()
                );
            }

            // after the sequence, flush and cross-check the OTHER read
            // paths — read_file_all and extract-to-file must produce the same
            // logical [0, size) content as FUSE read() and the model, including
            // zero-filled middle/tail holes from sparse writes and truncate-extend.
            // (Historically each path re-implemented assembly with different
            // assumptions: row-order concatenation, short tail, false verify fails.)
            engine
                .fsync(req.clone(), ino, 0, false)
                .await
                .map_err(|e| TestCaseError::fail(format!("final fsync: {e}")))?;
            let all = engine
                .read_file_all(ino)
                .await
                .map_err(|e| TestCaseError::fail(format!("read_file_all: {e}")))?
                .ok_or_else(|| TestCaseError::fail("read_file_all: inode vanished".to_string()))?;
            prop_assert!(
                all == model,
                "read_file_all mismatch: len {} vs model {}",
                all.len(),
                model.len()
            );
            let out = _dir.path().join("extract.bin");
            engine
                .extract_file_to(ino, &out)
                .await
                .map_err(|e| TestCaseError::fail(format!("extract_file_to: {e}")))?;
            let extracted = std::fs::read(&out)
                .map_err(|e| TestCaseError::fail(format!("read extracted file: {e}")))?;
            prop_assert!(
                extracted == model,
                "extract_file_to mismatch: len {} vs model {}",
                extracted.len(),
                model.len()
            );
            Ok(())
        });
        outcome?;
    }
}

/// Deterministic regression: middle holes and truncate-extend tails must be
/// identical zeros through every read path, and `verify` must not flag them.
/// (Before the fix: read_file_all concatenated chunks in row order and dropped
/// holes; extract left a SHORT file on a tail hole; verify_one bailed
/// "missing data" on a legitimate zero tail.) Hardcoded, not generated, so it
/// cannot be missed by an unlucky proptest seed.
#[test]
fn holes_read_identically_across_all_paths() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (engine, dir) = setup_engine().await;
        let req = Request::default();

        // Case 1: middle hole — single write far from offset 0.
        // Case 2: tail hole — write, then truncate-extend well past the data.
        // Case 3: inline tail hole — small (inline) write, truncate-extend.
        let cases: &[(&str, u64, usize, Option<u64>)] = &[
            ("middle_hole", 100_000, 30_000, None),
            ("tail_hole", 0, 20_000, Some(200_000)),
            ("inline_tail", 0, 64, Some(3_000)),
        ];
        for (name, write_off, write_len, extend_to) in cases {
            let ino = engine
                .mknod(req.clone(), 1, OsStr::new(name), libc::S_IFREG | 0o644, 0)
                .await
                .unwrap()
                .attr
                .ino;
            let data = vec![0xABu8; *write_len];
            engine
                .write(req.clone(), ino, 0, *write_off, &data, 0, 0)
                .await
                .unwrap();
            let mut model = vec![0u8; *write_off as usize + *write_len];
            model[*write_off as usize..].copy_from_slice(&data);
            if let Some(sz) = extend_to {
                engine
                    .setattr(
                        req.clone(),
                        ino,
                        None,
                        SetAttr {
                            size: Some(*sz),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
                model.resize(*sz as usize, 0);
            }
            engine.fsync(req.clone(), ino, 0, false).await.unwrap();

            // FUSE read()
            let mut got = Vec::with_capacity(model.len());
            while got.len() < model.len() {
                let piece = engine
                    .read(
                        req.clone(),
                        ino,
                        0,
                        got.len() as u64,
                        read_size(model.len() - got.len()).min(1024 * 1024),
                    )
                    .await
                    .unwrap();
                assert!(!piece.is_empty(), "{name}: short read at {}", got.len());
                got.extend_from_slice(&piece);
            }
            assert!(got == model, "{name}: FUSE read mismatch");

            // read_file_all
            let all = engine.read_file_all(ino).await.unwrap().unwrap();
            assert!(
                all == model,
                "{name}: read_file_all mismatch (len {} vs {})",
                all.len(),
                model.len()
            );

            // extract_file_to
            let out = dir.path().join(format!("{name}.out"));
            engine.extract_file_to(ino, &out).await.unwrap();
            let extracted = std::fs::read(&out).unwrap();
            assert!(
                extracted == model,
                "{name}: extract mismatch (len {} vs {})",
                extracted.len(),
                model.len()
            );
        }

        // verify must accept all three holed files (0 unrestorable).
        let (ok, bad) = engine.verify_all().await.unwrap();
        assert_eq!(bad, 0, "verify flagged a legitimate holed file");
        assert_eq!(ok, 3);
    });
}
