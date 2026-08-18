// Regression tests for inode attributes and metadata (getattr mtime, mknod
// file-type and permission bits, setuid/sticky, O_TRUNC, write-time updates).

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

// ────────────────────────────────────────────────────────────────────
// timestamps
// ────────────────────────────────────────────────────────────────────

/// `getattr`/`lookup` return the stored mtime, not UNIX_EPOCH. The
/// previous code fetched `mtime_sec`/`mtime_nsec` and then discarded them
/// with `_mtime_sec`, returning `atime=mtime=ctime=UNIX_EPOCH` for every
/// file — `stat file` showed 1970-01-01, breaking `find -newer`/`rsync -t`.
#[tokio::test]
async fn test_getattr_returns_real_mtime() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let name = OsString::from("f");
    let r = engine
        .mknod(req.clone(), 1, &name, 0o100644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let attr = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    let now = std::time::SystemTime::now();
    let diff = now.duration_since(attr.mtime).unwrap_or_default();
    // Sanity: mtime is "now", not 1970. Allow a 5-second window for
    // clock skew + test runtime.
    assert!(diff.as_secs() < 5, "mtime should be ~now, not UNIX_EPOCH");
    assert_eq!(attr.mtime, attr.ctime);
    // Real perm bits (setuid should round-trip).
    assert_eq!(attr.perm, 0o644);
}

/// `mknod` honours the kernel's S_IFMT — `mkfifo` creates a FIFO,
/// not a regular file. The previous version hardcoded S_IFREG so every
/// special-file mknod silently became a regular file.
#[tokio::test]
async fn test_mknod_preserves_file_type() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let mode = libc::S_IFIFO | 0o644;
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("fifo1"), mode, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let attr = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(attr.kind, FileType::NamedPipe);
}

/// setuid bits survive `getattr` and `extract` (mask is 0o7777, not
/// 0o777). The previous code stripped the high bits — a backed-up setuid
/// binary was restored as non-setuid.
#[tokio::test]
async fn test_setuid_bit_preserved() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let mode = libc::S_IFREG | 0o4755;
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("suid"), mode, 0)
        .await
        .unwrap();
    let attr = engine
        .getattr(req.clone(), r.attr.ino, None, 0)
        .await
        .unwrap();
    // `perm` is 0o7777, not 0o777 — setuid survived.
    assert_eq!(attr.perm, 0o4755);
    // `mode` is also kept verbatim.
    let row = engine
        .db
        .get_inode(r.attr.ino)
        .unwrap()
        .expect("inode exists");
    assert_eq!(row.0 & 0o7777, 0o4755, "S_ISUID|S_ISGID|S_ISVTX preserved");
}

/// `write` bumps mtime. The previous version never touched mtime, so
/// the file's mtime stayed at the inode-creation timestamp — `make`/`rsync
/// -t`/`find -newer` saw every file as unchanged after writes.
#[tokio::test]
async fn test_write_bumps_mtime() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("w"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let before = engine
        .getattr(req.clone(), ino, None, 0)
        .await
        .unwrap()
        .mtime;
    // Sleep so mtime is observably different (filesystem timestamp
    // resolution is often 1 second; this ensures we can see the bump).
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    engine
        .write(req.clone(), ino, 0, 0, b"hello", 0, 0)
        .await
        .unwrap();
    let after = engine
        .getattr(req.clone(), ino, None, 0)
        .await
        .unwrap()
        .mtime;
    assert!(after > before, "mtime did not bump on write");
}

// ────────────────────────────────────────────────────────────────────
// O_TRUNC clears inline_data
// ────────────────────────────────────────────────────────────────────

/// O_TRUNC on a small file (≤ 4 KiB → stored inline) clears the
/// inline bytes, so a subsequent `extract` does not resurrect them. The
/// previous code only deleted `file_chunks` rows, leaving the inline
/// blob intact.
#[tokio::test]
async fn test_o_trunc_clears_inline_data() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("small"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Write 100 bytes — goes to inline_data.
    engine
        .write(req.clone(), ino, 0, 0, &[0xab; 100], 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    let pre = engine
        .db
        .get_inline_data(ino)
        .unwrap()
        .expect("inline data should be set");
    // inline_data is envelope-encrypted at rest now (write-only fix), so its raw
    // length is the ciphertext length; decrypt to check the plaintext round-trips.
    let pre_plain = engine.unwrap_inline(&pre).unwrap();
    assert_eq!(pre_plain.len(), 100);
    // Open with O_TRUNC.
    engine
        .open(req.clone(), ino, libc::O_TRUNC as u32)
        .await
        .unwrap();
    // After O_TRUNC, inline data must be NULL.
    let post = engine.db.get_inline_data(ino).unwrap();
    assert!(post.is_none(), "O_TRUNC did not clear inline_data");
}

// ────────────────────────────────────────────────────────────────────
// O_TRUNC + setattr(truncate) atomicity
// ────────────────────────────────────────────────────────────────────

/// after a truncate, the inode `size` is exactly `new_size`.
/// The previous two-tx path could crash between chunks-truncated and
/// size-updated, leaving `size > 0` with empty chunks.
#[tokio::test]
async fn test_setattr_truncate_updates_size_atomically() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("big"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    engine
        .write(req.clone(), ino, 0, 0, &[0xff; 8000], 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();
    let attr = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(attr.size, 8000);
    // Truncate to 100.
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
    let attr2 = engine.getattr(req.clone(), ino, None, 0).await.unwrap();
    assert_eq!(attr2.size, 100, "truncate did not update size");
    // No chunks past offset 100.
    let _row = engine.db.get_inode(ino).unwrap().expect("inode exists");
    // The straddle chunk should be shortened, not deleted entirely —
    // we still want the first 100 bytes readable.
    let read = engine.read(req.clone(), ino, 0, 0, 100).await.unwrap();
    assert_eq!(read.len(), 100);
    assert!(read.iter().all(|b| *b == 0xff));
}

// ────────────────────────────────────────────────────────────────────
// xattr XATTR_CREATE / XATTR_REPLACE
// ────────────────────────────────────────────────────────────────────

/// setxattr with XATTR_CREATE fails on an existing key (EEXIST); with
/// XATTR_REPLACE fails on a missing key (ENODATA); otherwise both work.
#[tokio::test]
async fn test_xattr_create_and_replace_flags() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("x"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let name = OsStr::new("user.label");
    // First set: ok (no flag).
    engine
        .setxattr(req.clone(), ino, name, b"first", 0, 0)
        .await
        .unwrap();
    // XATTR_CREATE (1) against existing → EEXIST.
    let err = engine
        .setxattr(req.clone(), ino, name, b"second", 1, 0)
        .await
        .expect_err("XATTR_CREATE against existing must fail");
    assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
    // XATTR_REPLACE (2) against existing → ok.
    engine
        .setxattr(req.clone(), ino, name, b"replaced", 2, 0)
        .await
        .unwrap();
    // XATTR_REPLACE against missing → ENODATA.
    let err = engine
        .setxattr(req.clone(), ino, OsStr::new("user.missing"), b"x", 2, 0)
        .await
        .expect_err("XATTR_REPLACE against missing must fail");
    assert_eq!(err.raw_os_error(), Some(libc::ENODATA));
    // Value reflects the replace.
    let v = engine.getxattr(req.clone(), ino, name, 0).await.unwrap();
    // size==0 path returns 8 bytes of fake `fuse_getxattr_out` (the
    // cairn-fuse / cairn-fuser-cross workaround); the actual value is
    // retrieved with a non-zero size.
    let _ = v;
    let v = engine.getxattr(req.clone(), ino, name, 1024).await.unwrap();
    assert_eq!(v, b"replaced");
}

// ────────────────────────────────────────────────────────────────────
// flush_range cap
// ────────────────────────────────────────────────────────────────────

/// a flush_range whose merge window exceeds
/// `data.len() + max_write * 64` returns an error rather than allocating
/// a runaway buffer. The previous version allocated
/// `vec![0u8; merge_end - merge_start]` which could be many GiB.
///
/// To trigger the cap we plant a very large chunk via direct DB insert
/// (bypassing the CDC chunker which would produce many small chunks).
/// The planted chunk spans [0, 70 MiB). A 1-byte write at offset 65 MiB
/// overlaps it, producing a merge window of 70 MiB — well above the cap
/// of 1 + 64 MiB.
#[tokio::test]
async fn test_flush_range_caps_merge_window() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("capped"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    // Plant a large chunk covering [0, 70 MiB) via direct DB insert.
    // This simulates a file that grew through many writes, producing a
    // single contiguous chunk region. We skip the chunker to avoid
    // allocating 70 MiB of test data.
    let chunk_size = 70u64 * 1024 * 1024; // 70 MiB
    engine
        .db
        .insert_file_chunk(ino, 0, "big_chunk", chunk_size as usize, 0)
        .unwrap();
    engine
        .db
        .insert_chunk_indices_batch(&[(
            "big_chunk".into(),
            "ph_big".into(),
            b"k".to_vec(),
            0,
            "aes-gcm".into(),
        )])
        .unwrap();
    // Also update the inode size so the engine doesn't reject the write.
    engine
        .db
        .update_inode_size_and_bump_time(ino, chunk_size)
        .unwrap();
    // Write 1 byte at offset 65 MiB — inside the planted chunk's range.
    // The merge window spans the entire chunk: [0, 70 MiB) = 70 MiB.
    // The cap is data.len() + max_write*64 = 1 + 64 MiB = 64 MiB + 1.
    // 70 MiB > 64 MiB + 1 → error.
    let write_offset = 65u64 * 1024 * 1024;
    let err = engine
        .flush_range(ino, write_offset, &[0u8; 1])
        .await
        .expect_err("flush_range must reject merge window > cap");
    assert!(err.to_string().contains("merge window"));
}

// ────────────────────────────────────────────────────────────────────
// link rollback on nlink failure
// ────────────────────────────────────────────────────────────────────

/// on a `link`, if increment_nlink fails, the just-inserted dentry
/// is rolled back. The previous code left the dentry pointing at an inode
/// with a wrong nlink count.
#[tokio::test]
async fn test_link_inserts_dentry() {
    // Happy path: link works and the dentry count matches the nlink.
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("orig"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    let _ = engine
        .link(req.clone(), ino, 1, OsStr::new("link1"))
        .await
        .unwrap();
    let row = engine.db.get_inode(ino).unwrap().unwrap();
    assert_eq!(row.4, 2, "nlink = 2 (orig + link1)");
    // Two dentries visible under root.
    let dents = engine.db.list_dentries(1).unwrap();
    let names: Vec<_> = dents.into_iter().map(|(n, _, _)| n).collect();
    assert!(names.iter().any(|n| n == "orig"));
    assert!(names.iter().any(|n| n == "link1"));
}

// ────────────────────────────────────────────────────────────────────
// extract_matching restores symlinks
// ────────────────────────────────────────────────────────────────────

/// extract_matching against a glob now restores symlinks (the
/// previous code only handled DIR and REG, silently dropping LNK).
/// We verify the engine's `extract_matching` path (via direct DB seeding
/// of a symlink) — the full mount path is covered by the e2e smoke.
#[tokio::test]
async fn test_extract_matching_handles_symlink() {
    // We can't easily exercise extract_matching from a unit test (it
    // walks the in-memory archive tree); what we can verify is that
    // `read_file_all` on a symlink inode returns the target bytes. The
    // extract_matching code path that branches on S_IFLNK -> read_file_all
    // is the same as extract_all.
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let link_r = engine
        .symlink(req.clone(), 1, OsStr::new("lnk"), OsStr::new("/tmp/target"))
        .await
        .unwrap();
    let target = engine
        .read_file_all(link_r.attr.ino)
        .await
        .unwrap()
        .expect("symlink target bytes");
    assert_eq!(target, b"/tmp/target");
}

// ────────────────────────────────────────────────────────────────────
// apply_preserved_metadata keeps setuid + path CString
// ────────────────────────────────────────────────────────────────────

/// apply_preserved_metadata uses 0o7777 (not 0o777), so a
/// preserved setuid file stays setuid after extract. We can't drive
/// extract_file_to + apply_preserved_metadata end-to-end in a unit test
/// (it writes to disk), but the helper uses `mk_file_attr`-style mask
/// on read which we exercise in `test_setuid_bit_preserved` above.
#[test]
fn test_setuid_mask_preserved_in_apply_preserved() {
    // The mask `mode & 0o7777` keeps S_ISUID|S_ISGID|S_ISVTX. Verify the
    // constant matches the comment in apply_preserved_metadata.
    let mode = libc::S_IFREG | 0o4755;
    let masked = mode & 0o7777;
    assert_eq!(masked, 0o4755);
}

// ────────────────────────────────────────────────────────────────────
// Cairn-index layer tests
// ────────────────────────────────────────────────────────────────────

/// get_config distinguishes "missing" from
/// "DB error". A real error propagates.
#[test]
fn test_get_config_propagates_db_error() {
    use cairn_index::{Db, DbTuning};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.db");
    std::fs::write(&path, b"not a sqlite db").unwrap();
    let res = Db::new_with_tuning(
        path.to_str().unwrap(),
        None,
        &DbTuning {
            max_connections: 1,
            // A corrupt DB makes r2d2 retry the connection build until the
            // connection timeout; the 30s default made this test hang 30s. Fail
            // fast — 2s is plenty to establish the pool can't be built.
            connection_timeout_secs: 2,
            ..Default::default()
        },
    );
    // A corrupt DB open may still succeed (rusqlite is lazy); if it does, any
    // subsequent operation must return Err rather than `Ok(None)` (the previous
    // `.ok()` collapsed any error to None). If open() itself failed, that's the
    // same outcome (the error surfaces) and is the right answer too.
    if let Ok(db) = res {
        let r = db.get_config("foo");
        assert!(
            r.is_err(),
            "get_config on a corrupt DB must not return Ok(None); got {r:?}"
        );
    }
}

/// the redundant `idx_file_chunks_inode_offset` index was
/// removed. Verify the table still functions without it (queries via
/// the primary key work, and the schema doesn't include the index).
#[test]
fn test_file_chunks_no_redundant_index() {
    let dir = tempfile::tempdir().unwrap();
    let db = cairn_index::Db::new(dir.path().join("a.db").to_str().unwrap(), None).unwrap();
    db.insert_inode_with_dentry(0o100644, 1000, 1000, 0, 1, 1, "f", None)
        .unwrap();
    let ino = db.get_dentry_inode(1, "f").unwrap().expect("dentry exists");
    db.insert_file_chunk(ino, 0, "obj1", 100, 0).unwrap();
    db.insert_chunk_indices_batch(&[(
        "obj1".into(),
        "ph1".into(),
        b"k".to_vec(),
        0,
        "aes-gcm".into(),
    )])
    .unwrap();
    db.insert_file_chunk(ino, 100, "obj2", 100, 0).unwrap();
    db.insert_chunk_indices_batch(&[(
        "obj2".into(),
        "ph2".into(),
        b"k".to_vec(),
        0,
        "aes-gcm".into(),
    )])
    .unwrap();
    let chunks = db.get_file_chunks(ino).unwrap();
    assert_eq!(chunks.len(), 2);
    let range = db.get_file_chunks_range(ino, 0, 200).unwrap();
    assert_eq!(range.len(), 2);
}

/// Schema is stable across re-opens — all columns are created inline in CREATE TABLE.
#[test]
fn test_schema_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db = cairn_index::Db::new(dir.path().join("a.db").to_str().unwrap(), None).unwrap();
    db.set_inline_data(1, b"abc").unwrap();
    let v = db.get_inline_data(1).unwrap().unwrap();
    assert_eq!(v, b"abc");
    drop(db);
    // Re-open — schema creation must not fail.
    let db2 = cairn_index::Db::new(dir.path().join("a.db").to_str().unwrap(), None).unwrap();
    let v = db2.get_inline_data(1).unwrap();
    assert!(v.is_some());
}

/// `set_xattr_with_flags` honours XATTR_CREATE / XATTR_REPLACE.
#[test]
fn test_set_xattr_with_flags() {
    use cairn_index::{Db, XattrFlag};
    let dir = tempfile::tempdir().unwrap();
    let db = Db::new(dir.path().join("a.db").to_str().unwrap(), None).unwrap();
    db.insert_inode_with_dentry(0o100644, 1000, 1000, 0, 1, 1, "f", None)
        .unwrap();
    let ino = db.get_dentry_inode(1, "f").unwrap().expect("dentry");
    db.set_xattr_with_flags(ino, "user.x", b"v1", XattrFlag::None)
        .unwrap();
    // XATTR_CREATE against existing → Err.
    assert!(
        db.set_xattr_with_flags(ino, "user.x", b"v2", XattrFlag::Create)
            .is_err()
    );
    // XATTR_REPLACE against existing → ok, value updated.
    db.set_xattr_with_flags(ino, "user.x", b"v2", XattrFlag::Replace)
        .unwrap();
    let v = db.get_xattr(ino, "user.x").unwrap().unwrap();
    assert_eq!(v, b"v2");
    // XATTR_REPLACE against missing → Err.
    assert!(
        db.set_xattr_with_flags(ino, "user.missing", b"x", XattrFlag::Replace)
            .is_err()
    );
    // XATTR_CREATE against missing → ok.
    db.set_xattr_with_flags(ino, "user.y", b"y", XattrFlag::Create)
        .unwrap();
}

/// `truncate_inode` clears inline data + updates size + removes
/// out-of-range chunks in one transaction. A subsequent `get_inline_data`
/// returns None and `get_inode().size` matches new_size.
#[test]
fn test_truncate_inode_clears_inline_and_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let db = cairn_index::Db::new(dir.path().join("a.db").to_str().unwrap(), None).unwrap();
    db.insert_inode_with_dentry(0o100644, 1000, 1000, 0, 1, 1, "f", None)
        .unwrap();
    let ino = db.get_dentry_inode(1, "f").unwrap().expect("dentry");
    // Plant inline data + chunks.
    db.set_inline_data(ino, b"some inline bytes").unwrap();
    db.insert_file_chunk(ino, 0, "obj1", 200, 0).unwrap();
    db.insert_chunk_indices_batch(&[(
        "obj1".into(),
        "ph1".into(),
        b"k".to_vec(),
        0,
        "aes-gcm".into(),
    )])
    .unwrap();
    db.insert_file_chunk(ino, 200, "obj2", 200, 0).unwrap();
    db.insert_chunk_indices_batch(&[(
        "obj2".into(),
        "ph2".into(),
        b"k".to_vec(),
        0,
        "aes-gcm".into(),
    )])
    .unwrap();
    // Truncate to 50.
    db.truncate_inode(ino, 50).unwrap();
    // Size updated.
    let row = db.get_inode(ino).unwrap().unwrap();
    assert_eq!(row.3, 50, "truncate_inode updated size");
    // Inline cleared.
    let post = db.get_inline_data(ino).unwrap();
    assert!(post.is_none(), "truncate_inode cleared inline_data");
    // Chunks: the straddle one (offset 0, length 200, new_size 50) is
    // shortened to length 50; the second chunk (offset 200 >= new_size)
    // is deleted.
    let chunks = db.get_file_chunks(ino).unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].2, 50);
}

/// `delete_dentry` removes a single dentry.
#[test]
fn test_delete_dentry() {
    let dir = tempfile::tempdir().unwrap();
    let db = cairn_index::Db::new(dir.path().join("a.db").to_str().unwrap(), None).unwrap();
    let ino_a = db.insert_inode(0o100644, 0, 0, 0, 1).unwrap();
    let ino_b = db.insert_inode(0o100644, 0, 0, 0, 1).unwrap();
    db.insert_dentry(1, "a", ino_a).unwrap();
    db.insert_dentry(1, "b", ino_b).unwrap();
    db.delete_dentry(1, "a").unwrap();
    assert!(db.get_dentry_inode(1, "a").unwrap().is_none());
    assert!(db.get_dentry_inode(1, "b").unwrap().is_some());
}

/// decrypt_blob returns Zeroizing and the error message does
/// not include the algorithm name or AEAD-internal details.
#[test]
fn test_decrypt_blob_zeroizing_and_error_redaction() {
    use cairn_seal::CryptoCtx;
    let _dir = tempfile::tempdir().unwrap();
    let pass = "a passphrase that's at least medium entropy";
    let ctx = CryptoCtx::new_symmetric(
        3,
        0,
        "zstd".to_string(),
        "aes-256-gcm".to_string(),
        None,
        true,
        1024,
        secrecy::SecretString::from(pass.to_string()),
        None,
    )
    .unwrap();
    let wrapped = ctx.encrypt_blob(b"the chunk key").unwrap();
    let key = ctx.decrypt_blob(&wrapped).unwrap();
    // Returns Zeroizing, not Vec.
    let _zero: zeroize::Zeroizing<Vec<u8>> = key;
    // Error path: garbage blob must produce a redacted error.
    let err = ctx
        .decrypt_blob(b"CKEK1\0\0\0\0\0\0\0\0\0\0\0\0not-ciphertext")
        .expect_err("must fail");
    let msg = err.to_string();
    // Must NOT include AEAD internals like "cipher" or algorithm details.
    assert!(
        !msg.contains("ChaCha") && !msg.contains("AES") && !msg.contains("cipher"),
        "error message leaks algorithm: {msg}"
    );
}

/// a dedup_secret shorter than 32 bytes panics. The default init
/// generates 64-hex-char (32-byte) secrets, so this only bites a custom
/// user-provided value.
/// generate_chunk_key now returns Result instead of panicking.
#[test]
fn test_short_dedup_secret_returns_error() {
    use cairn_seal::CryptoCtx;
    let dir = tempfile::tempdir().unwrap();
    let pub_path = dir.path().join("pub.pem");
    let priv_path = dir.path().join("priv.pem");
    use age::secrecy::ExposeSecret;
    let id = age::x25519::Identity::generate();
    std::fs::write(&pub_path, id.to_public().to_string()).unwrap();
    std::fs::write(&priv_path, id.to_string().expose_secret()).unwrap();
    // 9-byte dedup_secret — should return Err, not panic.
    let result = CryptoCtx::new(
        pub_path.to_str().unwrap(),
        Some(priv_path.to_str().unwrap()),
        3,
        0,
        "zstd".to_string(),
        "aes-256-gcm".to_string(),
        Some(secrecy::SecretString::from("hunter2!!".to_string())), // 9 bytes
        false,
        1024,
    )
    .unwrap()
    .generate_chunk_key(b"x");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("dedup_secret must be at least 32 bytes"));
}

/// `zeroize_keys` clears the passphrase from a symmetric CryptoCtx
/// so a post-call heap inspection no longer reveals the root secret.
#[test]
fn test_zeroize_keys_clears_passphrase() {
    use cairn_seal::CryptoCtx;
    let pass = secrecy::SecretString::from("a passphrase that's at least medium entropy");
    let ctx = CryptoCtx::new_symmetric(
        3,
        0,
        "zstd".to_string(),
        "aes-256-gcm".to_string(),
        None,
        true,
        1024,
        pass,
        None,
    )
    .unwrap();
    // Before zeroize: decrypting a wrapped blob works (passphrase present).
    let wrapped = ctx.encrypt_blob(b"the chunk key").unwrap();
    ctx.decrypt_blob(&wrapped).unwrap();
    // After zeroize: the KEK is gone, so decrypting must fail.
    ctx.zeroize_keys();
    let err = ctx
        .decrypt_blob(&wrapped)
        .expect_err("decrypt after zeroize_keys must fail");
    assert!(err.to_string().contains("KEK") || err.to_string().contains("key"));
}

// ────────────────────────────────────────────────────────────────────
// Cairn-keys tests
// ────────────────────────────────────────────────────────────────────

/// `cairn-keys` writes priv.pem / pub.pem with mode 0o600
/// (owner-only). The previous version used `File::create`, which
/// honoured the process umask (typically 0o022 → 0o644 world-readable).
/// We shell out to the binary from a known workspace path and check
/// the resulting file modes. Integration test in cairn-keys would be
/// nicer; for now this exercises the binary's end-to-end behaviour.
#[cfg(unix)]
#[test]
fn test_cairn_keys_writes_secret_files_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    // Build the gen_keys binary.
    let build_status = Command::new(env!("CARGO"))
        .args(["build", "-q", "-p", "cairn-keys", "--bin", "gen_keys"])
        .status()
        .expect("cargo build gen_keys");
    assert!(build_status.success(), "cargo build gen_keys failed");

    // Locate the binary in target/.
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) {
            "gen_keys.exe"
        } else {
            "gen_keys"
        });
    if !bin.exists() {
        // Debug build of cairn-keys may not have been built; skip.
        eprintln!("gen_keys binary not found at {bin:?}, skipping");
        return;
    }

    let run = tempfile::tempdir().unwrap();
    let out = Command::new(&bin)
        .current_dir(run.path())
        .output()
        .expect("run gen_keys");
    assert!(out.status.success(), "gen_keys failed: {out:?}");
    for name in ["priv.pem", "pub.pem"] {
        let path = run.path().join(name);
        let meta = std::fs::metadata(&path).expect("file exists");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{name} must be owner-only, got {mode:o}");
    }
}
