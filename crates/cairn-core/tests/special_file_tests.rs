// Regression tests for special files and mknod (symlink target storage, and the
// setuid/setgid/sticky/FIFO/device bits preserved through mknod).

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

// symlink stores short targets as inline data
#[tokio::test]
async fn test_symlink_short_target_stored_inline() {
    let (engine, _dir) = setup_engine().await;

    let target = "/etc/passwd";
    let reply = engine
        .symlink(
            Request::default(),
            1,
            OsStr::new("link"),
            OsStr::new(target),
        )
        .await
        .unwrap();
    let ino = reply.attr.ino;

    let data = engine.readlink(Request::default(), ino).await.unwrap();
    assert_eq!(data, target.as_bytes());
}

#[tokio::test]
async fn test_symlink_longer_target_stored_inline() {
    let (engine, _dir) = setup_engine().await;

    let target =
        "/a/very/long/symlink/target/with/many/characters/to/test/inline/path/still/works/fine";
    let reply = engine
        .symlink(
            Request::default(),
            1,
            OsStr::new("longlink"),
            OsStr::new(target),
        )
        .await
        .unwrap();
    let ino = reply.attr.ino;

    let result = engine.readlink(Request::default(), ino).await.unwrap();
    assert_eq!(result, target.as_bytes());
}

// readdirplus perm includes setuid/setgid/sticky
#[tokio::test]
async fn test_mknod_setuid_perm_preserved() {
    let (engine, _dir) = setup_engine().await;

    let mode = libc::S_IFREG | 0o4755; // setuid + rwxr-xr-x
    let reply = engine
        .mknod(Request::default(), 1, OsStr::new("setuid_file"), mode, 0)
        .await
        .unwrap();
    let ino = reply.attr.ino;

    // getattr should preserve the setuid bit
    let attr = engine
        .getattr(Request::default(), ino, None, 0)
        .await
        .unwrap();
    assert_eq!(
        attr.perm & 0o4000,
        0o4000,
        "getattr must preserve setuid bit"
    );
}

#[tokio::test]
async fn test_mknod_sticky_bit_preserved() {
    let (engine, _dir) = setup_engine().await;

    let mode = libc::S_IFDIR | 0o1755; // sticky + rwxr-xr-x
    let reply = engine
        .mknod(Request::default(), 1, OsStr::new("sticky_dir"), mode, 0)
        .await
        .unwrap();
    let ino = reply.attr.ino;

    let attr = engine
        .getattr(Request::default(), ino, None, 0)
        .await
        .unwrap();
    assert_eq!(
        attr.perm & 0o1000,
        0o1000,
        "getattr must preserve sticky bit"
    );
}

// readdir/readdirplus maps all POSIX file types
#[tokio::test]
async fn test_mknod_fifo_type() {
    let (engine, _dir) = setup_engine().await;

    let mode = libc::S_IFIFO | 0o644;
    let reply = engine
        .mknod(Request::default(), 1, OsStr::new("myfifo"), mode, 0)
        .await
        .unwrap();
    let ino = reply.attr.ino;

    let attr = engine
        .getattr(Request::default(), ino, None, 0)
        .await
        .unwrap();
    assert_eq!(
        attr.kind,
        FileType::NamedPipe,
        "FIFO must be reported as NamedPipe"
    );
}

#[tokio::test]
async fn test_mknod_socket_type() {
    let (engine, _dir) = setup_engine().await;

    let mode = libc::S_IFSOCK | 0o644;
    let reply = engine
        .mknod(Request::default(), 1, OsStr::new("mysock"), mode, 0)
        .await
        .unwrap();
    let ino = reply.attr.ino;

    let attr = engine
        .getattr(Request::default(), ino, None, 0)
        .await
        .unwrap();
    assert_eq!(
        attr.kind,
        FileType::Socket,
        "Socket must be reported as Socket"
    );
}

#[tokio::test]
async fn test_mknod_char_device_type() {
    let (engine, _dir) = setup_engine().await;

    let mode = libc::S_IFCHR | 0o644;
    let reply = engine
        .mknod(
            Request::default(),
            1,
            OsStr::new("mychr"),
            mode,
            libc::makedev(1, 3) as u32,
        )
        .await
        .unwrap();
    let ino = reply.attr.ino;

    let attr = engine
        .getattr(Request::default(), ino, None, 0)
        .await
        .unwrap();
    assert_eq!(
        attr.kind,
        FileType::CharDevice,
        "Char device must be reported as CharDevice"
    );
}

// keyed content IDs reject invalid dedup configuration
#[test]
fn test_short_dedup_secret_returns_error_not_panic() {
    use age::secrecy::ExposeSecret;
    use cairn_seal::CryptoCtx;
    let dir = tempfile::tempdir().unwrap();
    let pub_path = dir.path().join("pub.pem");
    let priv_path = dir.path().join("priv.pem");
    let id = age::x25519::Identity::generate();
    std::fs::write(&pub_path, id.to_public().to_string()).unwrap();
    std::fs::write(&priv_path, id.to_string().expose_secret()).unwrap();

    let ctx = CryptoCtx::new(
        pub_path.to_str().unwrap(),
        Some(priv_path.to_str().unwrap()),
        3,
        0,
        "zstd".to_string(),
        "aes-256-gcm".to_string(),
        Some(secrecy::SecretString::from("short".to_string())), // 5 bytes
        false,
        1024,
    )
    .unwrap();

    let result = ctx.content_id(b"test");
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("dedup_secret must be at least 32 bytes"));
}

#[test]
fn test_content_id_is_deterministic_and_not_an_encryption_key() {
    use cairn_seal::CryptoCtx;
    let dir = tempfile::tempdir().unwrap();
    let pub_path = dir.path().join("pub.pem");
    let id = age::x25519::Identity::generate();
    std::fs::write(&pub_path, id.to_public().to_string()).unwrap();

    let ctx = CryptoCtx::new(
        pub_path.to_str().unwrap(),
        None,
        3,
        0,
        "zstd".to_string(),
        "aes-256-gcm".to_string(),
        None,
        false,
        1024,
    )
    .unwrap();

    let id = ctx.content_id(b"test data").unwrap().unwrap();
    assert_eq!(id.len(), 32);

    // Same input → same key (deterministic dedup)
    let id2 = ctx.content_id(b"test data").unwrap().unwrap();
    assert_eq!(id, id2);

    // Different input → different key
    let id3 = ctx.content_id(b"other data").unwrap().unwrap();
    assert_ne!(id, id3);
}

// SQL injection validation
#[test]
fn test_db_tuning_rejects_invalid_synchronous() {
    use cairn_index::{Db, DbTuning};
    let dir = tempfile::tempdir().unwrap();
    let tuning = DbTuning {
        synchronous: "'; DROP TABLE inodes; --".to_string(),
        // Invalid synchronous makes every pool connection fail to build; r2d2
        // retries until the connection timeout, so the 30s default made this
        // test hang 30s. Fail fast — the rejection is immediate per attempt.
        connection_timeout_secs: 2,
        ..DbTuning::default()
    };
    let result = Db::new_with_tuning(dir.path().join("test.db").to_str().unwrap(), None, &tuning);
    assert!(
        result.is_err(),
        "Invalid synchronous mode should be rejected"
    );
}

// indexes exist
#[test]
fn test_indexes_created_on_init() {
    let dir = tempfile::tempdir().unwrap();
    let db = cairn_index::Db::new(dir.path().join("test.db").to_str().unwrap(), None).unwrap();

    let conn = db.pool.get().unwrap();
    let idx1: String = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_file_chunks_object_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(idx1, "idx_file_chunks_object_id");

    let idx2: String = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_dentries_inode_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(idx2, "idx_dentries_inode_id");
}

// get_inode_name returns empty for root
#[test]
fn test_get_inode_name_root_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let db = cairn_index::Db::new(dir.path().join("test.db").to_str().unwrap(), None).unwrap();

    // Root inode (1) has no dentry → should return empty string, not error
    let name = db.get_inode_name(1).unwrap();
    assert_eq!(name, "");
}

// stable hash for RAID placement
#[test]
fn test_stable_hash_is_deterministic() {
    use std::collections::HashSet;
    let mut results = HashSet::new();
    for _ in 0..100 {
        let h = cairn_store::stable_hash_index("test_key", 1000);
        results.insert(h);
    }
    assert_eq!(results.len(), 1, "stable_hash_index must be deterministic");
}

#[test]
fn test_stable_hash_distributes() {
    let n = 10;
    let mut counts = vec![0u64; n];
    for i in 0..1000 {
        let h = cairn_store::stable_hash_index(&format!("key_{i}"), n);
        counts[h] += 1;
    }
    // Each bucket should have roughly 100 entries (1000/10).
    // Allow a 50% margin.
    for (i, &c) in counts.iter().enumerate() {
        assert!(
            c > 30 && c < 170,
            "bucket {i} has {c} entries — distribution too skewed"
        );
    }
}

// ─── created_at DEFAULT constraint ───

#[test]
fn test_chunk_index_created_at_default() {
    let dir = tempfile::tempdir().unwrap();
    let db = cairn_index::Db::new(dir.path().join("test.db").to_str().unwrap(), None).unwrap();

    // Insert via Db API — created_at should be set by the DEFAULT constraint.
    db.insert_inode_with_dentry(33206, 1000, 1000, 0, 1, 1, "f", None)
        .unwrap();
    let ino = db.get_dentry_inode(1, "f").unwrap().expect("dentry");
    // Insert directly into chunk_index so the FK in file_chunks is satisfied.
    let conn = db.pool.get().unwrap();
    conn.execute(
        "INSERT INTO chunk_index (object_id, plaintext_hash, sym_key, comp_type) VALUES ('obj1', 'hash', X'00', 0)",
        [],
    ).unwrap();
    drop(conn);
    db.insert_file_chunks_batch(&[(ino as u64, 0, "obj1".to_string(), 100, 0)])
        .unwrap();

    let conn = db.pool.get().unwrap();
    let created_at: i64 = conn
        .query_row(
            "SELECT created_at FROM chunk_index WHERE object_id = 'obj1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        created_at > 0,
        "created_at should be non-zero from DEFAULT, got {created_at}"
    );
}

// ─── Write-only guarantee for INLINE (small-file) data ───
//
// Regression for a real bug: inline data (files <= the inline threshold, and
// symlink targets) was stored as PLAINTEXT in the SQLCipher index, so a host
// with only the DB password + public key could read small files on an
// asymmetric (write-only) archive WITHOUT the private key — while chunked
// (large) files were correctly age-wrapped. Inline data is now envelope-wrapped
// like chunk keys, so the write-only property holds for every file size.
#[tokio::test]
async fn test_inline_data_write_only_envelope() {
    let (engine, dir) = setup_engine().await;
    let req = Request::default();
    let secret: &[u8] = b"INLINE-WRITE-ONLY-SECRET-DATA-that-must-not-leak";

    let r = engine
        .mknod(req.clone(), 1, OsStr::new("s"), 0o644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    engine
        .write(req.clone(), ino, 0, 0, secret, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();

    // Small write went to inline_data (not chunks) ...
    let stored = engine
        .db
        .get_inline_data(ino)
        .unwrap()
        .expect("small file must be stored inline");
    // ... and the stored blob must be envelope CIPHERTEXT — the plaintext must
    // not appear anywhere in it.
    assert!(
        !stored.windows(secret.len()).any(|w| w == secret),
        "inline data stored as plaintext — write-only leak"
    );

    // The archive holder (has the private key) reads it back byte-exact.
    assert_eq!(&engine.unwrap_inline(&stored).unwrap()[..], secret);

    // A public-key-only context (NO private key) must NOT be able to decrypt the
    // inline blob — this is the write-only property for small files.
    let pub_path = dir.path().join("pub.pem");
    let pub_only = cairn_seal::CryptoCtx::new(
        pub_path.to_str().unwrap(),
        None, // no private key
        3,
        10,
        "zstd".to_string(),
        "chacha20".to_string(),
        None,
        true,
        1024,
    )
    .unwrap();
    assert!(
        pub_only.decrypt_blob(&stored).is_err(),
        "public-key-only host read inline data — write-only guarantee broken"
    );
}

// a backup killed mid-file leaves a truncated file whose committed size is
// self-consistent with its chunks, so verify would green-light it. The
// incomplete-file marker makes verify report it NOT restorable.
#[tokio::test]
async fn test_f19_incomplete_backup_marker_fails_verify() {
    let (engine, _dir) = setup_engine().await;
    let req = Request::default();
    let data = vec![0xABu8; 100_000]; // chunked (> inline threshold)
    let r = engine
        .mknod(req.clone(), 1, OsStr::new("big"), 0o100_644, 0)
        .await
        .unwrap();
    let ino = r.attr.ino;
    engine
        .write(req.clone(), ino, 0, 0, &data, 0, 0)
        .await
        .unwrap();
    engine.fsync(req.clone(), ino, 0, false).await.unwrap();

    // A complete file verifies clean.
    assert_eq!(engine.verify_all().await.unwrap(), (1, 0));

    // Marked in-progress (killed mid-backup) → NOT restorable.
    engine.db.mark_file_incomplete(ino).unwrap();
    assert_eq!(
        engine.verify_all().await.unwrap(),
        (0, 1),
        "marked-incomplete file must fail verify"
    );

    // Cleared (resumed backup completed) → green again.
    engine.db.clear_file_incomplete(ino).unwrap();
    assert_eq!(engine.verify_all().await.unwrap(), (1, 0));
}
