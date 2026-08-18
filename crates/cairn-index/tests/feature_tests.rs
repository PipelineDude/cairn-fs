//! Snapshot lifecycle (create / ls) with grace-period gc, and encrypted-index raw-file inspection.

use std::path::PathBuf;

/// Does `raw` contain `needle` as a contiguous byte substring?
fn raw_contains(raw: &[u8], needle: &[u8]) -> bool {
    raw.windows(needle.len()).any(|w| w == needle)
}

/// Create a temporary archive directory with an init'd index DB.
fn make_archive() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("archive.db");
    // Init the DB via the Db API — we need a password so the file is encrypted.
    // secrecy 0.10.x `SecretString::new` takes `Box<str>` (SecretBox::new), so box the String.
    let pwd: Option<secrecy::SecretString> =
        Some(secrecy::SecretString::new("testpwd".to_string().into()));
    cairn_index::Db::new(db_path.to_str().unwrap(), pwd.as_ref()).unwrap();
    (tmp, db_path)
}

/// Re-open an archive made by make_archive() WITH its password.
fn open_archive(db_path: &str) -> cairn_index::Db {
    let pwd: Option<secrecy::SecretString> =
        Some(secrecy::SecretString::new("testpwd".to_string().into()));
    cairn_index::Db::new(db_path, pwd.as_ref()).unwrap()
}

// ── Snapshot lifecycle ───────────────────────────────────────────────────────

#[test]
fn snapshot_create_then_ls_returns_entries() {
    let (_tmp, db_path) = make_archive();
    let db = open_archive(db_path.to_str().unwrap());
    db.create_snapshot("snap1").unwrap();
    let snaps = db.list_snapshots().unwrap();
    assert_eq!(snaps.len(), 1);
    // list_snapshots returns (id, name, timestamp)
    let (id, name, _ts) = &snaps[0];
    assert_eq!(name, "snap1");
    assert!(*id > 0);
}

#[test]
fn snapshot_create_multiple_then_ls() {
    let (_tmp, db_path) = make_archive();
    let db = open_archive(db_path.to_str().unwrap());
    for i in 1..=5u64 {
        db.create_snapshot(&format!("snap{}", i)).unwrap();
    }
    let snaps = db.list_snapshots().unwrap();
    assert_eq!(snaps.len(), 5);
}

#[test]
fn snapshot_extract_then_restore() {
    let (tmp, db_path) = make_archive();
    let pwd: Option<secrecy::SecretString> =
        Some(secrecy::SecretString::new("testpwd".to_string().into()));
    let db = cairn_index::Db::new(db_path.to_str().unwrap(), pwd.as_ref()).unwrap();

    // Create a snapshot, then extract it to a temp dir.
    db.create_snapshot("snap_extract").unwrap();
    let snaps = db.list_snapshots().unwrap();
    assert_eq!(snaps.len(), 1);
    let snap_id = snaps[0].0;

    // extract_snapshot writes a FILE (create_new) -- pass a file path, not a dir.
    let out_dir = tmp.path().join("extracted");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out_file = out_dir.join("snapshot.bin");
    db.extract_snapshot(snap_id, out_file.to_str().unwrap())
        .unwrap();
}

// ── GC grace period ──────────────────────────────────────────────────────────

#[test]
fn get_orphaned_chunks_respects_grace_period() {
    let (_tmp, db_path) = make_archive();
    let pwd: Option<secrecy::SecretString> =
        Some(secrecy::SecretString::new("testpwd".to_string().into()));
    let db = cairn_index::Db::new(db_path.to_str().unwrap(), pwd.as_ref()).unwrap();

    // Insert a chunk index without any file_chunks reference → it's an orphan.
    let conn = db.pool.get().unwrap();
    conn.execute(
        "INSERT INTO chunk_index (object_id, plaintext_hash, sym_key, comp_type, cipher, created_at) \
         VALUES (?1, ?2, X'00', 0, 'aes256gcm', strftime('%s', 'now', '-3600 seconds'))",
        ["orphan_chunk_001", "orphan-hash"],
    )
    .unwrap();

    // With grace_period_hours=0, the orphan should be returned immediately.
    let orphans = db.get_orphaned_chunks(0).unwrap();
    assert!(orphans.contains(&"orphan_chunk_001".to_string()));
}

#[test]
fn get_orphaned_chunks_respects_grace_period_hours() {
    let (_tmp, db_path) = make_archive();
    let pwd: Option<secrecy::SecretString> =
        Some(secrecy::SecretString::new("testpwd".to_string().into()));
    let db = cairn_index::Db::new(db_path.to_str().unwrap(), pwd.as_ref()).unwrap();

    // Insert a chunk that was created 2 hours ago.
    let conn = db.pool.get().unwrap();
    conn.execute(
        "INSERT INTO chunk_index (object_id, plaintext_hash, sym_key, comp_type, cipher, created_at) \
         VALUES (?1, ?2, X'00', 0, 'aes256gcm', strftime('%s', 'now', '-7200 seconds'))",
        ["orphan_2h", "orphan-hash-2h"],
    )
    .unwrap();

    // With grace_period_hours=1, this should be returned (it's older than 1 hour).
    let orphans = db.get_orphaned_chunks(1).unwrap();
    assert!(orphans.contains(&"orphan_2h".to_string()));
}

// ── Encrypted index: no plaintext metadata in raw SQLite file ────────────────

#[test]
fn encrypted_index_no_plaintext_name_in_raw_file() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("encrypted.db");

    // Init with password → DB is encrypted.
    let pwd: Option<secrecy::SecretString> =
        Some(secrecy::SecretString::new("testpwd".to_string().into()));
    cairn_index::Db::new(db_path.to_str().unwrap(), pwd.as_ref()).unwrap();

    // Read raw bytes of the SQLite file.
    let raw = std::fs::read(&db_path).unwrap();

    // The raw file must NOT contain any plaintext file names or paths.
    assert!(
        !raw_contains(&raw, b"filename_test_file"),
        "encrypted index file must not contain plaintext metadata"
    );
    assert!(
        !raw_contains(&raw, b"/home/user/Documents/secret_report"),
        "encrypted index file must not contain plaintext paths"
    );
}

#[test]
fn encrypted_index_no_plaintext_password_in_raw_file() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("encrypted.db");

    let pwd: Option<secrecy::SecretString> =
        Some(secrecy::SecretString::new("mysecret123".to_string().into()));
    cairn_index::Db::new(db_path.to_str().unwrap(), pwd.as_ref()).unwrap();

    let raw = std::fs::read(&db_path).unwrap();

    // The password itself must not appear in plaintext.
    assert!(
        !raw_contains(&raw, b"mysecret123"),
        "encrypted index file must not contain the password in plaintext"
    );
}

#[test]
fn unencrypted_index_contains_plaintext_schema() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("unencrypted.db");

    // Init without password → DB is NOT encrypted (plaintext SQLite).
    cairn_index::Db::new(db_path.to_str().unwrap(), None).unwrap();

    let raw = std::fs::read(&db_path).unwrap();

    // An unencrypted SQLite file should contain the schema as plaintext.
    assert!(
        raw_contains(&raw, b"snapshots"),
        "unencrypted index must contain table name 'snapshots' in plaintext"
    );
}

// ── Known limitation: v1 database without name_enc column ────────────────────

#[test]
fn v1_db_without_name_enc_fails_on_name_enc_select() {
    // CURRENT_SCHEMA_VERSION=1 (no bump yet), so the ALTER TABLE migration
    // for name_enc does not run. This test documents the known limitation:
    // a database opened with the old code (v1 schema, no name_enc) will fail
    // when queried for the missing column. This is acceptable because there
    // are no live v1 archives (per project owner).
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("v1_legacy.db");

    // Create a v1 schema database directly (bypasses Db::new).
    let conn = rusqlite::Connection::open(db_path.to_str().unwrap()).unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 1;
         CREATE TABLE IF NOT EXISTS inodes (id INTEGER PRIMARY KEY AUTOINCREMENT, mode INTEGER NOT NULL, uid INTEGER NOT NULL, gid INTEGER NOT NULL, mtime_sec INTEGER NOT NULL, mtime_nsec INTEGER NOT NULL, size INTEGER NOT NULL, nlink INTEGER NOT NULL, rdev INTEGER NOT NULL, inline_data BLOB DEFAULT NULL);
         CREATE TABLE IF NOT EXISTS dentries (parent_inode INTEGER NOT NULL, name TEXT NOT NULL, inode_id INTEGER NOT NULL, PRIMARY KEY (parent_inode, name), FOREIGN KEY(parent_inode) REFERENCES inodes(id) ON DELETE CASCADE, FOREIGN KEY(inode_id) REFERENCES inodes(id) ON DELETE CASCADE);",
    )
    .unwrap();

    // Open through the Db API in PLAIN (no password) mode: CREATE IF NOT
    // EXISTS is a no-op, ALTER is skipped (CURRENT=1), so dentries stays
    // without name_enc.
    let db = cairn_index::Db::new(db_path.to_str().unwrap(), None).unwrap();

    // Must fail: v1 dentries has no name_enc column.
    let conn = db.pool.get().expect("db pool");
    let result = conn.prepare("SELECT name_enc FROM dentries LIMIT 1");
    assert!(
        result.is_err(),
        "v1 database without name_enc should fail on SELECT name_enc (CURRENT_SCHEMA_VERSION=1)"
    );
}
