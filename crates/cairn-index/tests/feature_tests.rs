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

/// Re-open the (encrypted) archive created by `make_archive` — the index is
/// SQLCipher-keyed, so every open needs the same password.
fn open_archive(db_path: &std::path::Path) -> cairn_index::Db {
    let pwd: Option<secrecy::SecretString> =
        Some(secrecy::SecretString::new("testpwd".to_string().into()));
    cairn_index::Db::new(db_path.to_str().unwrap(), pwd.as_ref()).unwrap()
}

/// Raw bytes of the archive INCLUDING its WAL sidecars: freshly written schema
/// can still live in `-wal`, so reading only the main file is flaky (and would
/// miss plaintext leaks that WAL would otherwise expose).
fn raw_archive_bytes(db_path: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let path = if suffix.is_empty() {
            db_path.to_path_buf()
        } else {
            std::path::PathBuf::from(format!("{}{}", db_path.display(), suffix))
        };
        if let Ok(mut bytes) = std::fs::read(&path) {
            out.append(&mut bytes);
        }
    }
    out
}

// ── Snapshot lifecycle ───────────────────────────────────────────────────────

#[test]
fn snapshot_create_then_ls_returns_entries() {
    let (_tmp, db_path) = make_archive();
    let db = open_archive(&db_path);
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
    let db = open_archive(&db_path);
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

    // `extract_snapshot` writes a FILE (create_new); it must not be handed an
    // existing directory path. Open it back to prove the frozen copy is valid.
    let out_file = tmp.path().join("extracted.db");
    db.extract_snapshot(snap_id, out_file.to_str().unwrap())
        .unwrap();
    assert!(out_file.is_file(), "extracted snapshot must be a file");
    let frozen = open_archive(&out_file);
    assert_eq!(frozen.list_snapshots().unwrap().len(), 0);
}

// ── GC grace period ──────────────────────────────────────────────────────────

#[test]
fn get_orphaned_chunks_respects_grace_period() {
    let (_tmp, db_path) = make_archive();
    let pwd: Option<secrecy::SecretString> =
        Some(secrecy::SecretString::new("testpwd".to_string().into()));
    let db = cairn_index::Db::new(db_path.to_str().unwrap(), pwd.as_ref()).unwrap();

    // Insert a chunk index without any file_chunks reference → it's an orphan.
    // Schema requires plaintext_hash + sym_key; created_at is an epoch integer.
    let conn = db.pool.get().unwrap();
    conn.execute(
        "INSERT INTO chunk_index (object_id, plaintext_hash, sym_key, created_at)
         VALUES (?1, ?2, ?3, strftime('%s','now') - 3600)",
        ("orphan_chunk_001", "ph-orphan-1", vec![0u8; 1]),
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

    // Insert a chunk that was created 2 hours ago (epoch seconds).
    let conn = db.pool.get().unwrap();
    conn.execute(
        "INSERT INTO chunk_index (object_id, plaintext_hash, sym_key, created_at)
         VALUES (?1, ?2, ?3, strftime('%s','now') - 7200)",
        ("orphan_2h", "ph-orphan-2h", vec![0u8; 1]),
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
    let raw = raw_archive_bytes(&db_path);

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

    let raw = raw_archive_bytes(&db_path);

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

    // Init without password → DB is NOT encrypted.
    cairn_index::Db::new(db_path.to_str().unwrap(), None).unwrap();

    let raw = raw_archive_bytes(&db_path);

    // An unencrypted SQLite file should contain the schema as plaintext.
    assert!(
        raw_contains(&raw, b"snapshots"),
        "unencrypted index must contain table name 'snapshots' in plaintext"
    );
}
