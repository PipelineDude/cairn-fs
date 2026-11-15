// Regression tests for chunk GC: straddling-chunk hole punch, and corrupt
// snapshot rows that were silently skipped during collection.

use cairn_index::Db;
use tempfile::TempDir;

fn setup_db() -> (Db, TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("test.db");
    let db = Db::new(db_path.to_str().unwrap(), None).unwrap();
    // file_chunks has FK on inode → inodes(id), so we need inode rows
    // for every test inode we use.
    let conn = db.pool.get().unwrap();
    for ino in 100u64..110u64 {
        conn.execute(
            "INSERT OR IGNORE INTO inodes (id, mode, uid, gid, mtime_sec, mtime_nsec, size, nlink, rdev)
             VALUES (?1, 33188, 0, 0, 0, 0, 0, 1, 0)",
            rusqlite::params![ino],
        )
        .unwrap();
    }
    (db, tmp)
}

/// Helper: insert a raw file_chunks row (bypasses replace_file_chunks which
/// requires a chunk_index entry).
fn insert_chunk_raw(db: &Db, inode: u64, offset: u64, object_id: &str, plain_len: u64) {
    let conn = db.pool.get().unwrap();
    conn.execute(
        "INSERT INTO file_chunks (inode, offset, object_id, plain_len, comp_type) VALUES (?1, ?2, ?3, ?4, 0)",
        rusqlite::params![inode, offset as i64, object_id, plain_len as i64],
    )
    .unwrap();
}

/// Helper: read back file_chunks for an inode.
fn read_chunks(db: &Db, inode: u64) -> Vec<(u64, u64)> {
    let conn = db.pool.get().unwrap();
    let mut stmt = conn
        .prepare("SELECT offset, plain_len FROM file_chunks WHERE inode = ?1 ORDER BY offset")
        .unwrap();
    let rows: Vec<(u64, u64)> = stmt
        .query_map(rusqlite::params![inode], |row| {
            Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows
}

// ---------------------------------------------------------------------------
// straddle chunk not split on hole punch
// ---------------------------------------------------------------------------

/// A chunk starting before the punch range but extending into it must be
/// shortened (not left intact).
#[test]
fn t046_straddle_chunk_shortened() {
    let (db, _tmp) = setup_db();
    let ino = 100; // arbitrary inode

    // Chunk A: [0, 1000) — straddles the punch range [200, 500)
    insert_chunk_raw(&db, ino, 0, "chunk_a", 1000);
    // Chunk B: [300, 600) — starts inside punch range, deleted by DELETE
    insert_chunk_raw(&db, ino, 300, "chunk_b", 300);
    // Chunk C: [1000, 2000) — fully outside, should survive
    insert_chunk_raw(&db, ino, 1000, "chunk_c", 1000);

    db.drop_file_chunks_range(ino, 200, 500).unwrap();

    let remaining = read_chunks(&db, ino);

    // Chunk A should be shortened to [0, 200), i.e. plain_len = 200 - 0 = 200
    let a = remaining.iter().find(|(off, _)| *off == 0);
    assert!(a.is_some(), "straddle chunk A must survive (shortened)");
    assert_eq!(
        a.unwrap().1,
        200,
        "straddle chunk A plain_len must be shortened to 200"
    );

    // Chunk B should be deleted (offset 300 >= 200 AND offset 300 < 500)
    let b = remaining.iter().find(|(off, _)| *off == 300);
    assert!(b.is_none(), "interior chunk B must be deleted");

    // Chunk C should survive untouched
    let c = remaining.iter().find(|(off, _)| *off == 1000);
    assert!(c.is_some(), "exterior chunk C must survive");
    assert_eq!(c.unwrap().1, 1000);
}

/// Punching an aligned range (offset == start) should not cause issues.
#[test]
fn t046_aligned_punch() {
    let (db, _tmp) = setup_db();
    let ino = 101;

    // Chunk at [0, 4096) — punch starts exactly at 0
    insert_chunk_raw(&db, ino, 0, "chunk_x", 4096);
    // Chunk at [8192, 12288) — outside
    insert_chunk_raw(&db, ino, 8192, "chunk_y", 4096);

    db.drop_file_chunks_range(ino, 0, 4096).unwrap();

    let remaining = read_chunks(&db, ino);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0, 8192);
}

/// A chunk fully inside the punch range is deleted (no straddle).
#[test]
fn t046_interior_chunk_deleted() {
    let (db, _tmp) = setup_db();
    let ino = 102;

    insert_chunk_raw(&db, ino, 0, "c1", 100);
    insert_chunk_raw(&db, ino, 200, "c2", 100); // fully inside [100, 400)
    insert_chunk_raw(&db, ino, 500, "c3", 100);

    db.drop_file_chunks_range(ino, 100, 400).unwrap();

    let remaining = read_chunks(&db, ino);
    assert_eq!(remaining.len(), 2);
    assert_eq!(remaining[0].0, 0);
    assert_eq!(remaining[0].1, 100);
    assert_eq!(remaining[1].0, 500);
}

/// A chunk starting inside the punch range and extending past it — the DELETE
/// should remove it (offset >= start).
#[test]
fn t046_tail_straddle_deleted() {
    let (db, _tmp) = setup_db();
    let ino = 103;

    // Chunk at [300, 1000) — offset 300 is inside [200, 500), should be deleted
    insert_chunk_raw(&db, ino, 300, "c1", 700);
    insert_chunk_raw(&db, ino, 0, "c0", 200);

    db.drop_file_chunks_range(ino, 200, 500).unwrap();

    let remaining = read_chunks(&db, ino);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0, 0);
}

// ---------------------------------------------------------------------------
// corrupt snapshot rows silently skipped in GC
// ---------------------------------------------------------------------------

/// get_all_used_chunks must return an error (not silently skip) when a
/// snapshot's file_chunks table has a corrupt row with an unparseable
/// object_id column.
#[test]
fn t047_corrupt_snapshot_row_causes_error() {
    let (db, _tmp) = setup_db();

    // Create a snapshot with valid data first.
    db.create_snapshot("test_snap").unwrap();

    let conn = db.pool.get().unwrap();

    // Get the snapshot's db_data (the VACUUM INTO file bytes)
    let snap_data: Vec<u8> = conn
        .query_row(
            "SELECT db_data FROM snapshots WHERE name = ?1",
            rusqlite::params!["test_snap"],
            |row| row.get(0),
        )
        .unwrap();

    // Write it to a temp file, corrupt it, and update the snapshot
    let tmp = tempfile::tempdir().unwrap();
    let snap_file = tmp.path().join("corrupt_snap.db");
    std::fs::write(&snap_file, &snap_data).unwrap();

    // Open the snapshot DB and insert a corrupt row
    {
        let snap_conn = rusqlite::Connection::open(&snap_file).unwrap();
        // Disable FK checks so we can insert a row with an inode that doesn't
        // exist in the snapshot's inodes table.
        snap_conn
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .unwrap();
        // Insert a BLOB value in object_id — rusqlite's r.get::<_, String>(0)
        // will fail because a BLOB is not valid UTF-8.
        snap_conn
            .execute_batch(
                "INSERT INTO file_chunks (inode, offset, object_id, plain_len, comp_type)
                 VALUES (999, 0, X'DEADBEEF', 100, 0);",
            )
            .unwrap();
    }

    // Read back and update the snapshot
    let corrupted_data = std::fs::read(&snap_file).unwrap();
    conn.execute(
        "UPDATE snapshots SET db_data = ?1 WHERE name = ?2",
        rusqlite::params![corrupted_data, "test_snap"],
    )
    .unwrap();

    // get_all_used_chunks should propagate the error (fix)
    let result = db.get_all_used_chunks();
    assert!(
        result.is_err(),
        "get_all_used_chunks must return Err for corrupt snapshot, got Ok"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("corrupt") || err_msg.contains("object_id"),
        "error message should mention corruption: {err_msg}"
    );
}
