// Regression tests for the dedup index consistency fixes (dedup audit
// 2026-11-17):
//  - replace_file_chunks validates every object_id against chunk_index
//    (writer-side mirror guard against gc deleting the row mid-flush);
//  - remove_chunk_from_index_if_unreferenced is an atomic check+delete.

use cairn_index::Db;
use rusqlite::params;
use tempfile::TempDir;

fn setup_db() -> (Db, TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::new(tmp.path().join("test.db").to_str().unwrap(), None).unwrap();
    let conn = db.pool.get().unwrap();
    for ino in 100u64..110u64 {
        conn.execute(
            "INSERT OR IGNORE INTO inodes (id, mode, uid, gid, mtime_sec, mtime_nsec, size, nlink, rdev)
             VALUES (?1, 33188, 0, 0, 0, 0, 0, 1, 0)",
            params![ino],
        )
        .unwrap();
    }
    (db, tmp)
}

fn oid(seed: u8) -> String {
    format!("{:02x}", seed).repeat(32)
}

fn seed_chunk_index(db: &Db, object_id: &str) {
    db.insert_chunk_indices_batch(&[(
        object_id.to_string(),
        format!("ph-{object_id}"),
        vec![7u8; 4],
        0i32,
        "chacha20".to_string(),
    )])
    .unwrap();
}

fn ref_file_chunk(db: &Db, ino: u64, object_id: &str) {
    db.pool
        .get()
        .unwrap()
        .execute(
            "INSERT INTO file_chunks (inode, offset, object_id, plain_len, comp_type) VALUES (?1, 0, ?2, 10, 0)",
            params![ino as i64, object_id],
        )
        .unwrap();
}

fn row_exists(db: &Db, object_id: &str) -> bool {
    db.pool
        .get()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM chunk_index WHERE object_id = ?1)",
            params![object_id],
            |r| r.get(0),
        )
        .unwrap()
}

/// Writer-side mirror guard: a flush must not be able to commit a
/// file_chunks reference whose chunk_index row is gone (gc raced mid-flush) —
/// that state silently drops the chunk from every read (INNER JOIN).
#[test]
fn replace_file_chunks_rejects_object_without_index_row() {
    let (db, _t) = setup_db();
    let missing = oid(0xa1);
    let err = db
        .replace_file_chunks(100, 0, 0, &[(0u64, missing.clone(), 10, 0)])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("no chunk_index row") && err.contains(&missing),
        "unexpected error: {err}"
    );
    // No partial state: the rejected refs must not have been inserted.
    let n: i64 = db
        .pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM file_chunks WHERE inode = 100",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0, "rejected insert must roll back the whole transaction");
}

/// Positive control: with the chunk_index row present (the normal chunker
/// order: batch index insert → replace_file_chunks), the write succeeds.
#[test]
fn replace_file_chunks_accepts_indexed_object() {
    let (db, _t) = setup_db();
    let o = oid(0xb2);
    seed_chunk_index(&db, &o);
    db.replace_file_chunks(101, 0, 0, &[(0u64, o.clone(), 10, 0)])
        .unwrap();
    let chunks = db.get_file_chunks(101).unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].0, o);
}

/// gc TOCTOU fix: check+delete in ONE transaction. A reference that
/// exists (or landed) before the transaction commits must keep the row.
#[test]
fn conditional_delete_keeps_row_with_live_reference() {
    let (db, _t) = setup_db();
    let o = oid(0xc3);
    seed_chunk_index(&db, &o);
    ref_file_chunk(&db, 102, &o);
    assert!(
        !db.remove_chunk_from_index_if_unreferenced(&o).unwrap(),
        "referenced chunk must not be deleted"
    );
    assert!(row_exists(&db, &o));
}

#[test]
fn conditional_delete_removes_unreferenced_row() {
    let (db, _t) = setup_db();
    let o = oid(0xd4);
    seed_chunk_index(&db, &o);
    assert!(db.remove_chunk_from_index_if_unreferenced(&o).unwrap());
    assert!(!row_exists(&db, &o));
    // Idempotent: second call deletes nothing, reports false.
    assert!(!db.remove_chunk_from_index_if_unreferenced(&o).unwrap());
}

#[test]
fn conditional_delete_pins_queued_chunks() {
    // Adversarial review 2026-11-18: a chunk enqueued for cloud upload but not
    // yet referenced (async mode enqueues before the file_chunks commit) must
    // survive the gc conditional delete — deleting the row strands the queue
    // entry and fails the flush's ref validation.
    let (db, _t) = setup_db();
    let o = oid(0x31);
    seed_chunk_index(&db, &o);
    db.enqueue_upload(&o).unwrap();
    assert!(db.is_in_upload_queue(&o).unwrap());
    assert!(
        !db.remove_chunk_from_index_if_unreferenced(&o).unwrap(),
        "queued chunk must keep its index row"
    );
    assert!(row_exists(&db, &o));
    db.dequeue_upload(&o).unwrap();
    assert!(!db.is_in_upload_queue(&o).unwrap());
    assert!(db.remove_chunk_from_index_if_unreferenced(&o).unwrap());
    assert!(!row_exists(&db, &o));
}
