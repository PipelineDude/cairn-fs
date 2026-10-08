// L04: races between pin (upload_queue), commit (file_chunks reference) and GC
// ack. Invariant asserted under a barrier + concurrent scans: an object is
// NEVER collectable while EITHER the pin is held OR a committed reference
// exists — the pin→commit hand-off has no "neither" window even when the
// dequeue happens right after the reference lands. Only after BOTH are gone
// does `get_orphaned_chunks` return it (honest GC, not silent data loss).
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use cairn_index::Db;

const OID: &str = "l04-object-1";
const INODE: u64 = 1; // first inserted inode auto-ids to 1

fn setup_db(dir: &tempfile::TempDir) -> Arc<Db> {
    let path = dir.path().join("l04.db");
    let db = Arc::new(Db::new(path.to_str().unwrap(), None).unwrap());
    db.insert_chunk_indices_batch(&[(
        OID.to_string(),
        "ph".to_string(),
        vec![],
        0,
        "none".to_string(),
    )])
    .unwrap();
    // The file_chunks FK needs a real inode; insert a minimal one.
    db.pool
        .get()
        .unwrap()
        .execute(
            "INSERT INTO inodes (mode, uid, gid, mtime_sec, mtime_nsec, size, nlink, rdev)
             VALUES (33188, 1000, 1000, 0, 0, 0, 1, 0)",
            [],
        )
        .unwrap();
    // Age the row so it WOULD be collectable if nothing protects it.
    db.pool
        .get()
        .unwrap()
        .execute(
            "UPDATE chunk_index SET created_at = strftime('%s','now') - 7200 WHERE object_id = ?1",
            [OID],
        )
        .unwrap();
    db
}

fn orphan_has(db: &Db, oid: &str) -> bool {
    db.get_orphaned_chunks(0).unwrap().iter().any(|o| o == oid)
}

fn drop_reference(db: &Db) {
    db.pool
        .get()
        .unwrap()
        .execute(
            "DELETE FROM file_chunks WHERE inode = ?1 AND object_id = ?2",
            rusqlite::params![INODE, OID],
        )
        .unwrap();
}

#[test]
fn pin_then_commit_never_leaves_a_collectable_window_under_concurrency() {
    let dir = tempfile::tempdir().unwrap();
    let db = setup_db(&dir);

    // State 1: pinned only → NOT collectable.
    db.enqueue_upload(OID).unwrap();
    assert!(!orphan_has(&db, OID), "pinned object must not be orphaned");

    // State 2: reference committed while still pinned → NOT collectable.
    db.insert_file_chunk(INODE, 0, OID, 64, 0).unwrap();
    assert!(
        !orphan_has(&db, OID),
        "referenced+pinned must not be orphaned"
    );

    // State 3: pin released, reference still held → STILL not collectable.
    db.dequeue_upload(OID).unwrap();
    assert!(
        !orphan_has(&db, OID),
        "referenced object must not be orphaned"
    );

    // State 4: reference removed AND pin gone → collectable (honest GC).
    drop_reference(&db);
    assert!(
        orphan_has(&db, OID),
        "unprotected old object must be collectable"
    );

    // The RACE loop: thread A performs the pin→commit hand-off (reference
    // INSERT then dequeue) while thread B scans orphans concurrently behind a
    // barrier. Every serialization point of SQLite must still exclude the
    // object — it is pinned, referenced, or both at every instant.
    for round in 0..40 {
        // Reset both protections for the next hand-off.
        db.insert_file_chunk(INODE, 0, OID, 64, 0).unwrap();
        db.enqueue_upload(OID).unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let barrier_a = barrier.clone();
        let barrier_b = barrier.clone();
        let db_a = db.clone();
        let db_b = db.clone();
        let done = Arc::new(AtomicBool::new(false));
        let done_b = done.clone();

        let a = thread::spawn(move || {
            db_a.insert_file_chunk(INODE, 0, OID, 64, 0).unwrap();
            barrier_a.wait();
            db_a.dequeue_upload(OID).unwrap();
            done.store(true, Ordering::SeqCst);
        });
        let b = thread::spawn(move || {
            barrier_b.wait();
            let mut under_race = false;
            while !done_b.load(Ordering::SeqCst) {
                if orphan_has(&db_b, OID) {
                    under_race = true;
                }
                thread::yield_now();
            }
            // Final scan after A finished (reference still held) must also miss.
            if orphan_has(&db_b, OID) {
                under_race = true;
            }
            under_race
        });

        a.join().unwrap();
        let under_race = b.join().unwrap();
        assert!(
            !under_race,
            "round {round}: object became collectable during pin→commit hand-off"
        );

        // Reference still held after the pin release in A → still safe…
        assert!(
            !orphan_has(&db, OID),
            "round {round}: reference must protect after dequeue"
        );
        // …and only after the reference is dropped does GC see it.
        drop_reference(&db);
        assert!(
            orphan_has(&db, OID),
            "round {round}: release must enable GC"
        );
    }
}
