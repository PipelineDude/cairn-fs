// Regression tests for index-layer fixes from the audit history. Each guards a
// documented bug and exercises an error/edge branch the happy-path suite misses.

use cairn_index::{Db, XattrError, XattrFlag};
use tempfile::TempDir;

fn db() -> (Db, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::new(dir.path().join("t.db").to_str().unwrap(), None).unwrap();
    (db, dir)
}

fn new_file(db: &Db, name: &str) -> u64 {
    db.insert_inode_with_dentry(libc::S_IFREG | 0o644, 0, 0, 0, 1, 1, name, None)
        .unwrap()
}

// increment_nlink is a single conditional UPDATE; a 0-row result (missing
// inode or nlink at the ceiling) is a hard error, not a silent no-op.
#[test]
fn test_increment_nlink_missing_inode_errors() {
    let (db, _d) = db();
    assert!(
        db.increment_nlink(987_654).is_err(),
        "increment_nlink on a missing inode must error"
    );
    // sanity: it succeeds on a real inode
    let ino = new_file(&db, "f");
    assert!(db.increment_nlink(ino).is_ok());
}

// XATTR_CREATE on an existing attr → AlreadyExists; XATTR_REPLACE on a
// missing attr → NotFound. (The existence probe must not swallow the flag logic.)
#[test]
fn test_set_xattr_flag_semantics() {
    let (db, _d) = db();
    let ino = new_file(&db, "f");

    db.set_xattr_with_flags(ino, "user.a", b"1", XattrFlag::None)
        .expect("plain set should succeed");

    match db.set_xattr_with_flags(ino, "user.a", b"2", XattrFlag::Create) {
        Err(XattrError::AlreadyExists(_)) => {}
        other => panic!("Create on an existing attr should be AlreadyExists, got {other:?}"),
    }
    match db.set_xattr_with_flags(ino, "user.absent", b"x", XattrFlag::Replace) {
        Err(XattrError::NotFound(_)) => {}
        other => panic!("Replace on a missing attr should be NotFound, got {other:?}"),
    }
    // Replace on the existing one succeeds and overwrites.
    db.set_xattr_with_flags(ino, "user.a", b"2", XattrFlag::Replace)
        .expect("Replace on an existing attr should succeed");
    assert_eq!(
        db.get_xattr(ino, "user.a").unwrap().as_deref(),
        Some(&b"2"[..])
    );
}
// (delete_inode's extended_attrs cleanup is a crate-internal path;
// its regression test lives in the inline `#[cfg(test)] mod tests` in lib.rs.)
