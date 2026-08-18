// --hide-names — end-to-end tests for optional file-name hiding.
//
// These assert the actual SECURITY property (names are not stored in plaintext),
// not just that restore works — a completely broken hide that stored the
// plaintext in the lookup column would still pass a naive round-trip test.
//
// `db.list_dentries(parent)` returns the RAW on-disk columns
// `(name_key, name_enc, inode)` with no decryption — exactly what a host with
// the index password would read via sqlite3. We assert directly against those.

use cairn_core::CairnEngine;
use cairn_core::types::*;
use dashmap::DashMap;
use lru::LruCache;
use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tempfile::TempDir;
use tokio::sync::Mutex;

const NAME_SECRET: [u8; 32] = [7u8; 32];
const SECRET_NAME: &str = "secret_filename.txt";

/// Build an asymmetric (pub+priv) engine. When `hide_names` is set, the crypto
/// context hashes dentry lookup keys and age-encrypts the real names.
async fn setup_engine(hide_names: bool) -> (CairnEngine, TempDir) {
    setup_engine_opts(hide_names, true).await
}

/// Like [`setup_engine`] but `with_priv = false` builds a **public-key-only**
/// engine (the untrusted-backup-host view): it can write hidden names but cannot
/// decrypt them back, so `readdir`/`extract` see opaque hashes.
async fn setup_engine_opts(hide_names: bool, with_priv: bool) -> (CairnEngine, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let pub_path = temp_dir.path().join("pub.pem");
    let priv_path = temp_dir.path().join("priv.pem");
    use age::secrecy::ExposeSecret;
    let identity = age::x25519::Identity::generate();
    let priv_key_val = identity.to_string().expose_secret().to_string();
    let pub_key_str = identity.to_public().to_string();
    std::fs::write(&pub_path, pub_key_str).unwrap();
    std::fs::write(&priv_path, priv_key_val).unwrap();

    let db_path = temp_dir.path().join("test.db");
    let db = Arc::new(cairn_index::Db::new(db_path.to_str().unwrap(), None).unwrap());
    let cache_dir = temp_dir.path().join("cache").to_string_lossy().to_string();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let mut crypto_ctx = cairn_seal::CryptoCtx::new(
        pub_path.to_str().unwrap(),
        with_priv.then(|| priv_path.to_str().unwrap()),
        3,
        10,
        "zstd".to_string(),
        "chacha20".to_string(),
        None,
        true,
        1024,
    )
    .unwrap();
    if hide_names {
        crypto_ctx = crypto_ctx.with_hide_names(NAME_SECRET);
    }

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

/// Raw dentry row for `name` under `parent` as it is stored on disk (no decrypt).
fn raw_dentry(engine: &CairnEngine, parent: u64) -> Vec<(String, Option<Vec<u8>>, u64)> {
    engine.db.list_dentries(parent).unwrap()
}

/// Display names for `parent` via the engine's readdir (decrypts in hide mode),
/// excluding the synthetic `.` / `..` entries.
async fn readdir_names(engine: &CairnEngine, parent: u64) -> Vec<String> {
    engine
        .readdir(Request::default(), parent, 0, 0)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name.to_string_lossy().to_string())
        .filter(|n| n != "." && n != "..")
        .collect()
}

/// Same as [`readdir_names`] but through `readdirplus` (a distinct code path that
/// also carries attrs — it must decrypt names too).
async fn readdirplus_names(engine: &CairnEngine, parent: u64) -> Vec<String> {
    engine
        .readdirplus(Request::default(), parent, 0, 0, 0)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name.to_string_lossy().to_string())
        .filter(|n| n != "." && n != "..")
        .collect()
}

// ─── The core security property: no plaintext name on disk ───

#[tokio::test]
async fn test_hide_names_stores_no_plaintext() {
    let (engine, _dir) = setup_engine(true).await;
    engine
        .mknod(
            Request::default(),
            1,
            OsStr::new(SECRET_NAME),
            libc::S_IFREG | 0o644,
            0,
        )
        .await
        .unwrap();

    // On-disk: the lookup column is NOT the plaintext, and name_enc is present.
    let rows = raw_dentry(&engine, 1);
    assert_eq!(rows.len(), 1);
    let (name_key, name_enc, _ino) = &rows[0];
    assert_ne!(
        name_key, SECRET_NAME,
        "hide_names must NOT store the plaintext name in the lookup column"
    );
    assert!(
        name_enc.is_some(),
        "hide_names must store the write-only encrypted name (name_enc)"
    );
    // The plaintext must not appear anywhere in the encrypted blob either.
    let enc = name_enc.as_ref().unwrap();
    assert!(
        !enc.windows(SECRET_NAME.len())
            .any(|w| w == SECRET_NAME.as_bytes()),
        "plaintext name leaked into name_enc ciphertext"
    );

    // Functional: lookup by name still resolves (keyed-hash lookup), and readdir
    // decrypts the real name back with the private key.
    let looked = engine
        .lookup(Request::default(), 1, OsStr::new(SECRET_NAME))
        .await;
    assert!(looked.is_ok(), "keyed lookup must find the hidden entry");
    assert_eq!(
        readdir_names(&engine, 1).await,
        vec![SECRET_NAME.to_string()]
    );
}

// ─── Control: normal mode is byte-identical (plaintext IS stored) ───

#[tokio::test]
async fn test_normal_mode_stores_plaintext_control() {
    let (engine, _dir) = setup_engine(false).await;
    engine
        .mknod(
            Request::default(),
            1,
            OsStr::new(SECRET_NAME),
            libc::S_IFREG | 0o644,
            0,
        )
        .await
        .unwrap();

    let rows = raw_dentry(&engine, 1);
    assert_eq!(rows.len(), 1);
    let (name_key, name_enc, _ino) = &rows[0];
    assert_eq!(
        name_key, SECRET_NAME,
        "normal archives store the plaintext name (pass-through) — the control"
    );
    assert!(name_enc.is_none(), "normal archives leave name_enc NULL");
    assert_eq!(
        readdir_names(&engine, 1).await,
        vec![SECRET_NAME.to_string()]
    );
}

// ─── rename refreshes name_enc (no stale old name) ───

#[tokio::test]
async fn test_hide_names_rename_refreshes_name_enc() {
    let (engine, _dir) = setup_engine(true).await;
    engine
        .mknod(
            Request::default(),
            1,
            OsStr::new("old.txt"),
            libc::S_IFREG | 0o644,
            0,
        )
        .await
        .unwrap();
    engine
        .rename(
            Request::default(),
            1,
            OsStr::new("old.txt"),
            1,
            OsStr::new("new.txt"),
        )
        .await
        .unwrap();

    // Old name no longer resolves; new name does.
    assert!(
        engine
            .lookup(Request::default(), 1, OsStr::new("old.txt"))
            .await
            .is_err(),
        "old name must not resolve after rename"
    );
    assert!(
        engine
            .lookup(Request::default(), 1, OsStr::new("new.txt"))
            .await
            .is_ok(),
        "new name must resolve after rename"
    );
    // readdir shows the NEW name only — proving name_enc was refreshed, not stale.
    assert_eq!(readdir_names(&engine, 1).await, vec!["new.txt".to_string()]);
    // And the raw stored name is still a hash, not plaintext.
    let rows = raw_dentry(&engine, 1);
    assert_eq!(rows.len(), 1);
    assert_ne!(rows[0].0, "new.txt");
    assert!(rows[0].1.is_some());
}

// ─── corrupt name_enc with the private key present → degrade, don't panic ───

#[tokio::test]
async fn test_hide_names_corrupt_name_enc_degrades_to_hash() {
    let (engine, _dir) = setup_engine(true).await;
    // Insert a dentry directly with a valid inode but a deliberately corrupt
    // name_enc (version byte 1 followed by garbage that cannot age-decrypt). The
    // "name" column stands in for the keyed-hash lookup key.
    let bogus_key = "deadbeefdeadbeefdeadbeefdeadbeef";
    let corrupt_enc = [1u8, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
    engine
        .db
        .insert_inode_with_dentry(
            libc::S_IFREG | 0o644,
            0,
            0,
            0,
            1,
            1,
            bogus_key,
            Some(&corrupt_enc),
        )
        .unwrap();

    // The private key IS loaded, so this is real corruption — resolve_dentry_name
    // must fall back to the opaque hash (logged) rather than panic or drop the entry.
    assert!(engine.crypto.has_private_key());
    let names = readdir_names(&engine, 1).await;
    assert_eq!(
        names,
        vec![bogus_key.to_string()],
        "corrupt name_enc must degrade to the lookup-key hash, not vanish or panic"
    );
}

// ─── extract: on-disk restore reconstructs the real names through a subtree ───

#[tokio::test]
async fn test_hide_names_extract_reconstructs_real_paths() {
    let (engine, dir) = setup_engine(true).await;
    let req = Request::default();

    // docs/report.txt with real content.
    let docs = engine
        .mkdir(req.clone(), 1, OsStr::new("docs"), 0o755, 0)
        .await
        .unwrap();
    let docs_ino = docs.attr.ino;
    let file = engine
        .mknod(
            req.clone(),
            docs_ino,
            OsStr::new("report.txt"),
            libc::S_IFREG | 0o644,
            0,
        )
        .await
        .unwrap();
    let content = b"top secret quarterly numbers";
    let fh = engine.open(req.clone(), file.attr.ino, 0).await.unwrap().0;
    engine
        .write(req.clone(), file.attr.ino, fh, 0, content, 0, 0)
        .await
        .unwrap();
    // Flush the write buffer to committed chunks so extract sees the content.
    engine
        .release(req.clone(), file.attr.ino, fh, 0, 0, true)
        .await
        .unwrap();

    // On disk, neither the dir nor the file name is stored in plaintext.
    assert_ne!(raw_dentry(&engine, 1)[0].0, "docs");
    assert_ne!(raw_dentry(&engine, docs_ino)[0].0, "report.txt");

    // Extract with the private key present → real names/paths on disk.
    let out = dir.path().join("restore");
    engine
        .extract_all(out.to_str().unwrap(), false)
        .await
        .unwrap();
    let restored = out.join("docs").join("report.txt");
    assert!(
        restored.is_file(),
        "extract must recreate docs/report.txt by its real name"
    );
    assert_eq!(std::fs::read(&restored).unwrap(), content);
}

// ─── hardlink: both names carry their own encrypted name ───

#[tokio::test]
async fn test_hide_names_hardlink_both_names_hidden() {
    let (engine, _dir) = setup_engine(true).await;
    let reply = engine
        .mknod(
            Request::default(),
            1,
            OsStr::new("a.txt"),
            libc::S_IFREG | 0o644,
            0,
        )
        .await
        .unwrap();
    let ino = reply.attr.ino;
    engine
        .link(Request::default(), ino, 1, OsStr::new("b.txt"))
        .await
        .unwrap();

    let mut names = readdir_names(&engine, 1).await;
    names.sort();
    assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);

    // Both dentries point at the same inode, and neither stores plaintext.
    let rows = raw_dentry(&engine, 1);
    assert_eq!(rows.len(), 2);
    for (name_key, name_enc, dentry_ino) in &rows {
        assert_eq!(*dentry_ino, ino, "both hardlink names share one inode");
        assert_ne!(name_key, "a.txt");
        assert_ne!(name_key, "b.txt");
        assert!(name_enc.is_some());
    }
}

// ─── unlink removes the hidden entry (delete-by-keyed-lookup) ───

#[tokio::test]
async fn test_hide_names_unlink_removes_hidden_entry() {
    let (engine, _dir) = setup_engine(true).await;
    let req = Request::default();
    engine
        .mknod(
            req.clone(),
            1,
            OsStr::new("gone.txt"),
            libc::S_IFREG | 0o644,
            0,
        )
        .await
        .unwrap();
    // unlink must resolve the keyed lookup key, not the plaintext, to find the row.
    engine
        .unlink(req.clone(), 1, OsStr::new("gone.txt"))
        .await
        .unwrap();
    assert!(
        engine
            .lookup(req.clone(), 1, OsStr::new("gone.txt"))
            .await
            .is_err(),
        "unlinked hidden entry must not resolve"
    );
    assert!(
        readdir_names(&engine, 1).await.is_empty(),
        "directory must be empty after unlink"
    );
    assert!(raw_dentry(&engine, 1).is_empty(), "dentry row must be gone");
}

// ─── rmdir removes an empty hidden dir; refuses a non-empty one ───

#[tokio::test]
async fn test_hide_names_rmdir_empty_and_notempty() {
    let (engine, _dir) = setup_engine(true).await;
    let req = Request::default();
    // Non-empty dir → rmdir must refuse (ENOTEMPTY), proving the keyed lookup +
    // emptiness check both work on hashed names.
    let d = engine
        .mkdir(req.clone(), 1, OsStr::new("full"), 0o755, 0)
        .await
        .unwrap();
    engine
        .mknod(
            req.clone(),
            d.attr.ino,
            OsStr::new("child"),
            libc::S_IFREG | 0o644,
            0,
        )
        .await
        .unwrap();
    let err = engine
        .rmdir(req.clone(), 1, OsStr::new("full"))
        .await
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOTEMPTY));

    // Empty dir → rmdir succeeds and the entry disappears.
    engine
        .mkdir(req.clone(), 1, OsStr::new("empty"), 0o755, 0)
        .await
        .unwrap();
    engine
        .rmdir(req.clone(), 1, OsStr::new("empty"))
        .await
        .unwrap();
    let names = readdir_names(&engine, 1).await;
    assert_eq!(
        names,
        vec!["full".to_string()],
        "only the non-empty dir remains, by its real name"
    );
}

// ─── symlink: NAME hidden, TARGET still readable (target rides the content path) ───

#[tokio::test]
async fn test_hide_names_symlink_name_hidden_target_readable() {
    let (engine, _dir) = setup_engine(true).await;
    let req = Request::default();
    let reply = engine
        .symlink(
            req.clone(),
            1,
            OsStr::new("link.lnk"),
            OsStr::new("/etc/passwd"),
        )
        .await
        .unwrap();

    // The symlink NAME is hidden on disk, decrypted for readdir.
    assert_ne!(raw_dentry(&engine, 1)[0].0, "link.lnk");
    assert!(raw_dentry(&engine, 1)[0].1.is_some());
    assert_eq!(
        readdir_names(&engine, 1).await,
        vec!["link.lnk".to_string()]
    );

    // The TARGET is content (age-encrypted to the pub key) — readable with priv.
    let target = engine.readlink(req.clone(), reply.attr.ino).await.unwrap();
    assert_eq!(target, b"/etc/passwd");
}

// ─── readdirplus decrypts names too (separate code path from readdir) ───

#[tokio::test]
async fn test_hide_names_readdirplus_decrypts() {
    let (engine, _dir) = setup_engine(true).await;
    let req = Request::default();
    for n in ["alpha.txt", "beta.txt"] {
        engine
            .mknod(req.clone(), 1, OsStr::new(n), libc::S_IFREG | 0o644, 0)
            .await
            .unwrap();
    }
    let mut names = readdirplus_names(&engine, 1).await;
    names.sort();
    assert_eq!(names, vec!["alpha.txt".to_string(), "beta.txt".to_string()]);
}

// ─── public-key-only host: names are opaque hashes, no panic, no error log ───

#[tokio::test]
async fn test_hide_names_pub_only_shows_hashes() {
    // A pub-only engine can WRITE hidden names but has no private key to read them.
    let (engine, _dir) = setup_engine_opts(true, false).await;
    assert!(!engine.crypto.has_private_key());
    engine
        .mknod(
            Request::default(),
            1,
            OsStr::new("private.txt"),
            libc::S_IFREG | 0o644,
            0,
        )
        .await
        .unwrap();

    // readdir cannot decrypt → shows the opaque lookup hash, never the real name.
    let names = readdir_names(&engine, 1).await;
    assert_eq!(names.len(), 1);
    assert_ne!(
        names[0], "private.txt",
        "pub-only host must not see the real name"
    );
    assert_eq!(
        names[0],
        raw_dentry(&engine, 1)[0].0,
        "display == stored lookup hash"
    );
}

// ─── selective extract (single file by path + glob) resolves through hashes ───

#[tokio::test]
async fn test_hide_names_selective_extract() {
    let (engine, dir) = setup_engine(true).await;
    let req = Request::default();
    let sub = engine
        .mkdir(req.clone(), 1, OsStr::new("dir"), 0o755, 0)
        .await
        .unwrap();
    for (parent, name, body) in [
        (1u64, "top.txt", b"T".as_slice()),
        (sub.attr.ino, "inner.log", b"I".as_slice()),
    ] {
        let r = engine
            .mknod(
                req.clone(),
                parent,
                OsStr::new(name),
                libc::S_IFREG | 0o644,
                0,
            )
            .await
            .unwrap();
        let fh = engine.open(req.clone(), r.attr.ino, 0).await.unwrap().0;
        engine
            .write(req.clone(), r.attr.ino, fh, 0, body, 0, 0)
            .await
            .unwrap();
        engine
            .release(req.clone(), r.attr.ino, fh, 0, 0, true)
            .await
            .unwrap();
    }

    // extract_single_file resolves each path component through its keyed hash.
    let single = dir.path().join("single");
    engine
        .extract_single_file("/dir/inner.log", single.to_str().unwrap(), false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(single.join("inner.log")).unwrap(), b"I");

    // extract_matching globs against the DECRYPTED names.
    let glob = dir.path().join("glob");
    engine
        .extract_matching("/*.txt", glob.to_str().unwrap(), false)
        .await
        .unwrap();
    assert!(
        glob.join("top.txt").is_file(),
        "glob must match the decrypted name"
    );
    assert!(
        !glob.join("dir").join("inner.log").exists(),
        "glob must not pull the non-matching file"
    );
}
