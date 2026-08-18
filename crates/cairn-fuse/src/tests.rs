use super::*;
use cairn_core::types::{FileAttr as NeutralFileAttr, FileType as NeutralFileType};
use fuse3::raw::Request;
use std::ffi::OsStr;
use std::io;
use std::time::{Duration, SystemTime};

#[test]
fn test_map_err() {
    let err = io::Error::from_raw_os_error(libc::ENOENT);
    assert_eq!(map_err(err), Errno::from(libc::ENOENT));

    let err_other = io::Error::other("test");
    assert_eq!(map_err(err_other), Errno::from(libc::EIO));
}

#[test]
fn test_map_time() {
    let now =
        SystemTime::UNIX_EPOCH + Duration::from_secs(1234567890) + Duration::from_nanos(123456789);
    let mapped = map_time(now);
    assert_eq!(mapped.sec, 1234567890);
    assert_eq!(mapped.nsec, 123456789);
}

#[test]
fn test_map_req() {
    let fuse_req = Request {
        unique: 0,
        uid: 1000,
        gid: 1000,
        pid: 1234,
    };
    let mapped = map_req(&fuse_req);
    assert_eq!(mapped.uid, 1000);
    assert_eq!(mapped.gid, 1000);
    assert_eq!(mapped.pid, 1234);
}

#[test]
fn test_map_attr_kinds() {
    let mut attr = NeutralFileAttr {
        ino: 42,
        size: 1024,
        blocks: 2,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: NeutralFileType::Directory,
        perm: 0o644,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        flags: 0,
        blksize: 4096,
    };

    attr.kind = NeutralFileType::Directory;
    assert_eq!(map_attr(attr.clone()).kind, fuse3::FileType::Directory);

    attr.kind = NeutralFileType::Symlink;
    assert_eq!(map_attr(attr.clone()).kind, fuse3::FileType::Symlink);

    attr.kind = NeutralFileType::BlockDevice;
    assert_eq!(map_attr(attr.clone()).kind, fuse3::FileType::BlockDevice);

    attr.kind = NeutralFileType::CharDevice;
    assert_eq!(map_attr(attr.clone()).kind, fuse3::FileType::CharDevice);

    attr.kind = NeutralFileType::NamedPipe;
    assert_eq!(map_attr(attr.clone()).kind, fuse3::FileType::NamedPipe);

    attr.kind = NeutralFileType::Socket;
    assert_eq!(map_attr(attr.clone()).kind, fuse3::FileType::Socket);
}

fn create_dummy_engine() -> (cairn_core::CairnEngine, tempfile::TempDir) {
    // file-backed DB — a pooled `:memory:` SQLite DB is per-connection, so
    // the multi-op integration test below (mkdir, getattr, ...) intermittently
    // hits a fresh empty connection and flakes.
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db = std::sync::Arc::new(cairn_index::Db::new(db_path.to_str().unwrap(), None).unwrap());
    let crypto = std::sync::Arc::new(
        cairn_seal::CryptoCtx::new_symmetric(
            1,
            0,
            "lz4".to_string(),
            "aes256gcm".to_string(),
            None,
            true,
            4096,
            secrecy::SecretString::from("testpass".to_string()),
            None,
        )
        .unwrap(),
    );
    let cache_dir = temp_dir.path().join("cache").to_string_lossy().to_string();
    let store = std::sync::Arc::new(cairn_store::CairnStore::new(
        cache_dir.clone(),
        vec![],
        None,
    ));

    let engine = cairn_core::CairnEngine {
        db,
        cache_dir,
        crypto,
        store,
        op: None,
        operators: vec![],
        raid_mode: "raid0".to_string(),
        skip_read_verify: false,
        force_remote_read: false,
        async_upload: false,
        auto_heal: false,
        write_buffers: std::sync::Arc::new(dashmap::DashMap::new()),
        last_index_hash: Default::default(),
        no_comp_ext: vec![],
        write_locks: dashmap::DashMap::new(),
        decrypted_chunk_cache: std::sync::Arc::new(tokio::sync::Mutex::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(256).unwrap(),
        ))),
        global_write_buffer_bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        chunk_cache_bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        write_buffer_inode_max: cairn_core::DEFAULT_WRITE_BUFFER_INODE_MAX,
        write_buffer_global_max: cairn_core::DEFAULT_WRITE_BUFFER_GLOBAL_MAX,
        chunk_cache_max_bytes: cairn_core::DEFAULT_CHUNK_CACHE_MAX_BYTES,
        max_write: cairn_core::DEFAULT_MAX_WRITE,
        max_file_size: cairn_core::DEFAULT_MAX_FILE_SIZE,
        backup_stats: std::sync::Arc::new(cairn_core::BackupStats::new()),
        gc_running: std::sync::Arc::new(tokio::sync::Mutex::new(())),
    };
    (engine, temp_dir)
}

#[tokio::test]
async fn test_cairnfs_integration() {
    let (engine, _dir) = create_dummy_engine();
    let fs = CairnFs(engine);
    let req = Request {
        unique: 0,
        uid: 1000,
        gid: 1000,
        pid: 1,
    };

    // 1. init
    let init_reply = fs.init(req).await.unwrap();
    assert_eq!(init_reply.max_write.get(), 1024 * 1024);

    // 2. mkdir
    let dir_name = OsStr::new("testdir");
    let mkdir_reply = fs.mkdir(req, 1, dir_name, 0o755, 0).await.unwrap();
    let dir_ino = mkdir_reply.attr.ino;
    assert!(dir_ino > 1);

    // 3. getattr on dir
    let getattr_reply = fs.getattr(req, dir_ino, None, 0).await.unwrap();
    assert_eq!(getattr_reply.attr.ino, dir_ino);

    // 4. mknod
    let file_name = OsStr::new("testfile.txt");
    let mknod_reply = fs
        .mknod(req, dir_ino, file_name, libc::S_IFREG | 0o644, 0)
        .await
        .unwrap();
    let file_ino = mknod_reply.attr.ino;
    assert!(file_ino > 1);

    // 5. lookup
    let lookup_reply = fs.lookup(req, dir_ino, file_name).await.unwrap();
    assert_eq!(lookup_reply.attr.ino, file_ino);

    // 6. open
    let open_reply = fs.open(req, file_ino, libc::O_RDWR as u32).await.unwrap();
    let fh = open_reply.fh;

    // 7. write
    let write_data = b"hello world";
    let write_reply = fs
        .write(req, file_ino, fh, 0, write_data, 0, 0)
        .await
        .unwrap();
    assert_eq!(write_reply.written, write_data.len() as u32);

    // 8. read
    let read_reply = fs.read(req, file_ino, fh, 0, 100).await.unwrap();
    assert_eq!(read_reply.data.as_ref(), write_data);

    // 9. setattr
    let set_attr = SetAttr {
        mode: Some(0o600),
        uid: None,
        gid: None,
        size: None,
        atime: None,
        mtime: None,
        ctime: None,
        lock_owner: None,
    };
    let setattr_reply = fs.setattr(req, file_ino, Some(fh), set_attr).await.unwrap();
    assert_eq!(setattr_reply.attr.perm, 0o600);

    // 10. fsync
    fs.fsync(req, file_ino, fh, false).await.unwrap();

    // 11. fallocate (might return ENOSYS depending on engine, just checking map_err or Ok)
    let _ = fs.fallocate(req, file_ino, fh, 0, 100, 0).await;

    // 12. copy_file_range (create second file)
    let file_name2 = OsStr::new("testfile2.txt");
    let mknod_reply2 = fs
        .mknod(req, dir_ino, file_name2, libc::S_IFREG | 0o644, 0)
        .await
        .unwrap();
    let file_ino2 = mknod_reply2.attr.ino;
    let open_reply2 = fs.open(req, file_ino2, libc::O_RDWR as u32).await.unwrap();
    let fh2 = open_reply2.fh;
    let _ = fs
        .copy_file_range(req, file_ino, fh, 0, file_ino2, fh2, 0, 5, 0)
        .await;
    fs.release(req, file_ino2, fh2, 0, 0, false).await.unwrap();

    // 13. release
    fs.release(req, file_ino, fh, 0, 0, false).await.unwrap();

    // 14. readdir
    use futures::StreamExt;
    let readdir_reply = fs.readdir(req, dir_ino, 0, 0).await.unwrap();
    let entries: Vec<_> = readdir_reply.entries.collect().await;
    assert!(!entries.is_empty());

    // 15. readdirplus
    let readdirplus_reply = fs.readdirplus(req, dir_ino, 0, 0, 0).await.unwrap();
    let entries_plus: Vec<_> = readdirplus_reply.entries.collect().await;
    assert!(!entries_plus.is_empty());

    // 16. link
    let link_name = OsStr::new("link.txt");
    let link_reply = fs.link(req, file_ino, dir_ino, link_name).await.unwrap();
    assert_eq!(link_reply.attr.ino, file_ino);

    // 17. symlink
    let symlink_name = OsStr::new("symlink.txt");
    let symlink_target = OsStr::new("");
    let symlink_reply = fs
        .symlink(req, dir_ino, symlink_name, symlink_target)
        .await
        .unwrap();
    let sym_ino = symlink_reply.attr.ino;

    // 18. readlink
    let readlink_reply = fs.readlink(req, sym_ino).await.unwrap();
    assert_eq!(readlink_reply.data.as_ref(), b"");

    // 19. xattr
    let xattr_name = OsStr::new("user.test");
    let xattr_val = b"xattr_value";
    let _ = fs
        .setxattr(req, file_ino, xattr_name, xattr_val, 0, 0)
        .await;
    let _ = fs.getxattr(req, file_ino, xattr_name, 100).await;
    let _ = fs.listxattr(req, file_ino, 100).await;
    let _ = fs.removexattr(req, file_ino, xattr_name).await;

    // 20. rename
    let rename_new_name = OsStr::new("renamed.txt");
    fs.rename(req, dir_ino, file_name, dir_ino, rename_new_name)
        .await
        .unwrap();

    // 21. unlink
    fs.unlink(req, dir_ino, rename_new_name).await.unwrap();
    fs.unlink(req, dir_ino, link_name).await.unwrap();
    fs.unlink(req, dir_ino, symlink_name).await.unwrap();
    fs.unlink(req, dir_ino, file_name2).await.unwrap();

    // 22. rmdir
    fs.rmdir(req, 1, dir_name).await.unwrap();

    // 23. destroy
    fs.destroy(req).await;
}
