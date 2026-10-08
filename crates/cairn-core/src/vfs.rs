//! Non-FUSE virtual filesystem API for programmatic archive access.
//!
//! `Vfs` wraps [`CairnEngine`] and exposes the read-only subset of operations
//! needed to browse and extract archive contents without requiring FUSE or
//! root privileges. Useful for:
//!
//! - Libraries and GUIs that want to list/preview files
//! - Cross-platform restore (macOS, Windows, BSDs)
//! - Scripts that need to extract a single file without mounting
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn example() -> anyhow::Result<()> {
//! use cairn_core::vfs::Vfs;
//!
//! let vfs = Vfs::open("my_archive.db", "secret-password").await?;
//!
//! // List root directory
//! for entry in vfs.readdir(1).await? {
//!     println!("{} (ino={}, size={})", entry.name, entry.ino, entry.size);
//! }
//!
//! // Read a file entirely
//! let data = vfs.read_file(42).await?;
//! # Ok(())
//! # }
//! ```

use crate::CairnEngine;
use crate::types::FileType;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Metadata for a single directory entry, returned by [`Vfs::readdir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name (filename only, no path separator).
    pub name: String,
    /// Inode number.
    pub ino: u64,
    /// File type (regular, directory, symlink, etc.).
    pub kind: FileType,
    /// File size in bytes (0 for directories/symlinks).
    pub size: u64,
    /// Unix mode bits (permission + type).
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Last modification time (seconds since UNIX epoch).
    pub mtime_sec: i64,
    /// Last modification time (nanoseconds).
    pub mtime_nsec: u32,
    /// Hard-link count.
    pub nlink: u32,
}

/// A non-FUSE virtual filesystem for reading archive contents.
pub struct Vfs {
    engine: Arc<CairnEngine>,
}

impl Vfs {
    /// Open an archive database with a password and return a `Vfs` handle.
    ///
    /// This creates the full [`CairnEngine`] (connection pool, crypto context,
    /// chunk store) — expect ~100ms startup on a warm DB.
    pub async fn open(db_path: &str, password: &str) -> anyhow::Result<Self> {
        use secrecy::SecretString;

        let pwd = SecretString::new(password.to_string().into());
        let db = cairn_index::Db::new_with_tuning(
            db_path,
            Some(&pwd),
            &cairn_index::DbTuning::default(),
        )?;

        // Read archive configuration
        let crypto_algo = db
            .get_config("crypto_algo")?
            .unwrap_or_else(|| "aes-256-gcm".to_string());
        let comp_algo = db
            .get_config("comp_algo")?
            .unwrap_or_else(|| "zstd".to_string());
        // a corrupt config value should not fail the mount (that would
        // lock the operator out of a working archive), but it must not vanish
        // silently either — log the parse failure, then fall back to the default.
        let comp_level: i32 = db
            .get_config("comp_level")?
            .unwrap_or_else(|| "3".to_string())
            .parse()
            .unwrap_or_else(|e| {
                tracing::warn!("invalid comp_level in DB config: {e} — using default 3");
                3
            });
        let comp_min_ratio: i32 = db
            .get_config("comp_min_ratio")?
            .unwrap_or_else(|| "5".to_string())
            .parse()
            .unwrap_or_else(|e| {
                tracing::warn!("invalid comp_min_ratio in DB config: {e} — using default 5");
                5
            });
        let comp_min_size: usize = db
            .get_config("comp_min_size")?
            .unwrap_or_else(|| "64".to_string())
            .parse()
            .unwrap_or_else(|e| {
                tracing::warn!("invalid comp_min_size in DB config: {e} — using default 64");
                64
            });
        let no_comp_ext_str = db
            .get_config("no_comp_ext")?
            .unwrap_or_else(|| "jpg,jpeg,png,mp4,zip,gz,zst".to_string());
        let no_comp_ext: Vec<String> = no_comp_ext_str
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let dedup_secret_val = match db.get_config("dedup_secret")? {
            Some(v) => v,
            None => {
                anyhow::bail!("Archive missing dedup_secret — cannot compute chunk hashes");
            }
        };
        let dedup_secret_opt = Some(SecretString::new(dedup_secret_val.into()));

        let symmetric = db.get_config("pub_key")?.is_none();
        if !symmetric {
            anyhow::bail!("Vfs::open only supports symmetric (password) archives");
        }

        let pass = pwd.clone();
        let existing_wrapped_kek = match db.get_config("wrapped_kek")? {
            Some(hex_str) => Some(
                hex::decode(&hex_str).map_err(|e| anyhow::anyhow!("Corrupt wrapped_kek: {e}"))?,
            ),
            None => None,
        };

        let crypto = Arc::new(cairn_seal::CryptoCtx::new_symmetric(
            comp_level,
            comp_min_ratio,
            comp_algo,
            crypto_algo,
            dedup_secret_opt,
            false,
            comp_min_size,
            pass,
            existing_wrapped_kek,
        )?);

        let cache_dir = format!("{db_path}_cache");
        let store: Arc<dyn cairn_store::ChunkStore> =
            Arc::new(cairn_store::CairnStore::new(cache_dir, vec![], None));

        let engine = Arc::new(CairnEngine {
            db: Arc::new(db),
            cache_dir: String::new(),
            crypto,
            op: None,
            operators: vec![],
            store,
            raid_mode: "1".to_string(),
            skip_read_verify: false,
            force_remote_read: false,
            async_upload: false,
            auto_heal: false,
            no_comp_ext,
            write_buffers: Arc::new(dashmap::DashMap::new()),
            write_locks: dashmap::DashMap::new(),
            decrypted_chunk_cache: Arc::new(tokio::sync::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(256).unwrap_or_else(|| unreachable!()),
            ))),
            global_write_buffer_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            chunk_cache_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            last_index_hash: Default::default(),
            gc_running: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            write_buffer_inode_max: 16 * 1024 * 1024,
            write_buffer_global_max: 128 * 1024 * 1024,
            chunk_cache_max_bytes: 32 * 1024 * 1024,
            max_write: 1024 * 1024,
            max_file_size: 1024 * 1024 * 1024 * 1024,
            backup_stats: std::sync::Arc::new(crate::BackupStats::new()),
        });

        Ok(Self { engine })
    }

    /// Open an archive from a pre-built [`CairnEngine`].
    pub fn from_engine(engine: Arc<CairnEngine>) -> Self {
        Self { engine }
    }

    /// List directory contents. `ino` is the parent inode (1 = root).
    pub async fn readdir(&self, ino: u64) -> anyhow::Result<Vec<DirEntry>> {
        let db = self.engine.db.clone();
        let dentries = tokio::task::spawn_blocking(move || db.list_dentries(ino))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;

        let mut result = Vec::with_capacity(dentries.len());
        for (name_key, name_enc, entry_ino) in dentries {
            // --hide-names: decrypt the real name for display (no-op in normal
            // archives; opaque hash fallback without the private key).
            let name = self
                .engine
                .resolve_dentry_name(&name_key, name_enc.as_deref());
            if let Some((mode, uid, gid, size, nlink, mtime_sec, mtime_nsec)) =
                self.getattr_raw(entry_ino).await?
            {
                let kind = crate::types::mode_to_filetype(mode);
                result.push(DirEntry {
                    name,
                    ino: entry_ino,
                    kind,
                    size,
                    mode,
                    uid,
                    gid,
                    mtime_sec,
                    mtime_nsec,
                    nlink,
                });
            }
        }
        Ok(result)
    }

    /// Get file/directory metadata by inode.
    pub async fn getattr(&self, ino: u64) -> anyhow::Result<Option<DirEntry>> {
        match self.getattr_raw(ino).await? {
            Some((mode, uid, gid, size, nlink, mtime_sec, mtime_nsec)) => {
                let kind = crate::types::mode_to_filetype(mode);
                Ok(Some(DirEntry {
                    name: String::new(),
                    ino,
                    kind,
                    size,
                    mode,
                    uid,
                    gid,
                    mtime_sec,
                    mtime_nsec,
                    nlink,
                }))
            }
            None => Ok(None),
        }
    }

    /// Read the entire content of a file by inode.
    pub async fn read_file(&self, ino: u64) -> anyhow::Result<Vec<u8>> {
        self.engine
            .read_file_all(ino)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Inode {ino} has no data"))
    }

    /// Read a symlink target by inode.
    pub async fn readlink(&self, ino: u64) -> anyhow::Result<Vec<u8>> {
        self.engine
            .read_file_all(ino)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Symlink inode {ino} has no target"))
    }

    /// Resolve a path to an inode. Returns `None` if not found.
    /// Follows symlinks encountered during path traversal (POSIX semantics).
    pub async fn resolve_path(&self, path: &str) -> anyhow::Result<Option<u64>> {
        let mut current_path = path.to_owned();

        // Max symlink-follow iterations to prevent infinite loops.
        for _ in 0..40 {
            let parts: Vec<&str> = current_path.trim_start_matches('/').split('/').collect();
            if parts.is_empty() || (parts.len() == 1 && parts[0].is_empty()) {
                return Ok(Some(1)); // root
            }

            let mut current_ino = 1u64;
            let mut symlink_found = false;

            for (idx, part) in parts.iter().enumerate() {
                if part.is_empty() {
                    continue;
                }
                let db = self.engine.db.clone();
                let parent = current_ino;
                // --hide-names: dentries are keyed by the lookup key, so match the
                // path component's key (the name itself in normal archives).
                let key = self.engine.crypto.name_lookup_key(parent, part)?;
                let dentries = tokio::task::spawn_blocking(move || db.list_dentries(parent))
                    .await
                    .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;

                current_ino = match dentries.iter().find(|(n, _, _)| n == &key) {
                    Some((_, _, ino)) => *ino,
                    None => return Ok(None),
                };

                let inode_info = tokio::task::spawn_blocking({
                    let db = self.engine.db.clone();
                    move || db.get_inode(current_ino)
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;

                if let Some((mode, _, _, _, _, _, _)) = inode_info {
                    let file_type = mode & libc::S_IFMT;
                    if file_type == libc::S_IFLNK {
                        let target = self.readlink(current_ino).await?;
                        let target_str = std::str::from_utf8(&target)
                            .map_err(|e| anyhow::anyhow!("symlink target not UTF-8: {e}"))?;
                        if target_str.starts_with('/') {
                            current_path = target_str.to_owned();
                        } else {
                            let parent_path = format!("/{}", parts[..=idx].join("/"));
                            current_path = format!("{parent_path}/{target_str}");
                        }
                        symlink_found = true;
                        break;
                    }
                }
            }

            if !symlink_found {
                return Ok(Some(current_ino));
            }
            // Loop continues with new resolved path.
        }
        Err(anyhow::anyhow!(
            "resolve_path: too many symlink follows (possible loop)"
        ))
    }

    /// Extract all files to a destination directory.
    pub async fn extract_all(&self, dest_dir: &str, preserve_metadata: bool) -> anyhow::Result<()> {
        self.engine.extract_all(dest_dir, preserve_metadata).await
    }

    /// Extract a single file by archive path.
    pub async fn extract_file(
        &self,
        archive_path: &str,
        dest_dir: &str,
        preserve_metadata: bool,
    ) -> anyhow::Result<()> {
        self.engine
            .extract_single_file(archive_path, dest_dir, preserve_metadata)
            .await
    }

    /// Get the underlying engine (for advanced use).
    pub fn engine(&self) -> &Arc<CairnEngine> {
        &self.engine
    }

    /// Extract a file to a specific destination path.
    pub async fn extract_to(&self, ino: u64, dest: &Path) -> anyhow::Result<()> {
        self.engine.extract_file_to(ino, dest).await
    }

    async fn getattr_raw(
        &self,
        ino: u64,
    ) -> anyhow::Result<Option<(u32, u32, u32, u64, u32, i64, u32)>> {
        let db = self.engine.db.clone();
        tokio::task::spawn_blocking(move || db.get_inode(ino))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))?
    }
}

/// Utility: list all files in an archive recursively, returning (path, ino) pairs.
pub async fn walk_archive(vfs: &Vfs) -> anyhow::Result<Vec<(PathBuf, u64)>> {
    let mut result = Vec::new();
    let mut stack = vec![(1u64, PathBuf::from("/"))];

    while let Some((ino, path)) = stack.pop() {
        let entries = vfs.readdir(ino).await?;
        for entry in entries {
            let child_path = path.join(&entry.name);
            if entry.kind == FileType::Directory {
                stack.push((entry.ino, child_path.clone()));
            }
            result.push((child_path, entry.ino));
        }
    }
    Ok(result)
}
