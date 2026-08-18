// The engine methods are now inherent (were fuse3::Filesystem trait methods) and keep
// the trait's argument shapes verbatim, so several exceed clippy's 7-arg threshold.
#![allow(clippy::too_many_arguments)]

pub mod maintenance;
pub mod manifest;
pub mod metrics;
pub mod restore;
pub mod types;
pub mod vfs;
#[cfg(feature = "cloud-storage")]
pub use crate::manifest::restore_index_from_cloud;
pub use crate::manifest::{Manifest, ManifestChunk};
pub use crate::metrics::{BackupStats, BackupStatsDelta, BackupStatsSnapshot, human_bytes};
use crate::types::{
    DirectoryEntry, DirectoryEntryPlus, EngineReplyEntry, FileAttr, FileType, Request, SetAttr,
    mode_to_filetype,
};
use std::ffi::OsStr;

use std::time::Duration;

const TTL: Duration = Duration::from_secs(1);

/// filesystem statistics for `statfs`/`df`. Plain struct (cairn-core stays
/// fuse3-free); the cairn-fuse adapter maps it to `fuse3`'s `ReplyStatFs`.
#[derive(Debug, Clone, Copy)]
pub struct EngineStatFs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

/// Free bytes on the filesystem backing `path` (the local chunk cache), via
/// `statvfs(3)`. Returns None if the syscall fails.
#[allow(unsafe_code)]
fn statvfs_free_bytes(path: &str) -> Option<u64> {
    let cpath = std::ffi::CString::new(path).ok()?;
    // SAFETY: `buf` is a valid, correctly-sized statvfs out-param; `cpath` is a
    // valid NUL-terminated C string. We only read the returned fields on success.
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(cpath.as_ptr(), &mut buf) };
    if rc != 0 {
        return None;
    }
    Some((buf.f_bavail as u64).saturating_mul(buf.f_frsize as u64))
}

static LOCAL_FLUSH_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Default per-inode write-buffer flush threshold (16 MB). See `CairnEngine::write_buffer_inode_max`.
pub const DEFAULT_WRITE_BUFFER_INODE_MAX: usize = 16 * 1024 * 1024;
/// Default global write-buffer budget across all inodes (128 MB). See `CairnEngine::write_buffer_global_max`.
pub const DEFAULT_WRITE_BUFFER_GLOBAL_MAX: usize = 128 * 1024 * 1024;
/// Default byte budget for the decrypted chunk LRU cache (32 MB). See `CairnEngine::chunk_cache_max_bytes`.
pub const DEFAULT_CHUNK_CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Default maximum FUSE read/write payload size (1 MiB). Larger values increase
/// throughput but also raise the worst-case RAM allocated per `read` call.
pub const DEFAULT_MAX_WRITE: u32 = 1024 * 1024;
/// Default maximum single-file size (1 TiB). Prevents unbounded hole creation
/// via sparse writes. Configurable via `--max-file-size-gib`.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024;
/// files smaller than or equal to this threshold are stored
/// as inline BLOBs in the `inodes` table, bypassing the CDC chunker. This
/// prevents data loss when FastCDC's minimum chunk size (16 KiB) causes
/// sub-threshold writes to produce chunks that overwrite the inline blob.
/// At 4 KiB the inline path avoids chunker overhead and store I/O for tiny
/// files (configs, metadata, small source files).
const INLINE_THRESHOLD: usize = 4096;
/// `DEFAULT_MAX_WRITE` as a `NonZeroU32`, verified at compile time.
pub const DEFAULT_MAX_WRITE_NZ: std::num::NonZeroU32 =
    match std::num::NonZeroU32::new(DEFAULT_MAX_WRITE) {
        Some(n) => n,
        None => panic!("DEFAULT_MAX_WRITE must be non-zero"),
    };

#[derive(Clone)]
pub struct CairnEngine {
    pub db: std::sync::Arc<cairn_index::Db>,
    pub cache_dir: String,
    pub crypto: std::sync::Arc<cairn_seal::CryptoCtx>,
    pub store: std::sync::Arc<dyn cairn_store::ChunkStore>,
    #[cfg_attr(not(feature = "cloud-storage"), allow(dead_code))]
    pub op: Option<cairn_store::CloudOperator>,
    pub operators: Vec<cairn_store::CloudOperator>,
    pub raid_mode: String,
    pub skip_read_verify: bool,
    /// When true, `fetch_chunk` bypasses the local cacache and reads from cloud
    /// backends only (on-host verify with a warm cache is not offsite proof).
    /// Wired from `verify`/`check`/`scrub --force-remote`.
    pub force_remote_read: bool,
    pub async_upload: bool,
    pub auto_heal: bool,
    pub no_comp_ext: Vec<String>,
    pub last_index_hash: std::sync::Arc<parking_lot::Mutex<[u8; 32]>>,
    /// advisory lock to prevent concurrent GC runs.
    pub gc_running: std::sync::Arc<tokio::sync::Mutex<()>>,
    // Value is Arc<Mutex<..>> (not bare Mutex) so callers clone the Arc out and
    // drop the DashMap shard guard BEFORE `.lock().await`. Holding a DashMap
    // Ref/RefMut across an await deadlocks (parking_lot shard lock pinned by a
    // suspended task) — same pattern `write_locks` already uses correctly.
    pub write_buffers: std::sync::Arc<
        dashmap::DashMap<u64, std::sync::Arc<tokio::sync::Mutex<crate::FileWriteState>>>,
    >,
    pub write_locks: dashmap::DashMap<u64, std::sync::Arc<tokio::sync::Mutex<()>>>,
    pub decrypted_chunk_cache:
        std::sync::Arc<tokio::sync::Mutex<lru::LruCache<String, zeroize::Zeroizing<Vec<u8>>>>>,
    /// Tracks total bytes across all write buffers for backpressure.
    pub global_write_buffer_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Tracks total bytes in the decrypted chunk cache for byte-budget eviction.
    pub chunk_cache_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Per-inode write-buffer flush threshold in bytes (`--write-buffer-inode-mb`).
    pub write_buffer_inode_max: usize,
    /// Global write-buffer budget in bytes across ALL inodes (`--write-buffer-global-mb`).
    /// A writer that observes the budget exceeded synchronously flushes its own
    /// buffer — that flush IS the backpressure (never sleep-wait on this limit:
    /// with many files each below the per-inode threshold nobody would flush and
    /// every writer would wait forever).
    pub write_buffer_global_max: usize,
    /// Byte budget for the decrypted chunk LRU cache (`--chunk-cache-mb`).
    pub chunk_cache_max_bytes: usize,
    /// Maximum FUSE read/write payload size in bytes (`--max-write-kb`).
    pub max_write: u32,
    /// Maximum single-file size in bytes (`--max-file-size-gib`). Files larger
    /// than this are rejected with EFBIG.
    pub max_file_size: u64,
    /// Per-operation backup statistics (dedup hits, new chunks, bytes).
    pub backup_stats: std::sync::Arc<BackupStats>,
}
#[derive(Clone)]
pub struct FileWriteState {
    pub start_offset: u64,
    pub data: zeroize::Zeroizing<Vec<u8>>,
    /// tracks bytes currently in `data` for the global counter.
    /// Enables a `Drop` impl that warns if the counter wasn't decremented.
    buffered_bytes: usize,
}

impl Drop for FileWriteState {
    fn drop(&mut self) {
        // a leak diagnostic, NOT an invariant — do not panic. A buffer is
        // legitimately dropped with unflushed bytes at teardown: a file written
        // but never released/fsync'd, or the whole write_buffers map torn down at
        // process exit (where the global counter is being freed anyway). Panicking
        // here (the old debug_assert) crashed debug builds on unmount and broke
        // the test suite. Kept as a debug-level log so a developer watching for a
        // real mid-operation counter drift still sees it.
        if self.buffered_bytes != 0 {
            tracing::debug!(
                "FileWriteState dropped with {} buffered bytes (expected at teardown; \
                 a leak only if seen repeatedly during normal operation)",
                self.buffered_bytes
            );
        }
    }
}

/// Build a `FileAttr` from the (mode, uid, gid, size, nlink, mtime_sec, mtime_nsec)
/// row returned by `db.get_inode()`:
/// - `mtime` is now derived from the stored `mtime_sec` / `mtime_nsec` (was
///   `UNIX_EPOCH` in every FUSE op); `atime` and `ctime` fall back to
///   `mtime` because the schema has no atime/ctime columns.
/// - The `kind` is now derived from the FULL `mode` (S_IFMT), not just DIR/LNK/else
///. FIFO/CHR/BLK/SOCK round-trip through `get_inode` as a real FileType.
/// - The `perm` keeps `S_ISUID | S_ISGID | S_ISVTX` (was masked to `0o777` —
///   setuid files lost their setuid bit on extract/lookup).
#[allow(clippy::too_many_arguments)]
pub(crate) fn mk_file_attr(
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    nlink: u32,
    mtime_sec: u64,
    mtime_nsec: u32,
) -> FileAttr {
    let kind = mode_to_filetype(mode);
    // `mtime_nsec` is u32 (0..=999_999_999); saturate to avoid `Duration` overflow
    // if a corrupt row stored > u32::MAX ns.
    let mtime = std::time::SystemTime::UNIX_EPOCH
        + std::time::Duration::new(mtime_sec, mtime_nsec.min(999_999_999));
    FileAttr {
        ino,
        size,
        blocks: size.div_ceil(512),
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime: mtime,
        kind,
        // `mode & 0o7777` keeps the full 12-bit permission+special-bits window
        // (S_ISUID|S_ISGID|S_ISVTX + the rwx bits). The FUSE perm field is a
        // u16 — pass 15 reduced setuid files to non-setuid on extract.
        perm: (mode & 0o7777) as u16,
        nlink,
        uid,
        gid,
        rdev: 0,
        flags: 0,
        blksize: 4096,
    }
}

/// Outcome of resolving a stored dentry to a display/on-disk name. Callers
/// that only display the name (readdir) can discard the distinction, but
/// callers that write real files (extract) must be able to tell a decrypted
/// real name from the opaque-hash fallback, so they can warn instead of
/// silently writing hash-named files to disk.
pub(crate) enum ResolvedName {
    Real(String),
    Opaque(String),
}

impl ResolvedName {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            ResolvedName::Real(s) | ResolvedName::Opaque(s) => s,
        }
    }

    pub(crate) fn into_string(self) -> String {
        match self {
            ResolvedName::Real(s) | ResolvedName::Opaque(s) => s,
        }
    }

    pub(crate) fn is_opaque(&self) -> bool {
        matches!(self, ResolvedName::Opaque(_))
    }
}

/// Free-function core of `CairnEngine::resolve_dentry_name`, taking `crypto`
/// directly so it can run inside a `spawn_blocking` closure that only clones
/// the `Arc<CryptoCtx>` (not the whole engine) — see readdir/readdirplus.
pub(crate) fn resolve_name(
    crypto: &cairn_seal::CryptoCtx,
    lookup_key: &str,
    name_enc: Option<&[u8]>,
) -> ResolvedName {
    if !crypto.hide_names {
        return ResolvedName::Real(lookup_key.to_string());
    }
    match name_enc {
        Some(blob) => match crypto.decrypt_name_cached(blob) {
            Ok(name) => ResolvedName::Real(name),
            Err(e) => {
                if crypto.has_private_key() {
                    tracing::error!(
                        "hide-names: failed to decrypt name for dentry {lookup_key} \
                         despite having the private key — the name_enc blob is corrupt; \
                         falling back to the opaque hash: {e}"
                    );
                }
                ResolvedName::Opaque(lookup_key.to_string())
            }
        },
        None => ResolvedName::Opaque(lookup_key.to_string()),
    }
}

impl CairnEngine {
    /// Convert any error into an `io::Error(EIO)` while logging it.
    pub(crate) fn to_eio(e: impl std::fmt::Display) -> std::io::Error {
        tracing::error!("EIO: {e}");
        std::io::Error::from_raw_os_error(libc::EIO)
    }

    /// Flush and shrink an in-memory write buffer, updating the global byte counter.
    fn clear_write_buffer(&self, state: &mut FileWriteState) {
        let len = state.data.len();
        state.data.clear();
        state.data.shrink_to_fit();
        state.buffered_bytes = 0;
        self.global_write_buffer_bytes
            .fetch_sub(len, std::sync::atomic::Ordering::Relaxed);
    }

    /// Return (or create) the per-inode write lock.
    fn get_write_lock(&self, ino: u64) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        self.write_locks
            .entry(ino)
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Build a read-only engine for snapshot diff / Vfs::open — no uploads, no heal.
    pub fn new_readonly(
        db: cairn_index::Db,
        crypto: std::sync::Arc<cairn_seal::CryptoCtx>,
        cache_dir: String,
        no_comp_ext: Vec<String>,
    ) -> Self {
        let store: std::sync::Arc<dyn cairn_store::ChunkStore> = std::sync::Arc::new(
            cairn_store::CairnStore::new(cache_dir.clone(), vec![], None),
        );
        Self {
            db: std::sync::Arc::new(db),
            cache_dir,
            crypto,
            op: None,
            operators: vec![],
            store,
            raid_mode: "1".to_string(),
            skip_read_verify: true,
            force_remote_read: false,
            async_upload: false,
            auto_heal: false,
            no_comp_ext,
            write_buffers: std::sync::Arc::new(dashmap::DashMap::new()),
            write_locks: dashmap::DashMap::new(),
            decrypted_chunk_cache: std::sync::Arc::new(tokio::sync::Mutex::new(
                lru::LruCache::new(
                    std::num::NonZeroUsize::new(256).unwrap_or_else(|| unreachable!()),
                ),
            )),
            global_write_buffer_bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            chunk_cache_bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            last_index_hash: Default::default(),
            gc_running: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            write_buffer_inode_max: 16 * 1024 * 1024,
            write_buffer_global_max: 128 * 1024 * 1024,
            chunk_cache_max_bytes: 32 * 1024 * 1024,
            max_write: 1024 * 1024,
            max_file_size: 1024 * 1024 * 1024 * 1024,
            backup_stats: std::sync::Arc::new(BackupStats::new()),
        }
    }

    /// Fork an engine with a different database (snapshot diff / mount-snapshot).
    /// Inherits crypto, store, operators, and tuning from the source.
    pub fn new_from_db(&self, db: cairn_index::Db) -> Self {
        Self {
            db: std::sync::Arc::new(db),
            cache_dir: self.cache_dir.clone(),
            crypto: self.crypto.clone(),
            op: self.op.clone(),
            operators: self.operators.clone(),
            store: self.store.clone(),
            raid_mode: self.raid_mode.clone(),
            skip_read_verify: true,
            force_remote_read: self.force_remote_read,
            async_upload: false,
            auto_heal: false,
            no_comp_ext: self.no_comp_ext.clone(),
            write_buffers: std::sync::Arc::new(dashmap::DashMap::new()),
            write_locks: dashmap::DashMap::new(),
            decrypted_chunk_cache: std::sync::Arc::new(tokio::sync::Mutex::new(
                lru::LruCache::new(
                    std::num::NonZeroUsize::new(16).unwrap_or_else(|| unreachable!()),
                ),
            )),
            global_write_buffer_bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            chunk_cache_bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            last_index_hash: Default::default(),
            gc_running: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            write_buffer_inode_max: self.write_buffer_inode_max,
            write_buffer_global_max: self.write_buffer_global_max,
            chunk_cache_max_bytes: self.chunk_cache_max_bytes,
            max_write: self.max_write,
            max_file_size: self.max_file_size,
            backup_stats: std::sync::Arc::new(BackupStats::new()),
        }
    }

    /// hard cap on the RMW merge window. The previous version
    /// widened the merge region to span the entire distance between the lowest
    /// and highest overlapping chunk, so a 1-byte non-contiguous write on a
    /// file with chunks spread across `[0, 10 GiB)` would allocate a 10 GiB
    /// buffer. We bound the merge to `data.len() + (max_write * MAX_MERGE_RMW)`;
    /// a write that exceeds this falls back to "flush old + restart" (the
    /// non-contiguous branch already does that), but the new cap protects the
    /// RMW path from runaway allocation when the surrounding chunks are huge.
    const MAX_MERGE_RMW: u32 = 64;

    /// Envelope-wrap inline (small-file) data before it is stored in
    /// `inodes.inline_data`, so a small file gets the SAME protection as a
    /// chunked one. Previously inline data sat as PLAINTEXT inside the SQLCipher
    /// DB — anyone with the DB password could read it even on an asymmetric
    /// (write-only) archive without the private key, breaking the write-only
    /// guarantee for every file <= the inline threshold (and symlink targets).
    /// Reuses the chunk-key envelope: age-wrapped in asymmetric mode (only the
    /// private key reads), KEK-wrapped in symmetric mode (the password reads).
    /// Empty stays empty (`set_inline_data` treats an empty slice as NULL).
    pub fn wrap_inline(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }
        self.crypto.encrypt_blob(plaintext)
    }

    /// Inverse of [`Self::wrap_inline`]: decrypt inline data read back from
    /// `inodes.inline_data`. In asymmetric mode this REQUIRES the private key,
    /// so a public-key-only host cannot read inline content — exactly the
    /// write-only property. Returns zeroizing plaintext.
    pub fn unwrap_inline(&self, stored: &[u8]) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
        if stored.is_empty() {
            return Ok(zeroize::Zeroizing::new(Vec::new()));
        }
        self.crypto.decrypt_blob(stored)
    }

    /// --hide-names write side: translate a dentry name into the pair stored in
    /// the index — `(lookup_key, name_enc)`. In normal archives this is
    /// `(name, None)`, a pure pass-through, so the on-disk layout is byte-identical.
    /// In a hide-names archive the key is a keyed hash and `name_enc` is the
    /// write-only age-encrypted real name.
    fn dentry_name_fields(
        &self,
        parent: u64,
        name: &str,
    ) -> std::io::Result<(String, Option<Vec<u8>>)> {
        let key = self
            .crypto
            .name_lookup_key(parent, name)
            .map_err(Self::to_eio)?;
        let enc = self.crypto.encrypt_name(name).map_err(Self::to_eio)?;
        Ok((key, enc))
    }

    /// --hide-names lookup side: the key used to find/delete/rename a dentry by
    /// name. Normal archives → the name itself; hide-names → the keyed hash.
    fn dentry_lookup_key(&self, parent: u64, name: &str) -> std::io::Result<String> {
        self.crypto
            .name_lookup_key(parent, name)
            .map_err(Self::to_eio)
    }

    /// --hide-names read side: resolve a stored dentry to a display name.
    /// Normal archives store the name in the lookup column → return it directly.
    /// Hide-names archives: decrypt `name_enc` with the private key; if the key
    /// is absent (public-key-only host) or decryption fails, gracefully fall back
    /// to the opaque hash so the archive still opens (ADR item 5).
    ///
    /// The two failure modes are NOT the same and must not be conflated: a
    /// missing private key is the expected public-key-only-host case → quiet
    /// hash fallback. But a decrypt failure WHILE the private key is present
    /// means the `name_enc` blob is corrupt (bit rot / partial write / a format
    /// bug) — on a trusted restore machine that silently loses the real name, so
    /// it is logged loudly before degrading (same policy as the other
    /// verification-failure cases).
    pub(crate) fn resolve_dentry_name(&self, lookup_key: &str, name_enc: Option<&[u8]>) -> ResolvedName {
        resolve_name(&self.crypto, lookup_key, name_enc)
    }

    /// Like `Db::get_inode_name`, but decrypt-aware: on a hide-names archive
    /// with the private key present, this returns the REAL name instead of the
    /// lookup-key hash. Used by anything that displays/logs/reasons about a
    /// name by extension (the compression-skip heuristic) or in an error
    /// report (verify/scrub) — `Db::get_inode_name` alone always returns the
    /// hash on a hide-names archive, since it has no crypto context.
    pub(crate) fn get_resolved_inode_name(&self, inode: u64) -> anyhow::Result<String> {
        let (lookup_key, name_enc) = self.db.get_inode_name_enc(inode)?;
        Ok(resolve_name(&self.crypto, &lookup_key, name_enc.as_deref()).into_string())
    }

    pub async fn flush_range(
        &self,
        ino: u64,
        start_offset: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let data_len_u64 = u64::try_from(data.len())
            .map_err(|_| anyhow::anyhow!("write data length exceeds u64"))?;
        let end_offset = start_offset
            .checked_add(data_len_u64)
            .ok_or_else(|| anyhow::anyhow!("flush_range: offset + len overflow"))?;

        // 1. Fetch overlapping chunks
        let chunks = self.db.get_file_chunks(ino)?;
        let mut merge_start = start_offset;
        let mut merge_end = end_offset;

        let mut overlapping = Vec::new();
        // Largest end offset across ALL chunks (not just overlapping ones). Used
        // to guard the inline fast-path: inline is served exclusively of chunks,
        // so we must never store inline while a chunk lives beyond the merge.
        let mut max_chunk_end: u64 = 0;
        for chunk in chunks {
            let (oid, c_off, c_len, sk, ct, cipher_algo) = chunk;
            let c_off =
                u64::try_from(c_off).map_err(|_| anyhow::anyhow!("chunk offset exceeds u64"))?;
            let c_len =
                u64::try_from(c_len).map_err(|_| anyhow::anyhow!("chunk length exceeds u64"))?;
            let c_end = c_off
                .checked_add(c_len)
                .ok_or_else(|| anyhow::anyhow!("chunk end overflow"))?;
            if c_end > max_chunk_end {
                max_chunk_end = c_end;
            }
            if c_off < end_offset && c_end > start_offset {
                overlapping.push((oid, c_off, c_len, sk, ct, cipher_algo));
                if c_off < merge_start {
                    merge_start = c_off;
                }
                if c_end > merge_end {
                    merge_end = c_end;
                }
            }
        }

        // cap the merge window. Without this, a file with
        // chunks spanning gigabytes forces a multi-gigabyte `vec![0u8; ...]`
        // on a single 1-byte non-contiguous write. The cap is
        // `data.len() + max_write * MAX_MERGE_RMW` (max-write sized slack
        // either side of the new data); writes outside this are still
        // handled by the non-contiguous branch in `write()`.
        let max_merge_window = data_len_u64
            .checked_add(u64::from(self.max_write) * u64::from(Self::MAX_MERGE_RMW))
            .ok_or_else(|| anyhow::anyhow!("flush_range: max_merge_window overflow"))?;

        // Fold existing inline_data into this read-modify-write. inline_data is a
        // single blob at offset 0 that the read path serves EXCLUSIVELY of chunks
        // (see read()); replace_file_chunks and the inline stores below clear it.
        // A flush that ignored it would silently drop the inline content the
        // instant this write forces chunked storage (root cause of soak r33). Fold
        // it in as a virtual chunk at [0, inline_len). If this write is so far past
        // a small inline file that folding down to offset 0 would blow the
        // merge-window cap, promote the inline blob to its own chunk instead so
        // both regions survive and the window stays bounded.
        let mut inline_to_fold: Option<zeroize::Zeroizing<Vec<u8>>> = None;
        let inline_existing = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_inline_data(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        if let Some(raw_inline) = inline_existing {
            let inline_plain = self.unwrap_inline(&raw_inline)?;
            if !inline_plain.is_empty() {
                let inline_len = u64::try_from(inline_plain.len())
                    .map_err(|_| anyhow::anyhow!("inline length exceeds u64"))?;
                let folded_span = merge_end.max(inline_len); // window would be [0, folded_span)
                if folded_span <= max_merge_window {
                    merge_start = 0;
                    if inline_len > merge_end {
                        merge_end = inline_len;
                    }
                    inline_to_fold = Some(inline_plain);
                } else {
                    self.promote_inline_to_chunk(ino, &inline_plain).await?;
                }
            }
        }

        if merge_end.saturating_sub(merge_start) > max_merge_window {
            anyhow::bail!(
                "flush_range: merge window {} bytes exceeds cap {} (data={} + max_write*MAX_MERGE_RMW={}); \
                 the caller should re-write at a non-contiguous offset or compact the file",
                merge_end.saturating_sub(merge_start),
                max_merge_window,
                data.len(),
                Self::MAX_MERGE_RMW,
            );
        }

        let merge_len = merge_end.saturating_sub(merge_start);
        let merge_len_usize = usize::try_from(merge_len)
            .map_err(|_| anyhow::anyhow!("merged region exceeds address space"))?;
        let mut merged_data = vec![0u8; merge_len_usize];

        let mut fetches = Vec::with_capacity(overlapping.len());
        for (oid, _, _, _, _, _) in &overlapping {
            fetches.push(self.fetch_chunk(oid));
        }
        let fetched_data = futures::future::join_all(fetches).await;

        // 2. Read old chunks and copy to merged_data
        let merge_start_usize = usize::try_from(merge_start)
            .map_err(|_| anyhow::anyhow!("merge start exceeds address space"))?;

        // Fold existing inline (offset 0) in as the base. When folding, merge_start
        // is 0, so the destination is [0, inline_len). Chunks (there are none while
        // inline exists) and the new data overlay on top afterwards.
        if let Some(inline_plain) = &inline_to_fold {
            let ilen = inline_plain.len();
            merged_data
                .get_mut(0..ilen)
                .ok_or_else(|| anyhow::anyhow!("merge buffer overflow folding inline"))?
                .copy_from_slice(inline_plain);
        }

        for (i, (oid, c_off, c_len, sk, ct, cipher_algo)) in overlapping.iter().enumerate() {
            let cipher = match &fetched_data[i] {
                Ok(data) => data,
                Err(e) => return Err(anyhow::anyhow!("Failed to fetch chunk {oid}: {e}")),
            };
            let comp_type = u8::try_from(*ct)
                .map_err(|_| anyhow::anyhow!("invalid comp_type for chunk {oid}"))?;
            let plain = self
                .crypto
                .decrypt_chunk_symmetric(cipher, sk, comp_type, cipher_algo)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to decrypt chunk for Read-Modify-Write (Missing private key?): {e}"
                    )
                })?;
            let c_off_usize = usize::try_from(*c_off)
                .map_err(|_| anyhow::anyhow!("chunk offset exceeds address space"))?;
            let dst = c_off_usize.saturating_sub(merge_start_usize);
            let c_len_usize = usize::try_from(*c_len)
                .map_err(|_| anyhow::anyhow!("chunk length exceeds address space"))?;
            let len = c_len_usize.min(plain.len());
            merged_data
                .get_mut(dst..dst + len)
                .ok_or_else(|| anyhow::anyhow!("merge buffer overflow copying chunk {oid}"))?
                .copy_from_slice(
                    plain
                        .get(..len)
                        .ok_or_else(|| anyhow::anyhow!("plain buffer underflow for chunk {oid}"))?,
                );
        }

        // 3. Overwrite with new data
        let start_offset_usize = usize::try_from(start_offset)
            .map_err(|_| anyhow::anyhow!("start offset exceeds address space"))?;
        let new_dst = start_offset_usize.saturating_sub(merge_start_usize);
        merged_data
            .get_mut(new_dst..new_dst + data.len())
            .ok_or_else(|| anyhow::anyhow!("merge buffer overflow writing new data"))?
            .copy_from_slice(data);

        // 4a. Determine if we should disable compression based on file extension
        // log a real DB error before treating the name as absent (the
        // extension hint then falls back to "compress", which is the safe default).
        let ext = self
            .get_resolved_inode_name(ino)
            .map_err(|e| tracing::warn!("compression-hint: get_resolved_inode_name(ino={ino}) failed: {e}"))
            .ok()
            .and_then(|name| {
                std::path::Path::new(&name)
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
            });

        let comp_algo_override = if let Some(e) = ext {
            if self.no_comp_ext.contains(&e) {
                Some("none".to_string())
            } else {
                None
            }
        } else {
            None
        };

        // small-data fast path — store inline and skip the CDC
        // chunker entirely. FastCDC's minimum chunk size (16 KiB) means any
        // sub-threshold write produces 1+ chunks that overwrite the inline blob,
        // silently losing data on the next O_TRUNC/extract cycle. Files ≤
        // INLINE_THRESHOLD are stored as a single BLOB in `inodes.inline_data`,
        // which the read path already handles (see `read()` inline branch).
        //
        // Only apply when merge_start == 0: inline_data is a single BLOB at
        // offset 0. A non-zero start offset means the data covers a middle
        // region of the file and must go through the chunker.
        // Also require no chunk to live beyond the merged region
        // (max_chunk_end <= merge_end): inline is served exclusively of chunks, so
        // inlining while a later chunk exists would hide it. Store inline and drop
        // the now-superseded (folded-in) chunks in a single transaction.
        if merge_start == 0 && merged_data.len() <= INLINE_THRESHOLD && max_chunk_end <= merge_end {
            let wrapped = self.wrap_inline(&merged_data)?;
            tokio::task::spawn_blocking({
                let db = self.db.clone();
                move || db.set_inline_and_clear_chunks(ino, &wrapped)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
            return Ok(());
        }

        // 5. Run Chunker — only for data above INLINE_THRESHOLD.
        let _permit = LOCAL_FLUSH_SEMAPHORE.acquire().await;
        let new_chunks = cairn_cdc::Chunker::process_data(
            &merged_data,
            &self.cache_dir,
            self.crypto.clone(),
            self.db.clone(),
            self.store.clone(),
            self.raid_mode.clone(),
            self.async_upload,
            comp_algo_override,
        )
        .await?;

        // Track dedup statistics
        for chunk in &new_chunks {
            if chunk.dedup_hit {
                self.backup_stats
                    .dedup_hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.backup_stats
                    .bytes_deduped
                    .fetch_add(chunk.plain_len, std::sync::atomic::Ordering::Relaxed);
            } else {
                self.backup_stats
                    .new_chunks
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.backup_stats
                    .bytes_written
                    .fetch_add(chunk.plain_len, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Adjust offsets of new chunks
        let chunk_refs: Vec<_> = new_chunks
            .iter()
            .map(|c| {
                let final_offset = u64::try_from(c.offset)
                    .map_err(|_| anyhow::anyhow!("new chunk offset exceeds u64"))?
                    .checked_add(merge_start)
                    .ok_or_else(|| anyhow::anyhow!("new chunk offset overflow"))?;
                Ok((final_offset, c.hash_key.clone(), c.plain_len, c.comp_type))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        // release the semaphore permit BEFORE the DB batch write.
        // The permit gates CDC chunking + upload (the expensive I/O path). The DB
        // replace_file_chunks below is a single fast transaction. Holding the
        // permit through it creates a convoy effect where large flushes block
        // small ones even after their I/O is done.
        drop(_permit);

        // 5. Update DB: atomic single-transaction replace (delete overlapping, insert
        //    new). replace_file_chunks also clears inline data inside that transaction.
        //
        // when the CDC chunker produces zero chunks (merged data
        // is below the minimum chunk size), we must NOT call replace_file_chunks —
        // it would clear inline_data with nothing to replace it, permanently
        // losing the file's content. Instead, store the merged data as inline.
        if chunk_refs.is_empty() {
            // Defensive: fastcdc returns the whole blob as one chunk when the
            // input is below min size, and merged_data is non-empty here, so this
            // is effectively unreachable. If it ever fires, inlining is only safe
            // at offset 0 with no chunk beyond the merge; anything else would
            // mis-place the data at offset 0 (inline is offset-0-based), so refuse.
            if merge_start == 0 && max_chunk_end <= merge_end {
                let wrapped = self.wrap_inline(&merged_data)?;
                tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    move || db.set_inline_and_clear_chunks(ino, &wrapped)
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
            } else {
                anyhow::bail!(
                    "flush_range: chunker produced no chunks for {}-byte data at \
                     merge_start {} — cannot store without corrupting inline offset \
                     semantics",
                    merged_data.len(),
                    merge_start
                );
            }
        } else {
            tokio::task::spawn_blocking({
                let db = self.db.clone();
                let o_min = merge_start;
                let o_max = merge_end;
                move || db.replace_file_chunks(ino, o_min, o_max, &chunk_refs)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        }

        Ok(())
    }

    /// Store an existing inline blob as a standalone chunk at offset 0 and clear
    /// inline. Used by `flush_range` for a disjoint far write whose flush would
    /// otherwise have to fold the inline all the way down to offset 0, blowing the
    /// merge-window cap. Preserves the inline content as chunk(s) so the caller's
    /// write then flushes independently with a bounded window.
    async fn promote_inline_to_chunk(&self, ino: u64, inline_plain: &[u8]) -> anyhow::Result<()> {
        if inline_plain.is_empty() {
            return Ok(());
        }
        let inline_len = u64::try_from(inline_plain.len())
            .map_err(|_| anyhow::anyhow!("inline length exceeds u64"))?;
        let _permit = LOCAL_FLUSH_SEMAPHORE.acquire().await;
        let new_chunks = cairn_cdc::Chunker::process_data(
            inline_plain,
            &self.cache_dir,
            self.crypto.clone(),
            self.db.clone(),
            self.store.clone(),
            self.raid_mode.clone(),
            self.async_upload,
            None,
        )
        .await?;
        drop(_permit);
        // Offsets returned by the chunker are relative to the blob start (0).
        let chunk_refs: Vec<_> = new_chunks
            .iter()
            .map(|c| {
                let off = u64::try_from(c.offset)
                    .map_err(|_| anyhow::anyhow!("promoted chunk offset exceeds u64"))?;
                Ok((off, c.hash_key.clone(), c.plain_len, c.comp_type))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if chunk_refs.is_empty() {
            // A non-empty blob always yields >= 1 chunk; keep inline as-is if not.
            return Ok(());
        }
        tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.replace_file_chunks(ino, 0, inline_len, &chunk_refs)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        Ok(())
    }

    pub async fn fetch_chunk(&self, hash_key: &str) -> anyhow::Result<Vec<u8>> {
        self.store
            .fetch_chunk(
                hash_key,
                &self.raid_mode,
                self.skip_read_verify,
                self.auto_heal,
                self.force_remote_read,
            )
            .await
    }

    #[cfg(feature = "cloud-storage")]
    pub async fn sync_index_to_cloud(&self) -> anyhow::Result<()> {
        if self.operators.is_empty() {
            return Ok(());
        }

        tracing::info!("Preparing to backup local index database to S3...");
        let db_bytes = self.db.backup_to_bytes()?;

        let current_hash = blake3::hash(&db_bytes).into();
        {
            let last_hash = self.last_index_hash.lock();
            if *last_hash == current_hash {
                tracing::info!("Index database is unchanged since last sync. Skipping upload.");
                return Ok(());
            }
            // do NOT update hash here — only after successful
            // upload. Updating before upload means a failed upload permanently
            // bricks cloud restore (hash says "unchanged", cloud has no manifest).
        }

        // Chunking the DB using fastcdc
        let chunker =
            fastcdc::v2020::FastCDC::new(&db_bytes, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024);
        let mut manifest_chunks = Vec::new();
        for chunk in chunker {
            let slice = &db_bytes[chunk.offset..chunk.offset + chunk.length];
            let sym_key = self.crypto.generate_chunk_key(slice)?;
            let (ciphertext, comp_type) = self
                .crypto
                .encrypt_chunk_symmetric(slice, &sym_key, None)
                .map_err(|e| anyhow::anyhow!("Crypto error: {e}"))?;

            let wrapped_key = self
                .crypto
                .encrypt_blob(&sym_key)
                .map_err(|e| anyhow::anyhow!("Envelope error: {e}"))?;

            let hash = blake3::hash(&ciphertext).to_hex().to_string();

            // index chunks follow the same rule as data chunks — the S3
            // object is the raw ciphertext (`blake3 == hash`); the wrapped key
            // travels in the manifest below, not in the object. `fetch_chunk`
            // in restore_index_from_cloud verifies blake3 and decrypts with
            // `chunk.wrapped_key` from the manifest.
            self.store
                .upload_chunk(ciphertext.clone(), &hash, &self.raid_mode)
                .await?;

            manifest_chunks.push(crate::ManifestChunk {
                hash,
                wrapped_key,
                comp_type,
                cipher_algo: self.crypto.crypto_algo.clone(),
            });
        }

        let manifest = crate::Manifest {
            chunks: manifest_chunks,
        };
        let manifest_bytes = serde_json::to_vec(&manifest)?;

        let sym_key = self.crypto.generate_chunk_key(&manifest_bytes)?;
        let (ciphertext, comp_type) = self
            .crypto
            .encrypt_chunk_symmetric(&manifest_bytes, &sym_key, None)
            .map_err(|e| anyhow::anyhow!("Crypto error: {e}"))?;

        let wrapped_key = self
            .crypto
            .encrypt_blob(&sym_key)
            .map_err(|e| anyhow::anyhow!("Envelope error: {e}"))?;

        // see cairn-cdc/src/lib.rs.
        if wrapped_key.len() > u16::MAX as usize {
            return Err(anyhow::anyhow!(
                "wrapped_key too large: {} bytes (max {})",
                wrapped_key.len(),
                u16::MAX
            ));
        }
        let wk_len = (wrapped_key.len() as u16).to_le_bytes();
        let algo_bytes = self.crypto.crypto_algo.as_bytes();
        if algo_bytes.len() > u8::MAX as usize {
            return Err(anyhow::anyhow!(
                "crypto_algo name too long: {} bytes (max {})",
                algo_bytes.len(),
                u8::MAX
            ));
        }
        let algo_len = algo_bytes.len() as u8;

        let upload_data = [
            wk_len.as_slice(),
            wrapped_key.as_slice(),
            &[comp_type, algo_len],
            algo_bytes,
            ciphertext.as_slice(),
        ]
        .concat();

        let s3_path = "meta/archive.db.enc".to_string();

        for op in &self.operators {
            op.write(&s3_path, upload_data.clone())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to upload index backup to S3: {e}"))?;
        }

        // update hash ONLY after all operators succeed.
        // A partial upload leaves the hash stale → next call retries (correct).
        // A successful upload sets the hash → next call skips (correct).
        {
            *self.last_index_hash.lock() = current_hash;
        }

        tracing::info!(
            "Index database successfully synced to all S3 operators as '{}'",
            s3_path
        );
        Ok(())
    }
}

// Concrete directory-listing stream types (were the Filesystem assoc types). The
// thin adapter (cairn-fuse) re-declares its GATs as aliases of these.

// These are the filesystem OPERATIONS as INHERENT methods (they keep the exact
// fuse3 signatures the trait had). cairn-fuse's `impl Filesystem for CairnFs`
// delegates to each of them. cairn-core stays fuse3-typed (engine/adapter seam,
// not a fuse-independent core).
impl CairnEngine {
    pub async fn init(&self, _req: Request) -> std::io::Result<u32> {
        Ok(self.max_write)
    }

    pub async fn lookup(
        &self,
        _req: Request,
        parent: u64,
        name: &OsStr,
    ) -> std::io::Result<EngineReplyEntry> {
        let name_str = name.to_string_lossy();
        let n = self.dentry_lookup_key(parent, &name_str)?;
        match tokio::task::spawn_blocking({
            let db = self.db.clone();
            let p = parent;
            move || db.get_dentry_inode(p, &n)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        {
            Ok(Some(ino)) => match tokio::task::spawn_blocking({
                let db = self.db.clone();
                let i = ino;
                move || db.get_inode(i)
            })
            .await
            .map_err(CairnEngine::to_eio)?
            {
                Ok(Some((mode, uid, gid, size, nlink, mtime_sec, mtime_nsec))) => {
                    let mtime_sec_u64 = u64::try_from(mtime_sec).unwrap_or(0);
                    let attr =
                        mk_file_attr(ino, mode, uid, gid, size, nlink, mtime_sec_u64, mtime_nsec);
                    Ok(EngineReplyEntry {
                        ttl: TTL,
                        attr,
                        generation: 0,
                    })
                }
                _ => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            },
            _ => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    pub async fn getattr(
        &self,
        _req: Request,
        ino: u64,
        _fh: Option<u64>,
        _flags: u32,
    ) -> std::io::Result<FileAttr> {
        match tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = ino;
            move || db.get_inode(i)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        {
            Ok(Some((mode, uid, gid, size, nlink, mtime_sec, mtime_nsec))) => {
                let mtime_sec_u64 = u64::try_from(mtime_sec)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                Ok(mk_file_attr(
                    ino,
                    mode,
                    uid,
                    gid,
                    size,
                    nlink,
                    mtime_sec_u64,
                    mtime_nsec,
                ))
            }
            _ => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    pub async fn read(
        &self,
        _req: Request,
        ino: u64,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> std::io::Result<Vec<u8>> {
        let db1 = self.db.clone();
        let inode_info = tokio::task::spawn_blocking(move || db1.get_inode(ino))
            .await
            .map_err(CairnEngine::to_eio)?
            .map_err(|e| {
                tracing::error!("get_inode failed for ino {}: {:?}", ino, e);
                std::io::Error::from_raw_os_error(libc::EIO)
            })?
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
        let file_size = inode_info.3;
        let requested_end = offset.checked_add(u64::from(size)).ok_or_else(|| {
            tracing::warn!("read: offset + size overflow for ino {ino}");
            std::io::Error::from_raw_os_error(libc::EINVAL)
        })?;
        let max_end = offset
            .checked_add(u64::from(self.max_write))
            .ok_or_else(|| {
                tracing::warn!("read: offset + max_write overflow for ino {ino}");
                std::io::Error::from_raw_os_error(libc::EINVAL)
            })?;
        let read_end = requested_end.min(file_size).min(max_end);
        let read_len = read_end.saturating_sub(offset);
        let read_len_usize = usize::try_from(read_len).map_err(|_| {
            tracing::warn!("read: read_len {read_len} does not fit in usize for ino {ino}");
            std::io::Error::from_raw_os_error(libc::EINVAL)
        })?;
        let offset_usize = usize::try_from(offset).map_err(|_| {
            tracing::warn!("read: offset {offset} does not fit in usize for ino {ino}");
            std::io::Error::from_raw_os_error(libc::EINVAL)
        })?;
        let mut result = vec![0u8; read_len_usize];

        // Snapshot the write buffer under the per-inode write lock (same lock
        // write()/fsync()/release() take). Without it, a concurrent write could
        // flush the buffer to chunks between our snapshot and our chunk fetch,
        // so the stale buffer clone would overlay NEW chunk data — a torn read.
        // The lock is held only for the cheap clone, then dropped before the
        // slow async chunk fetches so reads don't serialize writers.
        let wlock = self.get_write_lock(ino);
        let _wguard = wlock.lock().await;
        let state_arc = self.write_buffers.get(&ino).map(|e| e.value().clone());
        let state_opt = if let Some(arc) = state_arc {
            Some(arc.lock().await.clone())
        } else {
            None
        };
        drop(_wguard);
        drop(wlock);

        // propagate a DB read error instead of masking it as "no inline
        // data" (`.unwrap_or(None)`). Masking would fall through to the chunk path
        // and return an EMPTY read for an inline file on a transient DB error —
        // silent corruption on a read.
        if let Some(raw_inline) = self.db.get_inline_data(ino).map_err(CairnEngine::to_eio)? {
            // Decrypt the envelope-wrapped inline blob before serving. In
            // asymmetric mode without the private key this fails (EIO) — a
            // public-key-only host cannot read inline content.
            let inline_data = self
                .unwrap_inline(&raw_inline)
                .map_err(CairnEngine::to_eio)?;
            let data_start = offset_usize.min(inline_data.len());
            let data_end = (offset_usize + read_len_usize).min(inline_data.len());
            let copy_len = data_end - data_start;
            result[..copy_len].copy_from_slice(&inline_data[data_start..data_end]);

            if let Some(state) = state_opt {
                let buf_start = state.start_offset;
                let buf_data_len = u64::try_from(state.data.len())
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                let buf_end = buf_start
                    .checked_add(buf_data_len)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                if read_end > buf_start && offset < buf_end {
                    let overlap_start = offset.max(buf_start);
                    let overlap_end = read_end.min(buf_end);
                    let res_offset = overlap_start - offset;
                    let buf_offset = overlap_start - buf_start;
                    let overlap_len = overlap_end - overlap_start;
                    let res_start = usize::try_from(res_offset)
                        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                    let res_end = res_start
                        + usize::try_from(overlap_len)
                            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                    let buf_start_idx = usize::try_from(buf_offset)
                        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                    let buf_end_idx = buf_start_idx
                        + usize::try_from(overlap_len)
                            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                    result
                        .get_mut(res_start..res_end)
                        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?
                        .copy_from_slice(
                            state
                                .data
                                .get(buf_start_idx..buf_end_idx)
                                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?,
                        );
                }
            }
            return Ok(result);
        }

        tracing::trace!(
            "cairn_core::read: Calling get_file_chunks_range for ino {}",
            ino
        );
        let req_end = offset
            .checked_add(read_len)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let db2 = self.db.clone();
        let overlapping = tokio::task::spawn_blocking(move || {
            db2.get_file_chunks_range(ino, offset, req_end as u64)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        .map_err(|e| {
            tracing::error!("get_file_chunks_range failed for ino {}: {:?}", ino, e);
            std::io::Error::from_raw_os_error(libc::EIO)
        })?;

        // NOTE: no "sum(chunk_len) == file_size" assertion here — it does not hold
        // in legitimate states (data still in write_buffers pending flush; sparse
        // or truncate-extended files where read() zero-fills the gap). read()
        // handles those via the zero-filled `result` buffer + write-buffer overlay.

        // 2. Prefetch overlapping chunks

        let mut fetches = Vec::with_capacity(overlapping.len());
        for (hash, _, _, _, _, _) in &overlapping {
            tracing::trace!("cairn_core::read: Calling fetch_chunk for {}", hash);
            fetches.push(self.fetch_chunk(hash));
        }
        tracing::trace!(
            "cairn_core::read: before join_all for {} fetches",
            fetches.len()
        );
        let fetched_data = futures::future::join_all(fetches).await;
        tracing::trace!("cairn_core::read: after join_all");
        for (i, (hash, c_offset, c_len, wrapped_key, comp_type, cipher_algo)) in
            overlapping.into_iter().enumerate()
        {
            let chunk_end = c_offset
                .checked_add(c_len)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
            let chunk_end_u64 = u64::try_from(chunk_end)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
            let c_offset_u64 = u64::try_from(c_offset)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;

            let plain_cached = {
                let mut cache_lock = self.decrypted_chunk_cache.lock().await;
                cache_lock.get(&hash).cloned()
            };

            let plain = if let Some(cached) = plain_cached {
                cached
            } else {
                let cipher = match &fetched_data[i] {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!("read: chunk missing {}", e);
                        return Err(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                };

                let comp_type_u8 = u8::try_from(comp_type)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                let dec = self
                    .crypto
                    .decrypt_chunk_symmetric(cipher, &wrapped_key, comp_type_u8, &cipher_algo)
                    .map_err(CairnEngine::to_eio)?;
                let dec_len = dec.len();

                let mut cache_lock = self.decrypted_chunk_cache.lock().await;
                // Byte-budget eviction: evict oldest entries until we're under the byte cap
                while self
                    .chunk_cache_bytes
                    .load(std::sync::atomic::Ordering::Relaxed)
                    + dec_len
                    > self.chunk_cache_max_bytes
                    && !cache_lock.is_empty()
                {
                    if let Some((_, evicted)) = cache_lock.pop_lru() {
                        self.chunk_cache_bytes
                            .fetch_sub(evicted.len(), std::sync::atomic::Ordering::Relaxed);
                    }
                }
                cache_lock.put(hash.clone(), dec.clone());
                self.chunk_cache_bytes
                    .fetch_add(dec_len, std::sync::atomic::Ordering::Relaxed);
                dec
            };

            let overlap_start_in_chunk = offset_usize.saturating_sub(c_offset);
            let overlap_end_in_chunk = if req_end < chunk_end_u64 {
                usize::try_from(req_end.saturating_sub(c_offset_u64))
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?
            } else {
                c_len
            };
            let overlap_end_in_chunk = overlap_end_in_chunk.min(plain.len());
            if overlap_start_in_chunk >= overlap_end_in_chunk {
                continue;
            }
            let overlap_len = overlap_end_in_chunk - overlap_start_in_chunk;
            let dst_offset = c_offset.saturating_sub(offset_usize);

            result
                .get_mut(dst_offset..dst_offset + overlap_len)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?
                .copy_from_slice(
                    plain
                        .get(overlap_start_in_chunk..overlap_end_in_chunk)
                        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?,
                );
        }

        // Overlay any unflushed data from write_buffers!
        if let Some(state) = state_opt {
            if !state.data.is_empty() {
                let buf_start = state.start_offset;
                let buf_data_len = u64::try_from(state.data.len())
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                let buf_end = buf_start
                    .checked_add(buf_data_len)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;

                let req_start = offset;
                let req_end = offset
                    .checked_add(read_len)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                let overlap_start = req_start.max(buf_start);
                let overlap_end = req_end.min(buf_end);

                if overlap_start < overlap_end {
                    let dst = usize::try_from(overlap_start - req_start)
                        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                    let src = usize::try_from(overlap_start - buf_start)
                        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                    let len = usize::try_from(overlap_end - overlap_start)
                        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                    result
                        .get_mut(dst..dst + len)
                        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?
                        .copy_from_slice(
                            state
                                .data
                                .get(src..src + len)
                                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?,
                        );
                }
            }
        }

        tracing::trace!(
            "cairn_core::read successfully returning bytes for ino {}",
            ino
        );
        Ok(result)
    }

    pub async fn write(
        &self,
        _req: Request,
        ino: u64,
        _fh: u64,
        offset: u64,
        data: &[u8],
        _write_flags: u32,
        _flags: u32,
    ) -> std::io::Result<u32> {
        let lock = self.get_write_lock(ino);
        let _guard = lock.lock().await;

        // wrap sync DB calls in spawn_blocking so they don't
        // block the tokio worker thread.
        let inode_info = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_inode(ino)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        .map_err(CairnEngine::to_eio)?
        // The inode can legitimately vanish between open() and write(): Cairn
        // has no open-file refcounting, so unlink drops the row immediately.
        // ENOENT, not a panic that kills the FUSE request.
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
        let current_size = inode_info.3;
        let data_len_u64 = u64::try_from(data.len())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let write_end = offset
            .checked_add(data_len_u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        // Enforce a maximum file size to prevent unbounded hole creation
        // via sparse writes. Configurable via --max-file-size-gib (default 1 TiB).
        if write_end > self.max_file_size {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
        let new_size = current_size.max(write_end);

        let state_arc = self
            .write_buffers
            .entry(ino)
            .or_insert_with(|| {
                std::sync::Arc::new(tokio::sync::Mutex::new(crate::FileWriteState {
                    start_offset: offset,
                    data: zeroize::Zeroizing::new(Vec::new()),
                    buffered_bytes: 0,
                }))
            })
            .clone();
        let mut state = state_arc.lock().await;

        let seq_end = state
            .start_offset
            .checked_add(
                u64::try_from(state.data.len())
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?,
            )
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        if state.data.is_empty() {
            state.start_offset = offset;
            state.data.extend_from_slice(data);
            state.buffered_bytes += data.len();
            self.global_write_buffer_bytes
                .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
        } else if offset == seq_end {
            // Sequential append
            state.data.extend_from_slice(data);
            state.buffered_bytes += data.len();
            self.global_write_buffer_bytes
                .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
        } else {
            // Random write: flush the existing buffer, then restart it at the new offset.
            if let Err(e) = self.flush_range(ino, state.start_offset, &state.data).await {
                // The old buffer must survive intact for read-overlay/retry;
                // merging a non-contiguous write into it would corrupt both
                // ranges. Reject the new write instead of silently dropping it.
                tracing::error!(
                    "write: flush_range failed for ino {}: {}, rejecting non-contiguous write",
                    ino,
                    e
                );
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            self.clear_write_buffer(&mut state);
            state.start_offset = offset;
            state.data.extend_from_slice(data);
            state.buffered_bytes += data.len();
            self.global_write_buffer_bytes
                .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
        }

        // Flush when this inode's buffer exceeds its threshold OR the global budget
        // is exceeded. Draining our own buffer IS the backpressure: every writer
        // that observes the budget exceeded synchronously flushes its own
        // contribution before returning, so total buffered RAM stays bounded near
        // write_buffer_global_max regardless of how many files are open.
        // FastCDC boundaries might shift slightly for the last chunk, but this
        // guarantees durability and bounds RAM.
        let over_global = self
            .global_write_buffer_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            > self.write_buffer_global_max;
        if state.data.len() > self.write_buffer_inode_max || over_global {
            if over_global {
                tracing::debug!(
                    "write: global write buffers over {} MB — flushing ino {} early",
                    self.write_buffer_global_max / (1024 * 1024),
                    ino
                );
            }
            match self.flush_range(ino, state.start_offset, &state.data).await {
                Ok(()) => {
                    self.clear_write_buffer(&mut state);
                }
                Err(e) => {
                    tracing::error!(
                        "write: flush_range failed for ino {}: {}, keeping buffer for read overlay",
                        ino,
                        e
                    );
                    // Don't update inode size — it would claim a larger size than
                    // the sum of committed chunks, causing zero-fill reads on recovery.
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
            }
        }

        // bump mtime+ctime on every successful write so
        // `make`, `rsync -t`, and `find -newer` see honest mtime after
        // a backup-tool write. Combined with the size update in one tx.
        let new_size_u64 = new_size; // already u64 (current_size.max(write_end))
        // use try_from to prevent silent u32 truncation if
        // data.len() > u32::MAX (defensive — FUSE limits writes to max_write).
        let written = u32::try_from(data.len())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        tokio::task::spawn_blocking({
            let db = self.db.clone();
            let n_s = new_size_u64;
            move || db.update_inode_size_and_bump_time(ino, n_s)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        .map_err(CairnEngine::to_eio)?;
        Ok(written)
    }

    pub async fn readdir(
        &self,
        _req: Request,
        ino: u64,
        _fh: u64,
        offset: i64,
    ) -> std::io::Result<Vec<DirectoryEntry>> {
        let mut entries = Vec::new();

        if offset == 0 {
            entries.push(DirectoryEntry {
                inode: ino,
                offset: 1,
                kind: FileType::Directory,
                name: OsStr::new(".").into(),
            });
            let parent_ino = if ino == 1 {
                1
            } else {
                tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    move || db.get_parent_inode(ino)
                })
                .await
                .map_err(CairnEngine::to_eio)?
                .unwrap_or(1)
            };
            entries.push(DirectoryEntry {
                inode: parent_ino,
                offset: 2,
                kind: FileType::Directory,
                name: OsStr::new("..").into(),
            });
        }

        // Entry offsets are `dentry rowid + 2` (offsets 1 and 2 belong to `.`/`..`).
        // The kernel resumes a listing with the offset of the last entry it consumed,
        // so `offset - 2` is exactly the rowid to continue after. This is stateless:
        // it survives concurrent create/unlink (rowids don't shift like LIMIT/OFFSET)
        // and works when the kernel starts a listing via readdirplus and continues
        // via plain readdir (READDIRPLUS_AUTO) — both use the same cookie.
        let after_rowid = offset.saturating_sub(2).max(0);
        // Name decryption (age, CPU-bound) runs inside this same spawn_blocking
        // closure rather than after it, so a large hide-names listing doesn't
        // stall the tokio async worker decrypting up to 1000 names inline.
        let crypto = self.crypto.clone();
        let db_entries = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = ino;
            move || -> anyhow::Result<Vec<(i64, ResolvedName, u64, u32)>> {
                let rows = db.list_dentries_rowid_after(i, after_rowid, 1000)?;
                Ok(rows
                    .into_iter()
                    .map(|(rowid, name, name_enc, child_ino, kind)| {
                        let display = resolve_name(&crypto, &name, name_enc.as_deref());
                        (rowid, display, child_ino, kind)
                    })
                    .collect())
            }
        })
        .await
        .map_err(CairnEngine::to_eio)?
        .map_err(CairnEngine::to_eio)?;

        for (rowid, display, child_ino, kind) in db_entries {
            // map ALL POSIX file types (same as readdirplus/mk_file_attr).
            let file_type = match kind & libc::S_IFMT {
                libc::S_IFDIR => FileType::Directory,
                libc::S_IFLNK => FileType::Symlink,
                libc::S_IFIFO => FileType::NamedPipe,
                libc::S_IFCHR => FileType::CharDevice,
                libc::S_IFBLK => FileType::BlockDevice,
                libc::S_IFSOCK => FileType::Socket,
                _ => FileType::RegularFile,
            };
            entries.push(DirectoryEntry {
                inode: child_ino,
                offset: rowid + 2,
                kind: file_type,
                name: OsStr::new(&display.into_string()).into(),
            });
        }

        Ok(entries)
    }

    #[allow(clippy::needless_lifetimes)]
    pub async fn readdirplus(
        &self,
        _req: Request,
        parent: u64,
        _fh: u64,
        offset: u64,
        _lock_owner: u64,
    ) -> std::io::Result<Vec<DirectoryEntryPlus>> {
        let mut entries = Vec::new();

        if offset == 0 {
            if let Ok(Some((mode, uid, gid, size, nlink, mtime_sec, mtime_nsec))) =
                tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    let i = parent;
                    move || db.get_inode(i)
                })
                .await
                .map_err(CairnEngine::to_eio)?
            {
                entries.push(DirectoryEntryPlus {
                    inode: parent,
                    generation: 0,
                    kind: FileType::Directory,
                    name: OsStr::new(".").into(),
                    offset: 1,
                    attr: mk_file_attr(
                        parent,
                        mode,
                        uid,
                        gid,
                        size,
                        nlink,
                        // saturate negative mtime_sec instead of wrapping to huge u64.
                        u64::try_from(mtime_sec).unwrap_or(0),
                        mtime_nsec,
                    ),
                    entry_ttl: TTL,
                    attr_ttl: TTL,
                });
            }

            let parent_parent = tokio::task::spawn_blocking({
                let db = self.db.clone();
                let i = parent;
                move || db.get_parent_inode(i)
            })
            .await
            .map_err(CairnEngine::to_eio)?
            .unwrap_or(1);
            if let Ok(Some((mode, uid, gid, size, nlink, mtime_sec, mtime_nsec))) =
                tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    let i = parent_parent;
                    move || db.get_inode(i)
                })
                .await
                .map_err(CairnEngine::to_eio)?
            {
                entries.push(DirectoryEntryPlus {
                    inode: parent_parent,
                    generation: 0,
                    kind: FileType::Directory,
                    name: OsStr::new("..").into(),
                    offset: 2,
                    attr: mk_file_attr(
                        parent_parent,
                        mode,
                        uid,
                        gid,
                        size,
                        nlink,
                        // saturate a negative mtime_sec instead of a
                        // raw `as u64` sign-wrap (which yields a far-future mtime).
                        // Matches every other call site.
                        u64::try_from(mtime_sec).unwrap_or(0),
                        mtime_nsec,
                    ),
                    entry_ttl: TTL,
                    attr_ttl: TTL,
                });
            }
        }

        // Same rowid+2 offset cookie as readdir — see the comment there. The kernel
        // may continue a readdirplus listing with plain readdir calls, so both MUST
        // encode the same thing in the offset.
        // saturating cast prevents u64::MAX → negative i64 wrap.
        let after_rowid = i64::try_from(offset.saturating_sub(2)).unwrap_or(i64::MAX);
        // Name decryption runs inside this closure (see readdir's comment above
        // for why) — readdirplus is the hotter of the two, since kernels prefer
        // it (READDIRPLUS_AUTO) over plain readdir.
        let crypto = self.crypto.clone();
        #[allow(clippy::type_complexity)]
        let db_entries = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = parent;
            move || -> anyhow::Result<
                Vec<(i64, ResolvedName, u64, u32, u32, u32, u64, u32, i64, u32)>,
            > {
                let rows = db.list_dentries_rowid_after_plus(i, after_rowid, 1000)?;
                Ok(rows
                    .into_iter()
                    .map(
                        |(rowid, name, name_enc, ino, mode, uid, gid, size, nlink, mtime_sec, mtime_nsec)| {
                            let display = resolve_name(&crypto, &name, name_enc.as_deref());
                            (rowid, display, ino, mode, uid, gid, size, nlink, mtime_sec, mtime_nsec)
                        },
                    )
                    .collect())
            }
        })
        .await
        .map_err(CairnEngine::to_eio)?
        .map_err(CairnEngine::to_eio)?;

        for (rowid, display, ino, mode, uid, gid, size, nlink, mtime_sec, mtime_nsec) in db_entries
        {
            // map ALL POSIX file types, not just Dir/Symlink/Regular.
            // mk_file_attr (line 108) handles all 7 types; readdir must match.
            let kind = mode_to_filetype(mode);
            entries.push(DirectoryEntryPlus {
                inode: ino,
                generation: 0,
                kind,
                name: OsStr::new(&display.into_string()).into(),
                offset: rowid + 2,
                attr: FileAttr {
                    ino,
                    size,
                    blocks: size.div_ceil(512),
                    atime: std::time::SystemTime::UNIX_EPOCH
                    // saturate negative mtime_sec.
                    + std::time::Duration::new(u64::try_from(mtime_sec).unwrap_or(0), mtime_nsec.min(999_999_999)),
                    mtime: std::time::SystemTime::UNIX_EPOCH
                        + std::time::Duration::new(u64::try_from(mtime_sec).unwrap_or(0), mtime_nsec.min(999_999_999)),
                    ctime: std::time::SystemTime::UNIX_EPOCH
                        + std::time::Duration::new(u64::try_from(mtime_sec).unwrap_or(0), mtime_nsec.min(999_999_999)),
                    crtime: std::time::SystemTime::UNIX_EPOCH,
                    kind,
                    // 0o7777 keeps S_ISUID|S_ISGID|S_ISVTX bits.
                    // Was 0o777 which silently stripped setuid/setgid/sticky on
                    // readdirplus entries (kernel caches this, causing inconsistent
                    // FileType/perm vs stat via lookup).
                    perm: (mode & 0o7777) as u16,
                    nlink,
                    uid,
                    gid,
                    rdev: 0,
                    flags: 0,
                    blksize: 4096,
                },
                entry_ttl: TTL,
                attr_ttl: TTL,
            });
        }

        Ok(entries)
    }

    pub async fn mkdir(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
    ) -> std::io::Result<EngineReplyEntry> {
        let name_str = name.to_string_lossy();
        // apply the process umask to the requested mode
        // (FUSE passes the post-umask mode, so this is a no-op in the
        // typical case — but if a FUSE client passes a mode with setuid
        // bits set and the kernel doesn't pre-mask, we want the storage to
        // reflect the actual perm). 0o7777 keeps the full perm window.
        let dir_mode = libc::S_IFDIR | (mode & 0o7777);
        let (name_key, name_enc) = self.dentry_name_fields(parent, &name_str)?;

        match tokio::task::spawn_blocking({
            let db = self.db.clone();
            let m = dir_mode;
            let u = req.uid;
            let g = req.gid;
            let p = parent;
            let n = name_key;
            let enc = name_enc;
            move || {
                // reject mkdir if depth would exceed 4096 levels
                const MAX_MKDIR_DEPTH: u32 = 4096;
                let mut depth = 0u32;
                let mut cur = p;
                loop {
                    if cur == 1 {
                        break;
                    }
                    cur = db.get_parent_inode(cur).map_err(CairnEngine::to_eio)?;
                    depth += 1;
                    if depth >= MAX_MKDIR_DEPTH {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "directory depth exceeds limit (4096 levels)",
                        ));
                    }
                }
                db.insert_inode_with_dentry(m, u, g, 4096, 2, p, &n, enc.as_deref())
                    .map_err(CairnEngine::to_eio)
            }
        })
        .await
        .map_err(CairnEngine::to_eio)?
        {
            Ok(ino) => {
                let mtime = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default();
                let attr = mk_file_attr(
                    ino,
                    dir_mode,
                    req.uid,
                    req.gid,
                    4096,
                    2,
                    mtime.as_secs(),
                    mtime.subsec_nanos(),
                );
                Ok(EngineReplyEntry {
                    ttl: TTL,
                    attr,
                    generation: 0,
                })
            }
            Err(e) => {
                tracing::error!("DB error creating inode+dentry: {}", e);
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
        }
    }

    pub async fn mknod(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _rdev: u32,
    ) -> std::io::Result<EngineReplyEntry> {
        let name_str = name.to_string_lossy();
        // keep the kernel's full mode (S_IFMT + perm + special
        // bits). The previous `S_IFREG | (mode & 0o777)` silently turned
        // `mkfifo` / `mknod {b,c,s}` into regular files; `mkfifo` in a shell
        // pipeline would hang forever, and `cairn backup` of a directory
        // containing FIFOs would extract them as regular files.
        // Store the FULL mode (including S_IFMT) so mk_file_attr can reconstruct
        // the correct FileType on read.
        let (name_key, name_enc) = self.dentry_name_fields(parent, &name_str)?;
        match tokio::task::spawn_blocking({
            let db = self.db.clone();
            let m = mode;
            let u = req.uid;
            let g = req.gid;
            let p = parent;
            let n = name_key;
            let enc = name_enc;
            move || db.insert_inode_with_dentry(m, u, g, 0, 1, p, &n, enc.as_deref())
        })
        .await
        .map_err(CairnEngine::to_eio)?
        {
            Ok(ino) => {
                let mtime = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default();
                let attr = mk_file_attr(
                    ino,
                    mode,
                    req.uid,
                    req.gid,
                    0,
                    1,
                    mtime.as_secs(),
                    mtime.subsec_nanos(),
                );
                Ok(EngineReplyEntry {
                    ttl: TTL,
                    attr,
                    generation: 0,
                })
            }
            Err(e) => {
                tracing::error!("DB error creating inode+dentry: {}", e);
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
        }
    }

    /// `statfs` — logical size as total blocks, physical (dedup) size as
    /// used, and free space on the cache-dir filesystem as available, so `df`
    /// shows meaningful numbers on a mount (previously all zeros).
    pub async fn statfs(&self, _req: Request) -> std::io::Result<EngineStatFs> {
        let db = self.db.clone();
        let (logical, inodes) = tokio::task::spawn_blocking(move || {
            (
                db.total_logical_bytes().unwrap_or(0),
                db.total_inodes().unwrap_or(0),
            )
        })
        .await
        .map_err(CairnEngine::to_eio)?;
        let bsize: u32 = 4096;
        let bs = u64::from(bsize);
        let avail = statvfs_free_bytes(&self.cache_dir).unwrap_or(0);
        Ok(EngineStatFs {
            blocks: logical.div_ceil(bs),
            bfree: avail / bs,
            bavail: avail / bs,
            files: inodes,
            ffree: 0,
            bsize,
            namelen: 255,
            frsize: bsize,
        })
    }

    /// `create` = `mknod` + `open` in one FUSE round-trip (the common
    /// `O_CREAT|O_WRONLY` path). The kernel otherwise falls back to two calls.
    pub async fn create(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> std::io::Result<(EngineReplyEntry, u64, u32)> {
        let entry = self.mknod(req.clone(), parent, name, mode, 0).await?;
        let (fh, flags_out) = self.open(req, entry.attr.ino, flags).await?;
        Ok((entry, fh, flags_out))
    }

    pub async fn unlink(&self, _req: Request, parent: u64, name: &OsStr) -> std::io::Result<()> {
        let name_str = name.to_string_lossy();
        // --hide-names: dentries are keyed by the lookup key (the name itself in
        // normal archives, a keyed hash when hiding); look up and delete by it.
        let key = self.dentry_lookup_key(parent, &name_str)?;
        let n1 = key.clone();
        // distinguish DB errors from genuine ENOENT — previously
        // `if let Ok(Some(_ino))` silently turned any DB error into ENOENT.
        let dentry_result = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let p = parent;
            move || db.get_dentry_inode(p, &n1)
        })
        .await
        .map_err(CairnEngine::to_eio)?;
        match dentry_result {
            Ok(Some(_ino)) => {
                // propagate the unlink result instead of `let _ =`.
                // A real DB error now returns EIO; a successful unlink still
                // returns Ok(()). The `ino` binding is for symmetry with the
                // no-foreign-keys design; we don't link it to in-memory state
                // because the write_buffers entry is flushed lazily on release.
                let res = tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    let p = parent;
                    let n = key.clone();
                    move || db.atomic_unlink(p, &n, false)
                })
                .await
                .map_err(CairnEngine::to_eio)?;
                res.map(|_| ()).map_err(|e| {
                    tracing::error!("unlink: {parent}/{name:?}: {e}");
                    std::io::Error::from_raw_os_error(libc::EIO)
                })
            }
            Ok(None) => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            Err(e) => {
                tracing::error!("unlink: dentry lookup failed for {parent}/{name:?}: {e}");
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
        }
    }

    pub async fn rmdir(&self, _req: Request, parent: u64, name: &OsStr) -> std::io::Result<()> {
        let name_str = name.to_string_lossy();
        // --hide-names: look up / delete the dentry by its lookup key.
        let key = self.dentry_lookup_key(parent, &name_str)?;
        let n1 = key.clone();
        // distinguish DB errors from genuine ENOENT — previously
        // `if let Ok(Some(ino))` silently turned any DB error into ENOENT.
        let dentry_result = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let p = parent;
            move || db.get_dentry_inode(p, &n1)
        })
        .await
        .map_err(CairnEngine::to_eio)?;
        match dentry_result {
            Ok(Some(ino)) => {
                // match on the list_dentries Result so a real DB
                // error returns EIO instead of silently falling through as
                // "directory is empty" and removing a non-empty directory.
                let children = match tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    let i = ino;
                    move || db.list_dentries(i)
                })
                .await
                {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        tracing::error!("rmdir: list_dentries failed for ino {ino}: {e}");
                        return Err(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                    // log the panic message before collapsing to a generic EIO.
                    Err(join_err) => {
                        tracing::error!(
                            "rmdir: list_dentries task panicked for ino {ino}: {join_err}"
                        );
                        return Err(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                };
                if !children.is_empty() {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
                }
                let res = tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    let p = parent;
                    let n = key.clone();
                    move || db.atomic_unlink(p, &n, true)
                })
                .await
                .map_err(CairnEngine::to_eio)?;
                res.map(|_| ()).map_err(|e| {
                    tracing::error!("rmdir: {parent}/{name:?}: {e}");
                    std::io::Error::from_raw_os_error(libc::EIO)
                })
            }
            Ok(None) => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            Err(e) => {
                tracing::error!("rmdir: dentry lookup failed for {parent}/{name:?}: {e}");
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
        }
    }

    pub async fn rename(
        &self,
        _req: Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
    ) -> std::io::Result<()> {
        let name_str = name.to_string_lossy();
        let new_name_str = newname.to_string_lossy();

        // --hide-names: the source dentry is found by its OLD lookup key; the
        // moved dentry gets the NEW key AND a fresh name_enc for the new name
        // (atomic_rename refreshes name_enc so it never decrypts to the old
        // name). All are pass-through/None in normal archives.
        let old_key = self.dentry_lookup_key(parent, &name_str)?;
        let (new_key, new_name_enc) = self.dentry_name_fields(newparent, &new_name_str)?;

        // propagate the atomic_rename result. The previous
        // `let _ = ...` made a DB error invisible to the kernel — a rename
        // could half-succeed (cycle check done, target-overwrite done, dentry
        // update not done) and the caller would see Ok(()).
        let res = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let p = parent;
            let n = old_key;
            let np = newparent;
            let nn = new_key;
            let enc = new_name_enc;
            move || db.atomic_rename(p, &n, np, &nn, enc.as_deref())
        })
        .await
        .map_err(CairnEngine::to_eio)?;
        res.map(|_| ()).map_err(|e| {
            tracing::error!("rename: {parent}/{name:?} -> {newparent}/{newname:?}: {e}");
            std::io::Error::from_raw_os_error(libc::EIO)
        })
    }

    pub async fn link(
        &self,
        _req: Request,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
    ) -> std::io::Result<EngineReplyEntry> {
        // POSIX prohibits hardlinks to directories.
        let inode_info = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_inode(ino)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        .map_err(CairnEngine::to_eio)?
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
        if inode_info.0 as u32 & libc::S_IFMT == libc::S_IFDIR {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
        let new_name_str = newname.to_string_lossy();
        // --hide-names: the hardlink's new name gets its own lookup key + name_enc
        // (a shared inode with N names — the hardlink topology is visible to the
        // host regardless, per the ADR; only the name strings are hidden).
        let (new_key, new_name_enc) = self.dentry_name_fields(newparent, &new_name_str)?;
        // wrap sync DB calls in spawn_blocking.
        // add the dentry and bump nlink in ONE transaction (no
        // insert-then-increment-with-manual-rollback window). `foreign_keys=OFF`
        // means we cannot rely on a cascade; the single transaction is the guard.
        if let Err(e) = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let p = newparent;
            let n = new_key;
            let enc = new_name_enc;
            let i = ino;
            move || db.insert_dentry_with_nlink_increment(p, &n, i, enc.as_deref())
        })
        .await
        .map_err(CairnEngine::to_eio)?
        {
            tracing::error!("link: insert_dentry_with_nlink_increment failed for ino {ino}: {e}");
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }

        // Use lookup to return the ReplyEntry so it's exactly what the kernel expects
        self.lookup(_req, newparent, newname).await
    }

    pub async fn symlink(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        link: &OsStr,
    ) -> std::io::Result<EngineReplyEntry> {
        let name_str = name.to_string_lossy();
        let link_str = link.to_string_lossy();
        // symlinks have a single permission set (lrwxrwxrwx is
        // the convention; the mode bits are never honored on the symlink
        // itself but `extract` and `mkdir` need the correct 0o7777 window to
        // round-trip through the archive). FUSE does not pass a `mode` arg
        // to `symlink`, so 0o777 is the right default.
        let mode = libc::S_IFLNK | 0o777;
        // --hide-names: the symlink's NAME is hidden like any dentry. Its TARGET
        // is stored via the content path (wrap_inline / chunker), already
        // age-encrypted with the public key in asymmetric mode, so it needs no
        // separate handling here.
        let (name_key, name_enc) = self.dentry_name_fields(parent, &name_str)?;
        match tokio::task::spawn_blocking({
            let db = self.db.clone();
            let u = req.uid;
            let g = req.gid;
            let s = link_str.len() as u64;
            let p = parent;
            let n = name_key;
            let enc = name_enc;
            move || db.insert_inode_with_dentry(mode, u, g, s, 1, p, &n, enc.as_deref())
        })
        .await
        .map_err(CairnEngine::to_eio)?
        {
            Ok(ino) => {
                let link_bytes = link_str.as_bytes();
                // short symlink targets are stored as inline data
                // (same INLINE_THRESHOLD path as regular files). CDC's min chunk
                // size (16 KiB) would produce zero chunks for most symlink targets,
                // leaving readlink returning empty bytes — silent data corruption.
                if link_bytes.len() <= INLINE_THRESHOLD {
                    let wrapped = self.wrap_inline(link_bytes).map_err(CairnEngine::to_eio)?;
                    tokio::task::spawn_blocking({
                        let db = self.db.clone();
                        move || db.set_inline_data(ino, &wrapped)
                    })
                    .await
                    .map_err(CairnEngine::to_eio)?
                    .map_err(CairnEngine::to_eio)?;
                } else {
                    // propagate a chunking/upload failure instead of
                    // silently swallowing it. This chunked branch previously used
                    // `if let Ok(chunks) = …` with no `else`, so a store/upload/encrypt
                    // error left the symlink inode with ZERO chunks and `readlink`
                    // returning empty bytes — silent data loss. The inline branch
                    // above already propagates with `?`; fail with EIO here too.
                    let chunks = cairn_cdc::Chunker::process_data(
                        link_bytes,
                        &self.cache_dir,
                        self.crypto.clone(),
                        self.db.clone(),
                        self.store.clone(),
                        self.raid_mode.clone(),
                        self.async_upload,
                        None,
                    )
                    .await
                    .map_err(CairnEngine::to_eio)?;
                    // insert all chunks in a single
                    // transaction so a partial failure doesn't leave a
                    // dangling symlink with missing data.
                    let batch: Vec<_> = chunks
                        .into_iter()
                        .enumerate()
                        .map(|(idx, chunk)| {
                            (
                                ino,
                                idx,
                                chunk.hash_key.clone(),
                                chunk.plain_len,
                                chunk.comp_type,
                            )
                        })
                        .collect();
                    tokio::task::spawn_blocking({
                        let db = self.db.clone();
                        move || db.insert_file_chunks_batch(&batch)
                    })
                    .await
                    .map_err(CairnEngine::to_eio)?
                    .map_err(CairnEngine::to_eio)?;
                }

                // Use mk_file_attr for correct mtime and FileType decoding (was
                // hardcoded UNIX_EPOCH + FileType::Symlink, inconsistent with
                // lookup/getattr).
                let now = std::time::SystemTime::now();
                let ts = now
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let attr = mk_file_attr(
                    ino,
                    mode,
                    req.uid,
                    req.gid,
                    link_bytes.len() as u64,
                    1,
                    ts.as_secs(),
                    ts.subsec_nanos(),
                );
                Ok(EngineReplyEntry {
                    ttl: TTL,
                    attr,
                    generation: 0,
                })
            }
            // log the DB error before collapsing it to a generic EIO.
            Err(e) => {
                tracing::error!("symlink: insert_inode_with_dentry failed: {e}");
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
        }
    }

    pub async fn readlink(&self, _req: Request, ino: u64) -> std::io::Result<Vec<u8>> {
        // check inline data first (short symlink targets stored
        // via set_inline_data), then fall back to CDC chunks.
        let inline = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_inline_data(ino)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        .map_err(CairnEngine::to_eio)?;

        if let Some(raw) = inline {
            let data = self.unwrap_inline(&raw).map_err(CairnEngine::to_eio)?;
            // enforce PATH_MAX on inline symlink targets
            if data.len() > libc::PATH_MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "symlink target exceeds PATH_MAX",
                ));
            }
            return Ok(data.to_vec());
        }

        let chunks = self.db.get_file_chunks(ino).map_err(CairnEngine::to_eio)?;
        let mut result = Vec::new();

        for (hash, _, _, wrapped_key, comp_type, cipher_algo) in chunks {
            let cipher = self.fetch_chunk(&hash).await.map_err(CairnEngine::to_eio)?;
            let plain = self
                .crypto
                .decrypt_chunk_symmetric(&cipher, &wrapped_key, comp_type as u8, &cipher_algo)
                .map_err(CairnEngine::to_eio)?;
            // check length incrementally to avoid allocating gigabytes
            // before the PATH_MAX check catches a malicious symlink.
            result.extend_from_slice(&plain);
            if result.len() > libc::PATH_MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "symlink target exceeds PATH_MAX",
                ));
            }
        }

        Ok(result)
    }

    pub async fn setattr(
        &self,
        _req: Request,
        ino: u64,
        _fh: Option<u64>,
        set_attr: SetAttr,
    ) -> std::io::Result<FileAttr> {
        // Truncate must drop chunk data, not just the size field — otherwise
        // a rewrite (O_TRUNC) appends new chunks after the stale ones.
        if let Some(new_size) = set_attr.size {
            // Flush any pending write buffer FIRST, under the per-inode write
            // lock, so the truncate sees the full post-write state and a racing
            // write() cannot resurrect truncated data via the read-overlay.
            // Without this, `echo > f && truncate -s 0 f` could leave the old
            // buffered bytes reappearing on the next read:
            // the truncate + size update + inline clear are now in ONE tx
            // (cairn-index::truncate_inode) so a crash between the steps
            // cannot leave `size > 0` with empty chunks.
            self.flush_pending_buffer(ino).await?;

            // Inline files need engine-side handling: `truncate_inode` clears
            // inline_data unconditionally (correct only for truncate-to-0), which
            // would drop the file's content on any keep/extend truncate (soak found
            // Write[11]@0; Truncate 21132 -> read all zeros). read/extract serve
            // inline EXCLUSIVELY of chunks and require inline_len == size, so resize
            // the plaintext to new_size here (shrink drops the tail, extend
            // zero-pads); once it grows past the inline threshold, promote the
            // content to chunks (the tail is then a zero-filled hole, same as a
            // chunked truncate-extend). The crypto lives in the engine, not the DB.
            let inline_raw = tokio::task::spawn_blocking({
                let db = self.db.clone();
                move || db.get_inline_data(ino)
            })
            .await
            .map_err(CairnEngine::to_eio)?
            .map_err(CairnEngine::to_eio)?;

            let trunc_res: anyhow::Result<()> = async {
                match inline_raw {
                    Some(_) if new_size == 0 => {
                        let db = self.db.clone();
                        tokio::task::spawn_blocking(move || {
                            db.set_inline_and_clear_chunks(ino, &[])
                        })
                        .await
                        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
                    }
                    Some(raw) if new_size <= INLINE_THRESHOLD as u64 => {
                        let mut plain = self.unwrap_inline(&raw)?;
                        plain.resize(new_size as usize, 0);
                        let wrapped = self.wrap_inline(&plain)?;
                        let db = self.db.clone();
                        tokio::task::spawn_blocking(move || {
                            db.set_inline_and_clear_chunks(ino, &wrapped)
                        })
                        .await
                        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
                    }
                    Some(raw) => {
                        // Grows past inline capacity: promote content to chunks
                        // [0, L); the larger size is set by update_inode_attr below,
                        // leaving a zero-filled tail hole that read() zero-fills.
                        let plain = self.unwrap_inline(&raw)?;
                        self.promote_inline_to_chunk(ino, &plain).await?;
                    }
                    None => {
                        let db = self.db.clone();
                        tokio::task::spawn_blocking(move || db.truncate_inode(ino, new_size))
                            .await
                            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
                    }
                }
                Ok(())
            }
            .await;
            if let Err(e) = trunc_res {
                tracing::error!("setattr: truncating ino {} to {new_size}: {}", ino, e);
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
        }
        if let Err(e) = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = ino;
            let m = set_attr.mode;
            let u = set_attr.uid;
            let g = set_attr.gid;
            let s = set_attr.size;
            move || db.update_inode_attr(i, m, u, g, s)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        {
            tracing::error!("setattr: updating inode {}: {}", ino, e);
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }

        // distinguish a genuinely-missing inode (ENOENT) from a DB read error
        // on the post-update read-back. The old `if let Ok(Some(..)) … else ENOENT`
        // reported ENOENT even when the UPDATE succeeded but the read-back hit a DB
        // error — telling the caller the attribute change failed / the file vanished.
        match tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = ino;
            move || db.get_inode(i)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        {
            Ok(Some((mode, uid, gid, size, nlink, mtime_sec, mtime_nsec))) => Ok(mk_file_attr(
                ino,
                mode,
                uid,
                gid,
                size,
                nlink,
                // saturate negative mtime_sec.
                u64::try_from(mtime_sec).unwrap_or(0),
                mtime_nsec,
            )),
            Ok(None) => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            Err(e) => {
                tracing::error!("setattr: read-back get_inode({ino}) failed after update: {e}");
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
        }
    }

    pub async fn open(&self, _req: Request, ino: u64, flags: u32) -> std::io::Result<(u64, u32)> {
        #[cfg(feature = "cloud-storage")]
        {
            let is_write = flags & 3 != libc::O_RDONLY as u32;
            if is_write {
                if let Some(ref op) = self.op {
                    let lock_path = format!("locks/{ino}.lock");
                    // Atomic create-if-not-exists: the old `exists()` then
                    // `write()` was a TOCTOU race — two nodes could both see
                    // "no lock" and both write, both opening the same file for
                    // write. `write_with(if_not_exists)` is atomic on backends
                    // that support it (S3 conditional PUT, GCS ifGenerationMatch);
                    // if the backend lacks the capability the call falls back
                    // to a plain write (same risk as before, no worse). A failed
                    // conditional create means another node holds the lock → EBUSY.
                    //
                    // when the backend doesn't support conditional writes,
                    // the opendal driver may silently fall back to unconditional
                    // write. We detect the generic "capability unsupported" error
                    // and log a warning — the lock still degrades, but operators
                    // are informed.
                    let result = op
                        .write_with(&lock_path, vec![1u8])
                        .if_not_exists(true)
                        .await;
                    match result {
                        Ok(_) => {}
                        Err(e)
                            if e.to_string().contains("unsupported")
                                || e.to_string().contains("not support") =>
                        {
                            tracing::warn!(
                                "backend does not support conditional writes — \
                                 cloud lock for ino {ino} is advisory only. \
                                 Concurrent write access from multiple nodes is NOT safe: {e}"
                            );
                            // Still allow the open — but with degraded safety.
                        }
                        Err(e) => {
                            tracing::warn!("File {ino} is locked by another node: {e}");
                            return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
                        }
                    }
                }
            }
        }

        if flags & (libc::O_TRUNC as u32) != 0 {
            // O_TRUNC is an implicit truncate to 0: flush any pending buffer
            // first (same reason as setattr) so stale buffered bytes cannot
            // reappear, then drop all chunks + size + inline in ONE
            // transaction. The previous two-tx implementation
            // left a crash window where chunks were empty but `inodes.size`
            // was still pre-truncate; it also failed to clear `inline_data`,
            // so a backupped-then-truncated file would read as empty on the
            // mount but `extract` would still return the original bytes.
            self.flush_pending_buffer(ino).await?;
            tokio::task::spawn_blocking({
                let db = self.db.clone();
                move || db.truncate_inode(ino, 0)
            })
            .await
            .map_err(CairnEngine::to_eio)?
            .map_err(|e| {
                tracing::error!("open: O_TRUNC on ino {}: {}", ino, e);
                std::io::Error::from_raw_os_error(libc::EIO)
            })?;
        }
        Ok((0, 0))
    }

    pub async fn release(
        &self,
        _req: Request,
        _ino: u64,
        _fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> std::io::Result<()> {
        #[cfg(feature = "cloud-storage")]
        {
            let is_write = _flags & 3 != libc::O_RDONLY as u32;
            if is_write {
                if let Some(ref op) = self.op {
                    let lock_path = format!("locks/{_ino}.lock");
                    // a failed lock delete leaves a stale cloud write-lock, so
                    // the next write-open of this inode sees EBUSY. Log it instead of
                    // dropping the error silently.
                    if let Err(e) = op.delete(&lock_path).await {
                        tracing::warn!(
                            "release: failed to delete cloud write-lock {lock_path}: {e} — \
                             next write-open may see EBUSY"
                        );
                    }
                }
            }
        }

        // Serialize with write()/fsync() BEFORE reading the buffer (same lock
        // order as write(): write_locks → state). Snapshotting the buffer outside
        // the per-inode write lock races with a concurrent write appending to it:
        // the buffer entry would then be removed with the fresh bytes still inside
        // (data loss) and the global byte counter decremented for bytes that are
        // still resident (underflow → usize::MAX → permanent backpressure).
        let lock = self.get_write_lock(_ino);
        let _guard = lock.lock().await;

        let mut flush_err: Option<std::io::Error> = None;
        let state_arc = self.write_buffers.get(&_ino).map(|e| e.value().clone());
        if let Some(arc) = state_arc {
            let mut state = arc.lock().await;
            if state.data.is_empty() {
                drop(state);
                self.write_buffers.remove(&_ino);
            } else {
                match self
                    .flush_range(_ino, state.start_offset, &state.data)
                    .await
                {
                    Ok(()) => {
                        self.clear_write_buffer(&mut state);
                        drop(state);
                        self.write_buffers.remove(&_ino);
                    }
                    Err(e) => {
                        // Keep the buffer (and its share of the global counter) so
                        // read() can still overlay the data and a later flush retries.
                        // But do NOT return Ok: most applications never call fsync,
                        // so a silent success here would lose data without any signal.
                        // EIO tells the kernel the close did not durably persist.
                        tracing::error!(
                            "release: flush_range failed for ino {}: {}, keeping buffer for read overlay",
                            _ino,
                            e
                        );
                        flush_err = Some(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                }
            }
        }

        // Evict this inode's write-lock entry once nobody else can reach it —
        // otherwise the map grows by one Arc<Mutex> per inode ever touched
        // (~400 B each; measured ~0.4 GB extra RSS after a million creates).
        // Safe: remove_if runs under the shard write lock, and any thread
        // wanting this lock must clone the Arc through entry() under that same
        // shard lock — so strong_count == 1 proves the map holds the only Arc
        // and nobody can acquire it between the check and the removal.
        drop(_guard);
        drop(lock);
        self.write_locks
            .remove_if(&_ino, |_, l| std::sync::Arc::strong_count(l) == 1);

        if let Some(e) = flush_err {
            return Err(e);
        }
        Ok(())
    }

    pub async fn fsync(
        &self,
        _req: Request,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
    ) -> std::io::Result<()> {
        // Same lock order as write()/release(): write_locks → state. Snapshotting
        // the buffer outside the write lock let a racing write/release both flush
        // the same buffer and both fetch_sub its size — underflowing the global
        // counter to usize::MAX and locking every writer into backpressure.
        let lock = self.get_write_lock(_ino);
        let _guard = lock.lock().await;

        let state_arc = self.write_buffers.get(&_ino).map(|e| e.value().clone());
        if let Some(arc) = state_arc {
            let mut state = arc.lock().await;
            if !state.data.is_empty() {
                match self
                    .flush_range(_ino, state.start_offset, &state.data)
                    .await
                {
                    Ok(()) => {
                        self.clear_write_buffer(&mut state);
                    }
                    Err(e) => {
                        // POSIX: fsync must report failure — the data is NOT durable.
                        // The buffer is kept for read overlay and a later retry.
                        tracing::error!(
                            "fsync: flush_range failed for ino {}: {}, keeping buffer for read overlay",
                            _ino,
                            e
                        );
                        return Err(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                }
            }
        }
        Ok(())
    }

    /// Flush and clear an inode's pending write buffer under its per-inode write
    /// lock. Used by `setattr(truncate)` and `open(O_TRUNC)`: they must not race
    /// with a concurrent `write()` and must not leave a stale buffer that would
    /// resurrect truncated data on the next read-overlay. Returns `Err(EIO)`
    /// if the flush fails (the buffer is kept for read overlay, mirroring
    /// `fsync`/`release` semantics). No buffer → `Ok(())`.
    async fn flush_pending_buffer(&self, ino: u64) -> std::io::Result<()> {
        let lock = self.get_write_lock(ino);
        let _guard = lock.lock().await;

        let state_arc = self.write_buffers.get(&ino).map(|e| e.value().clone());
        if let Some(arc) = state_arc {
            let mut state = arc.lock().await;
            if !state.data.is_empty() {
                match self.flush_range(ino, state.start_offset, &state.data).await {
                    Ok(()) => {
                        self.clear_write_buffer(&mut state);
                    }
                    Err(e) => {
                        tracing::error!(
                            "flush_pending_buffer: flush_range failed for ino {}: {}, keeping buffer",
                            ino,
                            e
                        );
                        return Err(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn fallocate(
        &self,
        _req: Request,
        ino: u64,
        _fh: u64,
        offset: u64,
        length: u64,
        mode: u32,
    ) -> std::io::Result<()> {
        // Keep the existing size stable for the no-op (length 0) case.
        if length == 0 {
            return Ok(());
        }

        const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
        const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;

        let punch_hole = (mode & FALLOC_FL_PUNCH_HOLE) != 0;
        let keep_size = (mode & FALLOC_FL_KEEP_SIZE) != 0;

        // PUNCH_HOLE must be paired with KEEP_SIZE per POSIX/Linux; a hole punch
        // that also resized would be a different operation. Refuse misuse
        // loudly instead of silently doing the wrong thing.
        if punch_hole && !keep_size {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        // Serialize with write()/release() so the chunk mutation below doesn't
        // race a concurrent buffered write to the same range.
        self.flush_pending_buffer(ino).await?;

        if punch_hole {
            // Drop chunk rows in [offset, offset+length); readers will zero-fill
            // the gap (the existing read path already zero-fills missing ranges).
            // We model a hole as "no chunk rows here" + the inode size unchanged.
            let end = offset.saturating_add(length);
            if let Err(e) = tokio::task::spawn_blocking({
                let db = self.db.clone();
                move || db.drop_file_chunks_range(ino, offset, end)
            })
            .await
            .map_err(CairnEngine::to_eio)?
            {
                tracing::error!("fallocate: punch hole ino {ino}: {e}");
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            return Ok(());
        }

        // Default / KEEP_SIZE: allocate (logically) [offset, offset+length).
        // Cairn stores sparse files implicitly (a read of an unwritten range
        // zero-fills), so we only need to grow the recorded inode size when the
        // allocation extends past the current EOF and KEEP_SIZE is not set.
        if !keep_size {
            let new_end = offset.saturating_add(length);
            // enforce max_file_size — without this, fallocate can bypass
            // the size limit that write() enforces, allowing unbounded sparse files.
            if self.max_file_size > 0 && new_end > self.max_file_size {
                return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
            }
            let cur_size = tokio::task::spawn_blocking({
                let db = self.db.clone();
                let i = ino;
                move || db.get_inode(i)
            })
            .await
            .map_err(CairnEngine::to_eio)?
            .map_err(|e| {
                tracing::error!("fallocate: get_inode ino {ino}: {e}");
                std::io::Error::from_raw_os_error(libc::EIO)
            })?
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?
            .3; // size
            if new_end > cur_size {
                if let Err(e) = tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    move || db.update_inode_size(ino, new_end)
                })
                .await
                .map_err(CairnEngine::to_eio)?
                {
                    tracing::error!("fallocate: update size ino {ino}: {e}");
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
            }
        }
        Ok(())
    }

    pub async fn copy_file_range(
        &self,
        _req: Request,
        _inode_in: u64,
        _fh_in: u64,
        _offset_in: u64,
        _inode_out: u64,
        _fh_out: u64,
        _offset_out: u64,
        _length: u64,
        _flags: u64,
    ) -> std::io::Result<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    pub async fn setxattr(
        &self,
        _req: Request,
        inode: u64,
        name: &OsStr,
        value: &[u8],
        flags: u32,
        _position: u32,
    ) -> std::io::Result<()> {
        // Validate xattr name and value sizes against Linux limits.
        let name_bytes = name.as_encoded_bytes();
        if name_bytes.len() > 255 {
            return Err(std::io::Error::from_raw_os_error(libc::ERANGE));
        }
        if name_bytes.contains(&0) {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        if value.len() > 64 * 1024 {
            return Err(std::io::Error::from_raw_os_error(libc::ERANGE));
        }
        // honour FUSE's XATTR_CREATE (1) / XATTR_REPLACE (2)
        // flags. The previous version ignored them, so SELinux `setfattr -n`
        // would silently replace an existing label rather than fail.
        let flag = match flags {
            1 => cairn_index::XattrFlag::Create,
            2 => cairn_index::XattrFlag::Replace,
            _ => cairn_index::XattrFlag::None,
        };
        let result = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let n = name.to_string_lossy().to_string();
            let v = value.to_vec();
            move || db.set_xattr_with_flags(inode, &n, &v, flag)
        })
        .await
        .map_err(CairnEngine::to_eio)?;
        if let Err(e) = result {
            tracing::warn!("setxattr: failed for ino {inode} name {name:?}: {e}");
            // use typed XattrError → POSIX errno conversion instead of string matching.
            return Err(e.into());
        }
        Ok(())
    }

    pub async fn getxattr(
        &self,
        _req: Request,
        ino: u64,
        name: &OsStr,
        size: u32,
    ) -> std::io::Result<Vec<u8>> {
        // distinguish "no such xattr" from a real DB error. The previous
        // `if let Ok(Some(..))` collapsed a transient DB failure (pool exhaustion,
        // corruption) into ENODATA, so a file that genuinely has the xattr would
        // appear not to. Propagate errors as EIO; only a true miss is ENODATA.
        let val = match self.db.get_xattr(ino, &name.to_string_lossy()) {
            Ok(Some(val)) => val,
            Ok(None) => return Err(std::io::Error::from_raw_os_error(libc::ENODATA)),
            Err(e) => {
                tracing::error!("getxattr: DB error for ino {ino}: {e}");
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
        };
        if size == 0 {
            // fuse3 0.8.1 has a bug where ReplyXAttr::Size sets positive ERANGE error,
            // crashing the daemon. We bypass this by sending ReplyXAttr::Data with
            // exactly the bytes of fuse_getxattr_out.
            let mut data = Vec::with_capacity(8);
            data.extend_from_slice(&(val.len() as u32).to_ne_bytes());
            data.extend_from_slice(&[0u8; 4]);
            Ok(data)
        } else if (size as usize) < val.len() {
            Err(std::io::Error::from_raw_os_error(libc::ERANGE))
        } else {
            Ok(val)
        }
    }

    pub async fn listxattr(&self, _req: Request, ino: u64, size: u32) -> std::io::Result<Vec<u8>> {
        // a DB error here previously masqueraded as "no
        // xattrs" (the `if let Ok(names)` swallow). Propagate the error so a
        // busy / corrupt DB returns EIO instead of "no xattrs".
        let names = match tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.list_xattr(ino)
        })
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                tracing::error!("listxattr: ino {ino}: {e}");
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            // log the panic message before collapsing to a generic EIO.
            Err(join_err) => {
                tracing::error!("listxattr: ino {ino} task panicked: {join_err}");
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
        };
        {
            let mut buf = Vec::new();
            for n in names {
                buf.extend_from_slice(n.as_bytes());
                buf.push(0);
            }
            if size == 0 {
                let mut data = Vec::with_capacity(8);
                data.extend_from_slice(&(buf.len() as u32).to_ne_bytes());
                data.extend_from_slice(&[0u8; 4]);
                Ok(data)
            } else if (size as usize) < buf.len() {
                Err(std::io::Error::from_raw_os_error(libc::ERANGE))
            } else {
                Ok(buf)
            }
        }
    }

    pub async fn removexattr(&self, _req: Request, ino: u64, name: &OsStr) -> std::io::Result<()> {
        // wrap sync DB call in spawn_blocking.
        if let Err(e) = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let n = name.to_string_lossy().to_string();
            move || db.remove_xattr(ino, &n)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        {
            tracing::error!("removexattr: failed for ino {} name {:?}: {}", ino, name, e);
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }
    pub async fn destroy(&self, _req: Request) {
        // Flush every pending write buffer before the mount goes away. Without
        // this, a `release()` that failed to flush (and kept the buffer for
        // retry) would have its data silently dropped on unmount — the kernel
        // never re-calls release, so the buffer is orphaned and the bytes are
        // lost. Log each failure; we cannot surface an error out of destroy,
        // but the operator can see which inodes were not durably persisted.
        let inos: Vec<u64> = self.write_buffers.iter().map(|e| *e.key()).collect();
        for ino in inos {
            // acquire the per-inode write lock to serialize with any
            // concurrent write()/fsync() that might still be in flight (same
            // lock order as write(): write_locks -> state). Without this, a
            // concurrent write could modify state.data while destroy() reads
            // it, or create a new write_buffers entry after destroy() removes
            // it (data loss + global byte counter underflow).
            let wlock = self.get_write_lock(ino);
            let _wl = wlock.lock().await;
            let state_arc = self.write_buffers.get(&ino).map(|e| e.value().clone());
            if let Some(arc) = state_arc {
                let mut state = arc.lock().await;
                if !state.data.is_empty() {
                    match self.flush_range(ino, state.start_offset, &state.data).await {
                        Ok(()) => {
                            let flushed = state.data.len();
                            self.clear_write_buffer(&mut state);
                            tracing::info!("destroy: flushed {flushed} bytes for ino {ino}");
                        }
                        Err(e) => {
                            // a flush failure at unmount used to log
                            // "data is LOST" and silently drop the buffer — worse than
                            // the documented crash semantics because it happens on the
                            // *clean* unmount path with no durable signal. Retry a few
                            // times (the data is in memory; the error is usually
                            // transient), and if it still fails, mark the file
                            // INCOMPLETE in the index (marker) so the next
                            // `verify`/`extract` refuses it as not-fully-restorable
                            // rather than returning a silently-truncated file.
                            let mut flushed_ok = false;
                            for backoff_ms in [50u64, 200, 800] {
                                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms))
                                    .await;
                                if self
                                    .flush_range(ino, state.start_offset, &state.data)
                                    .await
                                    .is_ok()
                                {
                                    flushed_ok = true;
                                    break;
                                }
                            }
                            if flushed_ok {
                                let flushed = state.data.len();
                                self.clear_write_buffer(&mut state);
                                tracing::warn!(
                                    "destroy: flushed {flushed} bytes for ino {ino} after retry"
                                );
                            } else {
                                tracing::error!(
                                    "destroy: could not flush ino {ino} ({} bytes) after \
                                     retries: {e} — marking file INCOMPLETE so verify/extract \
                                     will flag it (un-fsync'd tail lost on unmount)",
                                    state.data.len()
                                );
                                // Durable operator signal outside the DB: FUSE destroy
                                // cannot return an error to the unmounting process.
                                let dirty_path =
                                    std::path::Path::new(&self.cache_dir).join("UNMOUNT_DIRTY");
                                let _ = std::fs::write(
                                    &dirty_path,
                                    format!(
                                        "unmount flush failed for ino {ino} ({} bytes): {e}\n\
                                         Run: cairn <archive> verify\n",
                                        state.data.len()
                                    ),
                                );
                                eprintln!(
                                    "ERROR: unmount could not flush ino {ino} — data may be incomplete. \
                                     See {} and run `cairn verify`.",
                                    dirty_path.display()
                                );
                                let db = self.db.clone();
                                match tokio::task::spawn_blocking(move || {
                                    db.mark_file_incomplete(ino)
                                })
                                .await
                                {
                                    Ok(Ok(())) => {}
                                    Ok(Err(me)) => tracing::error!(
                                        "destroy: also failed to mark ino {ino} incomplete: {me}"
                                    ),
                                    Err(je) => tracing::error!(
                                        "destroy: mark-incomplete task panicked for ino {ino}: {je}"
                                    ),
                                }
                            }
                        }
                    }
                }
                drop(state);
                self.write_buffers.remove(&ino);
            }
        }
        self.crypto.zeroize_keys();
    }
}

impl CairnEngine {
    /// Apply owner, timestamps, and xattrs from `ino` to the file at `path`.
    /// Used by the extract paths when `--preserve` is set. Mode is always applied
    /// (the extract already writes the data); owner/mtime/xattrs need privileges
    /// and failures are logged but not fatal — a non-root restore that can't
    /// chown should still produce a readable tree. Returns the xattr count set.
    #[cfg(unix)]
    async fn apply_preserved_metadata(&self, ino: u64, path: &std::path::Path) -> usize {
        use std::os::unix::fs::PermissionsExt;
        let mut applied = 0usize;

        // don't silently discard CString errors. A path
        // containing an embedded NUL would have skipped utimensat and
        // lsetxattr without complaint; warn and continue with metadata
        // restoration (chmod + chown can still proceed without the CString).
        let c_path = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!(
                    "preserve: path {path:?} contains NUL byte: {e} — skipping utimensat + lsetxattr"
                );
                None
            }
        };

        // Inode attributes (uid/gid/mtime) — fetch once.
        let attr = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = ino;
            move || db.get_inode(i)
        })
        .await;
        if let Ok(Ok(Some((mode, uid, gid, _size, _nlink, mtime_sec, mtime_nsec)))) = attr {
            // keep setuid/setgid/sticky bits (0o7777,
            // not 0o777). mtime/ctime are set to the SAME value because the
            // archive stores only mtime; atime is not stored (would need a
            // new schema column) and is not preserved.
            // Determine once whether this entry is a symlink. Every metadata op
            // below (chmod/chown/utimensat) follows symlinks by default, so
            // applying them to a symlink entry lands on its TARGET and silently
            // corrupts an unrelated file's mode/owner/mtime. This was a real bug:
            // extracting a symlink reset its target file's mtime to "now".
            let is_symlink = tokio::fs::symlink_metadata(path)
                .await
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);

            // chmod follows symlinks and Linux ignores a symlink's own permission
            // bits, so skip it for links rather than rewriting the target's mode.
            if !is_symlink {
                let perm = std::fs::Permissions::from_mode(mode & 0o7777);
                if let Err(e) = tokio::fs::set_permissions(path, perm).await {
                    tracing::warn!("preserve: chmod {:?}: {e}", path);
                }
            }
            // lchown (not chown) so a symlink's OWN ownership is set, never the
            // target's. For a regular file lchown behaves exactly like chown.
            // chown requires privilege; skip silently if not allowed.
            use std::os::unix::fs::lchown;
            if let Err(e) = lchown(path, Some(uid), Some(gid)) {
                tracing::debug!(
                    "preserve: lchown {:?} to {uid}:{gid}: {e} (need root?)",
                    path
                );
            }
            // mtime via libc utimensat (nanosecond precision).
            let times = [
                libc::timespec {
                    tv_sec: mtime_sec,
                    tv_nsec: mtime_nsec as i64,
                },
                libc::timespec {
                    tv_sec: mtime_sec,
                    tv_nsec: mtime_nsec as i64,
                },
            ];
            if let Some(cp) = &c_path {
                // AT_SYMLINK_NOFOLLOW: stamp the entry itself, never a symlink's
                // target (setting a symlink's mtime must not touch the file it
                // points at). No effect for regular files.
                let rc = unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        cp.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    tracing::warn!(
                        "preserve: utimensat {:?}: {} (errno {})",
                        path,
                        err,
                        err.raw_os_error().unwrap_or(-1)
                    );
                }
            }
        }

        // xattrs.
        // log a DB error rather than silently restoring no xattrs at all.
        let xattr_names = self.db.list_xattr(ino);
        if let Err(ref e) = xattr_names {
            tracing::warn!("preserve: list_xattr failed for ino {ino}: {e} — xattrs not restored");
        }
        if let Ok(names) = xattr_names {
            for name in names {
                // log a DB read error for one xattr (a missing value is a
                // benign skip); keep restoring the rest either way.
                let xattr_val = self.db.get_xattr(ino, &name);
                if let Err(ref e) = xattr_val {
                    tracing::warn!("preserve: get_xattr({name}) failed for ino {ino}: {e}");
                }
                if let Ok(Some(value)) = xattr_val {
                    #[cfg(unix)]
                    {
                        // Use libc::setxattr directly: std::os::unix::fs::xattr is
                        // nightly-only. `lsetxattr` operates on the symlink itself
                        // (not its target) — correct for restore semantics.
                        let Some(cp) = &c_path else { continue };
                        let c_name = match std::ffi::CString::new(name.as_bytes()) {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!("preserve: bad xattr name {name}: {e}");
                                continue;
                            }
                        };
                        let rc = unsafe {
                            libc::lsetxattr(
                                cp.as_ptr(),
                                c_name.as_ptr(),
                                value.as_ptr() as *const libc::c_void,
                                value.len(),
                                0,
                            )
                        };
                        if rc != 0 {
                            tracing::warn!(
                                "preserve: setxattr {:?} {name}: errno {} (need CAP_SYS_ADMIN for trusted.*)",
                                path,
                                unsafe { *libc::__errno_location() }
                            );
                        } else {
                            applied += 1;
                        }
                    }
                }
            }
        }
        applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statvfs_free_bytes_nul_path() {
        // CString::new rejects interior NUL bytes → .ok()? returns None
        assert!(statvfs_free_bytes("\0").is_none());
    }

    #[test]
    fn test_statvfs_free_bytes_valid_path() {
        // libc::statvfs on "/" succeeds in any container/VM
        let result = statvfs_free_bytes("/");
        assert!(result.is_some(), "statvfs on / should succeed");
        assert!(result.unwrap() > 0, "free bytes on / should be > 0");
    }

    #[test]
    fn test_to_eio() {
        let err = CairnEngine::to_eio("test error");
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
    }
}
