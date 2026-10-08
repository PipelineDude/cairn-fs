// The engine methods are now inherent (were fuse3::Filesystem trait methods) and keep
// the trait's argument shapes verbatim, so several exceed clippy's 7-arg threshold.
#![allow(clippy::too_many_arguments)]

pub mod hashing;
pub mod shared_reader;
pub mod types;
pub mod vfs;
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

/// Per-operation backup statistics, tracked via atomics on `CairnEngine`.
/// The backup handler snapshots counters before/after to compute deltas.
pub struct BackupStats {
    pub dedup_hits: std::sync::atomic::AtomicUsize,
    pub new_chunks: std::sync::atomic::AtomicUsize,
    pub bytes_deduped: std::sync::atomic::AtomicUsize,
    pub bytes_written: std::sync::atomic::AtomicUsize,
    pub files_processed: std::sync::atomic::AtomicUsize,
    pub files_skipped: std::sync::atomic::AtomicUsize,
}

impl BackupStats {
    pub fn new() -> Self {
        Self {
            dedup_hits: std::sync::atomic::AtomicUsize::new(0),
            new_chunks: std::sync::atomic::AtomicUsize::new(0),
            bytes_deduped: std::sync::atomic::AtomicUsize::new(0),
            bytes_written: std::sync::atomic::AtomicUsize::new(0),
            files_processed: std::sync::atomic::AtomicUsize::new(0),
            files_skipped: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn snapshot(&self) -> BackupStatsSnapshot {
        BackupStatsSnapshot {
            dedup_hits: self.dedup_hits.load(std::sync::atomic::Ordering::Relaxed),
            new_chunks: self.new_chunks.load(std::sync::atomic::Ordering::Relaxed),
            bytes_deduped: self
                .bytes_deduped
                .load(std::sync::atomic::Ordering::Relaxed),
            bytes_written: self
                .bytes_written
                .load(std::sync::atomic::Ordering::Relaxed),
            files_processed: self
                .files_processed
                .load(std::sync::atomic::Ordering::Relaxed),
            files_skipped: self
                .files_skipped
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        self.dedup_hits
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.new_chunks
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.bytes_deduped
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.bytes_written
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.files_processed
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.files_skipped
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for BackupStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default)]
pub struct BackupStatsSnapshot {
    pub dedup_hits: usize,
    pub new_chunks: usize,
    pub bytes_deduped: usize,
    pub bytes_written: usize,
    pub files_processed: usize,
    pub files_skipped: usize,
}

impl BackupStatsSnapshot {
    pub fn delta(&self, before: &BackupStatsSnapshot) -> BackupStatsDelta {
        BackupStatsDelta {
            dedup_hits: self.dedup_hits.saturating_sub(before.dedup_hits),
            new_chunks: self.new_chunks.saturating_sub(before.new_chunks),
            bytes_deduped: self.bytes_deduped.saturating_sub(before.bytes_deduped),
            bytes_written: self.bytes_written.saturating_sub(before.bytes_written),
            files_processed: self.files_processed.saturating_sub(before.files_processed),
            files_skipped: self.files_skipped.saturating_sub(before.files_skipped),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BackupStatsDelta {
    pub dedup_hits: usize,
    pub new_chunks: usize,
    pub bytes_deduped: usize,
    pub bytes_written: usize,
    pub files_processed: usize,
    pub files_skipped: usize,
}

impl std::fmt::Display for BackupStatsDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total_chunks = self.dedup_hits + self.new_chunks;
        let dedup_ratio = if total_chunks > 0 {
            self.dedup_hits as f64 / total_chunks as f64 * 100.0
        } else {
            0.0
        };
        let comp_ratio = if self.bytes_written > 0 && self.bytes_deduped > 0 {
            self.bytes_deduped as f64 / self.bytes_written as f64
        } else {
            0.0
        };
        write!(
            f,
            "files: {} processed, {} skipped | chunks: {} new, {} deduped ({:.1}%) | \
             bytes: {} written, {} deduped",
            self.files_processed,
            self.files_skipped,
            self.new_chunks,
            self.dedup_hits,
            dedup_ratio,
            human_bytes(self.bytes_written),
            human_bytes(self.bytes_deduped),
        )?;
        if comp_ratio > 1.0 {
            write!(f, " | compression: {:.1}x", comp_ratio)?;
        }
        Ok(())
    }
}

pub fn human_bytes(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;
    const GB: usize = 1024 * MB;
    if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

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

/// H13: read-only replica audit over all operators.  `verified` are safe to
/// skip in a resumable copy; `missing`/`corrupt` need re-copy (only READ
/// verification counts — inventory-implied presence is not proof).
#[derive(Default)]

/// H13b: outcome of a resumable read-write repair pass.
#[cfg(feature = "cloud-storage")]
#[derive(Debug)]
pub struct ReplicateReport {
    pub repaired: usize,
    pub verified_skipped: usize,
    pub unrepaired: Vec<(String, usize)>,
}

/// H13: read-only replica audit over all operators.
#[cfg(feature = "cloud-storage")]
pub struct ReplicaAudit {
    pub verified: Vec<(String, usize)>,
    pub missing: Vec<(String, usize)>,
    pub corrupt: Vec<(String, usize)>,
}

/// H14: deduplication statistics for the archive.
#[derive(Debug)]
pub struct DedupStats {
    pub logical_file_bytes: u64,
    pub inline_logical_bytes: u64,
    pub unique_object_count: usize,
    pub unique_object_bytes: u64,
    pub compressed_stored_bytes: u64,
    pub orphaned_objects: u64,
    pub savings_percent: f64,
}

/// H09: aggregate result of verifying every regular file's stored digest
/// (used by restore/scrub checks; `failed` entries break the "success" answer).
#[derive(Debug, Default)]

pub struct VerifyAllReport {
    pub verified: usize,
    pub missing_digest: usize,
    pub failed: Vec<(u64, String)>,
    /// H11: how many files were re-verified after they appeared unchanged.
    pub changed_during_read: usize,
    /// H11: total logical bytes checked across all files.
    pub bytes_read: u64,
}

/// H11: outcome of a per-file content stability check.  A stable file may
/// still fail its digest (Unverified); a file that changed concurrently while
/// we were hashing is reported separately.
pub enum VerifyOutcome {
    Verified { bytes_read: u64 },
    Unverified(String),
    ChangedDuringRead { bytes_read: u64 },
}

#[allow(dead_code)]
pub fn bytes_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SnapshotBundleManifest {
    version: u8,
    snapshot_id: u64,
    objects: Vec<String>,
    /// BF-04.4: blake3 hex of the `snapshot.db` bytes. Empty only in bundles
    /// exported before this field existed; import refuses those loudly.
    #[serde(default)]
    db_hash: String,
}

/// BF-04.9: exclusive advisory lock around a checkpoint file's
/// read-check-write. The checkpoint itself is replaced atomically (temp +
/// rename), so an flock on it cannot be held across the replace; the lock
/// therefore lives in a stable `<path>.lock` sidecar.
struct CheckpointLock {
    file: std::fs::File,
}

impl CheckpointLock {
    #[allow(unsafe_code)]
    fn acquire(path: &std::path::Path) -> anyhow::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let lock_path = std::path::PathBuf::from(lock_name);
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        // SAFETY: flock(2) on a valid fd; LOCK_EX blocks until the lock is
        // free, so concurrent recorders serialize here.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            anyhow::bail!(
                "cannot lock checkpoint {}: {}",
                lock_path.display(),
                std::io::Error::last_os_error()
            );
        }
        Ok(Self { file })
    }
}

impl Drop for CheckpointLock {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: releasing our own lock on a valid fd; drop cannot report.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl CairnEngine {
    /// Export one frozen snapshot and every ciphertext object it references.
    /// The bundle is opaque: no archive key or plaintext is required to copy it.
    pub async fn export_snapshot_bundle(
        &self,
        snap_id: u64,
        destination: &std::path::Path,
    ) -> anyhow::Result<()> {
        if destination.exists() {
            anyhow::bail!("bundle destination already exists: {destination:?}");
        }
        let parent = destination.parent().unwrap_or(std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        let temp = tempfile::Builder::new()
            .prefix(".cairn-export-")
            .tempdir_in(parent)?;
        let db_path = temp.path().join("snapshot.db");
        let ids = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.snapshot_used_objects(snap_id))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        self.db.extract_snapshot(
            snap_id,
            db_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 bundle path"))?,
        )?;
        let objects_dir = temp.path().join("chunks");
        std::fs::create_dir(&objects_dir)?;
        let mut objects: Vec<String> = ids.into_iter().collect();
        objects.sort();
        for id in &objects {
            if !Self::bundle_object_id_valid(id) {
                anyhow::bail!("invalid object id in snapshot");
            }
            let bytes = self.fetch_chunk(id).await?;
            if !crate::hashing::replica_matches(id, &bytes) {
                anyhow::bail!("cannot export corrupt object {id}");
            }
            std::fs::write(objects_dir.join(id), &bytes)?;
        }
        let manifest = SnapshotBundleManifest {
            version: 1,
            snapshot_id: snap_id,
            objects,
            db_hash: blake3::hash(&std::fs::read(&db_path)?).to_hex().to_string(),
        };
        std::fs::write(
            temp.path().join("manifest.json"),
            serde_json::to_vec(&manifest)?,
        )?;
        let temp_path = temp.keep();
        std::fs::rename(&temp_path, destination)
            .map_err(|e| anyhow::anyhow!("publish bundle failed: {e}"))?;
        Ok(())
    }

    /// Validate an opaque bundle then import its objects into a local cache.
    /// No existing cache entry is trusted or overwritten before validation.
    ///
    /// BF-04.4 hardening: the manifest must carry a matching blake3 of
    /// `snapshot.db` (otherwise a substitute DB would be imported), ids must be
    /// unique, and each object is read from disk exactly ONCE — the verified
    /// bytes are what gets written to the cache, so a file swapped between
    /// validation and publication cannot slip unverified bytes in (TOCTOU).
    pub async fn import_snapshot_bundle(
        bundle: &std::path::Path,
        cache_dir: &std::path::Path,
    ) -> anyhow::Result<u64> {
        let manifest: SnapshotBundleManifest =
            serde_json::from_slice(&std::fs::read(bundle.join("manifest.json"))?)?;
        if manifest.version != 1 || !bundle.join("snapshot.db").is_file() {
            anyhow::bail!("invalid snapshot bundle");
        }
        if manifest.db_hash.is_empty() {
            anyhow::bail!(
                "bundle manifest has no snapshot.db hash (exported by an older version); \
                 re-export the bundle"
            );
        }
        let db_bytes = std::fs::read(bundle.join("snapshot.db"))?;
        if blake3::hash(&db_bytes).to_hex().as_str() != manifest.db_hash {
            anyhow::bail!("bundle snapshot.db hash mismatch");
        }

        let mut seen = std::collections::HashSet::new();
        let mut verified: Vec<(String, Vec<u8>)> = Vec::with_capacity(manifest.objects.len());
        for id in &manifest.objects {
            if !Self::bundle_object_id_valid(id) {
                anyhow::bail!("invalid object id in bundle");
            }
            if !seen.insert(id.clone()) {
                anyhow::bail!("duplicate object id in bundle manifest");
            }
            let bytes = std::fs::read(bundle.join("chunks").join(id))?;
            if !crate::hashing::replica_matches(id, &bytes) {
                anyhow::bail!("bundle object hash mismatch");
            }
            verified.push((id.clone(), bytes));
        }

        std::fs::create_dir_all(cache_dir)?;
        for (id, bytes) in verified {
            cacache::write(cache_dir, &id, bytes).await?;
        }
        Ok(manifest.snapshot_id)
    }

    fn bundle_object_id_valid(id: &str) -> bool {
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
    }
    /// D03: shared-domain-aware chunk decrypt. When a domain key is configured
    /// (CAIRN_SHARED_DEDUP_SECRET) and the chunk is flagged `domain` in the
    /// index, decrypt via the domain path; otherwise fall back to the normal
    /// archive-scope `decrypt_chunk_symmetric`.
    fn decrypt_chunk_auto(
        &self,
        object_id: &str,
        ciphertext: &[u8],
        wrapped_key: &[u8],
        comp_type: u8,
        cipher_algo: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
        let reader = shared_reader::SharedChunkReader::from_archive_config(self.db.clone())?;
        if reader.domain_mode_active() {
            if let Some(pt) = reader.try_decrypt_domain(
                &self.crypto,
                object_id,
                ciphertext,
                wrapped_key,
                comp_type,
                cipher_algo,
            )? {
                return Ok(pt);
            }
        }
        self.crypto.decrypt_sealed_chunk(ciphertext, wrapped_key)
    }

    /// Build the shared-dedup write config from the archive-pinned domain
    /// store and secret-file path.  A configured shared archive must fail
    /// loudly when either resource is unavailable; silently falling back to
    /// archive-scoped writes breaks cross-archive deduplication.
    fn shared_dedup_write_config(
        &self,
    ) -> anyhow::Result<Option<cairn_cdc::shared::SharedDedupConfig>> {
        let Some(domain_id) = self.db.get_config("dedup_shared_domain")? else {
            return Ok(None);
        };
        let store_dir = self
            .db
            .get_config("dedup_shared_store_dir")?
            .ok_or_else(|| anyhow::anyhow!("shared-dedup archive has no shared store directory"))?;
        let secret_path = self.db.get_config("dedup_shared_secret_file")?;
        let expected = self
            .db
            .get_config("dedup_shared_namespace")?
            .ok_or_else(|| anyhow::anyhow!("shared-dedup archive has no persisted namespace"))?;
        // BF-04.10(b): the documented background path — CAIRN_SHARED_DEDUP_SECRET
        // in the environment — is now actually consulted by the engine and
        // validated against the archive's persisted namespace. The env secret
        // wins when set; a mismatch is an error, never a silent fallback.
        let secret = match std::env::var("CAIRN_SHARED_DEDUP_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(env_secret) => {
                let bytes = env_secret.into_bytes();
                if cairn_store::shared_dedup::derive_namespace(&domain_id, &bytes) != expected {
                    anyhow::bail!(
                        "CAIRN_SHARED_DEDUP_SECRET does not match this archive's configured domain"
                    );
                }
                bytes
            }
            None => {
                let secret_path = secret_path.ok_or_else(|| anyhow::anyhow!("shared-dedup archive has no secret source: set CAIRN_SHARED_DEDUP_SECRET (background) or configure a secret file at init"))?;
                let secret = std::fs::read(&secret_path).map_err(|e| {
                    anyhow::anyhow!("cannot read shared-dedup secret file {secret_path}: {e}")
                })?;
                if secret.is_empty() {
                    anyhow::bail!("shared-dedup secret file {secret_path} is empty");
                }
                secret
            }
        };
        if cairn_store::shared_dedup::derive_namespace(&domain_id, &secret) != expected {
            anyhow::bail!("shared-dedup secret does not match this archive's configured domain");
        }
        Ok(Some(cairn_cdc::shared::SharedDedupConfig {
            records_dir: store_dir,
            domain_id,
            domain_secret: secret,
        }))
    }

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

    /// Inline container: `CIN01 || BE32(wrapped record length) || wrapped record
    /// || ciphertext`. The sealed record authenticates the DEK, algorithm,
    /// compression, plaintext length, ciphertext length and ciphertext hash.
    const INLINE_SEALED_MAGIC: &'static [u8; 5] = b"CIN01";

    /// Seal inline (small-file) data before storing it in `inodes.inline_data`.
    /// Empty stays empty (`set_inline_data` treats an empty slice as NULL).
    pub fn wrap_inline(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }
        let sealed = self.crypto.seal_chunk(plaintext, Some("none"))?;
        let wrapped_len = u32::try_from(sealed.wrapped_key.len())
            .map_err(|_| anyhow::anyhow!("sealed inline record is too large"))?;
        let mut stored = Vec::with_capacity(
            Self::INLINE_SEALED_MAGIC.len()
                + 4
                + sealed.wrapped_key.len()
                + sealed.ciphertext.len(),
        );
        stored.extend_from_slice(Self::INLINE_SEALED_MAGIC);
        stored.extend_from_slice(&wrapped_len.to_be_bytes());
        stored.extend_from_slice(&sealed.wrapped_key);
        stored.extend_from_slice(&sealed.ciphertext);
        Ok(stored)
    }

    /// Inverse of [`Self::wrap_inline`]. No caller-supplied cipher or compression
    /// metadata is trusted: it comes only from the encrypted CSK02 record.
    pub fn unwrap_inline(&self, stored: &[u8]) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
        if stored.is_empty() {
            return Ok(zeroize::Zeroizing::new(Vec::new()));
        }
        let header_len = Self::INLINE_SEALED_MAGIC.len() + 4;
        if stored.len() < header_len || !stored.starts_with(Self::INLINE_SEALED_MAGIC) {
            anyhow::bail!("inline data is not a sealed CIN01 container");
        }
        let wrapped_len = u32::from_be_bytes(
            stored[Self::INLINE_SEALED_MAGIC.len()..header_len]
                .try_into()
                .expect("fixed inline length field"),
        ) as usize;
        let wrapped_end = header_len
            .checked_add(wrapped_len)
            .ok_or_else(|| anyhow::anyhow!("sealed inline length overflows"))?;
        if wrapped_len == 0 || wrapped_end >= stored.len() {
            anyhow::bail!("sealed inline container is truncated");
        }
        self.crypto
            .decrypt_sealed_chunk(&stored[wrapped_end..], &stored[header_len..wrapped_end])
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
    pub(crate) fn resolve_dentry_name(&self, lookup_key: &str, name_enc: Option<&[u8]>) -> String {
        if !self.crypto.hide_names {
            return lookup_key.to_string();
        }
        match name_enc {
            Some(blob) => match self.crypto.decrypt_name(blob) {
                Ok(name) => name,
                Err(e) => {
                    if self.crypto.has_private_key() {
                        tracing::error!(
                            "hide-names: failed to decrypt name for dentry {lookup_key} \
                             despite having the private key — the name_enc blob is corrupt; \
                             falling back to the opaque hash: {e}"
                        );
                    }
                    lookup_key.to_string()
                }
            },
            None => lookup_key.to_string(),
        }
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
                .decrypt_chunk_auto(oid, cipher, sk, comp_type, cipher_algo)
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
            .db
            .get_inode_name(ino)
            .map_err(|e| tracing::warn!("compression-hint: get_inode_name(ino={ino}) failed: {e}"))
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
            self.shared_dedup_write_config()?,
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

        // H09 digest is persisted at finalize (release), not here: computing it
        // inside flush_range would re-read every chunk on every commit and
        // disturb RMW/truncate semantics.

        Ok(())
    }

    /// H09: streaming digest of a file's logical content (sparse gaps hashed
    /// as zeroes, no full-file allocation).  Inline files hash their unwrapped
    /// inline blob; chunked files assemble chunk spans in offset order and
    /// reject overlap/duplicate placement.
    pub async fn compute_file_digest(
        &self,
        ino: u64,
    ) -> anyhow::Result<crate::hashing::FileDigest> {
        let inline = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.get_inline_data(ino))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        if let Some(wrapped) = inline {
            let data = self.unwrap_inline(&wrapped)?;
            let mut h = crate::hashing::FileHasher::new();
            h.update(&data)?;
            return Ok(h.finish());
        }
        let refs = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.get_file_chunks(ino))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        let logical_size = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.get_inode(ino))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
                .map(|inode| inode.3)
                .ok_or_else(|| anyhow::anyhow!("inode {ino} not found"))?
        };
        let mut ordered = refs;
        ordered.sort_by_key(|(_, offset, _, _, _, _)| *offset);
        let mut hasher = crate::hashing::FileHasher::new();
        let mut cursor = 0u64;
        for (oid, offset, plain_len, wrapped, comp_type, algo) in ordered {
            let cipher = self.fetch_chunk(&oid).await?;
            let plain = self.decrypt_chunk_auto(&oid, &cipher, &wrapped, comp_type as u8, &algo)?;
            let plain = plain
                .get(..plain_len)
                .ok_or_else(|| anyhow::anyhow!("chunk span exceeds decrypted data length"))?;
            let offset = offset as u64;
            if offset < cursor {
                anyhow::bail!("chunk span overlaps or duplicates earlier data");
            }
            hasher.update_zeros(offset - cursor)?;
            hasher.update(plain)?;
            cursor = offset
                .checked_add(plain.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("chunk span end overflow"))?;
        }
        if cursor > logical_size {
            anyhow::bail!("chunk spans extend beyond inode size");
        }
        hasher.update_zeros(logical_size - cursor)?;
        Ok(hasher.finish())
    }

    /// H09: compute and persist the file digest (called after each successful
    /// flush commit).
    pub async fn store_file_digest(&self, ino: u64) -> anyhow::Result<()> {
        let digest = self.compute_file_digest(ino).await?;
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.set_file_digest(ino, &digest.hash))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        Ok(())
    }

    /// H09: full-file verification against the last stored digest.  Returns an
    /// error on any mismatch (content, order or size) or missing stored digest.
    pub async fn verify_file_digest(&self, ino: u64) -> anyhow::Result<()> {
        let stored = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.get_file_digest(ino))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        }
        .ok_or_else(|| anyhow::anyhow!("file {ino} has no stored digest to verify against"))?;
        let expected = {
            let db = self.db.clone();
            let ino2 = ino;
            tokio::task::spawn_blocking(move || db.get_inode(ino2))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        }
        .map(|i| i.3)
        .unwrap_or(0);
        let actual = self.compute_file_digest(ino).await?;
        if actual.hash != stored || actual.logical_size != expected {
            anyhow::bail!(
                "file {ino} digest mismatch: expected logical size {expected}, computed logical size {}",
                actual.logical_size,
            );
        }
        Ok(())
    }

    /// H11: verify with a stable read (stat before, verify, stat after).
    /// When `(size, mtime_sec, mtime_nsec)` changes concurrently with the
    /// check, the result is `ChangedDuringRead` instead of a silent pass.
    pub async fn verify_file_stable(&self, ino: u64) -> VerifyOutcome {
        fn stat_tuple(db: &cairn_index::Db, ino: u64) -> Option<(u64, u64, u64)> {
            let inner = db.get_inode(ino).ok()??;
            let (mode, _uid, _gid, size, _nlink, mtime_sec, mtime_nsec) = inner;
            if (mode & 0o170000) != 0o100000 {
                return None;
            }
            Some((size, mtime_sec as u64, mtime_nsec as u64))
        }

        let db = self.db.clone();
        let pre = tokio::task::spawn_blocking(move || stat_tuple(&db, ino)).await;
        let Some((pre_size, pre_mtime_sec, pre_mtime_nsec)) = pre.ok().flatten() else {
            return VerifyOutcome::Unverified("inode missing or not a regular file".into());
        };

        match self.verify_file_digest(ino).await {
            Err(e) => VerifyOutcome::Unverified(e.to_string()),
            Ok(()) => {
                let db = self.db.clone();
                let post = tokio::task::spawn_blocking(move || stat_tuple(&db, ino)).await;
                let post_t = post.ok().flatten();
                let changed = match post_t {
                    Some((ps, pms, pmn)) => {
                        (ps, pms, pmn) != (pre_size, pre_mtime_sec, pre_mtime_nsec)
                    }
                    None => true,
                };
                if changed {
                    VerifyOutcome::ChangedDuringRead {
                        bytes_read: pre_size,
                    }
                } else {
                    VerifyOutcome::Verified {
                        bytes_read: pre_size,
                    }
                }
            }
        }
    }

    /// H09/H08: restore-check over the WHOLE tree.  Returns how many files
    /// verified against their stored digest and, when a digest is missing,
    /// the reason — so a restore/scrub can fail (or report) instead of
    /// silently assuming success.  Call this after a restore completes.
    pub async fn verify_all_file_digests(&self) -> anyhow::Result<VerifyAllReport> {
        let regular = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.list_regular_files())
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        let mut report = VerifyAllReport::default();
        for (ino, _size) in regular {
            match self.verify_file_stable(ino).await {
                VerifyOutcome::Verified { bytes_read } => {
                    report.verified += 1;
                    report.bytes_read += bytes_read;
                }
                VerifyOutcome::ChangedDuringRead { bytes_read } => {
                    report.changed_during_read += 1;
                    report.bytes_read += bytes_read;
                }
                VerifyOutcome::Unverified(msg) => {
                    if msg.contains("no stored digest") {
                        report.missing_digest += 1;
                    } else {
                        report.failed.push((ino, msg));
                    }
                }
            }
        }
        Ok(report)
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
            self.shared_dedup_write_config()?,
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
        match self
            .store
            .fetch_chunk(
                hash_key,
                &self.raid_mode,
                self.skip_read_verify,
                self.auto_heal,
                self.force_remote_read,
            )
            .await
        {
            Ok(ciphertext) => Ok(ciphertext),
            Err(original) if self.db.get_chunk_domain(hash_key)? => {
                let store_dir = self
                    .db
                    .get_config("dedup_shared_store_dir")?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "shared-domain chunk {hash_key} has no configured domain store"
                        )
                    })?;
                let namespace = self
                    .db
                    .get_config("dedup_shared_namespace")?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "shared-domain chunk {hash_key} has no configured namespace"
                        )
                    })?;
                let ciphertext =
                    cairn_store::shared_dedup::read_shared_object(&store_dir, &namespace, hash_key)
                        .map_err(|e| {
                            anyhow::anyhow!("{original}; shared-domain fallback failed: {e}")
                        })?;
                cacache::write(&self.cache_dir, hash_key, &ciphertext).await?;
                Ok(ciphertext)
            }
            Err(original) => Err(original),
        }
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
            let sealed = self
                .crypto
                .seal_chunk(slice, None)
                .map_err(|e| anyhow::anyhow!("Crypto error: {e}"))?;

            let manifest_chunk = crate::ManifestChunk {
                hash: sealed.object_id,
                wrapped_key: sealed.wrapped_key,
                comp_type: sealed.comp_type,
                cipher_algo: sealed.cipher_algo,
            };
            let hash = manifest_chunk.hash.clone();
            let ciphertext = sealed.ciphertext;
            let comp_type = manifest_chunk.comp_type;
            let wrapped_key = manifest_chunk.wrapped_key;

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

        let sealed_manifest = self
            .crypto
            .seal_chunk(&manifest_bytes, None)
            .map_err(|e| anyhow::anyhow!("Crypto error: {e}"))?;
        let ciphertext = sealed_manifest.ciphertext;
        let comp_type = sealed_manifest.comp_type;
        let wrapped_key = sealed_manifest.wrapped_key;

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

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ManifestChunk {
    pub hash: String,
    pub wrapped_key: Vec<u8>,
    pub comp_type: u8,
    pub cipher_algo: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub chunks: Vec<ManifestChunk>,
}

#[cfg(feature = "cloud-storage")]
pub async fn restore_index_from_cloud(
    operators: &[cairn_store::CloudOperator],
    crypto: &cairn_seal::CryptoCtx,
    archive_path: &str,
    cache_dir: &str,
    raid_mode: &str,
) -> anyhow::Result<()> {
    if operators.is_empty() {
        return Err(anyhow::anyhow!("No cloud operators configured for restore"));
    }

    tracing::info!("Downloading index database backup from S3...");
    let s3_path = "meta/archive.db.enc";

    // Try to read from the first operator that succeeds
    let mut data = None;
    for op in operators {
        match op.read(s3_path).await {
            Ok(d) => {
                data = Some(d);
                break;
            }
            // don't silently skip a failing backend — "first success wins"
            // is fine, but a steadily-degrading backend must not be invisible.
            Err(e) => tracing::warn!(
                "restore_index_from_cloud: a backend read failed, trying the next: {e}"
            ),
        }
    }

    let data = data
        .ok_or_else(|| anyhow::anyhow!("Failed to download index backup from any S3 operator"))?;
    let data = data.to_vec();

    if data.len() < 4 {
        return Err(anyhow::anyhow!("Downloaded index backup is too small"));
    }

    let wk_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + wk_len + 2 {
        return Err(anyhow::anyhow!(
            "Downloaded index backup is corrupted (invalid key length)"
        ));
    }

    let wrapped_key = &data[2..2 + wk_len];
    let _comp_type = data[2 + wk_len];
    let algo_len = data[2 + wk_len + 1] as usize;

    if data.len() < 2 + wk_len + 2 + algo_len {
        return Err(anyhow::anyhow!(
            "Downloaded index backup is corrupted (invalid algo length)"
        ));
    }

    let algo_bytes = &data[2 + wk_len + 2..2 + wk_len + 2 + algo_len];
    let _cipher_algo = String::from_utf8(algo_bytes.to_vec())
        .map_err(|_| anyhow::anyhow!("Invalid cipher algo in backup"))?;

    let ciphertext = &data[2 + wk_len + 2 + algo_len..];

    tracing::info!("Decrypting index database manifest...");
    let manifest_bytes = crypto
        .decrypt_sealed_chunk(ciphertext, wrapped_key)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt index backup: {e}"))?;

    let manifest: crate::Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse index manifest: {e}"))?;

    use cairn_store::ChunkStore;
    let store = cairn_store::CairnStore::new(cache_dir.to_string(), operators.to_vec(), None);

    let mut db_bytes = Vec::new();
    for chunk in manifest.chunks {
        let cipher = store
            .fetch_chunk(&chunk.hash, raid_mode, false, false, false)
            .await?;
        let dec = crypto
            .decrypt_sealed_chunk(&cipher, &chunk.wrapped_key)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt index chunk {}: {}", chunk.hash, e))?;
        db_bytes.extend_from_slice(&dec);
    }

    std::fs::write(archive_path, db_bytes)?;
    tracing::info!("Successfully restored index database to {}", archive_path);

    Ok(())
}

// Concrete directory-listing stream types (were the Filesystem assoc types). The
// thin adapter (cairn-fuse) re-declares its GATs as aliases of these.

// These are the filesystem OPERATIONS as INHERENT methods (they keep the exact
// fuse3 signatures the trait had). cairn-fuse's `impl Filesystem for CairnFs`
// delegates to each of them. cairn-core stays fuse3-typed (engine/adapter seam,
// not a fuse-independent core — see MIGRATION.md).
impl CairnEngine {
    /// H12: compare the protected reference set (chunk_index) with every
    /// durable ciphertext object present in the pool's backends.  Returns
    /// missing, corrupt and unreferenced sets.  Requires at least one
    /// cloud operator (the local-only backend doesn't list remote objects).
    #[cfg(feature = "cloud-storage")]
    pub async fn archive_inventory(&self) -> anyhow::Result<crate::hashing::InventoryReport> {
        let referenced = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.list_all_object_hashes())
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };

        let mut available: Vec<(String, Vec<u8>)> = Vec::new();
        for op in &self.operators {
            let lister = op
                .list("chunks/")
                .await
                .map_err(|e| anyhow::anyhow!("list chunks/ failed: {e}"))?;
            for entry in lister {
                let path = entry.path();
                let id = path.strip_prefix("chunks/").unwrap_or(path).to_string();
                let bytes = op
                    .read(path)
                    .await
                    .map_err(|e| anyhow::anyhow!("read {path}: {e}"))?
                    .to_vec();
                available.push((id, bytes));
            }
        }
        // Remote listings are not a transactionally consistent snapshot of all
        // stores.  A concurrent publish can otherwise be reported as an orphan.
        // Callers must obtain a separate completeness proof before using this
        // report to plan destructive reclamation.
        Ok(crate::hashing::inventory_report(
            referenced, available, false,
        ))
    }

    /// H13: read-only replication audit.  For every referenced object checks,
    /// per configured operator, whether the durable replica is PRESENT and
    /// byte-exact (`replica_matches` — blake3 of stored bytes === object id).
    /// No writes are performed; verified-only objects are the safe skip-set for
    /// a later resumable copy.
    #[cfg(feature = "cloud-storage")]
    pub async fn replication_audit(&self) -> anyhow::Result<ReplicaAudit> {
        // BF-04.8: this audit models "one full ciphertext replica per backend",
        // which is only true for raid1/fallback. On raid0/raid10 a healthy
        // backend legitimately lacks most objects (reported missing), and on
        // raid5/6 every shard hashes differently from the object id (reported
        // corrupt). Refuse loudly instead of reporting a healthy array as
        // damaged until a layout-aware audit exists.
        if !matches!(self.raid_mode.as_str(), "" | "1" | "raid1") {
            anyhow::bail!(
                "replica audit is not layout-aware for raid_mode '{}': one-replica-per-backend \
                 accounting would report healthy backends as missing/corrupt",
                self.raid_mode
            );
        }
        let object_ids = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.list_all_object_hashes())
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        let mut verified: Vec<(String, usize)> = Vec::new();
        let mut missing: Vec<(String, usize)> = Vec::new();
        let mut corrupt: Vec<(String, usize)> = Vec::new();

        for (op_index, op) in self.operators.iter().enumerate() {
            for id in &object_ids {
                let path = format!("chunks/{id}");
                match op.read(&path).await {
                    Ok(buf) => {
                        if crate::hashing::replica_matches(id, &buf.to_vec()) {
                            verified.push((id.clone(), op_index));
                        } else {
                            corrupt.push((id.clone(), op_index));
                        }
                    }
                    Err(_) => missing.push((id.clone(), op_index)),
                }
            }
        }
        Ok(ReplicaAudit {
            verified,
            missing,
            corrupt,
        })
    }

    /// H13b: resumable read-write repair.  For each referenced object, copies
    /// from the FIRST healthy source (a store replica or the local cache —
    /// always verified by `replica_matches`) into every other store where the
    /// replica is missing or corrupt.  Never claims success for an object with
    /// NO verified source; never repairs from an unverified source.
    #[cfg(feature = "cloud-storage")]
    pub async fn replicate_repair(&self) -> anyhow::Result<ReplicateReport> {
        // A RAID5/6 backend stores distinct encoded shards, not the raw
        // ciphertext addressed by `object_id`.  This repair loop operates on
        // whole ciphertext replicas; writing those bytes into a shard slot
        // would corrupt an otherwise recoverable stripe.  Refuse until a
        // shard-aware repair primitive exists.
        //
        // BF-04.8: raid0/raid10 are refused too — this loop writes the full
        // ciphertext to EVERY backend whose read fails, which silently turns a
        // 1-of-N (raid0) or 2-of-N (raid10) layout into N full copies.
        if !matches!(self.raid_mode.as_str(), "" | "1" | "raid1") {
            anyhow::bail!(
                "replica repair is not layout-aware for raid_mode '{}'; writing whole replicas \
                 would corrupt shards (raid5/6) or amplify copies (raid0/raid10)",
                self.raid_mode
            );
        }
        let object_ids = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.list_all_object_hashes())
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        let mut repaired = 0usize;
        let mut verified_skipped = 0usize;
        let mut unrepaired: Vec<(String, usize)> = Vec::new();

        for id in &object_ids {
            let path = format!("chunks/{id}");
            let mut source: Option<Vec<u8>> = None;
            for op in &self.operators {
                if let Ok(buf) = op.read(&path).await {
                    if crate::hashing::replica_matches(id, &buf.to_vec()) {
                        source = Some(buf.to_vec());
                        break;
                    }
                }
            }
            if source.is_none() {
                if let Ok(buf) = cacache::read(&self.cache_dir, id).await {
                    let buf = buf.to_vec();
                    if crate::hashing::replica_matches(id, &buf) {
                        source = Some(buf);
                    }
                }
            }

            let Some(source) = source else {
                for (idx, _op) in self.operators.iter().enumerate() {
                    unrepaired.push((id.clone(), idx));
                }
                continue;
            };

            for (op_index, op) in self.operators.iter().enumerate() {
                let healthy = match op.read(&path).await {
                    Ok(buf) => crate::hashing::replica_matches(id, &buf.to_vec()),
                    Err(_) => false,
                };
                if healthy {
                    verified_skipped += 1;
                } else {
                    op.write(&path, source.clone())
                        .await
                        .map_err(|e| anyhow::anyhow!("repair write {path}: {e}"))?;
                    match op.read(&path).await {
                        Ok(written) if crate::hashing::replica_matches(id, &written.to_vec()) => {
                            repaired += 1;
                        }
                        _ => unrepaired.push((id.clone(), op_index)),
                    }
                }
            }
        }
        Ok(ReplicateReport {
            repaired,
            verified_skipped,
            unrepaired,
        })
    }

    /// H14: deduplication statistics.  Logical file bytes (regular incl.
    /// inline), ACTUAL stored ciphertext bytes (each unique object read once),
    /// naive stored figure (sum of compressed plaintext lengths), orphan count
    /// and achieved savings.  Inline adds logical bytes but no pool objects.
    /// Cost: reads every unique object once.
    pub async fn dedup_stats(&self) -> anyhow::Result<DedupStats> {
        let regular = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.list_regular_files())
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        let mut logical_file_bytes = 0u64;
        let mut inline_logical_bytes = 0u64;
        for (ino, size) in regular {
            logical_file_bytes += size;
            let is_inline = {
                let db = self.db.clone();
                tokio::task::spawn_blocking(move || db.get_inline_data(ino))
                    .await
                    .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
            }
            .is_some();
            if is_inline {
                inline_logical_bytes += size;
            }
        }
        let unique_objects = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.list_all_object_hashes())
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        let mut unique_object_bytes = 0u64;
        for id in &unique_objects {
            let bytes = self.fetch_chunk(id).await?;
            unique_object_bytes += bytes.len() as u64;
        }
        let compressed_stored_bytes = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.total_plain_bytes())
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        let orphaned = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.get_orphaned_chunks(0))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?
                .unwrap_or_default()
        };
        let savings_percent = if logical_file_bytes > 0 {
            (1.0 - unique_object_bytes as f64 / logical_file_bytes as f64).max(0.0) * 100.0
        } else {
            0.0
        };
        Ok(DedupStats {
            logical_file_bytes,
            inline_logical_bytes,
            unique_object_count: unique_objects.len(),
            unique_object_bytes,
            compressed_stored_bytes,
            orphaned_objects: orphaned.len() as u64,
            savings_percent,
        })
    }

    /// H15: record the newest snapshot's tree root as a TRUSTED CHECKPOINT
    /// OUTSIDE the attackable stores (e.g. an admin-machine file that is never
    /// written by the cloud backends).  The checkpoint is advanced only for a
    /// strictly-newer immutable snapshot id and only when the snapshot has an authenticated
    /// root — losing/refusing the checkpoint must fail, never silently trust.
    pub async fn record_checkpoint(
        &self,
        snap_id: u64,
        checkpoint_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let (seq, root) = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || {
                let snaps = db.list_snapshots()?;
                let snap = snaps
                    .iter()
                    .find(|(id, _, _)| *id == snap_id)
                    .ok_or_else(|| anyhow::anyhow!("snapshot {snap_id} not found"))?;
                let root = db.snapshot_tree_root(snap.0)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "snapshot {snap_id} has no authenticated root; refusing to checkpoint"
                    )
                })?;
                Ok::<_, anyhow::Error>((snap.0, root))
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };

        // Atomic replace; never regress the checkpoint to an older timestamp.
        // BF-04.9: the read-check-write runs under an exclusive file lock, so
        // two concurrent recorders cannot both pass the sequence check and let
        // the older write win.
        let _lock = CheckpointLock::acquire(checkpoint_path)?;
        let existing = Self::read_checkpoint(checkpoint_path)?;
        if let Some((exists_seq, _)) = existing {
            if seq <= exists_seq {
                anyhow::bail!(
                    "checkpoint at {checkpoint_path:?} already at seq {exists_seq}; refusing to regress to {seq}"
                );
            }
        }
        let payload = format!("seq={seq}\nroot={}\n", bytes_hex(&root));
        Self::atomic_write_private(checkpoint_path, payload.as_bytes())?;
        Ok(())
    }

    /// Deliberately replace a checkpoint after an operator-approved retention
    /// rollback.  This is intentionally separate from `record_checkpoint` so
    /// ordinary callers retain the no-regression guarantee.
    pub async fn recheckpoint_after_prune(
        &self,
        snap_id: u64,
        checkpoint_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let root = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || {
                db.snapshot_tree_root(snap_id)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "snapshot {snap_id} has no authenticated root; refusing to checkpoint"
                    )
                })
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        // BF-04.9: serialize explicit re-anchors with ordinary recordings too
        // (the rewrite itself remains deliberate and unconditional).
        let _lock = CheckpointLock::acquire(checkpoint_path)?;
        let payload = format!("seq={snap_id}\nroot={}\n", bytes_hex(&root));
        Self::atomic_write_private(checkpoint_path, payload.as_bytes())
    }

    /// H15: verify that `snap_id` is the latest state per the trusted
    /// checkpoint -- rejects an older snapshot (rollback) and a root mismatch
    /// (tampering).  A missing/corrupt checkpoint is an explicit refusal,
    /// never a silent pass.
    pub async fn verify_snapshot_against_checkpoint(
        &self,
        snap_id: u64,
        checkpoint_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let (seq, root) = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || {
                let snaps = db.list_snapshots()?;
                let snap = snaps
                    .iter()
                    .find(|(id, _, _)| *id == snap_id)
                    .ok_or_else(|| anyhow::anyhow!("snapshot {snap_id} not found"))?;
                let root = db.snapshot_tree_root(snap.0)?.ok_or_else(|| {
                    anyhow::anyhow!("snapshot {snap_id} has no authenticated root")
                })?;
                Ok::<_, anyhow::Error>((snap.0, root))
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };
        let Some((cp_seq, cp_root)) = Self::read_checkpoint(checkpoint_path)? else {
            anyhow::bail!("no trusted checkpoint at {checkpoint_path:?}; refusing to validate");
        };
        if cp_seq > seq {
            anyhow::bail!(
                "snapshot {snap_id} (seq {seq}) is OLDER than the checkpoint (seq {cp_seq}) -- rollback"
            );
        }
        if cp_seq == seq && cp_root != root {
            anyhow::bail!("snapshot root does not match the trusted checkpoint (tampered)");
        }
        Ok(())
    }

    const SNAPSHOT_ROOT_INO: u64 = 1;

    /// H15: restore ONE file from a snapshot, authenticated end-to-end:
    /// 1. the snapshot must not be older than the TRUSTED checkpoint (rollback),
    /// 2. the file's leaf hash (kind·mode·name·file_digest) must be provably a
    ///    member of the snapshot's authenticated Merkle root (an inclusion
    ///    chain walked from the leaf up to `snapshot_tree_root`),
    /// 3. the chunk data read back from the store must match the stored file
    ///    digest (a path/digest mismatch is a loud error, never a silent file),
    /// 4. the result is written atomically (temp + rename) to `out_path`.
    ///
    /// `path` is root-relative (`"a/b.txt"` or `"/a/b.txt"`). Directories and
    /// symlinks are rejected: only authenticated regular files are restorable.
    pub async fn restore_path_from_snapshot(
        &self,
        snap_id: u64,
        path: &str,
        checkpoint_path: &std::path::Path,
        out_path: &std::path::Path,
    ) -> anyhow::Result<u64> {
        // Freshness gate first: an old snapshot must not silently win.
        self.verify_snapshot_against_checkpoint(snap_id, checkpoint_path)
            .await?;

        let expected_root = {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || db.snapshot_tree_root(snap_id))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
                .ok_or_else(|| anyhow::anyhow!("snapshot {snap_id} has no authenticated root"))?
        };

        // Materialize the snapshot's point-in-time database (temp file) and
        // open it with the SAME credentials as the live archive.
        let snap_dir = tempfile::tempdir()?;
        let snap_file = snap_dir.path().join("snapshot.db");
        {
            let db = self.db.clone();
            let f = snap_file.clone();
            tokio::task::spawn_blocking(move || db.extract_snapshot(snap_id, f.to_str().unwrap()))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        }
        let snap_db = {
            let db = self.db.clone();
            let f = snap_file.clone();
            tokio::task::spawn_blocking(move || {
                // BF-04.2: the frozen copy was written with the ARCHIVE's cipher
                // parameters; opening it with Db defaults makes every archive
                // created with a non-default --db-kdf-iter / CAIRN_KDF_ITER
                // unreadable here (wrong password error) even though the live
                // DB opens fine.
                let tuning = cairn_index::DbTuning {
                    kdf_iter: db.kdf_iter(),
                    ..Default::default()
                };
                cairn_index::Db::new_with_tuning(f.to_str().unwrap(), db.password(), &tuning)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        };

        let (ino, name, mode, parent_ino) = {
            let db = snap_db.clone();
            let p = path.to_string();
            tokio::task::spawn_blocking(move || Self::resolve_path_db(&db, &p))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
                .ok_or_else(|| anyhow::anyhow!("path {path:?} not found in snapshot {snap_id}"))?
        };

        // Inclusion chain: prove the leaf is in the snapshot's authenticated root.
        {
            let db = snap_db.clone();
            let (i, n, m) = (ino, name.clone(), mode);
            tokio::task::spawn_blocking(move || {
                Self::verify_snapshot_inclusion(&db, i, &n, m, parent_ino, expected_root)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        }

        let content = self
            .read_file_all_from_db(&snap_db, ino)
            .await?
            .ok_or_else(|| anyhow::anyhow!("inode {ino} has no readable content"))?;

        // The restored bytes must match the stored file digest (the same value
        // the snapshot leaf binds) before anything touches `out_path`.
        let stored_hash = {
            let db = snap_db.clone();
            let i = ino;
            tokio::task::spawn_blocking(move || db.get_file_digest(i))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
                .ok_or_else(|| anyhow::anyhow!("inode {ino} has no authenticated digest"))?
        };
        let stored_size = {
            let db = snap_db.clone();
            let i = ino;
            tokio::task::spawn_blocking(move || db.get_inode(i))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
                .map(|(_, _, _, size, _, _, _)| size)
                .ok_or_else(|| anyhow::anyhow!("inode {ino} missing"))?
        };
        let mut fh = crate::hashing::FileHasher::new();
        fh.update(&content)?;
        let actual_digest = fh.finish();
        if actual_digest.hash != stored_hash || actual_digest.logical_size != stored_size {
            anyhow::bail!("restored file digest does not match snapshot (corrupt or tampered)");
        }

        // Atomic write: temp in the same directory, fsync, rename.
        let parent = out_path.parent().unwrap_or(std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        Self::atomic_write_private(out_path, &content)?;

        Ok(content.len() as u64)
    }

    /// Resolve a root-relative path (`"a/b.txt"` or `"/a/b.txt"`) inside the
    /// given database to its inode. Returns `(ino, basename, mode)`.
    /// BF-04.3: also return the dentry's actual parent inode. A hardlinked
    /// inode has several parents, and `Db::get_parent_inode` (LIMIT 1) may
    /// return one that does not correspond to the requested path — the caller
    /// must thread the resolved (parent, name) into the inclusion proof.
    fn resolve_path_db(
        db: &cairn_index::Db,
        path: &str,
    ) -> anyhow::Result<Option<(u64, String, u32, u64)>> {
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if comps.is_empty() {
            return Ok(None); // the tree root itself is not a file
        }
        let mut parent = Self::SNAPSHOT_ROOT_INO;
        for (i, comp) in comps.iter().enumerate() {
            if *comp == "." || *comp == ".." {
                anyhow::bail!("path must not contain '.' or '..' components");
            }
            let ino = match db.get_dentry_inode(parent, comp)? {
                Some(ino) => ino,
                None => return Ok(None),
            };
            if i == comps.len() - 1 {
                let mode = match db.get_inode(ino)? {
                    Some((mode, _, _, _, _, _, _)) => mode,
                    None => return Ok(None),
                };
                return Ok(Some((ino, comp.to_string(), mode, parent)));
            }
            parent = ino;
        }
        Ok(None)
    }

    fn snapshot_kind(mode: u32) -> Option<u8> {
        match mode & 0o170000 {
            0o040000 => Some(2), // directory
            0o100000 => Some(1), // regular file
            0o120000 => Some(3), // symlink target digest
            _ => None,           // fifo/…: not authenticated
        }
    }

    /// H15: leaf hash in the exact encoding of `cairn-index::node_hash` /
    /// `tree_root` (kind·mode, length-prefixed name, content hash WITHOUT a
    /// separate logical_size — the size is already bound inside the file
    /// digest). The stored snapshot root and the trusted checkpoint are both
    /// produced by `tree_root`, so the inclusion chain must use THIS encoding,
    /// not the flat-list `hashing::snapshot_entry_hash` (which additionally
    /// binds `logical_size`).
    fn snapshot_leaf(kind: u8, mode: u32, name: &str, content: [u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("cairn snapshot entry v1");
        h.update(&[kind]);
        h.update(&mode.to_le_bytes());
        h.update(&(name.len() as u64).to_le_bytes());
        h.update(name.as_bytes());
        h.update(&content);
        *h.finalize().as_bytes()
    }

    /// Walk the inclusion chain from a node up to the snapshot root and prove
    /// (with Merkle inclusion proofs at every level) that the node's leaf hash
    /// is a member of `expected_root`. Directory contents bind
    /// `merkle_root_consistent(children)` exactly like `cairn-index::tree_root`.
    fn verify_snapshot_inclusion(
        db: &cairn_index::Db,
        mut cur_ino: u64,
        cur_name: &str,
        cur_mode: u32,
        parent_ino: u64,
        expected_root: [u8; 32],
    ) -> anyhow::Result<()> {
        // Owned so the climb can replace it with each ancestor's name; the
        // caller's `cur_name` is the exact dentry name of the requested path.
        let mut cur_name = cur_name.to_string();
        // BF-04.3: the first hop must use the PARENT OF THE REQUESTED PATH, not
        // `get_parent_inode` (LIMIT 1, arbitrary for hardlinks); deeper hops are
        // directories, which have exactly one dentry.
        let mut known_parent: Option<u64> = Some(parent_ino);
        let mut cur_hash = {
            let kind = Self::snapshot_kind(cur_mode)
                .ok_or_else(|| anyhow::anyhow!("node {cur_name:?} is not an authenticated kind"))?;
            let content = if kind == 1 || kind == 3 {
                db.get_file_digest(cur_ino)?
                    .ok_or_else(|| anyhow::anyhow!("node {cur_name:?} has no stored digest"))?
            } else {
                anyhow::bail!("path resolves to a non-file node");
            };
            Self::snapshot_leaf(kind, cur_mode, &cur_name, content)
        };

        loop {
            // Reaching the root node: the final entry hash binds the empty name.
            if cur_ino == Self::SNAPSHOT_ROOT_INO {
                if cur_hash != expected_root {
                    anyhow::bail!("inclusion chain does not match the snapshot root (tampered)");
                }
                return Ok(());
            }

            let parent = match known_parent.take() {
                Some(p) => p,
                None => db.get_parent_inode(cur_ino)?,
            };
            let children = db
                .children_nodes(parent)?
                .ok_or_else(|| anyhow::anyhow!("tree not fully authenticated at parent"))?;
            // Match (name, inode) — the same inode can legitimately appear
            // several times under one parent (two hardlinks in one directory),
            // and an id-only match could select the sibling entry, failing a
            // healthy file's proof.
            let idx = children
                .iter()
                .position(|(n, id, _, _)| *id == cur_ino && n == &cur_name)
                .or_else(|| children.iter().position(|(_, id, _, _)| *id == cur_ino))
                .ok_or_else(|| anyhow::anyhow!("inode {cur_ino} not found among its parent"))?;
            let hashes: Vec<[u8; 32]> = children.iter().map(|(_, _, _, h)| *h).collect();

            let proof = crate::hashing::merkle_proof_for(&hashes, idx).ok_or_else(|| {
                anyhow::anyhow!("cannot build inclusion proof for inode {cur_ino}")
            })?;
            let children_root = crate::hashing::merkle_root_consistent(&hashes);
            if !crate::hashing::verify_merkle_inclusion(&children_root, &cur_hash, &proof) {
                anyhow::bail!("inclusion proof failed at parent of inode {cur_ino} (tampered)");
            }

            if parent == Self::SNAPSHOT_ROOT_INO {
                // Parent is the root directory: its entry hash (empty name) is
                // the tree root itself anchored by the stored snapshot root.
                let p_mode = match db.get_inode(parent)? {
                    Some((mode, _, _, _, _, _, _)) => mode,
                    None => anyhow::bail!("parent inode missing"),
                };
                let root_leaf = Self::snapshot_leaf(2, p_mode, "", children_root);
                if root_leaf != expected_root {
                    anyhow::bail!("inclusion chain does not match the snapshot root (tampered)");
                }
                return Ok(());
            }

            // Otherwise climb: the parent's own node hash enters its parent.
            let (p_name, p_mode) = match db.get_inode(parent)? {
                Some((mode, _, _, _, _, _, _)) => (db.get_inode_name(parent)?, mode),
                None => anyhow::bail!("parent inode missing"),
            };
            cur_hash = Self::snapshot_leaf(2, p_mode, &p_name, children_root);
            cur_ino = parent;
            cur_name = p_name;
        }
    }

    /// Parse the trusted checkpoint file; returns None when it is absent.
    fn read_checkpoint(path: &std::path::Path) -> anyhow::Result<Option<(u64, [u8; 32])>> {
        let raw = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => anyhow::bail!("cannot read checkpoint {path:?}: {e}"),
        };
        let text =
            std::str::from_utf8(&raw).map_err(|_| anyhow::anyhow!("checkpoint is not UTF-8"))?;
        let mut seq: Option<u64> = None;
        let mut root_hex: Option<&str> = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("seq=") {
                seq = Some(
                    rest.parse::<u64>()
                        .map_err(|_| anyhow::anyhow!("bad seq"))?,
                );
            } else if let Some(rest) = line.strip_prefix("root=") {
                root_hex = Some(rest);
            }
        }
        let seq = seq.ok_or_else(|| anyhow::anyhow!("checkpoint missing seq"))?;
        let root_hex = root_hex.ok_or_else(|| anyhow::anyhow!("checkpoint missing root"))?;
        if root_hex.len() != 64 {
            anyhow::bail!("checkpoint root has wrong length");
        }
        let root_bytes =
            hex::decode(root_hex).map_err(|_| anyhow::anyhow!("checkpoint root not hex"))?;
        let mut root = [0u8; 32];
        root.copy_from_slice(&root_bytes);
        Ok(Some((seq, root)))
    }

    /// Write replacement content without following an attacker-controlled
    /// temporary symlink.  `NamedTempFile` creates the temporary entry with
    /// O_EXCL in the target directory; persisting it keeps rename atomic.
    fn atomic_write_private(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
        use std::io::Write;

        let parent = path.parent().unwrap_or(std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.write_all(bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(path)
            .map_err(|e| anyhow::anyhow!("atomic write to {path:?} failed: {}", e.error))?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

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
        tracing::trace!(
            "cairn_core::read STARTED for ino {} offset {} size {}",
            ino,
            offset,
            size
        );

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
                    .decrypt_chunk_auto(&hash, cipher, &wrapped_key, comp_type_u8, &cipher_algo)
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
        tracing::trace!(
            "cairn_core::write STARTED for ino {} offset {} len {}",
            ino,
            offset,
            data.len()
        );
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
        let db_entries = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = ino;
            move || db.list_dentries_rowid_after(i, after_rowid, 1000)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        .map_err(CairnEngine::to_eio)?;

        for (rowid, name, name_enc, child_ino, kind) in db_entries {
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
            // --hide-names: decrypt the real name for display (falls back to the
            // opaque hash if the private key is absent). No-op in normal archives.
            let display = self.resolve_dentry_name(&name, name_enc.as_deref());
            entries.push(DirectoryEntry {
                inode: child_ino,
                offset: rowid + 2,
                kind: file_type,
                name: OsStr::new(&display).into(),
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
        let db_entries = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = parent;
            move || db.list_dentries_rowid_after_plus(i, after_rowid, 1000)
        })
        .await
        .map_err(CairnEngine::to_eio)?
        .map_err(CairnEngine::to_eio)?;

        for (rowid, name, name_enc, ino, mode, uid, gid, size, nlink, mtime_sec, mtime_nsec) in
            db_entries
        {
            // map ALL POSIX file types, not just Dir/Symlink/Regular.
            // mk_file_attr (line 108) handles all 7 types; readdir must match.
            let kind = mode_to_filetype(mode);
            // --hide-names: decrypt for display (no-op in normal archives).
            let display = self.resolve_dentry_name(&name, name_enc.as_deref());
            entries.push(DirectoryEntryPlus {
                inode: ino,
                generation: 0,
                kind,
                name: OsStr::new(&display).into(),
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
        tracing::trace!(
            "cairn_core::mkdir STARTED for parent {} name {:?}",
            parent,
            name
        );
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
        tracing::trace!(
            "cairn_core::mknod STARTED for parent {} name {:?}",
            parent,
            name
        );
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
                        self.shared_dedup_write_config()
                            .map_err(CairnEngine::to_eio)?,
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

                // The authenticated snapshot tree must bind a symlink's target,
                // not merely its mode and name.  Store the same domain-separated
                // digest used for regular-file content before exposing the inode.
                let mut target_hasher = crate::hashing::FileHasher::new();
                target_hasher
                    .update(link_bytes)
                    .map_err(CairnEngine::to_eio)?;
                let target_digest = target_hasher.finish().hash;
                tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    move || db.set_file_digest(ino, &target_digest)
                })
                .await
                .map_err(CairnEngine::to_eio)?
                .map_err(CairnEngine::to_eio)?;

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
                .decrypt_chunk_auto(&hash, &cipher, &wrapped_key, comp_type as u8, &cipher_algo)
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
        // BF-04.7: a size mutation is a read-modify-write across the pending
        // buffer flush AND the chunk/size update; hold the per-inode write
        // lock for the whole sequence so a concurrent write()/fsync()/release()
        // cannot interleave between the flush and the mutation. Non-size
        // setattr calls (chmod/chown) stay lock-free.
        let _size_guard = if set_attr.size.is_some() {
            Some(self.get_write_lock(ino).lock_owned().await)
        } else {
            None
        };
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
            self.flush_pending_buffer_locked(ino).await?;

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

        // BF-04.1: a size/content mutation invalidates the stored H09 digest.
        // Without this, tree_root()/verify_file_digest() keep binding bytes the
        // file no longer has after a truncate, and a snapshot's root no longer
        // describes its frozen content.
        if set_attr.size.is_some() {
            self.store_file_digest(ino)
                .await
                .map_err(CairnEngine::to_eio)?;
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
            // BF-04.7: same read-modify-write lock scope as setattr — flush and
            // truncate must be atomic against concurrent writers.
            let _trunc_guard = self.get_write_lock(ino).lock_owned().await;
            // O_TRUNC is an implicit truncate to 0: flush any pending buffer
            // first (same reason as setattr) so stale buffered bytes cannot
            // reappear, then drop all chunks + size + inline in ONE
            // transaction. The previous two-tx implementation
            // left a crash window where chunks were empty but `inodes.size`
            // was still pre-truncate; it also failed to clear `inline_data`,
            // so a backupped-then-truncated file would read as empty on the
            // mount but `extract` would still return the original bytes.
            self.flush_pending_buffer_locked(ino).await?;
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
            // BF-04.1: truncate-to-0 invalidates the stored digest too.
            self.store_file_digest(ino)
                .await
                .map_err(CairnEngine::to_eio)?;
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
        tracing::trace!("cairn_core::release STARTED for ino {}", _ino);
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
        //
        // BF-04.7: the digest is published while the write lock is STILL held,
        // so it cannot be computed against chunk state that a concurrent
        // writer is mutating (a plain post-unlock store raced exactly that).
        if flush_err.is_none() {
            if let Err(e) = self.store_file_digest(_ino).await {
                flush_err = Some(CairnEngine::to_eio(e));
            }
        }
        drop(_guard);
        drop(lock);
        self.write_locks
            .remove_if(&_ino, |_, l| std::sync::Arc::strong_count(l) == 1);

        if let Some(e) = flush_err {
            return Err(e);
        }
        // H09: finalize-time whole-file digest (covers inline files that never
        // reach the flush_range hook; idempotent for chunked files).
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
        self.store_file_digest(_ino)
            .await
            .map_err(CairnEngine::to_eio)?;
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
        self.flush_pending_buffer_locked(ino).await
    }

    /// BF-04.7: the flush body without taking the per-inode lock. Callers that
    /// must serialize a whole read-modify-write sequence (setattr truncate,
    /// open(O_TRUNC)) hold the lock across flush AND mutation, so they cannot
    /// use the locking wrapper above (tokio mutexes are not reentrant).
    async fn flush_pending_buffer_locked(&self, ino: u64) -> std::io::Result<()> {
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
            // BF-04.11: readers zero-fill missing ranges, so a chunk ENTIRELY
            // inside [offset, end) can simply be dropped. A chunk that crosses
            // either boundary must be read-modify-written instead: the old
            // drop/shorten truncated only its head and threw away everything
            // after it, zeroing data OUTSIDE the punched range (verified with a
            // one-chunk file: punch [1000,2000) zeroed [2000,30000)).
            let end = offset.saturating_add(length);
            let rows = tokio::task::spawn_blocking({
                let db = self.db.clone();
                move || db.get_file_chunks_range(ino, offset, end)
            })
            .await
            .map_err(CairnEngine::to_eio)?
            .map_err(CairnEngine::to_eio)?;

            for (oid, row_off, row_len, wrapped, comp_type, algo) in rows {
                let row_off = row_off as u64;
                let row_end = row_off.saturating_add(row_len as u64);
                if row_off >= end || row_end <= offset {
                    continue;
                }
                if row_off >= offset && row_end <= end {
                    let db = self.db.clone();
                    let (i, s, e) = (ino, row_off, row_end);
                    if let Err(err) =
                        tokio::task::spawn_blocking(move || db.drop_file_chunks_range(i, s, e))
                            .await
                            .map_err(CairnEngine::to_eio)?
                    {
                        tracing::error!("fallocate: punch hole row drop ino {ino}: {err}");
                        return Err(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                    continue;
                }
                // Boundary-crossing row: zero only the intersection and keep
                // the rest. Re-chunking this span is fine — content binds.
                let cipher = self.fetch_chunk(&oid).await.map_err(CairnEngine::to_eio)?;
                let plain = self
                    .decrypt_chunk_auto(&oid, &cipher, &wrapped, comp_type as u8, &algo)
                    .map_err(CairnEngine::to_eio)?;
                let mut data = plain
                    .get(..row_len)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EIO))?
                    .to_vec();
                let zero_from = offset.saturating_sub(row_off) as usize;
                let zero_to = (end.min(row_end).saturating_sub(row_off)) as usize;
                if zero_from < zero_to && zero_to <= data.len() {
                    data[zero_from..zero_to].fill(0);
                }
                self.flush_range(ino, row_off, &data)
                    .await
                    .map_err(CairnEngine::to_eio)?;
            }
            // BF-04.1: a punched hole zeroes a byte range, so the stored digest
            // must be recomputed (the logical size is unchanged).
            self.store_file_digest(ino)
                .await
                .map_err(CairnEngine::to_eio)?;
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
                // BF-04.1: growing the logical size changes the digest's
                // size binding, so refresh it here as well.
                self.store_file_digest(ino)
                    .await
                    .map_err(CairnEngine::to_eio)?;
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

    pub async fn extract_all(&self, dest_dir: &str, preserve_metadata: bool) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(dest_dir).await?;

        // A single unreadable file (a lost/corrupt chunk) must NOT abort the whole
        // restore — the operator needs every OTHER file back. Failures are counted
        // and surfaced at the end (non-zero exit), like `backup`.
        let mut failures = 0u64;
        let mut stack = vec![(1u64, dest_dir.to_string())];
        // Hardlink recreation: maps an archive inode (nlink>1) to the first disk
        // path it was extracted to, so additional names for the same inode are
        // hard-linked on disk instead of written as independent copies.
        let mut hardlink_extract: std::collections::HashMap<u64, std::path::PathBuf> =
            std::collections::HashMap::new();

        while let Some((parent_ino, current_dir)) = stack.pop() {
            // a DB error while listing a directory must not silently
            // drop its whole subtree from the restore. Count it as a failure (so the
            // extract exits non-zero) and log it, while still restoring every other
            // branch — matching this function's "count and surface, never abort" rule.
            let dentries_result = tokio::task::spawn_blocking({
                let db = self.db.clone();
                let i = parent_ino;
                move || db.list_dentries(i)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?;
            if let Err(ref e) = dentries_result {
                failures += 1;
                tracing::error!(
                    "extract: list_dentries failed for dir inode {parent_ino}: {e} — subtree skipped"
                );
            }
            if let Ok(dentries) = dentries_result {
                for (name_key, name_enc, ino) in dentries {
                    // --hide-names: reconstruct the real on-disk name (falls back
                    // to the opaque hash if the private key is absent). Normal
                    // archives return the stored name unchanged.
                    let name = self.resolve_dentry_name(&name_key, name_enc.as_deref());
                    // match on both Ok/Err so DB errors are logged and
                    // counted instead of silently skipping the child entry.
                    let inode_result = tokio::task::spawn_blocking({
                        let db = self.db.clone();
                        let i = ino;
                        move || db.get_inode(i)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?;
                    let (mode, _uid, _gid, _size, nlink, _mtime_sec, _mtime_nsec) =
                        match inode_result {
                            Ok(Some(info)) => info,
                            Ok(None) => {
                                failures += 1;
                                tracing::error!(
                                    "extract: inode {ino} (name {name:?}) not found in DB — skipped"
                                );
                                continue;
                            }
                            Err(e) => {
                                failures += 1;
                                tracing::error!(
                                    "extract: get_inode({ino}) failed for {name:?}: {e} — skipped"
                                );
                                continue;
                            }
                        };
                    {
                        let name_path = std::path::Path::new(&name);
                        if name_path.is_absolute()
                            || name_path.components().any(|c| {
                                matches!(c, std::path::Component::ParentDir)
                                    || matches!(c, std::path::Component::CurDir)
                            })
                            || name.contains('/')
                        {
                            continue;
                        }
                        let path = std::path::Path::new(&current_dir).join(&name);

                        if mode & libc::S_IFMT == libc::S_IFDIR {
                            // Materialize the directory now: children are extracted
                            // into it, and empty directories must survive the restore.
                            // If a symlink already exists at the path, remove it so
                            // create_dir_all makes a real directory and children are
                            // not written through a redirected link.
                            if let Ok(meta) = tokio::fs::symlink_metadata(&path).await {
                                if meta.is_symlink() {
                                    let _ = tokio::fs::remove_file(&path).await;
                                }
                            }
                            tokio::fs::create_dir_all(&path).await?;
                            if preserve_metadata {
                                #[cfg(unix)]
                                {
                                    self.apply_preserved_metadata(ino, &path).await;
                                }
                            }
                            stack.push((ino, path.to_string_lossy().to_string()));
                        } else if mode & libc::S_IFMT == libc::S_IFLNK {
                            match self.read_file_all(ino).await {
                                Ok(Some(target_data)) => {
                                    let target_str = String::from_utf8_lossy(&target_data);
                                    #[cfg(unix)]
                                    let _ = tokio::fs::symlink(target_str.as_ref(), &path).await;
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    failures += 1;
                                    tracing::error!(
                                        "extract: symlink {path:?} could NOT be restored: {e}"
                                    );
                                    continue;
                                }
                            }
                            if preserve_metadata {
                                #[cfg(unix)]
                                {
                                    self.apply_preserved_metadata(ino, &path).await;
                                }
                            }
                        } else {
                            // Hardlink recreation: if this archive inode (nlink>1)
                            // was already extracted under another name, link the new
                            // name to that first path instead of writing a second
                            // independent copy — this restores the on-disk link and
                            // avoids re-decrypting the data. The shared inode already
                            // carries mode/mtime, so skip perms/preserve here.
                            if nlink > 1 {
                                if let Some(first) = hardlink_extract.get(&ino).cloned() {
                                    // Clear any stale/existing dest (re-extract case);
                                    // hard_link fails if the target already exists.
                                    let _ = tokio::fs::remove_file(&path).await;
                                    match tokio::fs::hard_link(&first, &path).await {
                                        Ok(()) => continue,
                                        Err(e) => {
                                            // Never lose the file — fall back to a copy.
                                            tracing::warn!(
                                                "extract: hard_link {path:?} -> {first:?} failed, copying: {e}"
                                            );
                                        }
                                    }
                                }
                            }
                            // Regular file: stream chunk-by-chunk to disk so a multi-GB
                            // file is never fully buffered in RAM (fix).
                            if let Err(e) = self.extract_file_to(ino, &path).await {
                                failures += 1;
                                tracing::error!("extract: {path:?} could NOT be restored: {e}");
                                continue;
                            }

                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                // keep setuid/setgid/sticky
                                // bits (0o7777, not 0o777) so a backed-up
                                // setuid binary is restored as setuid.
                                let perm = std::fs::Permissions::from_mode(mode & 0o7777);
                                let _ = tokio::fs::set_permissions(&path, perm).await;
                            }
                            if preserve_metadata {
                                #[cfg(unix)]
                                {
                                    self.apply_preserved_metadata(ino, &path).await;
                                }
                            }
                            // First name for this inode: remember it as the link
                            // target for any later name that shares the inode.
                            if nlink > 1 {
                                hardlink_extract.insert(ino, path.clone());
                            }
                        }
                    }
                }
            }
        }

        if failures > 0 {
            anyhow::bail!(
                "{failures} file(s) could NOT be restored (see the errors above); \
                 all other files were extracted"
            );
        }
        Ok(())
    }

    pub async fn extract_single_file(
        &self,
        file_path: &str,
        dest_dir: &str,
        preserve_metadata: bool,
    ) -> anyhow::Result<()> {
        let mut current_ino = 1u64;
        let path = std::path::Path::new(file_path);

        for comp in path.components() {
            if let std::path::Component::Normal(name) = comp {
                let name_str = name.to_string_lossy().to_string();
                // --hide-names: resolve each path component through its lookup key.
                let name_clone = self.crypto.name_lookup_key(current_ino, &name_str)?;
                let child_ino = tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    let p_ino = current_ino;
                    move || db.get_dentry_inode(p_ino, &name_clone)
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

                if let Some(ino) = child_ino {
                    current_ino = ino;
                } else {
                    anyhow::bail!("Path component '{}' not found", name_str);
                }
            }
        }

        let is_file = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let ino = current_ino;
            move || db.get_inode(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        .map(|(mode, ..)| mode & libc::S_IFMT == libc::S_IFREG)
        .unwrap_or(false);

        if !is_file {
            anyhow::bail!("Path '{}' is not a regular file", file_path);
        }

        tokio::fs::create_dir_all(dest_dir).await?;
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;
        let dest_path = std::path::Path::new(dest_dir).join(file_name);

        self.extract_file_to(current_ino, &dest_path).await?;

        if preserve_metadata {
            #[cfg(unix)]
            {
                self.apply_preserved_metadata(current_ino, &dest_path).await;
            }
        }

        Ok(())
    }

    pub async fn extract_matching(
        &self,
        pattern: &str,
        dest_dir: &str,
        preserve_metadata: bool,
    ) -> anyhow::Result<()> {
        let compiled_pattern = glob::Pattern::new(pattern)?;
        tokio::fs::create_dir_all(dest_dir).await?;

        let mut stack = vec![(1u64, String::new())];
        // Hardlink recreation (same as extract_all): archive inode (nlink>1) →
        // first extracted disk path. Only names that match the glob are linked;
        // if just one name of a group matches, it is written normally.
        let mut hardlink_extract: std::collections::HashMap<u64, std::path::PathBuf> =
            std::collections::HashMap::new();

        while let Some((parent_ino, current_vpath)) = stack.pop() {
            // a DB error listing a directory must fail the extract
            // loudly rather than silently omitting that subtree. extract_matching
            // has no per-file failure counter, so propagate the error (non-zero exit).
            let dentries_result = tokio::task::spawn_blocking({
                let db = self.db.clone();
                let i = parent_ino;
                move || db.list_dentries(i)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?;
            if let Err(e) = &dentries_result {
                return Err(anyhow::anyhow!(
                    "extract: list_dentries failed for dir inode {parent_ino}: {e}"
                ));
            }
            if let Ok(dentries) = dentries_result {
                for (name_key, name_enc, ino) in dentries {
                    // --hide-names: reconstruct the real name for glob-matching
                    // and on-disk paths (opaque hash fallback without the priv key).
                    let name = self.resolve_dentry_name(&name_key, name_enc.as_deref());
                    // match on both Ok/Err so DB errors are logged and
                    // the function fails loudly instead of silently skipping.
                    let inode_result = tokio::task::spawn_blocking({
                        let db = self.db.clone();
                        let i = ino;
                        move || db.get_inode(i)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?;
                    let (mode, _uid, _gid, _size, nlink, _mtime_sec, _mtime_nsec) =
                        match inode_result {
                            Ok(Some(info)) => info,
                            Ok(None) => {
                                tracing::error!(
                                    "extract: inode {ino} (name {name:?}) not found in DB — skipped"
                                );
                                continue;
                            }
                            Err(e) => {
                                return Err(anyhow::anyhow!(
                                    "extract: get_inode({ino}) failed for {name:?}: {e}"
                                ));
                            }
                        };
                    {
                        let name_path = std::path::Path::new(&name);
                        if name_path.is_absolute()
                            || name_path.components().any(|c| {
                                matches!(c, std::path::Component::ParentDir)
                                    || matches!(c, std::path::Component::CurDir)
                            })
                            || name.contains('/')
                        {
                            continue;
                        }

                        let new_vpath = if current_vpath.is_empty() {
                            format!("/{}", name)
                        } else {
                            format!("{}/{}", current_vpath, name)
                        };

                        let ifmt = mode & libc::S_IFMT;
                        if ifmt == libc::S_IFDIR {
                            stack.push((ino, new_vpath));
                        } else if ifmt == libc::S_IFLNK {
                            // `extract_all` already restores
                            // symlinks; `extract_matching` used to drop them
                            // silently. A glob over a directory tree with
                            // symlinks now extracts the symlinks.
                            let relative_path = new_vpath.trim_start_matches('/');
                            let dest_link_path = std::path::Path::new(dest_dir).join(relative_path);
                            if let Some(parent) = dest_link_path.parent() {
                                tokio::fs::create_dir_all(parent).await?;
                            }
                            match self.read_file_all(ino).await {
                                Ok(Some(target_data)) => {
                                    let target_str = String::from_utf8_lossy(&target_data);
                                    #[cfg(unix)]
                                    {
                                        if let Err(e) =
                                            tokio::fs::symlink(target_str.as_ref(), &dest_link_path)
                                                .await
                                        {
                                            tracing::warn!(
                                                "extract: symlink {dest_link_path:?} -> \
                                                 {target_str}: {e}"
                                            );
                                        }
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    tracing::warn!(
                                        "extract: symlink {dest_link_path:?} unreadable: {e}"
                                    );
                                }
                            }
                            if preserve_metadata {
                                #[cfg(unix)]
                                {
                                    self.apply_preserved_metadata(ino, &dest_link_path).await;
                                }
                            }
                        } else if ifmt == libc::S_IFREG
                            && (compiled_pattern.matches(&new_vpath)
                                || compiled_pattern.matches(new_vpath.trim_start_matches('/')))
                        {
                            let relative_path = new_vpath.trim_start_matches('/');
                            let dest_file_path = std::path::Path::new(dest_dir).join(relative_path);

                            if let Some(parent) = dest_file_path.parent() {
                                tokio::fs::create_dir_all(parent).await?;
                            }

                            // Hardlink recreation: link to the first extracted name
                            // sharing this inode instead of writing a second copy.
                            let mut linked = false;
                            if nlink > 1 {
                                if let Some(first) = hardlink_extract.get(&ino).cloned() {
                                    let _ = tokio::fs::remove_file(&dest_file_path).await;
                                    match tokio::fs::hard_link(&first, &dest_file_path).await {
                                        Ok(()) => linked = true,
                                        Err(e) => tracing::warn!(
                                            "extract: hard_link {dest_file_path:?} -> {first:?} failed, copying: {e}"
                                        ),
                                    }
                                }
                            }

                            if !linked {
                                self.extract_file_to(ino, &dest_file_path).await?;

                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::PermissionsExt;
                                    // keep setuid/setgid/sticky
                                    // bits (mask 0o7777, not 0o777) so a backed-up
                                    // setuid binary is restored as setuid.
                                    let perm = std::fs::Permissions::from_mode(mode & 0o7777);
                                    let _ = tokio::fs::set_permissions(&dest_file_path, perm).await;
                                }
                                if preserve_metadata {
                                    #[cfg(unix)]
                                    {
                                        self.apply_preserved_metadata(ino, &dest_file_path).await;
                                    }
                                }
                                // Remember this as the link target for later names.
                                if nlink > 1 {
                                    hardlink_extract.insert(ino, dest_file_path.clone());
                                }
                            }
                        }
                        // S_IFIFO / S_IFCHR / S_IFBLK / S_IFSOCK: the archive
                        // stores them but `extract_all` would `read_file_all`
                        // them which only makes sense for symlinks. Skip with
                        // a warning — special files cannot be round-tripped
                        // through a content-addressed chunk store reliably.
                        else if matches!(
                            ifmt,
                            libc::S_IFIFO | libc::S_IFCHR | libc::S_IFBLK | libc::S_IFSOCK
                        ) {
                            tracing::warn!(
                                "extract: skipping special file at {new_vpath} \
                                 (FIFO/CHR/BLK/SOCK cannot be reliably restored)"
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn read_file_all(&self, ino: u64) -> anyhow::Result<Option<Vec<u8>>> {
        self.read_file_all_from_db(&self.db, ino).await
    }

    /// H15: read the complete logical content of a file from the GIVEN
    /// database (e.g. a snapshot's point-in-time copy), assembling chunks
    /// through the shared engine store. Same placement rules as
    /// `read_file_all` (zero-filled holes, EOF clamp).
    pub async fn read_file_all_from_db(
        &self,
        db: &cairn_index::Db,
        ino: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        // assemble the LOGICAL content over [0, size) — chunks placed by
        // offset into a zero-filled buffer, so holes (sparse writes, truncate-
        // extend) read as zeros, exactly like the FUSE read() path. This used
        // to concatenate chunks in row order and ignore offsets: wrong bytes
        // for any non-contiguous file, short for any tail hole.
        let inode = tokio::task::spawn_blocking({
            let db = db.clone();
            move || db.get_inode(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        let Some(inode) = inode else {
            return Ok(None);
        };
        let size = usize::try_from(inode.3)
            .map_err(|_| anyhow::anyhow!("file size {} exceeds address space", inode.3))?;
        // `read_file_all` buffers the WHOLE file in RAM (unlike the
        // streaming `extract_file_to`). Cap it so a caller (e.g. `Vfs::read_file`)
        // cannot OOM the process on a multi-GiB regular file — stream via
        // `extract_file_to` / the FUSE `read` path for large files instead.
        const READ_FILE_ALL_MAX: usize = 256 * 1024 * 1024;
        if size > READ_FILE_ALL_MAX {
            anyhow::bail!(
                "read_file_all: file is {size} bytes (> {READ_FILE_ALL_MAX} cap) — \
                 use the streaming extract/read path for large files"
            );
        }
        let mut data = vec![0u8; size];

        // check inline data first (short symlink targets stored
        // via set_inline_data), then fall back to CDC chunks.
        let inline = tokio::task::spawn_blocking({
            let db = db.clone();
            move || db.get_inline_data(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        if let Some(raw) = inline {
            let plain = self.unwrap_inline(&raw)?;
            let n = plain.len().min(size);
            data[..n].copy_from_slice(&plain[..n]);
            return Ok(Some(data));
        }

        let chunks = tokio::task::spawn_blocking({
            let db = db.clone();
            let i = ino;
            move || db.get_file_chunks(i)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        let engine = self.clone();

        use futures::StreamExt;
        let mut stream = futures::stream::iter(chunks)
            .map(
                |(hash_key, offset, plain_len, wrapped_key, comp_type, cipher_algo)| {
                    let engine = engine.clone();
                    async move {
                        let cipher = engine.fetch_chunk(&hash_key).await?;
                        let comp_type_u8 = u8::try_from(comp_type).map_err(|_| {
                            anyhow::anyhow!("invalid comp_type for chunk {hash_key}")
                        })?;
                        let chunk_oid = hash_key.clone();
                        let plain = tokio::task::spawn_blocking(move || {
                            engine.decrypt_chunk_auto(
                                &chunk_oid,
                                &cipher,
                                &wrapped_key,
                                comp_type_u8,
                                &cipher_algo,
                            )
                        })
                        .await
                        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
                        if plain.len() < plain_len {
                            anyhow::bail!("chunk {hash_key} shorter than recorded length");
                        }
                        Ok::<_, anyhow::Error>((offset, plain[..plain_len].to_vec()))
                    }
                },
            )
            .buffered(16);

        while let Some(res) = stream.next().await {
            let (off, plain) = res?;
            // Clamp to the recorded size: a chunk tail past EOF (shrinking
            // truncate races, straddle chunks) must not grow the logical file.
            if off >= size {
                continue;
            }
            let n = plain.len().min(size - off);
            data[off..off + n].copy_from_slice(&plain[..n]);
        }
        Ok(Some(data))
    }

    /// Stream a regular file's chunks straight to `path`, decrypting one chunk at a
    /// time and writing it to disk — never buffering the whole file in RAM (fix).
    /// Chunks arrive in offset order (`get_file_chunks` ORDER BY offset), so a plain
    /// sequential write reproduces `read_file_all`'s concatenation exactly.
    ///
    /// Security: writes are performed to a temporary file in the same directory and
    /// atomically renamed onto `path`. This eliminates the TOCTOU race where an
    /// attacker replaces `path` with a symlink between `remove_file` and `create`.
    pub async fn extract_file_to(&self, ino: u64, path: &std::path::Path) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;

        // a file flagged
        // incomplete (marker: its last backup was interrupted) is restored
        // best-effort from whatever is COMMITTED, with a loud warning, rather than
        // REFUSED. The original bail broke the cardinal backup-tool rule that a failed
        // *new* backup must never make a *prior good* version unrestorable — a failed
        // overwrite leaves the old chunks intact in the index, and bailing stranded
        // them (the old, wholly-valid version became un-extractable). `verify` remains
        // the strict gate that flags these files; `extract` hands back the recoverable
        // bytes. NOTE (data-safety tradeoff): for a LARGE file whose overwrite failed
        // mid-flush the committed state can be MIXED (some new + some old chunks); this
        // restores it with only the warning below — `verify` is what catches it.
        let incomplete = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.is_file_incomplete(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?
        .unwrap_or(false);
        if incomplete {
            tracing::warn!(
                "extract: ino {ino} is flagged incomplete (its last backup was interrupted) — \
                 restoring committed data best-effort; run `verify`, and re-run `backup` to be safe"
            );
        }

        let path_buf = path.to_path_buf();
        let parent = path_buf
            .parent()
            .ok_or_else(|| anyhow::anyhow!("extract path has no parent: {path_buf:?}"))?
            .to_path_buf();

        // the extracted file must be exactly `size` bytes — a tail hole
        // (sparse write / truncate-extend) used to yield a SHORT file because
        // nothing wrote past the last chunk. `set_len(size)` below pads the
        // tail with zeros (and defensively clamps anything past EOF), matching
        // the FUSE read() view of the same inode.
        let recorded_size = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_inode(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        .ok_or_else(|| anyhow::anyhow!("extract: inode {ino} not found"))?
        .3;

        // Create a temporary file in the destination directory. `tempfile` places it
        // on the same filesystem, so the final `persist` is an atomic rename.
        let tmp = tokio::task::spawn_blocking({
            let p = parent.clone();
            move || {
                tempfile::NamedTempFile::new_in(&p)
                    .map_err(|e| anyhow::anyhow!("failed to create temp file in {p:?}: {e}"))
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

        // propagate a DB read error rather than extracting an empty file.
        if let Some(raw_inline) = self.db.get_inline_data(ino)? {
            let inline_data = self.unwrap_inline(&raw_inline)?;
            let mut file = tokio::fs::File::from_std(tmp.as_file().try_clone()?);
            file.write_all(&inline_data).await?;
            file.set_len(recorded_size).await?;
            drop(file);
            tokio::task::spawn_blocking(move || {
                tmp.persist(&path_buf)
                    .map_err(|e| anyhow::anyhow!("failed to rename temp file to {path_buf:?}: {e}"))
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
            return Ok(());
        }

        let chunks = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = ino;
            move || db.get_file_chunks(i)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

        let mut file = tokio::fs::File::from_std(tmp.as_file().try_clone()?);
        let engine = self.clone();

        use futures::StreamExt;
        let mut stream = futures::stream::iter(chunks)
            .map(
                |(hash_key, offset, plain_len, wrapped_key, comp_type, cipher_algo)| {
                    let engine = engine.clone();
                    async move {
                        let cipher = engine.fetch_chunk(&hash_key).await?;
                        let comp_type_u8 = u8::try_from(comp_type).map_err(|_| {
                            anyhow::anyhow!("invalid comp_type for chunk {hash_key}")
                        })?;
                        let chunk_oid = hash_key.clone();
                        let plain = tokio::task::spawn_blocking(move || {
                            engine.decrypt_chunk_auto(
                                &chunk_oid,
                                &cipher,
                                &wrapped_key,
                                comp_type_u8,
                                &cipher_algo,
                            )
                        })
                        .await
                        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
                        if plain.len() < plain_len {
                            anyhow::bail!("chunk {hash_key} shorter than recorded length");
                        }
                        Ok::<_, anyhow::Error>((offset, plain[..plain_len].to_vec()))
                    }
                },
            )
            .buffer_unordered(
                std::thread::available_parallelism().map_or(4, std::num::NonZero::get),
            );

        use tokio::io::AsyncSeekExt;
        while let Some(res) = stream.next().await {
            let (offset, data) = res?;
            let offset_u64 =
                u64::try_from(offset).map_err(|_| anyhow::anyhow!("chunk offset exceeds u64"))?;
            file.seek(std::io::SeekFrom::Start(offset_u64)).await?;
            file.write_all(&data).await?;
        }
        file.set_len(recorded_size).await?;
        drop(file);

        tokio::task::spawn_blocking(move || {
            tmp.persist(&path_buf)
                .map_err(|e| anyhow::anyhow!("failed to rename temp file to {path_buf:?}: {e}"))
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        Ok(())
    }

    pub async fn gc(&self, grace_period_hours: u64) -> anyhow::Result<(usize, usize)> {
        // prevent concurrent GC runs — a second GC during an active one
        // would see a partially-deleted index and double-delete or orphan chunks.
        let _gc_guard = self
            .gc_running
            .try_lock()
            .map_err(|_| anyhow::anyhow!("GC is already running (concurrent GC not supported)"))?;
        // `get_orphaned_chunks` excludes chunks referenced by the LIVE tree
        // (file_chunks) but is blind to snapshots — their chunks live inside blob
        // DBs, not queryable in SQL. Without this second filter, gc deletes chunks
        // that only a snapshot references, silently bricking that snapshot's
        // restore. `get_all_used_chunks` opens every snapshot and ERRORS on a
        // corrupt one, so gc fails safe rather than deleting what it can't verify.
        //
        // the used/orphan queries are not one transaction, but the
        // `grace_period_hours` filter in `get_orphaned_chunks` is the race guard:
        // a chunk a concurrent flush just wrote is younger than the grace window,
        // so it is never an orphan candidate. Only `--grace-period-hours 0`
        // removes this protection — do not run gc with grace 0 against a live
        // mount (OPERATING recommends 24h).
        let used = self.db.get_all_used_chunks()?;
        let orphaned: Vec<String> = self
            .db
            .get_orphaned_chunks(grace_period_hours)?
            .into_iter()
            .filter(|h| !used.contains(h))
            .collect();
        let mut total_removed = 0;

        let gc_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
        #[cfg_attr(not(feature = "cloud-storage"), allow(unused_mut))]
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        for hash_key in orphaned {
            let cache_dir = self.cache_dir.clone();
            let sem = gc_sem.clone();
            let db = self.db.clone();
            let _permit = sem
                .acquire()
                .await
                .map_err(|e| anyhow::anyhow!("GC semaphore closed: {e}"))?;
            // Remove the index row FIRST. The failure modes are asymmetric: an
            // orphaned blob (row gone, delete below fails) merely leaks storage
            // and the local sweep reclaims it, while a dangling row (data gone,
            // row removal fails) turns into EIO at read time.
            if let Err(e) = db.remove_chunk_from_index(&hash_key) {
                tracing::error!(
                    "gc: failed to remove {hash_key} from index: {e} — leaving its data in place"
                );
                drop(_permit);
                continue;
            }
            let _ = cacache::remove(&cache_dir, &hash_key).await;
            #[cfg(feature = "cloud-storage")]
            {
                let s3_path = format!("chunks/{hash_key}");
                let ops = self.operators.clone();
                let sem2 = gc_sem.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem2.acquire().await;
                    for op in &ops {
                        let _ = op.delete(&s3_path).await;
                    }
                    drop(_permit);
                }));
            }
            total_removed += 1;
            drop(_permit);
        }
        futures::future::join_all(handles).await;

        // Also clean up any lingering local cacache blobs that aren't referenced
        // anywhere. The protected set is used_chunks (file_chunks + snapshots)
        // UNION all chunk_index rows: a chunk still in the index is either in
        // active use or inside the grace window (orphaned but not yet
        // collectable). The old sweep used only `used_chunks`, so a grace-period
        // orphan's local blob was deleted while its index row survived — and the
        // next dedup hit on the same content found the row but no blob → `EIO`
        // on local-only archives.
        let mut local_orphans = 0;
        let mut protected = self.db.get_all_used_chunks()?;
        protected.extend(self.db.get_all_indexed_chunk_objects()?);
        for entry in cacache::list_sync(&self.cache_dir).flatten() {
            if !protected.contains(&entry.key) {
                let _ = cacache::remove(&self.cache_dir, &entry.key).await;
                local_orphans += 1;
            }
        }

        tracing::info!(
            "Garbage Collection complete: removed {} orphaned chunks globally, and {} local cache orphans",
            total_removed,
            local_orphans
        );
        Ok((total_removed, local_orphans))
    }

    /// Per-FILE integrity check: proves every file is actually restorable, which
    /// `scrub` does NOT — scrub verifies chunks exist and hash-match, but a file
    /// with a dangling chunk reference or a recorded size that no chunks back
    /// (the class: "size set, zero data") passes scrub and fails here.
    ///
    /// For each regular file it fetches and DECRYPTS every chunk (so it needs the
    /// read key — this measures restorability, not just presence), streaming one
    /// chunk at a time, and checks the decrypted total equals the recorded size.
    /// Returns `(ok, bad)` and logs each bad file with the reason.
    pub async fn verify_all(&self) -> anyhow::Result<(usize, usize)> {
        let files = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.list_regular_files()
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

        // files whose backup was interrupted (killed mid-write) carry a
        // durable marker. Their committed size is self-consistent with the
        // chunks actually written, so verify_one would pass them — but the file
        // is truncated. Treat any marked inode as NOT restorable.
        let incomplete: std::collections::HashSet<u64> = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.list_incomplete_files()
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?
        .unwrap_or_default()
        .into_iter()
        .collect();

        let mut ok = 0usize;
        let mut bad = 0usize;

        for (ino, size) in files {
            if incomplete.contains(&ino) {
                bad += 1;
                let name = self
                    .db
                    .get_inode_name(ino)
                    .unwrap_or_else(|_| format!("ino {ino}"));
                tracing::error!(
                    "verify: {name} (ino {ino}) is NOT restorable: backup was interrupted \
                     (killed mid-file) — the file is truncated. Re-run backup to complete it."
                );
                continue;
            }
            match self.verify_one(ino, size).await {
                Ok(()) => ok += 1,
                Err(e) => {
                    bad += 1;
                    let name = self
                        .db
                        .get_inode_name(ino)
                        .unwrap_or_else(|_| format!("ino {ino}"));
                    tracing::error!("verify: {name} (ino {ino}) is NOT restorable: {e}");
                }
            }
        }

        if bad > 0 {
            tracing::error!("verify: {ok} file(s) OK, {bad} file(s) NOT restorable");
        } else {
            tracing::info!("verify: all {ok} file(s) restorable");
        }
        Ok((ok, bad))
    }

    async fn verify_one(&self, ino: u64, size: u64) -> anyhow::Result<()> {
        // Inline files: the bytes are in the index, no chunks to resolve.
        // propagate a DB read error — verify must not silently treat an
        // unreadable inode as "0-byte / no inline" and PASS it as restorable.
        if let Some(raw) = self.db.get_inline_data(ino)? {
            // Decrypt so the size check is against the PLAINTEXT length (the
            // stored blob is now envelope ciphertext). Also proves the inline
            // content is actually recoverable with the current key.
            // inline may be SHORTER than the recorded size — a truncate-
            // extended inline file has a legitimate zero tail (read() zero-fills
            // it). Only inline LONGER than the size is an inconsistency.
            let inline = self.unwrap_inline(&raw)?;
            if inline.len() as u64 > size {
                anyhow::bail!("inline size {} > recorded {size}", inline.len());
            }
            return Ok(());
        }

        let chunks = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_file_chunks(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

        // Empty file: legitimately zero chunks. A non-empty file with none is the
        // V-15 footprint (size recorded, data never flushed).
        if chunks.is_empty() {
            if size == 0 {
                return Ok(());
            }
            anyhow::bail!("recorded size {size} but no chunks (data was never stored)");
        }

        for (hash_key, _offset, plain_len, wrapped_key, comp_type, cipher_algo) in chunks {
            let cipher = self
                .fetch_chunk(&hash_key)
                .await
                .map_err(|e| anyhow::anyhow!("chunk {hash_key} unreadable: {e}"))?;
            let engine = self.clone();
            let chunk_oid = hash_key.clone();
            let plain = tokio::task::spawn_blocking(move || {
                engine.decrypt_chunk_auto(
                    &chunk_oid,
                    &cipher,
                    &wrapped_key,
                    comp_type as u8,
                    &cipher_algo,
                )
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?
            .map_err(|e| anyhow::anyhow!("chunk {hash_key} does not decrypt: {e}"))?;
            if plain.len() < plain_len {
                anyhow::bail!(
                    "chunk {hash_key} decrypted to {} bytes < recorded {plain_len}",
                    plain.len()
                );
            }
        }

        // no under-coverage check — coverage gaps (middle or tail holes)
        // are LEGITIMATE zeros from sparse writes / truncate-extend, and read()/
        // extract now reproduce them as zeros. (The old `sum(plain_len) < size`
        // test was double-counting overlapping RMW chunks anyway.) The V-15
        // "size recorded but data never flushed" footprint is still caught above:
        // a non-empty file with ZERO chunks and no inline fails loudly.
        Ok(())
    }

    pub async fn scrub(&self) -> anyhow::Result<(usize, usize)> {
        // Iterate distinct chunk objects, not `file_chunks` rows: a chunk shared
        // by many files (the dedup case) was previously verified once per
        // reference — N times the work, N times the bandwidth on cloud reads.
        let chunks = self.db.get_all_distinct_chunk_objects()?;
        let mut corrupted = 0;
        let mut verified = 0;

        // Scrub verifies the durable copy. With cloud backends configured, force
        // a cloud read (bypass the local cache) and heal from redundancy — unless
        // the operator already set force_remote_read (same intent). On a
        // LOCAL-ONLY archive the cache IS the durable store — forcing a cloud
        // read there fails every fetch and reports a healthy archive as 100%
        // corrupt (masked until made scrub's exit code authoritative).
        let has_cloud = !self.operators.is_empty();
        let force_remote = self.force_remote_read || has_cloud;

        for hash_key in chunks {
            if let Ok(cipher) = self
                .store
                .fetch_chunk(&hash_key, &self.raid_mode, false, has_cloud, force_remote)
                .await
            {
                let actual_hash = blake3::hash(&cipher).to_hex().to_string();
                if actual_hash == hash_key {
                    verified += 1;
                } else {
                    // Report which files reference the corrupted chunk so the
                    // operator can assess impact and prioritise recovery.
                    let affected = self
                        .db
                        .get_inodes_using_chunk(&hash_key)
                        .unwrap_or_default();
                    let file_names: Vec<String> = affected
                        .iter()
                        .map(|ino| {
                            self.db
                                .get_inode_name(*ino)
                                .unwrap_or_else(|_| format!("ino {ino}"))
                        })
                        .collect();
                    tracing::error!(
                        "Corrupted chunk detected (hash mismatch): {} — affects {} file(s): {:?}",
                        hash_key,
                        file_names.len(),
                        file_names
                    );
                    corrupted += 1;
                }
            } else {
                let affected = self
                    .db
                    .get_inodes_using_chunk(&hash_key)
                    .unwrap_or_default();
                let file_names: Vec<String> = affected
                    .iter()
                    .map(|ino| {
                        self.db
                            .get_inode_name(*ino)
                            .unwrap_or_else(|_| format!("ino {ino}"))
                    })
                    .collect();
                tracing::error!(
                    "Missing chunk detected: {} — affects {} file(s): {:?}",
                    hash_key,
                    file_names.len(),
                    file_names
                );
                corrupted += 1;
            }
        }

        if corrupted > 0 {
            tracing::error!(
                "Scrub complete: {} chunks verified, {} corrupted/missing!",
                verified,
                corrupted
            );
        } else {
            tracing::info!(
                "Scrub complete: {} chunks verified successfully. No corruption detected.",
                verified
            );
        }

        Ok((verified, corrupted))
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

    // BF-04.9: the checkpoint lock itself must exclude concurrent holders and
    // be released on drop. This is the deterministic half of the fix; the
    // engine-level concurrent test is a stress guard on top of it.
    #[test]
    fn checkpoint_lock_excludes_concurrent_holders_and_releases_on_drop() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let cp = dir.path().join("c.checkpoint");
        let inside = std::sync::Arc::new(AtomicUsize::new(0));
        let max_inside = std::sync::Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let cp = cp.clone();
            let inside = inside.clone();
            let max_inside = max_inside.clone();
            handles.push(std::thread::spawn(move || {
                let _lock = CheckpointLock::acquire(&cp).unwrap();
                let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                max_inside.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(10));
                inside.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            max_inside.load(Ordering::SeqCst),
            1,
            "checkpoint lock allowed two concurrent holders"
        );

        // Released on drop: a fresh acquire must not block.
        let again = CheckpointLock::acquire(&cp).unwrap();
        drop(again);
        assert!(cp.with_file_name("c.checkpoint.lock").exists());
    }
}
