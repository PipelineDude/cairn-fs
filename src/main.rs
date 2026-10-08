use anyhow::Result;
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

mod shared_dedup;

/// generate an unpredictable temp file path in the given directory.
/// Uses 16 hex chars from OsRng (64 bits of entropy) so an attacker cannot
/// guess the name before the file is created.
fn random_temp_path(dir: &str, suffix: &str) -> String {
    use rand::RngCore;
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let hex = hex::encode(buf);
    format!("{dir}/{hex}.{suffix}")
}

/// The directory containing `archive`, for placing sibling temp files. A bare
/// filename (`backup.db`) has `Path::parent() == Some("")` — NOT `None` — so an
/// empty parent must fall back to "."; otherwise `format!("{dir}/...")` yields an
/// absolute "/..." at the root filesystem, which a non-root process can't write
/// (EACCES). This broke `snapshot rollback` / `diff` for any relative archive path.
fn archive_parent_dir(archive: &str) -> String {
    match std::path::Path::new(archive).parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_string_lossy().to_string(),
        _ => ".".to_string(),
    }
}

/// Prefix for KEK-encrypted config values stored in SQLite.
/// Distinguishes encrypted values from legacy plaintext for transparent
/// migration: old archives keep working, new writes are encrypted at rest
/// (defense-in-depth on top of SQLCipher).
const ENC_VALUE_PREFIX: &str = "ENC:v1:";

/// Encrypt a sensitive value for storage in the config table.
/// Uses the archive KEK (fast AES-256-GCM), same envelope as chunk keys.
fn encrypt_config_value(crypto: &cairn_seal::CryptoCtx, value: &str) -> Result<String> {
    let encrypted = crypto.encrypt_blob(value.as_bytes())?;
    Ok(format!("{}{}", ENC_VALUE_PREFIX, hex::encode(&encrypted)))
}

/// Decrypt a config value (handles both encrypted and plaintext).
/// Plaintext values are returned as-is for transparent migration from
/// pre-encryption archives.
fn decrypt_config_value(crypto: &cairn_seal::CryptoCtx, value: &str) -> Result<String> {
    if let Some(hex_data) = value.strip_prefix(ENC_VALUE_PREFIX) {
        let encrypted = hex::decode(hex_data)?;
        let decrypted = crypto.decrypt_blob(&encrypted)?;
        Ok(String::from_utf8((*decrypted).clone())?)
    } else {
        Ok(value.to_string())
    }
}

/// On-disk archive format version. Groundwork for future format evolution: bump
/// ONLY on a breaking change to the chunk blob layout, the envelope format, or
/// the metadata schema — never for additive config keys. A newer binary refuses
/// an archive whose version it doesn't know instead of silently misreading it
/// (a backup tool must fail loud, not corrupt).
const ARCHIVE_FORMAT_VERSION: u32 = 1;

/// minimum password length enforced at `init` (override with
/// `--allow-weak-password`). The SQLCipher KDF is GPU-brute-forceable, so a
/// short password guts the at-rest guarantee for the index/KEK.
const MIN_PASSWORD_LEN: usize = 8;

/// Gate an archive's on-disk format version against what this build supports.
/// A missing key means a pre-versioning archive (treated as version 1). A newer
/// version is refused — a backup tool must fail loud, not misread the archive.
fn check_format_version(stored: Option<&str>) -> Result<()> {
    // MISSING key = pre-versioning archive (→ 1). A key that is
    // PRESENT but not a number is corruption — refuse (do not coerce to 1).
    let on_disk: u32 = match stored {
        None => 1,
        Some(v) => v.parse().map_err(|e| {
            anyhow::anyhow!(
                "archive format_version '{v}' is not a number ({e}) — refusing to \
                 open a possibly corrupt or foreign archive"
            )
        })?,
    };
    if on_disk > ARCHIVE_FORMAT_VERSION {
        anyhow::bail!(
            "Archive format version {on_disk} is newer than this build supports \
             (max {ARCHIVE_FORMAT_VERSION}). Upgrade cairn to read it — refusing to \
             avoid misreading the archive."
        );
    }
    if on_disk < 1 {
        anyhow::bail!("archive format_version {on_disk} is invalid (minimum is 1)");
    }
    Ok(())
}

/// Derive the non-secret deduplication contract solely from archive-pinned
/// configuration.  A partial pool configuration is corruption, not an
/// invitation to quietly use archive-local equality.
fn dedup_contract(
    mode: &str,
    shared_domain: Option<&str>,
    shared_namespace: Option<&str>,
) -> Result<(&'static str, &'static str)> {
    match (mode, shared_domain, shared_namespace) {
        ("random", None, None) => Ok(("none", "none")),
        ("enabled", Some(_), Some(_)) => Ok(("pool", "blake3-keyed/pool-v1")),
        ("enabled", None, None) => Ok(("archive", "blake3-keyed/archive-v1")),
        ("random" | "enabled", _, _) => {
            anyhow::bail!("incomplete shared-dedup configuration in archive")
        }
        (other, _, _) => anyhow::bail!("unsupported dedup_mode {other:?}"),
    }
}

#[derive(Serialize)]
#[serde(tag = "event")]
enum LogEvent {
    BackupStarted {
        snapshot_name: String,
        timestamp: u64,
    },
    BackupFinished {
        snapshot_name: String,
        duration_ms: u128,
        timestamp: u64,
    },
    GcFinished {
        duration_ms: u128,
        total_removed: usize,
        local_orphans: usize,
        timestamp: u64,
    },
    ScrubFinished {
        duration_ms: u128,
        verified: usize,
        corrupted: usize,
        timestamp: u64,
    },
}

/// Hard upper bound on `--inline-max-size`. Above this, the `tokio::fs::read(path)`
/// at backup time will load the whole file into RAM (a single 10 GiB request
/// balloons RSS by 10 GiB). 64 MiB matches the chunker cap.
const MAX_INLINE_FILE_SIZE: usize = 64 * 1024 * 1024;

/// Validated init-time parameters: every enum-like value is checked
/// against an allow-list; every numeric that controls memory or compression
/// behaviour is range-checked. Refuse-and-explain beats silent fallthrough.
fn validate_init_args(
    crypto_algo: &str,
    comp_algo: &str,
    comp_level: i32,
    comp_min_ratio: i32,
    inline_max_size: usize,
) -> Result<()> {
    match crypto_algo {
        "aes-256-gcm" | "chacha20-poly1305" => {}
        other => {
            anyhow::bail!(
                "unsupported --crypto-algo: {other:?} (allowed: aes-256-gcm, chacha20-poly1305)"
            )
        }
    }
    match comp_algo {
        "zstd" | "lz4" | "none" => {}
        other => {
            anyhow::bail!("unsupported --comp-algo: {other:?} (allowed: zstd, lz4, none)")
        }
    }
    // zstd levels: 1..=22; lz4/none: 0..=16. Reject obviously-wrong values.
    if !(-7..=22).contains(&comp_level) {
        anyhow::bail!(
            "--comp-level {comp_level} out of range (zstd: 1..=22, lz4/none: any int; \
             negative values select a faster zstd preset)"
        );
    }
    if !(0..=100).contains(&comp_min_ratio) {
        anyhow::bail!(
            "--comp-min-ratio {comp_min_ratio} out of range 0..=100 \
             (0 = always keep compressed, 100 = keep only if compressed ≤ plaintext)"
        );
    }
    if inline_max_size > MAX_INLINE_FILE_SIZE {
        anyhow::bail!(
            "--inline-max-size {inline_max_size} exceeds hard cap of {MAX_INLINE_FILE_SIZE} \
             (files above this are always chunked; raising the cap risks OOM on backup \
             because the file is read into RAM in full)"
        );
    }
    Ok(())
}

/// Validated `--db-synchronous` (one of OFF/NORMAL/FULL/EXTRA) — the value is
/// interpolated verbatim into `PRAGMA synchronous = {sync}` (cairn-index) and a
/// typo silently no-ops in SQLite.
fn validate_db_synchronous(s: &str) -> Result<&str> {
    match s {
        "OFF" | "NORMAL" | "FULL" | "EXTRA" => Ok(s),
        other => anyhow::bail!(
            "unsupported --db-synchronous: {other:?} (allowed: OFF, NORMAL, FULL, EXTRA)"
        ),
    }
}

/// Human-readable summary of the last few `<archive>.log` events, newest last —
/// the health signal an operator reads to answer "did last night's backup finish
/// and was the archive scrubbed". Best-effort: returns None if the log is absent.
fn last_log_events(archive_path: &str) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(format!("{archive_path}.log")).ok()?;
    let lines: Vec<String> = raw
        .lines()
        .rev()
        .take(5)
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| {
            let ev = v.get("event").and_then(|e| e.as_str()).unwrap_or("?");
            let ts = v.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0);
            let detail = match ev {
                "BackupStarted" | "BackupFinished" => v
                    .get("snapshot_name")
                    .and_then(|s| s.as_str())
                    .map(|s| format!("snapshot={s}"))
                    .unwrap_or_default(),
                "GcFinished" => format!(
                    "removed={}",
                    v.get("total_removed").and_then(|x| x.as_u64()).unwrap_or(0)
                ),
                "ScrubFinished" => format!(
                    "verified={} corrupted={}",
                    v.get("verified").and_then(|x| x.as_u64()).unwrap_or(0),
                    v.get("corrupted").and_then(|x| x.as_u64()).unwrap_or(0)
                ),
                _ => String::new(),
            };
            format!("unix={ts}  {ev}  {detail}")
        })
        .collect();
    Some(lines.into_iter().rev().collect())
}

/// Bytes available (to a non-root process) on the filesystem holding `path`,
/// via `statvfs`. `None` if the path can't be stat'd. Used for a backup
/// pre-flight warning — the disk-full failure mode is real (a full volume makes
/// chunk writes fail with ENOSPC), and warning up front beats discovering it
/// mid-backup even though a mid-backup failure is handled safely (non-zero exit,
/// archive intact).
#[cfg(unix)]
fn available_bytes(path: &str) -> Option<u64> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: statvfs writes into a zeroed struct we own; we check the return.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some(st.f_bavail as u64 * st.f_frsize as u64)
}

/// Warn if the chunk-cache volume is critically low on free space. Non-fatal:
/// a small volume may still hold a small backup, so we advise rather than refuse.
#[cfg(unix)]
fn warn_if_low_disk(cache_dir: &str) {
    const FLOOR_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
    if let Some(free) = available_bytes(cache_dir) {
        if free < FLOOR_BYTES {
            tracing::warn!(
                "Only {} MiB free on the chunk-cache volume ({cache_dir}). A large backup may \
                 fail with ENOSPC — free space or point --cache-dir at a larger volume.",
                free / (1024 * 1024)
            );
        }
    }
}
#[cfg(not(unix))]
fn warn_if_low_disk(_cache_dir: &str) {}

/// Read a source file's extended attributes (name + value) WITHOUT following
/// symlinks. `cairn backup` used to silently drop xattrs entirely — the direct
/// ingestion path never read them, so ACLs / SELinux labels / file capabilities
/// / user attributes were lost on restore even with `--preserve`. Linux-only
/// (`llistxattr`/`lgetxattr`); returns empty on any error so a backup never
/// fails just because xattrs can't be read.
#[cfg(target_os = "linux")]
fn read_source_xattrs(path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    use std::os::unix::ffi::OsStrExt;
    let mut out = Vec::new();
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return out;
    };
    let list_len = unsafe { libc::llistxattr(cpath.as_ptr(), std::ptr::null_mut(), 0) };
    if list_len <= 0 {
        return out;
    }
    let mut names = vec![0u8; list_len as usize];
    let n = unsafe {
        libc::llistxattr(
            cpath.as_ptr(),
            names.as_mut_ptr() as *mut libc::c_char,
            names.len(),
        )
    };
    if n <= 0 {
        return out;
    }
    names.truncate(n as usize);
    // llistxattr returns NUL-separated attribute names.
    for raw in names.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        let Ok(cname) = std::ffi::CString::new(raw) else {
            continue;
        };
        let vlen =
            unsafe { libc::lgetxattr(cpath.as_ptr(), cname.as_ptr(), std::ptr::null_mut(), 0) };
        if vlen < 0 {
            continue;
        }
        let mut val = vec![0u8; vlen as usize];
        let vn = unsafe {
            libc::lgetxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                val.as_mut_ptr() as *mut libc::c_void,
                val.len(),
            )
        };
        if vn < 0 {
            continue;
        }
        val.truncate(vn as usize);
        out.push((String::from_utf8_lossy(raw).into_owned(), val));
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn read_source_xattrs(_path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    Vec::new()
}

/// Copy a source path's xattrs into the archive inode (best effort; a failure to
/// store one xattr must not abort the backup).
fn capture_xattrs(db: &cairn_index::Db, inode: u64, path: &std::path::Path) {
    for (name, value) in read_source_xattrs(path) {
        // best-effort (one bad xattr must not abort the backup), but log the
        // failure so a silently-dropped xattr is at least visible.
        if let Err(e) = db.set_xattr_with_flags(inode, &name, &value, cairn_index::XattrFlag::None)
        {
            tracing::warn!("backup: failed to store xattr '{name}' for inode {inode}: {e}");
        }
    }
}

/// SQLCipher `kdf_iter` from the `CAIRN_KDF_ITER` env var (default 256000, the
/// SQLCipher 4 secure default). Lowering it makes opening the DB much faster but
/// weakens the metadata index's brute-force resistance — intended for the test
/// suite. Warns if set below a safe floor. NOTE: whatever value creates an archive
/// must be used to re-open it (kdf_iter is not stored in the encrypted DB).
fn kdf_iter_from_env() -> u32 {
    match std::env::var("CAIRN_KDF_ITER")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
    {
        Some(n) if n < 50_000 => {
            tracing::warn!(
                "CAIRN_KDF_ITER={n} is far below the secure default (256000): the SQLCipher \
                 metadata index becomes much easier to brute-force. Use only for testing, and \
                 re-open this archive with the SAME value."
            );
            n.max(1)
        }
        Some(n) => n,
        None => 256_000,
    }
}

fn append_log(archive_path: &str, event: LogEvent) {
    let log_path = format!("{archive_path}.log");
    let log_result = {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&log_path)
    };
    if let Ok(mut file) = log_result {
        if let Ok(json) = serde_json::to_string(&event) {
            use std::io::Write;
            if writeln!(file, "{json}").is_err() {
                eprintln!("Warning: failed to write to backup log at {log_path}");
            }
        }
    }
}

/// Durable offline copy of the SQLCipher index (the map/SPOF).
///
/// Design: **copy the `.db`, never rebuild from chunks.** Checkpoint WAL so the
/// main DB file is self-contained, then `copy` + `fsync`. Records path/time in
/// config for `status`. Destination may be a directory (timestamped filename) or
/// an explicit file path.
fn copy_index_backup(
    db: &cairn_index::Db,
    archive: &str,
    dest_spec: &str,
    keep: usize,
) -> anyhow::Result<String> {
    let dest_spec = dest_spec.trim();
    if dest_spec.is_empty() {
        anyhow::bail!("index-backup destination is empty");
    }
    // Fold WAL into the main file so the copy is consistent without -wal/-shm.
    db.wal_checkpoint_truncate()
        .map_err(|e| anyhow::anyhow!("wal_checkpoint before index backup failed: {e}"))?;

    // When DEST is a directory we write a timestamped file and can rotate old
    // copies; when it is a file path we copy to it directly (one overwritten copy).
    let mut prune_target: Option<(std::path::PathBuf, String)> = None;
    let dest_path = {
        let p = std::path::Path::new(dest_spec);
        let as_dir = dest_spec.ends_with('/')
            || dest_spec.ends_with(std::path::MAIN_SEPARATOR)
            || p.is_dir();
        if as_dir {
            std::fs::create_dir_all(p)
                .map_err(|e| anyhow::anyhow!("create index-backup dir {dest_spec}: {e}"))?;
            let base = std::path::Path::new(archive)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("archive.db");
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            prune_target = Some((p.to_path_buf(), base.to_string()));
            p.join(format!("{base}.indexbak.{ts}"))
        } else {
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        anyhow::anyhow!("create index-backup parent {}: {e}", parent.display())
                    })?;
                }
            }
            p.to_path_buf()
        }
    };

    std::fs::copy(archive, &dest_path).map_err(|e| {
        anyhow::anyhow!(
            "index backup copy {} → {}: {e}",
            archive,
            dest_path.display()
        )
    })?;
    // Best-effort durability of the recovery copy.
    if let Ok(f) = std::fs::File::open(&dest_path) {
        let _ = f.sync_all();
    }
    if let Some(parent) = dest_path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(0o600));
    }

    // Rotation: for a directory destination, keep only the newest `keep` timestamped
    // copies (0 = keep all). Best-effort — the fresh copy above is already durable.
    if keep > 0 {
        if let Some((dir, base)) = &prune_target {
            prune_index_backups(dir, base, keep);
        }
    }

    let dest_s = dest_path.display().to_string();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = db.set_config("last_index_backup_path", &dest_s);
    let _ = db.set_config("last_index_backup_ts", &ts.to_string());
    Ok(dest_s)
}

/// Resolve index-backup destination: explicit flag, else `CAIRN_INDEX_BACKUP` env.
fn resolve_index_backup_dest(explicit: Option<&str>) -> Option<String> {
    if let Some(d) = explicit {
        let t = d.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    std::env::var("CAIRN_INDEX_BACKUP")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// How many timestamped index-backup copies to keep in a directory destination:
/// the explicit `--index-backup-keep N`, else `CAIRN_INDEX_BACKUP_KEEP`, else 0
/// (keep all — never prune). A set-but-invalid env value is ignored (kept at 0).
fn resolve_index_backup_keep(explicit: Option<u32>) -> usize {
    if let Some(n) = explicit {
        return n as usize;
    }
    match std::env::var("CAIRN_INDEX_BACKUP_KEEP") {
        Ok(v) => v.trim().parse::<usize>().unwrap_or_else(|_| {
            if !v.trim().is_empty() {
                tracing::warn!("invalid CAIRN_INDEX_BACKUP_KEEP='{v}' — keeping all copies");
            }
            0
        }),
        Err(_) => 0,
    }
}

/// Prune old `<base>.indexbak.<unix-seconds>` copies in `dir`, keeping the newest
/// `keep`. Only files matching that exact pattern (all-digit timestamp suffix) are
/// considered — any other file in the directory is left untouched. Best-effort:
/// a failure to remove one stale copy is logged, not fatal.
fn prune_index_backups(dir: &std::path::Path, base: &str, keep: usize) {
    let prefix = format!("{base}.indexbak.");
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!("index-backup rotation: cannot read {}: {e}", dir.display());
            return;
        }
    };
    let mut copies: Vec<(u64, std::path::PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_str()?;
            let ts_str = name.strip_prefix(&prefix)?;
            // Only our timestamped backups: the suffix must be a non-empty run of digits.
            if ts_str.is_empty() || !ts_str.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((ts_str.parse::<u64>().ok()?, e.path()))
        })
        .collect();
    if copies.len() <= keep {
        return;
    }
    copies.sort_by_key(|&(ts, _)| std::cmp::Reverse(ts)); // newest first
    for (_, path) in copies.into_iter().skip(keep) {
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::info!("index-backup rotation: removed old copy {}", path.display()),
            Err(e) => tracing::warn!(
                "index-backup rotation: cannot remove old copy {}: {e}",
                path.display()
            ),
        }
    }
}

const CHUNK_CACHE_CAP: std::num::NonZeroUsize = match std::num::NonZeroUsize::new(256) {
    Some(n) => n,
    None => panic!("256 is non-zero"),
};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Cairn — encrypted, deduplicated backup filesystem",
    long_about = "Cairn is an encrypted, deduplicated backup filesystem with asymmetric envelope\n\
                  encryption. It provides a FUSE mount for browsing backups and CLI commands\n\
                  for creating, restoring, and managing encrypted archives.\n\n\
                  Archives use SQLCipher for metadata encryption, age for key management,\n\
                  and content-defined chunking with BLAKE3 deduplication.\n\n\
                  FEATURES:\n\
                  • Incremental backup — skip unchanged files (mtime+size comparison)\n\
                  • Progress bar with ETA for backup and restore operations\n\
                  • Dry-run mode — preview what would be backed up without writing\n\
                  • Backup size estimation — check before writing\n\
                  • Mount specific snapshot — time-machine mode (--snapshot N)\n\
                  • Snapshot diff — compare two snapshots (snapshot diff A B)\n\
                  • Restore to original path (--to-source)\n\
                  • Per-backup dedup and compression stats\n\n\
                  SECURITY: prefer --password-file or CAIRN_PASSWORD env var over --password.",
    after_help = "ENVIRONMENT:\n  CAIRN_PASSWORD          Symmetric password (alternative to --password/--password-file)\n  CAIRN_MAX_WRITE_KB      Maximum FUSE read/write payload in KiB (default: 1024)\n  CAIRN_MAX_FILE_SIZE_GIB Maximum file size in GiB (default: 1024)\n  CAIRN_DB_POOL_SIZE      SQLite connection pool size, max (default: 16)\n  CAIRN_DB_CACHE_KB       Per-connection SQLite page cache in KiB (default: 64000)\n  CAIRN_DB_MMAP_KB        Per-connection mmap size in KiB (default: 32768)\n  CAIRN_DB_SYNCHRONOUS    SQLite synchronous mode: OFF|NORMAL|FULL|EXTRA (default: FULL)\n  CAIRN_DB_BUSY_TIMEOUT_MS Busy lock timeout in ms (default: 15000)\n  CAIRN_DB_CONNECTION_TIMEOUT_SECS Pool connection deadline in seconds (default: 30)\n  CAIRN_KDF_ITER          SQLCipher KDF iterations (default: 256000; low values warn — test-only, and the SAME value must be used to re-open the archive)\n  RUST_LOG                Log level: trace|debug|info|warn|error (default: info)"
)]
struct Args {
    /// Path to the `SQLite` archive
    #[arg(required = true)]
    archive: String,

    /// Symmetric password. Prefer the CAIRN_PASSWORD env var or
    /// --password-file: command-line arguments are visible via `ps aux`.
    #[arg(long, env = "CAIRN_PASSWORD", global = true)]
    password: Option<SecretString>,

    /// Read the symmetric password from a file (one line, trimmed).
    /// More secure than --password: file permissions control access.
    #[arg(long, conflicts_with = "password", global = true)]
    password_file: Option<String>,

    /// Public key
    #[arg(long, global = true)]
    pub_key: Option<String>,

    /// Private key
    #[arg(long, global = true)]
    priv_key: Option<SecretString>,

    /// Directory for local chunk cache
    #[arg(long, global = true)]
    cache_dir: Option<String>,

    /// File holding the shared-dedup domain secret. Required when opening an
    /// archive configured for shared dedup if its stored path is unavailable.
    #[arg(long, global = true)]
    shared_dedup_secret_file: Option<std::path::PathBuf>,

    /// Maximum local cache size in megabytes (0 = unlimited)
    #[arg(long, default_value_t = 0, global = true)]
    cache_limit_mb: u64,

    /// Per-file write buffer flush threshold, MB
    #[arg(long, default_value_t = cairn_core::DEFAULT_WRITE_BUFFER_INODE_MAX / (1024 * 1024), global = true)]
    write_buffer_inode_mb: usize,

    /// Total write buffer budget across all open files, MB (backpressure: a
    /// writer over this budget flushes its own buffer before returning)
    #[arg(long, default_value_t = cairn_core::DEFAULT_WRITE_BUFFER_GLOBAL_MAX / (1024 * 1024), global = true)]
    write_buffer_global_mb: usize,

    /// Decrypted chunk read-cache budget, MB
    #[arg(long, default_value_t = cairn_core::DEFAULT_CHUNK_CACHE_MAX_BYTES / (1024 * 1024), global = true)]
    chunk_cache_mb: usize,

    /// Maximum FUSE read/write payload size, KiB. Larger values raise per-request
    /// RAM allocation and throughput; smaller values limit worst-case memory.
    /// Valid range: 64..=8192 (64 KiB – 8 MiB).
    #[arg(long, default_value_t = cairn_core::DEFAULT_MAX_WRITE / 1024, env = "CAIRN_MAX_WRITE_KB", global = true)]
    max_write_kb: u32,

    /// Maximum single-file size in GiB. Files larger than this are rejected
    /// with EFBIG. Prevents unbounded hole creation via sparse writes.
    #[arg(
        long,
        default_value_t = 1024,
        env = "CAIRN_MAX_FILE_SIZE_GIB",
        global = true
    )]
    max_file_size_gib: u64,

    /// Wrapped-key cache capacity, entries (~64 bytes each)
    #[arg(long, default_value_t = cairn_seal::DEFAULT_SYM_KEY_CACHE_CAP, global = true)]
    sym_key_cache_cap: usize,

    /// SQLCipher/SQLite connection-pool size (max). Each connection reserves its
    /// own page cache (see `--db-cache-kb`) AND runs a full SQLCipher KDF when
    /// first opened, so worst-case resident memory is roughly
    /// `--db-pool-size * --db-cache-kb`. Only one connection is opened eagerly;
    /// the rest open on demand. Lower on memory-constrained hosts.
    #[arg(long, default_value_t = 16, env = "CAIRN_DB_POOL_SIZE", global = true)]
    db_pool_size: u32,

    /// Per-connection SQLite page cache, KiB (negative PRAGMA form). Larger =
    /// faster repeated reads, more RAM. Default 64000 (64 MiB/conn → up to 2 GiB
    /// at the default 16-connection pool → up to 1 GiB; lower for small hosts).
    #[arg(
        long,
        default_value_t = 64_000,
        env = "CAIRN_DB_CACHE_KB",
        global = true
    )]
    db_cache_kb: i64,

    /// SQLite `synchronous` PRAGMA. `FULL` (default; safest against power loss —
    /// the right choice for irreplaceable backup metadata) or `NORMAL` (faster,
    /// still crash-safe under WAL but weaker against power loss on filesystems
    /// that reorder WAL writes). One of: OFF, NORMAL, FULL, EXTRA.
    #[arg(
        long,
        default_value = "FULL",
        env = "CAIRN_DB_SYNCHRONOUS",
        global = true
    )]
    db_synchronous: String,

    /// Per-connection SQLite memory-mapped I/O size, KiB. Worst-case address
    /// space reserved = `--db-pool-size * --db-mmap-kb`. Lower for small hosts
    /// (`CAIRN_DB_MMAP_KB`).
    #[arg(long, default_value_t = 32 * 1024, env = "CAIRN_DB_MMAP_KB", global = true)]
    db_mmap_kb: i64,

    /// How long a transaction waits on a busy lock before failing with
    /// `SQLITE_BUSY`. Applied to EVERY pool connection.
    /// `CAIRN_DB_BUSY_TIMEOUT_MS`.
    #[arg(
        long,
        default_value_t = 15_000,
        env = "CAIRN_DB_BUSY_TIMEOUT_MS",
        global = true
    )]
    db_busy_timeout_ms: u32,

    /// `pool.get()` deadline in seconds. 0 = wait forever (DoS risk under
    /// `pool.get()` deadline in seconds. 0 = wait forever (DoS risk under
    /// slow disk). `CAIRN_DB_CONNECTION_TIMEOUT_SECS`.
    #[arg(
        long,
        default_value_t = 30,
        env = "CAIRN_DB_CONNECTION_TIMEOUT_SECS",
        global = true
    )]
    db_connection_timeout_secs: u32,

    /// Output in JSON format
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

// Custom Debug to prevent password leakage in logs / error output.
impl std::fmt::Debug for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Args")
            .field("archive", &self.archive)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("password_file", &self.password_file)
            .field("pub_key", &self.pub_key)
            .field("priv_key", &self.priv_key.as_ref().map(|_| "<redacted>"))
            .field("cache_dir", &self.cache_dir)
            .field("cache_limit_mb", &self.cache_limit_mb)
            .field("write_buffer_inode_mb", &self.write_buffer_inode_mb)
            .field("write_buffer_global_mb", &self.write_buffer_global_mb)
            .field("chunk_cache_mb", &self.chunk_cache_mb)
            .field("max_write_kb", &self.max_write_kb)
            .field("max_file_size_gib", &self.max_file_size_gib)
            .field("sym_key_cache_cap", &self.sym_key_cache_cap)
            .field("db_pool_size", &self.db_pool_size)
            .field("db_cache_kb", &self.db_cache_kb)
            .field("db_synchronous", &self.db_synchronous)
            .field("db_mmap_kb", &self.db_mmap_kb)
            .field("db_busy_timeout_ms", &self.db_busy_timeout_ms)
            .field(
                "db_connection_timeout_secs",
                &self.db_connection_timeout_secs,
            )
            .field("json", &self.json)
            .field("command", &self.command)
            .finish()
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new encrypted backup archive
    Init {
        #[arg(long, default_value = "aes-256-gcm")]
        crypto_algo: String,
        #[arg(long, default_value = "zstd")]
        comp_algo: String,
        #[arg(long, default_value_t = 3)]
        comp_level: i32,
        #[arg(long, default_value_t = 5)]
        comp_min_ratio: i32,
        #[arg(long, default_value_t = 64)]
        comp_min_size: usize,
        #[arg(long, default_value_t = 300)]
        index_sync_interval: u64,
        #[arg(long, default_value = "jpg,jpeg,png,mp4,zip,gz,zst")]
        no_comp_ext: String,
        #[arg(long)]
        max_upload_speed_mb: Option<usize>,
        #[arg(long, default_value_t = 4096)]
        inline_max_size: usize,
        /// Maximum privacy at the cost of deduplication: every chunk gets a fresh
        /// random key, so identical content produces different ciphertext. Closes
        /// the convergent-dedup confirmation oracle and the compression-oracle
        /// side channel (see SECURITY.md). Fixed at init — the mode is stored in
        /// the archive and cannot be flipped later.
        #[arg(long)]
        disable_dedup: bool,
        /// Keep this archive out of a selected pool while retaining ordinary
        /// archive-local deduplication.  This is the privacy boundary switch;
        /// it is fixed at init and never silently changed on reopen.
        #[arg(long, conflicts_with = "shared_dedup_domain")]
        disable_shared_dedup: bool,
        /// Shared-dedup domain id (BF-02): enables opt-in cross-archive
        /// deduplication within this domain. Requires --shared-dedup-secret-file;
        /// the two flags must come together and conflict with --disable-dedup.
        /// Only the derived non-secret namespace is stored in the archive.
        #[arg(long)]
        shared_dedup_domain: Option<String>,
        /// Directory shared by every archive in this domain. It holds the
        /// canonical ciphertext and the atomic domain mappings.
        #[arg(long)]
        shared_dedup_store_dir: Option<std::path::PathBuf>,
        /// Ransomware hardening: forbid gc / snapshot rm / snapshot prune forever
        /// (cannot be disabled through the CLI once set)
        #[arg(long)]
        append_only: bool,
        /// Re-initialise an existing archive (DESTRUCTIVE: invalidates every
        /// chunk encrypted with the existing keys). Default is to refuse.
        #[arg(long)]
        force: bool,
        /// Create the archive with NO password → the metadata index (file names,
        /// sizes, tree, xattrs) is stored UNENCRYPTED and readable by stock
        /// sqlite3. Required opt-in so a forgotten CAIRN_PASSWORD errors instead
        /// of silently shipping a cleartext index.
        #[arg(long)]
        allow_plaintext_index: bool,
        /// Accept a password shorter than the enforced minimum. Only use
        /// for throwaway/test archives — short passwords are GPU-brute-forceable.
        #[arg(long)]
        allow_weak_password: bool,
        /// Hide file/dir/symlink NAMES from an untrusted backup host (asymmetric
        /// archives only). Dentry lookup keys become keyed hashes and the real
        /// names are stored age-encrypted (write-only: only the private key reads
        /// them). Requires --pub-key and a password. Fixed at init, like
        /// --disable-dedup. Does NOT hide tree shape, sizes, mtimes, or xattr
        /// values — see HIDE_NAMES.md. Opt-in: it trades the password-only
        /// name-inspection escape hatch for name confidentiality.
        #[arg(long)]
        hide_names: bool,
    },
    /// Enable append-only mode (one-way: no CLI path disables it)
    AppendOnly,
    /// Upload local chunks to cloud backends (S3/GCS)
    Push {
        #[arg(long)]
        max_upload_speed_mb: Option<usize>,
    },
    /// Download index from cloud backends
    Pull,
    /// Show archive status and configuration
    Status,
    /// Remove unreferenced chunks older than grace period
    Gc {
        #[arg(long, default_value_t = 24)]
        grace_period_hours: u64,
    },
    /// Verify chunk integrity and optionally auto-heal from redundancy
    Scrub {
        #[arg(long)]
        auto_heal: bool,
        /// Bypass local chunk cache; read only from cloud backends (fails on
        /// local-only archives). Use after `push` to prove offsite durability
        /// (warm-cache verify is not an offsite proof).
        #[arg(long)]
        force_remote: bool,
    },
    /// Verify every file can be fully restored (read + decrypt all chunks).
    /// Proves restorability of *indexed* files — not that no inventory entry
    /// was deleted (no whole-archive signature; see THREAT_MODEL / HOSTILE audit).
    Verify {
        /// Bypass local chunk cache; read only from cloud backends.
        #[arg(long)]
        force_remote: bool,
        /// Fail if the archive has fewer than N regular files (ops completeness check).
        #[arg(long)]
        expect_min_files: Option<u64>,
    },
    /// Mount archive as a FUSE filesystem
    Mount {
        mountpoint: String,
        #[arg(long)]
        read_only: bool,
        #[arg(long)]
        allow_other: bool,
        /// Mount the archive as it was at a specific snapshot (time-machine mode)
        #[arg(long)]
        snapshot: Option<u64>,
    },
    /// Extract files from archive to disk (low-level, with glob/file-path filtering)
    Extract {
        dest_dir: String,
        /// Skip BLAKE3/hash verification on read (DANGEROUS). Requires
        /// `CAIRN_I_ACCEPT_CORRUPTION=1` in the environment in addition to this flag.
        #[arg(long)]
        dangerously_skip_verify: bool,
        /// Literal path inside the archive. Use `--glob` for shell-style wildcards
        /// (otherwise a filename containing `*` or `?` would be mis-routed to
        /// pattern matching).
        #[arg(long)]
        file_path: Option<String>,
        /// Shell-style glob pattern matched against the archive tree (e.g.
        /// `--glob '/home/*/report.txt'`). Mutually exclusive with
        /// `--file-path`.
        #[arg(long, conflicts_with = "file_path")]
        glob: Option<String>,
        /// Restore owner (uid/gid), timestamps (mtime), and xattrs in addition to
        /// data + mode. Off by default: extracting as root with `--preserve` will
        /// set file owners from the archive; without it, files are owned by the
        /// extracting user (safer default for unprivileged restore).
        #[arg(long)]
        preserve: bool,
    },
    /// Run the background GC and cloud-upload loops without a mount (`daemon start`)
    Daemon {
        /// Currently only `start`
        action: String,
        #[arg(long)]
        max_upload_speed_mb: Option<usize>,
    },
    /// Back up a directory tree into the archive
    Backup {
        source: String,
        #[arg(default_value = "/")]
        dest: String,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long)]
        max_upload_speed_mb: Option<usize>,
        #[arg(long)]
        inline_max_size: Option<usize>,
        /// Skip files unchanged since last backup (mtime+size fast path, then
        /// content fingerprint). Prefer a full backup for critical trees.
        #[arg(long)]
        incremental: bool,
        /// Show what would be backed up without writing
        #[arg(long)]
        dry_run: bool,
        /// Show estimated size before writing
        #[arg(long)]
        estimate: bool,
        /// Fail (non-zero) if any special files (FIFO/socket/device) were skipped.
        /// By default specials are skipped with a warning (OPERATING §9).
        #[arg(long)]
        strict: bool,
        /// After a successful backup, copy the SQLCipher index (`.db`) to PATH.
        /// PATH may be a directory (timestamped file) or a file. Same as env
        /// `CAIRN_INDEX_BACKUP`. Index is the map SPOF — **copy it**, do not try
        /// to rebuild from chunks (OPERATING / HOSTILE audit).
        #[arg(long, value_name = "PATH")]
        index_backup: Option<String>,
        /// With `--index-backup DIR`, keep only the newest N timestamped copies
        /// (older ones are pruned). 0 = keep all. Env: `CAIRN_INDEX_BACKUP_KEEP`.
        #[arg(long, value_name = "N")]
        index_backup_keep: Option<u32>,
        /// After a successful backup, create a named snapshot (point-in-time index
        /// state for completeness/ops — not a crypto inventory MAC).
        #[arg(long)]
        auto_snapshot: bool,
    },
    /// Copy the metadata index (`.db`) to an offline/off-host path.
    /// Prefer this over any “rebuild from chunks” fantasy — the index *is* the map.
    IndexBackup {
        /// Destination file or directory (timestamped name if directory).
        dest: String,
        /// When DEST is a directory, keep only the newest N timestamped copies
        /// (older ones are pruned). 0 = keep all. Env: `CAIRN_INDEX_BACKUP_KEEP`.
        #[arg(long, value_name = "N")]
        keep: Option<u32>,
    },
    /// Restore files from the archive to a directory (non-FUSE extraction)
    Restore {
        /// Destination directory to restore files into
        dest_dir: String,
        /// Literal path inside the archive to restore (default: all files)
        #[arg(long)]
        file_path: Option<String>,
        /// Shell-style glob pattern matched against the archive tree
        #[arg(long, conflicts_with = "file_path")]
        glob: Option<String>,
        /// Restore owner (uid/gid), timestamps (mtime), and xattrs
        #[arg(long)]
        preserve: bool,
        /// Skip read-verification of restored chunks (DANGEROUS: accepts
        /// corrupted or tampered chunks silently). Requires
        /// `CAIRN_I_ACCEPT_CORRUPTION=1` in the environment.
        #[arg(long)]
        dangerously_skip_verify: bool,
        /// Restore to the original source directory (stored during backup)
        #[arg(long)]
        to_source: bool,
    },
    /// Check archive integrity (synonym of `verify`: every file decrypt end-to-end)
    Check {
        /// Bypass local chunk cache; read only from cloud backends.
        #[arg(long)]
        force_remote: bool,
        /// Fail if the archive has fewer than N regular files.
        #[arg(long)]
        expect_min_files: Option<u64>,
    },
    /// Manage snapshots (create, list, delete, rollback, prune)
    Snapshot {
        #[command(subcommand)]
        cmd: SnapshotCommands,
    },
    /// Manage RAID backends (add, remove, set mode)
    Raid {
        #[command(subcommand)]
        cmd: RaidCommands,
    },
}

#[derive(Subcommand, Debug)]
enum SnapshotCommands {
    /// Create a named snapshot of the current archive state
    Create {
        name: String,
    },
    /// List all snapshots
    Ls,
    /// Delete a snapshot by ID
    Rm {
        id: u64,
    },
    /// Rollback archive to a specific snapshot (EXCLUSIVE lock; replaces the DB file).
    /// Non-atomic window is documented in ARCHITECTURE — never run on the sole copy
    /// without a prior offline DB copy. Use `--i-accept-non-atomic` to proceed.
    Rollback {
        id: u64,
        /// Required acknowledgement: crash mid file-swap is not fully guarded.
        #[arg(long)]
        i_accept_non_atomic: bool,
    },
    /// Delete old snapshots based on retention rules
    Prune {
        /// Max number of daily snapshots to keep (most-recent N distinct days).
        /// 0 = the rule does not apply (treated as unset). Use `--keep-daily 1`
        /// to keep exactly the most recent snapshot per day.
        #[arg(long)]
        keep_daily: Option<usize>,
        /// Max number of weekly snapshots to keep (most-recent N distinct ISO
        /// weeks). 0 = rule does not apply.
        #[arg(long)]
        keep_weekly: Option<usize>,
        /// Max number of monthly snapshots to keep (most-recent N distinct
        /// months). 0 = rule does not apply.
        #[arg(long)]
        keep_monthly: Option<usize>,
        /// Max number of yearly snapshots to keep (most-recent N distinct
        /// years). 0 = rule does not apply.
        #[arg(long)]
        keep_yearly: Option<usize>,
        /// Trusted checkpoint to explicitly re-anchor after this intentional
        /// history deletion. Required when the current checkpointed snapshot
        /// would be removed.
        #[arg(long, value_name = "PATH")]
        checkpoint: Option<String>,
    },
    /// Compare two snapshots and show added/removed/modified files
    Diff {
        /// First snapshot ID
        from: u64,
        /// Second snapshot ID
        to: u64,
    },
    /// Export one frozen snapshot and its opaque ciphertext objects as a portable bundle.
    Export {
        id: u64,
        dest: String,
    },
    /// Validate a portable bundle and import its ciphertext objects into this archive cache.
    Import {
        bundle: String,
    },
    /// Build a JSON deletion plan from an external JSON array of snapshot IDs.
    DeletePlan {
        ids_file: String,
        #[arg(long)]
        allow_empty_history: bool,
    },
    /// Atomically apply a previously generated deletion plan.
    DeleteApply {
        plan: String,
    },
    Protect {
        id: u64,
        #[arg(long)]
        off: bool,
    },
    Tags {
        id: u64,
        tags_json: String,
    },
}

#[derive(Subcommand, Debug)]
enum RaidCommands {
    /// Add a cloud backend (e.g. s3://bucket, gcs://bucket)
    Add { uri: String },
    /// Remove a backend by ID
    Remove { id: u64 },
    /// Set RAID mode (e.g. raid0, raid1)
    SetMode { mode: String },
}

#[derive(serde::Serialize)]
struct SnapshotStat {
    id: u64,
    name: String,
    timestamp: u64,
    protected: bool,
    tags: serde_json::Value,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SnapshotDeletePlan {
    api_version: u8,
    archive_id: String,
    history_revision: u64,
    ids: Vec<u64>,
    allow_empty_history: bool,
}

#[derive(serde::Serialize)]
struct SnapshotList {
    api_version: u8,
    archive_id: String,
    history_revision: u64,
    snapshots: Vec<SnapshotStat>,
}

/// Remove a file only if it is NOT a symlink (TOCTOU symlink-attack guard).
fn safe_remove_for_overwrite(path: &str) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!("Refused: {path} is a symlink — possible symlink attack");
        }
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Should this snapshot be kept under the given retention rule?
fn should_keep(seen: &mut std::collections::HashSet<String>, key: &str, max: usize) -> bool {
    if !seen.contains(key) && seen.len() < max {
        seen.insert(key.to_string());
        true
    } else {
        false
    }
}

/// Read a typed config value from the DB, falling back to a default.
fn db_config<T: std::str::FromStr + ToString>(
    db: &cairn_index::Db,
    key: &str,
    default: T,
) -> Result<T> {
    // a MISSING key uses the default silently
    // (correct); a PRESENT but unparseable value is corruption — log it, then fall
    // back to the default rather than failing every config-reading operation.
    Ok(match db.get_config(key)? {
        None => default,
        Some(v) => v.parse().unwrap_or_else(|_| {
            tracing::warn!(
                "config '{key}' has an invalid value '{v}' — using default {}",
                default.to_string()
            );
            default
        }),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !(64..=8192).contains(&args.max_write_kb) {
        anyhow::bail!(
            "--max-write-kb must be between 64 and 8192 (got {})",
            args.max_write_kb
        );
    }
    // validate --db-synchronous against SQLite's allow-list. A typo
    // (NORMALL, FAST) would otherwise be silently accepted by SQLite and the
    // user gets whatever the previous setting was.
    validate_db_synchronous(&args.db_synchronous)?;
    // catch the multiplication overflow on --cache-limit-mb before
    // the eviction loop empties the cacache silently.
    if args.cache_limit_mb != 0 && args.cache_limit_mb.checked_mul(1024 * 1024).is_none() {
        anyhow::bail!(
            "--cache-limit-mb {cache_limit_mb} overflows u64",
            cache_limit_mb = args.cache_limit_mb
        );
    }
    // Guard against absurdly large --db-cache-kb values that would OOM the
    // process (SQLite uses this as its page cache limit).
    const MAX_DB_CACHE_KB: i64 = 1024 * 1024; // 1 GB
    if args.db_cache_kb > MAX_DB_CACHE_KB {
        anyhow::bail!(
            "--db-cache-kb {} exceeds maximum ({} KB = 1 GB)",
            args.db_cache_kb,
            MAX_DB_CACHE_KB
        );
    }
    let level = match std::env::var("RUST_LOG").ok().as_deref() {
        Some("debug" | "DEBUG") => tracing::Level::DEBUG,
        Some("trace" | "TRACE") => tracing::Level::TRACE,
        Some("warn" | "WARN") => tracing::Level::WARN,
        Some("error" | "ERROR") => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    // #7: Resolve password from --password, --password-file, or CAIRN_PASSWORD env.
    let password = match (args.password.clone(), &args.password_file) {
        (Some(pwd), _) => Some(pwd),
        (None, Some(path)) => {
            let content = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("Cannot read password file '{path}': {e}"))?;
            // use the FIRST line (trimmed), as `--password-file`'s help
            // promises ("one line, trimmed"). The previous `content.trim()` used
            // the whole file, so a second line / trailing comment silently
            // changed the password from what the user expected.
            let first_line = content.lines().next().unwrap_or("").trim();
            if first_line.is_empty() {
                anyhow::bail!("Password file '{path}' is empty (first line is blank)");
            }
            // read directly into SecretString; no intermediate plain String copy.
            Some(secrecy::SecretString::from(first_line.to_owned()))
        }
        (None, None) => None,
    };

    // running without any password silently produced a
    // PLAINTEXT metadata index — file names, sizes, tree structure readable by
    // anyone with the file. Warn loudly on every invocation, not just init.
    if password.is_none() {
        eprintln!(
            "WARNING: no password given (--password / --password-file / CAIRN_PASSWORD) — \
             the metadata index is stored UNENCRYPTED (file names, sizes and structure \
             are readable by anyone who obtains the archive file)."
        );
        tracing::warn!("no password: SQLCipher index is plaintext");
    }

    let db_path = &args.archive;

    // Advisory archive lock (`<archive>.lock`).
    // SHARED: read-only / concurrent-safe commands (status, extract, verify, …).
    // EXCLUSIVE: any command that mutates the archive or replaces the DB file
    // (backup, gc, init --force, snapshot create/rm/prune/rollback, push, …).
    // OPERATING claims single-writer; previously only rollback took EXCL and two
    // concurrent backups could both exit 0 (H21). Held for process lifetime.
    #[cfg(unix)]
    let _archive_lock = {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let lock_path = format!("{}.lock", args.archive);
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&lock_path)?;
        let exclusive = matches!(
            &args.command,
            Commands::Init { .. }
                | Commands::AppendOnly
                | Commands::Push { .. }
                | Commands::Pull
                | Commands::Gc { .. }
                | Commands::Backup { .. }
                | Commands::IndexBackup { .. }
                | Commands::Daemon { .. }
                | Commands::Mount { .. }
                | Commands::Raid { .. }
                | Commands::Snapshot {
                    cmd: SnapshotCommands::Create { .. }
                        | SnapshotCommands::Rm { .. }
                        | SnapshotCommands::Rollback { .. }
                        | SnapshotCommands::Prune { .. }
                }
        );
        let op = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        } | libc::LOCK_NB;
        if unsafe { libc::flock(lock_file.as_raw_fd(), op) } != 0 {
            if exclusive {
                anyhow::bail!(
                    "Archive is in use by another cairn process (mounted or writing?). \
                     Unmount / stop the other process and retry."
                );
            }
            anyhow::bail!(
                "Archive is locked exclusively by another cairn process (write in progress) — retry later."
            );
        }
        lock_file
    };
    let cache_dir_base = args
        .cache_dir
        .clone()
        .unwrap_or_else(|| format!("{}_cache", args.archive));

    if !matches!(args.command, Commands::Init { .. }) && !std::path::Path::new(db_path).exists() {
        anyhow::bail!("Archive '{db_path}' does not exist. Please run 'init' first.");
    }

    // only long-lived processes keep a warm idle connection. For one-shot
    // commands min_idle MUST be 0 — a background pool replenish (SQLCipher KDF
    // inside libcrypto on an r2d2-worker thread) racing process exit segfaults
    // in OpenSSL's atexit teardown.
    let long_lived = matches!(
        args.command,
        Commands::Mount { .. } | Commands::Daemon { .. }
    );
    let db = cairn_index::Db::new_with_tuning(
        db_path,
        password.as_ref(),
        &cairn_index::DbTuning {
            max_connections: args.db_pool_size.max(1),
            cache_size_kb: args.db_cache_kb,
            mmap_size_kb: args.db_mmap_kb,
            synchronous: args.db_synchronous.clone(),
            busy_timeout_ms: args.db_busy_timeout_ms,
            connection_timeout_secs: args.db_connection_timeout_secs,
            kdf_iter: kdf_iter_from_env(),
            min_idle: if long_lived { 1 } else { 0 },
        },
    )?;

    // `init` writes the current version; every other command refuses an archive
    // from a newer (unknown) format rather than misreading it. Forward-safety
    // groundwork — harmless while only version 1 exists.
    if !matches!(args.command, Commands::Init { .. }) {
        check_format_version(db.get_config("format_version")?.as_deref())?;
    }

    match &args.command {
        Commands::Init {
            crypto_algo,
            comp_algo,
            comp_level,
            comp_min_ratio,
            comp_min_size,
            index_sync_interval,
            no_comp_ext,
            max_upload_speed_mb,
            inline_max_size,
            disable_dedup,
            disable_shared_dedup,
            shared_dedup_domain,
            shared_dedup_store_dir,
            append_only,
            force,
            allow_plaintext_index,
            allow_weak_password,
            hide_names,
        } => {
            // D01: resolve (and thereby validate) the shared-dedup pair BEFORE
            // any archive mutation -- absent/partial/conflicting/secret-file
            // errors abort init with nothing written. The secret is only held
            // in memory; the archive persists the NON-secret namespace.
            let shared_dedup = if *disable_shared_dedup {
                None
            } else {
                shared_dedup::resolve(
                    shared_dedup_domain.as_deref(),
                    args.shared_dedup_secret_file.as_deref(),
                    *disable_dedup,
                    // Background/long-running processes: the domain secret comes
                    // from the environment, not from a per-invocation file.  It is
                    // consumed in-memory only (never stored).
                    std::env::var("CAIRN_SHARED_DEDUP_SECRET")
                        .ok()
                        .map(|s| s.into_bytes()),
                )
                .map_err(|e| anyhow::anyhow!(e))?
            };
            if shared_dedup.is_some() && shared_dedup_store_dir.is_none() {
                anyhow::bail!(
                    "--shared-dedup-domain requires --shared-dedup-store-dir: \
                     archives in the domain must use one common filesystem store"
                );
            }
            if shared_dedup.is_some() && args.shared_dedup_secret_file.is_none() {
                anyhow::bail!(
                    "--shared-dedup-domain requires --shared-dedup-secret-file: \
                     the path is retained as an archive-local secret source for later writes"
                );
            }
            // A deliberately low CAIRN_KDF_ITER (< the 50k secure floor) marks a
            // throwaway/test archive — the production password policies below
            // don't apply there, so the test suite's short/absent
            // throwaway passwords don't need a per-call opt-in. Production
            // (default 256000) enforces both.
            let throwaway_kdf = std::env::var("CAIRN_KDF_ITER")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .is_some_and(|n| n < 50_000);
            // fail closed on a passwordless archive. Without a password the
            // SQLCipher index is plaintext (stock-sqlite3-readable metadata); a
            // forgotten CAIRN_PASSWORD must ERROR, not silently ship cleartext.
            // The loud warning stays for the explicit opt-in path.
            if password.is_none() && !*allow_plaintext_index && !throwaway_kdf {
                anyhow::bail!(
                    "Refusing to create an UNENCRYPTED archive: no password given \
                     (--password / --password-file / CAIRN_PASSWORD). The metadata index \
                     (file names, sizes, tree, xattrs) would be stored in cleartext. \
                     Set a password, or pass --allow-plaintext-index to intentionally \
                     create a plaintext-metadata archive."
                );
            }
            // enforce a minimum password strength at archive creation. A
            // 1-char password unlocks the index and (symmetric) wraps the KEK,
            // and the KDF is GPU-brute-forceable — a short password guts the
            // "loss/theft of storage medium" guarantee.
            if let Some(pwd) = &password {
                use secrecy::ExposeSecret;
                let len = pwd.expose_secret().chars().count();
                if len < MIN_PASSWORD_LEN && !*allow_weak_password && !throwaway_kdf {
                    anyhow::bail!(
                        "Password too short: {len} characters (minimum {MIN_PASSWORD_LEN}). \
                         A short password is GPU-brute-forceable and undermines index/KEK \
                         protection. Use a longer password, or pass --allow-weak-password \
                         for a throwaway/test archive."
                    );
                }
            }
            // --hide-names is only meaningful, and only safe, in the
            // untrusted-host (asymmetric) model WITH an encrypted index:
            //   * asymmetric (--pub-key): real names are age-encrypted write-only,
            //     so the pub-key-only host cannot read them back. In symmetric
            //     mode the host holds the password → it could decrypt names →
            //     hiding would be defeated.
            //   * encrypted index (password): the name-hashing secret lives under
            //     the SQLCipher password. A plaintext index would expose it, so
            //     storage theft could confirm-by-guess — breaking the guarantee.
            if *hide_names {
                if args.pub_key.is_none() {
                    anyhow::bail!(
                        "--hide-names requires an asymmetric archive (--pub-key). In symmetric \
                         (password-only) mode the backup host holds the password and could \
                         decrypt the names, which would defeat name hiding."
                    );
                }
                if password.is_none() {
                    anyhow::bail!(
                        "--hide-names requires a password: the name-hashing secret is stored in \
                         the encrypted index. Without a password the index (and that secret) \
                         would be plaintext, letting storage theft confirm names by guessing."
                    );
                }
            }
            // CLI validation: fail-loud on bogus enum-like values
            // and unbounded numerics. The previous pass silently accepted any
            // string for `comp_algo` and any `usize` for `inline_max_size`,
            // which led to decompression-bomb / OOM-by-config.
            validate_init_args(
                crypto_algo,
                comp_algo,
                *comp_level,
                *comp_min_ratio,
                *inline_max_size,
            )?;
            // refuse to silently re-initialise an
            // existing archive. Re-rolling `dedup_secret` / `wrapped_kek` would
            // orphan every existing chunk (chunks are encrypted with the OLD
            // secret). `--force` is the explicit "I know what I'm doing" escape
            // hatch (e.g. for recovery from a corrupt config).
            if !*force {
                if let Some(existing_format) = db.get_config("format_version")? {
                    anyhow::bail!(
                        "Archive '{db_path}' is already initialised (format_version = {existing_format}). \
                         Refusing to overwrite. Pass --force to re-initialise \
                         (DESTRUCTIVE: erases ALL files, snapshots and cached chunks in the archive)."
                    );
                }
                if db.get_config("dedup_secret")?.is_some() {
                    anyhow::bail!(
                        "Archive '{db_path}' already has a dedup_secret. Refusing to overwrite. \
                         Pass --force to re-initialise \
                         (DESTRUCTIVE: erases ALL files, snapshots and cached chunks in the archive)."
                    );
                }
            }
            if *force {
                // `init --force` wipes ALL data, so on an EXISTING archive
                // it is bound by the same key-model gate as gc / snapshot rm:
                //   * append-only  → refused (history is immutable by ratchet);
                //   * asymmetric   → requires the master (private) key, proven by
                //                    deriving the recipient from --priv-key and
                //                    matching the pinned one — otherwise a
                //                    public-key-only backup host could nuke the
                //                    whole archive, defeating the ransomware
                //                    guarantee ("pub-only host cannot destroy");
                //   * symmetric    → the password already unlocked the index (its
                //                    single secret), so --force is allowed.
                let existing_pub = db.get_config("pub_key")?;
                let archive_exists = existing_pub.is_some()
                    || db.get_config("format_version")?.is_some()
                    || db.get_config("dedup_secret")?.is_some();
                if archive_exists {
                    if db.get_config("append_only")?.as_deref() == Some("true") {
                        anyhow::bail!(
                            "Archive '{db_path}' is append-only — `init --force` is refused \
                             (history is immutable by ratchet)."
                        );
                    }
                    if let Some(pinned) = &existing_pub {
                        let proves_master = args
                            .priv_key
                            .as_ref()
                            .and_then(|pk| {
                                cairn_seal::CryptoCtx::new(
                                    args.pub_key.as_deref().unwrap_or(""),
                                    Some(pk.expose_secret()),
                                    *comp_level,
                                    *comp_min_ratio,
                                    comp_algo.clone(),
                                    crypto_algo.clone(),
                                    None,
                                    false,
                                    *comp_min_size,
                                )
                                .ok()
                                .and_then(|c| c.derived_recipient())
                            })
                            .as_deref()
                            == Some(pinned.as_str());
                        if !proves_master {
                            anyhow::bail!(
                                "`init --force` on an asymmetric archive requires the master \
                                 (private) key — pass --priv-key matching the archive's recipient. \
                                 A public-key-only host cannot destroy history (same rule as gc / \
                                 snapshot rm)."
                            );
                        }
                    }
                }
                // Full reset: `--force` turns an existing archive back into an
                // empty one. Without this it only re-rolled the config and left
                // every old file visible AND readable — a mislabeled "DESTRUCTIVE"
                // no-op. Wipe all data (root inode is recreated), then drop the
                // cached chunk blobs so the reset also reclaims disk.
                db.wipe_data()?;
                if std::path::Path::new(&cache_dir_base).exists() {
                    if let Err(e) = std::fs::remove_dir_all(&cache_dir_base) {
                        tracing::warn!(
                            "init --force: could not clear cache dir {cache_dir_base:?}: {e}"
                        );
                    }
                }
            }
            use rand::RngCore;
            let mut random_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut random_bytes);
            let generated_hex = hex::encode(random_bytes);
            db.set_config("format_version", &ARCHIVE_FORMAT_VERSION.to_string())?;
            db.set_config("dedup_secret", &generated_hex)?;
            db.set_config("crypto_algo", crypto_algo)?;
            db.set_config("comp_algo", comp_algo)?;
            db.set_config("comp_level", &comp_level.to_string())?;
            db.set_config("comp_min_ratio", &comp_min_ratio.to_string())?;
            db.set_config("comp_min_size", &comp_min_size.to_string())?;
            db.set_config("index_sync_interval", &index_sync_interval.to_string())?;
            db.set_config("no_comp_ext", no_comp_ext)?;
            if let Some(val) = max_upload_speed_mb {
                db.set_config("max_upload_speed_mb", &val.to_string())?;
            }
            db.set_config("inline_max_size", &inline_max_size.to_string())?;
            // the dedup mode is part of the archive's on-disk identity —
            // mixing convergent and random chunks in one archive would poison
            // dedup accounting, so it is fixed at init (a re-init needs --force,
            // which wipes the data anyway). "enabled" means keyed content IDs
            // for lookup while each physical object still has a random DEK and
            // nonce; "random" disables every dedup lookup.
            db.set_config(
                "dedup_mode",
                if *disable_dedup { "random" } else { "enabled" },
            )?;
            // --hide-names: a fresh random keyed-hash secret, stored under the
            // SQLCipher password like dedup_secret. Its PRESENCE marks the archive
            // as name-hiding; the open path loads it into the CryptoCtx. Fixed at
            // init — there is no CLI path to add/remove it later (a re-init needs
            // --force, which wipes the data).
            if *hide_names {
                let mut name_secret = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut name_secret);
                db.set_config("name_hash_secret", &hex::encode(name_secret))?;
            }
            // This is format metadata, not a secret and not a content hash.
            // It lets an operator see exactly which equality domain the index
            // used during restore/audit; a reader must never infer it from a
            // ciphertext object ID.
            let (dedup_scope, dedup_id_scheme) = if *disable_dedup {
                ("none", "none")
            } else if shared_dedup.is_some() {
                ("pool", "blake3-keyed/pool-v1")
            } else {
                ("archive", "blake3-keyed/archive-v1")
            };
            db.set_config("dedup_scope", dedup_scope)?;
            db.set_config("dedup_id_scheme", dedup_id_scheme)?;
            // D01: persist only the derived non-secret shared identity.  The
            // domain secret itself never touches disk; a later read of these
            // keys by backup/restore is D03's job.
            if let Some(sh) = &shared_dedup {
                db.set_config("dedup_shared_domain", &sh.domain_id)?;
                db.set_config("dedup_shared_namespace", &sh.namespace)?;
                db.set_config(
                    "dedup_shared_store_dir",
                    shared_dedup_store_dir
                        .as_ref()
                        .expect("validated with shared_dedup")
                        .to_string_lossy()
                        .as_ref(),
                )?;
                if let Some(path) = &args.shared_dedup_secret_file {
                    db.set_config("dedup_shared_secret_file", &path.to_string_lossy())?;
                }
            }
            if *append_only {
                db.set_config("append_only", "true")?;
            }
            // establish the archive key material HERE, not lazily at first
            // backup. Two concurrent first-backups otherwise each generated their
            // own random KEK, last-writer-wins on the config row, and the loser's
            // chunk keys became silently unrecoverable (both processes exit 0).
            let init_dedup_secret = Some(secrecy::SecretString::from(generated_hex.clone()));
            if let Some(pub_key_path) = args.pub_key.as_deref() {
                let ctx = cairn_seal::CryptoCtx::new(
                    pub_key_path,
                    None,
                    *comp_level,
                    *comp_min_ratio,
                    comp_algo.clone(),
                    crypto_algo.clone(),
                    init_dedup_secret,
                    *disable_dedup,
                    *comp_min_size,
                )?;
                let recipient = ctx.recipient_string().ok_or_else(|| {
                    anyhow::anyhow!("internal error: asymmetric crypto context has no recipient")
                })?;
                db.set_config("pub_key", &recipient)?;
            } else if let Some(pass) = password.clone() {
                let ctx = cairn_seal::CryptoCtx::new_symmetric(
                    *comp_level,
                    *comp_min_ratio,
                    comp_algo.clone(),
                    crypto_algo.clone(),
                    init_dedup_secret,
                    *disable_dedup,
                    *comp_min_size,
                    pass,
                    None,
                )?;
                // return a clean error instead of panicking. `main` is
                // Result-returning and uses `?`/`bail!` everywhere else; a panic here
                // would abort the CLI ungracefully (exit 139, friendly message lost).
                let blob = ctx.wrapped_kek().ok_or_else(|| {
                    anyhow::anyhow!(
                        "fresh symmetric CryptoCtx did not carry a pending KEK — init aborted"
                    )
                })?;
                db.set_config("wrapped_kek", &hex::encode(blob))?;
            }
            println!("Initialized {}", args.archive);
            return Ok(());
        }
        Commands::AppendOnly => {
            if db.get_config("append_only")?.as_deref() == Some("true") {
                println!("Archive is already append-only.");
                return Ok(());
            }
            db.set_config("append_only", "true")?;
            println!(
                "Archive is now append-only: gc, snapshot rm and snapshot prune are \
                 permanently refused. There is no CLI command to undo this."
            );
            return Ok(());
        }
        Commands::Raid { cmd: raid_cmd } => {
            match raid_cmd {
                RaidCommands::Add { uri } => {
                    let id = db.insert_backend(uri)?;
                    println!("Added backend {uri} with ID {id}");
                }
                RaidCommands::Remove { id } => {
                    db.delete_backend(*id)?;
                    println!("Removed backend ID {id}");
                }
                RaidCommands::SetMode { mode } => {
                    // validate the mode string. An unknown value (a typo
                    // like "rad5") was persisted and then silently fell back to
                    // full replication at mount time — the operator thought they
                    // had parity but had mirroring.
                    const VALID_RAID: &[&str] =
                        &["none", "raid0", "raid1", "raid5", "raid6", "raid10"];
                    if !VALID_RAID.contains(&mode.as_str()) {
                        anyhow::bail!(
                            "Unknown RAID mode '{mode}'. Valid: none|raid0|raid1|raid5|raid6|raid10"
                        );
                    }
                    db.set_config("raid_mode", mode)?;
                    println!("RAID mode set to {mode}");
                }
            }
            return Ok(());
        }
        _ => {}
    }

    let crypto_algo: String = db_config(&db, "crypto_algo", "aes-256-gcm".to_string())?;
    let comp_algo: String = db_config(&db, "comp_algo", "zstd".to_string())?;
    let comp_level: i32 = db_config(&db, "comp_level", 3)?;
    let comp_min_ratio: i32 = db_config(&db, "comp_min_ratio", 5)?;
    let comp_min_size: usize = db_config(&db, "comp_min_size", 64)?;
    #[cfg_attr(not(feature = "cloud-storage"), allow(unused_variables))]
    let index_sync_interval: u64 = db_config(&db, "index_sync_interval", 300)?;
    // Append-only (ransomware hardening): chunk data and snapshot history must
    // survive a compromised host — gc / snapshot rm / snapshot prune are refused,
    // the background GC never starts. The live tree stays fully writable (history
    // lives in snapshots, like borg's append-only). Client-side enforcement only:
    // pair with bucket-level immutability (S3 Object Lock) for the server side.
    let append_only = db.get_config("append_only")?.as_deref() == Some("true");

    let no_comp_ext_str: String = db_config(
        &db,
        "no_comp_ext",
        "jpg,jpeg,png,mp4,zip,gz,zst".to_string(),
    )?;
    let no_comp_ext: Vec<String> = no_comp_ext_str
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let symmetric = args.pub_key.is_none();

    // ── Archive key-model enforcement (part 1: the mode is pinned) ─────────
    // An asymmetric archive is marked by its pinned recipient, a symmetric one
    // by its stored wrapped_kek. Without this, the mode would be whatever the
    // CLI flags say per-invocation, and anyone holding just the DB password
    // could sidestep the key-gated destructive operations by simply not
    // passing --pub-key. Checked BEFORE building the crypto context — the
    // symmetric path persists a fresh KEK, which must never happen on an
    // asymmetric archive.
    let pinned_recipient = db.get_config("pub_key")?;
    let has_kek = db.get_config("wrapped_kek")?.is_some();
    if symmetric {
        if let Some(pinned) = &pinned_recipient {
            anyhow::bail!(
                "This archive is asymmetric (recipient {pinned}).\n\
                 Pass --pub-key (and --priv-key for restore/admin operations)."
            );
        }
    } else if has_kek {
        anyhow::bail!("This archive is symmetric (password-only); do not pass --pub-key.");
    }
    let dedup_secret_val = db.get_config("dedup_secret")?.ok_or_else(|| {
        anyhow::anyhow!(
            "archive has no dedup_secret; refusing to generate a new equality domain during open"
        )
    })?;
    let dedup_secret_opt = Some(secrecy::SecretString::new(dedup_secret_val.into()));

    // The dedup mode and equality-domain contract are archive-pinned.  There
    // are no real pre-contract archives, so an absent/unknown value is
    // corruption rather than a reason to guess a weaker fallback.
    let dedup_mode = db
        .get_config("dedup_mode")?
        .ok_or_else(|| anyhow::anyhow!("archive has no dedup_mode"))?;
    let disable_dedup = dedup_mode == "random";

    // D01 persisted only the NON-secret shared identity; the domain secret
    // itself never left the init process's memory.
    let shared_domain = db.get_config("dedup_shared_domain")?;
    let shared_namespace = db.get_config("dedup_shared_namespace")?;
    let (expected_scope, expected_scheme) = dedup_contract(
        &dedup_mode,
        shared_domain.as_deref(),
        shared_namespace.as_deref(),
    )?;
    let stored_scope = db
        .get_config("dedup_scope")?
        .ok_or_else(|| anyhow::anyhow!("archive has no dedup_scope"))?;
    let stored_scheme = db
        .get_config("dedup_id_scheme")?
        .ok_or_else(|| anyhow::anyhow!("archive has no dedup_id_scheme"))?;
    if stored_scope != expected_scope || stored_scheme != expected_scheme {
        anyhow::bail!(
            "dedup contract mismatch: archive records {stored_scope}/{stored_scheme}, \
             configuration requires {expected_scope}/{expected_scheme}"
        );
    }

    // --hide-names: load the (optional) name-hashing secret. Present only in
    // archives created with `init --hide-names`; it lives under the SQLCipher
    // password like dedup_secret. When present, the CryptoCtx hashes dentry
    // lookup keys and age-encrypts the real names.
    let hide_names_secret: Option<[u8; 32]> = match db.get_config("name_hash_secret")? {
        Some(hex_str) => {
            let raw = hex::decode(&hex_str)
                .map_err(|e| anyhow::anyhow!("Corrupt name_hash_secret in config: {e}"))?;
            let arr: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("name_hash_secret must be 32 bytes"))?;
            Some(arr)
        }
        None => None,
    };
    // Enforcement mirror of the init gate: name hiding is only sound in the
    // asymmetric model. A symmetric archive that somehow carries the secret
    // (manual edit / misuse) must fail loudly, never silently store names the
    // password-holding host can read.
    if hide_names_secret.is_some() && symmetric {
        anyhow::bail!(
            "This archive has a name-hashing secret but is symmetric (password-only). \
             --hide-names is only supported for asymmetric archives; refusing to open \
             so names are not silently exposed to the password holder."
        );
    }

    let crypto = if symmetric {
        let pass = password
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Symmetric mode (pub_key is none) requires password"))?;
        // The archive KEK envelope: one scrypt unwraps it at mount; chunk keys are
        // wrapped with the KEK itself (fast). Absent on fresh (and legacy pre-KEK)
        // archives — then a new KEK is generated and MUST be persisted before any
        // write, or the written chunk keys are unrecoverable on the next mount.
        let existing_wrapped_kek = match db.get_config("wrapped_kek")? {
            Some(hex_str) => Some(
                hex::decode(&hex_str)
                    .map_err(|e| anyhow::anyhow!("Corrupt wrapped_kek in config: {e}"))?,
            ),
            None => None,
        };
        let mut ctx = cairn_seal::CryptoCtx::new_symmetric(
            comp_level,
            comp_min_ratio,
            comp_algo.clone(),
            crypto_algo.clone(),
            dedup_secret_opt.clone(),
            disable_dedup,
            comp_min_size,
            pass.clone(),
            existing_wrapped_kek,
        )?
        .with_sym_key_cache_cap(args.sym_key_cache_cap);
        if let Some(blob) = ctx.wrapped_kek() {
            // `init` now creates the KEK, but an archive
            // can still reach here KEK-less (pre-init file, manually edited
            // config). Persist atomically and converge on whichever process
            // won — plain set_config was last-writer-wins and silently
            // orphaned the losing process's chunk keys.
            let ours = hex::encode(blob);
            let stored = db.set_config_if_absent("wrapped_kek", &ours)?;
            if stored != ours {
                let winning = hex::decode(&stored)
                    .map_err(|e| anyhow::anyhow!("Corrupt wrapped_kek in config: {e}"))?;
                ctx = cairn_seal::CryptoCtx::new_symmetric(
                    comp_level,
                    comp_min_ratio,
                    comp_algo,
                    crypto_algo,
                    dedup_secret_opt.clone(),
                    disable_dedup,
                    comp_min_size,
                    pass,
                    Some(winning),
                )?
                .with_sym_key_cache_cap(args.sym_key_cache_cap);
            }
        }
        std::sync::Arc::new(ctx)
    } else {
        let mut ctx = cairn_seal::CryptoCtx::new(
            args.pub_key.as_deref().unwrap_or(""),
            args.priv_key.as_ref().map(|s| s.expose_secret()),
            comp_level,
            comp_min_ratio,
            comp_algo,
            crypto_algo,
            dedup_secret_opt.clone(),
            disable_dedup,
            comp_min_size,
        )?
        .with_sym_key_cache_cap(args.sym_key_cache_cap);
        // --hide-names: enable name hashing + write-only name encryption. The
        // secret came from the SQLCipher config above (present iff the archive
        // was created with `init --hide-names`).
        if let Some(secret) = hide_names_secret {
            ctx = ctx.with_hide_names(secret);
        }
        std::sync::Arc::new(ctx)
    };

    // ── Archive key-model enforcement (part 2: pin + prove possession) ─────
    if !symmetric {
        let current = crypto.recipient_string().ok_or_else(|| {
            anyhow::anyhow!("internal error: asymmetric crypto context has no recipient")
        })?;
        match &pinned_recipient {
            None => {
                // atomic get-or-create — if a concurrent process pinned a
                // different recipient first, refuse instead of overwriting it.
                let stored = db.set_config_if_absent("pub_key", &current)?;
                if stored != current {
                    anyhow::bail!(
                        "--pub-key does not match this archive's pinned recipient \
                         (pinned concurrently by another process).\n  \
                         archive:  {stored}\n  provided: {current}\n\
                         Refusing to mix keys."
                    );
                }
            }
            Some(pinned) if *pinned == current => {}
            Some(pinned) => anyhow::bail!(
                "--pub-key does not match this archive's pinned recipient.\n  \
                 archive:  {pinned}\n  provided: {current}\n\
                 Refusing to mix keys."
            ),
        }
    }

    // Two-key model: the public key can only ADD, the private (master) key can
    // do everything. Possession is proven by deriving the recipient from the
    // private key and matching the pinned one. Symmetric archives have a single
    // secret, so there the only ratchet is the explicit append-only flag.
    let holds_master_key = if symmetric {
        true
    } else {
        let pinned = db.get_config("pub_key")?.ok_or_else(|| {
            anyhow::anyhow!("internal error: archive public key was not pinned after init")
        })?;
        crypto.derived_recipient().as_deref() == Some(pinned.as_str())
    };
    let destroy_block: Option<&str> = if append_only {
        Some("the archive is append-only")
    } else if !holds_master_key {
        Some(
            "destructive operations on an asymmetric archive require the master \
             (private) key — pass --priv-key; a public-key-only host can only append",
        )
    } else {
        None
    };

    // ── Load backends (after crypto context so URIs can be decrypted) ─────
    #[cfg_attr(not(feature = "cloud-storage"), allow(unused_variables))]
    // a DB error here silently hides all configured cloud backends (push/raid
    // would look unconfigured). Log it rather than defaulting to empty in silence.
    let raw_backends = db.list_backends().unwrap_or_else(|e| {
        tracing::warn!("could not load cloud backends from the index: {e}");
        Vec::new()
    });

    // Decrypt backend URIs that were encrypted with the archive
    // KEK. Legacy plaintext URIs (pre-encryption) pass through transparently.
    #[cfg_attr(not(feature = "cloud-storage"), allow(unused_variables))]
    let backends: Vec<(u64, String)> = raw_backends
        .into_iter()
        .map(|(id, uri)| {
            // a decrypt failure falls back to the stored value (which may be
            // ciphertext) — log it rather than silently presenting a garbled URI.
            let decrypted = decrypt_config_value(&crypto, &uri).unwrap_or_else(|e| {
                tracing::warn!("could not decrypt backend URI (id {id}): {e} — using stored value");
                uri
            });
            (id, decrypted)
        })
        .collect();

    #[cfg_attr(not(feature = "cloud-storage"), allow(unused_variables))]
    let mut raid_mode = db
        .get_config("raid_mode")?
        .unwrap_or_else(|| "none".to_string());

    #[allow(unused_mut)]
    let mut operators: Vec<cairn_store::CloudOperator> = Vec::new();

    #[cfg(feature = "cloud-storage")]
    {
        for (_id, uri_str) in &backends {
            if let Ok(url) = url::Url::parse(uri_str) {
                if url.scheme() == "s3" {
                    let bucket = url.path().trim_start_matches('/').to_string();
                    let mut builder = opendal::services::S3::default().bucket(&bucket);

                    if let Some(host) = url.host_str() {
                        let proto = if host == "localhost" || host.starts_with("127.0.0.") {
                            "http"
                        } else {
                            "https"
                        };
                        let mut ep = format!("{proto}://{host}");
                        if let Some(port) = url.port() {
                            ep = format!("{ep}:{port}");
                        }
                        builder = builder.endpoint(&ep);
                    }

                    for (k, v) in url.query_pairs() {
                        if k == "region" {
                            builder = builder.region(&v);
                        }
                        if k == "endpoint" {
                            builder = builder.endpoint(&v);
                        }
                    }
                    if !url.username().is_empty() {
                        builder = builder.access_key_id(url.username());
                    }
                    if let Some(pass) = url.password() {
                        builder = builder.secret_access_key(pass);
                    }

                    let o = opendal::Operator::new(builder)
                        .map_err(|e| anyhow::anyhow!("Failed to init S3: {e}"))?
                        .layer(
                            opendal::layers::RetryLayer::new()
                                .with_max_times(4)
                                .with_min_delay(std::time::Duration::from_millis(500)),
                        );
                    operators.push(o);
                } else if url.scheme() == "gcs" {
                    let bucket = url.path().trim_start_matches('/').to_string();
                    let mut builder = opendal::services::Gcs::default().bucket(&bucket);

                    for (k, v) in url.query_pairs() {
                        if k == "credential_path" {
                            builder = builder.credential_path(&v);
                        }
                    }

                    let o = opendal::Operator::new(builder)
                        .map_err(|e| anyhow::anyhow!("Failed to init GCS: {e}"))?
                        .layer(
                            opendal::layers::RetryLayer::new()
                                .with_max_times(4)
                                .with_min_delay(std::time::Duration::from_millis(500)),
                        );
                    operators.push(o);
                } else if url.scheme() == "azblob" {
                    let container = url.path().trim_start_matches('/').to_string();
                    let mut builder = opendal::services::Azblob::default().container(&container);

                    if !url.username().is_empty() {
                        builder = builder.account_name(url.username());
                    }
                    if let Some(pass) = url.password() {
                        builder = builder.account_key(pass);
                    }

                    let o = opendal::Operator::new(builder)
                        .map_err(|e| anyhow::anyhow!("Failed to init Azblob: {e}"))?
                        .layer(
                            opendal::layers::RetryLayer::new()
                                .with_max_times(4)
                                .with_min_delay(std::time::Duration::from_millis(500)),
                        );
                    operators.push(o);
                } else if url.scheme() == "fs" {
                    let root = url.path().to_string();
                    let builder = opendal::services::Fs::default().root(&root);

                    let o = opendal::Operator::new(builder)
                        .map_err(|e| anyhow::anyhow!("Failed to init FS: {e}"))?
                        .layer(
                            opendal::layers::RetryLayer::new()
                                .with_max_times(4)
                                .with_min_delay(std::time::Duration::from_millis(500)),
                        );
                    operators.push(o);
                }
            }
        }
    }

    if operators.len() > 1 && raid_mode == "none" {
        raid_mode = "raid0".to_string();
    }
    if raid_mode == "raid5" && operators.len() < 2 {
        tracing::error!("raid5 requires at least 2 S3 buckets");
        anyhow::bail!("raid5 requires at least 2 S3 buckets");
    }
    // raid10 mirrors pairs of backends; an odd count leaves the
    // last backend unpaired — silently LESS redundancy than "raid10" promises. Refuse
    // it outright (like the raid5/raid6 minimums below) instead of warning-and-
    // proceeding, so a backup can never be configured with weaker redundancy than
    // the operator believes they have.
    if raid_mode == "raid10" && operators.len() % 2 != 0 {
        tracing::error!(
            "raid10 requires an even number of backends (mirror pairs); got {}",
            operators.len()
        );
        anyhow::bail!(
            "raid10 requires an even number of backends (mirror pairs); got {} — \
             add or remove one backend",
            operators.len()
        );
    }
    if raid_mode == "raid6" && operators.len() < 3 {
        tracing::error!("raid6 requires at least 3 S3 buckets");
        anyhow::bail!("raid6 requires at least 3 S3 buckets");
    }
    let op = if operators.is_empty() {
        None
    } else {
        Some(operators[0].clone())
    };

    // D03b: a shared-dedup archive must run only on backends that can
    // provide atomic conditional publication. Whether the archive is opened
    // for backup or restore, refuse loudly instead of silently degrading to
    // check-then-write races (design §6, D00 review condition 2).
    if let (Some(domain), Some(namespace)) = (&shared_domain, &shared_namespace) {
        if !cairn_store::shared_dedup::shared_dedup_supported(&operators) {
            anyhow::bail!(
                "Archive participates in shared-dedup domain `{domain}` (namespace {namespace}) \
                 but the configured backends cannot provide atomic get-or-create for shared \
                 records — refusing to run in shared mode. Use isolated archive dedup \
                 or a filesystem-only backend."
            );
        }
        tracing::info!(
            "shared-dedup: archive participates in domain `{domain}` (namespace {namespace}) — \
             cross-archive dedup active for identical content in this domain"
        );
    }

    // dedup_secret is stored as PLAINTEXT hex (inside the already-SQLCipher-
    // encrypted DB). It must NOT be KEK-encrypted at rest: the load path reads it
    // *before* the crypto context exists (chicken-and-egg — the context needs it),
    // so it cannot decrypt an ENC:v1: value, and would then hash chunks with the
    // *ciphertext string* as the secret. That made the convergent chunk hash
    // differ from run 1 (plaintext secret) to run 2+ (ciphertext string), so
    // nothing deduplicated across separate backup runs — every repeat backup
    // stored a full duplicate. Encrypting it added no security (the KEK derives
    // from the same passphrase that unlocks SQLCipher) and broke dedup. Kept
    // plaintext.

    // Migrate plaintext backend URIs to encrypted storage.
    // The backends were loaded and decrypted above; now re-encrypt any
    // that were still plaintext and persist them.
    for (id, uri) in &backends {
        if !uri.starts_with(ENC_VALUE_PREFIX) {
            match encrypt_config_value(&crypto, uri) {
                // a failed *encryption* correctly leaves the plaintext row
                // untouched (safe). But the *persist* write used to be `let _ = …`,
                // so a DB-write failure after a successful encryption silently left
                // the plaintext-shaped URI in the index. Surface that instead.
                Ok(encrypted) => {
                    if let Err(e) = db.update_backend_uri(*id, &encrypted) {
                        tracing::error!(
                            "failed to persist encrypted backend URI for id {id}: {e} — \
                             plaintext URI remains in the index"
                        );
                    }
                }
                Err(e) => tracing::warn!(
                    "failed to encrypt backend URI for id {id}: {e} — left unmigrated"
                ),
            }
        }
    }

    if matches!(&args.command, Commands::Pull) {
        #[cfg(feature = "cloud-storage")]
        {
            cairn_core::restore_index_from_cloud(
                &operators,
                &crypto,
                db_path,
                &cache_dir_base,
                &raid_mode,
            )
            .await?;
        }
        return Ok(());
    }

    if db.get_config("raid_mode")?.is_none() {
        db.set_config("raid_mode", &raid_mode)?;
    }

    // use an explicit match. The old `if let Ok(Some(..))` matched neither
    // arm on a DB read error, silently skipping the topology check AND the persist —
    // a mount with the wrong backend count would proceed unvalidated. A DB error here
    // must refuse the mount, not bypass the safety check.
    match db.get_config("num_operators") {
        Ok(Some(saved_ops)) => {
            let saved_num: usize = saved_ops.parse().unwrap_or(0);
            if saved_num != operators.len() {
                tracing::error!(
                    "Topology mismatch! Archive was created with {} S3 buckets, but you passed {}. Refusing to mount.",
                    saved_num,
                    operators.len()
                );
                anyhow::bail!(
                    "Topology mismatch: archive needs {} S3 buckets, got {}",
                    saved_num,
                    operators.len()
                );
            }
        }
        Ok(None) => {
            db.set_config("num_operators", &operators.len().to_string())?;
        }
        Err(e) => anyhow::bail!("cannot verify backend count (num_operators): {e}"),
    }

    let mut auto_heal = false;
    let mut skip_read_verify = false;
    let mut async_upload = false;
    let mut current_upload_speed = None;
    match db.get_config("max_upload_speed_mb") {
        Ok(Some(s)) => {
            if let Ok(v) = s.parse::<usize>() {
                current_upload_speed = Some(v);
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("could not read max_upload_speed_mb config: {e}"),
    }

    match &args.command {
        Commands::Scrub { auto_heal: ah, .. } => auto_heal = *ah,
        Commands::Extract {
            dangerously_skip_verify,
            ..
        }
        | Commands::Restore {
            dangerously_skip_verify,
            ..
        } => {
            if *dangerously_skip_verify {
                // flag alone is not enough — require explicit env accept.
                let accepted = std::env::var("CAIRN_I_ACCEPT_CORRUPTION")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if !accepted {
                    anyhow::bail!(
                        "--dangerously-skip-verify requires CAIRN_I_ACCEPT_CORRUPTION=1 \
                         (refusing to silently accept corrupted/tampered chunks)"
                    );
                }
                eprintln!(
                    "WARNING: --dangerously-skip-verify is enabled — BLAKE3 chunk integrity \
                     checks are DISABLED. Corrupted or tampered chunks will be accepted silently."
                );
                tracing::warn!(
                    "--dangerously-skip-verify is enabled — BLAKE3 chunk integrity checks \
                     are DISABLED. Corrupted or tampered chunks will be accepted silently."
                );
            }
            skip_read_verify = *dangerously_skip_verify
        }
        Commands::Push {
            max_upload_speed_mb,
        } => {
            async_upload = true;
            if let Some(v) = max_upload_speed_mb {
                current_upload_speed = Some(*v);
            }
        }
        Commands::Daemon {
            max_upload_speed_mb,
            ..
        }
        | Commands::Backup {
            max_upload_speed_mb,
            ..
        } => {
            async_upload = true;
            if let Some(v) = max_upload_speed_mb {
                current_upload_speed = Some(*v);
            }
        }
        _ => {}
    }

    let rate_limiter = current_upload_speed.map(|limit| {
        std::sync::Arc::new(
            leaky_bucket::RateLimiter::builder()
                .max(limit * 1024 * 1024)
                .refill(limit * 1024 * 1024)
                .interval(std::time::Duration::from_secs(1))
                .build(),
        )
    });

    let chunk_store: std::sync::Arc<dyn cairn_store::ChunkStore> = std::sync::Arc::new(
        cairn_store::CairnStore::new(cache_dir_base.clone(), operators.clone(), rate_limiter),
    );

    // Validate write buffer sizes have reasonable upper bounds.
    // Unbounded values (e.g. usize::MAX) would cause OOM.
    if args.write_buffer_inode_mb > 1024 {
        anyhow::bail!(
            "--write-buffer-inode-mb {} exceeds maximum 1024 MB",
            args.write_buffer_inode_mb
        );
    }
    if args.write_buffer_global_mb > 1024 {
        anyhow::bail!(
            "--write-buffer-global-mb {} exceeds maximum 1024 MB",
            args.write_buffer_global_mb
        );
    }

    let force_remote_read = matches!(
        &args.command,
        Commands::Verify {
            force_remote: true,
            ..
        } | Commands::Check {
            force_remote: true,
            ..
        } | Commands::Scrub {
            force_remote: true,
            ..
        }
    );
    if force_remote_read && operators.is_empty() {
        anyhow::bail!(
            "--force-remote requires at least one cloud backend (raid add …); \
             on a local-only archive the cache IS the durable store — omit the flag"
        );
    }

    let engine = cairn_core::CairnEngine {
        db: std::sync::Arc::new(db.clone()),
        cache_dir: cache_dir_base.clone(),
        crypto,
        op,
        operators,
        store: chunk_store,
        raid_mode: raid_mode.clone(),
        skip_read_verify,
        force_remote_read,
        async_upload,
        auto_heal,
        no_comp_ext,
        write_buffers: std::sync::Arc::new(dashmap::DashMap::new()),
        write_locks: dashmap::DashMap::new(),
        decrypted_chunk_cache: std::sync::Arc::new(tokio::sync::Mutex::new(lru::LruCache::new(
            CHUNK_CACHE_CAP,
        ))),
        global_write_buffer_bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        chunk_cache_bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        last_index_hash: Default::default(),
        gc_running: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        write_buffer_inode_max: args.write_buffer_inode_mb * 1024 * 1024,
        write_buffer_global_max: args.write_buffer_global_mb * 1024 * 1024,
        chunk_cache_max_bytes: args.chunk_cache_mb * 1024 * 1024,
        max_write: args.max_write_kb * 1024,
        max_file_size: args.max_file_size_gib * 1024 * 1024 * 1024,
        backup_stats: std::sync::Arc::new(cairn_core::BackupStats::new()),
    };

    #[cfg(feature = "cloud-storage")]
    if async_upload && !engine.operators.is_empty() {
        let db_clone = engine.db.clone();
        let store_clone = engine.store.clone();
        let raid_mode_clone = engine.raid_mode.clone();
        tokio::spawn(async move {
            // drive the upload loop with
            // `for_each_concurrent` so the S3 semaphore is actually used
            // for parallelism (the previous sequential `for hash in queue`
            // acquired a permit per chunk but never let two uploads run at
            // once). Also acquire `PENDING_UPLOAD_SEMAPHORE` on entry and
            // release on exit so the process-exit drain loop in `main()` (the
            // `while PENDING_UPLOAD_SEMAPHORE.available_permits() < 1024`
            // block) actually waits for in-flight uploads before deciding to
            // sync the index to cloud. The previous loop never acquired this
            // semaphore at all, so the drain was a no-op and the index was
            // shipped before uploads completed.
            use futures::StreamExt;
            loop {
                // at the start of each pass, reset the
                // sticky UPLOAD_FAILED flag. The previous behaviour kept the
                // flag set forever after the first transient failure, even
                // after a clean drain completed — `sync_index_to_cloud` was
                // permanently skipped for the rest of the process lifetime.
                cairn_cdc::UPLOAD_FAILED.store(false, std::sync::atomic::Ordering::SeqCst);
                // a DB read error must not silently stall the upload loop as
                // if the queue were empty. Log it and re-arm UPLOAD_FAILED so the drain
                // does not treat "no uploads this pass" as success; retry next pass.
                let queue = db_clone.get_upload_queue().unwrap_or_else(|e| {
                    tracing::error!("upload worker: get_upload_queue failed: {e} — will retry");
                    cairn_cdc::UPLOAD_FAILED.store(true, std::sync::atomic::Ordering::SeqCst);
                    Vec::new()
                });
                {
                    let _ = futures::stream::iter(queue)
                        .map(|hash| {
                            let store = store_clone.clone();
                            let db = db_clone.clone();
                            let raid = raid_mode_clone.clone();
                            async move {
                                let _s3_permit = cairn_cdc::S3_UPLOAD_SEMAPHORE.acquire().await;
                                let _pending_permit =
                                    cairn_cdc::PENDING_UPLOAD_SEMAPHORE.acquire().await;
                                match store.upload_chunk_from_cache(&hash, &raid).await {
                                    Ok(()) => {
                                        // log a dequeue failure (harmless re-upload
                                        // next drain, but a persistent DB error should show).
                                        if let Err(e) = db.dequeue_upload(&hash) {
                                            tracing::warn!(
                                                "upload worker: dequeue_upload({hash}) failed after a successful upload: {e}"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "S3 upload failed for {}: {:?} — kept in queue for retry",
                                            &hash,
                                            e
                                        );
                                        cairn_cdc::UPLOAD_FAILED
                                            .store(true, std::sync::atomic::Ordering::SeqCst);
                                        // do NOT dequeue on failure. The
                                        // upload_queue IS the persistent retry
                                        // list — dropping a chunk here (the old
                                        // behavior) meant a transient
                                        // network error silently orphaned the
                                        // chunk: it stayed in the local cache
                                        // but `push` (which only uploads the
                                        // queue) could never re-send it, so the
                                        // cloud backup was permanently
                                        // incomplete despite a later "successful"
                                        // push. Keeping it queued lets the next
                                        // push/daemon complete the off-site copy.
                                    }
                                }
                            }
                        })
                        .for_each_concurrent(Some(64), |fut| fut)
                        .await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    if args.cache_limit_mb > 0 && engine.operators.is_empty() {
        tracing::warn!(
            "--cache-limit-mb ignored: no cloud backends configured, so the local \
             cache IS the only copy of the data — evicting it would destroy chunks."
        );
    }
    if args.cache_limit_mb > 0 && !engine.operators.is_empty() {
        let cache_limit_bytes = args.cache_limit_mb * 1024 * 1024;
        let cache_dir_enforce = cache_dir_base.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                // Collect cache entries via spawn_blocking to avoid blocking the
                // tokio runtime with list_sync on large caches.
                let cache_dir_clone = cache_dir_enforce.clone();
                let mut entries: Vec<_> = tokio::task::spawn_blocking(move || {
                    cacache::list_sync(&cache_dir_clone)
                        .flatten()
                        .collect::<Vec<_>>()
                })
                .await
                .unwrap_or_default();
                let mut total_size: u64 = entries.iter().map(|e| e.size as u64).sum();

                if total_size > cache_limit_bytes {
                    entries.sort_by_key(|e| e.time);
                    let mut removed = 0;
                    for entry in entries {
                        if total_size <= cache_limit_bytes {
                            break;
                        }
                        // Retry cache eviction up to 3 times on transient errors
                        // (file busy, permission race) to avoid orphaned chunks.
                        let mut evicted = false;
                        for attempt in 0..3 {
                            if cacache::remove(&cache_dir_enforce, &entry.key)
                                .await
                                .is_ok()
                            {
                                total_size = total_size.saturating_sub(entry.size as u64);
                                removed += 1;
                                evicted = true;
                                break;
                            }
                            if attempt < 2 {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    100 * (attempt + 1) as u64,
                                ))
                                .await;
                            }
                        }
                        if !evicted {
                            tracing::warn!(
                                "Cache eviction failed after 3 attempts for chunk {}",
                                entry.key
                            );
                        }
                    }
                    if removed > 0 {
                        tracing::info!(
                            "Cache limit enforced: removed {} oldest chunks to stay under {} MB",
                            removed,
                            args.cache_limit_mb
                        );
                    }
                }
            }
        });
    }

    let is_long_running = matches!(
        args.command,
        Commands::Mount { .. } | Commands::Daemon { .. }
    );
    if is_long_running && destroy_block.is_some() {
        tracing::info!(
            "Background garbage collection disabled: {}.",
            destroy_block.unwrap_or_default()
        );
    }
    if is_long_running && destroy_block.is_none() {
        let gc_engine = engine.clone();
        let args_archive_clone = args.archive.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                tracing::info!("Running background garbage collection...");
                let start = Instant::now();
                match gc_engine.gc(24).await {
                    Ok((total_removed, local_orphans)) => {
                        let duration = start.elapsed().as_millis();
                        let ts = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        append_log(
                            &args_archive_clone,
                            LogEvent::GcFinished {
                                duration_ms: duration,
                                total_removed,
                                local_orphans,
                                timestamp: ts,
                            },
                        );
                    }
                    Err(e) => tracing::error!("Background GC failed: {}", e),
                }
            }
        });

        #[cfg(feature = "cloud-storage")]
        if index_sync_interval > 0 {
            let sync_engine = engine.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(index_sync_interval)).await;
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(300),
                        sync_engine.sync_index_to_cloud(),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::error!("Failed to sync index to cloud: {e}"),
                        Err(_) => tracing::error!("Index cloud sync timed out after 5 minutes"),
                    }
                }
            });
        }
    }

    // scrub that finds corruption must exit non-zero (like check/verify).
    // Deferred to after the cloud drain so `scrub --auto-heal`'s re-uploads
    // still complete before the process exits.
    let mut scrub_corrupted: usize = 0;

    match &args.command {
        Commands::Status => {
            // a DB error must not silently render every counter as 0 — log it,
            // then show 0 (this is a display path, so a hard failure is not warranted).
            let logical_bytes = db.total_logical_bytes().unwrap_or_else(|e| {
                tracing::warn!("status: total_logical_bytes failed: {e}");
                0
            });
            let inodes = db.total_inodes().unwrap_or_else(|e| {
                tracing::warn!("status: total_inodes failed: {e}");
                0
            });
            let chunks = db.total_chunks().unwrap_or_else(|e| {
                tracing::warn!("status: total_chunks failed: {e}");
                0
            });
            let physical_bytes = db.total_physical_bytes().unwrap_or_else(|e| {
                tracing::warn!("status: total_physical_bytes failed: {e}");
                0
            });

            let snapshots = db.list_snapshots().unwrap_or_default();
            let unique_chunks = db.get_all_used_chunks().unwrap_or_default().len();
            let dedup_scope = db
                .get_config("dedup_scope")
                .unwrap_or(None)
                .unwrap_or_else(|| "unknown (legacy archive)".to_string());
            let dedup_id_scheme = db
                .get_config("dedup_id_scheme")
                .unwrap_or(None)
                .unwrap_or_else(|| "unknown (legacy archive)".to_string());

            let mut cache_bytes = 0;
            let cache_path = std::path::Path::new(&cache_dir_base);
            if cache_path.exists() {
                fn dir_bytes(p: &std::path::Path) -> u64 {
                    let mut total = 0;
                    if let Ok(rd) = std::fs::read_dir(p) {
                        for e in rd.flatten() {
                            if let Ok(md) = e.metadata() {
                                if md.is_dir() {
                                    total += dir_bytes(&e.path());
                                } else {
                                    total += md.len();
                                }
                            }
                        }
                    }
                    total
                }
                cache_bytes = dir_bytes(cache_path);
            }

            #[cfg(feature = "cloud-storage")]
            let pending = db.get_upload_queue_len().unwrap_or(0);
            #[cfg(not(feature = "cloud-storage"))]
            let pending = 0;

            #[cfg(feature = "cloud-storage")]
            let inflight = cairn_cdc::S3_UPLOAD_SEMAPHORE.available_permits();
            #[cfg(not(feature = "cloud-storage"))]
            let inflight = 128;

            if args.json {
                #[derive(serde::Serialize)]
                struct StatusJson {
                    archive: String,
                    logical_bytes: u64,
                    physical_bytes: u64,
                    cache_bytes: u64,
                    inodes: u64,
                    total_chunks: u64,
                    unique_chunks: usize,
                    dedup_ratio: f64,
                    snapshots: Vec<SnapshotStat>,
                    upload_pending: u64,
                    upload_inflight: usize,
                    append_only: bool,
                    dedup_scope: String,
                    dedup_id_scheme: String,
                }
                let dedup_ratio = if physical_bytes > 0 {
                    (logical_bytes as f64) / (physical_bytes as f64)
                } else {
                    0.0
                };
                let snaps = snapshots
                    .into_iter()
                    .map(|(id, name, timestamp)| SnapshotStat {
                        id,
                        name,
                        timestamp,
                        protected: db.snapshot_control(id).map(|v| v.0).unwrap_or(false),
                        tags: db
                            .snapshot_control(id)
                            .ok()
                            .and_then(|v| serde_json::from_str(&v.1).ok())
                            .unwrap_or(serde_json::Value::Array(vec![])),
                    })
                    .collect();
                let st = StatusJson {
                    archive: args.archive.clone(),
                    logical_bytes,
                    physical_bytes,
                    cache_bytes,
                    inodes,
                    total_chunks: chunks,
                    unique_chunks,
                    dedup_ratio,
                    snapshots: snaps,
                    upload_pending: pending,
                    upload_inflight: 128 - inflight,
                    append_only,
                    dedup_scope,
                    dedup_id_scheme,
                };
                println!("{}", serde_json::to_string(&st).unwrap_or_default());
                return Ok(());
            }

            println!("Cairn filesystem status for archive: {}", args.archive);
            println!("{:=<50}", "");
            if append_only {
                println!("  Mode:                 APPEND-ONLY (gc/rm/prune refused)");
            }
            println!("--- Content & Storage ---");
            println!("  Files/Inodes:         {inodes}");
            println!("  Logical size (raw):   {logical_bytes} bytes");
            println!("  Unique data chunks:   {unique_chunks} (out of {chunks} total)");
            println!("  Physical size (dedup):{physical_bytes} bytes");
            println!("  Local cache size:     {cache_bytes} bytes");
            println!("  Dedup scope:          {dedup_scope}");
            println!("  Dedup ID scheme:      {dedup_id_scheme}");

            if physical_bytes > 0 && logical_bytes > 0 {
                println!(
                    "  Dedup/Comp ratio:     {:.2}x",
                    (logical_bytes as f64) / (physical_bytes as f64)
                );
            }

            println!("\n--- Last operations (from {}.log) ---", args.archive);
            match last_log_events(&args.archive) {
                Some(lines) if !lines.is_empty() => {
                    for line in lines {
                        println!("  {line}");
                    }
                }
                _ => println!("  (no operation log yet)"),
            }

            println!("\n--- Index durability (copy the .db — do not rebuild from chunks) ---");
            match (
                db.get_config("last_index_backup_path")?,
                db.get_config("last_index_backup_ts")?,
                db.get_config("last_backup_file_count")?,
            ) {
                (Some(path), ts, nfiles) => {
                    println!("  Last index backup:    {path}");
                    if let Some(t) = ts {
                        println!("  Last index backup ts: {t} (unix)");
                    }
                    if let Some(n) = nfiles {
                        println!("  Last backup file cnt: {n} (use verify --expect-min-files)");
                    }
                }
                _ => {
                    println!(
                        "  Last index backup:    (none yet — run `cairn <db> index-backup DIR` \
                         or `backup --index-backup DIR` / CAIRN_INDEX_BACKUP)"
                    );
                }
            }

            println!("\n--- Snapshots ---");
            println!("  Total snapshots:      {}", snapshots.len());
            for (id, name, ts) in &snapshots {
                println!("    #{id} {name} (unix={ts})");
            }

            println!("\n--- Background Operations ---");
            #[cfg(feature = "cloud-storage")]
            {
                println!("  Upload queue (WAL):   {pending} chunks pending in DB");
                println!(
                    "  Active S3 uploads:    {} / 128 concurrent limit",
                    128 - inflight
                );
            }
            println!("{:=<50}", "");
        }
        Commands::IndexBackup { dest, keep } => {
            let path =
                copy_index_backup(&db, &args.archive, dest, resolve_index_backup_keep(*keep))?;
            println!("Index backup written: {path}");
            println!(
                "Keep this file off the backup host with the same care as priv.pem — \
                 chunks without this map are not restorable."
            );
            return Ok(());
        }
        Commands::Snapshot { cmd: snap_cmd } => match snap_cmd {
            SnapshotCommands::Ls => {
                let history = db.snapshot_history()?;
                let snapshots = history.snapshots;
                if args.json {
                    let snaps: Vec<SnapshotStat> = snapshots
                        .into_iter()
                        .map(|(id, name, timestamp)| SnapshotStat {
                            id,
                            name,
                            timestamp,
                            protected: db.snapshot_control(id).map(|v| v.0).unwrap_or(false),
                            tags: db
                                .snapshot_control(id)
                                .ok()
                                .and_then(|v| serde_json::from_str(&v.1).ok())
                                .unwrap_or(serde_json::Value::Array(vec![])),
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string(&SnapshotList {
                            api_version: 1,
                            archive_id: history.archive_id,
                            history_revision: history.revision,
                            snapshots: snaps
                        })?
                    );
                } else {
                    println!("--- Snapshots ---");
                    println!("  Total snapshots:      {}", snapshots.len());
                    for (id, name, ts) in &snapshots {
                        println!("    #{id} {name} (unix={ts})");
                    }
                }
            }
            SnapshotCommands::Create { name } => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                append_log(
                    &args.archive,
                    LogEvent::BackupStarted {
                        snapshot_name: name.clone(),
                        timestamp: ts,
                    },
                );
                let start = Instant::now();
                db.create_snapshot(name)?;
                let duration = start.elapsed().as_millis();
                let ts2 = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                append_log(
                    &args.archive,
                    LogEvent::BackupFinished {
                        snapshot_name: name.clone(),
                        duration_ms: duration,
                        timestamp: ts2,
                    },
                );

                #[cfg(feature = "cloud-storage")]
                if index_sync_interval == 0 {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(300),
                        engine.sync_index_to_cloud(),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::error!("Failed to sync index to cloud: {e}"),
                        Err(_) => tracing::error!("Index cloud sync timed out after 5 minutes"),
                    }
                }
            }
            SnapshotCommands::Rm { id } => {
                if let Some(reason) = destroy_block {
                    anyhow::bail!("Refused: {reason} (snapshot rm deletes history).");
                }
                // Consistency with `rollback`: reject a non-existent id instead of
                // a silent no-op DELETE, so a typo'd id is reported rather than
                // appearing to succeed.
                let snapshots = db.list_snapshots().unwrap_or_default();
                if !snapshots.iter().any(|(sid, _, _)| sid == id) {
                    anyhow::bail!("Snapshot #{id} not found (see `snapshot ls`)");
                }
                let deleted = db.delete_snapshot(*id)?;
                debug_assert!(deleted.is_some(), "existence checked above");
            }
            SnapshotCommands::Rollback {
                id,
                i_accept_non_atomic,
            } => {
                if !i_accept_non_atomic {
                    anyhow::bail!(
                        "snapshot rollback replaces the archive DB file and has a documented \
                         non-atomic crash window (ARCHITECTURE.md). Never run on the sole copy \
                         without an offline backup of the .db. Re-run with \
                         `--i-accept-non-atomic` after copying the archive."
                    );
                }
                let snapshots = db.list_snapshots().unwrap_or_default();
                let Some((_, snap_name, _)) = snapshots.iter().find(|(sid, _, _)| sid == id) else {
                    anyhow::bail!("Snapshot #{id} not found (see `snapshot ls`)");
                };
                let snap_name = snap_name.clone();

                // Snapshot the CURRENT state first so the rollback itself is
                // non-destructive (and therefore allowed on append-only archives):
                // everything the live tree had is recoverable by rolling forward.
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let pre_name = format!("pre-rollback-{ts}");
                db.create_snapshot(&pre_name)?;
                println!("Saved current state as snapshot '{pre_name}'.");

                // Offline safety copy of the live DB *before* the file swap
                //. If the rename window is interrupted, restore from this
                // sibling file manually.
                let bak_path = format!("{}.pre-rollback.bak", args.archive);
                db.wal_checkpoint_truncate()?;
                std::fs::copy(&args.archive, &bak_path).map_err(|e| {
                    anyhow::anyhow!("failed to write pre-rollback backup {bak_path}: {e}")
                })?;
                // Best-effort fsync of the backup file (durability of the recovery path).
                if let Ok(f) = std::fs::File::open(&bak_path) {
                    let _ = f.sync_all();
                }
                println!("Wrote offline recovery copy: {bak_path}");

                // Materialize the snapshot (with the current snapshot history carried
                // over) next to the archive, then swap it in (rename is atomic on
                // the same filesystem; crash between unlink-of-old semantics and
                // fully durable new file is the residual window).
                let archive_dir = archive_parent_dir(&args.archive);
                let tmp_path = random_temp_path(&archive_dir, "rollback.tmp");
                safe_remove_for_overwrite(&tmp_path)?;
                db.restore_snapshot_to(*id, &tmp_path)?;

                // Flush our WAL so nothing checkpoints stale pages later, and drop
                // the WAL/SHM files that belong to the database being replaced.
                db.wal_checkpoint_truncate()?;
                std::fs::rename(&tmp_path, &args.archive)?;
                // fsync the directory so the rename is durable
                if let Ok(dir) = std::fs::File::open(&archive_dir) {
                    let _ = dir.sync_all();
                }
                let _ = std::fs::remove_file(format!("{}-wal", args.archive));
                let _ = std::fs::remove_file(format!("{}-shm", args.archive));

                println!("Rolled back to snapshot #{id} ({snap_name}).");
                println!(
                    "Note: chunk data is not touched — chunks written after the snapshot \
                     remain in the store until `gc`; chunks already collected by `gc` since \
                     the snapshot may be missing from rolled-back files."
                );
                println!(
                    "Recovery: if this archive looks wrong, restore from {bak_path} \
                     (copy over the .db) before running other commands."
                );
                return Ok(());
            }
            SnapshotCommands::Prune {
                keep_daily,
                keep_weekly,
                keep_monthly,
                keep_yearly,
                checkpoint,
            } => {
                if let Some(reason) = destroy_block {
                    anyhow::bail!("Refused: {reason} (snapshot prune deletes history).");
                }
                // `Some(0)` is the borg/rsnapshot "rule does
                // not apply" sentinel (the previous version treated 0 as
                // "keep zero" → silently wiped every snapshot). Coerce to
                // None here so the rest of the logic only applies rules the
                // operator actually asked for.
                let keep_daily = keep_daily.and_then(|n| if n == 0 { None } else { Some(n) });
                let keep_weekly = keep_weekly.and_then(|n| if n == 0 { None } else { Some(n) });
                let keep_monthly = keep_monthly.and_then(|n| if n == 0 { None } else { Some(n) });
                let keep_yearly = keep_yearly.and_then(|n| if n == 0 { None } else { Some(n) });
                if keep_daily.is_none()
                    && keep_weekly.is_none()
                    && keep_monthly.is_none()
                    && keep_yearly.is_none()
                {
                    println!("No pruning rules specified.");
                    return Ok(());
                }

                let snapshots = db.list_snapshots().unwrap_or_default();
                if snapshots.is_empty() {
                    return Ok(());
                }

                let mut snaps = snapshots;
                snaps.sort_by_key(|s| std::cmp::Reverse(s.2));

                let mut kept_ids = std::collections::HashSet::new();

                let mut days_seen = std::collections::HashSet::new();
                let mut weeks_seen = std::collections::HashSet::new();
                let mut months_seen = std::collections::HashSet::new();
                let mut years_seen = std::collections::HashSet::new();

                for (id, _, ts) in &snaps {
                    if let Some(dt) = chrono::DateTime::from_timestamp(*ts as i64, 0) {
                        use chrono::Datelike;
                        let day_key = dt.format("%Y-%m-%d").to_string();
                        let week_key =
                            format!("{}-W{}", dt.iso_week().year(), dt.iso_week().week());
                        let month_key = dt.format("%Y-%m").to_string();
                        let year_key = dt.format("%Y").to_string();

                        let mut keep = false;

                        if let Some(kd) = keep_daily {
                            keep |= should_keep(&mut days_seen, &day_key, kd);
                        }

                        if let Some(kw) = keep_weekly {
                            keep |= should_keep(&mut weeks_seen, &week_key, kw);
                        }

                        if let Some(km) = keep_monthly {
                            keep |= should_keep(&mut months_seen, &month_key, km);
                        }

                        if let Some(ky) = keep_yearly {
                            keep |= should_keep(&mut years_seen, &year_key, ky);
                        }

                        if keep {
                            kept_ids.insert(*id);
                        }

                        days_seen.insert(day_key);
                        weeks_seen.insert(week_key);
                        months_seen.insert(month_key);
                        years_seen.insert(year_key);
                    }
                }

                for (id, _, _) in &snaps {
                    if !kept_ids.contains(id) {
                        if let Err(e) = db.delete_snapshot(*id) {
                            tracing::error!("Failed to delete snapshot {}: {}", id, e);
                        } else {
                            println!("Deleted snapshot #{id}");
                        }
                    }
                }
                if let Some(path) = checkpoint {
                    let remaining = db.list_snapshots()?;
                    let newest = remaining
                        .iter()
                        .max_by_key(|(id, _, _)| id)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "cannot re-anchor checkpoint: prune removed every snapshot"
                            )
                        })?;
                    engine
                        .recheckpoint_after_prune(newest.0, std::path::Path::new(&path))
                        .await?;
                    println!("Re-anchored trusted checkpoint at snapshot #{}.", newest.0);
                } else {
                    println!(
                        "Checkpoint was not changed; if a deleted snapshot was checkpointed, verification will refuse until you explicitly re-anchor it."
                    );
                }
            }
            SnapshotCommands::Diff { from, to } => {
                // #4: Snapshot diff — compare two snapshots
                let snapshots = db.list_snapshots().unwrap_or_default();
                let snap_from = snapshots.iter().find(|(id, _, _)| id == from);
                let snap_to = snapshots.iter().find(|(id, _, _)| id == to);
                if snap_from.is_none() {
                    anyhow::bail!("Snapshot #{from} not found (see `snapshot ls`)");
                }
                if snap_to.is_none() {
                    anyhow::bail!("Snapshot #{to} not found (see `snapshot ls`)");
                }

                // Restore both snapshots to temp files
                let archive_dir = archive_parent_dir(&args.archive);
                let tmp_from = random_temp_path(&archive_dir, "diff_from.tmp");
                let tmp_to = random_temp_path(&archive_dir, "diff_to.tmp");
                for p in [&tmp_from, &tmp_to] {
                    safe_remove_for_overwrite(p)?;
                }
                db.restore_snapshot_to(*from, &tmp_from)?;
                db.restore_snapshot_to(*to, &tmp_to)?;

                // Open both databases and walk their trees
                let db_from = cairn_index::Db::new_with_tuning(
                    &tmp_from,
                    password.as_ref(),
                    &cairn_index::DbTuning {
                        max_connections: 2,
                        cache_size_kb: args.db_cache_kb,
                        mmap_size_kb: args.db_mmap_kb,
                        synchronous: args.db_synchronous.clone(),
                        busy_timeout_ms: args.db_busy_timeout_ms,
                        connection_timeout_secs: args.db_connection_timeout_secs,
                        kdf_iter: kdf_iter_from_env(),
                        min_idle: 0,
                    },
                )?;
                let db_to = cairn_index::Db::new_with_tuning(
                    &tmp_to,
                    password.as_ref(),
                    &cairn_index::DbTuning {
                        max_connections: 2,
                        cache_size_kb: args.db_cache_kb,
                        mmap_size_kb: args.db_mmap_kb,
                        synchronous: args.db_synchronous.clone(),
                        busy_timeout_ms: args.db_busy_timeout_ms,
                        connection_timeout_secs: args.db_connection_timeout_secs,
                        kdf_iter: kdf_iter_from_env(),
                        min_idle: 0,
                    },
                )?;

                // Build a simple engine for each to use walk_archive
                let make_engine_for_db =
                    |db: cairn_index::Db| -> std::sync::Arc<cairn_core::CairnEngine> {
                        std::sync::Arc::new(engine.new_from_db(db))
                    };

                let eng_from = make_engine_for_db(db_from);
                let eng_to = make_engine_for_db(db_to);

                let vfs_from = cairn_core::vfs::Vfs::from_engine(eng_from.clone());
                let vfs_to = cairn_core::vfs::Vfs::from_engine(eng_to.clone());

                // A file's CONTENT fingerprint, for detecting modifications
                // (this powers incremental-backup deltas). Chunk `object_id`s are
                // content hashes, so any content change changes the fingerprint —
                // and it needs NO decryption or reading of file bytes. The old
                // size-only check missed every same-size edit. Directories have no
                // content and are compared by existence only (None).
                type FileType = cairn_core::types::FileType;
                fn fingerprint(
                    vfs: &cairn_core::vfs::Vfs,
                    ino: u64,
                    kind: FileType,
                ) -> anyhow::Result<Option<[u8; 32]>> {
                    if kind == FileType::Directory {
                        return Ok(None);
                    }
                    let db = &vfs.engine().db;
                    let mut h = blake3::Hasher::new();
                    // Ordered chunks (offset, plain_len, content-addressed object_id).
                    for (object_id, offset, plain_len, ..) in db.get_file_chunks(ino)? {
                        h.update(object_id.as_bytes());
                        h.update(&(offset as u64).to_le_bytes());
                        h.update(&(plain_len as u64).to_le_bytes());
                    }
                    // Small files (and symlink targets) live inline.
                    if let Some(inline) = db.get_inline_data(ino)? {
                        h.update(&inline);
                    }
                    Ok(Some(*h.finalize().as_bytes()))
                }

                // Walk collects path → (ino, kind); the fingerprint is computed
                // lazily only for paths present in both snapshots.
                async fn walk_tree(
                    vfs: &cairn_core::vfs::Vfs,
                ) -> anyhow::Result<std::collections::HashMap<std::path::PathBuf, (u64, FileType)>>
                {
                    let mut result = std::collections::HashMap::new();
                    let mut stack = vec![(1u64, std::path::PathBuf::from("/"))];
                    while let Some((ino, path)) = stack.pop() {
                        for entry in vfs.readdir(ino).await? {
                            let child_path = path.join(&entry.name);
                            if entry.kind == FileType::Directory {
                                stack.push((entry.ino, child_path.clone()));
                            }
                            result.insert(child_path, (entry.ino, entry.kind));
                        }
                    }
                    Ok(result)
                }

                let root = std::path::PathBuf::from("/");
                let paths_from: std::collections::HashMap<_, _> = walk_tree(&vfs_from)
                    .await?
                    .into_iter()
                    .filter(|(p, _)| p != &root)
                    .collect();
                let paths_to: std::collections::HashMap<_, _> = walk_tree(&vfs_to)
                    .await?
                    .into_iter()
                    .filter(|(p, _)| p != &root)
                    .collect();

                let mut added = Vec::new();
                let mut removed = Vec::new();
                let mut modified = Vec::new();

                for (path, (ino, kind)) in &paths_to {
                    if let Some((old_ino, old_kind)) = paths_from.get(path) {
                        // Changed type, or (same non-dir type) changed content.
                        let changed = old_kind != kind
                            || fingerprint(&vfs_from, *old_ino, *old_kind)?
                                != fingerprint(&vfs_to, *ino, *kind)?;
                        if changed {
                            modified.push(path.display().to_string());
                        }
                    } else {
                        added.push(path.display().to_string());
                    }
                }
                for path in paths_from.keys() {
                    if !paths_to.contains_key(path) {
                        removed.push(path.display().to_string());
                    }
                }

                added.sort();
                removed.sort();
                modified.sort();

                println!("--- Snapshot diff: #{from} → #{to} ---");
                if added.is_empty() && removed.is_empty() && modified.is_empty() {
                    println!("No differences.");
                } else {
                    if !added.is_empty() {
                        println!("Added ({}):", added.len());
                        for p in &added {
                            println!("  + {p}");
                        }
                    }
                    if !removed.is_empty() {
                        println!("Removed ({}):", removed.len());
                        for p in &removed {
                            println!("  - {p}");
                        }
                    }
                    if !modified.is_empty() {
                        println!("Modified ({}):", modified.len());
                        for p in &modified {
                            println!("  ~ {p}");
                        }
                    }
                    println!(
                        "Summary: +{} added, -{} removed, ~{} modified",
                        added.len(),
                        removed.len(),
                        modified.len()
                    );
                }

                // Clean up temp files
                let _ = std::fs::remove_file(&tmp_from);
                let _ = std::fs::remove_file(format!("{}-wal", tmp_from));
                let _ = std::fs::remove_file(format!("{}-shm", tmp_from));
                let _ = std::fs::remove_file(&tmp_to);
                let _ = std::fs::remove_file(format!("{}-wal", tmp_to));
                let _ = std::fs::remove_file(format!("{}-shm", tmp_to));
            }
            SnapshotCommands::Export { id, dest } => {
                engine
                    .export_snapshot_bundle(*id, std::path::Path::new(dest))
                    .await?;
                println!("Exported snapshot #{id} to {dest}.");
            }
            SnapshotCommands::Import { bundle } => {
                let id = cairn_core::CairnEngine::import_snapshot_bundle(
                    std::path::Path::new(bundle),
                    std::path::Path::new(&cache_dir_base),
                )
                .await?;
                println!("Imported ciphertext objects for snapshot #{id} into the local cache.");
            }
            SnapshotCommands::DeletePlan {
                ids_file,
                allow_empty_history,
            } => {
                let ids: Vec<u64> = serde_json::from_slice(&std::fs::read(ids_file)?)?;
                let history = db.snapshot_history()?;
                let known: std::collections::HashSet<u64> =
                    history.snapshots.iter().map(|s| s.0).collect();
                if ids.iter().any(|id| !known.contains(id)) {
                    anyhow::bail!("unknown snapshot id in plan");
                }
                if ids.len() != ids.iter().collect::<std::collections::HashSet<_>>().len() {
                    anyhow::bail!("duplicate snapshot id in plan");
                }
                if !*allow_empty_history && ids.len() >= history.snapshots.len() {
                    anyhow::bail!("EMPTY_HISTORY_FORBIDDEN");
                }
                println!(
                    "{}",
                    serde_json::to_string(&SnapshotDeletePlan {
                        api_version: 1,
                        archive_id: history.archive_id,
                        history_revision: history.revision,
                        ids,
                        allow_empty_history: *allow_empty_history
                    })?
                );
            }
            SnapshotCommands::DeleteApply { plan } => {
                if let Some(reason) = destroy_block {
                    anyhow::bail!("Refused: {reason} (snapshot delete applies history deletion).");
                }
                let plan: SnapshotDeletePlan = serde_json::from_slice(&std::fs::read(plan)?)?;
                if plan.api_version != 1 {
                    anyhow::bail!("unsupported delete-plan version");
                }
                let deleted = db.apply_snapshot_delete_plan(
                    &plan.archive_id,
                    plan.history_revision,
                    &plan.ids,
                    plan.allow_empty_history,
                )?;
                println!("{}", serde_json::to_string(&deleted)?);
            }
            SnapshotCommands::Protect { id, off } => {
                db.set_snapshot_control(*id, Some(!*off), None)?;
            }
            SnapshotCommands::Tags { id, tags_json } => {
                let _: Vec<String> = serde_json::from_str(tags_json)?;
                db.set_snapshot_control(*id, None, Some(tags_json))?;
            }
        },
        Commands::Gc { grace_period_hours } => {
            if let Some(reason) = destroy_block {
                anyhow::bail!("Refused: {reason} (gc deletes chunks).");
            }
            let start = Instant::now();
            let (total_removed, local_orphans) = engine.gc(*grace_period_hours).await?;
            let duration = start.elapsed().as_millis();
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            append_log(
                &args.archive,
                LogEvent::GcFinished {
                    duration_ms: duration,
                    total_removed,
                    local_orphans,
                    timestamp: ts,
                },
            );
        }
        Commands::Scrub { .. } => {
            let start = Instant::now();
            let (verified, corrupted) = engine.scrub().await?;
            let duration = start.elapsed().as_millis();
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            append_log(
                &args.archive,
                LogEvent::ScrubFinished {
                    duration_ms: duration,
                    verified,
                    corrupted,
                    timestamp: ts,
                },
            );
            // remember corruption for a non-zero exit at the end.
            scrub_corrupted = corrupted;
        }
        Commands::Verify {
            force_remote,
            expect_min_files,
        } => {
            if *force_remote {
                println!(
                    "verify --force-remote: bypassing local cache (proves offsite, not warm cache)"
                );
            }
            let (ok, bad) = engine.verify_all().await?;
            println!("Verify: {ok} file(s) restorable, {bad} NOT restorable.");
            println!(
                "Note: verify proves restorability of *indexed* files only — not that the \
                 inventory is complete (no whole-archive signature; see THREAT_MODEL)."
            );
            if let Some(min) = expect_min_files {
                if (ok as u64) < *min {
                    anyhow::bail!(
                        "verify --expect-min-files {min}: only {ok} file(s) restorable \
                         ({bad} corrupted) — inventory may be incomplete"
                    );
                }
            }
            if bad > 0 {
                anyhow::bail!(
                    "{bad} file(s) failed verification (see the errors above) — this archive \
                     cannot fully restore"
                );
            }
        }
        Commands::Extract {
            dest_dir,
            file_path,
            glob,
            preserve,
            ..
        } => {
            let preserve = *preserve;
            // `--file-path` is literal; `--glob` is the
            // explicit escape hatch for shell patterns. The previous version
            // auto-detected `*`/`?` in `--file-path`, which silently
            // mis-routed a literal filename like `report*final.txt`.
            match (file_path, glob) {
                (Some(_), Some(_)) => {
                    anyhow::bail!("--file-path and --glob are mutually exclusive")
                }
                (Some(fp), None) => {
                    engine.extract_single_file(fp, dest_dir, preserve).await?;
                }
                (None, Some(pattern)) => {
                    engine.extract_matching(pattern, dest_dir, preserve).await?;
                }
                (None, None) => {
                    engine.extract_all(dest_dir, preserve).await?;
                }
            }
        }
        Commands::Restore {
            dest_dir,
            file_path,
            glob,
            preserve,
            to_source,
            ..
        } => {
            let preserve = *preserve;
            // #5: --to-source restores to the original source directory
            let actual_dest = if *to_source {
                match db.get_config("backup_source_path")? {
                    Some(src) => {
                        if !std::path::Path::new(&src).exists() {
                            anyhow::bail!(
                                "Original source path '{}' does not exist. \
                                 Pass a destination directory instead.",
                                src
                            );
                        }
                        println!("Restoring to original source: {}", src);
                        src
                    }
                    None => {
                        anyhow::bail!(
                            "No source path stored in archive. \
                             Run `cairn backup` with source path to enable --to-source."
                        );
                    }
                }
            } else {
                dest_dir.clone()
            };
            match (file_path, glob) {
                (Some(_), Some(_)) => {
                    anyhow::bail!("--file-path and --glob are mutually exclusive")
                }
                (Some(fp), None) => {
                    engine
                        .extract_single_file(fp, &actual_dest, preserve)
                        .await?;
                }
                (None, Some(pattern)) => {
                    engine
                        .extract_matching(pattern, &actual_dest, preserve)
                        .await?;
                }
                (None, None) => {
                    engine.extract_all(&actual_dest, preserve).await?;
                }
            }
        }
        Commands::Check {
            force_remote,
            expect_min_files,
        } => {
            // README: check and verify are synonyms (same restorability check).
            if *force_remote {
                println!(
                    "check --force-remote: bypassing local cache (proves offsite, not warm cache)"
                );
            }
            let start = Instant::now();
            let (ok, bad) = engine.verify_all().await?;
            let duration = start.elapsed();
            println!(
                "Check completed in {:.1}s: {ok} file(s) restorable, {bad} NOT restorable.",
                duration.as_secs_f64()
            );
            if let Some(min) = expect_min_files {
                if (ok as u64) < *min {
                    anyhow::bail!(
                        "check --expect-min-files {min}: only {ok} file(s) restorable \
                         ({bad} corrupted) — inventory may be incomplete"
                    );
                }
            }
            if bad > 0 {
                anyhow::bail!("{bad} file(s) failed integrity check — archive may be corrupted");
            }
        }
        Commands::Mount {
            mountpoint,
            read_only,
            allow_other,
            snapshot: snap_id,
        } => {
            // #3: Mount specific snapshot — restore snapshot to temp file and mount that
            let archive_dir = archive_parent_dir(&args.archive);
            // Use tempfile for auto-cleanup on normal exit and panics.
            // On SIGKILL the file remains but is uniquely named and harmless.
            let mut snap_tmp_file: Option<tempfile::TempPath> = None;
            let mount_engine = if let Some(snap) = snap_id {
                let tmp_file = tempfile::Builder::new()
                    .prefix("snap-")
                    .suffix(".tmp")
                    .tempfile_in(&archive_dir)?;
                let tmp_path = tmp_file.path().to_path_buf();
                db.restore_snapshot_to(*snap, tmp_path.to_string_lossy().as_ref())?;
                println!("Restored snapshot #{snap} to temp file for mounting.");

                let snap_db = cairn_index::Db::new_with_tuning(
                    &tmp_path.to_string_lossy(),
                    password.as_ref(),
                    &cairn_index::DbTuning {
                        max_connections: args.db_pool_size.max(1),
                        cache_size_kb: args.db_cache_kb,
                        mmap_size_kb: args.db_mmap_kb,
                        synchronous: args.db_synchronous.clone(),
                        busy_timeout_ms: args.db_busy_timeout_ms,
                        connection_timeout_secs: args.db_connection_timeout_secs,
                        kdf_iter: kdf_iter_from_env(),
                        min_idle: 0,
                    },
                )?;
                snap_tmp_file = Some(tmp_file.into_temp_path());
                std::sync::Arc::new(engine.new_from_db(snap_db))
            } else {
                std::sync::Arc::new(engine.clone())
            };

            #[cfg(target_os = "linux")]
            {
                if !std::path::Path::new(mountpoint).exists() {
                    let _ = std::fs::create_dir_all(mountpoint);
                }

                let mut mount_options = fuse3::MountOptions::default();
                mount_options.fs_name("cairn");
                if *allow_other {
                    // Check that /etc/fuse.conf has user_allow_other enabled;
                    // without it, the kernel rejects allow_other and mount fails
                    // with a confusing "Operation not permitted" error.
                    let fuse_conf_ok = std::fs::read_to_string("/etc/fuse.conf")
                        .map(|c| {
                            c.lines()
                                .any(|l| l.trim_start().starts_with("user_allow_other"))
                        })
                        .unwrap_or(false);
                    if !fuse_conf_ok {
                        anyhow::bail!(
                            "--allow-other requires 'user_allow_other' in /etc/fuse.conf \
                             (add the line, or run without --allow-other)"
                        );
                    }
                    mount_options.allow_other(true);
                }
                mount_options.default_permissions(true);
                if *read_only {
                    mount_options.read_only(true);
                }

                tracing::info!("Mounting FUSE filesystem at {}...", mountpoint);
                let session = fuse3::raw::Session::new(mount_options);
                let fs = cairn_fuse::CairnFs((*mount_engine).clone());
                let mut mount_handle = session.mount_with_unprivileged(fs, mountpoint).await?;

                // Graceful shutdown: unmount on SIGTERM/SIGINT so chunk
                // write-buffers flush cleanly instead of being killed mid-write.
                // Uses fuse3's native unmount instead of shelling out to fusermount,
                // so it works even if fusermount is not installed.
                let signal_fut = async {
                    let _ = tokio::signal::ctrl_c().await;
                    tracing::info!("Received signal, unmounting...");
                };
                tokio::pin!(signal_fut);

                tokio::select! {
                    result = &mut mount_handle => {
                        match result {
                            Ok(()) => tracing::info!("FUSE unmounted."),
                            Err(e) => tracing::error!("FUSE session ended with error: {e}"),
                        }
                    }
                    _ = &mut signal_fut => {
                        tracing::info!("Unmounting FUSE filesystem...");
                        if let Err(e) = mount_handle.unmount().await {
                            tracing::error!("Failed to unmount: {e}");
                        } else {
                            tracing::info!("FUSE unmounted.");
                        }
                    }
                }
            }

            // Clean up snapshot temp file if we created one.
            // TempPath auto-deletes the main file on drop, but -wal/-shm
            // sidecars must be removed manually.
            if let Some(tmp_path) = snap_tmp_file {
                let path_buf = tmp_path.to_path_buf();
                drop(tmp_path); // auto-deletes the main .tmp file
                let _ = std::fs::remove_file(format!("{}-wal", path_buf.display()));
                let _ = std::fs::remove_file(format!("{}-shm", path_buf.display()));
            }
        }
        Commands::Daemon { action, .. } => {
            if action == "start" {
                tracing::info!("cairn daemon is running in background. Press Ctrl+C to exit.");
                let _ = tokio::signal::ctrl_c().await;
            } else {
                // unknown action should be reported, not silently ignored.
                eprintln!("Unknown daemon action '{action}'. Use 'start' to run cairn daemon.");
                anyhow::bail!("Unknown daemon action '{action}'");
            }
        }
        Commands::Backup {
            source,
            dest,
            exclude,
            inline_max_size,
            incremental,
            dry_run,
            estimate,
            strict,
            index_backup,
            index_backup_keep,
            auto_snapshot,
            max_upload_speed_mb: _,
        } => {
            let start = std::time::Instant::now();
            warn_if_low_disk(&cache_dir_base);
            tracing::info!("Starting direct backup of {} to {}", source, dest);
            let mut path_to_ino: std::collections::HashMap<std::path::PathBuf, u64> =
                std::collections::HashMap::new();
            // Hardlink preservation: maps a source (dev, inode) to the archive
            // inode it was first stored under, so additional names for the same
            // physical file are linked instead of re-stored (previously each name
            // became a separate file — content duplicated, the link relationship
            // lost). Falls back to a normal copy if linking fails.
            let mut hardlink_map: std::collections::HashMap<(u64, u64), u64> =
                std::collections::HashMap::new();
            // refuse the backup rather than silently dropping
            // an invalid `--exclude` glob. The previous version's `.ok()` made
            // `cairn backup --exclude '/data/[*.tmp' src` include files the
            // operator thought they had excluded. Fail loud — the user can
            // fix the pattern and retry.
            let mut exclude_patterns: Vec<glob::Pattern> = Vec::with_capacity(exclude.len());
            for p in exclude {
                match glob::Pattern::new(p) {
                    Ok(pat) => exclude_patterns.push(pat),
                    Err(e) => anyhow::bail!("--exclude: invalid glob pattern {p:?}: {e}"),
                }
            }

            let req = cairn_core::types::Request::default();
            let mut current_ino = 1u64;

            if dest != "/" {
                let parts: Vec<&str> = dest.split('/').filter(|s| !s.is_empty()).collect();
                for part in parts {
                    let os_part = std::ffi::OsStr::new(part);
                    match engine.lookup(req.clone(), current_ino, os_part).await {
                        Ok(entry) => {
                            current_ino = entry.attr.ino;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            let entry = engine
                                .mkdir(req.clone(), current_ino, os_part, 0o755, 0)
                                .await?;
                            current_ino = entry.attr.ino;
                        }
                        Err(e) => anyhow::bail!("Failed to lookup/mkdir dest: {e}"),
                    }
                }
            }

            let source_path = std::path::Path::new(source).canonicalize()?;
            // A SOURCE that is a single file (not a directory) was silently backed
            // up as NOTHING: WalkDir::min_depth(1) yields zero entries for a file
            // (the file sits at depth 0), so the loop processed 0 files and exited
            // 0 — no error, no data. Support a file source like restic/borg: walk
            // from depth 0 and map the file's PARENT to the DEST inode, so the file
            // lands at DEST/<basename>.
            let source_is_file = source_path.is_file();
            let walk_min_depth = if source_is_file { 0 } else { 1 };
            if source_is_file {
                if let Some(p) = source_path.parent() {
                    path_to_ino.insert(p.to_path_buf(), current_ino);
                }
            } else {
                path_to_ino.insert(source_path.clone(), current_ino);
            }

            let ignore_db_str = match std::path::Path::new(&args.archive).canonicalize() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(e) => {
                    tracing::warn!(
                        "backup: cannot canonicalize archive path {:?}: {}. \
                         The archive will NOT be excluded from backup.",
                        args.archive,
                        e
                    );
                    String::new()
                }
            };
            let ignore_cache = match std::path::Path::new(&engine.cache_dir).canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        "backup: cannot canonicalize cache dir {:?}: {}",
                        engine.cache_dir,
                        e
                    );
                    std::path::PathBuf::new()
                }
            };

            // First pass: collect all entries for progress bar and estimate
            let mut entries: Vec<_> = Vec::new();
            let mut total_source_bytes: u64 = 0;
            let mut file_count: u64 = 0;
            for entry in walkdir::WalkDir::new(&source_path)
                .min_depth(walk_min_depth)
                .follow_links(false)
            {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::error!("Failed to read entry: {}", e);
                        continue;
                    }
                };
                let path = entry.path();
                let path_str = path.to_string_lossy();
                if exclude_patterns.iter().any(|p| p.matches(&path_str)) {
                    continue;
                }
                if (!ignore_db_str.is_empty()
                    && (path_str == ignore_db_str
                        || path_str.starts_with(&format!("{ignore_db_str}/"))))
                    || (ignore_cache.components().count() > 0 && path.starts_with(&ignore_cache))
                {
                    continue;
                }
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        total_source_bytes += meta.len();
                        file_count += 1;
                    }
                }
                entries.push(entry);
            }

            // #2: Estimate mode — print size estimate and exit
            if *estimate {
                println!(
                    "Estimated backup: {} files, {} total",
                    file_count,
                    cairn_core::human_bytes(total_source_bytes as usize)
                );
                return Ok(());
            }

            // Dry-run: print what would be backed up
            if *dry_run {
                println!("--- Dry run: {} files would be backed up ---", file_count);
                for entry in &entries {
                    let path = entry.path();
                    if let Ok(meta) = entry.metadata() {
                        if meta.is_file() {
                            println!(
                                "  {} ({})",
                                path.display(),
                                cairn_core::human_bytes(meta.len() as usize)
                            );
                        }
                    }
                }
                println!(
                    "Total: {} files, {}",
                    file_count,
                    cairn_core::human_bytes(total_source_bytes as usize)
                );
                return Ok(());
            }

            // #6: Progress bar
            let progress = indicatif::ProgressBar::new(file_count);
            progress.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                    .expect("valid indicatif template")
                    .progress_chars("=>-"),
            );

            // Snapshot backup stats before starting
            let stats_before = engine.backup_stats.snapshot();

            // emit the operational events OPERATING §7 tells operators to
            // watch in `<archive>.db.log`. Previously `backup` wrote nothing, so
            // the documented `BackupFinished` health signal never fired (and
            // `status`'s "Last operations" stayed empty).
            append_log(
                &args.archive,
                LogEvent::BackupStarted {
                    snapshot_name: dest.clone(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                },
            );

            // Store source path for --to-source restore
            // log a persist failure — otherwise `restore --to-source` silently
            // has no source path recorded for this archive.
            if let Err(e) = db.set_config("backup_source_path", source) {
                tracing::error!(
                    "backup: failed to persist backup_source_path: {e} — \
                     `restore --to-source` will not work for this archive"
                );
            }

            let mut backup_failures = 0u64;
            let mut specials_skipped = 0u64;
            for entry in &entries {
                let path = entry.path();

                let path_str = path.to_string_lossy();
                if exclude_patterns.iter().any(|p| p.matches(&path_str)) {
                    tracing::info!("Skipping excluded path: {:?}", path);
                    progress.inc(1);
                    continue;
                }

                if (!ignore_db_str.is_empty()
                    && (path_str == ignore_db_str
                        || path_str.starts_with(&format!("{ignore_db_str}/"))))
                    || (ignore_cache.components().count() > 0 && path.starts_with(&ignore_cache))
                {
                    tracing::info!("Skipping backup archive/cache path: {:?}", path);
                    progress.inc(1);
                    continue;
                }

                let Some(parent) = path.parent() else {
                    progress.inc(1);
                    continue;
                };
                let parent_ino = match path_to_ino.get(parent) {
                    Some(ino) => *ino,
                    None => {
                        progress.inc(1);
                        continue;
                    }
                };

                let file_name = entry.file_name();
                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    // a file we cannot stat is a file we cannot back up — log it
                    // and count it so the operator sees a non-zero exit, instead of a
                    // silent gap in the archive.
                    Err(e) => {
                        tracing::warn!(
                            "backup: cannot read metadata for {:?}: {e} — skipping (NOT backed up)",
                            entry.path()
                        );
                        backup_failures += 1;
                        progress.inc(1);
                        continue;
                    }
                };

                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();

                if metadata.is_dir() {
                    let inode = match engine.lookup(req.clone(), parent_ino, file_name).await {
                        Ok(ent) => ent.attr.ino,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            match engine
                                .mkdir(req.clone(), parent_ino, file_name, mode, 0)
                                .await
                            {
                                Ok(ent) => ent.attr.ino,
                                Err(e) => {
                                    tracing::warn!("Failed to mkdir {:?}: {}", path, e);
                                    progress.inc(1);
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Error accessing dir {:?}: {}", path, e);
                            progress.inc(1);
                            continue;
                        }
                    };
                    path_to_ino.insert(path.to_path_buf(), inode);
                    capture_xattrs(&engine.db, inode, path);
                    progress.inc(1);
                } else if metadata.is_file() {
                    use std::os::unix::fs::MetadataExt;
                    // Hardlink preservation: a file with >1 link that we already
                    // stored under another name is the SAME physical inode — link
                    // the new name to the existing archive inode instead of storing
                    // its content again.
                    let hl_key = (metadata.dev(), metadata.ino());
                    if metadata.nlink() > 1 {
                        if let Some(&existing) = hardlink_map.get(&hl_key) {
                            match engine
                                .link(req.clone(), existing, parent_ino, file_name)
                                .await
                            {
                                Ok(_) => {
                                    progress.inc(1);
                                    continue;
                                }
                                Err(e) => {
                                    // Fall through and store a normal copy — never
                                    // drop the file just because linking failed.
                                    tracing::warn!(
                                        "backup: hardlink {:?} failed, storing as copy: {}",
                                        path,
                                        e
                                    );
                                }
                            }
                        }
                    }
                    // BUG-FIX: Reuse existing inode instead of unlink+create.
                    // The old unlink-then-create pattern destroyed the original
                    // data BEFORE the new write succeeded — if the write failed
                    // (e.g. read-only cache), the file was silently lost.
                    // Reusing the inode keeps old chunks intact until the new
                    // data is fully flushed.
                    let inode = match engine.lookup(req.clone(), parent_ino, file_name).await {
                        Ok(ent) => ent.attr.ino,
                        Err(_) => match engine
                            .mknod(req.clone(), parent_ino, file_name, mode, 0)
                            .await
                        {
                            Ok(ent) => ent.attr.ino,
                            Err(e) => {
                                tracing::warn!("Error creating file {:?}: {}", path, e);
                                progress.inc(1);
                                continue;
                            }
                        },
                    };

                    // Remember this archive inode as the target for any later
                    // hardlink to the same source (dev, inode).
                    if metadata.nlink() > 1 {
                        hardlink_map.entry(hl_key).or_insert(inode);
                    }

                    // #1: Incremental backup — skip unchanged files (size + mtime
                    // fast-path, then blake3 content fingerprint to catch same-size
                    // edits that mtime cannot detect).
                    if *incremental {
                        if let Ok(Some(inode_info)) = {
                            let db = engine.db.clone();
                            let ino = inode;
                            tokio::task::spawn_blocking(move || db.get_inode(ino))
                                .await
                                .unwrap_or(Ok(None))
                        } {
                            // InodeInfo: (mode, uid, gid, size, nlink, mtime_sec, mtime_nsec)
                            let archived_size = inode_info.3;
                            let archived_mtime_sec = inode_info.5;
                            let archived_mtime_nsec = inode_info.6;
                            let source_size = metadata.len();
                            let source_mtime = metadata
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| (d.as_secs(), d.subsec_nanos()))
                                .unwrap_or((0, 0));
                            if archived_size == source_size
                                && archived_mtime_sec
                                    == i64::try_from(source_mtime.0).unwrap_or(i64::MAX)
                                && archived_mtime_nsec == source_mtime.1
                            {
                                // Fast-path passed. Now verify content hasn't
                                // changed (same-size edit). Compute a blake3
                                // fingerprint over the archived chunks and compare
                                // with the source file's content hash.
                                let skip = {
                                    let db = engine.db.clone();
                                    let crypto = engine.crypto.clone();
                                    let src = path.to_path_buf();
                                    let ino = inode;
                                    tokio::task::spawn_blocking(move || {
                                        // Archived fingerprint: hash chunk object_ids.
                                        let chunks = db.get_file_chunks(ino)?;
                                        let inline = db.get_inline_data(ino)?;
                                        let archived_fp = {
                                            let mut h = blake3::Hasher::new();
                                            for (object_id, offset, plain_len, ..) in &chunks {
                                                h.update(object_id.as_bytes());
                                                h.update(&(*offset as u64).to_le_bytes());
                                                h.update(&(*plain_len as u64).to_le_bytes());
                                            }
                                            if let Some(ref data) = inline {
                                                // inline_data is envelope-encrypted
                                                // at rest; hash the PLAINTEXT so it
                                                // matches the source file's hash. On a
                                                // write-only host (no private key)
                                                // decrypt fails → propagates as "not
                                                // skipped" (the file is re-backed-up).
                                                let plain = crypto.decrypt_blob(data)?;
                                                h.update(&plain);
                                            }
                                            *h.finalize().as_bytes()
                                        };
                                        // Source fingerprint: hash the file bytes.
                                        let source_fp = {
                                            let bytes = std::fs::read(&src)?;
                                            let mut h = blake3::Hasher::new();
                                            h.update(&bytes);
                                            *h.finalize().as_bytes()
                                        };
                                        Ok::<_, anyhow::Error>(archived_fp == source_fp)
                                    })
                                    .await
                                    .unwrap_or(Ok(false))
                                    .unwrap_or(false)
                                };
                                if skip {
                                    engine
                                        .backup_stats
                                        .files_skipped
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    progress.inc(1);
                                    continue;
                                }
                            }
                        }
                    }

                    engine
                        .backup_stats
                        .files_processed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let current_inline_max_size = match inline_max_size {
                        Some(val) => {
                            if *val > MAX_INLINE_FILE_SIZE {
                                tracing::warn!(
                                    "backup: --inline-max-size {} exceeds cap {}; capping",
                                    val,
                                    MAX_INLINE_FILE_SIZE
                                );
                                MAX_INLINE_FILE_SIZE
                            } else {
                                *val
                            }
                        }
                        None => engine
                            .db
                            .get_config("inline_max_size")
                            .unwrap_or(None)
                            .unwrap_or_else(|| "4096".to_string())
                            .parse::<usize>()
                            .unwrap_or(4096),
                    };

                    if metadata.len() <= current_inline_max_size as u64 {
                        match tokio::fs::read(path).await {
                            Ok(data) => {
                                // Envelope-wrap before storing: inline data must not
                                // sit as plaintext in the DB (write-only property).
                                let recorded = engine
                                    .wrap_inline(&data)
                                    .and_then(|wrapped| {
                                        engine
                                            .db
                                            .set_inline_data(inode, &wrapped)
                                            .map_err(anyhow::Error::from)
                                    })
                                    .and_then(|()| {
                                        engine
                                            .db
                                            .clear_file_chunks(inode)
                                            .map_err(anyhow::Error::from)
                                    })
                                    .and_then(|()| {
                                        engine.db.update_inode_size(inode, data.len() as u64)
                                    });
                                if let Err(e) = recorded {
                                    tracing::error!(
                                        "backup: failed to record inline file {:?}: {} — NOT backed up",
                                        path,
                                        e
                                    );
                                    backup_failures += 1;
                                    progress.inc(1);
                                    continue;
                                }
                                tracing::debug!("Backed up file {:?} inline", path);
                            }
                            Err(e) => {
                                tracing::error!("backup: failed to read {:?}: {}", path, e);
                                backup_failures += 1;
                                progress.inc(1);
                                continue;
                            }
                        }
                    } else {
                        // when file cannot be opened (permissions, race
                        // deletion, NFS stale handle), log and count the failure
                        // instead of silently skipping it with exit 0.
                        match tokio::fs::File::open(path).await {
                            Err(e) => {
                                tracing::error!(
                                    "backup: failed to open {:?}: {} — NOT backed up",
                                    path,
                                    e
                                );
                                backup_failures += 1;
                                progress.inc(1);
                                continue;
                            }
                            Ok(mut f) => {
                                // mark the file in progress BEFORE writing any
                                // data, so a kill mid-file leaves a durable marker
                                // that `verify` treats as NOT restorable (the file's
                                // committed size would otherwise look self-consistent
                                // and pass). Cleared only after a full flush+finalize.
                                // if the marker can't be written, the safety
                                // net is gone for this file — skip it and count a
                                // failure (loud) rather than back it up unprotected.
                                if let Err(e) = engine.db.mark_file_incomplete(inode) {
                                    tracing::error!(
                                        "backup: could not mark {:?} in progress: {e} — skipping (NOT backed up)",
                                        path
                                    );
                                    backup_failures += 1;
                                    progress.inc(1);
                                    continue;
                                }
                                let mut buf = vec![0u8; 1024 * 1024];
                                let mut offset = 0;
                                let mut write_failed = false;
                                use tokio::io::AsyncReadExt;
                                loop {
                                    let n = match f.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(n) => n,
                                        Err(e) => {
                                            tracing::error!(
                                                "Failed to read local file {:?}: {}",
                                                path,
                                                e
                                            );
                                            write_failed = true;
                                            break;
                                        }
                                    };
                                    if let Err(e) = engine
                                        .write(req.clone(), inode, 0, offset, &buf[..n], 0, 0)
                                        .await
                                    {
                                        tracing::error!(
                                            "Failed to write to engine for {:?}: {}",
                                            path,
                                            e
                                        );
                                        write_failed = true;
                                        break;
                                    }
                                    offset += n as u64;
                                }
                                if let Err(e) = engine.fsync(req.clone(), inode, 0, false).await {
                                    tracing::error!("backup: flush failed for {:?}: {}", path, e);
                                    write_failed = true;
                                }
                                if write_failed {
                                    tracing::error!("backup: {:?} was NOT fully backed up", path);
                                    backup_failures += 1;
                                    progress.inc(1);
                                    continue;
                                }
                                if let Err(e) = engine.db.truncate_inode(inode, offset) {
                                    tracing::error!(
                                        "backup: failed to finalize (truncate) {:?}: {} — NOT fully backed up",
                                        path,
                                        e
                                    );
                                    backup_failures += 1;
                                    progress.inc(1);
                                    continue;
                                }
                                // file is fully written + finalized — clear the marker.
                                if let Err(e) = engine.db.clear_file_incomplete(inode) {
                                    tracing::warn!(
                                        "backup: could not clear in-progress mark for {:?}: {e}",
                                        path
                                    );
                                }
                                tracing::debug!("Backed up file {:?}", path);
                            }
                        }
                    }
                    // Record the SOURCE file's mtime. Writes stamp "now", but a
                    // backup must keep the real timestamp so `extract --preserve`
                    // restores it AND the next `--incremental` run's size+mtime
                    // check matches an unchanged file (otherwise it never skips).
                    if let Ok(mt) = metadata.modified() {
                        if let Ok(d) = mt.duration_since(std::time::UNIX_EPOCH) {
                            // log an mtime-record failure — otherwise the next
                            // `--incremental` run re-backs-up this unchanged file.
                            if let Err(e) = engine.db.set_inode_mtime(
                                inode,
                                i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                                d.subsec_nanos(),
                            ) {
                                tracing::warn!(
                                    "backup: failed to record mtime for inode {inode}: {e}"
                                );
                            }
                        }
                    }
                    capture_xattrs(&engine.db, inode, path);
                    progress.inc(1);
                } else if metadata.file_type().is_symlink() {
                    // Symlinks were silently dropped: the loop only handled is_dir
                    // and is_file, and a symlink is neither. Store it with its
                    // target so extract restores it as a symlink.
                    match std::fs::read_link(path) {
                        Ok(target) => {
                            match engine
                                .symlink(req.clone(), parent_ino, file_name, target.as_os_str())
                                .await
                            {
                                Ok(ent) => {
                                    // Record the symlink's OWN mtime (lstat, since
                                    // follow_links=false), matching the regular-file
                                    // path so `extract --preserve` restores it.
                                    if let Ok(mt) = metadata.modified() {
                                        if let Ok(d) = mt.duration_since(std::time::UNIX_EPOCH) {
                                            // log an mtime-record failure (see the
                                            // regular-file path above).
                                            if let Err(e) = engine.db.set_inode_mtime(
                                                ent.attr.ino,
                                                i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                                                d.subsec_nanos(),
                                            ) {
                                                tracing::warn!(
                                                    "backup: failed to record symlink mtime for inode {}: {e}",
                                                    ent.attr.ino
                                                );
                                            }
                                        }
                                    }
                                    capture_xattrs(&engine.db, ent.attr.ino, path);
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "backup: failed to store symlink {:?}: {}",
                                        path,
                                        e
                                    );
                                    backup_failures += 1;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("backup: failed to read symlink {:?}: {}", path, e);
                            backup_failures += 1;
                        }
                    }
                    progress.inc(1);
                } else {
                    // FIFO / socket / device / other specials: no payload data.
                    // OPERATING §9: skipped by design. Was silent — now loud.
                    #[cfg(unix)]
                    use std::os::unix::fs::FileTypeExt;
                    let ft = metadata.file_type();
                    let kind = {
                        #[cfg(unix)]
                        {
                            if ft.is_fifo() {
                                "fifo"
                            } else if ft.is_socket() {
                                "socket"
                            } else if ft.is_block_device() {
                                "block-device"
                            } else if ft.is_char_device() {
                                "char-device"
                            } else {
                                "special"
                            }
                        }
                        #[cfg(not(unix))]
                        {
                            let _ = ft;
                            "special"
                        }
                    };
                    tracing::warn!(
                        "backup: skipping {kind} {:?} (not recreated on restore; use --strict to fail)",
                        path
                    );
                    eprintln!(
                        "WARNING: skipped {kind} {} (not stored; recreate out-of-band on restore)",
                        path.display()
                    );
                    specials_skipped += 1;
                    progress.inc(1);
                }
            }
            progress.finish_and_clear();

            // #8/#9: Print per-backup stats
            let stats_after = engine.backup_stats.snapshot();
            let delta = stats_after.delta(&stats_before);
            tracing::info!("Backup completed in {:?}", start.elapsed());
            println!("Backup stats: {}", delta);
            if specials_skipped > 0 {
                println!(
                    "Skipped {specials_skipped} special file(s) (FIFO/socket/device) — \
                     not restorable as nodes (OPERATING §9)."
                );
            }
            // Ops completeness signal: persist file count so operators / verify
            // --expect-min-files can cross-check (not a cryptographic inventory).
            let file_count_after = match engine.db.list_regular_files() {
                Ok(v) => Some(v.len()),
                Err(e) => {
                    tracing::warn!("could not read regular-file count for ops-completeness: {e}");
                    None
                }
            };
            if let Some(n) = file_count_after {
                let _ = db.set_config("last_backup_file_count", &n.to_string());
                println!("Indexed regular files after backup: {n}");
                println!(
                    "Hint: verify --expect-min-files {n}  # ops completeness (not a crypto MAC)"
                );
            }

            // BackupFinished always fires (the exit code, below, carries
            // success/failure) so monitoring can confirm a backup ran and when.
            append_log(
                &args.archive,
                LogEvent::BackupFinished {
                    snapshot_name: dest.clone(),
                    duration_ms: start.elapsed().as_millis(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                },
            );

            #[cfg(feature = "cloud-storage")]
            {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(300),
                    engine.sync_index_to_cloud(),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::error!("Failed to sync index to cloud: {e}"),
                    Err(_) => tracing::error!("Index cloud sync timed out after 5 minutes"),
                }
            }

            if backup_failures > 0 {
                anyhow::bail!(
                    "backup finished with {backup_failures} file(s) NOT backed up \
                     (see the errors above); the archive is intact but incomplete"
                );
            }
            if *strict && specials_skipped > 0 {
                anyhow::bail!(
                    "backup --strict: {specials_skipped} special file(s) were skipped \
                     (FIFO/socket/device). Recreate them out-of-band or omit --strict."
                );
            }

            // Point-in-time index state (ops completeness / roll-forward), optional.
            if *auto_snapshot {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let name = format!("post-backup-{ts}");
                db.create_snapshot(&name)?;
                println!("Auto-snapshot created: {name}");
            }

            // Index durability: copy the .db (map SPOF). Fail loud if requested
            // and the copy fails — a backup without an index copy is incomplete ops.
            if let Some(dest_ib) = resolve_index_backup_dest(index_backup.as_deref()) {
                match copy_index_backup(
                    &db,
                    &args.archive,
                    &dest_ib,
                    resolve_index_backup_keep(*index_backup_keep),
                ) {
                    Ok(path) => {
                        println!("Index backup written: {path}");
                    }
                    Err(e) => {
                        anyhow::bail!(
                            "backup data is stored, but index backup failed: {e}. \
                             Re-run: cairn <archive> index-backup {dest_ib}"
                        );
                    }
                }
            } else {
                println!(
                    "NOTE: no index backup configured. The .db is the map SPOF — \
                     copy it with `backup --index-backup DIR`, `index-backup DIR`, \
                     or CAIRN_INDEX_BACKUP=DIR (do not try to rebuild from chunks)."
                );
            }
        }
        Commands::Push { .. } => {
            tracing::info!("Pushing to S3 (waiting for uploads to complete)...");
            #[cfg(feature = "cloud-storage")]
            {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(300),
                    engine.sync_index_to_cloud(),
                )
                .await
                {
                    Ok(Ok(())) => tracing::info!("Index successfully synced to cloud."),
                    Ok(Err(e)) => tracing::error!("Failed to sync index to cloud: {e}"),
                    Err(_) => tracing::error!("Index cloud sync timed out after 5 minutes"),
                }
            }
            // Also copy index offline if CAIRN_INDEX_BACKUP / operator path set via env only
            // (push has no --index-backup flag; env is enough for cron).
            if let Some(dest_ib) = resolve_index_backup_dest(None) {
                match copy_index_backup(
                    &db,
                    &args.archive,
                    &dest_ib,
                    resolve_index_backup_keep(None),
                ) {
                    Ok(path) => println!("Index backup written: {path}"),
                    Err(e) => {
                        anyhow::bail!("push succeeded locally but index backup failed: {e}")
                    }
                }
            }
            println!(
                "Offsite proof: on-host verify may use warm cache. After push, run:\n  \
                 cairn <archive> verify --force-remote   # or restore on another machine"
            );
        }
        Commands::Init { .. } | Commands::Raid { .. } | Commands::AppendOnly | Commands::Pull => {}
    }

    // set when a one-shot upload drain finishes with failures; makes the
    // command exit non-zero after key zeroization (declared here so it compiles
    // without the cloud-storage feature, where nothing ever sets it).
    #[cfg_attr(not(feature = "cloud-storage"), allow(unused_mut))]
    let mut upload_incomplete = false;

    #[cfg(feature = "cloud-storage")]
    if !engine.operators.is_empty() {
        // drain the upload queue with a deadline.
        // The previous loop polled `available_permits() < 1024` forever; a
        // dead backend would trap the process here for hours. The new
        // upload-task loop (above) actually acquires PENDING_UPLOAD_SEMAPHORE
        // on every upload, so this drain now correctly reflects the in-flight
        // count. We add a 5-minute cap so the operator can `SIGTERM` and
        // re-run later if the backend is unreachable.
        // chunks that keep failing stay queued for retry, so under a
        // persistent fault the drain runs to this deadline before exiting
        // non-zero (the data is safe in cache + queue; a later push retries).
        // Configurable so tests don't wait the full default.
        let drain_secs: u64 = std::env::var("CAIRN_UPLOAD_DRAIN_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        tracing::info!("Draining pending S3 uploads (max {drain_secs}s)...");
        let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(drain_secs);
        let mut last_log = std::time::Instant::now();
        // wait on the upload_queue TABLE (source of truth), not only the
        // in-flight semaphore. The old loop checked `available_permits() < 1024`
        // alone — but the async upload worker acquires that permit only AFTER
        // reading the queue, so a fast main thread saw an all-free semaphore
        // BEFORE the worker had started, declared "drained", and let the process
        // exit while chunks were still queued. Combined with the worker's
        // dequeue-on-failure that left the queue empty, cloud backups silently
        // shipped only the index (data chunks never uploaded) yet exited 0. The
        // extra per-chunk latency in asymmetric mode lost this race every time.
        // Now: not drained until the queue is empty AND nothing is in flight.
        loop {
            // a DB error here must not read as "0 queued" — combined with
            // in_flight==0 that would declare the drain complete and could exit 0 with
            // chunks still queued. Treat an error as "work may remain": flag it and
            // keep looping until the deadline (which then exits non-zero).
            let queued = match engine.db.get_upload_queue_len() {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(
                        "drain: get_upload_queue_len failed: {e} — assuming work remains"
                    );
                    cairn_cdc::UPLOAD_FAILED.store(true, std::sync::atomic::Ordering::SeqCst);
                    1
                }
            };
            let in_flight = 1024 - cairn_cdc::PENDING_UPLOAD_SEMAPHORE.available_permits();
            if queued == 0 && in_flight == 0 {
                break;
            }
            if std::time::Instant::now() >= drain_deadline {
                tracing::error!(
                    "Drain deadline (300s) reached with {queued} chunk(s) queued and \
                     {in_flight} in flight. Re-run `cairn push` later to retry."
                );
                cairn_cdc::UPLOAD_FAILED.store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }
            if last_log.elapsed() >= std::time::Duration::from_secs(10) {
                tracing::info!("Drain: {queued} queued, {in_flight} in flight; waiting...");
                last_log = std::time::Instant::now();
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if cairn_cdc::UPLOAD_FAILED.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::error!(
                "One or more chunks failed to upload to S3 — the cloud backup is INCOMPLETE. \
                 NOT syncing the index to the cloud (it would claim chunks that are not there). \
                 Fix connectivity/credentials and re-run to complete the backup."
            );
            // surface the failure as a non-zero exit for one-shot commands.
            // Previously `push`/`backup` exited 0 even when EVERY upload failed
            // (e.g. a wrong bucket → NoSuchBucket on all chunks) — the operator
            // saw success while nothing reached the cloud (silent incomplete
            // backup). The local cache still holds the data, so re-running after
            // fixing the config completes it. `mount`/`daemon` keep retrying in
            // the background and must NOT abort here.
            upload_incomplete = true;
        } else {
            tracing::info!("All uploads complete. Syncing index database to cloud before exit...");
            // log a final index-sync failure loudly — the chunks are durable but
            // the cloud copy's metadata is stale until the next successful push/daemon.
            match tokio::time::timeout(
                std::time::Duration::from_secs(300),
                engine.sync_index_to_cloud(),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::error!(
                    "failed to sync index database to cloud: {e} — cloud metadata is stale \
                     until the next successful push"
                ),
                Err(_) => tracing::error!(
                    "index cloud sync timed out after 5 minutes — cloud metadata is stale \
                     until the next successful push"
                ),
            }
        }
    }

    // Explicitly zeroize all in-memory keys before exiting. While
    // `destroy()` handles the FUSE case, non-FUSE commands (backup, gc, etc.)
    // and background tasks that hold `Arc<CryptoCtx>` may outlive main.
    engine.crypto.zeroize_keys();

    // a one-shot backup/push whose cloud uploads did not all complete must
    // report failure so cron/operators don't treat an incomplete off-site backup
    // as success. The data is safe in the local cache; re-run to finish.
    if upload_incomplete {
        anyhow::bail!(
            "cloud upload INCOMPLETE — one or more chunks did not reach the backend(s). \
             The local cache still holds the data; fix connectivity/credentials/bucket and \
             re-run `cairn <archive> push` to complete the off-site backup."
        );
    }

    // align scrub's exit code with check/verify — a scrub that reported
    // corrupted/missing chunks must not exit 0 (a cron `scrub || alert` relies
    // on this). Corruption is already logged above; this makes it authoritative.
    if scrub_corrupted > 0 {
        anyhow::bail!(
            "scrub found {scrub_corrupted} corrupted/missing chunk(s) — the archive is \
             damaged (see the errors above). With redundancy, `scrub --auto-heal` may \
             repair it; otherwise the affected files are not fully restorable."
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ARCHIVE_FORMAT_VERSION, check_format_version, dedup_contract};

    #[test]
    fn dedup_contract_has_only_three_explicit_equality_domains() {
        assert_eq!(
            dedup_contract("random", None, None).unwrap(),
            ("none", "none")
        );
        assert_eq!(
            dedup_contract("enabled", None, None).unwrap(),
            ("archive", "blake3-keyed/archive-v1")
        );
        assert_eq!(
            dedup_contract("enabled", Some("team-a"), Some("namespace")).unwrap(),
            ("pool", "blake3-keyed/pool-v1")
        );
        assert!(dedup_contract("enabled", Some("team-a"), None).is_err());
        assert!(dedup_contract("random", Some("team-a"), Some("namespace")).is_err());
        assert!(dedup_contract("unknown", None, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn available_bytes_reports_free_space() {
        // A real mount point reports a positive number; a bogus path is None.
        let free = super::available_bytes("/").expect("statvfs on / works");
        assert!(free > 0, "root filesystem should report some free space");
        assert!(super::available_bytes("/no/such/path/\u{1}").is_none());
        // The low-disk warning is a no-op that must never panic.
        super::warn_if_low_disk("/");
    }

    #[test]
    fn format_version_gate() {
        // Current and older versions are accepted.
        assert!(check_format_version(Some(&ARCHIVE_FORMAT_VERSION.to_string())).is_ok());
        // Missing key = pre-versioning archive, treated as v1.
        assert!(check_format_version(None).is_ok());
        // Unparseable PRESENT key is corruption — refuse.
        assert!(check_format_version(Some("garbage")).is_err());
        // A newer format is refused, not misread.
        let newer = (ARCHIVE_FORMAT_VERSION + 1).to_string();
        assert!(check_format_version(Some(&newer)).is_err());
        assert!(check_format_version(Some("0")).is_err());
    }

    #[test]
    fn prune_index_backups_keeps_newest_and_ignores_foreign() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        let base = "index.sqlite";
        // Four timestamped copies. The values are chosen so a lexicographic sort
        // disagrees with the numeric one ("9" > "400" as strings, 9 < 400 as
        // numbers): a regression to string-sorting the suffix would keep the wrong
        // two and fail this test.
        for ts in ["9", "80", "100", "400"] {
            fs::write(p.join(format!("{base}.indexbak.{ts}")), b"x").unwrap();
        }
        // Files that must never be touched: the live index, a non-numeric suffix,
        // and an unrelated file that merely shares the directory.
        fs::write(p.join(base), b"live").unwrap();
        fs::write(p.join(format!("{base}.indexbak.latest")), b"x").unwrap();
        fs::write(p.join("unrelated.txt"), b"x").unwrap();

        super::prune_index_backups(p, base, 2);

        let there = |name: &str| p.join(name).exists();
        // Newest two (numerically) kept; oldest two removed (proves the sort).
        assert!(there(&format!("{base}.indexbak.400")));
        assert!(there(&format!("{base}.indexbak.100")));
        assert!(!there(&format!("{base}.indexbak.80")));
        assert!(!there(&format!("{base}.indexbak.9")));
        // Everything not matching `<base>.indexbak.<digits>` is left alone.
        assert!(there(base));
        assert!(there(&format!("{base}.indexbak.latest")));
        assert!(there("unrelated.txt"));
    }

    #[test]
    fn resolve_index_backup_keep_and_dest() {
        use super::{resolve_index_backup_dest, resolve_index_backup_keep};
        // Explicit argument wins and short-circuits the environment.
        assert_eq!(resolve_index_backup_keep(Some(5)), 5);
        assert_eq!(
            resolve_index_backup_dest(Some("  /srv/idx  ")).as_deref(),
            Some("/srv/idx"),
            "explicit dest is trimmed"
        );
        // The env fallbacks. SAFETY: these two vars are read only by these two
        // helpers, and this single test function is the only place that mutates
        // them, so access stays serialized despite cargo's parallel test threads.
        unsafe {
            std::env::set_var("CAIRN_INDEX_BACKUP_KEEP", "3");
            std::env::set_var("CAIRN_INDEX_BACKUP", "/env/dest");
        }
        assert_eq!(resolve_index_backup_keep(None), 3);
        assert_eq!(
            resolve_index_backup_dest(None).as_deref(),
            Some("/env/dest")
        );
        // An invalid keep is ignored (→ 0 = keep all), never a hard error.
        unsafe {
            std::env::set_var("CAIRN_INDEX_BACKUP_KEEP", "notanumber");
        }
        assert_eq!(resolve_index_backup_keep(None), 0);
        // Unset → the defaults: keep all (0), no destination.
        unsafe {
            std::env::remove_var("CAIRN_INDEX_BACKUP_KEEP");
            std::env::remove_var("CAIRN_INDEX_BACKUP");
        }
        assert_eq!(resolve_index_backup_keep(None), 0);
        assert_eq!(resolve_index_backup_dest(None), None);
    }

    #[test]
    fn validate_init_args_guards() {
        use super::{MAX_INLINE_FILE_SIZE, validate_init_args};
        // A fully valid set is accepted.
        assert!(validate_init_args("aes-256-gcm", "zstd", 3, 90, 1024).is_ok());
        assert!(validate_init_args("chacha20-poly1305", "none", -7, 0, 0).is_ok());
        assert!(validate_init_args("aes-256-gcm", "lz4", 22, 100, MAX_INLINE_FILE_SIZE).is_ok());
        // A typo'd crypto or compression algo is refused (not silently defaulted).
        assert!(validate_init_args("aes-128", "zstd", 3, 90, 1024).is_err());
        assert!(validate_init_args("aes-256-gcm", "gzip", 3, 90, 1024).is_err());
        // Out-of-range compression level / ratio.
        assert!(validate_init_args("aes-256-gcm", "zstd", 23, 90, 1024).is_err());
        assert!(validate_init_args("aes-256-gcm", "zstd", -8, 90, 1024).is_err());
        assert!(validate_init_args("aes-256-gcm", "zstd", 3, 101, 1024).is_err());
        // Inline cap past the hard ceiling (OOM guard) is refused.
        assert!(
            validate_init_args("aes-256-gcm", "zstd", 3, 90, MAX_INLINE_FILE_SIZE + 1).is_err()
        );
    }

    #[test]
    fn validate_db_synchronous_whitelist() {
        use super::validate_db_synchronous;
        for ok in ["OFF", "NORMAL", "FULL", "EXTRA"] {
            assert_eq!(validate_db_synchronous(ok).unwrap(), ok);
        }
        // A typo would silently no-op inside `PRAGMA synchronous = …`, gutting the
        // durability setting — so it must be rejected up front, not passed through.
        assert!(validate_db_synchronous("normal").is_err()); // case-sensitive
        assert!(validate_db_synchronous("FSYNC").is_err());
        assert!(validate_db_synchronous("").is_err());
    }

    #[test]
    fn should_keep_caps_and_dedups() {
        use super::should_keep;
        let mut seen = std::collections::HashSet::new();
        // Distinct keys are kept until the cap is reached.
        assert!(should_keep(&mut seen, "mon", 2));
        assert!(should_keep(&mut seen, "tue", 2));
        // Cap reached → a new key is dropped.
        assert!(!should_keep(&mut seen, "wed", 2));
        // A duplicate of an already-kept key is dropped (does not consume a slot).
        assert!(!should_keep(&mut seen, "mon", 2));
        // max == 0 keeps nothing.
        let mut none = std::collections::HashSet::new();
        assert!(!should_keep(&mut none, "any", 0));
    }

    #[test]
    fn archive_parent_dir_fallbacks() {
        use super::archive_parent_dir;
        assert_eq!(
            archive_parent_dir("/srv/backups/archive.db"),
            "/srv/backups"
        );
        // A bare filename has no parent → current directory.
        assert_eq!(archive_parent_dir("archive.db"), ".");
    }

    #[cfg(unix)]
    #[test]
    fn safe_remove_for_overwrite_refuses_symlink() {
        use super::safe_remove_for_overwrite;
        let dir = tempfile::tempdir().unwrap();
        // A regular file at the target is removed so the caller can overwrite it.
        let plain = dir.path().join("plain");
        std::fs::write(&plain, b"x").unwrap();
        safe_remove_for_overwrite(plain.to_str().unwrap()).unwrap();
        assert!(!plain.exists());
        // A missing target is a no-op success.
        safe_remove_for_overwrite(dir.path().join("absent").to_str().unwrap()).unwrap();
        // A symlink at the target is REFUSED (symlink-attack guard) and left intact,
        // so we can never be tricked into deleting/overwriting the link's victim.
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"important").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(safe_remove_for_overwrite(link.to_str().unwrap()).is_err());
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(victim.exists(), "the symlink target must be untouched");
    }
}
