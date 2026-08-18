#![deny(unsafe_code)]

use anyhow::Result;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretString};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

/// Max extended attributes per inode: guards the index against an attacker
/// adding millions of xattrs to one inode. Far beyond any legitimate use.
pub const MAX_XATTRS_PER_INODE: i64 = 1024;

/// typed errors for xattr operations, replacing string-based matching.
#[derive(Debug)]
pub enum XattrError {
    /// XATTR_CREATE on an existing attribute.
    AlreadyExists(String),
    /// XATTR_REPLACE on a missing attribute.
    NotFound(String),
    /// Too many xattrs on one inode.
    TooMany { inode: u64, limit: i64 },
    /// Generic database error.
    Db(String),
}

impl std::fmt::Display for XattrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XattrError::AlreadyExists(name) => write!(f, "xattr exists (XATTR_CREATE): {name}"),
            XattrError::NotFound(name) => write!(f, "xattr missing (XATTR_REPLACE): {name}"),
            XattrError::TooMany { inode, limit } => {
                write!(f, "too many xattrs on inode {inode} (limit {limit})")
            }
            XattrError::Db(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for XattrError {}

/// Map XattrError to the correct POSIX errno.
impl From<XattrError> for std::io::Error {
    fn from(e: XattrError) -> Self {
        let errno = match &e {
            XattrError::AlreadyExists(_) => libc::EEXIST,
            XattrError::NotFound(_) => libc::ENODATA,
            XattrError::TooMany { .. } => libc::ENOSPC,
            XattrError::Db(_) => libc::EIO,
        };
        std::io::Error::from_raw_os_error(errno)
    }
}

impl From<rusqlite::Error> for XattrError {
    fn from(e: rusqlite::Error) -> Self {
        XattrError::Db(e.to_string())
    }
}

impl From<r2d2::Error> for XattrError {
    fn from(e: r2d2::Error) -> Self {
        XattrError::Db(e.to_string())
    }
}

pub type InodeInfo = (u32, u32, u32, u64, u32, i64, u32);
pub type FileChunkData = (String, usize, usize, Vec<u8>, i32, String);

/// (name_key, name_enc, inode). `name_key` = plaintext name (normal) or hex keyed-hash
/// (hide-names); `name_enc` = age-encrypted real name, `Some` only in hide-names archives.
pub type Dentry = (String, Option<Vec<u8>>, u64);
/// (rowid, name_key, name_enc, inode, mode) — rowid doubles as the readdir cookie.
pub type DentryRowid = (i64, String, Option<Vec<u8>>, u64, u32);
/// (rowid, name_key, name_enc, inode, mode, uid, gid, size, nlink, mtime_sec, mtime_nsec).
pub type DentryRowidPlus = (
    i64,
    String,
    Option<Vec<u8>>,
    u64,
    u32,
    u32,
    u32,
    u64,
    u32,
    i64,
    u32,
);

/// Apply SQLCipher cipher parameters and key a connection using sqlite3_key_v2 FFI.
/// checks the return value of sqlite3_key_v2.
/// used for ALL connection types (pool, snapshot temp, restore) for consistency.
#[allow(unsafe_code)]
fn apply_cipher_key(conn: &Connection, pwd: &SecretString, kdf_iter: u32) -> Result<()> {
    // Cipher PRAGMAs must precede PRAGMA key or they have no effect on the KDF.
    // kdf_iter is caller-controlled (256000 in production; lowered for tests).
    conn.execute_batch(&format!(
        "PRAGMA cipher_compatibility = 4;
         PRAGMA kdf_iter = {kdf_iter};"
    ))?;
    let passphrase = pwd.expose_secret();
    let ptr = passphrase.as_ptr() as *const std::os::raw::c_void;
    #[allow(clippy::cast_possible_truncation)]
    let len = passphrase.len() as std::os::raw::c_int;
    let rc = unsafe { rusqlite::ffi::sqlite3_key_v2(conn.handle(), std::ptr::null(), ptr, len) };
    if rc != rusqlite::ffi::SQLITE_OK {
        return Err(anyhow::anyhow!(
            "sqlite3_key_v2 failed with code {rc} (keying failure detected)"
        ));
    }
    Ok(())
}

/// Safe wrappers for `libc::getuid` / `libc::getgid`. These syscalls are
/// infallible on Linux, but the raw FFI is `unsafe`; the wrapper centralises
/// the `unsafe` block and documents why it is sound.
#[allow(unsafe_code)]
#[inline]
pub fn current_uid() -> u32 {
    // SAFETY: getuid(2) is always successful on Linux and returns a valid uid_t.
    unsafe { libc::getuid() }
}

#[allow(unsafe_code)]
#[inline]
pub fn current_gid() -> u32 {
    // SAFETY: getgid(2) is always successful on Linux and returns a valid gid_t.
    unsafe { libc::getgid() }
}

#[derive(Clone)]
pub struct Db {
    pub pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    // password is private; only accessible through getter.
    pwd: Option<SecretString>,
    // SQLCipher kdf_iter used for snapshot/restore connections (the pool uses the
    // customizer's copy). Kept so every keyed connection derives the key the same
    // way as the pool.
    kdf_iter: u32,
}

/// Tunable SQLite/SQLCipher pool parameters. All have safe back-compat defaults
/// (see [`DbTuning::default`]); pass a customized copy to [`Db::new_with_tuning`].
///
/// - `max_connections`: r2d2 pool cap. Each open connection reserves its own
///   SQLite page cache (`cache_size_kb`) and `mmap_size_kb` reservation, so
///   worst-case resident memory is roughly `max_connections * (cache_size_kb +
///   mmap_size_kb)` — lower either on constrained hosts (32 × 64 MiB
///   ≈ 2 GiB worst case).
/// - `cache_size_kb`: per-connection page cache in KiB (negative value passed
///   to `PRAGMA cache_size`, the SQLite KiB form). Larger = faster reads, more
///   RAM. `0` is treated as "use default" (64 MiB), NOT 1 KiB.
/// - `mmap_size_kb`: per-connection memory-mapped I/O reservation in KiB.
///   Default 32 MiB (was 256 MiB pre; 32 × 256 MiB = 8 GiB address-space
///   reservation overcommitted small hosts).
/// - `synchronous`: `FULL` (default; safest against power loss — the right choice
///   for irreplaceable backup metadata) or `NORMAL` (faster, still crash-safe under
///   WAL but weaker against power loss on filesystems that reorder WAL writes).
///   One of: `OFF`, `NORMAL`, `FULL`, `EXTRA`.
/// - `busy_timeout_ms`: how long a transaction waits on a busy lock before
///   failing with `SQLITE_BUSY`. Default 15 000 ms. CRITICAL: this PRAGMA must
///   run on EVERY pooled connection, not just the first one.
/// - `connection_timeout_secs`: how long `pool.get()` blocks waiting for a free
///   connection before failing. Default 30 s. `0` = "wait forever" (DoS risk
///   when all connections are stuck on slow disk).
pub struct DbTuning {
    pub max_connections: u32,
    pub cache_size_kb: i64,
    pub mmap_size_kb: i64,
    pub synchronous: String,
    pub busy_timeout_ms: u32,
    pub connection_timeout_secs: u32,
    /// SQLCipher `kdf_iter` (PBKDF2 rounds) applied to EVERY connection's key
    /// derivation. Default 256000 (SQLCipher 4 secure default). Lowering it makes
    /// opening the DB much faster but weakens brute-force resistance of the
    /// metadata index — intended for the test suite (set via `CAIRN_KDF_ITER`).
    /// MUST be identical when creating and re-opening an archive.
    pub kdf_iter: u32,
    /// Idle connections the pool keeps warm. `1` (default) suits long-lived
    /// processes (mount/daemon). Short-lived CLI commands MUST pass `0`:
    /// with a nonzero min_idle, checking out the only idle connection makes
    /// r2d2 schedule a fire-and-forget background replenish (`r2d2-worker-N`
    /// running the SQLCipher KDF inside libcrypto) that races process exit —
    /// OpenSSL's atexit teardown then segfaults the worker.
    pub min_idle: u32,
}

impl Default for DbTuning {
    fn default() -> Self {
        Self {
            max_connections: 16,
            cache_size_kb: 64_000,
            mmap_size_kb: 32 * 1024,
            // FULL (not NORMAL): a backup tool holds irreplaceable data, so pay
            // the extra fsync to survive power loss on filesystems that reorder
            // WAL writes. Overridable via --db-synchronous / CAIRN_DB_SYNCHRONOUS.
            synchronous: "FULL".to_string(),
            busy_timeout_ms: 15_000,
            connection_timeout_secs: 30,
            kdf_iter: 256_000,
            min_idle: 1,
        }
    }
}

struct SqlcipherCustomizer {
    key: std::sync::Arc<std::sync::Mutex<Option<SecretString>>>,
    cache_size_kb: i64,
    mmap_size_kb: i64,
    synchronous: String,
    busy_timeout_ms: u32,
    kdf_iter: u32,
}

impl std::fmt::Debug for SqlcipherCustomizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlcipherCustomizer")
            .field("cache_size_kb", &self.cache_size_kb)
            .field("mmap_size_kb", &self.mmap_size_kb)
            .field("synchronous", &self.synchronous)
            .field("busy_timeout_ms", &self.busy_timeout_ms)
            .field("kdf_iter", &self.kdf_iter)
            .finish()
    }
}

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for SqlcipherCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> std::result::Result<(), rusqlite::Error> {
        // a poisoned mutex (from a prior panic while the key
        // was held) must NOT skip key setup — that would add connections to the
        // pool without the SQLCipher key, causing silent garbage reads. The
        // inner value of a poisoned Mutex is still valid; recover it.
        let lock = self
            .key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(ref pwd) = *lock {
            // use shared helper that sets cipher PRAGMAs and
            // checks sqlite3_key_v2 return value. Uniform for pool, snapshot,
            // and restore connections.
            apply_cipher_key(conn, pwd, self.kdf_iter)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
        }
        // Apply EVERY per-connection PRAGMA here. The previous version only
        // set `busy_timeout` on the very first connection (Db::new_with_tuning
        // line 124), leaving 31/32 pool connections at SQLite's default 0 → EIO
        // storm under any concurrent FUSE load. The other PRAGMAs also re-apply
        // here, but they're idempotent (WAL/NORMAL/etc. are sticky settings).
        // cache_size: 0 → "use default" semantics (we substitute 64 MiB so a
        // user passing `--db-cache-kb 0` does NOT get a 1 KiB cache).
        // synchronous is validated upstream by the CLI.
        let effective_cache = if self.cache_size_kb <= 0 {
            64 * 1024
        } else {
            self.cache_size_kb
        };
        // validate synchronous against a whitelist to prevent
        // SQL injection. PRAGMA values are not parameterizable, so this is the
        // only defense. Previously relied on "validated upstream by the CLI"
        // which is unsound for a library crate.
        let sync = match self.synchronous.as_str() {
            "OFF" | "NORMAL" | "FULL" | "EXTRA" => self.synchronous.as_str(),
            other => {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISUSE),
                    Some(format!("invalid PRAGMA synchronous mode: {other}")),
                ));
            }
        };
        let batch = format!(
            "
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = {sync};
                PRAGMA cache_size = {cache};
                PRAGMA mmap_size = {mmap};
                PRAGMA temp_store = MEMORY;
                PRAGMA busy_timeout = {busy};
                ",
            cache = -effective_cache,
            mmap = self.mmap_size_kb.max(0) * 1024,
            busy = self.busy_timeout_ms,
        );
        conn.execute_batch(&batch)?;
        Ok(())
    }
}

/// xattr creation flags. The FUSE protocol passes
/// `XATTR_CREATE` (1, "fail if exists") and `XATTR_REPLACE` (2, "fail if
/// missing") — the previous unconditional `INSERT OR REPLACE` ignored
/// both, so SELinux `setfattr -n security.selinux -v ...` would silently
/// replace an existing label rather than failing as required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrFlag {
    None,
    Create,
    Replace,
}

impl Db {
    pub fn new(path: &str, password: Option<&SecretString>) -> Result<Self> {
        Self::new_with_tuning(path, password, &DbTuning::default())
    }

    /// Like [`Db::new`] but with operator-controlled pool/cache/durability tuning.
    /// `cache_size_kb`, `mmap_size_kb`, `synchronous`, and `busy_timeout_ms` are
    /// applied to *every* pooled connection on acquire, so the whole pool is
    /// consistent.
    pub fn new_with_tuning(
        path: &str,
        password: Option<&SecretString>,
        tuning: &DbTuning,
    ) -> Result<Self> {
        let manager = SqliteConnectionManager::file(path);

        let shared_key = if let Some(pwd) = password {
            std::sync::Arc::new(std::sync::Mutex::new(Some(pwd.clone())))
        } else {
            std::sync::Arc::new(std::sync::Mutex::new(None))
        };
        let customizer = SqlcipherCustomizer {
            key: shared_key,
            cache_size_kb: tuning.cache_size_kb,
            mmap_size_kb: tuning.mmap_size_kb,
            synchronous: tuning.synchronous.clone(),
            busy_timeout_ms: tuning.busy_timeout_ms,
            kdf_iter: tuning.kdf_iter,
        };

        // fail FAST and CLEARLY on a password/archive mismatch. Without
        // this probe a wrong password — or a password given for an archive
        // created without one, or a mismatched CAIRN_KDF_ITER — made every
        // pooled connection fail "file is not a database", and the caller only
        // saw a generic pool timeout after ~connection_timeout_secs of retries.
        if std::fs::metadata(path)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
        {
            let probe = Connection::open(path)?;
            if let Some(pwd) = password {
                apply_cipher_key(&probe, pwd, tuning.kdf_iter)?;
            }
            let probe_result: std::result::Result<i64, rusqlite::Error> =
                probe.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0));
            if probe_result.is_err() {
                if password.is_some() {
                    anyhow::bail!(
                        "Cannot decrypt archive '{path}': wrong password, a mismatched \
                         CAIRN_KDF_ITER, or the archive was created WITHOUT a password \
                         (then omit the password entirely)."
                    );
                }
                anyhow::bail!(
                    "Archive '{path}' is not readable without a password — it appears to be \
                     encrypted. Pass --password, --password-file or set CAIRN_PASSWORD."
                );
            }
        }

        // an unbounded `pool.get()` blocks the FUSE thread forever if
        // all connections are stuck in long-running transactions (e.g. a slow
        // `cacache::write`). Set a deadline so the caller gets `r2d2::Error`
        // (mapped to EAGAIN/EIO) and the kernel can retry.
        // min_idle(1): open exactly ONE connection eagerly, the rest lazily on
        // demand. Each connection runs a full SQLCipher KDF (256k PBKDF2) on
        // acquire, so the default `build()` — which eagerly opens all max_size
        // connections — cost ~0.23s × pool_size at every process start (~8s for a
        // 32-connection pool), paid by every short-lived CLI command. One eager
        // connection makes startup a single KDF (~1.2s); the pool grows toward
        // max_size only if concurrent load demands it.
        // min_idle comes from tuning (see DbTuning::min_idle): 1 keeps a warm
        // connection for long-lived processes; 0 is REQUIRED for short-lived
        // commands so no fire-and-forget background KDF races process exit
        // (segfault in libcrypto on r2d2-worker teardown).
        let pool = if tuning.connection_timeout_secs == 0 {
            r2d2::Pool::builder()
                .max_size(tuning.max_connections)
                .min_idle(Some(tuning.min_idle))
                .connection_customizer(Box::new(customizer))
                .build(manager)
                .map_err(|e| anyhow::anyhow!("Pool err: {e}"))?
        } else {
            r2d2::Pool::builder()
                .max_size(tuning.max_connections)
                .min_idle(Some(tuning.min_idle))
                .connection_customizer(Box::new(customizer))
                .connection_timeout(std::time::Duration::from_secs(
                    tuning.connection_timeout_secs as u64,
                ))
                .build(manager)
                .map_err(|e| anyhow::anyhow!("Pool err: {e}"))?
        };

        let conn = pool.get()?;
        // set restrictive permissions on the database file to prevent
        // local users from reading the encrypted database directly.
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            // Non-fatal on read-only mounts / CI environments; log and continue.
            tracing::warn!("chmod 0600 on {path} failed: {e}");
        }
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=15000;")?;
        // schema version tracking via PRAGMA user_version. Bump the
        // version constant when the schema changes; migration logic goes here.
        const CURRENT_SCHEMA_VERSION: u32 = 1;
        let existing_version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or(0);
        if existing_version > CURRENT_SCHEMA_VERSION {
            anyhow::bail!(
                "Database schema version {existing_version} is newer than supported version {CURRENT_SCHEMA_VERSION}. \
                 Please upgrade cairn before opening this database."
            );
        }
        if existing_version < CURRENT_SCHEMA_VERSION {
            // Migration v1 -> v2: add name_enc column for --hide-names support.
            // Only needed for existing v1 databases where the dentries table was
            // created without the column. New databases (version 0) already have
            // name_enc in the CREATE TABLE statement, so this is a no-op.
            if existing_version == 1 {
                let has_col: bool = conn
                    .prepare("SELECT name FROM pragma_table_info('dentries') WHERE name = 'name_enc'")
                    .and_then(|mut s| s.exists([]))
                    .unwrap_or(false);
                if has_col {
                    tracing::info!("dentries already has name_enc column -- skipping v1->v2 migration");
                } else {
                    tracing::info!("migrating dentries schema v1 -> v2 (add name_enc column)");
                    conn.execute_batch("ALTER TABLE dentries ADD COLUMN name_enc BLOB")?;
                }
            }
            conn.execute_batch(&format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION}"))?;
        }
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS inodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mode INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                gid INTEGER NOT NULL,
                mtime_sec INTEGER NOT NULL,
                mtime_nsec INTEGER NOT NULL,
                size INTEGER NOT NULL,
                nlink INTEGER NOT NULL,
                rdev INTEGER NOT NULL,
                inline_data BLOB DEFAULT NULL,
                ctime_sec INTEGER NOT NULL DEFAULT 0,
                ctime_nsec INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS dentries (
                parent_inode INTEGER NOT NULL,
                name TEXT NOT NULL,
                inode_id INTEGER NOT NULL,
                -- --hide-names: NULL in normal archives (name = plaintext); in
                -- hide-names archives `name` holds the hex keyed-hash lookup key and
                -- `name_enc` holds the age-encrypted real name (write-only).
                name_enc BLOB,
                PRIMARY KEY (parent_inode, name),
                FOREIGN KEY(parent_inode) REFERENCES inodes(id) ON DELETE CASCADE,
                FOREIGN KEY(inode_id) REFERENCES inodes(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS file_chunks (
                inode INTEGER NOT NULL,
                offset INTEGER NOT NULL,
                object_id TEXT NOT NULL,
                
                plain_len INTEGER NOT NULL,
                comp_type INTEGER NOT NULL,
                PRIMARY KEY (inode, offset),
                FOREIGN KEY(inode) REFERENCES inodes(id) ON DELETE CASCADE
            );

            -- index on file_chunks.object_id for JOIN performance.
            -- get_orphaned_chunks, get_file_chunks, and get_file_chunks_range
            -- all JOIN on object_id — without this index
            -- each is a full table scan (O(N×M) for orphan detection).
            CREATE INDEX IF NOT EXISTS idx_file_chunks_object_id ON file_chunks(object_id);

            -- index on dentries.inode_id for reverse lookups.
            -- get_parent_inode (called on every non-root getattr) does
            -- SELECT parent_inode FROM dentries WHERE inode_id = ? — without
            -- this index it's a full dentries scan.
            CREATE INDEX IF NOT EXISTS idx_dentries_inode_id ON dentries(inode_id);

            CREATE TABLE IF NOT EXISTS chunk_index (
                object_id TEXT PRIMARY KEY,
                plaintext_hash TEXT NOT NULL,
                sym_key BLOB NOT NULL,
                comp_type INTEGER NOT NULL DEFAULT 0,
                cipher TEXT NOT NULL DEFAULT 'aes256gcm',
                last_accessed INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS extended_attrs (
                inode INTEGER NOT NULL,
                name TEXT NOT NULL,
                value BLOB NOT NULL,
                PRIMARY KEY (inode, name),
                FOREIGN KEY(inode) REFERENCES inodes(id) ON DELETE CASCADE
            );

            -- a redundant `idx_file_chunks_inode_offset` (matches the
            -- table's own PRIMARY KEY) was a write-time tax for every chunk
            -- INSERT/DELETE. The PK is already an implicit unique B-tree on
            -- the same column prefix; the per-inode lookups in get_file_chunks
            -- / get_file_chunks_range are satisfied by the PK.

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                db_data BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS upload_queue (
                hash_key TEXT PRIMARY KEY,
                added_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS backends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uri TEXT NOT NULL UNIQUE
            );

            -- files whose `backup` is in progress. Marked before the data
            -- write, cleared only after a full flush+finalize. A row that
            -- survives (the process was killed mid-file) means the file is
            -- truncated/incomplete — `verify` reports it NOT restorable instead
            -- of green-lighting a partial file with a self-consistent size.
            CREATE TABLE IF NOT EXISTS incomplete_files (
                inode INTEGER PRIMARY KEY
            );
            ",
        )?;

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM inodes WHERE id = 1", [], |row| {
            row.get(0)
        })?;
        if count == 0 {
            let uid = current_uid();
            let gid = current_gid();
            conn.execute(
                "INSERT INTO inodes (id, mode, uid, gid, mtime_sec, mtime_nsec, size, nlink, rdev) 
                 VALUES (1, ?1, ?2, ?3, strftime('%s','now'), 0, 4096, 2, 0)",
                rusqlite::params![libc::S_IFDIR | 0o755, uid, gid],
            )?;
        }

        Ok(Self {
            pool,
            pwd: password.cloned(),
            kdf_iter: tuning.kdf_iter,
        })
    }

    /// Delete ALL filesystem data (inodes, dentries, chunks, xattrs, snapshots,
    /// upload queue, backends) in a single transaction, then re-create the empty
    /// root inode. The `config` table (crypto material, format version) is left
    /// intact. Used by `init --force` to reset an existing archive to empty.
    pub fn wipe_data(&self) -> Result<()> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        // Order does not matter (no FK enforcement), but list every data table so
        // a future table is a compile-visible omission here.
        //
        // every element of this array MUST be a
        // compile-time string literal. `format!("DELETE FROM {table}")` is the only
        // option — SQLite cannot bind a table identifier as a `?` parameter — so the
        // interpolated value is safe ONLY because it is never user- or DB-derived.
        // Never feed a dynamic/runtime table name into this loop.
        for table in [
            "file_chunks",
            "chunk_index",
            "extended_attrs",
            "dentries",
            "inodes",
            "snapshots",
            "upload_queue",
            "backends",
            "incomplete_files",
        ] {
            tx.execute(&format!("DELETE FROM {table}"), [])?; // SAFETY: `table` is a compile-time literal (SQLite can't bind identifiers)
        }
        // Re-create the root inode the DELETE above removed (mirrors the bootstrap
        // in new_with_tuning) so the archive has a valid root immediately, not
        // only after the next Db::new.
        tx.execute(
            "INSERT INTO inodes (id, mode, uid, gid, mtime_sec, mtime_nsec, size, nlink, rdev)
             VALUES (1, ?1, ?2, ?3, strftime('%s','now'), 0, 4096, 2, 0)",
            rusqlite::params![libc::S_IFDIR | 0o755, current_uid(), current_gid()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Insert an inode and its dentry in ONE transaction (single pool checkout,
    /// single WAL commit). Creation is two rows: committing them separately
    /// doubled the per-create cost — the dominant term when creating many small
    /// files (~400 creates/s measured) — and a dentry failure (duplicate name)
    /// left an already-committed orphaned inode behind.
    #[allow(clippy::too_many_arguments)] // mirrors insert_inode's args + (parent, name)
    pub fn insert_inode_with_dentry(
        &self,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        nlink: u32,
        parent: u64,
        name: &str,
        name_enc: Option<&[u8]>,
    ) -> Result<u64> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO inodes (mode, uid, gid, mtime_sec, mtime_nsec, size, nlink, rdev)
             VALUES (?1, ?2, ?3, strftime('%s','now'), 0, ?4, ?5, 0)",
            rusqlite::params![mode, uid, gid, size, nlink],
        )?;
        let ino = tx.last_insert_rowid() as u64;
        tx.execute(
            "INSERT INTO dentries (parent_inode, name, inode_id, name_enc) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![parent, name, ino, name_enc],
        )?;
        tx.commit()?;
        Ok(ino)
    }

    pub fn insert_inode(
        &self,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        nlink: u32,
    ) -> Result<u64> {
        let sql = "INSERT INTO inodes (mode, uid, gid, mtime_sec, mtime_nsec, size, nlink, rdev) 
                   VALUES (?1, ?2, ?3, strftime('%s','now'), 0, ?4, ?5, 0)";
        let conn = self.pool.get()?;
        conn.execute(sql, rusqlite::params![mode, uid, gid, size, nlink])?;
        Ok(conn.last_insert_rowid() as u64)
    }

    pub fn get_inode(&self, inode: u64) -> Result<Option<InodeInfo>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT mode, uid, gid, size, nlink, mtime_sec, mtime_nsec FROM inodes WHERE id = ?1 LIMIT 1")?;
        let mut rows = stmt.query(rusqlite::params![inode])?;
        if let Some(row) = rows.next()? {
            Ok(Some((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            )))
        } else {
            Ok(None)
        }
    }

    pub fn get_inline_data(&self, ino: u64) -> rusqlite::Result<Option<Vec<u8>>> {
        let conn = self.pool.get().map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e.to_string()),
            )
        })?;
        let mut stmt = conn.prepare("SELECT inline_data FROM inodes WHERE id = ?1 LIMIT 1")?;
        // Distinguish "no row" (legitimately no inline data) from a real DB error:
        // QueryReturnedNoRows → None; any other error propagates as EIO instead of
        // masquerading as "empty" and silently corrupting reads.
        match stmt.query_row(rusqlite::params![ino], |row| {
            row.get::<_, Option<Vec<u8>>>(0)
        }) {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn set_inline_data(&self, ino: u64, data: &[u8]) -> rusqlite::Result<()> {
        let conn = self.pool.get().map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e.to_string()),
            )
        })?;
        if data.is_empty() {
            conn.execute(
                "UPDATE inodes SET inline_data = NULL WHERE id = ?1",
                rusqlite::params![ino],
            )?;
        } else {
            conn.execute(
                "UPDATE inodes SET inline_data = ?1 WHERE id = ?2",
                rusqlite::params![data, ino],
            )?;
        }
        Ok(())
    }

    /// Store inline data AND drop every chunk of the inode in ONE transaction.
    /// The read path serves `inline_data` EXCLUSIVELY of chunks, so the two must
    /// never coexist. Doing both atomically avoids a crash window that would make
    /// the file read as empty (chunks gone, inline not yet set) or hide live
    /// chunks (inline set, chunks not yet cleared). An empty slice stores NULL.
    pub fn set_inline_and_clear_chunks(&self, ino: u64, data: &[u8]) -> rusqlite::Result<()> {
        let mut conn = self.pool.get().map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e.to_string()),
            )
        })?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM file_chunks WHERE inode = ?1",
            rusqlite::params![ino],
        )?;
        if data.is_empty() {
            tx.execute(
                "UPDATE inodes SET inline_data = NULL WHERE id = ?1",
                rusqlite::params![ino],
            )?;
        } else {
            tx.execute(
                "UPDATE inodes SET inline_data = ?1 WHERE id = ?2",
                rusqlite::params![data, ino],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// atomic chunk + size + inline truncate in a
    /// single transaction. The previous O_TRUNC path ran `truncate_file_chunks`
    /// and `update_inode_size` in two separate transactions, leaving a crash
    /// window where the chunks were empty but `inodes.size` was still the
    /// pre-truncate value; this also failed to clear `inline_data`, so a
    /// backupped-then-truncated file would read as empty on the mount but
    /// `extract` would still return the original bytes.
    pub fn truncate_inode(&self, ino: u64, new_size: u64) -> rusqlite::Result<()> {
        let mut conn = self.pool.get().map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e.to_string()),
            )
        })?;
        let tx = conn.transaction()?;
        // 1. The straddle chunk (the one that spans the new size) is shortened.
        //    The new plain_len = new_size - offset (how many bytes from this
        //    chunk's start remain after truncation). The previous formula
        //    `plain_len - (new_size - offset)` double-subtracted and produced
        //    an oversized chunk.
        tx.execute(
            "UPDATE file_chunks SET plain_len = ?2 - offset \
             WHERE inode = ?1 AND offset < ?2 AND (offset + plain_len) > ?2",
            rusqlite::params![ino, new_size as i64],
        )?;
        // 2. Chunks past the new size are deleted.
        tx.execute(
            "DELETE FROM file_chunks WHERE inode = ?1 AND offset >= ?2",
            rusqlite::params![ino, new_size as i64],
        )?;
        // 3. Inline data is cleared — a small file that was stored inline
        //    must not "resurrect" on the next extract after O_TRUNC.
        tx.execute(
            "UPDATE inodes SET inline_data = NULL WHERE id = ?1",
            rusqlite::params![ino],
        )?;
        // 4. Size + ctime are updated in lockstep.
        tx.execute(
            "UPDATE inodes SET size = ?2, ctime_sec = strftime('%s','now'), \
             ctime_nsec = 0 WHERE id = ?1",
            rusqlite::params![ino, new_size as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn clear_file_chunks(&self, ino: u64) -> rusqlite::Result<()> {
        let conn = self.pool.get().map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e.to_string()),
            )
        })?;
        conn.execute(
            "DELETE FROM file_chunks WHERE inode = ?1",
            rusqlite::params![ino],
        )?;
        Ok(())
    }

    pub fn insert_dentry(&self, parent: u64, name: &str, inode_id: u64) -> Result<()> {
        let sql = "INSERT INTO dentries (parent_inode, name, inode_id) VALUES (?1, ?2, ?3)";
        self.pool
            .get()
            .map_err(|e| anyhow::anyhow!("Pool error: {e}"))?
            .execute(sql, rusqlite::params![parent, name, inode_id])?;
        Ok(())
    }

    /// `link` must add the dentry AND bump `nlink` atomically — as two
    /// separate ops a crash (or a failed+un-rolled-back second op) leaves a
    /// dentry pointing at an inode whose `nlink` under-counts it. One
    /// transaction; the overflow guard is in the UPDATE's WHERE clause.
    pub fn insert_dentry_with_nlink_increment(
        &self,
        parent: u64,
        name: &str,
        inode_id: u64,
        name_enc: Option<&[u8]>,
    ) -> Result<()> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO dentries (parent_inode, name, inode_id, name_enc) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![parent, name, inode_id, name_enc],
        )?;
        let changed = tx.execute(
            "UPDATE inodes SET nlink = nlink + 1 WHERE id = ?1 AND nlink < ?2",
            rusqlite::params![inode_id, u32::MAX - 1],
        )?;
        if changed == 0 {
            return Err(anyhow::anyhow!(
                "link: inode {inode_id} missing or nlink at ceiling"
            ));
        }
        tx.commit()?;
        Ok(())
    }

    /// rollback helper for `link` — if incrementing `nlink`
    /// fails after the dentry was inserted, undo the insertion so the
    /// archive doesn't end up with a dentry pointing at an inode whose
    /// `nlink` no longer matches the real count of dentries.
    pub fn delete_dentry(&self, parent: u64, name: &str) -> Result<()> {
        self.pool
            .get()
            .map_err(|e| anyhow::anyhow!("Pool error: {e}"))?
            .execute(
                "DELETE FROM dentries WHERE parent_inode = ?1 AND name = ?2",
                rusqlite::params![parent, name],
            )?;
        Ok(())
    }

    pub fn get_dentry_inode(&self, parent: u64, name: &str) -> Result<Option<u64>> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT inode_id FROM dentries WHERE parent_inode = ?1 AND name = ?2")?;
        let mut rows = stmt.query(rusqlite::params![parent, name])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn list_dentries(&self, parent: u64) -> Result<Vec<Dentry>> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT name, name_enc, inode_id FROM dentries WHERE parent_inode = ?1")?;
        let rows = stmt.query_map(rusqlite::params![parent], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    /// Stateless readdir pagination. `after_rowid` is the dentry rowid of the last
    /// entry already delivered (0 = start of directory). Rowids are stable under
    /// concurrent insert/delete (unlike `LIMIT/OFFSET`, which shifts, and unlike a
    /// server-side cursor map, which one call type fills and another misses), and
    /// the same cookie works for both `readdir` and `readdirplus` — the kernel may
    /// mix them within one listing (READDIRPLUS_AUTO). An entry alive for the whole
    /// listing is returned exactly once.
    pub fn list_dentries_rowid_after(
        &self,
        parent: u64,
        after_rowid: i64,
        limit: i64,
    ) -> Result<Vec<DentryRowid>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT d.rowid, d.name, d.name_enc, d.inode_id, i.mode FROM dentries d JOIN inodes i ON d.inode_id = i.id WHERE d.parent_inode = ?1 AND d.rowid > ?2 ORDER BY d.rowid LIMIT ?3")?;
        let rows = stmt.query_map(rusqlite::params![parent, after_rowid, limit], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    /// `readdirplus` variant of [`Self::list_dentries_rowid_after`] — same rowid
    /// cookie, plus the inode attributes needed to fill each entry's `FileAttr`.
    pub fn list_dentries_rowid_after_plus(
        &self,
        parent: u64,
        after_rowid: i64,
        limit: i64,
    ) -> Result<Vec<DentryRowidPlus>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT d.rowid, d.name, d.name_enc, d.inode_id, i.mode, i.uid, i.gid, i.size, i.nlink, i.mtime_sec, i.mtime_nsec FROM dentries d JOIN inodes i ON d.inode_id = i.id WHERE d.parent_inode = ?1 AND d.rowid > ?2 ORDER BY d.rowid LIMIT ?3")?;
        let rows = stmt.query_map(rusqlite::params![parent, after_rowid, limit], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
            ))
        })?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn get_parent_inode(&self, inode: u64) -> Result<u64> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT parent_inode FROM dentries WHERE inode_id = ?1 LIMIT 1")?;
        // Distinguish "no row" (orphan inode / root → default to root parent) from a
        // real DB error; the old `.unwrap_or(None)` silently turned pool/SQL errors
        // into a wrong parent.
        let parent: Option<u64> = match stmt.query_row(rusqlite::params![inode], |row| row.get(0)) {
            Ok(p) => Some(p),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(parent.unwrap_or(1))
    }

    pub fn get_inode_name(&self, inode: u64) -> Result<String> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT name FROM dentries WHERE inode_id = ?1 LIMIT 1")?;
        // return empty string for missing dentry (consistent
        // with get_dentry_inode which returns Ok(None)). Previously propagated
        // QueryReturnedNoRows as Err, causing root inode and orphaned inodes to
        // error instead of returning a meaningful "no name" value.
        match stmt.query_row(rusqlite::params![inode], |row| row.get(0)) {
            Ok(name) => Ok(name),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(String::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// `get_inode_name` plus the `name_enc` blob, so a caller with a `CryptoCtx`
    /// can resolve a hide-names archive's lookup-key hash to the real name
    /// instead of displaying/logging the hash (`get_inode_name` alone cannot do
    /// this — it has no crypto context and only ever sees the lookup column).
    pub fn get_inode_name_enc(&self, inode: u64) -> Result<(String, Option<Vec<u8>>)> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT name, name_enc FROM dentries WHERE inode_id = ?1 LIMIT 1")?;
        match stmt.query_row(rusqlite::params![inode], |row| Ok((row.get(0)?, row.get(1)?))) {
            Ok(pair) => Ok(pair),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok((String::new(), None)),
            Err(e) => Err(e.into()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_chunk_indices_batch(
        &self,
        chunks: &[(String, String, Vec<u8>, i32, String)],
    ) -> Result<()> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO chunk_index (object_id, plaintext_hash, sym_key, comp_type, cipher) VALUES (?1, ?2, ?3, ?4, ?5)"
            )?;
            for (oid, ph, sk, ct, cipher) in chunks {
                stmt.execute(rusqlite::params![oid, ph, sk, ct, cipher])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_chunk_by_hash(
        &self,
        plaintext_hash: &str,
    ) -> Result<Option<(String, Vec<u8>, i32)>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT object_id, sym_key, comp_type FROM chunk_index WHERE plaintext_hash = ?1",
        )?;
        let res = stmt.query_row(rusqlite::params![plaintext_hash], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        });
        match res {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn insert_file_chunk(
        &self,
        inode: u64,
        offset: usize,
        object_id: &str,
        plain_len: usize,
        comp_type: i32,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT OR REPLACE INTO file_chunks (inode, offset, object_id, plain_len, comp_type)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![inode, offset as i64, object_id, plain_len as i64, comp_type],
        )?;
        Ok(())
    }

    /// atomically insert multiple file_chunks in a single
    /// transaction. Used by symlink creation for long targets (> INLINE_THRESHOLD)
    /// where each chunk must be present or none — partial inserts leave a
    /// dangling symlink with missing data.
    pub fn insert_file_chunks_batch(
        &self,
        chunks: &[(u64, usize, String, usize, i32)],
    ) -> Result<()> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO file_chunks (inode, offset, object_id, plain_len, comp_type)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for (inode, offset, object_id, plain_len, comp_type) in chunks {
                stmt.execute(rusqlite::params![
                    inode,
                    *offset as i64,
                    object_id,
                    *plain_len as i64,
                    comp_type
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Atomically replace the `file_chunks` rows for `inode` whose offset falls in
    /// `[del_start, del_end)` with `chunks` (each `(offset, object_id, plain_len,
    /// comp_type)`), in a SINGLE transaction. The DELETE-then-INSERT atomicity is
    /// load-bearing: it is the round-2 N1 fix against overwrite corruption — do not
    /// split it into separate calls. Replaces the raw SQL that used to live in
    /// cairn-fuse::flush_range (fix).
    pub fn replace_file_chunks(
        &self,
        inode: u64,
        del_start: u64,
        del_end: u64,
        chunks: &[(u64, String, usize, i32)],
    ) -> Result<()> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        // Inline data is superseded by the chunks written below; clearing it in the
        // SAME transaction keeps the file readable if we crash mid-flush (either the
        // old inline data or the new chunks are visible, never neither).
        tx.execute(
            "UPDATE inodes SET inline_data = NULL WHERE id = ?1",
            rusqlite::params![inode],
        )?;
        tx.execute(
            "DELETE FROM file_chunks WHERE inode = ?1 AND offset >= ?2 AND offset < ?3",
            rusqlite::params![inode, del_start, del_end],
        )?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO file_chunks (inode, offset, object_id, plain_len, comp_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for (offset, object_id, plain_len, comp_type) in chunks {
                stmt.execute(rusqlite::params![
                    inode,
                    *offset as i64,
                    object_id.as_str(),
                    *plain_len as i64,
                    comp_type
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_file_chunks(&self, inode: u64) -> Result<Vec<FileChunkData>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT c.object_id, c.offset, c.plain_len, i.sym_key, c.comp_type, i.cipher FROM file_chunks c JOIN chunk_index i ON c.object_id = i.object_id WHERE c.inode = ?1 ORDER BY c.offset ASC")?;
        let rows = stmt.query_map(rusqlite::params![inode], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?;
        let mut chunks = Vec::new();
        for r in rows {
            chunks.push(r?);
        }
        Ok(chunks)
    }

    pub fn get_file_chunks_range(
        &self,
        inode: u64,
        start: u64,
        end: u64,
    ) -> Result<Vec<FileChunkData>> {
        let conn = self.pool.get()?;
        // Overlap condition: chunk_start < req_end AND chunk_end > req_start
        // Since we don't have chunk_end indexed directly, we can just use offset < end and offset + plain_len > start
        let mut stmt = conn.prepare("SELECT c.object_id, c.offset, c.plain_len, i.sym_key, c.comp_type, i.cipher FROM file_chunks c JOIN chunk_index i ON c.object_id = i.object_id WHERE c.inode = ?1 AND c.offset < ?2 AND (c.offset + c.plain_len) > ?3 ORDER BY c.offset ASC")?;
        let rows = stmt.query_map(rusqlite::params![inode, end, start], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?;
        let mut chunks = Vec::new();
        for r in rows {
            chunks.push(r?);
        }
        Ok(chunks)
    }

    pub fn get_orphaned_chunks(&self, grace_period_hours: u64) -> Result<Vec<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT c.object_id 
             FROM chunk_index c 
             LEFT JOIN file_chunks f ON c.object_id = f.object_id 
             WHERE f.object_id IS NULL 
               AND (strftime('%s', 'now') - c.created_at) > ?1",
        )?;
        let rows = stmt.query_map([grace_period_hours * 3600], |row| row.get(0))?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    /// Every regular file as `(inode, recorded_size)`. Enumerates by inode (not
    /// dentry), so a hardlinked file is verified once. `0o170000`/`0o100000` are
    /// `S_IFMT`/`S_IFREG` — SQLite has no libc constants.
    pub fn list_regular_files(&self) -> Result<Vec<(u64, u64)>> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT id, size FROM inodes WHERE (mode & 61440) = 32768 ORDER BY id")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Return the list of inodes whose chunks reference the given object_id.
    /// Used by scrub to report which files are affected by a corrupted chunk.
    pub fn get_inodes_using_chunk(&self, object_id: &str) -> Result<Vec<u64>> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT DISTINCT inode FROM file_chunks WHERE object_id = ?1")?;
        let rows = stmt.query_map([object_id], |r| r.get(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_all_used_chunks(&self) -> Result<std::collections::HashSet<String>> {
        let conn = self.pool.get()?;
        let mut res = std::collections::HashSet::new();

        let mut stmt = conn.prepare("SELECT DISTINCT object_id FROM file_chunks")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let k: String = row.get(0)?;
            if !k.is_empty() {
                res.insert(k);
            }
        }

        // stream each snapshot's DB blob to a temp file via SQLite
        // incremental blob I/O instead of loading the whole thing into a Vec.
        // gc calls this over EVERY snapshot; buffering each full DB in RAM (one
        // at a time) scaled peak memory with the largest snapshot. Streaming caps
        // it at an 8 KiB copy buffer. Collect ids first — a blob handle borrows
        // the connection, so we can't hold one open while iterating a statement.
        let snap_ids: Vec<i64> = {
            let mut s = conn.prepare("SELECT id FROM snapshots")?;
            let rows = s.query_map([], |r| r.get::<_, i64>(0))?;
            rows.collect::<rusqlite::Result<Vec<i64>>>()?
        };
        for snap_id in snap_ids {
            let mut temp_file = tempfile::NamedTempFile::new()?;
            let temp_path = temp_file.path().to_string_lossy().to_string();
            {
                let mut blob = conn.blob_open(
                    rusqlite::DatabaseName::Main,
                    "snapshots",
                    "db_data",
                    snap_id,
                    true, // read-only
                )?;
                std::io::copy(&mut blob, &mut temp_file)?;
            }
            temp_file.flush()?;
            // A snapshot that fails to open or read is NOT silently skipped: its
            // chunks would otherwise be misclassified as orphans and deleted by
            // `gc`, permanently bricking that snapshot's restore. Surface the error.
            let snap_conn = Connection::open(&temp_path)
                .map_err(|e| anyhow::anyhow!("snapshot {snap_id} is corrupt: cannot open: {e}"))?;
            // Use shared helper (with return-code check) for snapshot connections.
            if let Some(ref pwd) = self.pwd {
                apply_cipher_key(&snap_conn, pwd, self.kdf_iter).map_err(|e| {
                    anyhow::anyhow!("snapshot {snap_id} is corrupt: cannot key: {e}")
                })?;
            }
            let mut c_stmt = snap_conn
                .prepare("SELECT DISTINCT object_id FROM file_chunks")
                .map_err(|e| {
                    anyhow::anyhow!("snapshot {snap_id} is corrupt: cannot prepare: {e}")
                })?;
            let mut c_rows = c_stmt.query([]).map_err(|e| {
                anyhow::anyhow!("snapshot {snap_id} is corrupt: cannot query file_chunks: {e}")
            })?;
            while let Some(r) = c_rows.next().map_err(|e| {
                anyhow::anyhow!("snapshot {snap_id} is corrupt: row read failed: {e}")
            })? {
                // column-level errors must not be silently discarded —
                // a missing object_id means GC would delete the chunk as an
                // orphan, bricking the snapshot's restore.
                let k: String = r.get(0).map_err(|e| {
                    anyhow::anyhow!(
                        "snapshot {snap_id} is corrupt: bad object_id column at row: {e}"
                    )
                })?;
                if !k.is_empty() {
                    res.insert(k);
                }
            }
        }

        Ok(res)
    }

    pub fn create_snapshot(&self, name: &str) -> Result<()> {
        // use a single connection for both backup_to_bytes and
        // the INSERT to avoid deadlock: two pool.get() calls from the same
        // thread can deadlock when the pool is near capacity.
        let conn = self.pool.get()?;
        let db_data = self.backup_to_bytes_conn(&conn)?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("system clock is before the Unix epoch: {e}"))?
            .as_secs();

        conn.execute(
            "INSERT INTO snapshots (name, timestamp, db_data) VALUES (?1, ?2, ?3)",
            rusqlite::params![name, ts, db_data],
        )?;

        Ok(())
    }

    pub fn backup_to_bytes(&self) -> Result<Vec<u8>> {
        let conn = self.pool.get()?;
        self.backup_to_bytes_conn(&conn)
    }

    /// Backup the database using an existing connection (avoids a second
    /// pool checkout — critical for callers that already hold a connection,
    /// such as `create_snapshot`).
    // `VACUUM INTO` is itself an atomic, point-in-time consistent copy of
    // the database — it CANNOT be wrapped in a `BEGIN IMMEDIATE` transaction
    // (SQLite forbids VACUUM inside a transaction). The snapshot *content* is
    // therefore already consistent; only the caller's recorded timestamp can be
    // a sub-second ahead of the VACUUM instant, which is harmless.
    fn backup_to_bytes_conn(&self, conn: &Connection) -> Result<Vec<u8>> {
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir
            .path()
            .join("backup.db")
            .to_string_lossy()
            .to_string();

        conn.execute("VACUUM INTO ?1", rusqlite::params![temp_path])?;

        {
            let temp_conn = Connection::open(&temp_path)?;
            if let Some(ref pwd) = self.pwd {
                apply_cipher_key(&temp_conn, pwd, self.kdf_iter)?;
            }
            temp_conn.execute("DELETE FROM snapshots", [])?;
            temp_conn.execute("VACUUM", [])?;
        }

        let db_data = std::fs::read(&temp_path)?;
        drop(temp_dir);
        Ok(db_data)
    }

    pub fn extract_snapshot(&self, snap_id: u64, out_path: &str) -> Result<()> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT db_data FROM snapshots WHERE id = ?1")?;
        let db_data: Vec<u8> = stmt.query_row(rusqlite::params![snap_id], |row| row.get(0))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(out_path)?;
            std::io::Write::write_all(&mut file, &db_data)?;
        }
        #[cfg(not(unix))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out_path)?;
            std::io::Write::write_all(&mut file, &db_data)?;
        }
        Ok(())
    }

    /// Materialize snapshot `snap_id` as a standalone database file at `out_path`,
    /// carrying over the CURRENT snapshot history (snapshot blobs are stored with
    /// an emptied `snapshots` table — restoring one verbatim would destroy every
    /// snapshot, including the ability to roll forward again).
    pub fn restore_snapshot_to(&self, snap_id: u64, out_path: &str) -> Result<()> {
        self.extract_snapshot(snap_id, out_path)?;

        let restored = Connection::open(out_path)?;
        if let Some(ref pwd) = self.pwd {
            apply_cipher_key(&restored, pwd, self.kdf_iter)?;
        }
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, name, timestamp, db_data FROM snapshots")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: u64 = row.get(0)?;
            let name: String = row.get(1)?;
            let ts: u64 = row.get(2)?;
            let data: Vec<u8> = row.get(3)?;
            restored.execute(
                "INSERT INTO snapshots (id, name, timestamp, db_data) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![id, name, ts, data],
            )?;
        }
        Ok(())
    }

    /// Flush the WAL into the main database file and truncate it. Called before
    /// snapshot rollback swaps the database file out from under the open pool, so
    /// no later checkpoint writes stale pages into the new file.
    pub fn wal_checkpoint_truncate(&self) -> Result<()> {
        let conn = self.pool.get()?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    pub fn list_snapshots(&self) -> Result<Vec<(u64, String, u64)>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, name, timestamp FROM snapshots ORDER BY id ASC")?;
        let mut rows = stmt.query([])?;
        let mut res = Vec::new();
        while let Some(row) = rows.next()? {
            res.push((row.get(0)?, row.get(1)?, row.get(2)?));
        }
        Ok(res)
    }

    /// Total logical size = sum of all inode sizes (bytes the user stored, pre-dedup/compression).
    pub fn total_logical_bytes(&self) -> Result<u64> {
        let conn = self.pool.get()?;
        let n: i64 = conn.query_row("SELECT COALESCE(SUM(size), 0) FROM inodes", [], |r| {
            r.get(0)
        })?;
        Ok(n as u64)
    }

    pub fn total_inodes(&self) -> Result<u64> {
        let conn = self.pool.get()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM inodes", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn total_chunks(&self) -> Result<u64> {
        let conn = self.pool.get()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM chunk_index", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn total_physical_bytes(&self) -> Result<u64> {
        let conn = self.pool.get()?;
        // Deduplicated storage: sum plain_len over DISTINCT object_ids, so a chunk
        // shared by many files is counted ONCE (the previous query summed every
        // file_chunks row, i.e. the LOGICAL size — it never reflected dedup, which
        // is the one thing this "(dedup)" number is supposed to show). Inline data
        // lives per-inode and is not deduplicated, so it is summed as-is.
        let n: i64 = conn.query_row(
            "SELECT COALESCE((SELECT SUM(plain_len) FROM
                        (SELECT object_id, MAX(plain_len) AS plain_len
                         FROM file_chunks GROUP BY object_id)), 0)
                  + COALESCE((SELECT SUM(LENGTH(inline_data)) FROM inodes WHERE inline_data IS NOT NULL), 0)",
            [],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    pub fn enqueue_upload(&self, hash_key: &str) -> Result<()> {
        let conn = self.pool.get()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("system clock is before the Unix epoch: {e}"))?
            .as_secs() as i64;
        conn.execute(
            "INSERT OR IGNORE INTO upload_queue (hash_key, added_at) VALUES (?1, ?2)",
            rusqlite::params![hash_key, now],
        )?;
        Ok(())
    }

    pub fn dequeue_upload(&self, hash_key: &str) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "DELETE FROM upload_queue WHERE hash_key = ?1",
            rusqlite::params![hash_key],
        )?;
        Ok(())
    }

    pub fn get_upload_queue(&self) -> Result<Vec<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT hash_key FROM upload_queue ORDER BY added_at ASC")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn get_upload_queue_len(&self) -> Result<u64> {
        let conn = self.pool.get()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM upload_queue", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// mark a file's backup as in progress (committed before writing its
    /// data). If the process dies mid-file the row survives and `verify` flags
    /// the file. `INSERT OR IGNORE` so a resumed backup is idempotent.
    pub fn mark_file_incomplete(&self, inode: u64) -> Result<()> {
        self.pool.get()?.execute(
            "INSERT OR IGNORE INTO incomplete_files (inode) VALUES (?1)",
            rusqlite::params![inode],
        )?;
        Ok(())
    }

    /// clear the in-progress mark once the file is fully flushed+finalized.
    pub fn clear_file_incomplete(&self, inode: u64) -> Result<()> {
        self.pool.get()?.execute(
            "DELETE FROM incomplete_files WHERE inode = ?1",
            rusqlite::params![inode],
        )?;
        Ok(())
    }

    /// is this inode's backup interrupted (marker present)?
    pub fn is_file_incomplete(&self, inode: u64) -> Result<bool> {
        let conn = self.pool.get()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM incomplete_files WHERE inode = ?1",
            rusqlite::params![inode],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// inodes whose backup was interrupted (truncated / incomplete).
    pub fn list_incomplete_files(&self) -> Result<Vec<u64>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT inode FROM incomplete_files")?;
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r? as u64);
        }
        Ok(res)
    }

    pub fn delete_snapshot(&self, snap_id: u64) -> Result<()> {
        self.pool.get()?.execute(
            "DELETE FROM snapshots WHERE id = ?1",
            rusqlite::params![snap_id],
        )?;
        Ok(())
    }

    pub fn remove_chunk_from_index(&self, object_id: &str) -> Result<()> {
        self.pool.get()?.execute(
            "DELETE FROM chunk_index WHERE object_id = ?1",
            rusqlite::params![object_id],
        )?;
        Ok(())
    }

    /// Distinct chunk object ids referenced by any file. Used by `scrub` to verify
    /// each physical chunk once instead of once per file reference (dedup makes
    /// the per-reference count N× the work).
    pub fn get_all_distinct_chunk_objects(&self) -> Result<Vec<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT DISTINCT object_id FROM file_chunks")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    /// Every object_id present in `chunk_index` (regardless of whether any file
    /// still references it). Used by the gc local sweep as a *protected* set: a
    /// chunk whose index row still exists is either in active use or inside the
    /// grace window (orphaned but not yet collectable). Removing its local cache
    /// blob prematurely turns a dedup hit into `EIO` on local-only archives, so
    /// the sweep must skip it until the index row is gone.
    pub fn get_all_indexed_chunk_objects(&self) -> Result<std::collections::HashSet<String>> {
        let conn = self.pool.get()?;
        let mut res = std::collections::HashSet::new();
        let mut stmt = conn.prepare("SELECT object_id FROM chunk_index")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let k: String = row.get(0)?;
            if !k.is_empty() {
                res.insert(k);
            }
        }
        Ok(res)
    }

    pub fn update_inode_size(&self, id: u64, size: u64) -> Result<()> {
        self.pool.get()?.execute(
            "UPDATE inodes SET size = ?1 WHERE id = ?2",
            rusqlite::params![size, id],
        )?;
        Ok(())
    }

    /// write-path atomic update of `size` + `mtime` + `ctime`
    /// in a single transaction. Replaces the previous two-step
    /// `update_inode_size` + (nothing for mtime), which left mtime at
    /// inode-creation time forever.
    pub fn update_inode_size_and_bump_time(&self, id: u64, size: u64) -> Result<()> {
        self.pool.get()?.execute(
            "UPDATE inodes SET size = ?1, \
             mtime_sec = strftime('%s','now'), mtime_nsec = 0, \
             ctime_sec = strftime('%s','now'), ctime_nsec = 0 \
             WHERE id = ?2",
            rusqlite::params![size, id],
        )?;
        Ok(())
    }

    /// Drop the `file_chunks` rows for `inode` whose offset falls in `[start, end)`
    /// — used by `fallocate(FALLOC_FL_PUNCH_HOLE)` to punch a sparse hole. The
    /// inode size is unchanged (KEEP_SIZE is mandatory for a hole punch); reads
    /// of the punched range zero-fill because no chunk covers it.
    pub fn drop_file_chunks_range(&self, inode: u64, start: u64, end: u64) -> Result<()> {
        let conn = self.pool.get()?;
        // shorten straddle chunks (starting before `start` but extending
        // into the punch range) before deleting interior/tail chunks. Without
        // this step, a straddle chunk is left intact and reads in the punched
        // range return stale data instead of zeros.
        conn.execute(
            "UPDATE file_chunks SET plain_len = ?2 - offset \
             WHERE inode = ?1 AND offset < ?2 AND (offset + plain_len) > ?2",
            rusqlite::params![inode, start],
        )?;
        conn.execute(
            "DELETE FROM file_chunks WHERE inode = ?1 AND offset >= ?2 AND offset < ?3",
            rusqlite::params![inode, start, end],
        )?;
        Ok(())
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Insert `value` for `key` only if the key is absent, and return the value
    /// that is now stored — the existing one if another writer got there first.
    /// One IMMEDIATE transaction, so concurrent creators of a first-use config
    /// value (the archive KEK, the pinned recipient) converge on a single
    /// winner instead of last-writer-wins silently orphaning the loser's data.
    pub fn set_config_if_absent(&self, key: &str, value: &str) -> Result<String> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO config (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )?;
        let stored: String = tx.query_row(
            "SELECT value FROM config WHERE key = ?1",
            rusqlite::params![key],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(stored)
    }

    /// Read a config value. Returns `Ok(None)` ONLY for "key not set"
    /// (`SQLITE_ROW` returned zero rows, surfaced as `QueryReturnedNoRows`);
    /// any other DB error propagates so a busy / corrupt / IO error is not
    /// misclassified as a missing key. Same discipline as
    /// `get_inline_data` and `get_parent_inode`.
    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT value FROM config WHERE key = ?1")?;
        match stmt.query_row(rusqlite::params![key], |row| row.get(0)) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("get_config({key}) failed: {e}")),
        }
    }

    pub fn increment_nlink(&self, id: u64) -> Result<()> {
        // atomic conditional increment. The overflow guard lives in
        // the WHERE clause so it is checked and applied in ONE statement — a
        // separate SELECT-then-UPDATE let two concurrent `link`s both pass the
        // check and double-increment past u32::MAX (a spurious later deletion).
        let changed = self.pool.get()?.execute(
            "UPDATE inodes SET nlink = nlink + 1 WHERE id = ?1 AND nlink < ?2",
            rusqlite::params![id, u32::MAX - 1],
        )?;
        if changed == 0 {
            return Err(anyhow::anyhow!(
                "increment_nlink failed for ino {id}: inode missing or nlink at ceiling (u32::MAX - 1)"
            ));
        }
        Ok(())
    }

    pub fn insert_backend(&self, uri: &str) -> Result<u64> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO backends (uri) VALUES (?1)",
            rusqlite::params![uri],
        )?;
        Ok(conn.last_insert_rowid() as u64)
    }

    pub fn delete_backend(&self, id: u64) -> Result<()> {
        self.pool
            .get()?
            .execute("DELETE FROM backends WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    }

    pub fn update_backend_uri(&self, id: u64, uri: &str) -> Result<()> {
        self.pool.get()?.execute(
            "UPDATE backends SET uri = ?1 WHERE id = ?2",
            rusqlite::params![uri, id],
        )?;
        Ok(())
    }

    pub fn list_backends(&self) -> Result<Vec<(u64, String)>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, uri FROM backends ORDER BY id ASC")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn atomic_unlink(
        &self,
        parent: u64,
        name: &str,
        enforce_empty_dir: bool,
    ) -> Result<(u64, u32)> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;

        let mut stmt =
            tx.prepare("SELECT inode_id FROM dentries WHERE parent_inode = ?1 AND name = ?2")?;
        let ino: u64 = stmt.query_row(rusqlite::params![parent, name], |row| row.get(0))?;
        drop(stmt);

        // A directory's nlink here is 2 (self + "..") by convention and is NOT
        // decremented when subdirectories are added/removed (mkdir keeps parent
        // nlink fixed — see cairn_core::mkdir). So the file-style "nlink -= 1;
        // delete if 0" loop NEVER deletes a directory: 2 → 1, never 0, leaving an
        // orphaned inode + its chunks forever. For directories, dropping the only
        // dentry makes the inode unreachable → delete it directly (after the
        // empty check). Files keep the refcount path.
        let mut type_stmt = tx.prepare("SELECT mode FROM inodes WHERE id = ?1")?;
        let mode: u32 = type_stmt.query_row(rusqlite::params![ino], |r| r.get(0))?;
        drop(type_stmt);
        let is_dir = mode & libc::S_IFMT == libc::S_IFDIR;

        if is_dir && enforce_empty_dir {
            let mut child_stmt =
                tx.prepare("SELECT 1 FROM dentries WHERE parent_inode = ?1 LIMIT 1")?;
            if child_stmt.exists(rusqlite::params![ino])? {
                return Err(anyhow::anyhow!("ENOTEMPTY"));
            }
        }

        tx.execute(
            "DELETE FROM dentries WHERE parent_inode = ?1 AND name = ?2",
            rusqlite::params![parent, name],
        )?;

        if is_dir {
            // Directory is now unreachable: remove the whole subtree (inode,
            // child inodes, and all their chunks — dentries/xattrs fall via the
            // ON DELETE CASCADE foreign keys) in this transaction.
            Self::delete_inode_recursive_internal(&tx, ino)?;
            tx.commit()?;
            return Ok((ino, 0));
        }

        tx.execute(
            "UPDATE inodes SET nlink = nlink - 1 WHERE id = ?1",
            rusqlite::params![ino],
        )?;

        let nlink: u32 = tx.query_row(
            "SELECT nlink FROM inodes WHERE id = ?1",
            rusqlite::params![ino],
            |row| row.get(0),
        )?;

        if nlink == 0 {
            Self::delete_inode_internal(&tx, ino)?;
        }

        tx.commit()?;
        Ok((ino, nlink))
    }

    // Internal helper for use inside a transaction
    fn delete_inode_internal(tx: &rusqlite::Transaction, id: u64) -> Result<()> {
        tx.execute("DELETE FROM inodes WHERE id = ?1", rusqlite::params![id])?;
        tx.execute(
            "DELETE FROM file_chunks WHERE inode = ?1",
            rusqlite::params![id],
        )?;
        // delete the inode's extended attributes too. `foreign_keys` is
        // OFF so the schema's `ON DELETE CASCADE` never fires — the recursive delete
        // path already deletes `extended_attrs` explicitly, but this non-recursive
        // file-unlink path did not, orphaning every xattr row on each unlink.
        tx.execute(
            "DELETE FROM extended_attrs WHERE inode = ?1",
            rusqlite::params![id],
        )?;
        // drop the in-progress marker too (no FK cascade with
        // foreign_keys OFF), or a deleted mid-backup inode leaves a phantom that
        // makes `verify` report a non-existent file as incomplete forever.
        tx.execute(
            "DELETE FROM incomplete_files WHERE inode = ?1",
            rusqlite::params![id],
        )?;
        Ok(())
    }

    /// Recursively delete a directory inode and everything beneath it. A recursive
    /// CTE walks the dentry tree from `root`; we then delete the dependent rows
    /// explicitly in dependency order — `foreign_keys` PRAGMA is OFF (the schema
    /// declares `ON DELETE CASCADE` but SQLite never enforces it without the
    /// pragma, and turning it on is a back-compat risk for archives carrying
    /// orphaned rows from older bugs), so we cannot rely on cascade here. Use only
    /// for directories: a file may have hardlinks (nlink > 1) and must follow the
    /// decrement-and-delete-if-0 path instead.
    fn delete_inode_recursive_internal(tx: &rusqlite::Transaction, root: u64) -> Result<()> {
        // compute the recursive CTE once into a temp table,
        // then reuse it for all 4 DELETE statements. Previously the identical
        // CTE was evaluated 4 times — O(4×N) for deep trees instead of O(N).
        tx.execute(
            "CREATE TEMP TABLE IF NOT EXISTS _descendants AS
             WITH RECURSIVE descendants(id) AS (
                 SELECT ?1
                 UNION
                 SELECT d.inode_id FROM dentries d JOIN descendants ON d.parent_inode = descendants.id
             )
             SELECT id FROM descendants",
            rusqlite::params![root],
        )?;
        tx.execute(
            "DELETE FROM file_chunks WHERE inode IN (SELECT id FROM _descendants)",
            [],
        )?;
        tx.execute(
            "DELETE FROM extended_attrs WHERE inode IN (SELECT id FROM _descendants)",
            [],
        )?;
        tx.execute(
            "DELETE FROM dentries WHERE parent_inode IN (SELECT id FROM _descendants)
                OR inode_id IN (SELECT id FROM _descendants)",
            [],
        )?;
        tx.execute(
            "DELETE FROM inodes WHERE id IN (SELECT id FROM _descendants)",
            [],
        )?;
        // clear markers for the whole deleted subtree.
        tx.execute(
            "DELETE FROM incomplete_files WHERE inode IN (SELECT id FROM _descendants)",
            [],
        )?;
        tx.execute("DROP TABLE IF EXISTS _descendants", [])?;
        Ok(())
    }

    pub fn atomic_rename(
        &self,
        parent: u64,
        name: &str,
        newparent: u64,
        newname: &str,
        newname_enc: Option<&[u8]>,
    ) -> Result<Option<(u64, u32)>> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;

        // 1. Resolve the source inode (must exist).
        let mut src_stmt =
            tx.prepare("SELECT inode_id FROM dentries WHERE parent_inode = ?1 AND name = ?2")?;
        // only "no such row" means the source is genuinely absent;
        // a real DB error must not be mislabeled as ENOENT — carry its context.
        let src_ino: u64 = src_stmt
            .query_row(rusqlite::params![parent, name], |r| r.get(0))
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    anyhow::anyhow!("ENOENT: Source does not exist")
                }
                other => anyhow::anyhow!("source inode lookup failed: {other}"),
            })?;
        drop(src_stmt);

        // 2. Cycle check: newparent must not be a descendant of the source.
        //    Prepare the parent-lookup ONCE and walk up with a bounded depth to
        //    defend against a corrupted dentry graph forming a cycle (the old
        //    loop re-prepared the statement every hop and had no bound).
        const MAX_DEPTH: u32 = 4096;
        let mut parent_stmt =
            tx.prepare("SELECT parent_inode FROM dentries WHERE inode_id = ?1")?;
        let mut curr = newparent;
        let mut depth = 0u32;
        while curr != 1 {
            if curr == src_ino {
                return Err(anyhow::anyhow!("EINVAL: Rename cycle detected"));
            }
            match parent_stmt.query_row(rusqlite::params![curr], |r| r.get::<_, u64>(0)) {
                Ok(p) => {
                    curr = p;
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => break,
                Err(e) => return Err(e.into()),
            }
            depth += 1;
            if depth >= MAX_DEPTH {
                return Err(anyhow::anyhow!(
                    "EINVAL: directory tree too deep or cyclic (rename cycle check exceeded {MAX_DEPTH} levels)"
                ));
            }
        }
        drop(parent_stmt);

        // 3. If the target exists, handle overwrite. A target DIRECTORY that is
        //    empty is fully removed (inode + chunks) — the file-style nlink--→0
        //    path never reaches 0 for directories (nlink=2 → 1), which used to
        //    leak an orphaned inode. Files keep the refcount path.
        let mut overwritten = None;
        let mut target_stmt =
            tx.prepare("SELECT inode_id FROM dentries WHERE parent_inode = ?1 AND name = ?2")?;
        // only "no such row" means the target is absent; a real DB error
        // (SQLITE_BUSY, corrupt page, I/O) must propagate, not be silently treated
        // as "target doesn't exist" (which would skip overwrite handling).
        let target_ino_opt: Option<u64> =
            match target_stmt.query_row(rusqlite::params![newparent, newname], |r| r.get(0)) {
                Ok(v) => Some(v),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(e.into()),
            };
        drop(target_stmt);

        if let Some(target_ino) = target_ino_opt {
            let mut type_stmt = tx.prepare("SELECT mode FROM inodes WHERE id = ?1")?;
            let target_mode: u32 =
                type_stmt.query_row(rusqlite::params![target_ino], |r| r.get(0))?;
            drop(type_stmt);
            let target_is_dir = target_mode & libc::S_IFMT == libc::S_IFDIR;

            if target_is_dir {
                let mut child_stmt =
                    tx.prepare("SELECT 1 FROM dentries WHERE parent_inode = ?1 LIMIT 1")?;
                if child_stmt.exists(rusqlite::params![target_ino])? {
                    return Err(anyhow::anyhow!("ENOTEMPTY: Target directory is not empty"));
                }
            }

            tx.execute(
                "DELETE FROM dentries WHERE parent_inode = ?1 AND name = ?2",
                rusqlite::params![newparent, newname],
            )?;

            if target_is_dir {
                Self::delete_inode_recursive_internal(&tx, target_ino)?;
                overwritten = Some((target_ino, 0));
            } else {
                tx.execute(
                    "UPDATE inodes SET nlink = nlink - 1 WHERE id = ?1",
                    rusqlite::params![target_ino],
                )?;
                let nlink: u32 = tx.query_row(
                    "SELECT nlink FROM inodes WHERE id = ?1",
                    rusqlite::params![target_ino],
                    |r| r.get(0),
                )?;
                if nlink == 0 {
                    Self::delete_inode_internal(&tx, target_ino)?;
                }
                overwritten = Some((target_ino, nlink));
            }
        }

        // --hide-names: refresh name_enc alongside the lookup key so the moved
        // dentry decrypts to the NEW name (a stale old name_enc would make
        // readdir/extract show the pre-rename name). NULL in normal archives.
        tx.execute(
            "UPDATE dentries SET parent_inode = ?1, name = ?2, name_enc = ?5 WHERE parent_inode = ?3 AND name = ?4",
            rusqlite::params![newparent, newname, parent, name, newname_enc],
        )?;
        tx.commit()?;
        Ok(overwritten)
    }

    /// Set an inode's stored mtime explicitly. `cairn backup` uses this to record
    /// the SOURCE file's mtime (writes otherwise stamp "now"), which is what makes
    /// `extract --preserve` restore the real timestamp AND makes the `--incremental`
    /// size+mtime skip actually match on an unchanged file.
    pub fn set_inode_mtime(&self, id: u64, mtime_sec: i64, mtime_nsec: u32) -> Result<()> {
        self.pool.get()?.execute(
            "UPDATE inodes SET mtime_sec = ?1, mtime_nsec = ?2 WHERE id = ?3",
            rusqlite::params![mtime_sec, mtime_nsec, id],
        )?;
        Ok(())
    }

    pub fn update_inode_attr(
        &self,
        id: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
    ) -> Result<()> {
        let mut conn = self.pool.get()?;
        // Single transaction: previously each attribute was a separate `execute`
        // (separate commit), so a crash mid-`setattr` could leave the inode with
        // mode updated but size/truncate not yet applied (or vice versa).
        let tx = conn.transaction()?;
        if let Some(m) = mode {
            tx.execute(
                "UPDATE inodes SET mode = ?1 WHERE id = ?2",
                rusqlite::params![m, id],
            )?;
        }
        if let Some(u) = uid {
            tx.execute(
                "UPDATE inodes SET uid = ?1 WHERE id = ?2",
                rusqlite::params![u, id],
            )?;
        }
        if let Some(g) = gid {
            tx.execute(
                "UPDATE inodes SET gid = ?1 WHERE id = ?2",
                rusqlite::params![g, id],
            )?;
        }
        if let Some(s) = size {
            tx.execute(
                "UPDATE inodes SET size = ?1 WHERE id = ?2",
                rusqlite::params![s, id],
            )?;
        }
        // POSIX ctime — bumped on any metadata change. The
        // FUSE adapter wires utimensat/atime/mtime through the adapter but
        // the previous engine dropped them on the floor; mtime is bumped
        // on write (cairn-core::write), ctime is bumped here. Schema
        // migration added `ctime_sec`/`ctime_nsec` columns.
        tx.execute(
            "UPDATE inodes SET ctime_sec = strftime('%s','now'), ctime_nsec = 0 \
             WHERE id = ?1",
            rusqlite::params![id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_xattr_with_flags(
        &self,
        inode_id: u64,
        name: &str,
        value: &[u8],
        flag: XattrFlag,
    ) -> std::result::Result<(), XattrError> {
        // wrap in a transaction to close the TOCTOU race window.
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        // only "no such row" means "not present"; any OTHER DB error must
        // propagate, not be coerced to `None` by `.ok()`. With `.ok()` a busy/locked
        // DB read looked like "absent" — a `Create` would proceed and a `Replace`
        // would wrongly report NotFound. (Same shape as atomic_rename.)
        let existing: Option<i64> = match tx.query_row(
            "SELECT 1 FROM extended_attrs WHERE inode = ?1 AND name = ?2 LIMIT 1",
            rusqlite::params![inode_id, name],
            |row| row.get(0),
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };
        let present = existing.is_some();
        match flag {
            XattrFlag::Create if present => {
                return Err(XattrError::AlreadyExists(name.to_owned()));
            }
            XattrFlag::Replace if !present => {
                return Err(XattrError::NotFound(name.to_owned()));
            }
            _ => {}
        }
        if present {
            tx.execute(
                "UPDATE extended_attrs SET value = ?3 WHERE inode = ?1 AND name = ?2",
                rusqlite::params![inode_id, name, value],
            )?;
        } else {
            // cap the number of xattrs per inode. Name length, value size and
            // NUL bytes are already checked at the FUSE layer, but the *count* was
            // unbounded — an attacker could add millions of entries to one inode
            // to exhaust the index. 1024 is far beyond any legitimate use (Linux
            // ext4 fits all of an inode's xattrs in one block).
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM extended_attrs WHERE inode = ?1",
                rusqlite::params![inode_id],
                |row| row.get(0),
            )?;
            if count >= MAX_XATTRS_PER_INODE {
                return Err(XattrError::TooMany {
                    inode: inode_id,
                    limit: MAX_XATTRS_PER_INODE,
                });
            }
            tx.execute(
                "INSERT INTO extended_attrs (inode, name, value) VALUES (?1, ?2, ?3)",
                rusqlite::params![inode_id, name, value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_xattr(&self, inode_id: u64, name: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT value FROM extended_attrs WHERE inode = ?1 AND name = ?2")?;
        let mut rows = stmt.query(rusqlite::params![inode_id, name])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn list_xattr(&self, inode_id: u64) -> Result<Vec<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT name FROM extended_attrs WHERE inode = ?1")?;
        let mut rows = stmt.query(rusqlite::params![inode_id])?;
        let mut res = Vec::new();
        while let Some(row) = rows.next()? {
            res.push(row.get(0)?);
        }
        Ok(res)
    }

    pub fn remove_xattr(&self, inode_id: u64, name: &str) -> Result<()> {
        let sql = "DELETE FROM extended_attrs WHERE inode = ?1 AND name = ?2";
        self.pool
            .get()
            .map_err(|e| anyhow::anyhow!("Pool error: {e}"))?
            .execute(sql, rusqlite::params![inode_id, name])?;
        Ok(())
    }
}

impl Db {
    #[cfg(test)]
    pub fn delete_inode(&self, id: u64) -> anyhow::Result<()> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        Self::delete_inode_internal(&tx, id)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Db {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let uri = format!("file:test_db_{}?mode=memory&cache=shared", id);
        Db::new(&uri, None).unwrap()
    }

    // get_inodes_using_chunk returns the DISTINCT inodes whose file_chunks
    // reference an object_id — scrub uses it to name the files a corrupt/missing
    // chunk affects. Must de-dup an inode that references the chunk twice, and
    // return empty for an unknown chunk.
    #[test]
    fn test_get_inodes_using_chunk() {
        let db = test_db();
        let a = db
            .insert_inode_with_dentry(libc::S_IFREG | 0o644, 0, 0, 0, 1, 1, "a", None)
            .unwrap();
        let b = db
            .insert_inode_with_dentry(libc::S_IFREG | 0o644, 0, 0, 0, 1, 1, "b", None)
            .unwrap();
        // inode a references obj1 twice (two offsets) + obj2 once; inode b references obj1.
        db.insert_file_chunk(a, 0, "obj1", 100, 0).unwrap();
        db.insert_file_chunk(a, 100, "obj1", 100, 0).unwrap();
        db.insert_file_chunk(a, 200, "obj2", 100, 0).unwrap();
        db.insert_file_chunk(b, 0, "obj1", 100, 0).unwrap();

        let mut users = db.get_inodes_using_chunk("obj1").unwrap();
        users.sort_unstable();
        let mut want = vec![a, b];
        want.sort_unstable();
        assert_eq!(
            users, want,
            "obj1 must map to both inodes, each once (DISTINCT)"
        );
        assert_eq!(db.get_inodes_using_chunk("obj2").unwrap(), vec![a]);
        assert!(
            db.get_inodes_using_chunk("nonexistent").unwrap().is_empty(),
            "unknown chunk → no inodes"
        );
    }

    // deleting an inode also removes its extended_attrs. foreign_keys is
    // OFF, so ON DELETE CASCADE never fires; the delete must clear xattrs itself,
    // or the rows leak and can reattach to a later inode that reuses the same id.
    #[test]
    fn test_delete_inode_removes_extended_attrs() {
        let db = test_db();
        let ino = db
            .insert_inode_with_dentry(libc::S_IFREG | 0o644, 0, 0, 0, 1, 1, "f", None)
            .unwrap();
        db.set_xattr_with_flags(ino, "user.k", b"v", XattrFlag::None)
            .unwrap();
        assert!(
            !db.list_xattr(ino).unwrap().is_empty(),
            "precondition: xattr set"
        );

        db.delete_inode(ino).unwrap();
        assert!(
            db.list_xattr(ino).unwrap().is_empty(),
            "delete_inode must drop the inode's extended_attrs"
        );
    }

    #[test]
    fn test_set_config_if_absent_converges() {
        // the first writer wins; every later writer gets the stored value
        // back instead of overwriting it (contrast set_config = last-writer-wins).
        let db = test_db();
        assert_eq!(db.set_config_if_absent("kek", "alpha").unwrap(), "alpha");
        assert_eq!(db.set_config_if_absent("kek", "beta").unwrap(), "alpha");
        assert_eq!(db.get_config("kek").unwrap().as_deref(), Some("alpha"));
        // Racing writers from many threads must all converge on one value.
        // File-backed DB: shared-cache :memory: uses table-level locks that
        // busy_timeout does not retry (SQLITE_LOCKED), unlike real archives.
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            Db::new(dir.path().join("race.db").to_str().unwrap(), None).unwrap(),
        );
        let results: Vec<String> = std::thread::scope(|s| {
            (0..8)
                .map(|i| {
                    let db = db.clone();
                    s.spawn(move || db.set_config_if_absent("race", &format!("v{i}")).unwrap())
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });
        let winner = db.get_config("race").unwrap().unwrap();
        assert!(
            results.iter().all(|r| *r == winner),
            "diverged: {results:?}"
        );
    }

    #[test]
    fn test_insert_and_get_inode() {
        let db = test_db();
        let ino = db
            .insert_inode(libc::S_IFREG | 0o644, 1000, 1000, 1024, 1)
            .unwrap();
        assert!(ino >= 2);

        let info = db.get_inode(ino).unwrap().unwrap();
        assert_eq!(info.0, libc::S_IFREG | 0o644); // mode
        assert_eq!(info.1, 1000); // uid
        assert_eq!(info.2, 1000); // gid
        assert_eq!(info.3, 1024); // size
        assert_eq!(info.4, 1); // nlink
    }

    #[test]
    fn test_dentry_operations() {
        let db = test_db();
        let parent = 1;

        let ino1 = db
            .insert_inode(libc::S_IFREG | 0o644, 1000, 1000, 0, 1)
            .unwrap();
        let ino2 = db
            .insert_inode(libc::S_IFREG | 0o644, 1000, 1000, 0, 1)
            .unwrap();

        db.insert_dentry(parent, "file1", ino1).unwrap();
        db.insert_dentry(parent, "file2", ino2).unwrap();

        let fetched_ino = db.get_dentry_inode(parent, "file1").unwrap().unwrap();
        assert_eq!(fetched_ino, ino1);

        let dentries = db.list_dentries(parent).unwrap();
        assert_eq!(dentries.len(), 2);

        // Rowid-cookie pagination: first page of 1, then resume after its rowid.
        let page1 = db.list_dentries_rowid_after(parent, 0, 1).unwrap();
        assert_eq!(page1.len(), 1);
        let page2 = db
            .list_dentries_rowid_after(parent, page1[0].0, 10)
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert_ne!(page1[0].1, page2[0].1, "pages must not overlap");
        let page3 = db
            .list_dentries_rowid_after(parent, page2[0].0, 10)
            .unwrap();
        assert!(page3.is_empty(), "listing must terminate");

        let plus = db.list_dentries_rowid_after_plus(parent, 0, 10).unwrap();
        assert_eq!(plus.len(), 2);
        assert_eq!(
            plus[0].0, page1[0].0,
            "readdir and readdirplus must share the same rowid cookie"
        );

        let parent_ino = db.get_parent_inode(ino1).unwrap();
        assert_eq!(parent_ino, parent);
    }

    #[test]
    fn test_file_chunks_operations() {
        let db = test_db();
        let ino = db
            .insert_inode(libc::S_IFREG | 0o644, 1000, 1000, 200, 1)
            .unwrap();

        db.insert_chunk_indices_batch(&[
            (
                "obj1".to_string(),
                "hash1".to_string(),
                b"key1".to_vec(),
                0,
                "aes-gcm".to_string(),
            ),
            (
                "obj2".to_string(),
                "hash2".to_string(),
                b"key2".to_vec(),
                0,
                "aes-gcm".to_string(),
            ),
        ])
        .unwrap();

        db.insert_file_chunk(ino, 0, "obj1", 100, 0).unwrap();
        db.insert_file_chunk(ino, 100, "obj2", 100, 0).unwrap();

        let chunks = db.get_file_chunks(ino).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, "obj1");
        assert_eq!(chunks[0].1, 0); // offset
        assert_eq!(chunks[1].0, "obj2");
        assert_eq!(chunks[1].1, 100);

        let by_hash = db.get_chunk_by_hash("hash1").unwrap().unwrap();
        assert_eq!(by_hash.0, "obj1");

        let used = db.get_all_used_chunks().unwrap();
        assert!(used.contains("obj1"));
        assert!(used.contains("obj2"));
    }

    #[test]
    fn test_xattr_operations() {
        let db = test_db();
        let ino = db
            .insert_inode(libc::S_IFREG | 0o644, 1000, 1000, 0, 1)
            .unwrap();

        db.set_xattr_with_flags(ino, "user.key1", b"val1", XattrFlag::Create)
            .unwrap();
        db.set_xattr_with_flags(ino, "user.key2", b"val2", XattrFlag::Create)
            .unwrap();

        let val1 = db.get_xattr(ino, "user.key1").unwrap().unwrap();
        assert_eq!(val1, b"val1");

        let mut attrs = db.list_xattr(ino).unwrap();
        attrs.sort();
        assert_eq!(attrs, vec!["user.key1", "user.key2"]);

        db.remove_xattr(ino, "user.key1").unwrap();
        assert!(db.get_xattr(ino, "user.key1").unwrap().is_none());
    }

    #[test]
    fn test_update_inode_attr_and_size() {
        let db = test_db();
        let ino = db
            .insert_inode(libc::S_IFREG | 0o644, 1000, 1000, 0, 1)
            .unwrap();

        db.update_inode_size(ino, 500).unwrap();
        let info1 = db.get_inode(ino).unwrap().unwrap();
        assert_eq!(info1.3, 500); // size

        db.update_inode_attr(
            ino,
            Some(libc::S_IFREG | 0o755),
            Some(2000),
            Some(2000),
            None,
        )
        .unwrap();
        let info2 = db.get_inode(ino).unwrap().unwrap();
        assert_eq!(info2.0, libc::S_IFREG | 0o755);
        assert_eq!(info2.1, 2000);
        assert_eq!(info2.2, 2000);
    }

    #[test]
    fn test_atomic_unlink_and_rename() {
        let db = test_db();
        let parent = 1;

        let ino = db
            .insert_inode(libc::S_IFREG | 0o644, 1000, 1000, 0, 2)
            .unwrap();
        db.insert_dentry(parent, "f1", ino).unwrap();
        db.insert_dentry(parent, "f2", ino).unwrap();

        // Unlink one
        let (u_ino, nlink) = db.atomic_unlink(parent, "f1", false).unwrap();
        assert_eq!(u_ino, ino);
        assert_eq!(nlink, 1);

        // Rename the other
        let dir_ino = db
            .insert_inode(libc::S_IFDIR | 0o755, 1000, 1000, 0, 2)
            .unwrap();
        db.atomic_rename(parent, "f2", dir_ino, "f2_renamed", None)
            .unwrap();

        assert!(db.get_dentry_inode(parent, "f2").unwrap().is_none());
        let new_ino = db.get_dentry_inode(dir_ino, "f2_renamed").unwrap().unwrap();
        assert_eq!(new_ino, ino);
    }

    #[test]
    fn test_atomic_unlink_directory() {
        let db = test_db();
        let parent = 1;

        let dir_ino = db
            .insert_inode(libc::S_IFDIR | 0o755, 1000, 1000, 0, 2)
            .unwrap();
        db.insert_dentry(parent, "dir1", dir_ino).unwrap();

        let file_ino = db
            .insert_inode(libc::S_IFREG | 0o644, 1000, 1000, 0, 1)
            .unwrap();
        db.insert_dentry(dir_ino, "file1", file_ino).unwrap();

        // Fails if enforce_empty_dir = true
        let res = db.atomic_unlink(parent, "dir1", true);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "ENOTEMPTY");

        // Succeeds if enforce_empty_dir = false
        assert!(db.atomic_unlink(parent, "dir1", false).is_ok());
    }

    #[test]
    fn test_snapshot_operations() {
        let db = test_db();

        let snaps = db.list_snapshots().unwrap();
        assert!(snaps.is_empty());

        db.create_snapshot("test_snap").unwrap();

        let snaps_after = db.list_snapshots().unwrap();
        assert_eq!(snaps_after.len(), 1);
        assert_eq!(snaps_after[0].1, "test_snap");

        let snap_id = snaps_after[0].0;

        let temp_out = std::env::temp_dir().join(format!("snap_out_{}.db", std::process::id()));
        db.extract_snapshot(snap_id, temp_out.to_str().unwrap())
            .unwrap();
        assert!(temp_out.exists());
        let _ = std::fs::remove_file(temp_out);

        db.delete_snapshot(snap_id).unwrap();
        assert!(db.list_snapshots().unwrap().is_empty());
    }

    #[test]
    fn unlink_last_link_removes_inode_and_chunks() {
        let db = test_db();
        let parent_ino = 1;
        let ino = db
            .insert_inode(libc::S_IFREG | 0o644, 0, 0, 100, 2)
            .unwrap();
        db.insert_dentry(parent_ino, "testfile", ino).unwrap();
        db.insert_dentry(parent_ino, "testfile2", ino).unwrap();
        db.insert_chunk_indices_batch(&[(
            "h0".to_string(),
            "ph0".to_string(),
            b"k".to_vec(),
            0,
            "aes-gcm".to_string(),
        )])
        .unwrap();
        db.insert_file_chunk(ino, 0, "h0", 100, 0).unwrap();

        let (unlinked_ino, nlink1) = db.atomic_unlink(parent_ino, "testfile", false).unwrap();
        assert_eq!(unlinked_ino, ino);
        assert_eq!(nlink1, 1);
        assert!(db.get_inode(ino).unwrap().is_some());

        let (_, nlink2) = db.atomic_unlink(parent_ino, "testfile2", false).unwrap();
        assert_eq!(nlink2, 0);

        db.delete_inode(ino).unwrap();
        assert!(db.get_inode(ino).unwrap().is_none());
        assert!(db.get_file_chunks(ino).unwrap().is_empty());
    }
}
