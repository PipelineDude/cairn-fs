# Cairn Architecture

Cairn is an encrypted, deduplicated backup filesystem exposed over FUSE. This document describes how it is built
and how data flows through it.

## Workspace layout

Cairn is a Cargo workspace. The binary is `cairn` (root `src/main.rs`, the CLI). All logic lives in `crates/`:

| Crate | Responsibility |
|---|---|
| `cairn-seal`  | On-disk crypto format: age X25519 key-wrap, AES-256-GCM / ChaCha20-Poly1305 chunk encryption, zstd/lz4 compression, convergent/keyed dedup-key derivation. |
| `cairn-index` | Metadata: SQLCipher store of inodes, dentries, the chunk map (`chunk_index`, `file_chunks`), xattrs and snapshots (r2d2 pool). |
| `cairn-store` | Chunk storage read path (local `cacache` → S3/GCS fallback) and the shared `CloudOperator`. |
| `cairn-cdc`   | Chunking + write pipeline: FastCDC, dedup lookup, per-chunk encrypt, and RAID upload to storage backends. |
| `cairn-core`  | The filesystem engine: `CairnEngine` with read/write/RMW/flush, lookup/getattr/…, gc/scrub, snapshots, extract. |
| `cairn-fuse`  | Thin fuse3 adapter (`CairnFs` wraps `cairn-core::CairnEngine` and implements `Filesystem` by delegation). |
| `cairn-keys`  | `gen_keys` binary: age keypair generation + Shamir split/combine of the master secret. |

Dependency direction is strictly downward: `main → cairn-fuse → cairn-core → {cdc, store, index} → seal`.

## Write path (backing up)
1. FUSE `write()` buffers data per inode (`FileWriteState`), guarded by the per-inode `write_locks` mutex.
   A buffer is flushed once it exceeds `--write-buffer-inode-mb` (16 MB default) **or** once the global
   byte counter across all buffers exceeds `--write-buffer-global-mb` (128 MB default). The global limit
   is enforced by the writer flushing **its own** buffer synchronously — never by sleep-waiting, which
   would deadlock once many files each hold a sub-threshold buffer. `release`/`fsync` take the same
   per-inode write lock *before* snapshotting the buffer, so flush + clear + counter-decrement is atomic
   with respect to concurrent writes (lock order everywhere: `write_locks` → buffer state).
2. On flush / `release` / `fsync`, `flush_range` does a read-modify-write of the touched byte range.
3. `cairn-cdc` splits the range into chunks with **FastCDC** (min 16 KiB / avg 64 KiB / max 256 KiB).
4. For each chunk it derives a **per-chunk symmetric key**: convergent `BLAKE3-keyed(dedup_secret, chunk_bytes)`
   (so identical content dedups), or a random key on archives created with `init --disable-dedup` (mode stored in
   config as `dedup_mode`). In convergent mode it then does a **dedup lookup** by content hash and skips storing
   chunks already present; in random mode every chunk is stored fresh.
5. New chunks are **compressed** (zstd/lz4) and **encrypted** (AES-256-GCM or ChaCha20-Poly1305, per `--crypto-algo`)
   with the per-chunk key. The cipher used is recorded per chunk so a later default change does not break old backups.
6. The per-chunk key is **wrapped with the age X25519 recipient** (`--pub-key`) — this is the envelope.
7. The encrypted chunk is written to the local `cacache` store and, if configured, uploaded to S3/GCS (RAID-0/1/5/6/10
   across buckets). `push`, `daemon` and `backup` upload asynchronously in the background to unblock local writes
   (there is no separate flag). Chunk metadata (content hash, offset, wrapped key, cipher, compression type) is
   recorded in the SQLCipher index.

## Read path (restoring)
1. Look up the file's chunks in the index (ordered by offset).
2. For each chunk: fetch from the local cache or, on miss, from S3/GCS. If a corrupted chunk is found on a cloud backend, it is mathematically reconstructed via RAID parity/mirrors. With `--auto-heal`, the reconstructed chunk is automatically re-uploaded to heal the remote backend.
3. If `--dangerously-skip-verify` is used (extract/restore), the hash validation and auto-healing are bypassed for maximum performance on trusted storage.
4. **Unwrap the per-chunk key with the age private key** (`--priv-key`); decrypt; decompress; place its bytes at the right offset.
5. `extract_all` streams chunk-by-chunk straight to the output file (never buffers a whole file in RAM).

## Concurrency model

- **Crypto operations** use `parking_lot::Mutex` (not `std::sync::Mutex`) to avoid lock poisoning. A panic in a
  critical section (e.g. age decryption) recovers the inner value instead of killing the daemon. See `cairn-seal`.
- **Write buffers** are per-inode, guarded by `DashMap<u64, Arc<tokio::sync::Mutex<FileWriteState>>>`. The
  per-inode write lock order is always `write_locks → buffer state` to prevent deadlock. Global backpressure
  uses an `AtomicUsize` counter — the writer that exceeds the budget flushes its own buffer synchronously.
- **GC** rate-limits cloud deletes with a `tokio::sync::Semaphore(16)`. Permits are explicitly `drop()`ed
  after each operation to guarantee release even if the task panics.
- **readdir/readdirplus** use stateless rowid-cookie pagination: an entry's FUSE offset is its dentry
  **rowid + 2** (`list_dentries_rowid_after[_plus]`), so a continuation call resumes after `offset - 2`
  with no server-side state. Rowids don't shift on concurrent create/unlink (unlike `LIMIT/OFFSET`), and
  the same cookie must be used by BOTH calls — the kernel may start a listing via readdirplus and continue
  via plain readdir (READDIRPLUS_AUTO), which is exactly how a per-call cursor map breaks.
- **`--hide-names` (optional, asymmetric archives).** The `dentries.name` column is a *lookup key*: the
  plaintext name in normal archives (byte-identical layout), or `BLAKE3-keyed(name_secret, LE64(parent)‖name)`
  when hiding. A second column `name_enc` holds the age-encrypted real name (write-only, `NULL` in normal
  archives). The engine translates `name → name_lookup_key(parent,name)` at every keyed boundary (lookup,
  unlink, rename, link, insert) and decrypts `name_enc` on read paths (readdir/extract); both are the
  identity/`None` when hiding is off. `name_secret` lives in the SQLCipher config. See `HIDE_NAMES.md`.

## Memory safety & secret handling

- **Crypto keys** use `zeroize::Zeroizing<Vec<u8>>` throughout the LRU symmetric-key cache and in `FileWriteState`
  buffers. Stack-allocated intermediate key material is manually zeroized after use (`key.zeroize()`).
- **age `Identity`** — the private key struct — owns its secret scalar behind `secrecy` and zeroizes in its own
  `Drop`. Do NOT overwrite its bytes manually (`from_raw_parts_mut` + `zeroize()`): that corrupts internal
  pointers and segfaults on drop.
- **`CryptoCtx::zeroize_keys()`** is called from `CairnEngine::destroy()` on FUSE unmount.

## Key invariants

- `flush_range` clears inline data **in the same SQLite transaction** as `replace_file_chunks`. If the process
  crashes between writing chunks and updating metadata, the inline data remains valid and the file is readable.
- If `flush_range` fails during `write()`, the inode size is NOT updated — otherwise a crash would leave a file
  claiming a larger size than the sum of committed chunks, producing zero-fill reads on recovery.

## Crash & failure consistency (what survives a kill -9, disk-full, or lost storage)

The archive is two layers: the **SQLCipher index** (the source of truth) and the **content-addressed chunk
store** (cacache locally, optionally S3/GCS). Chunks are immutable and named by hash, so a chunk is only ever
*added*, never mutated — a half-written chunk is a stray blob no metadata points at, not corruption.

- **Crash mid-write / power loss.** The index is SQLite in WAL mode: a metadata transaction either commits whole
  or not at all. A file becomes durable when its `replace_file_chunks` transaction commits; before that the file
  reads at its previous committed state. `fsync` forces the write buffer to durable chunks + a committed index.
  Worst case on an un-`fsync`'d crash is losing the last un-flushed write, never a corrupt or partially-updated file.
- **Disk full / storage write failure.** Chunk write fails → the file's flush fails → its size is not advanced and,
  for `cairn backup`, the file is skipped and the command exits **non-zero** (a cron job sees the failure). The
  existing archive is untouched — failed files are skipped, never half-committed. (Covered by the e2e smoke.)
- **Interrupted `cairn backup`.** Each file commits independently; killing a backup leaves every already-committed
  file intact and simply omits the rest. Re-running resumes — dedup skips the chunks already stored. There is no
  global "backup transaction" to leave dangling.
- **Lost / corrupted chunk in the store.** Detected at read time by AEAD (decryption fails rather than returning
  wrong bytes). With cloud RAID (1/5/6/10) the chunk is reconstructed from mirrors/parity, and `--auto-heal`
  re-uploads it. Without redundancy a lost chunk is an `EIO` on the affected file — other files are unaffected.
- **`.lock` + WAL sidecars.** An advisory `flock` serializes destructive ops (see below); `snapshot rollback`
  checkpoints and truncates the WAL before swapping the DB file so no stale page is written into the new archive.
- **Not fully guarded:** there is no whole-archive signature (verify proves indexed files only).
  `snapshot rollback` requires `--i-accept-non-atomic`, writes `*.pre-rollback.bak`, fsyncs the
  offline copy, then renames a materialised snapshot DB over the archive — residual crash window
  remains; never use on the sole copy. `verify --force-remote` bypasses local cache for offsite proof.
- **Locks:** write commands take exclusive `flock` on `<archive>.lock`; read commands take shared.

## Security model

See `SECURITY.md`, `THREAT_MODEL.md`.
- **Chunk store:** content-addressed encrypted blobs in `cacache` (local) and/or S3/GCS.
- **Index:** a SQLCipher database (`--password`) holding inodes, dentries, `chunk_index`, `file_chunks`, xattrs and
  snapshots.
- **Chunk-key wrapping:** age X25519 (`--pub-key`/`--priv-key`), or — in password-only mode — a random per-archive
  KEK (AES-256-GCM, `CKEK1` format) that is itself wrapped once with the passphrase via an age scrypt envelope stored
  in config `wrapped_kek`. One scrypt per mount; never one per chunk key. See `SECURITY.md`.
