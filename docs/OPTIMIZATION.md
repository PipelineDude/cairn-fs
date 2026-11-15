# Cairn optimization notes (2026-11-13)

Performance work done after the security rounds. Baseline measurements on the
local dev machine (CAIRN_KDF_ITER=1000, release build, LTO fat):

| Workload | Before | After | Notes |
|---|---|---|---|
| Backup 98 MB (200 files) | 1.61 s, 56 MB RSS | unchanged | already fast |
| Backup 100 k small files (391 MB) | 46.8 s | — | ~2 136 files/s; dominated by SQLCipher per-file commits |
| Extract 98 MB | 0.31 s, 32 MB RSS | unchanged | |
| Verify 98 MB | 0.54 s | unchanged | |
| Scrub 98 MB | 0.16 s | unchanged | |
| FUSE `ls -l` 100 k files | 17.2 s | 17.2 s (reverted 4096 batch) | 1000-entry batches are optimal for SQLCipher |
| FUSE `stat` 1000 distinct files | 8.58 s | 8.66 s (no gain) | cold, disk-bound on 464 MB index |

## Changes shipped

1. **FUSE metadata cache** (`cairn-core/src/lib.rs`, `meta_cache`).
   - `getattr` consults a 100 ms TTL `DashMap<u64, (FileAttr, Instant)>` before
     hitting SQLCipher.
   - Invalidated on every mutation: `write`, `setattr`, `mkdir`, `mknod`,
     `create`, `unlink`, `rename`, `link`, `release`.
   - Helps repeated `stat`/`getattr` on the same inode; cold bulk `stat` of
     distinct inodes is still disk-bound and unchanged.
   - All 13 `CairnEngine` construction sites updated (2 prod + vfs + 10 tests).

2. **`--no-fsync` for `backup`** (`src/main.rs`).
   - Skips the per-file `engine.fsync()` call, relying on the SQLCipher WAL
     commit for metadata durability and cacache's default (no per-chunk fsync)
     for chunk blobs.
   - Measured gain is small (fsync was ~16 % of time and SQLite still fsyncs
     on commit); the flag exists for hosts that want maximum throughput on
     trusted storage. Default keeps fsync on (durability).
   - `--db-synchronous OFF|NORMAL|FULL|EXTRA` remains the bigger lever.

3. **Readdir batch size experiment.**
   - Tried 1000 → 4096 entries per `list_dentries_rowid_after[_plus]` call.
   - Result: 4096 was *slower* (25.4 s vs 17.2 s for `ls -l` 100 k), so
     reverted to 1000. Documented so nobody re-tries it blindly.

4. **Index bloat investigation.**
   - 100 k tiny (≈ 40 B) files produce a 464 MB SQLCipher index (~4.6 KB/file).
   - `VACUUM` shrinks it by only 0.5 % — the size is real data, not free pages
     (one age-wrapped inline envelope per file inside SQLCipher pages).
   - Root cause is architectural: small files are stored inline in the index.
     Shrinking it would require moving inline data into the chunk store, which
     changes the read path and breaks the "small file = single-row read"
     property. Not attempted; recorded as a known trade-off.

## What was NOT changed (and why)

- **SQLCipher synchronous mode default** stays `FULL`. Changing it to `NORMAL`
  would give ~2× on HDD but weakens crash durability; the flag is already
  exposed (`--db-synchronous`).
- **Per-file commit batching** (one transaction per N files) would cut fsync
  count ~5× but breaks the per-file crash-safety invariant documented in
  `ARCHITECTURE.md` ("each file commits independently; killing a backup leaves
  every already-committed file intact"). Not attempted without an explicit
  product decision.
- **FUSE kernel caching** (`attr_ttl`/`entry_ttl`) already set to 1 s in the
  adapter; raising it improves `ls` but risks stale metadata after a write on
  another mount. Left at 1 s.
- **Cloud paths** (`sync_index_to_cloud`, `restore_index_from_cloud`) are not
  on the hot backup path and were not profiled.
- **Compression defaults** (zstd level 3) are already a reasonable speed/ratio
  trade-off; `--comp-algo lz4` is available for CPU-bound hosts.

## Recommended next steps if more speed is needed

1. Profile a real workload with `strace -c` and `/usr/bin/time` (perf is
   disabled on this kernel, `perf_event_paranoid=4`).
2. For many-small-files workloads, raise `--db-cache-kb` (default 64 MiB/conn)
   and `--db-pool-size` (default 16) to keep the 464 MB index in RAM.
3. For write-heavy FUSE workloads, consider `--db-synchronous NORMAL` on
   battery-backed / ZFS storage.
4. If the 464 MB index for 100 k tiny files is unacceptable, the fix is
   architectural (move inline data out of SQLCipher) — not a tuning change.
