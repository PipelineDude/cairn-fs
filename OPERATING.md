# Operating Cairn (pilot runbook)

A practical guide for running Cairn on real data during **test operation**. It assumes the
local (non-cloud) path; the S3/GCS RAID path is not yet exercised end-to-end.
Start a pilot on a **second** copy of data, never the only one.

## 0. The one rule

> A backup you have never restored is not a backup. Do a restore drill before you trust it,
> and repeat it on a schedule. Cairn gives you `verify` (below) so you don't have to wait for
> restore day to learn a backup is incomplete.

## 1. Set up

```bash
cargo build --release
# Asymmetric (recommended): back up from an untrusted host, restore only where the key lives.
cargo run --release -p cairn-keys --bin gen_keys      # writes pub.pem + priv.pem
#   → keep priv.pem OFF the backup host. Consider splitting it (§5).
export CAIRN_PASSWORD='a-strong-index-password'   # avoids passing --password in argv (ps-visible)
./target/release/cairn backup.db init --pub-key pub.pem
#   ^ the key model is FIXED at init: --pub-key here = asymmetric archive
#     (write-only hosts possible); init with only the password = symmetric
#     forever. The password must be present at init too — without one the
#     metadata index is stored unencrypted (cairn warns).
```

For a single-machine pilot with no key management, symmetric mode is fine (one password unlocks
everything — no write-only property): just omit `--pub-key` everywhere.

To also hide **file names** from the backup host, add `--hide-names` to the asymmetric `init`
(`cairn backup.db init --pub-key pub.pem --hide-names`). Fixed at init; names then need the
**private key** to read (the password alone no longer shows the real tree — a deliberate DR
trade-off). Sizes, tree shape, timestamps and xattr values stay visible. Details + threat
boundary: `HIDE_NAMES.md`.

## 2. Back up

```bash
# Index is the map SPOF: COPY the .db off-host. Never try to rebuild the tree from chunks.
mkdir -p /offsite/cairn-index
export CAIRN_INDEX_BACKUP=/offsite/cairn-index   # or pass --index-backup each time

# Direct ingestion (fast path):
cairn backup.db backup /data/to/protect --pub-key pub.pem \
    --index-backup /offsite/cairn-index \
    --auto-snapshot
#   Exit code is authoritative: 0 = every file stored, non-zero = at least one file NOT
#   backed up (the archive is intact — failed files are skipped, not half-written).
#   Index backup failure after a successful data write also exits non-zero.
#   ALWAYS check $? in cron:
cairn backup.db backup /data --pub-key pub.pem --index-backup /offsite/cairn-index \
    || mail -s 'CAIRN BACKUP FAILED' you@host <<<"see logs"

# One-shot index copy (no data walk):
cairn backup.db index-backup /offsite/cairn-index
# status shows Last index backup path/ts

# Rotation: when the destination is a DIRECTORY each run writes a timestamped copy
# (<archive>.indexbak.<unix>) and they accumulate. Keep only the newest N with
# --index-backup-keep (or CAIRN_INDEX_BACKUP_KEEP); 0 = keep all (the default):
cairn backup.db index-backup /offsite/cairn-index --keep 7
cairn backup.db backup /data --pub-key pub.pem \
    --index-backup /offsite/cairn-index --index-backup-keep 7
```

## 3. Verify (do this — it is the pilot's whole point)

```bash
cairn backup.db verify --pub-key pub.pem --priv-key priv.pem
#   Reads and DECRYPTS every *indexed* file's chunks. Exit non-zero = some file is not
#   restorable (missing/corrupt chunk, incomplete backup marker, …).
#   Needs the read key — it proves *restorability of what is in the index*, not that no
#   inventory entry was deleted (there is no whole-archive signature — THREAT_MODEL).
```

**Warm cache ≠ offsite.** On a backup host, read path is local cacache first, then cloud
(ARCHITECTURE). A green `verify` immediately after `backup` may only prove the **local cache**.
To prove offsite durability:

```bash
cairn backup.db push
# cold check: either wipe/rename the cache dir, or:
cairn backup.db verify --force-remote --pub-key pub.pem --priv-key priv.pem
# and/or restore drill on a *different* machine (§4)
```

Optional ops completeness: `verify --expect-min-files N` (compare to printed
`Indexed regular files after backup` from the backup run).

`verify` vs `scrub`: `scrub` checks chunks exist and hash-match (with cloud backends it
forces remote read); `verify` checks every *file* decrypts. Run both.

## 4. Restore drill (run before trusting Cairn, then periodically)

```bash
# Whole archive to a scratch dir, then diff against the source (asymmetric
# archives need --pub-key on every command, plus --priv-key to read):
cairn backup.db extract /scratch/restore --pub-key pub.pem --priv-key priv.pem
diff -r /data/to/protect /scratch/restore && echo "RESTORE OK"

# Single file (lands at /scratch/<basename>) / glob without mounting:
cairn backup.db extract /scratch --file-path '/data/report.pdf' --pub-key pub.pem --priv-key priv.pem
```

Do the drill on a **different machine** with only the archive + `priv.pem` + password present —
that is the scenario the whole design is for, and the only way to know it works.

## 5. Protect the keys (there is no reset)

Losing `priv.pem` loses every asymmetric backup; losing `--password` locks the index. Neither
can be reset — by design. Split the private key so no single loss is fatal:

```bash
gen_keys split priv.pem 2 3          # 3 shares, any 2 rebuild → share_1..3.bin
gen_keys combine priv.pem share_1.bin share_3.bin
```

Distribute shares across separate custody (people / locations / safes).

## 6. Ransomware hardening

**Hard prerequisite for the ransomware claim:** server-side immutability on the chunk/index
store (S3 Object Lock Compliance mode, GCS retention, or WORM). CLI append-only and
pub-only key gating are **client-side only** — raw credentials or SQLCipher+password can still
destroy history (README Honest limits, THREAT_MODEL, COMPARISON).

```bash
cairn backup.db append-only          # one-way CLI ratchet: gc / snapshot rm / prune refused
# also: Object Lock / retention on the bucket BEFORE production data
```

On an **asymmetric** archive, destructive ops through Cairn require the master (private) key,
so a pub-only host cannot `gc` / `snapshot rm` / `init --force`. That is necessary but **not
sufficient** without server-side immutability.

## 7. Health check (what to watch during the pilot)

```bash
cairn backup.db status               # shows last operations (from backup.db.log), snapshots, sizes
```

The `--- Last operations ---` block is your daily signal: confirm the latest `BackupFinished`
is recent and a `ScrubFinished`/verify ran with `corrupted=0`. The machine-readable event log is
`backup.db.log` (one JSON object per line) — point your monitoring at it.

**Watch during a pilot:** daemon RSS over days (a soak test is `tests/soak.sh`), free disk on
the cache/archive volume, and that `verify` stays green. Snapshots each cost ~the DB size, so
prune on a schedule (`snapshot prune --keep-daily N ...`) unless append-only.

**Run `gc` periodically if your data churns.** Deleting or overwriting a file does NOT reclaim its
old chunks — they linger until garbage collection. Without periodic `gc`, an archive under churn
grows without bound (disk *and* the daemon's memory, which tracks the index), even though only the
current files are live. This is by design (it's what makes snapshots and dedup cheap), but it means:

```bash
cairn backup.db gc --grace-period-hours 24    # reclaim chunks no live file/snapshot references
```

Measured behavior (`tests/soak.sh`): with a stable working set (data that dedups) RSS plateaus flat
and file descriptors are constant — no leak. With continuous *new* data and no `gc`, RSS climbs with
the archive. So: schedule `gc`. (`gc` is refused on append-only archives and on asymmetric archives
without the master key — that is the ransomware protection; run it from a trusted, keyed host.)

## 8. Concurrency & safety rails

- One writer per archive: `<archive>.lock` takes **exclusive** flock for backup/gc/snapshot
  mutate/mount/push/pull/init and **shared** for verify/extract/status. Don't point two writers
  at one archive.
- `snapshot rollback` requires `--i-accept-non-atomic`, auto-snapshots current state, and writes
  `archive.db.pre-rollback.bak` before the DB file swap. **Never** on the sole copy; residual
  non-atomic window is documented in ARCHITECTURE.
- Kill-9 / power loss loses at most the last un-`fsync`'d write, never a corrupt file
  (`ARCHITECTURE.md` → *Crash & failure consistency*). An interrupted `backup` resumes on re-run;
  incomplete mid-file is flagged by `verify` (F-19).
- **Index is SPOF:** **copy** the `.db` (and password custody) separately from chunks —
  `backup --index-backup DIR`, `index-backup DIR`, or `CAIRN_INDEX_BACKUP`. Losing the index or
  password makes chunks unusable; **do not** try to rebuild the tree from ciphertext chunks.

## 9. Known pilot-phase limits

| Area | Status |
|------|--------|
| Local asymmetric content + CLI gates | Pilot-ready with restore drills |
| Cloud (S3/GCS RAID, pull, auto-heal) | Exercised against local MinIO in-tree (`tests/cloud_*.sh`); treat multi-cloud production as **beta** until your own cold verify + second-machine drill |
| External cryptographic audit | **Not done** — pre-1.0 |
| Whole-archive inventory MAC | **Not present** — verify ≠ completeness of past inventory |
| Snapshot rollback crash window | Residual; requires `--i-accept-non-atomic` + offline bak |
| Linux only (fuse3) | Windows/macOS roadmap |

- Create throughput is ~450 small files/s (fine for most data; slow for millions of tiny files).
- **`backup` skips special files** (FIFO/socket/device) with a **WARNING**; use `--strict` to
  fail instead. Recreate specials out of band on restore. Regular files, dirs, symlinks,
  hardlinks, perms, mtimes, xattrs are preserved (`--preserve` for owner/timestamps/xattrs).
