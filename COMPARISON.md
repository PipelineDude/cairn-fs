# Cairn vs. established backup tools

Honest positioning against restic, BorgBackup, Kopia, bupstash and duplicity (2026-07).
Written to answer one question: *when is Cairn the right choice, and when is it not.*

## The three properties that define Cairn

| Property | restic | borg | kopia | bupstash | duplicity | **cairn** |
|---|---|---|---|---|---|---|
| **Write-only backup host** (host cannot read what it backed up) | ✗ symmetric repo key | ✗ symmetric | ✗ symmetric | ✅ put-key model | ✅ GPG public-key | ✅ age X25519 envelope |
| **Live mount** | read-only FUSE | read-only FUSE | read-only FUSE | ✗ none | ✗ none | ✅ **read/write** FUSE |
| **Cross-provider redundancy** | ✗ (one repo = one backend) | ✗ | ✗ | ✗ | ✗ | ✅* RAID-0/1/5/6/10 across S3/GCS/Azure/FS with parity reconstruction + auto-heal |

\* implemented, but the cloud path has not yet been exercised end-to-end against real object storage (see `OPERATING.md` §9) — treat as beta until the cloud pilot.

No competitor has more than one of the three. That combination — back up from an
untrusted host, browse/edit the archive as a normal filesystem, and survive the
loss of an entire storage provider — is the reason Cairn exists.

## Where the established tools win (know this before choosing Cairn)

- **Maturity and trust.** restic/borg/kopia have a decade of production use, huge
  user bases, fuzzing, and (for borg/restic) informal security reviews. **Cairn is
  pre-1.0, single-team, and has had no external cryptographic audit** — do not treat
  it as crypto-reviewed for sole-copy critical data.md` show residual design limits (client-side
  append-only, no inventory MAC, index SPOF).
- **Ransomware-hardened storage.** restic (rest-server `--append-only`) and borg
  (`borg serve --append-only`) enforce immutability in a *server* process. Cairn gates
  destruction on the **key model** instead: on asymmetric archives gc / snapshot rm /
  prune require the master (private) key, so a compromised public-key-only backup host
  cannot destroy history through the tool at all (plus a one-way append-only flag for
  symmetric archives). Content-addressed write-once chunks pair cleanly with bucket
  immutability (S3 Object Lock) — but there is no server component of its own, so on
  a plain dumb backend an attacker holding raw storage credentials can still delete data.
- **Multi-client repositories.** restic and kopia support many machines backing
  up concurrently into one deduplicated repository. Cairn is single-process per
  archive (advisory `flock`); dedup is per-archive.
- **Ecosystem.** restic+rclone reaches ~any storage; borg has borgmatic and years
  of tooling; kopia has a GUI. Cairn has a CLI (a GUI is on the roadmap).
- **Proven performance.** Their throughput/memory numbers are benchmarked by
  thousands of users. Cairn's are measured only by its own smoke tests.

## Parity (nothing lost by choosing Cairn here)

- **Content-defined dedup:** FastCDC (restic: Rabin; borg: buzhash; kopia/bupstash: CDC variants).
- **Compression:** zstd/lz4 per chunk, recorded per chunk (cipher too — old archives survive default changes).
- **AEAD encryption:** AES-256-GCM / ChaCha20-Poly1305 per chunk; encrypted (SQLCipher) metadata index.
- **Snapshots + GFS retention, GC with grace period, integrity scrub** — all present.
- **Verify-and-repair:** Cairn's scrub reconstructs corrupt chunks from RAID parity/mirrors
  and re-uploads (`--auto-heal`); restic/borg detect corruption but cannot repair without another copy.

## Closest relative: bupstash

bupstash pioneered the write-only model (put-key cannot decrypt or list). Differences:
bupstash has no mount at all and no multi-cloud RAID, and its author explicitly caps
its scope. (Neither tool has a Windows/macOS story today — Cairn's is a roadmap item.)
Cairn trades bupstash's minimalism for a bigger feature surface — which is both its
value and its risk.

## Honest bottom line

- Production data today, boring requirements → **restic or borg** (or kopia for the GUI).
- Untrusted backup sources, no mount needed, minimalist → **bupstash**.
- Write-only hosts **plus** a browsable read/write archive **plus** surviving a
  cloud provider's death, and you accept a young codebase → **Cairn** — after it
  gets an external crypto review (append-only mode exists; pair it with an
  object-locked bucket for server-side immutability).
