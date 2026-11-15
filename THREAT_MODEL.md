# Cairn Threat Model

Cairn is an encrypted, deduplicated **backup** tool. Its distinguishing property is **asymmetric (public/private-key)
envelope encryption**: you back up with only a *public* key, and reading requires the *private* key.

> Cairn is **not** an anti-forensic tool. It does not self-destruct, hide, or deny data. The earlier anti-forensic
> layer has been removed from the workspace.

## Assets
- **Backed-up file contents** — confidentiality and integrity.
- **Metadata** — file names, sizes, directory structure, timestamps.
- **Secrets** — the age private key, `--password` (index; in symmetric mode also the data), and the per-archive
  dedup secret (auto-generated at `init`, stored in the encrypted config).

## Core guarantee
Backing up needs only the **public key** (`--pub-key`) for *content* envelope encryption. The machine performing the
backup **cannot decrypt file contents** — it has no private key. Restoring content requires the **private key**
(`--priv-key`), held only on a trusted machine.

This guarantee applies to archive-local asymmetric content envelopes. **Opt-in shared-dedup domains are an
exception:** the domain secret wraps domain chunk keys, and any holder of that secret with access to the wrapped
records and ciphertext can read those chunks without the archive private key. A shared-domain writer therefore
has domain-wide chunk-read capability. Inline data and hidden names still use archive-specific envelopes. Use
archive-local deduplication for untrusted write-only backup hosts.

**Scope of "write-only": content only.** The backup host still holds the **index password**, so it can list and
read **metadata** (names, sizes, tree, xattr values). It is *not* "gets nothing." See Out of scope → Metadata.

> **Optional: `init --hide-names`** (asymmetric archives only) removes *file/dir/symlink names* from this list — they
> become keyed hashes plus write-only age-encrypted blobs, so the backup host can no longer read or enumerate them
> (it can still *confirm a specific guess*, since it holds the name-hashing secret). It does **not** hide tree shape,
> sizes, mtimes, hardlink topology, or **xattr values**. Opt-in, fixed at init. See `HIDE_NAMES.md`.

### Symmetric (password-only) mode weakens this
Without `--pub-key`, chunk keys are wrapped with a per-archive KEK whose passphrase is the same `--password` that
unlocks the index. Convenient (no key management), but the core guarantee above does **not** hold: any host that can
write can also read, and the password becomes the single secret protecting everything. Use asymmetric mode for
untrusted backup hosts; symmetric mode is for a trusted machine backing up to untrusted *storage*.

## In scope — what Cairn protects against
- **Compromise of an archive-local backup host / agent / CI runner.** With only the public key, index password and
  ciphertext, it cannot decrypt past archived content. Source plaintext currently present on that host is readable
  to an attacker who owns it, regardless of archive encryption. Shared-domain secrets grant the chunk-read capability
  described above.
- **Loss or theft of the storage medium / S3 bucket.** Chunks are encrypted; without the private key *and* the index
  password they are unreadable.
- **Tampering with stored chunks.** Each chunk is AEAD (AES-GCM or ChaCha20-Poly1305), so any modification is detected
  at decrypt time (decryption fails rather than returning wrong data).
- **Local disaster.** S3/GCS with RAID-0/1/5/6/10 keeps copies off the source machine.

## Recent hardening (2026-11)

- `verify`/`extract` now also check the stored H09 whole-file digest when present, catching
  under-coverage, chunk splicing and tampering that per-chunk AEAD alone would miss. Legitimate
  sparse files (no chunks, no digest) are no longer flagged as unrestorable.
- `--allow-other` is gated on `user_allow_other` in `/etc/fuse.conf`; without it the mount refuses.
  Even when enabled, a public-key-only host still cannot decrypt, but a *local* OS user on the mount
  host may read decrypted plaintext through the FUSE mount if file modes permit. Treat the mount host
  as trusted or run the mount as a dedicated user.
- Setuid/setgid are stripped on extract unless `--preserve`; `security.*`/`trusted.*` xattrs are never
  restored. `extract_matching` refuses to traverse pre-existing symlinks in the destination.
- `--hide-names` detects transplanted `name_enc` and falls back to the opaque hash.
- `scrub` validates the sealed chunk-key record and AEAD when a key is available.
- `--to-source` requires explicit acknowledgement and refuses protected system paths.
- `push`/`pull` carry a monotonic revision and archive identity; `pull` refuses stale/foreign indices.
- Shared-dedup secrets must be at least 32 bytes. Snapshots have an opt-in quota
  (`--snapshot-quota` / `CAIRN_SNAPSHOT_QUOTA`, default unlimited) to guard against snapshot spam.

## Out of scope — what Cairn does NOT protect (know these)
- **A compromised restore machine.** It holds the private key and password → full read access. Protect the private
  key; restore only on trusted machines.
- **Seizure of a machine that has the keys.** With the private key + password present, the data is readable. Cairn has
  no self-destruct, duress mode, or plausible deniability.
- **Metadata exposure.** Names, sizes, tree structure and **extended-attribute (xattr) values** live in the SQLCipher
  index. It is encrypted at rest with `--password`, but a leaked password or DB exposes this metadata (so a public-key-only
  backup host, which holds the password, can see it — but never file *content*, which is envelope-encrypted). Chunk sizes
  can leak coarse information about content. If xattr values are themselves sensitive, do not rely on the write-only
  property to hide them — they are protected at the metadata (password) level, like file names, not the content level.
  *Names* specifically can be upgraded to write-only hiding with `init --hide-names` (see `HIDE_NAMES.md`); sizes, tree,
  timestamps, hardlink topology and **xattr values** remain at the metadata level even then.
- **Dedup confirmation attacks.** An attacker who obtains the archive's dedup secret (it lives in the
  SQLCipher config, so this requires the index password) and a candidate file can test whether that file is present
  (its chunk hashes will match). Create the archive with `init --disable-dedup` to remove that lookup. Separately,
  the stored per-file H09 digest is an unkeyed BLAKE3 of the whole logical file, so an index reader can still test
  candidate whole files against it even with `--disable-dedup`. File metadata and compressed/padded sizes can also
  reveal information; disabling deduplication does not hide those channels.
- **Secrets on the command line.** `--password` passed in argv is visible in `ps`. Prefer `--password-file` or
  `CAIRN_PASSWORD` on shared hosts (see `SECURITY.md`).
- **Concurrent multi-node writes (experimental, cloud only).** When the same archive
  is mounted by more than one process against a shared cloud backend, an **atomic
  conditional write** (`opendal write_with(if_not_exists)`) gates write opens on a
  per-inode lock object — a backend that supports conditional PUT (S3, GCS) makes
  this race-free; one that does not falls back to a plain write (same risk as a
  racy lock, no worse). Multi-node is still outside the tested/supported target;
  the single-process advisory `flock` on `<archive>.lock` remains the primary guard.
- **Whole-archive integrity / availability.** An attacker with write access to the storage can delete chunks (detected
  as missing/short on read) but there is no single signature binding the whole archive together. **Mitigation:**
  on asymmetric archives destructive operations (gc, snapshot rm/prune, **snapshot rollback**) require the **master key**
  — the recipient is pinned in the archive and possession of the private key is proven by deriving it, so a
  public-key-only host can only append; an explicit one-way append-only flag covers symmetric archives (and
  hard-locks asymmetric ones). `push`/`pull` carry a monotonic revision so a stale/replayed index is refused on
  a given restore host. Both are client-side; pair with bucket-level immutability (S3 Object Lock / GCS retention)
  for server-side enforcement — chunks are content-addressed and write-once, so immutable buckets need no special
  support.

### Integrity trade-off: no application-level MAC per chunk

Cairn relies on **AEAD authentication tags** (AES-GCM / ChaCha20-Poly1305) for chunk integrity — each chunk's
cryptographic tag is verified on read. However, there is **no additional HMAC/MAC at the application level**:

- **What this means:** If an attacker can modify ciphertext chunks *and* their AEAD tags (e.g. via a compromised
  storage backend that holds encryption keys), AEAD alone cannot detect the tampering — the tag would be valid
  for the modified ciphertext.
- **Mitigation:** The content-addressed nature of chunks means any modification changes the hash, which is detected
  when the index references the wrong chunk. Additionally, cloud backends provide their own integrity guarantees
  (S3 ETag checksums, GCS CRC32C, Azure MD5) that protect against silent corruption.
- **Recommendation:** For high-assurance scenarios, use `init --disable-dedup` (random per-chunk keys make each
  chunk independently verifiable) and enable backend-side integrity checks (S3 Object Lock, GCS retention).

## Assumptions
- The age **private** key is kept secret and **off** backup hosts (write-only content model).
- The **index password is present on backup hosts** that write the archive — that is how the
  SQLCipher index is opened for append. Treat the password as a **metadata** secret, not as
  equivalent to the private key. (Earlier wording that required the password "off the backup
  hosts" contradicted the write path; this document is the source of truth.)
- The underlying primitives (age X25519, AES-256-GCM / ChaCha20-Poly1305, SQLCipher, BLAKE3) are
  assumed sound; **this project has had no external cryptographic audit** of the *implementation*
  (see `COMPARISON.md` / `OPERATING.md`). Do not treat pre-1.0 as production crypto review.
- Current archive writers generate a fresh random data key and nonce for each newly sealed chunk. Deduplication
  uses a separate keyed content identity and reuses existing objects; it does not derive encryption keys from content.
