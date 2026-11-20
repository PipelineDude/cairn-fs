# Cairn Security

How Cairn protects data, what to be careful with, and how to report issues. See `THREAT_MODEL.md` for what is and
isn't in scope, `ARCHITECTURE.md` for the data flow.

## Cryptographic primitives
- **Chunk-key wrapping (envelope):** age X25519. Back up with `--pub-key`, restore with `--priv-key`. The backup host
  never needs the private key.
- **Symmetric (password-only) mode:** without `--pub-key`, chunk keys are wrapped with a random per-archive **KEK**
  (AES-256-GCM, `CKEK1` blob format); the KEK itself is wrapped once with the passphrase (age scrypt envelope, config
  key `wrapped_kek`) — one scrypt per mount, and a wrong password fails at mount time.
  Note the trade-off: symmetric mode has no write-only property — anyone who can write can also read.
- **Chunk encryption:** AES-256-GCM or ChaCha20-Poly1305 (`--crypto-algo`), with a fresh random 256-bit data key and
  random 96-bit nonce for each newly sealed object, including inline files. The wrapped `CSK02` record binds the
  key, cipher, compression, plaintext length/hash and ciphertext length/hash. The nonce prefixes the ciphertext.
- **Deduplication identity:** a separate keyed BLAKE3 over the chunk content with a per-archive dedup secret.
  This identity is NOT the encryption key. The secret is **auto-generated at `init`** and stored inside SQLCipher;
  there is no CLI flag to supply it. Matching identities reuse an existing encrypted object. `init --disable-dedup`
  disables this lookup and stores every chunk freshly; the mode is fixed at init.
- **Metadata index:** SQLCipher, unlocked with `--password`.

### Equality and size leakage
Current production writers use randomized sealing, not the legacy fixed-nonce convergent helper. Deduplication
still exposes equality through the index and object reuse: a host with the index password also holds the dedup
secret and can test candidate chunks. `init --disable-dedup` removes that equality lookup.

Independently of deduplication, the index stores a per-file H09 digest: an unkeyed, domain-separated BLAKE3 of
the logical file content plus its size. Anyone who can read the index (the password holder, or anyone at all
with `--allow-plaintext-index`) can test a candidate whole file against that digest. This is a confirmation
oracle, not decryption: it does not reveal content, but it can prove that a known file is present even when
`--disable-dedup` is set. Write-only hosts store this digest from the plaintext stream so snapshots and restore
verification work without the private key.

Compression can leak information through stored sizes when an attacker can inject chosen data. Padding the
compressed payload to 4096-byte blocks only reduces this leakage; randomized encryption and disabling dedup do
not eliminate it. Use `--comp-algo none` when compression-size leakage is unacceptable. Reusing an AEAD nonce
under a repeated key remains forbidden.

### Shared-dedup domains are a shared decryption boundary
`init --shared-dedup-domain ... --shared-dedup-secret-file ...` opts into a different trust model. Domain chunks
have their sealed key records wrapped under a key derived from the domain secret. Any holder of that secret
with the corresponding records and ciphertext can decrypt those chunks **without an archive's private key**.
The writing host must have the domain secret; therefore it is not write-only for domain chunks, including chunks
published by other archives in the same domain. Inline data and hidden names retain their archive envelopes.
Domain records (the per-content metadata mapping) are themselves encrypted at rest under a key derived from
the domain secret, so read access to the domain store without the secret reveals nothing beyond access
patterns. Holder links (`holders/<content_id>/<holder-id>`, empty files) expose *within the already-trusted
domain* that some member references a content id; holder ids are random per-archive and reveal no identity
outside the domain. Keep untrusted write-only hosts in archive-local mode (omit the shared-domain options).
Every archive prints its holder id in `cairn <archive> status` ("GC holder id"); an archive that is destroyed
without a flow leaves its pins behind. They can be released surgically with
`cairn <archive> shared-gc --drop-holder <id> [--dry-run]` when the id was recorded before the archive
disappeared — safer than the age-based `--reclaim-stale-holders-days`, which cannot tell a destroyed archive
from a live-but-idle one. Otherwise pins are released only by that age-based sweep, and the holder id cannot
be discovered for a destroyed archive, so record it before destroying.
Prefer `cairn <archive> destroy-shared --i-accept-destroy` (drops all pins immediately) before deleting
the database, and `cairn <archive> heartbeat` (via cron) for live archives so they never look stale.

### Backend credentials and legacy configuration
Backend URIs are metadata protected by SQLCipher, not by the content recipient. A password-holding backup host
must be able to read them without loading a content private key. With `--allow-plaintext-index`, these credentials
are also plaintext; do not use that option for secret-bearing backend configuration.

Advanced URI overrides (`endpoint`, `credential_path`) can redirect traffic or read local files on the restore host,
so `raid add` accepts them only when the master (private) key is present. Plain URIs stay usable by write-only
hosts. `push`/`pull` carry a monotonic revision; `pull` refuses a stale or replayed index on a given host.

Older versions automatically wrote `ENC:v1:` envelopes using the content key model. For an asymmetric archive,
recover these once on a trusted machine with `--pub-key` and `--priv-key`, for example using `status`. Recovered
URIs are persisted under SQLCipher protection and subsequent public-key-only opens work. Missing keys or malformed
envelopes now stop the command instead of silently dropping the configured backend. If the old private key is lost,
reconfigure the affected backend with `raid remove` / `raid add` using the original credentials.

## Key custody (the part that matters most)
- The **age private key** is the crown jewel: anyone with it *and* `--password` can read every backup. Generate keys on
  a trusted machine (`cargo run -p cairn-keys --bin gen_keys` → `priv.pem` + `pub.pem`), keep `priv.pem` off backup
  hosts, and back it up separately from the archive.
- `pub.pem` is safe to distribute to any host that only writes backups.
- For shared custody, `cairn-keys` can Shamir-split the master secret into M-of-N shares.

## Operational caveats
- **Secrets in argv.** `--password` on the command line is visible in the process table (`ps`). Prefer
  `--password-file` or the `CAIRN_PASSWORD` env var on shared machines (env is still visible in
  `/proc/PID/environ` to same-uid attackers).
- **Not anti-forensic.** A machine holding the keys can read the data; there is no self-destruct or deniability.
- **Metadata at rest.** File names, sizes and structure are protected only by SQLCipher (`--password`). A leaked
  password exposes them. Backup hosts *hold* this password by design. **Optional:** `init --hide-names` (asymmetric
  archives) makes *names* write-only (keyed hashes + age-encrypted, readable only with the private key); sizes, tree,
  timestamps and xattr values are unaffected. See `HIDE_NAMES.md`.
- **Restore host trust.** Only mount with `--priv-key` on machines you trust — that is where the data becomes readable.
- **`--dangerously-skip-verify`.** Requires `CAIRN_I_ACCEPT_CORRUPTION=1` in addition to the flag; otherwise refused.
- **No external crypto audit yet.** Treat implementation trust accordingly until one is published.

## Recent hardening (2026-11)

- **Setuid/setgid** bits are stripped from restored files unless `--preserve` is given, so an
  attacker-controlled index cannot plant a setuid binary via a root restore. `security.*` and
  `trusted.*` xattrs are never restored, even with `--preserve`.
- **`extract_matching`** refuses to traverse a pre-existing symlink in the destination, closing the
  path-traversal that `extract_all` already guarded against.
- **`verify` and `extract`** now also check the stored H09 whole-file digest when present, catching
  under-coverage, chunk splicing and tampering that per-chunk AEAD alone would miss. Legitimate
  sparse files (no chunks, no digest) are no longer flagged as unrestorable.
- **`--hide-names`**: a transplanted `name_enc` is detected (`name_lookup_key` mismatch) and the
  entry falls back to its opaque hash instead of adopting the wrong name.
- **Scrub** validates the sealed chunk-key record (magic + length) and, when a private key is
  available, performs a full decrypt/AEAD check.
- **Shared-dedup** domain secrets must be at least 32 bytes.
- **Snapshots** have an opt-in quota (`snapshot_quota`, default `0` = unlimited) to guard against
  snapshot spam / storage exhaustion by a compromised write-only host. Set it via
  `--snapshot-quota N` at init or `CAIRN_SNAPSHOT_QUOTA` at runtime.
- **`--to-source`** requires `--i-accept-to-source` and refuses protected system paths.
- **`push`/`pull`** carry a monotonic revision and archive identity; `pull` refuses stale or
  foreign indices on a given host.

## Known boundaries (by design, not bugs)

- **Self-consistent index tampering.** An attacker who controls the index writer (master key) can
  repoint a file's chunks, size and H09 digest to another file's content and `verify` will pass,
  because there is no independent anchor: the index is the authority. Without a `--trusted-checkpoint`,
  such tampering is indistinguishable from a legitimate rewrite. This is the same trust boundary as
  the writer itself; a future `--trusted-checkpoint` re-anchoring closes it. Verified empirically
  2026-11 (chunks + size + digest swapped → `Verify: N OK, 0 NOT restorable`).
- **`zstd`/`zstd-safe` (unsound).** The remaining zstd advisories were cleared by bumping to
  `zstd 0.13.4` / `zstd-safe 7.4.0`. Decompression runs only after the per-chunk AEAD tag has
  verified, so a tampered compressed blob fails MAC before reaching the decoder; the unsound
  code paths (`CCtx::try_clone`, `train_from_buffer`) are not invoked by cairn.
- **Timing on digest compare.** `verify_file_digest` compares the recomputed and stored 32-byte
  digests with `!=` (early-exit). The digest is a deterministic function of plaintext the reader
  already holds, so this is not a secret; no constant-time primitive is used. Not considered a
  vulnerability.

## Transitive dependencies: yanked / unmaintained

Table of known problematic transitive dependencies that do not yet require an urgent update (no compatible
versions available, or the update breaks the build). Monitor updates on crates.io and RUSTSEC.

| Package | Version in cairn | Status | Dependency path | CVE / RUSTSEC | Action |
|---|---|---|---|---|---|
| **quick-xml** | 0.41.0 ✅ | Fixed | opendal → opendal-core → xml → quick-xml | RUSTSEC-2026-0195 (7.5), RUSTSEC-2026-0194 | Updated to >=0.41.0 in Cargo.lock |
| **spin** | 0.9.8 ⚠️ | unmaintained (crates.io) | cacache → dashmap → spin | No CVE, unmaintained since 2023 | Monitor; no replacement without updating dashmap |
| **async-std** | 1.13.2 ⚠️ | unmaintained (crates.io) | cacache → async-std | No CVE, unmaintained since 2024 | Monitor; updating cacache may help |
| **bincode** | 1.3.3 ⚠️ | unmaintained (crates.io) | cairn-store → bincode | RUSTSEC-2025-0141 | Monitor; no direct security impact |
| **memmap2** | 0.5.10 ⚠️ | unmaintained (crates.io) | cacache → memmap2 | RUSTSEC-2026-0186 (see section below) | Monitor; updating cacache may help |
| **fxhash** | 0.2.1 ⚠️ | unmaintained (crates.io) | dashmap → fxhash | No CVE, unmaintained since 2023 | Monitor; no replacement without updating dashmap |
| **rustls-pemfile** | 2.x ⚠️ | unmaintained (crates.io) | rproxy → rustls-pemfile | No CVE, unmaintained since 2024 | Monitor; updating rustls may help |
| **rsa** | 0.9.10 ⚠️ | Marvin timing side-channel (RUSTSEC-2023-0071) | opendal → reqsign-azure-storage → rsa | Only affects Azure Blob signing; not reachable on S3/GCS/fs backends | Monitor; update opendal when a patched rsa is available |
| **suppaftp** | ⚠️ | CRLF injection (RUSTSEC) | opendal → suppaftp (FTP backend) | Only relevant if an FTP backend is configured; cairn does not enable FTP by default | Do not use FTP backends, or update opendal |
| **libsqlite3-sys** | bundled ⚠️ | CVE-2026-119375 in bundled C SQLite | cairn-index → rusqlite (bundled-sqlcipher) | Affects the SQLCipher C library; no compatible patched rusqlite available | Monitor rusqlite releases; the index is password-protected at rest |

### Actions when a new vulnerability is found
1. Check `cargo audit` (if available) or https://rustsec.org/
2. Assess the dependency path: is the vulnerable function reachable in our code?
3. If critical — update the package and verify the build; if no compatible version exists — document the risk here.

## memmap2 via cacache (step 3)

**Path:** cairn → cacache → memmap2 (0.5.10)

memmap2 is used by cacache to memory-map cached files.
**RUSTSEC-2026-0186** — unchecked pointer offset, affects versions 0.5.9–<0.9.11.
The package has been unmaintained since 2024. Updating cacache to the latest version (13.1.0) does not resolve
the issue — memmap2 remains a dependency.

**Rationale for ignoring:** See `.cargo/audit.toml` — RUSTSEC-2026-0186 is added to `ignore` because
cairn does not use memmap2 directly; it is used only inside cacache for caching, and the attack vector
through this chain is absent in our scenario.

**Monitoring:** Watch for updates to memmap2 and cacache on crates.io. When a new memmap2 version or an updated
cacache using the new memmap2 version appears, check compatibility with cairn.

## Reporting a vulnerability
Report suspected security issues privately to the maintainer (see the repository's contact/`repository` field in
`Cargo.toml`). Please do not open public issues for undisclosed vulnerabilities.
