# Design notes

Long rationale that would otherwise bloat inline comments — see `COMMENTING.md`
for the rule. Code links here as `# docs/DESIGN-NOTES.md#N`.

## 1. `encrypt_name` stays per-call asymmetric (no cached/shared name key)

`CryptoCtx::encrypt_name` runs a full `age::Encryptor::with_recipients` (fresh
ephemeral X25519 keypair + ECDH + HKDF) on every call, rather than deriving one
symmetric key once per mount and reusing it (the way the archive KEK amortizes
the passphrase scrypt in symmetric mode).

This was considered and rejected. age's per-message ephemeral keypair is
generated and dropped immediately after use — a write-only host (no private
key) that has just encrypted a name retains **no residual capability to
decrypt** that name, or any other, a moment later: each ephemeral secret never
outlives the single call that created it. Caching the ECDH-derived wrap key
across calls to save the scalar-multiplication cost would keep that key
resident in the write-only host's memory for the entire mount session instead
— since the shared secret is reciprocal (the same key that lets the sender
wrap a file key lets a holder unwrap it), a session-long compromise of the
write-only host would then expose every name encrypted during that session,
not just whatever was in flight at the moment of compromise. That is a real
regression of the write-only guarantee the whole feature exists for, in
exchange for a saving that measures at ~93µs/call on this hardware
(`cargo test --release -p cairn-seal`, 2000 calls) — well under anything a
backup workload's disk/DB I/O would notice. Not worth the trade.

If `encrypt_name` throughput ever becomes an actual bottleneck (measured, not
assumed), the safe way to speed it up is a genuine hybrid scheme with
per-message forward secrecy preserved — e.g. HPKE's single-shot API, which
still burns one ephemeral ECDH per message but with a leaner KDF/AEAD
composition than age's stanza+STREAM layering — not caching the derived key.

## 2. Name hiding is on by default: why asymmetric + password are both required

Hiding names is only meaningful, and only safe, in the untrusted-host
(asymmetric) model with an encrypted index:

* Asymmetric (`--pub-key`): real names are age-encrypted write-only, so the
  pub-key-only host cannot read them back. In symmetric mode the host holds
  the password, so it could decrypt names — hiding would be defeated.
* Encrypted index (password): the name-hashing secret lives under the
  SQLCipher password. A plaintext index would expose that secret, so storage
  theft could confirm names by guessing — breaking the guarantee.

Since 2026-08-17, hiding is the DEFAULT whenever both conditions hold — no
flag needed. `--plaintext-names` opts out explicitly. A symmetric archive or
a missing password just can't meet the conditions: `init` silently proceeds
without hiding (a `tracing::warn!` on the missing-password path only, since
"no `--pub-key`" is an ordinary symmetric archive, not a degraded case).
This was an opt-in `--hide-names` flag before, refusing to init at all
without both conditions — the errors became silent skips + one warning
because failing default-on behavior outright would make the feature
unusable for anyone who runs symmetric or passwordless archives some of the
time. The open path's `hide_names_secret.is_some() && symmetric` guard still
hard-refuses to OPEN a symmetric archive that somehow carries the secret
(manual edit / a bug) — that check is about not silently exposing an
already-hidden archive, not about whether to enable hiding on write.

---

## 3. Decrypted-name cache (`CryptoCtx::decrypt_name_cached`)

Default-on hiding (§2) means every `readdir`/`readdirplus` on a hide-names
directory decrypts every entry's name, every call — unlike `encrypt_name`'s
per-file write cost (measured ~93µs/call, §1: negligible spread across a
whole backup), a listing pays this in one synchronous batch. Measured
(release build, `cargo test --release -p cairn-seal`, real `age` asymmetric
decrypt): **~180-230µs per name**, so an uncached `ls` costs roughly
**1.8ms at 10 files, 23ms at 100, 209ms at 1000** — the last one is a
noticeable interactive stall, not "not significant."

Fix: `decrypt_name_cached`, keyed by `BLAKE3(name_enc blob)`, same
"first reader computes, later readers of the same key wait" shape as the
existing chunk-key `sym_key_cache`. Re-listing the same directory (or
`ls`ing a tree already visited this session) hits the cache instead of
re-running age decryption. Measured: cached repeat listing drops to
**~1.0-1.1µs/name** (~200x), i.e. 10/100/1000-file repeat listings cost
~0.01/0.11/1.1ms — the FIRST `ls` of a never-seen directory still pays the
full uncached cost (nothing to cache yet), which is the correct trade-off:
amortizes the cost of repeat access, doesn't pretend the first decrypt can
be free.

Not zeroized-on-idle (only on `zeroize_keys()`, mirroring `sym_key_cache`):
only a process holding the private key ever populates this cache
(`encrypt_name` never reads it back), so caching a name that process can
already decrypt on demand at any time does not cross a new confidentiality
boundary — same reasoning already accepted for cached chunk keys.
