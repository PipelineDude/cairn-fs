# Hiding file names from an untrusted backup host

By default Cairn encrypts file **contents** (asymmetric mode: only the private key
reads them) but stores **metadata** — names, sizes, tree, timestamps, xattrs — in a
SQLCipher index that the backup host must open with the `--password`. So a backup
host, or anyone who leaks the index, can read your **file names** even though it can
never read file *content*.

Cairn closes the *names* part of that gap **by default**, whenever the archive is
asymmetric (`--pub-key`) with a password — no flag needed. Pass `--plaintext-names`
to opt out and keep the old behavior (real names visible to anyone with the
password). Either way it is **fixed at init** (like `--disable-dedup`): there is no
CLI path to add or remove it on an existing archive.

```bash
# names hidden by default; content write-only; requires a pub key AND a password
CAIRN_PASSWORD=… cairn --archive a.db --pub-key pub.pem init

# opt out: real names stay visible to anyone with the password (old default)
CAIRN_PASSWORD=… cairn --archive a.db --pub-key pub.pem init --plaintext-names
```

## When hiding applies

Hiding only ever turns on when BOTH hold; neither missing condition is an error —
`init` just proceeds without hiding (a warning on the password path, since that one
is easy to hit by accident):

- **Asymmetric** (`--pub-key`). In symmetric mode the host holds the password and
  could decrypt the names — hiding would be pointless — so a symmetric `init` never
  hides names, `--plaintext-names` or not.
- **A password.** The per-archive name-hashing secret lives in the encrypted index.
  Without a password the index (and that secret) would be plaintext, so storage
  theft could confirm names by guessing. `init` without a password warns and
  proceeds with plaintext names instead of hiding them.

## How it works

Each directory entry is stored as two columns instead of one plaintext name:

- **lookup key** `= keyed_BLAKE3(name_secret, parent_inode ‖ name)` — a deterministic
  keyed hash used to find/rename/delete an entry without ever revealing the name.
  `name_secret` is a random 32 bytes generated at init and kept in the encrypted config.
- **`name_enc`** `= version_byte ‖ age(pub_key, pad(name))` — the real name, encrypted
  **write-only** to the archive's public key. Only the private key reads it back. The
  name is padded to fixed-size blocks so the ciphertext length does not reveal the
  name's exact length. age uses a fresh ephemeral key per encryption, so two files with
  the same name get *different* ciphertext (no correlation).

- **Backup (host, pub key only):** computes the lookup key from the source name and
  writes `name_enc`; it never reads `name_enc` back, so incremental-by-path still works.
- **Restore / mount (private key present):** `readdir`/`extract` decrypt `name_enc` to
  show the real names; `lookup` matches by the keyed hash.
- **Public-key-only host:** `readdir` shows the opaque hashes; content and names stay
  unreadable. The archive still *opens* (graceful degradation — it does not hard-fail).
  `extract` in this state writes files under those hashes and warns loudly per file —
  see "What it hides" below for why that is worth noticing, not just accepting.

`--plaintext-names` archives (and symmetric archives) are **byte-identical** to
name-hiding's absence before this feature existed: the lookup column holds the
plaintext name and `name_enc` is `NULL`.

## What it hides — and what it does NOT

**Hidden** (from the backup host *and* from storage theft):

- file / directory / symlink **name strings**.
- **symlink targets** — already hidden, because they are stored via the content path
  (age-encrypted to the public key) in asymmetric mode.

**Still visible to the backup host** (it needs these to do incremental backup):

- **tree shape** — the inode graph, entries-per-directory, depth.
- **file sizes** — via chunk count/sizes (4 KiB padding only smooths them).
- **mtimes** — used for incremental change detection.
- **hardlink topology** — N names sharing one inode is visible (only the *names* are hidden).
- **xattr values** — hiding does **not** touch extended attributes. If xattr
  values are sensitive, do not rely on a hide-names archive to hide them too.

**Confirm-by-guess.** The backup host holds `name_secret`, so it can test a *specific*
guess — compute `keyed_BLAKE3(name_secret, parent ‖ "passwords.txt")` and look for that
hash. So the guarantee is: *the host cannot learn your names, but it can verify a name it
already suspects.* Storage theft **without** the password cannot even do that — the hash
is keyed and irreversible. Making even confirm-by-guess impossible would require keeping
`name_secret` off the host (KMS/HSM), which breaks incremental-by-path; out of scope.

## Disaster-recovery cost (why `--plaintext-names` exists)

With names hidden, the password alone shows only hashes; reconstructing real names
needs the **private key** (the same key content already needs, so no *new* hard
single-point-of-failure — but you do lose the password-only name-inspection escape
hatch: without `--plaintext-names` you cannot inspect the tree with a stock `sqlite3`
client using just the password, for recovery/debugging). `--plaintext-names` restores
that escape hatch by keeping real names visible to anyone with the password, same as
before this feature existed. Pick it deliberately if you rely on password-only
inspection more than you need name confidentiality from the backup host.
