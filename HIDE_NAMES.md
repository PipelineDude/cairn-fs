# `--hide-names` — hiding file names from an untrusted backup host

By default Cairn encrypts file **contents** (asymmetric mode: only the private key
reads them) but stores **metadata** — names, sizes, tree, timestamps, xattrs — in a
SQLCipher index that the backup host must open with the `--password`. So a backup
host, or anyone who leaks the index, can read your **file names** even though it can
never read file *content*.

`init --hide-names` closes the *names* part of that gap. It is **opt-in** and
**fixed at init** (like `--disable-dedup`): there is no CLI path to add or remove it
on an existing archive.

```bash
# names hidden; content write-only; requires a pub key AND a password
CAIRN_PASSWORD=… cairn --archive a.db --pub-key pub.pem init --hide-names
```

## Requirements

- **Asymmetric only** (`--pub-key`). In symmetric mode the host holds the password
  and could decrypt the names — hiding would be pointless — so `init --hide-names`
  refuses without a public key.
- **A password.** The per-archive name-hashing secret lives in the encrypted index.
  Without a password the index (and that secret) would be plaintext, so storage
  theft could confirm names by guessing. `init --hide-names` refuses without one.

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

Normal archives (without `--hide-names`) are **byte-identical** to before: the lookup
column holds the plaintext name and `name_enc` is `NULL`.

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
- **xattr values** — `--hide-names` does **not** touch extended attributes. If xattr
  values are sensitive, do not store them in a `--hide-names` archive expecting them hidden.

**Confirm-by-guess.** The backup host holds `name_secret`, so it can test a *specific*
guess — compute `keyed_BLAKE3(name_secret, parent ‖ "passwords.txt")` and look for that
hash. So the guarantee is: *the host cannot learn your names, but it can verify a name it
already suspects.* Storage theft **without** the password cannot even do that — the hash
is keyed and irreversible. Making even confirm-by-guess impossible would require keeping
`name_secret` off the host (KMS/HSM), which breaks incremental-by-path; out of scope.

## Disaster-recovery cost (why it is opt-in)

Without `--hide-names`, the password alone recovers real names — you can inspect the
tree with a stock `sqlite3` client for recovery/debugging. With `--hide-names`, the
password alone shows only hashes; reconstructing real names needs the **private key**
(the same key content already needs, so no *new* hard single-point-of-failure — but you
do lose the password-only name-inspection escape hatch). A backup tool is
recoverability-first, so this trade-off must be a deliberate choice, not a default.
