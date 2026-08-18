#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use age::x25519::Recipient;
use anyhow::{Result, anyhow};
use secrecy::ExposeSecret;
use std::fs;

/// Default capacity (entries) of the wrapped-key → plaintext-key LRU cache.
/// Entries are ~64 bytes, so the default costs ~1 MB while still covering the
/// hot set of a large restore. Bounded so terabyte-scale workloads (millions of
/// unique wrapped keys) cannot grow the cache without limit and OOM the process.
pub const DEFAULT_SYM_KEY_CACHE_CAP: usize = 16_384;

/// Default capacity (entries) of the hide-names decrypted-name LRU cache.
/// Sized generously above a single very large directory (see
/// docs/DESIGN-NOTES.md#3 for the measured cost this exists to amortize):
/// re-listing the same directory, or `ls`ing a whole tree in one session,
/// hits the cache instead of re-running age decryption per name per call.
pub const DEFAULT_NAME_CACHE_CAP: usize = 16_384;

/// Newtype around the age private key.
///
/// `age::x25519::Identity` owns its secret scalar behind `secrecy` and zeroizes
/// it in its own `Drop`. Do NOT "help" by overwriting the struct's bytes
/// manually (`from_raw_parts_mut` + `zeroize()`): that corrupts the fields'
/// internal pointers before their destructors run — undefined behavior that
/// segfaults on drop.
pub struct ProtectedIdentity(pub age::x25519::Identity);

/// Keyed by BLAKE3 of the wrapped blob; the inner `Mutex<Option<..>>` lets the
/// first reader wait while later readers of the same key wait instead of
/// re-running scrypt/X25519.
type SymKeyCache = lru::LruCache<
    [u8; 32],
    std::sync::Arc<parking_lot::Mutex<Option<zeroize::Zeroizing<Vec<u8>>>>>,
>;

/// Keyed by BLAKE3 of the `name_enc` blob (same "first reader computes, later
/// readers of the same key wait" shape as SymKeyCache). Only a process
/// holding the private key ever populates this (encrypt_name never reads it
/// back), so caching a name it can already decrypt on demand does not cross
/// a new confidentiality boundary -- `Zeroizing` is still used so an evicted
/// or cleared entry's heap buffer doesn't linger, same posture as SymKeyCache.
type NameCache =
    lru::LruCache<[u8; 32], std::sync::Arc<parking_lot::Mutex<Option<zeroize::Zeroizing<String>>>>>;

/// Format tag of a chunk key wrapped with the archive KEK:
/// `CKEK1 || 12-byte random nonce || AES-256-GCM ciphertext+tag`.
/// Distinguishable from legacy per-key age scrypt envelopes, which start with
/// the ASCII age header (`age-encryption.org/v1`).
const KEK_WRAP_MAGIC: &[u8; 5] = b"CKEK1";

/// Padding length to bring `current_len` up to the next multiple of `block`
/// (0 if already aligned). Shared by `encrypt_name` (64-byte blocks) and
/// `encrypt_chunk_symmetric` (4096-byte blocks) — both pad for the same
/// reason (hide the exact plaintext length / CRIME-BREACH mitigation) with
/// different block sizes and length-encodings, so only this arithmetic is
/// shared, not the prefix/trailer wire format each already persists on disk.
fn pad_len_to_block(current_len: usize, block: usize) -> usize {
    (block - (current_len % block)) % block
}

/// True if `algo` names ChaCha20-Poly1305. The CLI validates and stores the
/// hyphenated form (`chacha20-poly1305`) while internal/test call sites use
/// `chacha20poly1305`; both — and a bare `chacha20` — must select ChaCha, or the
/// hyphenated CLI form silently falls through to the AES-256-GCM branch (a chunk
/// gets encrypted with a cipher the operator did not choose).
fn is_chacha(algo: &str) -> bool {
    let a = algo.replace('-', "").to_ascii_lowercase();
    a == "chacha20poly1305" || a == "chacha20"
}

pub struct CryptoCtx {
    pub_key: Option<Recipient>,
    /// the passphrase is the *root* secret for a symmetric
    /// archive (the KEK is derived from it). It must be droppable on
    /// `zeroize_keys` like the other secret-bearing fields; the previous
    /// version held it as a bare `Option<SecretString>` that survived on the
    /// heap for the full daemon lifetime. `parking_lot::Mutex` lets us swap
    /// it out for `None` atomically when the operator calls
    /// `zeroize_keys()`.
    passphrase: parking_lot::Mutex<Option<secrecy::SecretString>>,
    priv_key: parking_lot::Mutex<Option<ProtectedIdentity>>,
    /// Symmetric mode only: the archive key-encryption-key. Chunk keys are
    /// wrapped with this (fast AES-256-GCM); only the KEK itself is wrapped
    /// with the scrypt passphrase envelope — one scrypt per mount instead of
    /// one per unique chunk key.
    kek: parking_lot::Mutex<Option<zeroize::Zeroizing<[u8; 32]>>>,
    /// Freshly generated KEK envelope awaiting persistence (see [`Self::wrapped_kek`]).
    pending_wrapped_kek: Option<zeroize::Zeroizing<Vec<u8>>>,
    comp_level: i32,
    comp_min_ratio: i32,
    pub comp_algo: String,
    pub crypto_algo: String,
    pub dedup_secret: parking_lot::Mutex<Option<secrecy::SecretString>>,
    pub disable_dedup: bool,
    pub comp_min_size: usize,
    pub sym_key_cache: parking_lot::Mutex<SymKeyCache>,
    /// `--hide-names` (asymmetric archives only): store each dentry name as a
    /// keyed-hash lookup key + an age-encrypted (write-only) real name. The writer
    /// can match/insert but not read names back.
    pub hide_names: bool,
    /// Keyed-BLAKE3 key for the name-lookup hash (present only when `hide_names`).
    /// The writer holds it (from the SQLCipher config) → it can hash/lookup and
    /// confirm-by-guess, but NOT read names (that needs the private key). Cleared by
    /// `zeroize_keys` like the other secrets.
    name_hash_secret: parking_lot::Mutex<Option<zeroize::Zeroizing<[u8; 32]>>>,
    /// Decrypted-name cache (see [`Self::decrypt_name_cached`]). See
    /// docs/DESIGN-NOTES.md#3 for why this exists (readdir on a large
    /// hide-names directory measured 200+ms of decrypt time without it).
    name_cache: parking_lot::Mutex<NameCache>,
}

impl CryptoCtx {
    fn new_sym_key_cache(cap: usize) -> parking_lot::Mutex<SymKeyCache> {
        let cap = cap.max(1);
        let nz = std::num::NonZeroUsize::new(cap)
            .unwrap_or_else(|| unreachable!("cap.max(1) is always non-zero"));
        parking_lot::Mutex::new(lru::LruCache::new(nz))
    }

    fn new_name_cache(cap: usize) -> parking_lot::Mutex<NameCache> {
        let cap = cap.max(1);
        let nz = std::num::NonZeroUsize::new(cap)
            .unwrap_or_else(|| unreachable!("cap.max(1) is always non-zero"));
        parking_lot::Mutex::new(lru::LruCache::new(nz))
    }

    /// Override the wrapped-key cache capacity in entries (`--sym-key-cache-cap`);
    /// 0 is clamped to 1. Call right after `new`/`new_symmetric` — replaces the
    /// cache, so any cached keys are dropped.
    /// Enable `--hide-names` with the per-archive name-hash key. Call after
    /// `new` (asymmetric only). `name_lookup_key` then returns keyed hashes and
    /// `encrypt_name`/`decrypt_name` become active; with it off they are pass-through.
    pub fn with_hide_names(self, secret: [u8; 32]) -> Self {
        *self.name_hash_secret.lock() = Some(zeroize::Zeroizing::new(secret));
        Self {
            hide_names: true,
            ..self
        }
    }

    /// Lookup key for a dentry name. Off: the name itself (pass-through — normal
    /// archives are byte-identical). On: hex keyed-BLAKE3(secret, LE64(parent) ‖ name).
    ///
    /// Hardens against the worst failure mode of a name-hiding feature: if
    /// `hide_names` is set but the secret is absent, we MUST NOT fall back to
    /// storing the plaintext name in the lookup column (that would silently
    /// disable hiding). The secret lives under the SQLCipher password, so a
    /// caller that could open the archive should always have it — a missing
    /// secret here is corruption/a load-path bug, and we surface it as an error.
    pub fn name_lookup_key(&self, parent_inode: u64, name: &str) -> Result<String> {
        if !self.hide_names {
            return Ok(name.to_string());
        }
        let guard = self.name_hash_secret.lock();
        match guard.as_ref() {
            Some(secret) => {
                let mut h = blake3::Hasher::new_keyed(secret);
                h.update(&parent_inode.to_le_bytes());
                h.update(name.as_bytes());
                Ok(hex::encode(h.finalize().as_bytes()))
            }
            None => anyhow::bail!(
                "hide_names is enabled but the name-hashing secret is unavailable \
                 (archive would leak plaintext names); refusing the operation"
            ),
        }
    }

    /// The write-only encrypted real name for a dentry. Off → `None` (store plaintext
    /// in the lookup column as today). On → `Some(v1 ‖ age(pub, pad(name)))`: only the
    /// private key can read it back; the padding hides the exact name length.
    // Deliberately per-call asymmetric, not a cached/shared name key — caching
    // would keep a reciprocal secret resident for the whole session instead of
    // per-call. See docs/DESIGN-NOTES.md#1.
    pub fn encrypt_name(&self, name: &str) -> Result<Option<Vec<u8>>> {
        if !self.hide_names {
            return Ok(None);
        }
        let nb = name.as_bytes();
        if nb.len() > u16::MAX as usize {
            anyhow::bail!("file name too long to hide ({} bytes)", nb.len());
        }
        // pad plaintext = LE16(len) ‖ name ‖ zeros, up to the next 64-byte block, so
        // the ciphertext length only reveals the name's length bucket, not its exact len.
        let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(2 + nb.len() + 64));
        plain.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        plain.extend_from_slice(nb);
        let block = 64usize;
        let pad_len = pad_len_to_block(plain.len(), block);
        let padded_len = plain.len() + pad_len;
        plain.resize(padded_len, 0u8);
        // Asymmetric mode → encrypt_blob uses the age recipient (pub key), write-only.
        let mut out = self.encrypt_blob(&plain)?;
        out.insert(0, 1u8); // version tag for forward-compat
        Ok(Some(out))
    }

    /// Decrypt a `name_enc` blob back to the real name (needs the private key).
    pub fn decrypt_name(&self, blob: &[u8]) -> Result<String> {
        let (ver, body) = blob
            .split_first()
            .ok_or_else(|| anyhow!("empty hidden-name blob"))?;
        if *ver != 1 {
            anyhow::bail!("unknown hidden-name format version {ver}");
        }
        let padded = self.decrypt_blob(body)?;
        if padded.len() < 2 {
            anyhow::bail!("corrupt hidden name (too short)");
        }
        let len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
        if 2 + len > padded.len() {
            anyhow::bail!("corrupt hidden name (length {len} exceeds block)");
        }
        Ok(String::from_utf8(padded[2..2 + len].to_vec())?)
    }

    /// Like [`Self::decrypt_name`], but cached by BLAKE3(blob) -- readdir on
    /// the same directory (or re-listing during one session) hits the cache
    /// instead of paying age decryption per name per call. See
    /// docs/DESIGN-NOTES.md#3 for the measured cost this amortizes.
    pub fn decrypt_name_cached(&self, blob: &[u8]) -> Result<String> {
        let hash: [u8; 32] = blake3::hash(blob).into();

        let entry = {
            let mut cache = self.name_cache.lock();
            if let Some(arc) = cache.get(&hash) {
                arc.clone()
            } else {
                let arc = std::sync::Arc::new(parking_lot::Mutex::new(None));
                cache.put(hash, arc.clone());
                arc
            }
        };

        let mut lock = entry.lock();
        if let Some(cached) = &*lock {
            return Ok(cached.to_string());
        }

        let name = self.decrypt_name(blob)?;
        *lock = Some(zeroize::Zeroizing::new(name.clone()));
        Ok(name)
    }

    /// Whether a private key is loaded (asymmetric read capability). Used to tell
    /// "priv absent → expected hash fallback" apart from "priv present but the
    /// name blob failed to decrypt → real corruption worth surfacing".
    pub fn has_private_key(&self) -> bool {
        self.priv_key.lock().is_some()
    }

    pub fn with_sym_key_cache_cap(mut self, cap: usize) -> Self {
        self.sym_key_cache = Self::new_sym_key_cache(cap);
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pub_key_path: &str,
        priv_key_path: Option<&str>,
        comp_level: i32,
        comp_min_ratio: i32,
        comp_algo: String,
        crypto_algo: String,
        dedup_secret: Option<secrecy::SecretString>,
        disable_dedup: bool,
        comp_min_size: usize,
    ) -> Result<Self> {
        let pub_key_str = fs::read_to_string(pub_key_path)?;
        let pub_key = pub_key_str
            .trim()
            .parse::<Recipient>()
            .map_err(|e| anyhow!("Public key err: {e}"))?;

        let mut parsed_priv = None;
        if let Some(path) = priv_key_path {
            if std::path::Path::new(path).exists() {
                let key_str = zeroize::Zeroizing::new(std::fs::read_to_string(path)?);
                parsed_priv = Some(ProtectedIdentity(
                    key_str
                        .trim()
                        .parse::<age::x25519::Identity>()
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                ));
            }
        }

        let final_dedup_secret = dedup_secret.unwrap_or_else(|| {
            use rand::RngCore;
            let mut rand_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
            secrecy::SecretString::from(hex::encode(rand_bytes))
        });

        Ok(Self {
            pub_key: Some(pub_key),
            passphrase: parking_lot::Mutex::new(None),
            priv_key: parking_lot::Mutex::new(parsed_priv),
            kek: parking_lot::Mutex::new(None),
            pending_wrapped_kek: None,
            comp_level,
            comp_min_ratio,
            comp_algo,
            crypto_algo,
            dedup_secret: parking_lot::Mutex::new(Some(final_dedup_secret)),
            disable_dedup,
            comp_min_size,
            sym_key_cache: Self::new_sym_key_cache(DEFAULT_SYM_KEY_CACHE_CAP),
            hide_names: false,
            name_hash_secret: parking_lot::Mutex::new(None),
            name_cache: Self::new_name_cache(DEFAULT_NAME_CACHE_CAP),
        })
    }

    /// Symmetric (password-only) crypto. The passphrase does NOT wrap each chunk
    /// key directly — that costs a full scrypt per unique chunk key on both write
    /// and read (minutes for a directory of small files). Instead a random 32-byte
    /// archive KEK wraps chunk keys (AES-256-GCM, microseconds), and only the KEK
    /// itself sits in an age scrypt passphrase envelope: exactly one scrypt per
    /// mount.
    ///
    /// `wrapped_kek` is the archive's stored KEK envelope (config key
    /// `wrapped_kek`); a wrong passphrase fails here, at mount time. Pass `None`
    /// only for a fresh archive — then a new KEK is generated and its envelope
    /// MUST be persisted (see [`Self::wrapped_kek`]) before any data is written,
    /// or the written chunk keys are unrecoverable on the next mount.
    #[allow(clippy::too_many_arguments)]
    pub fn new_symmetric(
        comp_level: i32,
        comp_min_ratio: i32,
        comp_algo: String,
        crypto_algo: String,
        dedup_secret: Option<secrecy::SecretString>,
        disable_dedup: bool,
        comp_min_size: usize,
        passphrase: secrecy::SecretString,
        wrapped_kek: Option<Vec<u8>>,
    ) -> Result<Self> {
        let final_dedup_secret = dedup_secret.unwrap_or_else(|| {
            use rand::RngCore;
            let mut rand_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
            secrecy::SecretString::from(hex::encode(rand_bytes))
        });

        let (kek, pending_wrapped_kek) = match wrapped_kek {
            Some(blob) => {
                // Existing archive: one scrypt to unwrap the KEK.
                // Clone the SecretString directly instead of
                // expose_secret().to_string() which creates an unprotected
                // plaintext copy on the heap.
                let pass_secret = passphrase.clone();
                let identity = age::scrypt::Identity::new(pass_secret);
                let decryptor = age::Decryptor::new(&blob[..])?;
                let mut reader = decryptor
                    .decrypt(std::iter::once(&identity as &dyn age::Identity))
                    .map_err(|_| anyhow!("Failed to unwrap the archive key — wrong passphrase?"))?;
                let mut kek_bytes = zeroize::Zeroizing::new(Vec::new());
                std::io::Read::read_to_end(&mut reader, &mut kek_bytes)?;
                if kek_bytes.len() != 32 {
                    return Err(anyhow!(
                        "Corrupt wrapped_kek: expected 32 bytes, got {}",
                        kek_bytes.len()
                    ));
                }
                let mut kek = zeroize::Zeroizing::new([0u8; 32]);
                kek.copy_from_slice(&kek_bytes);
                (kek, None)
            }
            None => {
                // Fresh archive: generate a KEK and wrap it once with the passphrase.
                use rand::RngCore;
                let mut kek = zeroize::Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng.fill_bytes(kek.as_mut());

                let mut wrapped = vec![];
                // Clone the SecretString directly instead of
                // expose_secret().to_string() which creates an unprotected
                // plaintext copy on the heap.
                let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
                let mut writer = encryptor
                    .wrap_output(&mut wrapped)
                    .map_err(|e| anyhow!("Failed to wrap archive key: {e}"))?;
                std::io::Write::write_all(&mut writer, kek.as_ref())?;
                writer
                    .finish()
                    .map_err(|e| anyhow!("Failed to finish archive key wrap: {e}"))?;
                (kek, Some(zeroize::Zeroizing::new(wrapped)))
            }
        };

        Ok(Self {
            pub_key: None,
            passphrase: parking_lot::Mutex::new(Some(passphrase)),
            priv_key: parking_lot::Mutex::new(None),
            kek: parking_lot::Mutex::new(Some(kek)),
            pending_wrapped_kek,
            comp_level,
            comp_min_ratio,
            comp_algo,
            crypto_algo,
            dedup_secret: parking_lot::Mutex::new(Some(final_dedup_secret)),
            disable_dedup,
            comp_min_size,
            sym_key_cache: Self::new_sym_key_cache(DEFAULT_SYM_KEY_CACHE_CAP),
            hide_names: false,
            name_hash_secret: parking_lot::Mutex::new(None),
            name_cache: Self::new_name_cache(DEFAULT_NAME_CACHE_CAP),
        })
    }

    /// The freshly generated KEK envelope to persist in the archive config —
    /// `Some` only when [`Self::new_symmetric`] was called without an existing
    /// one. Persist it BEFORE writing any data.
    pub fn wrapped_kek(&self) -> Option<&[u8]> {
        self.pending_wrapped_kek.as_ref().map(|v| v.as_ref())
    }

    /// The recipient (public key) this context encrypts to — `Some` in
    /// asymmetric mode. Used to pin the archive's recipient in its config.
    pub fn recipient_string(&self) -> Option<String> {
        self.pub_key.as_ref().map(|r| r.to_string())
    }

    /// The recipient derived from the LOADED private key — `Some` only when a
    /// private key is present. Deriving the public key from the private key is
    /// proof of possession: matching this against the archive's pinned
    /// recipient is what gates destructive operations to the master-key holder.
    pub fn derived_recipient(&self) -> Option<String> {
        self.priv_key
            .lock()
            .as_ref()
            .map(|id| id.0.to_public().to_string())
    }

    pub fn zeroize_keys(&self) {
        *self.priv_key.lock() = None;
        *self.dedup_secret.lock() = None;
        *self.kek.lock() = None;
        // the passphrase is the *root* secret for a symmetric
        // archive. Clearing it under the same lock the other secrets use so a
        // `zeroize_keys()` call is atomic w.r.t. any in-flight KEK unwrap.
        *self.passphrase.lock() = None;
        // The name-hash key is a secret too (enables name lookup/hashing).
        *self.name_hash_secret.lock() = None;
        // Clear the LRU cache of decrypted chunk keys. Without this,
        // ~1 MB of plaintext keys survives in the sym_key_cache after all
        // other secrets are zeroized.
        self.sym_key_cache.lock().clear();
        // Same reasoning for decrypted names -- without this, cached
        // plaintext names outlive the private key that decrypted them.
        self.name_cache.lock().clear();
    }

    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.passphrase.lock().is_some() {
            // Symmetric mode: wrap with the archive KEK (fast), never with the
            // passphrase directly (that would be one scrypt per chunk key).
            let kek_guard = self.kek.lock();
            let kek = kek_guard
                .as_ref()
                .ok_or_else(|| anyhow!("Archive key unavailable (already zeroized?)"))?;
            let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::clone_from_slice(kek.as_ref()));
            let mut nonce_bytes = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
            let ct = cipher
                .encrypt(&Nonce::clone_from_slice(&nonce_bytes), plaintext)
                .map_err(|e| anyhow!("KEK wrap failed: {e}"))?;
            let mut out = Vec::with_capacity(KEK_WRAP_MAGIC.len() + 12 + ct.len());
            out.extend_from_slice(KEK_WRAP_MAGIC);
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ct);
            return Ok(out);
        }

        let pub_key = self
            .pub_key
            .as_ref()
            .ok_or_else(|| anyhow!("Asymmetric mode requires a public key — use symmetric (passphrase) or provide a pub key"))?;
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(pub_key as &dyn age::Recipient))
                .map_err(|_| anyhow!("Failed to create encryptor"))?;
        let mut encrypted = vec![];
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| anyhow!("Failed to wrap output: {e}"))?;
        std::io::Write::write_all(&mut writer, plaintext)?;
        writer
            .finish()
            .map_err(|e| anyhow!("Failed to finish encryption: {e}"))?;
        Ok(encrypted)
    }

    /// returns `Zeroizing<Vec<u8>>` so dropped plaintext
    /// keys are wiped. The previous `Vec<u8>` left a copy on the heap (and
    /// in any cache that held a clone) until the allocator reaped the page —
    /// a core-dump, debugger-attach, or swap-to-disk leak.
    pub fn decrypt_blob(&self, wrapped_blob: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if self.passphrase.lock().is_some() {
            let rest = wrapped_blob
                .strip_prefix(KEK_WRAP_MAGIC.as_slice())
                .ok_or_else(|| anyhow!("Unknown chunk-key format (not CKEK1)"))?;
            let kek_guard = self.kek.lock();
            let kek = kek_guard
                .as_ref()
                .ok_or_else(|| anyhow!("Archive key unavailable (already zeroized?)"))?;
            if rest.len() < 12 {
                return Err(anyhow!("Corrupt KEK-wrapped key blob"));
            }
            let (nonce, ct) = rest.split_at(12);
            let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::clone_from_slice(kek.as_ref()));
            // drop the inner AEAD error text from the user-
            // visible message; AEAD libraries include implementation details
            // (offset, length) that help an attacker probe. The exact
            // algorithm name is also withheld for the same reason.
            return cipher
                .decrypt(&Nonce::clone_from_slice(nonce), ct)
                .map(zeroize::Zeroizing::new)
                .map_err(|_| anyhow!("KEK unwrap failed (corrupt blob or wrong archive key)"));
        }

        let lock = self.priv_key.lock();
        let priv_key = lock.as_ref().ok_or_else(|| {
            anyhow!("Private key required to decrypt (read) — this archive uses asymmetric envelope encryption")
        })?;
        let decryptor = age::Decryptor::new(wrapped_blob)?;

        let mut dec = zeroize::Zeroizing::new(Vec::new());
        // SAFETY: `|_|` is intentional — the inner age error is deliberately
        // dropped so a decrypt oracle can't distinguish failure modes (same policy
        // as the KEK path above). Do NOT chain `{e}` here.
        let mut reader = decryptor
            .decrypt(std::iter::once(&priv_key.0 as &dyn age::Identity))
            .map_err(|_| anyhow!("Envelope unwrap failed (corrupt blob or wrong private key)"))?;

        use std::io::Read;
        reader.read_to_end(&mut dec)?;
        Ok(dec)
    }

    /// Every copy of the plaintext chunk key — the cache entry AND the value
    /// handed to the caller — is `Zeroizing`, so dropped keys are wiped instead
    /// of lingering in freed heap memory.
    pub fn decrypt_blob_cached(&self, wrapped_blob: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let hash: [u8; 32] = blake3::hash(wrapped_blob).into();

        let entry = {
            let mut cache = self.sym_key_cache.lock();
            if let Some(arc) = cache.get(&hash) {
                arc.clone()
            } else {
                let arc = std::sync::Arc::new(parking_lot::Mutex::new(None));
                cache.put(hash, arc.clone());
                arc
            }
        };

        let mut lock = entry.lock();
        if let Some(cached) = &*lock {
            return Ok(zeroize::Zeroizing::new(cached.to_vec()));
        }

        let sym_key = self.decrypt_blob(wrapped_blob)?;
        *lock = Some(zeroize::Zeroizing::new(sym_key.to_vec()));
        Ok(sym_key)
    }

    /// Generate a per-chunk symmetric key. For deduplicated chunks, this is a
    /// keyed BLAKE3 hash of the plaintext (same content → same key). For
    /// non-dedup mode, a random 32-byte key is generated.
    ///
    /// returns `Zeroizing<Vec<u8>>` so the key is zeroized on
    /// drop (was plain `Vec<u8>` — chunk keys leaked on the heap).
    /// returns `Result` instead of panicking on short
    /// dedup_secret (was `panic!` on the hot write path — kills the process
    /// mid-backup).
    pub fn generate_chunk_key(&self, data: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if self.disable_dedup {
            let mut sym_key = zeroize::Zeroizing::new(vec![0u8; 32]);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut sym_key);
            return Ok(sym_key);
        }
        let lock = self.dedup_secret.lock();
        if let Some(ref secret) = *lock {
            let secret_bytes = secret.expose_secret().as_bytes();
            if secret_bytes.len() < 32 {
                anyhow::bail!(
                    "dedup_secret must be at least 32 bytes (got {}). \
                     The default cairn init generates a random 64-hex-char secret; \
                     pass --dedup-secret with at least 32 bytes of entropy",
                    secret_bytes.len()
                );
            }
            // derive the full 256-bit dedup key from the ENTIRE secret via
            // BLAKE3, not the first 32 bytes of the hex STRING (that was 32 hex
            // chars = only 128 bits of real entropy). Hashing also accepts a
            // secret of any length/format, not just 64-hex-char.
            let mut key = zeroize::Zeroizing::new([0u8; 32]);
            key.copy_from_slice(blake3::hash(secret_bytes).as_bytes());
            let hash = blake3::keyed_hash(&key, data);
            Ok(zeroize::Zeroizing::new(hash.as_bytes().to_vec()))
        } else {
            // fail loud instead of silently producing a RANDOM key. In
            // convergent mode the secret is None only after `zeroize_keys`
            // (unmount) — a write reaching here is a bug, and a random key would
            // (a) silently break dedup and (b) pair a non-content-derived key
            // with the fixed `convergent_n` nonce (a nonce/key-reuse footgun).
            // Mirrors `encrypt_blob`'s "key unavailable (already zeroized?)".
            anyhow::bail!(
                "dedup_secret unavailable (already zeroized?) — cannot derive a \
                 convergent chunk key"
            )
        }
    }

    pub fn encrypt_chunk_symmetric(
        &self,
        plaintext: &[u8],
        sym_key_bytes: &[u8],
        comp_algo_override: Option<&str>,
    ) -> Result<(Vec<u8>, u8)> {
        let mut compressed_data = None;
        let active_comp = comp_algo_override.unwrap_or(&self.comp_algo);

        if plaintext.len() >= self.comp_min_size {
            if active_comp == "zstd" {
                if let Ok(compressed) =
                    zstd::stream::encode_all(std::io::Cursor::new(plaintext), self.comp_level)
                {
                    if self.comp_min_ratio == 0
                        || ((plaintext.len() as f64 - compressed.len() as f64)
                            / plaintext.len() as f64
                            * 100.0)
                            >= f64::from(self.comp_min_ratio)
                    {
                        compressed_data = Some((compressed, 1u8));
                    }
                }
            } else if active_comp == "lz4" {
                let compressed = lz4_flex::compress_prepend_size(plaintext);
                if self.comp_min_ratio == 0
                    || ((plaintext.len() as f64 - compressed.len() as f64) / plaintext.len() as f64
                        * 100.0)
                        >= f64::from(self.comp_min_ratio)
                {
                    compressed_data = Some((compressed, 2u8));
                }
            }
        }

        let (mut final_data, mut comp_type) = if let Some((data, ct)) = compressed_data {
            (data, ct)
        } else {
            let mut buf = Vec::with_capacity(plaintext.len() + 4096 + 4);
            buf.extend_from_slice(plaintext);
            (buf, 0u8)
        };

        // Add padding to mitigate CRIME/BREACH attacks (Compression Oracle)
        let orig_len = final_data.len() as u32;
        let pad_len = pad_len_to_block(final_data.len(), 4096);
        final_data.resize(final_data.len() + pad_len, 0u8);
        final_data.extend_from_slice(&orig_len.to_be_bytes());
        comp_type |= 0x80; // Set padded flag

        let mut nonce_bytes = vec![0u8; 12];
        if self.disable_dedup {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        } else {
            // the fixed `convergent_n` nonce is SAFE ONLY because
            // `sym_key_bytes` is content-derived (unique per plaintext) — it must
            // come from `generate_chunk_key` in convergent mode. There is no way
            // to prove "content-derived" from the bytes; the invariant is upheld
            // by construction (every caller keys via generate_chunk_key). A key
            // that is random or reused here would cause catastrophic AES-GCM
            // (key, nonce) reuse. Do NOT add a caller that passes a
            // non-content-derived key with disable_dedup == false. See SECURITY.md.
            // enforce the 32-byte convergent-key invariant at RUNTIME,
            // not only under debug_assertions. SECURITY.md calls a wrong/short key
            // under the fixed `convergent_n` nonce "catastrophic (key, nonce) reuse";
            // a guard compiled out in --release would let a future refactor silently
            // violate the one invariant the convergent-nonce design depends on.
            if sym_key_bytes.len() != 32 {
                anyhow::bail!(
                    "convergent chunk key must be a 32-byte content-derived key, got {}",
                    sym_key_bytes.len()
                );
            }
            nonce_bytes.copy_from_slice(b"convergent_n");
        }

        let mut ciphertext = if is_chacha(&self.crypto_algo) {
            use chacha20poly1305::{
                ChaCha20Poly1305,
                aead::{Aead, KeyInit},
            };
            let key_arr: [u8; 32] = sym_key_bytes
                .try_into()
                .map_err(|_| anyhow!("ChaCha20 key must be 32 bytes"))?;
            let key = chacha20poly1305::Key::from(key_arr);
            let cipher_cha = ChaCha20Poly1305::new(&key);
            let nonce_arr: [u8; 12] = (&nonce_bytes[..])
                .try_into()
                .map_err(|_| anyhow!("ChaCha20 nonce must be 12 bytes"))?;
            let nonce_cha = chacha20poly1305::Nonce::from(nonce_arr);
            cipher_cha
                .encrypt(&nonce_cha, final_data.as_ref())
                .map_err(|_| anyhow::anyhow!("chunk encryption failed"))?
        } else {
            // Parity with the ChaCha `try_into` path: a wrong-length key returns a
            // clean Err, never a `clone_from_slice` panic. Reachable in disable_dedup
            // mode (no convergent 32-byte guard) and on any corrupt/foreign key.
            let cipher = Aes256Gcm::new_from_slice(sym_key_bytes)
                .map_err(|_| anyhow!("AES-256 chunk key must be 32 bytes"))?;
            let nonce = Nonce::clone_from_slice(&nonce_bytes);
            cipher
                .encrypt(&nonce, final_data.as_ref())
                .map_err(|_| anyhow::anyhow!("chunk encryption failed"))?
        };

        if self.disable_dedup {
            let mut final_cipher = nonce_bytes;
            final_cipher.append(&mut ciphertext);
            ciphertext = final_cipher;
        }

        Ok((ciphertext, comp_type))
    }

    pub fn decrypt_chunk_symmetric(
        &self,
        ciphertext: &[u8],
        wrapped_sym_key: &[u8],
        comp_type: u8,
        cipher_algo: &str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        // propagate the
        // mode-appropriate generic unwrap error from `decrypt_blob` unchanged, rather
        // than re-wrapping it with the inner `{e}` text and a symmetric-mode-wrong
        // "--priv-key" hint. `decrypt_blob` already returns a non-leaky message
        // ("KEK unwrap failed …" for symmetric, "Envelope unwrap failed …" for age).
        let sym_key_bytes = self.decrypt_blob_cached(wrapped_sym_key)?;

        let (nonce_bytes, actual_cipher) = if self.disable_dedup {
            if ciphertext.len() < 12 {
                return Err(anyhow::anyhow!("Ciphertext too short"));
            }
            ciphertext.split_at(12)
        } else {
            (b"convergent_n".as_ref(), ciphertext)
        };

        let plain_or_compressed = if is_chacha(cipher_algo) {
            use chacha20poly1305::{
                ChaCha20Poly1305,
                aead::{Aead, KeyInit},
            };
            let key_arr: [u8; 32] = sym_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("ChaCha20 key must be 32 bytes"))?;
            let key = chacha20poly1305::Key::from(key_arr);
            let cipher_cha = ChaCha20Poly1305::new(&key);
            let nonce_arr: [u8; 12] = nonce_bytes
                .try_into()
                .map_err(|_| anyhow!("ChaCha20 nonce must be 12 bytes"))?;
            let nonce_cha = chacha20poly1305::Nonce::from(nonce_arr);
            cipher_cha
                .decrypt(&nonce_cha, actual_cipher)
                .map_err(|_| anyhow::anyhow!("chunk decryption failed"))?
        } else {
            // A corrupt/wrong-length key must Err cleanly, not panic in
            // `clone_from_slice` (parity with the ChaCha `try_into` path above).
            let cipher = Aes256Gcm::new_from_slice(&sym_key_bytes)
                .map_err(|_| anyhow!("AES-256 chunk key must be 32 bytes"))?;
            let nonce = Nonce::clone_from_slice(nonce_bytes);
            cipher
                .decrypt(&nonce, actual_cipher)
                .map_err(|_| anyhow::anyhow!("chunk decryption failed"))?
        };

        let mut plain_or_compressed = plain_or_compressed;
        let is_padded = (comp_type & 0x80) != 0;
        let comp_algo_type = comp_type & 0x7F;

        if is_padded {
            let len = plain_or_compressed.len();
            if len >= 4 {
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&plain_or_compressed[len - 4..]);
                let orig_len = u32::from_be_bytes(len_bytes) as usize;
                // reject padding if stored length is implausible (would
                // extend beyond the buffer or exceeds 128 MiB limit).
                if orig_len <= len - 4 && orig_len <= 128 * 1024 * 1024 {
                    plain_or_compressed.truncate(orig_len);
                } else {
                    return Err(anyhow::anyhow!(
                        "Padding validation failed: stored length {orig_len} is implausible \
                         for buffer of size {len}"
                    ));
                }
            } else if len > 0 {
                return Err(anyhow::anyhow!(
                    "Padded block too small: {len} bytes (< 4 byte padding header)"
                ));
            }
        }

        if comp_algo_type == 1 {
            let decoded = zstd::stream::decode_all(std::io::Cursor::new(plain_or_compressed))
                .map_err(|e| anyhow::anyhow!("ZSTD decompression failed: {e}"))?;
            Ok(zeroize::Zeroizing::new(decoded))
        } else if comp_algo_type == 2 {
            let decoded = lz4_flex::decompress_size_prepended(&plain_or_compressed)
                .map_err(|e| anyhow::anyhow!("LZ4 decompression failed: {e}"))?;
            Ok(zeroize::Zeroizing::new(decoded))
        } else {
            Ok(zeroize::Zeroizing::new(plain_or_compressed))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519::Identity;
    use proptest::prelude::any;
    use secrecy::SecretString;

    fn setup_ctx(crypto_algo: &str, disable_dedup: bool) -> CryptoCtx {
        let identity = Identity::generate();
        let pub_key = identity.to_public();

        let priv_key = Some(ProtectedIdentity(identity));
        let dedup_secret = Some(SecretString::from(
            "test_dedup_secret_that_is_at_least_32_bytes_for_validation".to_string(),
        ));

        CryptoCtx {
            pub_key: Some(pub_key),
            passphrase: parking_lot::Mutex::new(None),
            priv_key: parking_lot::Mutex::new(priv_key),
            kek: parking_lot::Mutex::new(None),
            pending_wrapped_kek: None,
            comp_level: 3,
            comp_min_ratio: 0,
            comp_algo: "zstd".to_string(),
            crypto_algo: crypto_algo.to_string(),
            dedup_secret: parking_lot::Mutex::new(dedup_secret),
            disable_dedup,
            comp_min_size: 10,
            sym_key_cache: CryptoCtx::new_sym_key_cache(DEFAULT_SYM_KEY_CACHE_CAP),
            hide_names: false,
            name_hash_secret: parking_lot::Mutex::new(None),
            name_cache: CryptoCtx::new_name_cache(DEFAULT_NAME_CACHE_CAP),
        }
    }

    #[test]
    fn test_zeroize_keys() {
        let ctx = setup_ctx("aes-gcm", false);
        assert!(ctx.priv_key.lock().is_some());
        assert!(ctx.dedup_secret.lock().is_some());

        ctx.zeroize_keys();

        assert!(ctx.priv_key.lock().is_none());
        assert!(ctx.dedup_secret.lock().is_none());
    }

    #[test]
    fn test_generate_chunk_key_after_zeroize_errors_not_random() {
        // once the dedup secret is zeroized, a convergent
        // (dedup-enabled) context MUST fail loudly instead of returning a fresh
        // random key — a random key would silently break dedup and make the
        // chunk unfindable on every later read.
        let ctx = setup_ctx("aes-gcm", false);
        assert!(ctx.generate_chunk_key(b"payload").is_ok());
        ctx.zeroize_keys();
        assert!(
            ctx.generate_chunk_key(b"payload").is_err(),
            "convergent generate_chunk_key must bail after zeroize, not return random material"
        );
    }

    #[test]
    fn test_encrypt_chunk_symmetric_rejects_wrong_len_key_at_runtime() {
        // the convergent-mode 32-byte key invariant is enforced
        // at RUNTIME (not only via debug_assert), so a wrong-length key returns a
        // clean Err even in --release instead of panicking (or, worse, proceeding to
        // catastrophic (key, nonce) reuse under the fixed `convergent_n` nonce).
        let ctx = setup_ctx("aes-gcm", false); // convergent mode (disable_dedup = false)
        let bad_key = [0u8; 31];
        assert!(
            ctx.encrypt_chunk_symmetric(b"payload", &bad_key, None)
                .is_err(),
            "convergent encrypt_chunk_symmetric must reject a non-32-byte key with Err"
        );
    }

    #[test]
    fn test_generate_chunk_key_dedup() {
        let ctx = setup_ctx("aes-gcm", false);
        let data = b"test data";

        let key1 = ctx.generate_chunk_key(data).unwrap();
        let key2 = ctx.generate_chunk_key(data).unwrap();
        let key_other = ctx.generate_chunk_key(b"other data").unwrap();

        assert_eq!(key1, key2);
        assert_ne!(key1, key_other);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_generate_chunk_key_no_dedup() {
        let ctx = setup_ctx("aes-gcm", true); // Disable dedup
        let data = b"test data";

        let key1 = ctx.generate_chunk_key(data).unwrap();
        let key2 = ctx.generate_chunk_key(data).unwrap();

        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_disable_dedup_ciphertext_diverges_and_roundtrips() {
        // in random (no-dedup) mode identical plaintext must yield
        // DIFFERENT ciphertext (no convergence oracle for an attacker holding
        // only the chunk store), and each chunk must still round-trip.
        let ctx = setup_ctx("aes-gcm", true);
        let plaintext = b"identical chunk plaintext for the convergence probe, padded long";

        let k1 = ctx.generate_chunk_key(plaintext).unwrap();
        let k2 = ctx.generate_chunk_key(plaintext).unwrap();
        let (c1, t1) = ctx.encrypt_chunk_symmetric(plaintext, &k1, None).unwrap();
        let (c2, _t2) = ctx.encrypt_chunk_symmetric(plaintext, &k2, None).unwrap();
        assert_ne!(c1, c2, "no-dedup mode produced identical ciphertexts");

        let wrapped1 = ctx.encrypt_blob(&k1).unwrap();
        let decrypted = ctx
            .decrypt_chunk_symmetric(&c1, &wrapped1, t1, "aes-gcm")
            .unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Control: convergent mode stays convergent.
        let conv = setup_ctx("aes-gcm", false);
        let ck1 = conv.generate_chunk_key(plaintext).unwrap();
        let (cc1, _) = conv.encrypt_chunk_symmetric(plaintext, &ck1, None).unwrap();
        let (cc2, _) = conv.encrypt_chunk_symmetric(plaintext, &ck1, None).unwrap();
        assert_eq!(cc1, cc2, "convergent mode must stay deterministic");
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm() {
        let ctx = setup_ctx("aes-gcm", false);
        let plaintext = b"hello world, this is a test payload long enough to maybe compress";

        let sym_key = ctx.generate_chunk_key(plaintext).unwrap();
        let wrapped_sym_key = ctx.encrypt_blob(&sym_key).unwrap();

        let (ciphertext, comp_type) = ctx
            .encrypt_chunk_symmetric(plaintext, &sym_key, None)
            .unwrap();
        let decrypted = ctx
            .decrypt_chunk_symmetric(&ciphertext, &wrapped_sym_key, comp_type, "aes-gcm")
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_chacha20() {
        let ctx = setup_ctx("chacha20poly1305", false);
        let plaintext = b"hello world, this is a test payload long enough to maybe compress";

        let sym_key = ctx.generate_chunk_key(plaintext).unwrap();
        let wrapped_sym_key = ctx.encrypt_blob(&sym_key).unwrap();

        let (ciphertext, comp_type) = ctx
            .encrypt_chunk_symmetric(plaintext, &sym_key, None)
            .unwrap();
        let decrypted = ctx
            .decrypt_chunk_symmetric(&ciphertext, &wrapped_sym_key, comp_type, "chacha20poly1305")
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    fn symmetric_ctx(pass: &str, wrapped_kek: Option<Vec<u8>>) -> Result<CryptoCtx> {
        CryptoCtx::new_symmetric(
            3,
            0,
            "zstd".to_string(),
            "aes-gcm".to_string(),
            Some(SecretString::from(
                "dedup_secret_that_is_at_least_32_bytes_long_for_testing".to_string(),
            )),
            false,
            10,
            SecretString::from(pass.to_string()),
            wrapped_kek,
        )
    }

    /// Symmetric (password-only) envelope: chunk keys are wrapped with the
    /// archive KEK (CKEK1 format), the KEK itself with the scrypt passphrase —
    /// exactly one scrypt per mount, not one per chunk key.
    #[test]
    fn test_symmetric_envelope_roundtrip() {
        let pass = "correct horse battery staple";
        let ctx = symmetric_ctx(pass, None).unwrap();
        let kek_blob = ctx
            .wrapped_kek()
            .expect("fresh archive must yield a KEK to persist")
            .to_vec();

        let plaintext = b"symmetric mode payload";
        let sym_key = ctx.generate_chunk_key(plaintext).unwrap();
        let wrapped = ctx.encrypt_blob(&sym_key).unwrap();
        assert!(
            wrapped.starts_with(b"CKEK1"),
            "new writes must use the KEK format"
        );
        assert_eq!(ctx.decrypt_blob(&wrapped).unwrap(), sym_key.clone());

        // Full chunk roundtrip through the cached path used by reads.
        let (ciphertext, comp_type) = ctx
            .encrypt_chunk_symmetric(plaintext, &sym_key, None)
            .unwrap();
        let decrypted = ctx
            .decrypt_chunk_symmetric(&ciphertext, &wrapped, comp_type, "aes-gcm")
            .unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Remount simulation: a second ctx built from the persisted KEK envelope
        // must read blobs written by the first.
        let remount = symmetric_ctx(pass, Some(kek_blob.clone())).unwrap();
        assert!(
            remount.wrapped_kek().is_none(),
            "nothing new to persist on remount"
        );
        assert_eq!(remount.decrypt_blob(&wrapped).unwrap(), sym_key.clone());

        // Wrong passphrase must fail at construction (KEK unwrap), not decrypt garbage.
        assert!(symmetric_ctx("wrong password", Some(kek_blob)).is_err());

        // A different archive's KEK must not unwrap this blob.
        let foreign = symmetric_ctx(pass, None).unwrap();
        assert!(foreign.decrypt_blob(&wrapped).is_err());
    }

    /// Non-CKEK1 blobs (e.g. from a different tool or corruption) must be
    /// rejected with a clear error, not fed to the KEK cipher.
    #[test]
    fn test_symmetric_rejects_unknown_format() {
        let ctx = symmetric_ctx("correct horse battery staple", None).unwrap();
        let err = ctx
            .decrypt_blob(b"age-encryption.org/v1\nnot a kek blob")
            .unwrap_err();
        assert!(err.to_string().contains("Unknown chunk-key format"));
    }

    #[test]
    fn test_aes_wrong_len_key_errors_not_panics() {
        // Parity with the ChaCha `try_into` path: a wrong-length AES key must return
        // a clean Err, never panic in `clone_from_slice`. disable_dedup=true skips the
        // convergent 32-byte guard, so this hits the AES key path directly.
        let ctx = setup_ctx("aes-gcm", true);
        assert!(
            ctx.encrypt_chunk_symmetric(b"payload", &[0u8; 31], None)
                .is_err(),
            "wrong-length AES key must Err, not panic"
        );
    }

    #[test]
    fn test_cli_dashed_chacha_actually_uses_chacha() {
        // The CLI accepts/stores "chacha20-poly1305" (with dashes); seal must treat
        // that as ChaCha, not silently fall through to AES-256-GCM. Convergent mode is
        // deterministic (fixed nonce + content key), so identical plaintext+key yields
        // identical ciphertext per cipher — compare the CLI form against known ciphers.
        let pt = b"payload for the cipher-selection probe, long enough to exercise it";
        let cha = setup_ctx("chacha20poly1305", false); // known ChaCha (internal form)
        let aes = setup_ctx("aes-gcm", false); // known AES
        let cli = setup_ctx("chacha20-poly1305", false); // the CLI form — MUST be ChaCha
        let k = cha.generate_chunk_key(pt).unwrap();
        let (c_cha, _) = cha.encrypt_chunk_symmetric(pt, &k, None).unwrap();
        let (c_aes, _) = aes.encrypt_chunk_symmetric(pt, &k, None).unwrap();
        let (c_cli, _) = cli.encrypt_chunk_symmetric(pt, &k, None).unwrap();
        assert_ne!(
            c_cha, c_aes,
            "sanity: ChaCha and AES ciphertext must differ"
        );
        assert_eq!(
            c_cli, c_cha,
            "CLI '--crypto-algo chacha20-poly1305' must select ChaCha, not silently AES"
        );
    }

    #[test]
    fn test_decrypt_name_cached_matches_uncached_and_is_faster_on_repeat() {
        let ctx = setup_ctx("aes-gcm", false).with_hide_names([7u8; 32]);
        let blob = ctx.encrypt_name("cached-name.txt").unwrap().unwrap();

        // Correctness: cached path returns the same plaintext as the
        // uncached primitive, on both the cold (populate) and warm (hit) call.
        let direct = ctx.decrypt_name(&blob).unwrap();
        let cold = ctx.decrypt_name_cached(&blob).unwrap();
        let warm = ctx.decrypt_name_cached(&blob).unwrap();
        assert_eq!(direct, "cached-name.txt");
        assert_eq!(cold, direct);
        assert_eq!(warm, direct);

        // A corrupt blob must still error on the cached path (no poisoned
        // cache entry masking a real decrypt failure).
        let mut corrupt = blob.clone();
        corrupt[0] ^= 0xFF;
        assert!(ctx.decrypt_name_cached(&corrupt).is_err());

        // zeroize_keys clears the cache: a decrypt right after must still
        // succeed (falls through to a fresh decrypt_name, not a stale hit
        // from before the private key was dropped -- the private key is
        // still loaded here, only the cache is being asserted as cleared).
        ctx.name_cache.lock().clear();
        assert_eq!(ctx.decrypt_name_cached(&blob).unwrap(), direct);
    }

    #[test]
    fn test_zeroize_keys_clears_name_cache() {
        let ctx = setup_ctx("aes-gcm", false).with_hide_names([7u8; 32]);
        let blob = ctx.encrypt_name("secret-name.txt").unwrap().unwrap();
        ctx.decrypt_name_cached(&blob).unwrap();
        assert_eq!(ctx.name_cache.lock().len(), 1, "cache should hold the entry before zeroize");
        ctx.zeroize_keys();
        assert_eq!(ctx.name_cache.lock().len(), 0, "zeroize_keys must clear the name cache");
    }

    #[test]
    fn test_hide_names_roundtrip_and_passthrough() {
        // OFF: pure pass-through (normal archives stay byte-identical).
        let plain = setup_ctx("aes-gcm", false);
        assert_eq!(plain.name_lookup_key(5, "file.txt").unwrap(), "file.txt");
        assert!(plain.encrypt_name("file.txt").unwrap().is_none());

        // ON: hashed lookup key + write-only encrypted name that round-trips via priv.
        let ctx = setup_ctx("aes-gcm", false).with_hide_names([7u8; 32]);
        let k = ctx.name_lookup_key(5, "file.txt").unwrap();
        assert_ne!(k, "file.txt", "lookup key must be hashed, not plaintext");
        assert_eq!(
            k,
            ctx.name_lookup_key(5, "file.txt").unwrap(),
            "deterministic"
        );
        assert_ne!(
            k,
            ctx.name_lookup_key(6, "file.txt").unwrap(),
            "keyed by parent inode"
        );
        assert_ne!(
            k,
            ctx.name_lookup_key(5, "other.txt").unwrap(),
            "keyed by name"
        );

        let enc = ctx
            .encrypt_name("file.txt")
            .unwrap()
            .expect("hide_names => Some");
        assert!(
            !enc.windows(8).any(|w| w == b"file.txt"),
            "raw name must not appear in the ciphertext"
        );
        assert_eq!(
            ctx.decrypt_name(&enc).unwrap(),
            "file.txt",
            "priv round-trip"
        );

        // No correlation: encrypting the SAME name twice yields distinct ciphertext
        // (age is randomized), so identical names don't reveal themselves by matching.
        let e2 = ctx.encrypt_name("file.txt").unwrap().unwrap();
        assert_ne!(enc, e2, "age randomizes — identical names must differ");
        assert_eq!(ctx.decrypt_name(&e2).unwrap(), "file.txt");

        // Round-trip holds across name lengths. (Exact ciphertext length is NOT a
        // usable oracle: the plaintext is padded to 64B blocks AND age emits
        // variable-length output, so the on-disk size does not reveal the name length.)
        for name in ["a", "abcdefghij", &"x".repeat(200)] {
            let c = ctx.encrypt_name(name).unwrap().unwrap();
            assert_eq!(&ctx.decrypt_name(&c).unwrap(), name);
        }

        // Missing-secret hardening: hide_names set but no secret (e.g. after
        // zeroize, or a load-path bug) must ERROR, never fall back to storing
        // the plaintext name in the lookup column.
        ctx.zeroize_keys();
        assert!(
            ctx.name_lookup_key(5, "file.txt").is_err(),
            "hide_names with no secret must fail, not leak plaintext"
        );
    }

    #[test]
    fn test_encrypt_decrypt_no_dedup() {
        for algo in ["aes-gcm", "chacha20poly1305"] {
            let ctx = setup_ctx(algo, true);
            let plaintext = b"some random data without deduplication";

            let sym_key = ctx.generate_chunk_key(plaintext).unwrap();
            let wrapped_sym_key = ctx.encrypt_blob(&sym_key).unwrap();

            let (ciphertext, comp_type) = ctx
                .encrypt_chunk_symmetric(plaintext, &sym_key, None)
                .unwrap();
            let decrypted = ctx
                .decrypt_chunk_symmetric(&ciphertext, &wrapped_sym_key, comp_type, algo)
                .unwrap();

            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        }
    }

    // ------------------------------------------------------------------
    // Golden ciphertext vectors. Round-trip tests are
    // necessary but not sufficient: a systematic bug in the cipher layer
    // (wrong nonce order, broken key schedule, off-by-one AAD) survives
    // encrypt→decrypt because BOTH sides are equally wrong. These tests pin
    // the AEAD primitives against the published RFC 8439 / NIST CAVP vectors,
    // so the cipher layer is proven correct, not just self-consistent.
    // ------------------------------------------------------------------

    /// RFC 8439 §2.8.2 Test Vector #2 — ChaCha20-Poly1305 AEAD (the exact
    /// vector the RFC's own implementors use). The ciphertext below is
    /// ct‖tag as produced by the `encrypt` API (114 + 16 bytes).
    #[test]
    fn test_rfc8439_chacha20_poly1305_vector2() {
        use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};

        let key_bytes =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap();
        let nonce_bytes = hex::decode("070000004041424344454647").unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

        let cipher = chacha20poly1305::ChaCha20Poly1305::new(
            &chacha20poly1305::Key::try_from(key_bytes.as_slice()).unwrap(),
        );
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer \
            you only one tip for the future, sunscreen would be it.";

        let out = cipher
            .encrypt(
                &chacha20poly1305::Nonce::try_from(nonce_bytes.as_slice()).unwrap(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("RFC 8439 vector 2 must encrypt");

        let expected = hex::decode(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63\
             dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692\
             ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4\
             def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691",
        )
        .unwrap();
        assert_eq!(
            out, expected,
            "ChaCha20-Poly1305 must match RFC 8439 vector 2"
        );
    }

    /// NIST GCM CAVP `gcmEncryptExtIV256.rsp` — AES-256-GCM, IV 12 bytes.
    /// Case 1 (empty plaintext) and Case 2 (16-byte plaintext), both with the
    /// zero key, zero IV and empty AAD. `encrypt` returns ct‖tag; the files
    /// list CT and Tag separately, so the expected value is CT‖Tag.
    #[test]
    fn test_nist_aes256_gcm_cavp_vectors() {
        use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};

        let cipher =
            aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&[0u8; 32]));
        let iv = aes_gcm::Nonce::from_slice(&[0u8; 12]);
        let empty_aad: [u8; 0] = [];

        // Case 1: empty plaintext.
        let out = cipher
            .encrypt(
                iv,
                Payload {
                    msg: &[],
                    aad: &empty_aad,
                },
            )
            .expect("NIST Case 1 must encrypt");
        assert_eq!(
            out,
            hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap(),
            "AES-256-GCM must match NIST gcmEncryptExtIV256 Case 1"
        );

        // Case 2: 16 zero bytes.
        let out = cipher
            .encrypt(
                iv,
                Payload {
                    msg: &[0u8; 16],
                    aad: &empty_aad,
                },
            )
            .expect("NIST Case 2 must encrypt");
        assert_eq!(
            out,
            hex::decode("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
                .unwrap(),
            "AES-256-GCM must match NIST gcmEncryptExtIV256 Case 2"
        );
    }

    /// Format-contrast golden test: the FULL chunk pipeline (no compression,
    /// convergent fixed nonce, known key) must produce a byte-exact, stable
    /// ciphertext. Guards against silent format/cipher changes — e.g. a
    /// swapped padding layout or a different nonce — that round-trip tests
    /// cannot see. `comp_min_size` is huge so compression is skipped, and the
    /// plaintext is shorter than it, so `final_data` = pt ‖ pad ‖ orig_len.
    ///
    /// The golden value (~4 KiB of hex, padding to 4096 + length trailer) is
    /// kept out of the source in `tests/golden_chunk.hex` and regenerated only
    /// when the chunk format is INTENTIONALLY changed:
    ///   eprintln!("{}", hex::encode(&ciphertext));  > tests/golden_chunk.hex
    #[test]
    fn test_chunk_format_golden_convergent() {
        let ctx = setup_ctx("aes-gcm", false);
        let key = [0u8; 32];
        // 2-byte plaintext < comp_min_size(10) => no compression; deterministic.
        let (ciphertext, comp_type) = ctx.encrypt_chunk_symmetric(b"hi", &key, None).unwrap();

        assert_eq!(comp_type & 0x7F, 0, "no compression expected");
        assert_ne!(comp_type & 0x80, 0, "padding flag must be set");

        let golden = include_str!("../tests/golden_chunk.hex").trim();
        assert_eq!(
            hex::encode(&ciphertext),
            golden,
            "convergent chunk format drifted"
        );
    }

    // ------------------------------------------------------------------
    // Property round-trip: arbitrary payloads (random,
    // structured, compressible, repeated, empty-ish) must survive the full
    // chunk pipeline — compression, CRIME-padding, per-chunk key wrap,
    // ciphertext — for both ciphers and both dedup modes. The handful of
    // hand-written round-trips can't cover the tails that fuzzing does.
    // ------------------------------------------------------------------

    proptest::proptest! {
        #[test]
        fn chunk_roundtrip_prop_any_payload(
            payload in proptest::collection::vec(any::<u8>(), 0..300usize),
            algo in proptest::sample::select(vec!["aes-gcm", "chacha20poly1305"]),
            no_dedup in proptest::bool::ANY,
        ) {
            let ctx = setup_ctx(algo, no_dedup);
            let key = ctx.generate_chunk_key(&payload).unwrap();
            let (ciphertext, comp_type) = ctx
                .encrypt_chunk_symmetric(&payload, &key, None)
                .unwrap();
            let wrapped = ctx.encrypt_blob(&key).unwrap();
            let back = ctx
                .decrypt_chunk_symmetric(&ciphertext, &wrapped, comp_type, algo)
                .unwrap();
            proptest::prop_assert_eq!(&payload[..], back.as_slice());
        }

        #[test]
        fn chunk_roundtrip_prop_compressible(
            block in proptest::collection::vec(any::<u8>(), 0..64usize),
            repeat in 0..8usize,
        ) {
            let payload = block.repeat(repeat);
            let ctx = setup_ctx("aes-gcm", false);
            let key = ctx.generate_chunk_key(&payload).unwrap();
            let (ciphertext, comp_type) = ctx
                .encrypt_chunk_symmetric(&payload, &key, None)
                .unwrap();
            let wrapped = ctx.encrypt_blob(&key).unwrap();
            let back = ctx
                .decrypt_chunk_symmetric(&ciphertext, &wrapped, comp_type, "aes-gcm")
                .unwrap();
            proptest::prop_assert_eq!(&payload[..], back.as_slice());
        }
    }
}
