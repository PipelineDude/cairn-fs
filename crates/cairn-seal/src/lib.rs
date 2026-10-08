#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use age::x25519::Recipient;
use anyhow::{Result, anyhow};
use secrecy::ExposeSecret;
use std::fs;
use std::io::Read;

/// Default capacity (entries) of the wrapped-key → plaintext-key LRU cache.
/// Entries are ~64 bytes, so the default costs ~1 MB while still covering the
/// hot set of a large restore. Bounded so terabyte-scale workloads (millions of
/// unique wrapped keys) cannot grow the cache without limit and OOM the process.
pub const DEFAULT_SYM_KEY_CACHE_CAP: usize = 16_384;
pub const DEFAULT_MAX_PLAINTEXT_LEN: usize = 128 * 1024 * 1024;
const SEALED_KEY_MAGIC: &[u8; 5] = b"CSK02";
const SEALED_KEY_LEN: usize = 119;

/// A chunk with a random data-encryption key and authenticated metadata.
pub struct SealedChunk {
    pub object_id: String,
    pub wrapped_key: Vec<u8>,
    pub comp_type: u8,
    pub cipher_algo: String,
    pub plaintext_len: u64,
    pub ciphertext: Vec<u8>,
}

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

/// Format tag of a chunk key wrapped with the archive KEK:
/// `CKEK1 || 12-byte random nonce || AES-256-GCM ciphertext+tag`.
/// Distinguishable from legacy per-key age scrypt envelopes, which start with
/// the ASCII age header (`age-encryption.org/v1`).
const KEK_WRAP_MAGIC: &[u8; 5] = b"CKEK1";

/// True if `algo` names ChaCha20-Poly1305. The CLI validates and stores the
/// hyphenated form (`chacha20-poly1305`) while internal/test call sites use
/// `chacha20poly1305`; both — and a bare `chacha20` — must select ChaCha, or the
/// hyphenated CLI form silently falls through to the AES-256-GCM branch (a chunk
/// gets encrypted with a cipher the operator did not choose).
fn is_chacha(algo: &str) -> bool {
    let a = algo.replace('-', "").to_ascii_lowercase();
    a == "chacha20poly1305" || a == "chacha20"
}

/// enforce an exact mapping between the record's cipher ID byte and the
/// human-readable algorithm string.  An unknown ID or name must be rejected
/// (not silently fall through to an unintended branch).
const VALID_CIPHER_IDS: [u8; 2] = [0, 1]; // 0=AES-256-GCM, 1=ChaCha20-Poly1305
fn validate_cipher_pair(id: u8, algo: &str) -> Result<()> {
    if !VALID_CIPHER_IDS.contains(&id) {
        anyhow::bail!("unknown cipher id {id} (allowed: 0=AES-256-GCM, 1=ChaCha20-Poly1305)");
    }
    match (id, is_chacha(algo)) {
        (0, false) | (1, true) => Ok(()),
        (0, true) => anyhow::bail!("cipher id 0 (AES) contradicts algorithm name '{algo}'"),
        (1, false) => anyhow::bail!("cipher id 1 (ChaCha) contradicts algorithm name '{algo}'"),
        _ => anyhow::bail!("invalid cipher id {id}"),
    }
}

/// bounded decompression.  A malicious compressed block must never control
/// an allocation (LZ4's length prefix) or a decoder window (ZSTD's declared
/// frame size) before the SEALED record's authenticated `expected_len` and the
/// configured `max_plaintext_len` are enforced.
fn decompress_sealed(
    plain_or_compressed: Vec<u8>,
    comp_algo_type: u8,
    expected_len: Option<u64>,
    max_plaintext_len: usize,
) -> Result<Vec<u8>> {
    if comp_algo_type > 2 {
        anyhow::bail!("unknown compression flag in sealed chunk: {comp_algo_type}");
    }
    if expected_len.is_none() {
        // The authenticated record did not bind a plaintext length (legacy
        // path).  Decompression proceeds WITHOUT that bound — the caller MUST
        // still enforce the plaintext-hash verification; surface the degraded
        // mode explicitly instead of silently trusting the decompressed bytes.
        tracing::warn!(
            "decompress_sealed: no authenticated expected_len -- plaintext-hash \
             verification is the only remaining content check"
        );
    }
    let allowed: u64 = match expected_len {
        Some(len) => (len + 1).min(max_plaintext_len as u64 + 1),
        None => max_plaintext_len as u64 + 1,
    };
    if comp_algo_type == 1 {
        // ZSTD: reject a frame whose DECLARED content size exceeds the bound
        // before the decoder's window is allocated (the read path additionally
        // caps actual output with Read::take(limit+1) and a final length check).
        if let Some(declared) =
            zstd::zstd_safe::get_frame_content_size(plain_or_compressed.as_slice())
                .map_err(|_| anyhow::anyhow!("ZSTD frame header error"))?
        {
            if declared > allowed {
                anyhow::bail!(
                    "ZSTD frame declares {declared} bytes, exceeding the configured bound"
                );
            }
        }
        let limit = max_plaintext_len.saturating_add(64 * 1024);
        let mut decoder = zstd::stream::read::Decoder::new(plain_or_compressed.as_slice())
            .map_err(|e| anyhow::anyhow!("ZSTD decoder init failed: {e}"))?;
        let mut buf = Vec::new();
        std::io::Read::take(&mut decoder, limit as u64)
            .read_to_end(&mut buf)
            .map_err(|e| anyhow::anyhow!("ZSTD decompression failed: {e}"))?;
        if buf.len() > max_plaintext_len {
            anyhow::bail!("decompressed plaintext exceeds configured maximum");
        }
        Ok(buf)
    } else if comp_algo_type == 2 {
        // LZ4: the length prefix is attacker-controlled — validate it against
        // `allowed` BEFORE allocating, and decompress with an explicit bound.
        if plain_or_compressed.len() < 4 {
            anyhow::bail!("LZ4 block too small");
        }
        let (size_bytes, payload) = plain_or_compressed.split_at(4);
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap()) as u64;
        if size > allowed {
            anyhow::bail!("LZ4 declares {size} bytes, exceeding the configured bound");
        }
        Ok(lz4_flex::decompress(payload, size as usize)
            .map_err(|e| anyhow::anyhow!("LZ4 decompression failed: {e}"))?)
    } else {
        Ok(plain_or_compressed)
    }
}

/// Parsed view of a sealed chunk-key record (CSK02 format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRecordMeta {
    pub comp_type: u8,
    pub cipher_id: u8,
    pub plaintext_len: u64,
    pub ciphertext_len: u64,
    pub object_hash: [u8; 32],
    /// BLAKE3 of the original, uncompressed plaintext.  This value is inside
    /// the authenticated, encrypted key record: it is an integrity check, not
    /// an externally visible content fingerprint.
    pub plaintext_hash: [u8; 32],
}

/// Parse a sealed chunk-key record (D03 shared path): validates the CSK02
/// magic/length and exposes the bound metadata.
pub fn parse_sealed_record(record: &[u8]) -> Result<SealedRecordMeta> {
    if record.len() != SEALED_KEY_LEN || !record.starts_with(SEALED_KEY_MAGIC.as_slice()) {
        anyhow::bail!("not a sealed chunk-key record (CSK02)");
    }
    Ok(SealedRecordMeta {
        comp_type: record[37],
        cipher_id: record[38],
        plaintext_len: u64::from_le_bytes(record[39..47].try_into().unwrap()),
        ciphertext_len: u64::from_le_bytes(record[47..55].try_into().unwrap()),
        object_hash: record[55..87].try_into().unwrap(),
        plaintext_hash: record[87..119].try_into().unwrap(),
    })
}

/// Encode the sole on-disk sealed-record format.  Keep both archive and pool
/// writers on this function: a future field cannot accidentally be added to
/// only one of the two decryptable formats.
fn sealed_record(
    dek: &[u8],
    comp_type: u8,
    cipher_id: u8,
    plaintext: &[u8],
    ciphertext: &[u8],
    object_hash: &[u8; 32],
) -> zeroize::Zeroizing<Vec<u8>> {
    debug_assert_eq!(dek.len(), 32);
    let mut record = zeroize::Zeroizing::new(Vec::with_capacity(SEALED_KEY_LEN));
    record.extend_from_slice(SEALED_KEY_MAGIC);
    record.extend_from_slice(dek);
    record.push(comp_type);
    record.push(cipher_id);
    record.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
    record.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    record.extend_from_slice(object_hash);
    record.extend_from_slice(blake3::hash(plaintext).as_bytes());
    record
}

/// Domain wrapping key for cross-archive re-wrap (D00 review condition 4):
/// blake3 derive_key with the SAME context the design's §3 "cairn shared wrap
/// v1" naming bound before; distinct from the content-id KDF context.
pub fn shared_domain_wrapping_key(secret: &[u8]) -> [u8; 32] {
    blake3::derive_key("cairn shared wrap v1", secret)
}

/// Wrap (re-wrap) a sealed chunk-key record under a domain key:
/// `CKEK1 || 12-byte RANDOM nonce || AES-256-GCM ct+tag` — a fresh nonce per
/// wrap (condition 4), same envelope as archive KEK wraps.
pub fn wrap_with_domain_key(plaintext: &[u8], domain_key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(domain_key));
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let ct = cipher
        .encrypt(&Nonce::clone_from_slice(&nonce_bytes), plaintext)
        .map_err(|_| anyhow!("domain key wrap failed"))?;
    let mut out = Vec::with_capacity(KEK_WRAP_MAGIC.len() + 12 + ct.len());
    out.extend_from_slice(KEK_WRAP_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap a domain-wrapped sealed chunk-key record. Random nonce → both halves
/// of the AEAD bind the wrapped blob to the domain key.
pub fn unwrap_with_domain_key(
    blob: &[u8],
    domain_key: &[u8; 32],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let rest = blob
        .strip_prefix(KEK_WRAP_MAGIC.as_slice())
        .ok_or_else(|| anyhow!("Unknown blob format (not CKEK1)"))?;
    if rest.len() < 12 {
        return Err(anyhow!("Corrupt wrapped blob"));
    }
    let (nonce, ct) = rest.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(domain_key));
    cipher
        .decrypt(&Nonce::clone_from_slice(nonce), ct)
        .map(zeroize::Zeroizing::new)
        .map_err(|_| anyhow!("domain key unwrap failed (corrupt blob or wrong domain key)"))
}

/// A chunk sealed for canonical shared storing: the same random-DEK ciphertext
/// as archive-scope sealing, but with a second, domain-keyable wrap so any
/// archive in the domain can decrypt the one object.
pub struct SharedSealedChunk {
    pub object_id: String,
    pub archive_wrapped_key: Vec<u8>,
    pub domain_wrapped_key: Vec<u8>,
    pub comp_type: u8,
    pub cipher_algo: String,
    pub plaintext_len: u64,
    pub ciphertext_len: u64,
    pub object_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
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
    max_plaintext_len: usize,
}

impl CryptoCtx {
    fn new_sym_key_cache(cap: usize) -> parking_lot::Mutex<SymKeyCache> {
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
        let padded_len = plain.len().div_ceil(block) * block;
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

    pub fn with_max_plaintext_len(mut self, limit: usize) -> Self {
        self.max_plaintext_len = limit.min(DEFAULT_MAX_PLAINTEXT_LEN);
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
            max_plaintext_len: DEFAULT_MAX_PLAINTEXT_LEN,
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
            max_plaintext_len: DEFAULT_MAX_PLAINTEXT_LEN,
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
    #[cfg(test)]
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
            drop(lock); // R06: don't hold the dedup-secret mutex while hashing data
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

    /// Archive-scoped, keyed identity used only for deduplication. It is not an
    /// encryption key and is deliberately unavailable when dedup is disabled.
    pub fn content_id(&self, data: &[u8]) -> Result<Option<[u8; 32]>> {
        if self.disable_dedup {
            return Ok(None);
        }
        let guard = self.dedup_secret.lock();
        let secret = guard
            .as_ref()
            .ok_or_else(|| anyhow!("dedup_secret unavailable (already zeroized?)"))?;
        let bytes = secret.expose_secret().as_bytes();
        if bytes.len() < 32 {
            anyhow::bail!("dedup_secret must be at least 32 bytes");
        }
        let key = zeroize::Zeroizing::new(blake3::derive_key("cairn content identity v1", bytes));
        drop(guard);
        Ok(Some(*blake3::keyed_hash(&key, data).as_bytes()))
    }

    /// Encrypt with a freshly random DEK and nonce. The wrapped record binds the
    /// DEK, compression, cipher, plaintext length, ciphertext length and object
    /// hash, so callers cannot mix metadata from another object.
    pub fn seal_chunk(
        &self,
        plaintext: &[u8],
        comp_algo_override: Option<&str>,
    ) -> Result<SealedChunk> {
        if plaintext.len() > self.max_plaintext_len {
            anyhow::bail!(
                "plaintext exceeds configured maximum of {} bytes",
                self.max_plaintext_len
            );
        }
        let mut dek = zeroize::Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, dek.as_mut());
        let (ciphertext, comp_type) =
            self.encrypt_chunk_with_nonce_mode(plaintext, &dek[..], comp_algo_override, true)?;
        let object_hash = blake3::hash(&ciphertext);
        let cipher_id = if is_chacha(&self.crypto_algo) {
            1u8
        } else {
            0u8
        };
        let record = sealed_record(
            &dek[..],
            comp_type,
            cipher_id,
            plaintext,
            &ciphertext,
            object_hash.as_bytes(),
        );
        Ok(SealedChunk {
            object_id: object_hash.to_hex().to_string(),
            wrapped_key: self.encrypt_blob(&record)?,
            comp_type,
            cipher_algo: self.crypto_algo.clone(),
            plaintext_len: plaintext.len() as u64,
            ciphertext,
        })
    }

    /// Shared-dedup seal (D03): fresh RANDOM DEK + nonce, like seal_chunk, but
    /// the sealed chunk-key record is wrapped TWICE — with the publisher's
    /// archive key (unchanged local reads) and with the DOMAIN key (other
    /// archives in the domain unwrap+decrypt the same canonical object).  The
    /// domain-wrapped record becomes SharedDedupRecord.sealed_meta.
    pub fn seal_chunk_shared(
        &self,
        plaintext: &[u8],
        comp_algo_override: Option<&str>,
        domain_wrap_key: &[u8; 32],
    ) -> Result<SharedSealedChunk> {
        if plaintext.len() > self.max_plaintext_len {
            anyhow::bail!(
                "plaintext exceeds configured maximum of {} bytes",
                self.max_plaintext_len
            );
        }
        let mut dek = zeroize::Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, dek.as_mut());
        let (ciphertext, comp_type) =
            self.encrypt_chunk_with_nonce_mode(plaintext, &dek[..], comp_algo_override, true)?;
        let object_hash = blake3::hash(&ciphertext);
        let cipher_id = if is_chacha(&self.crypto_algo) {
            1u8
        } else {
            0u8
        };
        let record = sealed_record(
            &dek[..],
            comp_type,
            cipher_id,
            plaintext,
            &ciphertext,
            object_hash.as_bytes(),
        );
        Ok(SharedSealedChunk {
            object_id: object_hash.to_hex().to_string(),
            archive_wrapped_key: self.encrypt_blob(&record)?,
            domain_wrapped_key: wrap_with_domain_key(&record, domain_wrap_key)?,
            comp_type,
            cipher_algo: self.crypto_algo.clone(),
            plaintext_len: plaintext.len() as u64,
            ciphertext_len: ciphertext.len() as u64,
            object_hash: *object_hash.as_bytes(),
            ciphertext,
        })
    }

    pub fn decrypt_chunk_shared_record(
        &self,
        ciphertext: &[u8],
        record: &[u8],
        comp_type: u8,
        cipher_algo: &str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        // D03: shared-dedup reader path. `record` is the SEALED chunk-key
        // record recovered from the WINNER's shared record (domain-unwrapped,
        // see parse_sealed_record), not an archive-key wrap.  Validate the
        // full sealed-record invariants, then decrypt exactly like
        // decrypt_chunk_symmetric (kept as a sibling, not a refactor of an
        // audited hot path).
        let meta = parse_sealed_record(record)?;
        validate_cipher_pair(meta.cipher_id, cipher_algo)?;
        if meta.comp_type != comp_type {
            anyhow::bail!("sealed chunk metadata does not match request");
        }
        if meta.plaintext_len > self.max_plaintext_len as u64
            || meta.ciphertext_len != ciphertext.len() as u64
            || meta.object_hash != *blake3::hash(ciphertext).as_bytes()
        {
            anyhow::bail!("sealed chunk metadata is corrupt");
        }
        self._decrypt_with_dek(
            ciphertext,
            &record[5..37],
            comp_type,
            cipher_algo,
            meta.plaintext_len,
            &meta.plaintext_hash,
        )
    }

    /// Decrypt a sealed chunk whose 32-byte DEK we already hold (shared path).
    /// Mirrors the read tail of decrept_chunk_symmetric: random-nonce prefix,
    /// chacha/aes dispatch, pad/compression strip and length checks.
    #[allow(clippy::too_many_arguments)]
    fn _decrypt_with_dek(
        &self,
        ciphertext: &[u8],
        dek: &[u8],
        comp_type: u8,
        cipher_algo: &str,
        expected_len: u64,
        expected_hash: &[u8; 32],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if ciphertext.len() < 12 {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }
        let (nonce_bytes, actual_cipher) = ciphertext.split_at(12);
        let plain_or_compressed = if is_chacha(cipher_algo) {
            use chacha20poly1305::{
                ChaCha20Poly1305,
                aead::{Aead, KeyInit},
            };
            let key_arr: [u8; 32] = dek
                .try_into()
                .map_err(|_| anyhow!("ChaCha20 key must be 32 bytes"))?;
            let cipher_cha = ChaCha20Poly1305::new(&chacha20poly1305::Key::from(key_arr));
            let nonce_cha = chacha20poly1305::Nonce::from(
                <[u8; 12]>::try_from(nonce_bytes)
                    .map_err(|_| anyhow!("ChaCha20 nonce must be 12 bytes"))?,
            );
            cipher_cha
                .decrypt(&nonce_cha, actual_cipher)
                .map_err(|_| anyhow::anyhow!("chunk decryption failed"))?
        } else {
            let cipher = Aes256Gcm::new_from_slice(dek)
                .map_err(|_| anyhow!("AES-256 chunk key must be 32 bytes"))?;
            cipher
                .decrypt(&Nonce::clone_from_slice(nonce_bytes), actual_cipher)
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
                if orig_len <= len - 4 && orig_len <= 128 * 1024 * 1024 {
                    plain_or_compressed.truncate(orig_len);
                } else {
                    anyhow::bail!(
                        "padding length {orig_len} is implausible for buffer of size {len}"
                    );
                }
            } else if len > 0 {
                anyhow::bail!("Padded block too small: {len} bytes (< 4 byte padding header)");
            }
        }
        let plaintext = decompress_sealed(
            plain_or_compressed,
            comp_algo_type,
            Some(expected_len),
            self.max_plaintext_len,
        )?;
        if plaintext.len() != expected_len as usize {
            anyhow::bail!("sealed chunk plaintext length mismatch");
        }
        if blake3::hash(&plaintext).as_bytes() != expected_hash {
            anyhow::bail!("sealed chunk plaintext hash mismatch");
        }
        Ok(zeroize::Zeroizing::new(plaintext))
    }

    #[cfg(test)]
    pub fn encrypt_chunk_symmetric(
        &self,
        plaintext: &[u8],
        sym_key_bytes: &[u8],
        comp_algo_override: Option<&str>,
    ) -> Result<(Vec<u8>, u8)> {
        self.encrypt_chunk_with_nonce_mode(
            plaintext,
            sym_key_bytes,
            comp_algo_override,
            self.disable_dedup,
        )
    }

    fn encrypt_chunk_with_nonce_mode(
        &self,
        plaintext: &[u8],
        sym_key_bytes: &[u8],
        comp_algo_override: Option<&str>,
        random_nonce: bool,
    ) -> Result<(Vec<u8>, u8)> {
        let mut compressed_data = None;
        let active_comp = comp_algo_override.unwrap_or(&self.comp_algo);
        if active_comp != "none" && active_comp != "zstd" && active_comp != "lz4" {
            anyhow::bail!("unknown compression algorithm: {active_comp}");
        }

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
        let pad_len = (4096 - (final_data.len() % 4096)) % 4096;
        final_data.resize(final_data.len() + pad_len, 0u8);
        final_data.extend_from_slice(&orig_len.to_be_bytes());
        comp_type |= 0x80; // Set padded flag

        let mut nonce_bytes = vec![0u8; 12];
        if random_nonce {
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

        if random_nonce {
            let mut final_cipher = nonce_bytes;
            final_cipher.append(&mut ciphertext);
            ciphertext = final_cipher;
        }

        Ok((ciphertext, comp_type))
    }

    fn decrypt_chunk_symmetric(
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
        let record = self.decrypt_blob_cached(wrapped_sym_key)?;
        // reader accepts ONLY sealed CSK02 records.  Legacy raw 32-byte
        // wrapped keys are rejected (all current archive data is sealed; B05).
        let meta = parse_sealed_record(&record)?;
        validate_cipher_pair(meta.cipher_id, cipher_algo)?;
        if meta.comp_type != comp_type {
            anyhow::bail!("sealed chunk comp_type does not match request");
        }
        if meta.plaintext_len > self.max_plaintext_len as u64
            || meta.ciphertext_len != ciphertext.len() as u64
            || meta.object_hash != *blake3::hash(ciphertext).as_bytes()
        {
            anyhow::bail!("sealed chunk metadata is corrupt");
        }
        let (sym_key_bytes, expected_len) = (&record[5..37], Some(meta.plaintext_len as usize));

        // B05: all current archive objects are sealed (BF-01). The convergent
        // nonce read path predates sealing and is removed so decrypt never
        // depends on the runtime disable_dedup flag — the nonce always comes
        // from the ciphertext prefix written at seal time.
        if ciphertext.len() < 12 {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }
        let (nonce_bytes, actual_cipher) = ciphertext.split_at(12);

        let plain_or_compressed = if is_chacha(cipher_algo) {
            use chacha20poly1305::{
                ChaCha20Poly1305,
                aead::{Aead, KeyInit},
            };
            let key_arr: [u8; 32] = sym_key_bytes
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
            let cipher = Aes256Gcm::new_from_slice(sym_key_bytes)
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

        let plaintext = decompress_sealed(
            plain_or_compressed,
            comp_algo_type,
            expected_len.map(|e| e as u64),
            self.max_plaintext_len,
        )?;
        if let Some(expected_len) = expected_len {
            if plaintext.len() != expected_len {
                anyhow::bail!("sealed chunk plaintext length mismatch");
            }
        }
        if plaintext.len() > self.max_plaintext_len {
            anyhow::bail!("plaintext exceeds configured maximum");
        }
        if blake3::hash(&plaintext).as_bytes() != &meta.plaintext_hash {
            anyhow::bail!("sealed chunk plaintext hash mismatch");
        }
        Ok(zeroize::Zeroizing::new(plaintext))
    }

    /// Open a sealed chunk without trusting unauthenticated caller metadata.
    /// The compression and cipher settings are recovered from the authenticated
    /// CSK02 record before delegating to the normal sealed reader.
    pub fn decrypt_sealed_chunk(
        &self,
        ciphertext: &[u8],
        wrapped_key: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let record = self.decrypt_blob_cached(wrapped_key)?;
        if record.len() != SEALED_KEY_LEN || !record.starts_with(SEALED_KEY_MAGIC) {
            anyhow::bail!("record is not a sealed CSK02 chunk-key record");
        }
        let cipher_algo = match record[38] {
            0 => "aes-gcm",
            1 => "chacha20-poly1305",
            id => anyhow::bail!("unknown cipher id {id} in sealed chunk record"),
        };
        self.decrypt_chunk_symmetric(ciphertext, wrapped_key, record[37], cipher_algo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519::Identity;
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
            max_plaintext_len: DEFAULT_MAX_PLAINTEXT_LEN,
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
        // Sealed contract (R05/B05): even in no-dedup mode, two seal_chunk
        // calls on identical plaintext produce DIFFERENT ciphertext (random
        // DEK + nonce per chunk — no convergence oracle), and both round-trip
        // through the SEALED decrypt path (raw-key read is gone).
        for dedup_flag in [true, false] {
            let ctx = setup_ctx("aes-gcm", dedup_flag);
            let plaintext = b"identical chunk plaintext for the convergence probe, padded long";

            let a = ctx.seal_chunk(plaintext, None).unwrap();
            let b = ctx.seal_chunk(plaintext, None).unwrap();
            assert_ne!(a.ciphertext, b.ciphertext, "ciphertext must not converge");

            for sealed in [&a, &b] {
                let out = ctx
                    .decrypt_chunk_symmetric(
                        &sealed.ciphertext,
                        &sealed.wrapped_key,
                        sealed.comp_type,
                        &sealed.cipher_algo,
                    )
                    .unwrap();
                assert_eq!(plaintext.as_slice(), out.as_slice());
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm() {
        let ctx = setup_ctx("aes-gcm", false);
        let plaintext = b"hello world, this is a test payload long enough to maybe compress";

        let sealed = ctx.seal_chunk(plaintext, None).unwrap();
        let decrypted = ctx
            .decrypt_chunk_symmetric(
                &sealed.ciphertext,
                &sealed.wrapped_key,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_chacha20() {
        let ctx = setup_ctx("chacha20poly1305", false);
        let plaintext = b"hello world, this is a test payload long enough to maybe compress";

        let sealed = ctx.seal_chunk(plaintext, None).unwrap();
        let decrypted = ctx
            .decrypt_chunk_symmetric(
                &sealed.ciphertext,
                &sealed.wrapped_key,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn seal_chunk_random_objects_roundtrip() {
        for algo in ["aes-gcm", "chacha20-poly1305"] {
            for disable_dedup in [false, true] {
                let ctx = setup_ctx(algo, disable_dedup);
                let data = vec![42; 8192];
                let first = ctx.seal_chunk(&data, None).unwrap();
                let second = ctx.seal_chunk(&data, None).unwrap();
                assert_ne!(first.object_id, second.object_id);
                assert_ne!(first.ciphertext, second.ciphertext);
                assert_eq!(
                    ctx.decrypt_chunk_symmetric(
                        &first.ciphertext,
                        &first.wrapped_key,
                        first.comp_type,
                        &first.cipher_algo
                    )
                    .unwrap(),
                    data.clone().into()
                );
                assert_eq!(
                    ctx.decrypt_chunk_symmetric(
                        &second.ciphertext,
                        &second.wrapped_key,
                        second.comp_type,
                        &second.cipher_algo
                    )
                    .unwrap(),
                    data.into()
                );
            }
        }
    }

    #[test]
    fn seal_chunk_content_id_is_archive_keyed() {
        let ctx = setup_ctx("aes-gcm", false);
        let id = ctx.content_id(b"same").unwrap().unwrap();
        assert_eq!(ctx.content_id(b"same").unwrap(), Some(id));
        assert_ne!(ctx.content_id(b"different").unwrap(), Some(id));
        assert_eq!(
            setup_ctx("aes-gcm", true).content_id(b"same").unwrap(),
            None
        );
    }

    #[test]
    fn seal_chunk_rejects_authenticated_metadata_mismatch() {
        let ctx = setup_ctx("aes-gcm", false);
        let sealed = ctx.seal_chunk(&vec![b'a'; 16384], Some("zstd")).unwrap();
        assert!(
            ctx.decrypt_chunk_symmetric(
                &sealed.ciphertext,
                &sealed.wrapped_key,
                sealed.comp_type ^ 1,
                &sealed.cipher_algo
            )
            .is_err()
        );
        let mut record = ctx.decrypt_blob(&sealed.wrapped_key).unwrap();
        record[39..47].copy_from_slice(&10u64.to_le_bytes());
        let wrapped = ctx.encrypt_blob(&record).unwrap();
        assert!(
            ctx.decrypt_chunk_symmetric(
                &sealed.ciphertext,
                &wrapped,
                sealed.comp_type,
                &sealed.cipher_algo
            )
            .is_err()
        );
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

    fn plaintext_pair() -> &'static [u8] {
        b"shared-dedup canonical payload for the domain"
    }

    #[test]
    fn test_shared_domain_wrap_unwrap_roundtrip_random_nonce() {
        let key = shared_domain_wrapping_key(b"domain secret");
        let record = b"CSK02fixed-shared-record-bytes-for-the-wrap-test...";
        let wrapped = wrap_with_domain_key(record, &key).unwrap();
        assert!(wrapped.starts_with(b"CKEK1"), "must use the KEK envelope");
        assert!(wrapped.len() > record.len(), "nonce+tag overhead");
        let unwrapped = unwrap_with_domain_key(&wrapped, &key).unwrap();
        assert_eq!(unwrapped.as_slice(), record);
        // Distinct nonces per wrap → two wraps of the same record differ
        // (condition 4: no deterministic IV).
        let again = wrap_with_domain_key(record, &key).unwrap();
        assert_ne!(wrapped, again, "random nonce per wrap");
        // Wrong domain key fails loudly.
        assert!(unwrap_with_domain_key(&wrapped, &shared_domain_wrapping_key(b"other")).is_err());
    }

    #[test]
    fn test_seal_chunk_shared_domain_member_can_decrypt() {
        let ctx = symmetric_ctx("correct horse battery staple", None).unwrap();
        let domain_key = shared_domain_wrapping_key(b"shared domain secret");
        let plaintext = plaintext_pair();
        let sealed = ctx.seal_chunk_shared(plaintext, None, &domain_key).unwrap();

        // The domain-wrapped record parses to the bound metadata and the
        // ciphertext the record names.
        let record = unwrap_with_domain_key(&sealed.domain_wrapped_key, &domain_key).unwrap();
        let meta = parse_sealed_record(&record).unwrap();
        assert_eq!(meta.ciphertext_len, sealed.ciphertext_len);
        assert_eq!(meta.plaintext_len, sealed.plaintext_len);
        assert_eq!(meta.object_hash, sealed.object_hash);
        assert_eq!(meta.comp_type, sealed.comp_type);

        // A domain member (another archive, same domain secret) decrypts the
        // SAME canonical object:
        let decrypted = ctx
            .decrypt_chunk_shared_record(
                &sealed.ciphertext,
                &record,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
            .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_seal_chunk_shared_archive_path_still_works_for_publisher() {
        let ctx = symmetric_ctx("correct horse battery staple", None).unwrap();
        let domain_key = shared_domain_wrapping_key(b"shared domain secret");
        let plaintext = plaintext_pair();
        let sealed = ctx.seal_chunk_shared(plaintext, None, &domain_key).unwrap();

        // The publisher's own index stores the archive-key wrap; factory reads
        // still decrypt via decrypt_chunk_symmetric.
        let decrypted = ctx
            .decrypt_chunk_symmetric(
                &sealed.ciphertext,
                &sealed.archive_wrapped_key,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
            .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
        // ...and the domain wrap decrypts the same object as well.
        let record = unwrap_with_domain_key(&sealed.domain_wrapped_key, &domain_key).unwrap();
        let via_domain = ctx
            .decrypt_chunk_shared_record(
                &sealed.ciphertext,
                &record,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
            .unwrap();
        assert_eq!(via_domain.as_slice(), plaintext);
    }

    #[test]
    fn test_parse_sealed_record_rejects_truncated_or_mangled() {
        assert!(parse_sealed_record(b"short").is_err());
        let good = [0u8; SEALED_KEY_LEN];
        let mut rec = good;
        rec[0..5].copy_from_slice(SEALED_KEY_MAGIC);
        assert!(parse_sealed_record(&rec).is_ok());
        rec[80] ^= 0xFF; // corrupt object_hash region
        assert!(parse_sealed_record(&rec).is_ok(), "magic/len unchanged");
        // Mangle the magic instead:
        let mut bad = rec;
        bad[0] = b'X';
        assert!(parse_sealed_record(&bad).is_err());
    }

    #[test]
    fn sealed_plaintext_hash_is_checked_after_authenticated_unwrap() {
        let ctx = setup_ctx("aes-gcm", false);
        let sealed = ctx
            .seal_chunk(b"plaintext integrity", Some("none"))
            .unwrap();
        // Re-encrypting the altered record makes the outer wrapper valid, so
        // this reaches the post-decryption plaintext-hash check rather than
        // merely proving that AEAD rejects a corrupted wrapper.
        let mut record = ctx.decrypt_blob(&sealed.wrapped_key).unwrap();
        record[87] ^= 0x80;
        let altered = ctx.encrypt_blob(&record).unwrap();
        let err = ctx
            .decrypt_sealed_chunk(&sealed.ciphertext, &altered)
            .unwrap_err();
        assert!(err.to_string().contains("plaintext hash mismatch"), "{err}");
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

        // Full chunk roundtrip through the sealed (BF-01) path.
        let sealed = ctx.seal_chunk(plaintext, None).unwrap();
        let decrypted = ctx
            .decrypt_chunk_symmetric(
                &sealed.ciphertext,
                &sealed.wrapped_key,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
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

            let sealed = ctx.seal_chunk(plaintext, None).unwrap();
            let decrypted = ctx
                .decrypt_chunk_symmetric(
                    &sealed.ciphertext,
                    &sealed.wrapped_key,
                    sealed.comp_type,
                    &sealed.cipher_algo,
                )
                .unwrap();

            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        }
    }

    #[test]
    fn seal_rejects_unknown_compression_flag_on_roundtrip() {
        let ctx = setup_ctx("aes-gcm", false);
        let data = vec![7u8; 512];
        let sealed = ctx.seal_chunk(&data, None).unwrap();
        assert!(ctx.seal_chunk(&data, Some("none")).is_ok());
        let wrapped = sealed.wrapped_key.clone();
        let res = ctx.decrypt_chunk_symmetric(&sealed.ciphertext, &wrapped, 99u8, "aes-gcm");
        assert!(res.is_err());
    }

    #[test]
    fn seal_rejects_unknown_compression_algorithm_on_write() {
        let ctx = setup_ctx("aes-gcm", false);
        assert!(
            ctx.seal_chunk(b"hello".repeat(100).as_slice(), Some("bzip2"))
                .is_err()
        );
        assert!(
            ctx.encrypt_chunk_symmetric(b"data", &[0u8; 32], Some("bzip2"))
                .is_err()
        );
    }

    #[test]
    fn r04_lz4_oversized_prefix_is_rejected_before_allocation() {
        // the LZ4 length prefix is attacker-controlled.  A real lz4 block
        // with a HUGE prefixed size must be rejected against the authenticated
        // expected_len BEFORE any allocation happens.
        let original = vec![0x5Au8; 1024];
        let block = lz4_flex::compress(&original);
        let mut crafted = Vec::with_capacity(4 + block.len());
        crafted.extend_from_slice(&(1u64 << 30).to_le_bytes());
        crafted.extend_from_slice(&block);
        let err = decompress_sealed(crafted, 2, Some(1024), 1 << 20).unwrap_err();
        assert!(
            err.to_string().contains("exceeding the configured bound"),
            "{err}"
        );
    }

    #[test]
    fn r04_lz4_positive_control_and_malformed_header() {
        let original = vec![0x3Cu8; 2048];
        let block = lz4_flex::compress(&original);
        let mut proper = Vec::with_capacity(4 + block.len());
        proper.extend_from_slice(&(original.len() as u32).to_le_bytes());
        proper.extend_from_slice(&block);
        let out = decompress_sealed(proper, 2, Some(original.len() as u64), 1 << 20).unwrap();
        assert_eq!(out, original, "positive control must round-trip");

        let err = decompress_sealed(vec![1u8, 2], 2, Some(1), 1 << 10).unwrap_err();
        assert!(err.to_string().contains("LZ4 block too small"), "{err}");
    }

    #[test]
    fn r04_zstd_oversized_declared_content_is_rejected() {
        // A 1 MiB zero block compresses to a few hundred bytes, so the FRAME
        // HEADER still declares the full output size — decompress_sealed must
        // reject it against a small bound WITHOUT allocating megabytes.
        let big = vec![0u8; 1 << 20];
        let compressed = zstd::bulk::compress(&big, 3).unwrap();
        let err = decompress_sealed(compressed.clone(), 1, Some(1024), 1024).unwrap_err();
        assert!(
            err.to_string().contains("exceeding the configured bound"),
            "{err}"
        );
        // Positive control: the same stream decompresses when the bound is big
        // enough (no gigabytes; 1 MiB is fine).
        let out = decompress_sealed(compressed, 1, Some(1 << 20), 1 << 20).unwrap();
        assert_eq!(out, big);
    }

    #[test]
    fn seal_zstd_sealed_path_still_roundtrips_with_the_new_bound() {
        // Regression guard: legitimately sealed zstd/lz4 chunks still decrypt
        // through the real decrypt path now that the decoder gate is bounded.
        for comp in ["zstd", "lz4"] {
            let ctx = setup_ctx("aes-gcm", false);
            let data = b"The quick brown fox ".repeat(512);
            let sealed = ctx
                .seal_chunk(&data, Some(comp))
                .unwrap_or_else(|e| panic!("seal {comp}: {e}"));
            let out = ctx
                .decrypt_chunk_symmetric(
                    &sealed.ciphertext,
                    &sealed.wrapped_key,
                    sealed.comp_type,
                    &sealed.cipher_algo,
                )
                .unwrap_or_else(|e| panic!("decrypt {comp}: {e}"));
            assert_eq!(out.as_slice(), &data[..], "roundtrip {comp}");
        }
    }

    #[test]
    fn r05_raw_wrapped_key_is_rejected() {
        // Reader accepts ONLY sealed CSK02 records: a wrapped blob that unwraps
        // to 32 raw bytes (no CSK02 magic) must be refused.
        let ctx = setup_ctx("aes-gcm", false);
        let raw = b"R".repeat(32);
        let wrapped = ctx.encrypt_blob(&raw).unwrap();
        let ciphertext = b"nonce-prefixed-ciphertext-bytes";
        let err = ctx
            .decrypt_chunk_symmetric(ciphertext, &wrapped, 0, "aes-gcm")
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("not a sealed chunk-key record (CSK02)"),
            "{err}"
        );
    }

    #[test]
    fn r05_unknown_cipher_id_is_rejected() {
        let ctx = setup_ctx("aes-gcm", false);
        let data = b"cipher whitelist probe".repeat(4);
        let sealed = ctx.seal_chunk(&data, None).unwrap();
        // Materialize the sealed record, flip the cipher id to an unknown one
        // (9) and re-wrap it: decryption must refuse the pair explicitly.
        let mut rec = ctx.decrypt_blob(&sealed.wrapped_key).unwrap().to_vec();
        rec[38] = 9;
        let evil = ctx.encrypt_blob(&rec).unwrap();
        let err = ctx
            .decrypt_chunk_symmetric(&sealed.ciphertext, &evil, sealed.comp_type, "aes-gcm")
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown cipher id 9"), "{msg}");
    }

    #[test]
    fn plaintext_hash_mismatch_is_rejected_after_decompress_on_both_paths() {
        // Post-decompress plaintext-hash verification: a validly AEAD-wrapped
        // sealed record whose (authenticated) plaintext hash has been altered
        // must be rejected with "plaintext hash mismatch" on the archive path
        // AND on the shared/domain-read path.
        let ctx = setup_ctx("aes-gcm", false);
        let payload = b"post-decompress plaintext-hash verification".repeat(8);
        let sealed = ctx.seal_chunk(&payload, Some("zstd")).unwrap();

        // Archive path: flip the plaintext-hash field inside the SEALED record
        // and re-wrap it with the archive key.
        let mut record = ctx.decrypt_blob(&sealed.wrapped_key).unwrap().to_vec();
        assert_eq!(record.len(), 119, "CSK02 sealed record length");
        record[87..119].copy_from_slice(&[0xEEu8; 32]);
        let evil = ctx.encrypt_blob(&record).unwrap();
        let err = ctx
            .decrypt_chunk_symmetric(&sealed.ciphertext, &evil, sealed.comp_type, "aes-gcm")
            .unwrap_err();
        assert!(
            err.to_string().contains("plaintext hash mismatch"),
            "archive: {err}"
        );

        // Shared/domain path: same tamper inside the domain-wrapped record.
        let domain_key = shared_domain_wrapping_key(b"some pool secret");
        let shared = ctx
            .seal_chunk_shared(&payload, Some("zstd"), &domain_key)
            .unwrap();
        let mut sha_record = unwrap_with_domain_key(&shared.domain_wrapped_key, &domain_key)
            .unwrap()
            .to_vec();
        sha_record[87..119].copy_from_slice(&[0xCCu8; 32]);
        let err2 = ctx
            .decrypt_chunk_shared_record(
                &shared.ciphertext,
                &sha_record,
                shared.comp_type,
                &shared.cipher_algo,
            )
            .unwrap_err();
        assert!(
            err2.to_string().contains("plaintext hash mismatch"),
            "shared: {err2}"
        );

        // Positive controls: untouched records still decrypt on both paths.
        let ok1 = ctx
            .decrypt_chunk_symmetric(
                &sealed.ciphertext,
                &sealed.wrapped_key,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
            .unwrap();
        assert_eq!(ok1.as_slice(), payload);
        let rec2 = unwrap_with_domain_key(&shared.domain_wrapped_key, &domain_key).unwrap();
        let ok2 = ctx
            .decrypt_chunk_shared_record(
                &shared.ciphertext,
                &rec2,
                shared.comp_type,
                &shared.cipher_algo,
            )
            .unwrap();
        assert_eq!(ok2.as_slice(), payload);
    }
}
