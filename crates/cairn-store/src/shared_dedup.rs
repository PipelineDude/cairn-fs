//! D02: shared-dedup records + atomic conditional publication (BF-02).
//!
//! Shape per `SHARED_DEDUP_DESIGN.md` §4/§6 (reviewed, D00):
//!
//! - a **record** maps a shared `content_id` (in a `domain_ns`) to the stored
//!   object that holds the chunk ciphertext plus its sealed metadata;
//! - publication is an **atomic conditional-create**: the first writer wins,
//!   a concurrent loser reads the winner's record and uses it as-is;
//! - a backend that cannot provide atomic conditional-create refuses shared
//!   mode at the *capability gate* instead of silently check-then-writing.
//!
//! The local (filesystem) backend satisfies the gate with POSIX `O_CREAT|O_EXCL`
//! (atomic on a single node) — the record file IS the lock.  Cloud backends
//! via opendal are *not* yet proven to expose an atomic if-not-exists primitive
//! on this build (D00 review condition 2), so they fail the gate loudly here.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(feature = "cloud-storage")]
use crate::CloudOperator;
#[cfg(not(feature = "cloud-storage"))]
use crate::CloudOperator;

/// Wrapped chunk metadata that travels inside the shared record (design §4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedDedupMeta {
    /// Domain-wrapped sealed chunk-key record (CSK02), as produced by
    /// cairn_seal::seal_chunk_shared → domain wrap.
    pub wrapped_key: Vec<u8>,
    pub comp_type: u8,
    pub cipher_algo: String,
    pub plaintext_len: u64,
    pub ciphertext_len: u64,
    /// blake3 of the canonical ciphertext == SharedDedupRecord.object_id.
    pub blake3_hash: String,
}

/// One `dedup/shared/<ns>/<content_id>` mapping (design §4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedDedupRecord {
    pub format: String,
    pub domain_ns: String,
    pub content_id: String,
    pub object_id: String,
    pub sealed_meta: SharedDedupMeta,
    /// Existing archive-key sealed metadata re-wrapped by the domain key.
    pub wrapped_by_domain_key: bool,
}

impl SharedDedupRecord {
    pub fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// HKDF-style domain key (blake3 `derive_key` — the recommended key-derivation
/// from a single secret, equivalent to HKDF-expand in the design's §3 wording)
/// for shared CONTENT ids.
const SHARED_CONTENT_KDF_CONTEXT: &str = "cairn shared content v1";

/// Derive the 32-byte domain content-key from the domain secret.  The derived
/// key is a secret in its own right (every copy of the key is a
/// zeroizing container, not a plain array that the caller can forget to scrub).
pub fn shared_domain_content_key(secret: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(SHARED_CONTENT_KDF_CONTEXT, secret))
}

/// Shared content-id for `plaintext` under a domain (design §3):
/// `keyed_blake3(key = KDF(secret), input = ns_encoding(domain, plaintext))`
/// where the namespace embeds `domain|fingerprint(secret)`, so a different
/// domain OR secret yields a different content-id and no cross-sharing.
///
/// The result is also derived-key-shaped (keyed_blake3 output), so it lives in
/// a zeroizing container too; the on-disk mapping keeps only the hex form.
pub fn shared_content_id(domain_id: &str, secret: &[u8], plaintext: &[u8]) -> Zeroizing<[u8; 32]> {
    let ns = derive_namespace(domain_id, secret);
    let mut input = Vec::with_capacity(ns.len() + 1 + plaintext.len());
    input.extend_from_slice(ns.as_bytes());
    input.push(b'|');
    input.extend_from_slice(plaintext);
    let key = shared_domain_content_key(secret);
    let hash = blake3::keyed_hash(&key, &input);
    Zeroizing::new(*hash.as_bytes())
}

/// Verify a published record against the object it points to (design §7):
/// the stored ciphertext must hash to `sealed_meta.blake3_hash` and that must
/// equal the `object_id` the record binds the content_id to.
pub fn verify_shared_record(record: &SharedDedupRecord, object_bytes: &[u8]) -> anyhow::Result<()> {
    let actual = blake3::hash(object_bytes).to_hex().to_string();
    if actual != record.sealed_meta.blake3_hash {
        anyhow::bail!(
            "shared record mismatch: object {} hashes to {actual}, record expected {}",
            record.object_id,
            record.sealed_meta.blake3_hash
        );
    }
    if actual != record.object_id {
        anyhow::bail!(
            "shared record inconsistent: object_id {} != object hash {actual}",
            record.object_id
        );
    }
    if record.format != "cairn-shared-v1" {
        anyhow::bail!("unsupported shared record format: {}", record.format);
    }
    Ok(())
}

/// Result of one (possibly racing) publication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicCreateOutcome {
    /// This writer's record became the published one.
    Published,
    /// Another writer won the race; `record` is the winner's mapping,
    /// which the caller must verify and use instead.
    LostToExisting(SharedDedupRecord),
}

/// Store-level key for a shared record (design §4 "Store keys").
pub fn shared_record_key(namespace: &str, content_id: &str) -> String {
    format!("dedup/shared/{namespace}/{content_id}.json")
}

/// Filesystem key for the canonical ciphertext associated with a shared record.
/// Unlike an archive-local cacache entry, this path is intentionally identical
/// for every archive that joins the same domain store.
pub fn shared_object_key(namespace: &str, object_id: &str) -> String {
    format!("dedup/shared/{namespace}/objects/{object_id}")
}

/// Persist a canonical ciphertext before its mapping can be published.  A
/// mapping is written only after this call returns, so an adopter never sees a
/// record referring to a partially-written object.
pub fn put_shared_object(
    records_dir: &str,
    namespace: &str,
    object_id: &str,
    ciphertext: &[u8],
) -> anyhow::Result<()> {
    validate_storage_component(namespace, "namespace")?;
    validate_storage_component(object_id, "object id")?;
    let path = Path::new(records_dir).join(shared_object_key(namespace, object_id));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(ciphertext)?;
            file.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing = std::fs::read(&path)?;
            if blake3::hash(&existing).to_hex().as_str() != object_id {
                anyhow::bail!("shared object {object_id} exists but fails its hash check");
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Read and hash-verify a canonical ciphertext from the domain store.
pub fn read_shared_object(
    records_dir: &str,
    namespace: &str,
    object_id: &str,
) -> anyhow::Result<Vec<u8>> {
    validate_storage_component(namespace, "namespace")?;
    validate_storage_component(object_id, "object id")?;
    let path = Path::new(records_dir).join(shared_object_key(namespace, object_id));
    let bytes = std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!("shared object {object_id} is unavailable: {e}"))?;
    if blake3::hash(&bytes).to_hex().as_str() != object_id {
        anyhow::bail!("shared object {object_id} fails its hash check");
    }
    Ok(bytes)
}

/// Fingerprint of the domain secret (the non-secret identity persisted in an
/// archive's config).  Same derivation as the bin's `shared_dedup` module;
/// cairn-store is the single source of truth for the crypto seam.
pub fn fingerprint_secret(secret: &[u8]) -> String {
    blake3::hash(secret).to_hex()[..32].to_string()
}

/// Look up the published record for `content_id` in a domain store
/// (BF-04.10). `None` when this store has never seen the content. A corrupt
/// record is a loud error, never a silent miss — same rule as the race path.
pub fn read_shared_record(
    records_dir: &str,
    namespace: &str,
    content_id: &str,
) -> anyhow::Result<Option<SharedDedupRecord>> {
    validate_storage_component(namespace, "namespace")?;
    validate_storage_component(content_id, "content id")?;
    let path = Path::new(records_dir).join(shared_record_key(namespace, content_id));
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            anyhow::bail!(
                "cannot read shared record {content_id} at {}: {e}",
                path.display()
            )
        }
    };
    Ok(Some(SharedDedupRecord::from_json(&bytes)?))
}

pub fn derive_namespace(domain_id: &str, secret: &[u8]) -> String {
    // A namespace is a storage-path component, not a display name.  Hashing
    // the caller-supplied pool name avoids path traversal and makes the path
    // independent of punctuation in an otherwise human-readable pool ID.
    format!(
        "{}-{}",
        blake3::hash(domain_id.as_bytes()).to_hex(),
        fingerprint_secret(secret)
    )
}

fn validate_storage_component(component: &str, what: &str) -> anyhow::Result<()> {
    if component.is_empty()
        || component.contains('/')
        || component.contains('\\')
        || component == "."
        || component == ".."
    {
        anyhow::bail!("invalid shared {what} path component");
    }
    Ok(())
}

/// Capability gate (design §6). Cloud opendal buses have no proven atomic
/// if-not-exists primitive here yet -> refuse shared mode. Local FS => true.
#[cfg(feature = "cloud-storage")]
pub fn shared_dedup_supported(backends: &[CloudOperator]) -> bool {
    // Condition 2 (D00 review): opendal 0.57 does not expose a general
    // write_if_not_exists.  Until a per-service atomic-create path lands,
    // ANY configured cloud backend must refuse shared mode.
    backends.is_empty()
}

#[cfg(not(feature = "cloud-storage"))]
pub fn shared_dedup_supported(_backends: &[CloudOperator]) -> bool {
    // No cloud feature compiled: the only backend is the local filesystem,
    // which we can satisfy with O_CREAT|O_EXCL.
    true
}

/// Assert the gate; the caller reports a hard error when shared mode was
/// requested and the configured backends cannot publish atomically.
#[cfg(feature = "cloud-storage")]
pub fn ensure_shared_dedup_supported(backends: &[CloudOperator]) -> anyhow::Result<()> {
    if shared_dedup_supported(backends) {
        Ok(())
    } else {
        anyhow::bail!(
            "shared-dedup requires an atomic get-or-create backend; the configured cloud \
             backends do not expose write-if-not-exists on this build (opendal 0.57). \
             Use isolated archive dedup or a filesystem-only backend."
        )
    }
}

#[cfg(not(feature = "cloud-storage"))]
pub fn ensure_shared_dedup_supported(_backends: &[CloudOperator]) -> anyhow::Result<()> {
    Ok(())
}

/// Atomic conditional-create against the LOCAL filesystem backend
/// (single-node): publish `record` at `<records_dir>/dedup/shared/<ns>/<id>.json`
/// with `O_CREAT|O_EXCL`.  On EEXIST the winner's record is read back; a
/// corrupt winner record is a loud error (design §7).
pub async fn atomic_get_or_create_local(
    records_dir: &str,
    record: &SharedDedupRecord,
) -> anyhow::Result<AtomicCreateOutcome> {
    validate_storage_component(&record.domain_ns, "namespace")?;
    validate_storage_component(&record.content_id, "content id")?;
    let key = shared_record_key(&record.domain_ns, &record.content_id);
    let path = Path::new(records_dir).join(key);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write a complete, durable temporary file first.  Linking it into place
    // is a no-replace atomic publication on one filesystem: readers either
    // see no mapping or a fully-written mapping, never a zero-byte O_EXCL
    // destination that a concurrent writer is still filling.
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let temp = path.with_file_name(format!(
        ".cairn-shared-{}-{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> anyhow::Result<AtomicCreateOutcome> {
        let bytes = record.to_json()?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        use std::io::Write;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        match std::fs::hard_link(&temp, &path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    std::fs::File::open(parent)?.sync_all()?;
                }
                Ok(AtomicCreateOutcome::Published)
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let winner = std::fs::read(&path)
                    .map_err(|e| anyhow::anyhow!("shared record present but unreadable: {e}"))?;
                let winner = SharedDedupRecord::from_json(&winner).map_err(|e| anyhow::anyhow!(
                    "shared record at {} is corrupt ({e}); refusing to use or silently overwrite it -- loud fail per D00 §7",
                    path.display()
                ))?;
                Ok(AtomicCreateOutcome::LostToExisting(winner))
            }
            Err(e) => Err(anyhow::anyhow!(
                "shared record publish failed at {}: {e}",
                path.display()
            )),
        }
    })();
    let _ = std::fs::remove_file(&temp);
    result
}

/// Outcome of a full published-or-adopt cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedPublish {
    /// This process's record is the published mapping.
    Published(SharedDedupRecord),
    /// Another archive in the domain already published the content; this
    /// process adopted the WINNER's (independently verified) record.
    Adopted(SharedDedupRecord),
}

/// Publish a shared chunk or adopt the already-published winner (D02/§5.4 + §7).
///
/// Semantics: conditional-create first; on winning, return the published
/// record.  On losing, READ the winner's object through `read_object` and
/// verify it against the winner's record before adopting it -- a missing or
/// corrupt winner object is a LOUD error, never a silent mismatch (the caller
/// must not index a record whose object cannot be verified).
pub async fn publish_shared_or_adopt<F, Fut>(
    records_dir: &str,
    record: &SharedDedupRecord,
    read_object: F,
) -> anyhow::Result<SharedPublish>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send,
{
    match atomic_get_or_create_local(records_dir, record).await? {
        AtomicCreateOutcome::Published => Ok(SharedPublish::Published(record.clone())),
        AtomicCreateOutcome::LostToExisting(winner) => {
            let object = read_object(winner.object_id.clone()).await.map_err(|e| {
                anyhow::anyhow!(
                    "shared record adopted at {} but its object {} is unreadable: {e}",
                    shared_record_key(&winner.domain_ns, &winner.content_id),
                    winner.object_id
                )
            })?;
            verify_shared_record(&winner, &object).map_err(|e| {
                anyhow::anyhow!(
                    "shared winner object {} failed verification: {e}",
                    winner.object_id
                )
            })?;
            Ok(SharedPublish::Adopted(winner))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(ns: &str, content_id: &str, object_id: &str) -> SharedDedupRecord {
        SharedDedupRecord {
            format: "cairn-shared-v1".to_string(),
            domain_ns: ns.to_string(),
            content_id: content_id.to_string(),
            object_id: object_id.to_string(),
            sealed_meta: SharedDedupMeta {
                wrapped_key: b"domain-wrapped-record".to_vec(),
                comp_type: 0,
                cipher_algo: "aes-gcm".to_string(),
                plaintext_len: 4096,
                ciphertext_len: 4096,
                blake3_hash: "abc123".to_string(),
            },
            wrapped_by_domain_key: true,
        }
    }

    #[tokio::test]
    async fn publish_or_adopt_wins_and_publishes() {
        let dir = tempfile::tempdir().unwrap();
        let rec = sample_record("team-a|fing", "cid-1", "obj-1");
        let out = publish_shared_or_adopt(dir.path().to_str().unwrap(), &rec, |_| async {
            Err(anyhow::anyhow!("read must not run when publication wins"))
        })
        .await
        .unwrap();
        assert_eq!(out, SharedPublish::Published(rec));
    }

    #[tokio::test]
    async fn publish_or_adopt_loses_then_verifies_the_winner() {
        let dir = tempfile::tempdir().unwrap();
        let plaintext = b"chunk payload";
        let winner = SharedDedupRecord {
            format: "cairn-shared-v1".to_string(),
            domain_ns: "team-a|fing".to_string(),
            content_id: "cid-1".to_string(),
            object_id: blake3::hash(plaintext).to_hex().to_string(),
            sealed_meta: SharedDedupMeta {
                wrapped_key: b"domain-wrapped-record".to_vec(),
                comp_type: 0,
                cipher_algo: "aes-gcm".to_string(),
                plaintext_len: plaintext.len() as u64,
                ciphertext_len: plaintext.len() as u64,
                blake3_hash: blake3::hash(plaintext).to_hex().to_string(),
            },
            wrapped_by_domain_key: true,
        };
        assert_eq!(
            atomic_get_or_create_local(dir.path().to_str().unwrap(), &winner)
                .await
                .unwrap(),
            AtomicCreateOutcome::Published
        );
        let mut raced = winner.clone();
        raced.object_id = "our-own-object".to_string();
        let objects =
            std::collections::HashMap::from([(winner.object_id.clone(), plaintext.to_vec())]);
        for _ in 0..10 {
            let out = publish_shared_or_adopt(dir.path().to_str().unwrap(), &raced, |id| {
                let objects = objects.clone();
                async move {
                    objects
                        .get(&id)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("object {id} missing"))
                }
            })
            .await
            .unwrap();
            assert_eq!(out, SharedPublish::Adopted(winner.clone()));
        }
    }

    #[tokio::test]
    async fn publish_or_adopt_fails_loud_on_missing_winner_object() {
        let dir = tempfile::tempdir().unwrap();
        let rec = sample_record("team-a|fing", "cid-1", "obj-existing");
        atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec)
            .await
            .unwrap();
        let err = publish_shared_or_adopt(dir.path().to_str().unwrap(), &rec, |_| {
            std::future::ready(Err(anyhow::anyhow!("object gone")))
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unreadable"), "{err}");
    }

    #[tokio::test]
    async fn publish_or_adopt_fails_loud_on_corrupt_winner_object() {
        let dir = tempfile::tempdir().unwrap();
        let rec = sample_record("team-a|fing", "cid-1", "obj-corrupt");
        atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec)
            .await
            .unwrap();
        let err = publish_shared_or_adopt(dir.path().to_str().unwrap(), &rec, |_| {
            std::future::ready(Ok(b"not the right bytes".to_vec()))
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("failed verification"), "{err}");
    }

    #[tokio::test]
    async fn first_creator_publishes() {
        let dir = tempfile::tempdir().unwrap();
        let rec = sample_record("team-a|fing", "cid-1", "obj-1");
        let out = atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec)
            .await
            .unwrap();
        assert_eq!(out, AtomicCreateOutcome::Published);
    }

    #[tokio::test]
    async fn second_creator_reads_the_winner() {
        let dir = tempfile::tempdir().unwrap();
        let winner = sample_record("team-a|fing", "cid-1", "obj-1");
        let loser = sample_record("team-a|fing", "cid-1", "obj-1");

        let out = atomic_get_or_create_local(dir.path().to_str().unwrap(), &winner)
            .await
            .unwrap();
        assert_eq!(out, AtomicCreateOutcome::Published);

        // A racing second publisher (identical content_id, own object_id) must
        // lose and adopt the winner's record -- not overwrite it.
        let mut raced = loser.clone();
        raced.object_id = "obj-X".to_string();
        let out = atomic_get_or_create_local(dir.path().to_str().unwrap(), &raced)
            .await
            .unwrap();
        match out {
            AtomicCreateOutcome::LostToExisting(r) => {
                assert_eq!(r, winner);
                assert_ne!(r.object_id, "obj-X");
            }
            other => panic!("expected LostToExisting, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn different_namespaces_do_not_share_() {
        let dir = tempfile::tempdir().unwrap();
        let a = sample_record("team-a|fing", "cid-1", "obj-a");
        let b = sample_record("team-b|fing2", "cid-1", "obj-b");
        assert_eq!(
            atomic_get_or_create_local(dir.path().to_str().unwrap(), &a)
                .await
                .unwrap(),
            AtomicCreateOutcome::Published
        );
        // Same content_id, different domain/secret namespace -> no sharing.
        assert_eq!(
            atomic_get_or_create_local(dir.path().to_str().unwrap(), &b)
                .await
                .unwrap(),
            AtomicCreateOutcome::Published
        );
    }

    #[tokio::test]
    async fn corrupt_winner_record_is_a_loud_error() {
        let dir = tempfile::tempdir().unwrap();
        let first = sample_record("team-a|fing", "cid-1", "obj-1");
        atomic_get_or_create_local(dir.path().to_str().unwrap(), &first)
            .await
            .unwrap();
        let key = shared_record_key("team-a|fing", "cid-1");
        std::fs::write(dir.path().join(key), "{not-json").unwrap();

        let err = atomic_get_or_create_local(dir.path().to_str().unwrap(), &first)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("corrupt"), "{err}");
    }

    #[test]
    fn record_json_roundtrip() {
        let rec = sample_record("team-a|fing", "cid-1", "obj-1");
        let bytes = rec.to_json().unwrap();
        let back = SharedDedupRecord::from_json(&bytes).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn cloud_capability_gate_refuses_if_any_opendal_backend() {
        #[cfg(feature = "cloud-storage")]
        {
            use opendal::services::Memory;
            let op = opendal::Operator::new(Memory::default()).unwrap();
            assert!(!shared_dedup_supported(&[op]));
            assert!(ensure_shared_dedup_supported(&[]).is_ok());
            let e =
                ensure_shared_dedup_supported(
                    &[opendal::Operator::new(Memory::default()).unwrap()],
                )
                .unwrap_err();
            assert!(e.to_string().contains("get-or-create"), "{e}");
        }
        #[cfg(not(feature = "cloud-storage"))]
        {
            assert!(shared_dedup_supported(&[]));
            assert!(ensure_shared_dedup_supported(&[]).is_ok());
        }
    }

    #[test]
    fn shared_content_id_is_keyed_by_domain_secret_and_content() {
        let cid_a = shared_content_id("team-a", b"secret", b"plaintext chunk");
        let cid_b = shared_content_id("team-a", b"secret", b"other chunk");
        let cid_c = shared_content_id("team-a", b"other-secret", b"plaintext chunk");
        let cid_d = shared_content_id("team-b", b"secret", b"plaintext chunk");

        assert_eq!(cid_a.len(), 32);
        assert_ne!(cid_a, cid_b, "different plaintext must differ");
        assert_ne!(cid_a, cid_c, "different secret must differ");
        assert_ne!(cid_a, cid_d, "different domain must differ");
        // Deterministic.
        assert_eq!(
            cid_a,
            shared_content_id("team-a", b"secret", b"plaintext chunk")
        );
    }

    #[test]
    fn verify_shared_record_matches_object_or_fails_loud() {
        let plaintext = b"the chunk to publish";
        let object = blake3::hash(plaintext).to_hex().to_string();
        let rec = SharedDedupRecord {
            format: "cairn-shared-v1".to_string(),
            domain_ns: "team-a|fing".to_string(),
            content_id: "cid".to_string(),
            object_id: object.clone(),
            sealed_meta: SharedDedupMeta {
                wrapped_key: b"key".to_vec(),
                comp_type: 0,
                cipher_algo: "aes-gcm".to_string(),
                plaintext_len: plaintext.len() as u64,
                ciphertext_len: plaintext.len() as u64,
                blake3_hash: object,
            },
            wrapped_by_domain_key: true,
        };
        assert!(verify_shared_record(&rec, plaintext).is_ok());

        let tampered = SharedDedupRecord {
            object_id: "other-object".to_string(),
            ..rec.clone()
        };
        assert!(verify_shared_record(&tampered, plaintext).is_err());

        let bad_format = SharedDedupRecord {
            format: "ancient-v0".to_string(),
            ..rec
        };
        assert!(verify_shared_record(&bad_format, plaintext).is_err());
    }

    #[tokio::test]
    async fn two_archives_of_one_domain_converge_to_one_published_record() {
        // D03 restart-consistency seam: two archives in the same domain share
        // a content-id, both publish conditionally, and both end up pointing
        // at the SAME winning record (no duplicate object claims).
        let dir = tempfile::tempdir().unwrap();
        let domain = "team-a";
        let secret: &[u8] = b"domain secret bytes";
        let plaintext = b"identical chunk in two archives";

        for _ in 0..10 {
            let cid = shared_content_id(domain, secret, plaintext);
            let cid_hex = hex_encode(&cid);
            let object_id = blake3::hash(plaintext).to_hex().to_string();
            let rec = SharedDedupRecord {
                format: "cairn-shared-v1".to_string(),
                domain_ns: derive_namespace(domain, secret),
                content_id: cid_hex,
                object_id: object_id.clone(),
                sealed_meta: SharedDedupMeta {
                    wrapped_key: b"domain-wrapped-record".to_vec(),
                    comp_type: 0,
                    cipher_algo: "aes-gcm".to_string(),
                    plaintext_len: plaintext.len() as u64,
                    ciphertext_len: plaintext.len() as u64,
                    blake3_hash: object_id,
                },
                wrapped_by_domain_key: true,
            };
            // First archive publishes; second loses-and-adopts.
            let out = atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec)
                .await
                .unwrap();
            match out {
                AtomicCreateOutcome::Published => {}
                AtomicCreateOutcome::LostToExisting(winner) => {
                    assert_eq!(winner.object_id, rec.object_id);
                }
            }
            // Both records verify against the object.
            assert!(verify_shared_record(&rec, plaintext).is_ok());
        }
    }

    fn hex_encode(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
