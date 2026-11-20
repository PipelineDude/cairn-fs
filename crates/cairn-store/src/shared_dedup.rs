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

/// SH-8: drop a shared object from the domain store. Used after a publisher
/// LOSES the content race: its freshly sealed object is referenced by no
/// record (the winner's object_id is in the record) and would otherwise leak
/// in the domain store forever. Never call this for an object that a record
/// binds — the caller must have verified it lost, and must skip the delete
/// when its own object_id equals the winner's (same bytes → shared object).
pub fn remove_shared_object(
    records_dir: &str,
    namespace: &str,
    object_id: &str,
) -> anyhow::Result<()> {
    validate_storage_component(namespace, "namespace")?;
    validate_storage_component(object_id, "object id")?;
    let path = Path::new(records_dir).join(shared_object_key(namespace, object_id));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

// ---------------------------------------------------------------------------
// Holder links: cross-client refcount for domain GC (ROADMAP design 2026-11-18).
//
// Every archive that indexes a domain chunk (publish, adopt, or dedup-hit)
// registers `dedup/shared/<ns>/holders/<content_id>/<holder_id>` — an empty
// file named by a random per-archive holder id — BEFORE touching the record
// or object, so a reclaim pass can never delete content an archive is
// mid-flight on. `reclaim_unheld_records` deletes records+objects only while
// no holder link exists. The `holders/ENABLED` marker gates the whole scheme:
// a store populated by pre-refcount versions has no links AT ALL, and
// reclaiming there would be a mass-delete — shared-gc refuses such stores.
// Second layer (the marker itself is created lazily by the first holder):
// a record with NO holder directory at all predates refcount and is never
// reclaimed even once the marker exists — only records whose holder DIR
// exists but is empty (links dropped: destroyed archive / stale reclaim) are
// reclaimable. Fail-safe direction: a leak, never a mass-delete.
// ---------------------------------------------------------------------------

/// Holder-link namespace root for one (ns, content_id) pair.
fn holder_dir(
    records_dir: &str,
    namespace: &str,
    content_id: &str,
) -> anyhow::Result<std::path::PathBuf> {
    validate_storage_component(namespace, "namespace")?;
    validate_storage_component(content_id, "content id")?;
    Ok(Path::new(records_dir)
        .join(format!("dedup/shared/{namespace}/holders"))
        .join(content_id))
}

fn holders_marker_path(records_dir: &str, namespace: &str) -> anyhow::Result<std::path::PathBuf> {
    validate_storage_component(namespace, "namespace")?;
    Ok(Path::new(records_dir).join(format!("dedup/shared/{namespace}/holders/ENABLED")))
}

/// True when this namespace's store is refcount-aware (a holder link or the
/// ENABLED marker exists). Absent means: legacy store — reclaim is refused.
pub fn holders_enabled(records_dir: &str, namespace: &str) -> bool {
    holders_marker_path(records_dir, namespace)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// (Re)register this archive as a holder of `content_id`. Idempotent
/// (`create_new`; AlreadyExists is success). The ENABLED marker is written
/// with `create_new` too, so the first holder makes the store reclaim-safe.
pub fn add_shared_holder(
    records_dir: &str,
    namespace: &str,
    content_id: &str,
    holder_id: &str,
) -> anyhow::Result<()> {
    validate_storage_component(holder_id, "holder id")?;
    let dir = holder_dir(records_dir, namespace, content_id)?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("cannot create holder dir {}: {e}", dir.display()))?;
    let marker = holders_marker_path(records_dir, namespace)?;
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        if e.kind() != ErrorKind::AlreadyExists {
            anyhow::bail!(
                "cannot write holders ENABLED marker {}: {e}",
                marker.display()
            );
        }
    }
    let link = dir.join(holder_id);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&link)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            // A dedup hit is a USE: refresh the link mtime so
            // `--reclaim-stale-holders` measures last use, not first pin
            // (an archive whose content never changes would otherwise look
            // stale forever). Best-effort — a touch failure never fails the
            // registration itself.
            if let Ok(f) = std::fs::OpenOptions::new().append(true).open(&link) {
                let _ = f.set_times(
                    std::fs::FileTimes::new().set_modified(std::time::SystemTime::now()),
                );
            }
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(
            "cannot register holder link {}: {e} — refusing to index domain content \
             that GC could later reclaim",
            link.display()
        )),
    }
}

/// List holder links with their mtimes (mtime = last touch = usage proof).
/// A missing holders dir means "no holders" (not an error).
pub fn list_shared_holders(
    records_dir: &str,
    namespace: &str,
    content_id: &str,
) -> anyhow::Result<Vec<(String, std::time::SystemTime)>> {
    let dir = holder_dir(records_dir, namespace, content_id)?;
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => anyhow::bail!("cannot list holders {}: {e}", dir.display()),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| anyhow::anyhow!("holders readdir failed: {e}"))?;
        let ft = entry
            .file_type()
            .map_err(|e| anyhow::anyhow!("holders stat failed: {e}"))?;
        if !ft.is_file() {
            continue;
        }
        let mtime = entry
            .metadata()
            .map(|m| m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH))
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        out.push((entry.file_name().to_string_lossy().to_string(), mtime));
    }
    Ok(out)
}

/// Drop one holder link (used by stale-holder reclaim; there is no archive
/// destroy flow wired to this yet — see OPERATING.md re `--reclaim-stale-holders`).
pub fn remove_shared_holder(
    records_dir: &str,
    namespace: &str,
    content_id: &str,
    holder_id: &str,
) -> anyhow::Result<()> {
    validate_storage_component(holder_id, "holder id")?;
    let link = holder_dir(records_dir, namespace, content_id)?.join(holder_id);
    match std::fs::remove_file(&link) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Drop every holder link named `holder_id` across the whole namespace —
/// the operator escape hatch for an archive destroyed WITHOUT a destroy
/// flow, when its (random, per-archive) holder id is known: `cairn
/// <archive> status` prints it before the archive dies. Safer and targeted
/// compared to the age-based `--reclaim-stale-holders-days`. Returns the
/// number of links removed (or, for `dry_run`, that would be removed).
pub fn drop_holder_links(
    records_dir: &str,
    namespace: &str,
    holder_id: &str,
    dry_run: bool,
) -> anyhow::Result<u64> {
    validate_storage_component(namespace, "namespace")?;
    validate_storage_component(holder_id, "holder id")?;
    let root = Path::new(records_dir).join(format!("dedup/shared/{namespace}/holders"));
    let rd = match std::fs::read_dir(&root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => anyhow::bail!("cannot list {}: {e}", root.display()),
    };
    let mut dropped = 0;
    for entry in rd.flatten() {
        // Content-id subdirs only; the ENABLED marker and strays are skipped.
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => {}
            _ => continue,
        }
        let link = entry.path().join(holder_id);
        if dry_run {
            if link.exists() {
                dropped += 1;
            }
            continue;
        }
        match std::fs::remove_file(&link) {
            Ok(()) => dropped += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => anyhow::bail!("cannot drop holder link {}: {e}", link.display()),
        }
    }
    Ok(dropped)
}

/// Counters from a domain-store reclaim pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DomainGcReport {
    pub records_scanned: u64,
    pub held: u64,
    pub reclaimable: u64,
    pub reclaimed_records: u64,
    pub reclaimed_objects: u64,
    pub stale_holders_dropped: u64,
    pub aborted_races: u64,
    pub legacy_records: u64,
}

/// Reclaim records (and their objects) that NO holder link claims anymore.
/// Two-phase against concurrent adopters: rename the record aside, re-enumerate
/// holders — a link that appeared in between aborts (record restored).
/// Crash-safe: leftover `<cid>.reclaim-pending` files from a pass that died
/// mid-reclaim are resolved at the start of the next pass. A fresh `.json`
/// (content re-published after the crash) supersedes the leftover — the
/// quarantine is dropped, never renamed back over the fresh record. A bonded
/// holder restores the quarantine ONLY while its object still exists
/// (otherwise the links are stale: drop them and finish the reclaim). No
/// holders: finish the interrupted reclaim (object delete is idempotent).
/// Provenance layer: a `.json` with NO holder directory at all predates
/// refcount-aware publishers and is left alone (counted as legacy) even if
/// the lazily-created ENABLED marker exists.
/// `reclaim_stale_holders_days`: opt-in drop of holder links untouched for
/// that many days (archives destroyed without `destroy` leave links forever;
/// an IDLE archive also looks stale — only pass this when that trade is
/// acceptable; default None = never drop by age).
pub fn reclaim_unheld_records(
    records_dir: &str,
    namespace: &str,
    secret: &[u8],
    reclaim_stale_holders_days: Option<u64>,
    dry_run: bool,
) -> anyhow::Result<DomainGcReport> {
    use std::time::Duration;
    if !holders_enabled(records_dir, namespace) {
        anyhow::bail!(
            "domain namespace {namespace} has no holders/ENABLED marker — this store was \
             created before holder-refcount GC and has NO holder links at all; reclaiming \
             here would delete live content. Re-run backups with holder-aware versions first."
        );
    }
    validate_storage_component(namespace, "namespace")?;
    let ns_dir = Path::new(records_dir).join(format!("dedup/shared/{namespace}"));
    let mut report = DomainGcReport::default();
    let rd = match std::fs::read_dir(&ns_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(report),
        Err(e) => anyhow::bail!("cannot read domain record dir {}: {e}", ns_dir.display()),
    };
    let stale_age =
        reclaim_stale_holders_days.map(|d| Duration::from_secs(d.saturating_mul(86_400)));
    let now = std::time::SystemTime::now();
    // Partition: crash-recovery leftovers (a pass that died between
    // quarantining a record and deleting it leaves `<cid>.reclaim-pending`)
    // are resolved FIRST, before scanning fresh `.json` records.
    let mut all: Vec<_> = rd
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            (name.ends_with(".json") || name.ends_with(".reclaim-pending"))
                && e.file_type().map(|ft| ft.is_file()).unwrap_or(false)
        })
        .collect();
    all.sort_by_key(|e| e.file_name().to_string_lossy().to_string());
    let (leftovers, entries): (Vec<_>, Vec<_>) = all.into_iter().partition(|e| {
        e.file_name()
            .to_string_lossy()
            .ends_with(".reclaim-pending")
    });
    for entry in leftovers {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let content_id = file_name.trim_end_matches(".reclaim-pending").to_string();
        let pending_path = ns_dir.join(&file_name);
        let fresh = ns_dir.join(format!("{content_id}.json"));
        // A publisher that re-published this content while the quarantine
        // survived owns the namespace now. Drop the stale leftover: a
        // rename-back would silently CLOBBER the fresh record (and orphan
        // its object) with the doomed one.
        if fresh.exists() {
            match std::fs::remove_file(&pending_path) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => {
                    anyhow::bail!("domain gc: cannot drop superseded {content_id}: {e}")
                }
            }
            report.aborted_races += 1;
            continue;
        }
        let holders = list_shared_holders(records_dir, namespace, &content_id)?;
        // Path-bind the quarantined record to its file name before trusting
        // its object binding (same rule as read_shared_record).
        let bytes = std::fs::read(&pending_path).unwrap_or_default();
        let record = decrypt_record_bytes(&bytes, secret)
            .ok()
            .filter(|rec| rec.content_id == content_id && rec.domain_ns == namespace);
        if !holders.is_empty() {
            // A holder bonded while the pass was dead. Restore ONLY if the
            // object still exists: a restored record whose object was
            // already deleted would wedge every future publish of this
            // content (every adopter fails on the missing object forever).
            let object_ok = record
                .as_ref()
                .map(|rec| read_shared_object(records_dir, namespace, &rec.object_id).is_ok())
                .unwrap_or(false);
            if object_ok {
                match std::fs::rename(&pending_path, &fresh) {
                    Ok(()) => {}
                    // A concurrent gc pass restored it first: nothing to do.
                    Err(e) if e.kind() == ErrorKind::NotFound => {}
                    Err(e) => anyhow::bail!("domain gc: cannot restore {content_id}: {e}"),
                }
                report.aborted_races += 1;
                continue;
            }
            // Object gone (or record undecryptable): the links protect
            // nothing. Drop them, then finish the reclaim below.
            for (hid, _) in holders {
                remove_shared_holder(records_dir, namespace, &content_id, &hid)?;
            }
        }
        // No holders: finish the interrupted reclaim. The object may or may
        // not have been deleted already (remove_shared_object is idempotent).
        if let Some(rec) = record {
            remove_shared_object(records_dir, namespace, &rec.object_id)?;
            report.reclaimed_objects += 1;
        }
        match std::fs::remove_file(&pending_path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => anyhow::bail!("domain gc: cannot remove {content_id}: {e}"),
        }
        report.reclaimed_records += 1;
        let _ = std::fs::remove_dir(holder_dir(records_dir, namespace, &content_id)?);
    }
    for entry in entries {
        report.records_scanned += 1;
        let file_name = entry.file_name().to_string_lossy().to_string();
        let content_id = file_name.trim_end_matches(".json").to_string();
        let record = match read_shared_record(records_dir, namespace, &content_id, secret) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => {
                // Legacy plaintext or corrupt: never auto-delete; loud in report.
                tracing::warn!("domain gc: record {content_id} unreadable ({e}) — skipped");
                report.legacy_records += 1;
                continue;
            }
        };
        if let Some(age) = stale_age {
            for (hid, mtime) in list_shared_holders(records_dir, namespace, &content_id)? {
                // duration_since Errs when mtime is in the future (clock
                // skew): a future mtime is NOT old — never drop on skew.
                let old = now.duration_since(mtime).map(|d| d > age).unwrap_or(false);
                if old {
                    if !dry_run {
                        remove_shared_holder(records_dir, namespace, &content_id, &hid)?;
                    }
                    report.stale_holders_dropped += 1;
                }
            }
        }
        if !list_shared_holders(records_dir, namespace, &content_id)?.is_empty() {
            report.held += 1;
            continue;
        }
        // Second layer against the lazily-created ENABLED marker: a record
        // with NO holder directory at all was created by a pre-refcount
        // version (every refcount-aware publisher pins its holder link
        // BEFORE the record becomes visible). Its content may still be live
        // in archives that never learned holders — never reclaim it; count
        // it as legacy. An EMPTY holder dir proves refcount provenance with
        // all links dropped (destroyed archive / stale reclaim): reclaimable.
        if !holder_dir(records_dir, namespace, &content_id)?.is_dir() {
            tracing::warn!(
                "domain gc: record {content_id} predates holder-refcount GC (no holder \
                 dir) — left alone; re-backup its archives before it can be reclaimed"
            );
            report.legacy_records += 1;
            continue;
        }
        report.reclaimable += 1;
        if dry_run {
            continue;
        }
        // Two-phase: rename aside, re-check holders, then delete. A publisher
        // that adopted and linked between our check and the rename gets either
        // the rename (ENOENT: it will re-create via publish path, which
        // re-creates the record fresh) or sees its link here and we abort.
        let record_path = ns_dir.join(&file_name);
        let pending = ns_dir.join(format!("{content_id}.reclaim-pending"));
        match std::fs::rename(&record_path, &pending) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => anyhow::bail!("domain gc: cannot quarantine record {content_id}: {e}"),
        }
        if !list_shared_holders(records_dir, namespace, &content_id)?.is_empty() {
            // Race: a holder appeared mid-flight — restore the record.
            std::fs::rename(&pending, &record_path)
                .map_err(|e| anyhow::anyhow!("domain gc: cannot restore {content_id}: {e}"))?;
            report.aborted_races += 1;
            continue;
        }
        remove_shared_object(records_dir, namespace, &record.object_id)?;
        report.reclaimed_objects += 1;
        std::fs::remove_file(&pending)
            .map_err(|e| anyhow::anyhow!("domain gc: cannot remove record {content_id}: {e}"))?;
        report.reclaimed_records += 1;
        // Best-effort: drop the (now empty) holders dir; not empty means a
        // fresh holder raced in — leave it, the content is re-published by
        // whoever links it.
        let _ = std::fs::remove_dir(holder_dir(records_dir, namespace, &content_id)?);
    }
    Ok(report)
}

/// Fingerprint of the domain secret (the non-secret identity persisted in an
/// archive's config).  Same derivation as the bin's `shared_dedup` module;
/// cairn-store is the single source of truth for the crypto seam.
pub fn fingerprint_secret(secret: &[u8]) -> String {
    blake3::hash(secret).to_hex()[..32].to_string()
}

/// SH-2: records leak a lot in plaintext (chunk counts, plaintext AND
/// ciphertext lengths, algorithms, the object binding), so the JSON envelope
/// is encrypted at rest under a domain-key-derived AEAD key — the same
/// `magic || 12-byte random nonce || AES-256-GCM ct+tag` envelope as the
/// domain key wraps, but under its OWN KDF context so record encryption and
/// chunk-key wrapping can never share a key. Only domain members (secret
/// holders) can read the metadata now; the path itself stays keyed by the
/// already-keyed content_id, and object files remain ciphertext.
pub fn shared_record_encryption_key(secret: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key("cairn shared record wrap v1", secret))
}

fn encrypt_record_bytes(record: &SharedDedupRecord, secret: &[u8]) -> anyhow::Result<Vec<u8>> {
    let json = record.to_json()?;
    let key = shared_record_encryption_key(secret);
    cairn_seal::wrap_with_domain_key(&json, &key)
}

fn decrypt_record_bytes(blob: &[u8], secret: &[u8]) -> anyhow::Result<SharedDedupRecord> {
    if blob.first() == Some(&b'{') {
        anyhow::bail!(
            "shared record is stored in plaintext (pre-encryption v1 format) — re-run the \
             backup to republish this content under the encrypted record format"
        );
    }
    let key = shared_record_encryption_key(secret);
    let json = cairn_seal::unwrap_with_domain_key(blob, &key)
        .map_err(|_| anyhow::anyhow!("cannot decrypt shared record (wrong domain secret?)"))?;
    SharedDedupRecord::from_json(&json).map_err(|e| anyhow::anyhow!("corrupt shared record ({e})"))
}

/// Look up the published record for `content_id` in a domain store
/// (BF-04.10). `None` when this store has never seen the content. A corrupt
/// record is a loud error, never a silent miss — same rule as the race path.
/// The record body is encrypted at rest (SH-2): decrypting requires the
/// domain secret.
pub fn read_shared_record(
    records_dir: &str,
    namespace: &str,
    content_id: &str,
    secret: &[u8],
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
    Ok(Some(decrypt_record_bytes(&bytes, secret).and_then(
        |rec| {
            // Path binding (adversarial review 2026-11-18): a record must carry the
            // same (namespace, content_id) it is stored under; a record moved or
            // copied onto another content's path fails loudly here, before any
            // consumer relies on its object binding.
            if rec.content_id != content_id || rec.domain_ns != namespace {
                anyhow::bail!(
                    "shared record at {} does not match its path key (content {} / ns {} vs \
                 expected {} / {}) — possible store tampering",
                    path.display(),
                    rec.content_id,
                    rec.domain_ns,
                    content_id,
                    namespace
                );
            }
            Ok(rec)
        },
    )?))
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

pub fn validate_storage_component(component: &str, what: &str) -> anyhow::Result<()> {
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
    // any configured *remote* cloud backend must refuse shared mode.  A local
    // `fs://` backend is satisfied with O_CREAT|O_EXCL on one filesystem, so
    // shared mode stays usable for filesystem-only deployments.
    backends.iter().all(|op| {
        // CloudOperator wraps the opendal Operator; expose its scheme via the
        // stored URI is not available here, so we conservatively treat an empty
        // operator list (pure local) as supported and any non-empty list as
        // unsupported unless the scheme is fs.  The opendal Operator's
        // info().scheme() is the authoritative check.
        op.info().scheme() == "fs"
    })
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
    secret: &[u8],
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
        let bytes = encrypt_record_bytes(record, secret)?;
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
                let winner = decrypt_record_bytes(&winner, secret).map_err(|e| anyhow::anyhow!(
                    "shared record at {} is corrupt ({e}); refusing to use or silently overwrite it -- loud fail per D00 §7",
                    path.display()
                ))?;
                // Path binding (adversarial review 2026-11-18): the decrypted
                // record must describe exactly the content this path is keyed
                // by — a foreign record copied onto this path is a loud error,
                // not an adoptable mapping.
                if winner.content_id != record.content_id || winner.domain_ns != record.domain_ns {
                    anyhow::bail!(
                        "shared record at {} does not match its path key (content {} / ns {} vs \
                         expected {} / {}) — possible store tampering",
                        path.display(),
                        winner.content_id,
                        winner.domain_ns,
                        record.content_id,
                        record.domain_ns
                    );
                }
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
    secret: &[u8],
) -> anyhow::Result<SharedPublish>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send,
{
    match atomic_get_or_create_local(records_dir, record, secret).await? {
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

    const SECRET: &[u8] = b"test-domain-secret-must-be-long-enough-32b!";

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
        let out = publish_shared_or_adopt(
            dir.path().to_str().unwrap(),
            &rec,
            |_| async { Err(anyhow::anyhow!("read must not run when publication wins")) },
            SECRET,
        )
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
            atomic_get_or_create_local(dir.path().to_str().unwrap(), &winner, SECRET)
                .await
                .unwrap(),
            AtomicCreateOutcome::Published
        );
        let mut raced = winner.clone();
        raced.object_id = "our-own-object".to_string();
        let objects =
            std::collections::HashMap::from([(winner.object_id.clone(), plaintext.to_vec())]);
        for _ in 0..10 {
            let out = publish_shared_or_adopt(
                dir.path().to_str().unwrap(),
                &raced,
                |id| {
                    let objects = objects.clone();
                    async move {
                        objects
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| anyhow::anyhow!("object {id} missing"))
                    }
                },
                SECRET,
            )
            .await
            .unwrap();
            assert_eq!(out, SharedPublish::Adopted(winner.clone()));
        }
    }

    #[tokio::test]
    async fn publish_or_adopt_fails_loud_on_missing_winner_object() {
        let dir = tempfile::tempdir().unwrap();
        let rec = sample_record("team-a|fing", "cid-1", "obj-existing");
        atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec, SECRET)
            .await
            .unwrap();
        let err = publish_shared_or_adopt(
            dir.path().to_str().unwrap(),
            &rec,
            |_| std::future::ready(Err(anyhow::anyhow!("object gone"))),
            SECRET,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unreadable"), "{err}");
    }

    #[tokio::test]
    async fn publish_or_adopt_fails_loud_on_corrupt_winner_object() {
        let dir = tempfile::tempdir().unwrap();
        let rec = sample_record("team-a|fing", "cid-1", "obj-corrupt");
        atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec, SECRET)
            .await
            .unwrap();
        let err = publish_shared_or_adopt(
            dir.path().to_str().unwrap(),
            &rec,
            |_| std::future::ready(Ok(b"not the right bytes".to_vec())),
            SECRET,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("failed verification"), "{err}");
    }

    #[tokio::test]
    async fn first_creator_publishes() {
        let dir = tempfile::tempdir().unwrap();
        let rec = sample_record("team-a|fing", "cid-1", "obj-1");
        let out = atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec, SECRET)
            .await
            .unwrap();
        assert_eq!(out, AtomicCreateOutcome::Published);
    }

    #[tokio::test]
    async fn second_creator_reads_the_winner() {
        let dir = tempfile::tempdir().unwrap();
        let winner = sample_record("team-a|fing", "cid-1", "obj-1");
        let loser = sample_record("team-a|fing", "cid-1", "obj-1");

        let out = atomic_get_or_create_local(dir.path().to_str().unwrap(), &winner, SECRET)
            .await
            .unwrap();
        assert_eq!(out, AtomicCreateOutcome::Published);

        // A racing second publisher (identical content_id, own object_id) must
        // lose and adopt the winner's record -- not overwrite it.
        let mut raced = loser.clone();
        raced.object_id = "obj-X".to_string();
        let out = atomic_get_or_create_local(dir.path().to_str().unwrap(), &raced, SECRET)
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
            atomic_get_or_create_local(dir.path().to_str().unwrap(), &a, SECRET)
                .await
                .unwrap(),
            AtomicCreateOutcome::Published
        );
        // Same content_id, different domain/secret namespace -> no sharing.
        assert_eq!(
            atomic_get_or_create_local(dir.path().to_str().unwrap(), &b, SECRET)
                .await
                .unwrap(),
            AtomicCreateOutcome::Published
        );
    }

    #[tokio::test]
    async fn corrupt_winner_record_is_a_loud_error() {
        let dir = tempfile::tempdir().unwrap();
        let first = sample_record("team-a|fing", "cid-1", "obj-1");
        atomic_get_or_create_local(dir.path().to_str().unwrap(), &first, SECRET)
            .await
            .unwrap();
        let key = shared_record_key("team-a|fing", "cid-1");
        std::fs::write(dir.path().join(key), "{not-json").unwrap();

        let err = atomic_get_or_create_local(dir.path().to_str().unwrap(), &first, SECRET)
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

    /// SH-2: the record file on disk must not expose metadata in plaintext,
    /// must round-trip for the right secret, and must fail loudly for a wrong
    /// secret or a legacy plaintext record.
    #[tokio::test]
    async fn record_is_encrypted_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let rec = sample_record("team-a|fing", "cid-1", "obj-1");
        assert_eq!(
            atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec, SECRET)
                .await
                .unwrap(),
            AtomicCreateOutcome::Published
        );
        let on_disk =
            std::fs::read(dir.path().join(shared_record_key("team-a|fing", "cid-1"))).unwrap();
        for leak in [
            "plaintext_len",
            "ciphertext_len",
            "wrapped_key",
            "obj-1",
            "aes-gcm",
        ] {
            assert!(
                !on_disk.windows(leak.len()).any(|w| w == leak.as_bytes()),
                "record leaks {leak:?} in plaintext on disk"
            );
        }
        // Right secret: full round-trip through read_shared_record.
        let got = read_shared_record(dir.path().to_str().unwrap(), "team-a|fing", "cid-1", SECRET)
            .unwrap()
            .unwrap();
        assert_eq!(got, rec);
        // Wrong secret: loud, not a silent miss.
        let err = read_shared_record(
            dir.path().to_str().unwrap(),
            "team-a|fing",
            "cid-1",
            b"other-secret-32-bytes-long-long!!",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("decrypt"), "{err}");
    }

    #[test]
    fn legacy_plaintext_record_fails_with_republish_hint() {
        let err = decrypt_record_bytes(b"{\"format\":\"cairn-shared-v1\"}", SECRET)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("plaintext") && err.contains("republish"),
            "{err}"
        );
    }

    /// A bit-flip anywhere in the sealed record (nonce, ciphertext, or tag)
    /// must fail authentication loudly — never decrypt to garbage.
    #[tokio::test]
    async fn tampered_record_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let rec = sample_record("team-a|fing", "cid-1", "obj-1");
        atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec, SECRET)
            .await
            .unwrap();
        let path = dir.path().join(shared_record_key("team-a|fing", "cid-1"));
        let pristine = std::fs::read(&path).unwrap();

        // Flip one byte at several offsets past the envelope header: salt,
        // nonce, ciphertext body, and tag must all be authenticated.
        for off in [6usize, 20, 30, pristine.len() - 2, pristine.len() - 17] {
            let mut bad = pristine.clone();
            bad[off] ^= 0x01;
            std::fs::write(&path, &bad).unwrap();
            let err =
                read_shared_record(dir.path().to_str().unwrap(), "team-a|fing", "cid-1", SECRET)
                    .expect_err("tampered record at offset {off} must not verify");
            assert!(err.to_string().contains("decrypt"), "{err}");
        }

        // Truncating the record is rejected too.
        let mut short = pristine.clone();
        short.truncate(short.len() - 1);
        std::fs::write(&path, &short).unwrap();
        assert!(
            read_shared_record(dir.path().to_str().unwrap(), "team-a|fing", "cid-1", SECRET)
                .is_err()
        );
    }

    /// Path binding: a valid record copied onto ANOTHER content_id's path must
    /// fail loudly on both consume paths (lookup and publish-adopt), never be
    /// served or adopted as that content's mapping.
    #[tokio::test]
    async fn record_swapped_onto_other_path_fails_loud() {
        let dir = tempfile::tempdir().unwrap();
        let dir_s = dir.path().to_str().unwrap();
        let rec_a = sample_record("team-a|fing", "cid-1", "obj-1");
        atomic_get_or_create_local(dir_s, &rec_a, SECRET)
            .await
            .unwrap();

        // Plant A's ciphertext on cid-2's path.
        let a_bytes =
            std::fs::read(dir.path().join(shared_record_key("team-a|fing", "cid-1"))).unwrap();
        std::fs::write(
            dir.path().join(shared_record_key("team-a|fing", "cid-2")),
            &a_bytes,
        )
        .unwrap();

        // Lookup path: loud mismatch, never A's record under B's key.
        let err = read_shared_record(dir_s, "team-a|fing", "cid-2", SECRET)
            .expect_err("swapped record must not verify under the foreign path key");
        assert!(
            err.to_string().contains("does not match its path key"),
            "{err}"
        );

        // Publish path: publishing cid-2 adopts the planted winner — must bail.
        let rec_b = sample_record("team-a|fing", "cid-2", "obj-2");
        let err = atomic_get_or_create_local(dir_s, &rec_b, SECRET)
            .await
            .expect_err("planted winner must be rejected, not adopted");
        assert!(
            err.to_string().contains("does not match its path key"),
            "{err}"
        );
    }

    // ---- domain GC holder-refcount regression tests (ROADMAP 2026-11-18) ----

    #[test]
    fn holder_links_are_idempotent_and_enable_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        assert!(!holders_enabled(d, "team-a|fing"));
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-x").unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-x").unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-y").unwrap();
        assert!(holders_enabled(d, "team-a|fing"));
        let mut ids: Vec<_> = list_shared_holders(d, "team-a|fing", "cid-1")
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["holder-x".to_string(), "holder-y".to_string()]);
        remove_shared_holder(d, "team-a|fing", "cid-1", "holder-x").unwrap();
        remove_shared_holder(d, "team-a|fing", "cid-1", "holder-x").unwrap(); // idempotent
        assert_eq!(
            list_shared_holders(d, "team-a|fing", "cid-1")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            list_shared_holders(d, "team-a|fing", "no-such-cid")
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn reclaim_refuses_legacy_stores_and_respects_holders() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        // read_shared_object hash-verifies, so the object id must be the real
        // blake3 of the bytes (fake ids only work where objects are unread).
        let obj_bytes = b"obj-1 bytes";
        let oid = blake3::hash(obj_bytes).to_hex().to_string();
        let rec = sample_record("team-a|fing", "cid-1", &oid);
        atomic_get_or_create_local(d, &rec, SECRET).await.unwrap();
        put_shared_object(d, "team-a|fing", &oid, obj_bytes).unwrap();

        // No holders/ENABLED marker (store built by a pre-refcount version):
        // reclaim must refuse, never mass-delete.
        let err = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap_err();
        assert!(err.to_string().contains("holders/ENABLED"), "{err}");
        assert!(read_shared_object(d, "team-a|fing", &oid).is_ok());

        // Marker present + our holder: kept.
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-a").unwrap();
        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap();
        assert_eq!(rep.records_scanned, 1);
        assert_eq!(rep.held, 1);
        assert_eq!(rep.reclaimed_records, 0);
        let ro = read_shared_object(d, "team-a|fing", &oid);
        assert!(ro.is_ok(), "object gone after held-reclaim: {ro:?}");

        // Holder released: reclaimed (record + object gone, holders dir gone).
        remove_shared_holder(d, "team-a|fing", "cid-1", "holder-a").unwrap();
        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, true).unwrap();
        assert_eq!(rep.reclaimable, 1);
        assert!(read_shared_object(d, "team-a|fing", &oid).is_ok()); // dry-run kept
        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap();
        assert_eq!(rep.reclaimed_records, 1);
        assert_eq!(rep.reclaimed_objects, 1);
        assert!(
            read_shared_record(d, "team-a|fing", "cid-1", SECRET)
                .unwrap()
                .is_none()
        );
        assert!(read_shared_object(d, "team-a|fing", &oid).is_err());
        assert!(
            list_shared_holders(d, "team-a|fing", "cid-1")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn stale_holder_reclaim_drops_old_links() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        // read_shared_object hash-verifies, so the object id must be the real
        // blake3 of the bytes (fake ids only work where objects are unread).
        let obj_bytes = b"obj-1 bytes";
        let oid = blake3::hash(obj_bytes).to_hex().to_string();
        let rec = sample_record("team-a|fing", "cid-1", &oid);
        atomic_get_or_create_local(d, &rec, SECRET).await.unwrap();
        put_shared_object(d, "team-a|fing", &oid, obj_bytes).unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-dead").unwrap();

        // age=0 days: every link (created moments ago, already >0s old) is
        // stale → dropped → content becomes reclaimable.
        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, Some(0), false).unwrap();
        assert_eq!(rep.stale_holders_dropped, 1);
        assert_eq!(rep.reclaimed_records, 1);
        // With a generous N the same fresh link is kept.
        atomic_get_or_create_local(d, &rec, SECRET).await.unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-live").unwrap();
        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, Some(90), false).unwrap();
        assert_eq!(rep.stale_holders_dropped, 0);
        assert_eq!(rep.held, 1);
    }

    /// Targeted operator cleanup: drop ONE holder id across the namespace;
    /// other holders untouched, the freed content becomes reclaimable.
    #[tokio::test]
    async fn drop_holder_links_removes_only_that_holder() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let obj1 = b"content-one";
        let oid1 = blake3::hash(obj1).to_hex().to_string();
        let obj2 = b"content-two";
        let oid2 = blake3::hash(obj2).to_hex().to_string();
        atomic_get_or_create_local(d, &sample_record("team-a|fing", "cid-1", &oid1), SECRET)
            .await
            .unwrap();
        put_shared_object(d, "team-a|fing", &oid1, obj1).unwrap();
        atomic_get_or_create_local(d, &sample_record("team-a|fing", "cid-2", &oid2), SECRET)
            .await
            .unwrap();
        put_shared_object(d, "team-a|fing", &oid2, obj2).unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-dead").unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-live").unwrap();
        add_shared_holder(d, "team-a|fing", "cid-2", "holder-dead").unwrap();

        // Dry-run counts but touches nothing.
        assert_eq!(
            drop_holder_links(d, "team-a|fing", "holder-dead", true).unwrap(),
            2
        );
        assert_eq!(
            list_shared_holders(d, "team-a|fing", "cid-1")
                .unwrap()
                .len(),
            2
        );

        // Real drop: only holder-dead gone; live link and marker untouched.
        assert_eq!(
            drop_holder_links(d, "team-a|fing", "holder-dead", false).unwrap(),
            2
        );
        assert_eq!(
            drop_holder_links(d, "team-a|fing", "holder-dead", false).unwrap(),
            0 // idempotent
        );
        assert_eq!(
            list_shared_holders(d, "team-a|fing", "cid-1")
                .unwrap()
                .into_iter()
                .map(|(id, _)| id)
                .collect::<Vec<_>>(),
            vec!["holder-live".to_string()]
        );
        assert!(
            list_shared_holders(d, "team-a|fing", "cid-2")
                .unwrap()
                .is_empty()
        );
        assert!(holders_enabled(d, "team-a|fing"));

        // Reclaim now frees cid-2 (empty holder dir) but keeps cid-1 (held).
        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap();
        assert_eq!(rep.reclaimed_records, 1);
        assert_eq!(rep.held, 1);
        assert!(read_shared_object(d, "team-a|fing", &oid1).is_ok());
        assert!(read_shared_object(d, "team-a|fing", &oid2).is_err());
    }

    #[tokio::test]
    async fn reclaim_resolves_crash_leftover_pending_records() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let obj_bytes = b"obj-1 bytes";
        let oid = blake3::hash(obj_bytes).to_hex().to_string();
        let rec = sample_record("team-a|fing", "cid-1", &oid);
        atomic_get_or_create_local(d, &rec, SECRET).await.unwrap();
        put_shared_object(d, "team-a|fing", &oid, obj_bytes).unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-a").unwrap();

        // Simulate a pass that quarantined the record and died BEFORE deleting
        // anything: rename the record aside, keep object + holder.
        let ns_dir = dir.path().join("dedup/shared/team-a|fing");
        std::fs::rename(
            ns_dir.join("cid-1.json"),
            ns_dir.join("cid-1.reclaim-pending"),
        )
        .unwrap();
        // Holder present: the next pass restores the record.
        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap();
        assert_eq!(rep.aborted_races, 1);
        assert!(
            read_shared_record(d, "team-a|fing", "cid-1", SECRET)
                .unwrap()
                .is_some()
        );
        assert!(read_shared_object(d, "team-a|fing", &oid).is_ok());
        assert!(!ns_dir.join("cid-1.reclaim-pending").exists());

        // Now simulate the interrupted pass dying AFTER the object delete:
        // release the holder, rename aside, delete the object.
        remove_shared_holder(d, "team-a|fing", "cid-1", "holder-a").unwrap();
        std::fs::rename(
            ns_dir.join("cid-1.json"),
            ns_dir.join("cid-1.reclaim-pending"),
        )
        .unwrap();
        remove_shared_object(d, "team-a|fing", &oid).unwrap();
        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap();
        assert_eq!(rep.reclaimed_records, 1);
        assert!(read_shared_object(d, "team-a|fing", &oid).is_err());
        assert!(!ns_dir.join("cid-1.reclaim-pending").exists());
    }

    /// A lazily-created ENABLED marker (one new-version backup) must NOT make
    /// legacy records reclaimable: a record with no holder DIR at all was
    /// written by a pre-refcount version and may still be live.
    #[tokio::test]
    async fn legacy_record_without_holder_dir_survives_in_enabled_store() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let obj_bytes = b"legacy content";
        let oid = blake3::hash(obj_bytes).to_hex().to_string();
        let legacy = sample_record("team-a|fing", "cid-legacy", &oid);
        atomic_get_or_create_local(d, &legacy, SECRET)
            .await
            .unwrap();
        put_shared_object(d, "team-a|fing", &oid, obj_bytes).unwrap();

        // New-version archive backs up different content: the lazy ENABLED
        // marker appears, but the legacy record must NOT become reclaimable.
        let new_bytes = b"new content";
        let new_oid = blake3::hash(new_bytes).to_hex().to_string();
        let fresh = sample_record("team-a|fing", "cid-new", &new_oid);
        atomic_get_or_create_local(d, &fresh, SECRET).await.unwrap();
        put_shared_object(d, "team-a|fing", &new_oid, new_bytes).unwrap();
        add_shared_holder(d, "team-a|fing", "cid-new", "holder-n1").unwrap();

        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap();
        assert_eq!(rep.reclaimed_records, 0);
        assert_eq!(rep.legacy_records, 1);
        assert!(read_shared_object(d, "team-a|fing", &oid).is_ok());

        // Refcount-aware record with ALL links dropped (empty holder dir
        // proves provenance) IS reclaimable; the legacy record stays.
        remove_shared_holder(d, "team-a|fing", "cid-new", "holder-n1").unwrap();
        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap();
        assert_eq!(rep.reclaimed_records, 1);
        assert_eq!(rep.legacy_records, 1);
        assert!(read_shared_object(d, "team-a|fing", &oid).is_ok());
        assert!(read_shared_object(d, "team-a|fing", &new_oid).is_err());
    }

    /// A quarantine leftover must never rename back OVER a fresh record
    /// published after the crash — the fresh mapping wins, the stale
    /// quarantine is dropped.
    #[tokio::test]
    async fn leftover_restore_never_clobbers_a_fresh_record() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let obj_bytes = b"old content bytes";
        let oid = blake3::hash(obj_bytes).to_hex().to_string();
        let rec = sample_record("team-a|fing", "cid-1", &oid);
        atomic_get_or_create_local(d, &rec, SECRET).await.unwrap();
        put_shared_object(d, "team-a|fing", &oid, obj_bytes).unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-a").unwrap();

        // Interrupted pass: quarantine survived the object delete.
        let ns_dir = dir.path().join("dedup/shared/team-a|fing");
        std::fs::rename(
            ns_dir.join("cid-1.json"),
            ns_dir.join("cid-1.reclaim-pending"),
        )
        .unwrap();
        remove_shared_object(d, "team-a|fing", &oid).unwrap();
        remove_shared_holder(d, "team-a|fing", "cid-1", "holder-a").unwrap();

        // A publisher re-publishes the content while the leftover survives.
        let new_bytes = b"fresh content bytes";
        let new_oid = blake3::hash(new_bytes).to_hex().to_string();
        let fresh_rec = sample_record("team-a|fing", "cid-1", &new_oid);
        atomic_get_or_create_local(d, &fresh_rec, SECRET)
            .await
            .unwrap();
        put_shared_object(d, "team-a|fing", &new_oid, new_bytes).unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-b").unwrap();

        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap();
        assert_eq!(rep.aborted_races, 1);
        assert_eq!(rep.reclaimed_records, 0);
        assert!(!ns_dir.join("cid-1.reclaim-pending").exists());
        let kept = read_shared_record(d, "team-a|fing", "cid-1", SECRET)
            .unwrap()
            .expect("fresh record must survive");
        assert_eq!(kept.object_id, new_oid);
        assert!(read_shared_object(d, "team-a|fing", &new_oid).is_ok());
        assert_eq!(rep.held, 1);
    }

    /// A holder bonded onto a quarantine whose OBJECT is already gone must
    /// not resurrect a dangling record: the links protect nothing, they are
    /// dropped and the reclaim is finished.
    #[tokio::test]
    async fn leftover_holder_with_missing_object_finishes_reclaim() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let obj_bytes = b"obj-1 bytes";
        let oid = blake3::hash(obj_bytes).to_hex().to_string();
        let rec = sample_record("team-a|fing", "cid-1", &oid);
        atomic_get_or_create_local(d, &rec, SECRET).await.unwrap();
        put_shared_object(d, "team-a|fing", &oid, obj_bytes).unwrap();

        // Interrupted pass died AFTER the object delete; a concurrent
        // adopter bonded its link in the window.
        let ns_dir = dir.path().join("dedup/shared/team-a|fing");
        std::fs::rename(
            ns_dir.join("cid-1.json"),
            ns_dir.join("cid-1.reclaim-pending"),
        )
        .unwrap();
        remove_shared_object(d, "team-a|fing", &oid).unwrap();
        add_shared_holder(d, "team-a|fing", "cid-1", "holder-late").unwrap();

        let rep = reclaim_unheld_records(d, "team-a|fing", SECRET, None, false).unwrap();
        assert_eq!(rep.reclaimed_records, 1);
        assert_eq!(rep.aborted_races, 0);
        assert!(!ns_dir.join("cid-1.reclaim-pending").exists());
        assert!(!ns_dir.join("cid-1.json").exists());
        assert!(
            list_shared_holders(d, "team-a|fing", "cid-1")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn remove_shared_object_lets_loser_clean_up() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = b"loser ciphertext";
        let oid = blake3::hash(bytes).to_hex().to_string();
        put_shared_object(dir.path().to_str().unwrap(), "team-a|fing", &oid, bytes).unwrap();
        remove_shared_object(dir.path().to_str().unwrap(), "team-a|fing", &oid).unwrap();
        let err =
            read_shared_object(dir.path().to_str().unwrap(), "team-a|fing", &oid).unwrap_err();
        assert!(err.to_string().contains("unavailable"), "{err}");
        // Idempotent: removing again is a no-op, never an error.
        remove_shared_object(dir.path().to_str().unwrap(), "team-a|fing", &oid).unwrap();
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
            let out = atomic_get_or_create_local(dir.path().to_str().unwrap(), &rec, SECRET)
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
