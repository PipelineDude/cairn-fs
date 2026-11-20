//! D03 shared-dedup WRITE bridge for the chunker (BF-02).
//!
//! `publish_shared_chunk` implements the canonical cross-archive path of the
//! design's §5/§7:
//!
//! 1. seal the chunk ONCE (fresh random DEK + nonce) but wrap the sealed
//!    chunk-key record TWICE — archive key (own reads) and DOMAIN key (other
//!    archives in the domain) — via `cairn_seal::seal_chunk_shared`;
//! 2. cache the canonical ciphertext locally;
//! 3. conditionally publish the domain record; on a lost race ADOPT the
//!    winner's already-verified object (`cairn_store::shared_dedup::*`);
//! 4. a missing/corrupt winner object is a LOUD error, never an unverified
//!    index entry.
//!
//! The surrounding Chunker keeps its archive-scope fast path; this bridge is
//! what the (index-flag + read-path) integration drives next.

/// Shared-dedup publishing config (populated by the bin from the D01 config).
#[derive(Debug, Clone)]
pub struct SharedDedupConfig {
    pub records_dir: String,
    pub domain_id: String,
    /// SH-5: the domain key material is zeroized on every drop (the chunker
    /// clones this config per task — `Zeroizing`'s Clone bound guarantees every
    /// copy is scrubbed, which a plain `Vec<u8>` would not be).
    pub domain_secret: zeroize::Zeroizing<Vec<u8>>,
    /// Random per-archive id (persisted in the archive config) naming the
    /// holder links this archive registers for every domain chunk it indexes
    /// (domain GC refcount, ROADMAP 2026-11-18).
    pub holder_id: String,
}

/// Outcome of publishing one chunk into the domain.
#[derive(Debug)]
pub struct SharedChunkOutcome {
    /// The object to index: always the canonical WINNER's object_id.
    pub object_id: String,
    pub comp_type: u8,
    pub cipher_algo: String,
    pub plaintext_len: u64,
    pub ciphertext_len: u64,
    /// True when we adopted an already-published object (dedup hit).
    pub dedup_hit: bool,
    /// The shared record (published winner) for index/read wiring.
    pub record: cairn_store::shared_dedup::SharedDedupRecord,
}

/// Publish (or adopt) a chunk under the domain namespace.
///
/// Offline/local scope (filesystem-only backend, per the D02 capability
/// gate): records under `records_dir`, objects under the local cacache
/// `cache_dir`.  The cloud write path already exists upstream (`cairn-store`
/// upload); folding it in is the Chunker-integration chore.
pub async fn publish_shared_chunk(
    plaintext: &[u8],
    crypto: &cairn_seal::CryptoCtx,
    comp_override: Option<&str>,
    cfg: &SharedDedupConfig,
    cache_dir: &str,
) -> anyhow::Result<SharedChunkOutcome> {
    let domain_wrap_key = cairn_seal::shared_domain_wrapping_key(&cfg.domain_secret);

    let namespace = cairn_store::shared_dedup::derive_namespace(&cfg.domain_id, &cfg.domain_secret);
    let content_id =
        cairn_store::shared_dedup::shared_content_id(&cfg.domain_id, &cfg.domain_secret, plaintext);
    let content_id = content_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    // Domain GC: PIN FIRST — register the holder link before any record or
    // object is read. A reclaim pass can then never delete the record+object
    // while this archive is mid-flight on the content: gc aborts on any link
    // it sees, and there is no window where we hold verified bytes while the
    // content still looks unheld to gc (the old pin-after-verify order lost
    // exactly there). If the chunk never ends up published, the pin is a
    // harmless leak — stale-holder reclaim covers it.
    cairn_store::shared_dedup::add_shared_holder(
        &cfg.records_dir,
        &namespace,
        &content_id,
        &cfg.holder_id,
    )?;

    // BF-04.10: look the content up BEFORE sealing. Sealing first and adopting
    // after the race (the old order) persisted a fresh loser object — and a
    // cache entry for it — on every repeat write of identical content, with no
    // GC for any of them. The winner's record is fully verified here (key
    // unwrap, sealed-record parse, plaintext equality) before it is adopted.
    if let Some(existing) = cairn_store::shared_dedup::read_shared_record(
        &cfg.records_dir,
        &namespace,
        &content_id,
        &cfg.domain_secret,
    )? {
        let canonical = cairn_store::shared_dedup::read_shared_object(
            &cfg.records_dir,
            &namespace,
            &existing.object_id,
        )?;
        let existing_key = cairn_seal::unwrap_with_domain_key(
            &existing.sealed_meta.wrapped_key,
            &domain_wrap_key,
        )?;
        let existing_meta = cairn_seal::parse_sealed_record(&existing_key)?;
        let existing_plaintext = crypto.decrypt_chunk_shared_record(
            &canonical,
            &existing_key,
            existing_meta.comp_type,
            &existing.sealed_meta.cipher_algo,
        )?;
        if existing_plaintext.as_slice() == plaintext {
            cacache::write(cache_dir, &existing.object_id, canonical).await?;
            // Domain GC: a dedup hit is a USE — (re)register our holder link.
            cairn_store::shared_dedup::add_shared_holder(
                &cfg.records_dir,
                &namespace,
                &content_id,
                &cfg.holder_id,
            )?;
            let meta = &existing.sealed_meta;
            return Ok(SharedChunkOutcome {
                object_id: existing.object_id.clone(),
                comp_type: meta.comp_type,
                cipher_algo: meta.cipher_algo.clone(),
                plaintext_len: meta.plaintext_len,
                ciphertext_len: meta.ciphertext_len,
                dedup_hit: true,
                record: existing,
            });
        }
        // Same content-id but different bytes is impossible under the keyed
        // hash unless the record is corrupt; fall through to the normal
        // publish path, which re-verifies and fails loudly on a bad winner.
    }

    let sealed = crypto.seal_chunk_shared(plaintext, comp_override, &domain_wrap_key)?;

    cacache::write(cache_dir, &sealed.object_id, &sealed.ciphertext).await?;
    let my_object_id = sealed.object_id.clone();

    let record = cairn_store::shared_dedup::SharedDedupRecord {
        format: "cairn-shared-v1".to_string(),
        domain_ns: namespace,
        content_id,
        object_id: my_object_id.clone(),
        sealed_meta: cairn_store::shared_dedup::SharedDedupMeta {
            wrapped_key: sealed.domain_wrapped_key.clone(),
            comp_type: sealed.comp_type,
            cipher_algo: sealed.cipher_algo.clone(),
            plaintext_len: sealed.plaintext_len,
            ciphertext_len: sealed.ciphertext_len,
            blake3_hash: my_object_id.clone(),
        },
        wrapped_by_domain_key: true,
    };

    cairn_store::shared_dedup::put_shared_object(
        &cfg.records_dir,
        &record.domain_ns,
        &record.object_id,
        &sealed.ciphertext,
    )?;

    let published = match cairn_store::shared_dedup::publish_shared_or_adopt(
        &cfg.records_dir,
        &record,
        |object_id| {
            let records_dir = cfg.records_dir.clone();
            let namespace = record.domain_ns.clone();
            async move {
                cairn_store::shared_dedup::read_shared_object(&records_dir, &namespace, &object_id)
            }
        },
        &cfg.domain_secret,
    )
    .await?
    {
        cairn_store::shared_dedup::SharedPublish::Published(rec) => rec,
        cairn_store::shared_dedup::SharedPublish::Adopted(rec) => {
            // SH-8: we lost the race — our freshly sealed object is bound by
            // NO record (the winner's record names the winner's object), so
            // it would leak in the domain store forever. Best-effort delete
            // it now; skip when our object_id equals the winner's (identical
            // bytes → the object is shared and IS referenced).
            if rec.object_id != my_object_id {
                if let Err(e) = cairn_store::shared_dedup::remove_shared_object(
                    &cfg.records_dir,
                    &record.domain_ns,
                    &my_object_id,
                ) {
                    tracing::warn!(
                        "shared-dedup: loser object cleanup failed for {my_object_id}: {e}"
                    );
                }
            }
            rec
        }
    };

    let canonical = cairn_store::shared_dedup::read_shared_object(
        &cfg.records_dir,
        &published.domain_ns,
        &published.object_id,
    )?;
    // A valid ciphertext hash alone does not prove that a mapping points at
    // the requested content.  Before adopting (or indexing our own newly
    // published record), unwrap and fully validate the sealed record, then
    // compare its plaintext with the bytes we were asked to store.
    let winner_key =
        cairn_seal::unwrap_with_domain_key(&published.sealed_meta.wrapped_key, &domain_wrap_key)?;
    let winner_meta = cairn_seal::parse_sealed_record(&winner_key)?;
    let winner_plaintext = crypto.decrypt_chunk_shared_record(
        &canonical,
        &winner_key,
        winner_meta.comp_type,
        &published.sealed_meta.cipher_algo,
    )?;
    if winner_plaintext.as_slice() != plaintext {
        anyhow::bail!("shared dedup winner plaintext does not match requested chunk");
    }
    cacache::write(cache_dir, &published.object_id, canonical).await?;
    // Domain GC: register our holder link for the canonical (winner's) object
    // we are about to index — hard error: an archive must never index domain
    // content that GC could later consider unheld.
    cairn_store::shared_dedup::add_shared_holder(
        &cfg.records_dir,
        &published.domain_ns,
        &published.content_id,
        &cfg.holder_id,
    )?;

    let meta = &published.sealed_meta;
    Ok(SharedChunkOutcome {
        object_id: published.object_id.clone(),
        comp_type: meta.comp_type,
        cipher_algo: meta.cipher_algo.clone(),
        plaintext_len: meta.plaintext_len,
        ciphertext_len: meta.ciphertext_len,
        dedup_hit: published.object_id != sealed.object_id,
        record: published,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn cdc_ctx() -> cairn_seal::CryptoCtx {
        cairn_seal::CryptoCtx::new_symmetric(
            3,
            0,
            "zstd".to_string(),
            "aes-gcm".to_string(),
            Some(SecretString::from(
                "dedup_secret_that_is_at_least_32_bytes_long_for_testing".to_string(),
            )),
            false,
            10,
            SecretString::from("correct horse battery staple"),
            None,
        )
        .unwrap()
    }

    fn cfg(records: &str, domain: &str) -> SharedDedupConfig {
        SharedDedupConfig {
            records_dir: records.to_string(),
            domain_id: domain.to_string(),
            domain_secret: zeroize::Zeroizing::new(format!("domain-secret-{domain}").into_bytes()),
            holder_id: format!("holder-{domain}"),
        }
    }

    /// A domain member decrypts the canonical object end-to-end: unwrap the
    /// record's domain key, parse it, decrypt the object from the cache.
    fn assert_domain_decrypts(
        crypto: &cairn_seal::CryptoCtx,
        cfg: &SharedDedupConfig,
        cache_dir: &str,
        outcome: &SharedChunkOutcome,
        expected: &[u8],
    ) {
        let domain_wrap_key = cairn_seal::shared_domain_wrapping_key(&cfg.domain_secret);
        let record = cairn_seal::unwrap_with_domain_key(
            &outcome.record.sealed_meta.wrapped_key,
            &domain_wrap_key,
        )
        .unwrap();
        let parsed = cairn_seal::parse_sealed_record(&record).unwrap();
        assert_eq!(parsed.ciphertext_len, outcome.ciphertext_len);
        assert_eq!(parsed.plaintext_len, outcome.plaintext_len);
        let blob = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(cacache::read(cache_dir, &outcome.record.object_id))
        })
        .unwrap();
        let decrypted = crypto
            .decrypt_chunk_shared_record(&blob, &record, parsed.comp_type, &outcome.cipher_algo)
            .unwrap();
        assert_eq!(decrypted.as_slice(), expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn first_writer_publishes_own_canonical_object() {
        let base = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let cfg = cfg(base.path().to_str().unwrap(), "team-a");
        let plaintext = b"identical chunk across archives".repeat(3);
        let crypto = cdc_ctx();

        let out = publish_shared_chunk(
            &plaintext,
            &crypto,
            None,
            &cfg,
            cache.path().to_str().unwrap(),
        )
        .await
        .unwrap();
        assert!(!out.dedup_hit);
        assert_eq!(out.object_id, out.record.object_id);
        assert!(out.sealed_meta_is_ok());
        assert_domain_decrypts(
            &crypto,
            &cfg,
            cache.path().to_str().unwrap(),
            &out,
            &plaintext,
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn second_writer_adopts_the_single_canonical_object() {
        let base = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let cfg = cfg(base.path().to_str().unwrap(), "team-a");
        let plaintext = b"identical chunk across archives".repeat(3);
        let crypto = cdc_ctx();

        let first = publish_shared_chunk(
            &plaintext,
            &crypto,
            None,
            &cfg,
            cache.path().to_str().unwrap(),
        )
        .await
        .unwrap();
        let second = publish_shared_chunk(
            &plaintext,
            &crypto,
            None,
            &cfg,
            cache.path().to_str().unwrap(),
        )
        .await
        .unwrap();

        assert!(!first.dedup_hit);
        assert!(second.dedup_hit, "identical chunk must adopt");
        assert_eq!(
            second.object_id, first.object_id,
            "ONE canonical object per content"
        );
        assert_domain_decrypts(
            &crypto,
            &cfg,
            cache.path().to_str().unwrap(),
            &second,
            &plaintext,
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn repeated_writes_do_not_accumulate_loser_objects() {
        // BF-04.10: identical repeats must not leave a fresh sealed object per
        // call (the old seal-first order did, with no GC for the losers).
        let base = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let cfg = cfg(base.path().to_str().unwrap(), "team-a");
        let plaintext = b"repeat me five times".repeat(4);
        let crypto = cdc_ctx();

        for _ in 0..5 {
            publish_shared_chunk(
                &plaintext,
                &crypto,
                None,
                &cfg,
                cache.path().to_str().unwrap(),
            )
            .await
            .unwrap();
        }

        let ns = cairn_store::shared_dedup::derive_namespace("team-a", &cfg.domain_secret);
        let objects_dir = std::path::Path::new(base.path())
            .join("dedup/shared")
            .join(&ns)
            .join("objects");
        let count = std::fs::read_dir(&objects_dir).unwrap().count();
        assert_eq!(
            count, 1,
            "identical content must persist exactly one canonical object"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn separate_archives_adopt_from_the_domain_store() {
        let domain_store = tempfile::tempdir().unwrap();
        let first_cache = tempfile::tempdir().unwrap();
        let second_cache = tempfile::tempdir().unwrap();
        let cfg = cfg(domain_store.path().to_str().unwrap(), "team-a");
        let plaintext = b"identical chunk in two independent archives".repeat(3);

        let first = publish_shared_chunk(
            &plaintext,
            &cdc_ctx(),
            None,
            &cfg,
            first_cache.path().to_str().unwrap(),
        )
        .await
        .unwrap();
        let second = publish_shared_chunk(
            &plaintext,
            &cdc_ctx(),
            None,
            &cfg,
            second_cache.path().to_str().unwrap(),
        )
        .await
        .unwrap();

        assert!(second.dedup_hit);
        assert_eq!(second.object_id, first.object_id);
        assert!(
            cacache::read(second_cache.path(), &second.object_id)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn different_domains_do_not_dedup() {
        let base = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let plaintext = b"identical chunk across archives".repeat(3);
        let crypto = cdc_ctx();

        let a = publish_shared_chunk(
            &plaintext,
            &crypto,
            None,
            &cfg(base.path().join("a").to_str().unwrap(), "team-a"),
            cache.path().to_str().unwrap(),
        )
        .await
        .unwrap();
        let b = publish_shared_chunk(
            &plaintext,
            &crypto,
            None,
            &cfg(base.path().join("b").to_str().unwrap(), "team-b"),
            cache.path().to_str().unwrap(),
        )
        .await
        .unwrap();
        assert!(!b.dedup_hit);
        assert_ne!(a.object_id, b.object_id);
    }

    /// SH-8 regression: when two publishers race for the same content, the
    /// loser's freshly sealed object must NOT linger in the domain store —
    /// exactly one object file may remain afterwards. (The large payload makes
    /// the seal outlast the lookup, so both publishers realistically take the
    /// publish path; whichever loses must clean up.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn publisher_race_leaves_exactly_one_domain_object() {
        let base = tempfile::tempdir().unwrap();
        let records = base.path().join("records");
        let cache = base.path().join("cache");
        let crypto = cdc_ctx();
        let cfg = cfg(records.to_str().unwrap(), "team-race");
        let plaintext = vec![0xA7u8; 600_000]; // seal cost >> lookup cost

        let (x, y) = tokio::join!(
            publish_shared_chunk(&plaintext, &crypto, None, &cfg, cache.to_str().unwrap(),),
            publish_shared_chunk(&plaintext, &crypto, None, &cfg, cache.to_str().unwrap(),),
        );
        let x = x.unwrap();
        let y = y.unwrap();
        assert_eq!(x.object_id, y.object_id, "both must land on one object");

        let ns = cairn_store::shared_dedup::derive_namespace("team-race", &cfg.domain_secret);
        let objects_dir = records.join("dedup/shared").join(&ns).join("objects");
        let leftovers: Vec<_> = std::fs::read_dir(&objects_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            leftovers,
            vec![x.object_id.clone()],
            "SH-8: loser-race objects leaked into the domain store"
        );
    }

    impl SharedChunkOutcome {
        fn sealed_meta_is_ok(&self) -> bool {
            !self.record.sealed_meta.wrapped_key.is_empty()
                && self.record.sealed_meta.blake3_hash == self.object_id
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn chunker_shared_mode_publishes_and_dedups_with_domain_flag() {
        use std::sync::Arc;
        let base = tempfile::tempdir().unwrap();
        let cache = base.path().join("cache");
        let records = base.path().join("records");
        let db = Arc::new(
            cairn_index::Db::new(base.path().join("db.sqlcipher").to_str().unwrap(), None).unwrap(),
        );
        let store: Arc<dyn cairn_store::ChunkStore> = Arc::new(cairn_store::CairnStore::new(
            cache.to_string_lossy().to_string(),
            vec![],
            None,
        ));
        let crypto = std::sync::Arc::new(cdc_ctx());
        let cfg = crate::shared::SharedDedupConfig {
            records_dir: records.to_string_lossy().to_string(),
            domain_id: "team-a".to_string(),
            domain_secret: zeroize::Zeroizing::new(b"domain secret".to_vec()),
            holder_id: "holder-integration".to_string(),
        };
        let payload = b"chunk payload that must cross-archive dedup".repeat(20);

        let first = crate::Chunker::process_data(
            &payload,
            cache.to_str().unwrap(),
            crypto.clone(),
            db.clone(),
            store.clone(),
            "raid1".to_string(),
            false,
            None,
            Some(cfg.clone()),
        )
        .await
        .unwrap();
        let second = crate::Chunker::process_data(
            &payload,
            cache.to_str().unwrap(),
            crypto.clone(),
            db.clone(),
            store.clone(),
            "raid1".to_string(),
            false,
            None,
            Some(cfg.clone()),
        )
        .await
        .unwrap();

        assert!(
            first.iter().any(|c| !c.dedup_hit),
            "first write must publish new domain objects"
        );
        assert!(
            second.iter().any(|c| c.dedup_hit),
            "identical re-write must adopt the published objects"
        );
        // Every published object must be flagged domain in the index.
        for c in first.iter().filter(|c| !c.dedup_hit) {
            assert!(
                db.get_chunk_domain(&c.hash_key).unwrap(),
                "chunk {} not flagged domain",
                c.hash_key
            );
        }

        // Domain GC: publish AND dedup-hit both register our holder link.
        let ns = cairn_store::shared_dedup::derive_namespace("team-a", b"domain secret");
        assert!(cairn_store::shared_dedup::holders_enabled(
            records.to_str().unwrap(),
            &ns
        ));
        let holders_root = records.join("dedup/shared").join(&ns).join("holders");
        let mut stack = vec![holders_root];
        let mut links = 0;
        while let Some(d) = stack.pop() {
            if let Ok(rd) = std::fs::read_dir(&d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if e.file_name() == "holder-integration" {
                        links += 1;
                    }
                }
            }
        }
        assert!(
            links >= 1,
            "holder link missing after publish+adopt: {links}"
        );
    }
}
