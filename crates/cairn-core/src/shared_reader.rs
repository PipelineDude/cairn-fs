//! D03 reader bridge: decide between the archive-scope decrypt and the
//! shared-dedup domain decrypt for a chunk read.
//!
//! A domain chunk's `chunk_index.sym_key` holds the DOMAIN-WRAPPED sealed
//! chunk-key record (the `domain` flag is part of the current schema,
//! `cairn_index`).  cairn-core's
//! read sites already have the object_id in hand; this helper tells them
//! whether the domain path applies and, if so, decrypts it.  The domain key
//! comes from `CAIRN_SHARED_DEDUP_SECRET` (background processes; the same
//! source the bin's `resolve` already accepts) — the secret itself is never
//! persisted.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use zeroize::Zeroizing;

pub struct SharedChunkReader {
    domain_key: Option<[u8; 32]>,
    db: Arc<cairn_index::Db>,
}

impl SharedChunkReader {
    /// Build a reader from the archive-pinned secret source.  A shared-domain
    /// archive cannot silently fall back to archive-scope decryption.
    pub fn from_archive_config(db: Arc<cairn_index::Db>) -> Result<Self> {
        let Some(domain) = db.get_config("dedup_shared_domain")? else {
            return Ok(Self {
                domain_key: None,
                db,
            });
        };
        let path = db
            .get_config("dedup_shared_secret_file")?
            .ok_or_else(|| anyhow!("shared-dedup archive has no secret-file path"))?;
        let secret = std::fs::read(&path)
            .map_err(|e| anyhow!("cannot read shared-dedup secret file {path}: {e}"))?;
        let expected = db
            .get_config("dedup_shared_namespace")?
            .ok_or_else(|| anyhow!("shared-dedup archive has no persisted namespace"))?;
        if cairn_store::shared_dedup::derive_namespace(&domain, &secret) != expected {
            anyhow::bail!("shared-dedup secret does not match this archive's configured domain");
        }
        Ok(Self {
            domain_key: Some(cairn_seal::shared_domain_wrapping_key(&secret)),
            db,
        })
    }

    /// True when a domain key is configured (shared mode is live for reads).
    pub fn domain_mode_active(&self) -> bool {
        self.domain_key.is_some()
    }

    /// Try the shared-domain decrypt for `object_id`.
    ///
    /// Returns:
    /// - `Ok(None)` when the chunk is archive-scope (no domain flag) or no
    ///   domain key is configured — the caller keeps its existing
    ///   `decrypt_chunk_symmetric` path;
    /// - `Ok(Some(plaintext))` after unwrapping the domain key and passing
    ///   full sealed-record validation (D00 §7 guarantees);
    /// - `Err(..)` loudly when a chunk IS flagged domain but cannot be
    ///   verified/decrypted — never silently fall back to the archive path.
    pub fn try_decrypt_domain(
        &self,
        crypto: &cairn_seal::CryptoCtx,
        object_id: &str,
        ciphertext: &[u8],
        wrapped_key: &[u8],
        comp_type: u8,
        cipher_algo: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(domain_key) = self.domain_key else {
            return Ok(None);
        };
        if !self.db.get_chunk_domain(object_id)? {
            return Ok(None);
        }
        let record = cairn_seal::unwrap_with_domain_key(wrapped_key, &domain_key)?;
        let meta = cairn_seal::parse_sealed_record(&record)?;
        if meta.comp_type != comp_type {
            anyhow::bail!("shared chunk metadata does not match request: {object_id}");
        }
        let plain =
            crypto.decrypt_chunk_shared_record(ciphertext, &record, comp_type, cipher_algo)?;
        Ok(Some(plain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn seal_ctx() -> cairn_seal::CryptoCtx {
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
            SecretString::from("password for reader tests"),
            None,
        )
        .unwrap()
    }

    fn temp_db() -> (tempfile::TempDir, Arc<cairn_index::Db>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            cairn_index::Db::new(dir.path().join("r.db").to_str().unwrap(), None).unwrap(),
        );
        (dir, db)
    }

    /// Insert a chunk row + optionally flag it domain.
    fn insert_chunk(db: &cairn_index::Db, oid: &str, wrapped: &[u8], domain: bool) {
        db.insert_chunk_indices_batch(&[(
            oid.to_string(),
            format!("{oid}-ph"),
            wrapped.to_vec(),
            0,
            "aes-gcm".to_string(),
        )])
        .unwrap();
        if domain {
            db.set_chunk_domain(oid, true).unwrap();
        }
    }

    #[test]
    fn archive_scope_chunk_returns_none_without_domain_key() {
        let (_d, db) = temp_db();
        insert_chunk(&db, "obj", b"archive-wrap", false);
        let reader = SharedChunkReader {
            domain_key: None,
            db,
        };
        let ctx = seal_ctx();
        assert!(!reader.domain_mode_active());
        let r = reader
            .try_decrypt_domain(&ctx, "obj", b"ct", b"wrap", 0, "aes-gcm")
            .unwrap();
        assert!(
            r.is_none(),
            "archive-scope or no secret → caller keeps archive path"
        );
    }

    #[test]
    fn domain_chunk_decrypts_with_correct_domain_secret() {
        let (_d, db) = temp_db();
        let ctx = seal_ctx();
        let plaintext_vec = b"reader bridge plaintext payload".repeat(2);
        let plaintext = plaintext_vec.as_slice();
        let secret = b"shared domain secret";
        let domain_key = cairn_seal::shared_domain_wrapping_key(secret);
        let sealed = ctx.seal_chunk_shared(plaintext, None, &domain_key).unwrap();
        insert_chunk(&db, &sealed.object_id, &sealed.domain_wrapped_key, true);

        let reader = SharedChunkReader {
            domain_key: Some(domain_key),
            db,
        };
        let out = reader
            .try_decrypt_domain(
                &ctx,
                &sealed.object_id,
                &sealed.ciphertext,
                &sealed.domain_wrapped_key,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
            .unwrap()
            .expect("domain path must decrypt");
        assert_eq!(out.as_slice(), plaintext_vec.as_slice());
    }

    #[test]
    fn domain_chunk_with_wrong_secret_fails_loud() {
        let (_d, db) = temp_db();
        let ctx = seal_ctx();
        let plaintext = b"secret tied to one domain";
        let domain_key = cairn_seal::shared_domain_wrapping_key(b"team-a secret");
        let sealed = ctx.seal_chunk_shared(plaintext, None, &domain_key).unwrap();
        insert_chunk(&db, &sealed.object_id, &sealed.domain_wrapped_key, true);

        let wrong = cairn_seal::shared_domain_wrapping_key(b"team-b secret");
        let reader = SharedChunkReader {
            domain_key: Some(wrong),
            db,
        };
        let err = reader
            .try_decrypt_domain(
                &ctx,
                &sealed.object_id,
                &sealed.ciphertext,
                &sealed.domain_wrapped_key,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
            .unwrap_err();
        assert!(err.to_string().contains("unwrap failed"), "{err}");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (_d, db) = temp_db();
        let ctx = seal_ctx();
        let plaintext = b"verifiable canonical payload";
        let domain_key = cairn_seal::shared_domain_wrapping_key(b"domain secret");
        let sealed = ctx.seal_chunk_shared(plaintext, None, &domain_key).unwrap();
        insert_chunk(&db, &sealed.object_id, &sealed.domain_wrapped_key, true);

        let mut tampered = sealed.ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let reader = SharedChunkReader {
            domain_key: Some(domain_key),
            db,
        };
        let err = reader
            .try_decrypt_domain(
                &ctx,
                &sealed.object_id,
                &tampered,
                &sealed.domain_wrapped_key,
                sealed.comp_type,
                &sealed.cipher_algo,
            )
            .unwrap_err();
        assert!(err.to_string().contains("corrupt"), "{err}");
    }
}
