//! Shared-dedup domain (BF-02 / D00-D01).
//!
//! Opt-in cross-archive deduplication: an archive in a given domain publishes
//! its dedup content-IDs under `domain|fingerprint(secret)` (see
//! reports/SHARED_DEDUP_DESIGN.md).  D01 scope is only the *parameter +
//! secret plumbing*: the two CLI flags are coupled, conflict with
//! --disable-dedup, the secret is read from a file (never passed as a value,
//! never stored/printed), and the *non-secret* derived identity (domain id +
//! secret fingerprint) is what an archive persists in its SQLCipher config.
//!
//! The content-ID key derivation itself is D02 (cairn-cdc / cairn-store,
//! hardware requires the store to expose `atomic_get_or_create` ).

use std::path::Path;

/// Non-secret shared-dedup identity an archive persists in its config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedDedupConfig {
    pub domain_id: String,
    /// `domain_id|fingerprint(secret)` — the store-level namespace used both
    /// to derive shared content-IDs and as the record key prefix.
    pub namespace: String,
}

pub fn derive_namespace(domain_id: &str, secret: &[u8]) -> String {
    cairn_store::shared_dedup::derive_namespace(domain_id, secret)
}

/// Resolve the shared-dedup mode from the CLI pair.
///
/// Returns:
/// - `Ok(None)` when neither flag is present → archive-scope default (BF-01);
/// - `Ok(Some(config))` when the domain is present and a secret is available
///   (from the file or, for non-interactive processes, `env_secret` fed from
///   `CAIRN_SHARED_DEDUP_SECRET`);
/// - `Err` on partial/conflicting/malformed input or an unreadable secret.
///
/// The secret itself is never stored/printed; only its fingerprint enters the
/// archive config.
pub fn resolve(
    domain: Option<&str>,
    secret_file: Option<&Path>,
    disable_dedup: bool,
    env_secret: Option<Vec<u8>>,
) -> Result<Option<SharedDedupConfig>, String> {
    if domain.is_none() {
        // No domain → archive-scope default, unless a secret was handed to
        // us: a secret-file/env without a domain is still a partial call.
        if secret_file.is_some() || env_secret.is_some() {
            return Err(
                "--shared-dedup-secret-file / CAIRN_SHARED_DEDUP_SECRET requires \
                 --shared-dedup-domain: provide them together"
                    .to_string(),
            );
        }
        return Ok(None);
    }
    if disable_dedup {
        return Err(
            "--shared-dedup-* conflicts with --disable-dedup: random per-chunk keys \
             cannot deduplicate across archives"
                .to_string(),
        );
    }
    let domain_id = domain.unwrap().trim();
    if domain_id.is_empty() {
        return Err("--shared-dedup-domain must be a non-empty identifier".to_string());
    }
    if domain_id.len() > 64
        || !domain_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(
            "--shared-dedup-domain must use only [A-Za-z0-9_-] and be at most 64 chars".to_string(),
        );
    }
    // The file is authoritative when given (interactive init); the env secret
    // is the fallback for background/long-running processes that must not
    // require re-typing the domain secret on every invocation.
    let secret: Vec<u8> = if let Some(path) = secret_file {
        std::fs::read(path).map_err(|e| {
            format!(
                "cannot read --shared-dedup-secret-file {}: {e}",
                path.display()
            )
        })?
    } else if let Some(env) = env_secret {
        env
    } else {
        return Err(
            "--shared-dedup-domain requires a secret: --shared-dedup-secret-file, or \
             CAIRN_SHARED_DEDUP_SECRET for background processes"
                .to_string(),
        );
    };
    if secret.is_empty() {
        return Err(
            "shared-dedup secret is empty: nothing to key the domain namespace on".to_string(),
        );
    }
    Ok(Some(SharedDedupConfig {
        domain_id: domain_id.to_string(),
        namespace: derive_namespace(domain_id, &secret),
    }))
}

#[cfg(test)]
fn tpath(name: &str) -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "cairn-d01-{name}-{}-{}.bin",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn neither_flag_keeps_archive_scope_default() {
        assert_eq!(resolve(None, None, false, None).unwrap(), None);
    }

    #[test]
    fn partial_args_are_rejected() {
        let e = resolve(Some("team-a"), None, false, None).unwrap_err();
        assert!(e.contains("requires a secret"), "{e}");
        let e = resolve(None, Some(Path::new("/tmp/x")), false, None).unwrap_err();
        assert!(e.contains("requires --shared-dedup-domain"), "{e}");
    }

    #[test]
    fn conflicts_with_disable_dedup() {
        let tmp = tpath("template-empty");
        std::fs::write(&tmp, b"s3cr3t!").unwrap();
        let e = resolve(Some("team-a"), Some(&tmp), true, None).unwrap_err();
        assert!(e.contains("--disable-dedup"), "{e}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn empty_or_malformed_domain_is_rejected() {
        let tmp = tpath("template-secret");
        std::fs::write(&tmp, b"x").unwrap();
        assert!(resolve(Some("  "), Some(&tmp), false, None).is_err());
        assert!(resolve(Some("имя!"), Some(&tmp), false, None).is_err());
        let too_long = "a".repeat(65);
        assert!(resolve(Some(&too_long), Some(&tmp), false, None).is_err());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn unreadable_secret_file_is_an_error_without_any_outcome() {
        let missing = Path::new("/definitely/not/here/template-secret");
        let e = resolve(Some("team-a"), Some(missing), false, None).unwrap_err();
        assert!(e.contains("cannot read"), "{e}");
    }

    #[test]
    fn empty_secret_file_is_rejected() {
        let tmp = tpath("template-empty");
        std::fs::write(&tmp, b"").unwrap();
        let e = resolve(Some("team-a"), Some(&tmp), false, None).unwrap_err();
        assert!(e.contains("empty"), "{e}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn valid_pair_derives_deterministic_non_secret_namespace() {
        let tmp = tpath("template-secret");
        std::fs::write(&tmp, b"shared secret bytes").unwrap();
        let cfg = resolve(Some("team-a"), Some(&tmp), false, None)
            .unwrap()
            .unwrap();
        assert_eq!(cfg.domain_id, "team-a");
        let prefix = cairn_store::shared_dedup::derive_namespace("team-a", b"shared secret bytes");
        assert_eq!(cfg.namespace, prefix);
        assert!(!cfg.namespace.contains("shared secret bytes"));
        // Deterministic across calls with the same secret.
        let again = resolve(Some("team-a"), Some(&tmp), false, None)
            .unwrap()
            .unwrap();
        assert_eq!(cfg.namespace, again.namespace);
        // Different secret → different namespace.
        let other = tpath("template-secret2");
        std::fs::write(&other, b"other secret bytes").unwrap();
        let cfg2 = resolve(Some("team-a"), Some(&other), false, None)
            .unwrap()
            .unwrap();
        assert_ne!(cfg.namespace, cfg2.namespace);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&other);
    }
}
#[cfg(test)]
mod env_secret_tests {
    use super::*;

    #[test]
    fn env_secret_is_accepted_for_background_processes() {
        let cfg = resolve(Some("team-a"), None, false, Some(b"env secret".to_vec()))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.namespace, derive_namespace("team-a", b"env secret"));
        assert!(!cfg.namespace.contains("env secret"), "secret never leaked");
    }

    #[test]
    fn env_secret_does_not_replace_the_authoritative_file() {
        let tmp = tpath("template-secret-file");
        std::fs::write(&tmp, b"file secret").unwrap();
        let cfg = resolve(
            Some("team-a"),
            Some(&tmp),
            false,
            Some(b"env secret".to_vec()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.namespace, derive_namespace("team-a", b"file secret"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn domain_without_any_secret_is_an_error() {
        let e = resolve(Some("team-a"), None, false, None).unwrap_err();
        assert!(e.contains("requires a secret"), "{e}");
        assert!(e.contains("CAIRN_SHARED_DEDUP_SECRET"), "{e}");
    }
}
