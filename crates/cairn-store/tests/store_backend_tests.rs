//! CairnStore chunk read/write round-trip, cache behavior, cloud-storage feature-gate,
//! and edge-case coverage.

use cairn_store::ChunkStore;
use std::sync::Arc;

/// Helper: write a payload into the local cacache so fetch_chunk can find it.
async fn seed_cache(cache_dir: &str, hash_key: &str, payload: &[u8]) {
    cacache::write(cache_dir, hash_key, payload).await.unwrap();
}

/// Helper: create a CairnStore with no cloud operators (local-only mode).
fn make_store(cache_dir: String) -> cairn_store::CairnStore {
    cairn_store::CairnStore::new(cache_dir, vec![], None)
}

// ── Chunk read/write round-trip byte-for-byte ────────────────────────────────

#[tokio::test]
async fn store_roundtrip_single_chunk() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    let store = make_store(cache_dir.clone());

    let payload: Vec<u8> = (0..=255).cycle().take(4096).collect();
    let hash_key = blake3::hash(&payload).to_hex();

    // Seed the cache with the raw payload.
    seed_cache(&cache_dir, &hash_key, &payload).await;

    let fetched = store
        .fetch_chunk(&hash_key, "raid0", false, false, false)
        .await
        .unwrap();
    assert_eq!(fetched, payload);
}

#[tokio::test]
async fn store_roundtrip_large_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    let store = make_store(cache_dir.clone());

    // 1 MiB payload.
    let payload: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let hash_key = blake3::hash(&payload).to_hex();

    seed_cache(&cache_dir, &hash_key, &payload).await;

    let fetched = store
        .fetch_chunk(&hash_key, "raid0", false, false, false)
        .await
        .unwrap();
    assert_eq!(fetched.len(), payload.len());
    assert_eq!(fetched, payload);
}

#[tokio::test]
async fn store_roundtrip_binary_random() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    let store = make_store(cache_dir.clone());

    // Deterministic pseudo-random pattern (includes all byte values).
    let payload: Vec<u8> = (0..8192).map(|i| ((i * 251 + 17) % 256) as u8).collect();
    let hash_key = blake3::hash(&payload).to_hex();

    seed_cache(&cache_dir, &hash_key, &payload).await;

    let fetched = store
        .fetch_chunk(&hash_key, "raid0", false, false, false)
        .await
        .unwrap();
    assert_eq!(fetched, payload);
}

// ── Cache behavior (corruption detection + fallback) ─────────────────────────

#[tokio::test]
async fn store_corrupt_cache_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    let store = make_store(cache_dir.clone());

    let payload = b"good data".to_vec();
    let bad_payload = b"corrupted!".to_vec();
    let hash_key = blake3::hash(&payload).to_hex(); // correct hash of good data

    // Write WRONG data under the CORRECT hash key → cache entry is corrupt.
    seed_cache(&cache_dir, &hash_key, &bad_payload).await;

    // Without skip_verify, fetch_chunk should detect corruption and return Err
    // (because there are no cloud operators to fall back to).
    let result = store
        .fetch_chunk(&hash_key, "raid0", false, false, false)
        .await;
    assert!(
        result.is_err(),
        "corrupt cache entry should fail without cloud fallback"
    );
}

#[tokio::test]
async fn store_skip_verify_bypasses_hash_check() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    let store = make_store(cache_dir.clone());

    let payload = b"good data".to_vec();
    let bad_payload = b"corrupted!".to_vec();
    let hash_key = blake3::hash(&payload).to_hex();

    seed_cache(&cache_dir, &hash_key, &bad_payload).await;

    // skip_verify = true should return the raw bytes regardless of hash mismatch.
    let fetched = store
        .fetch_chunk(&hash_key, "raid0", true, false, false)
        .await
        .unwrap();
    assert_eq!(fetched, bad_payload);
}

// ── Cloud-storage feature flag: without cloud-storage feature, cloud ops fail ─

#[cfg(not(feature = "cloud-storage"))]
#[tokio::test]
async fn store_no_cloud_feature_fetch_missing_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    let store = make_store(cache_dir.clone());

    let hash_key = "nonexistent_chunk_hash".to_string();

    // No cloud-storage feature → fetch_chunk should bail with a specific error.
    let result = store
        .fetch_chunk(&hash_key, "raid0", false, false, false)
        .await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("cloud-storage") || err_msg.contains("missing from local"),
        "error should mention cloud-storage being disabled or chunk missing locally: {err_msg}"
    );
}

#[cfg(not(feature = "cloud-storage"))]
#[tokio::test]
async fn store_no_cloud_feature_upload_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    let store = make_store(cache_dir.clone());

    // Without cloud-storage, upload_chunk should succeed as a no-op (local-only mode).
    let result = store
        .upload_chunk(vec![1, 2, 3], "fake_hash", "raid0")
        .await;
    assert!(
        result.is_ok(),
        "upload without cloud feature should be a no-op"
    );
}

#[cfg(feature = "cloud-storage")]
#[tokio::test]
async fn store_cloud_feature_fetch_missing_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    // No operators → even with cloud feature, missing chunk fails.
    let store = make_store(cache_dir.clone());

    let hash_key = "missing_chunk".to_string();
    let result = store
        .fetch_chunk(&hash_key, "raid0", false, false, true)
        .await;
    assert!(result.is_err(), "force_cloud with no operators should fail");
}

// ── Edge cases: empty chunk, max-size chunk, concurrent reads ────────────────

#[tokio::test]
async fn store_empty_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    let store = make_store(cache_dir.clone());

    let payload: Vec<u8> = vec![];
    let hash_key = blake3::hash(&payload).to_hex();

    seed_cache(&cache_dir, &hash_key, &payload).await;

    let fetched = store
        .fetch_chunk(&hash_key, "raid0", false, false, false)
        .await
        .unwrap();
    assert!(fetched.is_empty());
}

#[tokio::test]
async fn store_max_size_chunk() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    let store = make_store(cache_dir.clone());

    // 4 MiB chunk (large but fits in memory).
    let size = 4 * 1024 * 1024;
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let hash_key = blake3::hash(&payload).to_hex();

    seed_cache(&cache_dir, &hash_key, &payload).await;

    let fetched = store
        .fetch_chunk(&hash_key, "raid0", false, false, false)
        .await
        .unwrap();
    assert_eq!(fetched.len(), size);
    assert_eq!(fetched, payload);
}

#[tokio::test]
async fn store_concurrent_reads_same_chunk() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    // CairnStore is not Clone — share it through an Arc across the reader tasks.
    let store = Arc::new(make_store(cache_dir.clone()));

    let payload: Vec<u8> = (0..4096).map(|i| (i % 127) as u8).collect();
    let hash_key = blake3::hash(&payload).to_hex();

    seed_cache(&cache_dir, &hash_key, &payload).await;

    // Spawn 10 concurrent readers for the same chunk.
    let mut handles = vec![];
    for _ in 0..10 {
        let store_clone = Arc::clone(&store);
        let hash_clone = hash_key;
        handles.push(tokio::spawn(async move {
            store_clone
                .fetch_chunk(&hash_clone, "raid0", false, false, false)
                .await
        }));
    }

    for handle in handles {
        let fetched = handle.await.unwrap().unwrap();
        assert_eq!(fetched, payload);
    }
}

#[tokio::test]
async fn store_concurrent_reads_different_chunks() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_str().unwrap().to_string();
    // CairnStore is not Clone — share it through an Arc across the reader tasks.
    let store = Arc::new(make_store(cache_dir.clone()));

    let payloads: Vec<_> = (0..5)
        .map(|i| {
            (0..1024)
                .map(|j| ((i + j) % 251) as u8)
                .collect::<Vec<u8>>()
        })
        .collect();

    let mut hash_keys = vec![];
    for payload in &payloads {
        let hk = blake3::hash(payload).to_hex();
        seed_cache(&cache_dir, &hk, payload).await;
        hash_keys.push(hk);
    }

    let mut handles = vec![];
    for (i, hk) in hash_keys.iter().enumerate() {
        let store_clone = Arc::clone(&store);
        let hash_clone = *hk;
        handles.push(tokio::spawn(async move {
            let fetched = store_clone
                .fetch_chunk(&hash_clone, "raid0", false, false, false)
                .await
                .unwrap();
            (i, fetched)
        }));
    }

    for handle in handles {
        let (idx, fetched) = handle.await.unwrap();
        assert_eq!(fetched, payloads[idx]);
    }
}

// ── stable_hash_index determinism ────────────────────────────────────────────

#[test]
fn store_stable_hash_deterministic() {
    let h1 = cairn_store::stable_hash_index("test_key", 10);
    let h2 = cairn_store::stable_hash_index("test_key", 10);
    assert_eq!(h1, h2, "same input must produce same hash index");
}

#[test]
fn store_stable_hash_modulus() {
    for modulus in [1, 2, 4, 8, 16, 100, 1024] {
        let idx = cairn_store::stable_hash_index("any_key", modulus);
        assert!(
            idx < modulus,
            "hash index {idx} must be < modulus {modulus}"
        );
    }
}

#[test]
fn store_stable_hash_different_inputs() {
    let h1 = cairn_store::stable_hash_index("key_a", 256);
    let h2 = cairn_store::stable_hash_index("key_b", 256);
    // With 256 buckets, collision is possible but extremely unlikely for different keys.
    // We assert they differ to confirm the hash function spreads well.
    assert_ne!(h1, h2, "different inputs should produce different indices");
}
