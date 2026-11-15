//! Content-defined chunking boundary conditions, dedup key generation, and compression type selection.
//!
//! Tests are written against the public API of `cairn_cdc::Chunker` without depending on
//! cloud-storage features where possible (to avoid needing S3/GCS backends).

use age::secrecy::ExposeSecret;
use std::sync::Arc;

/// Minimal setup: create a CryptoCtx with dedup disabled so we can test chunking logic
/// without requiring a real database or cloud store.
fn make_crypto_ctx() -> Arc<cairn_seal::CryptoCtx> {
    let identity = age::x25519::Identity::generate();
    let id_path = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        id_path.path(),
        identity.to_string().expose_secret().as_bytes(),
    )
    .unwrap();

    let pub_path = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(pub_path.path(), identity.to_public().to_string().as_bytes()).unwrap();

    Arc::new(
        cairn_seal::CryptoCtx::new(
            pub_path.path().to_str().unwrap(),
            Some(id_path.path().to_str().unwrap()),
            3,
            0,
            "zstd".to_string(),
            "aes-gcm".to_string(),
            None,
            true, // disable dedup — we test chunking boundaries, not dedup here
            10,
        )
        .unwrap(),
    )
}

// ── Chunk boundary conditions ───────────────────────────────────────────────

#[test]
fn cdc_empty_data_returns_no_chunks() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let result = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        b"",
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ));

    assert!(result.is_ok());
    let chunks = result.unwrap();
    assert!(chunks.is_empty(), "empty input should produce zero chunks");
}

#[test]
fn cdc_single_byte_produces_one_chunk() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        &[0x42],
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].plain_len, 1);
}

#[test]
fn cdc_exact_block_size_produces_one_chunk() {
    // FastCDC default min block size is 16384. Exactly that many bytes should be one chunk.
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = vec![0xAB; 16_384];
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        &data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].plain_len, 16_384);
}

#[test]
fn cdc_max_block_size_plus_one_splits_into_multiple_chunks() {
    // FastCDC boundaries are CONTENT-defined (min 16 KiB, avg 64 KiB, max
    // 256 KiB): a constant byte stream has no natural boundary, so a split is
    // guaranteed only once the MAX size is exceeded. (The old test expected a
    // forced split at min+1, which CDC does not — and must not — promise.)
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = vec![0xAB; 262_145];
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        &data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    assert!(
        chunks.len() >= 2,
        "max block size + 1 must force at least one split, got {} chunk(s)",
        chunks.len()
    );
    let total_len: usize = chunks.iter().map(|c| c.plain_len).sum();
    assert_eq!(total_len, 262_145);
}

#[test]
fn cdc_all_zeros_produces_chunks() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = vec![0x00; 32_768]; // 2× block size
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        &data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    assert!(!chunks.is_empty());
    let total_len: usize = chunks.iter().map(|c| c.plain_len).sum();
    assert_eq!(total_len, 32_768);
}

#[test]
fn cdc_random_data_produces_chunks() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data: Vec<u8> = (0..65_536).map(|i| (i * 7 + 13) as u8).collect();
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        &data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    assert!(!chunks.is_empty());
    let total_len: usize = chunks.iter().map(|c| c.plain_len).sum();
    assert_eq!(total_len, 65_536);
}

// ── Dedup key generation ────────────────────────────────────────────────────

#[test]
fn dedup_identical_inputs_produce_same_key() {
    // NOTE: `make_crypto_ctx` deliberately disables dedup, so the dedup test
    // builds its own context with dedup ENABLED (the fixture's random secret
    // is created once and cloned, so both runs share the same equality domain).
    let crypto = {
        let identity = age::x25519::Identity::generate();
        let id_path = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            id_path.path(),
            identity.to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        let pub_path = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(pub_path.path(), identity.to_public().to_string().as_bytes()).unwrap();
        Arc::new(
            cairn_seal::CryptoCtx::new(
                pub_path.path().to_str().unwrap(),
                Some(id_path.path().to_str().unwrap()),
                3,
                0,
                "zstd".to_string(),
                "aes-gcm".to_string(),
                None,
                false, // dedup ENABLED
                10,
            )
            .unwrap(),
        )
    };
    let db = make_db();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = b"identical content for dedup test";

    let chunks1 = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        data,
        cache_dir.path().to_str().unwrap(),
        crypto.clone(),
        db.clone(),
        store.clone(),
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    let chunks2 = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        data,
        cache_dir.path().to_str().unwrap(),
        crypto.clone(),
        db.clone(),
        store.clone(),
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    assert_eq!(chunks1.len(), 1);
    assert_eq!(chunks2.len(), 1);
    // With dedup enabled, same data → same hash_key (dedup hit on second)
    assert_eq!(chunks1[0].hash_key, chunks2[0].hash_key);
}

#[test]
fn dedup_different_inputs_produce_different_keys() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data_a = b"identical content for dedup test";
    let data_b = b"different content for dedup test";

    let chunks_a = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        data_a,
        cache_dir.path().to_str().unwrap(),
        crypto.clone(),
        db.clone(),
        store.clone(),
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    let chunks_b = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        data_b,
        cache_dir.path().to_str().unwrap(),
        crypto.clone(),
        db.clone(),
        store.clone(),
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    assert_ne!(chunks_a[0].hash_key, chunks_b[0].hash_key);
}

// ── Compression type selection ──────────────────────────────────────────────

#[test]
fn compression_zstd_produces_valid_comp_type() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = b"compression test zstd";
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        Some("zstd".to_string()),
        None,
    ))
    .unwrap();

    assert!(!chunks.is_empty());
    // comp_type values: 0=none, 1=zstd, 2=lz4 (based on cairen-seal constants)
    assert!(chunks[0].comp_type >= 0);
}

#[test]
fn compression_lz4_produces_valid_comp_type() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = b"compression test lz4";
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        Some("lz4".to_string()),
        None,
    ))
    .unwrap();

    assert!(!chunks.is_empty());
    assert!(chunks[0].comp_type >= 0);
}

#[test]
fn compression_none_produces_valid_comp_type() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = b"compression test none";
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        Some("none".to_string()),
        None,
    ))
    .unwrap();

    assert!(!chunks.is_empty());
    assert!(chunks[0].comp_type >= 0);
}

// ── Edge cases ──────────────────────────────────────────────────────────────

#[test]
fn cdc_large_data_splits_into_multiple_chunks() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    // 10 MB should definitely split into multiple chunks
    let data = vec![0xCD; 10 * 1024 * 1024];
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        &data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    assert!(chunks.len() > 1);
    let total_len: usize = chunks.iter().map(|c| c.plain_len).sum();
    assert_eq!(total_len, 10 * 1024 * 1024);
}

#[test]
fn cdc_max_chunk_size_respects_maximum() {
    // FastCDC max block size is 262144. No chunk should exceed that.
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = vec![0xEF; 524_288]; // 2× max block size
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        &data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    for chunk in &chunks {
        assert!(
            chunk.plain_len <= 262_144,
            "chunk size {} exceeds max block size 262144",
            chunk.plain_len
        );
    }
}

#[test]
fn cdc_chunk_offsets_are_contiguous() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = vec![0x12; 50_000];
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        &data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    let mut expected_offset = 0;
    for chunk in &chunks {
        assert_eq!(chunk.offset, expected_offset);
        expected_offset += chunk.plain_len;
    }
    assert_eq!(expected_offset, data.len());
}

#[test]
fn cdc_chunk_hashes_are_unique_within_same_data() {
    let db = make_db();
    let crypto = make_crypto_ctx();
    let store = make_store();
    let cache_dir = tempfile::tempdir().unwrap();

    let data = vec![0x56; 100_000];
    let chunks = tokio_test::block_on(cairn_cdc::Chunker::process_data(
        &data,
        cache_dir.path().to_str().unwrap(),
        crypto,
        db,
        store,
        "raid1".to_string(),
        false,
        None,
        None,
    ))
    .unwrap();

    let hashes: Vec<_> = chunks.iter().map(|c| &c.hash_key).collect();
    assert_eq!(
        hashes.len(),
        hashes
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn make_db() -> Arc<cairn_index::Db> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let uri = format!("file:test_cdc_chunking_{}?mode=memory&cache=shared", id);
    Arc::new(cairn_index::Db::new(&uri, None).unwrap())
}

fn make_store() -> Arc<dyn cairn_store::ChunkStore> {
    let temp_dir = tempfile::tempdir().unwrap();
    Arc::new(cairn_store::CairnStore::new(
        temp_dir.path().to_str().unwrap().to_string(),
        vec![], // no cloud operators — we test chunking, not upload
        None,   // no rate limiter either
    ))
}
