//! Cloud index-restore manifest (extracted from lib.rs 2026-08-16:
//! cairn-core split into focused modules).

/// One encrypted index chunk listed in the cloud manifest.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ManifestChunk {
    pub hash: String,
    pub wrapped_key: Vec<u8>,
    pub comp_type: u8,
    pub cipher_algo: String,
}

/// A serialized list of chunks that make up the encrypted index database.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub chunks: Vec<ManifestChunk>,
}

/// Re-assemble the encrypted index database from cloud chunks (the mirror of
/// the cloud index backup written at `sync_index_to_cloud`). Downloads the
/// `.enc` manifest, decrypts it, fetches each chunk and concatenates the
/// result into `archive_path`.
#[cfg(feature = "cloud-storage")]
pub async fn restore_index_from_cloud(
    operators: &[cairn_store::CloudOperator],
    crypto: &cairn_seal::CryptoCtx,
    archive_path: &str,
    cache_dir: &str,
    raid_mode: &str,
) -> anyhow::Result<()> {
    if operators.is_empty() {
        return Err(anyhow::anyhow!("No cloud operators configured for restore"));
    }

    tracing::info!("Downloading index database backup from S3...");
    let s3_path = "meta/archive.db.enc";

    // Try to read from the first operator that succeeds
    let mut data = None;
    for op in operators {
        match op.read(s3_path).await {
            Ok(d) => {
                data = Some(d);
                break;
            }
            // don't silently skip a failing backend — "first success wins"
            // is fine, but a steadily-degrading backend must not be invisible.
            Err(e) => tracing::warn!(
                "restore_index_from_cloud: a backend read failed, trying the next: {e}"
            ),
        }
    }

    let data = data
        .ok_or_else(|| anyhow::anyhow!("Failed to download index backup from any S3 operator"))?;
    let data = data.to_vec();

    if data.len() < 4 {
        return Err(anyhow::anyhow!("Downloaded index backup is too small"));
    }

    let wk_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + wk_len + 2 {
        return Err(anyhow::anyhow!(
            "Downloaded index backup is corrupted (invalid key length)"
        ));
    }

    let wrapped_key = &data[2..2 + wk_len];
    let comp_type = data[2 + wk_len];
    let algo_len = data[2 + wk_len + 1] as usize;

    if data.len() < 2 + wk_len + 2 + algo_len {
        return Err(anyhow::anyhow!(
            "Downloaded index backup is corrupted (invalid algo length)"
        ));
    }

    let algo_bytes = &data[2 + wk_len + 2..2 + wk_len + 2 + algo_len];
    let cipher_algo = String::from_utf8(algo_bytes.to_vec())
        .map_err(|_| anyhow::anyhow!("Invalid cipher algo in backup"))?;

    let ciphertext = &data[2 + wk_len + 2 + algo_len..];

    tracing::info!("Decrypting index database manifest...");
    let manifest_bytes = crypto
        .decrypt_chunk_symmetric(ciphertext, wrapped_key, comp_type, &cipher_algo)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt index backup: {e}"))?;

    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse index manifest: {e}"))?;

    use cairn_store::ChunkStore;
    let store = cairn_store::CairnStore::new(cache_dir.to_string(), operators.to_vec(), None);

    let mut db_bytes = Vec::new();
    for chunk in manifest.chunks {
        let cipher = store
            .fetch_chunk(&chunk.hash, raid_mode, false, false, false)
            .await?;
        let dec = crypto
            .decrypt_chunk_symmetric(
                &cipher,
                &chunk.wrapped_key,
                chunk.comp_type,
                &chunk.cipher_algo,
            )
            .map_err(|e| anyhow::anyhow!("Failed to decrypt index chunk {}: {}", chunk.hash, e))?;
        db_bytes.extend_from_slice(&dec);
    }

    std::fs::write(archive_path, db_bytes)?;
    tracing::info!("Successfully restored index database to {}", archive_path);

    Ok(())
}
