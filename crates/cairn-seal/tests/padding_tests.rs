// Test for the padding-alignment fix.
//
// When plaintext length is already a multiple of 4096, the ciphertext must
// NOT contain an extra 4096 bytes of dead padding.

use cairn_seal::CryptoCtx;
use tempfile::TempDir;

fn make_ctx() -> (CryptoCtx, TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let pub_path = tmp.path().join("pub.pem");
    let priv_path = tmp.path().join("priv.pem");

    use age::secrecy::ExposeSecret;
    let identity = age::x25519::Identity::generate();
    let priv_key_val = identity.to_string().expose_secret().to_string();
    let pub_key_str = identity.to_public().to_string();
    std::fs::write(&pub_path, &pub_key_str).unwrap();
    std::fs::write(&priv_path, &priv_key_val).unwrap();

    let ctx = CryptoCtx::new(
        pub_path.to_str().unwrap(),
        Some(priv_path.to_str().unwrap()),
        3, // comp_level
        0, // comp_min_ratio (no compression for small inputs)
        "zstd".to_string(),
        "chacha20".to_string(),
        None, // no dedup_secret
        true, // disable_dedup (random nonce)
        1024, // comp_min_size
    )
    .unwrap();
    (ctx, tmp)
}

/// Plaintext that is exactly 4096 bytes — the padding must add 0 extra bytes
/// (just the 4-byte orig_len trailer), not a full 4096-byte block.
#[test]
fn t045_aligned_input_no_extra_padding() {
    let (ctx, _tmp) = make_ctx();
    // 4096-byte input (aligned to 4096)
    let plaintext = vec![0xABu8; 4096];

    let sealed = ctx.seal_chunk(&plaintext, Some("none")).unwrap();
    let ciphertext = sealed.ciphertext;

    // ciphertext = nonce(12) + encrypted(padded_data + trailer(4)) + tag(16)
    // padded_data = plaintext + pad_len
    // encrypted_payload_len = ciphertext.len() - 12 - 16
    // data_plus_pad = encrypted_payload_len - 4

    let nonce_len = 12;
    let tag_len = 16;
    let trailer_len = 4;
    let encrypted_payload_len = ciphertext.len() - nonce_len - tag_len;
    let data_plus_pad = encrypted_payload_len - trailer_len;

    // For 4096-byte input: data_plus_pad should be 4096 (no padding)
    assert_eq!(
        data_plus_pad,
        4096,
        "aligned 4096-byte input should have 0 padding bytes, got {} extra",
        data_plus_pad - 4096
    );
}

/// Plaintext that is NOT aligned — padding must round up to next 4096 boundary.
#[test]
fn t045_unaligned_input_correct_padding() {
    let (ctx, _tmp) = make_ctx();
    // 100-byte input — should be padded to 4096
    let plaintext = vec![0xCDu8; 100];

    let sealed = ctx.seal_chunk(&plaintext, Some("none")).unwrap();
    let ciphertext = sealed.ciphertext;

    let nonce_len = 12;
    let tag_len = 16;
    let trailer_len = 4;
    let encrypted_payload_len = ciphertext.len() - nonce_len - tag_len;
    let data_plus_pad = encrypted_payload_len - trailer_len;

    // 100 bytes + padding to reach 4096 boundary = 4096
    assert_eq!(
        data_plus_pad, 4096,
        "100-byte input should pad to 4096, got {data_plus_pad}"
    );
}

/// 8192-byte input (2× aligned) — must have 0 extra padding.
#[test]
fn t045_double_aligned_no_extra_padding() {
    let (ctx, _tmp) = make_ctx();
    let plaintext = vec![0xEFu8; 8192];

    let sealed = ctx.seal_chunk(&plaintext, Some("none")).unwrap();
    let ciphertext = sealed.ciphertext;

    let nonce_len = 12;
    let tag_len = 16;
    let trailer_len = 4;
    let encrypted_payload_len = ciphertext.len() - nonce_len - tag_len;
    let data_plus_pad = encrypted_payload_len - trailer_len;

    assert_eq!(
        data_plus_pad,
        8192,
        "8192-byte input should have 0 padding, got {} extra",
        data_plus_pad - 8192
    );
}
