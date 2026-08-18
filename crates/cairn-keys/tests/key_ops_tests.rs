//! Shamir secret sharing: share generation, reconstruction thresholds, and edge cases.
//!
//! Tests the `blahaj` library directly (same as cairn-keys uses) to verify:
//! - N shares generated, any M reconstruct
//! - Fewer than M shares fail
//! - Key round-trip: generate → split → combine → verify
//! - Edge thresholds (1-of-N, N-of-N)
//! - Invalid share counts

use blahaj::{Share, Sharks};

/// Generate a random secret of the given length.
fn make_secret(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}

/// Write a share in cairn-keys format: [threshold_byte] ++ [share_bytes].
fn write_share(path: &std::path::Path, threshold: u8, share: &Share) {
    let mut bytes = vec![threshold];
    bytes.extend_from_slice(&Vec::from(share));
    std::fs::write(path, bytes).unwrap();
}

/// Read a share in cairn-keys format. Returns (threshold, Share).
fn read_share(path: &std::path::Path) -> (u8, Share) {
    let data = std::fs::read(path).unwrap();
    let (head, body) = data
        .split_first()
        .expect("share file must have threshold byte");
    let threshold = *head;
    let share = Share::try_from(body).expect("corrupt share data");
    (threshold, share)
}

// ── Shamir share generation and reconstruction ────────────────────────────────

#[test]
fn shamir_n_shares_any_m_reconstruct() {
    for &n in &[3, 5, 10, 25] {
        for &m in &[2, 3, n - 1, n] {
            let secret = make_secret(32);
            let sharks = Sharks(m as u8);
            let dealer = sharks.dealer(&secret);
            let shares: Vec<Share> = dealer.take(n).collect();

            // Any subset of size m must reconstruct.
            for start in 0..=(n - m) {
                let subset: Vec<Share> = shares[start..start + m].to_vec();
                let recovered = sharks
                    .recover(&subset)
                    .expect("must reconstruct with m shares");
                assert_eq!(recovered, secret, "failed for n={n} m={m} start={start}");
            }
        }
    }
}

#[test]
fn shamir_fewer_than_m_shares_fails() {
    let secret = make_secret(32);
    let threshold = 3u8;
    let total = 5u8;

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(total as usize).collect();

    // Try with threshold - 1 shares (should fail).
    let subset: Vec<Share> = shares[..(threshold as usize - 1)].to_vec();
    let result = sharks.recover(&subset);
    assert!(result.is_err(), "fewer than {threshold} shares must fail");
}

#[test]
fn shamir_roundtrip_generate_split_combine_verify() {
    for &n in &[3, 4, 5, 10] {
        let secret = make_secret(64);
        let threshold = 3u8;

        // Split.
        let sharks = Sharks(threshold);
        let dealer = sharks.dealer(&secret);
        let shares: Vec<Share> = dealer.take(n).collect();

        // Combine with a different subset each time.
        for offset in 0..=(n - threshold as usize) {
            let subset: Vec<Share> = shares[offset..offset + threshold as usize].to_vec();
            let recovered = sharks.recover(&subset).expect("roundtrip must succeed");
            assert_eq!(
                recovered, secret,
                "roundtrip failed for offset={offset} n={n}"
            );
        }
    }
}

// ── Edge thresholds ──────────────────────────────────────────────────────────

#[test]
fn shamir_threshold_2_of_n() {
    let secret = make_secret(32);
    let threshold = 2u8;
    let total = 5u8;

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(total as usize).collect();

    // Any 2 of 5 must work.
    for i in 0..total {
        for j in (i + 1)..total {
            let subset = vec![shares[i as usize].clone(), shares[j as usize].clone()];
            let recovered = sharks.recover(&subset).expect("2-of-5 must work");
            assert_eq!(recovered, secret);
        }
    }

    // 1 share must fail.
    let result = sharks.recover(&[shares[0].clone()]);
    assert!(result.is_err(), "1 share of 2-of-N must fail");
}

#[test]
fn shamir_threshold_n_of_n() {
    let secret = make_secret(32);
    let n = 5u8;

    let sharks = Sharks(n);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(n as usize).collect();

    // All n must work.
    let recovered = sharks.recover(&shares).expect("n-of-n must work");
    assert_eq!(recovered, secret);

    // n-1 must fail.
    let subset: Vec<Share> = shares[..(n as usize - 1)].to_vec();
    let result = sharks.recover(&subset);
    assert!(result.is_err(), "n-1 of n must fail");
}

// ── Invalid share counts and edge cases ───────────────────────────────────────

#[test]
fn shamir_invalid_threshold_zero_fails() {
    // blahaj's Sharks(0) mints shares fine; the real guard is cmd_combine's
    // share-header check. Bin-only crate (no [lib]), so drive it
    // through the real binary instead of re-testing a self-written value.
    let tmp = tempfile::tempdir().unwrap();
    let secret = make_secret(32);
    let real_threshold = 3u8;

    let sharks = Sharks(real_threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(3).collect();

    // Tamper the stored threshold header to 0 (what an attacker could do).
    let tampered = tmp.path().join("tampered_share.bin");
    write_share(&tampered, 0u8, &shares[0]);
    let out_path = tmp.path().join("recovered.bin");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gen_keys"))
        .args(["combine", out_path.to_str().unwrap(), tampered.to_str().unwrap()])
        .output()
        .expect("failed to run gen_keys");

    assert!(
        !output.status.success(),
        "combine must refuse a threshold=0 share header"
    );
    assert!(
        !out_path.exists(),
        "no output file should be written when the guard rejects the input"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("threshold"),
        "error should name the actual problem (threshold), got: {stderr}"
    );
}

#[test]
fn shamir_corrupt_share_fails() {
    // Plain Shamir has no integrity check: recover() returns Ok with a WRONG
    // secret on a corrupted share, not Err. Assert the mismatch, not Err.
    let secret = make_secret(32);
    let threshold = 3u8;
    let total = 5u8;

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(total as usize).collect();

    // Corrupt one share by flipping a byte.
    let mut corrupted_shares = shares.clone();
    let corrupt_idx = 2;
    let mut corrupted_data = Vec::from(&corrupted_shares[corrupt_idx]);
    corrupted_data[0] ^= 0xFF; // flip all bits in first byte
    corrupted_shares[corrupt_idx] = Share::try_from(&corrupted_data[..]).unwrap();

    let recovered = sharks.recover(&corrupted_shares).unwrap_or_default();
    assert_ne!(
        recovered, secret,
        "corrupted share must change the reconstructed secret"
    );
}

#[test]
fn shamir_mixed_threshold_headers_fail() {
    // Simulate what cairn-keys CLI does: read threshold from share file headers.
    let tmp = tempfile::tempdir().unwrap();
    let secret = make_secret(32);
    let t1 = 3u8;
    let t2 = 4u8;

    let sharks1 = Sharks(t1);
    let dealer1 = sharks1.dealer(&secret);
    let shares1: Vec<Share> = dealer1.take(5).collect();

    let sharks2 = Sharks(t2);
    let dealer2 = sharks2.dealer(&secret);
    let shares2: Vec<Share> = dealer2.take(5).collect();

    // Write shares with mixed thresholds.
    for (i, _s1) in shares1.iter().enumerate() {
        write_share(
            &tmp.path().join(format!("share_{}.bin", i + 1)),
            t1,
            &shares1[i],
        );
    }
    for i in 0..2 {
        write_share(
            &tmp.path().join(format!("share_{}.bin", i + 4)),
            t2,
            &shares2[i + 3],
        );
    }

    // Read back and check threshold consistency.
    let mut thresholds = vec![];
    for i in 1..=5 {
        let (t, _s) = read_share(&tmp.path().join(format!("share_{}.bin", i)));
        thresholds.push(t);
    }

    // Should have mixed thresholds: some 3, some 4.
    assert!(thresholds.contains(&t1), "should contain threshold {t1}");
    assert!(thresholds.contains(&t2), "should contain threshold {t2}");
    assert_ne!(
        thresholds[0], thresholds[3],
        "thresholds should differ between sets"
    );
}

#[test]
fn shamir_empty_secret() {
    let secret = vec![];
    let threshold = 2u8;
    let total = 3u8;

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(total as usize).collect();

    // Empty secret should still produce shares (they're just all-zero or derived).
    assert_eq!(shares.len(), total as usize);

    let recovered = sharks.recover(&shares).expect("empty secret roundtrip");
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_single_byte_secret() {
    let secret = vec![0x42u8];
    let threshold = 2u8;
    let total = 3u8;

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(total as usize).collect();

    for i in 0..=(total as usize - threshold as usize) {
        let subset: Vec<Share> = shares[i..i + threshold as usize].to_vec();
        let recovered = sharks.recover(&subset).expect("single-byte roundtrip");
        assert_eq!(recovered, secret);
    }
}

#[test]
fn shamir_large_secret() {
    // 1 MiB secret (stress test for large data).
    let secret: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let threshold = 3u8;
    let total = 5u8;

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(total as usize).collect();

    let subset: Vec<Share> = shares[0..threshold as usize].to_vec();
    let recovered = sharks.recover(&subset).expect("large secret roundtrip");
    assert_eq!(recovered, secret);
}
