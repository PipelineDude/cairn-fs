// L03.2: a SYNTHETIC failing backend must NOT produce a silent partial ack.
// One replica can never be written (opendal Fs rooted at a regular FILE — a
// write there is impossible for any user), the other replica (Memory) succeeds.
// The upload must retry ONLY the failed backend a bounded number of times and
// then return the honest "NOT fully redundant" error, while the good backend
// still holds the object.
#![cfg(feature = "cloud-storage")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use cairn_store::{CloudOperator, upload_chunk_impl};
use opendal::services::{Fs, Memory};
use std::time::Duration;

#[tokio::test]
async fn one_failing_backend_is_honest_partial_failure_not_silent_ack() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Good replica: in-memory opendal backend.
    let good: CloudOperator = opendal::Operator::new(Memory::default()).unwrap();

    // Bad replica: opendal Fs whose "root" is a REGULAR FILE — every opendal
    // operation on `/chunks/...` underneath it fails deterministically
    // (not a directory), regardless of which POSIX user runs the test.
    let blocked_path = temp_dir.path().join("blocked.file");
    std::fs::write(&blocked_path, b"not a directory").unwrap();
    let bad: CloudOperator =
        opendal::Operator::new(Fs::default().root(blocked_path.to_str().unwrap())).unwrap();

    let operators = vec![good.clone(), bad.clone()];
    let payload = b"L03.2 cannot-publish chunk payload".to_vec();
    let hash = blake3::hash(&payload).to_hex().to_string();
    let s3_path = format!("chunks/{hash}");

    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_arc = attempts.clone();
    let fast_backoff = move |_attempt: u32| {
        attempts_arc.fetch_add(1, Ordering::Relaxed);
        0u64 // no real sleep in the test
    };

    let result = upload_chunk_impl(
        payload.clone(),
        &hash,
        &operators,
        "raid1",
        &None,
        &fast_backoff,
    )
    .await;

    // Honest partial failure — never a silent Ok().
    let err = result.expect_err("upload with a failing replica must NOT succeed");
    assert!(
        err.to_string().contains("NOT fully redundant"),
        "error should name the partial-ack condition: {err}"
    );

    // Retries are bounded: the backoff is consulted for attempts 1..=5, then
    // the 6th round gives up. A runaway retry loop would exceed this.
    let n = attempts.load(Ordering::Relaxed);
    assert_eq!(n, 5, "bounded retry count, got {n}");

    // The GOOD replica still holds the verified object…
    let remote = good.read(&s3_path).await.unwrap().to_vec();
    assert_eq!(
        remote, payload,
        "good replica must contain the exact payload"
    );

    // …and the FAILING replica never silently looks "fine".
    let bad_read = bad.read(&s3_path).await;
    assert!(
        bad_read.is_err(),
        "failing replica must not contain the object"
    );

    // The retry counter was consulted only via the injected function: give the
    // L03.2 contract a strict lower bound too (no retries at all would also be
    // a bug — the good backend must reach consistency via retries).
    assert!(n >= 1, "the failed backend must have been retried");
    let _ = Duration::from_secs(0);
}
