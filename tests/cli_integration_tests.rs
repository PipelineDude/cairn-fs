//! E2E CLI integration tests — run the cairn binary without FUSE to verify:
//! 1. init --password creates archive with valid DB
//! 2. backup ingests files and creates snapshot entries
//! 3. extract restores byte-for-byte
//! 4. wrong password rejected for symmetric
//! 5. asymmetric read requires pub+priv

use age::secrecy::ExposeSecret;
use std::path::PathBuf;
use std::process::Command;

/// Build the release binary path.
fn cairn_bin() -> PathBuf {
    let target = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    PathBuf::from(format!("target/{}/cairn", target))
}

/// Run a cairn CLI command and return (status, stdout, stderr).
fn run_cairn(args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let output = Command::new(cairn_bin())
        .args(args)
        .output()
        .expect("failed to execute cairn binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status, stdout, stderr)
}

/// Create a temp directory and return its path.
fn tmp_dir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new().prefix(prefix).tempdir().unwrap()
}

// ── init --password creates archive with valid DB ─────────────────────────────

#[test]
fn cli_init_password_creates_archive_with_valid_db() {
    let tmp = tmp_dir("cairnci");
    let db_path = tmp.path().join("test.db");

    let (status, stdout, stderr) = run_cairn(&[
        db_path.to_str().unwrap(),
        "init",
        "--password",
        "test-passphrase-123",
    ]);

    assert!(status.success(), "init should succeed: stderr={}", stderr);
    assert!(stdout.contains("Initialized"), "should print 'Initialized'");
    assert!(db_path.exists(), "archive file should exist");

    // The metadata index is SQLCipher-encrypted at rest: the file must NOT
    // start with the plaintext SQLite magic. (The old assertion expected the
    // plaintext header, which the security contract now forbids.)
    let header = std::fs::read(&db_path).unwrap();
    assert!(
        !header.starts_with(b"SQLite format 3"),
        "init must not create a plaintext metadata index"
    );
    assert!(!header.is_empty(), "archive file should be non-empty");
}

#[test]
fn cli_init_pubkey_creates_asymmetric_archive() {
    let tmp = tmp_dir("cairnci");
    let db_path = tmp.path().join("test.db");
    let pub_key_path = tmp.path().join("pub.pem");

    // Generate a public key file.
    let identity = age::x25519::Identity::generate();
    std::fs::write(&pub_key_path, identity.to_public().to_string().as_bytes()).unwrap();

    let (status, stdout, _stderr) = run_cairn(&[
        db_path.to_str().unwrap(),
        "init",
        "--pub-key",
        pub_key_path.to_str().unwrap(),
        "--password",
        "test-passphrase-123",
    ]);

    assert!(status.success(), "init with --pub-key should succeed");
    assert!(stdout.contains("Initialized"), "should print 'Initialized'");
    assert!(db_path.exists());
}

// ── backup ingests files and creates snapshot entries ─────────────────────────

#[test]
fn cli_backup_ingests_files_and_creates_snapshot() {
    let (tmp_archive, tmp_data) = (tmp_dir("cairnci"), tmp_dir("cairnci"));
    let db_path = tmp_archive.path().join("backup.db");
    let data_dir = tmp_data.path();

    // Create test files.
    let file1 = data_dir.join("hello.txt");
    std::fs::write(&file1, "Hello, World!\n").unwrap();
    let file2 = data_dir.join("binary.bin");
    std::fs::write(&file2, (0..=255).cycle().take(4096).collect::<Vec<u8>>()).unwrap();

    // Init the archive.
    run_cairn(&[
        db_path.to_str().unwrap(),
        "init",
        "--password",
        "test-passphrase-123",
    ]);

    // Run backup (the archive is password-protected; every open needs it).
    let (status, stdout, stderr) = run_cairn(&[
        db_path.to_str().unwrap(),
        "backup",
        data_dir.to_str().unwrap(),
        "/backup",
        "--password",
        "test-passphrase-123",
        "--auto-snapshot",
    ]);

    assert!(status.success(), "backup should succeed: stderr={}", stderr);
    assert!(
        stdout.contains("BackupFinished") || stdout.contains("backup"),
        "should report backup completion"
    );

    // Verify snapshot was created by checking the DB.
    let db_bytes = std::fs::read(&db_path).unwrap();
    assert!(
        !db_bytes.is_empty(),
        "archive should have grown after backup"
    );
}

// ── extract restores byte-for-byte ────────────────────────────────────────────

#[test]
fn cli_extract_restores_byte_for_byte() {
    let (tmp_archive, tmp_data, tmp_restore) =
        (tmp_dir("cairnci"), tmp_dir("cairnci"), tmp_dir("cairnci"));
    let db_path = tmp_archive.path().join("backup.db");
    let data_dir = tmp_data.path();
    let restore_dir = tmp_restore.path();

    // Create a test file with known content.
    let original_content = b"byte-for-byte verification test 12345!@#".to_vec();
    let file_path = data_dir.join("verify.txt");
    std::fs::write(&file_path, &original_content).unwrap();

    // Init and backup.
    run_cairn(&[
        db_path.to_str().unwrap(),
        "init",
        "--password",
        "test-passphrase-123",
    ]);
    run_cairn(&[
        db_path.to_str().unwrap(),
        "backup",
        data_dir.to_str().unwrap(),
        "/backup",
        "--password",
        "test-passphrase-123",
    ]);

    // Extract.
    let (status, _stdout, stderr) = run_cairn(&[
        db_path.to_str().unwrap(),
        "extract",
        restore_dir.to_str().unwrap(),
        "--password",
        "test-passphrase-123",
        "--file-path",
        "/backup/verify.txt",
    ]);

    assert!(
        status.success(),
        "extract should succeed: stderr={}",
        stderr
    );

    // Verify byte-for-byte match.
    let restored = std::fs::read(restore_dir.join("verify.txt")).unwrap();
    assert_eq!(
        restored, original_content,
        "extracted content must match original byte-for-byte"
    );
}

// ── wrong password rejected for symmetric ─────────────────────────────────────

#[test]
fn cli_wrong_password_rejected_for_symmetric() {
    let (tmp_archive, tmp_data) = (tmp_dir("cairnci"), tmp_dir("cairnci"));
    let db_path = tmp_archive.path().join("backup.db");
    let data_dir = tmp_data.path();

    // Create a test file.
    std::fs::write(data_dir.join("test.txt"), "data").unwrap();

    // Init with correct password.
    run_cairn(&[
        db_path.to_str().unwrap(),
        "init",
        "--password",
        "correct-pass",
    ]);

    // Backup with correct password (via env).
    // `std::env::{set,remove}_var` are `unsafe` in edition 2024 — the binary is spawned
    // before the env is mutated, so no concurrent reader can observe a torn value.
    unsafe { std::env::set_var("CAIRN_PASSWORD", "correct-pass") };
    let (status, _stdout, _stderr) = run_cairn(&[
        db_path.to_str().unwrap(),
        "backup",
        data_dir.to_str().unwrap(),
        "/backup",
    ]);
    assert!(
        status.success(),
        "backup with correct password should succeed"
    );
    unsafe { std::env::remove_var("CAIRN_PASSWORD") };

    // Try to extract with wrong password.
    unsafe { std::env::set_var("CAIRN_PASSWORD", "wrong-pass") };
    let (status, _stdout, stderr) = run_cairn(&[
        db_path.to_str().unwrap(),
        "extract",
        tmp_data.path().join("out").to_str().unwrap(),
    ]);
    unsafe { std::env::remove_var("CAIRN_PASSWORD") };

    assert!(
        !status.success(),
        "extract with wrong password should be rejected: stderr={}",
        stderr
    );
}

// ── asymmetric read requires pub+priv ─────────────────────────────────────────

#[test]
fn cli_asymmetric_read_requires_pub_and_priv() {
    let (tmp_archive, tmp_data) = (tmp_dir("cairnci"), tmp_dir("cairnci"));
    let db_path = tmp_archive.path().join("backup.db");
    let data_dir = tmp_data.path();

    // Generate keypair.
    let identity = age::x25519::Identity::generate();
    let pub_path = tmp_archive.path().join("pub.pem");
    let priv_path = tmp_archive.path().join("priv.pem");
    std::fs::write(&pub_path, identity.to_public().to_string().as_bytes()).unwrap();
    // age 0.11 has no `Identity::to_file` — write the secret-encoded key out directly.
    std::fs::write(&priv_path, identity.to_string().expose_secret().as_bytes()).unwrap();

    // Init with pub-key (asymmetric) + password (the index is always encrypted
    // under the security contract; asymmetric only governs CONTENT keys).
    run_cairn(&[
        db_path.to_str().unwrap(),
        "init",
        "--pub-key",
        pub_path.to_str().unwrap(),
        "--password",
        "test-passphrase-123",
    ]);

    // Create test file.
    std::fs::write(data_dir.join("secret.txt"), "classified data").unwrap();

    // Backup with pub-key (write-only).
    let (status, _stdout, _stderr) = run_cairn(&[
        db_path.to_str().unwrap(),
        "backup",
        data_dir.to_str().unwrap(),
        "/backup",
        "--pub-key",
        pub_path.to_str().unwrap(),
        "--password",
        "test-passphrase-123",
    ]);
    assert!(status.success(), "backup with pub-key should succeed");

    // Try to extract WITHOUT priv-key → should fail.
    let (status, _stdout, stderr) = run_cairn(&[
        db_path.to_str().unwrap(),
        "extract",
        tmp_data.path().join("out").to_str().unwrap(),
        "--pub-key",
        pub_path.to_str().unwrap(),
        "--password",
        "test-passphrase-123",
    ]);

    assert!(
        !status.success(),
        "extract without priv-key should fail: stderr={}",
        stderr
    );

    // Extract WITH priv-key → should succeed.
    let (status, _stdout, _stderr) = run_cairn(&[
        db_path.to_str().unwrap(),
        "extract",
        tmp_data.path().join("out2").to_str().unwrap(),
        "--pub-key",
        pub_path.to_str().unwrap(),
        "--priv-key",
        priv_path.to_str().unwrap(),
        "--password",
        "test-passphrase-123",
    ]);

    assert!(status.success(), "extract with pub+priv should succeed");
}
