//! Preflight security regressions. No FUSE mount or external service required.
use age::secrecy::ExposeSecret;
use std::path::Path;
use std::process::{Command, Output};

const PASSWORD: &str = "preflight-test-password";

fn cli(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cairn"))
        .current_dir(dir)
        .env_remove("CAIRN_PASSWORD")
        .env_remove("CAIRN_SHARED_DEDUP_SECRET")
        .env("CAIRN_KDF_ITER", "1000")
        .args(["archive.db", "--password", PASSWORD, "--pub-key", "pub.pem"])
        .args(args)
        .output()
        .expect("run cairn")
}

fn succeeded(output: Output) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "cairn failed: {text}");
    text
}

/// tracing writes to STDOUT, anyhow errors to STDERR — match against both.
fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn archive() -> (tempfile::TempDir, age::x25519::Identity) {
    let dir = tempfile::tempdir().unwrap();
    let key = age::x25519::Identity::generate();
    std::fs::write(dir.path().join("pub.pem"), key.to_public().to_string()).unwrap();
    succeeded(cli(dir.path(), &["init"]));
    (dir, key)
}

fn db(dir: &Path) -> cairn_index::Db {
    cairn_index::Db::new_with_tuning(
        dir.join("archive.db").to_str().unwrap(),
        Some(&secrecy::SecretString::from(PASSWORD)),
        &cairn_index::DbTuning {
            kdf_iter: 1000,
            min_idle: 0,
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn pubkey_only_backend_survives_repeated_opens() {
    let (dir, key) = archive();
    let uri = format!("fs://{}", dir.path().join("remote").display());
    std::fs::write(dir.path().join("priv.pem"), key.to_string().expose_secret()).unwrap();
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "raid", "add", &uri],
    ));
    std::fs::remove_file(dir.path().join("priv.pem")).unwrap();
    for _ in 0..3 {
        let text = succeeded(cli(dir.path(), &["status"]));
        assert!(!text.contains("could not decrypt backend"), "{text}");
    }
    // Metadata credentials must be usable by the password-holding writer;
    // content envelopes must not be imposed on the backend configuration.
    assert_eq!(db(dir.path()).list_backends().unwrap()[0].1, uri);
}

#[test]
fn unreadable_backend_envelope_is_an_error() {
    let (dir, _) = archive();
    db(dir.path()).insert_backend("ENC:v1:not-hex").unwrap();
    let out = cli(dir.path(), &["status"]);
    assert!(!out.status.success(), "must not silently disable a backend");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("backend URI"), "{text}");
    assert!(!text.contains("not-hex"), "must not echo the stored URI");
}

#[test]
fn invalid_or_unsupported_backend_uri_is_an_error() {
    for uri in [
        "not-a-uri",
        "ftp://test-access:test-secret@example.invalid/bucket",
    ] {
        let (dir, _) = archive();
        db(dir.path()).insert_backend(uri).unwrap();
        let out = cli(dir.path(), &["status"]);
        assert!(!out.status.success(), "must not ignore backend {uri}");
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(!text.contains("test-secret"), "must not echo credentials");
    }
}

#[test]
fn legacy_backend_is_recovered_once_then_works_pubkey_only() {
    let (dir, key) = archive();
    let uri = format!("fs://{}", dir.path().join("legacy-remote").display());
    let crypto = cairn_seal::CryptoCtx::new(
        dir.path().join("pub.pem").to_str().unwrap(),
        None,
        3,
        0,
        "none".into(),
        "aes-256-gcm".into(),
        None,
        false,
        64,
    )
    .unwrap();
    let legacy = format!(
        "ENC:v1:{}",
        hex::encode(crypto.encrypt_blob(uri.as_bytes()).unwrap())
    );
    db(dir.path()).insert_backend(&legacy).unwrap();

    let out = cli(dir.path(), &["status"]);
    assert!(
        !out.status.success(),
        "legacy backend must require explicit recovery"
    );
    assert_eq!(db(dir.path()).list_backends().unwrap()[0].1, legacy);

    std::fs::write(dir.path().join("priv.pem"), key.to_string().expose_secret()).unwrap();
    succeeded(cli(dir.path(), &["--priv-key", "priv.pem", "status"]));
    std::fs::remove_file(dir.path().join("priv.pem")).unwrap();
    succeeded(cli(dir.path(), &["status"]));
    assert_eq!(db(dir.path()).list_backends().unwrap()[0].1, uri);
}

#[test]
fn raid_add_does_not_echo_backend_credentials() {
    let (dir, key) = archive();
    std::fs::write(dir.path().join("priv.pem"), key.to_string().expose_secret()).unwrap();
    let text = succeeded(cli(
        dir.path(),
        &[
            "--priv-key",
            "priv.pem",
            "raid",
            "add",
            "s3://test-access:test-secret@example.invalid/bucket",
        ],
    ));
    assert!(!text.contains("test-access"), "must not echo access key");
    assert!(!text.contains("test-secret"), "must not echo secret key");
}

#[test]
fn legacy_symmetric_backend_is_recovered() {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cairn"))
            .current_dir(dir.path())
            .env_remove("CAIRN_PASSWORD")
            .env_remove("CAIRN_SHARED_DEDUP_SECRET")
            .env("CAIRN_KDF_ITER", "1000")
            .args(["archive.db", "--password", PASSWORD])
            .args(args)
            .output()
            .unwrap()
    };
    succeeded(run(&["init"]));
    let database = db(dir.path());
    let wrapped_kek = hex::decode(database.get_config("wrapped_kek").unwrap().unwrap()).unwrap();
    let crypto = cairn_seal::CryptoCtx::new_symmetric(
        3,
        0,
        "none".into(),
        "aes-256-gcm".into(),
        None,
        false,
        64,
        secrecy::SecretString::from(PASSWORD),
        Some(wrapped_kek),
    )
    .unwrap();
    let uri = format!("fs://{}", dir.path().join("symmetric-remote").display());
    database
        .insert_backend(&format!(
            "ENC:v1:{}",
            hex::encode(crypto.encrypt_blob(uri.as_bytes()).unwrap())
        ))
        .unwrap();
    drop(database);
    succeeded(run(&["status"]));
    succeeded(run(&["status"]));
    assert_eq!(db(dir.path()).list_backends().unwrap()[0].1, uri);
}

#[test]
fn pubkey_only_backup_replaces_changed_files() {
    use rand::RngCore;

    let (dir, key) = archive();
    std::fs::create_dir(dir.path().join("source")).unwrap();
    let file = dir.path().join("source/data.bin");
    // Inline files bypass the chunk writer; their digest must still be stored
    // so a write-only host can create snapshots.
    std::fs::write(dir.path().join("source/tiny.txt"), b"small canary").unwrap();

    // First version stays inline; the second grows past the inline threshold,
    // so a reused inode would have to read and decrypt the old blob.
    std::fs::write(&file, vec![b'a'; 1000]).unwrap();
    succeeded(cli(dir.path(), &["backup", "source", "/data"]));

    let mut medium = vec![0u8; 600_000];
    rand::rngs::OsRng.fill_bytes(&mut medium);
    std::fs::write(&file, &medium).unwrap();
    succeeded(cli(dir.path(), &["backup", "source", "/data"]));

    // Third version overwrites an existing chunked file: without dropping the
    // old chunks first, flush_range performs a decrypting read-modify-write.
    let mut large = vec![0u8; 700_000];
    rand::rngs::OsRng.fill_bytes(&mut large);
    std::fs::write(&file, &large).unwrap();
    succeeded(cli(dir.path(), &["backup", "source", "/data"]));

    // Snapshot creation authenticates the tree using the stored digests only;
    // it must work without the private key.
    succeeded(cli(
        dir.path(),
        &["snapshot", "create", "write-only-snapshot"],
    ));

    // The digest accumulated from plaintext must equal the digest recomputed
    // from stored chunks, or verify would reject the file.
    std::fs::write(dir.path().join("priv.pem"), key.to_string().expose_secret()).unwrap();
    let text = succeeded(cli(
        dir.path(),
        &[
            "--priv-key",
            "priv.pem",
            "verify",
            "--expect-min-files",
            "2",
        ],
    ));
    assert!(text.contains("2 file(s) restorable"), "{text}");
    assert!(text.contains("0 NOT restorable"), "{text}");
}

#[test]
fn pubkey_only_backup_spans_write_buffer_flushes() {
    let (dir, key) = archive();
    std::fs::create_dir(dir.path().join("source")).unwrap();
    // Larger than the 16 MiB per-inode write buffer, so flush_range runs in the
    // middle of the source stream and the incremental digest must continue
    // across flushes without ever decrypting stored chunks.
    let payload: Vec<u8> = (0..17 * 1024 * 1024u64)
        .map(|i| (i.wrapping_mul(31) % 251) as u8)
        .collect();
    std::fs::write(dir.path().join("source/big.bin"), &payload).unwrap();
    succeeded(cli(dir.path(), &["backup", "source", "/data"]));

    std::fs::write(dir.path().join("priv.pem"), key.to_string().expose_secret()).unwrap();
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "extract", "restored"],
    ));
    assert_eq!(
        std::fs::read(dir.path().join("restored/data/big.bin")).unwrap(),
        payload
    );
}

#[test]
fn pubkey_only_hide_names_backup_and_rewrite() {
    use rand::RngCore;

    let dir = tempfile::tempdir().unwrap();
    let key = age::x25519::Identity::generate();
    std::fs::write(dir.path().join("pub.pem"), key.to_public().to_string()).unwrap();
    succeeded(cli(dir.path(), &["init", "--hide-names"]));
    std::fs::create_dir(dir.path().join("source")).unwrap();
    let file = dir.path().join("source/secret name.txt");

    let mut first = vec![0u8; 600_000];
    rand::rngs::OsRng.fill_bytes(&mut first);
    std::fs::write(&file, &first).unwrap();
    succeeded(cli(dir.path(), &["backup", "source", "/data"]));

    let mut second = vec![0u8; 620_000];
    rand::rngs::OsRng.fill_bytes(&mut second);
    std::fs::write(&file, &second).unwrap();
    succeeded(cli(dir.path(), &["backup", "source", "/data"]));

    std::fs::write(dir.path().join("priv.pem"), key.to_string().expose_secret()).unwrap();
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "extract", "restored"],
    ));
    assert_eq!(
        std::fs::read(dir.path().join("restored/data/secret name.txt")).unwrap(),
        second
    );
}

#[test]
fn pubkey_only_disable_dedup_backup_and_rewrite() {
    use rand::RngCore;

    let dir = tempfile::tempdir().unwrap();
    let key = age::x25519::Identity::generate();
    std::fs::write(dir.path().join("pub.pem"), key.to_public().to_string()).unwrap();
    succeeded(cli(dir.path(), &["init", "--disable-dedup"]));
    std::fs::create_dir(dir.path().join("source")).unwrap();
    let file = dir.path().join("source/data.bin");

    let mut first = vec![0u8; 600_000];
    rand::rngs::OsRng.fill_bytes(&mut first);
    std::fs::write(&file, &first).unwrap();
    succeeded(cli(dir.path(), &["backup", "source", "/data"]));

    let mut second = vec![0u8; 640_000];
    rand::rngs::OsRng.fill_bytes(&mut second);
    std::fs::write(&file, &second).unwrap();
    succeeded(cli(dir.path(), &["backup", "source", "/data"]));

    std::fs::write(dir.path().join("priv.pem"), key.to_string().expose_secret()).unwrap();
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "extract", "restored"],
    ));
    assert_eq!(
        std::fs::read(dir.path().join("restored/data/data.bin")).unwrap(),
        second
    );
}

#[cfg(feature = "cloud-storage")]
#[test]
fn pubkey_only_cloud_backup_restores_after_cache_loss() {
    use rand::RngCore;

    let (dir, key) = archive();
    let uri = format!("fs://{}", dir.path().join("remote").display());
    std::fs::write(dir.path().join("priv.pem"), key.to_string().expose_secret()).unwrap();
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "raid", "add", &uri],
    ));
    std::fs::remove_file(dir.path().join("priv.pem")).unwrap();
    std::fs::create_dir(dir.path().join("source")).unwrap();
    let mut payload = vec![0u8; 600_000];
    rand::rngs::OsRng.fill_bytes(&mut payload);
    std::fs::write(dir.path().join("source/large.bin"), &payload).unwrap();
    succeeded(cli(dir.path(), &["backup", "source", "/data"]));
    // This is a separate process: the former automatic migration made the
    // backend unreadable here unless the private content key was supplied.
    succeeded(cli(dir.path(), &["push"]));
    std::fs::remove_dir_all(dir.path().join("archive.db_cache")).unwrap();
    std::fs::write(dir.path().join("priv.pem"), key.to_string().expose_secret()).unwrap();
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "extract", "restored"],
    ));
}

#[cfg(feature = "cloud-storage")]
#[test]
fn cloud_pull_refuses_replayed_older_index() {
    let (dir, key) = archive();
    let uri = format!("fs://{}", dir.path().join("remote").display());
    write_priv(dir.path(), &key);
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "raid", "add", &uri],
    ));

    // v1
    std::fs::create_dir(dir.path().join("src1")).unwrap();
    std::fs::write(dir.path().join("src1/f.txt"), b"v1-data").unwrap();
    succeeded(cli(dir.path(), &["backup", "src1", "/data"]));
    succeeded(cli(dir.path(), &["push"]));
    let cloud_obj = dir.path().join("remote/meta/archive.db.enc");
    assert!(cloud_obj.exists(), "push must publish meta/archive.db.enc");
    let v1_blob = std::fs::read(&cloud_obj).unwrap();

    // v2
    std::fs::create_dir(dir.path().join("src2")).unwrap();
    std::fs::write(dir.path().join("src2/g.txt"), b"v2-data").unwrap();
    succeeded(cli(dir.path(), &["backup", "src2", "/data"]));
    succeeded(cli(dir.path(), &["push"]));

    // accept v2 on this host (sidecar now holds v2's revision)
    succeeded(cli(dir.path(), &["--priv-key", "priv.pem", "pull"]));

    // replay: overwrite the cloud object with the older v1 blob
    std::fs::write(&cloud_obj, &v1_blob).unwrap();
    let out = cli(dir.path(), &["--priv-key", "priv.pem", "pull"]);
    assert!(
        !out.status.success(),
        "pull must refuse a replayed older index"
    );
    let text = output_text(&out);
    assert!(
        text.contains("Refusing to pull an older index") || text.contains("older index"),
        "{text}"
    );

    // live index must be intact (not overwritten/truncated)
    succeeded(cli(dir.path(), &["--priv-key", "priv.pem", "verify"]));
}

#[cfg(feature = "cloud-storage")]
#[test]
fn cloud_pull_first_pull_echoes_revision() {
    let (dir, key) = archive();
    let uri = format!("fs://{}", dir.path().join("remote").display());
    write_priv(dir.path(), &key);
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "raid", "add", &uri],
    ));
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/f.txt"), b"hello").unwrap();
    succeeded(cli(dir.path(), &["backup", "src", "/data"]));
    succeeded(cli(dir.path(), &["push"]));

    // remove sidecar to simulate first pull on a fresh host
    let sidecar = dir.path().join("archive.db.push-revision");
    let _ = std::fs::remove_file(&sidecar);

    let out = cli(dir.path(), &["--priv-key", "priv.pem", "pull"]);
    assert!(
        out.status.success(),
        "first pull must succeed: {}",
        output_text(&out)
    );
    let text = output_text(&out);
    assert!(
        text.contains("Pulled index revision"),
        "pull must announce the revision: {text}"
    );
}

#[cfg(feature = "cloud-storage")]
#[test]
fn cloud_pull_refuses_unwritable_sidecar() {
    let (dir, key) = archive();
    let uri = format!("fs://{}", dir.path().join("remote").display());
    write_priv(dir.path(), &key);
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "raid", "add", &uri],
    ));
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/f.txt"), b"hello").unwrap();
    succeeded(cli(dir.path(), &["backup", "src", "/data"]));
    succeeded(cli(dir.path(), &["push"]));

    let _sidecar = dir.path().join("archive.db.push-revision");
    // ensure it exists (from push? no — push doesn't write sidecar; pull does).
    // First pull creates it.
    succeeded(cli(dir.path(), &["--priv-key", "priv.pem", "pull"]));

    // make the archive directory unwritable so the anchor (temp file +
    // rename) cannot be created — this is the failure mode the atomic
    // write introduces (a chmod 000 on the sidecar file itself does not
    // block rename on Unix).
    let dir_path = dir.path().to_path_buf();
    use std::os::unix::fs::PermissionsExt;
    let orig_mode = std::fs::metadata(&dir_path).unwrap().permissions().mode();
    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o555)).unwrap();
    let out = cli(dir.path(), &["--priv-key", "priv.pem", "pull"]);
    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(orig_mode)).unwrap();
    assert!(
        !out.status.success(),
        "pull must fail when the freshness anchor cannot be written: {}",
        output_text(&out)
    );
}

#[test]
fn fs_backend_root_with_traversal_is_refused() {
    let (dir, key) = archive();
    write_priv(dir.path(), &key);
    succeeded(cli(
        dir.path(),
        &["--priv-key", "priv.pem", "raid", "add", "fs:///etc/../etc"],
    ));
    std::fs::remove_file(dir.path().join("priv.pem")).unwrap();
    // The stored URI is accepted by `raid add` (it only validates syntax);
    // the traversal check fires when a host actually opens the backend.
    let out = cli(dir.path(), &["status"]);
    assert!(
        !out.status.success(),
        "traversing fs:// root must be refused"
    );
    let text = output_text(&out);
    assert!(
        text.contains("traversal") || text.contains("Refused"),
        "{text}"
    );
}

#[test]
fn index_backup_copy_is_owner_only() {
    let (dir, _key) = archive();
    let dest = dir.path().join("backupdir");
    std::fs::create_dir_all(&dest).unwrap();
    succeeded(cli(dir.path(), &["index-backup", dest.to_str().unwrap()]));
    for entry in std::fs::read_dir(&dest).unwrap() {
        let meta = entry.unwrap().metadata().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o600,
                "index-backup copy must be owner-only"
            );
        }
    }
}

// ── Round 6 (2026-11-12): master-key gates, scrub false alarm / under-report, ──
// ── inline H09, extract destination safety, unsafe dentry names              ──

/// A chunked archive (inline storage disabled) so backups produce real chunk
/// objects — needed for scrub coverage.
fn chunked_archive() -> (tempfile::TempDir, age::x25519::Identity) {
    let dir = tempfile::tempdir().unwrap();
    let key = age::x25519::Identity::generate();
    std::fs::write(dir.path().join("pub.pem"), key.to_public().to_string()).unwrap();
    succeeded(cli(dir.path(), &["init", "--inline-max-size", "0"]));
    (dir, key)
}

fn write_priv(dir: &Path, key: &age::x25519::Identity) {
    std::fs::write(dir.join("priv.pem"), key.to_string().expose_secret()).unwrap();
}

fn backup_payload(dir: &Path, bytes: usize) {
    std::fs::create_dir(dir.join("source")).unwrap();
    std::fs::write(dir.join("source/canary.bin"), vec![7u8; bytes]).unwrap();
    succeeded(cli(dir, &["backup", "source", "/data"]));
}

#[test]
fn master_key_gates_reject_fake_and_foreign_keys() {
    let (dir, key) = archive();
    // Fake path: the old presence-only gate let ANY --priv-key ARGUMENT through
    // and executed the command before the key was ever parsed.
    let out = cli(
        dir.path(),
        &[
            "--priv-key",
            "does-not-exist.pem",
            "raid",
            "set-mode",
            "raid1",
        ],
    );
    assert!(
        !out.status.success(),
        "fake --priv-key path must be refused"
    );

    // N1: plain `raid add` is now master-key gated on asymmetric archives
    // (topology ratchet / endpoint injection DoS).
    let out = cli(dir.path(), &["raid", "add", "fs:///tmp/whatever"]);
    assert!(
        !out.status.success(),
        "plain raid add on an asymmetric archive must be refused"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires the master (private) key"));
    let out = cli(
        dir.path(),
        &["--priv-key", "does-not-exist.pem", "append-only"],
    );
    assert!(
        !out.status.success(),
        "fake --priv-key path must be refused"
    );

    // Foreign key: a VALID age key belonging to another archive — refused.
    let foreign = age::x25519::Identity::generate();
    std::fs::write(
        dir.path().join("foreign.pem"),
        foreign.to_string().expose_secret(),
    )
    .unwrap();
    let out = cli(dir.path(), &["--priv-key", "foreign.pem", "append-only"]);
    assert!(!out.status.success(), "foreign master key must be refused");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does not match this archive's recipient")
    );

    // Positive control: the archive's own master key is accepted.
    write_priv(dir.path(), &key);
    succeeded(cli(dir.path(), &["--priv-key", "priv.pem", "append-only"]));
    assert_eq!(
        db(dir.path()).get_config("append_only").unwrap().as_deref(),
        Some("true")
    );
}

#[test]
fn scrub_is_green_on_healthy_asymmetric_chunked_archive() {
    let (dir, key) = chunked_archive();
    backup_payload(dir.path(), 20_000);
    write_priv(dir.path(), &key);
    // The CSK02-only shape check flagged EVERY healthy chunk of an asymmetric
    // archive (age-wrapped records are ~370 bytes, not 119) as
    // "(hash mismatch)". A healthy archive must exit 0.
    succeeded(cli(dir.path(), &["--priv-key", "priv.pem", "scrub"]));
}

#[test]
fn scrub_fails_loudly_on_dangling_chunk_reference() {
    let (dir, key) = chunked_archive();
    backup_payload(dir.path(), 20_000);
    let d = db(dir.path());
    let (ino, size) = d.list_regular_files().unwrap()[0];
    // Replace the whole chunk list with a single bogus reference. This now
    // goes through replace_file_chunks, which VALIDATES every object_id
    // against chunk_index (F-02 mirror guard) — a legitimate writer can no
    // longer create a dangling ref, so simulate a tampered DB with a raw
    // insert (same shape as the gc regression suite's helper).
    d.pool
        .get()
        .unwrap()
        .execute(
            "DELETE FROM file_chunks WHERE inode = ?1",
            rusqlite::params![ino as i64],
        )
        .unwrap();
    d.pool
        .get()
        .unwrap()
        .execute(
            "INSERT INTO file_chunks (inode, offset, object_id, plain_len, comp_type) VALUES (?1, 0, 'bogus-object-not-in-chunk-index', ?2, 0)",
            rusqlite::params![ino as i64, size as i64],
        )
        .unwrap();
    write_priv(dir.path(), &key);
    let out = cli(dir.path(), &["--priv-key", "priv.pem", "scrub"]);
    assert!(
        !out.status.success(),
        "scrub must fail on a chunk referenced without a chunk-index record: {}",
        output_text(&out)
    );
    assert!(output_text(&out).contains("no chunk-index record"));
}

/// SH-9b: two archives must not share one cache dir — cairn sweeps are
/// index-scoped and would delete each other's blobs. The ownership marker
/// refuses loudly; `--allow-shared-cache` is the documented override.
#[test]
fn shared_cache_dir_between_two_archives_is_refused_with_override() {
    let dir = tempfile::tempdir().unwrap();
    let run = |archive: &str, extra: &[&str]| -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_cairn"))
            .current_dir(dir.path())
            .env_remove("CAIRN_PASSWORD")
            .env_remove("CAIRN_SHARED_DEDUP_SECRET")
            .env("CAIRN_KDF_ITER", "1000")
            .args([archive])
            .args(["--password", PASSWORD, "--cache-dir", "onecache"])
            .args(extra)
            .output()
            .expect("run cairn")
    };
    succeeded(run("a.db", &["init"]));
    let out = run("b.db", &["init"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "second archive must be refused in a foreign cache dir: {text}"
    );
    assert!(text.contains("already owned"), "{text}");
    // The escape hatch works when the operator insists.
    let out2 = run("b.db", &["init", "--allow-shared-cache"]);
    assert!(
        out2.status.success(),
        "{}",
        String::from_utf8_lossy(&out2.stderr)
    );
}

#[test]
fn verify_catches_tampered_inline_file_digest() {
    let (dir, key) = archive();
    backup_payload(dir.path(), 100);
    write_priv(dir.path(), &key);
    succeeded(cli(dir.path(), &["--priv-key", "priv.pem", "verify"]));

    // Zero the stored H09 digest of the inline file: verify used to return
    // early for inline files and PASS.
    let d = db(dir.path());
    let (ino, _) = d.list_regular_files().unwrap()[0];
    d.set_file_digest(ino, &[0u8; 32]).unwrap();
    let out = cli(dir.path(), &["--priv-key", "priv.pem", "verify"]);
    assert!(
        !out.status.success(),
        "verify must catch a tampered inline digest: {}",
        output_text(&out)
    );
    assert!(output_text(&out).contains("digest mismatch"));
}

#[test]
fn failed_extract_preserves_pre_existing_destination_file() {
    let (dir, key) = archive();
    backup_payload(dir.path(), 100);
    let d = db(dir.path());
    let (ino, _) = d.list_regular_files().unwrap()[0];
    d.set_file_digest(ino, &[0u8; 32]).unwrap();
    write_priv(dir.path(), &key);

    std::fs::create_dir_all(dir.path().join("out/data")).unwrap();
    std::fs::write(
        dir.path().join("out/data/canary.bin"),
        b"PRE-EXISTING-GOOD-FILE",
    )
    .unwrap();
    let out = cli(dir.path(), &["--priv-key", "priv.pem", "extract", "out"]);
    assert!(
        !out.status.success(),
        "extract must fail on a digest mismatch"
    );
    assert_eq!(
        std::fs::read(dir.path().join("out/data/canary.bin")).unwrap(),
        b"PRE-EXISTING-GOOD-FILE",
        "a failed extract must not delete/overwrite the pre-existing destination"
    );
}

#[test]
fn extract_fails_loudly_on_unsafe_dentry_name() {
    let (dir, key) = archive();
    backup_payload(dir.path(), 100);
    // Tamper a dentry name into a path-traversal string. Silently omitting it
    // used to let `extract` exit 0 while restoring NOTHING.
    let d = db(dir.path());
    let (_, _, data_ino) = d
        .list_dentries(1)
        .unwrap()
        .into_iter()
        .find(|(name, _, _)| name == "data")
        .unwrap();
    d.atomic_rename(data_ino, "canary.bin", data_ino, "../escaped.bin", None)
        .unwrap();
    write_priv(dir.path(), &key);

    let out = cli(dir.path(), &["--priv-key", "priv.pem", "extract", "out"]);
    assert!(
        !out.status.success(),
        "unsafe dentry names must fail the extract: {}",
        output_text(&out)
    );
    assert!(output_text(&out).contains("unsafe dentry name"));
    assert!(!dir.path().join("out/escaped.bin").exists());
    assert!(!dir.path().join("out/data/escaped.bin").exists());
}

// ── Round 7: fault injection, pool exhaustion, fsync skip ─────────────────

#[test]
fn corrupt_db_fails_verify_not_panic() {
    let (dir, key) = archive();
    backup_payload(dir.path(), 100);
    write_priv(dir.path(), &key);
    // Corrupt the DB file
    let db_path = dir.path().join("archive.db");
    let mut data = std::fs::read(&db_path).unwrap();
    if data.len() > 100 {
        for b in data.iter_mut().take(100) {
            *b ^= 0xFF;
        }
    }
    std::fs::write(&db_path, &data).unwrap();
    let out = cli(dir.path(), &["--priv-key", "priv.pem", "verify"]);
    // Must fail, not panic (exit code != 0, no crash)
    assert!(!out.status.success(), "corrupt DB must fail verify");
}

#[test]
fn fsync_skip_backup_completes_and_verifies() {
    let (dir, key) = archive();
    backup_payload(dir.path(), 100);
    write_priv(dir.path(), &key);
    // Re-backup with --no-fsync into a fresh archive
    let (dir2, key2) = archive();
    write_priv(dir2.path(), &key2);
    let src = dir2.path().join("source");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("canary.bin"), vec![7u8; 100]).unwrap();
    succeeded(cli(
        dir2.path(),
        &[
            "--priv-key",
            "priv.pem",
            "backup",
            "source",
            "/data",
            "--no-fsync",
        ],
    ));
    succeeded(cli(dir2.path(), &["--priv-key", "priv.pem", "verify"]));
}

#[test]
fn pool_size_one_no_deadlock() {
    let (dir, key) = archive();
    backup_payload(dir.path(), 100);
    write_priv(dir.path(), &key);
    // Set env for pool size 1 — run verify concurrently with backup
    let out = Command::new(env!("CARGO_BIN_EXE_cairn"))
        .current_dir(dir.path())
        .env("CAIRN_DB_POOL_SIZE", "1")
        .env("CAIRN_KDF_ITER", "1000")
        .env_remove("CAIRN_PASSWORD")
        .env_remove("CAIRN_SHARED_DEDUP_SECRET")
        .args([
            "archive.db",
            "--password",
            PASSWORD,
            "--pub-key",
            "pub.pem",
            "--priv-key",
            "priv.pem",
            "verify",
        ])
        .output()
        .expect("run cairn");
    assert!(
        out.status.success(),
        "verify must succeed with pool size 1: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
