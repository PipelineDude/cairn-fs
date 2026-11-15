use age::secrecy::ExposeSecret;
use blahaj::{Share, Sharks};
use std::io::{Read, Write};

// Shamir split/combine uses `blahaj` — the maintained fork of `sharks` that fixed
// RUSTSEC-2024-0398 (biased polynomial coefficients). Same GF(256) scheme and API.
//
// Share file format: [1-byte threshold] ++ [share bytes]. The threshold header is
// what makes under-threshold reconstruction FAIL loudly: without it the threshold
// would have to be inferred from however many shares the user happens to pass,
// and Lagrange interpolation over too few shares silently yields a WRONG secret.

type Res = Result<(), Box<dyn std::error::Error>>;

/// every secret file (`priv.pem`, `share_*.bin`, combined output)
/// is opened with `O_NOFOLLOW` (refuse to follow a symlink an attacker
/// pre-created in the working directory) AND `O_CREAT | O_EXCL` (refuse to
/// overwrite a file the user might have placed there) AND `mode 0o600`
/// (owner-only read/write — the previous `File::create()` honoured the
/// process umask, typically 0o022 → `0o644`, world-readable private key).
#[cfg(unix)]
fn open_secret_file(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_secret_file(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// `pub.pem` holds a PUBLIC key — it is meant to be distributed and read by
/// other users/tools, so 0o600 (private-key mode) is needlessly restrictive. Use
/// 0o644, keeping the same `O_NOFOLLOW | O_EXCL` anti-clobber/anti-symlink guards.
#[cfg(unix)]
fn open_public_file(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o644)
        .open(path)
}

#[cfg(not(unix))]
fn open_public_file(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

// all logic lives in `run()` and uses `?`/`return Err(..)` — never
// `process::exit` — so Drop runs for every local on every path. This matters for the
// reconstructed master key (`recovered`, a `Zeroizing<Vec<u8>>`): the old code called
// `process::exit(1)` on the output-write error paths, which skipped Drop and left the
// key on the heap. `main` only exits the process AFTER `run()` has returned and all
// its locals (secrets included) have been dropped/zeroized.
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Res {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "split" {
        return cmd_split(&args);
    } else if args.len() > 1 && args[1] == "combine" {
        return cmd_combine(&args);
    }

    // reject unrecognized subcommands instead of silently
    // generating keys. A typo like `cairn-keys splt` would silently write
    // priv.pem/pub.pem — confusing and potentially dangerous.
    if args.len() > 1 {
        return Err(format!(
            "Unknown subcommand '{}'. Usage:\n  \
             cairn-keys split <secret_file> <M> <N>\n  \
             cairn-keys combine <out_file> <share_files...>\n  \
             cairn-keys  (generates new keypair)",
            args[1]
        )
        .into());
    }

    cmd_gen()
}

fn cmd_split(args: &[String]) -> Res {
    // split <secret_file> <M> <N>
    if args.len() < 5 {
        return Err("Usage: cairn-keys split <secret_file> <M> <N>".into());
    }
    let secret_file = &args[2];
    let threshold: u8 = args[3]
        .parse()
        .map_err(|_| "threshold must be a number 2-255")?;
    let total: u8 = args[4]
        .parse()
        .map_err(|_| "total must be a number 2-255")?;
    if threshold < 2 || total < threshold {
        return Err("need total >= threshold >= 2".into());
    }

    let mut f = std::fs::File::open(secret_file)
        .map_err(|e| format!("cannot open secret file {secret_file}: {e}"))?;
    // hold the master secret in Zeroizing so it is wiped from the heap on
    // drop — on the success path AND on any early-return error path.
    let mut secret = zeroize::Zeroizing::new(Vec::new());
    f.read_to_end(&mut secret)
        .map_err(|e| format!("cannot read secret file {secret_file}: {e}"))?;

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(total as usize).collect();
    drop(secret); // master secret no longer needed — wipe it now (Zeroizing on drop).

    for (i, share) in shares.iter().enumerate() {
        let path = format!("share_{}.bin", i + 1);
        let mut sf =
            open_secret_file(&path).map_err(|e| format!("cannot create share file {path}: {e}"))?;
        let mut bytes = vec![threshold];
        bytes.extend_from_slice(&Vec::from(share));
        sf.write_all(&bytes)
            .map_err(|e| format!("cannot write share file {path}: {e}"))?;
        // fsync — each share is part of the key; a power loss must not leave a
        // truncated share that silently fails reconstruction later.
        sf.sync_all()
            .map_err(|e| format!("cannot fsync share file {path}: {e}"))?;
    }
    println!("Split {secret_file} into {total} shares, requiring {threshold} to reconstruct.");
    Ok(())
}

fn cmd_combine(args: &[String]) -> Res {
    // combine <out_file> <share_files...>
    if args.len() < 4 {
        return Err("Usage: cairn-keys combine <out_file> <share_files...>".into());
    }
    let out_file = &args[2];
    let mut threshold: Option<u8> = None;
    let mut shares = Vec::new();
    for share_file in args.iter().skip(3) {
        let mut sf = std::fs::File::open(share_file)
            .map_err(|e| format!("cannot open share file {share_file}: {e}"))?;
        let mut bytes = Vec::new();
        sf.read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read share file {share_file}: {e}"))?;
        // a let-else keeps the guard but
        // cannot panic even if the guard is ever removed.
        let Some((head, body)) = bytes.split_first() else {
            return Err(format!("share file {share_file} is empty").into());
        };
        match threshold {
            None => threshold = Some(*head),
            Some(t) if t != *head => {
                return Err("share files disagree on the threshold — mixed share sets?".into());
            }
            _ => {}
        }
        let s = Share::try_from(body).map_err(|_| format!("corrupt share file {share_file}"))?;
        shares.push(s);
    }

    let threshold = threshold.ok_or("no share files given")?;
    // the threshold byte is read from the (untrusted) share files. Validate
    // it is >= 2 — a corrupt/tampered threshold of 0 or 1 slips past the
    // `shares.len() < threshold` check below (any count is >= 0/1) and would drive
    // `Sharks(threshold).recover` with a degenerate polynomial: a panic or, worse, a
    // silently-wrong reconstructed secret.
    if threshold < 2 {
        return Err(format!(
            "invalid threshold {threshold} in the share file header — a valid split needs \
             threshold >= 2 (corrupt or tampered share?)"
        )
        .into());
    }
    if shares.len() < threshold as usize {
        return Err(format!(
            "got {} share(s), but this secret needs {threshold} to reconstruct",
            shares.len()
        )
        .into());
    }

    // The reconstructed secret is the master key material — Zeroizing wipes it on drop
    // (every path out of `run()` runs Drop).
    let recovered = zeroize::Zeroizing::new(
        Sharks(threshold)
            .recover(&shares)
            .map_err(|e| format!("reconstruction failed: {e}"))?,
    );
    let mut f = open_secret_file(out_file)
        .map_err(|e| format!("cannot create output file {out_file} (mode 0o600 required): {e}"))?;
    f.write_all(&recovered)
        .map_err(|e| format!("cannot write output file {out_file}: {e}"))?;
    // fsync the reconstructed key file.
    f.sync_all()
        .map_err(|e| format!("cannot fsync output file {out_file}: {e}"))?;
    println!("Reconstructed secret into {out_file}");
    Ok(())
}

fn cmd_gen() -> Res {
    let secret = age::x25519::Identity::generate();
    let pubkey = secret.to_public();

    let mut priv_file = open_secret_file("priv.pem")
        .map_err(|e| format!("cannot create priv.pem (mode 0o600 required): {e}"))?;
    // hold the exposed private-key string in `Zeroizing` so the plaintext
    // copy is wiped after the write instead of lingering on the heap.
    let priv_str = zeroize::Zeroizing::new(secret.to_string().expose_secret().to_string());
    write!(priv_file, "{}", priv_str.as_str())
        .map_err(|e| format!("cannot write priv.pem: {e}"))?;
    // fsync so a power loss right after `gen_keys` cannot leave a
    // truncated/empty priv.pem (which would make every backup unrecoverable).
    priv_file
        .sync_all()
        .map_err(|e| format!("cannot fsync priv.pem: {e}"))?;

    // pub.pem is public — created 0o644 (readable), not 0o600.
    let mut pub_file =
        open_public_file("pub.pem").map_err(|e| format!("cannot create pub.pem: {e}"))?;
    write!(pub_file, "{pubkey}").map_err(|e| format!("cannot write pub.pem: {e}"))?;
    // fsync pub.pem too — a truncated public key silently breaks encryption setup.
    pub_file
        .sync_all()
        .map_err(|e| format!("cannot fsync pub.pem: {e}"))?;
    println!("Generated priv.pem and pub.pem");
    Ok(())
}
