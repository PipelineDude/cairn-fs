//! Restore operations (extracted from lib.rs 2026-08-16).

use crate::CairnEngine;

impl CairnEngine {
    pub async fn extract_all(&self, dest_dir: &str, preserve_metadata: bool) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(dest_dir).await?;

        // A single unreadable file (a lost/corrupt chunk) must NOT abort the whole
        // restore — the operator needs every OTHER file back. Failures are counted
        // and surfaced at the end (non-zero exit), like `backup`.
        let mut failures = 0u64;
        let mut stack = vec![(1u64, dest_dir.to_string())];
        // Hardlink recreation: maps an archive inode (nlink>1) to the first disk
        // path it was extracted to, so additional names for the same inode are
        // hard-linked on disk instead of written as independent copies.
        let mut hardlink_extract: std::collections::HashMap<u64, std::path::PathBuf> =
            std::collections::HashMap::new();

        while let Some((parent_ino, current_dir)) = stack.pop() {
            // a DB error while listing a directory must not silently
            // drop its whole subtree from the restore. Count it as a failure (so the
            // extract exits non-zero) and log it, while still restoring every other
            // branch — matching this function's "count and surface, never abort" rule.
            let dentries_result = tokio::task::spawn_blocking({
                let db = self.db.clone();
                let i = parent_ino;
                move || db.list_dentries(i)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?;
            if let Err(ref e) = dentries_result {
                failures += 1;
                tracing::error!(
                    "extract: list_dentries failed for dir inode {parent_ino}: {e} — subtree skipped"
                );
            }
            if let Ok(dentries) = dentries_result {
                for (name_key, name_enc, ino) in dentries {
                    // --hide-names: reconstruct the real on-disk name (falls back
                    // to the opaque hash if the private key is absent). Normal
                    // archives return the stored name unchanged. An Opaque result
                    // means this file is about to be WRITTEN TO DISK under its
                    // hash instead of its real name — count it as a failure (like
                    // every other partial-restore case here) and say so loudly,
                    // instead of the operator discovering hash-named files later.
                    let resolved_name = self.resolve_dentry_name(&name_key, name_enc.as_deref());
                    if resolved_name.is_opaque() {
                        failures += 1;
                        tracing::warn!(
                            "extract: name for dentry {name_key} could not be resolved to its \
                             real value (hide-names archive without the private key, or a \
                             corrupt name_enc blob) — writing to disk under the opaque hash name \
                             {opaque:?} instead",
                            opaque = resolved_name.as_str()
                        );
                    }
                    let name = resolved_name.into_string();
                    // match on both Ok/Err so DB errors are logged and
                    // counted instead of silently skipping the child entry.
                    let inode_result = tokio::task::spawn_blocking({
                        let db = self.db.clone();
                        let i = ino;
                        move || db.get_inode(i)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?;
                    let (mode, _uid, _gid, _size, nlink, _mtime_sec, _mtime_nsec) =
                        match inode_result {
                            Ok(Some(info)) => info,
                            Ok(None) => {
                                failures += 1;
                                tracing::error!(
                                    "extract: inode {ino} (name {name:?}) not found in DB — skipped"
                                );
                                continue;
                            }
                            Err(e) => {
                                failures += 1;
                                tracing::error!(
                                    "extract: get_inode({ino}) failed for {name:?}: {e} — skipped"
                                );
                                continue;
                            }
                        };
                    {
                        let name_path = std::path::Path::new(&name);
                        if name_path.is_absolute()
                            || name_path.components().any(|c| {
                                matches!(c, std::path::Component::ParentDir)
                                    || matches!(c, std::path::Component::CurDir)
                            })
                            || name.contains('/')
                        {
                            continue;
                        }
                        let path = std::path::Path::new(&current_dir).join(&name);

                        if mode & libc::S_IFMT == libc::S_IFDIR {
                            // Materialize the directory now: children are extracted
                            // into it, and empty directories must survive the restore.
                            // If a symlink already exists at the path, remove it so
                            // create_dir_all makes a real directory and children are
                            // not written through a redirected link.
                            if let Ok(meta) = tokio::fs::symlink_metadata(&path).await {
                                if meta.is_symlink() {
                                    let _ = tokio::fs::remove_file(&path).await;
                                }
                            }
                            tokio::fs::create_dir_all(&path).await?;
                            if preserve_metadata {
                                #[cfg(unix)]
                                {
                                    self.apply_preserved_metadata(ino, &path).await;
                                }
                            }
                            stack.push((ino, path.to_string_lossy().to_string()));
                        } else if mode & libc::S_IFMT == libc::S_IFLNK {
                            match self.read_file_all(ino).await {
                                Ok(Some(target_data)) => {
                                    let target_str = String::from_utf8_lossy(&target_data);
                                    #[cfg(unix)]
                                    let _ = tokio::fs::symlink(target_str.as_ref(), &path).await;
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    failures += 1;
                                    tracing::error!(
                                        "extract: symlink {path:?} could NOT be restored: {e}"
                                    );
                                    continue;
                                }
                            }
                            if preserve_metadata {
                                #[cfg(unix)]
                                {
                                    self.apply_preserved_metadata(ino, &path).await;
                                }
                            }
                        } else {
                            // Hardlink recreation: if this archive inode (nlink>1)
                            // was already extracted under another name, link the new
                            // name to that first path instead of writing a second
                            // independent copy — this restores the on-disk link and
                            // avoids re-decrypting the data. The shared inode already
                            // carries mode/mtime, so skip perms/preserve here.
                            if nlink > 1 {
                                if let Some(first) = hardlink_extract.get(&ino).cloned() {
                                    // Clear any stale/existing dest (re-extract case);
                                    // hard_link fails if the target already exists.
                                    let _ = tokio::fs::remove_file(&path).await;
                                    match tokio::fs::hard_link(&first, &path).await {
                                        Ok(()) => continue,
                                        Err(e) => {
                                            // Never lose the file — fall back to a copy.
                                            tracing::warn!(
                                                "extract: hard_link {path:?} -> {first:?} failed, copying: {e}"
                                            );
                                        }
                                    }
                                }
                            }
                            // Regular file: stream chunk-by-chunk to disk so a multi-GB
                            // file is never fully buffered in RAM (fix).
                            if let Err(e) = self.extract_file_to(ino, &path).await {
                                failures += 1;
                                tracing::error!("extract: {path:?} could NOT be restored: {e}");
                                continue;
                            }

                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                // keep setuid/setgid/sticky
                                // bits (0o7777, not 0o777) so a backed-up
                                // setuid binary is restored as setuid.
                                let perm = std::fs::Permissions::from_mode(mode & 0o7777);
                                let _ = tokio::fs::set_permissions(&path, perm).await;
                            }
                            if preserve_metadata {
                                #[cfg(unix)]
                                {
                                    self.apply_preserved_metadata(ino, &path).await;
                                }
                            }
                            // First name for this inode: remember it as the link
                            // target for any later name that shares the inode.
                            if nlink > 1 {
                                hardlink_extract.insert(ino, path.clone());
                            }
                        }
                    }
                }
            }
        }

        if failures > 0 {
            anyhow::bail!(
                "{failures} file(s) could NOT be restored (see the errors above); \
             all other files were extracted"
            );
        }
        Ok(())
    }

    pub async fn extract_single_file(
        &self,
        file_path: &str,
        dest_dir: &str,
        preserve_metadata: bool,
    ) -> anyhow::Result<()> {
        let mut current_ino = 1u64;
        let path = std::path::Path::new(file_path);

        for comp in path.components() {
            if let std::path::Component::Normal(name) = comp {
                let name_str = name.to_string_lossy().to_string();
                // --hide-names: resolve each path component through its lookup key.
                let name_clone = self.crypto.name_lookup_key(current_ino, &name_str)?;
                let child_ino = tokio::task::spawn_blocking({
                    let db = self.db.clone();
                    let p_ino = current_ino;
                    move || db.get_dentry_inode(p_ino, &name_clone)
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

                if let Some(ino) = child_ino {
                    current_ino = ino;
                } else {
                    anyhow::bail!("Path component '{}' not found", name_str);
                }
            }
        }

        let is_file = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let ino = current_ino;
            move || db.get_inode(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        .map(|(mode, ..)| mode & libc::S_IFMT == libc::S_IFREG)
        .unwrap_or(false);

        if !is_file {
            anyhow::bail!("Path '{}' is not a regular file", file_path);
        }

        tokio::fs::create_dir_all(dest_dir).await?;
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;
        let dest_path = std::path::Path::new(dest_dir).join(file_name);

        self.extract_file_to(current_ino, &dest_path).await?;

        if preserve_metadata {
            #[cfg(unix)]
            {
                self.apply_preserved_metadata(current_ino, &dest_path).await;
            }
        }

        Ok(())
    }

    pub async fn extract_matching(
        &self,
        pattern: &str,
        dest_dir: &str,
        preserve_metadata: bool,
    ) -> anyhow::Result<()> {
        let compiled_pattern = glob::Pattern::new(pattern)?;
        tokio::fs::create_dir_all(dest_dir).await?;

        let mut stack = vec![(1u64, String::new())];
        // Hardlink recreation (same as extract_all): archive inode (nlink>1) →
        // first extracted disk path. Only names that match the glob are linked;
        // if just one name of a group matches, it is written normally.
        let mut hardlink_extract: std::collections::HashMap<u64, std::path::PathBuf> =
            std::collections::HashMap::new();

        while let Some((parent_ino, current_vpath)) = stack.pop() {
            // a DB error listing a directory must fail the extract
            // loudly rather than silently omitting that subtree. extract_matching
            // has no per-file failure counter, so propagate the error (non-zero exit).
            let dentries_result = tokio::task::spawn_blocking({
                let db = self.db.clone();
                let i = parent_ino;
                move || db.list_dentries(i)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?;
            if let Err(e) = &dentries_result {
                return Err(anyhow::anyhow!(
                    "extract: list_dentries failed for dir inode {parent_ino}: {e}"
                ));
            }
            if let Ok(dentries) = dentries_result {
                for (name_key, name_enc, ino) in dentries {
                    // --hide-names: reconstruct the real name for glob-matching
                    // and on-disk paths (opaque hash fallback without the priv key).
                    // extract_matching has no per-file failure counter (see the
                    // comment above), so an unresolved name only gets a loud
                    // warning — same severity class as the symlink/hardlink
                    // soft-failures below, not a hard abort.
                    let resolved_name = self.resolve_dentry_name(&name_key, name_enc.as_deref());
                    if resolved_name.is_opaque() {
                        tracing::warn!(
                            "extract: name for dentry {name_key} could not be resolved to its \
                             real value — writing to disk under the opaque hash name {opaque:?} \
                             instead",
                            opaque = resolved_name.as_str()
                        );
                    }
                    let name = resolved_name.into_string();
                    // match on both Ok/Err so DB errors are logged and
                    // the function fails loudly instead of silently skipping.
                    let inode_result = tokio::task::spawn_blocking({
                        let db = self.db.clone();
                        let i = ino;
                        move || db.get_inode(i)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?;
                    let (mode, _uid, _gid, _size, nlink, _mtime_sec, _mtime_nsec) =
                        match inode_result {
                            Ok(Some(info)) => info,
                            Ok(None) => {
                                tracing::error!(
                                    "extract: inode {ino} (name {name:?}) not found in DB — skipped"
                                );
                                continue;
                            }
                            Err(e) => {
                                return Err(anyhow::anyhow!(
                                    "extract: get_inode({ino}) failed for {name:?}: {e}"
                                ));
                            }
                        };
                    {
                        let name_path = std::path::Path::new(&name);
                        if name_path.is_absolute()
                            || name_path.components().any(|c| {
                                matches!(c, std::path::Component::ParentDir)
                                    || matches!(c, std::path::Component::CurDir)
                            })
                            || name.contains('/')
                        {
                            continue;
                        }

                        let new_vpath = if current_vpath.is_empty() {
                            format!("/{}", name)
                        } else {
                            format!("{}/{}", current_vpath, name)
                        };

                        let ifmt = mode & libc::S_IFMT;
                        if ifmt == libc::S_IFDIR {
                            stack.push((ino, new_vpath));
                        } else if ifmt == libc::S_IFLNK {
                            // `extract_all` already restores
                            // symlinks; `extract_matching` used to drop them
                            // silently. A glob over a directory tree with
                            // symlinks now extracts the symlinks.
                            let relative_path = new_vpath.trim_start_matches('/');
                            let dest_link_path = std::path::Path::new(dest_dir).join(relative_path);
                            if let Some(parent) = dest_link_path.parent() {
                                tokio::fs::create_dir_all(parent).await?;
                            }
                            match self.read_file_all(ino).await {
                                Ok(Some(target_data)) => {
                                    let target_str = String::from_utf8_lossy(&target_data);
                                    #[cfg(unix)]
                                    {
                                        if let Err(e) =
                                            tokio::fs::symlink(target_str.as_ref(), &dest_link_path)
                                                .await
                                        {
                                            tracing::warn!(
                                                "extract: symlink {dest_link_path:?} -> \
                                             {target_str}: {e}"
                                            );
                                        }
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    tracing::warn!(
                                        "extract: symlink {dest_link_path:?} unreadable: {e}"
                                    );
                                }
                            }
                            if preserve_metadata {
                                #[cfg(unix)]
                                {
                                    self.apply_preserved_metadata(ino, &dest_link_path).await;
                                }
                            }
                        } else if ifmt == libc::S_IFREG
                            && (compiled_pattern.matches(&new_vpath)
                                || compiled_pattern.matches(new_vpath.trim_start_matches('/')))
                        {
                            let relative_path = new_vpath.trim_start_matches('/');
                            let dest_file_path = std::path::Path::new(dest_dir).join(relative_path);

                            if let Some(parent) = dest_file_path.parent() {
                                tokio::fs::create_dir_all(parent).await?;
                            }

                            // Hardlink recreation: link to the first extracted name
                            // sharing this inode instead of writing a second copy.
                            let mut linked = false;
                            if nlink > 1 {
                                if let Some(first) = hardlink_extract.get(&ino).cloned() {
                                    let _ = tokio::fs::remove_file(&dest_file_path).await;
                                    match tokio::fs::hard_link(&first, &dest_file_path).await {
                                        Ok(()) => linked = true,
                                        Err(e) => tracing::warn!(
                                            "extract: hard_link {dest_file_path:?} -> {first:?} failed, copying: {e}"
                                        ),
                                    }
                                }
                            }

                            if !linked {
                                self.extract_file_to(ino, &dest_file_path).await?;

                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::PermissionsExt;
                                    // keep setuid/setgid/sticky
                                    // bits (mask 0o7777, not 0o777) so a backed-up
                                    // setuid binary is restored as setuid.
                                    let perm = std::fs::Permissions::from_mode(mode & 0o7777);
                                    let _ = tokio::fs::set_permissions(&dest_file_path, perm).await;
                                }
                                if preserve_metadata {
                                    #[cfg(unix)]
                                    {
                                        self.apply_preserved_metadata(ino, &dest_file_path).await;
                                    }
                                }
                                // Remember this as the link target for later names.
                                if nlink > 1 {
                                    hardlink_extract.insert(ino, dest_file_path.clone());
                                }
                            }
                        }
                        // S_IFIFO / S_IFCHR / S_IFBLK / S_IFSOCK: the archive
                        // stores them but `extract_all` would `read_file_all`
                        // them which only makes sense for symlinks. Skip with
                        // a warning — special files cannot be round-tripped
                        // through a content-addressed chunk store reliably.
                        else if matches!(
                            ifmt,
                            libc::S_IFIFO | libc::S_IFCHR | libc::S_IFBLK | libc::S_IFSOCK
                        ) {
                            tracing::warn!(
                                "extract: skipping special file at {new_vpath} \
                             (FIFO/CHR/BLK/SOCK cannot be reliably restored)"
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn read_file_all(&self, ino: u64) -> anyhow::Result<Option<Vec<u8>>> {
        // assemble the LOGICAL content over [0, size) — chunks placed by
        // offset into a zero-filled buffer, so holes (sparse writes, truncate-
        // extend) read as zeros, exactly like the FUSE read() path. This used
        // to concatenate chunks in row order and ignore offsets: wrong bytes
        // for any non-contiguous file, short for any tail hole.
        let inode = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_inode(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        let Some(inode) = inode else {
            return Ok(None);
        };
        let size = usize::try_from(inode.3)
            .map_err(|_| anyhow::anyhow!("file size {} exceeds address space", inode.3))?;
        // `read_file_all` buffers the WHOLE file in RAM (unlike the
        // streaming `extract_file_to`). Cap it so a caller (e.g. `Vfs::read_file`)
        // cannot OOM the process on a multi-GiB regular file — stream via
        // `extract_file_to` / the FUSE `read` path for large files instead.
        const READ_FILE_ALL_MAX: usize = 256 * 1024 * 1024;
        if size > READ_FILE_ALL_MAX {
            anyhow::bail!(
                "read_file_all: file is {size} bytes (> {READ_FILE_ALL_MAX} cap) — \
             use the streaming extract/read path for large files"
            );
        }
        let mut data = vec![0u8; size];

        // check inline data first (short symlink targets stored
        // via set_inline_data), then fall back to CDC chunks.
        let inline = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_inline_data(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        if let Some(raw) = inline {
            let plain = self.unwrap_inline(&raw)?;
            let n = plain.len().min(size);
            data[..n].copy_from_slice(&plain[..n]);
            return Ok(Some(data));
        }

        let chunks = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = ino;
            move || db.get_file_chunks(i)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        let engine = self.clone();

        use futures::StreamExt;
        let mut stream = futures::stream::iter(chunks)
            .map(
                |(hash_key, offset, plain_len, wrapped_key, comp_type, cipher_algo)| {
                    let engine = engine.clone();
                    async move {
                        let cipher = engine.fetch_chunk(&hash_key).await?;
                        let crypto = engine.crypto.clone();
                        let comp_type_u8 = u8::try_from(comp_type).map_err(|_| {
                            anyhow::anyhow!("invalid comp_type for chunk {hash_key}")
                        })?;
                        let plain = tokio::task::spawn_blocking(move || {
                            crypto.decrypt_chunk_symmetric(
                                &cipher,
                                &wrapped_key,
                                comp_type_u8,
                                &cipher_algo,
                            )
                        })
                        .await
                        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
                        if plain.len() < plain_len {
                            anyhow::bail!("chunk {hash_key} shorter than recorded length");
                        }
                        Ok::<_, anyhow::Error>((offset, plain[..plain_len].to_vec()))
                    }
                },
            )
            .buffered(16);

        while let Some(res) = stream.next().await {
            let (off, plain) = res?;
            // Clamp to the recorded size: a chunk tail past EOF (shrinking
            // truncate races, straddle chunks) must not grow the logical file.
            if off >= size {
                continue;
            }
            let n = plain.len().min(size - off);
            data[off..off + n].copy_from_slice(&plain[..n]);
        }
        Ok(Some(data))
    }

    /// Stream a regular file's chunks straight to `path`, decrypting one chunk at a
    /// time and writing it to disk — never buffering the whole file in RAM (fix).
    /// Chunks arrive in offset order (`get_file_chunks` ORDER BY offset), so a plain
    /// sequential write reproduces `read_file_all`'s concatenation exactly.
    ///
    /// Security: writes are performed to a temporary file in the same directory and
    /// atomically renamed onto `path`. This eliminates the TOCTOU race where an
    /// attacker replaces `path` with a symlink between `remove_file` and `create`.
    pub async fn extract_file_to(&self, ino: u64, path: &std::path::Path) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;

        // a file flagged
        // incomplete (marker: its last backup was interrupted) is restored
        // best-effort from whatever is COMMITTED, with a loud warning, rather than
        // REFUSED. The original bail broke the cardinal backup-tool rule that a failed
        // *new* backup must never make a *prior good* version unrestorable — a failed
        // overwrite leaves the old chunks intact in the index, and bailing stranded
        // them (the old, wholly-valid version became un-extractable). `verify` remains
        // the strict gate that flags these files; `extract` hands back the recoverable
        // bytes. NOTE (data-safety tradeoff): for a LARGE file whose overwrite failed
        // mid-flush the committed state can be MIXED (some new + some old chunks); this
        // restores it with only the warning below — `verify` is what catches it.
        let incomplete = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.is_file_incomplete(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?
        .unwrap_or(false);
        if incomplete {
            tracing::warn!(
                "extract: ino {ino} is flagged incomplete (its last backup was interrupted) — \
             restoring committed data best-effort; run `verify`, and re-run `backup` to be safe"
            );
        }

        let path_buf = path.to_path_buf();
        let parent = path_buf
            .parent()
            .ok_or_else(|| anyhow::anyhow!("extract path has no parent: {path_buf:?}"))?
            .to_path_buf();

        // the extracted file must be exactly `size` bytes — a tail hole
        // (sparse write / truncate-extend) used to yield a SHORT file because
        // nothing wrote past the last chunk. `set_len(size)` below pads the
        // tail with zeros (and defensively clamps anything past EOF), matching
        // the FUSE read() view of the same inode.
        let recorded_size = tokio::task::spawn_blocking({
            let db = self.db.clone();
            move || db.get_inode(ino)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??
        .ok_or_else(|| anyhow::anyhow!("extract: inode {ino} not found"))?
        .3;

        // Create a temporary file in the destination directory. `tempfile` places it
        // on the same filesystem, so the final `persist` is an atomic rename.
        let tmp = tokio::task::spawn_blocking({
            let p = parent.clone();
            move || {
                tempfile::NamedTempFile::new_in(&p)
                    .map_err(|e| anyhow::anyhow!("failed to create temp file in {p:?}: {e}"))
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

        // propagate a DB read error rather than extracting an empty file.
        if let Some(raw_inline) = self.db.get_inline_data(ino)? {
            let inline_data = self.unwrap_inline(&raw_inline)?;
            let mut file = tokio::fs::File::from_std(tmp.as_file().try_clone()?);
            file.write_all(&inline_data).await?;
            file.set_len(recorded_size).await?;
            drop(file);
            tokio::task::spawn_blocking(move || {
                tmp.persist(&path_buf)
                    .map_err(|e| anyhow::anyhow!("failed to rename temp file to {path_buf:?}: {e}"))
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
            return Ok(());
        }

        let chunks = tokio::task::spawn_blocking({
            let db = self.db.clone();
            let i = ino;
            move || db.get_file_chunks(i)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;

        let mut file = tokio::fs::File::from_std(tmp.as_file().try_clone()?);
        let engine = self.clone();

        use futures::StreamExt;
        let mut stream = futures::stream::iter(chunks)
            .map(
                |(hash_key, offset, plain_len, wrapped_key, comp_type, cipher_algo)| {
                    let engine = engine.clone();
                    async move {
                        let cipher = engine.fetch_chunk(&hash_key).await?;
                        let crypto = engine.crypto.clone();
                        let comp_type_u8 = u8::try_from(comp_type).map_err(|_| {
                            anyhow::anyhow!("invalid comp_type for chunk {hash_key}")
                        })?;
                        let plain = tokio::task::spawn_blocking(move || {
                            crypto.decrypt_chunk_symmetric(
                                &cipher,
                                &wrapped_key,
                                comp_type_u8,
                                &cipher_algo,
                            )
                        })
                        .await
                        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
                        if plain.len() < plain_len {
                            anyhow::bail!("chunk {hash_key} shorter than recorded length");
                        }
                        Ok::<_, anyhow::Error>((offset, plain[..plain_len].to_vec()))
                    }
                },
            )
            .buffer_unordered(
                std::thread::available_parallelism().map_or(4, std::num::NonZero::get),
            );

        use tokio::io::AsyncSeekExt;
        while let Some(res) = stream.next().await {
            let (offset, data) = res?;
            let offset_u64 =
                u64::try_from(offset).map_err(|_| anyhow::anyhow!("chunk offset exceeds u64"))?;
            file.seek(std::io::SeekFrom::Start(offset_u64)).await?;
            file.write_all(&data).await?;
        }
        file.set_len(recorded_size).await?;
        drop(file);

        tokio::task::spawn_blocking(move || {
            tmp.persist(&path_buf)
                .map_err(|e| anyhow::anyhow!("failed to rename temp file to {path_buf:?}: {e}"))
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))??;
        Ok(())
    }
}
