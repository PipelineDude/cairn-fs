//! Thin fuse3 adapter for the Cairn filesystem.
#![cfg(target_os = "linux")]

use fuse3::raw::prelude::*;
use fuse3::raw::{Filesystem, Request};
use fuse3::{Errno, Result, Timestamp};
use std::ffi::OsStr;

fn map_err(e: std::io::Error) -> Errno {
    if let Some(code) = e.raw_os_error() {
        Errno::from(code)
    } else {
        Errno::from(libc::EIO)
    }
}

fn map_time(t: std::time::SystemTime) -> Timestamp {
    let d = t
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::new(d.as_secs() as i64, d.subsec_nanos())
}

fn map_attr(attr: cairn_core::types::FileAttr) -> FileAttr {
    FileAttr {
        ino: attr.ino,
        size: attr.size,
        blocks: attr.blocks,
        atime: map_time(attr.atime),
        mtime: map_time(attr.mtime),
        ctime: map_time(attr.ctime),
        kind: match attr.kind {
            cairn_core::types::FileType::Directory => fuse3::FileType::Directory,
            cairn_core::types::FileType::RegularFile => fuse3::FileType::RegularFile,
            cairn_core::types::FileType::Symlink => fuse3::FileType::Symlink,
            cairn_core::types::FileType::BlockDevice => fuse3::FileType::BlockDevice,
            cairn_core::types::FileType::CharDevice => fuse3::FileType::CharDevice,
            cairn_core::types::FileType::NamedPipe => fuse3::FileType::NamedPipe,
            cairn_core::types::FileType::Socket => fuse3::FileType::Socket,
        },
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        blksize: attr.blksize,
    }
}

const fn map_req(req: &Request) -> cairn_core::types::Request {
    cairn_core::types::Request {
        uid: req.uid,
        gid: req.gid,
        pid: req.pid,
    }
}

#[derive(Clone)]
pub struct CairnFs(pub cairn_core::CairnEngine);

impl Filesystem for CairnFs {
    type DirEntryStream<'a>
        = futures::stream::Iter<std::vec::IntoIter<Result<DirectoryEntry>>>
    where
        Self: 'a;
    type DirEntryPlusStream<'a>
        = futures::stream::Iter<std::vec::IntoIter<Result<DirectoryEntryPlus>>>
    where
        Self: 'a;

    async fn init(&self, req: Request) -> Result<ReplyInit> {
        let max_write = self.0.init(map_req(&req)).await.map_err(map_err)?;
        let max_write =
            std::num::NonZeroU32::new(max_write).unwrap_or(cairn_core::DEFAULT_MAX_WRITE_NZ);
        Ok(ReplyInit { max_write })
    }

    async fn lookup(&self, req: Request, parent: u64, name: &OsStr) -> Result<ReplyEntry> {
        let entry = self
            .0
            .lookup(map_req(&req), parent, name)
            .await
            .map_err(map_err)?;
        Ok(ReplyEntry {
            ttl: entry.ttl,
            attr: map_attr(entry.attr),
            generation: entry.generation,
        })
    }

    async fn getattr(
        &self,
        req: Request,
        ino: u64,
        fh: Option<u64>,
        flags: u32,
    ) -> Result<ReplyAttr> {
        let attr = self
            .0
            .getattr(map_req(&req), ino, fh, flags)
            .await
            .map_err(map_err)?;
        Ok(ReplyAttr {
            ttl: std::time::Duration::from_secs(1),
            attr: map_attr(attr),
        })
    }

    async fn read(
        &self,
        req: Request,
        ino: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        let data = self
            .0
            .read(map_req(&req), ino, fh, offset, size)
            .await
            .map_err(map_err)?;
        Ok(ReplyData { data: data.into() })
    }

    async fn write(
        &self,
        req: Request,
        ino: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
        write_flags: u32,
        flags: u32,
    ) -> Result<ReplyWrite> {
        let written = self
            .0
            .write(map_req(&req), ino, fh, offset, data, write_flags, flags)
            .await
            .map_err(map_err)?;
        Ok(ReplyWrite { written })
    }

    async fn readdir(
        &self,
        req: Request,
        ino: u64,
        fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<Self::DirEntryStream<'_>>> {
        let entries = self
            .0
            .readdir(map_req(&req), ino, fh, offset)
            .await
            .map_err(map_err)?;
        let mapped = entries
            .into_iter()
            .map(|e| {
                Ok(DirectoryEntry {
                    inode: e.inode,
                    offset: e.offset,
                    kind: match e.kind {
                        cairn_core::types::FileType::Directory => fuse3::FileType::Directory,
                        cairn_core::types::FileType::RegularFile => fuse3::FileType::RegularFile,
                        cairn_core::types::FileType::Symlink => fuse3::FileType::Symlink,
                        cairn_core::types::FileType::BlockDevice => fuse3::FileType::BlockDevice,
                        cairn_core::types::FileType::CharDevice => fuse3::FileType::CharDevice,
                        cairn_core::types::FileType::NamedPipe => fuse3::FileType::NamedPipe,
                        cairn_core::types::FileType::Socket => fuse3::FileType::Socket,
                    },
                    name: e.name,
                })
            })
            .collect::<Vec<_>>();
        Ok(ReplyDirectory {
            entries: futures::stream::iter(mapped),
        })
    }

    async fn readdirplus(
        &self,
        req: Request,
        parent: u64,
        fh: u64,
        offset: u64,
        lock_owner: u64,
    ) -> Result<ReplyDirectoryPlus<Self::DirEntryPlusStream<'_>>> {
        let entries = self
            .0
            .readdirplus(map_req(&req), parent, fh, offset, lock_owner)
            .await
            .map_err(map_err)?;
        let mapped = entries
            .into_iter()
            .map(|e| {
                Ok(DirectoryEntryPlus {
                    inode: e.inode,
                    generation: e.generation,
                    kind: match e.kind {
                        cairn_core::types::FileType::Directory => fuse3::FileType::Directory,
                        cairn_core::types::FileType::RegularFile => fuse3::FileType::RegularFile,
                        cairn_core::types::FileType::Symlink => fuse3::FileType::Symlink,
                        cairn_core::types::FileType::BlockDevice => fuse3::FileType::BlockDevice,
                        cairn_core::types::FileType::CharDevice => fuse3::FileType::CharDevice,
                        cairn_core::types::FileType::NamedPipe => fuse3::FileType::NamedPipe,
                        cairn_core::types::FileType::Socket => fuse3::FileType::Socket,
                    },
                    name: e.name,
                    offset: e.offset,
                    attr: map_attr(e.attr),
                    entry_ttl: e.entry_ttl,
                    attr_ttl: e.attr_ttl,
                })
            })
            .collect::<Vec<_>>();
        Ok(ReplyDirectoryPlus {
            entries: futures::stream::iter(mapped),
        })
    }

    async fn mkdir(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<ReplyEntry> {
        let entry = self
            .0
            .mkdir(map_req(&req), parent, name, mode, umask)
            .await
            .map_err(map_err)?;
        Ok(ReplyEntry {
            ttl: entry.ttl,
            attr: map_attr(entry.attr),
            generation: entry.generation,
        })
    }

    async fn mknod(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        rdev: u32,
    ) -> Result<ReplyEntry> {
        let entry = self
            .0
            .mknod(map_req(&req), parent, name, mode, rdev)
            .await
            .map_err(map_err)?;
        Ok(ReplyEntry {
            ttl: entry.ttl,
            attr: map_attr(entry.attr),
            generation: entry.generation,
        })
    }

    async fn unlink(&self, req: Request, parent: u64, name: &OsStr) -> Result<()> {
        self.0
            .unlink(map_req(&req), parent, name)
            .await
            .map_err(map_err)
    }

    async fn rmdir(&self, req: Request, parent: u64, name: &OsStr) -> Result<()> {
        self.0
            .rmdir(map_req(&req), parent, name)
            .await
            .map_err(map_err)
    }

    async fn rename(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
    ) -> Result<()> {
        self.0
            .rename(map_req(&req), parent, name, newparent, newname)
            .await
            .map_err(map_err)
    }

    async fn link(
        &self,
        req: Request,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
    ) -> Result<ReplyEntry> {
        let entry = self
            .0
            .link(map_req(&req), ino, newparent, newname)
            .await
            .map_err(map_err)?;
        Ok(ReplyEntry {
            ttl: entry.ttl,
            attr: map_attr(entry.attr),
            generation: entry.generation,
        })
    }

    async fn symlink(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        link: &OsStr,
    ) -> Result<ReplyEntry> {
        let entry = self
            .0
            .symlink(map_req(&req), parent, name, link)
            .await
            .map_err(map_err)?;
        Ok(ReplyEntry {
            ttl: entry.ttl,
            attr: map_attr(entry.attr),
            generation: entry.generation,
        })
    }

    async fn readlink(&self, req: Request, ino: u64) -> Result<ReplyData> {
        let data = self.0.readlink(map_req(&req), ino).await.map_err(map_err)?;
        Ok(ReplyData { data: data.into() })
    }

    async fn setattr(
        &self,
        req: Request,
        ino: u64,
        fh: Option<u64>,
        set_attr: SetAttr,
    ) -> Result<ReplyAttr> {
        // pass through atime/mtime from the kernel.
        // Previously discarded (set to None), making `touch` over FUSE
        // mounts silently no-op. ctime is always set by the kernel, not
        // by userspace, so we leave it as None. Convert fuse3::Timestamp
        // to SystemTime for the engine.
        let convert_ts = |t: Option<Timestamp>| -> Option<std::time::SystemTime> {
            t.map(|ts| std::time::UNIX_EPOCH + std::time::Duration::new(ts.sec as u64, ts.nsec))
        };
        let neutral_set_attr = cairn_core::types::SetAttr {
            mode: set_attr.mode,
            uid: set_attr.uid,
            gid: set_attr.gid,
            size: set_attr.size,
            atime: convert_ts(set_attr.atime),
            mtime: convert_ts(set_attr.mtime),
            ctime: None,
            fh: None,
        };
        let attr = self
            .0
            .setattr(map_req(&req), ino, fh, neutral_set_attr)
            .await
            .map_err(map_err)?;
        Ok(ReplyAttr {
            ttl: std::time::Duration::from_secs(1),
            attr: map_attr(attr),
        })
    }

    async fn open(&self, req: Request, ino: u64, flags: u32) -> Result<ReplyOpen> {
        let (fh, flags_out) = self
            .0
            .open(map_req(&req), ino, flags)
            .await
            .map_err(map_err)?;
        Ok(ReplyOpen {
            fh,
            flags: flags_out,
        })
    }

    // `statfs` so `df`/`stat -f` on the mount show real numbers.
    async fn statfs(&self, req: Request, _inode: u64) -> Result<ReplyStatFs> {
        let s = self.0.statfs(map_req(&req)).await.map_err(map_err)?;
        Ok(ReplyStatFs {
            blocks: s.blocks,
            bfree: s.bfree,
            bavail: s.bavail,
            files: s.files,
            ffree: s.ffree,
            bsize: s.bsize,
            namelen: s.namelen,
            frsize: s.frsize,
        })
    }

    // `create` fuses mknod+open into one round-trip for O_CREAT opens.
    async fn create(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<ReplyCreated> {
        let (entry, fh, flags_out) = self
            .0
            .create(map_req(&req), parent, name, mode, flags)
            .await
            .map_err(map_err)?;
        Ok(ReplyCreated {
            ttl: entry.ttl,
            attr: map_attr(entry.attr),
            generation: entry.generation,
            fh,
            flags: flags_out,
        })
    }

    async fn release(
        &self,
        req: Request,
        ino: u64,
        fh: u64,
        flags: u32,
        lock_owner: u64,
        flush: bool,
    ) -> Result<()> {
        self.0
            .release(map_req(&req), ino, fh, flags, lock_owner, flush)
            .await
            .map_err(map_err)
    }

    async fn fsync(&self, req: Request, ino: u64, fh: u64, datasync: bool) -> Result<()> {
        self.0
            .fsync(map_req(&req), ino, fh, datasync)
            .await
            .map_err(map_err)
    }

    async fn fallocate(
        &self,
        req: Request,
        ino: u64,
        fh: u64,
        offset: u64,
        length: u64,
        mode: u32,
    ) -> Result<()> {
        self.0
            .fallocate(map_req(&req), ino, fh, offset, length, mode)
            .await
            .map_err(map_err)
    }

    async fn copy_file_range(
        &self,
        req: Request,
        inode_in: u64,
        fh_in: u64,
        offset_in: u64,
        inode_out: u64,
        fh_out: u64,
        offset_out: u64,
        length: u64,
        flags: u64,
    ) -> Result<ReplyCopyFileRange> {
        let copied = self
            .0
            .copy_file_range(
                map_req(&req),
                inode_in,
                fh_in,
                offset_in,
                inode_out,
                fh_out,
                offset_out,
                length,
                flags,
            )
            .await
            .map_err(map_err)?;
        Ok(ReplyCopyFileRange { copied })
    }

    async fn setxattr(
        &self,
        req: Request,
        inode: u64,
        name: &OsStr,
        value: &[u8],
        flags: u32,
        position: u32,
    ) -> Result<()> {
        self.0
            .setxattr(map_req(&req), inode, name, value, flags, position)
            .await
            .map_err(map_err)
    }

    async fn getxattr(
        &self,
        req: Request,
        ino: u64,
        name: &OsStr,
        size: u32,
    ) -> Result<ReplyXAttr> {
        // always wrap in `ReplyXAttr::Data`. The engine
        // returns 8 bytes of `fuse_getxattr_out` (size + padding) when
        // `size == 0` and the actual value otherwise; the kernel retries
        // with the right size on the first response. This is a fuse3 0.8.1
        // workaround — on a newer fuse3 we'd use `ReplyXAttr::Size` for
        // `size == 0` and `ReplyXAttr::Data` otherwise. The cairn-fuse
        // tests deliberately ignore the return (size==0 path is the one
        // we can't validate without a live mount).
        let data = self
            .0
            .getxattr(map_req(&req), ino, name, size)
            .await
            .map_err(map_err)?;
        Ok(ReplyXAttr::Data(data.into()))
    }

    async fn listxattr(&self, req: Request, ino: u64, size: u32) -> Result<ReplyXAttr> {
        let data = self
            .0
            .listxattr(map_req(&req), ino, size)
            .await
            .map_err(map_err)?;
        Ok(ReplyXAttr::Data(data.into()))
    }

    async fn removexattr(&self, req: Request, ino: u64, name: &OsStr) -> Result<()> {
        self.0
            .removexattr(map_req(&req), ino, name)
            .await
            .map_err(map_err)
    }

    async fn destroy(&self, req: Request) {
        self.0.destroy(map_req(&req)).await;
    }
}

#[cfg(test)]
mod tests;
