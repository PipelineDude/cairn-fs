use std::ffi::OsString;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Directory,
    RegularFile,
    Symlink,
    BlockDevice,
    CharDevice,
    NamedPipe,
    Socket,
}

#[derive(Debug, Clone)]
pub struct FileAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub crtime: SystemTime,
    pub kind: FileType,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub flags: u32,
    pub blksize: u32,
}

#[derive(Debug, Clone)]
pub struct EngineReplyEntry {
    pub ttl: Duration,
    pub attr: FileAttr,
    pub generation: u64,
}

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub inode: u64,
    pub offset: i64,
    pub kind: FileType,
    pub name: OsString,
}

#[derive(Debug, Clone)]
pub struct DirectoryEntryPlus {
    pub inode: u64,
    pub generation: u64,
    pub kind: FileType,
    pub name: OsString,
    pub offset: i64,
    pub attr: FileAttr,
    pub entry_ttl: Duration,
    pub attr_ttl: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<SystemTime>,
    pub mtime: Option<SystemTime>,
    pub ctime: Option<SystemTime>,
    pub fh: Option<u64>,
}

pub fn mode_to_filetype(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFREG => FileType::RegularFile,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        libc::S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

#[derive(Debug, Clone, Default)]
pub struct Request {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}
