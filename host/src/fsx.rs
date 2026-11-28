//! Filesystem steps taken through open folder handles, so nothing on the way can be swapped for a link.
//!
//! Every folder from the top down to the one written is opened one name at a time with no-follow, and checked: a
//! real folder (never a link), owned by the trusted owner (root on a real install), writable by nobody else. A
//! folder anyone else could write would let them swap the whole path. A file is written beside under a new name and
//! renamed over the old one, so a reader sees the old file or the new one, never half of one. A file that already
//! holds the same bytes, mode and owner is left alone: running the install again changes nothing. A macOS access
//! control list that lets anyone else change a trusted folder is refused like a group-writable mode, and every
//! folder and file made here has its ACL cleared, so nothing is inherited from the folder above (`acl`).

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    fchmod, fchown, fstat, fsync, mkdirat, openat, readlinkat, renameat, statat, symlinkat, unlinkat, AtFlags,
    FileType, Gid, Mode, OFlags, Uid,
};
use rustix::io::Errno;

use crate::acl::{self, Guard};
use crate::error::{errno, failed, refused, Result};
use crate::util::{hex, is_plain_name, random_bytes};

pub const DIR_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC).union(OFlags::NONBLOCK);

/// Who may own what this tool writes: `root` owns the trusted folders and records, `dev` the developer's own
/// folders and the keys their services read. On a real install `root` is uid 0; tests use their own uid for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

/// Whether a write changed anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrote {
    Changed,
    Unchanged,
}

pub fn mode_bits(st_mode: impl Into<u32>) -> u32 {
    st_mode.into() & 0o7777
}

fn check_trusted_dir(fd: &OwnedFd, what: &Path, owner: u32) -> Result<()> {
    let st = fstat(fd).map_err(|e| errno(format!("reading {}", what.display()), e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        return Err(refused(format!("{} is not a folder", what.display())));
    }
    if st.st_uid != owner {
        return Err(refused(format!("{} is owned by uid {}, not uid {owner}", what.display(), st.st_uid)));
    }
    if mode_bits(st.st_mode) & 0o022 != 0 {
        return Err(refused(format!("{} can be written by users other than its owner", what.display())));
    }
    if let Some(why) = acl::unsafe_grant(fd, Guard::Writes)? {
        return Err(refused(format!("{}: {why}", what.display())));
    }
    Ok(())
}

/// The open file is owned by `uid`, has exactly `mode`, and no ACL lets anyone else read or change it: what a
/// private key must be before it is used again.
pub fn check_secret(fd: &OwnedFd, what: &str, uid: u32, mode: u32) -> Result<()> {
    let st = fstat(fd).map_err(|e| errno(format!("reading {what}"), e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(refused(format!("{what} is not a regular file")));
    }
    if st.st_uid != uid || mode_bits(st.st_mode) != mode {
        return Err(refused(format!(
            "{what} is uid {} mode {:o}; it must be uid {uid} mode {mode:o}",
            st.st_uid,
            mode_bits(st.st_mode)
        )));
    }
    if let Some(why) = acl::unsafe_grant(fd, Guard::ReadsAndWrites)? {
        return Err(refused(format!("{what}: {why}")));
    }
    Ok(())
}

/// Opens the regular file `name` in `dir` without following a link; `None` when absent.
pub fn open_file_at(dir: &OwnedFd, name: &str) -> Result<Option<OwnedFd>> {
    match openat(dir, name, FILE_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::LOOP) => Err(refused(format!("{name} is a link; it must be a regular file"))),
        Err(e) => Err(errno(format!("opening {name}"), e)),
    }
}

/// What a walk down to a folder found.
pub enum Walk {
    /// The folder, and each folder the walk made on the way.
    Found(OwnedFd, Vec<PathBuf>),
    /// The first folder on the way that does not exist (only when nothing may be made).
    Missing(PathBuf),
}

/// Walks to the folder `path` from `top` one name at a time, each folder on the way trusted (owned by `owner`,
/// writable by nobody else, never a link). `make` creates a missing folder with that mode, owned by `owner` (the
/// caller runs as that owner); without it a missing folder ends the walk as `Missing`.
pub fn walk_trusted(path: &Path, top: &Path, owner: u32, make: Option<u32>) -> Result<Walk> {
    let rel =
        path.strip_prefix(top).map_err(|_| refused(format!("{} is not under {}", path.display(), top.display())))?;
    let mut fd =
        rustix::fs::open(top, DIR_FLAGS, Mode::empty()).map_err(|e| errno(format!("opening {}", top.display()), e))?;
    check_trusted_dir(&fd, top, owner)?;
    let mut here = top.to_path_buf();
    let mut made = Vec::new();
    for c in rel.components() {
        let Component::Normal(name) = c else {
            return Err(refused(format!("{} has a part that is not a plain name", path.display())));
        };
        here.push(name);
        let mut new = None;
        if let Some(mode) = make {
            match mkdirat(&fd, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => new = Some(mode),
                Err(Errno::EXIST) => {}
                Err(e) => return Err(errno(format!("making {}", here.display()), e)),
            }
        }
        let next = match openat(&fd, name, DIR_FLAGS, Mode::empty()) {
            Ok(next) => next,
            Err(Errno::NOENT) if make.is_none() => return Ok(Walk::Missing(here)),
            Err(Errno::LOOP | Errno::NOTDIR) => {
                return Err(refused(format!("{} is a link or not a folder; it must be a real folder", here.display())))
            }
            Err(e) => return Err(errno(format!("opening {}", here.display()), e)),
        };
        if let Some(mode) = new {
            // A folder made just now takes the mode asked for, whatever the umask removed.
            fchmod(&next, Mode::from_raw_mode(mode as rustix::fs::RawMode))
                .map_err(|e| errno(format!("setting the mode of {}", here.display()), e))?;
            acl::clear(&next)?;
            made.push(here.clone());
        }
        check_trusted_dir(&next, &here, owner)?;
        fd = next;
    }
    Ok(Walk::Found(fd, made))
}

/// A handle on the folder `path`, reached from `top` as `walk_trusted` does; a missing folder is refused by name.
pub fn open_trusted_dir(path: &Path, top: &Path, owner: u32, make: Option<u32>) -> Result<OwnedFd> {
    match walk_trusted(path, top, owner, make)? {
        Walk::Found(fd, _) => Ok(fd),
        Walk::Missing(at) => Err(refused(format!("{} does not exist", at.display()))),
    }
}

/// The developer's own folder `name` inside the trusted folder `parent`, opened without following a link, and
/// theirs alone: owned by `uid`, closed to group and others, no access control list letting anyone else change it.
/// `None` when it is not there. `what` names it in a reason.
pub fn private_dir(parent: &OwnedFd, name: &str, what: &Path, uid: u32) -> Result<Option<OwnedFd>> {
    let fd = match openat(parent, name, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP | Errno::NOTDIR) => {
            return Err(refused(format!("{} is a link or not a folder", what.display())))
        }
        Err(e) => return Err(errno(format!("opening {}", what.display()), e)),
    };
    let st = fstat(&fd).map_err(|e| errno(format!("reading {}", what.display()), e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory
        || st.st_uid != uid
        || mode_bits(st.st_mode) & 0o077 != 0
    {
        return Err(refused(format!(
            "{} is uid {} mode {:o}; it must be uid {uid} mode 700 (install sets it)",
            what.display(),
            st.st_uid,
            mode_bits(st.st_mode)
        )));
    }
    if let Some(why) = acl::unsafe_grant(&fd, Guard::Writes)? {
        return Err(refused(format!("{}: {why}", what.display())));
    }
    Ok(Some(fd))
}

/// The regular file at the absolute `path`, opened one name at a time from `/` without following a link: every
/// folder on the way and the file itself owned by root or `uid`, writable by nobody else, with no access control
/// list letting anyone else change it. For reading a developer's own file as root, so nothing on the way can be
/// swapped for something else.
pub fn open_owned_path(path: &Path, uid: u32) -> Result<OwnedFd> {
    let rel = path.strip_prefix("/").map_err(|_| refused(format!("{} is not an absolute path", path.display())))?;
    let names: Vec<&std::ffi::OsStr> = rel
        .components()
        .map(|c| match c {
            Component::Normal(n) => Ok(n),
            _ => Err(refused(format!("{} has a part that is not a plain name", path.display()))),
        })
        .collect::<Result<_>>()?;
    let (file, dirs) = names.split_last().ok_or_else(|| refused(format!("{} names no file", path.display())))?;
    let owned = |fd: &OwnedFd, at: &Path| -> Result<rustix::fs::Stat> {
        let st = fstat(fd).map_err(|e| errno(format!("reading {}", at.display()), e))?;
        if (st.st_uid != 0 && st.st_uid != uid) || mode_bits(st.st_mode) & 0o022 != 0 {
            return Err(refused(format!(
                "{} is uid {} mode {:o}: it and every folder above it must be root's or uid {uid}'s and writable by \
                 nobody else",
                at.display(),
                st.st_uid,
                mode_bits(st.st_mode)
            )));
        }
        if let Some(why) = acl::unsafe_grant(fd, Guard::Writes)? {
            return Err(refused(format!("{}: {why}", at.display())));
        }
        Ok(st)
    };
    let mut here = PathBuf::from("/");
    let mut fd = rustix::fs::open("/", DIR_FLAGS, Mode::empty()).map_err(|e| errno("opening /", e))?;
    owned(&fd, &here)?;
    for name in dirs {
        here.push(name);
        fd = openat(&fd, *name, DIR_FLAGS, Mode::empty()).map_err(|e| match e {
            Errno::LOOP | Errno::NOTDIR => refused(format!("{} is a link or not a folder", here.display())),
            e => errno(format!("opening {}", here.display()), e),
        })?;
        owned(&fd, &here)?;
    }
    here.push(file);
    let f = openat(&fd, *file, FILE_FLAGS, Mode::empty()).map_err(|e| match e {
        Errno::LOOP => refused(format!("{} is a link; it must be a regular file", here.display())),
        e => errno(format!("opening {}", here.display()), e),
    })?;
    let st = owned(&f, &here)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(refused(format!("{} is not a regular file", here.display())));
    }
    Ok(f)
}

/// The folder `name` inside the trusted folder `parent`, made if missing, with exactly `mode` and `owner`. A
/// folder that exists with another owner is refused, never taken over.
pub fn ensure_dir(parent: &OwnedFd, name: &str, mode: u32, owner: Owner, what: &str) -> Result<(OwnedFd, Wrote)> {
    if !is_plain_name(name) {
        return Err(failed(format!("{name:?} is not a plain folder name")));
    }
    let mut wrote = Wrote::Unchanged;
    match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => wrote = Wrote::Changed,
        Err(Errno::EXIST) => {}
        Err(e) => return Err(errno(format!("making {what}"), e)),
    }
    let fd = openat(parent, name, DIR_FLAGS, Mode::empty()).map_err(|e| match e {
        Errno::LOOP | Errno::NOTDIR => refused(format!("{what} is a link or not a folder; it must be a real folder")),
        e => errno(format!("opening {what}"), e),
    })?;
    let st = fstat(&fd).map_err(|e| errno(format!("reading {what}"), e))?;
    if wrote == Wrote::Changed {
        fchown(&fd, Some(Uid::from_raw(owner.uid)), Some(Gid::from_raw(owner.gid)))
            .map_err(|e| errno(format!("giving {what} to uid {}", owner.uid), e))?;
    } else if st.st_uid != owner.uid {
        return Err(refused(format!("{what} exists and is owned by uid {}, not uid {}", st.st_uid, owner.uid)));
    }
    if wrote == Wrote::Changed || mode_bits(st.st_mode) != mode {
        fchmod(&fd, Mode::from_raw_mode(mode as rustix::fs::RawMode))
            .map_err(|e| errno(format!("setting the mode of {what}"), e))?;
        wrote = Wrote::Changed;
    }
    if wrote == Wrote::Changed || acl::has_entries(&fd)? {
        acl::clear(&fd)?;
        wrote = Wrote::Changed;
    }
    Ok((fd, wrote))
}

/// The bytes of the regular file `name` in `dir`, at most `max` bytes, never through a link. `None` when absent.
pub fn read_at(dir: &OwnedFd, name: &str, max: u64) -> Result<Option<Vec<u8>>> {
    let fd = match openat(dir, name, FILE_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => return Err(refused(format!("{name} is a link; it must be a regular file"))),
        Err(e) => return Err(errno(format!("opening {name}"), e)),
    };
    read_regular(fd, name, max).map(Some)
}

/// The bytes of an open regular file, at most `max`.
pub fn read_regular(fd: OwnedFd, what: &str, max: u64) -> Result<Vec<u8>> {
    let st = fstat(&fd).map_err(|e| errno(format!("reading {what}"), e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(refused(format!("{what} is not a regular file")));
    }
    let mut out = Vec::new();
    File::from(fd).take(max + 1).read_to_end(&mut out).map_err(|e| failed(format!("reading {what}: {e}")))?;
    if out.len() as u64 > max {
        return Err(refused(format!("{what} is larger than {max} bytes")));
    }
    Ok(out)
}

/// `data` as the regular file `name` in `dir`, with `mode` and `owner`, replacing any file there atomically. A
/// link or anything not a regular file in its place is refused. Unchanged when the same bytes, mode and owner are
/// already there.
pub fn write_at(dir: &OwnedFd, name: &str, data: &[u8], mode: u32, owner: Owner) -> Result<Wrote> {
    if !is_plain_name(name) {
        return Err(failed(format!("{name:?} is not a plain file name")));
    }
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return Err(refused(format!("{name} is a link or not a regular file; it was not replaced")));
            }
            if st.st_uid == owner.uid
                && st.st_gid == owner.gid
                && mode_bits(st.st_mode) == mode
                && st.st_size as u64 == data.len() as u64
            {
                if let Some(fd) = open_file_at(dir, name)? {
                    if !acl::has_entries(&fd)? && read_regular(fd, name, data.len() as u64)? == data {
                        return Ok(Wrote::Unchanged);
                    }
                }
            }
        }
        Err(Errno::NOENT) => {}
        Err(e) => return Err(errno(format!("reading {name}"), e)),
    }
    let tmp = format!(".{name}.{}.tmp", hex(&random_bytes::<6>()?));
    let fd = openat(
        dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| errno(format!("writing {name}"), e))?;
    let result = (|| {
        // Nothing is inherited: a new file takes no ACL entry from the folder it is made in.
        acl::clear(&fd)?;
        let mut f = File::from(fd);
        f.write_all(data).map_err(|e| failed(format!("writing {name}: {e}")))?;
        fchown(f.as_fd(), Some(Uid::from_raw(owner.uid)), Some(Gid::from_raw(owner.gid)))
            .map_err(|e| errno(format!("giving {name} to uid {}", owner.uid), e))?;
        fchmod(f.as_fd(), Mode::from_raw_mode(mode as rustix::fs::RawMode))
            .map_err(|e| errno(format!("setting the mode of {name}"), e))?;
        fsync(f.as_fd()).map_err(|e| errno(format!("saving {name}"), e))?;
        renameat(dir, tmp.as_str(), dir, name).map_err(|e| errno(format!("putting {name} in place"), e))
    })();
    if result.is_err() {
        let _ = unlinkat(dir, tmp.as_str(), AtFlags::empty());
    }
    result?;
    fsync(dir).map_err(|e| errno(format!("{name} was replaced, and the disk did not confirm it is saved"), e))?;
    Ok(Wrote::Changed)
}

/// `data` as a NEW regular file `name` in `dir`, with `mode` and `owner`, never replacing anything: it is written
/// whole beside under another name, saved, and then linked into place, which fails if `name` exists by then. So a
/// reader sees no file or the whole file, and a file made meanwhile by anyone else is never overwritten.
/// `Wrote::Unchanged` when `name` already exists (it was left as it is).
pub fn create_at(dir: &OwnedFd, name: &str, data: &[u8], mode: u32, owner: Owner) -> Result<Wrote> {
    if !is_plain_name(name) {
        return Err(failed(format!("{name:?} is not a plain file name")));
    }
    let tmp = format!(".{name}.{}.tmp", hex(&random_bytes::<6>()?));
    let fd = openat(
        dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| errno(format!("writing {name}"), e))?;
    let result = (|| {
        acl::clear(&fd)?;
        let mut f = File::from(fd);
        f.write_all(data).map_err(|e| failed(format!("writing {name}: {e}")))?;
        fchown(f.as_fd(), Some(Uid::from_raw(owner.uid)), Some(Gid::from_raw(owner.gid)))
            .map_err(|e| errno(format!("giving {name} to uid {}", owner.uid), e))?;
        fchmod(f.as_fd(), Mode::from_raw_mode(mode as rustix::fs::RawMode))
            .map_err(|e| errno(format!("setting the mode of {name}"), e))?;
        fsync(f.as_fd()).map_err(|e| errno(format!("saving {name}"), e))?;
        match rustix::fs::linkat(dir, tmp.as_str(), dir, name, AtFlags::empty()) {
            Ok(()) => Ok(Wrote::Changed),
            Err(Errno::EXIST) => Ok(Wrote::Unchanged),
            Err(e) => Err(errno(format!("putting {name} in place"), e)),
        }
    })();
    let _ = unlinkat(dir, tmp.as_str(), AtFlags::empty());
    let wrote = result?;
    fsync(dir).map_err(|e| errno(format!("{name} was made, and the disk did not confirm it is saved"), e))?;
    Ok(wrote)
}

/// The link `name` in `dir` pointing at `target`, replaced atomically. Unchanged when it already points there. A
/// file or folder in its place is refused.
pub fn link_at(dir: &OwnedFd, name: &str, target: &str) -> Result<Wrote> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            if FileType::from_raw_mode(st.st_mode) != FileType::Symlink {
                return Err(refused(format!("{name} exists and is not a link; it was not replaced")));
            }
            let now = readlinkat(dir, name, Vec::new()).map_err(|e| errno(format!("reading {name}"), e))?;
            if now.as_bytes() == target.as_bytes() {
                return Ok(Wrote::Unchanged);
            }
        }
        Err(Errno::NOENT) => {}
        Err(e) => return Err(errno(format!("reading {name}"), e)),
    }
    let tmp = format!(".{name}.{}.tmp", hex(&random_bytes::<6>()?));
    symlinkat(target, dir, tmp.as_str()).map_err(|e| errno(format!("making {name}"), e))?;
    if let Err(e) = renameat(dir, tmp.as_str(), dir, name) {
        let _ = unlinkat(dir, tmp.as_str(), AtFlags::empty());
        return Err(errno(format!("putting {name} in place"), e));
    }
    fsync(dir).map_err(|e| errno(format!("{name} was replaced, and the disk did not confirm it is saved"), e))?;
    Ok(Wrote::Changed)
}

/// Whether the regular file `name` in `dir` holds `data` with `mode` and `owner` already (no change needed).
pub fn holds(dir: &OwnedFd, name: &str, data: &[u8], mode: u32, owner: Owner) -> Result<bool> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
                || st.st_uid != owner.uid
                || st.st_gid != owner.gid
                || mode_bits(st.st_mode) != mode
                || st.st_size as u64 != data.len() as u64
            {
                return Ok(false);
            }
            match open_file_at(dir, name)? {
                Some(fd) if !acl::has_entries(&fd)? => {
                    Ok(read_regular(fd, name, data.len() as u64).ok().as_deref() == Some(data))
                }
                _ => Ok(false),
            }
        }
        Err(Errno::NOENT) => Ok(false),
        Err(e) => Err(errno(format!("reading {name}"), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn me() -> Owner {
        Owner { uid: rustix::process::getuid().as_raw(), gid: rustix::process::getgid().as_raw() }
    }

    #[test]
    fn a_write_is_atomic_and_a_second_identical_write_changes_nothing() {
        let t = tempfile::tempdir().unwrap();
        let dir = open_trusted_dir(t.path(), t.path(), me().uid, None).unwrap();
        assert_eq!(write_at(&dir, "r.json", b"{}\n", 0o644, me()).unwrap(), Wrote::Changed);
        let before = std::fs::metadata(t.path().join("r.json")).unwrap();
        assert_eq!(write_at(&dir, "r.json", b"{}\n", 0o644, me()).unwrap(), Wrote::Unchanged);
        let after = std::fs::metadata(t.path().join("r.json")).unwrap();
        assert_eq!(before.ino(), after.ino(), "an unchanged record keeps its inode");
        assert_eq!(after.permissions().mode() & 0o7777, 0o644);
        assert_eq!(write_at(&dir, "r.json", b"{\"a\":1}\n", 0o644, me()).unwrap(), Wrote::Changed);
        assert_eq!(std::fs::read(t.path().join("r.json")).unwrap(), b"{\"a\":1}\n");
        assert_eq!(
            write_at(&dir, "r.json", b"{}\n", 0o644, me()).unwrap(),
            Wrote::Changed,
            "a shorter record replaces a longer one"
        );
        assert_eq!(std::fs::read(t.path().join("r.json")).unwrap(), b"{}\n");
        let leftovers: Vec<_> = std::fs::read_dir(t.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn a_create_never_replaces_what_is_there_not_even_a_link() {
        let t = tempfile::tempdir().unwrap();
        let dir = open_trusted_dir(t.path(), t.path(), me().uid, None).unwrap();
        assert_eq!(create_at(&dir, "k.pem", b"first", 0o600, me()).unwrap(), Wrote::Changed);
        assert_eq!(std::fs::metadata(t.path().join("k.pem")).unwrap().permissions().mode() & 0o7777, 0o600);
        assert_eq!(create_at(&dir, "k.pem", b"second", 0o600, me()).unwrap(), Wrote::Unchanged);
        assert_eq!(std::fs::read(t.path().join("k.pem")).unwrap(), b"first", "never overwritten");
        std::fs::write(t.path().join("theirs"), b"theirs").unwrap();
        std::os::unix::fs::symlink(t.path().join("theirs"), t.path().join("l.pem")).unwrap();
        assert_eq!(create_at(&dir, "l.pem", b"ours", 0o600, me()).unwrap(), Wrote::Unchanged);
        assert_eq!(std::fs::read(t.path().join("theirs")).unwrap(), b"theirs", "nothing written through a link");
        let names: Vec<String> =
            std::fs::read_dir(t.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
    }

    #[test]
    fn a_link_in_place_of_a_record_is_refused_and_left_alone() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("elsewhere"), b"theirs").unwrap();
        std::os::unix::fs::symlink(t.path().join("elsewhere"), t.path().join("r.json")).unwrap();
        let dir = open_trusted_dir(t.path(), t.path(), me().uid, None).unwrap();
        let e = write_at(&dir, "r.json", b"ours", 0o644, me()).unwrap_err();
        assert!(e.reason.contains("is a link or not a regular file"), "{e}");
        assert_eq!(std::fs::read(t.path().join("elsewhere")).unwrap(), b"theirs");
        assert!(read_at(&dir, "r.json", 10).is_err());
    }

    #[test]
    fn a_link_on_the_way_down_is_refused() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("real")).unwrap();
        std::os::unix::fs::symlink(t.path().join("real"), t.path().join("var")).unwrap();
        let e = open_trusted_dir(&t.path().join("var/lib"), t.path(), me().uid, Some(0o755)).unwrap_err();
        assert!(e.reason.contains("is a link or not a folder"), "{e}");
        assert!(!t.path().join("real/lib").exists(), "nothing was made through the link");
    }

    #[test]
    fn a_folder_others_can_write_is_refused() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("open")).unwrap();
        std::fs::set_permissions(t.path().join("open"), std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = open_trusted_dir(&t.path().join("open/backend"), t.path(), me().uid, Some(0o755)).unwrap_err();
        assert!(e.reason.contains("can be written by users other than its owner"), "{e}");
    }

    #[test]
    fn a_folder_owned_by_another_user_is_refused() {
        let t = tempfile::tempdir().unwrap();
        // Not root: our folders are ours, so asking for root as the owner must refuse the very first one.
        if me().uid == 0 {
            return;
        }
        let e = open_trusted_dir(t.path(), t.path(), 0, None).unwrap_err();
        assert!(e.reason.contains("not uid 0"), "{e}");
    }

    #[test]
    fn ensure_dir_sets_the_mode_and_refuses_a_link() {
        let t = tempfile::tempdir().unwrap();
        let top = open_trusted_dir(t.path(), t.path(), me().uid, None).unwrap();
        let (_, w) = ensure_dir(&top, "run", 0o700, me(), "run").unwrap();
        assert_eq!(w, Wrote::Changed);
        let m = std::fs::metadata(t.path().join("run")).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o700);
        assert_eq!(ensure_dir(&top, "run", 0o700, me(), "run").unwrap().1, Wrote::Unchanged);
        std::os::unix::fs::symlink("/tmp", t.path().join("gateway")).unwrap();
        assert!(ensure_dir(&top, "gateway", 0o700, me(), "gateway").is_err());
    }

    #[test]
    fn a_trusted_folder_whose_acl_lets_another_user_add_or_delete_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let backend = t.path().join("backend");
        std::fs::create_dir(&backend).unwrap();
        std::fs::set_permissions(&backend, std::fs::Permissions::from_mode(0o755)).unwrap();
        open_trusted_dir(&backend, t.path(), me().uid, None).unwrap();
        crate::acl::tests::plant(&backend, "everyone allow add_file,delete_child");
        let e = open_trusted_dir(&backend, t.path(), me().uid, None).unwrap_err();
        assert!(e.reason.contains("access control list"), "{e}");
    }

    #[test]
    fn a_record_with_an_acl_is_rewritten_clean_and_a_new_file_inherits_nothing() {
        let t = tempfile::tempdir().unwrap();
        let dir = open_trusted_dir(t.path(), t.path(), me().uid, None).unwrap();
        write_at(&dir, "r.json", b"{}\n", 0o644, me()).unwrap();
        crate::acl::tests::plant(&t.path().join("r.json"), "everyone allow write");
        assert!(!holds(&dir, "r.json", b"{}\n", 0o644, me()).unwrap(), "a check sees the ACL as a change");
        assert_eq!(write_at(&dir, "r.json", b"{}\n", 0o644, me()).unwrap(), Wrote::Changed);
        let f = std::fs::File::open(t.path().join("r.json")).unwrap();
        assert!(!crate::acl::has_entries(&f).unwrap(), "the same bytes, and no ACL any more");
        // A folder whose ACL hands read to everyone on everything made in it (no write, so it is still trusted).
        crate::acl::tests::plant(t.path(), "everyone allow read,file_inherit,directory_inherit");
        let dir = open_trusted_dir(t.path(), t.path(), me().uid, None).unwrap();
        write_at(&dir, "ca.key", b"secret", 0o600, me()).unwrap();
        let k = std::fs::File::open(t.path().join("ca.key")).unwrap();
        assert!(!crate::acl::has_entries(&k).unwrap(), "a new key inherits no read grant");
        let (sub, _) = ensure_dir(&dir, "tls", 0o755, me(), "tls").unwrap();
        assert!(!crate::acl::has_entries(&sub).unwrap(), "a new folder inherits nothing either");
    }

    #[test]
    fn a_secret_must_be_its_owners_alone() {
        let t = tempfile::tempdir().unwrap();
        let dir = open_trusted_dir(t.path(), t.path(), me().uid, None).unwrap();
        write_at(&dir, "ca.key", b"k", 0o600, me()).unwrap();
        check_secret(&open_file_at(&dir, "ca.key").unwrap().unwrap(), "ca.key", me().uid, 0o600).unwrap();
        std::fs::set_permissions(t.path().join("ca.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_secret(&open_file_at(&dir, "ca.key").unwrap().unwrap(), "ca.key", me().uid, 0o600).is_err());
        std::fs::set_permissions(t.path().join("ca.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
        crate::acl::tests::plant(&t.path().join("ca.key"), "everyone allow read");
        let e = check_secret(&open_file_at(&dir, "ca.key").unwrap().unwrap(), "ca.key", me().uid, 0o600).unwrap_err();
        assert!(e.reason.contains("read or change"), "{e}");
    }

    #[test]
    fn link_at_points_and_repoints_atomically() {
        let t = tempfile::tempdir().unwrap();
        let top = open_trusted_dir(t.path(), t.path(), me().uid, None).unwrap();
        assert_eq!(link_at(&top, "current", "releases/a").unwrap(), Wrote::Changed);
        assert_eq!(link_at(&top, "current", "releases/a").unwrap(), Wrote::Unchanged);
        assert_eq!(link_at(&top, "current", "releases/b").unwrap(), Wrote::Changed);
        assert_eq!(std::fs::read_link(t.path().join("current")).unwrap(), Path::new("releases/b"));
        std::fs::write(t.path().join("file"), b"x").unwrap();
        assert!(link_at(&top, "file", "releases/b").is_err());
    }
}
