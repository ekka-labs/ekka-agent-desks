//! Filesystem steps taken through open folder handles, so nothing on the way can be swapped for a link.
//!
//! Every folder from the top down to the one written is opened one name at a time with no-follow, and checked: a
//! real folder (never a link), owned by the trusted owner (root on a real install), writable by nobody else. A
//! folder anyone else could write would let them swap the whole path. A file is written beside under a new name and
//! renamed over the old one, so a reader sees the old file or the new one, never half of one. A file that already
//! holds the same bytes, mode and owner is left alone: running the install again changes nothing.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    fchmod, fchown, fstat, fsync, mkdirat, openat, readlinkat, renameat, statat, symlinkat, unlinkat, AtFlags,
    FileType, Gid, Mode, OFlags, Uid,
};
use rustix::io::Errno;

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
    Ok(())
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
                if let Some(old) = read_at(dir, name, data.len() as u64)? {
                    if old == data {
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
            Ok(read_at(dir, name, data.len() as u64).ok().flatten().as_deref() == Some(data))
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
