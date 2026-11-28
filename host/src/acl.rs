//! macOS access control lists on what this tool trusts and writes.
//!
//! A folder owned by root with mode 0755 can still let another user add, delete or rename its entries through an
//! extended ACL, and a key file with mode 0600 can still be readable through one. So owner and mode are not enough:
//! every trusted folder and file is also refused when an ACL entry lets anyone but root write it (or, for a secret,
//! read it), and everything this tool creates gets its ACL cleared, so nothing is inherited from the folder above.

use std::os::fd::AsFd;

use crate::error::{failed, refused, Result};

/// What an ACL must not grant to anyone but root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// Writing, adding, deleting, renaming, or changing attributes, security or owner.
    Writes,
    /// All of that, and reading: for a private key.
    ReadsAndWrites,
}

#[cfg(target_os = "macos")]
mod sys {
    use std::os::raw::{c_int, c_void};

    pub type Acl = *mut c_void;
    pub type Entry = *mut c_void;
    pub type Permset = *mut c_void;

    pub const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    pub const ACL_FIRST_ENTRY: c_int = 0;
    pub const ACL_NEXT_ENTRY: c_int = -1;
    pub const ACL_EXTENDED_ALLOW: c_int = 1;
    pub const ID_TYPE_UID: c_int = 0;

    pub const READ_DATA: u32 = 1 << 1;
    pub const WRITE_DATA: u32 = 1 << 2;
    pub const DELETE: u32 = 1 << 4;
    pub const APPEND_DATA: u32 = 1 << 5;
    pub const DELETE_CHILD: u32 = 1 << 6;
    pub const WRITE_ATTRIBUTES: u32 = 1 << 8;
    pub const WRITE_EXTATTRIBUTES: u32 = 1 << 10;
    pub const WRITE_SECURITY: u32 = 1 << 12;
    pub const CHANGE_OWNER: u32 = 1 << 13;
    pub const ALL: [u32; 9] = [
        READ_DATA,
        WRITE_DATA,
        DELETE,
        APPEND_DATA,
        DELETE_CHILD,
        WRITE_ATTRIBUTES,
        WRITE_EXTATTRIBUTES,
        WRITE_SECURITY,
        CHANGE_OWNER,
    ];

    extern "C" {
        pub fn acl_get_fd_np(fd: c_int, ty: c_int) -> Acl;
        pub fn acl_get_link_np(path: *const std::os::raw::c_char, ty: c_int) -> Acl;
        pub fn acl_set_fd_np(fd: c_int, acl: Acl, ty: c_int) -> c_int;
        pub fn acl_init(count: c_int) -> Acl;
        pub fn acl_free(obj: *mut c_void) -> c_int;
        pub fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut Entry) -> c_int;
        pub fn acl_get_tag_type(entry: Entry, tag: *mut c_int) -> c_int;
        pub fn acl_get_permset(entry: Entry, permset: *mut Permset) -> c_int;
        pub fn acl_get_perm_np(permset: Permset, perm: c_int) -> c_int;
        pub fn acl_get_qualifier(entry: Entry) -> *mut c_void;
        pub fn mbr_uuid_to_id(uu: *const u8, id: *mut u32, id_type: *mut c_int) -> c_int;
    }
}

/// One ALLOW entry: the permissions it grants, and whether its principal is root's own user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Allow {
    perms: u32,
    root: bool,
}

#[cfg(target_os = "macos")]
fn allows(fd: impl AsFd) -> Result<(usize, Vec<Allow>)> {
    use std::os::fd::AsRawFd;
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: the ACL comes from the library for this descriptor; `entries_of` frees it.
    unsafe { entries_of(sys::acl_get_fd_np(raw, sys::ACL_TYPE_EXTENDED)) }
}

/// The entries of `acl`, then frees it. A null ACL is "none" when the OS says there is none.
#[cfg(target_os = "macos")]
unsafe fn entries_of(acl: sys::Acl) -> Result<(usize, Vec<Allow>)> {
    if acl.is_null() {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOENT) | Some(libc::ENOTSUP) => Ok((0, Vec::new())),
            _ => Err(refused(format!("an access control list could not be read ({e}); refused rather than skipped"))),
        };
    }
    let mut out = Vec::new();
    let mut count = 0;
    let mut entry: sys::Entry = std::ptr::null_mut();
    let mut which = sys::ACL_FIRST_ENTRY;
    // SAFETY: every pointer below is one the ACL library handed out for `acl`, and each is freed once.
    unsafe {
        while sys::acl_get_entry(acl, which, &mut entry) == 0 {
            which = sys::ACL_NEXT_ENTRY;
            count += 1;
            let mut tag = 0;
            if sys::acl_get_tag_type(entry, &mut tag) != 0 {
                sys::acl_free(acl);
                return Err(refused("an access control list entry could not be read; refused rather than skipped"));
            }
            if tag != sys::ACL_EXTENDED_ALLOW {
                continue;
            }
            let mut set: sys::Permset = std::ptr::null_mut();
            let mut perms = 0;
            if sys::acl_get_permset(entry, &mut set) != 0 {
                sys::acl_free(acl);
                return Err(refused("an access control list entry's permissions could not be read; refused"));
            }
            for p in sys::ALL {
                match sys::acl_get_perm_np(set, p as i32) {
                    1 => perms |= p,
                    0 => {}
                    _ => {
                        sys::acl_free(acl);
                        return Err(refused("an access control list permission could not be read; refused"));
                    }
                }
            }
            let q = sys::acl_get_qualifier(entry);
            let mut root = false;
            if !q.is_null() {
                let (mut id, mut ty) = (u32::MAX, -1);
                if sys::mbr_uuid_to_id(q as *const u8, &mut id, &mut ty) == 0 {
                    root = ty == sys::ID_TYPE_UID && id == 0;
                }
                sys::acl_free(q);
            }
            out.push(Allow { perms, root });
        }
        sys::acl_free(acl);
    }
    Ok((count, out))
}

/// Like `unsafe_grant`, by path and without opening the file or following a link at its end: for a check that
/// may not open it (a root-only key, checked as the developer). Root's own check opens the file.
#[cfg(target_os = "macos")]
pub fn unsafe_grant_path(path: &std::path::Path, guard: Guard) -> Result<Option<String>> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| failed("a path holds a NUL byte"))?;
    // SAFETY: a NUL-terminated path; `entries_of` frees the ACL.
    let (_, entries) = unsafe { entries_of(sys::acl_get_link_np(c.as_ptr(), sys::ACL_TYPE_EXTENDED))? };
    Ok(judge(&entries, guard))
}

#[cfg(not(target_os = "macos"))]
pub fn unsafe_grant_path(_path: &std::path::Path, _guard: Guard) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(not(target_os = "macos"))]
fn allows(_fd: impl AsFd) -> Result<(usize, Vec<Allow>)> {
    Ok((0, Vec::new()))
}

#[cfg(target_os = "macos")]
fn guarded(guard: Guard) -> u32 {
    use sys::*;
    let writes = WRITE_DATA
        | DELETE
        | APPEND_DATA
        | DELETE_CHILD
        | WRITE_ATTRIBUTES
        | WRITE_EXTATTRIBUTES
        | WRITE_SECURITY
        | CHANGE_OWNER;
    match guard {
        Guard::Writes => writes,
        Guard::ReadsAndWrites => writes | READ_DATA,
    }
}

#[cfg(not(target_os = "macos"))]
fn guarded(_guard: Guard) -> u32 {
    0
}

/// Why this object's ACL is unsafe under `guard`, or `None` when it grants nothing guarded to anyone but root.
pub fn unsafe_grant(fd: impl AsFd, guard: Guard) -> Result<Option<String>> {
    let (_, entries) = allows(fd)?;
    Ok(judge(&entries, guard))
}

fn judge(entries: &[Allow], guard: Guard) -> Option<String> {
    let bad = guarded(guard);
    entries.iter().find(|a| !a.root && a.perms & bad != 0).map(|_| match guard {
        Guard::Writes => "an access control list lets another user change it".to_string(),
        Guard::ReadsAndWrites => "an access control list lets another user read or change it".to_string(),
    })
}

/// Whether this object carries any ACL entry at all.
pub fn has_entries(fd: impl AsFd) -> Result<bool> {
    Ok(allows(fd)?.0 > 0)
}

/// Removes every ACL entry, inherited or not.
#[cfg(target_os = "macos")]
pub fn clear(fd: impl AsFd) -> Result<()> {
    use std::os::fd::AsRawFd;
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: an empty ACL from the library, set on this descriptor, then freed.
    unsafe {
        let empty = sys::acl_init(0);
        if empty.is_null() {
            return Err(failed("making an empty access control list failed"));
        }
        let rc = sys::acl_set_fd_np(raw, empty, sys::ACL_TYPE_EXTENDED);
        let e = std::io::Error::last_os_error();
        sys::acl_free(empty);
        if rc != 0 && e.raw_os_error() != Some(libc::ENOTSUP) {
            return Err(failed(format!("clearing an access control list: {e}")));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn clear(_fd: impl AsFd) -> Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) mod tests {
    use super::*;
    use std::path::Path;

    /// Adds an ACL entry with macOS's own `chmod +a` (tests only).
    pub(crate) fn plant(path: &Path, entry: &str) {
        let ok = std::process::Command::new("/bin/chmod").arg("+a").arg(entry).arg(path).status().unwrap().success();
        assert!(ok, "chmod +a {entry}");
    }

    fn open(p: &Path) -> std::fs::File {
        std::fs::File::open(p).unwrap()
    }

    #[test]
    fn a_grant_to_another_user_is_named_and_a_deny_is_not() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("d");
        std::fs::create_dir(&d).unwrap();
        assert_eq!(unsafe_grant(open(&d), Guard::Writes).unwrap(), None);
        plant(&d, "everyone deny delete");
        assert_eq!(unsafe_grant(open(&d), Guard::Writes).unwrap(), None, "a deny entry takes nothing away");
        plant(&d, "everyone allow add_file,delete_child");
        assert!(unsafe_grant(open(&d), Guard::Writes).unwrap().is_some());
        clear(open(&d)).unwrap();
        assert!(!has_entries(open(&d)).unwrap());
    }

    #[test]
    fn a_read_grant_is_unsafe_only_for_a_secret() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("key");
        std::fs::write(&f, b"k").unwrap();
        plant(&f, "everyone allow read");
        assert_eq!(unsafe_grant(open(&f), Guard::Writes).unwrap(), None);
        assert!(unsafe_grant(open(&f), Guard::ReadsAndWrites).unwrap().is_some());
        assert!(unsafe_grant_path(&f, Guard::ReadsAndWrites).unwrap().is_some(), "the same, by path");
    }
}
