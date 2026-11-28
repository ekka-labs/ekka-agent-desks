//! The one step that runs as root, and the same step as a check that changes nothing.
//!
//! `install` works out everything as the developer first: downloads checked, images pulled by digest.
//! It then runs this step as a check (as the developer, reading only what anyone may read) and asks for root only
//! when something root owns would change. So a second install with the same organization asks for nothing and
//! changes nothing. As root, this step takes a lock, refuses a foreign binding (one installation per Mac) before
//! any change, and then writes the binding, the developer's folders, the certificates, the gateway and adapter configuration, the verified
//! programs, the `current` link and the records. Root never runs a staged program: it copies the bytes and hashes
//! the copy it made against the pin embedded in this binary.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{openat, renameat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::adapter::{self, AdapterInputs};
use crate::binding::{Binding, Want};
use crate::error::{errno, failed, refused, Result};
use crate::fsx::{self, ensure_dir, walk_trusted, Owner, Walk, Wrote, DIR_FLAGS};
use crate::gateway_config;
use crate::identity;
use crate::local_build::{self, LocalBuild};
use crate::platform::macos::{
    Layout, BUNDLE, CA_CERT, CA_KEY, JWT_KID, JWT_PUBLIC, JWT_SIGNING, LEAF_CERT, LEAF_KEY, LEAF_META,
};
use crate::records::{self, Resources};
use crate::registration::{self, Registration};
use crate::release::{verify_binary, Pinned, Pins};
use crate::tls::{self, bundle, Ca, JwtKeys, LeafMeta};

/// Where the first release kept a developer's binding, inside their `D`.
const LEGACY_BINDING: &str = "binding.json";

/// Every raise of the desk ceiling, one JSON line each, root's.
const CEILING_RAISES: &str = "ceiling-raises.jsonl";

/// Present while the installation CA is being replaced; removed once the rotation is complete.
const ROTATING: &str = "ca-rotation.pending";

const MAX_PROGRAM: u64 = 256 * 1024 * 1024;

/// Either writes, or only compares and lists what would change.
pub struct Ctx {
    check_only: bool,
    pub changes: Vec<String>,
}

impl Ctx {
    pub fn apply() -> Self {
        Ctx { check_only: false, changes: Vec::new() }
    }

    pub fn check() -> Self {
        Ctx { check_only: true, changes: Vec::new() }
    }

    pub fn checking(&self) -> bool {
        self.check_only
    }

    fn note(&mut self, what: String) {
        self.changes.push(what);
    }

    /// The trusted folder `dir` from `top` (see `fsx::walk_trusted`), made when applying. Checking, a missing
    /// folder is a change and `None`.
    pub fn trusted_dir(&mut self, top: &Path, dir: &Path, owner: u32, mode: u32) -> Result<Option<OwnedFd>> {
        let make = if self.check_only { None } else { Some(mode) };
        match walk_trusted(dir, top, owner, make)? {
            Walk::Found(fd, made) => {
                for m in made {
                    self.note(format!("made {}", m.display()));
                }
                Ok(Some(fd))
            }
            Walk::Missing(at) => {
                self.note(format!("make {}", at.display()));
                Ok(None)
            }
        }
    }

    /// The folder `name` in `parent` with exactly `mode` and `owner`.
    pub fn sub_dir(
        &mut self,
        parent: Option<&OwnedFd>,
        path: &Path,
        name: &str,
        mode: u32,
        owner: Owner,
    ) -> Result<Option<OwnedFd>> {
        let full = path.join(name);
        let Some(parent) = parent else {
            self.note(format!("make {}", full.display()));
            return Ok(None);
        };
        if !self.check_only {
            let (fd, w) = ensure_dir(parent, name, mode, owner, &full.display().to_string())?;
            if w == Wrote::Changed {
                self.note(format!("made {}", full.display()));
            }
            return Ok(Some(fd));
        }
        match openat(parent, name, DIR_FLAGS, Mode::empty()) {
            Ok(fd) => {
                let st = rustix::fs::fstat(&fd).map_err(|e| errno(format!("reading {}", full.display()), e))?;
                if st.st_uid != owner.uid {
                    return Err(refused(format!(
                        "{} exists and is owned by uid {}, not uid {}",
                        full.display(),
                        st.st_uid,
                        owner.uid
                    )));
                }
                if fsx::mode_bits(st.st_mode) != mode {
                    self.note(format!("set the mode of {}", full.display()));
                }
                // An ACL entry on one of our folders is cleared by the root step; finding one is a change, never
                // a pass, so an otherwise unchanged install still runs root and clears it.
                if crate::acl::has_entries(&fd)? {
                    self.note(format!("clear the access control list of {}", full.display()));
                }
                Ok(Some(fd))
            }
            Err(Errno::NOENT) => {
                self.note(format!("make {}", full.display()));
                Ok(None)
            }
            Err(Errno::LOOP | Errno::NOTDIR) => {
                Err(refused(format!("{} is a link or not a folder; it must be a real folder", full.display())))
            }
            Err(e) => Err(errno(format!("opening {}", full.display()), e)),
        }
    }

    pub fn file(
        &mut self,
        dir: Option<&OwnedFd>,
        dir_path: &Path,
        name: &str,
        data: &[u8],
        mode: u32,
        owner: Owner,
    ) -> Result<()> {
        let full = dir_path.join(name);
        match dir {
            None => self.note(format!("write {}", full.display())),
            Some(d) if self.check_only => {
                if !fsx::holds(d, name, data, mode, owner)? {
                    self.note(format!("write {}", full.display()));
                }
            }
            Some(d) => {
                if fsx::write_at(d, name, data, mode, owner)? == Wrote::Changed {
                    self.note(format!("wrote {}", full.display()));
                }
            }
        }
        Ok(())
    }

    /// Renames the file `name` in `dir` to `to`, when there is one: out of reach of readers of `name`, kept as
    /// evidence.
    pub fn quarantine(&mut self, dir: Option<&OwnedFd>, dir_path: &Path, name: &str, to: &str) -> Result<()> {
        let Some(d) = dir else { return Ok(()) };
        match statat(d, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) if self.check_only => {
                self.note(format!("take {} out of use", dir_path.join(name).display()));
                Ok(())
            }
            Ok(_) => {
                renameat(d, name, d, to).map_err(|e| errno(format!("taking {name} out of use"), e))?;
                rustix::fs::fsync(d).map_err(|e| errno("saving a folder", e))?;
                self.note(format!("took {} out of use (kept as {to})", dir_path.join(name).display()));
                Ok(())
            }
            Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(errno(format!("reading {}", dir_path.join(name).display()), e)),
        }
    }

    /// Removes the file or link `name` in `dir`, when there is one.
    pub fn remove(&mut self, dir: Option<&OwnedFd>, dir_path: &Path, name: &str) -> Result<()> {
        let Some(d) = dir else { return Ok(()) };
        match statat(d, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Directory => {
                Err(refused(format!("{} is a folder; it was not removed", dir_path.join(name).display())))
            }
            Ok(_) if self.check_only => {
                self.note(format!("remove {}", dir_path.join(name).display()));
                Ok(())
            }
            Ok(_) => {
                rustix::fs::unlinkat(d, name, AtFlags::empty())
                    .map_err(|e| errno(format!("removing {}", dir_path.join(name).display()), e))?;
                rustix::fs::fsync(d).map_err(|e| errno("saving a folder", e))?;
                self.note(format!("removed {}", dir_path.join(name).display()));
                Ok(())
            }
            Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(errno(format!("reading {}", dir_path.join(name).display()), e)),
        }
    }

    pub fn link(&mut self, dir: Option<&OwnedFd>, dir_path: &Path, name: &str, target: &str) -> Result<()> {
        let full = dir_path.join(name);
        match dir {
            None => self.note(format!("point {} at {target}", full.display())),
            Some(d) if self.check_only => {
                let now = rustix::fs::readlinkat(d, name, Vec::new()).ok();
                if now.as_ref().map(|c| c.as_bytes()) != Some(target.as_bytes()) {
                    self.note(format!("point {} at {target}", full.display()));
                }
            }
            Some(d) => {
                if fsx::link_at(d, name, target)? == Wrote::Changed {
                    self.note(format!("pointed {} at {target}", full.display()));
                }
            }
        }
        Ok(())
    }
}

/// Whether the regular file `name` exists in `dir` (never through a link).
fn exists(dir: Option<&OwnedFd>, name: &str) -> Result<bool> {
    let Some(d) = dir else { return Ok(false) };
    match statat(d, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => Ok(true),
        Ok(_) => Err(refused(format!("{name} is a link or not a regular file"))),
        Err(Errno::NOENT) => Ok(false),
        Err(e) => Err(errno(format!("reading {name}"), e)),
    }
}

fn read(dir: Option<&OwnedFd>, name: &str, max: u64) -> Result<Option<Vec<u8>>> {
    match dir {
        Some(d) => fsx::read_at(d, name, max),
        None => Ok(None),
    }
}

/// Who owns what: root owns the trusted parts, the developer their own folders and the keys their services read.
#[derive(Debug, Clone, Copy)]
pub struct Owners {
    pub root: Owner,
    pub dev: Owner,
}

/// Everything the root step needs from the developer's side. Root re-checks every value: it is input, not trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPlan {
    pub schema: String,
    pub want: Want,
    pub gateway_staged: PathBuf,
    pub adapter_staged: Option<PathBuf>,
    /// The largest CPU and memory one desk may have, when the profile sets one (a developer's Mac does not).
    pub resources: Option<Resources>,
    /// Govern's answer to the gateway's registration, once it is registered. Root uses it only when it is this
    /// installation's (`registration`); every sign-in value is computed, and checked against it.
    pub registration: Option<Registration>,
    pub adapter: Option<AdapterInputs>,
    /// Replace an installation CA whose key is no longer root's alone, and the gateway certificate with it.
    #[serde(default)]
    pub rotate_ca: bool,
    /// Allow the desk CPU or memory ceiling to go up (it may always go down); recorded when used.
    #[serde(default)]
    pub raise_ceiling: bool,
    /// `install --rotate-adapter-key`: the adapter key is about to be replaced, so no sign-in is written for it.
    #[serde(default)]
    pub rotate_adapter_key: bool,
    /// A developer's local build in place of the releases it names: dev only (`local_build`). Root hashes the
    /// local adapter itself and records `"source": "local-build"`.
    #[serde(default)]
    pub local_build: Option<LocalBuild>,
}

pub const PLAN_SCHEMA: &str = "ekka-desk-host.root-plan/v2";

impl RootPlan {
    pub fn check(&self, pins: &Pins) -> Result<()> {
        if self.schema != PLAN_SCHEMA {
            return Err(refused(format!("the root plan is not {PLAN_SCHEMA}")));
        }
        self.want.check()?;
        if let Some(r) = &self.resources {
            if self.want.profile == crate::binding::PROFILE {
                return Err(refused(
                    "a developer's Mac gives a desk no CPU or memory limit of its own in this release; the plan names one",
                ));
            }
            r.check()?;
        }
        if let Some(lb) = &self.local_build {
            lb.check(&self.want.env)?;
            let local = lb.ekka_backend.as_ref().map(|p| Path::new(&p.path));
            if self.adapter_staged.is_some() && self.adapter_staged.as_deref() != local {
                return Err(refused("the plan stages another adapter than its local build names"));
            }
        }
        if let Some(a) = &self.adapter {
            adapter::check_keys(&a.govern_keys)?;
            if pins.adapter.is_none() || self.adapter_staged.is_none() {
                return Err(refused("the adapter is configured but not pinned or not staged"));
            }
        }
        for p in [Some(&self.gateway_staged), self.adapter_staged.as_ref()].into_iter().flatten() {
            if !p.is_absolute() {
                return Err(refused("a staged program is not named by an absolute path"));
            }
        }
        Ok(())
    }
}

/// Puts one verified program in the release's `bin`. Already right: unchanged. Otherwise the staged bytes are
/// read (never through a link, at most 256 MiB), hashed against the pin, and that same copy is written.
fn program(
    ctx: &mut Ctx,
    bin: Option<&OwnedFd>,
    bin_path: &Path,
    pin: &Pinned,
    staged: &Path,
    owners: Owners,
    checked: Option<&[u8]>,
) -> Result<()> {
    let root = owners.root;
    if let Some(have) = read(bin, &pin.binary, MAX_PROGRAM)? {
        if verify_binary(pin, &have).is_ok()
            && fsx::holds(bin.expect("read found it"), &pin.binary, &have, 0o755, root)?
        {
            return Ok(());
        }
    }
    if ctx.checking() {
        ctx.note(format!("install {}", bin_path.join(&pin.binary).display()));
        return Ok(());
    }
    let bytes = match checked {
        // A local build root already read and hashed, before any change (`local_adapter`): those same bytes.
        Some(b) => b.to_vec(),
        // What the developer staged: opened one folder at a time from `/`, never through a link anywhere on the way,
        // each folder root's or theirs; read once from that one handle, and these bytes are hashed and installed.
        None => fsx::read_regular(fsx::open_owned_path(staged, owners.dev.uid)?, &pin.binary, MAX_PROGRAM)?,
    };
    verify_binary(pin, &bytes)?;
    ctx.file(bin, bin_path, &pin.binary, &bytes, 0o755, root)
}

#[derive(Serialize)]
struct ReleaseRecord<'a> {
    schema: &'static str,
    /// `local-build` for a developer's local build (dev only); left out for a release.
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'static str>,
    release: &'a str,
    openshell_version: &'a str,
    gateway: &'a Pinned,
    adapter: Option<&'a Pinned>,
}

/// A legacy binding's folder or file is trusted only when owned by root or that developer, writable by nobody
/// else, with no ACL letting anyone else change it.
fn legacy_trusted(fd: &OwnedFd, what: &Path, uid: u32, root: u32) -> Result<()> {
    let st = rustix::fs::fstat(fd).map_err(|e| errno(format!("reading {}", what.display()), e))?;
    if (st.st_uid != uid && st.st_uid != root) || fsx::mode_bits(st.st_mode) & 0o022 != 0 {
        return Err(refused(format!(
            "{} is uid {} mode {:o}: an old binding anyone else could have written is not trusted; nothing was changed",
            what.display(),
            st.st_uid,
            fsx::mode_bits(st.st_mode)
        )));
    }
    if let Some(why) = crate::acl::unsafe_grant(fd, crate::acl::Guard::Writes)? {
        return Err(refused(format!("{}: {why}; nothing was changed", what.display())));
    }
    Ok(())
}

/// Bindings the first release wrote, one per developer at `ekka-dev/<uid>/binding.json`, each checked to be what
/// it says (its uid is its folder's), trusted (`legacy_trusted`), and read without following a link.
fn legacy_bindings(l: &Layout, root: u32) -> Result<Vec<Binding>> {
    let dir = match walk_trusted(&l.ekka_dev(), &l.top, root, None)? {
        Walk::Found(fd, _) => fd,
        Walk::Missing(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    let mut entries = rustix::fs::Dir::read_from(&dir).map_err(|e| errno("listing the installations", e))?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|e| errno("listing the installations", e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(uid) = name.parse::<u32>() else { continue };
        let sub = match openat(&dir, name.as_str(), DIR_FLAGS, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOTDIR) => continue,
            Err(e) => return Err(errno(format!("opening {}", l.ekka_dev().join(&name).display()), e)),
        };
        let path = l.ekka_dev().join(&name);
        legacy_trusted(&sub, &path, uid, root)?;
        let Some(file) = fsx::open_file_at(&sub, LEGACY_BINDING)? else { continue };
        legacy_trusted(&file, &path.join(LEGACY_BINDING), uid, root)?;
        {
            let bytes = fsx::read_regular(file, LEGACY_BINDING, 64 * 1024)?;
            let b = Binding::parse(&bytes)?;
            if b.uid != uid {
                return Err(refused(format!("{}/{LEGACY_BINDING} names uid {}; nothing was changed", name, b.uid)));
            }
            out.push(b);
        }
    }
    Ok(out)
}

/// A developer's local adapter build (dev only), read one folder at a time from `/` (no link, each folder root's or
/// theirs, a regular file, at most 256 MiB) and hashed here against the manifest's sha256: any difference is
/// refused, before anything changes. The bytes read are the ones installed.
fn local_adapter(pin: &Pinned, staged: &Path, dev_uid: u32) -> Result<Vec<u8>> {
    let fd = fsx::open_owned_path(staged, dev_uid)?;
    let bytes = fsx::read_regular(fd, &pin.binary, MAX_PROGRAM)?;
    verify_binary(pin, &bytes).map_err(|e| {
        refused(format!("the local build's adapter {}: {}; nothing was changed", staged.display(), e.reason))
    })?;
    Ok(bytes)
}

/// Does (or, checking, lists) every root-owned part of the installation. Returns the binding in force.
/// The CA key, when one exists, may be used again only while it is root's alone: owner root, mode 0600, and no
/// ACL letting anyone else read or change it. Checking, as the developer, this reads the key's metadata only.
fn ca_key_problem(ctx: &Ctx, tls: Option<&OwnedFd>, tls_path: &Path, root: Owner) -> Result<Option<String>> {
    let Some(dir) = tls else { return Ok(None) };
    if !exists(Some(dir), CA_KEY)? {
        return Ok(None);
    }
    let what = tls_path.join(CA_KEY).display().to_string();
    let found = if ctx.checking() {
        let st = statat(dir, CA_KEY, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| errno(format!("reading {what}"), e))?;
        if st.st_uid != root.uid || fsx::mode_bits(st.st_mode) != 0o600 {
            Some(format!("{what} is uid {} mode {:o}", st.st_uid, fsx::mode_bits(st.st_mode)))
        } else {
            crate::acl::unsafe_grant_path(&tls_path.join(CA_KEY), crate::acl::Guard::ReadsAndWrites)?
                .map(|why| format!("{what}: {why}"))
        }
    } else {
        let fd = fsx::open_file_at(dir, CA_KEY)?.ok_or_else(|| failed("the CA key went missing"))?;
        fsx::check_secret(&fd, &what, root.uid, 0o600).err().map(|e| e.reason)
    };
    Ok(found)
}

/// Does (or, checking, lists) every root-owned part of the installation. Returns the binding in force.
pub fn root_apply(
    plan: &RootPlan,
    l: &Layout,
    owners: Owners,
    pins: &Pins,
    system_roots: &[u8],
    ctx: &mut Ctx,
) -> Result<Binding> {
    // A local build is dev only, refused here before anything; then its parts stand in for the pins they replace.
    if let Some(lb) = &plan.local_build {
        lb.check(&plan.want.env)?;
    }
    let pins = &pins.with_local(plan.local_build.as_ref());
    plan.check(pins)?;
    let (root, dev) = (owners.root, owners.dev);
    let local_adapter = match (&pins.adapter, &plan.adapter_staged) {
        (Some(pin), Some(staged)) if pins.adapter_local => Some(local_adapter(pin, staged, dev.uid)?),
        _ => None,
    };
    let top = &l.top;

    // One installation per Mac: the machine-wide binding names the organization, the developer's uid and the
    // environment. Anything else is refused here, before any path, shared or not, is changed.
    let existing = Binding::read(&l.binding())?;
    if let Some(b) = &existing {
        b.check_same(&plan.want)?;
    }
    let mut lock_dir = None;
    let _lock = if ctx.checking() {
        None
    } else {
        let dev_dir = ctx.trusted_dir(top, &l.ekka_dev(), root.uid, 0o755)?.ok_or_else(|| failed("no lock folder"))?;
        let fd = openat(
            &dev_dir,
            ".install.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| errno("taking the install lock", e))?;
        rustix::fs::flock(&fd, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|e| errno("taking the install lock", e))?;
        lock_dir = Some(dev_dir);
        Some(fd)
    };
    // Applying, will this step change what the gateway trusts? The same step as a check, under the lock, says.
    let trust_will_change = !ctx.checking() && {
        let mut probe = Ctx::check();
        root_apply(plan, l, owners, pins, system_roots, &mut probe)?;
        let trusted = [l.tls_dir(), l.gateway_toml(), l.d().join(registration::RECORD)];
        probe.changes.iter().any(|c| trusted.iter().any(|p| c.contains(&p.display().to_string())))
    };
    // Again under the lock: another install may have bound this Mac in between.
    let existing = match (existing, Binding::read(&l.binding())?) {
        (_, Some(now)) => {
            now.check_same(&plan.want)?;
            Some(now)
        }
        (before, None) => before,
    };
    // A binding the first release kept per developer still claims this Mac: every one must be this install's,
    // or nothing is changed. This developer's own is carried over (its installation id kept) and then retired.
    let legacy = legacy_bindings(l, root.uid)?;
    for b in &legacy {
        b.check_same(&plan.want)?;
        if existing.as_ref().is_some_and(|e| e.installation_id != b.installation_id) {
            return Err(refused(
                "this Mac holds two different installations' bindings; nothing was changed. Retire one first",
            ));
        }
    }
    let migrated = existing.is_none() && !legacy.is_empty();
    let binding = match existing.or_else(|| legacy.into_iter().next()) {
        Some(b) => b,
        None => plan.want.new_binding()?,
    };
    let ekka_dev = match lock_dir {
        Some(fd) => Some(fd),
        None => ctx.trusted_dir(top, &l.ekka_dev(), root.uid, 0o755)?,
    };
    ctx.file(ekka_dev.as_ref(), &l.ekka_dev(), "binding.json", &binding.bytes(), 0o644, root)?;

    // A ceiling only goes down unless raising it was asked for, by name: checked before anything is written.
    let records_dir = l.records();
    let old_ceiling = match fsx::walk_trusted(&records_dir, top, root.uid, None)? {
        Walk::Found(fd, _) => match fsx::read_at(&fd, records::CEILING, 64 * 1024)? {
            Some(bytes) => Some(serde_json::from_slice::<records::Ceiling>(&bytes).map_err(|_| {
                refused("the existing provider ceiling cannot be read, so it cannot be compared; nothing was changed")
            })?),
            None => None,
        },
        Walk::Missing(_) => None,
    };
    // Going from a limit to none, or to a larger one, is a raise; from none to a limit, or a smaller one, is not.
    let raised = old_ceiling.as_ref().is_some_and(|c| match (&c.resources, &plan.resources) {
        (Some(_), None) => true,
        (Some(o), Some(n)) => n.max_cpu_millicores > o.max_cpu_millicores || n.max_memory_mib > o.max_memory_mib,
        (None, _) => false,
    });
    if raised && !plan.raise_ceiling {
        let show = |r: &Option<Resources>| match r {
            Some(r) => format!("{} millicores and {} MiB", r.max_cpu_millicores, r.max_memory_mib),
            None => "no limit".to_string(),
        };
        let old = &old_ceiling.as_ref().expect("raised implies a ceiling").resources;
        return Err(refused(format!(
            "the desk ceiling is {}; raising it to {} needs --raise-ceiling. Nothing was changed",
            show(old),
            show(&plan.resources)
        )));
    }

    let d = l.d();
    let dfd = ctx.trusted_dir(top, &d, root.uid, 0o755)?;
    if migrated || dfd.as_ref().map(|fd| exists(Some(fd), LEGACY_BINDING)).transpose()?.unwrap_or(false) {
        ctx.remove(dfd.as_ref(), &d, LEGACY_BINDING)?;
    }

    // The developer's folders, each 0700: the services' state and their sockets.
    ctx.sub_dir(dfd.as_ref(), &d, "enclave", 0o700, dev)?;
    let gw = ctx.sub_dir(dfd.as_ref(), &d, "gateway", 0o700, dev)?;
    for name in ["config", "data", "state", "cache"] {
        ctx.sub_dir(gw.as_ref(), &l.gateway_dir(), name, 0o700, dev)?;
    }
    let be = ctx.sub_dir(dfd.as_ref(), &d, "backend", 0o700, dev)?;
    ctx.sub_dir(be.as_ref(), &l.backend_dir(), "permits", 0o700, dev)?;
    let run = ctx.sub_dir(dfd.as_ref(), &d, "run", 0o700, dev)?;
    ctx.sub_dir(run.as_ref(), &l.run_dir(), "backend", 0o700, dev)?;

    // Certificates: the CA key root's alone; the gateway's key the developer's, who runs the gateway. A CA key
    // that is not root's alone any more is never used again: it is refused, or replaced with --rotate-ca.
    let tls_path = l.tls_dir();
    let tls = ctx.sub_dir(dfd.as_ref(), &d, "tls", 0o755, root)?;
    let jwt = ctx.sub_dir(tls.as_ref(), &tls_path, "jwt", 0o755, root)?;
    // What the gateway trusts, read through the folders just checked. When this step will change any of it, the
    // restart marker is written (and saved) BEFORE the first change, so a stop part way still asks for a restart; it
    // stays until launchd confirms one (`registration::finish`).
    let trust_before = registration::trust_digest_at(dfd.as_ref(), tls.as_ref(), jwt.as_ref())?;
    let mut marker_early = false;
    if trust_will_change {
        let stop = !matches!(plan.registration.as_ref().map(|r| r.verify(&binding)), Some(Ok(_)));
        let marker = registration::RestartPending::new(stop, format!("pending {trust_before}"));
        ctx.file(run.as_ref(), &l.run_dir(), registration::RESTART_PENDING, &marker.bytes(), 0o644, root)?;
        marker_early = true;
    }
    // A rotation that started is finished, whatever stopped it: the marker is written before the new key and
    // removed only once the new CA, the gateway certificate and the bundle are all in place.
    let rotating = exists(tls.as_ref(), ROTATING)?;
    let exposed = if rotating { None } else { ca_key_problem(ctx, tls.as_ref(), &tls_path, root)? };
    if let Some(why) = &exposed {
        if !plan.rotate_ca {
            return Err(refused(format!(
                "the installation CA's key may have been seen by someone else ({why}); it is not used again. Run \
                 install again with --rotate-ca to make a new CA and gateway certificate"
            )));
        }
    }
    let mut ca: Option<Ca> = None;
    let mut ca_pem: Option<Vec<u8>> = read(tls.as_ref(), CA_CERT, 64 * 1024)?;
    // --rotate-ca always rotates: also a CA whose certificate and key do not belong together.
    let rotate = rotating || plan.rotate_ca;
    let make_ca = !exists(tls.as_ref(), CA_KEY)? || rotate;
    if make_ca {
        if ctx.checking() {
            ctx.note(if rotating {
                format!("finish the CA rotation in {}", tls_path.display())
            } else {
                format!("make the installation CA in {}", tls_path.display())
            });
            ca_pem = None;
        } else {
            if rotate {
                ctx.file(tls.as_ref(), &tls_path, ROTATING, b"rotating\n", 0o600, root)?;
            }
            let (new, key_pem, cert_pem) = Ca::generate(&binding.installation_id)?;
            ctx.file(tls.as_ref(), &tls_path, CA_KEY, key_pem.as_bytes(), 0o600, root)?;
            ctx.file(tls.as_ref(), &tls_path, CA_CERT, cert_pem.as_bytes(), 0o644, root)?;
            ca = Some(new);
            ca_pem = Some(cert_pem.into_bytes());
        }
    } else if !ctx.checking() {
        let key_pem = read(tls.as_ref(), CA_KEY, 64 * 1024)?.ok_or_else(|| failed("the CA key went missing"))?;
        let key_pem = String::from_utf8(key_pem).map_err(|_| refused("the installation's CA key is not PEM"))?;
        let loaded = Ca::load(&binding.installation_id, &key_pem)?;
        if let Some(pem) = &ca_pem {
            // The certificate must be this key's: a CA certificate and key that do not belong together is never
            // trusted again.
            if !tls::cert_matches_key(pem, &key_pem)? {
                return Err(refused(format!(
                    "{} is not the certificate of the installation CA's key; it is not used. Run install again with \
                     --rotate-ca to make a new CA and gateway certificate",
                    tls_path.join(CA_CERT).display()
                )));
            }
        }
        if ca_pem.is_none() {
            // An install stopped between the CA's key and its certificate: the same key and name make a
            // certificate everything already trusting this CA's key accepts.
            let pem = loaded.cert_pem();
            ctx.file(tls.as_ref(), &tls_path, CA_CERT, pem.as_bytes(), 0o644, root)?;
            ca_pem = Some(pem.into_bytes());
        }
        ca = Some(loaded);
    }
    if ctx.checking() && ca_pem.is_none() && exists(tls.as_ref(), CA_KEY)? {
        ctx.note(format!("restore {}", tls_path.join(CA_CERT).display()));
    }
    let meta: Option<LeafMeta> =
        read(tls.as_ref(), LEAF_META, 64 * 1024)?.and_then(|m| serde_json::from_slice(&m).ok());
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let renew = match &ca_pem {
        None => true,
        Some(pem) => {
            LeafMeta::needs_renewal(meta.as_ref(), pem, now)
                || !exists(tls.as_ref(), LEAF_KEY)?
                || read(tls.as_ref(), LEAF_CERT, 64 * 1024)?.is_none_or(|leaf| !tls::leaf_chains_to(&leaf, pem))
        }
    };
    if renew {
        match (&ca, &ca_pem) {
            (Some(ca), Some(pem)) if !ctx.checking() => {
                let pem_text = std::str::from_utf8(pem).map_err(|_| refused("the CA certificate is not PEM"))?;
                let (cert, key, meta) = ca.leaf(pem_text)?;
                ctx.file(tls.as_ref(), &tls_path, LEAF_KEY, key.as_bytes(), 0o600, dev)?;
                ctx.file(tls.as_ref(), &tls_path, LEAF_CERT, cert.as_bytes(), 0o644, root)?;
                let mut m = serde_json::to_vec_pretty(&meta).map_err(|e| failed(e.to_string()))?;
                m.push(b'\n');
                ctx.file(tls.as_ref(), &tls_path, LEAF_META, &m, 0o644, root)?;
            }
            _ => ctx.note(format!("make the gateway certificate in {}", tls_path.display())),
        }
    }
    let jwt_path = l.jwt_dir();
    match read(jwt.as_ref(), JWT_SIGNING, 64 * 1024)? {
        None if ctx.checking() => ctx.note(format!("make the gateway's token keys in {}", jwt_path.display())),
        None => {
            let k = JwtKeys::generate()?;
            ctx.file(jwt.as_ref(), &jwt_path, JWT_SIGNING, k.signing_pem.as_bytes(), 0o600, dev)?;
            ctx.file(jwt.as_ref(), &jwt_path, JWT_PUBLIC, k.public_pem.as_bytes(), 0o644, root)?;
            ctx.file(jwt.as_ref(), &jwt_path, JWT_KID, k.kid.as_bytes(), 0o644, root)?;
        }
        Some(signing) => {
            let signing = String::from_utf8(signing).map_err(|_| refused("the gateway's token key is not PEM"))?;
            let (public_pem, _) = JwtKeys::public_of(&signing)?;
            ctx.file(jwt.as_ref(), &jwt_path, JWT_PUBLIC, public_pem.as_bytes(), 0o644, root)?;
            if read(jwt.as_ref(), JWT_KID, 256)?.is_none_or(|k| k.len() != 32) {
                if ctx.checking() {
                    ctx.note(format!("write {}", jwt_path.join(JWT_KID).display()));
                } else {
                    let kid = JwtKeys::generate()?.kid;
                    ctx.file(jwt.as_ref(), &jwt_path, JWT_KID, kid.as_bytes(), 0o644, root)?;
                }
            }
        }
    }
    match &ca_pem {
        Some(pem) => ctx.file(tls.as_ref(), &tls_path, BUNDLE, &bundle(system_roots, pem)?, 0o644, root)?,
        None => ctx.note(format!("write {}", tls_path.join(BUNDLE).display())),
    }
    if rotate && !ctx.checking() {
        ctx.remove(tls.as_ref(), &tls_path, ROTATING)?;
    }

    // The gateway's and the adapter's configuration: root's, from computed values only. The issuer is Govern's
    // for this environment and organization; the audience and roles claim follow the registered gateway's id,
    // and only a registration that is this installation's is used. Without one, the gateway's trust
    // configuration is removed, so an old one is never left in place.
    match plan.registration.as_ref().map(|r| r.verify(&binding).map(|oidc| (r, oidc))) {
        Some(Ok((r, oidc))) => {
            let gateway_toml = gateway_config::render(l, &oidc, &l.docker_socket(), pins)?;
            ctx.file(dfd.as_ref(), &d, registration::RECORD, &registration::Record::of(r).bytes(), 0o644, root)?;
            #[cfg(test)]
            if !ctx.checking() && tests::CRASH_AFTER_RECORD.with(|c| c.get()) {
                return Err(failed("a test stopped the root step after the registration record"));
            }
            ctx.file(dfd.as_ref(), &d, "gateway.toml", gateway_toml.as_bytes(), 0o644, root)?;
        }
        _ => {
            ctx.remove(dfd.as_ref(), &d, "gateway.toml")?;
            ctx.remove(dfd.as_ref(), &d, registration::RECORD)?;
        }
    }
    // What the gateway trusts changed in this step: a running gateway must restart on it (or stop, with nothing to
    // trust). The marker is root's, in the developer's run folder, so their side can remove it once launchd
    // confirms; until then every install finishes it first.
    let trust_after = registration::trust_digest_at(dfd.as_ref(), tls.as_ref(), jwt.as_ref())?;
    if !ctx.checking() && (trust_after != trust_before || marker_early) {
        let stop = !exists(dfd.as_ref(), "gateway.toml")?;
        let marker = registration::RestartPending::new(stop, trust_after);
        ctx.file(run.as_ref(), &l.run_dir(), registration::RESTART_PENDING, &marker.bytes(), 0o644, root)?;
    }
    if let Some(inputs) = &plan.adapter {
        let issuer = identity::issuer(&binding.env, &binding.org)?;
        // The desk-pass sign-in only when this installation's registration names this key and the pinned adapter
        // reads it; otherwise left out (an older adapter refuses a file that has it).
        // The key's thumbprint as root reads it now, under the install lock, through the folder handle it checked
        // (no link, the developer's 0600 file, no ACL): never the plan's word for it. A key being replaced is none.
        let key_kid = match (&be, plan.rotate_adapter_key) {
            (Some(dir), false) => {
                let path = l.backend_dir().join(crate::adapter_key::KEY_FILE);
                crate::adapter_key::read_key(dir, &path, dev.uid).kid().map(str::to_string)
            }
            _ => None,
        };
        let signin = adapter::signin(l, &binding, plan.registration.as_ref(), key_kid.as_deref(), pins).ok();
        let cfg = adapter::config_bytes(l, &binding.org, inputs, &issuer, signin.as_ref())?;
        ctx.file(dfd.as_ref(), &d, "backend-config.json", &cfg, 0o644, root)?;
    }

    // The verified programs, then the `current` link.
    let release = pins.release_id();
    let opt = l.opt();
    let ofd = ctx.trusted_dir(top, &opt, root.uid, 0o755)?;
    let rels = ctx.sub_dir(ofd.as_ref(), &opt, "releases", 0o755, root)?;
    let rel_path = l.release_dir(&release);
    let rel = ctx.sub_dir(rels.as_ref(), &opt.join("releases"), &release, 0o755, root)?;
    let bin = ctx.sub_dir(rel.as_ref(), &rel_path, "bin", 0o755, root)?;
    let bin_path = rel_path.join("bin");
    program(ctx, bin.as_ref(), &bin_path, &pins.gateway, &plan.gateway_staged, owners, None)?;
    if let (Some(pin), Some(staged)) = (&pins.adapter, &plan.adapter_staged) {
        program(ctx, bin.as_ref(), &bin_path, pin, staged, owners, local_adapter.as_deref())?;
    }
    let record = ReleaseRecord {
        schema: "ekka-desk-host.release/v1",
        source: pins.adapter_local.then_some(local_build::SOURCE),
        release: &release,
        openshell_version: &pins.openshell_version,
        gateway: &pins.gateway,
        adapter: pins.adapter.as_ref().filter(|_| plan.adapter_staged.is_some()),
    };
    let mut rec = serde_json::to_vec_pretty(&record).map_err(|e| failed(e.to_string()))?;
    rec.push(b'\n');
    ctx.file(rel.as_ref(), &rel_path, "release.json", &rec, 0o644, root)?;
    ctx.link(ofd.as_ref(), &opt, "current", &format!("releases/{release}"))?;

    // The records EKKA's desk commands build a grant from. The desk image only by a published, pinned digest.
    // A raise is logged (and saved to disk) before the raised ceiling is written: never a raise without its record.
    if raised {
        let old = old_ceiling.expect("raised implies a ceiling").resources;
        let note = serde_json::json!({"schema": "ekka-desk-host.ceiling-raise/v1",
            "at_unix": time::OffsetDateTime::now_utc().unix_timestamp(), "uid": plan.want.uid,
            "from": old, "to": plan.resources});
        let mut line = note.to_string().into_bytes();
        line.push(b'\n');
        let mut log = read(ekka_dev.as_ref(), CEILING_RAISES, 1024 * 1024)?.unwrap_or_default();
        log.extend_from_slice(&line);
        ctx.file(ekka_dev.as_ref(), &l.ekka_dev(), CEILING_RAISES, &log, 0o644, root)?;
    }
    let image = records::expected_image(pins.desk_image.as_ref(), plan.local_build.as_ref())?;
    records::write(ctx, top, &records_dir, root, image.as_deref(), plan.resources)?;
    // A local build is said beside the records, root's, so nothing reads them as a release's; gone with it.
    let rfd = ctx.trusted_dir(top, &records_dir, root.uid, 0o755)?;
    match &plan.local_build {
        Some(lb) => {
            ctx.file(rfd.as_ref(), &records_dir, local_build::MARKER, &local_build::marker_bytes(lb), 0o644, root)?
        }
        None => ctx.remove(rfd.as_ref(), &records_dir, local_build::MARKER)?,
    }
    if image.is_none() {
        // No published image is pinned: an image record left from before is taken out of the runner's reach (kept
        // beside it, renamed, as evidence), so desks wait closed rather than run an image nobody pinned.
        let fd = ctx.trusted_dir(top, &records_dir, root.uid, 0o755)?;
        let stamp = time::OffsetDateTime::now_utc().unix_timestamp();
        ctx.quarantine(fd.as_ref(), &records_dir, records::IMAGE, &format!("{}.unpinned-{stamp}", records::IMAGE))?;
    }
    Ok(binding)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    thread_local! {
        /// A stop part way, as a crash or a full disk would make one: right after the registration record is written.
        pub(crate) static CRASH_AFTER_RECORD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    pub(crate) const ORG: &str = "7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7";
    const FOREIGN: &str = "0d0e0f10-1112-4314-8516-171819202122";
    const GATEWAY: &str = crate::registration::tests::GATEWAY;

    /// Installs once, then again with Govern's registration for this installation, as a registered gateway is.
    pub(crate) fn registered(r: &mut Rig, owners: Owners) -> Binding {
        let b = root_apply(&r.plan, &r.layout, owners, &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        r.plan.registration = Some(Registration::from_answer(&crate::registration::tests::answer(&b)).unwrap());
        root_apply(&r.plan, &r.layout, owners, &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        b
    }

    pub(crate) fn me() -> Owner {
        Owner { uid: rustix::process::getuid().as_raw(), gid: rustix::process::getgid().as_raw() }
    }

    fn fake_program() -> Vec<u8> {
        let mut b = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x02, 0, 0, 0];
        b.extend_from_slice(b"a stand-in for NVIDIA's gateway");
        b
    }

    pub(crate) struct Rig {
        pub dir: tempfile::TempDir,
        pub layout: Layout,
        pub pins: Pins,
        pub plan: RootPlan,
        pub roots: Vec<u8>,
    }

    pub(crate) fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        // Its real path: a Mac's temporary folder is under /var, a link, and root reads what is staged without one.
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let top = base.join("root");
        std::fs::create_dir(&top).unwrap();
        std::fs::set_permissions(&top, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = base.join("home");
        std::fs::create_dir(&home).unwrap();
        let staged = home.join("openshell-gateway");
        std::fs::write(&staged, fake_program()).unwrap();
        let mut pins = Pins::embedded().unwrap();
        pins.gateway.binary_sha256 = crate::util::sha256_hex(&fake_program());
        let layout = Layout { top, uid: me().uid, home };
        let plan = RootPlan {
            schema: PLAN_SCHEMA.into(),
            want: Want {
                org: ORG.into(),
                uid: me().uid,
                env: "prod".into(),
                profile: crate::binding::PROFILE.into(),
                runtime: crate::binding::RUNTIME.into(),
            },
            gateway_staged: staged,
            adapter_staged: None,
            resources: None,
            registration: None,
            adapter: None,
            rotate_ca: false,
            raise_ceiling: false,
            rotate_adapter_key: false,
            local_build: None,
        };
        let roots = std::fs::read(crate::net::system_roots_path()).unwrap();
        Rig { dir, layout, pins, plan, roots }
    }

    pub(crate) fn owners() -> Owners {
        Owners { root: me(), dev: me() }
    }

    /// Every path under `p` with its size, mode and modification time.
    fn snapshot(p: &Path) -> BTreeMap<PathBuf, (u64, u32, i64, i64)> {
        let mut out = BTreeMap::new();
        let mut stack = vec![p.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                let m = std::fs::symlink_metadata(e.path()).unwrap();
                out.insert(e.path(), (m.len(), m.mode(), m.mtime(), m.mtime_nsec()));
                if m.is_dir() {
                    stack.push(e.path());
                }
            }
        }
        out
    }

    #[test]
    fn a_first_install_writes_everything_and_a_same_org_retry_changes_nothing() {
        let mut r = rig();
        let b = registered(&mut r, owners());
        assert_eq!(b.org, ORG);
        assert!(r.layout.gateway_toml().exists());

        let mut check = Ctx::check();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut check).unwrap();
        assert!(check.changes.is_empty(), "a check after install finds nothing to do: {:?}", check.changes);

        let before = snapshot(r.dir.path());
        let mut again = Ctx::apply();
        let b2 = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut again).unwrap();
        assert!(again.changes.is_empty(), "{:?}", again.changes);
        assert_eq!(b2.installation_id, b.installation_id, "the same installation");
        assert_eq!(snapshot(r.dir.path()), before, "a same-org retry touches no file");
    }

    #[test]
    fn a_foreign_org_is_refused_before_any_change() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let before = snapshot(r.dir.path());
        let mut foreign = r.plan.clone();
        foreign.want.org = FOREIGN.into();
        for mut ctx in [Ctx::check(), Ctx::apply()] {
            let e = root_apply(&foreign, &r.layout, owners(), &r.pins, &r.roots, &mut ctx).unwrap_err();
            assert_eq!(e.kind, crate::error::Kind::Refused);
            assert!(e.reason.contains(ORG) && e.reason.contains(FOREIGN), "{e}");
            assert!(ctx.changes.is_empty());
        }
        assert_eq!(snapshot(r.dir.path()), before, "nothing changed");
    }

    #[test]
    fn folders_keys_records_and_programs_get_their_owners_and_modes() {
        let mut r = rig();
        registered(&mut r, owners());
        let mode = |p: PathBuf| std::fs::symlink_metadata(&p).unwrap().permissions().mode() & 0o7777;
        let l = &r.layout;
        assert_eq!(mode(l.d()), 0o755);
        for p in
            [l.enclave_home(), l.gateway_dir(), l.backend_dir(), l.run_dir(), l.backend_socket_dir(), l.permits_dir()]
        {
            assert_eq!(mode(p.clone()), 0o700, "{}", p.display());
        }
        for x in ["config", "data", "state", "cache"] {
            assert_eq!(mode(l.gateway_dir().join(x)), 0o700);
        }
        assert_eq!(mode(l.tls_dir().join(CA_KEY)), 0o600, "the CA key is its owner's alone");
        assert_eq!(mode(l.tls_dir().join(LEAF_KEY)), 0o600);
        assert_eq!(mode(l.jwt_dir().join(JWT_SIGNING)), 0o600);
        assert_eq!(mode(l.tls_dir().join(CA_CERT)), 0o644);
        assert_eq!(mode(l.gateway_toml()), 0o644);
        assert_eq!(mode(l.binding()), 0o644);
        let bin = l.release_dir(&r.pins.release_id()).join("bin/openshell-gateway");
        assert_eq!(mode(bin.clone()), 0o755);
        assert_eq!(std::fs::read(&bin).unwrap(), fake_program());
        assert_eq!(
            std::fs::read_link(l.opt().join("current")).unwrap(),
            PathBuf::from(format!("releases/{}", r.pins.release_id()))
        );
        for rec in [records::BASELINE, records::CEILING] {
            assert_eq!(mode(l.records().join(rec)), 0o644);
        }
        assert!(!l.records().join(records::IMAGE).exists(), "no published desk image pinned: no image record");
        // The gateway's certificate chains to the CA on disk and names both of its addresses.
        let meta: LeafMeta = serde_json::from_slice(&std::fs::read(l.tls_dir().join(LEAF_META)).unwrap()).unwrap();
        assert_eq!(meta.ca_sha256, crate::util::sha256_hex(&std::fs::read(l.tls_dir().join(CA_CERT)).unwrap()));
        let bundle = std::fs::read(l.tls_dir().join(BUNDLE)).unwrap();
        assert!(bundle.starts_with(&r.roots) && bundle.ends_with(&std::fs::read(l.tls_dir().join(CA_CERT)).unwrap()));
    }

    #[test]
    fn a_staged_program_with_a_swapped_byte_is_never_installed() {
        let r = rig();
        let mut bytes = fake_program();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&r.plan.gateway_staged, &bytes).unwrap();
        let e = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap_err();
        assert!(e.reason.contains("the program hashes to"), "{e}");
        let bin = r.layout.release_dir(&r.pins.release_id()).join("bin/openshell-gateway");
        assert!(!bin.exists());
        assert!(std::fs::symlink_metadata(r.layout.opt().join("current")).is_err(), "nothing was activated");
    }

    #[test]
    fn a_staged_program_that_is_a_link_is_refused() {
        let r = rig();
        let real = r.dir.path().join("real-program");
        std::fs::rename(&r.plan.gateway_staged, &real).unwrap();
        std::os::unix::fs::symlink(&real, &r.plan.gateway_staged).unwrap();
        assert!(root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).is_err());
    }

    #[test]
    fn an_acl_on_an_existing_release_folder_is_a_change_in_the_preflight_and_root_clears_it() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let bin = r.layout.release_dir(&r.pins.release_id()).join("bin");
        crate::acl::tests::plant(&bin, "everyone allow add_file,delete_child");
        let mut check = Ctx::check();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut check).unwrap();
        assert!(
            check.changes.iter().any(|c| c.contains("access control list") && c.contains("/bin")),
            "{:?}",
            check.changes
        );
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(!crate::acl::has_entries(std::fs::File::open(&bin).unwrap()).unwrap(), "root cleared it");
    }

    #[test]
    fn an_interrupted_rotation_is_finished_on_the_next_install() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let t = r.layout.tls_dir();
        let old_ca = std::fs::read(t.join(CA_CERT)).unwrap();
        // Stopped after the new key was written, before its certificate: the new key is protected, the old
        // certificate (and the leaf and bundle trusting it) are still there, and the marker says so.
        let (_, new_key, _) = Ca::generate("11111111-2222-4333-8444-555555555555").unwrap();
        std::fs::write(t.join(CA_KEY), new_key).unwrap();
        std::fs::write(t.join(ROTATING), b"rotating\n").unwrap();
        let mut check = Ctx::check();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut check).unwrap();
        assert!(check.changes.iter().any(|c| c.contains("finish the CA rotation")), "{:?}", check.changes);
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let ca = std::fs::read(t.join(CA_CERT)).unwrap();
        let key = String::from_utf8(std::fs::read(t.join(CA_KEY)).unwrap()).unwrap();
        assert_ne!(ca, old_ca, "the old CA is no longer trusted");
        assert!(tls::cert_matches_key(&ca, &key).unwrap());
        assert!(tls::leaf_chains_to(&std::fs::read(t.join(LEAF_CERT)).unwrap(), &ca));
        assert!(std::fs::read(t.join(BUNDLE)).unwrap().ends_with(&ca), "the bundle trusts the new CA only");
        assert!(!t.join(ROTATING).exists(), "the rotation is complete");
    }

    #[test]
    fn a_ca_certificate_that_is_not_its_keys_is_refused_and_a_foreign_leaf_is_reissued() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let t = r.layout.tls_dir();
        let (other, _, other_ca) = Ca::generate("99999999-2222-4333-8444-555555555555").unwrap();
        // A leaf from another CA in place of the gateway's: re-issued from this installation's CA.
        let (foreign_leaf, _, _) = other.leaf(&other_ca).unwrap();
        std::fs::write(t.join(LEAF_CERT), foreign_leaf).unwrap();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let ca = std::fs::read(t.join(CA_CERT)).unwrap();
        assert!(tls::leaf_chains_to(&std::fs::read(t.join(LEAF_CERT)).unwrap(), &ca));
        // A CA certificate that does not belong to the key: refused, and nothing is trusted from it.
        std::fs::write(t.join(CA_CERT), other_ca).unwrap();
        let e = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap_err();
        assert!(e.reason.contains("is not the certificate of the installation CA's key"), "{e}");
    }

    /// A rig with the backend adapter pinned (at `version`) and staged, and the enrolled Enclave's inputs.
    pub(crate) fn with_adapter(r: &mut Rig, version: &str) {
        let mut program = fake_program();
        program.extend_from_slice(b" and the adapter");
        let staged = r.layout.home.join("ekka-backend");
        std::fs::write(&staged, &program).unwrap();
        r.pins.adapter = Some(Pinned {
            binary: "ekka-backend".into(),
            archive_url: "https://example.com/a.tar.gz".into(),
            checksums_url: "https://example.com/sums.txt".into(),
            release_asset: "ekka-backend-aarch64-apple-darwin.tar.gz".into(),
            archive_sha256: "a".repeat(64),
            binary_sha256: crate::util::sha256_hex(&program),
        });
        r.pins.adapter_version = Some(version.into());
        r.plan.adapter_staged = Some(staged);
        r.plan.adapter = Some(AdapterInputs {
            node_id: "2f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19".into(),
            govern_keys: vec![crate::adapter::GovernKey {
                key_id: "govern-gate-token-v1".into(),
                public_key_b64: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
            }],
        });
    }

    fn adapter_config(r: &Rig) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(r.layout.adapter_config()).unwrap()).unwrap()
    }

    #[test]
    fn the_adapter_signs_in_with_a_desk_pass_only_for_its_registered_key_and_a_release_that_reads_it() {
        let mut r = rig();
        with_adapter(&mut r, "0.3.0");
        registered(&mut r, owners());
        let key = crate::adapter_key::ensure(&r.layout, owners(), false, None).unwrap();
        let kid = key.state.kid().unwrap().to_string();
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../vendor/ekka-contracts/backend/adapter-config.v1.schema.json"))
                .unwrap();
        let apply = |r: &mut Rig, registered_kid: Option<&str>, rotating: bool, from: Option<&str>| {
            r.plan.registration.as_mut().unwrap().adapter_kid = registered_kid.map(str::to_string);
            r.plan.rotate_adapter_key = rotating;
            r.pins.adapter_signin_from = from.map(str::to_string);
            root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
            let v = adapter_config(r);
            assert_eq!(crate::schema_check::errors(&v, &schema), Vec::<String>::new(), "the whole file, every time");
            v["backend_gateway"]["signin"].clone()
        };
        // Today: no adapter release reads it, so it is never written, even for the registered key.
        assert!(apply(&mut r, Some(&kid), false, None).is_null());
        // A release that reads it, and the registered key: written, naming this installation, this gateway and the key.
        let signin = apply(&mut r, Some(&kid), false, Some("0.3.0"));
        let b = Binding::read(&r.layout.binding()).unwrap().unwrap();
        assert_eq!(
            signin,
            serde_json::json!({"mode": "ekka_desk_pass.v1", "installation_id": b.installation_id, "gateway_id": GATEWAY,
                "key_path": r.layout.backend_dir().join("adapter-key.pem").display().to_string()})
        );
        assert_eq!(adapter_config(&r)["backend_gateway"]["issuer"], identity::issuer("prod", ORG).unwrap());
        // Any one of these missing, and it is taken out again: an older adapter, another key, a key being replaced, no registered kid.
        assert!(apply(&mut r, Some(&kid), false, Some("0.4.0")).is_null(), "the pinned 0.3.0 predates 0.4.0");
        assert!(apply(&mut r, Some("oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"), false, Some("0.3.0")).is_null());
        assert!(apply(&mut r, Some(&kid), true, Some("0.3.0")).is_null());
        assert!(apply(&mut r, None, false, Some("0.3.0")).is_null());
        assert!(apply(&mut r, Some(&kid), false, Some("0.3.0")).is_object());
        r.plan.registration = None;
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(adapter_config(&r)["backend_gateway"]["signin"].is_null(), "not registered: never written");
    }

    /// A dev rig with a developer's local adapter build named by a local build manifest, at its real path.
    fn local_rig() -> (Rig, PathBuf, Vec<u8>) {
        let mut r = rig();
        r.plan.want.env = "dev".into();
        let mut program = fake_program();
        program.extend_from_slice(b" built on this Mac");
        let home = std::fs::canonicalize(&r.layout.home).unwrap();
        let path = home.join("ekka-backend");
        std::fs::write(&path, &program).unwrap();
        r.plan.adapter_staged = Some(path.clone());
        r.plan.local_build = Some(LocalBuild {
            ekka: None,
            ekka_backend: Some(local_build::Program {
                path: path.display().to_string(),
                sha256: crate::util::sha256_hex(&program),
            }),
            desk_image: Some(local_build::Image { image_id: format!("sha256:{}", "c".repeat(64)) }),
        });
        (r, path, program)
    }

    #[test]
    fn a_local_build_is_refused_for_staging_and_prod_before_any_change() {
        for env in ["staging", "prod"] {
            let (mut r, _, _) = local_rig();
            r.plan.want.env = env.into();
            let before = snapshot(r.dir.path());
            for mut ctx in [Ctx::check(), Ctx::apply()] {
                let e = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut ctx).unwrap_err();
                assert!(e.reason.contains("--env dev only"), "{env}: {e}");
                assert!(ctx.changes.is_empty());
            }
            assert_eq!(snapshot(r.dir.path()), before, "{env}: nothing changed");
        }
    }

    #[test]
    fn a_local_adapter_is_installed_only_after_roots_own_hash_matches_and_never_reads_as_a_release() {
        let (r, path, program) = local_rig();
        // Changed after the manifest was written: root's own hash refuses it before any change.
        std::fs::write(&path, b"\xcf\xfa\xed\xfe something else").unwrap();
        let before = snapshot(r.dir.path());
        let e = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap_err();
        assert!(e.reason.contains("the local build's adapter") && e.reason.contains("nothing was changed"), "{e}");
        assert_eq!(snapshot(r.dir.path()), before, "refused before any change");
        // The manifest's bytes: installed like a release, and said to be a local build wherever root writes.
        std::fs::write(&path, &program).unwrap();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let pins = r.pins.with_local(r.plan.local_build.as_ref());
        let rel = r.layout.release_dir(&pins.release_id());
        assert_eq!(std::fs::read(rel.join("bin/ekka-backend")).unwrap(), program);
        let release: serde_json::Value =
            serde_json::from_slice(&std::fs::read(rel.join("release.json")).unwrap()).unwrap();
        assert_eq!(release["source"], "local-build");
        let marker = std::fs::read(r.layout.records().join(local_build::MARKER)).unwrap();
        assert_eq!(local_build::read_marker(Some(marker)).unwrap(), r.plan.local_build);
        let image: serde_json::Value =
            serde_json::from_slice(&std::fs::read(r.layout.records().join(records::IMAGE)).unwrap()).unwrap();
        assert_eq!(image, serde_json::json!({"image": "ekka-desk:local", "id": format!("sha256:{}", "c".repeat(64))}));
        let mut check = Ctx::check();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut check).unwrap();
        assert!(check.changes.is_empty(), "a second install changes nothing: {:?}", check.changes);
        // Back to releases: the marker goes, and the image nobody pinned is taken out of use.
        let mut release_plan = r.plan.clone();
        release_plan.local_build = None;
        release_plan.adapter_staged = None;
        root_apply(&release_plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(!r.layout.records().join(local_build::MARKER).exists());
        assert!(!r.layout.records().join(records::IMAGE).exists());
    }

    #[test]
    fn status_says_local_build_loudly_for_each_replaced_part() {
        let (r, _, _) = local_rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let s = crate::status::status_with(&r.layout, &r.pins, None, owners());
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["local_build"]["notice"], "LOCAL BUILD, NOT A SIGNED RELEASE (dev only)");
        assert_eq!(v["local_build"]["source"], "local-build");
        assert!(v["local_build"]["ekka_backend"]["sha256"].is_string() && v["local_build"]["desk_image"].is_object());
        let lines = s.local_build.as_ref().unwrap().lines();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| l.starts_with("LOCAL BUILD, NOT A SIGNED RELEASE (dev only)")), "{lines:?}");
        let release = s.checks.iter().find(|c| c.id == "release").unwrap();
        assert!(
            !release.reason.as_deref().unwrap_or("").contains("current is"),
            "the local release is the one expected: {release:?}"
        );
        // A release install shows none.
        let plain = rig();
        root_apply(&plain.plan, &plain.layout, owners(), &plain.pins, &plain.roots, &mut Ctx::apply()).unwrap();
        let v = serde_json::to_value(crate::status::status_with(&plain.layout, &plain.pins, None, owners())).unwrap();
        assert!(v.get("local_build").is_none());
    }

    /// Root reads what the developer staged one folder at a time, never through a link anywhere on the way: a folder
    /// on the path swapped for a link is refused, even when the program behind it is the pinned one.
    #[test]
    fn a_staged_program_reached_through_a_linked_folder_is_refused() {
        let mut r = rig();
        let real = r.layout.home.join("real-cache");
        std::fs::create_dir(&real).unwrap();
        std::fs::copy(&r.plan.gateway_staged, real.join("openshell-gateway")).unwrap();
        std::os::unix::fs::symlink(&real, r.layout.home.join("cache-link")).unwrap();
        r.plan.gateway_staged = r.layout.home.join("cache-link/openshell-gateway");
        let e = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap_err();
        assert!(e.reason.contains("is a link"), "{e}");
        let bin = r.layout.release_dir(&r.pins.release_id()).join("bin/openshell-gateway");
        assert!(!bin.exists(), "nothing was installed from behind the link");
    }

    /// Root decides the sign-in from the key it reads itself, under the install lock, never from what the plan says.
    #[test]
    fn the_sign_in_follows_the_key_root_reads_not_the_plan() {
        let mut r = rig();
        with_adapter(&mut r, "0.3.0");
        registered(&mut r, owners());
        r.pins.adapter_signin_from = Some("0.3.0".into());
        let kid =
            crate::adapter_key::ensure(&r.layout, owners(), false, None).unwrap().state.kid().unwrap().to_string();
        r.plan.registration.as_mut().unwrap().adapter_kid = Some(kid.clone());
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(adapter_config(&r)["backend_gateway"]["signin"].is_object(), "the registered key is on disk");
        // Another key on disk than the one Govern registered: taken out, whatever the plan says.
        crate::adapter_key::ensure(&r.layout, owners(), true, None).unwrap();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(adapter_config(&r)["backend_gateway"]["signin"].is_null());
        // A key root cannot use as it is (readable by others): no sign-in.
        crate::adapter_key::ensure(&r.layout, owners(), true, None).unwrap();
        let key = r.layout.backend_dir().join(crate::adapter_key::KEY_FILE);
        let kid = crate::adapter_key::inspect(&r.layout, owners()).kid().unwrap().to_string();
        r.plan.registration.as_mut().unwrap().adapter_kid = Some(kid);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(adapter_config(&r)["backend_gateway"]["signin"].is_null());
    }

    /// The adapter opens its key one folder at a time from `/`, refusing a link: `/var` is one on a Mac, so the
    /// path written is the real one.
    #[test]
    fn the_adapter_key_path_is_the_real_private_var_path() {
        let l = Layout::system(501, PathBuf::from("/Users/dev"));
        let mut r = rig();
        with_adapter(&mut r, "0.3.0");
        let b = registered(&mut r, owners());
        let mut reg = r.plan.registration.clone().unwrap();
        reg.adapter_kid = Some("oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U".into());
        r.pins.adapter_signin_from = Some("0.3.0".into());
        let s = crate::adapter::signin(&l, &b, Some(&reg), reg.adapter_kid.as_deref(), &r.pins).unwrap();
        assert_eq!(s.key_path, "/private/var/db/ekka-dev/501/backend/adapter-key.pem");
        let cfg = crate::adapter::config_bytes(
            &l,
            ORG,
            r.plan.adapter.as_ref().unwrap(),
            &identity::issuer("prod", ORG).unwrap(),
            Some(&s),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&cfg).unwrap();
        assert_eq!(v["backend_gateway"]["signin"]["key_path"], "/private/var/db/ekka-dev/501/backend/adapter-key.pem");
        assert!(!String::from_utf8(cfg).unwrap().contains("\"/var/"), "never through the /var link");
        let issuer = identity::issuer("prod", ORG).unwrap();
        let mut wrong = s.clone();
        wrong.key_path = "/var/db/ekka-dev/501/backend/adapter-key.pem".into();
        assert!(crate::adapter::config_bytes(&l, ORG, r.plan.adapter.as_ref().unwrap(), &issuer, Some(&wrong)).is_err());
        let keycloak = "https://desks.example.com/realms/ekka-desks";
        assert!(crate::adapter::config_bytes(&l, ORG, r.plan.adapter.as_ref().unwrap(), keycloak, Some(&s)).is_err());
    }

    #[test]
    fn without_this_installations_registration_the_gateways_trust_configuration_is_removed() {
        let mut r = rig();
        let b = registered(&mut r, owners());
        let record = r.layout.d().join(registration::RECORD);
        let rec: registration::Record = serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        assert_eq!((rec.gateway_id.as_str(), rec.installation_id.as_str()), (GATEWAY, b.installation_id.as_str()));
        assert_eq!(rec.issuer, identity::issuer("prod", ORG).unwrap());
        // Another installation's registration (another gateway in the same organization): not used, and the
        // configuration made from the earlier one is removed with it.
        let mut other = crate::registration::tests::answer(&b);
        other["gateway"]["installation_id"] = "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d".into();
        let mut foreign = r.plan.clone();
        foreign.registration = Some(Registration::from_answer(&other).unwrap());
        let mut check = Ctx::check();
        root_apply(&foreign, &r.layout, owners(), &r.pins, &r.roots, &mut check).unwrap();
        assert!(
            check.changes.iter().any(|c| c.contains("remove") && c.contains("gateway.toml")),
            "{:?}",
            check.changes
        );
        root_apply(&foreign, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(!r.layout.gateway_toml().exists() && !record.exists());
        // Registered again, then no registration at all: removed again, never left in place.
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(r.layout.gateway_toml().exists());
        let mut none = r.plan.clone();
        none.registration = None;
        root_apply(&none, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(!r.layout.gateway_toml().exists() && !record.exists());
    }

    #[test]
    fn a_trust_change_leaves_a_root_owned_restart_marker_until_the_developers_side_confirms() {
        let mut r = rig();
        registered(&mut r, owners());
        let marker = r.layout.run_dir().join(registration::RESTART_PENDING);
        let read =
            || -> registration::RestartPending { serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap() };
        assert_eq!(read().action, "restart", "the registration changed what the gateway trusts");
        let fd = |p: PathBuf| fsx::open_trusted_dir(&p, &r.layout.top, me().uid, None).ok();
        let (d, tls, jwt) = (fd(r.layout.d()), fd(r.layout.tls_dir()), fd(r.layout.jwt_dir()));
        assert_eq!(read().trust_digest, registration::trust_digest_at(d.as_ref(), tls.as_ref(), jwt.as_ref()).unwrap());
        // Confirmed by launchd on the developer's side: removed there. A same-org retry then changes nothing.
        std::fs::remove_file(&marker).unwrap();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(!marker.exists());
        // The registration taken away: the configuration goes, and the gateway must stop.
        let mut none = r.plan.clone();
        none.registration = None;
        root_apply(&none, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert_eq!(read().action, "stop");
        // A malformed or production registration stops it the same way, with no error before the cleanup.
        registered(&mut r, owners());
        let mut prod = crate::registration::tests::answer(&Binding::read(&r.layout.binding()).unwrap().unwrap());
        prod["gateway"]["gateway_id"] = "urn:ekka:desk-gateway:production:0b6f4a52-1c3d-4e5f-8a9b-0c1d2e3f4a5b".into();
        let mut bad = r.plan.clone();
        bad.registration = Some(Registration::from_answer(&prod).unwrap());
        root_apply(&bad, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(!r.layout.gateway_toml().exists());
        assert_eq!(read().action, "stop");
    }

    #[test]
    fn a_legacy_binding_anyone_else_could_have_written_is_refused() {
        let r = rig();
        plant_legacy(&r.layout, me().uid, ORG);
        std::fs::set_permissions(r.layout.d().join(LEGACY_BINDING), std::fs::Permissions::from_mode(0o666)).unwrap();
        let e = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::check()).unwrap_err();
        assert!(e.reason.contains("is not trusted"), "{e}");
        std::fs::set_permissions(r.layout.d().join(LEGACY_BINDING), std::fs::Permissions::from_mode(0o644)).unwrap();
        crate::acl::tests::plant(&r.layout.d(), "everyone allow add_file,delete_child");
        assert!(root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::check()).is_err());
    }

    #[test]
    fn rotate_ca_always_rotates_even_a_protected_key_with_the_wrong_certificate() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let (_, _, other_ca) = Ca::generate("99999999-2222-4333-8444-555555555555").unwrap();
        std::fs::write(r.layout.tls_dir().join(CA_CERT), other_ca).unwrap();
        let mut rotate = r.plan.clone();
        rotate.rotate_ca = true;
        root_apply(&rotate, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let ca = std::fs::read(r.layout.tls_dir().join(CA_CERT)).unwrap();
        let key = String::from_utf8(std::fs::read(r.layout.tls_dir().join(CA_KEY)).unwrap()).unwrap();
        assert!(tls::cert_matches_key(&ca, &key).unwrap());
    }

    /// An earlier install's ceiling with a CPU and memory limit, as a profile that sets one writes it.
    fn plant_limited_ceiling(l: &Layout) -> Vec<u8> {
        let bytes = records::ceiling_bytes(Some(Resources { max_cpu_millicores: 4000, max_memory_mib: 8192 })).unwrap();
        std::fs::write(l.records().join(records::CEILING), &bytes).unwrap();
        bytes
    }

    #[test]
    fn a_developer_mac_plan_naming_a_desk_limit_is_refused_before_any_write() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let before = snapshot(r.dir.path());
        let mut limited = r.plan.clone();
        limited.resources = Some(Resources { max_cpu_millicores: 2000, max_memory_mib: 4096 });
        for mut ctx in [Ctx::check(), Ctx::apply()] {
            let e = root_apply(&limited, &r.layout, owners(), &r.pins, &r.roots, &mut ctx).unwrap_err();
            assert!(e.reason.contains("no CPU or memory limit of its own"), "{e}");
        }
        assert_eq!(snapshot(r.dir.path()), before);
    }

    #[test]
    fn going_from_a_limit_to_none_needs_raise_ceiling_and_is_logged_before_it_is_written() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let limited = plant_limited_ceiling(&r.layout);
        for mut ctx in [Ctx::check(), Ctx::apply()] {
            let e = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut ctx).unwrap_err();
            assert!(e.reason.contains("--raise-ceiling"), "{e}");
        }
        assert_eq!(std::fs::read(r.layout.records().join(records::CEILING)).unwrap(), limited);
        // Asked by name, with the records write failing at its first file: the raise is on record first.
        let base = r.layout.records().join(records::BASELINE);
        std::fs::remove_file(&base).unwrap();
        std::fs::create_dir(&base).unwrap();
        let mut raise = r.plan.clone();
        raise.raise_ceiling = true;
        assert!(root_apply(&raise, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).is_err());
        let log = std::fs::read_to_string(r.layout.ekka_dev().join(CEILING_RAISES)).unwrap();
        assert!(log.contains("\"to\":null"), "{log}");
        std::fs::remove_dir(&base).unwrap();
        root_apply(&raise, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(r.layout.records().join(records::CEILING)).unwrap()).unwrap();
        assert!(v.get("resources").is_none());
    }

    #[test]
    fn the_restart_marker_is_written_before_the_first_trust_change_and_survives_a_stop_part_way() {
        let mut r = rig();
        let b = registered(&mut r, owners());
        let marker = r.layout.run_dir().join(registration::RESTART_PENDING);
        std::fs::remove_file(&marker).unwrap(); // the developer's side confirmed the first start
                                                // Another valid registration for this installation: the record changes, then the step stops.
        let mut other = crate::registration::tests::answer(&b);
        let id = "urn:ekka:desk-gateway:development:1b6f4a52-1c3d-4e5f-8a9b-0c1d2e3f4a5b";
        other["gateway"]["gateway_id"] = id.into();
        other["gateway"]["oidc"]["audience"] = id.into();
        let mut next = r.plan.clone();
        next.registration = Some(Registration::from_answer(&other).unwrap());
        CRASH_AFTER_RECORD.with(|c| c.set(true));
        let stopped = root_apply(&next, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply());
        CRASH_AFTER_RECORD.with(|c| c.set(false));
        assert!(stopped.is_err());
        assert!(marker.exists(), "a step stopped after changing what the gateway trusts still asks for a restart");
    }

    #[test]
    fn a_fifo_or_link_in_place_of_a_trust_file_is_refused_never_read() {
        let mut r = rig();
        registered(&mut r, owners());
        let toml = r.layout.gateway_toml();
        std::fs::remove_file(&toml).unwrap();
        let c = std::ffi::CString::new(toml.display().to_string()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let (plan, layout, pins, roots) = (r.plan.clone(), r.layout.clone(), r.pins.clone(), r.roots.clone());
        std::thread::spawn(move || {
            let _ = tx.send(root_apply(&plan, &layout, owners(), &pins, &roots, &mut Ctx::apply()).is_err());
        });
        assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(10)), Ok(true), "refused, and never hung");
        std::fs::remove_file(&toml).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", &toml).unwrap();
        assert!(root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).is_err());
    }

    /// A binding as the first release wrote it, in `ekka-dev/<uid>/`.
    fn plant_legacy(l: &Layout, uid: u32, org: &str) -> Binding {
        let dir = l.ekka_dev().join(uid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        for p in
            [l.top.join("private"), l.top.join("private/var"), l.top.join("private/var/db"), l.ekka_dev(), dir.clone()]
        {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let want = Want { uid, org: org.into(), ..rig().plan.want };
        let b = want.new_binding().unwrap();
        std::fs::write(dir.join(LEGACY_BINDING), b.bytes()).unwrap();
        b
    }

    #[test]
    fn a_legacy_binding_for_another_developer_or_organization_is_refused_before_any_change() {
        for (uid, org) in [(me().uid + 1, ORG), (me().uid, FOREIGN)] {
            let r = rig();
            plant_legacy(&r.layout, uid, org);
            let before = snapshot(r.dir.path());
            for mut ctx in [Ctx::check(), Ctx::apply()] {
                let e = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut ctx).unwrap_err();
                assert_eq!(e.kind, crate::error::Kind::Refused, "{e}");
                assert!(ctx.changes.is_empty());
            }
            // Only the lock the refusal was made under: nothing else was made or changed.
            let after = snapshot(r.dir.path());
            let made: Vec<_> = after.keys().filter(|k| !before.contains_key(*k)).collect();
            assert!(made.iter().all(|k| k.ends_with(".install.lock")), "{made:?}");
            assert!(before.iter().all(|(k, v)| after.get(k) == Some(v) || k.is_dir()), "nothing changed");
        }
    }

    #[test]
    fn this_developers_legacy_binding_is_carried_over_and_retired() {
        let r = rig();
        let old = plant_legacy(&r.layout, me().uid, ORG);
        let b = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert_eq!(b.installation_id, old.installation_id, "the same installation, its id kept");
        assert_eq!(Binding::read(&r.layout.binding()).unwrap().unwrap().installation_id, old.installation_id);
        assert!(!r.layout.d().join(LEGACY_BINDING).exists(), "the per-developer binding is retired");
    }

    #[test]
    fn an_image_record_nobody_pinned_is_taken_out_of_use_and_kept() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let image = r.layout.records().join(records::IMAGE);
        std::fs::write(&image, b"{\"image\":\"ekka-desk:local\",\"id\":\"sha256:1\"}\n").unwrap();
        let mut check = Ctx::check();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut check).unwrap();
        assert!(check.changes.iter().any(|c| c.contains("out of use")), "{:?}", check.changes);
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert!(!image.exists(), "no unpinned image record is left where the runner reads it");
        let kept: Vec<_> = std::fs::read_dir(r.layout.records())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("desk-image.json.unpinned-"))
            .collect();
        assert_eq!(kept.len(), 1, "kept as evidence");
    }

    #[test]
    fn an_install_stopped_after_the_ca_key_finishes_with_the_same_key() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let key = std::fs::read(r.layout.tls_dir().join(CA_KEY)).unwrap();
        std::fs::remove_file(r.layout.tls_dir().join(CA_CERT)).unwrap();
        let mut ctx = Ctx::apply();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut ctx).unwrap();
        assert_eq!(std::fs::read(r.layout.tls_dir().join(CA_KEY)).unwrap(), key, "the CA key is kept");
        assert!(r.layout.tls_dir().join(CA_CERT).exists());
        let meta: LeafMeta =
            serde_json::from_slice(&std::fs::read(r.layout.tls_dir().join(LEAF_META)).unwrap()).unwrap();
        let ca = std::fs::read(r.layout.tls_dir().join(CA_CERT)).unwrap();
        assert_eq!(meta.ca_sha256, crate::util::sha256_hex(&ca), "the gateway certificate follows the CA file");
    }

    #[test]
    fn a_plan_that_is_not_well_formed_is_refused() {
        // (A production or malformed registration is not refused here: it fails closed, its trust removed; see
        // a_trust_change_leaves_a_root_owned_restart_marker_until_the_developers_side_confirms.)
        let r = rig();
        let mut p = r.plan.clone();
        p.gateway_staged = PathBuf::from("relative/path");
        assert!(root_apply(&p, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::check()).is_err());
        let mut p = r.plan.clone();
        p.want.env = "local".into();
        assert!(root_apply(&p, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::check()).is_err());
    }

    /// The gateway's issuer, roles and audience in an installed gateway.toml.
    fn oidc_of(l: &Layout) -> toml::Table {
        let t: toml::Table = std::fs::read_to_string(l.gateway_toml()).unwrap().parse().unwrap();
        t["openshell"]["gateway"]["oidc"].as_table().unwrap().clone()
    }

    #[test]
    fn the_gateway_trusts_only_the_computed_issuer_and_a_plan_naming_another_changes_nothing() {
        let mut r = rig();
        registered(&mut r, owners());
        let o = oidc_of(&r.layout);
        assert_eq!(o["issuer"].as_str(), Some(format!("https://govern.ekka.ai/oidc/orgs/{ORG}").as_str()));
        assert_eq!(o["audience"].as_str(), Some(GATEWAY));
        assert_eq!(o["roles_claim"].as_str(), Some("ekka_roles.development"));
        let before = std::fs::read(r.layout.gateway_toml()).unwrap();
        // A plan carrying its own issuer, as the previous plan format did, is not a plan root reads.
        let mut forged = serde_json::to_value(&r.plan).unwrap();
        forged["oidc"] = serde_json::json!({"issuer": "https://attacker.example.com/oidc/orgs/x", "audience": "x",
            "roles_claim": "r", "admin_role": "a", "user_role": "u", "scopes_claim": "scope", "jwks_ttl_secs": 300});
        assert!(serde_json::from_value::<RootPlan>(forged).is_err());
        assert_eq!(std::fs::read(r.layout.gateway_toml()).unwrap(), before, "gateway.toml unchanged");
    }

    #[test]
    fn a_ceiling_above_the_compiled_in_maxima_is_refused_and_no_local_image_is_ever_recorded() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let ceiling = std::fs::read(r.layout.records().join(records::CEILING)).unwrap();
        let mut wide = r.plan.clone();
        wide.resources = Some(Resources { max_cpu_millicores: 64_000, max_memory_mib: 262_144 });
        // On a developer's Mac any limit in the plan is refused, before any write (the caps hold for other profiles).
        for mut ctx in [Ctx::check(), Ctx::apply()] {
            assert!(root_apply(&wide, &r.layout, owners(), &r.pins, &r.roots, &mut ctx).is_err());
        }
        assert_eq!(std::fs::read(r.layout.records().join(records::CEILING)).unwrap(), ceiling);
        // The plan has no way to name a desk image: only a pinned, published one is ever recorded.
        let mut forged = serde_json::to_value(&r.plan).unwrap();
        forged["desk_image_id"] = format!("sha256:{}", "e".repeat(64)).into();
        assert!(serde_json::from_value::<RootPlan>(forged).is_err());
        assert!(!r.layout.records().join(records::IMAGE).exists());
        let mut pins = r.pins.clone();
        pins.desk_image = Some(crate::release::DeskImagePin {
            image: format!("ghcr.io/example/desk@sha256:{}", "1".repeat(64)),
            image_id: format!("sha256:{}", "2".repeat(64)),
        });
        root_apply(&r.plan, &r.layout, owners(), &pins, &r.roots, &mut Ctx::apply()).unwrap();
        let rec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(r.layout.records().join(records::IMAGE)).unwrap()).unwrap();
        assert_eq!(rec["id"], format!("sha256:{}", "2".repeat(64)), "the pinned content id, and only that");
    }

    #[test]
    fn a_second_developer_or_organization_is_refused_before_any_shared_path_changes() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let before = snapshot(r.dir.path());
        // Another developer on the same Mac (another uid, so another D), even for the same organization, and
        // another developer for another organization: both would share the records, the release and `current`.
        let other_uid = me().uid + 1;
        for org in [ORG, FOREIGN] {
            let mut second = r.plan.clone();
            second.want.uid = other_uid;
            second.want.org = org.into();
            let layout = Layout { uid: other_uid, ..r.layout.clone() };
            for mut ctx in [Ctx::check(), Ctx::apply()] {
                let e = root_apply(&second, &layout, owners(), &r.pins, &r.roots, &mut ctx).unwrap_err();
                assert_eq!(e.kind, crate::error::Kind::Refused, "{e}");
                assert!(e.reason.contains("One installation per Mac"), "{e}");
                assert!(ctx.changes.is_empty());
            }
        }
        assert_eq!(snapshot(r.dir.path()), before, "no shared record, release or link changed");
    }

    #[test]
    fn an_exposed_ca_key_is_never_used_again_and_rotation_replaces_ca_and_certificate() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let key = r.layout.tls_dir().join(CA_KEY);
        let (old_key, old_ca) =
            (std::fs::read(&key).unwrap(), std::fs::read(r.layout.tls_dir().join(CA_CERT)).unwrap());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let before = snapshot(r.dir.path());
        for mut ctx in [Ctx::check(), Ctx::apply()] {
            let e = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut ctx).unwrap_err();
            assert!(e.reason.contains("--rotate-ca") && e.reason.contains("mode 644"), "{e}");
        }
        assert_eq!(snapshot(r.dir.path()), before, "refused: nothing used, nothing changed");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        crate::acl::tests::plant(&key, "everyone allow read");
        assert!(root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::check())
            .unwrap_err()
            .reason
            .contains("read or change"));
        let mut rotate = r.plan.clone();
        rotate.rotate_ca = true;
        root_apply(&rotate, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        assert_ne!(std::fs::read(&key).unwrap(), old_key, "a new CA key");
        let ca = std::fs::read(r.layout.tls_dir().join(CA_CERT)).unwrap();
        assert_ne!(ca, old_ca, "a new CA certificate");
        let fd = std::fs::File::open(&key).unwrap();
        assert!(!crate::acl::has_entries(&fd).unwrap(), "the new key carries no ACL");
        let meta: LeafMeta =
            serde_json::from_slice(&std::fs::read(r.layout.tls_dir().join(LEAF_META)).unwrap()).unwrap();
        assert_eq!(meta.ca_sha256, crate::util::sha256_hex(&ca), "the gateway certificate is from the new CA");
        // And once rotated, an ordinary install changes nothing.
        let mut again = Ctx::apply();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut again).unwrap();
        assert!(again.changes.is_empty(), "{:?}", again.changes);
    }

    /// As root (CI runs this with sudo; never on a developer's Mac): what root writes, the developer who ran
    /// sudo cannot replace, and the CA key is root's alone. Each attempt is a real program run as that developer.
    #[test]
    #[ignore = "needs root: CI runs it with sudo"]
    fn root_a_developer_cannot_replace_a_record_nor_read_the_ca_key() {
        use std::os::unix::process::CommandExt;
        assert_eq!(rustix::process::geteuid().as_raw(), 0, "run with sudo");
        let dev_uid: u32 = std::env::var("SUDO_UID").expect("run with sudo").parse().unwrap();
        let dev = crate::platform::macos::user_by_uid(dev_uid).unwrap();
        // Under /private/tmp, not root's own temporary folder, which the developer cannot enter: a refusal must
        // come from what install wrote, never from a folder above it. The two allowed reads below prove that.
        let dir = tempfile::Builder::new().tempdir_in("/private/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut r = rig();
        let top = dir.path().join("root");
        std::fs::create_dir(&top).unwrap();
        std::fs::set_permissions(&top, std::fs::Permissions::from_mode(0o755)).unwrap();
        r.layout = Layout { top, uid: dev.uid, home: dev.home.clone() };
        r.plan.want.uid = dev.uid;
        let owners = Owners { root: Owner { uid: 0, gid: 0 }, dev: Owner { uid: dev.uid, gid: dev.gid } };
        registered(&mut r, owners);

        let as_dev = |prog: &str, args: &[&std::path::Path]| {
            std::process::Command::new(prog)
                .args(args)
                .uid(dev.uid)
                .gid(dev.gid)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        };
        let l = &r.layout;
        let ceiling = l.records().join(records::CEILING);
        let before = std::fs::read(&ceiling).unwrap();
        assert!(!as_dev("/bin/cp", &[Path::new("/etc/hosts"), &ceiling]), "overwrite a record");
        assert!(!as_dev("/bin/mv", &[&ceiling, &l.records().join("moved.json")]), "rename a record away");
        assert!(!as_dev("/usr/bin/touch", &[&l.records().join("planted.json")]), "plant a record");
        assert!(!as_dev("/bin/rm", &[&ceiling]), "remove a record");
        assert_eq!(std::fs::read(&ceiling).unwrap(), before);
        assert!(!as_dev("/bin/cat", &[&l.tls_dir().join(CA_KEY)]), "read the CA key");
        assert!(!as_dev("/bin/cp", &[Path::new("/etc/hosts"), &l.gateway_toml()]), "widen the gateway config");
        assert!(!as_dev("/usr/bin/touch", &[&l.d().join("planted")]), "write in D itself");
        assert!(as_dev("/bin/cat", &[&l.tls_dir().join(LEAF_KEY)]), "the developer's gateway reads its own key");
        assert!(
            as_dev("/usr/bin/touch", &[&l.gateway_dir().join("state/x")]),
            "the developer's gateway writes its state"
        );
        // And the runner's way of reading them passes: a walk from the top, every folder root's, no links.
        fsx::open_trusted_dir(&l.records(), &l.top, 0, None).unwrap();
        // A second install as root changes nothing.
        let mut again = Ctx::apply();
        root_apply(&r.plan, &r.layout, owners, &r.pins, &r.roots, &mut again).unwrap();
        assert!(again.changes.is_empty(), "{:?}", again.changes);
    }
}
