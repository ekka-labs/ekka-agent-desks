//! The one step that runs as root, and the same step as a check that changes nothing.
//!
//! `install` works out everything as the developer first: downloads checked, images pulled, the desk image built.
//! It then runs this step as a check (as the developer, reading only what anyone may read) and asks for root only
//! when something root owns would change. So a second install with the same organization asks for nothing and
//! changes nothing. As root, this step takes a lock, refuses a foreign binding before any change, and then writes
//! the binding, the developer's folders, the certificates, the gateway and adapter configuration, the verified
//! programs, the `current` link and the records. Root never runs a staged program: it copies the bytes and hashes
//! the copy it made against the pin embedded in this binary.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::adapter::{self, AdapterInputs};
use crate::binding::{Binding, Want};
use crate::error::{errno, failed, refused, Result};
use crate::fsx::{self, ensure_dir, walk_trusted, Owner, Walk, Wrote, DIR_FLAGS};
use crate::gateway_config;
use crate::identity::Gateway;
use crate::platform::macos::{
    Layout, BUNDLE, CA_CERT, CA_KEY, JWT_KID, JWT_PUBLIC, JWT_SIGNING, LEAF_CERT, LEAF_KEY, LEAF_META,
};
use crate::records::{self, Resources};
use crate::release::{verify_binary, Pinned, Pins};
use crate::tls::{bundle, Ca, JwtKeys, LeafMeta};
use crate::util::is_digest;

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
    pub desk_image_id: String,
    pub resources: Resources,
    pub oidc: Gateway,
    pub adapter: Option<AdapterInputs>,
}

pub const PLAN_SCHEMA: &str = "ekka-desk-host.root-plan/v1";

impl RootPlan {
    pub fn check(&self, pins: &Pins) -> Result<()> {
        if self.schema != PLAN_SCHEMA {
            return Err(refused(format!("the root plan is not {PLAN_SCHEMA}")));
        }
        self.want.check()?;
        self.oidc.check(&self.want.org)?;
        if !is_digest(&self.desk_image_id) {
            return Err(refused("the desk image id is not sha256:<64 lowercase hex>"));
        }
        self.resources.check()?;
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
    root: Owner,
) -> Result<()> {
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
    let fd =
        rustix::fs::open(staged, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, Mode::empty())
            .map_err(|e| errno(format!("opening the staged {}", pin.binary), e))?;
    let bytes = fsx::read_regular(fd, &pin.binary, MAX_PROGRAM)?;
    verify_binary(pin, &bytes)?;
    ctx.file(bin, bin_path, &pin.binary, &bytes, 0o755, root)
}

#[derive(Serialize)]
struct ReleaseRecord<'a> {
    schema: &'static str,
    release: &'a str,
    openshell_version: &'a str,
    gateway: &'a Pinned,
    adapter: Option<&'a Pinned>,
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
    plan.check(pins)?;
    let (root, dev) = (owners.root, owners.dev);
    let top = &l.top;

    // Refused before any change: an installation bound to anything else.
    let existing = Binding::read(&l.binding())?;
    if let Some(b) = &existing {
        b.check_same(&plan.want)?;
    }
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
        Some(fd)
    };
    // Again under the lock: another install may have bound it in between.
    let existing = match (existing, Binding::read(&l.binding())?) {
        (_, Some(now)) => {
            now.check_same(&plan.want)?;
            Some(now)
        }
        (before, None) => before,
    };
    let binding = match existing {
        Some(b) => b,
        None => plan.want.new_binding()?,
    };

    let d = l.d();
    let dfd = ctx.trusted_dir(top, &d, root.uid, 0o755)?;
    ctx.file(dfd.as_ref(), &d, "binding.json", &binding.bytes(), 0o644, root)?;

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

    // Certificates: the CA key root's alone; the gateway's key the developer's, who runs the gateway.
    let tls_path = l.tls_dir();
    let tls = ctx.sub_dir(dfd.as_ref(), &d, "tls", 0o755, root)?;
    let jwt = ctx.sub_dir(tls.as_ref(), &tls_path, "jwt", 0o755, root)?;
    let mut ca: Option<Ca> = None;
    let mut ca_pem: Option<Vec<u8>> = read(tls.as_ref(), CA_CERT, 64 * 1024)?;
    if !exists(tls.as_ref(), CA_KEY)? {
        if ctx.checking() {
            ctx.note(format!("make the installation CA in {}", tls_path.display()));
            ca_pem = None;
        } else {
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
                || !exists(tls.as_ref(), LEAF_CERT)?
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

    // The gateway's and the adapter's configuration: root's, so a developer's process cannot widen them.
    let gateway_toml = gateway_config::render(l, &plan.oidc, &l.docker_socket(), pins)?;
    ctx.file(dfd.as_ref(), &d, "gateway.toml", gateway_toml.as_bytes(), 0o644, root)?;
    if let Some(inputs) = &plan.adapter {
        let cfg = adapter::config_bytes(l, &binding.org, inputs, &plan.oidc.issuer)?;
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
    program(ctx, bin.as_ref(), &bin_path, &pins.gateway, &plan.gateway_staged, root)?;
    if let (Some(pin), Some(staged)) = (&pins.adapter, &plan.adapter_staged) {
        program(ctx, bin.as_ref(), &bin_path, pin, staged, root)?;
    }
    let record = ReleaseRecord {
        schema: "ekka-desk-host.release/v1",
        release: &release,
        openshell_version: &pins.openshell_version,
        gateway: &pins.gateway,
        adapter: pins.adapter.as_ref().filter(|_| plan.adapter_staged.is_some()),
    };
    let mut rec = serde_json::to_vec_pretty(&record).map_err(|e| failed(e.to_string()))?;
    rec.push(b'\n');
    ctx.file(rel.as_ref(), &rel_path, "release.json", &rec, 0o644, root)?;
    ctx.link(ofd.as_ref(), &opt, "current", &format!("releases/{release}"))?;

    // The records EKKA's desk commands build a grant from.
    records::write(ctx, top, &l.records(), root, &plan.desk_image_id, plan.resources)?;
    Ok(binding)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    pub(crate) const ORG: &str = "7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7";
    const FOREIGN: &str = "0d0e0f10-1112-4314-8516-171819202122";

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
        let top = dir.path().join("root");
        std::fs::create_dir(&top).unwrap();
        std::fs::set_permissions(&top, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let staged = home.join("openshell-gateway");
        std::fs::write(&staged, fake_program()).unwrap();
        let mut pins = Pins::embedded().unwrap();
        pins.gateway.binary_sha256 = crate::util::sha256_hex(&fake_program());
        let layout = Layout { top, uid: me().uid, home };
        let profile =
            crate::identity::Profile::parse(include_str!("../../deploy/macos/identity-profile.sample.json")).unwrap();
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
            desk_image_id: format!("sha256:{}", "e".repeat(64)),
            resources: Resources { max_cpu_millicores: 4000, max_memory_mib: 8192 },
            oidc: profile.gateway,
            adapter: None,
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
        let r = rig();
        let mut first = Ctx::apply();
        let b = root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut first).unwrap();
        assert_eq!(b.org, ORG);
        assert!(first.changes.len() > 20, "{:?}", first.changes);

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
        foreign.oidc.issuer = format!("https://govern.example.com/oidc/orgs/{FOREIGN}");
        foreign.desk_image_id = format!("sha256:{}", "f".repeat(64));
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
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
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
        for rec in [records::BASELINE, records::IMAGE, records::CEILING] {
            assert_eq!(mode(l.records().join(rec)), 0o644);
        }
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
    fn a_new_ceiling_is_one_change_and_the_ca_is_kept() {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let ca = std::fs::read(r.layout.tls_dir().join(CA_CERT)).unwrap();
        let mut plan = r.plan.clone();
        plan.resources.max_memory_mib = 4096;
        let mut ctx = Ctx::apply();
        root_apply(&plan, &r.layout, owners(), &r.pins, &r.roots, &mut ctx).unwrap();
        assert_eq!(ctx.changes.len(), 1, "{:?}", ctx.changes);
        assert_eq!(std::fs::read(r.layout.tls_dir().join(CA_CERT)).unwrap(), ca, "the CA is never remade");
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
        let r = rig();
        let mut p = r.plan.clone();
        p.desk_image_id = "ekka-desk:local".into();
        assert!(root_apply(&p, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::check()).is_err());
        let mut p = r.plan.clone();
        p.gateway_staged = PathBuf::from("relative/path");
        assert!(root_apply(&p, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::check()).is_err());
        let mut p = r.plan.clone();
        p.oidc.issuer = "http://insecure.example.com".into();
        assert!(root_apply(&p, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::check()).is_err());
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
        root_apply(&r.plan, &r.layout, owners, &r.pins, &r.roots, &mut Ctx::apply()).unwrap();

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
