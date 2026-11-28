//! `ekka-desk-host`: installs and checks one EKKA desk host. With `ekka`, it is one of the two programs an
//! installation runs: no shell script, no Python, no Compose and no OpenShell command line. It installs NVIDIA's
//! OpenShell gateway and EKKA's backend adapter as verified programs, writes the root-owned records EKKA's desk
//! commands read, and runs the Enclave, the gateway and the adapter as the developer's own services.

mod acl;
mod adapter;
mod adapter_key;
mod apply;
mod binding;
mod bootstrap;
mod ekka;
mod error;
mod fsx;
mod gateway_config;
mod gateway_grpc;
mod gateway_setup;
mod http1;
mod identity;
mod install;
mod kit;
mod local_build;
mod meter;
mod net;
mod openshell;
mod platform;
mod records;
mod registration;
mod release;
mod runtime;
#[cfg(test)]
mod schema_check;
mod sigstore;
mod status;
mod tls;
mod util;

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use error::{refused, usage, Error, Result};

const HELP: &str = "ekka-desk-host: installs and checks one EKKA desk host (this release: a native Apple Silicon Mac).

  ekka-desk-host install --profile developer-native --runtime docker-desktop \\
      --env <env> --org <tenant id> --identity-profile <file> \\
      [--ekka <absolute path>] [--rotate-ca] [--rotate-adapter-key] [--local-build <dir>]
      Installs for the developer running it, run from /usr/local/libexec/ekka-desk-host/ekka-desk-host (root's).
      Asks for the password once, and only when something root owns must change. One installation per Mac:
      another organization, developer or environment is refused before any change. --rotate-ca replaces an
      installation CA whose key is no longer root's alone, and the gateway certificate with it. Desks on a
      developer's Mac have no CPU or memory limit of their own in this release; Docker Desktop's VM bounds them.
      The adapter's signing key is made once and never replaced, except with --rotate-adapter-key (then register
      the new key again). --local-build <dir> (--env dev only) installs the builds <dir>/local-build.json names
      in place of releases, by their sha256; status and doctor say LOCAL BUILD for each.

  <one-time setup authorization> | ekka-desk-host gateway-setup [--json]
      The gateway's one-time setup, as yourself: the authorization (ekds_...) comes on stdin only, from
      ekka desk setup --local. Exit 0 set up, 4 waiting (run again), 3 refused, 1 failed.

  ekka-desk-host status [--json]     what this host observes, with a reason for each failure
  ekka-desk-host doctor [--json]     status, and live probes that change nothing
  ekka-desk-host version

Not in this release: doctor --exercise and recover.
";

fn value(args: &[String], i: &mut usize, flag: &str) -> Result<String> {
    *i += 1;
    args.get(*i).cloned().ok_or_else(|| usage(format!("{flag} needs a value")))
}

fn number(args: &[String], i: &mut usize, flag: &str) -> Result<u64> {
    value(args, i, flag)?.parse().map_err(|_| usage(format!("{flag} takes a whole number")))
}

fn parse_install(args: &[String]) -> Result<install::Args> {
    let mut a = install::Args::default();
    let mut identity = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => a.profile = value(args, &mut i, "--profile")?,
            "--runtime" => a.runtime = value(args, &mut i, "--runtime")?,
            "--env" => a.env = value(args, &mut i, "--env")?,
            "--org" => a.org = value(args, &mut i, "--org")?,
            "--identity-profile" => identity = Some(PathBuf::from(value(args, &mut i, "--identity-profile")?)),
            "--ekka" => a.ekka = Some(PathBuf::from(value(args, &mut i, "--ekka")?)),
            "--desk-cpu-millicores" => a.cpu_millicores = Some(number(args, &mut i, "--desk-cpu-millicores")?),
            "--desk-memory-mib" => a.memory_mib = Some(number(args, &mut i, "--desk-memory-mib")?),
            "--rotate-ca" => a.rotate_ca = true,
            "--rotate-adapter-key" => a.rotate_adapter_key = true,
            "--local-build" => a.local_build = Some(PathBuf::from(value(args, &mut i, "--local-build")?)),
            "--raise-ceiling" => a.raise_ceiling = true,
            other => return Err(usage(format!("install does not take {other:?}"))),
        }
        i += 1;
    }
    for (flag, v) in [("--profile", &a.profile), ("--runtime", &a.runtime), ("--env", &a.env), ("--org", &a.org)] {
        if v.is_empty() {
            return Err(usage(format!("install needs {flag}")));
        }
    }
    a.identity_profile = identity.ok_or_else(|| usage("install needs --identity-profile <file>"))?;
    Ok(a)
}

fn json_flag(args: &[String], cmd: &str) -> Result<bool> {
    match args {
        [] => Ok(false),
        [j] if j == "--json" => Ok(true),
        [x, ..] if x == "--exercise" => Err(refused("doctor --exercise comes with the next release")),
        _ => Err(usage(format!("{cmd} takes only --json"))),
    }
}

fn developer_layout() -> Result<platform::macos::Layout> {
    let uid = rustix::process::getuid().as_raw();
    let user = platform::macos::user_by_uid(uid)?;
    Ok(platform::macos::Layout::system(uid, user.home))
}

fn print_checks(ok: bool, checks: &[status::Check]) {
    for c in checks {
        match &c.reason {
            None => println!("  ok    {}", c.id),
            Some(r) => println!("  FAIL  {}: {r}", c.id),
        }
    }
    println!("{}", if ok { "ready" } else { "not ready" });
}

/// The root step: only through `install`'s own sudo, for the developer who ran it.
fn apply_root() -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(refused("the root step runs only as root, from install"));
    }
    let exe = std::env::current_exe().map_err(|e| refused(format!("finding this program: {e}")))?;
    platform::macos::trusted_self(
        &exe,
        std::path::Path::new(platform::macos::HOST_BINARY),
        std::path::Path::new("/"),
        0,
    )?;
    let mut input = Vec::new();
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut input)
        .map_err(|e| refused(format!("reading the root plan: {e}")))?;
    let plan: apply::RootPlan =
        serde_json::from_slice(&input).map_err(|e| refused(format!("the root plan is not one: {e}")))?;
    let caller: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok());
    if caller != Some(plan.want.uid) {
        return Err(refused("the root step is for the developer who ran install with sudo, and no one else"));
    }
    let user = platform::macos::user_by_uid(plan.want.uid)?;
    let layout = platform::macos::Layout::system(user.uid, user.home.clone());
    let owners =
        apply::Owners { root: fsx::Owner { uid: 0, gid: 0 }, dev: fsx::Owner { uid: user.uid, gid: user.gid } };
    let roots =
        std::fs::read(net::system_roots_path()).map_err(|e| refused(format!("the system's public roots: {e}")))?;
    let pins = release::Pins::embedded()?;
    let mut ctx = apply::Ctx::apply();
    let result = apply::root_apply(&plan, &layout, owners, &pins, &roots, &mut ctx);
    for c in &ctx.changes {
        eprintln!("   root: {c}");
    }
    let binding = result?;
    let report = serde_json::json!({"changes": ctx.changes, "installation_id": binding.installation_id});
    println!("{report}");
    Ok(())
}

fn run(args: Vec<String>) -> Result<ExitCode> {
    let (cmd, rest) = args.split_first().map(|(c, r)| (c.as_str(), r)).unwrap_or(("help", &[]));
    match cmd {
        "install" => {
            let a = parse_install(rest)?;
            let out = install::run(&a)?;
            println!("== done");
            for c in &out.changes {
                println!("   changed: {c}");
            }
            if out.changes.is_empty() {
                println!("   nothing changed");
            }
            for p in &out.pending {
                println!("   waiting: {p}");
            }
            Ok(if out.pending.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(4) })
        }
        "status" => {
            let json = json_flag(rest, "status")?;
            let s = status::status(&developer_layout()?, &release::Pins::embedded()?, None);
            if json {
                println!("{}", serde_json::to_string_pretty(&s).map_err(|e| refused(e.to_string()))?);
            } else {
                for line in s.local_build.iter().flat_map(|lb| lb.lines()) {
                    println!("{line}");
                }
                let mut all = s.checks.clone();
                all.push(s.bootstrap.clone());
                print_checks(s.ok, &all);
                println!("note: {}", s.desk_limits);
            }
            Ok(ExitCode::SUCCESS)
        }
        "doctor" => {
            let json = json_flag(rest, "doctor")?;
            let d = status::doctor(&developer_layout()?, &release::Pins::embedded()?);
            if json {
                println!("{}", serde_json::to_string_pretty(&d).map_err(|e| refused(e.to_string()))?);
            } else {
                for line in d.local_build.iter().flat_map(|lb| lb.lines()) {
                    println!("{line}");
                }
                print_checks(d.ok, &d.checks);
                println!("note: {}", d.desk_limits);
            }
            Ok(if d.ok { ExitCode::SUCCESS } else { ExitCode::from(1) })
        }
        "gateway-setup" => gateway_setup::command(rest),
        "recover" => Err(refused("recover comes with the next release")),
        "__apply-root" => apply_root().map(|_| ExitCode::SUCCESS),
        "version" | "--version" => {
            println!("ekka-desk-host {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(usage(format!("unknown command {other:?}; see ekka-desk-host help"))),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(code) => code,
        Err(Error { kind, reason }) => {
            let e = Error { kind, reason };
            eprintln!("ekka-desk-host: {}", e.reason);
            ExitCode::from(e.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn install_takes_exactly_its_flags() {
        let a = parse_install(&s(&[
            "--profile",
            "developer-native",
            "--runtime",
            "docker-desktop",
            "--env",
            "prod",
            "--org",
            "7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7",
            "--identity-profile",
            "/tmp/p.json",
        ]))
        .unwrap();
        assert_eq!(a.identity_profile, PathBuf::from("/tmp/p.json"));
        assert!(!a.rotate_adapter_key, "the adapter key is replaced only when asked by name");
        assert!(parse_install(&s(&["--profile", "developer-native"])).is_err());
        assert!(parse_install(&s(&["--yes"])).is_err());
        assert!(parse_install(&s(&["--desk-cpu-millicores", "lots"])).is_err());
    }

    #[test]
    fn rotating_the_adapter_key_is_asked_for_by_name() {
        let mut v = vec![
            "--profile",
            "developer-native",
            "--runtime",
            "docker-desktop",
            "--env",
            "prod",
            "--org",
            "7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7",
            "--identity-profile",
            "/tmp/p.json",
        ];
        v.push("--rotate-adapter-key");
        assert!(parse_install(&s(&v)).unwrap().rotate_adapter_key);
    }

    #[test]
    fn a_local_build_is_refused_outside_dev_before_anything_else() {
        let t = tempfile::tempdir().unwrap();
        for env in ["staging", "prod"] {
            let e = run(s(&[
                "install",
                "--profile",
                "developer-native",
                "--runtime",
                "docker-desktop",
                "--env",
                env,
                "--org",
                "7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7",
                "--identity-profile",
                "/tmp/p.json",
                "--local-build",
                &t.path().display().to_string(),
            ]))
            .unwrap_err();
            assert_eq!(e.kind, error::Kind::Refused, "{env}: {e}");
            assert!(e.reason.contains("--local-build is for --env dev only"), "{env}: {e}");
        }
    }

    #[test]
    fn gateway_setup_never_takes_the_authorization_from_the_command_line_nor_echoes_it() {
        let secret = "ekds_Q2xhdWRlIGRvZXMgbm90IGtub3cgdGhpcyBvbmUuIEd";
        let e = run(s(&["gateway-setup", secret])).unwrap_err();
        assert_eq!(e.kind, error::Kind::Refused);
        assert!(e.reason.contains("stdin only") && !e.reason.contains(secret), "{e}");
        assert_eq!(run(s(&["gateway-setup", "--json", "--force"])).unwrap_err().kind, error::Kind::Usage);
    }

    #[test]
    fn exercise_and_recover_are_named_as_the_next_release() {
        assert!(json_flag(&s(&["--exercise", "--json"]), "doctor").unwrap_err().reason.contains("next release"));
        assert!(run(s(&["recover"])).unwrap_err().reason.contains("next release"));
        assert_eq!(run(s(&["bogus"])).unwrap_err().kind, error::Kind::Usage);
    }

    #[test]
    fn the_root_step_refuses_anyone_but_root() {
        if rustix::process::geteuid().as_raw() != 0 {
            assert!(apply_root().unwrap_err().reason.contains("only as root"));
        }
    }
}
