//! The memory meter: a tiny pinned container inside Docker Desktop's Linux VM that prints the VM's memory and
//! pressure once a second. On a Mac the memory that matters is the VM's, and Docker's API gives neither its
//! available memory nor any pressure reading; the Enclave reads these lines through the Engine API and fails
//! closed when the meter is missing, stale or malformed.
//!
//! The image is a pinned busybox with no network, no mounts, a read-only root, no capabilities, a nobody user,
//! small memory and process limits, rotated logs, and restart unless stopped (so it comes back with Docker
//! Desktop, not only after a failure). `install` starts it; `status` and `doctor` report it.

use serde_json::{json, Value};

/// The meter's output, version 1. One sample per second, plain text lines, nothing else on stdout:
///
/// ```text
///   ekka-meter/1 <unix_seconds> meminfo <one raw line of /proc/meminfo>
///   ekka-meter/1 <unix_seconds> pressure/memory <one raw line of /proc/pressure/memory>
///   ekka-meter/1 <unix_seconds> pressure/cpu <one raw line of /proc/pressure/cpu>
///   ekka-meter/1 <unix_seconds> end
/// ```
///
/// Every line of the three files is printed, in that order, all with the same <unix_seconds>, then the `end`
/// line. A sample without its `end` line is incomplete and the reader ignores it. If a file cannot be read, print
/// `ekka-meter/1 <unix_seconds> error <file>` instead of its lines (the reader then fails closed). Keep it
/// producible by a busybox shell loop (no JSON), so the meter image stays a pinned busybox with no network, no
/// mounts, read-only.
///
/// Three fixed facts from the runner's reader, matched exactly:
/// 1. Container name is exactly `ekka-vm-meter`.
/// 2. The reader uses the developer's Docker Desktop socket `$HOME/.docker/run/docker.sock` (the Enclave runs as
///    that user). Start the meter on that same Docker context.
/// 3. The reader reads stdout only, no TTY (create the container with Tty=false). Nothing but `ekka-meter/1 ...`
///    lines may ever reach stdout: any other line in the last 300 fails closed, so no shell noise, no banners;
///    send any diagnostics to stderr. One sample per second; samples must carry the VM's current unix seconds
///    (the reader accepts at most 3 s behind and 1 s ahead of the Mac's clock).
///
/// `proc_root` is `/proc` in the container (another folder only in tests); `samples` is `None` there (forever).
pub fn script(proc_root: &str, samples: Option<u32>) -> String {
    let (head, tail) = match samples {
        None => ("while :; do".to_string(), "done".to_string()),
        Some(n) => (format!("n=0; while [ \"$n\" -lt {n} ]; do n=$((n+1));"), "done".to_string()),
    };
    format!(
        "{head}
  t=$(date +%s)
  for f in meminfo pressure/memory pressure/cpu; do
    if out=$(cat \"{proc_root}/$f\" 2>/dev/null) && [ -n \"$out\" ]; then
      printf '%s\\n' \"$out\" | while IFS= read -r line; do printf '{FORMAT} %s %s %s\\n' \"$t\" \"$f\" \"$line\"; done
    else
      printf '{FORMAT} %s error %s\\n' \"$t\" \"$f\"
    fi
  done
  printf '{FORMAT} %s end\\n' \"$t\"
  sleep 1
{tail}
"
    )
}

/// Every line on the meter's stdout starts with this.
pub const FORMAT: &str = "ekka-meter/1";
/// The container's exact name, which the Enclave's reader looks up.
pub const NAME: &str = "ekka-vm-meter";
/// How stale or early the newest sample may be, as the reader accepts it.
pub const MAX_BEHIND_SECS: i64 = 3;
pub const MAX_AHEAD_SECS: i64 = 1;
/// How many of the newest lines the reader checks.
pub const READER_LINES: usize = 300;
const FILES: [&str; 3] = ["meminfo", "pressure/memory", "pressure/cpu"];

/// The Engine API body that creates the meter.
pub fn container(image: &str) -> Value {
    json!({
        "Image": image,
        "Entrypoint": ["/bin/sh", "-c"],
        "Cmd": [script("/proc", None)],
        "User": "65534:65534",
        "Tty": false,
        "OpenStdin": false,
        "AttachStdin": false,
        "AttachStdout": false,
        "AttachStderr": false,
        "NetworkDisabled": true,
        "Labels": {
            "com.ekka.desk-host.role": "vm-meter",
            "com.ekka.desk-host.format": FORMAT,
            "com.ekka.desk-host.image": image,
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": true,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": false,
            "Binds": [],
            "Mounts": [],
            "RestartPolicy": {"Name": "unless-stopped"},
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "1m", "max-file": "3"}},
            "Memory": 32 * 1024 * 1024,
            "PidsLimit": 32,
            "NanoCpus": 100_000_000,
        }
    })
}

/// Whether a running container is the meter this release makes: its image, no TTY, no network, read-only, no
/// mounts. Each difference is named.
pub fn differences(inspect: &Value, image: &str) -> Vec<String> {
    let mut out = Vec::new();
    let c = &inspect["Config"];
    let h = &inspect["HostConfig"];
    if c["Image"].as_str() != Some(image) {
        out.push("it runs another image than the pinned one".to_string());
    }
    if c["Tty"].as_bool() != Some(false) {
        out.push("it has a TTY (the reader needs Tty=false)".to_string());
    }
    if h["NetworkMode"].as_str() != Some("none") {
        out.push("it has a network".to_string());
    }
    if h["ReadonlyRootfs"].as_bool() != Some(true) {
        out.push("its root is writable".to_string());
    }
    if inspect["Mounts"].as_array().is_some_and(|m| !m.is_empty()) {
        out.push("it has mounts".to_string());
    }
    if c["Cmd"].get(0).and_then(Value::as_str) != Some(script("/proc", None).as_str()) {
        out.push("it runs another command than this release's meter".to_string());
    }
    out
}

/// The newest complete sample in the meter's last lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub unix_seconds: i64,
    /// Files the meter could not read in that sample (the reader fails closed on any).
    pub errors: Vec<String>,
}

/// The newest complete sample, or why there is none. Any line that is not a meter line fails, as the reader does.
pub fn newest_sample(lines: &[&str]) -> Result<Sample, String> {
    let lines: Vec<&str> = lines.iter().copied().filter(|l| !l.is_empty()).collect();
    let start = lines.len().saturating_sub(READER_LINES);
    let mut parsed = Vec::new();
    for l in &lines[start..] {
        let rest = l.strip_prefix(FORMAT).and_then(|r| r.strip_prefix(' '));
        let Some(rest) = rest else {
            return Err("a line on the meter's output is not a meter line".into());
        };
        let mut parts = rest.splitn(3, ' ');
        let t: i64 = parts.next().and_then(|t| t.parse().ok()).ok_or("a meter line has no time")?;
        let kind = parts.next().ok_or("a meter line has no kind")?;
        parsed.push((t, kind, parts.next().unwrap_or("")));
    }
    let end = parsed.iter().rposition(|(_, k, _)| *k == "end").ok_or("the meter has printed no complete sample")?;
    let t = parsed[end].0;
    let mut errors = Vec::new();
    let mut seen = Vec::new();
    for (lt, kind, rest) in parsed[..end].iter().rev().take_while(|(lt, k, _)| *lt == t && *k != "end") {
        debug_assert_eq!(*lt, t);
        if *kind == "error" {
            errors.push(rest.to_string());
        } else if FILES.contains(kind) {
            seen.push(*kind);
        } else {
            return Err(format!("a meter line names an unknown file: {kind}"));
        }
    }
    for f in FILES {
        if !seen.contains(&f) && !errors.iter().any(|e| e == f) {
            return Err(format!("the newest sample has no {f} lines"));
        }
    }
    Ok(Sample { unix_seconds: t, errors })
}

/// Whether a sample from `t` is fresh at `now`, as the reader judges it.
pub fn fresh(t: i64, now: i64) -> Result<(), String> {
    if now - t > MAX_BEHIND_SECS {
        return Err(format!("the newest sample is {} s old (at most {MAX_BEHIND_SECS} s)", now - t));
    }
    if t - now > MAX_AHEAD_SECS {
        return Err(format!(
            "the newest sample is {} s ahead of this Mac's clock (at most {MAX_AHEAD_SECS} s)",
            t - now
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn run_once(proc_root: &std::path::Path) -> (String, String) {
        let out =
            Command::new("/bin/sh").arg("-c").arg(script(&proc_root.display().to_string(), Some(1))).output().unwrap();
        (String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
    }

    #[test]
    fn one_sample_is_every_line_of_the_three_files_then_end_and_nothing_else() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("pressure")).unwrap();
        std::fs::write(t.path().join("meminfo"), "MemTotal:        8131592 kB\nMemAvailable:    6000000 kB\n").unwrap();
        std::fs::write(
            t.path().join("pressure/memory"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
        std::fs::write(t.path().join("pressure/cpu"), "some avg10=1.50 avg60=0.70 avg300=0.20 total=12345\n").unwrap();
        let (out, err) = run_once(t.path());
        assert!(err.is_empty(), "{err}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 6, "{out}");
        let ts = lines[0].split(' ').nth(1).unwrap();
        assert_eq!(lines[0], format!("ekka-meter/1 {ts} meminfo MemTotal:        8131592 kB"));
        assert_eq!(
            lines[2],
            format!("ekka-meter/1 {ts} pressure/memory some avg10=0.00 avg60=0.00 avg300=0.00 total=0")
        );
        assert_eq!(
            lines[4],
            format!("ekka-meter/1 {ts} pressure/cpu some avg10=1.50 avg60=0.70 avg300=0.20 total=12345")
        );
        assert_eq!(lines[5], format!("ekka-meter/1 {ts} end"));
        let s = newest_sample(&lines).unwrap();
        assert!(s.errors.is_empty());
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        fresh(s.unix_seconds, now).unwrap();
    }

    #[test]
    fn an_unreadable_file_is_one_error_line_on_stdout_and_no_noise() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("meminfo"), "MemTotal: 1 kB\n").unwrap();
        let (out, err) = run_once(t.path());
        assert!(err.is_empty(), "diagnostics go nowhere near stdout: {err}");
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.iter().all(|l| l.starts_with("ekka-meter/1 ")), "{out}");
        assert!(lines[1].ends_with(" error pressure/memory") && lines[2].ends_with(" error pressure/cpu"), "{out}");
        assert_eq!(newest_sample(&lines).unwrap().errors, ["pressure/cpu", "pressure/memory"]);
    }

    #[test]
    fn the_reader_rules_are_applied_to_the_newest_lines() {
        assert!(newest_sample(&["hello", "ekka-meter/1 5 end"]).is_err(), "a banner fails closed");
        assert!(newest_sample(&["ekka-meter/1 5 meminfo a"]).is_err(), "no end, no sample");
        let partial = ["ekka-meter/1 5 meminfo a", "ekka-meter/1 5 end"];
        assert!(newest_sample(&partial).unwrap_err().contains("pressure/memory"));
        let older_complete_newer_partial = [
            "ekka-meter/1 5 meminfo a",
            "ekka-meter/1 5 pressure/memory b",
            "ekka-meter/1 5 pressure/cpu c",
            "ekka-meter/1 5 end",
            "ekka-meter/1 6 meminfo a",
        ];
        assert_eq!(newest_sample(&older_complete_newer_partial).unwrap().unix_seconds, 5);
        assert!(
            fresh(100, 104).is_err() && fresh(100, 103).is_ok() && fresh(102, 100).is_err() && fresh(101, 100).is_ok()
        );
    }

    #[test]
    fn the_container_is_sealed_and_recognised() {
        let img =
            "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec";
        let c = container(img);
        assert_eq!(c["Tty"], false);
        assert_eq!(c["HostConfig"]["NetworkMode"], "none");
        assert_eq!(c["HostConfig"]["ReadonlyRootfs"], true);
        assert_eq!(c["HostConfig"]["Mounts"], json!([]));
        assert_eq!(c["HostConfig"]["LogConfig"]["Config"]["max-file"], "3");
        let inspect = json!({"Config": {"Image": img, "Tty": false, "Cmd": c["Cmd"]}, "HostConfig": c["HostConfig"], "Mounts": []});
        assert!(differences(&inspect, img).is_empty());
        let mut tty = inspect.clone();
        tty["Config"]["Tty"] = true.into();
        assert!(differences(&tty, img)[0].contains("TTY"));
    }

    /// The real meter in Docker Desktop's VM, with this crate's own Engine API client: pinned busybox, nobody, no
    /// network, read-only, no TTY. Two samples, then the container is removed. Needs Docker Desktop; never in CI.
    #[test]
    #[ignore = "needs Docker Desktop on this Mac"]
    fn docker_desktop_meter_prints_two_fresh_complete_samples() {
        use crate::runtime::docker::Docker;
        let home = std::env::var("HOME").unwrap();
        let docker = Docker::new(&std::path::Path::new(&home).join(".docker/run/docker.sock"));
        let pins = crate::release::Pins::embedded().unwrap();
        docker.pull(&pins.meter_image).unwrap();
        let mut body = container(&pins.meter_image);
        body["Cmd"] = json!([script("/proc", Some(2))]);
        body["HostConfig"]["RestartPolicy"] = json!({"Name": "no"});
        let name = format!("ekka-vm-meter-selftest-{}", std::process::id());
        let id = docker.create(Some(&name), &body).unwrap();
        docker.start(&id).unwrap();
        let start = std::time::Instant::now();
        while docker.container(&id).unwrap().unwrap()["State"]["Running"].as_bool() == Some(true) {
            assert!(start.elapsed().as_secs() < 30, "the meter did not finish two samples");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let inspect = docker.container(&id).unwrap().unwrap();
        let lines = docker.stdout_tail(&id, READER_LINES).unwrap();
        docker.remove(&id).unwrap();
        assert_eq!(inspect["State"]["ExitCode"], 0, "{inspect}");
        assert_eq!(inspect["Config"]["Tty"], false);
        assert_eq!(inspect["HostConfig"]["NetworkMode"], "none");
        assert_eq!(inspect["HostConfig"]["ReadonlyRootfs"], true);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let s = newest_sample(&refs).unwrap();
        assert!(s.errors.is_empty(), "the VM's files are readable as nobody: {:?}", s.errors);
        let ends = refs.iter().filter(|l| l.ends_with(" end")).count();
        assert_eq!(ends, 2, "{lines:?}");
        for f in FILES {
            assert!(refs.iter().any(|l| l.split(' ').nth(2) == Some(f)), "{f} printed");
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        assert!(now - s.unix_seconds <= 30, "the VM's clock is the Mac's: {} vs {now}", s.unix_seconds);
        eprintln!("{}", lines.join("\n"));
    }
}
