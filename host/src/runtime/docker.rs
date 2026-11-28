//! Docker Desktop through its Engine API, over the developer's own socket (`$HOME/.docker/run/docker.sock`),
//! as the developer. No `docker` command is run. Every image is named by digest; what an image holds is checked
//! against its pin before the gateway is allowed to use it.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::error::{failed, refused, Result};
use crate::http1::{self, query_escape, Response};
use crate::release::ImagePin;
use crate::util::{is_digest, sha256_hex};

const API: &str = "/v1.44";
/// Docker Desktop's VM on Apple Silicon.
pub const PLATFORM: &str = "linux/arm64";
const MAX_JSON: usize = 16 * 1024 * 1024;
const MAX_ARCHIVE: usize = 512 * 1024 * 1024;

pub struct Docker {
    socket: PathBuf,
}

/// What Docker says about its VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub os_type: String,
    pub arch: String,
    pub cpus: u64,
    pub memory_bytes: u64,
    pub server_version: String,
    pub operating_system: String,
}

/// An image reference split into the repository and its digest.
pub fn split_ref(image: &str) -> Result<(String, String)> {
    let (name, digest) = image.rsplit_once('@').ok_or_else(|| refused(format!("{image} is not pinned by digest")))?;
    if !is_digest(digest) {
        return Err(refused(format!("{image} is not pinned by a sha256 digest")));
    }
    // Drop a tag from the last path part only (a registry port has a colon before the first slash).
    let repo = match name.rfind('/') {
        Some(i) => match name[i..].find(':') {
            Some(j) => &name[..i + j],
            None => name,
        },
        None => name.split(':').next().unwrap_or(name),
    };
    Ok((repo.to_string(), digest.to_string()))
}

impl Docker {
    pub fn new(socket: &Path) -> Self {
        Docker { socket: socket.to_path_buf() }
    }

    fn request(
        &self,
        method: &str,
        target: &str,
        body: Option<(&str, &[u8])>,
        timeout: Duration,
    ) -> Result<Response<BufReader<UnixStream>>> {
        let mut s = UnixStream::connect(&self.socket).map_err(|e| {
            failed(format!("Docker Desktop is not answering at {} ({e}); start Docker Desktop", self.socket.display()))
        })?;
        s.set_read_timeout(Some(timeout)).ok();
        s.set_write_timeout(Some(timeout)).ok();
        let mut headers = vec![("Accept", "application/json")];
        if let Some((ct, _)) = body {
            headers.push(("Content-Type", ct));
        }
        let path = format!("{API}{target}");
        http1::write_request(&mut s, method, &path, "docker", &headers, body.map(|(_, b)| b).unwrap_or(&[]))
            .map_err(|e| failed(format!("asking Docker: {e}")))?;
        http1::read_response(BufReader::new(s))
    }

    fn json(&self, method: &str, target: &str, body: Option<&Value>) -> Result<(u16, Value)> {
        let bytes = body.map(|b| serde_json::to_vec(b).unwrap_or_default());
        let resp =
            self.request(method, target, bytes.as_deref().map(|b| ("application/json", b)), Duration::from_secs(60))?;
        let status = resp.status;
        let data = resp.bytes(MAX_JSON)?;
        let v = if data.is_empty() { Value::Null } else { serde_json::from_slice(&data).unwrap_or(Value::Null) };
        Ok((status, v))
    }

    fn fail(what: &str, status: u16, v: &Value) -> crate::error::Error {
        let msg = v["message"].as_str().unwrap_or("");
        failed(format!("Docker refused to {what} ({status}): {msg}"))
    }

    pub fn ping(&self) -> Result<()> {
        let resp = self.request("GET", "/_ping", None, Duration::from_secs(10))?;
        if resp.status != 200 {
            return Err(failed(format!("Docker answered {} to a ping", resp.status)));
        }
        Ok(())
    }

    pub fn info(&self) -> Result<Info> {
        let (status, v) = self.json("GET", "/info", None)?;
        if status != 200 {
            return Err(Self::fail("describe itself", status, &v));
        }
        Ok(Info {
            os_type: v["OSType"].as_str().unwrap_or("").into(),
            arch: v["Architecture"].as_str().unwrap_or("").into(),
            cpus: v["NCPU"].as_u64().unwrap_or(0),
            memory_bytes: v["MemTotal"].as_u64().unwrap_or(0),
            server_version: v["ServerVersion"].as_str().unwrap_or("").into(),
            operating_system: v["OperatingSystem"].as_str().unwrap_or("").into(),
        })
    }

    /// An image by name or id; `None` when Docker does not have it.
    pub fn image(&self, reference: &str) -> Result<Option<Value>> {
        let (status, v) = self.json("GET", &format!("/images/{reference}/json"), None)?;
        match status {
            200 => Ok(Some(v)),
            404 => Ok(None),
            s => Err(Self::fail("describe an image", s, &v)),
        }
    }

    /// Reads a streamed answer of JSON lines; any `error` in it fails. Returns every `aux` object seen.
    fn stream(resp: Response<BufReader<UnixStream>>, what: &str) -> Result<Vec<Value>> {
        if resp.status != 200 {
            let status = resp.status;
            let v: Value = serde_json::from_slice(&resp.bytes(MAX_JSON).unwrap_or_default()).unwrap_or(Value::Null);
            return Err(Self::fail(what, status, &v));
        }
        let mut aux = Vec::new();
        let mut reader = BufReader::new(resp.body);
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = (&mut reader)
                .take(MAX_JSON as u64)
                .read_until(b'\n', &mut line)
                .map_err(|e| failed(format!("reading Docker's answer to {what}: {e}")))?;
            if n == 0 {
                break;
            }
            let Ok(v) = serde_json::from_slice::<Value>(&line) else { continue };
            if let Some(e) = v.get("error").and_then(Value::as_str) {
                return Err(failed(format!("Docker could not {what}: {e}")));
            }
            if let Some(a) = v.get("aux") {
                aux.push(a.clone());
            }
        }
        Ok(aux)
    }

    /// Pulls an image by its digest, for this VM's platform, unless Docker has it already.
    pub fn pull(&self, image: &str) -> Result<()> {
        let (repo, digest) = split_ref(image)?;
        let by_digest = format!("{repo}@{digest}");
        if self.image(&by_digest)?.is_some() {
            return Ok(());
        }
        let target = format!(
            "/images/create?fromImage={}&tag={}&platform={}",
            query_escape(&repo),
            query_escape(&digest),
            query_escape(PLATFORM)
        );
        let resp = self.request("POST", &target, None, Duration::from_secs(600))?;
        Self::stream(resp, &format!("pull {by_digest}"))?;
        if self.image(&by_digest)?.is_none() {
            return Err(failed(format!("Docker pulled {by_digest} and then did not have it")));
        }
        Ok(())
    }

    pub fn container(&self, name: &str) -> Result<Option<Value>> {
        let (status, v) = self.json("GET", &format!("/containers/{name}/json"), None)?;
        match status {
            200 => Ok(Some(v)),
            404 => Ok(None),
            s => Err(Self::fail("describe a container", s, &v)),
        }
    }

    pub fn create(&self, name: Option<&str>, body: &Value) -> Result<String> {
        let mut target = format!("/containers/create?platform={}", query_escape(PLATFORM));
        if let Some(n) = name {
            target.push_str(&format!("&name={}", query_escape(n)));
        }
        let (status, v) = self.json("POST", &target, Some(body))?;
        if status != 201 {
            return Err(Self::fail("create a container", status, &v));
        }
        v["Id"].as_str().map(str::to_string).ok_or_else(|| failed("Docker created a container and named no id"))
    }

    pub fn start(&self, id: &str) -> Result<()> {
        let (status, v) = self.json("POST", &format!("/containers/{id}/start"), None)?;
        match status {
            204 | 304 => Ok(()),
            s => Err(Self::fail("start a container", s, &v)),
        }
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        let (status, v) = self.json("DELETE", &format!("/containers/{id}?force=true"), None)?;
        match status {
            204 | 404 => Ok(()),
            s => Err(Self::fail("remove a container", s, &v)),
        }
    }

    /// The bytes of the one regular file at `path` inside a (stopped) container.
    pub fn copy_out(&self, id: &str, path: &str) -> Result<Vec<u8>> {
        let resp = self.request(
            "GET",
            &format!("/containers/{id}/archive?path={}", query_escape(path)),
            None,
            Duration::from_secs(120),
        )?;
        if resp.status != 200 {
            return Err(failed(format!("Docker could not copy {path} out ({})", resp.status)));
        }
        let tar_bytes = resp.bytes(MAX_ARCHIVE)?;
        let mut archive = tar::Archive::new(&tar_bytes[..]);
        let mut found = None;
        for entry in archive.entries().map_err(|e| failed(format!("Docker's copy of {path} is not a tar: {e}")))? {
            let mut e = entry.map_err(|e| failed(format!("Docker's copy of {path}: {e}")))?;
            if !e.header().entry_type().is_file() || found.is_some() {
                return Err(refused(format!("{path} in the image is not one regular file")));
            }
            let mut b = Vec::new();
            e.read_to_end(&mut b).map_err(|e| failed(format!("Docker's copy of {path}: {e}")))?;
            found = Some(b);
        }
        found.ok_or_else(|| refused(format!("{path} is not in the image")))
    }

    /// The image is pulled by digest and the program in it is the pinned one, for linux/arm64. Nothing runs.
    pub fn verify_image(&self, pin: &ImagePin) -> Result<()> {
        self.pull(&pin.image)?;
        let (repo, digest) = split_ref(&pin.image)?;
        let id =
            self.create(None, &json!({"Image": format!("{repo}@{digest}"), "Cmd": ["none"], "NetworkDisabled": true}))?;
        let got = self.copy_out(&id, &pin.binary_in_image);
        let _ = self.remove(&id);
        let got = sha256_hex(&got?);
        if got != pin.binary_sha256 {
            return Err(refused(format!(
                "{} holds {} with sha256 {got}, not the pinned {}; the gateway will not use it",
                pin.image, pin.binary_in_image, pin.binary_sha256
            )));
        }
        Ok(())
    }

    /// The last `tail` lines the container wrote to stdout (not stderr), for a container without a TTY.
    pub fn stdout_tail(&self, name: &str, tail: usize) -> Result<Vec<String>> {
        let resp = self.request(
            "GET",
            &format!("/containers/{name}/logs?stdout=1&stderr=0&tail={tail}"),
            None,
            Duration::from_secs(30),
        )?;
        if resp.status != 200 {
            return Err(failed(format!("Docker could not read {name}'s output ({})", resp.status)));
        }
        let raw = resp.bytes(MAX_JSON)?;
        Ok(demux_stdout(&raw)?.lines().map(str::to_string).collect())
    }

    /// Builds the desk image from its recipe, tagged and labelled; returns its content id.
    pub fn build(&self, files: &[(&str, &[u8], u32)], tag: &str, labels: &BTreeMap<String, String>) -> Result<String> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data, mode) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_path(name).map_err(|e| failed(format!("the desk image recipe: {e}")))?;
            h.set_cksum();
            b.append(&h, *data).map_err(|e| failed(format!("the desk image recipe: {e}")))?;
        }
        let context = b.into_inner().map_err(|e| failed(format!("the desk image recipe: {e}")))?;
        let labels = serde_json::to_string(labels).unwrap_or_default();
        let target = format!(
            "/build?t={}&labels={}&rm=1&forcerm=1&pull=0&version=1&platform={}",
            query_escape(tag),
            query_escape(&labels),
            query_escape(PLATFORM)
        );
        let resp = self.request("POST", &target, Some(("application/x-tar", &context)), Duration::from_secs(1800))?;
        let aux = Self::stream(resp, "build the desk image")?;
        let id = aux
            .iter()
            .filter_map(|a| a["ID"].as_str())
            .next_back()
            .map(str::to_string)
            .ok_or_else(|| failed("Docker built the desk image and named no id"))?;
        if !is_digest(&id) {
            return Err(failed("Docker named the desk image with something that is not an image id"));
        }
        Ok(id)
    }
}

/// The stdout frames of a non-TTY log stream: each frame is 8 bytes (stream, 0, 0, 0, size big-endian) then data.
pub fn demux_stdout(raw: &[u8]) -> Result<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if raw.len() - i < 8 {
            return Err(failed("Docker's log stream ended inside a frame header"));
        }
        let stream = raw[i];
        let size = u32::from_be_bytes([raw[i + 4], raw[i + 5], raw[i + 6], raw[i + 7]]) as usize;
        i += 8;
        if raw.len() - i < size {
            return Err(failed("Docker's log stream ended inside a frame"));
        }
        if stream == 1 {
            out.extend_from_slice(&raw[i..i + size]);
        }
        i += size;
    }
    String::from_utf8(out).map_err(|_| failed("the container's output is not text"))
}

/// The label the desk image carries: the first 16 hex of the sha256 of its recipe's files, in name order (the
/// same value the Linux installer computes).
pub fn recipe_source(files: &[(&str, &[u8], u32)]) -> String {
    let mut sorted: Vec<_> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let all: Vec<u8> = sorted.iter().flat_map(|(_, d, _)| d.iter().copied()).collect();
    sha256_hex(&all)[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_references_split_into_repository_and_digest() {
        let d = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            split_ref(&format!("ghcr.io/nvidia/openshell/supervisor@{d}")).unwrap().0,
            "ghcr.io/nvidia/openshell/supervisor"
        );
        assert_eq!(split_ref(&format!("docker.io/library/busybox:1.37.0@{d}")).unwrap().0, "docker.io/library/busybox");
        assert_eq!(split_ref(&format!("localhost:5000/x@{d}")).unwrap().0, "localhost:5000/x");
        assert!(split_ref("busybox:latest").is_err());
        assert!(split_ref("busybox@sha256:short").is_err());
    }

    #[test]
    fn only_stdout_frames_are_kept() {
        let mut raw = vec![1, 0, 0, 0, 0, 0, 0, 4];
        raw.extend_from_slice(b"out\n");
        raw.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 4]);
        raw.extend_from_slice(b"err\n");
        assert_eq!(demux_stdout(&raw).unwrap(), "out\n");
        assert!(demux_stdout(&[1, 0, 0, 0, 0, 0, 0, 9, b'x']).is_err());
    }

    #[test]
    fn the_recipe_label_matches_the_linux_installers() {
        // find desk/image -type f | LC_ALL=C sort | xargs cat | sha256sum | cut -c1-16
        let files = crate::kit::DESK_IMAGE;
        let mut all = Vec::new();
        for name in ["Dockerfile", "ekka-git-credential", "managed-settings.json"] {
            all.extend_from_slice(files.iter().find(|f| f.0 == name).unwrap().1);
        }
        assert_eq!(recipe_source(&files), sha256_hex(&all)[..16]);
    }

    /// The pinned supervisor and sandbox runtime, pulled by digest for linux/arm64 into Docker Desktop, hold the
    /// programs pinned for aarch64; a wrong pin is refused. Needs Docker Desktop; never in CI.
    #[test]
    #[ignore = "needs Docker Desktop on this Mac"]
    fn docker_desktop_pinned_images_hold_their_programs() {
        let home = std::env::var("HOME").unwrap();
        let docker = Docker::new(&Path::new(&home).join(".docker/run/docker.sock"));
        let pins = crate::release::Pins::embedded().unwrap();
        docker.verify_image(&pins.supervisor).unwrap();
        docker.verify_image(&pins.sandbox).unwrap();
        let mut wrong = pins.sandbox.clone();
        wrong.binary_sha256 = "0".repeat(64);
        assert!(docker.verify_image(&wrong).unwrap_err().reason.contains("not the pinned"));
    }

    /// The Engine API build this crate uses for the desk image, on a two-line recipe: the returned id is the image
    /// Docker then holds under the tag, with the label. Needs Docker Desktop; never in CI. The image is left for
    /// the caller to remove (tag `ekka-desk-host-selftest`).
    #[test]
    #[ignore = "needs Docker Desktop on this Mac"]
    fn docker_desktop_builds_a_recipe_and_names_its_id() {
        let home = std::env::var("HOME").unwrap();
        let docker = Docker::new(&Path::new(&home).join(".docker/run/docker.sock"));
        let pins = crate::release::Pins::embedded().unwrap();
        docker.pull(&pins.meter_image).unwrap();
        let recipe = format!("FROM {}\nRUN true\n", pins.meter_image);
        let files: [(&str, &[u8], u32); 1] = [("Dockerfile", recipe.as_bytes(), 0o644)];
        let labels = BTreeMap::from([("ekka.desk.source".to_string(), recipe_source(&files))]);
        let id = docker.build(&files, "ekka-desk-host-selftest:latest", &labels).unwrap();
        let img = docker.image("ekka-desk-host-selftest:latest").unwrap().unwrap();
        assert_eq!(img["Id"].as_str(), Some(id.as_str()));
        assert_eq!(img["Config"]["Labels"]["ekka.desk.source"].as_str(), Some(recipe_source(&files).as_str()));
        assert_eq!(img["Architecture"], "arm64");
    }
}
