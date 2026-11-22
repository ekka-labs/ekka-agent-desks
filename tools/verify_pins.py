"""Check deploy/pins.json, this setup's committed pins for NVIDIA's OpenShell gateway and supervisor.

    python3 tools/verify_pins.py                    shape only: digests and checksums are well formed
    python3 tools/verify_pins.py --online           + each release tarball matches NVIDIA's checksums file,
                                                      and the binary inside it matches the committed sha256
    python3 tools/verify_pins.py --online --images  + the binary inside each pinned image matches too (needs docker)
    ... --machine <uname -m>                        only that processor type (an install checks its own only)

NVIDIA signs neither image, so the binary is the check: the committed sha256 must equal the binary in
NVIDIA's checksummed release tarball AND the binary in the image this setup runs. Each processor type this
setup installs on (PLATFORMS, keyed by `uname -m`) has its own release tarball and its own sha256, and each
is checked; the image is one multi-platform index, read once per platform. Setup compares against these
committed values, never against a page it fetches at run time.
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PINS = os.path.join(ROOT, "deploy", "pins.json")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^ghcr\.io/nvidia/openshell/[a-z-]+@sha256:[0-9a-f]{64}$")
COMPONENTS = ("gateway", "supervisor")
# `uname -m` of each machine this setup installs on, and the image platform docker runs there.
PLATFORMS = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}


def binary_sha256(pins, name, machine_name):
    """The committed sha256 of a component's binary for one processor type."""
    return pins[name]["platforms"][machine_name]["binary_sha256"]


def load(path=PINS):
    with open(path) as f:
        return json.load(f)["openshell"]


def shape_errors(pins):
    """Every reason the pins are malformed; empty when they are well formed."""
    errors = []
    if not re.fullmatch(r"\d+\.\d+\.\d+", pins.get("version", "")):
        errors.append("version is not MAJOR.MINOR.PATCH")
    if pins.get("release") != f"https://github.com/NVIDIA/OpenShell/releases/download/v{pins.get('version')}":
        errors.append("release is not NVIDIA's download URL for this version")
    for machine in PLATFORMS:
        entry = pins.get("cli", {}).get("platforms", {}).get(machine, {})
        if (entry.get("release_asset") != f"openshell-{machine}-unknown-linux-musl.tar.gz"
                or not HEX64.fullmatch(entry.get("archive_sha256", ""))):
            errors.append(f"invalid CLI archive pin for {machine}")
    for name in COMPONENTS:
        c = pins.get(name) or {}
        if not IMAGE.fullmatch(c.get("image", "")):
            errors.append(f"{name}.image is not pinned by digest (ghcr.io/nvidia/openshell/...@sha256:<64 hex>)")
        if not c.get("binary_in_image", "").startswith("/"):
            errors.append(f"{name}.binary_in_image is not an absolute path")
        if not c.get("release_checksums"):
            errors.append(f"{name}.release_checksums is missing")
        platforms = c.get("platforms") or {}
        if sorted(platforms) != sorted(PLATFORMS):
            errors.append(f"{name}.platforms is not exactly {', '.join(sorted(PLATFORMS))}")
        for m in sorted(set(platforms) & set(PLATFORMS)):
            p = platforms[m] or {}
            if not HEX64.fullmatch(p.get("binary_sha256", "")):
                errors.append(f"{name}.platforms.{m}.binary_sha256 is not 64 lowercase hex")
            # NVIDIA's own file name for this processor type, so a pin cannot name another platform's tarball.
            if not re.fullmatch(rf"openshell-{name}-{m}-unknown-linux-gnu\.tar\.gz", p.get("release_asset", "")):
                errors.append(f"{name}.platforms.{m}.release_asset is not NVIDIA's {m} tarball")
        shas = [(platforms.get(m) or {}).get("binary_sha256") for m in PLATFORMS]
        if len(set(shas)) != len(shas):
            errors.append(f"{name}: two processor types pin the same sha256")
    return errors


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def release_binary_sha256(pins, name, machine_name):
    """The sha256 of the one binary in NVIDIA's release tarball, after checking the tarball itself."""
    c = pins[name]
    asset = c["platforms"][machine_name]["release_asset"]
    sums = fetch(f"{pins['release']}/{c['release_checksums']}").decode()
    want = [line.split()[0] for line in sums.splitlines() if line.endswith(" " + asset)]
    if len(want) != 1:
        raise SystemExit(f"{name}: {asset} is not listed exactly once in {c['release_checksums']}")
    blob = fetch(f"{pins['release']}/{asset}")
    if hashlib.sha256(blob).hexdigest() != want[0]:
        raise SystemExit(f"{name}: {asset} does not match NVIDIA's checksums file")
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
        files = [m for m in t.getmembers() if m.isfile()]
        if len(files) != 1:
            raise SystemExit(f"{name}: expected one file in {c['release_asset']}, found {len(files)}")
        return hashlib.sha256(t.extractfile(files[0]).read()).hexdigest()


def platform_image(image, platform):
    """<repo>@<digest> of one platform's image inside the pinned index, read from the index itself.

    Pulled by its own digest, not as `--platform` of the index: Docker's classic image store keeps one platform
    per digest and refuses a second ("cannot overwrite digest"; measured on GitHub's ubuntu-24.04 runner)."""
    raw = subprocess.run(["docker", "buildx", "imagetools", "inspect", "--raw", image],
                         check=True, capture_output=True).stdout
    if "sha256:" + hashlib.sha256(raw).hexdigest() != image.split("@", 1)[1]:
        raise SystemExit(f"{image}: the registry answered an index that is not the pinned digest")
    want_os, want_arch = platform.split("/")
    found = [m["digest"] for m in json.loads(raw).get("manifests", [])
             if (m.get("platform") or {}).get("os") == want_os and (m.get("platform") or {}).get("architecture") == want_arch]
    if len(found) != 1:
        raise SystemExit(f"{image}: the pinned index holds {len(found)} images for {platform}, not one")
    return image.split("@", 1)[0] + "@" + found[0]


def image_binary_sha256(pins, name, machine_name):
    """The sha256 of the binary inside the pinned image for one platform (docker pull, create, cp; nothing runs)."""
    c = pins[name]
    platform = PLATFORMS[machine_name]
    ref = platform_image(c["image"], platform)
    subprocess.run(["docker", "pull", "-q", "--platform", platform, ref], check=True, stdout=subprocess.DEVNULL)
    cid = subprocess.run(["docker", "create", "--platform", platform, ref, "x"],
                         check=True, capture_output=True, text=True).stdout.strip()
    try:
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "bin")
            subprocess.run(["docker", "cp", f"{cid}:{c['binary_in_image']}", out], check=True)
            with open(out, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
    finally:
        subprocess.run(["docker", "rm", cid], stdout=subprocess.DEVNULL)


def main(argv):
    pins = load()
    errors = shape_errors(pins)
    if errors:
        print("\n".join(f"pins: {e}" for e in errors))
        return 1
    if argv == ["--version"]:
        print(pins["version"])
        return 0
    if argv[:1] == ["--cli-pin"]:
        if len(argv) != 3 or argv[1] not in PLATFORMS or argv[2] not in ("release_asset", "archive_sha256"):
            return 1
        print(pins["cli"]["platforms"][argv[1]][argv[2]])
        return 0
    print(f"pins: shape OK (OpenShell {pins['version']})")
    failed = False
    machines = list(PLATFORMS)
    if "--machine" in argv:
        i = argv.index("--machine")
        only = argv[i + 1] if i + 1 < len(argv) else ""
        if only not in PLATFORMS:
            print(f"pins: no pins for processor type '{only}'; pinned: {', '.join(PLATFORMS)}")
            return 1
        machines = [only]
    for name in COMPONENTS:
        for m in machines:
            want = binary_sha256(pins, name, m)
            checks = []
            if "--online" in argv:
                checks.append(("NVIDIA's release tarball", release_binary_sha256(pins, name, m)))
            if "--images" in argv:
                checks.append((f"the pinned image ({PLATFORMS[m]})", image_binary_sha256(pins, name, m)))
            for where, got in checks:
                ok = got == want
                failed |= not ok
                print(f"pins: {name} {m} binary in {where}: {'matches' if ok else 'DIFFERS: ' + got}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
