"""Pull an immutable image with temporary, private Docker credentials."""
import json
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import urlsplit

from .files import root_directory
from .registry import TEMPORARY, docker_config, read_credential, registry_use
from .runtime import HostError, STATE

IMAGE = re.compile(r"[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}")
# Trusted system locations only, in this order; never a search of PATH.
COSIGN = ("/usr/local/bin/cosign", "/usr/bin/cosign")
ROOT_UID = 0


def cosign_path():
    """The first installed cosign: a root-owned executable regular file, never a link, whose own folder chain (the
    path that is looked up, not wherever a link leads) is root-owned and not writable by others."""
    candidates = COSIGN
    for candidate in candidates:
        path = Path(candidate)
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        root_directory(path.parent)
        if stat.S_ISLNK(info.st_mode):
            raise HostError("cosign at " + candidate + " is a link; install the binary itself there")
        if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022 or not info.st_mode & 0o111:
            raise HostError("cosign at " + candidate + " must be a root-owned executable that others cannot change")
        return str(path)
    raise HostError("cosign is not installed in " + " or ".join(candidates) + "; nothing was pulled")


def pull(runtime, ref, identity=None, issuer=None):
    if not IMAGE.fullmatch(ref):
        raise HostError("the image must name a registry, repository and sha256 digest; tags are refused")
    # Given at all (even empty) means a signature check was asked for: never skip it silently.
    if (identity is None) != (issuer is None):
        raise HostError("--signed-by and --issuer must be supplied together")
    if identity is not None and (not identity or not issuer):
        raise HostError("--signed-by and --issuer must both name a value; nothing was pulled")
    if identity is not None:
        if any(not (33 <= ord(c) <= 126) for text in (identity, issuer) for c in text) or max(len(identity), len(issuer)) > 4096:
            raise HostError("the signature identity and issuer must be printable public identifiers")
        url = urlsplit(issuer)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
            raise HostError("the signature issuer must be an https issuer URL without credentials or a fragment")
    if not runtime.installed():
        raise HostError("the default desks installation is not complete")
    cosign = cosign_path() if identity is not None else None
    secrets = root_directory(STATE / "secrets")
    host = ref.split("/", 1)[0]
    saved = read_credential(secrets / "registry" / (host + ".env"))
    action = "image pull " + ref
    runtime.audit(action, "requested")
    try:
        with registry_use(STATE), tempfile.TemporaryDirectory(prefix=TEMPORARY[1], dir=secrets) as folder:
            config = Path(folder) / "docker"
            config.mkdir(mode=0o700)
            docker = ["/usr/bin/docker", "--config", docker_config(config, host)]
            if saved:
                user, token = saved
                runtime.run([*docker, "login", host, "--username", user, "--password-stdin"], stdin=token)
            if cosign is not None:
                runtime.run(["/usr/bin/env", "DOCKER_CONFIG=" + str(config), cosign, "verify",
                             "--certificate-identity", identity, "--certificate-oidc-issuer", issuer, ref], timeout=180)
            runtime.run([*docker, "pull", "--quiet", ref], timeout=900)
            found = runtime.run([*docker, "image", "inspect", "--format", "{{json .RepoDigests}}", ref])
            try:
                digests = json.loads(found.stdout)
            except ValueError:
                raise HostError("the pulled image's digest could not be read; nothing is approved for desk use") from None
            expected = "@" + ref.split("@", 1)[1]
            if not isinstance(digests, list) or not any(isinstance(d, str) and d.endswith(expected) for d in digests):
                raise HostError("the pulled image does not report the requested digest; nothing is approved for desk use")
    except Exception:
        runtime.audit(action, "not_verified")
        raise
    runtime.audit(action, "verified_digest")
    runtime.output("Image available: " + ref)
    runtime.output("A separate EKKA desk grant is required before a desk may use this image.")
