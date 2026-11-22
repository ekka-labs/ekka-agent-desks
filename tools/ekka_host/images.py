"""Pull an immutable image with temporary, private Docker credentials."""
import json
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

from .files import root_directory
from .registry import read_credential
from .runtime import HostError, STATE

IMAGE = re.compile(r"[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}")


def pull(runtime, ref, identity=None, issuer=None):
    if not IMAGE.fullmatch(ref):
        raise HostError("the image must name a registry, repository and sha256 digest; tags are refused")
    if bool(identity) != bool(issuer):
        raise HostError("--signed-by and --issuer must be supplied together")
    if identity:
        if any(not (33 <= ord(c) <= 126) for text in (identity, issuer) for c in text) or max(len(identity), len(issuer)) > 4096:
            raise HostError("the signature identity and issuer must be printable public identifiers")
        url = urlsplit(issuer)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
            raise HostError("the signature issuer must be an https issuer URL without credentials or a fragment")
    if not runtime.installed():
        raise HostError("the default desks installation is not complete")
    secrets = root_directory(STATE / "secrets")
    host = ref.split("/", 1)[0]
    saved = read_credential(secrets / "registry" / (host + ".env"))
    action = "image pull " + ref
    runtime.audit(action, "requested")
    try:
        with tempfile.TemporaryDirectory(prefix=".image-pull-", dir=secrets) as folder:
            config = Path(folder) / "docker"
            config.mkdir(mode=0o700)
            docker = ["/usr/bin/docker", "--config", str(config)]
            if saved:
                user, token = saved
                runtime.run([*docker, "login", host, "--username", user, "--password-stdin"], stdin=token)
            if identity:
                runtime.run(["/usr/bin/env", "DOCKER_CONFIG=" + str(config), "/usr/local/bin/cosign", "verify",
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
