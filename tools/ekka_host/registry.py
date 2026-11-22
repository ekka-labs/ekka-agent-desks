"""Root-owned registry credentials; values enter through hidden input or stdin."""
import base64
import getpass
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import warnings

from .files import atomic_secret, private_destination, root_directory, root_file
from .runtime import HostError, STATE

HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?")
USER = re.compile(r"[A-Za-z0-9._-]{1,128}")
CAP = 8192


def valid_token(token):
    return 1 <= len(token) <= CAP and all(33 <= ord(c) <= 126 for c in token)


def read_token(stream=None):
    stream = sys.stdin if stream is None else stream
    try:
        if stream.isatty():
            # getpass falls back to VISIBLE input with only a warning when it cannot switch echo off. Refuse instead.
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                try:
                    token = getpass.getpass("Registry read credential (hidden): ")
                except getpass.GetPassWarning:
                    raise HostError("this terminal cannot hide input; pipe the credential on stdin instead. "
                                    "Nothing was kept") from None
        else:
            token = stream.read(CAP + 3)
            if len(token) > CAP + 2:
                raise HostError("input must contain one registry credential, at most 8192 characters")
            if token.endswith("\n"):
                token = token[:-1]
                if token.endswith("\r"):
                    token = token[:-1]
    except (EOFError, KeyboardInterrupt):
        raise HostError("credential input was interrupted; nothing was kept") from None
    if not valid_token(token):
        raise HostError("input must contain one registry credential without spaces or additional lines")
    return token


def hostname(host):
    """The registry's name without a port: the policy applies to the registry, whatever port reaches it."""
    return host.rsplit(":", 1)[0] if ":" in host else host


def github_packages(host):
    name = hostname(host)
    return name == "ghcr.io" or name.endswith(".pkg.github.com")


def docker_config(folder, host, user=None, token=None):
    """A private Docker config that names an entry for the registry. Docker picks a host credential helper (pass,
    secretservice) only for a config with NO auth entry, so with this one every credential stays in this file and
    goes when the folder does. Returns the folder to pass to --config."""
    entry = {} if user is None else {"auth": base64.b64encode((user + ":" + token).encode()).decode()}
    fd = os.open(Path(folder) / "config.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({"auths": {host: entry}}, stream)
    return str(folder)


def read_credential(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    fields = {}
    for line in root_file(path, private=True).splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in ("REGISTRY_USER", "REGISTRY_TOKEN") or key in fields:
            raise HostError("the registry credential file is malformed")
        fields[key] = value
    user, token = fields.get("REGISTRY_USER", ""), fields.get("REGISTRY_TOKEN", "")
    if not USER.fullmatch(user) or not valid_token(token):
        raise HostError("the registry credential file is malformed")
    return user, token


def directory(runtime):
    if not runtime.installed():
        raise HostError("the default desks installation is not complete")
    base = root_directory(STATE / "secrets")
    path = base / "registry"
    try:
        path.lstat()
    except FileNotFoundError:
        return base, path, False
    root_directory(path)
    return base, path, True


def login(runtime, host, user, token_source=read_token):
    if len(host) > 259 or not HOST.fullmatch(host) or not USER.fullmatch(user):
        raise HostError("registry login needs a registry host, username and one credential on stdin")
    base, store, exists = directory(runtime)
    target = store / (host + ".env")
    if exists:
        private_destination(target)
    action = "registry login " + host + " " + user
    runtime.audit(action, "requested")
    try:
        token = token_source()
        if not valid_token(token):
            raise HostError("input must contain one registry credential without spaces or additional lines")
        if github_packages(host):
            if not re.fullmatch(r"ghp_[A-Za-z0-9]+", token):
                raise HostError("GitHub Packages requires a classic token with only read:packages scope")
            headers = runtime.run(["/usr/bin/curl", "-q", "--fail", "--silent", "--show-error",
                "--max-time", "20", "--config", "-", "--output", "/dev/null", "--dump-header", "-",
                "https://api.github.com/user"], stdin='header = "Authorization: token ' + token + '"\n', timeout=30)
            scopes = [line.split(":", 1)[1].strip() for line in headers.stdout.splitlines()
                      if line.lower().startswith("x-oauth-scopes:")]
            if scopes != ["read:packages"]:
                raise HostError("GitHub token must have exactly read:packages scope; nothing was kept")
        with tempfile.TemporaryDirectory(prefix=".registry-login-", dir=base) as folder:
            runtime.run(["/usr/bin/docker", "--config", docker_config(folder, host), "login", host,
                         "--username", user, "--password-stdin"], stdin=token)
            if not exists:
                store.mkdir(mode=0o700)
                root_directory(store)
            atomic_secret(target, "REGISTRY_USER=" + user + "\nREGISTRY_TOKEN=" + token + "\n")
    except Exception:
        runtime.audit(action, "not_verified")
        raise
    runtime.audit(action, "credential_kept")
    runtime.output("Registry credential kept for " + host + " as " + user)


def show(runtime):
    _, store, exists = directory(runtime)
    if not exists:
        runtime.output("No registry credentials kept; public images need none.")
        return
    paths = sorted(store.glob("*.env"))
    entries = []
    for path in paths:
        host = path.stem
        if not HOST.fullmatch(host):
            raise HostError("a registry credential has an invalid host name")
        value = read_credential(path)
        if value is None:
            raise HostError("registry credentials changed while listing; run show again")
        user, _ = value
        entries.append(host + " as " + user)
    for line in entries or ["No registry credentials kept; public images need none."]:
        runtime.output(line)


def logout(runtime, host):
    if not HOST.fullmatch(host):
        raise HostError("registry logout needs a registry host")
    _, store, exists = directory(runtime)
    target = store / (host + ".env")
    if exists:
        private_destination(target)
    action = "registry logout " + host
    runtime.audit(action, "requested")
    try:
        if exists:
            target.unlink(missing_ok=True)
            fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    except Exception:
        runtime.audit(action, "not_verified")
        raise
    runtime.audit(action, "credential_removed")
    runtime.output("No local credential kept for " + host)
