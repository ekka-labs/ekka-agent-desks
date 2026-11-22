"""Root-owned registry credentials; values enter through hidden input or stdin."""
import base64
import contextlib
import fcntl
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
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


# Temporary Docker configs: this command's own, and up.sh's (mktemp names). A credential can be left in one if the
# process that made it was killed; logout removes them while no login or pull is running.
TEMPORARY = (".registry-login-", ".image-pull-")
LEGACY_TEMPORARY = (".registry-login.", ".image-pull.")
LEGACY_AGE = 3600       # up.sh takes no lock, so only its folders older than any pull are removed


@contextlib.contextmanager
def registry_use(state, exclusive=False):
    """Logins and pulls share this lock; logout takes it alone, so it never removes a live pull's folder."""
    fd = os.open(Path(state) / "registry.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise HostError("the registry lock must be a private root-owned regular file")
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostError("a registry login, pull or logout is running; run this again when it finishes") from None
        yield
    finally:
        os.close(fd)


def remove_abandoned(base):
    """Temporary Docker configs a killed login or pull left behind. Call only under registry_use(exclusive=True)."""
    removed = []
    now = time.time()
    for entry in os.scandir(base):
        native, legacy = entry.name.startswith(TEMPORARY), entry.name.startswith(LEGACY_TEMPORARY)
        if not (native or legacy):
            continue
        info = os.lstat(entry.path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            continue
        if legacy and now - info.st_mtime < LEGACY_AGE:
            continue
        shutil.rmtree(entry.path)
        removed.append(entry.name)
    return removed


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
        with registry_use(STATE), tempfile.TemporaryDirectory(prefix=TEMPORARY[0], dir=base) as folder:
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
    base, store, exists = directory(runtime)
    target = store / (host + ".env")
    if exists:
        private_destination(target)
    action = "registry logout " + host
    runtime.audit(action, "requested")
    try:
        with registry_use(STATE, exclusive=True):
            removed = remove_abandoned(base)
        if removed:
            runtime.output("Removed " + str(len(removed)) + " temporary Docker configuration(s) an interrupted "
                           "login or pull left behind")
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
