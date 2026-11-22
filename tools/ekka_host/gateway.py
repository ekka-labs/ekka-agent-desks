"""Native named emergency stop, with a temporary administrator client.

Provider changes and ordinary desk changes belong to governed EKKA commands.
The vendor binary is already installed and verified by installation; this path
neither downloads a binary nor evaluates the installation's environment files.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import tempfile

import openshell_allow as allow
from .files import root_directory, root_file
from .runtime import ADMIN_HOME_PREFIX, ADMIN_PENDING, HostError, STATE, STACK

ROOT = Path(__file__).resolve().parents[2]
NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
# The desks live in this NVIDIA workspace (up.sh's OPENSHELL_WORKSPACE). NVIDIA's CLI otherwise sends "default".
WORKSPACE = "desks"
REGISTRATION = "ekka-agent-desks"
SETUP_CLIENT = "desks-setup"
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class Terminated(BaseException):
    """A termination signal arrived; the temporary administrator is still switched off before exit."""


def _terminate(signum, frame):
    raise Terminated()


@contextlib.contextmanager
def _signals(handler, which=STOP_SIGNALS):
    previous = {number: signal.getsignal(number) for number in which}
    try:
        for number in which:
            signal.signal(number, handler)
        yield
    finally:
        for number, old in previous.items():
            if old is not None:
                signal.signal(number, old)


def validate(runtime, argv):
    try:
        command = allow.check(argv)
    except allow.Refused:
        # Legacy diagnostics mention up.sh. Native recovery names its own door.
        raise HostError("emergency stop requires exactly one plain desk name") from None
    if command != allow.STOP:
        raise HostError("this recovery door allows named emergency stop only; use ekka desk for ordinary operations")
    if not runtime.installed():
        raise HostError("the default desks installation is not complete")
    service = runtime.service(STACK)
    if service["LoadState"] != "loaded" or service["ActiveState"] != "active":
        raise HostError("the desks stack must be active before gateway recovery")
    root_directory(STATE)
    names = [line.split("=", 1)[1] for line in root_file(STATE / "desks.env").splitlines()
             if line.startswith("DESKS_NAME=")]
    if len(names) != 1 or not NAME.fullmatch(names[0]) or ".." in names[0]:
        raise HostError("host settings must contain one plain gateway DNS name")
    binary = STATE / "bin/openshell"
    root_directory(binary.parent)
    info = binary.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111:
        raise HostError("the installed NVIDIA CLI must be a root-owned executable regular file")
    root_file(STATE / "tls/ca.crt")
    root_file(STATE / "secrets/keycloak-admin-password", private=True)
    # This script and its imported realm definition are trusted installation code.
    script = ROOT / "deploy/keycloak/apply_realm.py"
    root_file(script)
    root_file(script.with_name("realm.json"))
    try:
        version = json.loads(root_file(ROOT / "deploy/pins.json"))["openshell"]["version"]
    except (ValueError, KeyError, TypeError):
        raise HostError("the installed NVIDIA version pin could not be read") from None
    if not isinstance(version, str):
        raise HostError("invalid NVIDIA CLI version pin")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise HostError("invalid NVIDIA CLI version pin")
    actual = runtime.run([str(binary), "--version"]).stdout.strip().split()
    if not actual or actual[-1] != version:
        raise HostError("the installed NVIDIA CLI does not match this installation's version pin")
    return names[0], binary, script


def emergency_stop(runtime, desk):
    argv = ["sandbox", "stop", desk]
    name, binary, script = validate(runtime, argv)
    # One lock for every temporary-admin session, native and up.sh alike (up.sh's as_gateway_admin takes it too).
    # Otherwise one could disable the other's identity while its request is still running, or re-enable it.
    fd = os.open(STATE / "gateway-admin.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        # The command runs as root (cli.main refuses otherwise), so the owner must be root.
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise HostError("gateway recovery lock must be a private root-owned regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostError("another gateway administrator session is running; run this again when it finishes") from None
        # SIGTERM and SIGHUP raise, so the cleanup below still runs; Ctrl-C already raises KeyboardInterrupt.
        with _signals(_terminate, (signal.SIGTERM, signal.SIGHUP)):
            _reconcile(runtime, script)
            _run(runtime, argv, name, binary, script)
    finally:
        os.close(fd)


def _keycloak(script):
    env = {"KC_URL": "https://127.0.0.1:8443", "KC_CA": str(STATE / "tls/ca.crt"),
           "KC_ADMIN_USER": "desks-bootstrap",
           "KC_ADMIN_PASSWORD_FILE": str(STATE / "secrets/keycloak-admin-password"),
           "PYTHONDONTWRITEBYTECODE": "1"}
    return ["/usr/bin/python3", str(script), "setup-client"], env


def _disable(runtime, kc, kc_env):
    """Switch the setup client off and read it back. Termination signals and console output cannot stop it:
    they are ignored (children inherit that) and nothing is printed while it runs."""
    try:
        with _signals(signal.SIG_IGN):
            runtime.run([*kc, "off"], environment=kc_env, quiet=True)
            # A successful PUT alone is not proof the identity is disabled.
            return runtime.run([*kc, "status"], environment=kc_env, quiet=True).stdout.strip() == "disabled"
    except Exception:
        return False


def _private_marker(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise HostError("the gateway administrator session marker must be a private regular file")
        os.write(fd, b"open\n")
        os.fsync(fd)
    finally:
        os.close(fd)


def _reconcile(runtime, script):
    """A session that ended abruptly (SIGKILL, power loss) left its marker or its temporary home. Switch the client
    off and remove that sign-in before anything else is enabled."""
    leftovers = sorted(p for p in STATE.iterdir() if p.name.startswith(ADMIN_HOME_PREFIX))
    pending = STATE / ADMIN_PENDING
    if not leftovers and not os.path.lexists(pending):
        return
    runtime.audit("gateway-admin reconcile", "requested")
    kc, kc_env = _keycloak(script)
    if not _disable(runtime, kc, kc_env):
        runtime.audit("gateway-admin reconcile", "temporary_admin_disable_not_verified")
        raise HostError("a previous gateway administrator session did not finish and its setup client is not confirmed "
                        "disabled; disable desks-setup in Keycloak before retrying")
    for path in leftovers:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise HostError("an unexpected entry uses the temporary administrator folder name; inspect " + str(path))
        shutil.rmtree(path)
    with contextlib.suppress(FileNotFoundError):
        pending.unlink()
    runtime.audit("gateway-admin reconcile", "previous_session_closed")
    runtime.output("A previous gateway administrator session did not finish; its setup client is now confirmed "
                   "disabled and its temporary sign-in removed.")


def _registered(config, endpoint, issuer):
    """The registration NVIDIA's CLI kept, read back before any sign-in uses the secret. A failed `gateway add`
    can remove it and still exit zero; `login` would then fall back to another registration of the same name."""
    path = Path(config) / "openshell" / "gateways" / REGISTRATION / "metadata.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise HostError("the temporary gateway registration was not kept; no sign-in was attempted") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise HostError("the temporary gateway registration is not a regular file; no sign-in was attempted")
        data = os.read(fd, 65537)
    finally:
        os.close(fd)
    try:
        metadata = json.loads(data) if len(data) <= 65536 else None
    except ValueError:
        metadata = None
    expected = {"gateway_endpoint": endpoint, "auth_mode": "oidc", "oidc_issuer": issuer,
                "oidc_client_id": SETUP_CLIENT}
    if not isinstance(metadata, dict) or any(metadata.get(k) != v for k, v in expected.items()):
        raise HostError("the temporary gateway registration does not name this gateway's endpoint, issuer and "
                        "client; no sign-in was attempted")


def _run(runtime, argv, name, binary, script):
    action = "emergency-stop " + argv[-1]
    runtime.audit(action, "requested")
    kc, kc_env = _keycloak(script)
    pending = STATE / ADMIN_PENDING
    secret = ""
    failed = None
    # Written before access is enabled, removed only after it is confirmed disabled.
    _private_marker(pending)
    try:
        # `on` can fail AFTER enabling access. The finally block runs even then.
        secret = runtime.run([*kc, "on"], environment=kc_env).stdout
        if not secret or len(secret) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
            raise HostError("the temporary gateway credential was not returned correctly")
        with tempfile.TemporaryDirectory(prefix=ADMIN_HOME_PREFIX, dir=STATE) as home:
            config = Path(home) / "config"
            system = Path(home) / "system"
            system.mkdir(mode=0o700)   # empty: no registration outside this session can be used
            endpoint = "https://" + name + ":8080"
            issuer = "https://" + name + "/realms/ekka-desks"
            env = {"HOME": home, "XDG_CONFIG_HOME": str(config), "OPENSHELL_SYSTEM_GATEWAY_DIR": str(system),
                   "SSL_CERT_FILE": str(STATE / "tls/ca.crt"), "OPENSHELL_OIDC_CLIENT_SECRET": secret}
            runtime.run([str(binary), "gateway", "add", endpoint, "--name", REGISTRATION, "--oidc-issuer", issuer,
                         "--oidc-client-id", SETUP_CLIENT, "--oidc-audience", "ekka-desks"], environment=env)
            _registered(config, endpoint, issuer)
            runtime.run([str(binary), "gateway", "login", REGISTRATION], environment=env)
            runtime.run([str(binary), "-g", REGISTRATION, "--workspace", WORKSPACE, *argv],
                        environment=env, timeout=150)
    except BaseException as error:
        failed = error
    secret = ""
    # A signal that lands before _disable has switched signals off interrupts nothing: it is retried.
    while True:
        try:
            disabled = _disable(runtime, kc, kc_env)
            break
        except (Terminated, KeyboardInterrupt) as error:
            failed = failed or error
    if not disabled:
        runtime.audit(action, "temporary_admin_disable_not_verified")
        raise HostError("the temporary setup client may still be enabled; disable desks-setup in Keycloak before retrying") from None
    with contextlib.suppress(FileNotFoundError):
        pending.unlink()
    if failed is not None:
        runtime.audit(action, "not_verified_admin_disabled")
        if isinstance(failed, (KeyboardInterrupt, SystemExit)):
            raise failed
        if isinstance(failed, Terminated):
            raise HostError("stopped by a termination signal; its setup client was disabled; inspect before retrying") from None
        raise HostError("gateway command did not complete; its setup client was disabled; inspect before retrying") from None
    runtime.audit(action, "command_completed_admin_disabled")
    runtime.output("Emergency stop was acknowledged and its temporary setup client is disabled.")
    # Do not echo arbitrary vendor output, which can contain provider configuration.
    runtime.output("Confirm the desk's state with ekka desk status; the acknowledgement alone is not a state check.")
