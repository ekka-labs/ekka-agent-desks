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
LOCK = "gateway-admin.lock"          # up.sh's as_gateway_admin locks the same file
LEGACY_HOME = "openshell-admin"      # up.sh's session folder, which its marker names
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class Terminated(BaseException):
    """A termination signal arrived; the temporary administrator is still switched off before exit."""


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
    # Every child of the session inherits this lock (keep_fds), so a child still running after this process died,
    # an `on` in flight for example, keeps the next session out until it has finished.
    fd = os.open(STATE / LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        # The command runs as root (cli.main refuses otherwise), so the owner must be root.
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise HostError("gateway recovery lock must be a private root-owned regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostError("another gateway administrator session is running; run this again when it finishes") from None
        # Ctrl-C, SIGTERM and SIGHUP are noted, never raised: the session stops after the step it is in, and no signal
        # can land between that step and the cleanup that switches access off.
        noted = []
        with _signals(lambda number, frame: noted.append(number)):
            _reconcile(runtime, script, fd)
            _run(runtime, argv, name, binary, script, fd, noted)
    finally:
        os.close(fd)


def _keycloak(script):
    env = {"KC_URL": "https://127.0.0.1:8443", "KC_CA": str(STATE / "tls/ca.crt"),
           "KC_ADMIN_USER": "desks-bootstrap",
           "KC_ADMIN_PASSWORD_FILE": str(STATE / "secrets/keycloak-admin-password"),
           "PYTHONDONTWRITEBYTECODE": "1"}
    return ["/usr/bin/python3", str(script), "setup-client"], env


def _disable(runtime, kc, kc_env, fd=None):
    """Switch the setup client off and read it back. Termination signals and console output cannot stop it:
    they are ignored (children inherit that) and nothing is printed while it runs."""
    keep = () if fd is None else (fd,)
    try:
        with _signals(signal.SIG_IGN):
            runtime.run([*kc, "off"], environment=kc_env, quiet=True, keep_fds=keep)
            # A successful PUT alone is not proof the identity is disabled.
            return runtime.run([*kc, "status"], environment=kc_env, quiet=True,
                               keep_fds=keep).stdout.strip() == "disabled"
    except Exception:
        return False


def _sync_state():
    folder = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(folder)
    finally:
        os.close(folder)


def _write_marker(record):
    """The open session, durably: written (file and folder synced) before access is enabled."""
    fd = os.open(STATE / ADMIN_PENDING, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise HostError("the gateway administrator session marker must be a private regular file")
        data = (json.dumps(record, sort_keys=True) + "\n").encode()
        if os.write(fd, data) != len(data):
            raise HostError("the gateway administrator session marker could not be written")
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync_state()


def _read_marker():
    """None when there is no marker; {} when it cannot be read as one (the client is still switched off)."""
    try:
        fd = os.open(STATE / ADMIN_PENDING, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        return {}
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return {}
        data = os.read(fd, 4097)
    finally:
        os.close(fd)
    try:
        record = json.loads(data) if len(data) <= 4096 else {}
    except ValueError:
        return {}
    return record if isinstance(record, dict) else {}


def _recorded_home(record):
    """The one temporary home a marker names, if it is still exactly that folder; never anything else."""
    home = record.get("home")
    if not isinstance(home, str):
        return None
    path = Path(home)
    if path.parent != STATE or not (path.name.startswith(ADMIN_HOME_PREFIX) or path.name == LEGACY_HOME):
        return None
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        return None
    if path.name != LEGACY_HOME and (record.get("dev"), record.get("ino")) != (info.st_dev, info.st_ino):
        return None
    return path


def _reconcile(runtime, script, fd=None):
    """A session that ended abruptly (SIGKILL, power loss) left its marker. Switch the client off and remove the
    sign-in folder that marker names, before anything else is enabled. Nothing the marker does not name is removed."""
    record = _read_marker()
    if record is None:
        strays = sorted(p.name for p in STATE.iterdir() if p.name.startswith(ADMIN_HOME_PREFIX))
        if strays:
            runtime.output("Left as they are, recorded by no session: " + ", ".join(strays))
        return
    try:
        runtime.audit("gateway-admin reconcile", "requested")
        audited = True
    except (OSError, HostError):
        audited = False     # switching access off is still attempted: it only ever removes access
    kc, kc_env = _keycloak(script)
    if not _disable(runtime, kc, kc_env, fd):
        with contextlib.suppress(OSError, HostError):
            runtime.audit("gateway-admin reconcile", "temporary_admin_disable_not_verified")
        raise HostError("a previous gateway administrator session did not finish and its setup client is not confirmed "
                        "disabled; disable desks-setup in Keycloak before retrying")
    home = _recorded_home(record)
    if home is not None:
        shutil.rmtree(home)
    (STATE / ADMIN_PENDING).unlink()
    _sync_state()
    if not audited:
        raise HostError("a previous gateway administrator session's setup client is now confirmed disabled, but the "
                        "host audit log cannot be written, so no new session was started")
    runtime.audit("gateway-admin reconcile", "previous_session_closed")
    runtime.output("A previous gateway administrator session did not finish; its setup client is now confirmed "
                   "disabled" + (" and its temporary sign-in removed." if home is not None else "."))


def _registered(config, endpoint, issuer):
    """The registration NVIDIA's CLI kept, read back before any sign-in uses the secret. A failed `gateway add`
    can remove it and still exit zero; `login` would then fall back to another registration of the same name."""
    path = Path(config) / "openshell" / "gateways" / REGISTRATION / "metadata.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
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


def _run(runtime, argv, name, binary, script, fd=None, noted=()):
    action = "emergency-stop " + argv[-1]
    runtime.audit(action, "requested")
    kc, kc_env = _keycloak(script)
    # The sign-in folder exists, and the marker names it, before access is enabled. It holds no secret until login.
    home = Path(tempfile.mkdtemp(prefix=ADMIN_HOME_PREFIX, dir=STATE))
    try:
        info = home.lstat()
        _write_marker({"home": str(home), "dev": info.st_dev, "ino": info.st_ino})
    except BaseException:
        shutil.rmtree(home, ignore_errors=True)
        raise
    failed = None

    def step(args, env, timeout=90):
        result = runtime.run(args, environment=env, timeout=timeout, keep_fds=() if fd is None else (fd,))
        if noted:
            raise Terminated()
        return result

    try:
        if noted:
            raise Terminated()
        # `on` can fail AFTER enabling access. The cleanup below runs even then.
        secret = step([*kc, "on"], kc_env).stdout
        if not secret or len(secret) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
            raise HostError("the temporary gateway credential was not returned correctly")
        config = home / "config"
        system = home / "system"
        system.mkdir(mode=0o700)   # empty: no registration outside this session can be used
        endpoint = "https://" + name + ":8080"
        issuer = "https://" + name + "/realms/ekka-desks"
        env = {"HOME": str(home), "XDG_CONFIG_HOME": str(config), "OPENSHELL_SYSTEM_GATEWAY_DIR": str(system),
               "SSL_CERT_FILE": str(STATE / "tls/ca.crt"), "OPENSHELL_OIDC_CLIENT_SECRET": secret}
        secret = ""
        step([str(binary), "gateway", "add", endpoint, "--name", REGISTRATION, "--oidc-issuer", issuer,
              "--oidc-client-id", SETUP_CLIENT, "--oidc-audience", "ekka-desks"], env)
        _registered(config, endpoint, issuer)
        step([str(binary), "gateway", "login", REGISTRATION], env)
        step([str(binary), "-g", REGISTRATION, "--workspace", WORKSPACE, *argv], env, timeout=150)
    except BaseException as error:
        failed = error
    env = None
    disabled = _disable(runtime, kc, kc_env, fd)
    with _signals(signal.SIG_IGN):
        shutil.rmtree(home, ignore_errors=True)
    if not disabled:
        runtime.audit(action, "temporary_admin_disable_not_verified")
        raise HostError("the temporary setup client may still be enabled; disable desks-setup in Keycloak before retrying") from None
    if not os.path.lexists(home):
        (STATE / ADMIN_PENDING).unlink()
        _sync_state()
    if failed is not None:
        runtime.audit(action, "not_verified_admin_disabled")
        if isinstance(failed, (KeyboardInterrupt, SystemExit)):
            raise failed
        if noted or isinstance(failed, Terminated):
            raise HostError("stopped by a signal; its setup client was disabled; inspect before retrying") from None
        raise HostError("gateway command did not complete; its setup client was disabled; inspect before retrying") from None
    runtime.audit(action, "command_completed_admin_disabled")
    runtime.output("Emergency stop was acknowledged and its temporary setup client is disabled.")
    # Do not echo arbitrary vendor output, which can contain provider configuration.
    runtime.output("Confirm the desk's state with ekka desk status; the acknowledgement alone is not a state check.")
