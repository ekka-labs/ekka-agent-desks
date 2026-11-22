"""Native named emergency stop, with a temporary administrator client.

Provider changes and ordinary desk changes belong to governed EKKA commands.
The vendor binary is already installed and verified by installation; this path
neither downloads a binary nor evaluates the installation's environment files.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile

import openshell_allow as allow
from .files import root_directory, root_file
from .runtime import HostError, STATE, STACK

ROOT = Path(__file__).resolve().parents[2]
NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")


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
    # Serialize native temporary-admin sessions. Otherwise one could disable the
    # other's identity while its request is still running.
    fd = os.open(STATE / "gateway-admin.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            raise HostError("gateway recovery lock must be a private root-owned regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostError("another native gateway recovery command is running") from None
        _run(runtime, argv, name, binary, script)
    finally:
        os.close(fd)


def _run(runtime, argv, name, binary, script):
    action = "emergency-stop " + argv[-1]
    runtime.audit(action, "requested")
    kc_env = {"KC_URL": "https://127.0.0.1:8443", "KC_CA": str(STATE / "tls/ca.crt"),
              "KC_ADMIN_USER": "desks-bootstrap",
              "KC_ADMIN_PASSWORD_FILE": str(STATE / "secrets/keycloak-admin-password"),
              "PYTHONDONTWRITEBYTECODE": "1"}
    kc = ["/usr/bin/python3", str(script), "setup-client"]
    secret = ""
    failed = None
    disabled = False
    try:
        # `on` can fail AFTER enabling access. The finally block runs even then.
        secret = runtime.run([*kc, "on"], environment=kc_env).stdout
        if not secret or len(secret) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
            raise HostError("the temporary gateway credential was not returned correctly")
        with tempfile.TemporaryDirectory(prefix=".gateway-admin-", dir=STATE) as home:
            env = {"HOME": home, "SSL_CERT_FILE": str(STATE / "tls/ca.crt"),
                   "OPENSHELL_OIDC_CLIENT_SECRET": secret}
            runtime.run([str(binary), "gateway", "add", "https://" + name + ":8080",
                         "--name", "ekka-agent-desks", "--oidc-issuer", "https://" + name + "/realms/ekka-desks",
                         "--oidc-client-id", "desks-setup", "--oidc-audience", "ekka-desks"], environment=env)
            runtime.run([str(binary), "gateway", "login", "ekka-agent-desks"], environment=env)
            runtime.run([str(binary), "-g", "ekka-agent-desks", *argv], environment=env, timeout=150)
    except BaseException as error:
        failed = error
    finally:
        secret = ""
        try:
            runtime.run([*kc, "off"], environment=kc_env)
            # A successful PUT alone is not proof the identity is disabled.
            state = runtime.run([*kc, "status"], environment=kc_env).stdout.strip()
            if state != "disabled":
                raise HostError("the setup client is not confirmed disabled")
            disabled = True
        except BaseException:
            pass
    if not disabled:
        runtime.audit(action, "temporary_admin_disable_not_verified")
        raise HostError("the temporary setup client may still be enabled; disable desks-setup in Keycloak before retrying") from None
    if failed is not None:
        runtime.audit(action, "not_verified_admin_disabled")
        if isinstance(failed, (KeyboardInterrupt, SystemExit)):
            raise failed
        raise HostError("gateway command did not complete; its setup client was disabled; inspect before retrying") from None
    runtime.audit(action, "command_completed_admin_disabled")
    runtime.output("Emergency stop was acknowledged and its temporary setup client is disabled.")
    # Do not echo arbitrary vendor output, which can contain provider configuration.
    runtime.output("Confirm the desk's state with ekka desk status; the acknowledgement alone is not a state check.")
