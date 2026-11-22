"""The narrow system-service boundary of ekka-desk-host.

No shell, inherited tool selection, environment-file evaluation or desk action.
The initial release operates the existing default installation only.
"""
import datetime
import fcntl
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess

ENCLAVE = "ekka.service"
STACK = "ekka-desks.service"
STATE = Path("/var/lib/ekka-agent-desks")
SOCKET = Path("/run/ekka/openshell-interceptor.sock")
AUDIT = Path("/var/log/ekka-desk-host.jsonl")
# Present while a temporary gateway administrator session is open; left behind only if that session ended abruptly.
ADMIN_PENDING = "gateway-admin.pending"
ADMIN_HOME_PREFIX = ".gateway-admin-"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class HostError(Exception):
    """A host action could not be completed or verified."""


class Runtime:
    def __init__(self, output=print):
        self.output = output

    def run(self, args, allowed=(0,), stdin=None, timeout=90, environment=None, quiet=False, keep_fds=()):
        # Cleanup runs quietly: a closed console must never stop the command that switches access off.
        if not quiet:
            self.output("→ " + shlex.join(args))
        try:
            result = subprocess.run(args, input=stdin,
                                    stdin=subprocess.DEVNULL if stdin is None else None,
                                    capture_output=True, text=True, env={**ENV, **(environment or {})},
                                    timeout=timeout, check=False, pass_fds=tuple(keep_fds))
        except (OSError, subprocess.TimeoutExpired) as error:
            # A timeout is an unknown result; do not automatically retry a change.
            raise HostError("command did not finish; inspect the host before retrying") from error
        if result.returncode not in allowed:
            # Do not echo arbitrary service/tool output into operator logs.
            raise HostError("command failed with exit code " + str(result.returncode))
        return result

    def service(self, unit):
        raw = self.run(["/usr/bin/systemctl", "show", unit, "--no-pager",
                        "--property=LoadState,ActiveState,SubState,UnitFileState,Result"]).stdout.strip()
        values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        if not {"LoadState", "ActiveState", "SubState"} <= values.keys():
            raise HostError("systemd returned an incomplete service status")
        return values

    def socket_exists(self):
        try:
            return stat.S_ISSOCK(SOCKET.lstat().st_mode)
        except FileNotFoundError:
            return False

    def installed(self):
        return (STATE / "up" / "started").is_file()

    def unfinished_admin_session(self):
        """True when a temporary gateway administrator session left its marker and no session holds the lock now:
        a session in progress also has a marker, and is not reported as abandoned."""
        if not os.path.lexists(STATE / ADMIN_PENDING):
            return False
        try:
            fd = os.open(STATE / "gateway-admin.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return True
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        finally:
            os.close(fd)
        return True

    def audit(self, action, outcome):
        record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "action": action, "outcome": outcome, "uid": os.getuid(),
                  "sudo_uid": os.environ.get("SUDO_UID")}
        # A local attacker must not redirect root's log through a link, or make
        # it writable by a desk. Refuse the action if its audit cannot be kept.
        fd = os.open(AUDIT, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
                raise HostError("host audit log must be a root-owned private regular file")
            encoded = (json.dumps(record, sort_keys=True) + "\n").encode()
            if os.write(fd, encoded) != len(encoded):
                raise HostError("host audit record could not be completely written")
            os.fsync(fd)
        finally:
            os.close(fd)


def status(runtime):
    if not runtime.installed():
        raise HostError("the default desks installation is not complete")
    enclave = runtime.service(ENCLAVE)
    stack = runtime.service(STACK)
    socket = runtime.socket_exists()
    for name, values in ((ENCLAVE, enclave), (STACK, stack)):
        runtime.output(name + ": " + values["LoadState"] + ", " + values["ActiveState"] + "/" + values["SubState"])
        if values.get("UnitFileState") in ("masked", "masked-runtime"):
            runtime.output(name + " is masked; this command does not remove an emergency stop")
        if values.get("Result") == "start-limit-hit":
            runtime.output(name + " reached its start limit; inspect its journal before restarting")
    runtime.output("interceptor socket: " + ("present" if socket else "missing"))
    unfinished = runtime.unfinished_admin_session()
    if unfinished:
        runtime.output("gateway setup client: a temporary administrator session did not finish; treat desks-setup "
                       "as enabled until the next emergency-stop switches it off and removes its sign-in")
    if unfinished or any(s["LoadState"] != "loaded" or s["ActiveState"] != "active"
           for s in (enclave, stack)) or not socket:
        raise HostError("host services are not ready")
    # This is host readiness, not a claim that a desk job or model works.


def stack_change(runtime, verb):
    if verb not in ("start", "stop"):
        raise HostError("only stack start and stop are supported")
    if not runtime.installed():
        raise HostError("the default desks installation is not complete")
    if verb == "start":
        enclave = runtime.service(ENCLAVE)
        if enclave["LoadState"] != "loaded" or enclave["ActiveState"] != "active" or not runtime.socket_exists():
            raise HostError("start the Enclave and check its interceptor before starting the desks stack")
    current = runtime.service(STACK)
    if current["LoadState"] != "loaded":
        raise HostError("the desks stack service is not loaded; no change was made")
    if verb == "start" and current.get("UnitFileState") in ("masked", "masked-runtime"):
        raise HostError("the desks stack is masked; no emergency stop was removed")
    runtime.audit("stack " + verb, "requested")
    try:
        runtime.run(["/usr/bin/systemctl", verb, STACK])
        after = runtime.service(STACK)
        expected = "active" if verb == "start" else "inactive"
        if after["LoadState"] != "loaded" or after["ActiveState"] != expected:
            raise HostError("stack did not reach " + expected + "; inspect its journal")
    except Exception:
        runtime.audit("stack " + verb, "not_verified")
        raise
    runtime.audit("stack " + verb, "verified_" + expected)
    runtime.output("desks stack: " + expected)
