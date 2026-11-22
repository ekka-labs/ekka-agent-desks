"""Native host recovery uses the existing settle procedure, without up.sh."""
import shlex
from pathlib import Path

import desks_settle as procedure
from .runtime import HostError, STATE, STACK
from .files import root_file

ENV_FILE = Path("/etc/ekka/desks.env")


def environment():
    values = [line.split("=", 1)[1] for line in root_file(ENV_FILE).splitlines()
              if line.startswith("EKKA_ENV=")]
    if len(values) != 1 or values[0] not in ("local", "dev", "staging", "prod"):
        raise HostError("host settings must name one EKKA_ENV; no recovery was started")
    return values[0]


def recover(runtime, verb, desk, operation, backend_id=None):
    if not procedure.DESK.fullmatch(desk) or not procedure.UUID.fullmatch(operation):
        raise HostError("recovery needs a plain desk name and a lowercase operation UUID")
    if backend_id is not None and not procedure.UUID.fullmatch(backend_id):
        raise HostError("the backend id must be a lowercase UUID")
    if verb not in ("settle", "unhold") or (verb == "unhold" and backend_id is not None):
        raise HostError("invalid recovery action")
    if not runtime.installed():
        raise HostError("the default desks installation is not complete")
    service = runtime.service(STACK)
    if service["LoadState"] != "loaded" or service["ActiveState"] != "active" or service.get("UnitFileState") in ("masked", "masked-runtime"):
        raise HostError("the desks stack must be active and unmasked before recovery")
    env = environment()
    # Read settings before any action, with a fixed state root, never shell input.
    root_file(STATE / "backend" / "config.json")
    root_file(STATE / "gateway.toml")
    identity = ["/usr/sbin/runuser", "-u", "ekka", "--", "/usr/bin/env", "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/var/lib/ekka",
                "EKKA_HOME=/var/lib/ekka/.ekka", "EKKA_ENV=" + env, "LANG=C.UTF-8"]

    def docker(args, stdin=None):
        result = runtime.run(["/usr/bin/docker", *args], allowed=range(256),
                             stdin=stdin, timeout=150)
        return result.returncode, result.stdout

    def ekka(args):
        result = runtime.run([*identity, "/usr/local/bin/ekka", *args], allowed=range(256))
        return result.returncode, result.stdout

    def read_lock(path):
        # A path in the Enclave's home is read as that user, never as root.
        result = runtime.run([*identity, "/usr/bin/cat", "--", path], allowed=range(256))
        if result.returncode != 0:
            raise OSError("the Enclave lock could not be read")
        return result.stdout

    args = [desk, "--operation", operation]
    if backend_id is not None:
        args.extend(["--backend-id", backend_id])
    if verb == "unhold":
        args.insert(0, "--unhold")
    action = " ".join([verb, desk, operation])
    runtime.audit(action, "requested")
    try:
        result = procedure.main(args, run=docker, ekka=ekka, read=read_lock, state=str(STATE),
                                unhold_command="sudo " + shlex.quote(str(Path(__file__).resolve().parents[2] / "ekka-desk-host")) + " unhold")
        if result != 0:
            raise HostError("recovery did not complete; inspect the desk and any retained hold")
    except Exception:
        runtime.audit(action, "not_verified")
        raise
    runtime.audit(action, "procedure_completed")
    # The backend consumes a settle marker on the next governed status read.
    runtime.output("Recovery procedure completed; confirm the outcome with ekka desk status " + desk)
