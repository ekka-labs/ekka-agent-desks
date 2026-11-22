"""Settle ONE unfinished desk change on this machine (EKKA regression coverage).

    sudo ./up.sh desks settle <desk> --operation <request id> [--backend-id <uuid>]
    sudo ./up.sh desks unhold <desk> --operation <request id>

EKKA does not settle an unfinished desk change on its own; this procedure does, for one named change, after it has
seen that desk stop changing. The change is named by its request id, the lowercase UUID that `ekka desk status`
prints, that a `running` answer carries, and that the desk's lock holds. In order:

  1. The desk's lock must be exactly `admin:<request id>` (with ` unknown` while its outcome is unknown): the
     Enclave's claim for this change. Otherwise there is nothing to settle: it says who holds the desk, if anyone,
     and changes nothing.
  2. A hold is written first (@ekka-ai/contracts backend/settle-hold.v1.schema.json), as `settle/<request id>.hold`
     in the adapter's state: while it exists the adapter never re-issues the change, so nothing sends it again
     after the restart. A hold left by an earlier settle that stopped is kept as it is.
  3. The gateway restarts, so no handler of the change is still alive.
  4. The desk's containers, found by NVIDIA OpenShell's labels, are watched until none is in a transitional state
     and their set and states have not changed for the quiet window: the driver's stop timeout plus 30 seconds. The
     Docker daemon finishes a stop or a remove on its own, so a gateway restart alone proves nothing. After 10
     minutes it gives up, prints the states and writes no marker.
  5. The lock is read again. If it no longer names this change, the change was settled meanwhile; no marker, and
     the hold is removed.
  6. The marker (@ekka-ai/contracts backend/settle-marker.v1.schema.json) is written to the backend adapter's state
     volume as `settle/<request id>.json`, owned by the adapter's user, mode 0600, through a one-shot container with
     no network, and the hold is removed in the same step. The adapter reads the marker once, for this change only,
     at the next `ekka desk status`.

If it stops anywhere after step 2, the hold STAYS and the change stays held. A person checks the desk, then removes
the hold with `up.sh desks unhold`; the adapter may then re-issue the change, or it is settled again. Unhold removes a
hold only while the named desk's lock still names that change, so a hold is never released through another desk.
One settle or unhold runs at a time on a machine (`settle.lock` in the installation's state folder).

The gateway restart in step 3 stops every running desk on this machine, not only this one: NVIDIA OpenShell's
gateway stops the sandboxes it manages when it shuts down. Jobs running on other desks are interrupted too.

Standard library only. Every Docker call goes through one function, so the tests replace it.
"""
import contextlib
import datetime as dt
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import time

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DESK = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
ENCLAVE_USER = "ekka"            # the native Enclave's user; its home is below
ENCLAVE_HOME = "/var/lib/ekka/.ekka"
GATEWAY = "ekka-desks-gateway-1"
STATE_VOLUME = "ekka-desks_ekka-backend-state"
# The one-shot writer: the alpine image compose.yml already pins (gateway-init), never a tag.
WRITER_IMAGE = "alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
ADAPTER_USER = "2000:1000"
TRANSITIONAL = {"created", "restarting", "removing"}
DOCKER_STATES = {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
DEFAULT_STOP_TIMEOUT = 10        # NVIDIA OpenShell's Docker driver, the same in 0.1.3 and 0.1.4: openshell-core config.rs:32
QUIET_EXTRA = 30
GIVE_UP_AFTER = 600
POLL = 2
LOCK_LIMIT = 512                 # a lock holds one short line: `admin:<uuid>[ unknown]` or a job's attempt id
ADMIN_LOCK = re.compile(r"admin:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?: unknown)?")
JOB_LOCK = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
# Read as the Enclave's user, by a bounded reader that follows no link at ANY level: it walks from / one folder at a
# time, each opened with O_NOFOLLOW | O_DIRECTORY, then opens the lock itself with O_NOFOLLOW and refuses anything but
# a regular file with one link. Exit 3: the lock file itself is absent (nothing holds the desk). Any other non-zero
# exit (7: a folder on the way is missing or not a real folder) means the lock could not be read safely.
LOCK_READER = (
    "import os, stat, sys\n"
    "parts = sys.argv[1].split('/')\n"
    "if parts[0] != '' or any(p in ('', '.', '..') for p in parts[1:]):\n"
    "    sys.exit(8)\n"
    "fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)\n"
    "for part in parts[1:-1]:\n"
    "    try:\n"
    "        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)\n"
    "    except OSError:\n"
    "        sys.exit(7)\n"
    "try:\n"
    "    fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY, dir_fd=fd)\n"
    "except FileNotFoundError:\n"
    "    sys.exit(3)\n"
    "except OSError:\n"
    "    sys.exit(4)\n"
    "info = os.fstat(fd)\n"
    "if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:\n"
    "    sys.exit(5)\n"
    f"data = os.read(fd, {LOCK_LIMIT + 1})\n"
    f"if len(data) > {LOCK_LIMIT}:\n"
    "    sys.exit(6)\n"
    "sys.stdout.write(data.decode('ascii'))\n")
USAGE = ("usage: sudo ./up.sh desks settle <desk> --operation <request id> [--backend-id <uuid>]\n"
         "       sudo ./up.sh desks unhold <desk> --operation <request id>")


class Refused(Exception):
    """A reason to stop with nothing written."""


def docker(args, stdin=None):
    r = subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True,
                       stdin=None if stdin is not None else subprocess.DEVNULL)
    return r.returncode, r.stdout


def enclave_ekka(args):
    """The ekka command as the native Enclave's user, with its home and a clean environment (deploy/lib.sh)."""
    env = os.environ.get("EKKA_ENV", "prod")
    r = subprocess.run(["runuser", "-u", ENCLAVE_USER, "--", "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
                        "HOME=/var/lib/ekka", f"EKKA_HOME={ENCLAVE_HOME}", f"EKKA_ENV={env}", "LANG=C.UTF-8",
                        "/usr/local/bin/ekka", *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout


def read_as_enclave(path):
    """The desk's lock, read as the native Enclave's user (never as root) through LOCK_READER."""
    r = subprocess.run(["runuser", "-u", ENCLAVE_USER, "--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin",
                        "HOME=/var/lib/ekka", "LANG=C.UTF-8", "/usr/bin/python3", "-I", "-c", LOCK_READER, path],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if r.returncode == 3:
        raise FileNotFoundError(path)
    if r.returncode != 0:
        raise OSError("the desk lock could not be read")
    return r.stdout


@contextlib.contextmanager
def one_at_a_time(state):
    """One settle or unhold at a time on this machine, so an unhold never removes a hold a settle is still using."""
    try:
        fd = os.open(os.path.join(state, "settle.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise Refused("the settle lock in the installation's state folder could not be opened; nothing was "
                      "changed") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise Refused("the settle lock in the installation's state folder is not a private regular file; "
                          "nothing was changed")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("another settle or unhold is running on this machine; nothing was changed. "
                          "Run this again when it finishes") from None
        yield
    finally:
        os.close(fd)


def now():
    return dt.datetime.now(dt.timezone.utc)


def stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def stop_timeout(gateway_toml_text):
    """The Docker driver's stop timeout: the gateway's config if it sets one, else OpenShell's fixed default."""
    section = re.search(r"^\[openshell\.drivers\.docker\]\s*$(.*?)(?=^\[|\Z)", gateway_toml_text, re.M | re.S)
    if section:
        m = re.search(r"^\s*stop_timeout_secs\s*=\s*(\d+)", section.group(1), re.M)
        if m:
            return int(m.group(1))
    return DEFAULT_STOP_TIMEOUT


def holds(lock_text, operation_id):
    """True when the lock is this change's claim: exactly `admin:<id>`, or `admin:<id> unknown`."""
    held = (lock_text or "").strip()
    return held in (f"admin:{operation_id}", f"admin:{operation_id} unknown")


def holder(lock_text):
    """Who the lock names, for the operator: a job's attempt, another change, or nobody. Only a lock in one of the
    two shapes the Enclave writes is quoted; anything else is described, never printed."""
    held = (lock_text or "").strip()
    if not held:
        return "nothing holds it"
    if ADMIN_LOCK.fullmatch(held):
        return f"another change holds it ({held})"
    if JOB_LOCK.fullmatch(held):
        return f"a job holds it (attempt {held})"
    return "the lock holds something this procedure does not recognize"


def containers(desk, run=docker):
    """[(id, state, sandbox id)] of the desk's containers, by OpenShell's labels."""
    rc, out = run(["ps", "-a", "--no-trunc", "--filter", "label=openshell.ai/managed-by=openshell",
                   "--filter", f"label=openshell.ai/sandbox-name={desk}",
                   "--format", '{{.ID}}\t{{.State}}\t{{.Label "openshell.ai/sandbox-id"}}'])
    if rc != 0:
        raise Refused("docker cannot list the desk's containers")
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and re.fullmatch(r"[0-9a-f]{64}", parts[0]) and parts[1] in DOCKER_STATES:
            rows.append((parts[0], parts[1], parts[2]))
        elif line.strip():
            raise Refused(f"docker answered a container line this procedure cannot read: {line[:80]!r}")
    return sorted(rows)


def wait_quiet(desk, window, run=docker, clock=now, sleep=time.sleep, give_up=GIVE_UP_AFTER, poll=POLL):
    """Wait until no container is transitional and the set and states are unchanged for `window` seconds."""
    start = clock()
    last, quiet_since = None, None
    while True:
        rows = containers(desk, run)
        snap = [(c, s) for c, s, _ in rows]
        t = clock()
        if any(s in TRANSITIONAL for _, s in snap):
            quiet_since = None
        elif snap != last or quiet_since is None:
            quiet_since = t
        last = snap
        if quiet_since is not None and (t - quiet_since).total_seconds() >= window:
            return rows, t
        if (t - start).total_seconds() >= give_up:
            states = ", ".join(f"{c[:12]} {s}" for c, s in snap) or "no containers"
            raise Refused(f"the desk did not stop changing within {give_up // 60} minutes ({states}); "
                          "no marker was written")
        sleep(poll)


def in_state(script, stdin=None, run=docker):
    """One shell script in the adapter's state volume, as the adapter's user, with no network: the only way this
    procedure writes or removes anything there."""
    return run(["run", "--rm", "-i", "--network", "none", "--user", ADAPTER_USER, "-v", f"{STATE_VOLUME}:/s",
                WRITER_IMAGE, "sh", "-c", script], stdin)


def write_hold(operation_id, at, run=docker):
    """The hold (settle-hold.v1), written before the restart: umask 077 makes it 0600, written beside then renamed.
    Returns the hold written, or None when one was already there."""
    hold = {"operation_id": operation_id, "held_at": stamp(at)}
    script = (f"umask 077; mkdir -p /s/settle; h=/s/settle/{operation_id}.hold; "
              "if [ -e \"$h\" ]; then echo held; exit 4; fi; "
              "cat > \"$h.tmp\" && mv \"$h.tmp\" \"$h\"")
    rc, _ = in_state(script, json.dumps(hold), run)
    if rc == 4:
        return None
    if rc != 0:
        raise Refused("the hold could not be written to the adapter's state volume; nothing was restarted")
    return hold


def remove_hold(operation_id, run=docker):
    """True when a hold was there and is gone, False when there was none."""
    rc, said = in_state(f"h=/s/settle/{operation_id}.hold; if [ -e \"$h\" ]; then rm -f \"$h\" && echo removed; "
                        "else echo none; fi", None, run)
    if rc != 0:
        raise Refused(f"the hold for {operation_id} could not be removed from the adapter's state volume")
    return "removed" in said


def gateway_identity(config_text):
    """`<backend_gateway.url>#<backend_gateway.workspace>` from the backend adapter's own config.json, the string the
    adapter compares a marker's gateway_identity with, byte for byte (@ekka-ai/contracts settle-marker.v1). Read from
    that file, never restated here, so the two cannot disagree (regression review)."""
    try:
        bg = json.loads(config_text)["backend_gateway"]
        url, workspace = bg["url"], bg["workspace"]
    except (ValueError, KeyError, TypeError):
        raise Refused("the backend adapter's configuration names no backend_gateway url and workspace; "
                      "no marker can name its gateway") from None
    if not (isinstance(url, str) and url and isinstance(workspace, str) and workspace):
        raise Refused("the backend adapter's configuration names no backend_gateway url and workspace; "
                      "no marker can name its gateway")
    return f"{url}#{workspace}"


def settle(desk, operation_id, backend_id=None, run=docker, clock=now, sleep=time.sleep,
           restart=None, read_lock=None, gateway_toml="", give_up=GIVE_UP_AFTER, poll=POLL, out=print, identity=None, unhold_command="sudo ./up.sh desks unhold"):
    """The whole procedure. Returns the marker written, or None when there was nothing to settle."""
    if not DESK.match(desk):
        raise Refused(f"'{desk}' is not a desk name")
    if not UUID.match(operation_id):
        raise Refused("the operation is its request id, a lowercase UUID, as `ekka desk status` prints it")
    if backend_id is not None and not UUID.match(backend_id):
        raise Refused("--backend-id is the sandbox's id, a lowercase UUID")
    if not identity:
        raise Refused("no gateway identity from the backend adapter's configuration; nothing was changed")
    lock = read_lock()
    if not holds(lock, operation_id):
        out(f"change {operation_id} does not hold desk '{desk}': {holder(lock)}. Nothing to settle; nothing changed.")
        return None
    window = stop_timeout(gateway_toml) + QUIET_EXTRA
    if write_hold(operation_id, clock(), run) is None:
        out(f"change {operation_id} is already held (settle/{operation_id}.hold, from a settle that stopped); kept")
    else:
        out(f"held change {operation_id}: the adapter will not re-issue it (settle/{operation_id}.hold)")
    try:
        return _settle_held(desk, operation_id, backend_id, run, clock, sleep, restart, read_lock, window, give_up,
                            poll, out, identity)
    except Refused as e:
        raise Refused(f"{e}. The hold stays, so change {operation_id} is not re-issued. Check the desk with "
                      f"`ekka desk status {desk}`, then: {unhold_command} {desk} --operation {operation_id}") from e


def _settle_held(desk, operation_id, backend_id, run, clock, sleep, restart, read_lock, window, give_up, poll, out,
                 identity):
    """Steps 3 to 6, with the hold in place."""
    out("restarting the gateway, so no handler of the change is alive; running desks on this machine stop with it")
    restart()
    restarted_at = clock()
    out(f"watching desk '{desk}' until it has not changed for {window} s (at most {give_up // 60} minutes)")
    rows, quiet_until = wait_quiet(desk, window, run, clock, sleep, give_up, poll)
    lock = read_lock()
    if not holds(lock, operation_id):
        # Only positive evidence lets the hold go: the lock file is gone (None), or another change's claim replaced
        # it. Anything else, a job's attempt id included (one word proves nothing on its own), keeps the hold.
        if lock is not None and not ADMIN_LOCK.fullmatch(lock.strip()):
            raise Refused("the desk lock no longer names this change, but it names no other change either; "
                          "no marker was written")
        remove_hold(operation_id, run)
        out(f"change {operation_id} no longer holds desk '{desk}': it was settled meanwhile. No marker was written, "
            "and the hold is removed.")
        return None
    ids = {sid for _, _, sid in rows if sid}
    if len(ids) > 1:
        raise Refused(f"the desk's containers name {len(ids)} sandboxes; no marker was written")
    sandbox = ids.pop() if ids else backend_id
    if sandbox is None and rows:
        raise Refused("the desk's containers name no sandbox; no marker was written")
    # No desk found by its labels and no --backend-id: a create that never reached the desk. The marker says so with
    # a null backend id and no containers. The adapter accepts that only for a create, and only when its own read-back
    # after the restart finds no desk either; for a deleted desk, pass --backend-id from `ekka desk status`.
    if sandbox is not None and not UUID.match(sandbox):
        raise Refused("the containers name a sandbox id that is not a lowercase UUID; no marker was written")
    if backend_id is not None and sandbox != backend_id:
        raise Refused(f"the containers belong to sandbox {sandbox}, not {backend_id}; no marker was written")
    marker = {"operation_id": operation_id, "desk": desk, "backend_id": sandbox, "gateway_identity": identity,
              "gateway_restarted_at": stamp(restarted_at), "quiet_until": stamp(quiet_until),
              "containers": [{"id": c, "state": s} for c, s, _ in rows]}
    name = f"{operation_id}.json"
    # umask 077 makes it 0600; written beside, then renamed, so the adapter never reads half a marker; never over
    # a marker already waiting or already used.
    # The hold goes in the same step as the marker appears: never a moment with neither.
    script = (f"umask 077; mkdir -p /s/settle; f=/s/settle/{name}; "
              "if [ -e \"$f\" ] || [ -e \"$f.used\" ]; then echo exists; exit 3; fi; "
              f"cat > \"$f.tmp\" && mv \"$f.tmp\" \"$f\" && rm -f /s/settle/{operation_id}.hold")
    rc, said = in_state(script, json.dumps(marker), run)
    if rc == 3:
        raise Refused(f"a marker for {operation_id} is already waiting or was already used; nothing was written")
    if rc != 0:
        raise Refused("the marker could not be written to the adapter's state volume")
    if sandbox is None:
        out(f"wrote settle/{name}: no desk was found by its labels (a create that never reached the desk), "
            f"quiet until {stamp(quiet_until)}")
    else:
        out(f"wrote settle/{name}: {len(rows)} containers, quiet until {stamp(quiet_until)}")
    out(f"the hold is removed; next: as an organization admin, run `ekka desk status {desk}`. It reads this marker once and settles "
        f"change {operation_id}.")
    return marker


def parse(argv):
    """(desk, operation id, backend id or None), or None for a malformed command line."""
    if len(argv) not in (3, 5) or argv[1] != "--operation" or (len(argv) == 5 and argv[3] != "--backend-id"):
        return None
    return argv[0], argv[2], argv[4] if len(argv) == 5 else None


def unhold(desk, op, read_lock, run=docker):
    """`up.sh desks unhold <desk> --operation <request id>`: a person removes a hold a stopped settle left. Only while
    that desk's lock still names the change: the hold file names no desk, so the lock is what binds the two. A hold
    whose change has ended (the lock no longer names it) is inert: the adapter never re-issues an ended change."""
    lock = read_lock()
    if not holds(lock, op):
        raise Refused(f"change {op} does not hold desk '{desk}': {holder(lock)}. Its hold, if there is one, belongs to "
                      "another desk or to a change that has ended; nothing was removed")
    if remove_hold(op, run):
        print(f"removed the hold on change {op} (desk '{desk}'): the adapter may re-issue it, or settle it again")
    else:
        print(f"change {op} had no hold; nothing changed")


def main(argv, run=docker, ekka=enclave_ekka, read=read_as_enclave, state=None,
         unhold_command="sudo ./up.sh desks unhold"):
    releasing = argv[:1] == ["--unhold"]
    args = parse(argv[1:] if releasing else argv)
    if args is None or (releasing and args[2] is not None):
        print(USAGE, file=sys.stderr)
        return 2
    desk, op, backend_id = args
    try:
        # The desk name and the change are checked before either is part of any path.
        if not DESK.match(desk):
            raise Refused(f"'{desk}' is not a desk name")
        if not UUID.match(op):
            raise Refused("the operation is its request id, a lowercase UUID, as `ekka desk status` prints it")
        rc, listing = ekka(["desk", "list"])
        m = re.search(r"/var/lib/ekka/\S*/desks", listing) if rc == 0 else None
        if not m:
            raise Refused("the Enclave did not name its desks folder; is it running?")
        lock_path = f"{m.group(0)}/.state/{desk}.lock"

        def read_lock():
            try:
                return read(lock_path)
            except FileNotFoundError:
                return None             # no lock file: nothing holds the desk
            except OSError:
                raise Refused("the desk lock could not be read; nothing was changed") from None

        state = state if state is not None else os.environ.get("DESKS_STATE", "/var/lib/ekka-agent-desks")
        if releasing:
            with one_at_a_time(state):
                unhold(desk, op, read_lock, run)
            return 0
        # The gateway's identity as the adapter itself has it, read before anything is held or restarted.
        config = os.path.join(state, "backend", "config.json")
        try:
            with open(config) as f:
                identity = gateway_identity(f.read())
        except OSError:
            raise Refused(f"the backend adapter's configuration is missing ({config}); desk administration is not set "
                          "up on this machine, so there is no change to settle. Nothing was changed") from None
        toml = ""
        try:
            with open(os.path.join(state, "gateway.toml")) as f:
                toml = f.read()
        except OSError:
            pass

        def restart():
            rc, _ = run(["restart", "-t", "120", GATEWAY])
            if rc != 0:
                raise Refused("the gateway did not restart; no marker was written")

        with one_at_a_time(state):
            settle(desk, op, backend_id, run=run, read_lock=read_lock, gateway_toml=toml, restart=restart,
                   identity=identity, unhold_command=unhold_command)
        return 0
    except Refused as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
