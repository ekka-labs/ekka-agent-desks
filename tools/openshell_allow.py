"""Which NVIDIA openshell commands `sudo ./up.sh openshell` runs as the gateway's administrator.

    python3 tools/openshell_allow.py <log file> <openshell arguments...>

Owner, 2026-10-15: "Nothing happens on a desk except through EKKA." So this machine's own door to NVIDIA's CLI keeps
exactly four kinds of command, each named in full below, and refuses every other by name before the CLI runs:

  - reads, which change nothing;
  - `sandbox stop <desk>`, the on-box kill switch for when EKKA's cloud is unreachable. The desk is always named:
    with no name NVIDIA stops the last one used;
  - provider setup: providers and their keys are set at install, on this machine, and so is their refresh;
  - a file copy, `sandbox upload` and `sandbox download` (owner, 2026-11-14: EKKA has no governed copy yet, so this
    machine's administrator may copy, "as long as it is not introducing insecurity"). The desk is always named and no
    flag but upload's `--no-git-ignore` is taken. Both paths on the desk are under /sandbox, the one folder a desk
    writes. A download is the dangerous direction: it runs as root and what arrives was packed by a `tar` INSIDE the
    desk, so every byte is the desk's own. It therefore lands only in a folder that exists, is empty, belongs to the
    administrator running it and that nobody else can write, and `--settle-download <folder>` (run by up.sh after
    the copy, whatever its result) then removes every link and special file and clears every setuid, setgid and
    group- or other-write bit, saying what it removed. Root never reads through a link a desk made.

A secret never travels as an argument, where `ps` and this log would show it: a credential is named and read from the
environment (`--credential KEY`, `--secret-material-env`), never written as `KEY=VALUE`. Refresh material goes only
through `--secret-material-env`: NVIDIA's `--material KEY=VALUE` is refused, so no value can be sent the wrong way. A
provider never takes the administrator's own sign-in as its key (`--from-oidc-token`).

The call always goes to this machine's gateway. NVIDIA's gateway flags are global, so one placed after the command
would still win over the `-g ekka-agent-desks` up.sh puts before it; `-g`, `--gateway`, `--gateway-endpoint` and
`--gateway-insecure` are refused in every spelling, and up.sh clears their environment twins (OPENSHELL_GATEWAY*).
`--workspace` stays: it picks a workspace on this same gateway.

Every allowed call is appended to the log, with the command and the person who ran sudo, before it runs.
Exit 0: allowed and logged. Exit 1: refused, nothing logged and nothing run.
"""
import datetime as dt
import json
import os
import re
import stat
import sys

READS = {("status",), ("sandbox", "list"), ("sandbox", "get"), ("provider", "list"), ("provider", "get"),
         ("provider", "list-profiles"), ("provider", "refresh", "status")}
STOP = ("sandbox", "stop")
PROVIDER_SETUP = {("provider", "create"), ("provider", "update"), ("provider", "delete"),
                  ("provider", "refresh", "configure"), ("provider", "refresh", "rotate"),
                  ("provider", "refresh", "delete")}
UPLOAD = ("sandbox", "upload")
DOWNLOAD = ("sandbox", "download")
ALLOWED = READS | PROVIDER_SETUP | {STOP, UPLOAD, DOWNLOAD}
DESK_ROOT = "/sandbox"   # the one folder a desk writes (desk/policy.json: includeWorkdir)
DESK = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
EKKA = "desk changes run through EKKA: ekka desk <op>"


class Refused(Exception):
    pass


def command(argv):
    """The command words at the front, exactly as NVIDIA names them: no alias, no flag before them."""
    for n in (3, 2, 1):
        if tuple(argv[:n]) in ALLOWED:
            return tuple(argv[:n])
    words = []
    for a in argv[:3]:
        if a.startswith("-"):
            break
        words.append(a)
    raise Refused(f"openshell {' '.join(words) or '(no command)'}: {EKKA}")


def flag_values(rest, name):
    """Every value given to `--name`, in either spelling: `--name v` or `--name=v`."""
    out = []
    for i, a in enumerate(rest):
        if a == name and i + 1 < len(rest):
            out.append(rest[i + 1])
        elif a.startswith(name + "="):
            out.append(a[len(name) + 1:])
    return out


def given(rest, name):
    """True when `--name` appears, in either spelling: `--name v` or `--name=v`."""
    return any(a == name or a.startswith(name + "=") for a in rest)


GATEWAY_FLAGS = ("--gateway", "--gateway-endpoint", "--gateway-insecure")
# Variables of this setup's own: the administrator session's sign-in among them. None is ever read into a provider.
RESERVED_SOURCE = "OPENSHELL_"


def env_sources(rest):
    """Every environment variable a provider call reads a value from: `--credential KEY` and
    `--secret-material-env KEY[=ENVVAR]`, trimmed as NVIDIA's CLI trims them (OpenShell 0.1.9 commands/common.rs)."""
    out = [v.strip() for v in flag_values(rest, "--credential") if "=" not in v]
    for v in flag_values(rest, "--secret-material-env"):
        key, sep, env = v.partition("=")
        out.append((env if sep else key).strip())
    return out


def short_g(a):
    """`-g`, `-gNAME`, `-g=NAME`, or `g` inside a cluster of short flags such as `-vg`."""
    return a.startswith("-") and not a.startswith("--") and "g" in a[1:].split("=", 1)[0]


def check(argv):
    """The command these arguments name, or Refused with the line to print."""
    cmd = command(argv)
    rest = argv[len(cmd):]
    if cmd in (UPLOAD, DOWNLOAD):
        check_copy(cmd, rest)
    if cmd == STOP:
        if len(rest) != 1 or not DESK.match(rest[0]):
            raise Refused("openshell sandbox stop: name exactly one desk, e.g. sudo ./up.sh openshell sandbox stop code-desk")
    if any(a == "--from-oidc-token" for a in rest):
        raise Refused("openshell --from-oidc-token: the gateway administrator's own sign-in never becomes a desk's key")
    if any("=" in v for v in flag_values(rest, "--credential")):
        raise Refused("openshell --credential KEY=VALUE: a secret is never an argument; name the key and pass it in the "
                      "environment: sudo --preserve-env=KEY ./up.sh openshell ... --credential KEY")
    for source in env_sources(rest):
        if source.startswith(RESERVED_SOURCE):
            raise Refused(f"openshell: {source} belongs to this setup and is never read into a provider; "
                          "name the variable that holds the provider's own key")
    for name in ("--material", "--secret-material-key"):
        if given(rest, name):
            raise Refused(f"openshell {name}: refresh material is never an argument; pass each value in the "
                          "environment: sudo --preserve-env=ENVVAR ./up.sh openshell ... --secret-material-env KEY=ENVVAR")
    for name in GATEWAY_FLAGS:
        if given(rest, name):
            raise Refused(f"openshell {name}: the call always goes to this machine's gateway; "
                          "drop the flag: sudo ./up.sh openshell <command>")
    if any(short_g(a) for a in rest):
        raise Refused("openshell -g: the call always goes to this machine's gateway; "
                      "drop the flag: sudo ./up.sh openshell <command>")
    return cmd


def desk_path(path, what):
    """A path on the desk: absolute, under /sandbox, no `..` step. NVIDIA's CLI checks it again on the desk's side."""
    parts = path.split("/")
    if not path.startswith(DESK_ROOT + "/") or ".." in parts or "\x00" in path or path.startswith("-"):
        raise Refused(f"openshell {what}: the path on the desk is absolute and under {DESK_ROOT}/, with no '..' "
                      f"(got {path!r})")
    return path


def download_folder(path):
    """Where a download may land: a real, empty folder of the administrator's that nobody else can write."""
    if not path.startswith("/") or ".." in path.split("/"):
        raise Refused(f"openshell sandbox download: the folder on this machine is an absolute path with no '..' (got {path!r})")
    try:
        st = os.lstat(path)
    except OSError:
        raise Refused(f"openshell sandbox download: {path} does not exist; make it first: "
                      f"sudo install -d -m 0700 {path}") from None
    if not stat.S_ISDIR(st.st_mode):
        raise Refused(f"openshell sandbox download: {path} is not a real folder (a link or a file is refused)")
    if st.st_uid != os.geteuid():
        raise Refused(f"openshell sandbox download: {path} does not belong to the administrator running this")
    if st.st_mode & 0o022:
        raise Refused(f"openshell sandbox download: {path} can be written by others; fix: chmod go-w {path}")
    if os.listdir(path):
        raise Refused(f"openshell sandbox download: {path} is not empty; a download lands in a new, empty folder")
    return path


def check_copy(cmd, rest):
    what = " ".join(cmd)
    flags = [a for a in rest if a.startswith("-")]
    allowed = ["--no-git-ignore"] if cmd == UPLOAD else []
    for f in flags:
        if f not in allowed:
            raise Refused(f"openshell {what} {f}: no flag is taken here"
                          + (" but --no-git-ignore" if cmd == UPLOAD else ""))
    words = [a for a in rest if not a.startswith("-")]
    if cmd == UPLOAD:
        if len(words) not in (2, 3) or not DESK.match(words[0]):
            raise Refused("openshell sandbox upload: name the desk, the local path and, when not the desk's work folder, "
                          f"the folder on the desk: sudo ./up.sh openshell sandbox upload <desk> <local path> [{DESK_ROOT}/<folder>/]")
        if not os.path.lexists(words[1]):
            raise Refused(f"openshell sandbox upload: {words[1]} does not exist on this machine")
        if len(words) == 3:
            desk_path(words[2], what)
    else:
        if len(words) != 3 or not DESK.match(words[0]):
            raise Refused("openshell sandbox download: name the desk, the path on the desk and an empty folder on this "
                          f"machine: sudo ./up.sh openshell sandbox download <desk> {DESK_ROOT}/<path> <empty folder>")
        desk_path(words[1], what)
        download_folder(words[2])


def settle(folder, out=sys.stdout):
    """After a download: remove every link and special file under `folder`, and clear setuid, setgid, sticky and
    group- or other-write bits on what is left. Nothing is followed. Returns how many entries were removed."""
    removed = 0
    for top, dirs, files in os.walk(folder, topdown=True, followlinks=False):
        for name in list(dirs) + files:
            path = os.path.join(top, name)
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                kind = "link" if stat.S_ISLNK(st.st_mode) else "special file"
                os.unlink(path)
                if name in dirs:
                    dirs.remove(name)
                removed += 1
                print(f"removed a {kind} the desk sent: {path}", file=out)
                continue
            clean = st.st_mode & 0o755
            if stat.S_IMODE(st.st_mode) != clean:
                os.chmod(path, clean)
    return removed


def log_line(argv, now=None, env=os.environ):
    who = env.get("SUDO_USER") or env.get("USER") or "unknown"
    at = (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return json.dumps({"at": at, "user": who, "command": ["openshell", *argv]}, separators=(",", ":"))


def append(path, line):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (line + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def main(argv):
    if len(argv) < 1:
        print("usage: openshell_allow.py <log file> <openshell arguments...>", file=sys.stderr)
        return 2
    if argv[0] == "--settle-download":   # after a download, by up.sh: the folder the call just checked
        if len(argv) != 2 or not os.path.isdir(argv[1]) or os.path.islink(argv[1]):
            print("usage: openshell_allow.py --settle-download <folder>", file=sys.stderr)
            return 2
        try:
            n = settle(argv[1])
        except OSError as e:
            print(f"REFUSED: {argv[1]} could not be made safe ({e.strerror}); do not use what is in it", file=sys.stderr)
            return 1
        print(f"the download is in {argv[1]}" + (f"; {n} entr{'y' if n == 1 else 'ies'} the desk sent as a link or "
              "special file removed" if n else "; plain files and folders only"))
        return 0
    path, args = argv[0], argv[1:]
    try:
        check(args)
    except Refused as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 1
    try:
        append(path, log_line(args))
    except OSError as e:
        print(f"REFUSED: the call could not be logged ({e.strerror}); nothing was run", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
