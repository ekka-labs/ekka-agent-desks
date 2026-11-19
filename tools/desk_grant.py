"""Project admission and provider host checks for the installer.

Project records are inputs to `ekka desk grant update --yes`, which builds and applies FULL limits.
"""
import argparse
import datetime as dt
import glob
import json
import os
import re
import sys
import unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


class Refused(Exception):
    pass


def profile_file_hosts(path):
    """The endpoint hosts ONE profile file names, sorted, each checked. The one parser of a profile's hosts: the
    project checks and the installer's ceiling record (tools/desk_records.py) both read hosts through it."""
    hosts = set()
    with open(path, encoding="utf-8") as f:
        for m in re.finditer(r"^\s*-?\s*host:\s*([^\s#]+)\s*$", f.read(), re.M):
            host = m.group(1).strip("'\"")
            if not HOST.match(host):
                raise Refused(f"{os.path.basename(path)} names a host the limits cannot hold: {host!r}")
            hosts.add(host)
    return sorted(hosts)


def profile_hosts(providers_dir=os.path.join(ROOT, "providers"), files=None):
    """Every endpoint host the profiles name, sorted, each checked: `files`, the very profiles this install puts in
    the gateway (up.sh passes them, an install's own providers.local file in place of a shipped one), or else every
    shipped profile. One source: a profile the gateway holds can never sit outside the ceiling."""
    hosts = set()
    for path in (files if files else sorted(glob.glob(os.path.join(providers_dir, "*.yaml")))):
        hosts.update(profile_file_hosts(path))
    if not hosts:
        raise Refused("no provider profile names a host; the ceiling would be empty")
    return sorted(hosts)


def baseline_hosts(policy):
    """The hosts desk/policy.json itself opens (its network_policies), which sit inside the ceiling."""
    hosts = set()
    for rule in (policy.get("network_policies") or policy.get("networkPolicies") or {}).values():
        for ep in rule.get("endpoints", []):
            if ep.get("host"):
                hosts.add(ep["host"])
    return sorted(hosts)


UTC_Z = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def utc_z(when):
    return when.astimezone(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_z(text):
    if not isinstance(text, str) or not UTC_Z.match(text):
        raise Refused(f"{text!r} is not a UTC time written YYYY-MM-DDTHH:MM:SSZ")
    try:
        return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise Refused(f"{text!r} is not a real time") from None


PROJECT_KEYS = ("name", "image_id", "policy_digest", "since")
# Creation may use project file rules; later changes still keep the desk's own pinned filesystem baseline.
POLICY_MUST_EQUAL = ("process", "landlock")
# Everything a project's policy file may hold: the shipped policy's own parts, and its network rules under either
# spelling; new OpenShell fields need an explicit review before admission.
POLICY_PARTS = ("version", "filesystem") + POLICY_MUST_EQUAL + ("networkPolicies", "network_policies")
MAX_POLICY_PATH_BYTES = 4095
WRITE_PROTECTED = (
    "/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/libexec", "/etc", "/proc", "/sys",
    "/dev", "/boot", "/root", "/run", "/var/run", "/var/lib", "/var/log", "/home",
    "/sandbox/ekka-workspace", "/sandbox/.ekka-inputs", "/.openshell",
)
READ_PROTECTED = (
    "/root", "/home", "/run", "/var/run", "/var/lib", "/proc", "/sys", "/dev", "/boot", "/.openshell",
)


def within(path, parent):
    """Component-boundary comparison of already normalized Linux paths, without touching the host filesystem."""
    return path == parent or parent == "/" or path.startswith(parent + "/")


def overlaps(path, protected):
    return within(path, protected) or within(protected, path)


def check_policy_path(path, key):
    prefix = f"filesystem.{key}"
    if not isinstance(path, str):
        raise Refused(f"{prefix} must be a list of strings")
    # Reject surrogate escapes as well as control/format characters before UTF-8 encoding or diagnostics.
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in path):
        raise Refused(f"{prefix} paths must not contain control or invalid Unicode characters")
    if len(path.encode("utf-8")) > MAX_POLICY_PATH_BYTES:
        raise Refused(f"{prefix} paths must not exceed {MAX_POLICY_PATH_BYTES} UTF-8 bytes")
    if not path.startswith("/"):
        raise Refused(f"{prefix} paths must be absolute")
    if path != "/" and any(part in ("", ".", "..") for part in path.split("/")[1:]):
        raise Refused(f"{prefix} paths must already be normalized without empty, dot or dot-dot parts")
    if any(c in path for c in "*?[]{}\\"):
        raise Refused(f"{prefix} paths must not contain glob or wildcard characters")


def check_project_filesystem(filesystem, shipped, name):
    """Lexical admission floors, not an image/mount/symlink audit; paths belong to the desk, never the host."""
    if not isinstance(filesystem, dict):
        raise Refused("filesystem must be an object")
    other = sorted(set(filesystem) - set(shipped))
    if other:
        raise Refused(f"filesystem has unknown keys: {', '.join(other)}")
    if canonical(filesystem.get("includeWorkdir")) != canonical(shipped["includeWorkdir"]):
        raise Refused("filesystem.includeWorkdir must stay exactly as shipped")
    for key in ("readOnly", "readWrite"):
        paths = filesystem.get(key)
        if not isinstance(paths, list):
            raise Refused(f"filesystem.{key} must be a list of strings")
        for path in paths:
            check_policy_path(path, key)
        if len(set(paths)) != len(paths):
            raise Refused(f"filesystem.{key} must not contain duplicate paths")
    ro, rw = filesystem["readOnly"], filesystem["readWrite"]
    both = sorted(set(ro) & set(rw))
    if both:
        raise Refused(f"filesystem.readOnly and filesystem.readWrite must not share a path: {both[0]!r}")
    missing = sorted(set(shipped["readOnly"]) - set(ro))
    if missing:
        raise Refused(f"filesystem.readOnly must keep every shipped entry, including {missing[0]!r}")

    # Dedicated project namespaces avoid guessing ownership of arbitrary image folders or host mount aliases.
    project_roots = (f"/opt/projects/{name}", f"/var/cache/{name}")
    read_roots = (*shipped["readOnly"], *shipped["readWrite"], *project_roots,
                  "/opt/project-tools", "/sandbox/ekka-workspace", "/sandbox/.ekka-inputs")
    for path in ro:
        if path in shipped["readOnly"]:
            continue
        # Keep /proc itself, but never add a rule resolved through its magic links (for example self/root).
        blocked = next((root for root in READ_PROTECTED if overlaps(path, root)), None)
        if blocked:
            raise Refused(f"filesystem.readOnly path {path!r} overlaps protected location {blocked!r}")
        if not any(within(path, root) for root in read_roots):
            raise Refused(f"filesystem.readOnly path {path!r} is outside the allowed project read locations")
    for path in rw:
        if path in shipped["readWrite"]:
            continue  # Only exact shipped device entries are grandfathered, including /dev/shm.
        blocked = next((root for root in WRITE_PROTECTED if overlaps(path, root)), None)
        if blocked:
            raise Refused(f"filesystem.readWrite path {path!r} overlaps protected location {blocked!r}")
        if not any(within(path, root) for root in ("/tmp", *project_roots)):
            raise Refused(f"filesystem.readWrite path {path!r} is outside the allowed project write locations")


def check_project(record):
    """A project's record, held to its shape (closed) before it reaches a grant."""
    if not isinstance(record, dict) or sorted(record) != sorted(PROJECT_KEYS):
        raise Refused(f"a project record holds exactly {', '.join(PROJECT_KEYS)}")
    if not NAME.match(record["name"] if isinstance(record["name"], str) else ""):
        raise Refused(f"{record['name']!r} is not a project name (lowercase letters, digits, '.', '_' and '-')")
    for key in ("image_id", "policy_digest"):
        if not DIGEST.match(record[key] if isinstance(record[key], str) else ""):
            raise Refused(f"{record[key]!r} is not sha256:<64 lowercase hex>")
    parse_utc_z(record["since"])
    return {k: record[k] for k in PROJECT_KEYS}


def project(name, image_id, policy_digest, policy, shipped, ceiling, now):
    """The record `sudo ekka desk grant project add` writes, or Refused. `policy` is the project's policy file,
    `shipped` is desk/policy.json, `ceiling` the hosts this install's profiles name."""
    if not isinstance(policy, dict):
        raise Refused("the project's policy is not a JSON object")
    other = sorted(k for k in policy if k not in POLICY_PARTS)
    if other:
        raise Refused(f"the project's policy holds {', '.join(other)}; a project policy holds only "
                      f"{', '.join(POLICY_PARTS[:-1])}")
    if "networkPolicies" in policy and "network_policies" in policy:
        raise Refused("the project's policy names its network rules twice (networkPolicies and network_policies)")
    if canonical(policy.get("version")) != canonical(shipped.get("version")):
        raise Refused("the project's policy changes `version`; it keeps the shipped policy's")
    for part in POLICY_MUST_EQUAL:
        if canonical(policy.get(part)) != canonical(shipped.get(part)):
            raise Refused(f"the project's policy changes `{part}`; it must stay exactly as shipped")
    check_project_filesystem(policy.get("filesystem"), shipped["filesystem"], name)
    outside = [h for h in baseline_hosts(policy) if h not in ceiling]
    if outside:
        raise Refused(f"the project's policy opens {', '.join(outside)}, outside the ceiling the profiles set; "
                      "a host reaches a desk through a provider profile on this server")
    return check_project({"name": name, "image_id": image_id, "policy_digest": policy_digest, "since": utc_z(now)})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv, now=None):
    p = argparse.ArgumentParser(prog="desk_grant.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    prj = sub.add_parser("project", help="the record for a project: its image and its own policy")
    prj.add_argument("--name", required=True)
    prj.add_argument("--image-id", required=True)
    prj.add_argument("--policy-digest", required=True)
    prj.add_argument("--policy", required=True, help="the project's policy file")
    prj.add_argument("--profile", action="append", default=[], help="a profile file this install puts in the gateway")
    a = p.parse_args(argv)
    when = now or dt.datetime.now(dt.timezone.utc)
    try:
        if a.cmd == "project":
            with open(os.path.join(ROOT, "desk", "policy.json"), encoding="utf-8") as f:
                shipped = json.load(f)
            try:
                mine = load(a.policy)
            except ValueError:
                raise Refused(f"{a.policy} is not JSON") from None
            print(json.dumps(project(a.name, a.image_id, a.policy_digest, mine, shipped,
                                     profile_hosts(files=a.profile), when), indent=2))
    except Refused as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
