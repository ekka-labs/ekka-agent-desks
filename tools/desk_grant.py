"""Discovery window and project records, plus the installer's local grant display.

Only `ekka desk grant update --yes` builds and applies FULL limits. This tool writes
window/project inputs for that command; `show` reads the confirmed CLI limits record.
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


def full_limits(value):
    """Read the installer's FULL limits, never an unresolved FOLLOW or a mixture of the two."""
    if not isinstance(value, dict) or not value:
        raise Refused("the desks grant carries no limits")
    if "follow" in value:
        raise Refused("the desks grant carries FOLLOW, not FULL limits")
    with open(os.path.join(ROOT, "vendor", "ekka-contracts", "governance", "grant-constraints",
                           "desks.v1.schema.json"), encoding="utf-8") as f:
        full = json.load(f)["$defs"]["full"]
    missing = [k for k in full["required"] if k not in value]
    if missing:
        raise Refused(f"the desks grant's limits lack {', '.join(missing)}")
    extra = sorted(set(value) - set(full["properties"]))
    if extra:
        raise Refused(f"the desks grant's limits have unknown keys: {', '.join(extra)}")
    return value


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



IMAGE_REF = re.compile(r"^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$")   # the same rule as up.sh's
UTC_Z = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
NAME_PREFIX = "discover-"      # contracts desks.v1 `discovery.name_prefix`, a constant
DEFAULT_MINUTES = 60
MAX_MINUTES = 240
MAX_WINDOW_IMAGES = 4          # contracts desks.v1 `discovery.image_digests`: 1 to 4
MAX_WINDOW_PROVIDERS = 8       # contracts desks.v1 `discovery.providers`: 0 to 8
DISCOVERY_KEYS = ("image_digests", "providers", "name_prefix", "expires_at")


def utc_z(when):
    return when.astimezone(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_z(text):
    if not isinstance(text, str) or not UTC_Z.match(text):
        raise Refused(f"{text!r} is not a UTC time written YYYY-MM-DDTHH:MM:SSZ")
    try:
        return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise Refused(f"{text!r} is not a real time") from None


def check_discovery(block):
    """The grant's `discovery` block, held to its contract shape (closed) before it reaches a grant."""
    if not isinstance(block, dict) or sorted(block) != sorted(DISCOVERY_KEYS):
        raise Refused(f"a discovery block holds exactly {', '.join(DISCOVERY_KEYS)}")
    images, providers = block["image_digests"], block["providers"]
    if not isinstance(images, list) or not 1 <= len(images) <= MAX_WINDOW_IMAGES or len(set(images)) != len(images):
        raise Refused(f"a discovery window names 1 to {MAX_WINDOW_IMAGES} distinct images")
    for d in images:
        if not DIGEST.match(d if isinstance(d, str) else ""):
            raise Refused(f"{d!r} is not sha256:<64 lowercase hex>")
    if not isinstance(providers, list) or len(providers) > MAX_WINDOW_PROVIDERS or len(set(providers)) != len(providers):
        raise Refused(f"a discovery window names at most {MAX_WINDOW_PROVIDERS} distinct providers")
    for name in providers:
        if not NAME.match(name if isinstance(name, str) else ""):
            raise Refused(f"{name!r} is not a provider name")
    if block["name_prefix"] != NAME_PREFIX:
        raise Refused(f"a discovery desk's name starts with {NAME_PREFIX!r}, nothing else")
    parse_utc_z(block["expires_at"])
    return {"image_digests": sorted(images), "providers": sorted(providers), "name_prefix": NAME_PREFIX,
            "expires_at": block["expires_at"]}


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




def window(image_ref, providers, minutes, now, granted_providers=None):
    """The window file `sudo ekka desk grant discovery` writes: the grant's `discovery` block, and the image's own
    name and the opening time for `show`. `granted_providers`, the providers the grant in force holds: a window naming
    any other is refused, since a desk holding it could never be created."""
    if not IMAGE_REF.match(image_ref or ""):
        raise Refused(f"{image_ref!r} is not <registry>/<name>@sha256:<64 hex>, the exact image the desk is created from "
                      "(a tag can move; a digest cannot)")
    if not providers:
        raise Refused("name the providers the discovery desk may hold, for example github,bitbucket")
    for name in providers:
        if not NAME.match(name or ""):
            raise Refused(f"{name!r} is not a provider name")
    if len(set(providers)) != len(providers) or len(providers) > MAX_WINDOW_PROVIDERS:
        raise Refused(f"name 1 to {MAX_WINDOW_PROVIDERS} distinct providers")
    if granted_providers is not None:
        missing = sorted(set(providers) - set(granted_providers))
        if missing:
            raise Refused(f"{', '.join(missing)} is not connected on this server, so no desk may hold it; "
                          "connect it first: <the key> | sudo ekka desk connect <provider>")
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= MAX_MINUTES:
        raise Refused(f"--minutes is a whole number from 1 to {MAX_MINUTES}")
    block = check_discovery({"image_digests": [image_ref.rsplit("@", 1)[1]], "providers": sorted(providers),
                             "name_prefix": NAME_PREFIX, "expires_at": utc_z(now + dt.timedelta(minutes=minutes))})
    return {"image_ref": image_ref, "since": utc_z(now), "discovery": block}




def show(lim, extras=None, profiles=(), now=None, projects=()):
    """`sudo ekka desk grant show`: what a desk made through EKKA may use on this server, in words. Each image digest
    carries its name: the shipped one is what the install built (ekka-desk:local), and a discovery window's is named
    from its own record."""
    lim = full_limits(lim)
    net = lim["policy_baseline"]["network"]
    extras = extras or {}
    disc = lim.get("discovery")
    win_images = set((disc or {}).get("image_digests", []))
    ref = extras.get("image_ref") or "(not recorded)"
    connected = list(lim["providers"])
    waiting = [p for p in profiles if p not in connected]
    projects = [check_project(p) for p in projects]
    by_image = {p["image_id"]: p["name"] for p in projects}
    by_policy = {p["policy_digest"]: p["name"] for p in projects}

    def image_name(d):
        if d in win_images:
            return f"the discovery image {ref}"
        if d in by_image:
            return f"project {by_image[d]}, an image built on this server"
        return "ekka-desk:local, built by the install"

    lines = ["The desks grant: what a desk made through EKKA may use on this server", "",
             "DESK IMAGE (a desk runs only one of these)" if len(lim["image_digests"]) > 1
             else "DESK IMAGE (a desk runs only this image)"]
    lines += [f"  {image_name(d)}\n      {d}" for d in lim["image_digests"]]
    lines += ["", "DESK POLICY (what a desk may reach on the network)"]
    lines += [(f"  project {by_policy[d]}, its own policy" if d in by_policy else "  desk/policy.json, the shipped policy")
              + f"\n      {d}" for d in lim["policy_digests"]]
    lines += [f"  opens: {', '.join(net['allowed_hosts']) or 'no host'}, on port {', '.join(map(str, net['allowed_ports']))}",
              f"  address ranges: {', '.join(net['allowed_cidrs']) or 'none'}",
              f"  read the shipped policy:  cat {os.path.abspath(os.path.join(ROOT, 'desk', 'policy.json'))}",
              "", "PROVIDERS (the keys a desk may use)"]
    if connected:
        lines.append(f"  connected: {', '.join(connected)}")
    else:
        lines.append("  none connected yet, so a desk can use no key.")
    if waiting:
        lines.append(f"  on this server, not connected: {', '.join(waiting)}")
        lines.append("  connect one, the key piped in and never typed:  <the key> | sudo ekka desk connect <provider>")
    if profiles:
        lines.append(f"  what each provider may reach:  cat {os.path.abspath(os.path.join(ROOT, 'providers'))}/<provider>.yaml")
    lines += ["", "HOSTS A PROVIDER MAY EVER REACH (the ceiling; a provider's own profile picks from these)",
              f"  {', '.join(lim['allowed_hosts'])}", ""]
    if disc:
        until = disc["expires_at"]
        providers = ", ".join(disc["providers"]) or "none"
        what = (f"image {ref}, providers {providers}; a desk named {disc['name_prefix']}* made from that image with "
                "only those providers may use NVIDIA OpenShell's auto approval mode")
        if (now or dt.datetime.now(dt.timezone.utc)) < parse_utc_z(until):
            lines.append(f"DISCOVERY WINDOW open until {until} (opened {extras.get('since') or 'at an unrecorded time'}): {what}."
                         " End it: sudo ekka desk grant restore")
        else:
            lines.append(f"DISCOVERY WINDOW closed at {until} (expired): no desk may enter auto approval mode. "
                         f"The image stays in the grant until: sudo ekka desk grant restore")
    elif projects:
        lines.append("no discovery window")
    else:
        lines.append("no discovery window: the shipped limits are in force")
    for p in projects:
        lines.append(f"PROJECT {p['name']} (added {p['since']}): a desk may be created from its image with its policy. "
                     f"Take it out: sudo ekka desk grant project remove {p['name']}")
    return "\n".join(lines)


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
    win = sub.add_parser("window", help="the file for a discovery window: the grant's discovery block")
    win.add_argument("--image-ref", required=True)
    win.add_argument("--providers", required=True, help="the providers the discovery desk may hold, comma separated")
    win.add_argument("--minutes", type=int, default=DEFAULT_MINUTES, help=f"how long it is open, 1 to {MAX_MINUTES}")
    win.add_argument("--limits", default=None, help="the limits in force; a provider they do not hold is refused")
    sh = sub.add_parser("show"); sh.add_argument("limits_file"); sh.add_argument("extras_file", nargs="?")
    sh.add_argument("--profiles", default="", help="the profiles this server has, comma separated")
    sh.add_argument("--project", action="append", default=[], help="a project's record, to name its image and policy")
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
        elif a.cmd == "window":
            granted = None
            if a.limits:
                with open(a.limits, encoding="utf-8") as f:
                    granted = full_limits(json.load(f))["providers"]
            names = [n.strip() for n in a.providers.split(",") if n.strip()]
            print(json.dumps(window(a.image_ref, names, a.minutes, when, granted), indent=2))
        elif a.cmd == "show":
            with open(a.limits_file, encoding="utf-8") as f:
                lim = json.load(f)
            extras = None
            if a.extras_file and os.path.exists(a.extras_file):
                with open(a.extras_file, encoding="utf-8") as f:
                    extras = json.load(f)
            print(show(lim, extras, [p for p in a.profiles.split(",") if p], now=when,
                       projects=[load(f) for f in a.project]))
    except Refused as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
