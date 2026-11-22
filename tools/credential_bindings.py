"""Add the credential lifecycle methods to the installed interceptor allowlists."""
import os
from pathlib import Path
import re
import sys
import tempfile

METHODS = ("ConfigureProviderRefresh", "RotateProviderCredential", "DeleteProviderRefresh")
PREFIX = "openshell.v1.OpenShell/"
HEADER = "[[openshell.gateway.interceptors]]"
BINDING = "[[openshell.gateway.interceptors.bindings]]"
REQUIRED = {"ekka-governance": ("validate", "fail_closed"), "ekka-observer": ("post_commit", "fail_open")}


def missing(cfg):
    items = cfg["openshell"]["gateway"].get("interceptors", [])
    needed = {}
    for name, (phase, failure) in REQUIRED.items():
        matches = [item for item in items if item.get("name") == name]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one interceptor named {name}")
        item = matches[0]
        if item.get("binding_policy") != "allowlist" or item.get("failure_policy") != failure:
            raise ValueError(f"unexpected failure or binding policy for {name}")
        needed[name] = []
        for method in METHODS:
            bindings = [b for b in item.get("bindings", []) if b.get("rpc") == PREFIX + method]
            if not bindings:
                needed[name].append(method)
            elif len(bindings) != 1 or bindings[0].get("phases") != [phase]:
                raise ValueError(f"unexpected {method} binding for {name}")
    return needed


def block(method, phase):
    return f'\n{BINDING}\nrpc = "{PREFIX}{method}"\nphases = ["{phase}"]\n'


def refresh(path):
    from gateway_preflight import plain_toml, tomllib
    parse = tomllib.loads if tomllib else plain_toml
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected a regular gateway configuration file")
    old = path.read_text()
    needed = missing(parse(old))
    if not any(needed.values()):
        return
    headers = list(re.finditer(r"(?m)^[ \t]*\[\[openshell\.gateway\.interceptors\]\][ \t]*(?:#.*)?$", old))
    items = parse(old)["openshell"]["gateway"]["interceptors"]
    if len(headers) != len(items):
        raise ValueError("unrecognized interceptor headers; configuration unchanged")
    new = old
    for i in reversed(range(len(items))):
        name = items[i].get("name")
        if needed.get(name):
            pos = headers[i+1].start() if i+1 < len(headers) else len(old)
            addition = "".join(block(m, REQUIRED[name][0]) for m in needed[name])
            new = new[:pos] + addition + "\n" + new[pos:]
    desired = parse(old)
    for item in desired["openshell"]["gateway"]["interceptors"]:
        name = item.get("name")
        for method in needed.get(name, []):
            item.setdefault("bindings", []).append({"rpc": PREFIX + method, "phases": [REQUIRED[name][0]]})
    if parse(new) != desired:
        raise ValueError("configuration round-trip changed unrelated settings")
    st = path.stat()
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new)
            f.flush()
            if os.geteuid() == 0:
                os.fchown(f.fileno(), st.st_uid, st.st_gid)
            os.fchmod(f.fileno(), st.st_mode & 0o777)
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        refresh(Path(sys.argv[1]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(f"gateway allowlist refresh refused: {error}")
