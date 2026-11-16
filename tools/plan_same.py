"""Whether a plan the installer just wrote is already EKKA's newest version of it.

`ekka plan create` makes a new version on every call, by design, so a grant step that ran it for every plan
created nine new versions each time, with nothing changed. The installer now asks first:

    python3 tools/plan_same.py latest <plan file> <agent> < `ekka plan list --all --json`
        prints the identity and visibility of the newest active version of the file's plan owned by <agent>, or
        nothing when there is none or any candidate cannot be read
    python3 tools/plan_same.py same <plan file> <agent> < `ekka plan show <identity> --definition --json`
        exit 0 when that version is the file: the same definition and name, owned by <agent>; 1 otherwise

<agent> is the agent's code (`desks`). The file names the agent by its id, and EKKA's answers name the owner only by
its code, so the code the installer resolved that id from is what is compared.

Anything it cannot read answers "not the same" (no identity, or exit 1), so the installer creates a version, as
it did before. A wrong "same" would leave a changed plan uninstalled; a wrong "different" only makes a version.
"""
import json
import sys


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def version_key(version):
    try:
        return tuple(int(p) for p in str(version).split("."))
    except ValueError:
        return None


def read_file(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    plan, definition = d.get("plan"), d.get("definition")
    if not (isinstance(plan, dict) and isinstance(plan.get("code"), str) and isinstance(definition, dict)):
        raise ValueError("not a plan file")
    return plan, definition


def latest(path, agent, listed):
    plan, _ = read_file(path)
    rows = listed.get("plans")
    if not isinstance(rows, list) or listed.get("total") != len(rows):
        return None   # a page of the list, or another shape: cannot tell, so a version is made
    found = []
    for r in rows:
        if not isinstance(r, dict) or r.get("plan_code") != plan["code"] or r.get("status") != "active":
            continue
        owner = r.get("owner_agent")
        if not (isinstance(owner, dict) and owner.get("agent_code") == agent):
            continue
        key = version_key(r.get("version"))
        if not key or not isinstance(r.get("plan_identity"), str) or not isinstance(r.get("visibility"), str):
            return None   # a candidate that cannot be read might be the newest: never fall back to an older one
        found.append((key, r["plan_identity"], r["visibility"]))
    if not found:
        return None
    _, identity, visibility = max(found)
    return f"{identity} {visibility}"


def same(path, agent, shown):
    plan, definition = read_file(path)
    owner = shown.get("owner_agent")
    return (isinstance(shown.get("plan_json"), dict) and canonical(shown["plan_json"]) == canonical(definition)
            and shown.get("plan_code") == plan["code"] and shown.get("name") == plan.get("name")
            and isinstance(owner, dict) and owner.get("agent_code") == agent)


def main(argv):
    try:
        data = json.loads(sys.stdin.read())
        if argv[1:2] == ["latest"] and len(argv) == 4:
            found = latest(argv[2], argv[3], data) if isinstance(data, dict) else None
            if found:
                print(found)
            return 0
        if argv[1:2] == ["same"] and len(argv) == 4:
            return 0 if isinstance(data, dict) and same(argv[2], argv[3], data) else 1
    except (ValueError, OSError, RecursionError):
        return 1
    print(__doc__.split("\n\n")[1].strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
