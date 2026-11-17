"""Read CLI answers as data; never build limits or decide how to update a write grant.

read-grant <agent id> <api gate>: stdin is `ekka gate grant list --json`.
record <dest> <agent id> <api gate>: stdin is a successful `ekka desk grant show --json`, after update.
"""
import json
import re
import sys
from pathlib import Path

import desk_records
from schema_check import schema_errors


class Refused(Exception):
    pass


def read_json(stream):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refused("CLI JSON has duplicate keys")
            result[key] = value
        return result

    def invalid_constant(_):
        raise Refused("CLI JSON has a non-JSON number")

    text = stream.read(4 * 1024 * 1024 + 1)
    if len(text) > 4 * 1024 * 1024:
        raise Refused("CLI JSON is too large")
    try:
        return json.loads(text, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, RecursionError):
        raise Refused("CLI answer is not one valid JSON document") from None


def read_grant(rows, agent, gate):
    if not agent or not re.fullmatch(r"enclave[0-9a-f]{8}Api", gate):
        raise Refused("missing agent or invalid API gate")
    if not isinstance(rows, list):
        raise Refused("CLI grant list is not an array")
    found = False
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("agent_id"), str) or type(row.get("is_active")) is not bool:
            raise Refused("CLI grant row has no valid agent or active flag")
        if row["agent_id"] != agent or not row["is_active"]:
            continue
        scope = row.get("scope")
        if not isinstance(scope, dict) or not isinstance(scope.get("capability"), str):
            raise Refused("an active desks agent grant has no readable scope")
        if scope["capability"] != "api.read":
            continue
        if not all(isinstance(scope.get(k), str) for k in ("instance_id", "resource_name")):
            raise Refused("an active read grant has no readable resource")
        found |= scope["instance_id"] == gate and scope["resource_name"] == "apis/desks"
    return "active" if found else "missing"


def confirmed_limits(answer, agent, gate):
    grants = answer.get("grants") if isinstance(answer, dict) else None
    if (not isinstance(grants, dict) or grants.get("status") != "read"
            or grants.get("agent") != agent or grants.get("gate") != gate):
        raise Refused("CLI show did not confirm the expected agent and API gate")
    preview = answer.get("preview") if isinstance(answer, dict) else None
    decision = preview.get("decision") if isinstance(preview, dict) else None
    if (not isinstance(decision, dict) or decision.get("action") != "keep"
            or not isinstance(decision.get("id"), str) or not decision["id"]):
        raise Refused("CLI show did not confirm a keep decision")
    proposed = preview.get("proposed")
    path = Path(__file__).resolve().parents[1] / "vendor/ekka-contracts/governance/grant-constraints/desks.v1.schema.json"
    with path.open(encoding="utf-8") as source:
        schema = json.load(source)
    if schema_errors(proposed, schema["$defs"]["full"], schema):
        # Never echo arbitrary JSON values (or unknown keys) into a diagnostic.
        raise Refused("CLI show did not return valid FULL limits at preview.proposed")
    return (json.dumps(proposed, indent=2, allow_nan=False) + "\n").encode()


def main(argv):
    try:
        if len(argv) == 3 and argv[0] == "read-grant":
            print(read_grant(read_json(sys.stdin), argv[1], argv[2]))
        elif len(argv) == 4 and argv[0] == "record":
            desk_records.write(argv[1], confirmed_limits(read_json(sys.stdin), argv[2], argv[3]))
        else:
            raise Refused("usage: desk_grant_cli.py read-grant <agent> <gate> | record <dest> <agent> <gate>")
    except desk_records.NotConfirmedSaved:
        print("REFUSED: grant record replaced, but the disk did not confirm it is saved", file=sys.stderr)
        return 1
    except (Refused, desk_records.Refused) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, RecursionError):
        print("REFUSED: grant record could not be read, validated or written", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
