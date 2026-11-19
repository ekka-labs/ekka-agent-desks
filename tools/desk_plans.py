"""The example plans for one desk: setup and ask, from the templates in ekka/plans/. Setup runs
desk/setup/desk-setup.sh as a command job (no AI); ask sends a platform prompt to the desk's agent.

    python3 tools/desk_plans.py <desk> <out-dir> [<agent id>]

A job step names its desk once, as a literal `resource: desks/<name>`; EKKA refuses a desk taken from a plan
input. So each desk gets its own copy of each plan, made here from one template, and a second desk is set up
and asked through its own plans. A plan code allows only letters and digits in each segment, so the desk name
is written in camelCase there: code-desk becomes example.desk.ask.codeDesk.v1.

Writes <out-dir>/plan-setup-<desk>.json and <out-dir>/plan-ask-<desk>.json, and prints each plan code.

    python3 tools/desk_plans.py --admin <api gate> <out-dir> [<agent id>]

The two desk administration plans of an organization, ekka.desk.read.v1 and ekka.desk.write.v1,
serve every adapter operation in runner 0.6.12 or newer. Each plan is one call through the Enclave's API gate
to the backend adapter on `apis/desks`, may be run only by an organization admin, and reads two facts from
the adapter's answer: `outcome` and `desk_ready`. Both take the route as a whole input; the write also takes
the whole request and its body hash. One pair serves every desk.
Writes <out-dir>/plan-desk-read.json and <out-dir>/plan-desk-write.json, and prints each plan code.
Standard library only.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLANS = ("setup", "ask")
DESK = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")   # EKKA's desks/<name>


def desk_code(desk):
    """The desk name as one plan-code segment: code-desk -> codeDesk, 2nd.desk -> desk2ndDesk."""
    if not DESK.match(desk):
        raise ValueError(f"'{desk}' is not a desk name: lowercase letters, digits, '.', '_' or '-', starting with "
                         "a letter or digit, at most 63 characters")
    parts = [p for p in re.split(r"[._-]", desk) if p]
    if not parts:
        raise ValueError(f"'{desk}' has no letters or digits to name a plan with")
    if parts[0][0].isdigit():
        parts.insert(0, "desk")
    return parts[0] + "".join(p[0].upper() + p[1:] for p in parts[1:])


def _fill(value, desk, code):
    if isinstance(value, str):
        return value.replace("{{desk}}", desk).replace("{{deskCode}}", code)
    if isinstance(value, list):
        return [_fill(v, desk, code) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, desk, code) for k, v in value.items()}
    return value


# The setup plan is a command job, not an AI: desk/setup/desk-setup.sh, sent in words.
SETUP_SCRIPT = os.path.join(ROOT, "desk", "setup", "desk-setup.sh")
MAX_WORD = 4096   # the desk request's limit on one command word (ekka.job.desk.request v1)
MAX_WORDS = 64    # and on the words in one command


def script_words(path):
    """A script in words of at most MAX_WORD bytes, cut at line ends, so it can grow past one word."""
    with open(path, encoding="utf-8") as f:
        script = f.read()
    words, cur = [], ""
    for line in script.splitlines(keepends=True):
        if len(line.encode()) > MAX_WORD:
            raise ValueError(f"one line of {os.path.relpath(path, ROOT)} is over {MAX_WORD} bytes")
        if len((cur + line).encode()) > MAX_WORD:
            words.append(cur)
            cur = ""
        cur += line
    words.append(cur)
    return words


def setup_command():
    """bash runs the script's words joined back. The run's repos and run id are the two words before them: plain
    arguments, never part of the script, so an address cannot become a command."""
    words = ["/bin/bash", "-c", 'R=$1; I=$2; shift 2; eval "$(printf %s "$@")"', "desk-setup",
             "@input.repos", "@ekka.run_id", *script_words(SETUP_SCRIPT)]
    if len(words) > MAX_WORDS:
        raise ValueError(f"the setup command needs {len(words)} words; a desk request takes at most {MAX_WORDS}")
    return words


def render(plan, desk, agent=None):
    """One plan for one desk, from its template; `agent` sets the owning agent."""
    with open(os.path.join(ROOT, "ekka", "plans", f"{plan}.json")) as f:
        d = _fill(json.load(f), desk, desk_code(desk))
    for op in d["definition"]["operations"]:
        for s in op["steps"]:
            if s.get("inputs", {}).get("command") == "{{setupCommand}}":
                s["inputs"]["command"] = setup_command()
    if "{{" in json.dumps(d):
        raise ValueError(f"ekka/plans/{plan}.json has a placeholder this tool does not fill")
    if agent:
        d["plan"]["agent"] = agent
    return d


ADMIN_INPUTS = {
    "body_sha256": "The SHA-256 of the body as the API gate encodes it, lowercase hex. With no body, the SHA-256 of "
                   "zero bytes, so a body slipped in is refused.",
    "path": "The adapter route, starting with /v1/, for example /v1/grant-facts or /v1/desks/code-desk/stop.",
    "request": "The request: method is POST, PUT or DELETE; body is the optional exact JSON object as the CLI built it.",
}
GENERAL_ADMIN_PLANS = ("read", "write")
# What a plan reads from the adapter's answer. `running` is left out on purpose: the adapter answers it only at its
# deadline, as an HTTP 202, and a fact outside the enum fails the step. Not `required`: Govern refuses a required
# field the API gate does not promise, and a fact that is missing fails the run through the transitions' default.
ADMIN_FACTS = {
    "type": "object",
    "properties": {
        "outcome": {"type": "string", "enum": ["ready", "refused", "unknown"]},
        "desk_ready": {"type": "boolean"},
    },
}
API_GATE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")   # Govern's gate instance id
ADMIN_USAGE = "python3 tools/desk_plans.py --admin <api gate> <out-dir> [<agent id>]"


def general_admin_plan(op, api_gate, agent=None):
    """A general adapter call: the route and write request are whole-value inputs."""
    if op not in GENERAL_ADMIN_PLANS:
        raise ValueError(f"'{op}' is not a general desk administration plan; there are: read, write")
    call = {"resource": "apis/desks", "key": "@input.path"}
    contract = {"resource": {"type": "string"}, "key": {"type": "string"}}
    if op == "write":
        name = "Change something on the desk server"
        inputs = ("path", "request", "body_sha256")
        # Embedded references are resolved only in value.body, never value.method. Bind the whole request.
        call.update(value="@input.request", body_sha256="@input.body_sha256")
        contract["value"] = {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["POST", "PUT", "DELETE"], "required": True},
                "body": {"type": "object"},
            },
        }
        contract["body_sha256"] = {"type": "string"}
    else:
        name = "Read from the desk server"
        inputs = ("path",)
        call["expect"] = {"status": 200}
        contract["expect"] = {"type": "object"}
    if not API_GATE.match(api_gate or ""):
        raise ValueError(f"'{api_gate}' is not an API gate instance id, for example enclaveb0000002Api")
    plan = {
        "plan": {"code": f"desk.{op}.v1", "name": name},
        "definition": {
            "schema_version": "ekka.plan.v2",
            "requires_role": "admin",
            "inputs": {i: ADMIN_INPUTS[i] for i in inputs},
            "operations": [{
                "id": "desk",
                "display_name": f"{name}, through the backend adapter",
                "execution": {"preferred": {"mode": "async", "runtime": "node"}},
                "max_visits": 1,
                "steps": [{
                    "id": "call",
                    "action_ref": "ekka.gate.api.v1",
                    "target": api_gate,
                    "op": op,
                    "feature": f"api.{op}",
                    "identity": {"requires_user_context": True},
                    "action_input": {},
                    "inputs": call,
                    "step_input_contract": {"type": "object", "properties": contract, "required": sorted(contract)},
                    "step_output_contract": ADMIN_FACTS,
                }],
                "transitions": {"output.outcome == 'ready'": "end", "default": "fail"},
            }],
        },
    }
    if agent:
        plan["plan"]["agent"] = agent
    return plan


def main_admin(argv):
    if len(argv) not in (2, 3):
        print(ADMIN_USAGE, file=sys.stderr)
        return 2
    api_gate, out = argv[0], argv[1]
    agent = argv[2] if len(argv) == 3 else None
    try:
        plans = [general_admin_plan(op, api_gate, agent) for op in GENERAL_ADMIN_PLANS]
        for d in plans:
            op = d["plan"]["code"].split(".")[1]
            path = os.path.join(out, f"plan-desk-{op}.json")
            with open(path, "w") as f:
                json.dump(d, f, indent=2)
            print(f"{path} ekka.{d['plan']['code']}")
    except ValueError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    return 0


def main(argv):
    if argv[:1] == ["--admin"]:
        return main_admin(argv[1:])
    if len(argv) not in (2, 3):
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    desk, out = argv[0], argv[1]
    agent = argv[2] if len(argv) == 3 else None
    try:
        for plan in PLANS:
            d = render(plan, desk, agent)
            path = os.path.join(out, f"plan-{plan}-{desk}.json")
            with open(path, "w") as f:
                json.dump(d, f, indent=2)
            print(f"{path} ekka.{d['plan']['code']}")
    except ValueError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
