"""The two general desk administration plans for runner 0.6.8 or newer.

Each reads or writes an adapter route through the Enclave's API gate, as an organization admin.
The facts are checked against the answers in vendor/ekka-contracts (published @ekka-ai/contracts 0.83.0).
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
VENDOR = os.path.join(ROOT, "vendor", "ekka-contracts")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import desk_plans  # noqa: E402

GATE = "enclaveb0000002Api"
GENERAL_OPS = ["read", "write"]


def vendored(path):
    with open(os.path.join(VENDOR, path), encoding="utf-8") as f:
        return json.load(f)


def step(plan):
    return plan["definition"]["operations"][0]["steps"][0]


def facts_accept(contract, answer):
    """The plan's fact check on arrival: each declared fact present in a 2xx answer must fit its declaration."""
    for name, decl in contract["properties"].items():
        if name not in answer:
            continue
        value = answer[name]
        if decl.get("type") == "boolean" and not isinstance(value, bool):
            return False
        if decl.get("type") == "string" and not isinstance(value, str):
            return False
        if "enum" in decl and value not in decl["enum"]:
            return False
    return True


class TheVendoredContract(unittest.TestCase):
    def test_is_the_published_files_byte_for_byte(self):
        manifest = vendored("MANIFEST.json")
        self.assertEqual(manifest["version"], "0.83.0")
        self.assertEqual(manifest["tag"], "v0.83.0")
        for path, digest in manifest["files"].items():
            with open(os.path.join(VENDOR, path), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, path)
        on_disk = sorted(f"backend/samples/{n}" for n in os.listdir(os.path.join(VENDOR, "backend", "samples")))
        self.assertEqual(sorted(p for p in manifest["files"] if p.startswith("backend/samples/")), on_disk,
                         "a sample with no manifest entry, or an entry with no file")
        self.assertIn("backend/samples/result.grant-facts-ready.json", manifest["files"])


class TheGeneralPlans(unittest.TestCase):
    def test_are_named_for_read_and_write_with_the_given_owner_and_gate(self):
        names = {"read": "Read from the desk server", "write": "Change something on the desk server"}
        self.assertEqual(list(desk_plans.GENERAL_ADMIN_PLANS), GENERAL_OPS)
        for op, name in names.items():
            with self.subTest(op=op):
                plan = desk_plans.general_admin_plan(op, "exampleApi", "example-agent")
                self.assertEqual(plan["plan"], {"code": f"desk.{op}.v1", "name": name, "agent": "example-agent"})
                d = plan["definition"]
                self.assertEqual(d["schema_version"], "ekka.plan.v2")
                self.assertNotIn("runs_as", d)
                self.assertEqual(d["requires_role"], "admin")
                self.assertEqual(len(d["operations"]), 1)
                operation = d["operations"][0]
                self.assertEqual(operation["max_visits"], 1)
                self.assertEqual(operation["execution"], {"preferred": {"mode": "async", "runtime": "node"}})
                self.assertEqual(len(operation["steps"]), 1)
                s = step(plan)
                self.assertEqual((s["op"], s["feature"]), (op, f"api.{op}"))
                self.assertEqual((s["action_ref"], s["target"]), ("ekka.gate.api.v1", "exampleApi"))
                self.assertEqual(s["identity"], {"requires_user_context": True})
                self.assertEqual(s["action_input"], {})

    def test_read_binds_the_whole_route_and_requires_only_path(self):
        plan = desk_plans.general_admin_plan("read", GATE)
        self.assertEqual(list(plan["definition"]["inputs"]), ["path"])
        s = step(plan)
        self.assertEqual(s["inputs"], {"resource": "apis/desks", "key": "@input.path", "expect": {"status": 200}})
        self.assertEqual(s["step_input_contract"], {
            "type": "object",
            "properties": {"resource": {"type": "string"}, "key": {"type": "string"}, "expect": {"type": "object"}},
            "required": ["expect", "key", "resource"],
        })

    def test_write_binds_the_whole_request_and_pins_its_body(self):
        plan = desk_plans.general_admin_plan("write", GATE)
        self.assertEqual(list(plan["definition"]["inputs"]), ["path", "request", "body_sha256"])
        self.assertEqual(plan["definition"]["inputs"]["body_sha256"], desk_plans.ADMIN_INPUTS["body_sha256"])
        s = step(plan)
        self.assertEqual(s["inputs"], {
            "resource": "apis/desks", "key": "@input.path", "value": "@input.request", "body_sha256": "@input.body_sha256",
        })
        self.assertEqual(s["step_input_contract"], {
            "type": "object",
            "properties": {
                "resource": {"type": "string"},
                "key": {"type": "string"},
                "value": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "enum": ["POST", "PUT", "DELETE"], "required": True},
                        "body": {"type": "object"},
                    },
                },
                "body_sha256": {"type": "string"},
            },
            "required": ["body_sha256", "key", "resource", "value"],
        })

    def test_omitting_the_agent_keeps_the_product_default(self):
        for op in GENERAL_OPS:
            self.assertNotIn("agent", desk_plans.general_admin_plan(op, GATE)["plan"])

    def test_refuses_invalid_gates_and_unknown_operations(self):
        for op in GENERAL_OPS:
            for bad in ["", "enclave 1", "-x", "../gate"]:
                with self.subTest(op=op, gate=bad), self.assertRaises(ValueError):
                    desk_plans.general_admin_plan(op, bad)
        with self.assertRaises(ValueError):
            desk_plans.general_admin_plan("connect", GATE)


class TheFacts(unittest.TestCase):
    """EKKA output validation: each plan's facts, checked against the adapter's own answers."""

    def setUp(self):
        self.samples = {n[len("result."):-len(".json")]: vendored(f"backend/samples/{n}")
                        for n in os.listdir(os.path.join(VENDOR, "backend", "samples"))
                        if n.startswith("result.")}   # the answers only: the config, marker and hold samples are not

    def test_are_outcome_and_desk_ready_and_nothing_else(self):
        for op in GENERAL_OPS:
            contract = step(desk_plans.general_admin_plan(op, GATE))["step_output_contract"]
            self.assertEqual(contract["properties"], {
                "outcome": {"type": "string", "enum": ["ready", "refused", "unknown"]},
                "desk_ready": {"type": "boolean"},
            }, op)
            self.assertNotIn("required", contract, f"{op}: Govern refuses a required field the gate does not promise")

    def test_take_every_answer_a_plan_reaches_and_refuse_running(self):
        for op in GENERAL_OPS:
            contract = step(desk_plans.general_admin_plan(op, GATE))["step_output_contract"]
            for name, answer in self.samples.items():
                with self.subTest(op=op, sample=name):
                    self.assertEqual(facts_accept(contract, answer), answer["outcome"] != "running",
                                     "ready, refused and unknown cross; running, the 202 at the deadline, fails")
        self.assertIn("running", {a["outcome"] for a in self.samples.values()}, "the running answer is vendored")

    def test_only_ready_ends_the_run_well(self):
        for op in GENERAL_OPS:
            transitions = desk_plans.general_admin_plan(op, GATE)["definition"]["operations"][0]["transitions"]
            self.assertEqual(transitions, {"output.outcome == 'ready'": "end", "default": "fail"}, op)


class TheTool(unittest.TestCase):
    def test_writes_only_the_two_general_plans_and_names_each(self):
        out = tempfile.mkdtemp()
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "desk_plans.py"), "--admin", GATE, out, "a-1"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(GENERAL_OPS), 2)
        self.assertEqual(sorted(os.listdir(out)), sorted(f"plan-desk-{op}.json" for op in GENERAL_OPS))
        self.assertEqual([line.split()[1] for line in r.stdout.splitlines()], [f"ekka.desk.{op}.v1" for op in GENERAL_OPS])
        for op in GENERAL_OPS:
            with open(os.path.join(out, f"plan-desk-{op}.json")) as f:
                plan = json.load(f)
            self.assertEqual(plan["plan"]["agent"], "a-1")
            self.assertNotIn("runs_as", plan["definition"])
            self.assertEqual(step(plan)["target"], GATE)

    def test_refuses_a_bad_gate_by_name(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "desk_plans.py"), "--admin", "bad gate",
                            tempfile.mkdtemp()], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("REFUSED: 'bad gate' is not an API gate instance id", r.stderr)


if __name__ == "__main__":
    unittest.main()
