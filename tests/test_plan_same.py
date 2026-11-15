"""tools/plan_same.py: a plan is "the same" only when EKKA's newest version of it has the file's definition, name and
agent; anything else, unreadable included, is "not the same", so the installer creates a version as before."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TOOL = os.path.join(ROOT, "tools", "plan_same.py")
PLAN = {"plan": {"code": "desk.stop.v1", "name": "Stop a desk", "agent": "237d65b5-0000-4000-8000-000000000001"},
        "definition": {"schema_version": "plan.v1", "inputs": {"desk": "The desk"}, "operations": [{"op": "x"}]}}


def plan_file(content=PLAN):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(content, f)
    f.close()
    return f.name


def run(*args, stdin=""):
    return subprocess.run([sys.executable, TOOL, *args], input=stdin, capture_output=True, text=True)


def row(version, status="active", agent="desks", code="desk.stop.v1", visibility="unlisted"):
    return {"plan_code": code, "plan_identity": f"ekka.{code}@{version}", "version": version, "status": status,
            "owner_agent": {"agent_code": agent}, "visibility": visibility}


def shown(definition=PLAN["definition"], name="Stop a desk", agent="desks", code="desk.stop.v1"):
    return json.dumps({"plan_code": code, "name": name, "plan_json": definition, "owner_agent": {"agent_code": agent}})


class TheNewestVersion(unittest.TestCase):
    def test_the_newest_active_version_of_this_plan_by_this_agent(self):
        rows = [row("2.0.9"), row("2.0.10"), row("2.0.11", status="archived"), row("3.0.0", agent="other"),
                row("9.0.0", code="desk.start.v1")]
        r = run("latest", plan_file(), "desks", stdin=json.dumps({"plans": rows, "total": len(rows)}))
        self.assertEqual(r.stdout.strip(), "ekka.desk.stop.v1@2.0.10 unlisted", "2.0.10 beats 2.0.9 by number, not text")

    def test_a_candidate_it_cannot_read_names_none_never_an_older_one(self):
        # A newer version with an unreadable number might be the newest: falling back to 2.0.9 could skip a change.
        for bad in ({**row("2.0.10"), "version": "2.0.x"}, {**row("2.0.10"), "plan_identity": None},
                    {**row("2.0.10"), "visibility": None}):
            rows = [row("2.0.9"), bad]
            r = run("latest", plan_file(), "desks", stdin=json.dumps({"plans": rows, "total": len(rows)}))
            self.assertEqual(r.stdout.strip(), "", bad)

    def test_none_held_or_a_list_it_cannot_trust_names_none(self):
        for stdin in (json.dumps({"plans": [], "total": 0}), json.dumps({"plans": [row("2.0.1")], "total": 2}),
                      "[]", "not json", ""):
            r = run("latest", plan_file(), "desks", stdin=stdin)
            self.assertEqual(r.stdout.strip(), "", stdin)


class TheSamePlan(unittest.TestCase):
    def test_the_same_definition_name_and_agent_is_the_same(self):
        self.assertEqual(run("same", plan_file(), "desks", stdin=shown()).returncode, 0)

    def test_any_difference_or_anything_unreadable_is_not_the_same(self):
        changed = {**PLAN["definition"], "inputs": {}}
        for stdin in (shown(definition=changed), shown(name="Stop"), shown(agent="other"), shown(code="desk.x.v1"),
                      json.dumps({"plan_json": None}), "not json", ""):
            self.assertEqual(run("same", plan_file(), "desks", stdin=stdin).returncode, 1, stdin[:60])

    def test_a_file_that_is_not_a_plan_is_not_the_same(self):
        self.assertEqual(run("same", plan_file({"nope": 1}), "desks", stdin=shown()).returncode, 1)


if __name__ == "__main__":
    unittest.main()
