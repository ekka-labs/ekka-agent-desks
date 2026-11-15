"""The example plans for each desk, and the prompts they pin.

A plan names its desk as a literal resource, so each desk gets its own copy, made by tools/desk_plans.py from
ekka/plans/. The ask plan ends well only when the job succeeded and the Enclave collected an answer file; every
other arm before that one fails.
"""
import glob
import json
import os
import re
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import desk_plans  # noqa: E402

# EKKA's platform prompts are not in this repository, and neither are their tests.
PROMPT_PLANS = ("ask",)   # the plans that send the desk's agent a prompt; setup is a command job


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def step(plan):
    return plan["definition"]["operations"][0]["steps"][0]



class ADeskName(unittest.TestCase):
    def test_becomes_one_camel_case_segment(self):
        self.assertEqual(desk_plans.desk_code("code-desk"), "codeDesk")
        self.assertEqual(desk_plans.desk_code("business.desk_2"), "businessDesk2")
        self.assertEqual(desk_plans.desk_code("2nd-desk"), "desk2ndDesk")
        self.assertEqual(desk_plans.desk_code("walk-desk"), "walkDesk")

    def test_that_is_not_a_desk_name_is_refused(self):
        for bad in ["", "Bad Desk", "-x", "desk/../x", "a" * 64]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                desk_plans.desk_code(bad)


class EachDesksPlans(unittest.TestCase):
    def test_the_templates_name_no_desk(self):
        for plan in desk_plans.PLANS:
            text = read(os.path.join(ROOT, "ekka", "plans", f"{plan}.json"))
            self.assertNotIn("code-desk", text, f"ekka/plans/{plan}.json names a desk; use {{{{desk}}}}")

    def test_name_the_desk_once_as_their_resource_and_carry_its_code(self):
        for plan in desk_plans.PLANS:
            d = desk_plans.render(plan, "business-desk", "agent-1")
            self.assertEqual(step(d)["resource"], "desks/business-desk")
            self.assertEqual(d["plan"]["code"], f"example.desk.{plan}.businessDesk.v1")
            self.assertEqual(d["plan"]["agent"], "agent-1")
            self.assertNotIn("{{", json.dumps(d))
            self.assertNotIn("desk", step(d)["inputs"], "a job step names its desk once, as its resource")



class TheAskPlan(unittest.TestCase):
    def setUp(self):
        self.plan = desk_plans.render("ask", "code-desk")
        self.op = self.plan["definition"]["operations"][0]

    def test_ends_well_only_when_the_enclave_collected_an_answer(self):
        outputs = {o["kind"]: o["path"] for o in step(self.plan)["inputs"]["outputs"]}
        self.assertEqual(outputs.get("answer"), ".ekka/answer.md")
        # Declared, so the Enclave's measured digest of the collected file crosses as a bounded fact. Undeclared,
        # it never reaches the transition and every ask fails (measured on a walk, 2026-10-13).
        declared = step(self.plan)["step_output_contract"]["properties"].get("answer")
        self.assertEqual(declared, {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"})
        self.assert_ends_only_on_success_with_an_answer(self.op["transitions"])

    def assert_ends_only_on_success_with_an_answer(self, transitions):
        # The grammar has no `&&`, and the first matching arm wins. Govern's validator needs an explicit
        # `verdict == 'failed'` arm, and a job's verdict is only succeeded or failed. So "ends
        # only on succeeded AND an answer" is: every arm BEFORE the one end arm fails, the first is the failed
        # verdict, the end arm is the collected answer, and anything else falls to a failing default.
        arms = list(transitions.items())
        ends = [i for i, (_, target) in enumerate(arms) if target == "end"]
        self.assertEqual([arms[i][0] for i in ends], ["exists(output.answer)"], "only a collected answer may end the run well")
        self.assertEqual(arms[0], ("output.verdict == 'failed'", "fail"), "a failed job fails before the answer is looked at")
        self.assertEqual([t for _, t in arms[:ends[0]]], ["fail"] * ends[0], "every arm before the end arm fails")
        self.assertEqual(arms[ends[0] + 1:], [("default", "fail")], "a fail arm after the end arm never fires once an answer exists")

    def test_planted_a_fail_arm_after_the_end_arm_is_caught(self):
        # v0.1.2's order: a timed-out step that still collected an (old) answer file ended well.
        planted = {"output.verdict == 'failed'": "fail", "exists(output.answer)": "end",
                   "output.status == 'timeout'": "fail", "default": "fail"}
        with self.assertRaises(AssertionError):
            self.assert_ends_only_on_success_with_an_answer(planted)
        with self.assertRaises(AssertionError):
            self.assert_ends_only_on_success_with_an_answer({"exists(output.answer)": "end", "default": "fail"})

    def assert_the_answer_is_the_enclaves(self, s, prompt):
        outputs = {o["kind"]: o["path"] for o in s["inputs"]["outputs"]}
        self.assertIn("answer", outputs, "output.answer is the Enclave's digest only when answer is a declared output")
        record = s["inputs"].get("facts_from")
        self.assertNotEqual(record, "answer", "the agent's record must not be the answer itself")
        self.assertNotEqual(outputs.get(record), outputs["answer"], "the record and the answer are different files")
        # The agent writes no hash; computing one needs a command the desk does not allow.
        self.assertNotIn("answer_sha256", prompt)
        self.assertNotIn("SHA-256", prompt)

    def test_setup_reuses_existing_checkouts(self):
        # No AI clones. The setup plan runs desk/setup/desk-setup.sh, which clones only an absent folder and
        # reuses a checkout as it is; tests/test_desk_setup.py runs it.
        s = step(desk_plans.render('setup', 'code-desk'))
        self.assertNotIn('prompt', s)
        script = read(desk_plans.SETUP_SCRIPT)
        self.assertEqual(''.join(s['inputs']['command'][6:]), script)
        self.assertNotIn('reset --hard', script)
        self.assertNotIn('git checkout', script)
        self.assertNotIn('git switch', script)



class TheUnattendedCommandRules(unittest.TestCase):
    """A desk runs unattended, so a command Claude Code holds for approval fails the run. Every command a
    desk runs must be one the desk image allows unattended (tests/test_image_modes.py)."""

    def test_the_plans_pin_the_unattended_versions(self):
        self.assertNotIn("prompt", step(desk_plans.render("setup", "code-desk")))   # a command job
        self.assertEqual(step(desk_plans.render("ask", "code-desk"))["prompt"]["version"], 8)

    def test_setup_record_names_its_own_run(self):
        # The Enclave can bind the collected desk map to the run that wrote it, as the ask record already is.
        s = step(desk_plans.render("setup", "code-desk"))
        self.assertEqual(s["inputs"]["run_id"], "@ekka.run_id")
        self.assertEqual(s["inputs"]["command"][5], "@ekka.run_id")   # the script's run id: RUN=${I-}
        self.assertIn('jq -s --arg run "$RUN"', read(desk_plans.SETUP_SCRIPT))
