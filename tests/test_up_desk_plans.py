"""up.sh create_desk_plans: a plan EKKA refuses stops the install, by name.

EKKA never refuses an identical plan: it makes a patch version (measured on staging, 2026-10-13). So every
refusal is real, and treating one as "kept" would leave a machine running its old plan after an upgrade it
never got. The function runs here with `docker` stubbed: the copy succeeds and `plan create` answers as told.
"""
import os
import re
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def function():
    with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
        text = f.read()
    found = [re.search(rf"^{n}\(\) \{{\n.*?^\}}\n", text, re.S | re.M) for n in ("create_desk_plans", "install_plans", "share_plan")]
    assert all(found), "create_desk_plans, install_plans or share_plan is not in up.sh"
    return "".join(m.group(0) for m in found)


def run(reply, rc):
    state = tempfile.mkdtemp()
    script = f"""
set -euo pipefail
DESKS_STATE={state}; DESKS_AGENT=desks
ENCLAVE_HOME=$DESKS_STATE/enclave-home
ekka_in() {{ docker compose exec -T ekka-enclave ekka "$@"; }}   # the test's docker stub reads the ekka words after the marker
enclave_home_file() {{ mkdir -p "$(dirname "$ENCLAVE_HOME/$1")"; cat > "$ENCLAVE_HOME/$1"; }}
ok() {{ echo "ok: $*"; }}
die() {{ echo "die: $*" >&2; exit 1; }}
docker() {{
  case "$*" in
    *"plan create"*) printf '%s\\n' "$PLAN_REPLY"; return "$PLAN_RC" ;;
    *"plan publish"*) echo "✓ ${{@: -1}}: requested for org" ;;   # as EKKA answers an offer of an unlisted version
    *"plan approve"*) echo "✓ ${{@: -1}} is now org" ;;
    *) return 0 ;;
  esac
}}
{function()}
create_desk_plans business-desk agent-1
"""
    env = dict(os.environ, PLAN_REPLY=reply, PLAN_RC=str(rc))
    result = subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, env=env)
    import json
    result.plans = []
    for name in ('setup', 'ask'):
        path = os.path.join(state, 'plans', f'plan-{name}-business-desk.json')
        if os.path.exists(path):
            with open(path) as f:
                result.plans.append(json.load(f))
    return result


class CreateDeskPlans(unittest.TestCase):
    def test_planted_a_refusal_of_any_kind_stops_it_with_the_reason(self):
        r = run("  STAGING   a rehearsal\nvalidation_error: platform prompt \"example-prompt@1\" not found or inactive", 1)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("die: the plan ekka.example.desk.setup.businessDesk.v1 was not created", r.stderr)
        self.assertIn('platform prompt "example-prompt@1" not found or inactive', r.stderr)
        self.assertNotIn("kept", r.stdout + r.stderr)
        self.assertNotIn("ok: plan", r.stdout, "a refused plan must not be reported as made")

    def test_the_ask_plan_pins_the_published_unattended_prompt(self):
        result = run('Plan created: test@1.0.0', 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        ask = result.plans[1]['definition']['operations'][0]['steps'][0]
        self.assertEqual(ask['prompt'], {'source': 'platform', 'slug': 'desk-ask', 'version': 8})
    def test_a_created_plan_names_its_new_version(self):
        r = run("✓ Plan created: ekka.example.desk.setup.businessDesk.v1@1.0.1 · unlisted", 0)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok: plan ekka.example.desk.setup.businessDesk.v1@1.0.1, owned by desks", r.stdout)


class SharedDeskPlans(unittest.TestCase):
    """A second member runs a desk's plans without the administrator, so each new version of a desk's setup and
    ask plans is offered to the organization and accepted. Only a version EKKA just reported `unlisted`: an offer of a
    version already at `org` goes to EKKA's PUBLIC catalog, and up.sh runs again on every upgrade."""

    def share(self, created, published="requested for org", approved="is now org", sharing=None, text=None, held=""):
        state = tempfile.mkdtemp()
        calls = os.path.join(state, "calls")
        fn = function() if text is None else "".join(
            re.search(rf"^{n}\(\) \{{\n.*?^\}}\n", text, re.S | re.M).group(0)
            for n in ("create_desk_plans", "install_plans", "share_plan"))
        script = f"""
set -euo pipefail
DESKS_STATE={state}; DESKS_AGENT=desks
ENCLAVE_HOME=$DESKS_STATE/enclave-home
ekka_in() {{ docker compose exec -T ekka-enclave ekka "$@"; }}   # the test's docker stub reads the ekka words after the marker
enclave_home_file() {{ mkdir -p "$(dirname "$ENCLAVE_HOME/$1")"; cat > "$ENCLAVE_HOME/$1"; }}
ok() {{ echo "ok: $*"; }}
die() {{ echo "die: $*" >&2; exit 1; }}
docker() {{
  case "$*" in
    *"plan create "*"/plans/plan-setup"*) echo "plan create setup" >> {calls}; printf '%s\\n' "${{CREATED//NAME/setup}}" ;;
    *"plan create "*"/plans/plan-ask"*) echo "plan create ask" >> {calls}; printf '%s\\n' "${{CREATED//NAME/ask}}" ;;
    *"plan list --all --json"*) [ -n "$HELD" ] && python3 - "$DESKS_STATE/plans" "$HELD" <<'PY'
import json, os, sys
rows = []
for n in sorted(os.listdir(sys.argv[1])):
    p = json.load(open(os.path.join(sys.argv[1], n)))["plan"]
    rows.append({{"plan_code": p["code"], "plan_identity": "ekka." + p["code"] + "@1.0.3", "version": "1.0.3",
                 "status": "active", "visibility": sys.argv[2], "owner_agent": {{"agent_code": "desks"}}}})
print(json.dumps({{"plans": rows, "total": len(rows)}}))
PY
      ;;
    *"plan show "*"--definition --json"*) [ -n "$HELD" ] && python3 - "$DESKS_STATE/plans" "$*" <<'PY'
import json, os, sys
code = [w for w in sys.argv[2].split() if w.startswith("ekka.")][0].split("@")[0][len("ekka."):]
for n in sorted(os.listdir(sys.argv[1])):
    d = json.load(open(os.path.join(sys.argv[1], n)))
    if d["plan"]["code"] == code:
        print(json.dumps({{"plan_code": code, "name": d["plan"].get("name"), "plan_json": d["definition"],
                          "owner_agent": {{"agent_code": "desks"}}}}))
PY
      ;;
    *"plan publish "*) echo "publish ${{@: -1}}" >> {calls}; printf '%s\\n' "✓ ${{@: -1}}: $PUBLISHED" ;;
    *"plan approve "*) echo "approve ${{@: -1}}" >> {calls}; printf '%s\\n' "✓ ${{@: -1}} $APPROVED" ;;
    *) return 0 ;;
  esac
}}
{fn}
create_desk_plans business-desk agent-1 {sharing or ""}
"""
        env = dict(os.environ, CREATED=created, PUBLISHED=published, APPROVED=approved, HELD=held)
        out = subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, env=env)
        done = open(calls).read().splitlines() if os.path.exists(calls) else []
        return out, done

    UNLISTED = "✓ Plan created: ekka.example.desk.NAME.businessDesk.v1@1.0.3 · unlisted"

    def test_a_new_unlisted_version_is_offered_to_the_org_and_accepted(self):
        out, calls = self.share(self.UNLISTED)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(calls, ["plan create setup", "publish ekka.example.desk.setup.businessDesk.v1@1.0.3",
                                 "approve ekka.example.desk.setup.businessDesk.v1@1.0.3",
                                 "plan create ask", "publish ekka.example.desk.ask.businessDesk.v1@1.0.3",
                                 "approve ekka.example.desk.ask.businessDesk.v1@1.0.3"])
        self.assertIn("every member of this organization may run it", out.stdout)

    def test_an_unchanged_plan_left_unshared_by_an_earlier_run_is_shared_now(self):
        # Not created again, but an earlier run that made the version and then failed to share it is finished.
        out, calls = self.share(self.UNLISTED, held="unlisted")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(calls, ["publish ekka.example.desk.setup.businessDesk.v1@1.0.3",
                                 "approve ekka.example.desk.setup.businessDesk.v1@1.0.3",
                                 "publish ekka.example.desk.ask.businessDesk.v1@1.0.3",
                                 "approve ekka.example.desk.ask.businessDesk.v1@1.0.3"])
        self.assertEqual(out.stdout.count("(unchanged, no new version)"), 2, out.stdout)

    def test_an_unchanged_plan_already_shared_is_neither_created_nor_offered(self):
        out, calls = self.share(self.UNLISTED, held="org")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(calls, [], "no create, and no offer of an org version to EKKA's public catalog")

    def test_a_version_already_at_org_is_never_offered_again(self):
        out, calls = self.share("✓ Plan created: ekka.example.desk.NAME.businessDesk.v1@1.0.3 · org")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse([c for c in calls if c.startswith(("publish", "approve"))], calls)
        self.assertIn("not offered (an offer of an org plan would go to EKKA's public catalog)", out.stdout)

    def test_an_unknown_standing_is_never_offered(self):
        out, calls = self.share("Plan created: test@1.0.0")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse([c for c in calls if c.startswith(("publish", "approve"))], calls)

    def test_an_offer_anywhere_but_the_org_is_never_approved(self):
        out, calls = self.share(self.UNLISTED, published="requested for public")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("offered somewhere other than this organization, so it was not approved", out.stderr)
        self.assertFalse([c for c in calls if c.startswith("approve")], calls)

    def test_an_approval_that_lands_elsewhere_stops_the_install(self):
        out, _ = self.share(self.UNLISTED, approved="is now public")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("approved to something other than this organization", out.stderr)

    def test_private_plans_are_never_offered(self):
        out, calls = self.share(self.UNLISTED, sharing="private")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(calls, ["plan create setup", "plan create ask"])

    def test_the_desk_admin_plans_are_never_offered(self):
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
        admin = re.search(r"^create_desk_admin_plans\(\) \{\n.*?^\}\n", text, re.S | re.M).group(0)
        self.assertIn('install_plans "$made" private', admin)

    def test_planted_reds_are_caught(self):
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
        no_rung_guard = text.replace('if [[ -z $identity || $rung != unlisted ]]; then', 'if [[ -z $identity ]]; then')
        self.assertNotEqual(no_rung_guard, text)
        _, calls = self.share("✓ Plan created: ekka.example.desk.NAME.businessDesk.v1@1.0.3 · org", text=no_rung_guard)
        self.assertTrue([c for c in calls if c.startswith("publish")], "PLANTED: an org version offered again (public)")
        no_org_check = text.replace('grep -q "requested for org" <<<"$out"', 'true')
        self.assertNotEqual(no_org_check, text)
        _, calls = self.share(self.UNLISTED, published="requested for public", text=no_org_check)
        self.assertTrue([c for c in calls if c.startswith("approve")], "PLANTED: an offer to public approved")


if __name__ == "__main__":
    unittest.main()
