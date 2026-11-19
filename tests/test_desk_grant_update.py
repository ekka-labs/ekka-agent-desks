"""The installer bootstraps read access, delegates updates, and records only confirmed CLI limits."""
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import desk_grant_cli as cli
import desk_records

AGENT = "example-agent"
GATE = "enclaveb0000001Api"
LIMITS = json.loads((ROOT / "tests/fixtures/desks-grant.json").read_text())
ANSWER = {"grants": {"status": "read", "agent": AGENT, "gate": GATE}, "preview": {"decision": {"action": "keep", "id": "example-grant"}, "proposed": LIMITS}}
READ = {"agent_id": AGENT, "is_active": True,
        "scope": {"instance_id": GATE, "resource_name": "apis/desks", "capability": "api.read", "constraints": None}}


def function(name):
    return re.search(rf"^{name}\(\) \{{.*?^\}}\n", (ROOT / "up.sh").read_text(), re.S | re.M).group(0)


class UpdateStep(unittest.TestCase):
    def run_step(self, rows=None, answer=None, fail="", list_text=None, plan_fails=False, record_fails=False, grant_record_fails=False, agent="desks", retired="files"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            backend = state / "backend"
            backend.mkdir(parents=True)
            (backend / "desks-grant.json").write_text('{"old_record":true}\n')
            (state / "up.env").write_text("EKKA_BACKEND_IMAGE=example\n")
            # Already written by the image/baseline steps and project commands.
            inputs = {"desk-image.json": {"image": "ekka-desk:local", "id": LIMITS["image_digests"][0]},
                      "baseline-policy.json": json.loads((ROOT / "desk/policy.json").read_text()),
                      "projects/acme.project.json": {"name": "acme"}}
            for name, value in inputs.items():
                path = backend / name
                path.parent.mkdir(exist_ok=True)
                path.write_text(json.dumps(value))
            target = root / "untouched"
            target.write_text("unchanged")
            for name in cli.RETIRED_FILES:
                path = backend / name
                if retired == "files":
                    path.write_text("not JSON; must never be read")
                elif retired == "links":
                    path.symlink_to(target)
                elif retired == "dangling":
                    path.symlink_to(root / "missing")
                elif retired == "directory":
                    path.mkdir()
            (root / "tools").mkdir()
            # Exercise the real parsers and atomic writer in a trusted test-owned tree.
            for name in ("desk_grant_cli", "desk_records"):
                (root / f"tools/{name}.py").write_text('''import os, sys
sys.path.insert(0, os.environ["REAL_TOOLS"])
import desk_records
original = desk_records.write
def write(dest, data):
    if os.environ["RECORD_FAIL"] == "1" or (os.environ["GRANT_RECORD_FAIL"] == "1" and dest.endswith("/desks-grant.json")):
        raise desk_records.Refused("test record write failure")
    original(dest, data, top=os.environ["TEST_ROOT"], owner=os.getuid())
desk_records.write = write
import ''' + name + ''' as command
if hasattr(command, "remove_retired"):
    remove = command.remove_retired
    command.remove_retired = lambda folder: remove(folder, top=os.environ["TEST_ROOT"], owner=os.getuid())
sys.exit(command.main(sys.argv[1:]))
''')
            (root / "docker").write_text('''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as out: out.write(json.dumps(args) + "\\n")
key = " ".join(args)
if args[:2] == ["image", "inspect"]: print("sha256:" + "d" * 64)
elif key == "enclave status --json": print('{"node_id":"example-node"}')
elif key == "agent list --json": print('{"agents":[{"agent_code":"desks","agent_id":"example-agent"}]}')
elif key == "gate list --json": print('[{"connector_type":"api","node_id":"example-node","instance_id":"enclaveb0000001Api"}]')
elif key == "gate grant list --json": print(os.environ["ROWS"])
elif key == "desk grant show --json": print(os.environ["ANSWER"])
elif key == "desk grant update --yes":
    folder = os.path.join(os.environ["DESKS_STATE"], "backend")
    for name in ("desk-image.json", "baseline-policy.json", "provider-ceiling.json", "projects/acme.project.json"):
        assert os.path.isfile(os.path.join(folder, name)), name
    for name in ("desks-grant.extras.json", "discovery-policy.json", "discovery-composed.json"):
        assert not os.path.lexists(os.path.join(folder, name)), name
    print("Update completed")
elif args[:3] == ["gate", "grant", "add"]: print("Granted api.read")
else: raise SystemExit("unexpected CLI call")
if key.startswith(os.environ["FAIL_CALL"]) and os.environ["FAIL_CALL"]:
    print("CLI refused the requested operation", file=sys.stderr)
    sys.exit(7)
''')
            (root / "docker").chmod(0o755)
            script = '''set -euo pipefail
die() { echo "$*" >&2; exit 1; }
say() { :; }; ok() { echo "ok: $*"; }
ekka_in() { docker "$@"; }
create_desk_admin_plans() {
  echo '["plans", "read", "write"]' >> "$CALLS"
  [[ $PLAN_FAIL != 1 ]] || die "plan refused"
}
profile_names() { echo github; }
profile_source() { echo "$REAL_PROVIDERS/$1.yaml"; }
''' + function("step_desk_grant") + '\n(step_desk_grant) || exit $?\necho finished\n'
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], DESKS_STATE=str(state),
                       DESKS_AGENT=agent, TEST_ROOT=str(root), REAL_TOOLS=str(ROOT / "tools"),
                       REAL_PROVIDERS=str(ROOT / "providers"), CALLS=str(root / "calls"),
                       ROWS=list_text if list_text is not None else json.dumps([] if rows is None else rows),
                       ANSWER=json.dumps(ANSWER if answer is None else answer), FAIL_CALL=fail,
                       PLAN_FAIL=str(int(plan_fails)), RECORD_FAIL=str(int(record_fails)),
                       GRANT_RECORD_FAIL=str(int(grant_record_fails)))
            result = subprocess.run(["bash", "-c", script], cwd=root, env=env, capture_output=True, text=True, timeout=30)
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()] if (root / "calls").exists() else []
            record = json.loads((backend / "desks-grant.json").read_text())
            mode = (backend / "desks-grant.json").stat().st_mode & 0o777
            for name, value in inputs.items():
                self.assertEqual(json.loads((backend / name).read_text()), value)
            self.assertEqual(target.read_text(), "unchanged")
            self.assertFalse(list(backend.glob(".*.tmp")))
            self.assertFalse(any(c[:3] == ["gate", "grant", "revoke"] for c in calls))
            return result, calls, record, mode

    def test_retired_names_are_unlinked_before_update_including_links(self):
        for kind in ("files", "links", "dangling", "absent"):
            with self.subTest(kind=kind):
                result, calls, _, _ = self.run_step(retired=kind)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(["desk", "grant", "update", "--yes"], calls)
                lines = [line for line in result.stdout.splitlines() if "removed retired grant files:" in line]
                self.assertEqual(len(lines), 0 if kind == "absent" else 1)
                if lines:
                    self.assertTrue(all(name in lines[0] for name in cli.RETIRED_FILES))

    def test_cleanup_failure_stops_before_update(self):
        result, calls, record, _ = self.run_step(retired="directory")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("retired grant files could not be removed", result.stderr)
        self.assertFalse(any(call[:2] == ["desk", "grant"] for call in calls))
        self.assertEqual(record, {"old_record": True})

    def test_only_cleanup_names_the_retired_window_file_in_installer_tools(self):
        paths = [ROOT / "up.sh", *(ROOT / "tools").rglob("*.py"), *(ROOT / "tools").rglob("*.sh")]
        hits = [(path.relative_to(ROOT).as_posix(), line.strip()) for path in paths
                for line in path.read_text().splitlines() if "desks-grant.extras.json" in line]
        self.assertEqual(hits, [("tools/desk_grant_cli.py",
                               'RETIRED_FILES = ("desks-grant.extras.json", "discovery-policy.json", "discovery-composed.json")')])

    def test_missing_read_grant_is_added_then_update_and_show_confirm_the_record(self):
        result, calls, record, mode = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        add = ["gate", "grant", "add", "--agent", "desks", "--type", "api", "--instance", GATE,
               "--resource", "apis/desks", "--capability", "api.read", "--ttl", "31536000", "--no-fingerprint"]
        self.assertIn(add, calls)
        self.assertLess(calls.index(["plans", "read", "write"]), calls.index(add))
        self.assertEqual(calls[-2:], [["desk", "grant", "update", "--yes"], ["desk", "grant", "show", "--json"]])
        self.assertEqual(record, LIMITS)
        self.assertEqual(mode, 0o644)

    def test_an_active_matching_read_grant_skips_only_the_bootstrap(self):
        result, calls, record, _ = self.run_step(rows=[READ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c[:3] == ["gate", "grant", "add"] for c in calls))
        self.assertIn(["desk", "grant", "update", "--yes"], calls)
        self.assertEqual(record, LIMITS)

    def test_inactive_and_other_scopes_do_not_satisfy_read_access(self):
        for row in ({**READ, "is_active": False}, {**READ, "agent_id": "other-agent"},
                    *({**READ, "scope": {**READ["scope"], key: value}} for key, value in
                      (("instance_id", "enclaveb0000002Api"), ("resource_name", "apis/other"), ("capability", "api.write")))):
            with self.subTest(row=row):
                result, calls, _, _ = self.run_step(rows=[row])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(sum(c[:3] == ["gate", "grant", "add"] for c in calls), 1)

    def test_cli_failure_stops_even_when_it_printed_success_or_valid_json(self):
        for failed in ("gate grant list", "gate grant add", "desk grant update", "desk grant show"):
            with self.subTest(failed=failed):
                result, calls, record, _ = self.run_step(fail=failed)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("CLI refused the requested operation", result.stderr)
                self.assertEqual(record, {"old_record": True})
                self.assertTrue(" ".join(calls[-1]).startswith(failed), calls)
                if failed == "desk grant update":
                    self.assertIn("no grant was removed by the installer", result.stderr)
                if failed == "desk grant show":
                    self.assertIn("grant is in place but its record could not be confirmed", result.stderr)

    def test_invalid_list_never_authorizes_a_bootstrap_or_update(self):
        for text in ('{}', 'null', '[{}]', '[]\n[]', '[{"agent_id":"example-agent","is_active":"true"}]'):
            with self.subTest(text=text):
                result, calls, record, _ = self.run_step(list_text=text)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls[-1], ["gate", "grant", "list", "--json"])
                self.assertEqual(record, {"old_record": True})

    def test_only_keep_with_full_limits_can_replace_the_record(self):
        invalid = [None, [], {}, {"preview": []}]
        invalid += [{"grants": ANSWER["grants"], "preview": {"decision": {"action": action}, "proposed": LIMITS}}
                    for action in ("add", "replace", "refuse", "keep")]
        for proposed in ({}, {"follow": {"grant": "org_desks"}, "requires_role": "admin"},
                         {**LIMITS, "providers": "github"}, {**LIMITS, "policy_baseline": []},
                         {**LIMITS, "image_digests": ["$(touch /tmp/never-execute)"]},
                         {**LIMITS, "unexpected": "private-value"}):
            invalid.append({"grants": ANSWER["grants"], "preview": {"decision": ANSWER["preview"]["decision"], "proposed": proposed}})
        for answer in invalid:
            if answer is None:  # run_step's default is the valid response
                answer = {"preview": None}
            with self.subTest(answer=answer):
                result, _, record, _ = self.run_step(answer=answer)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(record, {"old_record": True})
                self.assertNotIn("private-value", result.stderr)

    def test_show_for_another_agent_or_gate_cannot_replace_the_record(self):
        for key in ("agent", "gate", "status"):
            answer = {**ANSWER, "grants": {**ANSWER["grants"], key: "other"}}
            result, _, record, _ = self.run_step(answer=answer)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(record, {"old_record": True})

    def test_a_failed_record_write_after_update_reports_the_grant_is_in_place(self):
        result, calls, record, _ = self.run_step(grant_record_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls[-1], ["desk", "grant", "show", "--json"])
        self.assertEqual(record, {"old_record": True})
        self.assertIn("grant is in place but its record could not be confirmed", result.stderr)

    def test_custom_agent_is_refused_before_bootstrapping_the_wrong_agent(self):
        result, calls, record, _ = self.run_step(agent="other-agent")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires DESKS_AGENT=desks", result.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(record, {"old_record": True})

    def test_failed_identity_reads_cannot_be_hidden_by_valid_output(self):
        for failed in ("enclave status", "agent list", "gate list"):
            result, calls, record, _ = self.run_step(fail=failed)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(" ".join(calls[-1]).startswith(failed))
            self.assertEqual(record, {"old_record": True})

    def test_plan_or_record_failure_stops_before_any_grant_call(self):
        for args in ({"plan_fails": True}, {"record_fails": True}):
            result, calls, record, _ = self.run_step(**args)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(any(c[:2] in (["gate", "grant"], ["desk", "grant"]) for c in calls))
            self.assertEqual(record, {"old_record": True})

    def test_only_the_cli_builds_writes_and_revokes_write_grants(self):
        source = (ROOT / "up.sh").read_text()
        commands = source.replace("\\\n", " ")
        for line in commands.splitlines():
            if "gate grant add" in line:
                self.assertNotIn("--constraint", line)
                self.assertNotIn("--capability api.write", line)
        self.assertNotIn("gate grant revoke", function("step_desk_grant"))
        self.assertNotIn("desk_provider_args", source)
        self.assertNotRegex(source, r"desk_grant\.py (limits|decide)")


class CliRecord(unittest.TestCase):
    def test_cleanup_refuses_untrusted_parent_folders(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = root / "backend"
            backend.mkdir()
            record = backend / cli.RETIRED_FILES[0]
            record.write_text("untouched")
            link = root / "link"
            link.symlink_to(backend, target_is_directory=True)
            for folder, owner, mode in ((link, os.getuid(), 0o755), (backend, os.getuid(), 0o777),
                                        (backend, os.getuid() + 1, 0o755)):
                backend.chmod(mode)
                with self.assertRaises(desk_records.Refused):
                    cli.remove_retired(folder, top=root, owner=owner)
                self.assertEqual(record.read_text(), "untouched")
            backend.chmod(0o755)
            self.assertEqual(cli.remove_retired(backend, top=root, owner=os.getuid()), [record.name])
            self.assertEqual(cli.remove_retired(backend, top=root, owner=os.getuid()), [])

    def test_rejects_duplicate_json_keys_non_json_numbers_and_trailing_output(self):
        for text in ('{"preview":{},"preview":{}}', 'NaN', '{} trailing', '[] []'):
            with self.assertRaises(cli.Refused):
                cli.read_json(io.StringIO(text))

    def test_confirmed_record_replaces_atomically_with_owner_and_mode_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "desks-grant.json"
            data = cli.confirmed_limits(ANSWER, AGENT, GATE)
            desk_records.write(path, data, top=directory, owner=os.getuid())
            self.assertEqual(path.stat().st_uid, os.getuid())
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(json.loads(path.read_bytes()), LIMITS)
            target = Path(directory) / "target"
            target.write_text("untouched")
            path.unlink()
            path.symlink_to(target)
            with self.assertRaises(desk_records.Refused):
                desk_records.write(path, data, top=directory, owner=os.getuid())
            self.assertEqual(target.read_text(), "untouched")
