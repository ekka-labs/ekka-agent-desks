"""Native host recovery exercises the existing procedure with the Docker fake."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import desks_settle as procedure
from ekka_host.cli import main
from ekka_host.runtime import HostError
from ekka_host.settlement import environment, recover, root_file
from test_desks_settle import Clock, FakeDocker, OP
from test_native_host import Host


def procedure_reader(args):
    return getattr(procedure, "LOCK_READER", None) in args


class RecoveryHost(Host):
    def __init__(self):
        super().__init__()
        self.docker = FakeDocker([[]])
        self.restart_failure = False
        self.lock_failure = False
        self.lock = "admin:" + OP

    def run(self, args, allowed=(0,), stdin=None, timeout=90):
        self.calls.append(tuple(args))
        if args[0] == "/usr/bin/docker":
            if args[1] == "restart":
                rc, out = (1 if self.restart_failure else 0), ""
            else:
                rc, out = self.docker(args[1:], stdin)
        elif "/usr/bin/cat" in args or procedure_reader(args):
            self.asserted_reader = args
            rc, out = (1, "") if self.lock_failure else (0, self.lock)
        elif "/usr/local/bin/ekka" in args:
            rc, out = 0, "code-desk /var/lib/ekka/.ekka/desks/code-desk"
        else:
            raise AssertionError(args)
        return subprocess.CompletedProcess(args, rc, out, "")


class NativeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.state = Path(self.folder.name)
        (self.state / "backend").mkdir()
        (self.state / "backend/config.json").write_text(json.dumps({"backend_gateway": {
            "url": "https://host.openshell.internal:8080", "workspace": "desks"}}))
        (self.state / "gateway.toml").write_text("")
        self.clock = Clock()
        self.original_settle = procedure.settle
        self.host = RecoveryHost()

    def invoke(self, verb="settle"):
        def settle(*args, **kwargs):
            return self.original_settle(*args, clock=self.clock, sleep=self.clock.sleep, **kwargs)
        with patch("ekka_host.settlement.STATE", self.state), \
             patch("ekka_host.settlement.environment", return_value="prod"), \
             patch("ekka_host.settlement.root_file", side_effect=lambda p: Path(p).read_text()), \
             patch("desks_settle.settle", side_effect=settle), \
             patch.dict(os.environ, {"DESKS_STATE":"/wrong-state", "EKKA_ENV":"wrong-env"}), \
             contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as errors:
            result = main([verb, "code-desk", "--operation", OP], runtime=self.host, uid=0)
        self.errors = errors.getvalue()
        self.output = output.getvalue()
        return result

    def test_settle_writes_the_marker_and_reads_locks_as_the_enclave_user(self):
        self.assertEqual(self.invoke(), 0)
        self.assertIn(OP + ".json", self.host.docker.files)
        self.assertNotIn(OP + ".hold", self.host.docker.files)
        reader = self.host.asserted_reader
        self.assertEqual(reader[:4], ["/usr/sbin/runuser", "-u", "ekka", "--"])
        self.assertIn("EKKA_ENV=prod", reader)
        self.assertNotIn("EKKA_ENV=wrong-env", reader)
        self.assertEqual(self.host.records[0][1], "requested")
        self.assertEqual(self.host.records[-1][1], "procedure_completed")
        self.assertIn("confirm the outcome", self.host.lines[-1])

    def test_failed_restart_keeps_the_hold_and_never_claims_completion(self):
        self.host.restart_failure = True
        self.assertEqual(self.invoke(), 1)
        self.assertIn(OP + ".hold", self.host.docker.files)
        self.assertNotIn(OP + ".json", self.host.docker.files)
        self.assertIn("ekka-desk-host unhold", self.errors)
        self.assertNotIn("up.sh", self.errors)
        self.assertEqual(self.host.records[-1][1], "not_verified")
        self.assertFalse(any("procedure completed" in line for line in self.host.lines))

    def test_an_unreadable_lock_is_refused_before_a_hold_or_restart(self):
        self.host.lock_failure = True
        self.assertEqual(self.invoke(), 1)
        self.assertFalse(self.host.docker.calls)
        self.assertEqual(self.host.records[-1][1], "not_verified")

    def test_unhold_removes_only_the_named_hold_without_restart(self):
        self.host.docker.files = {OP + ".hold":"held", "other.hold":"keep"}
        self.assertEqual(self.invoke("unhold"), 0)
        self.assertEqual(self.host.docker.files, {"other.hold":"keep"})
        self.assertFalse(any(c[:2] == ("/usr/bin/docker", "restart") for c in self.host.calls))

    def test_no_mutation_if_audit_fails_or_input_is_invalid(self):
        self.host.fail_audit = True
        with self.assertRaises(HostError):
            recover(self.host, "settle", "../escape", OP)
        self.assertEqual(self.host.calls, [])
        with self.assertRaises(OSError), patch("ekka_host.settlement.environment", return_value="prod"), \
             patch("ekka_host.settlement.root_file", return_value=""):
            recover(self.host, "settle", "code-desk", OP)
        self.assertFalse(any(c[0].startswith("/usr/") for c in self.host.calls))

    def test_no_docker_change_when_the_initial_audit_is_unavailable(self):
        self.host.fail_audit = True
        self.assertEqual(self.invoke(), 1)
        self.assertFalse(self.host.docker.calls)
        self.assertFalse(any(c[:2] == ("/usr/bin/docker", "restart") for c in self.host.calls))

    def test_root_settings_reject_links_and_writable_ancestors(self):
        target = self.state / "settings"
        target.write_text("EKKA_ENV=prod")
        link = self.state / "linked-settings"
        link.symlink_to(target)
        for path in (target, link):
            with self.assertRaises(HostError):
                root_file(path)

    def test_environment_is_one_explicit_setting_never_evaluated(self):
        for text in ("", "EKKA_ENV=prod\nEKKA_ENV=dev", "EKKA_ENV=$(touch /tmp/unwanted)"):
            with patch("ekka_host.settlement.root_file", return_value=text):
                with self.assertRaises(HostError):
                    environment()
        with patch("ekka_host.settlement.root_file", return_value="EKKA_ENV=prod\n"):
            self.assertEqual(environment(), "prod")


class RealLockReader(RecoveryHost):
    """The lock read runs for real, as this user, with the Enclave-user prefix taken off: the reader the code
    chose (cat on the unfixed code, the bounded reader after) meets a real file, link or absence."""

    def __init__(self, desks):
        super().__init__()
        self.desks = str(desks)       # stands in for the Enclave's /var/lib/ekka/.ekka/desks

    def run(self, args, allowed=(0,), stdin=None, timeout=90):
        if "LANG=C.UTF-8" in args and "/usr/local/bin/ekka" not in args:
            command = list(args[args.index("LANG=C.UTF-8") + 1:])
            command[0] = {"/usr/bin/python3": sys.executable}.get(command[0], shutil.which(os.path.basename(command[0])))
            command[-1] = command[-1].replace("/var/lib/ekka/.ekka/desks", self.desks, 1)
            self.calls.append(tuple(args))
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode not in allowed:
                raise HostError("command failed with exit code " + str(result.returncode))
            return result
        return super().run(args, allowed, stdin, timeout)


class RecoveryReviewFixes(unittest.TestCase):
    """Unhold is bound to its desk, a lock is read safely, a missing lock is no lock, and the restart's reach."""
    setUp = NativeRecoveryTests.setUp   # the same fixture, without running NativeRecoveryTests's cases again
    invoke = NativeRecoveryTests.invoke   # the same fixture, without running NativeRecoveryTests's cases again

    def invoke_with_lock(self, verb="settle", place=None):
        lock = self.state / "desks" / ".state" / "code-desk.lock"
        lock.parent.mkdir(parents=True)
        if place is not None:
            place(lock)
        host = RealLockReader(self.state / "desks")
        host.docker = self.host.docker
        self.host = host
        return self.invoke(verb)

    def test_unhold_never_releases_another_desks_change(self):
        other = "9d4c2b1a-8e7f-4a6b-9c5d-3e2f1a0b9c8d"
        self.host.lock = "admin:" + other          # code-desk is held by a different change
        self.host.docker.files = {OP + ".hold": "held"}
        self.assertEqual(self.invoke("unhold"), 1)
        self.assertEqual(self.host.docker.files, {OP + ".hold": "held"}, "another desk's hold was released")

    def test_a_lock_that_is_a_link_is_never_followed_or_printed(self):
        secret = self.state / "credential"
        secret.write_text("TOKEN=planted-credential-value\n")
        self.assertEqual(self.invoke_with_lock(place=lambda lock: lock.symlink_to(secret)), 1)
        self.assertNotIn("planted-credential-value", self.output + self.errors + str(self.host.lines))
        self.assertFalse(self.host.docker.calls, "a hold or restart followed an unreadable lock")

    def test_an_oversized_lock_is_refused_not_read(self):
        self.assertEqual(self.invoke_with_lock(place=lambda lock: lock.write_text("a" * 1_000_000)), 1)
        self.assertNotIn("a" * 100, self.output + self.errors)

    def test_a_missing_lock_means_nothing_holds_the_desk(self):
        self.assertEqual(self.invoke_with_lock(place=None), 0, self.errors)
        self.assertIn("nothing holds it", self.output)
        self.assertFalse(self.host.docker.calls, "nothing to settle, yet a hold or restart happened")

    def test_settle_says_every_running_desk_stops(self):
        from ekka_host.cli import parser
        text = " ".join(parser()._subparsers._group_actions[0].choices["settle"].format_help().split()) + \
            " ".join(next(a.help for a in parser()._subparsers._group_actions[0]._choices_actions
                          if a.dest == "settle").split())
        self.assertIn("stops every running desk", text)
        root = Path(__file__).resolve().parents[1]
        for guide in ("docs/NATIVE-HOST.md", "docs/OPERATIONS.md"):
            self.assertIn("stops every running desk", " ".join((root / guide).read_text().split()), guide)

