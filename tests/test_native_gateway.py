"""Emergency recovery never leaves a failed temporary-client cleanup implicit."""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from ekka_host import gateway
from ekka_host.cli import main
from ekka_host.runtime import HostError, Runtime
from test_native_host import Host
from test_desk_admin_client import run as realm_run

SECRET = "PLANTED_TEMPORARY_SETUP_SECRET"


def registration(env):
    """Where NVIDIA's CLI 0.1.9 keeps a user registration: $XDG_CONFIG_HOME, else $HOME/.config (core paths.rs)."""
    config = env.get("XDG_CONFIG_HOME") or os.path.join(env["HOME"], ".config")
    return Path(config, "openshell", "gateways", "ekka-agent-desks", "metadata.json")


class GatewayHost(Host):
    """Keycloak's setup client and NVIDIA's CLI, as they behave: `gateway add` keeps the registration it was given
    (or, when its sign-in fails, removes it and still exits 0), `gateway login` reads the user registration and falls
    back to the system folder, /etc/openshell unless OPENSHELL_SYSTEM_GATEWAY_DIR names another (bootstrap
    metadata.rs and paths.rs), and `sandbox stop` stops the desk in --workspace, else OPENSHELL_WORKSPACE, else
    "default" (cli main.rs)."""

    def __init__(self, etc=None):
        super().__init__()
        self.processes = []
        self.fail = None
        self.enabled = False
        self.ignore_disable = False
        self.add_rolls_back = False
        self.etc = etc               # stands in for /etc/openshell
        self.signed_in_at = []       # the issuer each `login` sent the secret to
        self.stopped = []            # (workspace, desk)
        self.quiet = []              # the step of every call made with quiet=True
        self.on_step = {}            # step -> callable, run before the step's effect
        self.kept = []               # the fds each child was given

    def run(self, args, allowed=(0,), stdin=None, timeout=90, environment=None, quiet=False, keep_fds=()):
        self.processes.append((args, environment))
        self.kept.append(tuple(keep_fds))
        step = args[-1] if "setup-client" in args else (
            "login" if "login" in args else "add" if "add" in args else "stop")
        if quiet:
            self.quiet.append(step)
        if step in self.on_step:
            self.on_step[step]()
        if step == "on":
            self.enabled = True  # It may fail AFTER enabling the identity.
        if self.fail == step:
            raise HostError("planted command failure")
        if self.fail == "interrupt" and step == "stop":
            raise KeyboardInterrupt()
        if step == "off" and not self.ignore_disable:
            self.enabled = False
        env = environment or {}
        if step == "add" and not self.add_rolls_back:
            path = registration(env)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"name": "ekka-agent-desks", "gateway_endpoint": args[3], "auth_mode": "oidc",
                                        "oidc_issuer": args[args.index("--oidc-issuer") + 1],
                                        "oidc_client_id": args[args.index("--oidc-client-id") + 1]}))
        if step == "login":
            system = env.get("OPENSHELL_SYSTEM_GATEWAY_DIR") or self.etc
            found = [p for p in (registration(env),
                                 Path(system, "gateways", "ekka-agent-desks", "metadata.json") if system else None)
                     if p is not None and p.exists()]
            if not found:
                raise HostError("no such gateway")
            self.signed_in_at.append(json.loads(found[0].read_text())["oidc_issuer"])
        if step == "stop":
            workspace = args[args.index("--workspace") + 1] if "--workspace" in args else \
                env.get("OPENSHELL_WORKSPACE", "default")
            self.stopped.append((workspace, args[-1]))
        out = SECRET if step == "on" else ("enabled" if self.enabled else "disabled") if step == "status" else ""
        return subprocess.CompletedProcess(args, 0, out, "")


class NativeGatewayTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.state = Path(self.folder.name)
        self.host = GatewayHost()
        replacement = patch("ekka_host.gateway.STATE", self.state)
        replacement.start()
        self.addCleanup(replacement.stop)

    def run_stop(self):
        gateway._run(self.host, ["sandbox", "stop", "code-desk"], "gateway.example",
                     Path("/installed/openshell"), Path("/installed/apply_realm.py"))

    def test_stop_is_fixed_to_this_gateway_and_leaves_no_temporary_sign_in(self):
        self.run_stop()
        self.assertFalse(self.host.enabled)
        self.assertEqual(list(self.state.iterdir()), [])
        args, env = self.host.processes[-3]
        self.assertEqual(args, ["/installed/openshell", "-g", "ekka-agent-desks", "--workspace", "desks",
                                "sandbox", "stop", "code-desk"])
        self.assertEqual(env["OPENSHELL_OIDC_CLIENT_SECRET"], SECRET)
        self.assertFalse(Path(env["HOME"]).exists())
        self.assertNotIn(SECRET, str([p[0] for p in self.host.processes]) + str(self.host.lines) + str(self.host.records))
        self.assertEqual(self.host.records[-1], ("emergency-stop code-desk", "command_completed_admin_disabled"))
        self.assertEqual(self.host.processes[-1][0][-1], "status")

    def test_every_failure_still_disables_and_checks_the_setup_client(self):
        for step in ("on", "add", "login", "stop"):
            with self.subTest(step=step):
                host = GatewayHost()
                host.fail = step
                self.host = host
                with self.assertRaisesRegex(HostError, "inspect before retrying"):
                    self.run_stop()
                self.assertFalse(host.enabled)
                self.assertEqual([p[0][-1] for p in host.processes[-2:]], ["off", "status"])
                self.assertEqual(host.records[-1][1], "not_verified_admin_disabled")
                self.assertEqual(list(self.state.iterdir()), [])

    def test_interrupt_cleans_up_before_propagating(self):
        self.host.fail = "interrupt"
        with self.assertRaises(KeyboardInterrupt):
            self.run_stop()
        self.assertFalse(self.host.enabled)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_failed_or_unapplied_disable_never_reports_completion(self):
        for mode in ("off", "status", "unchanged"):
            with self.subTest(mode=mode):
                self.host = GatewayHost()
                self.host.fail = mode
                self.host.ignore_disable = mode == "unchanged"
                with self.assertRaisesRegex(HostError, "may still be enabled"):
                    self.run_stop()
                self.assertEqual(self.host.records[-1][1], "temporary_admin_disable_not_verified")
                self.assertEqual(self.host.lines, [])
                # The marker stays: the next session switches the client off before anything else.
                self.assertEqual([p.name for p in self.state.iterdir()], ["gateway-admin.pending"])
                (self.state / "gateway-admin.pending").unlink()

    def test_initial_audit_failure_does_not_enable_anything(self):
        self.host.fail_audit = True
        with self.assertRaises(OSError):
            self.run_stop()
        self.assertEqual(self.host.processes, [])

    def test_arbitrary_vendor_changes_and_unnamed_stop_are_refused_before_io(self):
        for args in (["sandbox", "stop"], ["sandbox", "stop", "--gateway=elsewhere"],
                     ["sandbox", "create", "code-desk"], ["provider", "delete", "key"], ["status"]):
            with self.subTest(args=args), self.assertRaises(HostError):
                gateway.validate(self.host, args)
        self.assertEqual(self.host.calls, [])
        self.assertEqual(self.host.processes, [])

    def test_native_cli_only_passes_the_one_named_desk(self):
        with patch("ekka_host.cli.emergency_stop") as call:
            self.assertEqual(main(["emergency-stop", "code-desk"], runtime=self.host, uid=0), 0)
        call.assert_called_once_with(self.host, "code-desk")

    def test_explicit_child_environment_is_not_printed_or_inherited(self):
        runtime = Runtime(output=self.host.output)
        with patch.dict("os.environ", {"OPENSHELL_GATEWAY": "elsewhere", "HTTP_PROXY": "elsewhere"}):
            with patch("ekka_host.runtime.subprocess.run") as call:
                call.return_value = subprocess.CompletedProcess([], 0, "", "")
                runtime.run(["/installed/openshell", "status"], environment={"OPENSHELL_OIDC_CLIENT_SECRET": SECRET})
                env = call.call_args.kwargs["env"]
        self.assertEqual(env["OPENSHELL_OIDC_CLIENT_SECRET"], SECRET)
        self.assertNotIn("OPENSHELL_GATEWAY", env)
        self.assertNotIn("HTTP_PROXY", env)
        self.assertNotIn(SECRET, str(self.host.lines))

    def test_setup_client_status_reads_without_changing_or_printing_a_secret(self):
        class Keycloak:
            def __init__(self, client):
                self.client = client
            def get(self, path):
                if not path.endswith("/clients?clientId=desks-setup"):
                    raise AssertionError("status read outside the named client")
                return [] if self.client is None else [self.client]
            def write(self, *args):
                raise AssertionError("status must not write")
        record = {"id": "c0ffee", "clientId": "desks-setup"}
        for client, expected in ((None, "disabled"), ({**record, "enabled": False}, "disabled"),
                                 ({**record, "enabled": True}, "enabled")):
            code, output = realm_run(["setup-client", "status"], Keycloak(client))
            self.assertEqual((code, output.strip()), (0, expected))
        for client in ({}, {**record, "enabled": "false"}, {**record, "enabled": 0}):
            with self.assertRaises(SystemExit):
                realm_run(["setup-client", "status"], Keycloak(client))

    def test_version_mismatch_refuses_before_administrator_access(self):
        def settings(path, **kwargs):
            if str(path).endswith("desks.env"):
                return "DESKS_NAME=gateway.example\n"
            return '{"openshell":{"version":"0.1.4"}}' if str(path).endswith("pins.json") else "trusted"
        with patch("ekka_host.gateway.root_directory"), patch("ekka_host.gateway.root_file", side_effect=settings):
            with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)):
                with self.assertRaisesRegex(HostError, "version pin"):
                    gateway.validate(self.host, ["sandbox", "stop", "code-desk"])
        self.assertEqual(len(self.host.processes), 1)
        self.assertEqual(self.host.processes[0][0][-1], "--version")
        self.assertFalse(self.host.enabled)

    def test_lock_refuses_a_link_before_enabling_the_client(self):
        target = self.state / "elsewhere"
        target.write_text("unchanged")
        (self.state / "gateway-admin.lock").symlink_to(target)
        with patch("ekka_host.gateway.validate", return_value=("gateway.example", Path("/installed/openshell"), Path("/installed/apply_realm.py"))):
            with self.assertRaises(OSError):
                gateway.emergency_stop(self.host, "code-desk")
        self.assertEqual(self.host.processes, [])
        self.assertEqual(target.read_text(), "unchanged")



class KeycloakAnswers:
    """The client list as Keycloak's admin API might answer it, including answers that are not one exact record."""

    def __init__(self, answer):
        self.answer = answer
        self.writes = []

    def get(self, path):
        return self.answer

    def write(self, *args):
        self.writes.append(args)


class NamedStopTargetsTheDesksWorkspace(unittest.TestCase):
    """The stop must reach desks/<desk>, never default/<desk>."""

    def test_named_stop_reaches_the_desks_workspace_only(self):
        with tempfile.TemporaryDirectory() as folder, patch("ekka_host.gateway.STATE", Path(folder)):
            host = GatewayHost()
            gateway._run(host, ["sandbox", "stop", "code-desk"], "gateway.example",
                         Path("/installed/openshell"), Path("/installed/apply_realm.py"))
        self.assertEqual(host.stopped, [("desks", "code-desk")])


class TheSecretReachesOnlyThisGatewaysIssuer(unittest.TestCase):
    """A `gateway add` whose sign-in fails removes its registration and exits 0; `login` must not then
    fall back to another registration of the same name and send the setup secret to its issuer."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.state = Path(self.folder.name, "state")
        self.state.mkdir()
        etc = Path(self.folder.name, "etc-openshell")
        old = etc / "gateways" / "ekka-agent-desks" / "metadata.json"
        old.parent.mkdir(parents=True)
        old.write_text(json.dumps({"gateway_endpoint": "https://elsewhere.example:8080", "auth_mode": "oidc",
                                   "oidc_issuer": "https://elsewhere.example/realms/other",
                                   "oidc_client_id": "desks-setup"}))
        self.host = GatewayHost(etc=str(etc))

    def run_stop(self):
        with patch("ekka_host.gateway.STATE", self.state):
            gateway._run(self.host, ["sandbox", "stop", "code-desk"], "gateway.example",
                         Path("/installed/openshell"), Path("/installed/apply_realm.py"))

    def test_a_rolled_back_registration_never_signs_in_elsewhere(self):
        self.host.add_rolls_back = True
        with self.assertRaisesRegex(HostError, "inspect before retrying"):
            self.run_stop()
        self.assertEqual(self.host.signed_in_at, [], "the setup secret was sent to another issuer")
        self.assertFalse(self.host.enabled)
        self.assertEqual(self.host.stopped, [])

    def test_the_kept_registration_is_this_gateway(self):
        self.run_stop()
        self.assertEqual(self.host.signed_in_at, ["https://gateway.example/realms/ekka-desks"])


class CleanupSurvivesSignalsAndAClosedConsole(unittest.TestCase):
    """SIGTERM, Ctrl-C during the disable, a closed console, and an abrupt death."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.state = Path(self.folder.name)
        replacement = patch("ekka_host.gateway.STATE", self.state)
        replacement.start()
        self.addCleanup(replacement.stop)
        self.installed = patch("ekka_host.gateway.validate", return_value=(
            "gateway.example", Path("/installed/openshell"), Path("/installed/apply_realm.py")))

    def test_sigterm_during_the_stop_still_disables_the_client_and_removes_the_sign_in(self):
        # In a child process: on the unfixed code SIGTERM simply ends the process.
        child = """
import json, os, signal, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[2])
from ekka_host import gateway
from test_native_gateway import GatewayHost
state = Path(sys.argv[3])
host = GatewayHost()
host.on_step["stop"] = lambda: os.kill(os.getpid(), signal.SIGTERM)
def record():
    Path(sys.argv[4]).write_text(json.dumps({"enabled": host.enabled, "records": host.records}))
host.on_step["on"] = record
host.on_step["status"] = record
try:
    with patch("ekka_host.gateway.STATE", state), patch("ekka_host.gateway.validate", return_value=(
            "gateway.example", Path("/installed/openshell"), Path("/installed/apply_realm.py"))):
        gateway.emergency_stop(host, "code-desk")
except Exception as error:
    print(type(error).__name__, error)
record()
"""
        tests = Path(__file__).resolve().parent
        result_file = self.state.parent / (self.state.name + ".result")
        self.addCleanup(lambda: result_file.unlink(missing_ok=True))
        result = subprocess.run([sys.executable, "-c", child, str(tests.parent / "tools"), str(tests),
                                 str(self.state), str(result_file)], capture_output=True, text=True, timeout=60)
        outcome = json.loads(result_file.read_text())
        self.assertFalse(outcome["enabled"], "the setup client was left enabled: " + result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stopped by a signal", result.stdout)
        self.assertEqual([p.name for p in self.state.iterdir() if p.name != "gateway-admin.lock"], [],
                         "a sign-in or marker was left behind")

    def test_ctrl_c_during_the_disable_does_not_stop_it(self):
        host = GatewayHost()
        host.on_step["off"] = lambda: os.kill(os.getpid(), signal.SIGINT)
        previous = signal.signal(signal.SIGINT, signal.default_int_handler)   # Python's own Ctrl-C behavior
        try:
            with self.installed:
                gateway.emergency_stop(host, "code-desk")
        finally:
            signal.signal(signal.SIGINT, previous)
        self.assertFalse(host.enabled)
        self.assertEqual(host.records[-1], ("emergency-stop code-desk", "command_completed_admin_disabled"))

    def test_a_closed_console_does_not_stop_the_disable(self):
        state = {"enabled": False, "closed": False}

        def console(line):
            if state["closed"]:
                raise BrokenPipeError()

        def system(args, **kwargs):
            step = args[-1] if "setup-client" in args else (
                "login" if "login" in args else "add" if "add" in args else "stop")
            if step == "on":
                state["enabled"] = True
            if step == "off":
                state["enabled"] = False
            if step == "add":
                path = registration(kwargs["env"])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"gateway_endpoint": args[3], "auth_mode": "oidc",
                                            "oidc_issuer": args[args.index("--oidc-issuer") + 1],
                                            "oidc_client_id": "desks-setup"}))
            if step == "stop":
                state["closed"] = True      # the operator's terminal went away during the stop
            out = SECRET if step == "on" else ("enabled" if state["enabled"] else "disabled") if step == "status" else ""
            return subprocess.CompletedProcess(args, 0, out, "")

        runtime = Runtime(output=console)
        runtime.audit = lambda action, outcome: None
        with patch("ekka_host.runtime.subprocess.run", side_effect=system), self.assertRaises(BaseException):
            gateway._run(runtime, ["sandbox", "stop", "code-desk"], "gateway.example",
                         Path("/installed/openshell"), Path("/installed/apply_realm.py"))
        self.assertFalse(state["enabled"], "a closed console stopped the disable")

    def test_an_abruptly_ended_session_is_closed_before_the_next_one(self):
        left = self.state / ".gateway-admin-abc123"
        (left / "config").mkdir(parents=True)
        (left / "config" / "oidc_token.json").write_text("{}")
        info = left.lstat()
        (self.state / "gateway-admin.pending").write_text(json.dumps(
            {"home": str(left), "dev": info.st_dev, "ino": info.st_ino}))
        host = GatewayHost()
        host.enabled = True                  # the killed session never switched it off
        with self.installed:
            gateway.emergency_stop(host, "code-desk")
        steps = [p[0][-1] for p in host.processes]
        self.assertEqual(steps[:2], ["off", "status"], "the old session's client was not switched off first")
        self.assertFalse(left.exists(), "the old sign-in was left on disk")
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), ["gateway-admin.lock"])
        self.assertIn(("gateway-admin reconcile", "previous_session_closed"), host.records)

    def test_status_reports_an_unfinished_session(self):
        from ekka_host.runtime import status
        (self.state / "gateway-admin.pending").write_text("{}")
        lines = []
        host = Runtime(output=lines.append)
        host.installed = lambda: True
        host.socket_exists = lambda: True
        host.service = lambda unit: {"LoadState": "loaded", "ActiveState": "active", "SubState": "running"}
        with patch("ekka_host.runtime.STATE", self.state), self.assertRaises(HostError):
            status(host)
        self.assertTrue(any("did not finish" in line for line in lines))


class SessionRecoveryIsExact(unittest.TestCase):
    """Signals are noted, never raised; children hold the session lock; a marker names exactly one sign-in folder;
    an unwritable audit log never stops access being switched off; status tells a live session from a dead one."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.state = Path(self.folder.name)
        replacement = patch("ekka_host.gateway.STATE", self.state)
        replacement.start()
        self.addCleanup(replacement.stop)
        self.installed = patch("ekka_host.gateway.validate", return_value=(
            "gateway.example", Path("/installed/openshell"), Path("/installed/apply_realm.py")))

    def test_every_session_child_holds_the_session_lock(self):
        host = GatewayHost()
        with self.installed:
            gateway.emergency_stop(host, "code-desk")
        self.assertTrue(host.kept)
        self.assertTrue(all(len(k) == 1 for k in host.kept), "a session child ran without the lock: " + str(host.kept))
        self.assertEqual(len(set(host.kept)), 1)

    def test_the_runtime_hands_the_lock_to_the_child(self):
        with patch("ekka_host.runtime.subprocess.run") as call:
            call.return_value = subprocess.CompletedProcess([], 0, "", "")
            Runtime(output=lambda line: None).run(["/bin/true"], keep_fds=(7,))
        self.assertEqual(call.call_args.kwargs["pass_fds"], (7,))

    def test_a_signal_is_noted_and_the_session_stops_after_its_current_step(self):
        host = GatewayHost()
        host.on_step["add"] = lambda: os.kill(os.getpid(), signal.SIGINT)
        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        try:
            with self.installed, self.assertRaisesRegex(HostError, "stopped by a signal"):
                gateway.emergency_stop(host, "code-desk")
        finally:
            signal.signal(signal.SIGINT, previous)
        steps = [p[0][-1] if "setup-client" in p[0] else p[0][1] for p in host.processes]
        self.assertNotIn("login", steps, "the session went on after the signal")
        self.assertFalse(host.enabled)
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), ["gateway-admin.lock"])

    def test_an_unwritable_audit_log_never_stops_the_old_session_being_switched_off(self):
        (self.state / "gateway-admin.pending").write_text("{}")
        host = GatewayHost()
        host.enabled = True
        host.fail_audit = True
        with self.installed, self.assertRaisesRegex(HostError, "audit log"):
            gateway.emergency_stop(host, "code-desk")
        self.assertFalse(host.enabled, "access stayed on because the audit log could not be written")
        self.assertNotIn("on", [p[0][-1] for p in host.processes], "a new session started without its audit")

    def test_only_the_recorded_sign_in_folder_is_removed(self):
        recorded = self.state / ".gateway-admin-recorded"
        recorded.mkdir()
        info = recorded.lstat()
        (self.state / "gateway-admin.pending").write_text(json.dumps(
            {"home": str(recorded), "dev": info.st_dev, "ino": info.st_ino}))
        backup = self.state / ".gateway-admin-backup-of-something"
        backup.mkdir()
        (backup / "keep.txt").write_text("keep")
        (self.state / ".gateway-admin-note").write_text("a file with the prefix")
        host = GatewayHost()
        with self.installed:
            gateway.emergency_stop(host, "code-desk")
        self.assertFalse(recorded.exists())
        self.assertTrue((backup / "keep.txt").exists(), "an unrecorded folder was deleted")
        self.assertEqual(host.records[-1], ("emergency-stop code-desk", "command_completed_admin_disabled"))

    def test_status_does_not_call_a_live_session_abandoned(self):
        import fcntl
        from ekka_host.runtime import status
        (self.state / "gateway-admin.pending").write_text("{}")
        lines = []
        host = Runtime(output=lines.append)
        host.installed = lambda: True
        host.socket_exists = lambda: True
        host.service = lambda unit: {"LoadState": "loaded", "ActiveState": "active", "SubState": "running"}
        fd = os.open(self.state / "gateway-admin.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)             # an emergency stop is running now
            with patch("ekka_host.runtime.STATE", self.state):
                status(host)
        finally:
            os.close(fd)
        self.assertFalse(any("did not finish" in line for line in lines))


class TheSetupClientStateIsReadStrictly(unittest.TestCase):
    """An empty body, null, {} or anything but one exact desks-setup record is an unknown state."""

    def test_an_unreadable_answer_is_never_disabled(self):
        for answer in (None, {}, "", [{"id": "x", "clientId": "other", "enabled": False}],
                       [{"id": "x", "clientId": "desks-setup", "enabled": False}] * 2,
                       [{"clientId": "desks-setup", "enabled": False}]):
            for verb in ("status", "off"):
                with self.subTest(answer=answer, verb=verb):
                    keycloak = KeycloakAnswers(answer)
                    with self.assertRaises(SystemExit):
                        realm_run(["setup-client", verb], keycloak)
                    self.assertEqual(keycloak.writes, [])

    def test_an_answered_empty_list_is_disabled(self):
        self.assertEqual(realm_run(["setup-client", "status"], KeycloakAnswers([]))[1].strip(), "disabled")


if __name__ == "__main__":
    unittest.main()
