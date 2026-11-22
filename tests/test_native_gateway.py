"""Emergency recovery never leaves a failed temporary-client cleanup implicit."""
from pathlib import Path
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


class GatewayHost(Host):
    def __init__(self):
        super().__init__()
        self.processes = []
        self.fail = None
        self.enabled = False
        self.ignore_disable = False

    def run(self, args, allowed=(0,), stdin=None, timeout=90, environment=None):
        self.processes.append((args, environment))
        step = args[-1] if "setup-client" in args else (
            "login" if "login" in args else "add" if "add" in args else "stop")
        if step == "on":
            self.enabled = True  # It may fail AFTER enabling the identity.
        if self.fail == step:
            raise HostError("planted command failure")
        if self.fail == "interrupt" and step == "stop":
            raise KeyboardInterrupt()
        if step == "off" and not self.ignore_disable:
            self.enabled = False
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
        self.assertEqual(args, ["/installed/openshell", "-g", "ekka-agent-desks", "sandbox", "stop", "code-desk"])
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
                self.assertEqual(list(self.state.iterdir()), [])

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
        for client, expected in ((None, "disabled"), ({"enabled": False}, "disabled"),
                                 ({"enabled": True}, "enabled")):
            code, output = realm_run(["setup-client", "status"], Keycloak(client))
            self.assertEqual((code, output.strip()), (0, expected))
        for client in ({}, {"enabled": "false"}, {"enabled": 0}):
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


if __name__ == "__main__":
    unittest.main()
