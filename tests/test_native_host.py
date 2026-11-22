"""Exercise the native CLI's refusal and verified-service boundaries."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from ekka_host.cli import main
from ekka_host.runtime import ENCLAVE, STACK, HostError, Runtime, stack_change, status


class Host:
    def __init__(self):
        self.lines = []
        self.calls = []
        self.records = []
        self.ready = True
        self.socket = True
        self.states = {ENCLAVE: "active", STACK: "active"}
        self.masked = False
        self.loaded = True
        self.apply = True
        self.fail_audit = False

    def output(self, line):
        self.lines.append(line)

    def installed(self):
        return self.ready

    def socket_exists(self):
        return self.socket

    def service(self, unit):
        self.calls.append(("read", unit))
        return {"LoadState": "loaded" if self.loaded else "not-found",
                "ActiveState": self.states[unit], "SubState": "running",
                "UnitFileState": "masked" if self.masked else "enabled"}

    def audit(self, action, outcome):
        if self.fail_audit:
            raise OSError("log unavailable")
        self.records.append((action, outcome))

    def run(self, args):
        self.calls.append(tuple(args))
        if self.apply:
            self.states[STACK] = "active" if args[1] == "start" else "inactive"


class NativeHostTests(unittest.TestCase):
    def test_start_uses_only_system_service_and_verifies_it(self):
        host = Host()
        host.states[STACK] = "inactive"
        stack_change(host, "start")
        self.assertIn(("/usr/bin/systemctl", "start", STACK), host.calls)
        self.assertEqual(host.calls[-1], ("read", STACK))
        self.assertEqual(host.records, [("stack start", "requested"),
                                        ("stack start", "verified_active")])

    def test_stop_does_not_stop_the_enclave(self):
        host = Host()
        stack_change(host, "stop")
        self.assertEqual(host.states[ENCLAVE], "active")
        self.assertIn(("/usr/bin/systemctl", "stop", STACK), host.calls)
        self.assertEqual(host.records[-1], ("stack stop", "verified_inactive"))

    def test_start_preserves_mask_and_missing_interceptor(self):
        for condition in ("mask", "socket", "enclave", "installation", "unit"):
            with self.subTest(condition=condition):
                host = Host()
                if condition == "mask": host.masked = True
                if condition == "socket": host.socket = False
                if condition == "enclave": host.states[ENCLAVE] = "inactive"
                if condition == "installation": host.ready = False
                if condition == "unit": host.loaded = False
                with self.assertRaises(HostError):
                    stack_change(host, "start")
                self.assertFalse(any(call[0] == "/usr/bin/systemctl" for call in host.calls))
                self.assertEqual(host.records, [])

    def test_successful_command_with_unchanged_state_is_not_success(self):
        host = Host()
        host.apply = False
        with self.assertRaisesRegex(HostError, "did not reach inactive"):
            stack_change(host, "stop")
        self.assertEqual(host.records[-1], ("stack stop", "not_verified"))
        self.assertNotIn("desks stack: inactive", host.lines)

    def test_no_action_when_audit_cannot_be_written(self):
        host = Host()
        host.fail_audit = True
        with self.assertRaises(OSError):
            stack_change(host, "stop")
        self.assertFalse(any(call[0] == "/usr/bin/systemctl" for call in host.calls))

    def test_status_requires_both_loaded_services_and_real_socket(self):
        for condition in ("ready", "socket", "stack", "enclave", "unit", "installation"):
            with self.subTest(condition=condition):
                host = Host()
                if condition == "socket": host.socket = False
                if condition in ("stack", "enclave"):
                    host.states[STACK if condition == "stack" else ENCLAVE] = "inactive"
                if condition == "unit": host.loaded = False
                if condition == "installation": host.ready = False
                if condition == "ready":
                    status(host)
                else:
                    with self.assertRaises(HostError): status(host)
                self.assertEqual(host.records, [])

    def test_non_root_and_desk_actions_never_touch_host(self):
        host = Host()
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(main(["stack", "stop"], runtime=host, uid=1000), 1)
            self.assertEqual(main(["connect", "github"], runtime=host, uid=0), 2)
        self.assertIn("ekka desk connect", errors.getvalue())
        self.assertEqual(host.calls, [])

    def test_process_environment_is_clean_and_no_shell_is_used(self):
        runtime = Runtime(output=lambda _: None)
        with patch.dict(os.environ, {"SYSTEMD_HOST": "unwanted-host", "SECRET": "do-not-inherit"}):
            with patch("ekka_host.runtime.subprocess.run") as call:
                call.return_value = subprocess.CompletedProcess([], 0, "active", "")
                self.assertEqual(runtime.run(["/usr/bin/systemctl", "is-active", STACK]), "active")
                self.assertNotIn("SYSTEMD_HOST", call.call_args.kwargs["env"])
                self.assertNotIn("SECRET", call.call_args.kwargs["env"])
                self.assertNotIn("shell", call.call_args.kwargs)

    def test_incomplete_service_read_is_refused(self):
        with patch("ekka_host.runtime.subprocess.run") as call:
            call.return_value = subprocess.CompletedProcess([], 0, "ActiveState=active", "")
            with self.assertRaises(HostError): Runtime(output=lambda _: None).service(STACK)

    def test_symlink_cannot_redirect_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "target"
            target.write_text("unchanged")
            link = Path(folder) / "audit"
            link.symlink_to(target)
            with patch("ekka_host.runtime.AUDIT", link):
                with self.assertRaises(OSError): Runtime().audit("stack stop", "requested")
            self.assertEqual(target.read_text(), "unchanged")

    def test_socket_check_refuses_regular_files_and_links(self):
        with tempfile.TemporaryDirectory() as folder:
            regular = Path(folder) / "socket"
            regular.touch()
            link = Path(folder) / "link"
            link.symlink_to(regular)
            for path in (regular, link, Path(folder) / "missing"):
                with patch("ekka_host.runtime.SOCKET", path):
                    self.assertFalse(Runtime().socket_exists())

    def test_entry_point_has_help_without_privilege(self):
        command = Path(__file__).resolve().parents[1] / "ekka-desk-host"
        result = subprocess.run([sys.executable, str(command), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("not implemented yet", " ".join(result.stdout.split()))
        self.assertIn("stack", result.stdout)


if __name__ == "__main__":
    unittest.main()
