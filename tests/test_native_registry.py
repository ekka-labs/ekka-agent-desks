"""Native registry operations keep input off argv and preserve failed updates."""
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from ekka_host import registry
from ekka_host.runtime import HostError
from test_native_host import Host

TOKEN = "PLANTED_READ_CREDENTIAL"
CLASSIC = "ghp_" + "a" * 36


class RegistryHost(Host):
    def __init__(self):
        super().__init__()
        self.processes = []
        self.scope = "read:packages"
        self.login_fails = False

    def run(self, args, allowed=(0,), stdin=None, timeout=90):
        self.processes.append((args, stdin))
        if "login" in args and self.login_fails:
            raise HostError("registry refused the credential")
        out = "X-OAuth-Scopes: " + self.scope + "\r\n" if args[0] == "/usr/bin/curl" else ""
        return subprocess.CompletedProcess(args, 0, out, "")


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.state = Path(self.folder.name)
        (self.state / "secrets").mkdir()
        self.host = RegistryHost()
        for replacement in (
            patch("ekka_host.registry.STATE", self.state),
            patch("ekka_host.registry.root_directory", side_effect=lambda p: Path(p)),
            patch("ekka_host.files.root_directory", side_effect=lambda p: Path(p)),
            patch("ekka_host.registry.private_destination"),
            patch("ekka_host.files.private_destination"),
            patch("ekka_host.registry.root_file", side_effect=lambda p, **_: p.read_text()),
        ):
            replacement.start()
            self.addCleanup(replacement.stop)

    def login(self, host="registry.example", token=TOKEN):
        registry.login(self.host, host, "reader", lambda: token)

    def test_login_keeps_a_private_file_only_after_a_confirmed_login(self):
        self.login()
        path = self.state / "secrets/registry/registry.example.env"
        self.assertIn("REGISTRY_TOKEN=" + TOKEN, path.read_text())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        args, value = self.host.processes[0]
        self.assertIn("--password-stdin", args)
        self.assertNotIn(TOKEN, " ".join(args))
        self.assertEqual(value, TOKEN)
        self.assertEqual(self.host.records[-1][1], "credential_kept")
        self.assertEqual([p.name for p in (self.state / "secrets").iterdir()], ["registry"])
        self.assertFalse(any(TOKEN in line for line in self.host.lines))

    def test_github_checks_the_exact_read_scope_without_putting_the_token_on_argv(self):
        self.login("ghcr.io", CLASSIC)
        curl, value = self.host.processes[0]
        self.assertEqual(curl[:2], ["/usr/bin/curl", "-q"])
        self.assertEqual(curl[-1], "https://api.github.com/user")
        self.assertIn(CLASSIC, value)
        self.assertNotIn(CLASSIC, " ".join(curl))
        self.assertIn("login", self.host.processes[1][0])

    def test_a_wider_or_missing_github_scope_keeps_nothing(self):
        for scope in ("repo, read:packages", "", "write:packages"):
            self.host.scope = scope
            self.host.processes.clear()
            with self.assertRaises(HostError):
                self.login("ghcr.io", CLASSIC)
            self.assertEqual(len(self.host.processes), 1)
            self.assertEqual(list((self.state / "secrets").iterdir()), [])

    def test_a_failed_rotation_keeps_the_previous_file(self):
        self.login()
        path = self.state / "secrets/registry/registry.example.env"
        previous = path.read_bytes()
        self.host.login_fails = True
        with self.assertRaises(HostError):
            self.login(token="REPLACEMENT_READ_CREDENTIAL")
        self.assertEqual(path.read_bytes(), previous)
        self.assertEqual(self.host.records[-1][1], "not_verified")
        self.assertEqual([p.name for p in (self.state / "secrets").iterdir()], ["registry"])

    def test_show_never_prints_the_value_and_logout_removes_only_one_host(self):
        self.login()
        self.login("another.example")
        self.host.lines.clear()
        registry.show(self.host)
        self.assertEqual(self.host.lines, ["another.example as reader", "registry.example as reader"])
        registry.logout(self.host, "registry.example")
        self.assertFalse((self.state / "secrets/registry/registry.example.env").exists())
        self.assertTrue((self.state / "secrets/registry/another.example.env").exists())

    def test_bad_host_or_unwritable_audit_never_asks_for_a_secret(self):
        def secret():
            self.fail("credential input was reached")
        with self.assertRaises(HostError):
            registry.login(self.host, "../escape", "reader", secret)
        self.host.fail_audit = True
        with self.assertRaises(OSError):
            registry.login(self.host, "registry.example", "reader", secret)
        self.assertEqual(self.host.processes, [])
        self.assertEqual(list((self.state / "secrets").iterdir()), [])

    def test_single_line_input_is_bounded_and_rejects_trailing_data(self):
        self.assertEqual(registry.read_token(io.StringIO(TOKEN + "\r\n")), TOKEN)
        for value in ("", TOKEN + "\nsecond", "a" * 8193, "a" * 8192 + "\r\nextra"):
            with self.assertRaises(HostError):
                registry.read_token(io.StringIO(value))
