"""Immutable pulls verify the digest and keep Docker credentials temporary."""
import json
from pathlib import Path
import subprocess
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from ekka_host.images import pull
from ekka_host.runtime import HostError
from test_native_host import Host

DIGEST = "a" * 64
REF = "registry.example/team/desk@sha256:" + DIGEST
TOKEN = "PLANTED_IMAGE_READ_CREDENTIAL"


class ImageHost(Host):
    def __init__(self):
        super().__init__()
        self.processes = []
        self.found = [REF]
        self.signature_failure = False

    def run(self, args, allowed=(0,), stdin=None, timeout=90):
        self.processes.append((args, stdin))
        if "/usr/local/bin/cosign" in args and self.signature_failure:
            raise HostError("signature verification failed")
        if "login" in args:
            config = Path(args[args.index("--config") + 1])
            (config / "config.json").write_text(json.dumps({"auths":{"registry.example":{"auth":TOKEN}}}))
        out = json.dumps(self.found) if "inspect" in args else ""
        return subprocess.CompletedProcess(args, 0, out, "")


class NativeImageTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.state = Path(self.folder.name)
        self.secrets = self.state / "secrets"
        self.secrets.mkdir()
        self.host = ImageHost()

    def invoke(self, **kwargs):
        with patch("ekka_host.images.STATE", self.state), \
             patch("ekka_host.images.root_directory", return_value=self.secrets), \
             patch("ekka_host.registry.root_file", side_effect=lambda p, **_: p.read_text()):
            pull(self.host, kwargs.pop("ref", REF), **kwargs)

    def save_credential(self, text=None):
        folder = self.secrets / "registry"
        folder.mkdir()
        (folder / "registry.example.env").write_text(text if text is not None else
            "REGISTRY_USER=reader\nREGISTRY_TOKEN=" + TOKEN + "\n")

    def test_public_pull_verifies_a_digest_and_removes_its_temporary_config(self):
        self.invoke()
        args = [a for a, _ in self.host.processes]
        self.assertTrue(any("pull" in a for a in args))
        self.assertEqual(args[-1][-1], REF)
        self.assertIn("inspect", args[-1])
        self.assertEqual(list(self.secrets.iterdir()), [])
        self.assertEqual(self.host.records[-1][1], "verified_digest")
        self.assertIn("separate EKKA desk grant", self.host.lines[-1])

    def test_private_login_uses_stdin_and_cleans_up_even_on_a_signature_failure(self):
        self.save_credential()
        self.host.signature_failure = True
        with self.assertRaises(HostError):
            self.invoke(identity="https://example.com/release", issuer="https://issuer.example")
        login, value = self.host.processes[0]
        self.assertIn("--password-stdin", login)
        self.assertEqual(value, TOKEN)
        self.assertNotIn(TOKEN, " ".join(login))
        self.assertFalse(any("pull" in a for a, _ in self.host.processes))
        self.assertEqual([p.name for p in self.secrets.iterdir()], ["registry"])
        self.assertEqual(self.host.records[-1][1], "not_verified")
        self.assertFalse(any(TOKEN in line for line in self.host.lines))

    def test_a_pull_acknowledgement_without_the_requested_digest_is_refused(self):
        self.host.found = ["registry.example/team/desk@sha256:" + "b" * 64]
        with self.assertRaisesRegex(HostError, "does not report the requested digest"):
            self.invoke()
        self.assertEqual(self.host.records[-1][1], "not_verified")
        self.assertFalse(any("Image available" in line for line in self.host.lines))
        self.assertEqual(list(self.secrets.iterdir()), [])

    def test_bad_reference_or_signature_arguments_never_touch_the_host(self):
        for options in ({"ref":"registry.example/team/desk:latest"}, {"ref":"--version"},
                        {"identity":"https://example.com/release"},
                        {"identity":"bad\x1bidentity", "issuer":"https://issuer.example"},
                        {"identity":"release", "issuer":"https://user:password@example.com"}):
            with self.subTest(options=options), self.assertRaises(HostError):
                self.invoke(**options)
        self.assertEqual(self.host.processes, [])
        self.assertEqual(self.host.records, [])

    def test_malformed_credential_is_not_evaluated_or_printed(self):
        self.save_credential("REGISTRY_USER=reader\nREGISTRY_TOKEN=" + TOKEN + "\nEXTRA=not-allowed\n")
        with self.assertRaises(HostError) as error:
            self.invoke()
        self.assertNotIn(TOKEN, str(error.exception))
        self.assertEqual(self.host.processes, [])
        self.assertEqual(self.host.records, [])

    def test_no_temp_files_or_commands_when_the_first_audit_fails(self):
        self.host.fail_audit = True
        with self.assertRaises(OSError):
            self.invoke()
        self.assertEqual(self.host.processes, [])
        self.assertEqual(list(self.secrets.iterdir()), [])

    def test_private_registry_files_cannot_be_group_or_world_readable(self):
        from ekka_host.files import root_file
        source = self.state / "settings"
        source.write_text("REGISTRY_TOKEN=" + TOKEN)
        directory = os.stat_result((stat.S_IFDIR | 0o700, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        for mode in (0o640, 0o644):
            file = os.stat_result((stat.S_IFREG | mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            with patch("ekka_host.files.Path.lstat", return_value=directory), \
                 patch("ekka_host.files.os.fstat", return_value=file):
                with self.assertRaises(HostError):
                    root_file(source, private=True)
