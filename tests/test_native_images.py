"""Immutable pulls verify the digest and keep Docker credentials temporary."""
import contextlib
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


def contains_auth(folder):
    """Docker CLI's ConfigFile.ContainsAuth (cli/config/configfile/file.go): a credsStore, a credHelpers entry or an
    auths entry. Without one, LoadDefaultConfigFile selects a host credential helper (credentials.DetectDefaultStore:
    pass or secretservice, when installed)."""
    try:
        config = json.loads((Path(folder) / "config.json").read_text())
    except FileNotFoundError:
        return False
    return bool(config.get("credsStore") or config.get("credHelpers") or config.get("auths"))


class DockerWithAHelper(ImageHost):
    """Docker on a host with a credential helper installed: what lands in the helper outlives the pull."""

    def __init__(self, cosign=("/usr/local/bin/cosign",)):
        super().__init__()
        self.helper = {}
        self.helper_reads = 0
        self.cosign = set(cosign)

    def run(self, args, allowed=(0,), stdin=None, timeout=90):
        named = [a for a in args if a.endswith("/cosign")]
        if named and named[0] not in self.cosign:
            self.processes.append((args, stdin))
            raise HostError("command did not finish; inspect the host before retrying")   # exec: not found
        if "--config" in args and not contains_auth(args[args.index("--config") + 1]):
            self.processes.append((args, stdin))
            if "login" in args:
                self.helper[args[args.index("login") + 1]] = stdin
            else:
                self.helper_reads += 1
            return subprocess.CompletedProcess(args, 0, json.dumps(self.found) if "inspect" in args else "", "")
        return super().run(args, allowed, stdin, timeout)


class NativeImageTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.state = Path(self.folder.name)
        self.secrets = self.state / "secrets"
        self.secrets.mkdir()
        self.host = ImageHost()

    def invoke(self, real_cosign=False, **kwargs):
        cosign = patch("ekka_host.images.cosign_path", return_value="/usr/local/bin/cosign", create=True)
        with patch("ekka_host.images.STATE", self.state), \
             patch("ekka_host.images.root_directory", return_value=self.secrets), \
             patch("ekka_host.registry.root_file", side_effect=lambda p, **_: p.read_text()), \
             (contextlib.nullcontext() if real_cosign else cosign):
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


class PullReviewFixes(unittest.TestCase):
    """Credentials stay out of host helpers, asked-for signature checks always run, and cosign's location."""
    setUp = NativeImageTests.setUp   # the same fixture, without running NativeImageTests's cases again
    invoke = NativeImageTests.invoke   # the same fixture, without running NativeImageTests's cases again
    save_credential = NativeImageTests.save_credential   # the same fixture, without running NativeImageTests's cases again

    def test_a_credential_never_reaches_a_host_credential_helper(self):
        self.host = DockerWithAHelper()
        self.save_credential()
        self.invoke()
        self.assertEqual(self.host.helper, {}, "the registry credential was stored in the host's helper")
        self.assertEqual(self.host.helper_reads, 0, "the pull read the host's helper")
        self.assertEqual(self.host.records[-1][1], "verified_digest")

    def test_empty_signing_options_never_skip_the_signature_check(self):
        for identity, issuer in (("", ""), ("", "https://issuer.example"), ("https://example.com/release", "")):
            with self.subTest(identity=identity, issuer=issuer), self.assertRaises(HostError):
                self.invoke(identity=identity, issuer=issuer)
        self.assertEqual(self.host.processes, [], "a pull ran without the signature check it was asked for")

    def test_cosign_is_found_in_its_other_trusted_location(self):
        folder = self.state / "usr-bin"
        folder.mkdir()
        cosign = folder / "cosign"
        cosign.write_text("#!/bin/sh\n")
        cosign.chmod(0o755)
        self.host = DockerWithAHelper(cosign=(str(cosign),))
        with patch("ekka_host.images.COSIGN", (str(self.state / "usr-local-bin/cosign"), str(cosign)), create=True), \
             patch("ekka_host.images.ROOT_UID", os.getuid(), create=True):
            self.invoke(real_cosign=True, identity="https://example.com/release", issuer="https://issuer.example")
        self.assertEqual(self.host.records[-1][1], "verified_digest")
        self.assertTrue(any(str(cosign) in a for a, _ in self.host.processes))

    def test_a_linked_cosign_is_refused_and_its_own_folder_is_the_one_checked(self):
        # A link in a folder someone else controls could point at any root-owned program that exits 0.
        target = self.state / "target"
        target.mkdir()
        program = target / "true"
        program.write_text("#!/bin/sh\n")
        program.chmod(0o755)
        lookup = self.state / "lookup"
        lookup.mkdir()
        (lookup / "cosign").symlink_to(program)
        checked = []
        with patch("ekka_host.images.COSIGN", (str(lookup / "cosign"),), create=True), \
             patch("ekka_host.images.ROOT_UID", os.getuid(), create=True), \
             patch("ekka_host.images.root_directory", side_effect=lambda p: checked.append(Path(p)) or Path(p)), \
             patch("ekka_host.images.STATE", self.state), \
             patch("ekka_host.registry.root_file", side_effect=lambda p, **_: p.read_text()), \
             self.assertRaises(HostError):
            pull(self.host, REF, "https://example.com/release", "https://issuer.example")
        self.assertIn(lookup, checked, "the folder the program is looked up in was not checked")
        self.assertEqual(self.host.processes, [], "a linked cosign ran")

    def test_a_cosign_others_can_change_is_refused(self):
        folder = self.state / "usr-bin"
        folder.mkdir()
        cosign = folder / "cosign"
        cosign.write_text("#!/bin/sh\n")
        cosign.chmod(0o777)
        with patch("ekka_host.images.COSIGN", (str(cosign),), create=True), \
             patch("ekka_host.images.ROOT_UID", os.getuid(), create=True), \
             self.assertRaisesRegex(HostError, "cosign"):
            self.invoke(real_cosign=True, identity="https://example.com/release", issuer="https://issuer.example")
        self.assertEqual(self.host.processes, [])
