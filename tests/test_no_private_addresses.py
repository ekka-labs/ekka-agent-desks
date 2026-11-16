"""No file in this public repository carries what tools/public_check.py refuses.

That is: an email address outside the reserved example domains, a private EKKA repository reference, a
coding-assistant session link or a co-author trailer. The same check runs in CI on every pull request's commit
messages, title and body.

Every file git would publish is read: tracked files and new ones git does not ignore (`git ls-files -co
--exclude-standard`), the checker's own included. There is no hand-made skip list. Bytes that are not UTF-8 are
replaced, never a reason to skip; a file that cannot be read, or a git that cannot list the files, fails the test.
"""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import public_check  # noqa: E402

# Made-up parts, joined at run time from variables (Python joins two literals at compile time, which would put the
# whole refused text into this file's bytecode), so nothing here carries what the check refuses.
AT, ORG, SES, TRL = "@", "ekka-" + "ai/", "session", "by: "


def git_list(root, *args):
    """A git file list. A git that fails, or warns (it lists what it could and exits 0 when a folder cannot be
    read), raises: an incomplete list is never "nothing to check"."""
    r = subprocess.run(["git", "-C", root, "ls-files", "-z", *args], capture_output=True, check=True)
    if r.stderr.strip():
        raise RuntimeError("git could not list every file: " + r.stderr.decode("utf-8", errors="replace").strip())
    return {p for p in r.stdout.decode("utf-8", errors="replace").split("\0") if p}


def publishable(root):
    """What git would publish from `root`: tracked and new non-ignored files, minus tracked files deleted here."""
    return sorted(git_list(root, "-co", "--exclude-standard") - git_list(root, "-d"))


def scan(root, files):
    found = {}
    for n, rel in enumerate(files):
        # The path is published too (a file named after someone's address, a folder copied from a private
        # repository). A path that hits is reported by its place in the list, never by its name.
        name_hits = public_check.hits(rel)
        if name_hits:
            found.setdefault(f"published path number {n}", []).extend(f"in its name: {k}" for k, _ in name_hits)
            rel_label = f"published path number {n}"
        else:
            rel_label = rel
        path = os.path.join(root, rel)
        # A link is published as its target's text, so that text is what is checked; anything else is read. A path
        # that cannot be read raises: a failure, never a skip.
        text = os.readlink(path) if os.path.islink(path) else public_check.read(path)
        for kind, line in public_check.hits(text):
            found.setdefault(rel_label, []).append(f"line {line}: {kind}")
    return found


class NothingPrivateInAnyFile(unittest.TestCase):
    def test_no_file_git_would_publish_carries_an_address_a_private_repository_or_a_session(self):
        files = publishable(ROOT)
        self.assertIn(os.path.join("tools", "public_check.py"), files, "the checker is scanned too")
        self.assertEqual(scan(ROOT, files), {}, "this repository is public")

    def test_a_new_file_not_yet_committed_is_scanned(self):
        d = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q", d], check=True)
        with open(os.path.join(d, "new.txt"), "w") as f:
            f.write("mail someone" + AT + "somecompany.io\n")
        self.assertEqual(list(scan(d, publishable(d))), ["new.txt"])

    def test_a_file_that_is_not_utf8_is_still_read(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "blob.bin"), "wb") as f:
            f.write(b"\xff\xfe junk then mail someone" + AT.encode() + b"somecompany.io\n")
        self.assertEqual(list(scan(d, ["blob.bin"])), ["blob.bin"])

    def test_utf16_and_utf32_text_is_read(self):
        d = tempfile.mkdtemp()
        text = "export\nmail someone" + AT + "somecompany.io and " + ORG + "some-private-repo\n"
        files = {"bom16.txt": text.encode("utf-16"), "be16.txt": text.encode("utf-16-be"),
                 "le16.txt": text.encode("utf-16-le"), "bom32.txt": text.encode("utf-32")}
        for name, data in files.items():
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        found = scan(d, sorted(files))
        self.assertEqual(sorted(found), sorted(files))
        for name in files:
            self.assertEqual(sorted(h.split(": ")[1] for h in found[name]),
                             ["email address", "private repository reference"], name)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "public_check.py"), "--stdin"],
                           input=text.encode("utf-16"), capture_output=True)
        self.assertEqual(r.returncode, 1)

    def test_a_link_is_checked_by_the_text_git_publishes(self):
        d = tempfile.mkdtemp()
        os.symlink("/home/someone" + AT + "somecompany.io/nowhere", os.path.join(d, "link"))   # dangling, too
        self.assertEqual(list(scan(d, ["link"])), ["link"])

    def test_a_path_is_checked_and_never_printed(self):
        d = tempfile.mkdtemp()
        bad = [os.path.join("contacts", "someone" + AT + "somecompany.io.txt"),
               ORG + "some-private-repo/README.md"]
        for rel in bad:
            os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
            with open(os.path.join(d, rel), "w") as f:
                f.write("clean text\n")
        found = scan(d, bad)
        self.assertEqual(sorted(found), ["published path number 0", "published path number 1"])
        self.assertNotIn("somecompany", repr(found))
        self.assertNotIn("some-private-repo", repr(found))

    def test_a_path_that_cannot_be_read_fails(self):
        with self.assertRaises(OSError):
            scan(tempfile.mkdtemp(), ["missing.txt"])

    def test_a_git_that_warns_fails(self):
        d = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q", d], check=True)
        os.mkdir(os.path.join(d, "locked"))
        with open(os.path.join(d, "locked", "f.txt"), "w") as f:
            f.write("x")
        os.chmod(os.path.join(d, "locked"), 0)
        try:
            if os.access(os.path.join(d, "locked"), os.R_OK):
                self.skipTest("running as root: a folder cannot be made unreadable")
            with self.assertRaises(RuntimeError):
                publishable(d)
        finally:
            os.chmod(os.path.join(d, "locked"), 0o755)

    def test_a_folder_git_cannot_list_fails_the_test(self):
        with self.assertRaises(subprocess.CalledProcessError):
            publishable(tempfile.mkdtemp())   # not a repository: no list is never "nothing to check"


class TheCheckItself(unittest.TestCase):
    def test_it_refuses_what_must_never_be_public(self):
        for n, text in enumerate(("mail someone" + AT + "somecompany.io", "MAIL SOMEONE" + AT + "SOMECOMPANY.IO",
                     "a.b+tag" + AT + "mail.sub.somecompany.io", "<dev" + AT + "somecompany.io>",
                     '"John Doe"' + AT + "somecompany.io", '"a,b"' + AT + "somecompany.io",
                     '"_sample"' + AT + "somecompany.io", '"!"' + AT + "somecompany.io",
                     "Signed: dev" + AT + "users.noreply.github.com",
                     "ops" + AT + "ekka.ai", "see " + ORG + "some-private-repo#12", ORG + ".github",
                     AT + ORG + "some-private-package", ORG + "contracts",
                     "https://claude.ai/code/" + SES + "_x", "Co-authored-" + TRL + "A Model")):
            self.assertTrue(public_check.hits(text), f"refused case number {n}")

    def test_it_allows_example_addresses_and_the_one_package_name(self):
        for n, text in enumerate(("you" + AT + "example.com", "pat" + AT + "example.net", "a" + AT + "sub.example.org",
                     AT + ORG + "contracts 0.76.0", "NVIDIA/OpenShell#2676", "{{" + AT + "input.desk}}",
                     '{"body": "' + AT + 'input.body"}', '["x", "' + AT + 'input.repos"]',
                     '"https://host/x" + "' + AT + 'github.com/o/r"')):
            self.assertEqual(public_check.hits(text), [], f"allowed case number {n}")

    def test_a_hit_names_its_kind_and_line_never_the_value(self):
        value = "someone" + AT + "somecompany.io"
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "public_check.py"), "--stdin"],
                           input=f"clean line\nmail {value}\n", capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout), (1, "stdin:2: email address\n"))
        self.assertNotIn("somecompany", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
