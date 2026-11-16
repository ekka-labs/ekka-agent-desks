"""The two records the installer writes for EKKA's desk commands (tools/desk_records.py).

What matters is who can change them: root only. So the tests plant the ways someone else could: a link where the
record goes, a link or a writable folder on the way to it, a folder owned by someone else. Each is refused before a
byte is written. A failure before the rename leaves the old record whole. A failure after it leaves the new record
in place and says so: replaced, and the disk did not confirm it is saved.

Most tests run as any user, with their own folder as the trusted top and their own uid as the owner. The last one
needs root: as another user it reads the record and is refused writing, deleting or renaming over it.
"""
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import desk_records as dr  # noqa: E402

ME = os.getuid()
ID = "sha256:" + "ab" * 32
POLICY = os.path.join(ROOT, "desk", "policy.json")


class Top(unittest.TestCase):
    """A trusted top folder of the test's own, 0755, as / is on a server."""

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.top = os.path.realpath(self._d.name)
        os.chmod(self.top, 0o755)

    def tearDown(self):
        for dirpath, dirnames, _ in os.walk(self.top):
            for d in dirnames:
                p = os.path.join(dirpath, d)
                if not os.path.islink(p):
                    os.chmod(p, 0o755)
        self._d.cleanup()

    def path(self, *names):
        return os.path.join(self.top, *names)

    def write(self, dest, data, owner=ME):
        dr.write(dest, data, top=self.top, owner=owner)

    def leftovers(self, folder):
        return [n for n in os.listdir(folder) if n.endswith(".tmp")]


class Writes(Top):
    def test_the_baseline_is_the_reviewed_policy_byte_for_byte_0644(self):
        dest = self.path("state", "backend", "baseline-policy.json")
        self.write(dest, dr.baseline_bytes(POLICY))
        with open(POLICY, "rb") as a, open(dest, "rb") as b:
            self.assertEqual(a.read(), b.read())
        st = os.stat(dest)
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid), (0o644, ME))
        for folder in (self.path("state"), self.path("state", "backend")):
            self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o755, "made 0755")
        self.assertEqual(self.leftovers(self.path("state", "backend")), [])

    def test_a_new_record_replaces_the_old_one_whole(self):
        dest = self.path("baseline-policy.json")
        self.write(dest, b'{"version": 1}\n')
        before = os.stat(dest).st_ino
        self.write(dest, b'{"version": 2}\n')
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), b'{"version": 2}\n')
        self.assertNotEqual(os.stat(dest).st_ino, before, "renamed into place, never written over")
        self.assertEqual(self.leftovers(self.top), [])

    def test_a_rename_that_fails_leaves_the_old_record_as_it_was(self):
        dest = self.path("baseline-policy.json")
        self.write(dest, b'{"version": 1}\n')
        with mock.patch.object(dr.os, "replace", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                self.write(dest, b'{"version": 2}\n')
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), b'{"version": 1}\n')
        self.assertEqual(self.leftovers(self.top), [], "the half-made record is removed")

    def test_the_image_record_names_the_desk_image_and_its_id(self):
        dest = self.path("desk-image.json")
        self.write(dest, dr.image_bytes(ID))
        with open(dest) as f:
            self.assertEqual(json.load(f), {"image": "ekka-desk:local", "id": ID})


class Refusals(Top):
    def assertRefused(self, dest, data=b"{}\n", owner=ME, says=""):
        with self.assertRaises(dr.Refused) as e:
            self.write(dest, data, owner=owner)
        self.assertIn(says, str(e.exception))
        return e.exception

    def test_a_link_where_the_record_goes_is_refused_and_left_alone(self):
        target = self.path("elsewhere.json")
        with open(target, "w") as f:
            f.write("untouched")
        os.symlink(target, self.path("baseline-policy.json"))
        self.assertRefused(self.path("baseline-policy.json"), says="is a link")
        with open(target) as f:
            self.assertEqual(f.read(), "untouched")

    def test_a_folder_where_the_record_goes_is_refused(self):
        os.mkdir(self.path("baseline-policy.json"))
        self.assertRefused(self.path("baseline-policy.json"), says="not a regular file")

    def test_a_link_on_the_way_is_refused(self):
        real = self.path("real")
        os.mkdir(real, 0o755)
        os.symlink(real, self.path("state"))
        self.assertRefused(self.path("state", "baseline-policy.json"), says="is a link or not a folder")
        self.assertEqual(os.listdir(real), [], "nothing written through the link")

    def test_a_folder_others_can_write_is_refused_anywhere_on_the_way(self):
        for mode in (0o775, 0o757, 0o777):
            for depth in (("a",), ("a", "b")):
                with self.subTest(mode=oct(mode), depth=depth):
                    os.makedirs(self.path("a", "b"), mode=0o755, exist_ok=True)
                    os.chmod(self.path("a", "b"), 0o755)
                    os.chmod(self.path("a"), 0o755)
                    os.chmod(self.path(*depth), mode)
                    dest = self.path("a", "b", "baseline-policy.json")
                    self.assertRefused(dest, says="can be written by users other than its owner")
                    self.assertFalse(os.path.exists(dest))

    def test_a_top_others_can_write_is_refused(self):
        os.chmod(self.top, 0o777)
        self.assertRefused(self.path("baseline-policy.json"), says="can be written")

    def test_a_folder_owned_by_someone_else_is_refused(self):
        self.assertRefused(self.path("baseline-policy.json"), owner=ME + 1, says=f"not owned by uid {ME + 1}")
        self.assertFalse(os.path.exists(self.path("baseline-policy.json")))

    def test_a_path_outside_the_top_is_refused(self):
        self.assertRefused(os.path.join(os.path.dirname(self.top), "x.json"), says="is not under")

    def test_a_record_name_that_is_not_plain_is_refused(self):
        for name in (".hidden.json", "x.json\n"):
            with self.subTest(name=name):
                self.assertRefused(self.path(name), says="not a plain file name")


class Inputs(unittest.TestCase):
    def test_the_shipped_desk_policy_is_a_baseline(self):
        self.assertTrue(dr.baseline_bytes(POLICY))

    def test_a_baseline_that_is_not_a_json_object_or_too_large_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            for name, data, says in (
                ("not-json", b"{ not json", "is not JSON"),
                ("array", b"[1, 2]", "not a JSON object"),
                ("big", b'{"x": "' + b"a" * (1024 * 1024) + b'"}', "larger than"),
            ):
                p = os.path.join(d, name)
                with open(p, "wb") as f:
                    f.write(data)
                with self.subTest(name), self.assertRaises(dr.Refused) as e:
                    dr.baseline_bytes(p)
                self.assertIn(says, str(e.exception))

    def test_an_image_id_must_be_a_full_sha256(self):
        for bad in ("", "sha256:" + "ab" * 31, "sha256:" + "AB" * 32, "ab" * 32, ID + "\n", "sha512:" + "ab" * 32):
            with self.subTest(bad=bad), self.assertRaises(dr.Refused):
                dr.image_bytes(bad)


class CommandLineWrites(Top):
    def run_image_command(self, dest):
        write = dr.write
        with mock.patch.object(dr, "write", side_effect=lambda dest, data: write(dest, data, top=self.top, owner=ME)), \
                mock.patch.object(sys, "stderr", new_callable=io.StringIO) as err, \
                mock.patch.object(sys, "stdout", new_callable=io.StringIO) as out:
            code = dr.main(["image", ID, dest])
        return code, err.getvalue(), out.getvalue()

    def test_a_failed_rename_reports_not_written_and_keeps_the_old_record(self):
        dest = self.path("desk-image.json")
        self.write(dest, b"old record\n")
        before = os.stat(dest).st_ino
        with mock.patch.object(dr.os, "replace", side_effect=OSError(28, "No space left on device")) as replace:
            code, err, out = self.run_image_command(dest)
        replace.assert_called_once()
        self.assertEqual(code, 1)
        self.assertIn("the image record was not written", err)
        self.assertNotIn("was replaced", err)
        self.assertEqual(out, "")
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), b"old record\n")
        self.assertEqual(os.stat(dest).st_ino, before)
        self.assertEqual(self.leftovers(self.top), [])

    def test_a_failed_folder_fsync_reports_replaced_and_not_confirmed_saved(self):
        dest = self.path("desk-image.json")
        self.write(dest, b"old record\n")
        before = os.stat(dest).st_ino
        fsync = os.fsync

        def fail_on_folder(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(5, "Input/output error")
            return fsync(fd)

        with mock.patch.object(dr.os, "fsync", side_effect=fail_on_folder) as sync:
            code, err, out = self.run_image_command(dest)
        self.assertEqual(sync.call_count, 2, "the file fsync succeeds before the folder fsync fails")
        self.assertEqual(code, 3)
        self.assertIn("the image record was replaced", err)
        self.assertIn("the disk did not confirm it is saved", err)
        self.assertNotIn("not written", err)
        self.assertEqual(out, "")
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), dr.image_bytes(ID))
        self.assertNotEqual(os.stat(dest).st_ino, before)
        self.assertEqual(self.leftovers(self.top), [])


class CommandLine(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "tools", "desk_records.py"), *args],
                              capture_output=True, text=True)

    def test_usage(self):
        self.assertEqual(self.run_tool().returncode, 2)
        self.assertEqual(self.run_tool("other", "a", "b").returncode, 2)

    @unittest.skipIf(os.geteuid() == 0, "as root, a temporary folder can be root's")
    def test_the_command_line_trusts_only_root_from_slash(self):
        """The command line takes no top and no owner: as anyone but root, under folders that are not root's,
        it refuses and writes nothing."""
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "baseline-policy.json")
            r = self.run_tool("baseline", POLICY, dest)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("REFUSED", r.stderr)
            self.assertFalse(os.path.exists(dest))


@unittest.skipUnless(os.geteuid() == 0, "needs root: written as root, tried as another user")
class AnotherUser(unittest.TestCase):
    """As root, from /, into a root-owned folder: another user reads the record, and cannot write it, delete it
    or rename another file over it."""

    def test_another_user_reads_and_cannot_change_the_record(self):
        base = tempfile.mkdtemp(prefix="ekka-records-test-", dir="/")  # every folder root's, as on a server
        try:
            os.chmod(base, 0o755)
            os.chown(base, 0, 0)
            dest = os.path.join(base, "backend", "baseline-policy.json")
            dr.write(dest, dr.baseline_bytes(POLICY))
            probe = (
                "import os, sys\n"
                "os.setgid(65534); os.setuid(65534)\n"
                "d = sys.argv[1]; f = os.path.join(d, 'baseline-policy.json')\n"
                "out = [str(len(open(f, 'rb').read()) > 0)]\n"
                "for name, act in (('write', lambda: open(f, 'ab')), ('delete', lambda: os.unlink(f)),\n"
                "                  ('plant', lambda: open(os.path.join(d, 'x.json'), 'w')),\n"
                "                  ('rename', lambda: os.rename(f, f + '.old'))):\n"
                "    try: act(); out.append(name + ':allowed')\n"
                "    except PermissionError: out.append(name + ':refused')\n"
                "print(' '.join(out))\n"
            )
            r = subprocess.run([sys.executable, "-c", probe, os.path.dirname(dest)], capture_output=True, text=True)
            self.assertEqual(r.stdout.split(),
                             ["True", "write:refused", "delete:refused", "plant:refused", "rename:refused"], r.stderr)
        finally:
            subprocess.run(["rm", "-rf", base])


if __name__ == "__main__":
    unittest.main()
