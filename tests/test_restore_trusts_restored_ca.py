"""A restore puts the RESTORED certificate authority where the Enclave and the gateway read it.

The Enclave trusts the desks' sign-in service through its own copy of the CA, /etc/ekka/desks-ca.crt, which is outside
the backup. Restoring onto a machine that was set up again left the new setup's CA there: the Enclave started,
refused the restored certificates, and every desk read "issuer did not answer". The step runs here with certs.sh
stubbed: the real one writes under /etc and needs root.
"""
import os
import re
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
BACKUP = os.path.join(ROOT, "deploy", "backup.sh")


def read():
    with open(BACKUP) as f:
        return f.read()


def run(text, certs_exit=0):
    """Run trust_restored_ca from `text` in a folder whose certs.sh records how it was called."""
    parts = [re.search(rf"^{n}\(\) +\{{[^\n]*\}}\n", text, re.M).group(0) for n in ("say", "die")]
    parts.append(re.search(r"^trust_restored_ca\(\) +\{.*?^\}\n", text, re.S | re.M).group(0))
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "certs.sh"), "w") as f:
        f.write(f'echo "$1 $DESKS_STATE" > called\nexit {certs_exit}\n')
    r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + "".join(parts) + "trust_restored_ca; echo went-on\n"],
                       capture_output=True, text=True, cwd=d, env=dict(os.environ, DESKS_STATE="/restored/state"), timeout=30)
    called = open(os.path.join(d, "called")).read().strip() if os.path.exists(os.path.join(d, "called")) else ""
    return r, called


def restored_before_anything_starts(text):
    """True when the restore puts the CA in place after the state is unpacked and before the Enclave starts."""
    restore = text[text.index("  restore)"):]
    step = restore.find("    trust_restored_ca\n")
    return step != -1 and restore.index('-xzf "$d/desks-state.tgz"') < step < restore.index("systemctl start ekka")


class TheRestoredCa(unittest.TestCase):
    def test_it_is_built_from_the_restored_state(self):
        r, called = run(read())
        self.assertEqual((r.returncode, called), (0, "bundle /restored/state"), r.stderr)
        self.assertIn("went-on", r.stdout)

    def test_a_failure_stops_the_restore_before_anything_starts(self):
        r, _ = run(read(), certs_exit=3)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("went-on", r.stdout)
        self.assertIn("nothing was started", r.stderr)

    def test_the_restore_does_it_after_the_state_and_before_the_enclave(self):
        self.assertTrue(restored_before_anything_starts(read()))

    def test_planted_a_restore_without_the_step_fails_the_same_check(self):
        text = read()
        planted = text.replace("    trust_restored_ca\n", "")
        self.assertNotEqual(planted, text)
        self.assertFalse(restored_before_anything_starts(planted), "PLANTED: a restore that leaves the old copy passes")

    def test_planted_a_failure_that_is_ignored_fails_the_same_check(self):
        text = read()
        planted = text.replace('|| die "the restored certificate authority', '|| true # "the restored certificate authority')
        self.assertNotEqual(planted, text)
        r, _ = run(planted, certs_exit=3)
        self.assertIn("went-on", r.stdout, "PLANTED: the restore went on after the CA could not be placed")


if __name__ == "__main__":
    unittest.main()
