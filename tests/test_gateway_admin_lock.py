"""up.sh as_gateway_admin, beside ekka-desk-host's emergency stop: one temporary-admin session at a time on a machine,
under one lock file both take, and NVIDIA's CLI sees no gateway registration but the one this session added.

The function runs from up.sh exactly, with Keycloak's script, NVIDIA's CLI and the port probe stubbed, as in
test_as_gateway_admin. The lock is held here the way the native command holds it: flock on the same file.
"""
import fcntl
import os
import subprocess
import tempfile
import unittest

from test_as_gateway_admin import function

LOCK = "gateway-admin.lock"   # ekka_host.gateway.emergency_stop locks STATE / this name


def run(d):
    log = os.path.join(d, "log")
    stubs = os.path.join(d, "bin")
    os.mkdir(stubs)
    with open(os.path.join(stubs, "openssl"), "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    with open(os.path.join(stubs, "os"), "w") as f:
        # What NVIDIA's CLI would see: the system registry folder it falls back to, and whether it holds anything.
        f.write(f'#!/bin/sh\necho "os $1 $2 system=${{OPENSHELL_SYSTEM_GATEWAY_DIR:-/etc/openshell}} '
                f'entries=$(ls -A "${{OPENSHELL_SYSTEM_GATEWAY_DIR:-/etc/openshell}}" 2>/dev/null | wc -l | tr -d " ") '
                f'xdg=${{XDG_CONFIG_HOME:-unset}}" >> "{log}"\nexit 0\n')
    for name in ("openssl", "os"):
        os.chmod(os.path.join(stubs, name), 0o755)
    open(log, "w").close()
    script = f"""
set -euo pipefail
DESKS_STATE={d}; OS={stubs}/os; NAME=desks.example.com
die() {{ echo "die: $*" >&2; exit 1; }}
install_cli() {{ :; }}
getent() {{ return 0; }}
kc() {{ echo "kc $*" >> {log}; case "$1 $2" in "setup-client on") printf the-secret ;; esac; }}
action() {{ echo did-the-call; }}
{function()}
rc=0; as_gateway_admin action || rc=$?
echo "rc=$rc"
"""
    env = dict(os.environ, PATH=stubs + os.pathsep + os.environ["PATH"], XDG_CONFIG_HOME=os.path.join(d, "elsewhere"))
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
    with open(log) as f:
        return r, f.read().splitlines()


class OneSessionAtATime(unittest.TestCase):
    def test_a_session_in_progress_elsewhere_stops_this_one_before_the_client_is_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            fd = os.open(os.path.join(d, LOCK), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)          # an emergency stop is running
                r, calls = run(d)
            finally:
                os.close(fd)
            self.assertNotIn("kc setup-client on", calls, "the setup client was enabled under another session")
            self.assertNotIn("did-the-call", r.stdout)
            self.assertIn("another gateway administrator session is running", r.stderr)

    def test_the_lock_is_released_when_the_session_ends(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run(d)
            self.assertIn("rc=0", r.stdout, r.stderr)
            fd = os.open(os.path.join(d, LOCK), os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # raises if the finished session still held it
            finally:
                os.close(fd)
            self.assertEqual(os.stat(os.path.join(d, LOCK)).st_mode & 0o777, 0o600)

    def test_a_lock_that_is_a_link_is_refused_and_its_target_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "target")
            with open(target, "w") as f:
                f.write("unchanged")
            os.symlink(target, os.path.join(d, LOCK))
            r, calls = run(d)
            self.assertNotIn("kc setup-client on", calls)
            self.assertIn("lock", r.stderr)
            with open(target) as f:
                self.assertEqual(f.read(), "unchanged")


class OnlyThisSessionsRegistration(unittest.TestCase):
    def test_nvidias_cli_falls_back_to_an_empty_registry_of_this_session(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run(d)
            self.assertIn("rc=0", r.stdout, r.stderr)
            seen = [c for c in calls if c.startswith("os gateway")]
            self.assertTrue(seen)
            for call in seen:
                self.assertIn(f"system={d}/openshell-admin/system ", call, "the CLI can fall back to /etc/openshell")
                self.assertIn("entries=0 ", call)
                self.assertTrue(call.endswith("xdg=unset"), "an inherited XDG_CONFIG_HOME moves the registration")
            self.assertFalse(os.path.exists(os.path.join(d, "openshell-admin")), "the session's folder was kept")


if __name__ == "__main__":
    unittest.main()
