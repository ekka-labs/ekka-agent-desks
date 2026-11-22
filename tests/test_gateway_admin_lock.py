"""up.sh as_gateway_admin, beside ekka-desk-host's emergency stop: one temporary-admin session at a time on a machine,
under one lock file both take, and NVIDIA's CLI sees no gateway registration but the one this session added.

The function runs from up.sh exactly, with Keycloak's script, NVIDIA's CLI and the port probe stubbed, as in
test_as_gateway_admin. The lock is held here the way the native command holds it: flock on the same file.
"""
import fcntl
import json
import os
import subprocess
import tempfile
import unittest

from test_as_gateway_admin import META_SH, function

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
                f'xdg=${{XDG_CONFIG_HOME:-unset}}" >> "{log}"\n'
                f'case "$1 $2" in "gateway add") {META_SH} ;; esac\nexit 0\n')
    for name in ("openssl", "os"):
        os.chmod(os.path.join(stubs, name), 0o755)
    open(log, "w").close()
    script = f"""
set -euo pipefail
DESKS_STATE={d}; OS={stubs}/os; NAME=desks.example.com
die() {{ echo "die: $*" >&2; exit 1; }}
install_cli() {{ :; }}
getent() {{ return 0; }}
kc() {{ echo "kc $*" >> {log}; case "$1 $2" in "setup-client on") printf the-secret ;;
  "setup-client status") echo disabled ;; esac; }}
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


def run_session(d, action="echo did-the-call", status="disabled", add="keeps"):
    """as_gateway_admin with NVIDIA's CLI behaving as 0.1.9 does: `gateway add` refuses a name whose user registration
    already exists (commands/gateway.rs), and `login` signs in with whatever registration its home holds."""
    log = os.path.join(d, "log")
    stubs = os.path.join(d, "bin")
    os.makedirs(stubs, exist_ok=True)
    meta = "$HOME/.config/openshell/gateways/ekka-agent-desks/metadata.json"
    with open(os.path.join(stubs, "openssl"), "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    with open(os.path.join(stubs, "os"), "w") as f:
        f.write(f"""#!/bin/sh
case "$1 $2" in
  "gateway add")
    [ -e "{meta}" ] && exit 1
    case "$ADD" in
      keeps) {META_SH} ;;
      elsewhere) mkdir -p "$(dirname "{meta}")"
                 printf '{{"gateway_endpoint":"%s","auth_mode":"oidc","oidc_issuer":"https://elsewhere.example/r","oidc_client_id":"desks-setup"}}' "$3" > "{meta}" ;;
    esac ;;
  "gateway login") [ -e "{meta}" ] || exit 1
    echo "login $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["oidc_issuer"])' "{meta}")" >> "{log}" ;;
esac
exit 0
""")
    for name in ("openssl", "os"):
        os.chmod(os.path.join(stubs, name), 0o755)
    open(log, "a").close()
    script = f"""
set -euo pipefail
DESKS_STATE={d}; OS={stubs}/os; NAME=desks.example.com
die() {{ echo "die: $*" >&2; exit 1; }}
install_cli() {{ :; }}
getent() {{ return 0; }}
kc() {{ echo "kc $*" >> {log}; case "$1 $2" in "setup-client on") printf the-secret ;;
  "setup-client status") echo "$STATUS" ;; esac; }}
action() {{ {action}; }}
{function()}
rc=0; as_gateway_admin action || rc=$?
echo "rc=$rc"
"""
    env = dict(os.environ, PATH=stubs + os.pathsep + os.environ["PATH"], STATUS=status, ADD=add)
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
    with open(log) as f:
        return r, f.read().splitlines()


class TheLegacySessionIsRecoverable(unittest.TestCase):
    """up.sh's session gets what the native one has: a fresh home, the kept registration read back before sign-in,
    a marker while it is open, a switch-off that is read back, and a trap for Ctrl-C, SIGTERM and SIGHUP."""

    def test_a_home_an_interrupted_session_left_is_never_reused(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.path.join(d, "openshell-admin", ".config", "openshell", "gateways", "ekka-agent-desks")
            os.makedirs(old)
            with open(os.path.join(old, "metadata.json"), "w") as f:
                f.write('{"gateway_endpoint":"https://desks.example.com:8080","auth_mode":"oidc",'
                        '"oidc_issuer":"https://elsewhere.example/r","oidc_client_id":"desks-setup"}')
            r, calls = run_session(d)
            self.assertIn("rc=0", r.stdout, r.stderr)
            self.assertEqual([c for c in calls if c.startswith("login ")],
                             ["login https://desks.example.com/realms/ekka-desks"], "the secret signed in elsewhere")

    def test_a_kept_registration_naming_another_issuer_never_signs_in(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, add="elsewhere")
            self.assertFalse([c for c in calls if c.startswith("login ")], "signed in with another issuer")
            self.assertIn("could not sign in", r.stderr)
            self.assertIn("kc setup-client off", calls)

    def test_an_open_session_is_recorded_and_the_record_removed_after(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, action=f'cat "{d}/gateway-admin.pending" >> "{d}/seen"')
            self.assertIn("rc=0", r.stdout, r.stderr)
            with open(os.path.join(d, "seen")) as f:
                self.assertEqual(json.loads(f.read()), {"home": f"{d}/openshell-admin"})
            self.assertFalse(os.path.exists(os.path.join(d, "gateway-admin.pending")))

    def test_a_switch_off_that_does_not_read_back_is_never_done(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, status="enabled")
            self.assertNotIn("rc=0", r.stdout)
            self.assertIn("not confirmed switched off", r.stderr)
            self.assertTrue(os.path.exists(os.path.join(d, "gateway-admin.pending")), "the open session was forgotten")

    def test_sigterm_during_the_call_switches_access_off_before_leaving(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, action="kill -TERM $$; sleep 1")
            self.assertNotIn("rc=", r.stdout, "the session went on after SIGTERM")
            self.assertEqual(calls[-2:], ["kc setup-client off", "kc setup-client status"], calls)
            self.assertFalse(os.path.exists(os.path.join(d, "gateway-admin.pending")))
            self.assertFalse(os.path.exists(os.path.join(d, "openshell-admin")), "the sign-in stayed on disk")


if __name__ == "__main__":
    unittest.main()
