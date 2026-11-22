"""up.sh as_gateway_admin: one temporary-admin session at a time on a machine, under one lock file, and NVIDIA's CLI
sees no gateway registration but the one this session wrote.

The function runs from up.sh exactly, with Keycloak's script, NVIDIA's CLI and the port probe stubbed, as in
test_as_gateway_admin. Another session is stood in for by holding flock on the same file.
"""
import fcntl
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from test_as_gateway_admin import META_SH, ROOT, function

LOCK = "gateway-admin.lock"


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
kc() {{ echo "kc $*" >> {log}; case "$1 $2" in "setup-client on") printf 'c-setup\nthe-secret' ;;
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
                fcntl.flock(fd, fcntl.LOCK_EX)          # another session is running
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


def run_session(d, action="echo did-the-call", status="disabled", on_hook=":", rm_fails=False,
                login_hook=":", off_hook=":", caller='rc=0; as_gateway_admin action || rc=$?; echo "rc=$rc"'):
    """as_gateway_admin with NVIDIA's CLI behaving as 0.1.9 does: `login` needs a registration in its home and signs
    in with whatever registration that is (commands/gateway.rs, gateway_login). A `gateway add` is recorded, and keeps
    what it was given as NVIDIA's CLI does."""
    log = os.path.join(d, "log")
    stubs = os.path.join(d, "bin")
    os.makedirs(stubs, exist_ok=True)
    meta = "$HOME/.config/openshell/gateways/ekka-agent-desks/metadata.json"
    with open(os.path.join(stubs, "openssl"), "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    with open(os.path.join(stubs, "os"), "w") as f:
        f.write(f"""#!/bin/sh
case "$1 $2" in
  "gateway add") echo "add secret=${{OPENSHELL_OIDC_CLIENT_SECRET:+set}}" >> "{log}"; {META_SH} ;;
  "gateway login") [ -e "{meta}" ] || exit 1
    echo "sign-in secret=${{OPENSHELL_OIDC_CLIENT_SECRET:+set}}" >> "{log}"
    eval "$LOGIN_HOOK"
    echo "registered $(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))' "{meta}")" >> "{log}"
    echo "login $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["oidc_issuer"])' "{meta}")" >> "{log}" ;;
esac
exit 0
""")
    for name in ("openssl", "os"):
        os.chmod(os.path.join(stubs, name), 0o755)
    open(log, "a").close()
    script = f"""
set -euo pipefail
DESKS_STATE={d}; OS={stubs}/os; NAME=desks.example.com; export MAIN_PID=$$
die() {{ echo "die: $*" >&2; exit 1; }}
install_cli() {{ :; }}
getent() {{ return 0; }}
say() {{ echo "say: $*"; }}
kc() {{ echo "kc $*" >> {log}; case "$1 $2" in "setup-client on") {on_hook}; printf 'c-setup\nthe-secret' ;;
  "setup-client off") {off_hook} ;;
  "setup-client status") echo "$STATUS" ;; esac; }}
{"rm() { return 1; }" if rm_fails is True else ""}
{'rm() { [ -e "$DESKS_STATE/rm-once" ] && return 1; : > "$DESKS_STATE/rm-once"; command rm "$@"; }' if rm_fails == "later" else ""}
action() {{ {action}; }}
{function()}
{caller}
"""
    env = dict(os.environ, PATH=stubs + os.pathsep + os.environ["PATH"], STATUS=status, LOGIN_HOOK=login_hook)
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
    with open(log) as f:
        return r, f.read().splitlines()


class TheLegacySessionIsRecoverable(unittest.TestCase):
    """A fresh home with a registration this session writes, a switch-off that is read back, and Ctrl-C, SIGTERM and
    SIGHUP handled: access is switched off and the caller gets 130 back, so its own cleanup runs."""

    def test_a_home_an_interrupted_session_left_is_never_reused(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.path.join(d, "openshell-admin", ".config", "openshell", "gateways", "ekka-agent-desks")
            os.makedirs(old)
            with open(os.path.join(old, "metadata.json"), "w") as f:
                f.write('{"gateway_endpoint":"https://desks.example.com:8080","auth_mode":"oidc",'
                        '"oidc_issuer":"https://other.example/realms/x","oidc_client_id":"desks-setup"}')
            r, calls = run_session(d)
            self.assertIn("rc=0", r.stdout, r.stderr)
            self.assertEqual([c for c in calls if c.startswith("login ")],
                             ["login https://desks.example.com/realms/ekka-desks"], "an old registration was used")

    def test_a_switch_off_that_does_not_read_back_is_never_done(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, status="enabled")
            self.assertNotIn("rc=0", r.stdout)
            self.assertIn("not confirmed off", r.stderr)

    def test_sigterm_during_the_call_switches_access_off_and_returns_to_the_caller(self):
        # The caller must get control back: `up.sh openshell sandbox download` makes the downloaded folder safe after
        # the call, whatever the call's result. A call that already ran keeps its own result.
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, action="kill -TERM $$; sleep 1; return 0")
            self.assertIn("rc=0", r.stdout, r.stderr)
            self.assertIn("its result stands", r.stdout)
            self.assertEqual(calls[-2:], ["kc setup-client off c-setup", "kc setup-client status c-setup"], calls)
            self.assertFalse(os.path.exists(os.path.join(d, "openshell-admin")), "the sign-in stayed on disk")

    def test_a_signal_during_sign_in_stops_the_call_from_starting(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, login_hook="kill -TERM $MAIN_PID")   # the session's own shell, not the sign-in step
            self.assertIn("rc=130", r.stdout, r.stderr)
            self.assertNotIn("did-the-call", r.stdout, "the call started after the signal")
            self.assertEqual(calls[-2:], ["kc setup-client off c-setup", "kc setup-client status c-setup"], calls)

    def test_a_signal_during_the_switch_off_is_not_lost(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, action=":", off_hook="kill -TERM $$")
            self.assertIn("rc=0", r.stdout, r.stderr)   # the call had already run; its result stands
            self.assertIn("interrupted", r.stdout, "the signal during the switch-off was lost")
            self.assertEqual(calls[-2:], ["kc setup-client off c-setup", "kc setup-client status c-setup"], calls)

    def test_a_switch_off_that_fails_still_hands_back_for_the_download_safety_pass(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, status="enabled",
                                   caller='rc=0; as_gateway_admin action || rc=$?; echo "safety-pass rc=$rc"')
            self.assertIn("safety-pass rc=70", r.stdout, r.stderr)
            self.assertFalse(os.path.exists(os.path.join(d, "openshell-admin")), "the sign-in stayed on disk")

    def test_no_other_session_starts_while_the_call_runs(self):
        contender = ("python3 -c 'import fcntl, os, sys; fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
                     "try:\n    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); print(\"contender got the lock\")\n"
                     "except BlockingIOError:\n    print(\"contender refused\")' \"$DESKS_STATE/gateway-admin.lock\"")
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, action=contender)
            self.assertIn("contender refused", r.stdout, r.stdout + r.stderr)

    def test_a_signal_before_the_sign_in_skips_the_call(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, on_hook="kill -TERM $$")
            self.assertIn("rc=130", r.stdout, r.stderr)
            self.assertFalse([c for c in calls if c.startswith("login ")], "it signed in after the signal")
            self.assertEqual(calls[-2:], ["kc setup-client off c-setup", "kc setup-client status c-setup"], calls)

    def test_a_sign_in_folder_that_cannot_be_removed_stops_the_session_first(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "openshell-admin", ".config"))   # an interrupted session's folder
            r, calls = run_session(d, rm_fails=True)
            self.assertNotIn("rc=", r.stdout)
            self.assertIn("could not be removed", r.stderr)
            self.assertNotIn("kc setup-client on", calls)


class EachEndOfSessionResultIsSaidAsItIs(unittest.TestCase):
    def test_a_folder_left_on_disk_is_said_without_doubting_the_switch_off(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, rm_fails="later")       # removed at the start, not at the end
            self.assertIn("rc=70", r.stdout, r.stderr)
            self.assertIn("could not be removed", r.stderr)
            self.assertNotIn("switched on", r.stderr, "a setup client read back as off was said to be on")

    def test_an_interrupted_session_whose_switch_off_did_not_read_back_never_says_it_is_off(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d, on_hook="kill -TERM $$", status="enabled")
            self.assertIn("rc=70", r.stdout, r.stderr)
            self.assertIn("interrupted: the call did not run", r.stdout)
            self.assertNotIn("switched off again", r.stdout)


class TheSecretOnlyReachesTheSignIn(unittest.TestCase):
    def test_the_gateway_is_registered_without_any_sign_in_and_signed_in_once_with_the_secret(self):
        # No `gateway add`: in OpenShell 0.1.9 it signs in as it registers, with or without the secret. The session
        # writes the registration itself, in the shape `gateway add` writes, and only `gateway login` gets the secret.
        with tempfile.TemporaryDirectory() as d:
            r, calls = run_session(d)
            self.assertIn("rc=0", r.stdout, r.stderr)
            self.assertFalse([c for c in calls if c.startswith("add ")], "the registration step signs in")
            self.assertEqual([c for c in calls if c.startswith("sign-in ")], ["sign-in secret=set"])
            self.assertIn("registered " + json.dumps({
                "auth_mode": "oidc", "gateway_endpoint": "https://desks.example.com:8080", "gateway_port": 0,
                "is_remote": True, "name": "ekka-agent-desks", "oidc_audience": "ekka-desks",
                "oidc_client_id": "desks-setup", "oidc_issuer": "https://desks.example.com/realms/ekka-desks"},
                sort_keys=True), calls)


def download_function():
    """up.sh's download caller. Older versions ran it inline in the `openshell` verb; that inline code is wrapped the
    same way here, so a run against an older up.sh measures what it did."""
    with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^download_settled\(\) \{.*?^\}\n", text, re.S | re.M)
    if m:
        return m.group(0)
    inline = text[text.index('if [[ "${1:-} ${2:-}" == "sandbox download" ]]; then'):]
    inline = inline[inline.index("\n") + 1:inline.index("\n    fi\n")]
    inline = "\n".join(line for line in inline.splitlines() if not line.strip().startswith("#"))
    return "download_settled() {\n" + inline.replace("exit $rc", "return $rc") + "\n}\n"


def run_download(d, login="ok", copy_exit=0, interrupt_the_pass=False, log_traps=False):
    """`up.sh openshell sandbox download` from as_gateway_admin through the safety pass, in a session of its own so a
    Ctrl-C reaches exactly this process group. The copy writes a plain file and a link into the destination; the
    real tools/openshell_allow.py --settle-download makes it safe. With interrupt_the_pass, the pass's own process
    group gets SIGINT just as the pass starts, as a Ctrl-C would. With log_traps, every change the main shell makes to
    its signal handling is logged, in order, through a wrapper around bash's own `trap`."""
    log = os.path.join(d, "log")
    stubs = os.path.join(d, "bin")
    os.makedirs(stubs, exist_ok=True)
    dest = os.path.join(d, "downloaded")
    real_python = shutil.which("python3")
    with open(os.path.join(stubs, "openssl"), "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    with open(os.path.join(stubs, "os"), "w") as f:
        f.write(f"""#!/bin/sh
[ "$1" = -g ] && shift 2
case "$1 $2" in
  "gateway add") {META_SH} ;;
  "gateway login") [ -e "$HOME/.config/openshell/gateways/ekka-agent-desks/metadata.json" ] && [ "{login}" = ok ] || exit 1 ;;
  "sandbox download") mkdir -p "{dest}"; echo data > "{dest}/plain.txt"; ln -s /etc/hosts "{dest}/link"
                      exit {copy_exit} ;;
esac
exit 0
""")
    with open(os.path.join(stubs, "python3"), "w") as f:
        f.write(f"""#!/bin/sh
case " $* " in *" --settle-download "*)
  echo pass-started >> "{log}"
  {"kill -INT 0; sleep 0.3" if interrupt_the_pass else ":"} ;;
esac
exec "{real_python}" "$@"
""")
    for name in ("openssl", "os", "python3"):
        os.chmod(os.path.join(stubs, name), 0o755)
    open(log, "a").close()
    script = f"""
set -euo pipefail
cd {ROOT}
DESKS_STATE={d}; OS={stubs}/os; NAME=desks.example.com
die() {{ echo "die: $*" >&2; exit 1; }}
install_cli() {{ :; }}
getent() {{ return 0; }}
say() {{ echo "say: $*"; }}
kc() {{ echo "kc $*" >> {log}; case "$1 $2" in "setup-client on") printf 'c-setup\nthe-secret' ;;
  "setup-client status") echo disabled ;; esac; }}
{'trap() { [ "$BASH_SUBSHELL" = 0 ] && [ "${1:-}" != -p ] && echo "trap [$1] ${*:2}" >> ' + log + '; builtin trap "$@"; }' if log_traps else ""}
{function()}
{download_function()}
rc=0; download_settled sandbox download code-desk /sandbox/out "{dest}" || rc=$?
echo "rc=$rc"
"""
    env = dict(os.environ, PATH=stubs + os.pathsep + os.environ["PATH"])
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60,
                       start_new_session=True)
    with open(log) as f:
        return r, f.read().splitlines(), dest


class TheDownloadIsAlwaysMadeSafe(unittest.TestCase):
    def test_a_ctrl_c_during_the_safety_pass_does_not_stop_it(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls, dest = run_download(d, interrupt_the_pass=True)
            self.assertIn("pass-started", calls)
            self.assertTrue(os.path.exists(os.path.join(dest, "plain.txt")))
            self.assertFalse(os.path.lexists(os.path.join(dest, "link")), "the pass was stopped: a link is still there")
            # The copy had finished before the Ctrl-C: like any call that already ran, its result stands.
            self.assertIn("rc=0", r.stdout, r.stderr)

    def test_signals_are_never_at_their_default_from_the_copy_until_the_pass_ends(self):
        # At the default, a Ctrl-C ends the shell and the pass never runs. The handoff from the session back to the
        # download caller goes straight from one handler to the next, and the pass starts with signals ignored.
        with tempfile.TemporaryDirectory() as d:
            r, calls, dest = run_download(d, log_traps=True)
            self.assertIn("rc=0", r.stdout, r.stderr)
            changes = [c for c in calls[:calls.index("pass-started")] if c.startswith("trap ")]
            self.assertEqual(changes[0], "trap [noted=1] INT TERM HUP", changes)
            self.assertFalse([c for c in changes if c.startswith("trap [-]")], f"a signal went back to its default: {changes}")
            self.assertEqual(changes[-1], "trap [] INT TERM HUP", f"the pass started with signals handled: {changes}")

    def test_a_failed_sign_in_still_hands_back_to_the_pass(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls, dest = run_download(d, login="fails")
            self.assertIn("pass-started", calls, "the safety pass was skipped")
            self.assertNotIn("rc=0", r.stdout)

    def test_a_copy_that_exits_like_a_failed_sign_in_is_still_its_own_result(self):
        with tempfile.TemporaryDirectory() as d:
            r, calls, dest = run_download(d, copy_exit=97)
            self.assertNotIn("could not sign in", r.stderr, "the copy's own exit was read as a failed sign-in")
            self.assertIn("pass-started", calls)
            self.assertFalse(os.path.lexists(os.path.join(dest, "link")))
            self.assertIn("rc=97", r.stdout)


if __name__ == "__main__":
    unittest.main()
