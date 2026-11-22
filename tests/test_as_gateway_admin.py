"""up.sh as_gateway_admin: each of its own steps is checked, even when a caller runs it with `||`.

`as_gateway_admin is_member "$sub" || rc=$?` switches set -e off inside the function and its subshell, so a failed
step went unnoticed: the call ran without a sign-in, or the gateway's setup client stayed switched on after it.
Here the function runs from up.sh exactly, in that `||` context, with Keycloak's script, NVIDIA's CLI and the port
probe stubbed.
"""
import os
import re
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
META = ".config/openshell/gateways/ekka-agent-desks/metadata.json"   # where 0.1.9 reads a registration
# A `gateway add` keeps what it was given under $HOME/.config/openshell, as NVIDIA's CLI does (metadata.rs), so a
# version of up.sh that still calls it is measured on what it then does, not on a stub that refuses it.
META_SH = 'mkdir -p "$HOME/.config/openshell/gateways/ekka-agent-desks"; printf \'{"gateway_endpoint":"%s","auth_mode":"oidc","oidc_issuer":"%s","oidc_client_id":"%s"}\' "$3" "$7" "$9" > "$HOME/.config/openshell/gateways/ekka-agent-desks/metadata.json"'


def function(text=None):
    if text is None:
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
    return re.search(r"^as_gateway_admin\(\) \{.*?^\}\n", text, re.S | re.M).group(0)


def run(action="echo did-the-call; return 0", on="ok", login="ok", off="ok", fn=None):
    d = tempfile.mkdtemp()
    log = os.path.join(d, "log")
    stubs = os.path.join(d, "bin")
    os.mkdir(stubs)
    with open(os.path.join(stubs, "openssl"), "w") as f:
        f.write("#!/bin/sh\nexit 0\n")   # the gateway answers on 8080 at once
    with open(os.path.join(stubs, "os"), "w") as f:
        f.write(f'#!/bin/sh\necho "os $*" >> "{log}"\n'
                f'case "$1 $2" in "gateway login") [ -e "$HOME/{META}" ] && [ "$LOGIN" = ok ] || exit 1 ;;\n'
                f'  "gateway add") {META_SH} ;; esac\nexit 0\n')   # login needs a registration in its home
    for name in ("openssl", "os"):
        os.chmod(os.path.join(stubs, name), 0o755)
    script = f"""
set -euo pipefail
DESKS_STATE={d}; OS={stubs}/os; NAME=desks.example.com
die() {{ echo "die: $*" >&2; exit 1; }}
install_cli() {{ :; }}
getent() {{ return 0; }}
kc() {{ echo "kc $*" >> {log}
  case "$1 $2" in
    "setup-client on") case "$ON" in ok) printf 'c-setup\nthe-secret' ;; named) printf 'c-setup\n'; return 1 ;;
                                     whole-then-failed) printf 'c-setup\nthe-secret'; return 1 ;; *) return 1 ;; esac ;;
    "setup-client off") [ "$OFF" = ok ] || return 1 ;;
    "setup-client status") echo disabled ;;
  esac; }}
action() {{ {action}; }}
{fn if fn is not None else function()}
rc=0; as_gateway_admin action || rc=$?
echo "rc=$rc"
"""
    env = dict(os.environ, PATH=stubs + os.pathsep + os.environ["PATH"], ON=on, LOGIN=login, OFF=off)
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
    with open(log) as f:
        calls = f.read().splitlines()
    return r, calls


class EachStepIsChecked(unittest.TestCase):
    def test_a_call_runs_signed_in_and_the_setup_client_is_switched_off_after(self):
        r, calls = run()
        self.assertIn("did-the-call", r.stdout)
        self.assertIn("rc=0", r.stdout)
        self.assertEqual(calls[-2:], ["kc setup-client off c-setup", "kc setup-client status c-setup"],
                         "this very client switched off, then read back by its id")

    def test_the_calls_own_answer_comes_back(self):
        r, _ = run(action="return 1")
        self.assertIn("rc=1", r.stdout, "1 is the member check's 'a list that answered does not name them'")

    def test_a_failed_sign_in_never_runs_the_call(self):
        r, calls = run(login="fails")
        self.assertNotIn("did-the-call", r.stdout)
        # 69 goes back to the caller (whose own cleanup runs): never an answer of the call, which did not run.
        self.assertIn("rc=69", r.stdout)
        self.assertIn("could not sign in to NVIDIA's gateway", r.stderr)
        self.assertIn("kc setup-client off c-setup", calls, "switched off even then")

    def test_a_setup_client_that_is_not_switched_on_runs_nothing(self):
        r, calls = run(on="fails")
        self.assertNotIn("did-the-call", r.stdout)
        self.assertIn("did not switch the gateway's setup client on", r.stderr)
        self.assertFalse(any(c.startswith("os ") for c in calls))

    def test_a_failed_switch_on_that_cannot_be_undone_is_said(self):
        # `on` enables the client before reading its secret: if both it and the `off` after it fail, the client may
        # still be enabled, and the message must not say nothing changed.
        r, _ = run(on="fails", off="fails")
        self.assertNotIn("did-the-call", r.stdout)
        self.assertIn("may still be switched on", r.stderr)
        self.assertNotIn("nothing was changed", r.stderr)

    def test_a_failed_switch_on_is_still_read_back_when_the_switch_off_fails(self):
        r, calls = run(on="fails", off="fails")
        self.assertIn("kc setup-client status", calls, "the read-back was skipped because the switch-off failed")
        self.assertIn("may still be switched on", r.stderr)

    def test_a_switch_on_that_failed_after_naming_its_client_switches_off_that_client(self):
        # `on` wrote the id line, then failed before the secret: the switch-off and its read-back use that id.
        r, calls = run(on="named")
        self.assertIn("kc setup-client off c-setup", calls)
        self.assertIn("kc setup-client status c-setup", calls)
        self.assertNotIn("did-the-call", r.stdout)
        self.assertIn("nothing was changed", r.stderr)

    def test_a_switch_on_that_failed_after_writing_both_lines_never_signs_in(self):
        # `on` exits 0 only once the client is enabled whole: its exit status counts, not only what it wrote.
        r, calls = run(on="whole-then-failed")
        self.assertFalse([c for c in calls if c.startswith("os gateway login")], "it signed in after a failed switch-on")
        self.assertNotIn("did-the-call", r.stdout)
        self.assertIn("kc setup-client off c-setup", calls)
        self.assertIn("kc setup-client status c-setup", calls)

    def test_a_setup_client_left_on_is_never_reported_as_done(self):
        # The caller gets control back (its own cleanup still runs), with 70: never an answer of the call it guards.
        r, _ = run(off="fails")
        self.assertIn("did-the-call", r.stdout)
        self.assertIn("rc=70", r.stdout)
        self.assertIn("may still be switched on", r.stderr)

    def test_planted_the_unchecked_steps_pass_a_failed_sign_in_and_a_client_left_on(self):
        old = function().replace('if (( signin == 1 && interrupted == 0 )); then', 'if (( interrupted == 0 )); then') \
                        .replace('(( client_off == 1 && home_gone == 1 )) || return 70', ':')
        self.assertNotEqual(old, function())
        r, _ = run(login="fails", fn=old)
        self.assertIn("did-the-call", r.stdout, "PLANTED: without the check the call ran with no sign-in")
        r, _ = run(off="fails", fn=old)
        self.assertIn("rc=0", r.stdout, "PLANTED: without the check a client left on reported done")


if __name__ == "__main__":
    unittest.main()
