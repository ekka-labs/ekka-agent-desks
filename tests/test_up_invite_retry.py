"""sudo ekka desk invite <username> <email>: a retry finishes an invite that stopped half-way.

An invite makes the person's sign-in account in Keycloak, then adds them to the desk workspace. When the second step
failed, the installer said "run invite again", but the rerun stopped at once with "invited already", because the
one-time password file was kept; and Keycloak refuses a second account for the same name (review of
ekka-labs/ekka-agent-desks#1). A rerun now looks the account up (`apply_realm.py person-id`), reads the workspace,
and adds the person if it does not hold them. Someone fully invited is still refused, as before.
"""
import json
import os
import re
import subprocess
import tempfile
import unittest

from test_up_revoke import PERSON, ROOT, FakeKeycloak, call

OS_STUB = r"""#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
open(os.environ["CALLS"], "a").write(json.dumps(a) + "\n")
if "add" in a:
    sys.exit(0 if os.environ["ADD"] == "ok" else 1)
if "list" in a:
    # A list that fails, or answers something that is not one whole member list; else, as NVIDIA's CLI 0.1.4 prints
    # it, the members named in LIST.
    odd = {"empty": "", "null": "null", "garbage": "not json at all", "error": '{"error": "upstream timeout"}',
           "errors-array": '{"errors": []}', "null-member": '{"members": [null], "next_page_token": ""}',
           "null-members": '{"members": null, "warnings": []}',
           "no-subject": '{"members": [{"role": "user"}], "next_page_token": ""}',
           "more-pages": '{"members": [{"subject": "someone-else", "role": "user"}], "next_page_token": "p2"}',
           "deep": "[" * 600 + "]" * 600,
           "no-token": '{"members": []}', "null-token": '{"members": [], "next_page_token": null}',
           "no-role": '{"members": [{"subject": "someone-else"}], "next_page_token": ""}',
           "null-role": '{"members": [{"subject": "someone-else", "role": null}], "next_page_token": ""}',
           "with-error": '{"members": [], "next_page_token": "", "error": "partial answer"}',
           "repeated-token": '{"members": [], "next_page_token": "p2", "next_page_token": ""}',
           "repeated-subject": '{"members": [{"subject": "%s", "subject": "someone-else", "role": "user"}], '
                               '"next_page_token": ""}' % os.environ.get("PERSON", ""),
           "named-inside": '{"members": [{"subject": "x-%s-y", "role": "user"}], "next_page_token": ""}'
                           % os.environ.get("PERSON", "")}
    raw = {"nul": b'{"members": [], "next_page_token": ""}\x00\n',
           "bad-utf8": b'{"members": [{"subject": "\xff", "role": "user"}], "next_page_token": ""}\n',
           "surrogate": b'{"members": [{"subject": "\\ud800", "role": "user"}], "next_page_token": ""}\n'}
    if os.environ["LIST"] == "fails": sys.exit(1)
    if os.environ["LIST"] in raw:  # bytes as written: a shell variable would drop the NUL before the check saw it
        sys.stdout.buffer.write(raw[os.environ["LIST"]]); sys.exit(0)
    if os.environ["LIST"] in odd:
        print(odd[os.environ["LIST"]]); sys.exit(0)
    print(json.dumps({"members": [{"subject": s, "role": "user"} for s in os.environ["LIST"].split(",") if s],
                      "next_page_token": ""}))
"""


def invite_block(text=None):
    if text is None:
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
    m = re.search(r"^  invite\)  #.*?^    exit 0 ;;\n", text, re.S | re.M)
    assert m, "up.sh has no invite) block"
    return m.group(0)


def run_invite(invited_before, listed="", add="ok", block=None, helper="ok"):
    """Run up.sh's invite) block for pat with Keycloak's script and NVIDIA's CLI stubbed."""
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "secrets", "people"))
    os.makedirs(os.path.join(d, "people"))
    with open(os.path.join(d, "up.env"), "w") as f:
        f.write("DESKS_NAME=desks.example.com\n")
    pf = os.path.join(d, "secrets", "people", "pat-password")
    if invited_before:
        with open(pf, "w") as f:
            f.write("the-first-one-time-password")
    stub = os.path.join(d, "openshell")
    with open(stub, "w") as f:
        f.write(OS_STUB)
    os.chmod(stub, 0o755)
    calls, kc_calls = os.path.join(d, "calls.jsonl"), os.path.join(d, "kc")
    script = f"""
set -euo pipefail
DESKS_STATE={d}; OS={stub}
ok() {{ echo "ok: $*"; }}
die() {{ echo "die: $*" >&2; exit 1; }}
id() {{ echo 0; }}
python3() {{ case "$*" in
    *"apply_realm.py person-id"*|*"apply_realm.py person "*) echo "$*" >> {kc_calls}; echo {PERSON} ;;
    *apply_realm.py*) echo "$*" >> {kc_calls} ;;
    *workspace_member.py*) if [[ $HELPER == crash ]]; then echo "Traceback: a crash" >&2; return 1; fi
      command python3 "$@" ;;
    *) command python3 "$@" ;;  # the installer's own helpers (tools/workspace_member.py) run for real
  esac; }}
as_gateway_admin() {{ ( "$@" ); }}
set -- invite pat pat@example.com
case "$1" in
{block if block is not None else invite_block()}
esac
echo "fell through"
"""
    env = dict(os.environ, CALLS=calls, ADD=add, LIST=listed, PERSON=PERSON, HELPER=helper)
    r = subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, env=env, timeout=30)
    seen = []
    if os.path.exists(calls):
        with open(calls) as f:
            seen = [json.loads(x) for x in f]
    kc = []
    if os.path.exists(kc_calls):
        with open(kc_calls) as f:
            kc = f.read().splitlines()
    password = None
    if os.path.exists(pf):
        with open(pf) as f:
            password = f.read()
    return r, seen, kc, password


ADDED = ["-g", "ekka-agent-desks", "workspace", "member", "add", "--workspace", "desks", "--subject", PERSON,
         "--role", "user"]


def a_retry_finishes_the_invite(block=None):
    r, calls, kc, password = run_invite(invited_before=True, listed="someone-else", block=block)
    return (r.returncode == 0 and ADDED in calls and "ok: pat (pat@example.com) may use desks" in r.stdout
            and password == "the-first-one-time-password" and not any("person pat" in k for k in kc))


class PersonIdInKeycloak(unittest.TestCase):
    def test_an_enabled_person_is_named_by_id_and_nothing_is_written(self):
        kc = FakeKeycloak()
        rc, out = call(kc, "person-id", "pat")
        self.assertEqual((rc, out.strip(), kc.writes), (0, PERSON, []))

    def test_a_name_that_is_not_here_is_refused(self):
        rc, _ = call(FakeKeycloak(), "person-id", "pta")
        self.assertIn("no sign-in account named pta", str(rc))

    def test_a_revoked_person_is_refused(self):
        rc, _ = call(FakeKeycloak(enabled=False), "person-id", "pat")
        self.assertIn("is revoked", str(rc))

    def test_an_administrator_is_not_named(self):
        rc, out = call(FakeKeycloak(), "person-id", "boss")
        self.assertIn("is an administrator", str(rc))
        self.assertEqual(out, "", "a refusal prints no id")

    def test_an_administrator_through_a_group_is_not_named(self):
        rc, out = call(FakeKeycloak(person_admin_via_group=True), "person-id", "pat")
        self.assertIn("is an administrator", str(rc))
        self.assertEqual(out, "")

    def test_malformed_role_entries_name_no_one(self):
        rc, out = call(FakeKeycloak(roles_malformed=True), "person-id", "pat")
        self.assertIn("could not read the person's roles", str(rc))
        self.assertEqual(out, "")

    def test_a_role_with_an_empty_name_names_no_one(self):
        rc, out = call(FakeKeycloak(roles_malformed=[{"name": ""}]), "person-id", "pat")
        self.assertIn("could not read the person's roles", str(rc))
        self.assertEqual(out, "")

    def test_a_disabled_administrator_is_named_an_administrator_not_revoked(self):
        # "revoked, invite again" would lead the operator to re-enable an administrator.
        rc, out = call(FakeKeycloak(admin_enabled=False), "person-id", "boss")
        self.assertIn("is an administrator", str(rc))
        self.assertEqual(out, "")

    def test_an_unclear_sign_in_flag_names_no_one(self):
        # Keycloak always sends a boolean; anything else (missing, null, a string) is never read as "can sign in".
        for odd in (None, "true", 1):
            rc, out = call(FakeKeycloak(enabled=odd), "person-id", "pat")
            self.assertIn("could not read whether pat can sign in", str(rc), odd)
            self.assertEqual(out, "", odd)

    def test_unreadable_roles_name_no_one(self):
        rc, out = call(FakeKeycloak(roles_unreadable=True), "person-id", "pat")
        self.assertIn("could not read the person's roles", str(rc))
        self.assertEqual(out, "")


class InviteRetryInUpSh(unittest.TestCase):
    def test_a_first_invite_makes_the_account_and_adds_the_person(self):
        r, calls, kc, password = run_invite(invited_before=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(ADDED, calls)
        self.assertTrue(any("apply_realm.py person pat pat@example.com" in k for k in kc), kc)
        self.assertTrue(password)

    def test_a_retry_after_a_failed_workspace_step_finishes_it(self):
        self.assertTrue(a_retry_finishes_the_invite())

    def test_someone_fully_invited_is_refused_as_before(self):
        r, calls, _, password = run_invite(invited_before=True, listed=PERSON)
        self.assertEqual(r.returncode, 1)
        self.assertIn("pat was invited already", r.stderr)
        self.assertNotIn(ADDED, calls)
        self.assertEqual(password, "the-first-one-time-password")

    def test_a_workspace_that_cannot_be_read_stops_and_adds_no_one(self):
        r, calls, _, _ = run_invite(invited_before=True, listed="fails")
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not be read", r.stderr)
        self.assertNotIn(ADDED, calls)

    def test_a_list_that_answers_no_member_list_stops_and_adds_no_one(self):
        # Empty, null, not JSON, or an error object: never read as "the workspace does not hold pat".
        for listed in ("empty", "null", "garbage", "error", "errors-array", "null-member", "null-members", "no-subject", "more-pages", "deep",
                       "no-token", "null-token", "no-role", "null-role", "with-error",
                       "repeated-token", "repeated-subject",
                       "nul", "bad-utf8", "surrogate"):
            r, calls, _, _ = run_invite(invited_before=True, listed=listed)
            self.assertEqual(r.returncode, 1, listed)
            self.assertIn("could not be read", r.stderr, listed)
            self.assertNotIn(ADDED, calls, listed)

    def test_planted_a_helper_that_crashes_adds_no_one(self):
        # Python exits 1 on a crash, the code a bare exit-code check would read as "not a member".
        r, calls, _, _ = run_invite(invited_before=True, listed="someone-else", helper="crash")
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not be read", r.stderr)
        self.assertNotIn(ADDED, calls)

    def test_planted_the_old_substring_check_adds_someone_on_an_empty_answer(self):
        block = invite_block()
        start = block.index("        local found  #")
        end = block.index("esac  # only the printed word counts\n") + len("esac  # only the printed word counts\n")
        old = block[:start] + ('        local members\n'
                               '        members=$("$OS" -g ekka-agent-desks workspace member list --workspace desks '
                               '--page-size 10000 -o json) || return 2\n'
                               '        grep -qF -- "$1" <<<"$members"\n') + block[end:]
        self.assertNotEqual(old, invite_block(), "the plant must change the block")
        r, calls, _, _ = run_invite(invited_before=True, listed="empty", block=old)
        self.assertIn(ADDED, calls, "PLANTED: the old check must add someone on an empty answer, or this test proves nothing")

    def test_planted_the_old_invite_cannot_finish_a_retry(self):
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
        old = re.sub(r"^    if \[\[ -e \$pf \]\]; then\n.*?^    fi\n",
                     '    [[ -e $pf ]] && die "$who was invited already; their one-time password: sudo cat $pf"\n'
                     "    ( umask 077; openssl rand -base64 24 | tr -d '\\n' > \"$pf\" )\n", invite_block(text),
                     flags=re.S | re.M)
        self.assertNotEqual(old, invite_block(text), "the plant must change the block")
        self.assertFalse(a_retry_finishes_the_invite(block=old), "PLANTED: the old invite passes the retry check")


if __name__ == "__main__":
    unittest.main()
