"""sudo ekka desk revoke <username> (the installer's revoke verb): a person taken off the desks.

Runner 0.1.111 refuses `ekka desk access remove` and names this command: a person's sign-in only reads, and
membership changes on the desk backend's machine. Keycloak's side runs here against a fake admin API; up.sh's side
runs in bash with NVIDIA's CLI stubbed. The walk (tools/walk.sh) measures the real thing: the revoked person's next
read is refused.
"""
import copy
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "deploy", "keycloak"))
import apply_realm  # noqa: E402

with open(apply_realm.SPEC) as f:
    SPEC = json.load(f)
REALM = apply_realm.realm_path(SPEC)
PERSON = "0a0b0c0d-1111-4222-8333-444455556666"
ADMIN = "9a9b9c9d-1111-4222-8333-444455556666"


class FakeKeycloak:
    """The admin API calls `person` and `revoke` make: one person, one administrator, two clients."""

    def __init__(self, enabled=True, online=1, offline=1, person_admin_via_group=False, roles_unreadable=False,
                 roles_malformed=False, admin_enabled=True):
        self.users = {
            PERSON: {"id": PERSON, "username": "pat", "email": "pat@example.com", "enabled": enabled,
                     "emailVerified": True, "attributes": {"team": ["desks"]}},
            ADMIN: {"id": ADMIN, "username": "boss", "email": "boss@example.com", "enabled": admin_enabled},
        }
        self.online = [{"id": f"on-{i}"} for i in range(online)]
        self.offline = {"c-cli": [{"id": f"off-{i}"} for i in range(offline)], "c-other": []}
        self.writes = []
        # Effective realm roles: the administrator's directly; the person's only through a group when asked.
        self.effective = {ADMIN: ["openshell-admin"],
                          PERSON: ["openshell-user"] + (["openshell-admin"] if person_admin_via_group else [])}
        self.roles_unreadable = roles_unreadable
        self.roles_malformed = roles_malformed

    def get(self, path):
        m = re.fullmatch(re.escape(REALM) + r"/users\?exact=true&username=(.+)", path)
        if m:
            return [copy.deepcopy(u) for u in self.users.values() if u["username"] == m.group(1)]
        m = re.fullmatch(re.escape(REALM) + r"/users/([0-9a-f-]{36})", path)
        if m:
            return copy.deepcopy(self.users.get(m.group(1)))
        if path == REALM + "/roles/openshell-admin/users?max=10000":   # DIRECT holders only, as Keycloak answers it
            return None if self.roles_unreadable else [{"id": ADMIN, "username": "boss"}]
        m = re.fullmatch(re.escape(REALM) + r"/users/([0-9a-f-]{36})/role-mappings/realm/composite", path)
        if m:
            if self.roles_malformed:
                return self.roles_malformed if isinstance(self.roles_malformed, list) else [None, {"id": "no-name"}]
            return None if self.roles_unreadable else [{"name": r} for r in self.effective.get(m.group(1), [])]
        if path == REALM + "/clients?max=1000":
            return [{"id": "c-cli", "clientId": "ekka-cli"}, {"id": "c-other", "clientId": "other"}]
        if path == REALM + f"/users/{PERSON}/sessions":
            return list(self.online)
        m = re.fullmatch(re.escape(REALM) + rf"/users/{PERSON}/offline-sessions/(c-[a-z]+)", path)
        if m:
            return list(self.offline[m.group(1)])
        raise AssertionError("unexpected GET " + path)

    def write(self, method, path, body):
        self.writes.append((method, path, copy.deepcopy(body)))
        m = re.fullmatch(re.escape(REALM) + r"/users/([0-9a-f-]{36})", path)
        if method == "PUT" and m:
            self.users[m.group(1)] = body   # Keycloak keeps exactly what was sent
            return None
        if method == "DELETE" and path.startswith(REALM + "/sessions/"):
            sid = path.rsplit("/", 1)[1].split("?")[0]
            if path.endswith("?isOffline=true"):
                for c in self.offline.values():
                    c[:] = [s for s in c if s["id"] != sid]
            else:
                self.online = [s for s in self.online if s["id"] != sid]
            return None
        if method == "PUT" and path.endswith("/reset-password"):
            return None
        raise AssertionError(f"unexpected {method} {path}")


def call(kc, *argv, password_file=None):
    old = apply_realm.Api
    apply_realm.Api = lambda: kc
    env_old = os.environ.get("KC_PERSON_PASSWORD_FILE")
    if password_file:
        os.environ["KC_PERSON_PASSWORD_FILE"] = password_file
    out = io.StringIO()
    try:
        with redirect_stdout(out):
            try:
                rc = apply_realm.main(list(argv))
            except SystemExit as e:
                return e.code, out.getvalue()
        return rc, out.getvalue()
    finally:
        apply_realm.Api = old
        if password_file:
            if env_old is None:
                os.environ.pop("KC_PERSON_PASSWORD_FILE", None)
            else:
                os.environ["KC_PERSON_PASSWORD_FILE"] = env_old


class RevokeInKeycloak(unittest.TestCase):
    def test_a_person_is_disabled_first_then_every_session_ends_and_nothing_else_changes(self):
        kc = FakeKeycloak(online=2, offline=1)
        rc, out = call(kc, "revoke", "pat")
        self.assertEqual((rc, out.strip()), (0, PERSON), "prints the id the gateway's workspace uses")
        self.assertEqual(kc.writes[0][:2], ("PUT", f"{REALM}/users/{PERSON}"), "disabled before any session ends")
        self.assertFalse(kc.users[PERSON]["enabled"])
        self.assertEqual((kc.users[PERSON]["email"], kc.users[PERSON]["attributes"]),
                         ("pat@example.com", {"team": ["desks"]}), "the whole record went back, only enabled changed")
        self.assertEqual((kc.online, kc.offline["c-cli"]), ([], []), "online and offline sessions, every client")
        self.assertIn(("DELETE", f"{REALM}/sessions/off-0?isOffline=true", None), kc.writes)

    def test_running_it_again_changes_nothing(self):
        kc = FakeKeycloak(enabled=False, online=0, offline=0)
        rc, out = call(kc, "revoke", "pat")
        self.assertEqual((rc, out.strip(), kc.writes), (0, PERSON, []))

    def test_planted_an_administrator_is_refused_and_nothing_is_written(self):
        kc = FakeKeycloak()
        rc, _ = call(kc, "revoke", "boss")
        self.assertIn("is an administrator; nothing was changed", str(rc))
        self.assertEqual(kc.writes, [])
        self.assertTrue(kc.users[ADMIN]["enabled"])

    def test_planted_a_name_that_is_not_here_is_refused(self):
        kc = FakeKeycloak()
        rc, _ = call(kc, "revoke", "pta")
        self.assertIn("there is no person pta; nothing was changed", str(rc))
        self.assertEqual(kc.writes, [])


class InviteAfterRevoke(unittest.TestCase):
    def password(self):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write("a-one-time-password-1234")
        f.close()
        return f.name

    def test_a_revoked_person_is_enabled_again_with_a_new_one_time_password(self):
        kc = FakeKeycloak(enabled=False, online=0, offline=0)
        rc, out = call(kc, "person", "pat", "pat@example.com", password_file=self.password())
        self.assertEqual((rc, out.strip()), (0, PERSON), "the same id: the gateway re-adds the same subject")
        self.assertTrue(kc.users[PERSON]["enabled"])
        self.assertEqual(kc.users[PERSON]["email"], "pat@example.com")
        reset = [w for w in kc.writes if w[1].endswith("/reset-password")]
        self.assertEqual(reset, [("PUT", f"{REALM}/users/{PERSON}/reset-password",
                                  {"type": "password", "value": "a-one-time-password-1234", "temporary": True})])

    def test_a_disabled_administrator_is_never_enabled_again_here(self):
        # Disabled in the admin console, an administrator looks like a revoked person: no write, no new password.
        kc = FakeKeycloak(admin_enabled=False)
        rc, out = call(kc, "person", "boss", "boss@example.com", password_file=self.password())
        self.assertIn("boss is an administrator; nothing was changed", str(rc))
        self.assertEqual((kc.writes, out), ([], ""))

    def test_a_disabled_administrator_through_a_group_is_never_enabled_again_here(self):
        kc = FakeKeycloak(enabled=False, person_admin_via_group=True)
        rc, out = call(kc, "person", "pat", "pat@example.com", password_file=self.password())
        self.assertIn("pat is an administrator; nothing was changed", str(rc))
        self.assertEqual((kc.writes, out), ([], ""))

    def test_unreadable_roles_enable_no_one(self):
        kc = FakeKeycloak(enabled=False, roles_unreadable=True)
        rc, out = call(kc, "person", "pat", "pat@example.com", password_file=self.password())
        self.assertIn("could not read the person's roles", str(rc))
        self.assertEqual((kc.writes, out), ([], ""))

    def test_an_unclear_sign_in_flag_enables_no_one(self):
        for odd in (None, "false", 0):
            kc = FakeKeycloak(enabled=odd)
            rc, out = call(kc, "person", "pat", "pat@example.com", password_file=self.password())
            self.assertIn("could not read whether pat can sign in", str(rc), odd)
            self.assertEqual((kc.writes, out), ([], ""), odd)

    def test_a_person_still_enabled_is_refused_as_before(self):
        kc = FakeKeycloak()
        rc, _ = call(kc, "person", "pat", "pat@example.com", password_file=self.password())
        self.assertIn("pat already exists", str(rc))
        self.assertEqual(kc.writes, [])


# ── up.sh's side: its `revoke)` block, run in bash with Keycloak's script and NVIDIA's CLI stubbed ──
OS_STUB = r"""#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
open(os.environ["CALLS"], "a").write(json.dumps(a) + "\n")
if "remove" in a:
    sys.exit(0 if os.environ["REMOVE"] == "ok" else 1)
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


def revoke_block(text=None):
    if text is None:
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
    m = re.search(r"^  revoke\)  #.*?^    exit 0 ;;\n", text, re.S | re.M)
    assert m, "up.sh has no revoke) block"
    return m.group(0)


def run_revoke(args, keycloak_says=PERSON, remove="ok", listed="", block=None, helper="ok"):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "secrets", "people"))
    with open(os.path.join(d, "up.env"), "w") as f:
        f.write("DESKS_NAME=desks.example.com\n")
    pf = os.path.join(d, "secrets", "people", "pat-password")
    with open(pf, "w") as f:
        f.write("x")
    stub = os.path.join(d, "openshell")
    with open(stub, "w") as f:
        f.write(OS_STUB)
    os.chmod(stub, 0o755)
    calls = os.path.join(d, "calls.jsonl")
    script = f"""
set -euo pipefail
DESKS_STATE={d}; OS={stub}
ok() {{ echo "ok: $*"; }}
die() {{ echo "die: $*" >&2; exit 1; }}
id() {{ echo 0; }}
python3() {{ if [[ $* == *"apply_realm.py revoke"* ]]; then [[ $KC == fail ]] && {{ echo "keycloak: refused" >&2; return 1; }}; echo "$KC"
  elif [[ $* == *workspace_member.py* && $HELPER == crash ]]; then echo "Traceback: a crash" >&2; return 1
  else command python3 "$@"; fi; }}  # the installer's own helpers (tools/workspace_member.py) run for real
as_gateway_admin() {{ ( "$@" ); }}
set -- {' '.join(args)}
case "$1" in
{block if block is not None else revoke_block()}
esac
echo "fell through"
"""
    env = dict(os.environ, CALLS=calls, KC=keycloak_says, REMOVE=remove, LIST=listed, PERSON=PERSON, HELPER=helper)
    r = subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, env=env, timeout=30)
    seen = []
    if os.path.exists(calls):
        with open(calls) as f:
            seen = [json.loads(x) for x in f]
    return r, seen, os.path.exists(pf)


class RevokeInUpSh(unittest.TestCase):
    def test_the_person_leaves_the_desk_workspace_and_their_one_time_password_file(self):
        r, calls, pf_left = run_revoke(["revoke", "pat"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok: pat may no longer use desks", r.stdout)
        self.assertIn(["-g", "ekka-agent-desks", "workspace", "member", "remove", "--workspace", "desks",
                       "--subject", PERSON], calls)
        self.assertFalse(pf_left)

    def test_already_out_of_the_workspace_is_done_when_the_list_agrees(self):
        r, _, _ = run_revoke(["revoke", "pat"], remove="fails", listed="someone-else")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_planted_a_failed_remove_with_the_person_still_listed_stops(self):
        r, _, pf_left = run_revoke(["revoke", "pat"], remove="fails", listed=PERSON)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("may still be in the desk workspace", r.stderr)
        self.assertTrue(pf_left, "nothing reports done")

    def test_planted_a_list_that_fails_is_never_read_as_not_a_member(self):
        r, _, _ = run_revoke(["revoke", "pat"], remove="fails", listed="fails")
        self.assertNotEqual(r.returncode, 0, "a list that did not answer must not count as 'not a member'")
        self.assertIn("may still be in the desk workspace", r.stderr)

    def test_planted_a_list_that_answers_no_member_list_is_never_read_as_not_a_member(self):
        # Empty, null, not JSON, or an error object: a failed remove is not done because the answer named no one.
        for listed in ("empty", "null", "garbage", "error", "errors-array", "null-member", "null-members", "no-subject", "more-pages", "deep",
                       "no-token", "null-token", "no-role", "null-role", "with-error",
                       "repeated-token", "repeated-subject",
                       "nul", "bad-utf8", "surrogate"):
            r, _, pf_left = run_revoke(["revoke", "pat"], remove="fails", listed=listed)
            self.assertNotEqual(r.returncode, 0, listed)
            self.assertIn("may still be in the desk workspace", r.stderr, listed)
            self.assertTrue(pf_left, listed)

    def test_planted_a_helper_that_crashes_is_never_read_as_not_a_member(self):
        # Python exits 1 on a crash: only the printed word "absent" makes a failed remove done.
        r, _, pf_left = run_revoke(["revoke", "pat"], remove="fails", listed="someone-else", helper="crash")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("may still be in the desk workspace", r.stderr)
        self.assertTrue(pf_left)

    def test_a_subject_inside_a_longer_value_is_not_the_person(self):
        r, _, _ = run_revoke(["revoke", "pat"], remove="fails", listed="named-inside")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_planted_keycloak_refusing_changes_nothing_at_the_gateway(self):
        r, calls, pf_left = run_revoke(["revoke", "boss"], keycloak_says="fail")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(calls, [])
        self.assertTrue(pf_left)

    def test_planted_a_bad_name_or_a_second_word_is_refused_before_anything(self):
        for args in (["revoke"], ["revoke", "Pat!"], ["revoke", "pat", "extra"]):
            r, calls, _ = run_revoke(args)
            self.assertNotEqual(r.returncode, 0, args)
            self.assertIn("usage: sudo ekka desk revoke <username>", r.stderr)
            self.assertEqual(calls, [])

    def test_planted_without_the_remove_the_person_stays_and_revoke_stops(self):
        block = revoke_block()
        line = '      "$OS" -g ekka-agent-desks workspace member remove --workspace desks --subject "$1" >/dev/null 2>&1 && return 0\n'
        self.assertEqual(block.count(line), 1)
        r, _, _ = run_revoke(["revoke", "pat"], listed=PERSON, block=block.replace(line, ""))
        self.assertNotEqual(r.returncode, 0)


class TheAdministratorCheckFailsClosed(unittest.TestCase):
    """An administrator by any route (directly, a group, a composite role) is never revoked, and a role lookup that
    does not answer stops the command instead of reading as "not an administrator"."""

    def test_an_administrator_through_a_group_is_not_revoked(self):
        kc = FakeKeycloak(person_admin_via_group=True)
        rc, out = call(kc, "revoke", "pat")
        self.assertIn("is an administrator; nothing was changed", str(rc))
        self.assertEqual((kc.writes, out), ([], ""))

    def test_malformed_role_entries_stop_revoke_with_nothing_written(self):
        kc = FakeKeycloak(roles_malformed=True)
        rc, out = call(kc, "revoke", "pat")
        self.assertIn("could not read the person's roles", str(rc))
        self.assertEqual((kc.writes, out), ([], ""))

    def test_a_role_with_an_empty_name_stops_revoke_with_nothing_written(self):
        kc = FakeKeycloak(roles_malformed=[{"name": "openshell-user"}, {"name": ""}])
        rc, out = call(kc, "revoke", "pat")
        self.assertIn("could not read the person's roles", str(rc))
        self.assertEqual((kc.writes, out), ([], ""))

    def test_unreadable_roles_stop_revoke_with_nothing_written(self):
        kc = FakeKeycloak(roles_unreadable=True)
        rc, out = call(kc, "revoke", "pat")
        self.assertIn("could not read the person's roles", str(rc))
        self.assertEqual((kc.writes, out), ([], ""))

if __name__ == "__main__":
    unittest.main()
