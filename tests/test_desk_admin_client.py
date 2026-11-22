"""The backend adapter's desk-admin client, and its secret into the Enclave's vault.

`apply_realm.py admin-client on` makes the confidential client `ekka-desk-admin`: a service account with the
openshell-admin role and exactly the desk administration scopes, never openshell:all. Its secret leaves Keycloak
only into a pipe, and up.sh's connect_desk_admin pipes it into `ekka api connect desks --stdin` inside the Enclave,
so it is never a file, an argument or a terminal.
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
SECRET = "s3cr3t-value-never-on-disk"


class FakeKeycloak:
    """The admin API calls `admin-client` makes, over a live realm without the client."""

    def __init__(self):
        self.scopes = [{"id": f"s-{n}", "name": n} for n in
                       ("openshell:all", "sandbox:read", "sandbox:write", "provider:read", "workspace:read", "config:read")]
        self.client = None
        self.defaults = set()
        self.roles = []

    def get(self, path):
        if path == REALM:
            return {"realm": "ekka-desks"}
        if path == REALM + "/client-scopes":
            return list(self.scopes)
        if path.startswith(REALM + "/clients?clientId="):
            # A copy, as an HTTP answer is: a change to it reaches Keycloak only through a write.
            return [copy.deepcopy(self.client)] if self.client and path.endswith("=" + apply_realm.ADMIN_CLIENT) else []
        if path == REALM + "/clients/c-admin/default-client-scopes":
            return [s for s in self.scopes if s["name"] in self.defaults]
        if path == REALM + "/clients/c-admin/service-account-user":
            return {"id": "u-sa"}
        if path == REALM + "/roles/openshell-admin":
            return {"name": "openshell-admin"}
        if path.startswith(REALM + "/clients/c-admin/user-sessions"):
            return []
        if path.startswith(REALM + "/clients/c-admin/offline-sessions"):
            return []
        if path == REALM + "/clients/c-admin/client-secret":
            return {"value": SECRET}
        raise AssertionError("unexpected GET " + path)

    def write(self, method, path, body):
        m = re.fullmatch(re.escape(REALM) + r"/clients/c-admin/default-client-scopes/s-(.+)", path)
        if path == REALM + "/clients" and method == "POST":
            self.client = {"id": "c-admin", **body}
        elif path == REALM + "/clients/c-admin" and method == "PUT":
            # As Keycloak 26.7.4 does (measured): a field the update leaves out keeps its value, named attributes
            # merge, and an attribute set to "" is removed.
            attrs = {**self.client.get("attributes", {}), **body.get("attributes", {})}
            attrs = {k: v for k, v in attrs.items() if v != ""}
            self.client = {**self.client, **body, "attributes": attrs}
        elif path == REALM + "/users/u-sa/role-mappings/realm" and method == "POST":
            self.roles += [r["name"] for r in body]
        elif path == REALM + "/client-scopes" and method == "POST":
            self.scopes.append({"id": "s-" + body["name"], "name": body["name"]})
        elif m and method == "PUT":
            self.defaults.add(m.group(1))
        elif m and method == "DELETE":
            self.defaults.discard(m.group(1))
        else:
            raise AssertionError(f"unexpected {method} {path}")


class Piped(io.StringIO):
    def isatty(self):
        return False


def run(argv, kc):
    real = apply_realm.Api
    apply_realm.Api = lambda: kc
    out = Piped()
    try:
        with redirect_stdout(out):
            code = apply_realm.main(argv)
    finally:
        apply_realm.Api = real
    return code, out.getvalue()


class TheAdminClient(unittest.TestCase):
    def test_holds_exactly_the_desk_administration_it_performs(self):
        kc = FakeKeycloak()
        code, out = run(["admin-client", "on"], kc)
        self.assertEqual(code, 0)
        self.assertEqual(sorted(kc.defaults), apply_realm.ADMIN_SCOPES)
        self.assertNotIn("openshell:all", kc.defaults)
        self.assertEqual(kc.roles, ["openshell-admin"])
        c = kc.client
        self.assertEqual((c["clientId"], c["publicClient"], c["serviceAccountsEnabled"], c["enabled"]),
                         ("ekka-desk-admin", False, True, True))
        self.assertFalse(c["standardFlowEnabled"] or c["directAccessGrantsEnabled"] or c["implicitFlowEnabled"],
                         "a service account only: no person signs in as it")
        self.assertEqual(out, SECRET, "the secret, and nothing else, into the pipe")

    def test_turning_it_on_finishes_an_owed_sign_out_and_leaves_none_owed(self):
        # A run that stopped while ending the adapter's sessions left the marker; `on` ends them and clears it,
        # and its own enable must not write the marker back from the copy it read first.
        kc = FakeKeycloak()
        run(["admin-client", "on"], kc)
        kc.client["attributes"][apply_realm.SIGN_OUT_OWED] = "pending"
        run(["admin-client", "on"], kc)
        self.assertNotIn(apply_realm.SIGN_OUT_OWED, kc.client["attributes"])
        self.assertIs(kc.client["enabled"], True)

    def test_creates_the_write_scopes_a_live_realm_lacks(self):
        kc = FakeKeycloak()
        run(["admin-client", "on"], kc)
        self.assertIn("config:write", {s["name"] for s in kc.scopes})

    def test_its_scopes_are_exactly_the_five_the_adapters_calls_need(self):
        # Written here from OpenShell 0.1.4's annotations, never read from the code under test (scope review).
        # config:read since desk backend v0.1.6: GetSandboxConfig (the approval mode read back after it is set),
        # GetDraftPolicy and GetDraftHistory (a discovery desk's evidence). Without it the read-back was refused
        # (PermissionDenied, a box, 5 Nov 2026). Still read-only: no wider scope is granted.
        kc = FakeKeycloak()
        run(["admin-client", "on"], kc)
        self.assertEqual(sorted(kc.defaults), ["config:read", "config:write", "provider:read", "sandbox:read", "sandbox:write"])
        for wider in ("provider:write", "workspace:read", "workspace:write", "openshell:all"):
            self.assertNotIn(wider, kc.defaults, f"{wider}: more than the adapter's calls need")

    def test_refuses_to_print_its_secret_to_a_terminal(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        kc, err = FakeKeycloak(), io.StringIO()
        real_out, real_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = Tty(), err
        try:
            self.assertEqual(apply_realm.main(["admin-client", "on"]), 2)
        finally:
            sys.stdout, sys.stderr = real_out, real_err
        self.assertIsNone(kc.client)
        self.assertNotIn(SECRET, err.getvalue())

    def test_off_disables_it_and_prints_no_secret(self):
        kc = FakeKeycloak()
        run(["admin-client", "on"], kc)
        code, out = run(["admin-client", "off"], kc)
        self.assertEqual(code, 0)
        self.assertIs(kc.client["enabled"], False)
        self.assertNotIn(SECRET, out)


def up_function(name):
    with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.S | re.M)
    assert m, f"{name} is not in up.sh"
    return m.group(0)


class ConnectDeskAdmin(unittest.TestCase):
    def run_it(self, kc_rc=0):
        state, seen = tempfile.mkdtemp(), tempfile.mkdtemp()
        os.makedirs(os.path.join(state, "deploy"))
        script = f"""
set -euo pipefail
DESKS_STATE={state}
ok() {{ echo "ok: $*"; }}
die() {{ echo "die: $*" >&2; exit 1; }}
kc() {{ printf '%s' "$KC_SECRET"; return {kc_rc}; }}
ekka_in() {{ printf '%s\\n' "$@" > {seen}/args; cat > {seen}/stdin; }}
cd {state}
{up_function("connect_desk_admin")}
connect_desk_admin
"""
        r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30,
                           stdin=subprocess.DEVNULL, env=dict(os.environ, KC_SECRET=SECRET))
        def read(name):
            path = os.path.join(seen, name)
            if not os.path.exists(path):
                return ""
            with open(path) as fh:
                return fh.read()
        args, stdin = read("args").split("\n"), read("stdin")
        return r, args, stdin, state

    def test_the_secret_reaches_the_vault_through_stdin_only(self):
        r, args, stdin, state = self.run_it()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(stdin, SECRET)
        self.assertEqual(args[:7], ["api", "connect", "desks", "--input",
                                   "socket=/run/ekka-backend/backend.sock", "--reach", "loopback"])
        self.assertIn("--stdin", args)
        self.assertNotIn(SECRET, " ".join(args), "never an argument")
        self.assertNotIn(SECRET, r.stdout + r.stderr, "never printed")
        for root, _, files in os.walk(state):
            for f in files:
                with open(os.path.join(root, f), errors="ignore") as fh:
                    self.assertNotIn(SECRET, fh.read(), f"the secret is on disk in {f}")

    def test_python_writer_finishes_when_connect_returns_without_reading(self):
        for result in (0, 1):
            with self.subTest(result=result):
                script = f"""
set -euo pipefail
ok() {{ :; }}
die() {{ echo "$*" >&2; exit 1; }}
kc() {{ python3 -c 'import sys; sys.stdout.write("example-credential" * 100000); sys.stdout.flush()'; }}
ekka_in() {{ echo "connect returned" >&2; return {result}; }}
{up_function("connect_desk_admin")}
connect_desk_admin
"""
                r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, result, r.stderr)
                self.assertNotIn("BrokenPipeError", r.stderr)
                self.assertNotIn("example-credential", r.stdout + r.stderr)
                if result:
                    self.assertIn("connect returned", r.stderr)

    def test_a_failure_anywhere_in_the_pipe_stops_the_install(self):
        r, _, _, _ = self.run_it(kc_rc=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("did not reach the Enclave's vault", r.stderr)


REFUSED = ("ekka api connect: 'desks' is already connected to a different configuration, and replacing it would leave "
           "every grant that names it pointing somewhere nobody approved.\n  what differs: {what}\n"
           "  Nothing was changed. The credential was not asked for, and the existing connection is untouched.\n")


class ReconnectOnWiderPaths(unittest.TestCase):
    """EKKA's desks catalog entry widened its paths (1.1.0). The Enclave refuses to replace a connection whose paths
    changed; when the paths are the ONLY difference the installer disconnects and connects again, on purpose. Any
    other difference still stops the install, and nothing is disconnected."""

    def run_it(self, what, disconnect_rc=0, second_rc=0, early=False):
        state, seen = tempfile.mkdtemp(), tempfile.mkdtemp()
        os.makedirs(os.path.join(state, "deploy"))
        refusal = REFUSED.format(what=what)
        writer = ("python3 -c 'import sys; sys.stdout.write(\"example-credential\" * 100000); sys.stdout.flush()'"
                  if early else "printf '%s' \"$KC_SECRET\"")
        script = f"""
set -euo pipefail
DESKS_STATE={state}
ok() {{ echo "ok: $*"; }}
die() {{ echo "die: $*" >&2; exit 1; }}
kc() {{ {writer}; }}
ekka_in() {{
  local n; n=$(( $(cat {seen}/n 2>/dev/null || echo 0) + 1 )); echo $n > {seen}/n
  printf '%s\\n' "$*" >> {seen}/calls
  [[ {int(early)} == 1 ]] || cat > {seen}/stdin.$n
  case "$1 $2" in
    "api disconnect") [[ {disconnect_rc} == 0 ]] || echo "planted: the documentation could not be removed" >&2; return {disconnect_rc} ;;
    "api connect") if [[ $n == 1 ]]; then printf '%s' "$REFUSAL" >&2; return 1; fi; return {second_rc} ;;
  esac
}}
cd {state}
{up_function("connect_desk_admin")}
connect_desk_admin
"""
        r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30,
                           stdin=subprocess.DEVNULL, env=dict(os.environ, KC_SECRET=SECRET, REFUSAL=refusal))
        path = os.path.join(seen, "calls")
        calls = open(path).read().splitlines() if os.path.exists(path) else []
        stdins = [open(os.path.join(seen, f)).read() for f in sorted(os.listdir(seen)) if f.startswith("stdin.")]
        return r, calls, stdins

    def test_only_wider_paths_reconnects_on_purpose_and_keeps_the_secret_off_the_command_line(self):
        r, calls, stdins = self.run_it("the paths it may reach")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([c.split()[:3] for c in calls],
                         [["api", "connect", "desks"], ["api", "disconnect", "desks"], ["api", "connect", "desks"]])
        self.assertIn("--yes", calls[1])
        self.assertEqual([s for s in stdins if s], [SECRET, SECRET], "the secret through stdin, both connects")
        self.assertNotIn(SECRET, "".join(calls) + r.stdout + r.stderr)
        self.assertIn("reconnected with the paths", r.stdout)

    def test_both_connect_attempts_can_return_before_reading_the_python_writer(self):
        for result in (0, 1):
            r, calls, _ = self.run_it("the paths it may reach", second_rc=result, early=True)
            self.assertEqual(r.returncode, result, r.stderr)
            self.assertEqual(len(calls), 3)
            self.assertNotIn("BrokenPipeError", r.stderr)
            self.assertNotIn("example-credential", r.stdout + r.stderr)

    def test_any_other_difference_stops_the_install_and_disconnects_nothing(self):
        for what in ("the destination (unix:/a -> unix:/b)", "how it authenticates",
                     "the paths it may reach, how it authenticates", "the setup value 'socket'"):
            with self.subTest(what=what):
                r, calls, _ = self.run_it(what)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(len(calls), 1, "no disconnect, no second connect")
                self.assertIn("did not reach the Enclave's vault", r.stderr)
                self.assertIn("what differs", r.stderr, "the Enclave's reason is shown")

    def test_a_failed_disconnect_or_reconnect_stops_the_install_by_name(self):
        r, calls, _ = self.run_it("the paths it may reach", disconnect_rc=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertIn("did not disconnect cleanly", r.stderr)
        self.assertIn("may already be removed", r.stderr)
        self.assertIn("planted: the documentation could not be removed", r.stderr, "the Enclave's reason is shown")
        r, calls, _ = self.run_it("the paths it may reach", second_rc=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("did not connect again", r.stderr)


class SetupKeycloak:
    """The admin API calls `setup-client` makes, as Keycloak answers them. `listed` False is a client the list leaves
    out (the list returns only clients the reader may see), while a read by its id still finds it. `answer` replaces
    the list's answer outright; `sticky` ignores writes, as a client that will not change does. `scope_read_id` and
    `role_read_id` give the assignments back under another id, as a record that only shares the name would."""

    def __init__(self, client=None, listed=True, answer=None, scope=True, sticky=False, scope_read_id=None,
                 role_read_id=None):
        self.scopes = [{"id": "s-all", "name": "openshell:all"}] if scope else []
        self.scope_read_id = scope_read_id
        self.role_read_id = role_read_id
        self.reads = []
        self.client = client
        self.listed = listed
        self.answer = answer
        self.sticky = sticky
        self.defaults = set()
        self.roles = []
        self.created = None
        self.writes = []
        self.calls = 0

    def get(self, path):
        self.calls += 1
        self.reads.append(path)
        if path == REALM + "/client-scopes":
            return list(self.scopes)
        if path == REALM + "/clients?clientId=desks-setup":
            if self.answer is not None:
                return self.answer
            return [copy.deepcopy(self.client)] if self.client and self.listed else []
        if path == REALM + "/clients/c-setup":
            return copy.deepcopy(self.client) if self.client else None    # 404: no such client
        if path == REALM + "/clients/c-setup/default-client-scopes":
            return [{**s, "id": self.scope_read_id or s["id"]} for s in self.scopes if s["id"] in self.defaults]
        if path == REALM + "/clients/c-setup/service-account-user":
            return {"id": "u-setup"}
        if path == REALM + "/roles/openshell-admin":
            return {"id": "r-admin", "name": "openshell-admin"}
        if path == REALM + "/users/u-setup/role-mappings/realm":
            return [{"id": self.role_read_id or "r-admin", "name": r} for r in self.roles]
        if path == REALM + "/clients/c-setup/client-secret":
            return {"value": SECRET}
        raise AssertionError("unexpected GET " + path)

    def write(self, method, path, body):
        self.writes.append((method, path, body))
        if self.sticky:
            return None
        if path == REALM + "/clients" and method == "POST":
            self.created = dict(body)
            self.client = {"id": "c-setup", **body}
        elif path == REALM + "/clients/c-setup" and method == "PUT":
            self.client = {**self.client, **body}
        elif path == REALM + "/clients/c-setup/default-client-scopes/s-all" and method == "PUT":
            self.defaults.add("s-all")
        elif path == REALM + "/users/u-setup/role-mappings/realm" and method == "POST":
            self.roles += [r["name"] for r in body]
        else:
            raise AssertionError(f"unexpected {method} {path}")


RECORD = {"id": "c-setup", "clientId": "desks-setup"}


class TheSetupClientIsReadStrictly(unittest.TestCase):
    """up.sh switches its temporary gateway administrator off with `setup-client off <id>` and reads it back with
    `setup-client status <id>`: by the client's own id, never by an empty list, which proves nothing."""

    def test_an_unreadable_list_is_never_disabled_and_never_skips_the_switch_off(self):
        for answer in ({}, "", [{"id": "x", "clientId": "other", "enabled": False}],
                       [{**RECORD, "enabled": False}] * 2, [{"clientId": "desks-setup", "enabled": False}],
                       [{**RECORD, "enabled": "false"}]):
            for verb in ("status", "off"):
                with self.subTest(answer=answer, verb=verb):
                    kc = SetupKeycloak(answer=answer)
                    with self.assertRaises(SystemExit):
                        run(["setup-client", verb], kc)
                    self.assertEqual(kc.writes, [])

    def test_a_client_the_list_leaves_out_is_read_switched_off_and_read_back_by_its_id(self):
        kc = SetupKeycloak({**RECORD, "enabled": True}, listed=False)
        self.assertNotEqual(run(["setup-client", "status"], kc)[1].strip(), "disabled",
                            "an empty list was read as switched off")
        self.assertEqual(run(["setup-client", "status", "c-setup"], kc), (0, "enabled\n"))
        with self.assertRaises(SystemExit):
            run(["setup-client", "off"], kc)          # no id: it cannot be found, so it cannot be confirmed off
        self.assertIs(kc.client["enabled"], True)
        self.assertEqual(run(["setup-client", "off", "c-setup"], kc)[0], 0)
        self.assertIs(kc.client["enabled"], False)
        self.assertEqual(run(["setup-client", "status", "c-setup"], kc), (0, "disabled\n"))

    def test_a_switch_off_that_does_not_read_back_is_refused(self):
        kc = SetupKeycloak({**RECORD, "enabled": True}, sticky=True)
        with self.assertRaises(SystemExit):
            run(["setup-client", "off", "c-setup"], kc)

    def test_a_client_that_cannot_be_read_by_its_id_has_no_state(self):
        for verb in ("off", "status"):
            with self.subTest(verb=verb):
                kc = SetupKeycloak(None)
                with self.assertRaises(SystemExit):
                    run(["setup-client", verb, "c-setup"], kc)
                # The refusal comes from the direct read of that id, not from an earlier step.
                self.assertEqual(kc.reads, [REALM + "/clients/c-setup"])
                self.assertEqual(kc.writes, [])

    def test_a_client_id_up_sh_would_drop_is_never_used_or_written(self):
        # up.sh keeps an id only of [0-9A-Za-z-]: a client it could not switch off by its id is refused first.
        for verb in ("on", "off"):
            with self.subTest(verb=verb):
                kc, out = SetupKeycloak(answer=[{"id": "c/../x", "clientId": "desks-setup", "enabled": False}]), Piped()
                real = apply_realm.Api
                apply_realm.Api = lambda: kc
                try:
                    with self.assertRaises(SystemExit), redirect_stdout(out):
                        apply_realm.main(["setup-client", verb])
                finally:
                    apply_realm.Api = real
                self.assertEqual(kc.writes, [])
                self.assertNotIn("c/../x", out.getvalue())


class TheSetupClientIsWholeBeforeItIsEnabled(unittest.TestCase):
    def test_on_reports_the_id_then_the_secret(self):
        kc = SetupKeycloak({**RECORD, "enabled": False})
        self.assertEqual(run(["setup-client", "on"], kc), (0, "c-setup\n" + SECRET))

    def test_a_client_an_interrupted_on_left_gets_its_scope_and_role(self):
        kc = SetupKeycloak({**RECORD, "enabled": False})
        code, _ = run(["setup-client", "on"], kc)
        self.assertEqual(code, 0)
        self.assertEqual(kc.roles, ["openshell-admin"], "enabled without the administrator role")
        self.assertEqual(kc.defaults, {"s-all"})
        self.assertIs(kc.client["enabled"], True)

    def test_a_new_client_is_created_disabled_and_enabled_once_whole(self):
        kc = SetupKeycloak()
        self.assertEqual(run(["setup-client", "on"], kc)[0], 0)
        self.assertIs(kc.created["enabled"], False, "created enabled, before its role was assigned")
        self.assertEqual(kc.roles, ["openshell-admin"])
        self.assertIs(kc.client["enabled"], True)
        run(["setup-client", "on"], kc)
        self.assertEqual(kc.roles, ["openshell-admin"], "the role was assigned twice")

    def test_a_realm_without_its_scope_never_enables_it(self):
        kc = SetupKeycloak({**RECORD, "enabled": False}, scope=False)
        with self.assertRaises(SystemExit):
            run(["setup-client", "on"], kc)
        self.assertIs(kc.client["enabled"], False)

    def test_assignments_that_do_not_read_back_never_enable_it(self):
        kc = SetupKeycloak({**RECORD, "enabled": False}, sticky=True)
        with self.assertRaises(SystemExit):
            run(["setup-client", "on"], kc)
        self.assertFalse(any(w[0] == "PUT" and w[1].endswith("/clients/c-setup") for w in kc.writes),
                         "it was enabled before its scope and role read back")

    def test_a_scope_or_role_that_reads_back_under_another_id_never_enables_it(self):
        for kw in ({"scope_read_id": "s-other"}, {"role_read_id": "r-other"}):
            with self.subTest(**kw):
                kc = SetupKeycloak({**RECORD, "enabled": False}, **kw)
                with self.assertRaises(SystemExit):
                    run(["setup-client", "on"], kc)
                self.assertFalse(any(w[0] == "PUT" and w[1].endswith("/clients/c-setup") for w in kc.writes),
                                 "it was enabled on an assignment that only shares the name")

    def test_a_terminal_is_refused_before_anything_changes(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        kc, err = SetupKeycloak({**RECORD, "enabled": False}), io.StringIO()
        real = apply_realm.Api
        apply_realm.Api = lambda: kc
        real_out, real_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = Tty(), err
        try:
            self.assertEqual(apply_realm.main(["setup-client", "on"]), 2)
        finally:
            sys.stdout, sys.stderr = real_out, real_err
            apply_realm.Api = real
        self.assertEqual(kc.writes, [])
        self.assertIs(kc.client["enabled"], False)


if __name__ == "__main__":
    unittest.main()
