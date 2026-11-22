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


class KeycloakAnswers:
    """The client list as Keycloak's admin API might answer it, including answers that are not one exact record."""

    def __init__(self, answer):
        self.answer = answer
        self.writes = []

    def get(self, path):
        if not path.endswith("/clients?clientId=desks-setup"):
            raise AssertionError("read outside the setup client: " + path)
        return self.answer

    def write(self, *args):
        self.writes.append(args)


class TheSetupClientIsReadStrictly(unittest.TestCase):
    """up.sh switches its temporary gateway administrator off with `setup-client off` and reads it back with
    `setup-client status`. An empty body, null, {} or anything but one exact desks-setup record is an unknown state:
    never "disabled", and never a reason to skip the switch-off."""

    RECORD = {"id": "c0ffee", "clientId": "desks-setup"}

    def test_an_unreadable_answer_is_never_disabled_and_never_skips_the_switch_off(self):
        for answer in (None, {}, "", [{"id": "x", "clientId": "other", "enabled": False}],
                       [{**self.RECORD, "enabled": False}] * 2, [{"clientId": "desks-setup", "enabled": False}],
                       [{**self.RECORD, "enabled": "false"}]):
            for verb in ("status", "off"):
                with self.subTest(answer=answer, verb=verb):
                    keycloak = KeycloakAnswers(answer)
                    with self.assertRaises(SystemExit):
                        run(["setup-client", verb], keycloak)
                    self.assertEqual(keycloak.writes, [])

    def test_status_reads_without_writing(self):
        for answer, expected in (([], "disabled"), ([{**self.RECORD, "enabled": False}], "disabled"),
                                 ([{**self.RECORD, "enabled": True}], "enabled")):
            keycloak = KeycloakAnswers(answer)
            code, output = run(["setup-client", "status"], keycloak)
            self.assertEqual((code, output.strip()), (0, expected))
            self.assertEqual(keycloak.writes, [])

    def test_off_disables_the_one_exact_record(self):
        keycloak = KeycloakAnswers([{**self.RECORD, "enabled": True}])
        code, _ = run(["setup-client", "off"], keycloak)
        self.assertEqual(code, 0)
        self.assertEqual(keycloak.writes[-1][0], "PUT")
        self.assertIs(keycloak.writes[-1][2]["enabled"], False)


class SetupKeycloak:
    """The admin API calls `setup-client on` makes. `client` may start as a desks-setup client an interrupted `on`
    left behind: created, but without its scope or its role."""

    def __init__(self, client=None):
        self.scopes = [{"id": "s-all", "name": "openshell:all"}]
        self.client = client
        self.defaults = set()
        self.roles = []
        self.created = None

    def get(self, path):
        if path == REALM + "/client-scopes":
            return list(self.scopes)
        if path == REALM + "/clients?clientId=desks-setup":
            return [copy.deepcopy(self.client)] if self.client else []
        if path == REALM + "/clients/c-setup/default-client-scopes":
            return [s for s in self.scopes if s["id"] in self.defaults]
        if path == REALM + "/clients/c-setup/service-account-user":
            return {"id": "u-setup"}
        if path == REALM + "/roles/openshell-admin":
            return {"name": "openshell-admin"}
        if path == REALM + "/users/u-setup/role-mappings/realm":
            return [{"name": r} for r in self.roles]
        if path == REALM + "/clients/c-setup/client-secret":
            return {"value": SECRET}
        raise AssertionError("unexpected GET " + path)

    def write(self, method, path, body):
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


class TheSetupClientIsWholeBeforeItIsEnabled(unittest.TestCase):
    def test_a_client_an_interrupted_on_left_gets_its_scope_and_role(self):
        kc = SetupKeycloak({"id": "c-setup", "clientId": "desks-setup", "enabled": False})
        code, out = run(["setup-client", "on"], kc)
        self.assertEqual((code, out), (0, SECRET))
        self.assertEqual(kc.roles, ["openshell-admin"], "enabled without the administrator role")
        self.assertEqual(kc.defaults, {"s-all"})
        self.assertIs(kc.client["enabled"], True)

    def test_a_new_client_is_created_disabled_and_enabled_once_whole(self):
        kc = SetupKeycloak()
        code, _ = run(["setup-client", "on"], kc)
        self.assertEqual(code, 0)
        self.assertIs(kc.created["enabled"], False, "created enabled, before its role was assigned")
        self.assertEqual(kc.roles, ["openshell-admin"])
        self.assertIs(kc.client["enabled"], True)
        run(["setup-client", "on"], kc)
        self.assertEqual(kc.roles, ["openshell-admin"], "the role was assigned twice")


if __name__ == "__main__":
    unittest.main()
