"""up.sh openshell: an allow-list, each allowed call logged, every other command refused by name.

The command words are NVIDIA OpenShell 0.1.4's own (crates/openshell-cli/src/main.rs), written here from that source,
not read from the code under test.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TOOL = os.path.join(ROOT, "tools", "openshell_allow.py")
EKKA = "desk changes run through EKKA: ekka desk <op>"


def run(*args, user="alice"):
    log = os.path.join(tempfile.mkdtemp(), "openshell-admin.log")
    env = dict(os.environ, SUDO_USER=user)
    r = subprocess.run([sys.executable, TOOL, log, *args], capture_output=True, text=True, env=env,
                       stdin=subprocess.DEVNULL, timeout=30)
    lines = []
    if os.path.exists(log):
        with open(log) as f:
            lines = [json.loads(x) for x in f]
    return r, lines, log


class Allowed(unittest.TestCase):
    def assertAllowedAndLogged(self, *args):
        r, lines, log = run(*args)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["command"], ["openshell", *args])
        self.assertEqual(lines[0]["user"], "alice", "the person who ran sudo")
        self.assertRegex(lines[0]["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(os.stat(log).st_mode & 0o777, 0o600)

    def test_a_read(self):
        self.assertAllowedAndLogged("provider", "list")

    def test_the_kill_switch_stops_one_named_desk(self):
        self.assertAllowedAndLogged("sandbox", "stop", "code-desk")

    def test_a_providers_refresh_is_set_on_the_box(self):
        self.assertAllowedAndLogged("provider", "refresh", "configure", "aws", "--credential-key", "AWS_ACCESS_KEY_ID",
                                    "--strategy", "aws-sts-assume-role", "--secret-material-env", "role_arn=ROLE_ARN",
                                    "--secret-material-env", "aws_secret_access_key=SOURCE_SECRET")

    def test_a_workspace_on_this_gateway_may_be_named(self):
        self.assertAllowedAndLogged("provider", "list", "--workspace", "desks")

    def test_a_provider_key_named_from_the_environment(self):
        self.assertAllowedAndLogged("provider", "create", "--name", "github", "--type", "github", "--credential", "GITHUB_TOKEN")

    def test_the_log_keeps_every_call(self):
        r1, _, log = run("provider", "list")
        subprocess.run([sys.executable, TOOL, log, "status"], check=True, capture_output=True, stdin=subprocess.DEVNULL)
        with open(log) as f:
            self.assertEqual([json.loads(x)["command"][1] for x in f], ["provider", "status"])


class Refused(unittest.TestCase):
    def assertRefused(self, args, says):
        r, lines, _ = run(*args)
        self.assertEqual(r.returncode, 1, args)
        self.assertIn(says, r.stderr)
        self.assertEqual(lines, [], "a refused call is never logged as run")

    def test_planted_sandbox_create_is_refused_by_name(self):
        self.assertRefused(["sandbox", "create", "--name", "x"], f"REFUSED: openshell sandbox create: {EKKA}")

    def test_planted_every_other_desk_write_is_refused_by_name(self):
        for args in (["sandbox", "delete", "code-desk"], ["sandbox", "start", "code-desk"],
                     ["sandbox", "exec", "code-desk", "--", "sh"], ["sandbox", "connect", "code-desk"],
                     ["policy", "set", "code-desk"], ["settings", "set"], ["workspace", "member", "add"],
                     ["provider", "profile", "import"], ["sandbox", "provider", "attach"]):
            self.assertRefused(args, EKKA)

    def test_planted_an_alias_or_a_flag_before_the_command_is_refused(self):
        self.assertRefused(["sb", "list"], EKKA)
        self.assertRefused(["-g", "other", "provider", "list"], f"openshell (no command): {EKKA}")
        self.assertRefused([], EKKA)

    def test_planted_a_stop_must_name_one_desk(self):
        for args in (["sandbox", "stop"], ["sandbox", "stop", "a", "b"], ["sandbox", "stop", "--all"],
                     ["sandbox", "stop", "../x"]):
            self.assertRefused(args, "name exactly one desk")

    def test_planted_a_secret_as_an_argument_is_refused(self):
        self.assertRefused(["provider", "create", "--name", "g", "--type", "github", "--credential", "TOKEN=abc"],
                           "a secret is never an argument")
        self.assertRefused(["provider", "update", "g", "--credential=TOKEN=abc"], "a secret is never an argument")
        self.assertRefused(["provider", "refresh", "configure", "aws", "--secret-material-key", "k"],
                           "refresh material is never an argument")

    def test_planted_refresh_material_as_an_argument_is_refused(self):
        # regression review: `--material refresh_token=abc` passed, and NVIDIA stores it as ordinary material.
        for args in (["--material", "refresh_token=abc"], ["--material=refresh_token=abc"],
                     ["--material", "role_arn=arn:aws:iam::1:role/r"]):
            self.assertRefused(["provider", "refresh", "configure", "aws", "--credential-key", "K",
                                "--strategy", "aws-sts-assume-role", *args],
                               "openshell --material: refresh material is never an argument")

    def test_planted_a_gateway_flag_after_the_command_is_refused(self):
        # Global in NVIDIA's CLI, so one after the command would override up.sh's `-g ekka-agent-desks`.
        for args, flag in ((["--gateway", "other"], "--gateway"), (["--gateway=other"], "--gateway"),
                           (["--gateway-endpoint", "https://gw.example.com"], "--gateway-endpoint"),
                           (["--gateway-endpoint=https://gw.example.com"], "--gateway-endpoint"),
                           (["--gateway-insecure"], "--gateway-insecure"),
                           (["--gateway-insecure=true"], "--gateway-insecure"),
                           (["-g", "other"], "-g"), (["-gother"], "-g"), (["-g=other"], "-g"), (["-vg", "other"], "-g")):
            self.assertRefused(["provider", "list", *args], f"openshell {flag}: the call always goes to this machine's gateway")
        self.assertRefused(["sandbox", "stop", "code-desk", "-g", "other"], "name exactly one desk")

    def test_planted_the_administrators_own_sign_in_never_becomes_a_key(self):
        self.assertRefused(["provider", "update", "g", "--from-oidc-token"], "never becomes a desk's key")

    def test_planted_a_log_that_is_a_link_is_never_followed(self):
        d = tempfile.mkdtemp()
        target, log = os.path.join(d, "elsewhere"), os.path.join(d, "openshell-admin.log")
        os.symlink(target, log)
        r = subprocess.run([sys.executable, TOOL, log, "provider", "list"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=30)
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not be logged", r.stderr)
        self.assertFalse(os.path.exists(target))


class UpSh(unittest.TestCase):
    def test_up_sh_checks_and_logs_before_nvidias_cli_runs(self):
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"^  openshell\)(.*?);;", text, re.S | re.M)
        self.assertTrue(m)
        body = m.group(1)
        guard = body.find('python3 tools/openshell_allow.py "$DESKS_STATE/openshell-admin.log" "$@" || exit 1')
        self.assertGreater(guard, 0, "up.sh openshell does not run the allow-list")
        self.assertLess(guard, body.find("as_gateway_admin"), "the allow-list must run before NVIDIA's CLI")

    def test_planted_gateway_environment_never_reaches_nvidias_cli(self):
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
        body = re.search(r"^as_gateway_admin\(\) \{.*?^\}\n", text, re.S | re.M).group(0)
        call = re.search(r'\n\s+"\$@"\n', body)
        self.assertTrue(call, "as_gateway_admin runs its call")
        # Every step that reaches NVIDIA's CLI (sign-in, and the call) starts from a cleared environment.
        unsets = list(re.finditer(r"unset ([A-Z_ ]+)\n", body))
        self.assertTrue(unsets, "as_gateway_admin clears NVIDIA's gateway environment")
        for unset in unsets:
            self.assertEqual(set(unset.group(1).split()),
                             {"OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_INSECURE",
                              "XDG_CONFIG_HOME"})
        self.assertLess(unsets[-1].start(), call.start(), "cleared before the call runs")
        self.assertLess(unsets[0].start(), body.find('gateway login'), "cleared before the sign-in")


if __name__ == "__main__":
    unittest.main()


class ACopy(unittest.TestCase):
    """`sandbox upload` and `sandbox download`, for this machine's administrator (owner, 2026-11-14). The words and the
    argument order are NVIDIA OpenShell 0.1.4's own (`sandbox upload <NAME> <LOCAL_PATH> [DEST]`,
    `sandbox download <NAME> <SANDBOX_PATH> [DEST]`), read from its help on a box and from crates/openshell-cli."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.local = os.path.join(self.d, "be.bundle")
        with open(self.local, "w") as f:
            f.write("x")
        self.into = os.path.join(self.d, "out")
        os.mkdir(self.into, 0o700)

    def ok(self, *args):
        r, lines, _ = run(*args)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(lines[0]["command"], ["openshell", *args])
        self.assertEqual(lines[0]["user"], "alice")

    def no(self, args, says):
        r, lines, _ = run(*args)
        self.assertEqual(r.returncode, 1, (args, r.stdout))
        self.assertIn(says, r.stderr, args)
        self.assertEqual(lines, [], "a refused call is never logged as run")

    def test_an_upload_names_the_desk_and_is_logged(self):
        self.ok("sandbox", "upload", "acme-admin", self.local)
        self.ok("sandbox", "upload", "acme-admin", self.local, "/sandbox/ekka-workspace/reference/")
        self.ok("sandbox", "upload", "acme-admin", self.d, "/sandbox/in", "--no-git-ignore")

    def test_a_download_lands_in_an_empty_folder_of_the_administrators(self):
        self.ok("sandbox", "download", "acme-admin", "/sandbox/ekka-workspace/out/work.bundle", self.into)

    def test_planted_an_upload_that_is_not_exactly_a_desk_and_its_paths_is_refused(self):
        for args, says in (
                (["sandbox", "upload"], "name the desk"),
                (["sandbox", "upload", "acme-admin"], "name the desk"),
                (["sandbox", "upload", "../x", self.local], "name the desk"),
                (["sandbox", "upload", "acme-admin", self.local, "/sandbox/a", "/sandbox/b"], "name the desk"),
                (["sandbox", "upload", "acme-admin", os.path.join(self.d, "missing")], "does not exist on this machine"),
                (["sandbox", "upload", "acme-admin", self.local, "/etc/passwd"], "under /sandbox/"),
                (["sandbox", "upload", "acme-admin", self.local, "/sandbox/../etc/x"], "under /sandbox/"),
                (["sandbox", "upload", "acme-admin", self.local, "relative/path"], "under /sandbox/"),
                (["sandbox", "upload", "acme-admin", self.local, "/sandboxed/x"], "under /sandbox/"),
                (["sandbox", "upload", "acme-admin", self.local, "--workspace", "other"], "no flag is taken here"),
                (["sandbox", "upload", "acme-admin", self.local, "-g", "other"], "no flag is taken here"),
                (["sandbox", "upload", "acme-admin", self.local, "--gateway-endpoint=https://x"], "no flag is taken here")):
            self.no(args, says)

    def test_planted_a_download_outside_the_desks_folder_or_into_an_unsafe_folder_is_refused(self):
        full = os.path.join(self.d, "full"); os.mkdir(full, 0o700)
        with open(os.path.join(full, "f"), "w") as f:
            f.write("x")
        loose = os.path.join(self.d, "loose"); os.mkdir(loose); os.chmod(loose, 0o777)
        link = os.path.join(self.d, "link"); os.symlink(self.into, link)
        src = "/sandbox/ekka-workspace/out/work.bundle"
        for args, says in (
                (["sandbox", "download"], "name the desk"),
                (["sandbox", "download", "acme-admin", src], "name the desk"),
                (["sandbox", "download", "ACME", src, self.into], "name the desk"),
                (["sandbox", "download", "acme-admin", "/etc/shadow", self.into], "under /sandbox/"),
                (["sandbox", "download", "acme-admin", "/sandbox/../root/.ssh", self.into], "under /sandbox/"),
                (["sandbox", "download", "acme-admin", "work.bundle", self.into], "under /sandbox/"),
                (["sandbox", "download", "acme-admin", src, os.path.join(self.d, "missing")], "does not exist; make it first"),
                (["sandbox", "download", "acme-admin", src, self.local], "is not a real folder"),
                (["sandbox", "download", "acme-admin", src, link], "is not a real folder"),
                (["sandbox", "download", "acme-admin", src, loose], "can be written by others"),
                (["sandbox", "download", "acme-admin", src, full], "is not empty"),
                (["sandbox", "download", "acme-admin", src, "out"], "an absolute path"),
                (["sandbox", "download", "acme-admin", src, self.into + "/../out"], "an absolute path"),
                (["sandbox", "download", "acme-admin", src, self.into, "--no-git-ignore"], "no flag is taken here"),
                (["sandbox", "download", "acme-admin", src, self.into, "--workspace=x"], "no flag is taken here")):
            self.no(args, says)

    def test_a_folder_that_belongs_to_somebody_else_is_refused(self):
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import openshell_allow as oa
        real = os.geteuid
        os.geteuid = lambda: real() + 1   # as if another account ran it
        try:
            with self.assertRaises(oa.Refused) as c:
                oa.download_folder(self.into)
        finally:
            os.geteuid = real
        self.assertIn("does not belong to the administrator", str(c.exception))


class TheFolderIsMadeSafe(unittest.TestCase):
    """What a download brings was packed by a `tar` inside the desk, so its bytes are the desk's. Before anybody reads
    the folder, every link and special file is gone and no file can raise rights or be written by others."""

    def settle(self, folder):
        return subprocess.run([sys.executable, TOOL, "--settle-download", folder], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=30)

    def test_links_and_special_files_are_removed_and_modes_are_cleared(self):
        d = tempfile.mkdtemp()
        secret = os.path.join(tempfile.mkdtemp(), "secret")
        with open(secret, "w") as f:
            f.write("the box's own file")
        os.makedirs(os.path.join(d, "repo", "sub"))
        with open(os.path.join(d, "repo", "work.bundle"), "w") as f:
            f.write("bundle")
        os.symlink(secret, os.path.join(d, "repo", "passwd"))                       # a link to a file outside
        os.symlink(os.path.dirname(secret), os.path.join(d, "repo", "etc"))         # a link to a FOLDER outside
        os.symlink("nowhere", os.path.join(d, "repo", "sub", "dangling"))
        os.mkfifo(os.path.join(d, "repo", "sub", "pipe"))
        tool = os.path.join(d, "repo", "sub", "tool")
        with open(tool, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(tool, 0o6777)
        os.chmod(os.path.join(d, "repo", "sub"), 0o2777)
        r = self.settle(d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("4 entries the desk sent as a link or special file removed", r.stdout)
        left = sorted(os.path.relpath(os.path.join(t, n), d) for t, ds, fs in os.walk(d) for n in ds + fs)
        self.assertEqual(left, ["repo", "repo/sub", "repo/sub/tool", "repo/work.bundle"])
        self.assertEqual(stat_mode(tool), 0o755, "setuid, setgid and write by others are gone")
        self.assertEqual(stat_mode(os.path.join(d, "repo", "sub")), 0o755)
        with open(secret) as f:
            self.assertEqual(f.read(), "the box's own file", "nothing was followed")
        self.assertTrue(os.path.exists(secret))

    def test_a_clean_download_says_so_and_removes_nothing(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "work.bundle"), "w") as f:
            f.write("bundle")
        r = self.settle(d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("plain files and folders only", r.stdout)
        self.assertEqual(os.listdir(d), ["work.bundle"])

    def test_it_takes_one_real_folder(self):
        d = tempfile.mkdtemp()
        link = os.path.join(d, "l"); os.symlink(tempfile.mkdtemp(), link)
        for args in ([link], [os.path.join(d, "missing")], []):
            r = subprocess.run([sys.executable, TOOL, "--settle-download", *args], capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=30)
            self.assertEqual(r.returncode, 2, args)

    def test_up_sh_settles_the_folder_whatever_the_copy_did(self):
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            up = f.read()
        block = up[up.index('if [[ "${1:-} ${2:-}" == "sandbox download" ]]; then'):]
        block = block[:block.index("\n    fi\n")]
        self.assertIn('as_gateway_admin "$OS" -g ekka-agent-desks "$@" || rc=$?', block, "a failed copy does not skip the next line")
        self.assertIn('python3 tools/openshell_allow.py --settle-download "${@: -1}" || rc=1', block)
        self.assertLess(block.index("as_gateway_admin"), block.index("--settle-download"))


def stat_mode(path):
    import stat as _stat
    return _stat.S_IMODE(os.lstat(path).st_mode)
