"""Exercise the real server CLI wrapper and public-default bootstrap without a gateway or credentials."""
import json
import os
from pathlib import Path
import pty
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def function(name):
    text = (ROOT/'up.sh').read_text()
    return re.search(rf'^{name}\(\) \{{.*?^\}}\n', text, re.S | re.M).group(0)


class ServerCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'deploy').mkdir()
        self.log = self.root/'args'
        self.capture = self.root/'copied'
        self.capture.mkdir()
        # Record the actual wrapper's compose invocation. It may copy only public files.
        (self.root/'deploy'/'setup.sh').write_text('''#!/bin/bash
set -eu
printf '%s\\0' "$@" >> "$ARG_LOG"
if [[ $1 == compose && $2 == cp ]]; then
  cp "$3" "$CAPTURE/$(basename "$3")"
elif [[ $1 == compose && $2 == exec ]]; then
  cat > "$CAPTURE/stdin"
fi
''')
        self.env = dict(os.environ, ARG_LOG=str(self.log), CAPTURE=str(self.capture))

    def wrapper(self, args, terminal=False):
        stub = 'enclave_ekka() { printf "%s\\0" "$@" >> "$ARG_LOG"; [[ -t 0 ]] || cat > "$CAPTURE/stdin"; }\n'
        script = 'set -euo pipefail\ndie() { echo "$1" >&2; exit 2; }\n'+stub+function('server_ekka')+'\nserver_ekka "$@"\n'
        argv = ['/bin/bash','-c',script,'wrapper']+args
        if terminal:
            master, slave = pty.openpty()
            try:
                # No input is expected by this fixture's interactive invocation.
                (self.root/'deploy'/'setup.sh').write_text('printf "%s\\0" "$@" > "$ARG_LOG"\n')
                return subprocess.run(argv,cwd=self.root,env=self.env,stdin=slave,stdout=slave,stderr=slave,timeout=10)
            finally:
                os.close(slave); os.close(master)
        return subprocess.run(argv,cwd=self.root,env=self.env,input='public input',capture_output=True,text=True,timeout=10)

    def args(self):
        return self.log.read_bytes().decode().rstrip('\0').split('\0')

    def test_pipe_keeps_stdin_and_disables_tty(self):
        r=self.wrapper(['secret','put','TEST','--stdin'])
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.args(),['secret','put','TEST','--stdin'], 'the ekka words, to the native Enclave as its user')
        self.assertEqual((self.capture/'stdin').read_text(),'public input')

    def test_real_terminal_allows_interactive_desk_login(self):
        r=self.wrapper(['desk','login'],terminal=True)
        self.assertEqual(r.returncode,0)
        self.assertEqual(self.args(),['desk','login'])

    def test_credential_options_are_not_forwarded_or_echoed(self):
        for option in ['--token','--access-token','--refresh-token','--id-token','--password','--client-secret','--api-key','--secret']:
            for args in ([option,'PLANTED_PRIVATE_VALUE'],[option+'=PLANTED_PRIVATE_VALUE']):
                with self.subTest(args=args):
                    r=self.wrapper(['desk','login']+args)
                    self.assertEqual(r.returncode,2)
                    self.assertIn('do not pass a credential',r.stderr)
                    self.assertNotIn('PLANTED_PRIVATE_VALUE',r.stdout+r.stderr)
                    self.assertFalse(self.log.exists(),'compose must never receive the argument')

    def test_token_word_in_a_question_is_not_a_credential_option(self):
        r=self.wrapper(['plan','run','example','--input','question=What does --token mean?'])
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.args()[-1],'question=What does --token mean?')

    def test_bootstrap_copies_no_cached_person_or_secret(self):
        state=self.root/'state'
        people=state/'people'; people.mkdir(parents=True)
        (people/'desks-ca.pem').write_text('PUBLIC_CA')
        (people/'desk-policy.json').write_text('{}')
        (people/'cached-person-token.json').write_text('PLANTED_PRIVATE_TOKEN')
        cli=state/'enclave-cli'; cli.mkdir()
        public={'gateway':'ekka-desks','url':'https://gateway:8080'}
        (cli/'backend.json').write_text(json.dumps(public))
        self.env['DESKS_STATE']=str(state)
        stubs=('ENCLAVE_HOME="$CAPTURE"\nenclave_home_file() { cat > "$CAPTURE/$1"; }\n'
               'ekka_in() { printf "%s\\0" "$@" >> "$ARG_LOG"; }\n')
        r=subprocess.run(['/bin/bash','-c','set -euo pipefail\n'+stubs+function('configure_enclave_cli')+'\nconfigure_enclave_cli'],
                         cwd=self.root,env=self.env,capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual({p.name for p in self.capture.iterdir()},{'desks-ca.pem','desk-policy.json','backend.json'})
        self.assertEqual(json.loads((self.capture/'backend.json').read_text()),public)
        self.assertEqual(self.args(),['desk','backend','set',str(self.capture/'backend.json')])
        self.assertNotIn('PLANTED_PRIVATE_TOKEN',''.join(p.read_text() for p in self.capture.iterdir()))


class TheEkkaVerbEnds(unittest.TestCase):
    """`./up.sh ekka <command>` runs the command and EXITS. The native enclave_ekka returns where the container version
    exec'd into compose, and the install sequence after the verb dispatch then ran on the walk box (measured:
    "./up.sh: line 158: MODE: unbound variable" after a successful `whoami`)."""

    def test_up_sh_ekka_exits_after_the_command_and_runs_no_install_step(self):
        with tempfile.TemporaryDirectory() as d:
            for name, body in (("id", "echo 0\n"), ("runuser", 'printf "%s\\n" "$@" > "$LOG"\n')):
                Path(d, name).write_text("#!/bin/bash\n" + body); os.chmod(Path(d, name), 0o755)
            env = dict(os.environ, PATH=d + ":" + os.environ["PATH"], LOG=str(Path(d, "log")), DESKS_STATE=str(Path(d, "state")))
            r = subprocess.run(["bash", str(ROOT/"up.sh"), "ekka", "whoami"], capture_output=True, text=True, env=env, timeout=30, cwd=ROOT)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stderr, "", "no install step spoke")
            self.assertEqual(Path(d, "log").read_text().splitlines()[-1], "whoami")
            # and a failing command's status is the verb's status
            Path(d, "runuser").write_text("#!/bin/bash\nexit 7\n")
            r = subprocess.run(["bash", str(ROOT/"up.sh"), "ekka", "whoami"], capture_output=True, text=True, env=env, timeout=30, cwd=ROOT)
            self.assertEqual(r.returncode, 7)


class TheGrantVerb(unittest.TestCase):
    """Project add/remove use the real installer verb with local stubs and test-owned records."""

    def run_verb(self, d, *args):
        env = dict(os.environ, PATH=d + ":" + os.environ["PATH"], DESKS_STATE=str(Path(d, "state")))
        return subprocess.run(["bash", str(ROOT/"up.sh"), "grant", *args], capture_output=True, text=True, env=env, timeout=60,
                              cwd=ROOT, stdin=subprocess.DEVNULL)

    def box(self, d, *provider_args):
        Path(d, "id").write_text("#!/bin/bash\necho 0\n"); os.chmod(Path(d, "id"), 0o755)
        state = Path(d, "state"); (state/"backend").mkdir(parents=True)
        (state/"up.env").write_text("DESKS_NAME=desks.example.test\nEKKA_BACKEND_IMAGE=ghcr.io/example/backend@sha256:" + "f" * 64 + "\n")
        lim = json.loads((ROOT/"tests/fixtures/desks-grant.json").read_text())
        if not provider_args:
            lim["providers"] = []
            lim["provider_config_digests"] = {}
        (state/"backend"/"desks-grant.json").write_text(json.dumps(lim))
        return state

    P_IMAGE = "sha256:" + "1" * 64

    def project_box(self, d, docker):
        """A box with a docker that knows one image and digests any policy; the grant step then fails (no Enclave
        here), which must keep the input records without claiming the grant is unchanged."""
        state = self.box(d, "--provider", "github=sha256:" + "c" * 64)
        Path(d, "docker").write_text("#!/bin/bash\n" + docker); os.chmod(Path(d, "docker"), 0o755)
        shipped = json.loads((ROOT/"desk"/"policy.json").read_text())
        key = "networkPolicies" if "networkPolicies" in shipped else "network_policies"
        own = dict(shipped); own[key] = {}
        Path(d, "own.json").write_text(json.dumps(own))
        rooted = dict(own); rooted["process"] = {"runAsUser": "0", "runAsGroup": "0"}
        Path(d, "rooted.json").write_text(json.dumps(rooted))
        Path(d, "notjson.json").write_text("not json")
        os.symlink(str(Path(d, "own.json")), str(Path(d, "link.json")))
        return state

    KNOWS_THE_IMAGE = ('if [[ "$1 $2" == "image inspect" ]]; then [[ "${@: -1}" == sha256:' + "1" * 64 + ' ]] && { echo "${@: -1}"; exit 0; }; exit 1; fi\n'
                       'if [[ "$1" == run && " $* " == *" digest policy "* ]]; then cat >/dev/null; echo sha256:' + "2" * 64 + '; exit 0; fi\n'
                       'exit 1\n')

    def left_behind(self, state):
        folder = state/"backend"/"projects"
        return sorted(p.name for p in folder.iterdir()) if folder.exists() else []

    def test_project_add_and_remove_refresh_after_changing_the_record(self):
        with tempfile.TemporaryDirectory() as d:
            state = self.project_box(d, self.KNOWS_THE_IMAGE)
            source = (ROOT / "up.sh").read_text()
            verb = source[source.index("  grant)"):source.index("  desk-grant)")]
            script = '''set -euo pipefail
die() { echo "$*" >&2; exit 1; }
ok() { echo "$*"; }
profile_names() { echo github; }
profile_source() { echo "$PWD/providers/$1.yaml"; }
step_desk_grant() {
  if [[ -f $DESKS_STATE/backend/projects/acme.project.json ]]; then
    cp "$DESKS_STATE/backend/projects/acme.project.json" "$DESKS_STATE/seen.json"
  else
    echo removed > "$DESKS_STATE/seen-removed"
  fi
  echo refresh >> "$DESKS_STATE/refreshes"
}
enclave_home_file() { mkdir -p "$ENCLAVE_HOME/projects"; cat > "$ENCLAVE_HOME/$1"; }
case "$1" in
''' + verb + '\nesac\n'
            env = dict(os.environ, PATH=d + ":" + os.environ["PATH"], DESKS_STATE=str(state),
                       ENCLAVE_HOME=str(state / "enclave"))
            def run(*args):
                return subprocess.run(["bash", "-c", script, "test", "grant", "project", *args],
                                      cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
            result = run("add", "acme", "--image", self.P_IMAGE, "--policy", str(Path(d, "own.json")))
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads((state / "backend/projects/acme.project.json").read_text())
            self.assertEqual(record["image_id"], self.P_IMAGE)
            self.assertEqual(json.loads((state / "seen.json").read_text()), record)
            self.assertEqual((state / "enclave/projects/acme.policy.json").read_bytes(), Path(d, "own.json").read_bytes())
            self.assertIn("ekka desk create", result.stdout)
            result = run("remove", "acme")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((state / "seen-removed").exists())
            self.assertEqual(self.left_behind(state), [])
            self.assertEqual((state / "refreshes").read_text().splitlines(), ["refresh", "refresh"])

    def test_project_add_refuses_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as d:
            state = self.project_box(d, self.KNOWS_THE_IMAGE)
            before = (state/"backend"/"desks-grant.json").read_text()
            own, img = str(Path(d, "own.json")), self.P_IMAGE
            for args, why in (
                    (("add", "acme", "--image", "acme-desk:local", "--policy", own), "a tag can move, an ID cannot"),
                    (("add", "acme", "--image", "ghcr.io/x/y@" + img, "--policy", own), "a tag can move, an ID cannot"),
                    (("add", "acme", "--image", "sha256:" + "9" * 64, "--policy", own), "is not on this server"),
                    (("add", "acme", "--image", img), "--policy must name the project's policy file"),
                    (("add", "acme", "--image", img, "--policy", str(Path(d, "missing.json"))), "--policy must name the project's policy file"),
                    (("add", "acme", "--image", img, "--policy", str(Path(d, "link.json"))), "not a link"),
                    (("add", "acme", "--image", img, "--policy", str(Path(d, "rooted.json"))), "changes `process`"),
                    (("add", "acme", "--image", img, "--policy", own, "--minutes", "5"), "usage: sudo ekka desk grant project"),
                    (("add", "ACME", "--image", img, "--policy", own), "a project's name is lowercase"),
                    (("add", "../x", "--image", img, "--policy", own), "a project's name is lowercase"),
                    (("add",), "a project's name is lowercase"),
                    (("replace", "acme"), "usage: sudo ekka desk grant project"),
                    (("remove", "acme", "extra"), "usage: sudo ekka desk grant project")):
                r = self.run_verb(d, "project", *args)
                self.assertEqual(r.returncode, 1, (args, r.stdout, r.stderr)); self.assertIn(why, r.stderr, args)
                self.assertEqual(self.left_behind(state), [], args)
                self.assertEqual((state/"backend"/"desks-grant.json").read_text(), before, args)

    def test_a_policy_the_adapter_does_not_read_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            refuses = self.KNOWS_THE_IMAGE.replace("cat >/dev/null; echo sha256:" + "2" * 64 + "; exit 0", "cat >/dev/null; echo POLICY_INVALID >&2; exit 2")
            state = self.project_box(d, refuses)
            r = self.run_verb(d, "project", "add", "acme", "--image", self.P_IMAGE, "--policy", str(Path(d, "notjson.json")))
            self.assertEqual(r.returncode, 1); self.assertIn("does not read", r.stderr)
            self.assertEqual(self.left_behind(state), [])

    def test_a_failed_project_add_leaves_no_record_behind(self):
        with tempfile.TemporaryDirectory() as d:
            state = self.project_box(d, self.KNOWS_THE_IMAGE)
            r = self.run_verb(d, "project", "add", "acme", "--image", self.P_IMAGE, "--policy", str(Path(d, "own.json")))
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("project acme was not added", r.stderr)
            self.assertEqual(self.left_behind(state), [], "a record nobody confirmed must not apply on a later run")

    def test_remove_of_a_project_that_is_not_there_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            state = self.project_box(d, self.KNOWS_THE_IMAGE)
            r = self.run_verb(d, "project", "remove", "acme")
            self.assertEqual(r.returncode, 0, r.stderr); self.assertIn("no project acme is in the grant", r.stdout)

    def test_a_failed_project_removal_puts_the_record_back(self):
        with tempfile.TemporaryDirectory() as d:
            state = self.project_box(d, self.KNOWS_THE_IMAGE)
            folder = state/"backend"/"projects"; folder.mkdir()
            rec = {"name": "acme", "image_id": self.P_IMAGE, "policy_digest": "sha256:" + "2" * 64, "since": "2026-11-14T12:00:00Z"}
            (folder/"acme.project.json").write_text(json.dumps(rec)); (folder/"acme.policy.json").write_text("{}")
            r = self.run_verb(d, "project", "remove", "acme")
            self.assertEqual(r.returncode, 1); self.assertIn("project acme was not removed", r.stderr)
            self.assertEqual(self.left_behind(state), ["acme.policy.json", "acme.project.json"])
            self.assertEqual(json.loads((folder/"acme.project.json").read_text()), rec)


class TheRegistryAndImageVerbs(unittest.TestCase):
    """`sudo ekka desk registry login|show|logout` and `sudo ekka desk image pull`, as the real
    up.sh verbs with `id` stubbed. Driven to their refusals and to `show`; the login and the pull themselves need a registry."""

    def run_verb(self, d, verb, *args, stdin=None):
        env = dict(os.environ, PATH=d + ":" + os.environ["PATH"], DESKS_STATE=str(Path(d, "state")))
        return subprocess.run(["bash", str(ROOT/"up.sh"), verb, *args], capture_output=True, text=True, env=env, timeout=60, cwd=ROOT,
                              input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL)

    def test_refusals_keep_nothing_and_show_reads_back(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "id").write_text("#!/bin/bash\necho 0\n"); os.chmod(Path(d, "id"), 0o755)
            state = Path(d, "state"); (state/"secrets").mkdir(parents=True)
            (state/"up.env").write_text("DESKS_NAME=desks.example.test\n")
            r = self.run_verb(d, "registry", "show"); self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("no registry credential kept", r.stdout)
            r = self.run_verb(d, "registry", "login", "ghcr.io", "someone", stdin="not-a-classic-token")
            self.assertEqual(r.returncode, 1); self.assertIn("needs a classic token", r.stderr)
            r = self.run_verb(d, "registry", "login", "ghcr.io", "someone", stdin="ghp_two words")
            self.assertEqual(r.returncode, 1); self.assertIn("exactly one token", r.stderr)
            r = self.run_verb(d, "registry", "login", "bad host", "someone", stdin="x"); self.assertEqual(r.returncode, 1); self.assertIn("usage", r.stderr)
            self.assertEqual(list((state/"secrets").glob("registry/*")), [], "nothing kept after a refusal")
            self.assertEqual([p.name for p in (state/"secrets").iterdir()], [], "no throwaway folder left behind")
            r = self.run_verb(d, "image", "pull", "ghcr.io/x/y:latest"); self.assertEqual(r.returncode, 1); self.assertIn("a tag can move", r.stderr)
            r = self.run_verb(d, "image", "pull", "ghcr.io/x/y@sha256:" + "a" * 64, "--signed-by", "id"); self.assertEqual(r.returncode, 1); self.assertIn("go together", r.stderr)
            r = self.run_verb(d, "registry", "logout", "ghcr.io"); self.assertEqual(r.returncode, 0, r.stderr)


class TheRegistryAndImageReviewFixes(unittest.TestCase):
    """The up.sh side: a registry port keeps the GitHub scope check, no host helper keeps a credential, and an
    asked-for signature check always runs. docker, curl and cosign are stubs that log;
    docker behaves as Docker CLI does with a host credential helper installed: a login whose --config folder has no
    auth entry goes to the helper (configfile ContainsAuth, credentials.DetectDefaultStore)."""
    run_verb = TheRegistryAndImageVerbs.run_verb   # the same fixture, without running TheRegistryAndImageVerbs's cases again

    REF = "ghcr.io/x/y@sha256:" + "a" * 64

    def box(self, d, scopes="read:packages"):
        log = Path(d, "log")
        log.write_text("")
        stubs = {
            "id": "#!/bin/bash\necho 0\n",
            "curl": f"#!/bin/bash\necho curl >> {log}\nprintf 'HTTP/2 200\\r\\nx-oauth-scopes: {scopes}\\r\\n\\r\\n'\n",
            "cosign": f"#!/bin/bash\necho cosign >> {log}\n",
            "install": "#!/bin/bash\nargs=(); while (($#)); do case $1 in -o|-g) shift 2 ;; *) args+=(\"$1\"); shift ;; esac; done\n"
                       "exec /usr/bin/install \"${args[@]}\"\n",
            "docker": f"""#!/bin/bash
cfg=""; [[ $1 == --config ]] && {{ cfg=$2; shift 2; }}
case $1 in
  login) if [[ -n $cfg ]] && grep -q '"auths": *{{ *"' "$cfg/config.json" 2>/dev/null; then echo "docker login file" >> {log}
         else echo "docker login helper $(cat)" >> {log}; fi ;;
  pull) echo "docker pull $*" >> {log} ;;
  image) echo "{self.REF}" ;;
  *) : ;;
esac
""",
        }
        for name, text in stubs.items():
            Path(d, name).write_text(text)
            os.chmod(Path(d, name), 0o755)
        state = Path(d, "state")
        (state / "secrets").mkdir(parents=True)
        (state / "up.env").write_text("DESKS_NAME=desks.example.test\n")
        return log

    def test_a_registry_port_does_not_skip_the_github_scope_check(self):
        with tempfile.TemporaryDirectory() as d:
            log = self.box(d, scopes="repo, read:packages")
            r = self.run_verb(d, "registry", "login", "ghcr.io:443", "someone", stdin="ghp_" + "a" * 36)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("curl", log.read_text().split())
            self.assertNotIn("docker login", log.read_text(), "a token wider than read:packages reached docker")

    def test_a_login_never_reaches_a_host_credential_helper(self):
        with tempfile.TemporaryDirectory() as d:
            log = self.box(d)
            r = self.run_verb(d, "registry", "login", "registry.example.test", "someone", stdin="planted-token")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("helper", log.read_text(), "the token went to the host's credential helper")
            self.assertIn("docker login file", log.read_text())

    def test_a_pull_with_a_kept_credential_never_reaches_a_host_credential_helper(self):
        with tempfile.TemporaryDirectory() as d:
            log = self.box(d)
            folder = Path(d, "state", "secrets", "registry")
            folder.mkdir()
            (folder / "ghcr.io.env").write_text("REGISTRY_USER=someone\nREGISTRY_TOKEN=planted-token\n")
            r = self.run_verb(d, "image", "pull", self.REF)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("helper", log.read_text())

    def test_empty_signing_options_never_skip_the_signature_check(self):
        with tempfile.TemporaryDirectory() as d:
            log = self.box(d)
            r = self.run_verb(d, "image", "pull", self.REF, "--signed-by", "", "--issuer", "")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertNotIn("docker pull", log.read_text(), "pulled without the signature check it was asked for")


class TheRootOwnedCopy(unittest.TestCase):
    """`sudo ekka desk connect|invite|revoke|plans|grant|registry|image` run up.sh from the root-owned copy the installer
    makes (snapshot_stack), never the checkout. Every repository folder the tools read by ROOT must be in that copy.
    Measured 2026-10-31: `ekka desk plans` failed on the server because `ekka/plans/` was not copied."""

    def test_the_copy_holds_every_folder_the_tools_read(self):
        import re as _re
        up = (ROOT/"up.sh").read_text()
        line = next(l for l in up.splitlines() if l.strip().startswith('cp -a ') and '$SNAPSHOT.new/' in l)
        copied = set(line.split('cp -a', 1)[1].split('"$SNAPSHOT.new/"')[0].split())
        read = set()
        for f in (ROOT/"tools").glob("*.py"):
            read |= set(_re.findall(r'os\.path\.join\(ROOT, "([a-z_-]+)"', f.read_text()))
        self.assertTrue(read, "the scan found the folders the tools read")
        self.assertEqual(sorted(read - copied), [], "folders the tools read that the root-owned copy leaves out")
        self.assertTrue({"tools", "up.sh"} <= copied)


if __name__ == '__main__':
    unittest.main()
