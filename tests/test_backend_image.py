"""The backend adapter's public image: one registry value, pulled by digest, a signature checked.

Owner, 2026-10-17: the adapter is the public ekka-labs/ekka-backend, its image ghcr.io/ekka-labs/ekka-backend, a
public package: no registry login, so none is kept on the machine or handed to cosign. The bash functions run
here with `docker` stubbed: the stub records its arguments.
"""
import copy
import hashlib
import json
import os
import pty
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import backend_image as bi  # noqa: E402

DIGEST = "sha256:" + "ab" * 32
# The identity a real release would carry, written here from the release, not from the code under test.
RELEASED = "https://github.com/ekka-labs/ekka-backend/.github/workflows/release.yml@refs/tags/v0.1.0"
# The required public release identity regexp, written here, not read from the code under test.
IDENTITY = r"^https://github\.com/ekka-labs/ekka-backend/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$"

RECORD_STUB = r"""import json, os, sys
with open(os.environ["CALLS"], "a") as f:
    f.write(json.dumps({"argv": sys.argv}) + "\n")
sys.exit(int(os.environ.get("RECORD_RC", "0")))
"""

STUB = r"""#!/usr/bin/env python3
import hashlib, json, os, sys
data = sys.stdin.read() if sys.argv[1:2] == ["login"] else ""
with open(os.environ["CALLS"], "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "stdin_digest": hashlib.sha256(data.encode()).hexdigest() if data else None}) + "\n")
if sys.argv[1:2] == ["run"]:
    sys.exit(int(os.environ.get("VERIFY_RC", "0")))
if sys.argv[1:2] == ["version"]:
    print(os.environ.get("DOCKER_ARCH", "amd64"))
if sys.argv[1:3] == ["image", "inspect"]:
    print(os.environ.get("IMAGE_ARCH", "amd64"))
"""


def function(name):
    with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", text, re.S | re.M)
    assert m, f"{name} is not in up.sh"
    return m.group(0)


def run(fn, args, root=ROOT, stdin_bytes=b"", tty=False, env_extra=None):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "bin"))
    with open(os.path.join(d, "bin", "docker"), "w") as f:
        f.write(STUB)
    os.chmod(os.path.join(d, "bin", "docker"), 0o755)
    calls = os.path.join(d, "calls.jsonl")
    script = f"""
set -euo pipefail
say() {{ :; }}
ok() {{ echo "ok: $*"; }}
die() {{ echo "die: $*" >&2; exit 1; }}
{function(fn)}
{fn} {' '.join(args)}
"""
    env = dict(os.environ, CALLS=calls, PATH=f"{d}/bin:{os.environ['PATH']}", HOME=d, DESKS_STATE=os.path.join(d, "state"))
    env.update(env_extra or {})
    if tty:
        master, slave = pty.openpty()
        r = subprocess.run(["bash", "-c", script], cwd=root, stdin=slave, capture_output=True, text=True, env=env,
                           timeout=30)
        os.close(master)
        os.close(slave)
    else:
        r = subprocess.run(["bash", "-c", script], cwd=root, input=stdin_bytes, capture_output=True, env=env,
                           timeout=30)
        r = subprocess.CompletedProcess(r.args, r.returncode, r.stdout.decode(), r.stderr.decode())
    seen = []
    if os.path.exists(calls):
        with open(calls) as f:
            seen = [json.loads(x) for x in f]
    return r, seen


def copy_with(backend):
    """A copy of this setup's tools and pins, with the backend pin replaced."""
    d = tempfile.mkdtemp()
    shutil.copytree(os.path.join(ROOT, "tools"), os.path.join(d, "tools"))
    # The real writer refuses temporary state under untrusted parents. Only this copied command is stubbed;
    # test_desk_records exercises its ownership, path and atomic-write checks.
    with open(os.path.join(d, "tools", "desk_records.py"), "w") as f:
        f.write(RECORD_STUB)
    os.makedirs(os.path.join(d, "deploy"))
    with open(os.path.join(ROOT, "deploy", "pins.json")) as f:
        pins = json.load(f)
    pins["ekka_backend"] = backend
    with open(os.path.join(d, "deploy", "pins.json"), "w") as f:
        json.dump(pins, f)
    return d


class ThePin(unittest.TestCase):
    def setUp(self):
        self.b = bi.load()

    def test_the_committed_pin_is_well_formed_and_names_ekka_labs(self):
        self.assertEqual(bi.shape_errors(self.b), [])
        self.assertEqual(self.b["registry"], "ghcr.io/ekka-labs")

    def test_the_shipped_setup_pins_a_released_image(self):
        # A digest is required: without one the setup cannot install the adapter at all.
        self.assertIsNotNone(self.b["digest"], "no ekka-backend release is pinned")
        self.assertRegex(bi.image(self.b), r"^ghcr\.io/ekka-labs/ekka-backend@sha256:[0-9a-f]{64}$")

    def test_the_identity_is_exactly_the_one_named_for_the_move(self):
        self.assertEqual(bi.identity(self.b), IDENTITY)

    def test_one_line_moves_the_image_and_the_identity_together(self):
        b = dict(self.b, digest=DIGEST)
        self.assertEqual(bi.image(b), f"ghcr.io/ekka-labs/ekka-backend@{DIGEST}")
        self.assertRegex(RELEASED, bi.identity(b))
        self.assertNotRegex(RELEASED.replace("ekka-labs", "another-org"), bi.identity(b),
                            "a release signed in another organization is refused")

    def test_planted_the_identity_accepts_only_this_repositorys_release_workflow_on_a_version_tag(self):
        rx = bi.identity(self.b)
        for other in (RELEASED.replace("ekka-labs/", "someone-else/"),
                      RELEASED.replace("ekka-backend/", "ekka-backend-fork/"),
                      RELEASED.replace("release.yml", "ci.yml"),
                      RELEASED.replace("refs/tags/v0.1.0", "refs/heads/main"),
                      RELEASED + "x"):
            self.assertNotRegex(other, rx, other)

    def test_planted_a_malformed_pin_is_refused_by_name(self):
        for key, value, says in (("registry", "docker.io/another-org", "registry"),
                                 ("digest", "latest", "digest"),
                                 ("release_workflow", "../release.yml", "release_workflow"),
                                 ("cosign_image", "gcr.io/projectsigstore/cosign:latest", "cosign_image")):
            b = copy.deepcopy(self.b)
            b[key] = value
            self.assertTrue(any(says in e for e in bi.shape_errors(b)), key)

    def test_no_image_until_a_digest_is_pinned(self):
        with self.assertRaisesRegex(ValueError, "no ekka-backend digest is pinned"):
            bi.image(dict(self.b, digest=None))

    def test_the_cosign_image_is_pinned_by_digest(self):
        # The Enclave itself is installed by EKKA's installer with the host's cosign; this image checks the adapter only.
        self.assertRegex(self.b["cosign_image"], r"^gcr\.io/projectsigstore/cosign:v[0-9.]+@sha256:[0-9a-f]{64}$")


class PullAndVerify(unittest.TestCase):
    def test_nothing_is_pulled_while_no_release_is_pinned(self):
        r, calls = run("step_backend_image", [], root=copy_with(dict(bi.load(), digest=None)))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(calls, [])

    def test_the_pinned_digest_is_pulled_and_its_signature_checked_against_the_release_workflow(self):
        root = copy_with(dict(bi.load(), digest=DIGEST))
        r, calls = run("step_backend_image", [], root=root)
        self.assertEqual(r.returncode, 0, r.stderr)
        image = f"ghcr.io/ekka-labs/ekka-backend@{DIGEST}"
        self.assertEqual(calls[0]["argv"], ["pull", "-q", image])
        verify = calls[1]["argv"]
        self.assertEqual(verify[0], "run")
        cosign_at = verify.index(bi.load()["cosign_image"])
        self.assertEqual(verify[cosign_at + 1], "verify", "cosign is asked to VERIFY, not anything else")
        self.assertEqual(verify[verify.index("--certificate-identity-regexp") + 1], bi.identity(bi.load()))
        self.assertEqual(verify[verify.index("--certificate-oidc-issuer") + 1], bi.ISSUER)
        self.assertEqual(verify[-1], image)
        self.assertFalse(any("docker-config" in a or "DOCKER_CONFIG" in a or ".docker" in a for a in verify),
                         "a public image: cosign is given none of this machine's Docker logins")

    def test_the_verified_image_writes_the_shipped_baseline_to_the_state_folder(self):
        root = copy_with(dict(bi.load(), digest=DIGEST))
        state = os.path.join(tempfile.mkdtemp(), "state")
        r, calls = run("step_backend_image", [], root=root, env_extra={"DESKS_STATE": state})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(calls), 5)
        args = calls[-1]["argv"]
        self.assertEqual(args[:3], ["tools/desk_records.py", "baseline", "desk/policy.json"])
        self.assertEqual(args[3], os.path.join(state, "backend", "baseline-policy.json"))
        self.assertEqual(calls[-2]["argv"][:2], ["image", "inspect"])

    def test_a_failed_or_unconfirmed_baseline_write_stops_the_step(self):
        for rc in ("1", "3"):
            with self.subTest(rc=rc):
                r, calls = run("step_backend_image", [], root=copy_with(dict(bi.load(), digest=DIGEST)),
                               env_extra={"RECORD_RC": rc})
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("the baseline policy record could not be confirmed", r.stderr)
                self.assertEqual(calls[-1]["argv"][0], "tools/desk_records.py")

    def test_the_pulled_image_is_checked_for_this_machines_processor_type(self):
        root = copy_with(dict(bi.load(), digest=DIGEST))
        image = f"ghcr.io/ekka-labs/ekka-backend@{DIGEST}"
        for arch in ("amd64", "arm64"):
            r, calls = run("step_backend_image", [], root=root, env_extra={"DOCKER_ARCH": arch, "IMAGE_ARCH": arch})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(calls[2]["argv"], ["version", "--format", "{{.Server.Arch}}"])
            self.assertEqual(calls[3]["argv"], ["image", "inspect", "--format", "{{.Architecture}}", image])

    def test_planted_an_image_built_for_another_processor_type_is_refused_by_name(self):
        # An ekka-backend release published for amd64 only, on an aarch64 machine: it would pull, then never start.
        root = copy_with(dict(bi.load(), digest=DIGEST))
        r, calls = run("step_backend_image", [], root=root, env_extra={"DOCKER_ARCH": "arm64", "IMAGE_ARCH": "amd64"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("built for 'amd64', and this machine runs 'arm64' images", r.stderr)
        self.assertNotIn("ok: backend adapter", r.stdout)
        self.assertFalse(any(c["argv"][0] == "tools/desk_records.py" for c in calls))

    def test_planted_an_image_that_is_not_signed_by_the_release_workflow_never_runs(self):
        root = copy_with(dict(bi.load(), digest=DIGEST))
        r, calls = run("step_backend_image", [], root=root, env_extra={"VERIFY_RC": "1"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not signed by EKKA's release workflow", r.stderr)
        self.assertFalse(any(c["argv"][0] == "tools/desk_records.py" for c in calls))


class UpSh(unittest.TestCase):
    def test_up_sh_runs_it(self):
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("step_images; step_backend_image; step_enclave_install; step_init;", text)
        steps = text.split("step_preflight; step_host_accounts;", 1)[1]
        self.assertLess(steps.index("step_backend_image;"), steps.index("step_start;"))

    def test_the_public_backend_image_is_pulled_with_no_registry_login(self):
        """The backend adapter's image is public (owner, 2026-10-17): its step signs in nowhere and uses no kept credential.
        Registry credentials are only for project images (`sudo ekka desk registry login`,
        `sudo ekka desk image pull`); the backend step must never reach for them."""
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
        step = re.search(r"^step_backend_image\(\) \{.*?^\}\n", text, re.S | re.M).group(0)
        self.assertNotRegex(step, r"docker [^\n]*login", "no Docker sign-in; the comment may say the word")
        self.assertNotIn("registry_", step, "none of the credential helpers")
        self.assertNotIn("--config", step, "no Docker config but the default, which holds no login")
        self.assertIn("docker pull -q", step)


if __name__ == "__main__":
    unittest.main()
