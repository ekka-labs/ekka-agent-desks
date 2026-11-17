"""This setup and the Enclave upgrade together.

This setup installs the backend adapter and makes people's sign-ins read only. Only an Enclave release whose
`ekka desk` runs EKKA's plans works with it, so up.sh refuses an older one by name, and turns the adapter on
at the image pins.json pins. There is no older path (the owner's ruling: no backward compatibility).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
GATE = os.path.join(ROOT, "tools", "release_gate.py")
DIGEST = "sha256:" + "b" * 64
IMAGE = "ghcr.io/example/ekka-backend@" + DIGEST
BACKEND = {"registry": "ghcr.io/example", "digest": DIGEST, "release_workflow": ".github/workflows/release.yml",
           "cosign_image": "gcr.io/projectsigstore/cosign:v2.6.5@sha256:" + "c" * 64}


def gate(have, need):
    return subprocess.run([sys.executable, GATE, have, need], capture_output=True, text=True).returncode


def up_function(name):
    with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", text, re.S | re.M)
    assert m, f"{name} is not in up.sh"
    return m.group(0)


def bash(script, cwd=ROOT):
    return subprocess.run(["bash", "-c", "set -euo pipefail\n" + script], cwd=cwd, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=30)


STUBS = """
ok() { echo "ok: $*"; }
die() { echo "die: $*" >&2; exit 1; }
say() { :; }
host_env_files() { :; }      # /etc/ekka/desks.env and /etc/hosts: root's, not a test's
openshell_gid() { echo 990; }
"""


class TheVersionGate(unittest.TestCase):
    def test_equal_or_newer_passes_and_older_does_not(self):
        self.assertEqual(gate("0.1.112", "0.1.112"), 0)
        self.assertEqual(gate("0.1.113", "0.1.112"), 0)
        self.assertEqual(gate("0.2.0", "0.1.112"), 0)
        self.assertEqual(gate("v0.1.112", "0.1.112"), 0)
        self.assertEqual(gate("0.1.111", "0.1.112"), 1)
        self.assertEqual(gate("0.1.9", "0.1.10"), 1, "numbers, not text: 9 is older than 10")

    def test_a_version_it_cannot_read_is_never_new_enough(self):
        for bad in ("", "latest", "0.1", "0.1.112-rc1", "0.1.x"):
            with self.subTest(bad=bad):
                self.assertEqual(gate(bad, "0.1.112"), 2)


class UpShRefusesAnOlderEnclave(unittest.TestCase):
    def run_gate(self, have, need):
        return bash(STUBS + f"EKKA_VERSION={have}\nDESK_ADMIN_MIN_EKKA={need}\n" + up_function("release_gate") + "release_gate")

    def test_an_older_enclave_is_refused_naming_both_releases_and_the_window(self):
        r = self.run_gate("0.1.109", "0.1.112")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("needs EKKA 0.1.112 or newer, and this machine runs 0.1.109", r.stderr)
        self.assertIn("upgrade together", r.stderr)

    def test_the_named_release_or_newer_installs(self):
        for have in ("0.6.8", "0.6.9"):
            with self.subTest(have=have):
                r = self.run_gate(have, "0.6.8")
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_no_named_release_refuses_every_install(self):
        r = self.run_gate("0.1.112", "")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("names none yet", r.stderr)

    def test_an_unreadable_release_is_refused(self):
        self.assertNotEqual(self.run_gate("latest", "0.1.112").returncode, 0)

    def test_the_shipped_default_release_meets_the_shipped_floor(self):
        # A fresh install runs the default EKKA_VERSION. If the floor moves and the default does not, every new
        # install is refused by its own default.
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
        floor = re.search(r"^DESK_ADMIN_MIN_EKKA=(\S*)$", text, re.M).group(1)
        default = re.search(r"retained \"\$DESKS_STATE\" EKKA_VERSION (\S+?)\)\}$", text, re.M).group(1)
        self.assertEqual(floor, "0.6.8", "the first runner using only the two general desk plans")
        self.assertEqual(default, "0.6.9")
        self.assertEqual(gate(default, floor), 0, f"the default {default} is older than the floor {floor}")
        self.assertEqual(self.run_gate(default, floor).returncode, 0)

    def test_no_fallback_release_is_older_than_the_floor(self):
        # 2026-10-14 (deploy/backup.sh): a compose run without up.env came back on compose.yml's fallback, a 0.1.105
        # Enclave below a release that cannot be rolled back. Every fallback names a release the floor admits.
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            floor = re.search(r"^DESK_ADMIN_MIN_EKKA=(\S*)$", f.read(), re.M).group(1)
        # The Enclave is no longer a compose service: the release is pinned by up.sh alone (EKKA_VERSION, retained in
        # up.env), installed by EKKA's installer. compose.yml carries NO EKKA_VERSION fallback at all.
        with open(os.path.join(ROOT, "deploy", "compose.yml"), encoding="utf-8") as f:
            self.assertEqual(re.findall(r"\$\{EKKA_VERSION[^}]*\}", f.read()), [])
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            default = re.search(r"retained \"\$DESKS_STATE\" EKKA_VERSION (\S+?)\)\}$", f.read(), re.M).group(1)
        self.assertEqual(gate(default, floor), 0, f"up.sh falls back to {default}, older than the floor {floor}")

    def test_preflight_runs_the_gate(self):
        self.assertIn("release_gate", up_function("step_preflight"))
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            run = re.search(r"^step_preflight; .*$", f.read(), re.M).group(0).split("; ")
        self.assertLess(run.index("step_preflight"), run.index("step_start"), "refused before anything starts")

    def test_a_retained_older_release_is_refused_with_the_upgrade_line(self):
        # A home installed at 0.6.7 saved EKKA_VERSION=0.6.7 in up.env. A plain rerun keeps it, so the
        # gate must refuse it by name and say how to upgrade; an explicit EKKA_VERSION at the floor passes.
        with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
            text = f.read()
        pick = re.search(r"^EKKA_VERSION=\$\{EKKA_VERSION:-.*\}$", text, re.M).group(0)
        floor = re.search(r"^DESK_ADMIN_MIN_EKKA=\S*$", text, re.M).group(0)
        state = tempfile.mkdtemp()
        with open(os.path.join(state, "up.env"), "w") as f:
            f.write("EKKA_VERSION=0.6.7\nEKKA_ENV=prod\n")
        script = f"{STUBS}DESKS_STATE={state}\n{floor}\n{up_function('release_gate')}\n"
        r = bash(f"{script}unset EKKA_VERSION; {pick}\nrelease_gate")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("this machine runs 0.6.7", r.stderr)
        self.assertIn("run again with EKKA_VERSION=0.6.8", r.stderr)
        self.assertEqual(bash(f"{script}EKKA_VERSION=0.6.8; {pick}\nrelease_gate").returncode, 0)
        shutil.rmtree(state)


class KeepInstalledNewerRelease(unittest.TestCase):
    def select(self, installed, retained=None, explicit=None, allow_downgrade=False):
        with tempfile.TemporaryDirectory() as state:
            if retained:
                with open(os.path.join(state, 'up.env'), 'w') as stream:
                    stream.write('EKKA_VERSION=' + retained + '\n')
            with open(os.path.join(ROOT, 'up.sh')) as stream:
                text = stream.read()
            pick = re.search(r'^EKKA_VERSION=\$\{EKKA_VERSION:-.*\}$', text, re.M).group(0)
            script = STUBS + f'DESKS_STATE={state}\n'
            script += 'unset EKKA_VERSION\n' if explicit is None else f'EKKA_VERSION={explicit}\n'
            script += 'EKKA_VERSION_EXPLICIT=${EKKA_VERSION:+yes}\n' + pick + '\n'
            script += 'EKKA_ALLOW_DOWNGRADE=' + ('1' if allow_downgrade else '0') + '\n'
            script += f'installed_enclave_version() {{ echo "{installed}"; }}\n'
            script += up_function('keep_newer_enclave') + 'keep_newer_enclave\necho "$EKKA_VERSION"'
            result = bash(script)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

    def test_fresh_default_and_retained_versions(self):
        self.assertEqual(self.select(''), '0.6.9')
        self.assertEqual(self.select('', retained='0.6.8'), '0.6.8')
        self.assertEqual(self.select('0.6.9', retained='0.6.10'), '0.6.10')

    def test_existing_runner_never_downgrades_for_implicit_version(self):
        for have in ('0.6.9', '0.6.10', '0.7.0', '1.0.0'):
            for retained in (None, '0.6.8', '0.6.9'):
                with self.subTest(have=have, retained=retained):
                    self.assertEqual(self.select(have, retained), have)
        self.assertEqual(self.select('0.7.0', allow_downgrade=True), '0.7.0')

    def test_preserved_newer_runner_never_downloads_the_default(self):
        script = STUBS + """
EKKA_VERSION=0.6.9; EKKA_VERSION_EXPLICIT=; SNAPSHOT=/unused
installed_enclave_version() { echo 0.7.0; }
curl() { echo UNEXPECTED_DOWNLOAD; return 1; }
render() { :; }
""" + up_function('keep_newer_enclave') + up_function('step_enclave_install')
        result = bash(script + 'keep_newer_enclave\nstep_enclave_install')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('UNEXPECTED_DOWNLOAD', result.stdout)
        self.assertIn('ekka 0.7.0 at /usr/local/bin/ekka', result.stdout)

    def test_explicit_older_request_is_left_for_installers_downgrade_gate(self):
        self.assertEqual(self.select('0.7.0', explicit='0.6.9'), '0.6.9')
        self.assertEqual(self.select('0.7.0', explicit='0.6.9', allow_downgrade=True), '0.6.9')
        fn = up_function('step_enclave_install')
        self.assertIn('[[ ${EKKA_ALLOW_DOWNGRADE:-} == 1 ]] && downgrade=(--allow-downgrade)', fn)

    def test_selection_precedes_writing_retained_settings(self):
        preflight = up_function('step_preflight')
        self.assertLess(preflight.index('keep_newer_enclave'), preflight.index('  release_gate'))
        with open(os.path.join(ROOT, 'up.sh')) as stream:
            chain = re.search(r'^step_preflight; .*$', stream.read(), re.M).group(0)
        self.assertLess(chain.index('step_preflight'), chain.index('step_settings'))


class TheAdapterIsOnAtItsPinnedImage(unittest.TestCase):
    def settings(self, pins, config=True):
        work = tempfile.mkdtemp()
        os.makedirs(os.path.join(work, "deploy"))
        shutil.copytree(os.path.join(ROOT, "tools"), os.path.join(work, "tools"))
        with open(os.path.join(work, "deploy", "pins.json"), "w") as f:
            json.dump(pins, f)
        state = os.path.join(work, "state")
        if config:   # an install whose adapter configuration step_desk_admin already wrote
            os.makedirs(os.path.join(state, "backend"))
            open(os.path.join(state, "backend", "config.json"), "w").close()
        script = STUBS + f"""
DESKS_STATE={state}; MODE=server; NAME=desks.example.test; EKKA_VERSION=0.6.8; EKKA_ENV=prod
OPENSHELL_TELEMETRY=off
ip() {{ echo "1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.10"; }}
stat() {{ echo 999; }}
""" + up_function("step_settings") + "step_settings"
        r = bash(script, cwd=work)
        env = os.path.join(state, "up.env")
        text = ""
        if os.path.exists(env):
            with open(env) as f:
                text = f.read()
        shutil.rmtree(work)
        return r, text

    def test_up_env_turns_the_profile_on_at_the_pinned_digest_once_its_configuration_exists(self):
        r, env = self.settings({"openshell": {}, "ekka_backend": BACKEND})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("COMPOSE_PROFILES=desk-admin\n", env)
        self.assertIn(f"EKKA_BACKEND_IMAGE={IMAGE}\n", env)

    def test_a_server_listens_on_every_address_and_names_the_one_people_reach(self):
        r, env = self.settings({"openshell": {}, "ekka_backend": BACKEND})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DESKS_EDGE_BIND=0.0.0.0\n", env)
        self.assertIn("DESKS_GATEWAY_BIND=0.0.0.0\n", env)
        self.assertIn("DESKS_ADDRESS=192.0.2.10\n", env, "this machine's own source address, from the route")

    def test_planted_a_fresh_install_with_no_configuration_does_not_start_the_adapter_and_says_why(self):
        # regression review: COMPOSE_PROFILES in up.env is honored by --env-file (measured, Compose 5.5.1), so
        # on a fresh install the first `up` would start the adapter before step_desk_admin writes its config.
        r, env = self.settings({"openshell": {}, "ekka_backend": BACKEND}, config=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("COMPOSE_PROFILES", env)
        self.assertIn(f"EKKA_BACKEND_IMAGE={IMAGE}\n", env, "the image is pinned all the same")
        self.assertIn("the backend adapter starts once its configuration is written", r.stdout)

    def test_the_adapter_starts_only_after_its_configuration_is_written(self):
        body = up_function("step_desk_admin")
        written, on, started = (body.index("write_adapter_config"), body.index("COMPOSE_PROFILES=desk-admin"),
                                body.index("systemctl restart ekka-desks"))
        self.assertLess(written, on)
        self.assertLess(on, started)

    def test_no_pinned_image_stops_before_up_env_is_written(self):
        r, env = self.settings({"openshell": {}, "ekka_backend": dict(BACKEND, digest=None)})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("names no ekka-backend image", r.stderr)
        self.assertEqual(env, "", "never an up.env with an empty image")


class TheUpgradeNote(unittest.TestCase):
    def test_says_the_kit_and_the_enclave_upgrade_together(self):
        with open(os.path.join(ROOT, "docs", "OPERATIONS.md"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("this setup and the Enclave together, in one maintenance window", text)
        self.assertIn("refuses to install on an older Enclave", text)


if __name__ == "__main__":
    unittest.main()
