"""Every binary up.sh downloads, fetched for real for THIS machine's processor type, by up.sh's own lines.

Online, so skipped unless EKKA_ONLINE_DOWNLOADS=1. CI runs it on an x86_64 runner and on an aarch64 runner
(.github/workflows/tests.yml, job `install`). For each download: up.sh's own fetch_pinned checks the pinned
sha256 of the publisher's file, and this test then reads the ELF header of what was installed, so a pin that
names the other processor type's file fails here. Docker Compose and buildx are fetched by the exact preflight
lines of up.sh, with a `docker` on PATH that says neither plugin is installed; the openshell CLI by install_cli.
"""
import os
import json
import platform
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# ELF e_machine: the processor type a Linux binary is built for.
E_MACHINE = {"x86_64": 62, "aarch64": 183}


def up_sh():
    with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
        return f.read()


def function(text, name):
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", text, re.S | re.M)
    assert m, f"{name} is not in up.sh"
    return m.group(0)


def elf_machine(path):
    with open(path, "rb") as f:
        head = f.read(20)
    if head[:4] != b"\x7fELF":
        return None
    return struct.unpack("<H", head[18:20])[0]


@unittest.skipUnless(os.environ.get("EKKA_ONLINE_DOWNLOADS") == "1", "online: set EKKA_ONLINE_DOWNLOADS=1")
@unittest.skipUnless(platform.system() == "Linux" and platform.machine() in E_MACHINE, "a Linux x86_64 or aarch64 machine")
class Downloads(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        os.makedirs(os.path.join(self.dir, "bin"))
        # A docker that has neither plugin, so the preflight lines download both.
        with open(os.path.join(self.dir, "bin", "docker"), "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(os.path.join(self.dir, "bin", "docker"), 0o755)

    def run_up_sh_lines(self, body):
        text = up_sh()
        pins = re.search(r"^COMPOSE_VER=.*?^esac\n", text, re.S | re.M).group(0)
        tag = re.search(r"^OPENSHELL_TAG=.*\n", text, re.M).group(0)
        script = f"""
set -euo pipefail
ok() {{ echo "ok: $*"; }}
die() {{ echo "die: $*" >&2; exit 1; }}
{tag}{pins}
{function(text, "fetch_pinned")}
{function(text, "install_cli")}
PLUGINS={self.dir}/plugins; OS={self.dir}/openshell
mkdir -p "$PLUGINS"
{body}
"""
        env = dict(os.environ, PATH=f"{self.dir}/bin:{os.environ['PATH']}")
        r = subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, env=env, timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout

    def assert_this_machine(self, path):
        self.assertTrue(os.path.isfile(path), path)
        self.assertEqual(elf_machine(path), E_MACHINE[platform.machine()],
                         f"{path} is not built for {platform.machine()}")

    def test_compose_and_buildx_are_this_machines_and_match_their_pins(self):
        lines = [line for line in up_sh().splitlines()
                 if re.match(r"^  docker (compose|buildx) version >/dev/null 2>&1 \|\| \{ fetch_pinned ", line)]
        self.assertEqual(len(lines), 2, "up.sh's preflight fetches Compose and buildx on one line each")
        out = self.run_up_sh_lines("\n".join(lines))
        self.assertIn(f"({platform.machine()})", out)
        self.assert_this_machine(os.path.join(self.dir, "plugins", "docker-compose"))
        self.assert_this_machine(os.path.join(self.dir, "plugins", "docker-buildx"))

    def test_the_openshell_cli_is_this_machines_matches_its_pin_and_runs(self):
        out = self.run_up_sh_lines("install_cli")
        self.assertIn(f"({platform.machine()}, pinned sha256)", out)
        cli = os.path.join(self.dir, "openshell")
        self.assert_this_machine(cli)
        version = subprocess.run([cli, "--version"], capture_output=True, text=True, timeout=60).stdout
        with open(os.path.join(ROOT, "deploy", "pins.json")) as source:
            tag = json.load(source)["openshell"]["version"]
        self.assertRegex(version, rf" {re.escape(tag)}$")


if __name__ == "__main__":
    unittest.main()
