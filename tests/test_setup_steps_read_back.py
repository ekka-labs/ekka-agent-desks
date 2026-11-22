"""Two up.sh steps that once reported success on what they were told, not on what is there.

install_cli runs under a caller's `||` (as_gateway_admin's callers), which switches set -e off: every step is checked
by hand, and the CLI at our path must then name the pinned version. admin_setup accepts "already" from the gateway,
so the workspace and the Enclave's membership are read back before the setup counts as done. Each function runs from
up.sh exactly, with NVIDIA's CLI and the download stubbed.
"""
import os
import re
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SUB = "0a0b0c0d-1111-4222-8333-444455556666"


def function(name):
    with open(os.path.join(ROOT, "up.sh"), encoding="utf-8") as f:
        text = f.read()
    return re.search(rf"^{name}\(\) \{{.*?^\}}\n", text, re.S | re.M).group(0)


def run(script, env=None):
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, cwd=ROOT, timeout=60,
                          env=dict(os.environ, **(env or {})))


class TheCliIsInstalledOrNothingIs(unittest.TestCase):
    def install(self, tar_body):
        d = tempfile.mkdtemp()
        script = f"""
set -euo pipefail
OS={d}/bin/openshell; OPENSHELL_TAG=v0.1.9; OPENSHELL_CLI_SHA=pinned; OPENSHELL_CLI_FILE=os.tgz; MACHINE=x86_64
die() {{ echo "die: $*" >&2; exit 1; }}
ok() {{ echo "ok: $*"; }}
fetch_pinned() {{ : > "$2"; }}
tar() {{ {tar_body}; }}
# GNU install's -D (the servers'): create the parent folders. macOS's install takes -D differently.
install() {{ local dest=${{@: -1}} src=${{@: -2:1}}; mkdir -p "$(dirname "$dest")" && cp "$src" "$dest" && chmod 0755 "$dest"; }}
{function("install_cli")}
rc=0; install_cli || rc=$?
echo "rc=$rc"
"""
        return run(script)

    def test_an_archive_that_does_not_unpack_is_never_reported_installed(self):
        r = self.install("return 2")
        self.assertNotIn("ok: installed", r.stdout)
        self.assertNotIn("rc=0", r.stdout)
        self.assertIn("could not be unpacked", r.stderr)

    def test_a_cli_that_does_not_name_the_pinned_version_is_never_used(self):
        # The archive unpacks to a CLI of another version: it must not be taken for the pinned one.
        r = self.install('mkdir -p "$4"; printf \'#!/bin/sh\\necho "openshell 0.1.4"\\n\' > "$4/openshell"; '
                         'chmod 0755 "$4/openshell"')
        self.assertNotIn("ok: installed", r.stdout)
        self.assertNotIn("rc=0", r.stdout)
        self.assertIn("does not report version 0.1.9", r.stderr)

    def test_the_pinned_cli_is_installed(self):
        r = self.install('mkdir -p "$4"; printf \'#!/bin/sh\\necho "openshell 0.1.9"\\n\' > "$4/openshell"; '
                         'chmod 0755 "$4/openshell"')
        self.assertIn("ok: installed", r.stdout, r.stderr)
        self.assertIn("rc=0", r.stdout)


class TheSetupReadsBackTheWorkspace(unittest.TestCase):
    def setup(self, listed):
        d = tempfile.mkdtemp()
        cli = os.path.join(d, "os")
        with open(cli, "w") as f:
            f.write(f"""#!/bin/sh
[ "$1" = -g ] && shift 2
case "$1 $2 $3" in
  "workspace create "*) echo "error: the gateway refused the request" >&2; exit 1 ;;
  "workspace member add") echo "error: the gateway refused the request" >&2; exit 1 ;;
  "workspace member list") printf '%s' '{listed}' ;;
esac
""")
        os.chmod(cli, 0o755)
        script = f"""
set -euo pipefail
OS={cli}
sync_profiles() {{ echo synced; }}
{function("admin_setup")}
rc=0; admin_setup {SUB} || rc=$?
echo "rc=$rc"
"""
        return run(script)

    def test_a_workspace_that_does_not_hold_the_enclave_is_not_a_finished_setup(self):
        r = self.setup('{"members": [], "next_page_token": ""}')
        self.assertNotIn("synced", r.stdout, "the setup went on as if the Enclave were a member")
        self.assertNotIn("rc=0", r.stdout)
        self.assertIn("does not hold the Enclave", r.stderr)

    def test_a_workspace_that_cannot_be_read_back_is_not_a_finished_setup(self):
        r = self.setup("not a member list")
        self.assertNotIn("synced", r.stdout)
        self.assertNotIn("rc=0", r.stdout)

    def test_an_already_made_workspace_and_membership_are_accepted(self):
        r = self.setup('{"members": [{"subject": "%s", "role": "user"}], "next_page_token": ""}' % SUB)
        self.assertIn("synced", r.stdout, r.stderr)
        self.assertIn("rc=0", r.stdout)


if __name__ == "__main__":
    unittest.main()
