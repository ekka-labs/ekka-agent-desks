"""The desk image is built from this repository's own recipe, desk/image, at this commit: no other source is fetched."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class OwnImageSource(unittest.TestCase):
    def run_images(self, missing=False):
        text = (ROOT / 'up.sh').read_text()
        function = re.search(r'^step_images\(\) \{.*?^\}', text, re.M | re.S).group(0)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / 'desk/image'
            image.mkdir(parents=True)
            if not missing:
                (image / 'Dockerfile').write_text('FROM scratch\n')
            calls = root / 'calls'
            script = '''set -euo pipefail
say() { :; }; ok() { :; }; die() { echo "$*" >&2; exit 1; }
git() { printf 'git %s\\n' "$*" >> "$CALLS"; return "$GIT_STATUS"; }
docker() { printf 'docker %s\\n' "$*" >> "$CALLS"; return 0; }
''' + function + '\nstep_images\n'
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                env=dict(os.environ, ROOT=str(root), CALLS=str(calls), GIT_STATUS='0',
                         OPENSHELL_TAG='v0.1.4', EKKA_VERSION='test', DESKS_STATE=str(root)))
            return result, (calls.read_text() if calls.exists() else '')

    def test_build_uses_this_repositorys_own_recipe_and_fetches_nothing(self):
        result, calls = self.run_images()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('git ', calls, 'the image source is this checkout; nothing is fetched at install')
        self.assertRegex(calls, r'docker build .*/desk/image(\s|$)')

    def test_a_missing_recipe_stops_before_any_build(self):
        result, calls = self.run_images(missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('docker build', calls)
        self.assertIn('desk image source is missing', result.stderr)
