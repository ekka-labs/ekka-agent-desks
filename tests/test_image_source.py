"""The desk image is built from this repository's own recipe, desk/image, at this commit: no other source is fetched."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
IMAGE_ID = 'sha256:' + 'cd' * 32

RECORD_STUB = r'''import json, os, sys
with open(os.environ['CALLS'], 'a') as f:
    f.write(json.dumps({'argv': sys.argv}) + '\n')
sys.exit(int(os.environ['RECORD_RC']))
'''

DOCKER_STUB = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f:
    f.write(json.dumps({'argv': ['docker'] + args}) + '\n')
if args[:2] == ['image', 'inspect']:
    if args[2:4] == ['--format', '{{.Id}}']:
        if os.environ['INSPECT_RC'] != '0':
            sys.exit(int(os.environ['INSPECT_RC']))
        print(os.environ['IMAGE_ID'])
    else:
        print(os.environ['SOURCE_LABEL'])
elif args[:1] == ['build']:
    print('sha256:' + 'ef' * 32)
    sys.exit(int(os.environ['BUILD_RC']))
else:
    sys.exit('unexpected Docker command')
'''


class OwnImageSource(unittest.TestCase):
    def run_images(self, missing=False, unchanged=False, pinned=True, record_rc=0, inspect_rc=0, build_rc=0):
        text = (ROOT / 'up.sh').read_text()
        function = re.search(r'^step_images\(\) \{.*?^\}', text, re.M | re.S).group(0)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / 'desk/image'
            image.mkdir(parents=True)
            recipe = 'FROM scratch\n'
            if not missing:
                (image / 'Dockerfile').write_text(recipe)
            (root / 'tools').mkdir()
            shutil.copyfile(ROOT / 'tools/backend_image.py', root / 'tools/backend_image.py')
            # The real writer refuses temporary state under untrusted parents. Stub only this copied command;
            # test_desk_records exercises its ownership, path and atomic-write checks.
            (root / 'tools/desk_records.py').write_text(RECORD_STUB)
            (root / 'deploy').mkdir()
            pins = json.loads((ROOT / 'deploy/pins.json').read_text())
            pins['ekka_backend']['digest'] = 'sha256:' + 'ab' * 32 if pinned else None
            (root / 'deploy/pins.json').write_text(json.dumps(pins))
            (root / 'bin').mkdir()
            (root / 'bin/docker').write_text(DOCKER_STUB)
            (root / 'bin/docker').chmod(0o755)
            state = root / 'state with spaces'
            calls = root / 'calls'
            script = '''set -euo pipefail
say() { :; }; ok() { :; }; die() { echo "$*" >&2; exit 1; }
git() { printf '{"argv": ["git"]}\\n' >> "$CALLS"; return 0; }
''' + function + '\nstep_images\necho continued\n'
            result = subprocess.run(['bash', '-c', script], cwd=root, capture_output=True, text=True, timeout=30,
                env=dict(os.environ, ROOT=str(root), CALLS=str(calls), PATH=f"{root / 'bin'}:{os.environ['PATH']}",
                         OPENSHELL_TAG='v0.1.4', EKKA_VERSION='test', DESKS_STATE=str(state), IMAGE_ID=IMAGE_ID,
                         SOURCE_LABEL=hashlib.sha256(recipe.encode()).hexdigest()[:16] if unchanged else '',
                         RECORD_RC=str(record_rc), INSPECT_RC=str(inspect_rc), BUILD_RC=str(build_rc)))
            seen = [json.loads(line)['argv'] for line in calls.read_text().splitlines()] if calls.exists() else []
            return result, seen, state

    def test_build_uses_this_repositorys_own_recipe_and_fetches_nothing(self):
        result, calls, state = self.run_images()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c[0] == 'git' for c in calls), 'the image source is this checkout; nothing is fetched')
        build = next(c for c in calls if c[:2] == ['docker', 'build'])
        self.assertEqual(build[-1], str(state.parent / 'desk/image'))

    def test_a_missing_recipe_stops_before_any_build(self):
        result, calls, _ = self.run_images(missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIn('desk image source is missing', result.stderr)

    def test_the_record_uses_the_inspected_id_after_a_build_and_when_unchanged(self):
        for unchanged in (False, True):
            with self.subTest(unchanged=unchanged):
                result, calls, state = self.run_images(unchanged=unchanged)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls[0], ['docker', 'image', 'inspect', '-f',
                                           '{{index .Config.Labels "ekka.desk.source"}}', 'ekka-desk:local'])
                self.assertEqual(len(calls), 3 if unchanged else 4)
                if not unchanged:
                    self.assertEqual(calls[1][:2], ['docker', 'build'])
                self.assertEqual(calls[-2], ['docker', 'image', 'inspect', '--format', '{{.Id}}', 'ekka-desk:local'])
                self.assertEqual(calls[-1], ['tools/desk_records.py', 'image', IMAGE_ID,
                                            str(state / 'backend/desk-image.json')])
                self.assertIn('continued', result.stdout)

    def test_no_record_is_written_without_a_pinned_adapter(self):
        for unchanged in (False, True):
            with self.subTest(unchanged=unchanged):
                result, calls, _ = self.run_images(unchanged=unchanged, pinned=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(c[0] == 'tools/desk_records.py' for c in calls))
                self.assertFalse(any('{{.Id}}' in c for c in calls))
                self.assertIn('continued', result.stdout)

    def test_a_failed_or_unconfirmed_record_write_stops_the_step(self):
        for unchanged in (False, True):
            for rc in (1, 3):
                with self.subTest(unchanged=unchanged, rc=rc):
                    result, calls, _ = self.run_images(unchanged=unchanged, record_rc=rc)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('the desk image record could not be confirmed', result.stderr)
                    self.assertEqual(calls[-1][0], 'tools/desk_records.py')
                    self.assertNotIn('continued', result.stdout)

    def test_a_failed_inspection_stops_before_writing_a_record(self):
        result, calls, _ = self.run_images(inspect_rc=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('the desk image is not built', result.stderr)
        self.assertFalse(any(c[0] == 'tools/desk_records.py' for c in calls))
        self.assertNotIn('continued', result.stdout)

    def test_a_failed_build_stops_before_inspecting_or_writing_the_record(self):
        result, calls, _ = self.run_images(build_rc=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('the desk image did not build', result.stderr)
        self.assertEqual(calls[-1][:2], ['docker', 'build'])
        self.assertNotIn('continued', result.stdout)
