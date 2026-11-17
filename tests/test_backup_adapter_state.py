"""A backup carries the backend adapter's recovery store, and a restore puts it back or empties it.

The adapter keeps open operations and settlement holds in the ekka-backend-state volume. backup.sh saved the
gateway's volume and the Enclave's home but never this one, so a restore left the adapter's newer state beside older
gateway and Enclave state. The functions run here with docker stubbed:
the whole script needs root, and a real restore replaces /var/lib/ekka.
"""
import os
import re
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
BACKUP = os.path.join(ROOT, "deploy", "backup.sh")
# `docker volume ls`: the volume present, absent, or Docker failing to answer (exit 42).
DOCKER = '''echo "docker $*" >> "$CALLS"
if [ "$1 $2" = "volume ls" ]; then
  case ${VOL_STATE:-present} in present) echo ekka-desks_ekka-backend-state ;; absent) ;; error) exit 42 ;; esac
fi
exit 0'''


def read(path=BACKUP):
    with open(path) as f:
        return f.read()


def run(call, text=None, folder_has=(), vol_state="present"):
    """Run `call` (with $D the backup folder) on backup.sh's functions; (result, docker calls)."""
    text = text or read()
    parts = [re.search(r"^ALPINE=.*\n", text, re.M).group(0)]
    for name in ("say", "die", "vol"):
        parts.append(re.search(rf"^{name}\(\) +\{{[^\n]*\}}\n", text, re.M).group(0))
    for name in ("backend_volume", "save_backend_state", "restore_backend_state"):
        parts.append(re.search(rf"^{name}\(\) +\{{.*?^\}}\n", text, re.S | re.M).group(0))
    d = tempfile.mkdtemp()
    for f in folder_has:
        open(os.path.join(d, f), "w").close()
    stubs = os.path.join(d, "bin")
    os.mkdir(stubs)
    with open(os.path.join(stubs, "docker"), "w") as f:
        f.write("#!/bin/sh\n" + DOCKER + "\n")
    os.chmod(os.path.join(stubs, "docker"), 0o755)
    calls = os.path.join(d, "calls")
    env = dict(os.environ, PATH=stubs + os.pathsep + os.environ["PATH"], CALLS=calls, VOL_STATE=vol_state, D=d)
    r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + "".join(parts) + call + "\n"],
                       capture_output=True, text=True, env=env, timeout=30)
    made = []
    if os.path.exists(calls):
        with open(calls) as f:
            made = f.read().splitlines()
    return r, made


BACKUP_STEP = 'adapter=$(backend_volume); save_backend_state "$D" "$adapter"'


def docker_error_stops_the_backup(text=None):
    """True when Docker failing to answer stops the backup: an error, no archive, no "none to back up"."""
    r, calls = run(BACKUP_STEP, text, vol_state="error")
    return r.returncode != 0 and not any(c.startswith("docker run") for c in calls) and "none to back up" not in r.stdout


def asked_before_stop_and_saved_after(text):
    backup = text[text.index("  backup)"):text.index("  restore)")]
    try:
        return (backup.index("adapter=$(backend_volume)") < backup.index("stop_writers")
                < backup.index('save_backend_state "$d" "$adapter"'))
    except ValueError:
        return False


class TheAdapterStateTravelsWithTheBackup(unittest.TestCase):
    def test_a_server_with_the_adapter_saves_its_volume(self):
        r, calls = run(BACKUP_STEP)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any("ekka-desks_ekka-backend-state:/v" in c and "/b/ekka-backend-state.tgz" in c
                            and "-czpf" in c for c in calls), calls)

    def test_a_server_without_the_adapter_creates_no_volume(self):
        # `docker run -v name:/v` would silently create an empty volume: none is run when there is none.
        r, calls = run(BACKUP_STEP, vol_state="absent")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(any(c.startswith("docker run") for c in calls), calls)
        self.assertIn("none to back up", r.stdout)

    def test_docker_failing_to_answer_stops_the_backup(self):
        # An error read as "no adapter" made a backup without its state, and restoring that emptied the store.
        self.assertTrue(docker_error_stops_the_backup())

    def test_it_is_asked_before_the_writers_stop_and_saved_after(self):
        self.assertTrue(asked_before_stop_and_saved_after(read()))

    def test_a_restore_puts_the_saved_state_back(self):
        r, calls = run('restore_backend_state "$D"', folder_has=["ekka-backend-state.tgz"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(calls[:2], ["docker volume rm -f ekka-desks_ekka-backend-state",
                                     "docker volume create ekka-desks_ekka-backend-state"])
        self.assertTrue(any("-xzpf /b/ekka-backend-state.tgz" in c for c in calls), calls)

    def test_a_backup_without_it_restores_an_empty_store_not_a_newer_one(self):
        r, calls = run('restore_backend_state "$D"')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(calls, ["docker volume rm -f ekka-desks_ekka-backend-state"])
        self.assertIn("starts empty", r.stdout)

    def test_the_restore_runs_after_the_writers_stop(self):
        text = read()
        restore = text[text.index("  restore)"):]
        self.assertLess(restore.index("stop_writers"), restore.index('restore_backend_state "$d"'))

    def test_planted_an_error_read_as_no_adapter_fails_the_same_check(self):
        text = read()
        planted = text.replace('|| die "Docker did not answer', '|| true # "Docker did not answer')
        self.assertNotEqual(planted, text)
        self.assertFalse(docker_error_stops_the_backup(planted), "PLANTED: an error read as no adapter passes")

    def test_planted_a_backup_that_skips_the_save_fails_the_same_check(self):
        text = read()
        planted = text.replace('    save_backend_state "$d" "$adapter"\n', "")
        self.assertNotEqual(planted, text)
        self.assertFalse(asked_before_stop_and_saved_after(planted), "PLANTED: a backup without the save passes")


if __name__ == "__main__":
    unittest.main()
