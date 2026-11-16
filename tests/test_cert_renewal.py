"""`deploy/certs.sh renew` keeps each server key readable by the service that reads it.

setup.sh gives the edge's key to uid 101 (nginx-unprivileged) and the gateway's to uid 1000, once, at init. Renewal
runs as root under `umask 077` and replaced each key with a new root-owned one, so after the documented
renew-then-restart neither service could read its key (review of ekka-labs/ekka-agent-desks#1). A renewed key now
takes the owner the key it replaces had.

A test cannot make files owned by other users without root, so `stat` reports each service's real owner (the edge's
101:101, the gateway's 1000:1000) and `chown` records what it was asked to do.
"""
import os
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CERTS = os.path.join(ROOT, "deploy", "certs.sh")
OWNERS = {"gateway": "1000:1000", "edge": "101:101"}
OLD_KEY = "old key\n"


def renew(with_old_keys=True, script=CERTS):
    """Run `renew` on a fresh state folder; (result, chown calls, tls folder)."""
    d = tempfile.mkdtemp()
    tls = os.path.join(d, "tls")
    os.makedirs(tls)
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{tls}/ca.key"], check=True)
    subprocess.run(["openssl", "req", "-x509", "-new", "-key", f"{tls}/ca.key", "-subj", "/CN=test CA", "-days", "3650",
                    "-sha256", "-out", f"{tls}/ca.crt"], check=True, capture_output=True)
    if with_old_keys:
        for svc in OWNERS:
            os.makedirs(f"{tls}/{svc}")
            with open(f"{tls}/{svc}/tls.key", "w") as f:
                f.write(OLD_KEY)
    stubs = os.path.join(d, "bin")
    os.makedirs(stubs)
    calls = os.path.join(d, "calls")
    stub = {
        "chown": f'echo "chown $*" >> "{calls}"',
        # `stat -c %u:%g <file>` (Linux) or `stat -f %u:%g <file>` (BSD). Only the key being replaced belongs to its
        # service; anything else (the new key and certificate, made by root) is 0:0, as on a real renewal.
        "stat": 'for a; do f=$a; done\ncase $f in */gateway/tls.key) echo 1000:1000 ;; */edge/tls.key) echo 101:101 ;; *) echo 0:0 ;; esac',
    }
    for name, body in stub.items():
        with open(os.path.join(stubs, name), "w") as f:
            f.write(f"#!/bin/sh\n{body}\n")
        os.chmod(os.path.join(stubs, name), 0o755)
    env = dict(os.environ, DESKS_STATE=d, PATH=stubs + os.pathsep + os.environ["PATH"])
    r = subprocess.run(["bash", script, "renew", "desks.example"], capture_output=True, text=True, env=env, timeout=60)
    made = []
    if os.path.exists(calls):
        with open(calls) as f:
            made = f.read().splitlines()
    return r, made, tls


def problems(r, calls, tls):
    """What is wrong with a renewal that started from keys the services own: nothing for a good one."""
    found = []
    if r.returncode != 0:
        found.append(f"exit {r.returncode}: {r.stderr.strip()}")
    for svc, owner in OWNERS.items():
        if f"chown {owner} {tls}/{svc}/tls.key.new {tls}/{svc}/tls.crt.new" not in calls:
            found.append(f"{svc}: the new key and certificate were not given {owner}")
        with open(f"{tls}/{svc}/tls.key") as f:
            if f.read() == OLD_KEY:
                found.append(f"{svc}: the old key is still installed")
        cert = subprocess.run(["openssl", "x509", "-in", f"{tls}/{svc}/tls.crt", "-noout", "-subject"],
                              capture_output=True, text=True)
        if cert.returncode != 0 or "desks.example" not in cert.stdout:
            found.append(f"{svc}: no new certificate installed")
        for left in ("tls.key.new", "tls.crt.new"):
            if os.path.exists(f"{tls}/{svc}/{left}"):
                found.append(f"{svc}: {left} was left behind")
    return found


class ARenewedKeyKeepsItsOwner(unittest.TestCase):
    def test_each_service_keeps_its_own_owner_and_gets_a_new_key(self):
        self.assertEqual(problems(*renew()), [])

    def test_a_first_key_changes_no_owner(self):
        # init: no key to take an owner from; setup.sh gives the keys to their services right after.
        r, calls, _ = renew(with_old_keys=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(calls, [])

    def test_planted_a_renewal_that_keeps_no_owner_fails_the_same_check(self):
        with open(CERTS) as f:
            text = f.read()
        planted = text.replace('[[ -n $owner ]] && chown', '[[ -n $owner ]] && : chown')
        self.assertNotEqual(planted, text)
        path = os.path.join(tempfile.mkdtemp(), "certs.sh")
        with open(path, "w") as f:
            f.write(planted)
        found = problems(*renew(script=path))
        self.assertTrue(any("were not given 1000:1000" in p for p in found), found)
        self.assertTrue(any("were not given 101:101" in p for p in found), found)

    def test_planted_an_owner_read_from_the_new_key_fails_the_same_check(self):
        # Reading the owner of tls.key.new (root's) instead of the key it replaces keeps 0:0: unreadable by the service.
        with open(CERTS) as f:
            text = f.read()
        planted = text.replace('stat -c %u:%g "$dir/tls.key"', 'stat -c %u:%g "$dir/tls.key.new"') \
                      .replace('stat -f %u:%g "$dir/tls.key"', 'stat -f %u:%g "$dir/tls.key.new"')
        self.assertNotEqual(planted, text)
        path = os.path.join(tempfile.mkdtemp(), "certs.sh")
        with open(path, "w") as f:
            f.write(planted)
        found = problems(*renew(script=path))
        self.assertTrue(any("were not given 1000:1000" in p for p in found), found)
        self.assertTrue(any("were not given 101:101" in p for p in found), found)


if __name__ == "__main__":
    unittest.main()
