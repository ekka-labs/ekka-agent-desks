"""Existing stopped desks and existing customized gateway files during upgrade."""
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import credential_bindings as bindings
import gateway_preflight as gp
from upgrade_desks import inventory


class UpgradeGuards(unittest.TestCase):
    def test_legacy_bootstrap_in_persisted_inventory_blocks_with_no_running_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            volume = Path(tmp).resolve()
            conn = sqlite3.connect(volume / "gateway.db")
            with conn:
                conn.execute("CREATE TABLE objects(id TEXT,name TEXT,object_type TEXT)")
                conn.execute("INSERT INTO objects VALUES ('id-1','code-desk','sandbox')")
            conn.close()
            folder = volume / ".local/state/openshell/docker-sandbox-tokens/ekka-desks/id-1"
            folder.mkdir(parents=True)
            record = folder / "boundary-bootstrap.json"
            record.write_text(json.dumps({"outer_fence": {}, "session_id": "private-fixture"}))
            before = record.read_bytes()
            with self.assertRaisesRegex(ValueError, "code-desk") as caught:
                inventory(volume, True)
            self.assertNotIn("private-fixture", str(caught.exception))
            self.assertEqual(record.read_bytes(), before)
            record.unlink()
            with self.assertRaisesRegex(ValueError, "cannot verify bootstrap"):
                inventory(volume, True)
            record.write_text(json.dumps({"provisioning_evidence": {}}))
            inventory(volume, True)

    def test_refresh_preserves_custom_settings_and_checks_both_interceptors(self):
        template = (ROOT / "deploy/gateway/gateway.toml.template").read_text()
        previous = template
        for phase, _ in bindings.REQUIRED.values():
            for method in bindings.METHODS:
                previous = previous.replace(bindings.block(method, phase), "")
        previous += '\n[operator_example]\ncustom = "preserve me"\n'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gateway.toml"
            path.write_text(previous)
            original = gp.read_toml(path)
            self.assertTrue(all(len(v) == 3 for v in bindings.missing(original).values()))
            bindings.refresh(path)
            after = gp.read_toml(path)
            self.assertEqual(after["operator_example"], original["operator_example"])
            self.assertFalse(any(bindings.missing(after).values()))
            stat = path.stat()
            bindings.refresh(path)
            self.assertEqual(path.stat().st_ino, stat.st_ino)
            path.write_text(previous.replace('failure_policy = "fail_closed"', 'failure_policy = "fail_open"'))
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                bindings.refresh(path)
            self.assertEqual(path.read_bytes(), before)
