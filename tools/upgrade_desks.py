"""Read the default Docker gateway's persisted inventory before upgrading it."""
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from contextlib import closing

VOLUME = "ekka-desks_gateway-state"


def inventory(volume, installed):
    db = volume / "gateway.db"
    if not db.exists() and not installed:
        return
    if not db.is_file() or db.is_symlink():
        raise ValueError("cannot verify the installed gateway database")
    root = volume / ".local/state/openshell/docker-sandbox-tokens/ekka-desks"
    incompatible = []
    with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)) as conn:
        for identifier, name in conn.execute("SELECT id,name FROM objects WHERE object_type='sandbox'"):
            if not re.fullmatch(r"[a-zA-Z0-9_-]+", identifier):
                raise ValueError("gateway contains an invalid desk identifier")
            record = root / identifier / "boundary-bootstrap.json"
            if record.resolve() != record or not record.is_file():
                raise ValueError(f"cannot verify bootstrap for desk {name!r}; inspect the desk before upgrading")
            try:
                data = json.loads(record.read_bytes())
            except ValueError:
                raise ValueError(f"unreadable bootstrap for desk {name!r}") from None
            if not isinstance(data, dict) or "outer_fence" in data or not isinstance(data.get("provisioning_evidence"), dict):
                incompatible.append(repr(name or identifier))
    if incompatible:
        raise ValueError("incompatible stored desk bootstrap: " + ", ".join(incompatible)
                         + ". Preserve the desk's work and configuration, then retire the desk through EKKA "
                           "before upgrading. Recreate it after the upgrade. Stopping it alone is insufficient.")


def check(state):
    installed = (state / "up/started").is_file()
    names = subprocess.check_output(["docker", "volume", "ls", "--format", "{{.Name}}"], text=True).splitlines()
    if VOLUME not in names:
        if installed:
            raise ValueError("the installed gateway volume was not found; cannot verify existing desks")
        return
    mount = subprocess.check_output(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}", VOLUME], text=True).strip()
    if not os.path.isabs(mount) or not Path(mount).is_dir():
        raise ValueError("the gateway volume is not accessible on this host")
    inventory(Path(mount).resolve(), installed)


if __name__ == "__main__":
    try:
        check(Path(sys.argv[1]))
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError) as error:
        sys.exit(f"gateway upgrade refused: {error}")
