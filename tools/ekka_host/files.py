"""Fixed root-owned host files and directories, without shell evaluation."""
import os
from pathlib import Path
import stat
from .runtime import HostError


def root_directory(path):
    path = Path(path)
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise HostError("host settings directories must be root-owned and not writable by others")
    return path


def root_file(path, private=False):
    """Read fixed root-owned settings; reject links and writable ancestors."""
    path = Path(path)
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise HostError("host recovery settings must be root-owned and not writable by others")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o077 if private else 0o022):
            raise HostError("host recovery settings must be regular root-owned files")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
            text = stream.read(65537)
        if len(text) > 65536:
            raise HostError("host recovery settings are too large")
        return text
    finally:
        os.close(fd)

