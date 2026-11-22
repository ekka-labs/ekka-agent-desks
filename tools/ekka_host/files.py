"""Fixed root-owned host files and directories, without shell evaluation."""
import os
from pathlib import Path
import stat
import tempfile
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
            raise HostError("host settings must be root-owned and not writable by others")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o077 if private else 0o022):
            raise HostError("host settings must be regular root-owned files")
        try:
            with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
                text = stream.read(65537)
        except UnicodeError:
            raise HostError("host settings must be UTF-8 text") from None
        if len(text) > 65536:
            raise HostError("host settings are too large")
        return text
    finally:
        os.close(fd)


def private_destination(path):
    path = Path(path)
    root_directory(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
        raise HostError("a credential destination must be a single private root-owned regular file")


def atomic_secret(path, text):
    path = Path(path)
    private_destination(path)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)
