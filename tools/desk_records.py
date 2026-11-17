"""Records the installer writes for EKKA's desk commands, root-owned: readable by every user, writable by root only.

    python3 tools/desk_records.py baseline <policy.json> <dest>   the reviewed baseline policy, byte for byte
    python3 tools/desk_records.py image <image id> <dest>         the desk image the installer built: {"image", "id"}
    python3 tools/desk_records.py ceiling <dest> <profile.yaml>...  the provider ceiling: each profile's hosts, and all

The backend adapter reads the baseline (read-only, at /etc/ekka-backend/baseline-policy.json in its container) and
answers its digest; EKKA's desk commands read the image and provider ceiling records. These build a desks grant's limits,
so the Enclave's user, who runs those commands, must be able to read them and must never be able to change them.

So every folder from / down to the record is checked: a real folder (never a link), owned by root, writable by
nobody else. A folder anyone else could write would let them swap the whole path. The folders are walked one name at
a time through open folder handles, so nothing can be swapped between the check and the write. The record is
written beside under a new name and renamed over the old one: a reader sees the old record or the new one, never half
of one. A failure before the rename leaves the old record as it was. A failure after it (the disk not confirming
the folder is saved) is reported as that: the record was replaced, and the disk did not confirm it is saved.
"""
import json
import os
import re
import secrets
import stat
import sys

IMAGE = "ekka-desk:local"
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")             # matched whole (fullmatch): "$" would pass a trailing newline
MAX_POLICY = 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class Refused(Exception):
    pass


class NotConfirmedSaved(Exception):
    """The record was replaced, and the disk did not confirm the change is saved."""


def _trusted(fd, what, owner):
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise Refused(f"{what} is not a folder")
    if st.st_uid != owner:
        raise Refused(f"{what} is not owned by uid {owner}")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise Refused(f"{what} can be written by users other than its owner")


def open_folder(path, top="/", owner=0, make=False):
    """A handle on `path`, reached from `top` one name at a time, each folder on the way trusted. `make` creates
    a missing folder, 0755. `top` and `owner` are for tests; the command line always uses / and root."""
    path, top = os.path.abspath(path), os.path.abspath(top)
    rel = os.path.relpath(path, top)
    if rel == os.curdir:
        names = []
    elif rel == os.pardir or rel.startswith(os.pardir + os.sep):
        raise Refused(f"{path} is not under {top}")
    else:
        names = rel.split(os.sep)
    fd = os.open(top, DIR_FLAGS)
    try:
        _trusted(fd, top, owner)
        here = top
        for name in names:
            here = os.path.join(here, name)
            made = False
            if make:
                try:
                    os.mkdir(name, 0o755, dir_fd=fd)
                    made = True
                except FileExistsError:
                    pass
            try:
                nfd = os.open(name, DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                raise Refused(f"{here} does not exist") from None
            except OSError:
                raise Refused(f"{here} is a link or not a folder; it must be a real folder") from None
            os.close(fd)
            fd = nfd
            if made:
                os.fchmod(fd, 0o755)
            _trusted(fd, here, owner)
        return fd
    except BaseException:
        os.close(fd)
        raise


def write(dest, data, top="/", owner=0):
    """`data` at `dest`, 0644, owned by `owner`, replacing any record there atomically."""
    folder, name = os.path.split(os.path.abspath(dest))
    if not NAME.fullmatch(name):
        raise Refused(f"{name!r} is not a plain file name")
    dfd = open_folder(folder, top, owner, make=True)
    tmp = None
    try:
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                raise Refused(f"{dest} is a link or not a regular file; remove it and run again")
        except FileNotFoundError:
            pass
        tmp = f".{name}.{secrets.token_hex(6)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            if os.write(fd, data) != len(data):
                raise Refused("the record was not written whole")
            os.fchmod(fd, 0o644)
            if os.fstat(fd).st_uid != owner:
                raise Refused(f"{dest} would not be owned by uid {owner}; run as that user")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = None
        try:
            os.fsync(dfd)
        except OSError as e:
            raise NotConfirmedSaved(f"{e.__class__.__name__}: {e.strerror}") from e
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
        os.close(dfd)


def baseline_bytes(src):
    """The reviewed baseline, byte for byte: a JSON object, at most 1 MiB. The adapter decides whether it is a
    SandboxPolicy, by the same function it enforces with."""
    with open(src, "rb") as f:
        data = f.read(MAX_POLICY + 1)
    if len(data) > MAX_POLICY:
        raise Refused(f"{src} is larger than {MAX_POLICY} bytes")
    try:
        doc = json.loads(data)
    except ValueError:
        raise Refused(f"{src} is not JSON") from None
    if not isinstance(doc, dict):
        raise Refused(f"{src} is not a JSON object")
    return data


def image_bytes(image_id):
    if not IMAGE_ID.fullmatch(image_id):
        raise Refused(f"{image_id!r} is not an image id (sha256:<64 lowercase hex>)")
    return (json.dumps({"image": IMAGE, "id": image_id}, indent=2) + "\n").encode()


def ceiling_bytes(files):
    """The provider ceiling: each profile the gateway holds (by its file's name) and the hosts it names, and every
    host together. Read through desk_grant.profile_file_hosts, also used by project policy checks."""
    import desk_grant
    if not files:
        raise Refused("no provider profile was given")
    profiles = {}
    try:
        for path in files:
            name = os.path.basename(path)
            if not name.endswith(".yaml") or not desk_grant.NAME.fullmatch(name[:-5]):
                raise Refused(f"{name!r} is not a provider profile file (<name>.yaml)")
            if name[:-5] in profiles:
                raise Refused(f"two profile files are named {name!r}")
            profiles[name[:-5]] = desk_grant.profile_file_hosts(path)
        hosts = desk_grant.profile_hosts(files=files)
    except desk_grant.Refused as e:
        raise Refused(str(e)) from None
    if sorted({h for hs in profiles.values() for h in hs}) != hosts:
        raise Refused("the profiles' hosts do not add up to the grant's ceiling")
    doc = {"profiles": [{"name": n, "hosts": profiles[n]} for n in sorted(profiles)], "hosts": hosts}
    return (json.dumps(doc, indent=2) + "\n").encode()


def main(argv):
    if argv[:1] == ["ceiling"] and len(argv) >= 3:
        kind, dest, data_of = "ceiling", argv[1], lambda: ceiling_bytes(argv[2:])
    elif len(argv) == 3 and argv[0] in ("baseline", "image"):
        kind, source, dest = argv
        data_of = (lambda: baseline_bytes(source)) if kind == "baseline" else (lambda: image_bytes(source))
    else:
        print("usage: python3 tools/desk_records.py baseline <policy.json> <dest>\n"
              "       python3 tools/desk_records.py image <image id> <dest>\n"
              "       python3 tools/desk_records.py ceiling <dest> <profile.yaml>...", file=sys.stderr)
        return 2
    try:
        data = data_of()
        write(dest, data)
    except NotConfirmedSaved as e:
        print(f"the {kind} record was replaced ({dest}), but the disk did not confirm it is saved ({e}); "
              "run again", file=sys.stderr)
        return 3
    except Refused as e:
        print(f"REFUSED: {e}; the {kind} record was not written", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"REFUSED: {e.__class__.__name__}: {e.strerror}; the {kind} record was not written", file=sys.stderr)
        return 1
    print(f"the {kind} record: {dest}, root-owned, 0644")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
