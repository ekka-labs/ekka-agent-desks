"""What must never reach this public repository: python3 tools/public_check.py [--stdin | <file>...].

This repository is public. A file, a commit message or a pull request's text here must carry none of:
- an email address, quoted or not, except the reserved example domains (example.com, example.net, example.org);
- a reference to a private EKKA repository. The one name allowed is the vendored contracts' package,
  written exactly as its package name with the leading at sign;
- a link to a coding-assistant session, or a co-author trailer.
Exit 0 when clean, 1 with one line per hit. A hit names its kind and where it is (file and line), never the value
it found: CI logs are public too, so printing the value would publish it. CI runs this on every pull request's
commit messages, title and body; tests/test_no_private_addresses.py runs it on every file.
"""
import re
import sys

DOMAIN = r"([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})\b"
# A quoted name is anything quoted EXCEPT text made only of spaces, colons, commas, plus signs and brackets: that
# is JSON such as {"body": "@input.body"} or code joining strings ("..." + "@..."), not a name.
MAIL = re.compile(r"(?:\"(?![\s:,+{}\[\]]*\")[^\"\n]+\"|[a-z0-9._%+-]+)@" + DOMAIN, re.I)
EXAMPLE = re.compile(r"(?:^|\.)example\.(?:com|net|org)$", re.I)
PRIVATE_REPO = re.compile(r"(?<![\w.-])@?ekka-ai/[a-z0-9._-]+", re.I)
PACKAGE = "@ekka-" + "ai/contracts"   # split, so this file passes its own check
SESSION = re.compile(r"claude\.ai/code/" + "session", re.I)
TRAILER = re.compile(r"^\s*co-authored-" + r"by:", re.I | re.M)


def hits(text):
    """[(kind, line number)] for every hit; the values themselves are never returned."""
    found = []

    def line_of(pos):
        return text.count("\n", 0, pos) + 1
    found += [("email address", line_of(m.start())) for m in MAIL.finditer(text) if not EXAMPLE.search(m.group(1))]
    found += [("private repository reference", line_of(m.start())) for m in PRIVATE_REPO.finditer(text)
              if m.group(0).lower() != PACKAGE]
    found += [("coding-assistant session link", line_of(m.start())) for m in SESSION.finditer(text)]
    found += [("co-author trailer", line_of(m.start())) for m in TRAILER.finditer(text)]
    return found


def text_of(data):
    """Bytes as text to check. UTF-16 and UTF-32 (with a byte-order mark, or UTF-16 without one, which shows as
    zero bytes between letters) are decoded first, so an exported file cannot hide an address in them. Anything else
    is UTF-8 with bad bytes replaced, never a reason to skip."""
    for bom, codec in ((b"\xff\xfe\x00\x00", "utf-32-le"), (b"\x00\x00\xfe\xff", "utf-32-be"),
                       (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if data.startswith(bom):   # the plain reading too: two bytes that look like a mark prove nothing
            return data[len(bom):].decode(codec, errors="replace") + "\n" + data.decode("utf-8", errors="replace")
    if b"\x00" in data:   # UTF-16 without a mark, or binary: check it with the zero bytes taken out as well
        return data.decode("utf-8", errors="replace") + "\n" + data.replace(b"\x00", b"").decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


def read(path):
    with open(path, "rb") as f:
        return text_of(f.read())


def main(argv):
    if argv[1:] == ["--stdin"]:
        sources = [("stdin", text_of(sys.stdin.buffer.read()))]
    elif len(argv) > 1:
        sources = [(path, read(path)) for path in argv[1:]]
    else:
        print(__doc__.splitlines()[0], file=sys.stderr)
        return 2
    bad = [f"{name}:{line}: {kind}" for name, text in sources for kind, line in hits(text)]
    for entry in bad:
        print(entry)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
