"""Whether the gateway's workspace member list names one subject: python3 tools/workspace_member.py <subject> < list.

The list is what `openshell workspace member list -o json` prints, piped in as it was written: a shell variable
would drop a NUL byte before this could see it. NVIDIA OpenShell 0.1.4 prints one page as
{"members": [{"subject": "<sub>", "role": "<role>"}, ...], "next_page_token": "<token>"} (crates/openshell-cli:
run.rs workspace_member_list, output.rs paginated_collection_value).

It prints `named` (a member's subject is exactly this one) or `absent` (a whole, well-formed list that does not hold
it), and exits 0. Anything else (no word printed, another exit code, a crash) means the answer could not be read:
an empty answer, not JSON, a key repeated in any object, any key more or less than that shape (an "error" beside
the members too), a member without a non-empty subject or a role NVIDIA names, or a list with another page.
The callers act on the printed word, never on the exit code alone, so `invite` never adds someone it could not
check and `revoke` never calls a failed removal done.
"""
import json
import sys


def no_repeated_keys(pairs):
    """json.loads keeps the LAST of two equal keys, so a repeated "next_page_token" or "subject" could hide a page or
    a member: an object that repeats a key is not an answer."""
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("a key is repeated")
    return dict(pairs)


def is_text(s):
    """A non-empty string that is real Unicode: JSON can escape a lone surrogate (\\ud800), which is no character."""
    try:
        return isinstance(s, str) and bool(s) and bool(s.encode("utf-8"))
    except UnicodeEncodeError:
        return False


def state(raw, subject):
    """'named', 'absent', or None when the answer (bytes, as NVIDIA's CLI wrote them) is not one whole member list."""
    try:
        listed = json.loads(raw.decode("utf-8"), object_pairs_hook=no_repeated_keys)
    except (ValueError, RecursionError):  # invalid UTF-8 and a NUL byte too: both are ValueErrors
        return None
    if not isinstance(listed, dict) or set(listed) != {"members", "next_page_token"}:
        return None
    if not isinstance(listed["members"], list) or listed["next_page_token"] != "":
        return None  # a token means more members on another page: absence on this one proves nothing
    for m in listed["members"]:
        if not (isinstance(m, dict) and set(m) == {"subject", "role"} and is_text(m["subject"])
                and m["role"] in ("admin", "user", "unknown")):
            return None
    return "named" if any(m["subject"] == subject for m in listed["members"]) else "absent"


def main(argv):
    if len(argv) != 2 or not argv[1]:
        print("usage: python3 tools/workspace_member.py <subject> < member-list.json", file=sys.stderr)
        return 2
    found = state(sys.stdin.buffer.read(), argv[1])
    if found is None:
        print("the workspace member list could not be read", file=sys.stderr)
        return 2
    print(found)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
