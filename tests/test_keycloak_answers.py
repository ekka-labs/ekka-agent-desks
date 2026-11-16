"""invite and revoke act on Keycloak's answers only when they are whole and plainly about the person named.

A repeated key, a lookup that is not one list naming exactly that person, a record that carries credentials, a
sign-in flag that is not a plain boolean, a session list that cannot be read, or a write that found no target each
stop the command with nothing more written. A revoked person is given the new one-time password while still
disabled, so a failure never brings them back with the password they had.
"""
import io
import json
import re
import tempfile
import unittest
import urllib.error
from unittest import mock

from test_up_revoke import ADMIN, PERSON, REALM, FakeKeycloak, apply_realm, call


class Answering(FakeKeycloak):
    """FakeKeycloak with one answer replaced: `answers` maps a path pattern to what Keycloak says there."""

    def __init__(self, answers=None, fail_write=None, **kw):
        super().__init__(**kw)
        self.answers = answers or {}
        self.fail_write = fail_write

    def get(self, path):
        for pattern, answer in self.answers.items():
            if re.fullmatch(re.escape(REALM) + pattern, path):
                return answer
        return super().get(path)

    def write(self, method, path, body):
        if self.fail_write and self.fail_write in path:
            self.writes.append(("FAILED", method, path))
            raise SystemExit(f"keycloak: {method} {path}: HTTP 500")
        return super().write(method, path, body)


LOOKUP = r"/users\?exact=true&username=pat"


def password():
    f = tempfile.NamedTemporaryFile("w", delete=False)
    f.write("a-one-time-password-1234")
    f.close()
    return f.name


class TheHttpAnswer(unittest.TestCase):
    """apply_realm.Api._send: what a raw answer becomes."""

    def send(self, method, body=b"", error=None):
        api = apply_realm.Api.__new__(apply_realm.Api)
        api.base, api.ctx = "https://kc.example", None

        def urlopen(req, context=None, timeout=None):
            if error:
                raise urllib.error.HTTPError(req.full_url, error, "no", {}, io.BytesIO(b""))
            return mock.MagicMock(__enter__=lambda s: mock.Mock(read=lambda: body), __exit__=lambda *a: False)
        with mock.patch.object(apply_realm.urllib.request, "urlopen", urlopen):
            return api._send(method, "/admin/realms/r/x")

    def test_a_repeated_key_is_not_an_answer(self):
        # Python would keep the second "name": an administrator read as an ordinary person.
        with self.assertRaises(SystemExit) as e:
            self.send("GET", b'[{"name": "openshell-admin", "name": "openshell-user"}]')
        self.assertIn("repeats a key", str(e.exception.code))

    def test_a_repeated_key_deep_inside_is_not_an_answer(self):
        with self.assertRaises(SystemExit):
            self.send("GET", b'{"id": "x", "attributes": {"a": [1], "a": [2]}}')

    def test_an_answer_that_is_not_json_stops(self):
        with self.assertRaises(SystemExit) as e:
            self.send("GET", b"<html>proxy error</html>")
        self.assertIn("not JSON", str(e.exception.code))

    def test_a_whole_answer_is_read(self):
        self.assertEqual(self.send("GET", b'[{"name": "openshell-user"}]'), [{"name": "openshell-user"}])

    def test_not_found_answers_a_read_and_a_delete(self):
        self.assertIsNone(self.send("GET", error=404))
        self.assertIsNone(self.send("DELETE", error=404))

    def test_a_put_or_post_that_found_nothing_did_not_happen(self):
        for method in ("PUT", "POST"):
            with self.assertRaises(SystemExit, msg=method) as e:
                self.send(method, error=404)
            self.assertIn("HTTP 404", str(e.exception.code))


class TheAccountLookup(unittest.TestCase):
    """find_person: one list that names exactly this person, or nothing is chosen, created or reset."""

    BAD = {"null": None, "an object": {}, "false": False, "zero": 0, "a string": "",
           "another person": [{"id": ADMIN, "username": "boss"}],
           "two accounts": [{"id": PERSON, "username": "pat"}, {"id": ADMIN, "username": "pat"}],
           "no id": [{"username": "pat"}], "an id that is not one": [{"id": "../users", "username": "pat"}]}

    def test_a_bad_lookup_stops_person_with_nothing_written(self):
        for name, answer in self.BAD.items():
            kc = Answering({LOOKUP: answer}, enabled=False)
            rc, out = call(kc, "person", "pat", "pat@example.com", password_file=password())
            self.assertIn("could not read the account named pat", str(rc), name)
            self.assertEqual((kc.writes, out), ([], ""), name)

    def test_a_bad_lookup_stops_revoke_and_person_id(self):
        for name, answer in self.BAD.items():
            for cmd in ("revoke", "person-id"):
                kc = Answering({LOOKUP: answer})
                rc, out = call(kc, cmd, "pat")
                self.assertIn("could not read the account named pat", str(rc), (cmd, name))
                self.assertEqual((kc.writes, out), ([], ""), (cmd, name))

    def test_an_empty_list_is_no_account(self):
        rc, _ = call(Answering({LOOKUP: []}), "person-id", "pat")
        self.assertIn("no sign-in account named pat", str(rc))


class TheRecordSentBack(unittest.TestCase):
    def test_a_record_carrying_credentials_is_never_sent_back(self):
        # Keycloak applies credentials sent in a user update: revoke would set a password it never chose.
        record = {"id": PERSON, "username": "pat", "enabled": True,
                  "credentials": [{"type": "password", "value": "chosen-elsewhere", "temporary": False}]}
        kc = Answering({rf"/users/{PERSON}": record})
        rc, out = call(kc, "revoke", "pat")
        self.assertIn("could not read pat's record", str(rc))
        self.assertEqual((kc.writes, out), ([], ""))

    def test_another_persons_record_is_never_sent_back(self):
        kc = Answering({rf"/users/{PERSON}": {"id": ADMIN, "username": "boss", "enabled": True}})
        rc, _ = call(kc, "revoke", "pat")
        self.assertIn("could not read pat's record", str(rc))
        self.assertEqual(kc.writes, [])


class RevokeReadsTheSignInFlag(unittest.TestCase):
    def test_an_unclear_flag_stops_revoke_with_nothing_written(self):
        for odd in (None, 0, "", [], {}):
            kc = FakeKeycloak(enabled=odd)
            rc, out = call(kc, "revoke", "pat")
            self.assertIn("could not read whether pat can sign in", str(rc), odd)
            self.assertEqual((kc.writes, out), ([], ""), odd)


class EverySessionIsListed(unittest.TestCase):
    def test_an_unreadable_session_list_is_never_none(self):
        for pattern in (rf"/users/{PERSON}/sessions", r"/clients\?max=1000",
                        rf"/users/{PERSON}/offline-sessions/c-cli"):
            for answer in (None, {}, [None], [{"no": "id"}]):
                kc = Answering({pattern: answer})
                rc, out = call(kc, "revoke", "pat")
                self.assertIn("could not read", str(rc), (pattern, answer))
                self.assertEqual(out, "", "no id printed, so up.sh changes nothing at the gateway")

    def test_a_thousand_clients_is_not_every_client(self):
        many = [{"id": f"c-{i}", "clientId": f"c{i}"} for i in range(1000)]
        rc, out = call(Answering({r"/clients\?max=1000": many}), "revoke", "pat")
        self.assertIn("a thousand clients or more", str(rc))
        self.assertEqual(out, "")


class InviteAfterRevokeKeepsTheAccountDisabledUntilReady(unittest.TestCase):
    def test_the_new_password_is_set_before_the_account_is_enabled(self):
        kc = FakeKeycloak(enabled=False, online=0, offline=0)
        rc, _ = call(kc, "person", "pat", "pat@example.com", password_file=password())
        self.assertEqual(rc, 0)
        paths = [(m, p) for m, p, _ in kc.writes]
        self.assertLess(paths.index(("PUT", f"{REALM}/users/{PERSON}/reset-password")),
                        paths.index(("PUT", f"{REALM}/users/{PERSON}")))

    def test_a_failed_reset_leaves_the_account_disabled(self):
        kc = Answering(fail_write="/reset-password", enabled=False, online=0, offline=0)
        rc, out = call(kc, "person", "pat", "pat@example.com", password_file=password())
        self.assertIn("HTTP 500", str(rc))
        self.assertFalse(kc.users[PERSON]["enabled"], "never enabled with the password from before the revoke")
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
