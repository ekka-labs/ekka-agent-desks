"""up.sh desks settle: one unfinished change, settled only after the desk stopped changing.

Docker is replaced by a fake that answers `ps` from a scripted sequence of container states and records every
call, and the clock advances only when the procedure sleeps. So each case is exact and takes no real time.
The marker's and the hold's fields are written here from the contract, never read from the code under test, and a
test holds them to the vendored @ekka-ai/contracts 0.83.0 schemas (vendor/ekka-contracts/backend/settle-*.json).
"""
import datetime as dt
import io
import json
import os
import re
import socket
import subprocess
import sys
import unittest
from unittest import mock
import tempfile
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import desks_settle as ds  # noqa: E402

OP = "3f1c2a9e-5b7d-4e2a-9c1b-7d6e5f4a3b2c"
SANDBOX = "6a1f2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
A, B = "a" * 64, "b" * 64
MARKER_FIELDS = {"operation_id", "desk", "backend_id", "gateway_identity", "gateway_restarted_at", "quiet_until",
                 "containers"}
# What the adapter's config.json names (backend_gateway url#workspace), as the vendored adapter-config sample does.
IDENTITY = "https://host.openshell.internal:8080#desks"
REQUEST_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$")


class Clock:
    def __init__(self):
        self.t = dt.datetime(2026, 10, 16, 5, 0, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += dt.timedelta(seconds=s)


class FakeDocker:
    """`ps` answers the next scripted listing (the last one repeats); `run` writes into the adapter's state, and
    keeps it in `files`, so a test sees what is there: the hold, the marker, or neither."""

    def __init__(self, listings, write_rc=0, hold_rc=0, files=None):
        self.listings, self.write_rc, self.hold_rc = list(listings), write_rc, hold_rc
        self.calls, self.written, self.held, self.files = [], None, None, dict(files or {})

    def __call__(self, args, stdin=None):
        self.calls.append(args)
        if args[0] == "ps":
            rows = self.listings.pop(0) if len(self.listings) > 1 else self.listings[0]
            return 0, "".join(f"{c}\t{s}\t{sid}\n" for c, s, sid in rows)
        if args[0] == "run":
            script = args[-1]
            hold = re.search(r"h=/s/settle/(\S+\.hold);", script)
            if hold and "rm -f" in script:                       # remove_hold
                return 0, "removed\n" if self.files.pop(hold.group(1), None) is not None else "none\n"
            if hold:                                             # write_hold
                if self.hold_rc:
                    return self.hold_rc, ""
                if hold.group(1) in self.files:
                    return 4, "held\n"
                self.held = stdin
                self.files[hold.group(1)] = stdin
                return 0, ""
            self.written = stdin                                 # the marker, and the hold gone with it
            if self.write_rc == 0:
                name = re.search(r"f=/s/settle/(\S+\.json);", script).group(1)
                self.files[name] = stdin
                removed = re.search(r"rm -f /s/settle/(\S+\.hold)$", script)
                if removed:
                    self.files.pop(removed.group(1), None)
            return self.write_rc, "exists\n" if self.write_rc == 3 else ""
        raise AssertionError(f"unexpected docker call {args}")


def enclave(args):
    """`ekka desk list` as the native Enclave answers it: names its desks folder."""
    return 0, "code-desk  /var/lib/ekka/.ekka/home/desks/code-desk\n"


def go(listings, locks=(f"admin:{OP}",), op=OP, backend_id=None, write_rc=0, give_up=600, toml="", docker=None):
    clock, said, restarts = Clock(), [], []
    docker = docker or FakeDocker(listings, write_rc)
    locks = list(locks)
    read_lock = lambda: locks.pop(0) if len(locks) > 1 else locks[0]  # noqa: E731
    marker = ds.settle("code-desk", op, backend_id, identity=IDENTITY, run=docker, clock=clock, sleep=clock.sleep,
                       restart=lambda: restarts.append(clock()), read_lock=read_lock, gateway_toml=toml,
                       give_up=give_up, out=said.append)
    return marker, docker, said, restarts


STOPPING = [(A, "running", SANDBOX), (B, "running", SANDBOX)]
STOPPED = [(A, "exited", SANDBOX), (B, "exited", SANDBOX)]


class Settles(unittest.TestCase):
    def test_a_stopped_desk_gets_one_marker_in_the_contract_shape(self):
        marker, docker, said, restarts = go([STOPPING, STOPPED])
        self.assertEqual(len(restarts), 1)
        self.assertEqual(set(marker), MARKER_FIELDS)
        self.assertEqual(json.loads(docker.written), marker)
        self.assertEqual(marker["operation_id"], OP)
        self.assertTrue(REQUEST_ID.match(marker["operation_id"]) and REQUEST_ID.match(marker["backend_id"]))
        self.assertTrue(TIME.match(marker["gateway_restarted_at"]) and TIME.match(marker["quiet_until"]))
        self.assertEqual(marker["containers"], [{"id": A, "state": "exited"}, {"id": B, "state": "exited"}])
        self.assertEqual(marker["gateway_identity"], "https://host.openshell.internal:8080#desks",
                         "<backend_gateway.url>#<backend_gateway.workspace>, as the adapter builds it")
        quiet = (dt.datetime.fromisoformat(marker["quiet_until"].replace("Z", "+00:00"))
                 - dt.datetime.fromisoformat(marker["gateway_restarted_at"].replace("Z", "+00:00"))).total_seconds()
        self.assertGreaterEqual(quiet, 40, "the quiet window is the stop timeout (10 s) plus 30 s")
        self.assertIn(f"settle/{OP}.json", said[-2])
        self.assertEqual(sorted(docker.files), [f"{OP}.json"], "the marker is there, and the hold is gone")

    def test_the_marker_is_the_request_id_file_written_by_the_adapters_user_with_no_network(self):
        _, docker, _, _ = go([STOPPED])
        run = next(c for c in docker.calls if c[0] == "run" and ".json" in c[-1])
        self.assertEqual(run[run.index("--network") + 1], "none")
        self.assertEqual(run[run.index("--user") + 1], "2000:1000")
        self.assertIn("ekka-desks_ekka-backend-state:/s", run)
        self.assertRegex(run[run.index("-v") + 2], r"^alpine:[0-9.]+@sha256:[0-9a-f]{64}$", "a pinned digest, never a tag")
        script = run[-1]
        self.assertIn("umask 077", script)
        self.assertIn(f"f=/s/settle/{OP}.json", script)
        self.assertIn('[ -e "$f.used" ]', script, "a used marker is never written again")
        self.assertIn('mv "$f.tmp" "$f"', script, "the adapter never reads half a marker")

    def test_an_unknown_change_is_settled_too(self):
        marker, _, _, _ = go([STOPPED], locks=(f"admin:{OP} unknown",))
        self.assertEqual(marker["operation_id"], OP)

    def test_a_deleted_desk_settles_with_no_containers_given_its_backend_id(self):
        marker, _, _, _ = go([[]], backend_id=SANDBOX)
        self.assertEqual(marker["containers"], [])
        self.assertEqual(marker["backend_id"], SANDBOX)

    def test_the_quiet_window_follows_the_gateways_own_stop_timeout(self):
        self.assertEqual(ds.stop_timeout("[openshell.drivers.docker]\nstop_timeout_secs = 25\n"), 25)
        self.assertEqual(ds.stop_timeout("[openshell.drivers.k8s]\nstop_timeout_secs = 25\n"), 10)
        self.assertEqual(ds.stop_timeout(""), 10)


class StopStillRunning(unittest.TestCase):
    """A stop still running in Docker when the gateway is killed. The container
    ignores SIGTERM, so Docker shows it `running` until the gateway's stop_timeout_secs (60 here) ends in SIGKILL.
    settle must not write the marker until the container has exited, and the hold keeps the change from being
    re-issued (so a `status` in between keeps the desk excluded)."""

    TOML = "[openshell.drivers.docker]\nstop_timeout_secs = 60\n"
    RUNNING = [(A, "running", SANDBOX)]
    EXITED = [(A, "exited", SANDBOX)]

    def run_settle(self, toml):
        # Polled every 2 s: running for 70 s after the restart (SIGTERM ignored, SIGKILL at 60 s), then exited.
        docker = FakeDocker([self.RUNNING] * 35 + [self.EXITED])
        seen, clock, restarts = [], Clock(), []

        def spy(args, stdin=None):
            if args[0] == "ps":
                seen.append((clock(), sorted(docker.files)))
            return docker(args, stdin)
        marker = ds.settle("code-desk", OP, None, identity=IDENTITY, run=spy, clock=clock, sleep=clock.sleep,
                           restart=lambda: restarts.append(clock()), read_lock=lambda: f"admin:{OP}",
                           gateway_toml=toml, out=lambda *_: None)
        return marker, seen, restarts[0]

    def test_no_marker_until_the_container_exits_and_the_hold_stands_meanwhile(self):
        marker, seen, restarted = self.run_settle(self.TOML)
        exited_at = restarted + dt.timedelta(seconds=70)
        self.assertEqual(marker["containers"], [{"id": A, "state": "exited"}], "never the running state")
        quiet = dt.datetime.fromisoformat(marker["quiet_until"].replace("Z", "+00:00"))
        self.assertGreaterEqual((quiet - exited_at).total_seconds(), 90, "60 s stop timeout + 30 s after the exit")
        while_running = [files for t, files in seen if t < exited_at]
        self.assertTrue(while_running)
        self.assertTrue(all(files == [f"{OP}.hold"] for files in while_running),
                        "while the stop runs: the hold is there, and no marker")

    def test_planted_the_gateways_stop_timeout_ignored_would_settle_a_running_container(self):
        # Why the window reads the gateway's own setting: with the 10 s default, 40 s of an unchanged `running`
        # looks settled, and the marker would record a container Docker was still stopping.
        marker, _, _ = self.run_settle("")
        self.assertEqual(marker["containers"], [{"id": A, "state": "running"}])


class Refuses(unittest.TestCase):
    def assertNothingDone(self, docker, restarts):
        self.assertEqual(restarts, [], "the gateway was restarted")
        self.assertIsNone(docker.written, "a marker was written")

    def test_planted_a_job_holding_the_desk_is_left_alone(self):
        marker, docker, said, restarts = go([STOPPED], locks=("attempt-7f2c",))
        self.assertIsNone(marker)
        self.assertNothingDone(docker, restarts)
        self.assertIn("a job holds it (attempt attempt-7f2c)", said[0])

    def test_planted_another_change_holding_the_desk_is_left_alone(self):
        other = "9d4c2b1a-8e7f-4a6b-9c5d-3e2f1a0b9c8d"
        marker, docker, said, restarts = go([STOPPED], locks=(f"admin:{other}",))
        self.assertIsNone(marker)
        self.assertNothingDone(docker, restarts)
        self.assertIn(f"another change holds it (admin:{other})", said[0])

    def test_planted_a_lock_that_only_starts_with_this_change_is_not_this_change(self):
        for lock in (f"admin:{OP}x", f"admin:{OP} unknown later", f"admin:{OP.upper()}", f"job:{OP}", ""):
            marker, docker, _, restarts = go([STOPPED], locks=(lock,))
            self.assertIsNone(marker, lock)
            self.assertNothingDone(docker, restarts)

    def test_planted_the_old_run_step_task_id_is_refused(self):
        with self.assertRaisesRegex(ds.Refused, "request id, a lowercase UUID"):
            go([STOPPED], op=f"{SANDBOX}/admin/{OP}", locks=(f"admin:{SANDBOX}/admin/{OP}",))
        with self.assertRaises(ds.Refused):
            go([STOPPED], op=OP.upper())

    def test_planted_a_desk_that_never_stops_changing_gets_no_marker(self):
        removing = [(A, "removing", SANDBOX)]
        with self.assertRaisesRegex(ds.Refused, r"did not stop changing within 10 minutes \(aaaaaaaaaaaa removing\)"):
            go([removing])

    def test_planted_a_desk_that_keeps_flipping_gets_no_marker(self):
        flip = [[(A, "running", SANDBOX)], [(A, "exited", SANDBOX)]] * 400
        with self.assertRaisesRegex(ds.Refused, "did not stop changing"):
            go(flip)

    def test_planted_a_change_settled_during_the_wait_gets_no_marker(self):
        marker, docker, said, restarts = go([STOPPED], locks=(f"admin:{OP}", None))   # None: the lock file is gone
        self.assertIsNone(marker)
        self.assertEqual(len(restarts), 1)
        self.assertIsNone(docker.written)
        self.assertIn("settled meanwhile", said[-1])

    def test_planted_a_marker_already_waiting_or_used_is_never_replaced(self):
        with self.assertRaisesRegex(ds.Refused, "already waiting or was already used"):
            go([STOPPED], write_rc=3)

    def test_a_create_that_never_reached_the_desk_settles_with_a_null_backend_id_and_no_containers(self):
        marker, docker, said, _ = go([[]])
        self.assertEqual(set(marker), MARKER_FIELDS)
        self.assertIsNone(marker["backend_id"])
        self.assertEqual(marker["containers"], [])
        self.assertEqual(json.loads(docker.written), marker)
        self.assertIn("no desk was found by its labels", said[-2])

    def test_planted_containers_that_name_no_sandbox_get_no_marker(self):
        with self.assertRaisesRegex(ds.Refused, "name no sandbox"):
            go([[(A, "exited", "")]])

    def test_planted_containers_of_another_sandbox_get_no_marker(self):
        with self.assertRaisesRegex(ds.Refused, "not 9d4c2b1a"):
            go([STOPPED], backend_id="9d4c2b1a-8e7f-4a6b-9c5d-3e2f1a0b9c8d")
        two = [(A, "exited", SANDBOX), (B, "exited", "9d4c2b1a-8e7f-4a6b-9c5d-3e2f1a0b9c8d")]
        with self.assertRaisesRegex(ds.Refused, "name 2 sandboxes"):
            go([two])

    def test_planted_a_container_line_it_cannot_read_stops_it(self):
        with self.assertRaisesRegex(ds.Refused, "cannot read"):
            go([[("abc", "exited", SANDBOX)]])


class Hold(unittest.TestCase):
    """settle-hold.v1: nothing re-issues the change while it is settled."""

    def test_the_hold_is_written_before_the_restart_and_gone_with_the_marker(self):
        docker = FakeDocker([STOPPED])
        order = []
        real = docker.__call__

        def spy(args, stdin=None):
            if args[0] == "run":
                order.append("hold" if ".hold;" in args[-1] and "rm -f" not in args[-1] else "marker")
            return real(args, stdin)
        clock, restarts = Clock(), []
        ds.settle("code-desk", OP, None, identity=IDENTITY, run=spy, clock=clock, sleep=clock.sleep,
                  restart=lambda: (order.append("restart"), restarts.append(clock())),
                  read_lock=lambda: f"admin:{OP}", out=lambda *_: None)
        self.assertEqual(order[:3], ["hold", "restart", "marker"])
        hold = json.loads(docker.held)
        self.assertEqual(set(hold), {"operation_id", "held_at"}, "strictly the contract's two fields")
        self.assertEqual(hold["operation_id"], OP)
        self.assertTrue(TIME.match(hold["held_at"]))
        self.assertLessEqual(dt.datetime.fromisoformat(hold["held_at"].replace("Z", "+00:00")), restarts[0])
        self.assertEqual(sorted(docker.files), [f"{OP}.json"])

    def test_the_hold_file_is_the_request_id_written_by_the_adapters_user_with_no_network(self):
        _, docker, _, _ = go([STOPPED])
        run = next(c for c in docker.calls if c[0] == "run" and ".hold;" in c[-1])
        self.assertEqual(run[run.index("--network") + 1], "none")
        self.assertEqual(run[run.index("--user") + 1], "2000:1000")
        self.assertIn("umask 077", run[-1], "mode 0600")
        self.assertIn(f"h=/s/settle/{OP}.hold;", run[-1])
        self.assertIn('mv "$h.tmp" "$h"', run[-1])

    def test_planted_a_marker_that_fails_to_land_leaves_the_hold(self):
        # The required write order: the marker is renamed into place, and ONLY THEN is the hold
        # removed, so the two are never both absent. A failed write or rename never reaches the `rm`.
        _, docker, _, _ = go([STOPPED])
        script = next(c for c in docker.calls if c[0] == "run" and ".json" in c[-1])[-1]
        self.assertRegex(script, rf'cat > "\$f\.tmp" && mv "\$f\.tmp" "\$f" && rm -f /s/settle/{OP}\.hold$',
                         "write, then rename, then remove the hold, each only if the step before succeeded")
        docker = FakeDocker([STOPPED], write_rc=1)
        with self.assertRaisesRegex(ds.Refused, "could not be written.*The hold stays"):
            go(None, docker=docker)
        self.assertEqual(list(docker.files), [f"{OP}.hold"], "no marker, and the hold is still there")

    def test_planted_a_desk_that_never_stops_changing_leaves_the_hold_and_says_how_to_clear_it(self):
        flip = [[(A, "running", SANDBOX)], [(A, "exited", SANDBOX)]] * 400
        docker = FakeDocker(flip)
        with self.assertRaisesRegex(ds.Refused, rf"The hold stays.*desks unhold code-desk --operation {OP}"):
            go(None, docker=docker)
        self.assertEqual(list(docker.files), [f"{OP}.hold"], "no marker, and the hold is still there")

    def test_planted_a_gateway_that_does_not_restart_leaves_the_hold(self):
        docker = FakeDocker([STOPPED])
        clock = Clock()

        def restart():
            raise ds.Refused("the gateway did not restart; no marker was written")
        with self.assertRaisesRegex(ds.Refused, "The hold stays"):
            ds.settle("code-desk", OP, None, identity=IDENTITY, run=docker, clock=clock, sleep=clock.sleep, restart=restart,
                      read_lock=lambda: f"admin:{OP}", out=lambda *_: None)
        self.assertEqual(list(docker.files), [f"{OP}.hold"])

    def test_a_hold_left_by_a_stopped_settle_is_kept_and_the_settle_goes_on(self):
        earlier = json.dumps({"operation_id": OP, "held_at": "2026-10-16T04:00:00Z"})
        docker = FakeDocker([STOPPED], files={f"{OP}.hold": earlier})
        marker, _, said, _ = go(None, docker=docker)
        self.assertIsNotNone(marker)
        self.assertTrue(any("already held" in s for s in said))
        self.assertIsNone(docker.held, "the earlier hold is not rewritten")
        self.assertEqual(sorted(docker.files), [f"{OP}.json"])

    def test_a_change_settled_meanwhile_removes_its_hold(self):
        docker = FakeDocker([STOPPED])
        marker, _, said, _ = go(None, locks=(f"admin:{OP}", None), docker=docker)
        self.assertIsNone(marker)
        self.assertEqual(docker.files, {}, "nothing left: no marker, no hold")
        self.assertIn("hold is removed", said[-1])

    def test_planted_a_hold_that_cannot_be_written_stops_before_the_restart(self):
        docker = FakeDocker([STOPPED], hold_rc=1)
        restarts = []
        clock = Clock()
        with self.assertRaisesRegex(ds.Refused, "nothing was restarted"):
            ds.settle("code-desk", OP, None, identity=IDENTITY, run=docker, clock=clock, sleep=clock.sleep,
                      restart=lambda: restarts.append(1), read_lock=lambda: f"admin:{OP}", out=lambda *_: None)
        self.assertEqual(restarts, [])

    def test_a_desk_held_by_a_job_gets_no_hold(self):
        docker = FakeDocker([STOPPED])
        go(None, locks=("attempt-7f2c",), docker=docker)
        self.assertEqual(docker.files, {})
        self.assertFalse(any(c[0] == "run" for c in docker.calls))

    def test_unhold_removes_the_one_hold_and_says_so(self):
        docker = FakeDocker([STOPPED], files={f"{OP}.hold": "{}", "other.hold": "{}"})
        state = tempfile.mkdtemp()
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.dict(os.environ, {"DESKS_STATE": state}):
            self.assertEqual(ds.main(["--unhold", "code-desk", "--operation", OP], run=docker, ekka=enclave,
                                     read=lambda path: f"admin:{OP}"), 0)
        self.assertEqual(list(docker.files), ["other.hold"])
        self.assertIn("removed the hold", out.getvalue())
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.dict(os.environ, {"DESKS_STATE": state}):
            self.assertEqual(ds.main(["--unhold", "code-desk", "--operation", OP], run=docker, ekka=enclave,
                                     read=lambda path: f"admin:{OP}"), 0)
        self.assertIn("had no hold", out.getvalue())

    def test_planted_unhold_with_a_path_or_a_bad_id_never_reaches_docker(self):
        calls = []
        for argv in (["--unhold", "../x", "--operation", OP], ["--unhold", "code-desk", "--operation", "../" + OP]):
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(ds.main(argv, run=lambda a, s=None: calls.append(a) or (0, "")), 1, argv)
        self.assertEqual(calls, [])
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(ds.main(["--unhold", "code-desk", "--operation", OP, "--backend-id", SANDBOX]), 2)


class TheVendoredContract(unittest.TestCase):
    """The marker and the hold are the published contract's shapes (@ekka-ai/contracts 0.83.0, vendored)."""

    VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor", "ekka-contracts", "backend")

    def vendored(self, name):
        with open(os.path.join(self.VENDOR, name)) as f:
            return json.load(f)

    def test_the_marker_written_has_exactly_the_schemas_fields(self):
        schema = self.vendored("settle-marker.v1.schema.json")
        self.assertEqual(set(schema["required"]), MARKER_FIELDS)
        self.assertEqual(set(schema["properties"]), MARKER_FIELDS)
        marker, _, _, _ = go([STOPPED])
        self.assertEqual(set(marker), set(schema["required"]))

    def test_the_gateway_identity_is_the_contracts_url_and_workspace(self):
        config = self.vendored("samples/adapter-config.json")["backend_gateway"]
        with open(os.path.join(self.VENDOR, "samples", "adapter-config.json")) as f:
            from_config = ds.gateway_identity(f.read())
        self.assertEqual(from_config, f"{config['url']}#{config['workspace']}")
        self.assertEqual(self.vendored("samples/settle-marker.json")["gateway_identity"], from_config)
        self.assertEqual(from_config, IDENTITY)

    def test_an_absent_create_is_the_contracts_null_form(self):
        sample = self.vendored("samples/settle-marker.create-absent.json")
        marker, _, _, _ = go([[]])
        self.assertIsNone(sample["backend_id"])
        self.assertEqual((marker["backend_id"], marker["containers"]), (sample["backend_id"], sample["containers"]))

    def test_the_hold_written_has_exactly_the_schemas_fields(self):
        schema = self.vendored("settle-hold.v1.schema.json")
        self.assertFalse(schema["additionalProperties"])
        _, docker, _, _ = go([STOPPED])
        self.assertEqual(set(json.loads(docker.held)), set(schema["required"]))
        self.assertEqual(set(self.vendored("samples/settle-hold.json")), set(schema["required"]))


class TheGatewayIdentity(unittest.TestCase):
    """Read from the adapter's own config.json, never restated in this setup (regression review)."""

    def test_the_marker_carries_what_the_adapters_config_names(self):
        other = "https://gateway.example.com:9443#team-desks"
        clock, docker = Clock(), FakeDocker([STOPPED])
        marker = ds.settle("code-desk", OP, None, identity=other, run=docker, clock=clock, sleep=clock.sleep,
                           restart=lambda: None, read_lock=lambda: f"admin:{OP}", out=lambda *_: None)
        self.assertEqual(marker["gateway_identity"], other)

    def test_planted_a_config_without_the_gateway_is_refused_by_name(self):
        for text in ("{}", "not json", '{"backend_gateway": {"url": "https://x:1"}}',
                     '{"backend_gateway": {"url": "", "workspace": "desks"}}'):
            with self.assertRaisesRegex(ds.Refused, "names no backend_gateway url and workspace"):
                ds.gateway_identity(text)

    def test_planted_no_identity_changes_nothing(self):
        docker, restarts, clock = FakeDocker([STOPPED]), [], Clock()
        with self.assertRaisesRegex(ds.Refused, "no gateway identity"):
            ds.settle("code-desk", OP, None, identity=None, run=docker, clock=clock, sleep=clock.sleep,
                      restart=lambda: restarts.append(1), read_lock=lambda: f"admin:{OP}", out=lambda *_: None)
        self.assertEqual((restarts, docker.calls), ([], []), "no hold, no restart")


class CreatedIsStillChanging(unittest.TestCase):
    def test_a_container_still_created_never_settles(self):
        # `created` is a container Docker made and never started: still changing, so no quiet window starts.
        with self.assertRaisesRegex(ds.Refused, "did not stop changing"):
            go([[(A, "created", SANDBOX)]], give_up=120)


class CommandLine(unittest.TestCase):
    def test_a_malformed_command_prints_the_usage(self):
        for argv in ([], ["code-desk"], ["code-desk", "--op", OP], ["code-desk", "--operation", OP, "--backend", SANDBOX]):
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(ds.main(argv, run=lambda *a, **k: (0, "")), 2, argv)
            self.assertIn("--operation <request id>", err.getvalue())

    def test_planted_a_desk_name_that_is_a_path_never_reaches_docker(self):
        calls = []
        err = io.StringIO()
        with redirect_stderr(err):
            rc = ds.main(["../x", "--operation", OP], run=lambda a, s=None: calls.append(a) or (0, ""))
        self.assertEqual(rc, 1)
        self.assertEqual(calls, [])
        self.assertIn("not a desk name", err.getvalue())

    def test_the_lock_is_read_from_the_enclaves_desks_folder(self):
        calls = []

        def docker(args, stdin=None):
            calls.append(args)
            raise AssertionError(args)

        def ekka(args):   # the native Enclave, as its user
            calls.append(["ekka", *args])
            self.assertEqual(args, ["desk", "list"])
            return 0, "code-desk  /var/lib/ekka/.ekka/home/desks/code-desk\n"

        def read(path):   # the lock, read in the Enclave's folder
            calls.append(["read", path])
            return "attempt-7f2c\n"
        state = tempfile.mkdtemp()
        os.makedirs(os.path.join(state, "backend"))
        with open(os.path.join(state, "backend", "config.json"), "w") as f:
            json.dump({"backend_gateway": {"url": "https://host.openshell.internal:8080", "workspace": "desks"}}, f)
        with mock.patch.dict(os.environ, {"DESKS_STATE": state}):
            rc = ds.main(["code-desk", "--operation", OP], run=docker, ekka=ekka, read=read)
        self.assertEqual(rc, 0, "a desk held by a job is nothing to settle, not a failure")
        self.assertIn(["read", "/var/lib/ekka/.ekka/home/desks/.state/code-desk.lock"], calls)
        self.assertFalse(any(c[0] in ("restart", "run") for c in calls))


class NoAdapterConfig(unittest.TestCase):
    def test_planted_a_machine_without_the_adapters_config_is_refused_before_anything_changes(self):
        calls = []
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"DESKS_STATE": tempfile.mkdtemp()}), redirect_stderr(err):
            rc = ds.main(["code-desk", "--operation", OP], run=lambda a, s=None: calls.append(a) or (0, ""),
                         ekka=lambda a: (0, "code-desk  /var/lib/ekka/.ekka/home/desks/code-desk\n"))
        self.assertEqual(rc, 1)
        self.assertIn("the backend adapter's configuration is missing", err.getvalue())
        self.assertFalse(any(c[0] in ("restart", "run") for c in calls), "no hold, no restart")


class ReviewFixes(unittest.TestCase):
    """Unhold is bound to its desk and never runs during a settle; a lock is read without following a link,
    bounded, and only a recognized holder is ever printed."""

    OTHER = "9d4c2b1a-8e7f-4a6b-9c5d-3e2f1a0b9c8d"

    def state(self):
        state = tempfile.mkdtemp()
        os.makedirs(os.path.join(state, "backend"))
        with open(os.path.join(state, "backend", "config.json"), "w") as f:
            json.dump({"backend_gateway": {"url": "https://host.openshell.internal:8080", "workspace": "desks"}}, f)
        return state

    def test_unhold_refuses_a_change_another_desk_holds(self):
        docker = FakeDocker([STOPPED], files={f"{OP}.hold": "{}"})
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()), \
             mock.patch.dict(os.environ, {"DESKS_STATE": self.state()}):
            rc = ds.main(["--unhold", "code-desk", "--operation", OP], run=docker, ekka=enclave,
                         read=lambda path: f"admin:{self.OTHER}")
        self.assertEqual(rc, 1)
        self.assertEqual(list(docker.files), [f"{OP}.hold"], "another desk's hold was released")
        self.assertIn("does not hold desk 'code-desk'", err.getvalue())

    def test_unhold_never_runs_while_a_settle_is_using_the_hold(self):
        state = self.state()
        seen = {}

        class DockerThatUnholdsDuringTheRestart(FakeDocker):
            def __call__(self, args, stdin=None):
                if args[0] == "restart":
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        seen["rc"] = ds.main(["--unhold", "code-desk", "--operation", OP], run=self, ekka=enclave,
                                             read=lambda path: f"admin:{OP}")
                    seen["files"] = sorted(self.files)
                    self.calls.append(args)
                    return 0, ""
                return super().__call__(args, stdin)
        docker = DockerThatUnholdsDuringTheRestart([STOPPED])
        clock, settle = Clock(), ds.settle
        quick = lambda *a, **k: settle(*a, clock=clock, sleep=clock.sleep, **k)  # noqa: E731  no real waiting
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), mock.patch.object(ds, "settle", quick), \
             mock.patch.dict(os.environ, {"DESKS_STATE": state}):
            rc = ds.main(["code-desk", "--operation", OP], run=docker, ekka=enclave,
                         read=lambda path: f"admin:{OP}")
        self.assertEqual(seen["rc"], 1, "an unhold ran while the settle was using the hold")
        self.assertEqual(seen["files"], [f"{OP}.hold"])
        self.assertEqual(rc, 0)

    def test_a_lock_that_is_a_link_is_never_followed_or_printed(self):
        folder = os.path.realpath(tempfile.mkdtemp())   # a path with no link in it, /var on macOS included
        other = os.path.join(folder, "other-file")
        with open(other, "w") as f:
            f.write("text-from-another-file\n")
        desks = os.path.join(folder, "desks")
        os.makedirs(os.path.join(desks, ".state"))
        os.symlink(other, os.path.join(desks, ".state", "code-desk.lock"))
        rc, out = self.settle_reading_for_real(desks)
        self.assertNotIn("text-from-another-file", out)
        self.assertEqual(rc, 1)

    def test_an_oversized_lock_is_refused_not_read(self):
        folder = os.path.realpath(tempfile.mkdtemp())
        desks = os.path.join(folder, "desks")
        os.makedirs(os.path.join(desks, ".state"))
        with open(os.path.join(desks, ".state", "code-desk.lock"), "w") as f:
            f.write("a" * 1_000_000)
        rc, out = self.settle_reading_for_real(desks)
        self.assertEqual(rc, 1)
        self.assertNotIn("a" * 100, out)

    @unittest.skipUnless(hasattr(os, "O_PATH"), "the look before the open needs O_PATH (Linux)")
    def test_a_lock_that_is_not_a_file_is_looked_at_before_it_is_opened(self):
        # The reader first looks at the lock without opening it. A socket cannot be opened at all, so a reader that
        # opens first ends on the failed open (4); one that looks first refuses it as not a regular file (5).
        folder = os.path.realpath(tempfile.mkdtemp())
        lock = os.path.join(folder, "code-desk.lock")
        s = socket.socket(socket.AF_UNIX)
        try:
            s.bind(lock)
            r = subprocess.run([sys.executable, "-c", ds.LOCK_READER, lock], capture_output=True, timeout=30)
        finally:
            s.close()
        self.assertEqual(r.returncode, 5, r.stderr)
        self.assertEqual(r.stdout, b"")

    def lock_bytes_through_the_reader(self, data, argv, docker):
        """ds.main with its default reader, run for real as this user, on a lock file holding exactly `data`."""
        folder = os.path.realpath(tempfile.mkdtemp())
        desks = os.path.join(folder, "desks")
        os.makedirs(os.path.join(desks, ".state"))
        with open(os.path.join(desks, ".state", "code-desk.lock"), "wb") as f:
            f.write(data)
        return self.settle_reading_for_real(desks, argv=argv, docker=docker)

    def test_a_line_ending_the_enclave_never_writes_is_not_a_claim(self):
        # The Enclave writes `admin:<id>` with no terminator. Read through the real reader process, a lock with a
        # carriage return or CRLF added is not this change's claim: unhold keeps the hold, settle starts nothing.
        for data in (f"admin:{OP}\r\n".encode(), f"admin:{OP}\r".encode(), f"admin:{OP}\n".encode()):
            with self.subTest(data=data):
                docker = FakeDocker([STOPPED], files={f"{OP}.hold": "{}"})
                rc, out = self.lock_bytes_through_the_reader(data, ["--unhold", "code-desk", "--operation", OP], docker)
                self.assertEqual(rc, 1, out)
                self.assertEqual(list(docker.files), [f"{OP}.hold"], "a hold was released on a damaged claim")

                class Docker(FakeDocker):
                    def __call__(self, args, stdin=None):
                        if args[0] == "restart":
                            self.calls.append(args)
                            return 0, ""
                        return super().__call__(args, stdin)
                docker = Docker([STOPPED])
                rc, out = self.lock_bytes_through_the_reader(data, ["code-desk", "--operation", OP], docker)
                self.assertEqual(docker.files, {}, "a settle started on a damaged claim")
                self.assertFalse(any(c[0] == "restart" for c in docker.calls))

    def settle_reading_for_real(self, desks, argv=None, docker=None):
        """up.sh's own path: ds.main with its default reader, run for real as this user (runuser and its clean
        environment taken off), against the folder standing in for the Enclave's desks."""
        real_run = subprocess.run

        def as_this_user(command, **kwargs):
            if command[:1] == ["runuser"]:
                command = list(command[command.index("LANG=C.UTF-8") + 1:])
                command[0] = sys.executable if command[0] == "/usr/bin/python3" else command[0]
                command[-1] = command[-1].replace("/var/lib/ekka/.ekka/home/desks", desks, 1)
            return real_run(command, **kwargs)
        out, err = io.StringIO(), io.StringIO()
        real_open = open

        def opened(path, *args, **kwargs):   # the unfixed reader opens the lock itself, as root
            if isinstance(path, str):
                path = path.replace("/var/lib/ekka/.ekka/home/desks", desks, 1)
            return real_open(path, *args, **kwargs)
        with redirect_stdout(out), redirect_stderr(err), mock.patch.object(ds.subprocess, "run", as_this_user), \
             mock.patch("builtins.open", opened), mock.patch.dict(os.environ, {"DESKS_STATE": self.state()}):
            rc = ds.main(argv or ["code-desk", "--operation", OP], run=docker or FakeDocker([STOPPED]), ekka=enclave)
        return rc, out.getvalue() + err.getvalue()

    def test_an_emptied_or_unrecognized_lock_keeps_the_hold(self):
        # The Enclave removes a lock to free a desk; it never empties one. Only positive evidence releases the hold.
        for second in ("", "\x00\x01", "admin:not-a-uuid"):
            with self.subTest(second=second):
                docker = FakeDocker([STOPPED])
                with self.assertRaisesRegex(ds.Refused, "The hold stays"):
                    go(None, locks=(f"admin:{OP}", second), docker=docker)
                self.assertEqual(list(docker.files), [f"{OP}.hold"])

    def test_a_change_another_holder_took_over_releases_its_hold(self):
        docker = FakeDocker([STOPPED])
        marker, _, said, _ = go(None, locks=(f"admin:{OP}", f"admin:{self.OTHER}"), docker=docker)
        self.assertIsNone(marker)
        self.assertEqual(docker.files, {})

    def test_a_lock_behind_a_linked_folder_is_not_read(self):
        folder = os.path.realpath(tempfile.mkdtemp())
        real = os.path.join(folder, "real")
        os.makedirs(os.path.join(real, "desks", ".state"))
        with open(os.path.join(real, "desks", ".state", "code-desk.lock"), "w") as f:
            f.write(f"admin:{OP}")
        os.symlink(real, os.path.join(folder, "linked"))
        rc, out = self.settle_reading_for_real(os.path.join(folder, "linked", "desks"))
        self.assertEqual(rc, 1, out)
        self.assertIn("could not be read", out)

    def test_a_job_word_in_the_lock_is_not_evidence_the_change_ended(self):
        # A damaged lock holding one word looks like a job's attempt id. Releasing the hold on that would let the
        # adapter re-issue a change that may still be running.
        docker = FakeDocker([STOPPED])
        with self.assertRaisesRegex(ds.Refused, "The hold stays"):
            go(None, locks=(f"admin:{OP}", "pending"), docker=docker)
        self.assertEqual(list(docker.files), [f"{OP}.hold"])

    def test_a_reader_that_cannot_start_is_never_read_as_no_lock(self):
        # The first read claims the change; on the second, runuser cannot start. That says nothing about the lock.
        state = self.state()

        class Docker(FakeDocker):
            def __call__(self, args, stdin=None):
                if args[0] == "restart":
                    self.calls.append(args)
                    return 0, ""
                return super().__call__(args, stdin)
        docker = Docker([STOPPED])
        reads = []

        def runuser(command, **kwargs):
            reads.append(command)
            if len(reads) == 1:
                return subprocess.CompletedProcess(command, 0, f"admin:{OP}".encode(), b"")
            raise FileNotFoundError(2, "No such file or directory", "runuser")
        clock, settle = Clock(), ds.settle
        quick = lambda *a, **k: settle(*a, clock=clock, sleep=clock.sleep, **k)  # noqa: E731
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err), mock.patch.object(ds, "settle", quick), \
             mock.patch.object(ds.subprocess, "run", runuser), mock.patch.dict(os.environ, {"DESKS_STATE": state}):
            rc = ds.main(["code-desk", "--operation", OP], run=docker, ekka=enclave)
        self.assertEqual(len(reads), 2, "the second read, whose start fails, was never reached")
        self.assertEqual(rc, 1, err.getvalue())
        self.assertEqual(list(docker.files), [f"{OP}.hold"], "the hold was released without the lock being seen")

    def test_a_claim_with_a_control_character_is_not_another_change(self):
        docker = FakeDocker([STOPPED])
        with self.assertRaisesRegex(ds.Refused, "The hold stays"):
            go(None, locks=(f"admin:{OP}", f"admin:{self.OTHER}\x1c"), docker=docker)
        self.assertEqual(list(docker.files), [f"{OP}.hold"])

    def test_an_unmatched_hold_is_not_sent_to_an_unhold_that_cannot_match_it(self):
        docker = FakeDocker([STOPPED])
        with self.assertRaises(ds.Refused) as refused:
            go(None, locks=(f"admin:{OP}", "pending"), docker=docker)
        self.assertIn("by hand", str(refused.exception))
        self.assertNotIn("desks unhold", str(refused.exception))

    def test_the_restart_says_every_running_desk_stops(self):
        marker, docker, said, restarts = go([STOPPED])
        self.assertTrue(any("running desks on this machine stop" in line for line in said), said)
        guide = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "OPERATIONS.md")
        with open(guide, encoding="utf-8") as f:
            self.assertIn("stops every running desk on this machine", " ".join(f.read().split()))

    def test_only_a_recognized_holder_is_printed(self):
        self.assertEqual(ds.holder(f"admin:{self.OTHER}"), f"another change holds it (admin:{self.OTHER})")
        self.assertEqual(ds.holder("attempt-7f2c"), "a job holds it (attempt attempt-7f2c)")
        for text in ("TOKEN=planted-credential-value", "-----BEGIN PRIVATE KEY-----", "admin:not-a-uuid secret"):
            self.assertNotIn(text.split("=")[-1].split()[-1], ds.holder(text), text)


class UpSh(unittest.TestCase):
    def test_up_sh_runs_it_and_lists_it(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "up.sh"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("#   sudo ./up.sh desks settle <desk> --operation <request id>", text)
        self.assertRegex(text, r'desks\)[^\n]*\n(?:[^\n]*\n){0,4}[^\n]*exec python3 tools/desks_settle\.py "\$\{@:3\}"')


if __name__ == "__main__":
    unittest.main()
