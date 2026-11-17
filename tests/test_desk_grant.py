"""Discovery/project admission checks and the installer's local grant display."""
import copy
import datetime as dt
import io
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import desk_grant as dg
import schema_check

SCHEMA = json.loads(Path(ROOT, "vendor/ekka-contracts/governance/grant-constraints/desks.v1.schema.json").read_text())
POLICY = json.loads(Path(ROOT, "desk/policy.json").read_text())
IMAGE = "sha256:" + "d" * 64
POLICY_DIGEST = "sha256:" + "e" * 64
NOW = dt.datetime(2026, 10, 16, tzinfo=dt.timezone.utc)
P_IMAGE = "sha256:" + "1" * 64
P_POLICY = "sha256:" + "2" * 64
P_NOW = dt.datetime(2026, 11, 14, 12, 0, 0, tzinfo=dt.timezone.utc)


def sample():
    return json.loads(Path(ROOT, "tests/fixtures/desks-grant.json").read_text())


class TheDiscoveryWindow(unittest.TestCase):
    """`sudo ekka desk grant discovery --image <ref> --providers <a,b> [--minutes N]`: the project's image and the
    grant's `discovery` block, for NVIDIA OpenShell's auto approval mode on one discovery desk. No policy, address
    range or port is added: the desk runs the shipped policy, and the backend adapter's permit gates the rest."""
    PROJ = "sha256:" + "a" * 64
    REF = "ghcr.io/example/project@sha256:" + "a" * 64

    def open_window(self, providers=("github", "bitbucket"), minutes=60, granted=None):
        return dg.window(self.REF, list(providers), minutes, NOW, granted)

    def cli(self, *argv, now=NOW):
        import contextlib
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = dg.main(list(argv), now=now)
            except SystemExit as e:   # argparse refusing a value
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def test_the_window_writes_the_discovery_block_and_the_contract_accepts_it(self):
        w = self.open_window()
        self.assertEqual(w["discovery"], {"image_digests": [self.PROJ], "providers": ["bitbucket", "github"],
                                          "name_prefix": "discover-", "expires_at": "2026-10-16T01:00:00Z"})
        self.assertEqual((w["image_ref"], w["since"]), (self.REF, "2026-10-16T00:00:00Z"))
        self.assertEqual(schema_check.schema_errors(w["discovery"], SCHEMA["$defs"]["full"]["properties"]["discovery"], SCHEMA), [])

    def test_the_window_lasts_60_minutes_unless_told_and_240_at_most(self):
        for args, until in (((), "2026-10-16T01:00:00Z"), (("--minutes", "15"), "2026-10-16T00:15:00Z"),
                            (("--minutes", "240"), "2026-10-16T04:00:00Z")):
            rc, out, err = self.cli("window", "--image-ref", self.REF, "--providers", "github", *args)
            self.assertEqual(rc, 0, err)
            self.assertEqual(json.loads(out)["discovery"]["expires_at"], until, args)
        for bad in ("241", "0", "-5", "1000"):
            rc, out, err = self.cli("window", "--image-ref", self.REF, "--providers", "github", "--minutes", bad)
            self.assertEqual((rc, out), (1, ""), bad)
            self.assertIn("--minutes is a whole number from 1 to 240", err)
        rc, out, _ = self.cli("window", "--image-ref", self.REF, "--providers", "github", "--minutes", "sixty")
        self.assertEqual((rc, out), (2, ""), "not a number: refused before anything is written")

    def test_planted_a_bad_image_reference_is_refused(self):
        for ref in ("ghcr.io/example/project:latest", "ghcr.io/example/project@sha256:" + "a" * 63,
                    "ghcr.io/example/project@sha256:" + "A" * 64, "project@sha256:" + "a" * 64,
                    "ghcr.io/example/project@sha512:" + "a" * 64, "", "ghcr.io/Example/project@sha256:" + "a" * 64):
            with self.assertRaisesRegex(dg.Refused, "a tag can move; a digest cannot", msg=ref):
                dg.window(ref, ["github"], 60, NOW)

    def test_planted_a_bad_provider_list_is_refused(self):
        for providers in ([], ["../github"], ["GitHub"], ["git hub"], [""], ["github", "github"],
                          [f"p{i}" for i in range(9)]):
            with self.assertRaises(dg.Refused, msg=str(providers)):
                self.open_window(providers=providers)
        with self.assertRaisesRegex(dg.Refused, "bitbucket is not connected on this server"):
            self.open_window(providers=["github", "bitbucket"], granted=["github"])
        self.assertEqual(self.open_window(providers=["github"], granted=["github", "bitbucket"])["discovery"]["providers"], ["github"])

    def test_the_command_line_holds_the_providers_to_the_grant_in_force(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "limits.json")
            with open(path, "w") as f:
                json.dump(sample(), f)   # github only
            rc, out, err = self.cli("window", "--image-ref", self.REF, "--providers", "github,bitbucket", "--limits", path)
            self.assertEqual((rc, out), (1, ""))
            self.assertIn("bitbucket is not connected", err)
            rc, out, err = self.cli("window", "--image-ref", self.REF, "--providers", " github ", "--limits", path)
            self.assertEqual(rc, 0, err)
            self.assertEqual(json.loads(out)["discovery"]["providers"], ["github"])

    def test_planted_a_discovery_block_off_its_contract_never_reaches_a_grant(self):
        good = self.open_window()["discovery"]
        for bad in ({**good, "name_prefix": "prod-"}, {**good, "allowed_cidrs": ["0.0.0.0/0"]},
                    {k: v for k, v in good.items() if k != "expires_at"},
                    {**good, "image_digests": []}, {**good, "image_digests": ["sha256:" + c * 64 for c in "abcde"]},
                    {**good, "image_digests": ["sha256:short"]}, {**good, "providers": ["../x"]},
                    {**good, "expires_at": "2026-10-16T01:00:00+00:00"}, {**good, "expires_at": "2026-13-45T01:00:00Z"}):
            with self.assertRaises(dg.Refused, msg=str(bad)):
                dg.check_discovery(bad)


    def test_show_says_the_window_is_open_for_which_image_and_providers_until_when(self):
        w = self.open_window()
        lim = sample()
        lim["discovery"] = w["discovery"]
        lim["image_digests"].append(self.PROJ)
        t = dg.show(lim, w, now=NOW + dt.timedelta(minutes=30))
        self.assertIn("the discovery image " + self.REF + "\n      " + self.PROJ, t)
        self.assertIn("ekka-desk:local, built by the install\n      " + IMAGE, t)
        self.assertIn("DISCOVERY WINDOW open until 2026-10-16T01:00:00Z (opened 2026-10-16T00:00:00Z): image " + self.REF
                      + ", providers bitbucket, github; a desk named discover-* made from that image with only those"
                      " providers may use NVIDIA OpenShell's auto approval mode. End it: sudo ekka desk grant restore", t)
        late = dg.show(lim, w, now=NOW + dt.timedelta(minutes=60))
        self.assertIn("DISCOVERY WINDOW closed at 2026-10-16T01:00:00Z (expired): no desk may enter auto approval mode.", late)
        self.assertNotIn("open until", late)
        self.assertIn("no discovery window: the shipped limits are in force", dg.show(sample(), None, now=NOW))

    def test_show_names_the_image_the_policy_and_the_providers_in_words(self):
        # Label each digest and explain an empty provider list, so the reader knows what was granted
        # and how to connect a key.
        lim = sample()
        lim["providers"] = []
        lim["provider_config_digests"] = {}
        t = dg.show(lim, None, ["claude-code", "github"])
        self.assertIn("ekka-desk:local, built by the install\n      " + IMAGE, t)
        self.assertIn("desk/policy.json, the shipped policy\n      " + POLICY_DIGEST, t)
        self.assertIn("read the shipped policy:  cat " + os.path.abspath(os.path.join(ROOT, "desk", "policy.json")), t)
        self.assertIn("none connected yet, so a desk can use no key.", t)
        self.assertIn("on this server, not connected: claude-code, github", t)
        self.assertIn("<the key> | sudo ekka desk connect <provider>", t)
        t = dg.show(sample(), None, ["claude-code", "github"])
        self.assertIn("connected: github\n  on this server, not connected: claude-code\n", t)

    def test_the_wide_open_discovery_policy_and_the_packs_are_gone(self):
        # NVIDIA OpenShell's gateway, as this installer ships it, refuses the host-less policy over the public internet
        # (FAILED_PRECONDITION, measured with any image), so nothing may point a person at it again.
        for gone in ("desk/policy-discovery.json", "desk/packs"):
            self.assertFalse(os.path.exists(os.path.join(ROOT, gone)), gone)
        import subprocess
        hits = subprocess.run(["git", "grep", "-n", "-I", "-e", "policy-discovery", "-e", "--packs", "-e", "grant packs",
                               "-e", "discovery-policy.json", "--", ".", ":!tests"],   # tests plant the old words as refusals
                              cwd=ROOT, capture_output=True, text=True).stdout
        self.assertEqual([h for h in hits.splitlines() if "discovery-policy.json\"" not in h and "discovery-composed" not in h],
                         [], "only restore's clean-up of an older window may name the old files")


class CommandLine(unittest.TestCase):
    def test_follow_is_refused_when_showing_limits_or_opening_a_window(self):
        import contextlib
        import tempfile
        follow = {"follow": {"grant": "org_desks"}, "requires_role": "admin"}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "limits.json")
            for limits in (follow, {**sample(), **follow}):
                with open(path, "w") as f:
                    json.dump(limits, f)
                for argv in (["show", path], ["window", "--image-ref", "ghcr.io/example/project@sha256:" + "a" * 64,
                                              "--providers", "github", "--limits", path]):
                    out, err = io.StringIO(), io.StringIO()
                    with self.subTest(argv=argv), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        rc = dg.main(argv, now=NOW)
                    self.assertEqual((rc, out.getvalue()), (1, ""))
                    self.assertIn("FOLLOW, not FULL", err.getvalue())



def project_policy(**over):
    """A project's policy: the shipped one with no network of its own, the strictest a project can ask for."""
    mine = copy.deepcopy(POLICY)
    mine["networkPolicies" if "networkPolicies" in mine else "network_policies"] = {}
    mine.update(over)
    return mine


def record(name="acme", image=P_IMAGE, policy=P_POLICY):
    return dg.project(name, image, policy, project_policy(), POLICY, dg.profile_hosts(), P_NOW)


class AProject(unittest.TestCase):
    """`sudo ekka desk grant project add <name> --image sha256:<id> --policy <file>`: a project's own image, built on
    the box, and its own policy join the grant's two lists; the shipped ones stay. The backend adapter has always
    read both as lists."""




    def test_project_policy_floors_refuse_each_attack_by_name(self):
        cases = []

        def case(label, section, value, why):
            mine = project_policy()
            mine[section] = value
            cases.append((label, mine, why))

        def filesystem_case(label, key, value, why):
            fs = copy.deepcopy(POLICY["filesystem"])
            fs[key] = value
            case(label, "filesystem", fs, why)

        for key in ("readOnly", "readWrite"):
            for value in (None, "/tmp", {}, [1], [None], [True], [[]], [{}]):
                filesystem_case(repr(value), key, value, f"filesystem.{key} must be a list of strings")
            for path, why in (("relative", "absolute"), ("", "absolute"),
                              ("/tmp/../etc", "normalized"), ("//etc", "normalized"),
                              ("/tmp/./file", "normalized"), ("/tmp//file", "normalized"),
                              ("/tmp/file/", "normalized"), ("/tmp/*", "glob or wildcard"),
                              ("/tmp/?", "glob or wildcard"), ("/tmp/[ab]", "glob or wildcard"),
                              ("/tmp/{a,b}", "glob or wildcard"), ("/tmp/\\x", "glob or wildcard"),
                              ("/tmp/\nfile", "control"), ("/tmp/\x00file", "control"),
                              ("/tmp/\x7ffile", "control"), ("/tmp/\x85file", "control"),
                              ("/tmp/\u202efile", "control"), ("/tmp/\ud800", "invalid Unicode"),
                              ("/tmp/" + "x" * 4091, "4095 UTF-8 bytes"),
                              ("/tmp/" + "é" * 2046, "4095 UTF-8 bytes")):
                filesystem_case(repr(path), key, POLICY["filesystem"][key] + [path], why)
            filesystem_case("duplicate", key, POLICY["filesystem"][key] * 2,
                            f"filesystem.{key} must not contain duplicate paths")
            fs = copy.deepcopy(POLICY["filesystem"])
            del fs[key]
            case("missing list", "filesystem", fs, f"filesystem.{key} must be a list of strings")

        for path in ("/", "/bin", "/sbin", "/usr", "/usr/local/bin", "/lib", "/lib32", "/lib64", "/libexec",
                     "/etc", "/var", "/var/lib/docker", "/var/lib/ekka/.ekka", "/var/log/jobs",
                     "/proc/1", "/sys/kernel", "/dev", "/dev/sda", "/dev/shm/extra", "/dev/null/extra",
                     "/boot", "/root", "/run", "/var/run/docker.sock", "/home", "/home/other/.ssh",
                     "/home/node", "/sandbox", "/sandbox/ekka-workspace", "/sandbox/ekka-workspace/repo",
                     "/sandbox/.ekka-inputs", "/sandbox/.ekka-inputs/job", "/.openshell"):
            # Keep the cross-list rule separate from the protected-location rule.
            why = "must not share a path" if path in POLICY["filesystem"]["readOnly"] else "overlaps protected location"
            filesystem_case(path, "readWrite", POLICY["filesystem"]["readWrite"] + [path], why)
        for path in ("/opt", "/opt/project-tools", "/opt/projects", "/opt/projects/acme-other",
                     "/var/cache", "/var/cache/other", "/var/cache/acme-other", "/data", "/host", "/mnt"):
            filesystem_case(path, "readWrite", POLICY["filesystem"]["readWrite"] + [path],
                            "outside the allowed project write locations")
        for path in ("/", "/root/.ssh", "/home/other/.ssh", "/home/node/.ssh", "/var", "/var/lib/docker",
                     "/var/lib/ekka/.ekka", "/run/secrets", "/var/run/docker.sock", "/sys", "/dev/sda", "/.openshell",
                     "/proc/1", "/proc/self/root", "/proc/self/root/root", "/proc/1/fd/3"):
            filesystem_case(path, "readOnly", POLICY["filesystem"]["readOnly"] + [path],
                            "overlaps protected location")
        for path in ("/opt", "/opt/other", "/opt/project-tools-other", "/var/cache", "/var/cache/other",
                     "/sandbox", "/sandbox/.ekka-inputs-other", "/host", "/mnt/host", "/media", "/data"):
            filesystem_case(path, "readOnly", POLICY["filesystem"]["readOnly"] + [path],
                            "outside the allowed project read locations")
        for value in (None, [], "filesystem", True):
            case("not an object", "filesystem", value, "filesystem must be an object")
        for value in (False, None, 1, "true"):
            filesystem_case("changed includeWorkdir", "includeWorkdir", value, "filesystem.includeWorkdir")
        fs = copy.deepcopy(POLICY["filesystem"])
        del fs["includeWorkdir"]
        case("missing includeWorkdir", "filesystem", fs, "filesystem.includeWorkdir")
        filesystem_case("unknown key", "allowAll", True, "filesystem has unknown keys: allowAll")
        for path in POLICY["filesystem"]["readOnly"]:
            filesystem_case("dropped baseline read", "readOnly",
                            [p for p in POLICY["filesystem"]["readOnly"] if p != path],
                            "filesystem.readOnly must keep every shipped entry")
        fs = copy.deepcopy(POLICY["filesystem"])
        fs["readOnly"].remove("/etc")
        fs["readWrite"].append("/etc")
        case("move etc to writes", "filesystem", fs, "filesystem.readOnly must keep every shipped entry")
        fs = copy.deepcopy(POLICY["filesystem"])
        for key in ("readOnly", "readWrite"):
            fs[key].append("/var/cache/acme")
        case("same path in both lists", "filesystem", fs, "must not share a path")
        for part, value in (("process", {"runAsUser": "0", "runAsGroup": "1000"}),
                            ("process", {"runAsUser": "1000", "runAsGroup": "0"}),
                            ("process", {"runAsUser": 1000, "runAsGroup": 1000}),
                            ("process", None), ("landlock", {"compatibility": "best_effort"}),
                            ("landlock", None), ("version", True), ("version", 1.0), ("version", 2)):
            case(part, part, value, f"changes `{part}`")

        for label, mine, why in cases:
            with self.subTest(attack=label, refusal=why):
                with self.assertRaises(dg.Refused) as caught:
                    dg.project("acme", P_IMAGE, P_POLICY, mine, POLICY, dg.profile_hosts(), P_NOW)
                self.assertIn(why, str(caught.exception))
                self.assertNotIn("\n", str(caught.exception))

    def test_project_file_additions_and_tighter_writes_are_accepted(self):
        for key, paths in (
            ("readOnly", ["/opt/project-tools", "/opt/project-tools/bin", "/etc/ssl",
                          "/sandbox/.ekka-inputs", "/sandbox/ekka-workspace/repo", "/var/cache/acme/tools"]),
            ("readWrite", ["/var/cache/acme", "/var/cache/acme/build", "/opt/projects/acme",
                           "/opt/projects/acme/build", "/tmp/acme", "/tmp/" + "x" * 4090]),
        ):
            for path in paths:
                with self.subTest(key=key, path=path):
                    mine = project_policy()
                    mine["filesystem"][key].append(path)
                    before = copy.deepcopy(mine)
                    self.assertEqual(dg.project("acme", P_IMAGE, P_POLICY, mine, POLICY, dg.profile_hosts(), P_NOW), record())
                    self.assertEqual(mine, before, "validation does not rewrite the policy being digested")
        mine = project_policy()
        mine["filesystem"]["readWrite"] = []
        mine["filesystem"]["readOnly"].reverse()
        self.assertEqual(dg.project("acme", P_IMAGE, P_POLICY, mine, POLICY, dg.profile_hosts(), P_NOW), record())
        mine["filesystem"]["readWrite"] = ["/var/cache/project"]
        self.assertEqual(dg.project("project", P_IMAGE, P_POLICY, mine, POLICY, dg.profile_hosts(), P_NOW)["name"], "project")

    def test_network_ceiling_is_unchanged_with_project_file_rules(self):
        for key in ("networkPolicies", "network_policies"):
            for host, accepted in (("github.com", True), ("evil.example.com", False)):
                with self.subTest(key=key, host=host):
                    mine = project_policy()
                    mine.pop("networkPolicies", None)
                    mine.pop("network_policies", None)
                    rule = copy.deepcopy(next(iter(POLICY["networkPolicies"].values())))
                    rule["endpoints"][0]["host"] = host
                    mine[key] = {"project": rule}
                    mine["filesystem"]["readOnly"].append("/opt/project-tools")
                    mine["filesystem"]["readWrite"].append("/var/cache/acme")
                    if accepted:
                        self.assertEqual(dg.project("acme", P_IMAGE, P_POLICY, mine, POLICY, dg.profile_hosts(), P_NOW), record())
                    else:
                        with self.assertRaisesRegex(dg.Refused, "outside the ceiling"):
                            dg.project("acme", P_IMAGE, P_POLICY, mine, POLICY, dg.profile_hosts(), P_NOW)

    def test_planted_without_the_must_equal_check_a_root_policy_would_be_accepted(self):
        # The red this check prevents: the same call with the parts it compares emptied.
        keep = dg.POLICY_MUST_EQUAL
        dg.POLICY_MUST_EQUAL = ()
        try:
            got = dg.project("acme", P_IMAGE, P_POLICY, project_policy(process={"runAsUser": "0", "runAsGroup": "0"}),
                             POLICY, dg.profile_hosts(), P_NOW)
        finally:
            dg.POLICY_MUST_EQUAL = keep
        self.assertEqual(got["name"], "acme")

    def test_a_policy_holding_any_other_part_is_refused_by_name(self):
        for over, why in (({"networkMiddlewares": {"m": {}}}, "holds networkMiddlewares"),
                          ({"userNamespaces": True}, "holds userNamespaces"),
                          ({"version": 2}, "changes `version`"),
                          ({"networkPolicies": {}, "network_policies": {}}, "names its network rules twice")):
            with self.assertRaises(dg.Refused, msg=over) as c:
                dg.project("acme", P_IMAGE, P_POLICY, project_policy(**over), POLICY, dg.profile_hosts(), P_NOW)
            self.assertIn(why, str(c.exception))
        for bad in ([], "policy", None):
            with self.assertRaises(dg.Refused, msg=bad):
                dg.project("acme", P_IMAGE, P_POLICY, bad, POLICY, dg.profile_hosts(), P_NOW)

    def test_a_policy_opening_a_host_outside_the_ceiling_is_refused(self):
        key = "networkPolicies" if "networkPolicies" in POLICY else "network_policies"
        rule = copy.deepcopy(next(iter(POLICY[key].values())))
        rule["endpoints"][0]["host"] = "evil.example.com"
        with self.assertRaises(dg.Refused) as c:
            dg.project("acme", P_IMAGE, P_POLICY, project_policy(**{key: {"x": rule}}), POLICY, dg.profile_hosts(), P_NOW)
        self.assertIn("evil.example.com, outside the ceiling", str(c.exception))

    def test_a_policy_keeping_a_host_inside_the_ceiling_is_accepted(self):
        key = "networkPolicies" if "networkPolicies" in POLICY else "network_policies"
        got = dg.project("acme", P_IMAGE, P_POLICY, project_policy(**{key: POLICY[key]}), POLICY, dg.profile_hosts(), P_NOW)
        self.assertEqual(got, {"name": "acme", "image_id": P_IMAGE, "policy_digest": P_POLICY, "since": "2026-11-14T12:00:00Z"})

    def test_a_bad_name_or_digest_is_refused(self):
        for name, image, policy in (("ACME", P_IMAGE, P_POLICY), ("../x", P_IMAGE, P_POLICY), ("", P_IMAGE, P_POLICY),
                                    ("acme", "acme-desk:local", P_POLICY), ("acme", "sha256:ABC", P_POLICY),
                                    ("acme", P_IMAGE, "latest")):
            with self.assertRaises(dg.Refused, msg=(name, image, policy)):
                dg.project(name, image, policy, project_policy(), POLICY, dg.profile_hosts(), P_NOW)

    def test_a_record_with_another_shape_never_reaches_a_grant(self):
        good = record()
        for bad in ({**good, "discovery": {}}, {k: v for k, v in good.items() if k != "since"}, [good], "acme",
                    {**good, "image_id": "ekka-desk:local"}, {**good, "since": "yesterday"}):
            with self.assertRaises(dg.Refused, msg=bad):
                dg.check_project(bad)


    def test_show_names_the_project_beside_its_image_and_policy(self):
        lim = sample()
        lim["image_digests"].append(P_IMAGE)
        lim["policy_digests"].append(P_POLICY)
        text = dg.show(lim, projects=[record()], now=P_NOW)
        self.assertIn("project acme, an image built on this server\n      " + P_IMAGE, text)
        self.assertIn("ekka-desk:local, built by the install\n      " + IMAGE, text)
        self.assertIn("project acme, its own policy\n      " + P_POLICY, text)
        self.assertIn("desk/policy.json, the shipped policy\n      " + POLICY_DIGEST, text)
        self.assertIn("sudo ekka desk grant project remove acme", text)
        self.assertNotIn("the shipped limits are in force", text)
        self.assertIn("the shipped limits are in force", dg.show(sample(), now=P_NOW))

    def test_the_command_prints_the_record_and_a_refusal_prints_nothing(self):
        import contextlib, tempfile
        with tempfile.TemporaryDirectory() as d:
            good, bad, bad_files = (os.path.join(d, name) for name in ("good.json", "bad.json", "bad-files.json"))
            mine = project_policy()
            mine["filesystem"]["readOnly"].append("/opt/project-tools")
            mine["filesystem"]["readWrite"].append("/var/cache/acme")
            with open(good, "w") as f:
                json.dump(mine, f)
            with open(bad, "w") as f:
                json.dump(project_policy(process={"runAsUser": "0", "runAsGroup": "0"}), f)
            mine["filesystem"]["readWrite"].append("/")
            with open(bad_files, "w") as f:
                json.dump(mine, f)
            for path, want in ((good, 0), (bad, 1), (bad_files, 1), (os.path.join(d, "missing.json"), None)):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    try:
                        rc = dg.main(["project", "--name", "acme", "--image-id", P_IMAGE, "--policy-digest", P_POLICY,
                                      "--policy", path], now=P_NOW)
                    except OSError:
                        rc = None
                self.assertEqual(rc, want, path)
                if want == 0:
                    self.assertEqual(json.loads(out.getvalue()), record())
                else:
                    self.assertEqual(out.getvalue(), "", "a refusal writes no record")
                    if path == bad_files:
                        self.assertIn("filesystem.readWrite", err.getvalue())


class TheGatewayNeverPullsADeskImage(unittest.TestCase):
    """The grant pins the content ID of the image this machine built. A pull could put another image under the
    same name, so the docker driver must use only what is already here (OpenShell ImagePullPolicy::Never)."""

    def test_the_docker_driver_never_pulls(self):
        from gateway_preflight import read_toml   # tomllib where Python has it, the plain reader on 3.9 and 3.10
        config = read_toml(os.path.join(ROOT, "deploy", "gateway", "gateway.toml.template"))
        self.assertEqual(config["openshell"]["drivers"]["docker"].get("image_pull_policy"), "never")
