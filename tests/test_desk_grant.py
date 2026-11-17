"""Project admission and provider host checks."""
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

POLICY = json.loads(Path(ROOT, "desk/policy.json").read_text())
P_IMAGE = "sha256:" + "1" * 64
P_POLICY = "sha256:" + "2" * 64
P_NOW = dt.datetime(2026, 11, 14, 12, 0, 0, tzinfo=dt.timezone.utc)



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
