import json
import os
import plistlib
import stat
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import native_workspace_guest_inventory_probe as probe  # noqa: E402


class Entry:
    def __init__(self, name, path=None, mode=stat.S_IFREG | 0o755, size=1):
        """Represent one directory entry with a predictable stat result."""
        self.name, self.path = name, path or name
        self._stat = os.stat_result((mode, 1, 1, 1, 501, 20, size, 0, 0, 0))

    def stat(self, follow_symlinks=False):
        return self._stat


class Scan:
    def __init__(self, entries):
        """Provide a minimal context-managed directory scan."""
        self.entries = entries

    def __enter__(self):
        """Return the entries in this scan."""
        return iter(self.entries)

    def __exit__(self, *args):
        """Leave scan cleanup to the test fixture."""
        return False


class GuestInventoryProbeTests(unittest.TestCase):
    def test_fixed_command_uses_nonroot_identity_and_clean_environment(self):
        command = probe.command_template("/fixed/tart", "owned-vm", "loader")
        self.assertEqual(command[3:12], ["/usr/bin/sudo", "-n", "-u", "admin", "-g", "staff",
                                         "--", "/usr/bin/env", "-i"])
        self.assertIn("CARGO_NET_OFFLINE=true", command)
        self.assertIn("RUSTUP_AUTO_INSTALL=0", command)
        self.assertIn("HOMEBREW_NO_AUTO_UPDATE=1", command)
        self.assertEqual(command[-5:], ["/usr/bin/python3", "-I", "-c", "loader",
                                        "<fixed-source-bundle-b64>"])
        self.assertNotIn("AWS_SECRET_ACCESS_KEY=", " ".join(command))

    def test_shared_bundle_sources_and_guest_hash_binding(self):
        bundle = probe.build_bundle()
        self.assertEqual(set(bundle["sourceSha256"]), set(probe.SOURCE_FILES))
        self.assertRegex(bundle["bundleSha256"], r"^[0-9a-f]{64}$")
        report = self._collect_guest()
        self.assertEqual(report["sourceSha256"], bundle["sourceSha256"])

    def test_alternate_python_scan_deduplicates_aliases_before_candidate_cap(self):
        aliases = [Entry("python3." + str(i), "/opt/homebrew/bin/python3." + str(i))
                   for i in range(10, 20)]
        current = Entry("python3.13", "/opt/homebrew/opt/python@3.13/bin/python3.13")
        scans = {
            "/opt/homebrew/opt": [Entry("python@3.13", "/opt/homebrew/opt/python@3.13",
                                         stat.S_IFDIR | 0o755)],
            "/opt/homebrew/bin": [*aliases, current],
            "/opt/homebrew/opt/python/bin": [],
            "/opt/homebrew/opt/python@3.13/bin": [current],
        }

        def scandir(path):
            return Scan(scans.get(path, []))
        with mock.patch.object(probe.os, "scandir", side_effect=scandir), \
                mock.patch.object(probe.os.path, "realpath", side_effect=lambda path:
                                  "/same/interpreter" if "python3." in path and "3.13" not in path
                                  else path), \
                mock.patch.object(probe, "_run", side_effect=lambda argv, _deadline:
                                  {"state": "present", "version": "Python 3.9.6" if argv[0] == "/usr/bin/python3"
                                   else "Python 3.13.7"}):
            result = probe._python_candidates(10**30)
        paths = [item["path"] for item in result["items"]]
        self.assertIn("/opt/homebrew/opt/python@3.13/bin/python3.13", paths)
        self.assertEqual(result["items"][-1]["version"], "Python 3.13.7")

    def test_apple_git_placeholder_is_never_invoked(self):
        with mock.patch.object(probe, "_tool_path", return_value="/usr/bin/git"), \
                mock.patch.object(probe, "_run") as run:
            result = probe._fixed_tool("git", 10**30)
        run.assert_not_called()
        self.assertEqual(result["state"], "unsupported")
        self.assertIsNone(result["version"])
        self.assertEqual(result["errorCode"], "apple_git_not_invoked")

    def test_apple_git_placeholder_row_is_valid_in_full_report(self):
        with self._guest_patches(), \
                mock.patch.object(probe, "_python_candidates", return_value=self._python_fixture()), \
                mock.patch.object(probe, "_rust_tools", return_value=self._rust_fixture()), \
                mock.patch.object(probe, "_tool_path", side_effect=lambda name:
                                  "/usr/bin/git" if name == "git" else None), \
                mock.patch.object(probe, "_sdk_inventory", return_value=self._sdk_fixture()), \
                mock.patch.object(probe, "_shallow_inventory", return_value={
                    "state": "missing", "bytesObserved": 0, "entriesObserved": 0,
                    "scanComplete": False}), \
                mock.patch.object(probe.shutil, "disk_usage", side_effect=OSError), \
                mock.patch.object(probe, "_run", return_value={"state": "missing", "version": None}):
            report = probe.collect_guest()
        self.assertEqual(report["tools"]["git"]["state"], "unsupported")
        hashes = dict(report["sourceSha256"])
        self.assertEqual(probe._validated_report(json.dumps(report).encode(), b"", hashes), report)

    def test_rust_argv_uses_only_direct_fixed_tools(self):
        calls = []

        def direct(path, args, deadline):
            calls.append([path, *args])
            return {"state": "missing", "path": path, "version": None}
        with mock.patch.object(probe, "_direct_tool", side_effect=direct):
            probe._rust_tools(10**30)
        self.assertEqual(calls, [
            [probe.RUST_TOOLCHAIN + "/bin/rustc", "--version", "--verbose"],
            [probe.RUST_TOOLCHAIN + "/bin/cargo", "--version"],
            ["/Users/admin/.cargo/bin/cargo-nextest", "--version"]])

    def test_rust_producer_error_and_budget_rows_are_valid_in_full_report(self):
        report = self._collect_guest()
        regular = os.stat_result((stat.S_IFREG | 0o755, 1, 1, 1, 501, 20, 1, 0, 0, 0))
        with mock.patch.object(probe.os, "lstat", return_value=regular), \
                mock.patch.object(probe.os.path, "realpath", side_effect=lambda path: path), \
                mock.patch.object(probe.os, "access", return_value=True), \
                mock.patch.object(probe.os, "stat", side_effect=FileNotFoundError), \
                mock.patch.object(probe.time, "monotonic", side_effect=[0, 11, 11]), \
                mock.patch.object(probe.canary, "_run_bounded", side_effect=
                                  probe.canary.CanaryError("probe_failed")):
            report["rust"].update(probe._rust_tools(10))
        self.assertEqual(report["rust"]["rustc"]["state"], "unsupported")
        self.assertEqual(report["rust"]["rustc"]["errorCode"], "probe_failed")
        self.assertEqual(report["rust"]["cargo"]["state"], "budget_exhausted")
        hashes = dict(report["sourceSha256"])
        self.assertEqual(probe._validated_report(json.dumps(report).encode(), b"", hashes), report)

    def test_collector_checks_runtime_identity_env_commands_and_sources(self):
        commands = []

        def run(argv, deadline):
            commands.append(argv)
            version = "24A123" if argv[:2] == ["/usr/bin/sw_vers", "-buildVersion"] else "observed"
            return {"state": "present", "version": version}
        with self._guest_patches(), \
                mock.patch.object(probe, "_python_candidates", return_value=self._python_fixture()), \
                mock.patch.object(probe, "_rust_tools", return_value=self._rust_fixture()), \
                mock.patch.object(probe, "_fixed_tool", side_effect=lambda name, deadline:
                                  {"state": "present", "path": "/opt/homebrew/bin/" + name,
                                   "version": "observed"}), \
                mock.patch.object(probe, "_sdk_inventory", return_value=self._sdk_fixture()), \
                mock.patch.object(probe, "_shallow_inventory", return_value={
                    "state": "present", "uid": 501, "mode": 0o700, "sizeBytes": 0,
                    "bytesObserved": 0, "entriesObserved": 0,
                    "scanComplete": False}), \
                mock.patch.object(probe.shutil, "disk_usage", return_value=type("Usage", (), {
                    "total": 100, "free": 50})()), \
                mock.patch.object(probe, "_run", side_effect=run):
            report = probe.collect_guest()
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["prepared"])
        self.assertFalse(report["nativeQualified"])
        self.assertEqual(report["runtime"]["osBuild"]["version"], "24A123")
        self.assertIn(["/opt/homebrew/bin/pkg-config", "--modversion", "gstreamer-1.0"], commands)
        self.assertEqual(set(report["sourceSha256"]), {"inventory", "canary"})
        hashes = dict(report["sourceSha256"])
        encoded = json.dumps(report).encode()
        self.assertEqual(probe._validated_report(encoded, b"", hashes), report)
        report["sourceSha256"]["inventory"] = "0" * 64
        with self.assertRaises(ValueError):
            probe._validated_report(json.dumps(report).encode(), b"", hashes)

    def test_runtime_and_root_guards_run_before_any_probe(self):
        with self._guest_patches(), mock.patch.object(probe.platform, "system", return_value="Linux"), \
                mock.patch.object(probe, "_run") as run, mock.patch.object(probe, "_source_hashes") as hashes:
            with self.assertRaisesRegex(ValueError, "guest_runtime_invalid"):
                probe.collect_guest()
        run.assert_not_called()
        with self._guest_patches(), mock.patch.dict(probe.os.environ, {"UNEXPECTED_TEST_ENV": "fixture-only"}), \
                mock.patch.object(probe, "_run") as run:
            with self.assertRaisesRegex(ValueError, "guest_environment_invalid"):
                probe.collect_guest()
        run.assert_not_called()
        hashes.assert_not_called()
        with self._guest_patches(), mock.patch.object(probe.os, "geteuid", return_value=0), \
                mock.patch.object(probe, "_run") as run:
            with self.assertRaisesRegex(ValueError, "guest_identity_invalid"):
                probe.collect_guest()
        run.assert_not_called()

    def test_shared_deadline_returns_partial_observations(self):
        with self._guest_patches(), \
                mock.patch.object(probe, "_python_candidates", return_value=self._python_fixture()), \
                mock.patch.object(probe, "_rust_tools", return_value=self._rust_fixture()), \
                mock.patch.object(probe, "_fixed_tool", return_value={"state": "present",
                    "path": "/opt/homebrew/bin/pkg-config", "version": "1.8"}), \
                mock.patch.object(probe, "_sdk_inventory", return_value=self._sdk_fixture()), \
                mock.patch.object(probe, "_shallow_inventory", return_value={
                    "state": "present", "uid": 501, "mode": 0o700, "sizeBytes": 0,
                    "bytesObserved": 0, "entriesObserved": 0,
                    "scanComplete": False}), \
                mock.patch.object(probe.shutil, "disk_usage", side_effect=OSError), \
                mock.patch.object(probe.time, "monotonic", side_effect=[0] + [25] * 40):
            report = probe.collect_guest()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["runtime"]["osBuild"]["state"], "budget_exhausted")
        self.assertEqual(report["pkgConfigModules"]["gstreamer-1.0"]["state"], "budget_exhausted")
        self.assertEqual(report["resources"]["memoryBytes"]["state"], "budget_exhausted")

    def test_collect_guest_shared_deadline_skips_late_inner_command(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return b"17179869184", b""

        with self._guest_patches(), \
                mock.patch.object(probe, "_python_candidates", return_value=self._python_fixture()), \
                mock.patch.object(probe, "_rust_tools", return_value=self._rust_fixture()), \
                mock.patch.object(probe, "_fixed_tool", return_value={
                    "state": "missing", "path": None, "version": None}), \
                mock.patch.object(probe, "_sdk_inventory", return_value=self._sdk_fixture()), \
                mock.patch.object(probe, "_shallow_inventory", return_value={
                    "state": "missing", "bytesObserved": 0, "entriesObserved": 0,
                    "scanComplete": False}), \
                mock.patch.object(probe.shutil, "disk_usage", side_effect=OSError), \
                mock.patch.object(probe.canary, "_run_bounded", side_effect=run), \
                mock.patch.object(probe.time, "monotonic", side_effect=[0, 23, 25]):
            report = probe.collect_guest()
        self.assertEqual(calls, [["/usr/sbin/sysctl", "-n", "hw.memsize"]])
        self.assertEqual(report["runtime"]["osBuild"]["state"], "budget_exhausted")
        hashes = dict(report["sourceSha256"])
        self.assertEqual(probe._validated_report(json.dumps(report).encode(), b"", hashes), report)

    def test_sdk_settings_read_uses_bounded_hash_and_marks_oversize_unsupported(self):
        sdk = Entry("MacOSX15.sdk", "/fixed/SDKs/MacOSX15.sdk", stat.S_IFDIR | 0o755)
        calls = []

        def scandir(path):
            return Scan([sdk] if path == "/Library/Developer/CommandLineTools/SDKs" else [])

        def bounded(path, *, maximum, collect):
            calls.append((str(path), maximum, collect))
            raise probe.canary.CanaryError("base_vm_file_too_large")
        with mock.patch.object(probe.os, "scandir", side_effect=scandir), \
                mock.patch.object(probe.canary, "_hash_file", side_effect=bounded), \
                mock.patch.object(probe, "_run", return_value={"state": "missing", "version": None}):
            result = probe._sdk_inventory(10**30)
        self.assertEqual(calls, [("/fixed/SDKs/MacOSX15.sdk/SDKSettings.plist", 16 * 1024, True)])
        self.assertEqual(result["locations"][0]["sdks"], [{"state": "unsupported"}])

    def test_sdk_list_root_is_unsupported_and_full_report_valid(self):
        sdk = Entry("MacOSX15.sdk", "/fixed/SDKs/MacOSX15.sdk", stat.S_IFDIR | 0o755)

        def scandir(path):
            return Scan([sdk] if path == "/fixed/SDKs" else [])

        with mock.patch.object(probe.os, "scandir", side_effect=scandir), \
                mock.patch.object(probe.canary, "_hash_file", return_value=(
                    "0" * 64, 2, plistlib.dumps([]))):
            location, _ = probe._sdk_location("clt", "/fixed/SDKs", 10**30)
        report = self._collect_guest()
        report["sdk"]["locations"][0] = location
        self.assertEqual(location["sdks"], [{"state": "unsupported"}])
        hashes = dict(report["sourceSha256"])
        self.assertEqual(probe._validated_report(json.dumps(report).encode(), b"", hashes), report)

    def test_sdk_xcode_enumeration_reports_early_cap(self):
        apps = [Entry("Other-" + str(i) + ".app", "/Applications/Other-" + str(i) + ".app",
                      stat.S_IFDIR | 0o755) for i in range(70)]

        def scandir(path):
            return Scan(apps if path == "/Applications" else [])
        with mock.patch.object(probe.os, "scandir", side_effect=scandir), \
                mock.patch.object(probe, "_run", return_value={"state": "missing", "version": None}):
            result = probe._sdk_inventory(10**30)
        self.assertTrue(result["scanCapped"])

    def test_sdk_xcode_inventory_reads_sdk_settings_from_discovered_app_path(self):
        app = Entry("Xcode-Fixture.app", "/Applications/Xcode-Fixture.app", stat.S_IFDIR | 0o755)
        sdk = Entry("MacOSX15.4.sdk", "/Applications/Xcode-Fixture.app/Contents/Developer/Platforms/"
                    "MacOSX.platform/Developer/SDKs/MacOSX15.4.sdk", stat.S_IFDIR | 0o755)
        expected_plist = sdk.path + "/SDKSettings.plist"
        reads = []

        def scandir(path):
            return Scan([app] if path == "/Applications" else
                        [sdk] if path == "/Applications/Xcode-Fixture.app/Contents/Developer/Platforms/"
                        "MacOSX.platform/Developer/SDKs" else [])

        def hashed(path, *, maximum, collect):
            reads.append((str(path), maximum, collect))
            return "0" * 64, 1, plistlib.dumps({"Version": "15.4", "CanonicalName": "macosx15.4"})

        with mock.patch.object(probe.os, "scandir", side_effect=scandir), \
                mock.patch.object(probe.canary, "_hash_file", side_effect=hashed), \
                mock.patch.object(probe, "_run", return_value={"state": "present",
                                                                 "version": "version: 1.2.3"}):
            result = probe._sdk_inventory(10**30)

        self.assertEqual(reads, [(expected_plist, 16 * 1024, True)])
        xcode = next(location for location in result["locations"] if location["label"] == "xcode")
        self.assertEqual(xcode["sdks"], [{"state": "present", "version": "15.4",
                                           "canonicalName": "macosx15.4"}])
        self.assertNotIn("/Applications/Xcode-Fixture.app", json.dumps(result))

    def test_shallow_cache_never_descends_and_never_claims_complete(self):
        child = Entry("registry", "/Users/admin/.cargo/registry", stat.S_IFDIR | 0o755)
        regular = Entry("config", "/Users/admin/.cargo/config", size=7)
        with mock.patch.object(probe, "_metadata", return_value={"state": "present", "uid": 501, "mode": 0o700}), \
                mock.patch.object(probe.os, "scandir", return_value=Scan([child, regular])) as scan:
            result = probe._shallow_inventory("/Users/admin/.cargo", 10**30)
        scan.assert_called_once_with("/Users/admin/.cargo")
        self.assertEqual(result["bytesObserved"], 7)
        self.assertFalse(result["scanComplete"])

    def test_validator_rejects_extra_fields_wrong_source_and_oversized_output(self):
        report = self._collect_guest()
        hashes = dict(report["sourceSha256"])
        self.assertEqual(probe._validated_report(json.dumps(report).encode(), b"", hashes), report)
        for invalid in (dict(report, extra=True), dict(report, nativeQualified=True),
                        dict(report, sourceSha256={"inventory": "0" * 64, "canary": "1" * 64})):
            with self.assertRaises(ValueError):
                probe._validated_report(json.dumps(invalid).encode(), b"", hashes)
        with self.assertRaises(ValueError):
            probe._validated_report(b"x" * (probe.MAX_REPORT_BYTES + 1), b"", hashes)

    def test_validator_rejects_malformed_nested_observations_as_canary_error(self):
        original = self._collect_guest()
        hashes = dict(original["sourceSha256"])
        cases = []

        def changed(change):
            value = json.loads(json.dumps(original))
            change(value)
            cases.append(value)
        changed(lambda v: v["pythonCandidates"]["items"].append(
            {"path": "/fixed/python", "state": [], "version": None}))
        changed(lambda v: v["pythonCandidates"].update(items=[]))
        changed(lambda v: v["pythonCandidates"]["items"].append(
            {"path": None, "state": "present", "version": "Python fake"}))
        changed(lambda v: v["pythonCandidates"]["items"].append(
            {"path": "relative/python", "state": "present", "version": "Python fake"}))
        changed(lambda v: v["pythonCandidates"]["items"].append(
            {"path": "/fixed/python", "canonicalPath": None,
             "state": "present", "version": "Python fake"}))
        changed(lambda v: v["tools"]["just"].update(state="present", version=None))
        changed(lambda v: v["rust"]["rustc"].update(state=[]))
        changed(lambda v: v["rust"]["rustc"].update(errorCode=[]))
        changed(lambda v: v["rust"]["rustc"].update(path="/other/rustc"))
        changed(lambda v: v["tools"]["just"].update(version=7))
        changed(lambda v: v["pkgConfigModules"]["glib-2.0"].update(extra=True))
        changed(lambda v: v["sdk"].update(cltReceipt={"state": "present", "version": []}))
        changed(lambda v: v["sdk"].update(locations=[]))
        changed(lambda v: v["sdk"].update(locations=[{"label": [], "state": "present", "sdks": []}]))
        changed(lambda v: v["sdk"].update(locations=[{"label": "clt", "state": "present",
            "sdks": [{"state": "present", "version": 1, "canonicalName": "macosx"}]}]))
        changed(lambda v: v["resources"]["disk"].update(totalBytes=True))
        changed(lambda v: v["resources"]["cargoHome"].update(entriesObserved=True))
        changed(lambda v: v["resources"]["rustupHome"].update(bytesObserved=2**80))
        changed(lambda v: v["pythonCandidates"].update(items=[
            {"path": "/x", "state": "missing", "version": None}] * (probe.MAX_CANDIDATES + 2)))
        changed(lambda v: v["rust"].pop("cargo"))
        for invalid in cases:
            with self.subTest(report=invalid), self.assertRaises(probe.canary.CanaryError) as caught:
                probe._validated_report(json.dumps(invalid).encode(), b"", hashes)
            self.assertEqual(caught.exception.args[0], "native_guest_inventory_report_invalid")

    def test_collect_converts_malformed_guest_json_to_failure_result(self):
        bundle = probe.build_bundle()
        report = self._collect_guest()
        report["pythonCandidates"]["items"].append(
            {"path": "/fixed/python", "state": [], "version": None})

        def fake_runner(*args, **kwargs):
            return json.dumps(report).encode(), b""
        with tempfile.TemporaryDirectory() as directory:
            result = probe.collect("/fixed/tart", "owned-vm", {}, directory, bundle,
                                   run_bounded=fake_runner)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failureCode"], "native_guest_inventory_report_invalid")
        self.assertIsNone(result["report"])

    def test_outer_failure_stays_separate_from_guest_report(self):
        bundle = {"loader": "fixed", "argument": "AA==", "sourceSha256": {}, "bundleSha256": "b" * 64}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(probe.canary, "_run_bounded", side_effect=probe.canary.CanaryError("tart_command_timeout")), \
                mock.patch.object(probe.canary, "_raw_evidence", return_value=None):
            result = probe.collect("/fixed/tart", "owned-vm", {}, directory, bundle)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failureCode"], "tart_command_timeout")
        self.assertIsNone(result["report"])

    def _guest_patches(self):
        return mock.ExitStack() if hasattr(mock, "ExitStack") else _GuestPatches()

    def _collect_guest(self):
        with self._guest_patches(), \
                mock.patch.object(probe, "_python_candidates", return_value=self._python_fixture()), \
                mock.patch.object(probe, "_rust_tools", return_value=self._rust_fixture()), \
                mock.patch.object(probe, "_fixed_tool", return_value={"state": "missing", "path": None,
                                                                        "version": None}), \
                mock.patch.object(probe, "_sdk_inventory", return_value=self._sdk_fixture()), \
                mock.patch.object(probe, "_shallow_inventory", return_value={
                    "state": "missing", "bytesObserved": 0, "entriesObserved": 0,
                    "scanComplete": False}), \
                mock.patch.object(probe.shutil, "disk_usage", side_effect=OSError), \
                mock.patch.object(probe, "_run", return_value={"state": "missing", "version": None}):
            return probe.collect_guest()

    def _python_fixture(self):
        return {"state": "present", "items": [{"path": probe.sys.executable,
                "state": "present", "version": "Python fake"}]}

    def _rust_fixture(self):
        return {"rustc": {"path": probe.RUST_TOOLCHAIN + "/bin/rustc",
                           "state": "missing", "version": None},
                "cargo": {"path": probe.RUST_TOOLCHAIN + "/bin/cargo",
                          "state": "missing", "version": None},
                "cargoNextest": {"path": "/Users/admin/.cargo/bin/cargo-nextest",
                                 "state": "missing", "version": None}}

    def _sdk_fixture(self):
        return {"locations": [{"label": "clt", "state": "missing", "sdks": []}],
                "scanCapped": False, "cltReceipt": {"state": "missing", "version": None}}


class _GuestPatches:
    def __enter__(self):
        self.stack = unittest.mock.patch.multiple(probe.os, geteuid=mock.DEFAULT,
                                                   getegid=mock.DEFAULT, chdir=mock.DEFAULT)
        patched = self.stack.__enter__()
        patched["geteuid"].return_value = 501
        patched["getegid"].return_value = 20
        patched["chdir"].return_value = None
        self.env = mock.patch.dict(probe.os.environ, probe.FIXED_ENV, clear=True)
        self.env.__enter__()
        self.platform = mock.patch.multiple(probe.platform, system=mock.DEFAULT,
                                            mac_ver=mock.DEFAULT, machine=mock.DEFAULT)
        p = self.platform.__enter__()
        p["system"].return_value = "Darwin"
        p["mac_ver"].return_value = ("15.0", "", "24A123")
        p["machine"].return_value = "arm64"
        return self

    def __exit__(self, *args):
        self.platform.__exit__(*args)
        self.env.__exit__(*args)
        self.stack.__exit__(*args)
        return False


if __name__ == "__main__":
    unittest.main()
