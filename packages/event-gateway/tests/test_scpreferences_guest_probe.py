"""Offline tests for fixed SCPreferences guest-probe packaging and validation."""

import base64
import hashlib
import importlib.util
from io import StringIO
import json
from pathlib import Path
import shutil
import subprocess  # nosec B404 -- fixed Python child with fake preference/source fixtures only.
import sys
import tempfile
import unittest
import zlib
from unittest.mock import patch
from contextlib import redirect_stdout
from contextlib import contextmanager

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import qualify_offline_macos_vm as canary  # noqa: E402
import scpreferences_guest_probe as probe  # noqa: E402

SOURCE_SCRIPTS = HERE.parent / "scripts"


@contextmanager
def scratch_bundle_sources():
    with tempfile.TemporaryDirectory(prefix="scpreferences-source-copy-") as temp:
        root = Path(temp)
        paths = {}
        for key, filename in probe.SOURCE_FILES.items():
            source = SOURCE_SCRIPTS / filename
            destination = root / filename
            shutil.copyfile(source, destination)
            paths[key] = destination
        with patch.object(probe, "SOURCE_PATHS", paths):
            yield paths


def report_for(hashes):
    return {
        "kind": probe.REPORT_KIND,
        "status": "passed",
        "apiQualified": True,
        "effectiveDaemonQualified": False,
        "failureCode": None,
        "checks": {name: True for name in probe.CHECKS},
        "savedValuePresent": False,
        "sourceSha256": hashes,
        "journalDirectory": "/private/tmp/softnet-scpreferences-api-01234567",
    }


class SCPreferencesGuestProbeTests(unittest.TestCase):
    def test_bundle_contains_only_four_fixed_hashed_sources_with_bounded_encoding(self):
        with scratch_bundle_sources():
            bundle = probe.build_bundle()
        packed = base64.b64decode(bundle["argument"], validate=True)
        raw = zlib.decompress(packed)
        files = json.loads(raw)
        expected_names = set(probe.SOURCE_FILES.values())
        self.assertEqual(set(files), expected_names)
        self.assertLessEqual(len(raw), probe.MAX_SOURCE_BYTES)
        self.assertLessEqual(len(bundle["argument"]), probe.MAX_BUNDLE_ARG)
        expected_hashes = {}
        for key, filename in probe.SOURCE_FILES.items():
            content = base64.b64decode(files[filename]["content"], validate=True)
            digest = hashlib.sha256(content).hexdigest()
            self.assertEqual(files[filename]["sha256"], digest)
            expected_hashes[key] = digest
        self.assertEqual(bundle["sourceSha256"], expected_hashes)
        self.assertEqual(bundle["bundleSha256"], hashlib.sha256(bundle["argument"].encode()).hexdigest())

    def test_guest_loader_executes_only_fake_modules_and_reports_verified_source_hashes(self):
        with tempfile.TemporaryDirectory(prefix="fake-scpreferences-sources-") as temp:
            source_dir = Path(temp)
            (source_dir / "qualify_offline_macos_vm.py").write_text("BOUNDARY_MODULE = True\n")
            (source_dir / "softnet_preferences.py").write_text("PREFERENCES_MODULE = True\n")
            (source_dir / "softnet_recovery.py").write_text("RECOVERY_MODULE = True\n")
            fake_guest = '''import hashlib, json, pathlib
import qualify_offline_macos_vm, softnet_preferences, softnet_recovery
def qualify_guest_apis():
    root = pathlib.Path(__file__).parent
    files = {"guestApi": root / "qualify_scpreferences_guest.py",
             "offlineCanary": pathlib.Path(qualify_offline_macos_vm.__file__),
             "softnetPreferences": pathlib.Path(softnet_preferences.__file__),
             "softnetRecovery": pathlib.Path(softnet_recovery.__file__)}
    checks = ("environmentSupported", "captureCompleted", "targetWriteAppliedSynchronized",
              "freshTargetReadback", "lockContentionRejected", "restoreCompleted",
              "freshOriginalReadback", "restoredMarkerVerified")
    return {"kind": "scpreferences-guest-api-qualification-v1", "status": "passed",
            "apiQualified": True, "effectiveDaemonQualified": False, "failureCode": None,
            "checks": {name: True for name in checks}, "savedValuePresent": False,
            "sourceSha256": {key: hashlib.sha256(path.read_bytes()).hexdigest()
                             for key, path in files.items()},
            "journalDirectory": "/private/tmp/softnet-scpreferences-api-fake0000"}
'''
            (source_dir / "qualify_scpreferences_guest.py").write_text(fake_guest)
            with patch.object(probe, "SOURCE_PATHS", {
                    "offlineCanary": source_dir / "qualify_offline_macos_vm.py",
                    "softnetPreferences": source_dir / "softnet_preferences.py",
                    "softnetRecovery": source_dir / "softnet_recovery.py",
                    "guestApi": source_dir / "qualify_scpreferences_guest.py"}):
                bundle = probe.build_bundle()
            result = subprocess.run(  # nosec B603 -- fixed interpreter and inline fixture; no shell or external command.
                [sys.executable, "-I", "-c", probe.LOADER, bundle["argument"]],
                check=False, capture_output=True, timeout=10, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(probe._validated_report(result.stdout.encode(), b"", bundle["sourceSha256"]), report)
        self.assertFalse(report["effectiveDaemonQualified"])
        source_bundle = json.loads(zlib.decompress(base64.b64decode(bundle["argument"])))
        source_bundle["unexpected.py"] = {}
        invalid_argument = base64.b64encode(zlib.compress(
            json.dumps(source_bundle, sort_keys=True, separators=(",", ":")).encode())).decode()
        invalid = subprocess.run(  # nosec B603 -- fixed loader with intentionally invalid fixture data, no shell.
            [sys.executable, "-I", "-c", probe.LOADER, invalid_argument],
                                 check=False, capture_output=True, timeout=10, text=True)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(invalid.stdout, "")

    def test_report_rejects_unqualified_extra_and_mismatched_source_records(self):
        hashes = {name: "a" * 64 for name in probe.SOURCE_FILES}
        report = report_for(hashes)
        self.assertEqual(probe._validated_report(json.dumps(report).encode(), b"", hashes), report)
        cases = [
            {**report, "extra": True},
            {**report, "effectiveDaemonQualified": True},
            {**report, "checks": {**report["checks"], "restoreCompleted": False}},
            {**report, "sourceSha256": dict(hashes, guestApi="b" * 64)},
            {**report, "journalDirectory": "/private/tmp/../etc/passwd"},
        ]
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    canary.CanaryError, "scpreferences_api_report_unqualified"):
                probe._validated_report(json.dumps(invalid).encode(), b"", hashes)
        with self.assertRaisesRegex(canary.CanaryError, "scpreferences_api_output_invalid"):
            probe._validated_report(json.dumps(report).encode(), b"diagnostic", hashes)

    def test_qualify_uses_fixed_bounded_sudo_command_and_keeps_bundle_binding(self):
        hashes = {name: "c" * 64 for name in probe.SOURCE_FILES}
        bundle = {"argument": "QkFORExF", "sourceSha256": hashes, "bundleSha256": "d" * 64}
        output = json.dumps(report_for(hashes)).encode()
        captured = {}

        def run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            for path, data in zip(kwargs["capture_paths"], (output, b"")):
                Path(path).write_bytes(data)
            return output, b""

        with tempfile.TemporaryDirectory(prefix="probe-evidence-") as temp:
            result = probe.qualify("/fixed/tart", "offline-canary-123", {"PATH": "/usr/bin"},
                                   temp, bundle, run_bounded=run)
            self.assertEqual(set(result), {"report"})
            self.assertEqual(Path(temp, "scpreferences-api-stdout.bin").read_bytes(), output)
            self.assertEqual(Path(temp, "scpreferences-api-stderr.bin").read_bytes(), b"")
            self.assertEqual(captured["argv"], ["/fixed/tart", "exec", "offline-canary-123",
                "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-c", probe.LOADER, "QkFORExF"])
            self.assertEqual(captured["kwargs"], {
                "timeout": 30, "env": {"PATH": "/usr/bin"}, "output_limit": 16 * 1024,
                "capture_paths": (Path(temp, "scpreferences-api-stdout.bin"),
                                  Path(temp, "scpreferences-api-stderr.bin"))})
            self.assertEqual(probe.metadata(bundle)["sourceSha256"], hashes)
            self.assertEqual(probe.command_template("/fixed/tart", "offline-canary-123")[-1],
                             "<fixed-source-bundle-b64>")

    def test_source_files_must_be_regular_and_bundle_size_is_bounded(self):
        with tempfile.TemporaryDirectory(prefix="probe-sources-") as temp:
            root = Path(temp)
            for filename in probe.SOURCE_FILES.values():
                (root / filename).write_text("source\n")
            link = root / probe.SOURCE_FILES["guestApi"]
            data = link.read_text()
            link.unlink()
            link.symlink_to(root / probe.SOURCE_FILES["offlineCanary"])
            sources = {key: root / name for key, name in probe.SOURCE_FILES.items()}
            with patch.object(probe, "SOURCE_PATHS", sources), self.assertRaisesRegex(
                    canary.CanaryError, "scpreferences_api_source_unsafe"):
                probe.build_bundle()
            link.unlink()
            link.write_text(data)
            with patch.object(probe, "SOURCE_PATHS", sources), patch.object(
                    probe, "MAX_BUNDLE_ARG", 1), self.assertRaisesRegex(
                        canary.CanaryError, "scpreferences_api_bundle_oversized"):
                probe.build_bundle()

    def test_cli_module_identity_keeps_probe_failures_as_stable_canary_errors(self):
        spec = importlib.util.spec_from_file_location("cli_canary", canary.__file__)
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        self.assertIsNot(cli.CanaryError, probe.canary.CanaryError)
        with patch.object(probe, "build_bundle", side_effect=probe.canary.CanaryError("bundle_failed")):
            with self.assertRaisesRegex(cli.CanaryError, "^bundle_failed$"):
                cli._prepare_scpreferences_api(True)
        with patch.object(probe, "qualify", side_effect=probe.canary.CanaryError("probe_failed")):
            with self.assertRaisesRegex(cli.CanaryError, "^probe_failed$"):
                cli._run_scpreferences_api(probe, {"sourceSha256": {}, "bundleSha256": "a" * 64},
                                          "/fixed/tart", "clone", {}, Path("unused"), None, {}, [])

    def test_cli_flag_is_opt_in_and_only_forwards_a_boolean(self):
        args = ["--base-vm", "prepared", "--receipt", "receipt.json", "--evidence-dir", "evidence"]
        summary = {"kind": "offline-macos-vm-boundary-canary-v1", "status": "passed"}
        with patch.object(canary, "qualify", return_value=summary) as qualify, \
                redirect_stdout(StringIO()):
            self.assertEqual(canary.main(args), 0)
        self.assertNotIn("scpreferences_api", qualify.call_args.kwargs)
        with patch.object(canary, "qualify", return_value=summary) as qualify, \
                redirect_stdout(StringIO()):
            self.assertEqual(canary.main([*args, "--scpreferences-api"]), 0)
        self.assertIs(qualify.call_args.kwargs["scpreferences_api"], True)
        with self.assertRaisesRegex(canary.CanaryError, "invalid_scpreferences_api_flag"):
            canary.qualify("prepared", "unused", "unused", scpreferences_api=1)


if __name__ == "__main__":
    unittest.main()
