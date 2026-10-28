"""Controller integration for the opt-in native guest inventory collector."""

import builtins
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import test_offline_macos_vm as fixture

canary = fixture.canary


MODULE_NAME = "native_workspace_guest_inventory_probe"
STDOUT_NAME = "native-workspace-guest-inventory-stdout.json"
STDERR_NAME = "native-workspace-guest-inventory-stderr.bin"
MAX_REPORT_BYTES = 16 * 1024
HASHES = {"inventory": "a" * 64, "canary": "b" * 64}
BUNDLE = {"argument": "fixed-test-bundle", "sourceSha256": HASHES,
          "bundleSha256": "c" * 64, "loader": "fixed-loader"}


class NativeWorkspaceGuestInventoryIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.harness = fixture.OfflineMacosVmCanaryTest()
        self.harness.setUp()

    def tearDown(self):
        self.harness.tearDown()

    def _qualify(self, **options):
        class FixedUuid:
            hex = "c" * 32

        with patch.multiple(canary, CANARY_TIMEOUT=2, VM_READY_TIMEOUT=4,
                            VM_READY_PROBE_TIMEOUT=0.2,
                            TART_BINARY_SHA256=canary._sha256(self.harness.tart.read_bytes())), \
                patch.object(canary.uuid, "uuid4", return_value=FixedUuid()), \
                patch.object(canary.shutil, "disk_usage",
                             return_value=SimpleNamespace(free=200 * 1024**3)):
            return canary.qualify("prepared-macos15", self.harness.receipt_path,
                                  self.harness.evidence, tart=str(self.harness.tart),
                                  tart_home=self.harness.tart_home, **options)

    def _probe(self, *, collect, build_bundle=None, command_template=None):
        def template(tart, clone, loader):
            if command_template is not None:
                return command_template(tart, clone, loader)
            return [str(tart), "exec", clone, "/usr/bin/sudo", "-n", "-u", "admin",
                    "-g", "staff", "--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin",
                    "/usr/bin/python3", "-I", "-c", loader, "<fixed-source-bundle-b64>"]

        return SimpleNamespace(
            canary=canary, MAX_REPORT_BYTES=MAX_REPORT_BYTES,
            build_bundle=(build_bundle or (lambda: BUNDLE)),
            command_template=template, collect=collect,
        )

    def _install_probe(self, probe):
        return patch.dict(sys.modules, {MODULE_NAME: probe})

    def _saved(self):
        return json.loads((self.harness.evidence / "offline-macos-vm-canary.json").read_text())

    def test_default_does_not_import_or_collect_inventory(self):
        self.harness._write_fake_tart(frames="both")
        self.harness._write_receipt()
        imports = []
        real_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name == MODULE_NAME:
                imports.append(name)
                raise AssertionError("default path imported inventory probe")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=guarded_import):
            self._qualify()

        saved = self._saved()
        self.assertEqual(imports, [])
        self.assertNotIn("nativeWorkspaceGuestInventory", saved)
        self.assertFalse(any("fixed-source-bundle-b64" in command[-1]
                             for command in saved["hostCommandTemplates"]))

    def test_opt_in_collects_after_baseline_and_publishes_metadata_command_and_raw_files(self):
        self.harness._write_fake_tart(frames="both")
        self.harness._write_receipt()
        stdout = b'{"kind":"fixed-inventory-fixture","status":"passed"}\n'
        stderr = b""
        calls = []
        report = {"kind": "fixed-inventory-fixture", "status": "passed",
                  "collectionOnly": True, "prepared": False, "nativeQualified": False}

        def collect(tart, clone, env, evidence, bundle, *, run_bounded):
            evidence = Path(evidence)
            calls.append((tart, clone, env, bundle, run_bounded))
            self.assertTrue((evidence / "frame-ipv4.bin").is_file())
            self.assertTrue((evidence / "frame-ipv6.bin").is_file())
            self.assertTrue((self.harness.tart_home / "guest-started").is_file())
            (evidence / STDOUT_NAME).write_bytes(stdout)
            (evidence / STDERR_NAME).write_bytes(stderr)
            records = {name: canary._raw_evidence(evidence / name, MAX_REPORT_BYTES, [])
                       for name in (STDOUT_NAME, STDERR_NAME)}
            return {"status": "passed", "report": report, "bundleSha256": BUNDLE["bundleSha256"],
                    "failureCode": None, "rawEvidence": records}

        build_calls = []
        probe = self._probe(collect=collect,
                            build_bundle=lambda: (build_calls.append(True), BUNDLE)[1])
        with self._install_probe(probe):
            self._qualify(native_workspace_guest_inventory=True)

        self.assertEqual(build_calls, [True])
        saved = self._saved()
        metadata = saved["nativeWorkspaceGuestInventory"]
        self.assertEqual(saved["status"], "passed", saved)
        self.assertNotIn("scpreferencesApi", saved)
        self.assertNotIn("softnetDhcp", saved)
        self.assertEqual(metadata["sourceSha256"], HASHES)
        self.assertEqual(metadata["bundleSha256"], BUNDLE["bundleSha256"])
        self.assertEqual(metadata["status"], "passed")
        self.assertEqual(metadata["report"], report)
        self.assertIsNone(metadata["failureCode"])
        self.assertTrue(metadata["collectionOnly"])
        self.assertFalse(metadata["prepared"])
        self.assertFalse(metadata["nativeQualified"])
        self.assertEqual(metadata["rawReport"], {"file": STDOUT_NAME, "maxBytes": MAX_REPORT_BYTES})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], self.harness.tart)
        self.assertEqual(calls[0][1], saved["cloneVmName"])
        self.assertEqual(calls[0][2]["TART_HOME"], str(self.harness.tart_home))
        self.assertIs(calls[0][3], BUNDLE)
        self.assertIs(calls[0][4], canary._run_bounded)
        template = [str(self.harness.tart), "exec", saved["cloneVmName"], "/usr/bin/sudo", "-n",
                    "-u", "admin", "-g", "staff", "--", "/usr/bin/env", "-i",
                    "PATH=/usr/bin:/bin", "/usr/bin/python3", "-I", "-c", BUNDLE["loader"],
                    "<fixed-source-bundle-b64>"]
        self.assertIn(template, saved["hostCommandTemplates"])
        for name, expected in ((STDOUT_NAME, stdout), (STDERR_NAME, stderr)):
            record = saved["rawEvidence"][name]
            self.assertEqual(record, {"bytes": len(expected), "sha256": canary._sha256(expected),
                                      "maxBytes": MAX_REPORT_BYTES})
            self.assertEqual((self.harness.evidence / name).read_bytes(), expected)
            self.assertEqual(metadata["rawEvidence"][name], record)
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertFalse((self.harness.tart_home / "vms" / saved["cloneVmName"]).exists())

    def test_failed_collection_preserves_failure_data_and_cleans_owned_clone(self):
        self.harness._write_fake_tart(frames="both")
        self.harness._write_receipt()
        stdout = b'{"partial":"inventory"}\n'
        stderr = b"collector diagnostic"
        report = {"partial": "preserved"}

        def collect(_tart, _clone, _env, evidence, _bundle, *, run_bounded):
            evidence = Path(evidence)
            (evidence / STDOUT_NAME).write_bytes(stdout)
            (evidence / STDERR_NAME).write_bytes(stderr)
            records = {name: canary._raw_evidence(evidence / name, MAX_REPORT_BYTES, [])
                       for name in (STDOUT_NAME, STDERR_NAME)}
            return {"status": "failed", "report": report, "bundleSha256": BUNDLE["bundleSha256"],
                    "failureCode": "native_guest_inventory_output_invalid", "rawEvidence": records}

        with self._install_probe(self._probe(collect=collect)), \
                self.assertRaisesRegex(canary.CanaryError, "native_guest_inventory_collection_failed"):
            self._qualify(native_workspace_guest_inventory=True)

        saved = self._saved()
        metadata = saved["nativeWorkspaceGuestInventory"]
        self.assertEqual(saved["status"], "failed")
        self.assertEqual(saved["error"], "native_guest_inventory_collection_failed")
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["failureCode"], "native_guest_inventory_output_invalid")
        self.assertEqual(metadata["report"], report)
        self.assertEqual(saved["rawEvidence"][STDOUT_NAME]["sha256"], canary._sha256(stdout))
        self.assertEqual(saved["rawEvidence"][STDERR_NAME]["sha256"], canary._sha256(stderr))
        clone = saved["cloneVmName"]
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertEqual([path.name for path in (self.harness.tart_home / "vms").iterdir()],
                         ["prepared-macos15"])
        self.assertFalse((self.harness.tart_home / "vms" / clone).exists())

    def test_unexpected_collection_status_fails_closed_and_keeps_metadata(self):
        report = {"partial": "preserved"}
        probe = self._probe(collect=lambda *_args, **_kwargs: {
            "status": "unexpected", "report": report, "failureCode": "odd_status",
            "rawEvidence": {STDOUT_NAME: None, STDERR_NAME: None},
        })
        result, commands = {}, []
        with self.assertRaisesRegex(canary.CanaryError, "native_guest_inventory_collection_failed"):
            canary._run_native_workspace_guest_inventory(
                probe, BUNDLE, "/fixed/tart", "offline-canary-fixed", {}, self.harness.evidence,
                canary._run_bounded, result, commands)
        self.assertEqual(result["nativeWorkspaceGuestInventory"]["status"], "unexpected")
        self.assertEqual(result["nativeWorkspaceGuestInventory"]["failureCode"], "odd_status")
        self.assertEqual(result["nativeWorkspaceGuestInventory"]["report"], report)

    def test_bundle_preflight_failure_prevents_clone(self):
        self.harness._write_fake_tart(frames="both")
        self.harness._write_receipt()
        tart_commands = []
        real_runner = canary._run_bounded

        def tracked_runner(argv, **kwargs):
            tart_commands.append(tuple(argv))
            return real_runner(argv, **kwargs)

        def fail_build():
            raise canary.CanaryError("native_guest_inventory_bundle_invalid")

        probe = self._probe(collect=lambda *_args, **_kwargs: self.fail("collector ran"),
                            build_bundle=fail_build)
        with self._install_probe(probe), \
                self.assertRaisesRegex(canary.CanaryError, "native_guest_inventory_bundle_invalid"):
            self._qualify(native_workspace_guest_inventory=True, run_bounded=tracked_runner)

        self.assertFalse(any(len(argv) > 1 and argv[1] == "clone" for argv in tart_commands))
        self.assertEqual([path.name for path in (self.harness.tart_home / "vms").iterdir()],
                         ["prepared-macos15"])

    def test_frame_boundary_failure_never_dispatches_inventory(self):
        self.harness._write_fake_tart(frames="ipv4")
        self.harness._write_receipt()
        calls = []
        probe = self._probe(collect=lambda *_args, **_kwargs: calls.append(True))
        with self._install_probe(probe), \
                self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
            self._qualify(native_workspace_guest_inventory=True)
        self.assertEqual(calls, [])
        self.assertEqual(self._saved()["error"], "guest_external_frames_not_observed")

    def test_cli_forwards_only_boolean_opt_in_and_rejects_custom_command(self):
        receipt, evidence = self.harness.receipt_path, self.harness.evidence
        common = ["--base-vm", "prepared-macos15", "--receipt", str(receipt),
                  "--evidence-dir", str(evidence), "--tart", str(self.harness.tart)]
        calls = []

        def qualify(*args, **kwargs):
            calls.append((args, kwargs))
            return {"status": "passed"}

        for extra in ([], ["--native-workspace-guest-inventory"]):
            stdout = __import__("io").StringIO()
            with patch.object(canary, "qualify", side_effect=qualify), \
                    patch.object(canary, "TART_BINARY_SHA256", "d" * 64), \
                    patch("sys.stdout", stdout):
                self.assertEqual(canary.main([*common, *extra]), 0)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "passed")

        self.assertNotIn("native_workspace_guest_inventory", calls[0][1])
        self.assertIs(calls[1][1]["native_workspace_guest_inventory"], True)
        with patch("sys.stderr", __import__("io").StringIO()), self.assertRaises(SystemExit):
            canary.main([*common, "--native-workspace-guest-inventory-command", "anything"])


if __name__ == "__main__":
    unittest.main()
