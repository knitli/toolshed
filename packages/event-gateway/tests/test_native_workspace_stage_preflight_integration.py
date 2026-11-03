"""Exercise the fixed source preflight inside the existing owned-clone lifecycle."""

import builtins
from contextlib import redirect_stderr, redirect_stdout
import io
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_native_workspace_guest_inventory_integration as inventory_fixture

canary = inventory_fixture.canary
MODULE = "native_workspace_stage_preflight_probe"
LOG_NAMES = ("stage-inputs-receiver.stdout.bin", "stage-inputs-receiver.stderr.bin",
             "stage-inputs-import.stdout.bin", "stage-inputs-import.stderr.bin")


class StagePreflightIntegrationTest(unittest.TestCase):
    setUp = inventory_fixture.NativeWorkspaceGuestInventoryIntegrationTest.setUp
    tearDown = inventory_fixture.NativeWorkspaceGuestInventoryIntegrationTest.tearDown
    _qualify = inventory_fixture.NativeWorkspaceGuestInventoryIntegrationTest._qualify
    _probe = inventory_fixture.NativeWorkspaceGuestInventoryIntegrationTest._probe
    _install_probe = inventory_fixture.NativeWorkspaceGuestInventoryIntegrationTest._install_probe
    _saved = inventory_fixture.NativeWorkspaceGuestInventoryIntegrationTest._saved

    def _preflight(self, *, collect=None, build=None):
        def receive(_tart, _clone, _env, evidence, _bundle, *, run_bounded, cancel_check):
            self.assertTrue(callable(cancel_check))
            self.assertFalse(cancel_check())
            self.assertTrue((evidence / "frame-ipv4.bin").is_file())
            self.assertTrue((evidence / "frame-ipv6.bin").is_file())
            for name in LOG_NAMES:
                (evidence / name).write_bytes(b"")
            (evidence / "native-workspace-stage-inputs.tar.gz").write_bytes(b"fixed archive")
            return {"status": "passed", "qualified": False, "importSmoke": "passed",
                    "hostCommandTemplates": [["fixed", "stdin-receiver"], ["fixed", "import"]]}

        return SimpleNamespace(canary=canary, MAX_REPORT_BYTES=32768, MAX_ARCHIVE_BYTES=4194304,
                               LOG_NAMES=LOG_NAMES, build_bundle=build or (lambda: {"fixed": True}),
                               collect=collect or receive)

    def _inventory_stub(self):
        def collect(_tart, _clone, _env, evidence, _bundle, *, run_bounded):
            (evidence / inventory_fixture.STDOUT_NAME).write_bytes(b"fixed inventory\n")
            (evidence / inventory_fixture.STDERR_NAME).write_bytes(b"")
            return {"status": "passed", "report": {"prepared": False}}

        return self._probe(collect=collect)

    def test_stage_preflight_runs_under_drop_boundary_with_inventory_and_owned_cleanup(self):
        self.harness._write_fake_tart(frames="both")
        self.harness._write_receipt()
        with self._install_probe(self._inventory_stub()), patch.dict(sys.modules, {MODULE: self._preflight()}):
            self._qualify(native_workspace_stage_inputs_preflight=True)
        saved = self._saved()
        self.assertEqual(saved["status"], "passed")
        self.assertEqual(saved["nativeWorkspaceGuestInventory"]["status"], "passed")
        self.assertFalse(saved["nativeWorkspaceStagePreflight"]["qualified"])
        self.assertFalse(saved["nativeWorkspaceStagePreflight"]["prepared"])
        self.assertEqual(saved["frameCounters"]["hostTransmitted"], 0)
        self.assertNotIn("softnetDhcp", saved)
        self.assertNotIn("scpreferencesApi", saved)
        self.assertTrue(all(saved["rawEvidence"][name] for name in LOG_NAMES))
        self.assertTrue(saved["rawEvidence"]["native-workspace-stage-inputs.tar.gz"])
        self.assertIn(["fixed", "stdin-receiver"], saved["hostCommandTemplates"])
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertFalse((self.harness.tart_home / "vms" / saved["cloneVmName"]).exists())

    def test_stage_bundle_failure_happens_before_clone(self):
        self.harness._write_fake_tart(frames="both")
        self.harness._write_receipt()

        def fail():
            raise ValueError("fixture invalid source pin")

        with self._install_probe(self._inventory_stub()), \
                patch.dict(sys.modules, {MODULE: self._preflight(build=fail)}), \
                self.assertRaisesRegex(canary.CanaryError, "native_workspace_stage_preflight_bundle_failed"):
            self._qualify(native_workspace_stage_inputs_preflight=True)
        self.assertEqual([p.name for p in (self.harness.tart_home / "vms").iterdir()], ["prepared-macos15"])
        self.assertFalse(self.harness.evidence.joinpath("offline-macos-vm-canary.json").exists())

    def test_stage_failure_retains_logs_and_normalizes_cleanup_metadata(self):
        self.harness._write_fake_tart(frames="both")
        self.harness._write_receipt()

        def fail(_tart, _clone, _env, evidence, _bundle, **_kwargs):
            (evidence / LOG_NAMES[0]).write_bytes(b"invalid receiver receipt\n")
            error = canary.CanaryError("receiver_receipt_mismatch")
            error.cleanup_errors = ()
            raise error

        with self._install_probe(self._inventory_stub()), \
                patch.dict(sys.modules, {MODULE: self._preflight(collect=fail)}), \
                self.assertRaisesRegex(canary.CanaryError, "receiver_receipt_mismatch"):
            self._qualify(native_workspace_stage_inputs_preflight=True)
        saved = self._saved()
        self.assertEqual(saved["status"], "failed")
        self.assertEqual(saved["nativeWorkspaceStagePreflight"]["failureCode"], "receiver_receipt_mismatch")
        self.assertTrue(saved["rawEvidence"][LOG_NAMES[0]])
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertFalse((self.harness.tart_home / "vms" / saved["cloneVmName"]).exists())

    def test_stage_result_cannot_claim_preparation_or_qualification(self):
        for extra in ({"qualified": True}, {"prepared": True}, {"status": "unexpected"}):
            with self.subTest(extra=extra):
                probe = self._preflight(collect=lambda *_args, **_kw: {
                    "status": "passed", "qualified": False, **extra})
                with self.assertRaisesRegex(canary.CanaryError, "native_workspace_stage_preflight_failed"):
                    canary._run_native_workspace_stage_preflight(
                        probe, {}, "/fixed/tart", "fixed-clone", {}, self.harness.evidence,
                        canary._run_bounded, {}, [], lambda: False)

    def test_default_never_imports_new_preflight(self):
        real_import = builtins.__import__

        def guarded(name, *args, **kwargs):
            if name == MODULE:
                self.fail("default path imported source preflight")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=guarded):
            self.assertEqual(canary._prepare_native_workspace_stage_preflight(False), (None, None))

    def test_cli_only_forwards_boolean_preflight_and_rejects_commands(self):
        common = ["--base-vm", "prepared-macos15", "--receipt", str(self.harness.receipt_path),
                  "--evidence-dir", str(self.harness.evidence)]
        with patch.object(canary, "qualify", return_value={"status": "passed"}) as qualify, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(canary.main([*common, "--native-workspace-stage-inputs-preflight"]), 0)
        self.assertIs(qualify.call_args.kwargs["native_workspace_stage_inputs_preflight"], True)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            canary.main([*common, "--native-workspace-stage-inputs-preflight-command", "anything"])
        with self.assertRaisesRegex(canary.CanaryError, "invalid_native_workspace_stage_inputs_preflight_flag"):
            canary.qualify("prepared-macos15", "unused", "unused", native_workspace_stage_inputs_preflight="yes")


if __name__ == "__main__":
    unittest.main()
