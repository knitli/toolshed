"""Bounded opt-in helpers and full fake-Tart lifecycle tests."""

import builtins
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import test_offline_macos_vm as fixture

canary = fixture.canary

import gateway_public_root_inventory_probe as probe  # noqa: E402

MODULE_NAME = "gateway_public_root_inventory_probe"
STDOUT_NAME = "gateway-public-root-inventory-stdout.json"
STDERR_NAME = "gateway-public-root-inventory-stderr.bin"
HASHES = {"probe": "a" * 64}
BUNDLE = {
    "argument": "fixed-bundle",
    "sourceSha256": HASHES,
    "bundleSha256": "b" * 64,
    "loader": "fixed-loader",
}
REPORT = {"schemaVersion": probe.SCHEMA_VERSION, "publicTrustRootsSha256": "c" * 64}


class GatewayPublicRootInventoryIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tls-inventory-controller-")
        self.evidence = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_default_does_not_import_or_build_bundle(self):
        real_import = builtins.__import__
        imports = []

        def guarded_import(name, *args, **kwargs):
            if name == MODULE_NAME:
                imports.append(name)
                raise AssertionError("default path imported TLS inventory probe")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=guarded_import):
            self.assertEqual(
                canary._prepare_gateway_public_root_inventory(False), (None, None)
            )
        self.assertEqual(imports, [])

    def test_opt_in_runs_one_fixed_bounded_command_and_records_separate_evidence(self):
        with (
            patch.object(probe, "build_bundle", return_value=BUNDLE),
            patch.dict(sys.modules, {MODULE_NAME: probe}),
        ):
            selected, bundle = canary._prepare_gateway_public_root_inventory(True)
        self.assertIs(selected, probe)
        result, commands, calls = {"rawEvidence": {}}, [], []
        output = b'{"status":"passed","sourceSha256":{"probe":"fixture"},"report":{}}\n'

        def runner(argv, *, timeout, env, output_limit, capture_paths):
            calls.append((argv, timeout, env, output_limit, capture_paths))
            for path, content in zip(capture_paths, (output, b"")):
                Path(path).write_bytes(content)
            return output, b""

        with patch.object(probe, "validate_guest_output", return_value=REPORT):
            canary._run_gateway_public_root_inventory(
                selected,
                bundle,
                "/fixed/tart",
                "owned-clone",
                {"PATH": "/usr/bin"},
                self.evidence,
                runner,
                result,
                commands,
            )
        canary._append_gateway_public_root_inventory_evidence(
            selected, result, self.evidence, []
        )

        metadata = result["gatewayPublicRootInventory"]
        self.assertEqual(metadata["status"], "passed")
        self.assertEqual(metadata["report"], REPORT)
        self.assertEqual(metadata["sourceSha256"], HASHES)
        self.assertEqual(metadata["bundleSha256"], BUNDLE["bundleSha256"])
        self.assertEqual(
            metadata["rawReport"],
            {"file": STDOUT_NAME, "maxBytes": probe.MAX_REPORT_BYTES},
        )
        self.assertEqual(len(commands), len(calls))
        self.assertEqual(commands[0][-1], "<fixed-source-bundle-b64>")
        self.assertEqual(calls[0][0][-1], BUNDLE["argument"])
        self.assertEqual(calls[0][1], 30)
        self.assertEqual(calls[0][3], 64 * 1024)
        self.assertEqual(
            calls[0][4], (self.evidence / STDOUT_NAME, self.evidence / STDERR_NAME)
        )
        self.assertNotIn("SSL_CERT_FILE=", " ".join(commands[0]))
        self.assertNotIn("SSL_CERT_DIR=", " ".join(commands[0]))
        self.assertEqual(set(result["rawEvidence"]), {STDOUT_NAME, STDERR_NAME})
        self.assertEqual(metadata["rawEvidence"][STDOUT_NAME]["bytes"], len(output))

    def test_bad_report_preserves_bounded_captures_and_fails_closed(self):
        output = b'{"partial":"invalid"}\n'

        def runner(_argv, *, capture_paths, **_kwargs):
            for path, content in zip(capture_paths, (output, b"")):
                Path(path).write_bytes(content)
            return output, b""

        result, commands = {"rawEvidence": {}}, []
        with self.assertRaisesRegex(
            canary.CanaryError, "gateway_public_root_inventory_collection_failed"
        ):
            canary._run_gateway_public_root_inventory(
                probe,
                BUNDLE,
                "/fixed/tart",
                "owned-clone",
                {},
                self.evidence,
                runner,
                result,
                commands,
            )
        canary._append_gateway_public_root_inventory_evidence(
            probe, result, self.evidence, []
        )
        metadata = result["gatewayPublicRootInventory"]
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["failureCode"], "guest_output_invalid")
        self.assertEqual(result["rawEvidence"][STDOUT_NAME]["bytes"], len(output))

    def test_flag_validation_and_cli_reject_custom_command(self):
        with self.assertRaisesRegex(
            canary.CanaryError, "invalid_gateway_public_root_inventory_flag"
        ):
            canary._validate_gateway_public_root_inventory_flag(1)
        stderr = io.StringIO()
        argv = [
            "--base-vm", "prepared-macos15",
            "--receipt", "/fixture/base-receipt.json",
            "--evidence-dir", "/fixture/evidence",
            "--gateway-public-root-inventory-command", "anything",
        ]
        with patch.object(
            canary, "qualify", return_value={"status": "passed"}
        ) as qualify, patch("sys.stderr", stderr):
            with self.assertRaises(SystemExit) as raised:
                canary.main(argv)
        self.assertEqual(raised.exception.code, 2)
        self.assertIn(
            "unrecognized arguments: --gateway-public-root-inventory-command anything",
            stderr.getvalue(),
        )
        qualify.assert_not_called()


class GatewayPublicRootInventoryQualificationTest(unittest.TestCase):
    """Exercise the opt-in through the full fake-Tart controller lifecycle."""

    def setUp(self):
        self.harness = fixture.OfflineMacosVmCanaryTest()
        self.harness.setUp()

    def tearDown(self):
        self.harness.tearDown()

    def _qualify(self, **options):
        class FixedUuid:
            hex = "c" * 32

        with (
            patch.multiple(
                canary,
                CANARY_TIMEOUT=2,
                VM_READY_TIMEOUT=4,
                VM_READY_PROBE_TIMEOUT=0.2,
                TART_BINARY_SHA256=canary._sha256(self.harness.tart.read_bytes()),
            ),
            patch.object(canary.uuid, "uuid4", return_value=FixedUuid()),
            patch.object(
                canary.shutil, "disk_usage", return_value=SimpleNamespace(free=200 * 1024**3)
            ),
            patch.object(canary.os, "killpg", side_effect=lambda pid, sig: os.kill(pid, sig)),
        ):
            return canary.qualify(
                "prepared-macos15",
                self.harness.receipt_path,
                self.harness.evidence,
                tart=str(self.harness.tart),
                tart_home=self.harness.tart_home,
                **options,
            )

    def _probe(self, report):
        return SimpleNamespace(
            ProbeError=probe.ProbeError,
            MAX_REPORT_BYTES=64 * 1024,
            command_template=lambda tart, clone, loader: [
                str(tart), "exec", clone, "/usr/bin/sudo", "-n", "-u", "admin", "-g",
                "staff", "--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin",
                "/usr/bin/python3", "-I", "-c", loader, "<fixed-source-bundle-b64>",
            ],
            validate_guest_output=lambda stdout, stderr, hashes: report,
        )

    def _saved(self):
        return json.loads(
            (self.harness.evidence / "offline-macos-vm-canary.json").read_text()
        )

    def test_qualify_orders_tls_collection_after_baseline_and_cleans_owned_clone(self):
        self.harness._write_fake_tart(frames="both")
        self.harness._write_receipt()
        before = {
            name: (self.harness.base_vm_dir / name).read_bytes()
            for name in ("config.json", "disk.img", "nvram.bin")
        }
        stdout = b'{"status":"passed","sourceSha256":{"probe":"a"}}\n'
        stderr = b""
        report = {
            "schemaVersion": probe.SCHEMA_VERSION,
            "rootInventoryScope": probe.ROOT_INVENTORY_SCOPE,
            "publicRootCount": 1,
            "publicTrustRootsSha256": "c" * 64,
        }
        tls_probe = self._probe(report)
        bundle = {
            "argument": "fixed-bundle-argument",
            "sourceSha256": {"probe": "a" * 64},
            "bundleSha256": "b" * 64,
            "loader": "fixed-loader",
        }
        tls_probe.build_bundle = lambda: bundle
        invocations = []
        real_runner = canary._run_bounded

        def runner(argv, **kwargs):
            if argv[-1] == bundle["argument"]:
                evidence = self.harness.evidence
                self.assertTrue((evidence / "frame-ipv4.bin").is_file())
                self.assertTrue((evidence / "frame-ipv6.bin").is_file())
                self.assertTrue((self.harness.tart_home / "guest-started").is_file())
                invocations.append(list(argv))
                for path, content in zip(kwargs["capture_paths"], (stdout, stderr)):
                    Path(path).write_bytes(content)
                return stdout, stderr
            return real_runner(argv, **kwargs)

        with patch.dict(sys.modules, {MODULE_NAME: tls_probe}):
            self._qualify(
                gateway_public_root_inventory=True,
                run_bounded=runner,
            )

        saved = self._saved()
        metadata = saved["gatewayPublicRootInventory"]
        self.assertEqual(saved["status"], "passed", saved)
        self.assertEqual(metadata["status"], "passed")
        self.assertEqual(metadata["report"], report)
        self.assertTrue(metadata["collectionOnly"])
        self.assertFalse(metadata["prepared"])
        self.assertFalse(metadata["nativeQualified"])
        self.assertEqual(metadata["sourceSha256"], bundle["sourceSha256"])
        self.assertEqual(metadata["bundleSha256"], bundle["bundleSha256"])
        self.assertEqual(len(invocations), 1)
        self.assertEqual(invocations[0][-1], bundle["argument"])
        self.assertIn("gatewayPublicRootInventory", saved)
        self.assertNotIn("nativeWorkspaceGuestInventory", saved)
        for name, content in (
            (STDOUT_NAME, stdout),
            (STDERR_NAME, stderr),
        ):
            record = saved["rawEvidence"][name]
            self.assertEqual(record["bytes"], len(content))
            self.assertEqual(record["sha256"], canary._sha256(content))
            self.assertEqual(record["maxBytes"], 64 * 1024)
            self.assertEqual(metadata["rawEvidence"][name], record)
            self.assertEqual((self.harness.evidence / name).read_bytes(), content)
        clone = saved["cloneVmName"]
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertFalse((self.harness.tart_home / "vms" / clone).exists())
        self.assertEqual(
            before,
            {
                name: (self.harness.base_vm_dir / name).read_bytes()
                for name in ("config.json", "disk.img", "nvram.bin")
            },
        )

    def test_frame_failure_skips_tls_probe_and_finally_removes_clone(self):
        self.harness._write_fake_tart(frames="ipv4")
        self.harness._write_receipt()
        before = (self.harness.base_vm_dir / "disk.img").read_bytes()
        tls_probe = self._probe({})
        calls = []
        tls_probe.build_bundle = lambda: {"argument": "fixed"}

        def runner(argv, **kwargs):
            if argv[-1] == "fixed":
                calls.append(argv)
            return canary._run_bounded(argv, **kwargs)

        with (
            patch.dict(sys.modules, {MODULE_NAME: tls_probe}),
            self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"),
        ):
            self._qualify(gateway_public_root_inventory=True, run_bounded=runner)

        saved = self._saved()
        self.assertEqual(calls, [])
        self.assertNotIn("gatewayPublicRootInventory", saved)
        self.assertEqual(saved["error"], "guest_external_frames_not_observed")
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertEqual(
            [path.name for path in (self.harness.tart_home / "vms").iterdir()],
            ["prepared-macos15"],
        )
        self.assertEqual((self.harness.base_vm_dir / "disk.img").read_bytes(), before)

    def test_tls_command_cleanup_error_taints_result_but_finally_removes_owned_clone(self):
        self.harness._write_fake_tart(frames="both")
        self.harness._write_receipt()
        before = (self.harness.base_vm_dir / "disk.img").read_bytes()
        tls_probe = self._probe({})
        stdout = b'{"partial":"captured"}\n'
        stderr = b""
        bundle = {"argument": "fixed-bundle-argument", "sourceSha256": {"probe": "a" * 64},
                  "bundleSha256": "b" * 64, "loader": "fixed-loader"}
        tls_probe.build_bundle = lambda: bundle
        real_runner = canary._run_bounded

        def runner(argv, **kwargs):
            if argv[-1] == bundle["argument"]:
                for path, content in zip(kwargs["capture_paths"], (stdout, stderr)):
                    Path(path).write_bytes(content)
                error = canary.CanaryError("tart_command_timeout")
                canary._attach_command_cleanup(error, ("bounded_child_cleanup_failed",))
                raise error
            return real_runner(argv, **kwargs)

        with (
            patch.dict(sys.modules, {MODULE_NAME: tls_probe}),
            self.assertRaisesRegex(
                canary.CanaryError, "gateway_public_root_inventory_collection_failed"
            ),
        ):
            self._qualify(gateway_public_root_inventory=True, run_bounded=runner)

        saved = self._saved()
        self.assertEqual(saved["status"], "tainted")
        self.assertIn("bounded_child_cleanup_failed", saved["cleanupErrors"])
        metadata = saved["gatewayPublicRootInventory"]
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["failureCode"], "tart_command_timeout")
        self.assertEqual(saved["rawEvidence"][STDOUT_NAME]["sha256"], canary._sha256(stdout))
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertEqual(
            [path.name for path in (self.harness.tart_home / "vms").iterdir()],
            ["prepared-macos15"],
        )
        self.assertEqual((self.harness.base_vm_dir / "disk.img").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
