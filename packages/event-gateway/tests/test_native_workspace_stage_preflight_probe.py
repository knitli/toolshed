"""Host-side contract tests for the fixed, offline stage-input preflight."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess  # nosec B404 -- fixed local interpreters and receiver source only.
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import native_workspace_stage_inputs as staging  # noqa: E402
import native_workspace_stage_preflight_probe as probe  # noqa: E402
import qualify_offline_macos_vm as canary  # noqa: E402


def _digest(data):
    return hashlib.sha256(data).hexdigest()


class FakeBoundedRunner:
    """Capture the fixed host contract and return explicit receipt fixtures."""

    def __init__(self, bundle, *, receipt_change=None, import_error=None,
                 import_stdout=None, import_stderr=b""):
        """Configure fixed test receipts and explicit failure fixtures."""
        self.bundle = bundle
        self.receipt_change = receipt_change
        self.import_error = import_error
        self.import_stdout = import_stdout
        self.import_stderr = import_stderr
        self.calls = []
        self.input_bytes = None
        self.input_fd = None
        self.last_import_stdout = None
        self.last_import_stderr = None

    def __call__(self, argv, *, timeout, env, output_limit, input_fd=None,
                 capture_paths=None, cancel_check=None):
        self.calls.append((list(argv), timeout, dict(env), output_limit, capture_paths, cancel_check))
        self.assertions(argv, timeout, output_limit, capture_paths)
        if input_fd is not None:
            self.input_fd = input_fd
            assert os.O_ACCMODE & fcntl.fcntl(input_fd, fcntl.F_GETFL) == os.O_RDONLY
            self.input_bytes = os.read(input_fd, self.bundle["manifest"]["archiveBytes"] + 1)
            stdout = self._receipt()
            stderr = b""
        else:
            if self.import_error is not None:
                raise self.import_error
            self.assert_import(argv)
            stdout = self._import_receipt() if self.import_stdout is None else self.import_stdout
            stderr = self.import_stderr
            self.last_import_stdout, self.last_import_stderr = stdout, stderr
        for path, data in zip(capture_paths, (stdout, stderr)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        return stdout, stderr

    def assertions(self, argv, timeout, output_limit, capture_paths):
        assert timeout == probe.COMMAND_TIMEOUT <= 45
        assert output_limit == probe.MAX_OUTPUT_BYTES == 32 * 1024
        assert len(capture_paths) == 2
        assert all(not Path(path).exists() for path in capture_paths)
        assert "/usr/bin/env" in argv
        assert "-i" in argv

    def assert_import(self, argv):
        assert argv[-6:-3] == ["/opt/homebrew/bin/python3", "-I", "-B"]
        assert argv[-3] == "-c"
        assert argv[-2] == probe.IMPORT_CODE

    def _receipt(self):
        manifest = self.bundle["manifest"]
        receipt = {"status": "inputs-received", "qualified": False,
                   "archiveSha256": manifest["archiveSha256"],
                   "manifestSha256": manifest["manifestSha256"],
                   "memberCount": manifest["memberCount"], "totalBytes": manifest["totalBytes"],
                   "members": manifest["members"],
                   "root": "/private/tmp/native-workspace-inputs-fixture"}
        if self.receipt_change is not None:
            self.receipt_change(receipt)
        return (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()

    def _import_receipt(self):
        receipt = {"kind": probe.IMPORT_KIND, "status": "passed", "qualified": False,
                   "pythonVersion": "3.14.1",
                   "pythonExecutable": "/opt/homebrew/Cellar/python@3.14/3.14.1/bin/python3.14"}
        return (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()


class NativeWorkspaceStagePreflightTests(unittest.TestCase):
    """Exercise the real receiver and the host's bounded-command contract."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = Path(self.temp.name)
        self.bundle = staging.build_bundle()

    def test_receiver_fixture_executes_locally_and_receipt_is_exact_and_unqualified(self):
        """Receive the fixture bundle, import its stager, and prove missing input fails."""
        result = subprocess.run([sys.executable, "-I", "-B", "-c", self.bundle["receiver"]],  # nosec B603 -- fixed receiver; fixture archive on stdin.
                                input=self.bundle["archive"], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False,
                                env={**os.environ, "TMPDIR": str(self.evidence)})
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(set(receipt), {"root", "status", "qualified", "archiveSha256",
                                        "manifestSha256", "memberCount", "totalBytes", "members"})
        self.assertEqual(receipt["status"], "inputs-received")
        self.assertIs(receipt["qualified"], False)
        self.assertEqual(receipt["archiveSha256"], _digest(self.bundle["archive"]))
        self.assertEqual(receipt["manifestSha256"], self.bundle["manifest"]["manifestSha256"])
        root = Path(receipt["root"])
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        self.assertEqual(json.loads((root / staging.RECEIPT_NAME).read_text()),
                         {key: receipt[key] for key in receipt if key != "root"})
        imported = subprocess.run(  # nosec B603 -- fixed import source and test-owned extracted root.
                                   [sys.executable, "-I", "-B", "-c", probe.IMPORT_CODE, str(root)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        import_receipt = json.loads(imported.stdout)
        self.assertEqual(set(import_receipt), {"kind", "status", "qualified", "pythonVersion",
                                               "pythonExecutable"})
        self.assertEqual(import_receipt["kind"], probe.IMPORT_KIND)
        self.assertEqual(import_receipt["status"], "passed")
        self.assertIs(import_receipt["qualified"], False)
        self.assertGreaterEqual(tuple(map(int, import_receipt["pythonVersion"].split("."))),
                                (3, 13, 0))
        self.assertEqual(import_receipt["pythonExecutable"], os.path.realpath(sys.executable))
        dependency = root / "packages/event-gateway/scripts/native_workspace_qualification.py"
        dependency.unlink()
        broken = subprocess.run(  # nosec B603 -- same fixed import after removing a fixture dependency.
                                [sys.executable, "-I", "-B", "-c", probe.IMPORT_CODE, str(root)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False)
        self.assertNotEqual(broken.returncode, 0)
        self.assertIn(b"native_workspace_qualification", broken.stderr)

    def test_host_contract_passes_verified_archive_fd_and_fixed_import_only(self):
        """Require exact archive bytes, read-only FD, and fixed import argv and evidence."""
        runner = FakeBoundedRunner(self.bundle)
        report = probe.collect("/fixed/tart", "owned-vm", {"HOST_ONLY": "ignored"},
                               self.evidence, self.bundle, runner, cancel_check=lambda: False)
        self.assertEqual(report["kind"], probe.KIND)
        self.assertEqual(report["status"], "passed")
        self.assertIs(report["qualified"], False)
        self.assertEqual(report["archiveSha256"], self.bundle["manifest"]["archiveSha256"])
        self.assertEqual(report["sourceSha256"], {
            item["path"]: item["sha256"] for item in self.bundle["manifest"]["members"]
        })
        self.assertEqual(runner.input_bytes, self.bundle["archive"])
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(runner.calls[0][0][:4], ["/fixed/tart", "exec", "-i", "owned-vm"])
        self.assertEqual(runner.calls[1][0][-6:], ["/opt/homebrew/bin/python3", "-I", "-B", "-c",
                                                   probe.IMPORT_CODE,
                                                   "/private/tmp/native-workspace-inputs-fixture"])
        self.assertEqual(len(report["hostCommandTemplates"]), 2)
        self.assertEqual(report["importSmoke"]["kind"], probe.IMPORT_KIND)
        self.assertEqual(report["importSmoke"]["pythonVersion"], "3.14.1")
        self.assertIs(report["importSmoke"]["qualified"], False)
        self.assertEqual(report["importSmoke"]["stdoutSha256"], _digest(runner.last_import_stdout))
        self.assertEqual(report["importSmoke"]["stderrSha256"], _digest(b""))
        archive_path = self.evidence / "native-workspace-stage-inputs.tar.gz"
        self.assertEqual(stat.S_IMODE(archive_path.stat().st_mode), 0o600)
        self.assertEqual(archive_path.read_bytes(), self.bundle["archive"])
        with self.assertRaises(OSError):
            os.fstat(runner.input_fd)
        self.assertTrue(all(path.exists() for path in runner.calls[0][4] + runner.calls[1][4]))

    def test_wrong_receipt_digest_and_guest_root_fail_before_import(self):
        """Reject altered receiver state, archive digest, and noncanonical guest root."""
        variants = (
            (lambda receipt: receipt.update(status="not-received"), "receiver_receipt_mismatch"),
            (lambda receipt: receipt.update(archiveSha256="0" * 64), "receiver_receipt_mismatch"),
            (lambda receipt: receipt.update(root="/private/tmp/elsewhere"), "invalid_guest_root"),
        )
        for change, message in variants:
            with self.subTest(message=message):
                runner = FakeBoundedRunner(self.bundle, receipt_change=change)
                with self.assertRaisesRegex(canary.CanaryError, message):
                    probe.collect("/fixed/tart", "owned-vm", {}, self.evidence,
                                  self.bundle, runner)
                self.assertEqual(len(runner.calls), 1)
                self.assertIsNotNone(runner.input_fd)
                with self.assertRaises(OSError):
                    os.fstat(runner.input_fd)
                for path in self.evidence.glob("stage-inputs-*.stdout.bin"):
                    path.unlink()
                for path in self.evidence.glob("stage-inputs-*.stderr.bin"):
                    path.unlink()
                (self.evidence / "native-workspace-stage-inputs.tar.gz").unlink()

    def test_archive_digest_is_checked_before_any_command_and_archive_removed(self):
        """Reject archive corruption before the bounded runner can execute."""
        altered = dict(self.bundle, archive=self.bundle["archive"] + b"x")
        runner = FakeBoundedRunner(self.bundle)
        with self.assertRaisesRegex(probe.PreflightError, "bundle_archive_digest_mismatch"):
            probe.collect("/fixed/tart", "owned-vm", {}, self.evidence, altered, runner)
        self.assertEqual(runner.calls, [])
        self.assertFalse((self.evidence / "native-workspace-stage-inputs.tar.gz").exists())

    def test_import_failure_and_timeout_propagate_and_close_archive_fd(self):
        """Propagate bounded-runner failures and release the archive descriptor."""
        runner = FakeBoundedRunner(self.bundle, import_error=canary.CanaryError("tart_command_failed"))
        with self.assertRaisesRegex(canary.CanaryError, "tart_command_failed"):
            probe.collect("/fixed/tart", "owned-vm", {}, self.evidence, self.bundle, runner)
        self.assertEqual(len(runner.calls), 2)
        with self.assertRaises(OSError):
            os.fstat(runner.input_fd)

        for path in self.evidence.iterdir():
            path.unlink()
        timeout_fds = []

        def timeout(*_args, input_fd=None, **_kwargs):
            timeout_fds.append(input_fd)
            raise canary.CanaryError("tart_command_timeout")

        with self.assertRaisesRegex(canary.CanaryError, "tart_command_timeout"):
            probe.collect("/fixed/tart", "owned-vm", {}, self.evidence,
                          self.bundle, timeout)
        self.assertEqual(len(timeout_fds), 1)
        with self.assertRaises(OSError):
            os.fstat(timeout_fds[0])

    def test_import_receipt_rejects_old_version_malformed_stdout_and_stderr(self):
        """Require the exact passing Python runtime receipt and clean stderr."""
        old_version = json.dumps({"kind": probe.IMPORT_KIND, "status": "passed",
                                  "qualified": False, "pythonVersion": "3.12.9",
                                  "pythonExecutable": "/opt/homebrew/Cellar/python@3.12/3.12.9/bin/python3.12"}).encode()
        bad_executable = json.dumps({"kind": probe.IMPORT_KIND, "status": "passed",
                                     "qualified": False, "pythonVersion": "3.13.0",
                                     "pythonExecutable": "/usr/bin/python3"}).encode()
        cases = ((old_version, b"", "import_python_version_unqualified"),
                 (bad_executable, b"", "import_python_executable_unqualified"),
                 (b"not json", b"", "invalid_import_receipt"),
                 (None, b"unexpected stderr", "import_smoke_stderr_unexpected"))
        for stdout, stderr, message in cases:
            with self.subTest(message=message):
                runner = FakeBoundedRunner(self.bundle, import_stdout=stdout,
                                           import_stderr=stderr)
                with self.assertRaisesRegex(canary.CanaryError, message):
                    probe.collect("/fixed/tart", "owned-vm", {}, self.evidence,
                                  self.bundle, runner)
                self.assertEqual(len(runner.calls), 2)
                with self.assertRaises(OSError):
                    os.fstat(runner.input_fd)
                for path in self.evidence.iterdir():
                    path.unlink()


if __name__ == "__main__":
    unittest.main()
