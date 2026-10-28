"""Offline tests for fail-closed Softnet run admission state."""

import hashlib
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import qualify_offline_macos_vm as canary  # noqa: E402 -- Script modules load from their local directory.
import softnet_recovery as recovery  # noqa: E402 -- Script modules load from their local directory.
import softnet_run_state as run_state  # noqa: E402 -- Script modules load from their local directory.


class SoftnetRunStateTests(unittest.TestCase):
    """Check state admission and record validation using private local fixtures."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="softnet-state-test-", dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "state"
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.owner_uid_patch = patch.object(recovery, "OWNER_UID", os.getuid())
        self.euid_patch = patch.object(recovery.os, "geteuid", return_value=os.getuid())
        self.owner_uid_patch.start()
        self.euid_patch.start()
        self.addCleanup(self.euid_patch.stop)
        self.addCleanup(self.owner_uid_patch.stop)
        self.identity = {
            "vmName": "softnet-test-vm",
            "macAddress": "02:00:00:00:00:01",
            "tartBinarySha256": canary.TART_BINARY_SHA256,
            "softnetBinarySha256": "a" * 64,
            "admissionSha256": "b" * 64,
        }

    def _run_with_recovery_records(self, state):
        run, run_id = state.begin(self.identity)
        fd = recovery._directory(run)
        try:
            reserved = recovery._file(fd, "reserved", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            os.close(reserved)
            recovery._publish(fd, "snapshot.plist", plistlib.dumps(
                {"version": 1, "present": False, "before": b"", "target": b"bplist00"},
                fmt=plistlib.FMT_BINARY))
            recovery._publish(fd, "restored", b"restored\n")
            recovery._publish(fd, "launch.plist", plistlib.dumps(
                {"vmName": self.identity["vmName"], "macAddress": self.identity["macAddress"]},
                fmt=plistlib.FMT_BINARY))
            recovery._publish(fd, "stop.plist", plistlib.dumps(
                self._stop_evidence(), fmt=plistlib.FMT_BINARY))
        finally:
            os.close(fd)
        for name in ("helper-logs", "vm-logs"):
            log_dir = run / name
            log_dir.mkdir(mode=0o700)
            log_fd = recovery._directory(log_dir)
            try:
                for filename in run_state.LOG_FILES:
                    handle = recovery._file(log_fd, filename,
                                            os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                    os.close(handle)
            finally:
                os.close(log_fd)
        return run, run_id

    @staticmethod
    def _stop_evidence():
        return {"vmReaped": True, "helperReaped": True, "vmStopped": True}

    def _completed_run(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            state.complete(run, self._stop_evidence())
        return run

    @staticmethod
    def _rewrite(path, data):
        path.write_bytes(data)
        path.chmod(0o600)

    def test_begin_publishes_identity_in_a_retained_uuid_run_and_keeps_lock_file(self):
        with run_state.State(self.root) as state:
            run, run_id = state.begin(self.identity)
            self.assertRegex(run_id, r"\A[0-9a-f]{32}\Z")
            record = plistlib.loads((run / "identity.plist").read_bytes())
            self.assertEqual(record, {
                "kind": run_state.STATE_KIND,
                "version": 1,
                "runId": run_id,
                "identity": self.identity,
            })
            self.assertEqual((run.stat().st_mode & 0o777), 0o700)
        self.assertEqual((self.root / "controller.lock").stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.root / "controller.lock").exists())

    def test_unfinished_run_blocks_next_admission(self):
        with run_state.State(self.root) as state:
            run, _ = state.begin(self.identity)
            self.assertTrue(run.exists())
        with self.assertRaisesRegex(recovery.RecoveryError, "unresolved_run"):
            with run_state.State(self.root):
                self.fail("unfinished run admitted")

    def test_complete_requires_all_stop_proofs(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_stop_evidence"):
                state.complete(run, {"vmReaped": True, "helperReaped": True, "vmStopped": False})

    def test_complete_requires_snapshot_record(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            (run / "snapshot.plist").unlink()
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_entries"):
                state.complete(run, self._stop_evidence())

    def test_complete_requires_stop_record(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            (run / "stop.plist").unlink()
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_entries"):
                state.complete(run, self._stop_evidence())

    def test_completion_is_bound_to_active_run_and_published_immutably(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_active_run"):
                state.complete(run.parent / "other", {
                    "vmReaped": True, "helperReaped": True, "vmStopped": True})
            evidence = self._stop_evidence()
            state.complete(run, evidence)
            complete = plistlib.loads((run / "complete.plist").read_bytes())
            self.assertEqual(complete["stopEvidence"], evidence)
            with self.assertRaisesRegex(recovery.RecoveryError, "state_not_ready"):
                state.complete(run, evidence)
        with run_state.State(self.root):
            pass

    def test_standalone_restored_marker_does_not_complete_a_run(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
        with self.assertRaisesRegex(recovery.RecoveryError, "unresolved_run"):
            with run_state.State(self.root):
                self.fail("standalone restored marker admitted")

    def test_completion_detects_changed_snapshot_and_unknown_root_entries(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            state.complete(run, self._stop_evidence())
        (run / "snapshot.plist").write_bytes(b"changed")
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_completion"):
            with run_state.State(self.root):
                self.fail("changed snapshot accepted")

        (run / "snapshot.plist").write_bytes(b"changed")
        (self.root / "surprise").write_text("x")
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_state_entries"):
            with run_state.State(self.root):
                self.fail("unknown state entry accepted")

    def test_corrupt_identity_blocks_admission(self):
        run = self._completed_run()
        identity_path = run / "identity.plist"
        identity = plistlib.loads(identity_path.read_bytes())
        identity["identity"]["tartBinarySha256"] = "c" * 64
        identity_bytes = plistlib.dumps(identity, fmt=plistlib.FMT_BINARY, sort_keys=True)
        self._rewrite(identity_path, identity_bytes)
        complete_path = run / "complete.plist"
        complete = plistlib.loads(complete_path.read_bytes())
        complete["identitySha256"] = hashlib.sha256(identity_bytes).hexdigest()
        self._rewrite(complete_path, plistlib.dumps(complete, fmt=plistlib.FMT_BINARY, sort_keys=True))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            with run_state.State(self.root):
                self.fail("corrupt identity accepted")

    def test_corrupt_complete_record_blocks_admission(self):
        run = self._completed_run()
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        complete["version"] = 2
        self._rewrite(run / "complete.plist", plistlib.dumps(complete, fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_completion"):
            with run_state.State(self.root):
                self.fail("corrupt completion accepted")

    def test_malformed_stop_record_blocks_admission(self):
        run = self._completed_run()
        stop_bytes = b"not a plist"
        self._rewrite(run / "stop.plist", stop_bytes)
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        complete["stopSha256"] = hashlib.sha256(stop_bytes).hexdigest()
        self._rewrite(run / "complete.plist", plistlib.dumps(complete, fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_stop"):
            with run_state.State(self.root):
                self.fail("malformed stop evidence accepted")

    def test_stop_record_must_match_completion(self):
        run = self._completed_run()
        self._rewrite(run / "stop.plist", plistlib.dumps(
            self._stop_evidence(), fmt=plistlib.FMT_XML))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_completion"):
            with run_state.State(self.root):
                self.fail("changed stop evidence accepted")

    def test_run_logs_reject_symlinks(self):
        run = self._completed_run()
        log = run / "helper-logs" / "tart-stdout.bin"
        log.unlink()
        target = self.root.parent / "log-target"
        target.write_bytes(b"safe")
        log.symlink_to(target)
        with self.assertRaises(OSError):
            with run_state.State(self.root):
                self.fail("symlinked log accepted")

    def test_run_logs_reject_oversized_files(self):
        run = self._completed_run()
        log = run / "vm-logs" / "tart-stderr.bin"
        log.write_bytes(b"x" * (run_state.MAX_LOG_BYTES + 1))
        log.chmod(0o600)
        with self.assertRaisesRegex(recovery.RecoveryError, "oversized_run_log"):
            with run_state.State(self.root):
                self.fail("oversized log accepted")

    def test_reservation_only_run_without_identity_fails_closed(self):
        with run_state.State(self.root) as state:
            run, _ = state.begin(self.identity)
            (run / "identity.plist").unlink()
            fd = recovery._directory(run)
            reserved = recovery._file(fd, "reserved", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            os.close(reserved)
            os.close(fd)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_entries"):
            with run_state.State(self.root):
                self.fail("reservation without identity accepted")

    def test_reentering_state_rejects_before_opening_more_descriptors(self):
        state = run_state.State(self.root)
        state.__enter__()
        root_fd, lock_fd = state._root_fd, state._lock_fd
        try:
            with patch.object(recovery, "_directory", wraps=recovery._directory) as directory:
                with self.assertRaisesRegex(recovery.RecoveryError, "state_already_entered"):
                    state.__enter__()
                directory.assert_not_called()
            self.assertEqual((state._root_fd, state._lock_fd), (root_fd, lock_fd))
            os.fstat(root_fd)
            os.fstat(lock_fd)
        finally:
            state.__exit__(None, None, None)

    def test_controller_lock_is_nonblocking_and_never_unlinked(self):
        state = run_state.State(self.root)
        state.__enter__()
        try:
            with self.assertRaisesRegex(recovery.RecoveryError, "controller_busy"):
                with run_state.State(self.root):
                    self.fail("concurrent state lock acquired")
        finally:
            state.__exit__(None, None, None)
        self.assertTrue((self.root / "controller.lock").is_file())
        self.assertEqual(os.stat(self.root / "controller.lock").st_nlink, 1)


if __name__ == "__main__":
    unittest.main()
