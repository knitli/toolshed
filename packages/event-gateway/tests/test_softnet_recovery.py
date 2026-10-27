"""Offline tests for the narrowly scoped Softnet bootpd rollback journal."""

import fcntl
import os
from pathlib import Path
import plistlib
import stat
import subprocess  # nosec B404 -- Fixed interpreter and private fake-preference crash probe.
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import softnet_recovery as recovery  # noqa: E402 -- Script modules are loaded from their local directory.
import qualify_offline_macos_vm as canary  # noqa: E402 -- Script modules are loaded from their local directory.


class Preferences:
    """In-memory stand-in for the locked SystemConfiguration preference pair."""

    def __init__(self):
        """Start with absent bootpd preferences and no injected failures."""
        self.current = None
        self.staged = None
        self.commit_error = None
        self.apply_error = None
        self.sync_error = None
        self.read_error = None
        self.read_error_at = None
        self.on_synchronize = None
        self.reads = 0
        self.commits = 0
        self.applies = 0
        self.syncs = 0

    def __enter__(self):
        """Model a fresh locked read session."""
        self.staged = self.current
        return self

    def __exit__(self, *_):
        """Release the fake lock without suppressing errors."""
        return False

    def read(self):
        self.reads += 1
        if self.read_error and (self.read_error_at is None or self.reads == self.read_error_at):
            raise self.read_error
        return self.current

    def write(self, value):
        self.staged = value

    def commit_apply(self):
        self.commits += 1
        if self.commit_error:
            raise self.commit_error
        self.current = self.staged
        self.applies += 1
        if self.apply_error:
            raise self.apply_error

    def synchronize(self):
        self.syncs += 1
        if self.sync_error:
            raise self.sync_error
        if self.on_synchronize:
            self.on_synchronize()

    @staticmethod
    def equal(left, right):
        if left is None or right is None:
            return left is None and right is None
        return plistlib.loads(left) == plistlib.loads(right)

    @staticmethod
    def encode_target():
        return plistlib.dumps(
            {"DHCPLeaseTimeSecs": 600, "dhcp_ignore_client_identifier": True},
            fmt=plistlib.FMT_BINARY,
            sort_keys=True,
        )

    @staticmethod
    def validate(blob):
        if blob is not None:
            plistlib.loads(blob)
        return blob


class SoftnetRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="softnet-recovery-test-", dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve() / "journal"
        self.directory.mkdir(mode=0o700)
        self.directory.chmod(0o700)
        self.preferences = Preferences()
        self.factory = lambda: self.preferences
        self._owner_checks()

    def _owner_checks(self):
        # Treat this user-owned fixture like the root-owned production journal.
        self.owner_uid_patch = patch.object(recovery, "OWNER_UID", os.getuid(), create=True)
        self.euid_patch = patch.object(recovery.os, "geteuid", return_value=os.getuid())
        self.owner_uid_patch.start()
        self.euid_patch.start()
        self.addCleanup(self.euid_patch.stop)
        self.addCleanup(self.owner_uid_patch.stop)

    def _journal(self):
        return self.directory / "snapshot.plist"

    def _read_journal(self):
        return plistlib.loads(self._journal().read_bytes())

    def _write_journal(self, value):
        self._journal().write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY))
        self._journal().chmod(0o600)

    def _capture(self):
        recovery.capture(self.directory, preferences_factory=self.factory)

    def _reserve(self):
        fd = os.open(self.directory / "reserved", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)

    def test_capture_records_absent_prior_value_and_exact_target_without_mutating_preferences(self):
        self._capture()
        record = self._read_journal()
        self.assertEqual(record["version"], 1)
        self.assertFalse(record["present"])
        self.assertEqual(record["before"], b"")
        self.assertEqual(record["target"], Preferences.encode_target())
        self.assertIsNone(self.preferences.current)
        self.assertEqual(self.preferences.commits, 0)

    def test_capture_preserves_complete_existing_dictionary_value(self):
        before = plistlib.dumps(
            {"enabled": True, "custom": [1, "keep"], "nested": {"retain": "all"}},
            fmt=plistlib.FMT_BINARY,
            sort_keys=True,
        )
        self.preferences.current = before
        self._capture()
        self.assertTrue(self._read_journal()["present"])
        self.assertEqual(self._read_journal()["before"], before)
        self.assertEqual(self._read_journal()["target"], Preferences.encode_target())
        self.assertEqual(self.preferences.current, before)

    def test_capture_reservation_is_exclusive_and_persists_after_success(self):
        self._capture()
        self.assertTrue((self.directory / "reserved").exists())
        reads = self.preferences.reads
        with self.assertRaises(FileExistsError):
            recovery.capture(self.directory, preferences_factory=self.factory)
        self.assertEqual(self.preferences.reads, reads)

    def test_process_must_be_root_before_opening_journal(self):
        with patch.object(recovery.os, "geteuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(recovery.RecoveryError, "root_required"):
                self._capture()
        self.assertFalse((self.directory / "reserved").exists())

    def test_capture_failure_does_not_change_preferences_or_publish_snapshot(self):
        self.preferences.read_error = OSError("injected")
        with self.assertRaisesRegex(OSError, "injected"):
            self._capture()
        self.assertIsNone(self.preferences.current)
        self.assertFalse(self._journal().exists())
        self.assertTrue((self.directory / "reserved").exists())

    def test_restore_applies_exact_previous_value_and_publishes_marker(self):
        before = plistlib.dumps({"opaque": ["all", 7]}, fmt=plistlib.FMT_BINARY)
        self.preferences.current = before
        self._capture()
        self.preferences.current = Preferences.encode_target()
        recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual(self.preferences.current, before)
        self.assertEqual(self.preferences.staged, before)
        self.assertEqual(self.preferences.commits, 1)
        self.assertEqual(self.preferences.syncs, 1)
        self.assertTrue((self.directory / "restored").exists())

    def test_restore_of_absent_prior_bootpd_value_restores_absence(self):
        self._capture()
        self.preferences.current = Preferences.encode_target()
        recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertIsNone(self.preferences.current)

    def test_restore_is_idempotent_and_recommits_when_already_at_before(self):
        before = plistlib.dumps({"keep": "byte-for-byte"}, fmt=plistlib.FMT_BINARY)
        self.preferences.current = before
        self._capture()
        self.preferences.current = Preferences.encode_target()
        recovery.restore(self.directory, preferences_factory=self.factory)
        recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual(self.preferences.current, before)
        self.assertEqual(self.preferences.commits, 2)
        self.assertEqual(self.preferences.syncs, 2)

    def test_completed_journal_refuses_later_target_value(self):
        self._capture()
        self.preferences.current = Preferences.encode_target()
        recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual((self.directory / "restored").read_bytes(), b"restored\n")
        self.preferences.current = Preferences.encode_target()
        with self.assertRaisesRegex(recovery.RecoveryError, "completed_preference_changed"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual(self.preferences.commits, 1)

    def test_process_death_after_marker_rename_leaves_recoverable_single_link_journal(self):
        self._capture()
        script = """import os, sys, plistlib
sys.path.insert(0, sys.argv[2])
import softnet_recovery as recovery
recovery.OWNER_UID = os.getuid()
class Preferences:
    def __init__(self):
        self.current = plistlib.dumps({'DHCPLeaseTimeSecs': 600, 'dhcp_ignore_client_identifier': True}, fmt=plistlib.FMT_BINARY)
        self.staged = self.current
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def read(self): return self.current
    def write(self, value): self.staged = value
    def commit_apply(self): self.current = self.staged
    def synchronize(self): pass
    def equal(self, left, right):
        return (left is None and right is None) or (left is not None and right is not None and plistlib.loads(left) == plistlib.loads(right))
    def encode_target(self):
        return plistlib.dumps({'DHCPLeaseTimeSecs': 600, 'dhcp_ignore_client_identifier': True}, fmt=plistlib.FMT_BINARY)
    def validate(self, blob): plistlib.loads(blob)
real_rename = recovery._rename_new
def exit_after_marker(fd, source, destination):
    real_rename(fd, source, destination)
    if destination == 'restored': os._exit(42)
recovery._rename_new = exit_after_marker
recovery.restore(sys.argv[1], preferences_factory=Preferences)
"""
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        child = subprocess.run(
            [sys.executable, "-c", script, str(self.directory), str(Path(recovery.__file__).resolve().parent)],
            capture_output=True, text=True, timeout=10, env=environment,
        )  # nosec B603 -- fixed Python snippet uses only this private fake-preference fixture.
        self.assertEqual(child.returncode, 42, child.stderr)

        marker = self.directory / "restored"
        marker_info = marker.stat()
        self.assertEqual(marker_info.st_nlink, 1)
        self.assertEqual(marker.read_bytes(), b"restored\n")
        recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual(marker.read_bytes(), b"restored\n")

    def test_restore_refuses_preference_drift_without_writing(self):
        self._capture()
        changed = plistlib.dumps({"thirdParty": True}, fmt=plistlib.FMT_BINARY)
        self.preferences.current = changed
        with self.assertRaisesRegex(recovery.RecoveryError, "preference_drift"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual(self.preferences.current, changed)
        self.assertEqual(self.preferences.commits, 0)
        self.assertFalse((self.directory / "restored").exists())

    def test_failed_commit_or_apply_does_not_publish_restored_marker(self):
        self._capture()
        self.preferences.current = Preferences.encode_target()
        self.preferences.commit_error = OSError("commit")
        with self.assertRaisesRegex(OSError, "commit"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertFalse((self.directory / "restored").exists())

        self.preferences.commit_error = None
        self.preferences.apply_error = OSError("apply")
        with self.assertRaisesRegex(OSError, "apply"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertFalse((self.directory / "restored").exists())
        self.preferences.apply_error = None
        recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual(self.preferences.commits, 3)
        self.assertEqual(self.preferences.current, None)
        self.assertEqual((self.directory / "restored").read_bytes(), b"restored\n")

    def test_failed_synchronization_does_not_publish_restored_marker(self):
        self._capture()
        self.preferences.current = Preferences.encode_target()
        self.preferences.sync_error = OSError("sync")
        with self.assertRaisesRegex(OSError, "sync"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertFalse((self.directory / "restored").exists())

    def test_failed_readback_does_not_publish_restored_marker(self):
        self._capture()
        self.preferences.current = Preferences.encode_target()
        self.preferences.read_error = OSError("readback")
        self.preferences.read_error_at = self.preferences.reads + 2
        with self.assertRaisesRegex(OSError, "readback"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertFalse((self.directory / "restored").exists())

    def test_invalid_completion_marker_blocks_preference_access(self):
        self._capture()
        marker = self.directory / "restored"
        marker.write_bytes(b"wrong\n")
        marker.chmod(0o600)
        reads = self.preferences.reads
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_completion"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual(self.preferences.reads, reads)
        self.assertEqual(self.preferences.commits, 0)

    def test_completion_marker_collision_never_replaces_existing_marker(self):
        self._capture()
        marker = self.directory / "restored"

        def race_marker():
            marker.write_bytes(b"operator evidence\n")
            marker.chmod(0o600)

        self.preferences.on_synchronize = race_marker
        self.preferences.current = Preferences.encode_target()
        with self.assertRaises(FileExistsError):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual(marker.read_bytes(), b"operator evidence\n")

    def test_existing_snapshot_is_not_replaced_when_reservation_is_absent(self):
        snapshot = self._journal()
        original = plistlib.dumps(
            {"version": 1, "present": False, "before": b"", "target": Preferences.encode_target()},
            fmt=plistlib.FMT_BINARY,
        )
        snapshot.write_bytes(original)
        snapshot.chmod(0o600)

        with self.assertRaises(FileExistsError):
            self._capture()

        self.assertEqual(snapshot.read_bytes(), original)
        self.assertTrue((self.directory / "reserved").exists())

    def test_interruption_after_snapshot_rename_leaves_readable_single_link_journal(self):
        actual_rename = recovery._rename_new

        class Interrupted(BaseException):
            """Model process death after the atomic publication syscall."""

        def rename_then_interrupt(fd, source, destination):
            actual_rename(fd, source, destination)
            if destination == "snapshot.plist":
                raise Interrupted("after_snapshot_publish")

        with patch.object(recovery, "_rename_new", side_effect=rename_then_interrupt):
            with self.assertRaisesRegex(Interrupted, "after_snapshot_publish"):
                self._capture()

        snapshot_info = self._journal().stat()
        self.assertEqual(snapshot_info.st_nlink, 1)
        self.assertEqual(self._read_journal()["version"], 1)
        recovery.restore(self.directory, preferences_factory=self.factory)
        self.assertEqual((self.directory / "restored").read_bytes(), b"restored\n")

    def test_restore_requires_snapshot_and_rejects_corrupt_or_oversized_snapshot(self):
        self._reserve()
        with self.assertRaises(FileNotFoundError):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self._journal().write_bytes(b"not a plist")
        self._journal().chmod(0o600)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_snapshot"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        self._journal().write_bytes(b"x" * (recovery.MAX_RECORD + 1))
        with self.assertRaisesRegex(recovery.RecoveryError, "unsafe_record"):
            recovery.restore(self.directory, preferences_factory=self.factory)

    def test_restore_rejects_wrong_snapshot_schema_and_unrecognized_target(self):
        self._reserve()
        wrong_shape = {"version": 1, "present": False, "before": b"", "target": b"bplist00bad",
                       "extra": True}
        self._write_journal(wrong_shape)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_snapshot"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        wrong_target = {"version": 1, "present": False, "before": b"",
                        "target": plistlib.dumps({"other": True}, fmt=plistlib.FMT_BINARY)}
        self._write_journal(wrong_target)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_target"):
            recovery.restore(self.directory, preferences_factory=self.factory)
        inconsistent_absence = {"version": 1, "present": False, "before": b"unexpected",
                                "target": Preferences.encode_target()}
        self._write_journal(inconsistent_absence)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_snapshot"):
            recovery.restore(self.directory, preferences_factory=self.factory)

    def test_capture_lock_exclusion_refuses_existing_reservation(self):
        self._capture()
        reservation = self.directory / "reserved"
        fd = os.open(reservation, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                recovery.restore(self.directory, preferences_factory=self.factory)
        finally:
            os.close(fd)

    def test_failed_snapshot_publication_never_returns_success_or_reuses_directory(self):
        fsync = recovery.os.fsync
        calls = 0

        def fail_directory_publication(fd):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError("injected directory fsync failure")
            return fsync(fd)

        with patch.object(recovery.os, "fsync", side_effect=fail_directory_publication):
            with self.assertRaisesRegex(OSError, "injected"):
                self._capture()
        self.assertTrue((self.directory / "reserved").exists())
        with self.assertRaises(FileExistsError):
            recovery.capture(self.directory, preferences_factory=self.factory)
        self.directory.joinpath("snapshot.plist").write_bytes(b"not a plist")
        self._journal().chmod(0o600)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_snapshot"):
            recovery.restore(self.directory, preferences_factory=self.factory)

    def test_restore_rejects_symlink_journal(self):
        outside = Path(self.temp.name).resolve() / "outside"
        self._capture()
        outside.write_bytes(self._journal().read_bytes())
        outside.chmod(0o600)
        self._journal().unlink()
        self._journal().symlink_to(outside)
        with self.assertRaises(OSError):
            recovery.restore(self.directory, preferences_factory=self.factory)

    def test_restore_rejects_hardlinked_journal(self):
        self._capture()
        os.link(self._journal(), self.directory / "second-link")
        with self.assertRaisesRegex(recovery.RecoveryError, "unsafe_record"):
            recovery.restore(self.directory, preferences_factory=self.factory)

    def test_restore_rejects_non_private_journal_mode(self):
        self._capture()
        journal = self._journal()
        journal.chmod(0o644)
        with self.assertRaisesRegex(recovery.RecoveryError, "unsafe_record"):
            recovery.restore(self.directory, preferences_factory=self.factory)

    def test_restore_rejects_journal_owned_by_another_uid(self):
        self._capture()
        real_fstat = recovery.os.fstat

        class ForeignOwner:
            def __init__(self, info):
                self._info = info
                self.st_uid = info.st_uid + 1

            def __getattr__(self, name):
                return getattr(self._info, name)

        def foreign_file_owner(fd):
            info = real_fstat(fd)
            return ForeignOwner(info) if stat.S_ISREG(info.st_mode) else info

        with patch.object(recovery.os, "fstat", side_effect=foreign_file_owner):
            with self.assertRaisesRegex(recovery.RecoveryError, "unsafe_record"):
                recovery.restore(self.directory, preferences_factory=self.factory)

    def test_capture_rejects_symlinked_directory(self):
        link = Path(self.temp.name) / "link"
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(OSError):
            recovery.capture(link, preferences_factory=self.factory)

    def test_capture_rejects_non_private_directory(self):
        unsafe = Path(self.temp.name) / "unsafe"
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o755)
        with self.assertRaisesRegex(recovery.RecoveryError, "unsafe_directory"):
            recovery.capture(unsafe, preferences_factory=self.factory)

    def test_directory_acl_failure_is_rejected_before_preference_access(self):
        real_acl_check = canary._check_tart_acl

        def reject_directory_acl(path, *, fd=None):
            if fd is not None and stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("injected directory ACL failure")
            return real_acl_check(path, fd=fd)

        with patch.object(canary, "_check_tart_acl", side_effect=reject_directory_acl):
            with self.assertRaisesRegex(OSError, "injected directory ACL"):
                self._capture()
        self.assertEqual(self.preferences.reads, 0)
        self.assertEqual(self.preferences.commits, 0)

    def test_file_acl_failure_is_rejected_before_preference_access(self):
        real_acl_check = canary._check_tart_acl

        def reject_file_acl(path, *, fd=None):
            if fd is not None and stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("injected file ACL failure")
            return real_acl_check(path, fd=fd)

        with patch.object(canary, "_check_tart_acl", side_effect=reject_file_acl):
            with self.assertRaisesRegex(OSError, "injected file ACL"):
                self._capture()
        self.assertEqual(self.preferences.reads, 0)
        self.assertEqual(self.preferences.commits, 0)


if __name__ == "__main__":
    unittest.main()
