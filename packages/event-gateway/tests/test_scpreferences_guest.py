"""Offline checks for the fixed guest SCPreferences API probe."""

import hashlib
import os
from pathlib import Path
import plistlib
import subprocess  # nosec B404 -- fixed Python child with fake preference/source fixtures only.
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SOURCE_SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import qualify_scpreferences_guest as guest_api  # noqa: E402
import qualify_offline_macos_vm as canary  # noqa: E402
import softnet_preferences  # noqa: E402
import softnet_recovery as recovery  # noqa: E402


class FakePreferences:
    """In-memory typed preference API with a process-wide nonwaiting lock."""

    target = plistlib.dumps(
        {"DHCPLeaseTimeSecs": 600, "dhcp_ignore_client_identifier": True},
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )
    current = None
    locked = False
    constructors = 0
    fail_read_once = False
    fail_target_commit_once = False
    external_change_on_target_read = False

    def __init__(self):
        """Count construction and initialize this instance's staged value."""
        type(self).constructors += 1
        self.staged = None

    def __enter__(self):
        """Acquire the fake nonwaiting lock and snapshot the current value."""
        if type(self).locked:
            raise softnet_preferences.PreferencesError("preferences_lock_failed:3002:busy")
        type(self).locked = True
        self.staged = type(self).current
        return self

    def __exit__(self, *_):
        """Release the fake lock without suppressing exceptions."""
        type(self).locked = False
        return False

    def read(self):
        if type(self).fail_read_once:
            type(self).fail_read_once = False
            raise OSError("injected capture read failure")
        current = type(self).current
        if type(self).external_change_on_target_read and current == type(self).target:
            type(self).external_change_on_target_read = False
            type(self).current = plistlib.dumps(
                {"writtenBy": "outside-actor"}, fmt=plistlib.FMT_BINARY)
        return current

    def write(self, value):
        self.staged = value

    def commit_apply(self):
        type(self).current = self.staged
        if type(self).fail_target_commit_once and self.staged == type(self).target:
            type(self).fail_target_commit_once = False
            raise OSError("injected target commit failure")

    def synchronize(self):
        return None

    @classmethod
    def encode_target(cls):
        return cls.target

    @staticmethod
    def equal(left, right):
        return left == right

    @staticmethod
    def validate(blob):
        plistlib.loads(blob)


class SCPreferencesGuestQualificationTests(unittest.TestCase):
    """Exercise real journal code around a fake preference API and temporary records."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scpreferences-guest-test-")
        self.addCleanup(self.temp.cleanup)
        self.owner_patch = patch.object(recovery, "OWNER_UID", os.getuid())
        self.euid_patch = patch.object(guest_api.os, "geteuid", return_value=os.getuid())
        self.owner_patch.start()
        self.euid_patch.start()
        self.addCleanup(self.euid_patch.stop)
        self.addCleanup(self.owner_patch.stop)
        self.journal_root = Path(self.temp.name).resolve() / "journals"
        self.journal_root.mkdir(mode=0o700)
        real_mkdtemp = tempfile.mkdtemp
        self.tempdir_patch = patch.object(
            guest_api.tempfile, "mkdtemp",
            side_effect=lambda prefix, **_: real_mkdtemp(prefix=prefix, dir=self.journal_root))
        self.tempdir_patch.start()
        self.addCleanup(self.tempdir_patch.stop)
        FakePreferences.current = plistlib.dumps(
            {"prior": ["secret-do-not-report", 7]}, fmt=plistlib.FMT_BINARY)
        FakePreferences.locked = False
        FakePreferences.constructors = 0
        FakePreferences.fail_read_once = False
        FakePreferences.fail_target_commit_once = False
        FakePreferences.external_change_on_target_read = False
        self.preferences_patch = patch.object(guest_api, "Preferences", FakePreferences)
        self.preferences_patch.start()
        self.addCleanup(self.preferences_patch.stop)
        self.real_lock_probe = guest_api._probe_nonwaiting_lock
        self.lock_probe_patch = patch.object(guest_api, "_probe_nonwaiting_lock", return_value=True)
        self.lock_probe_patch.start()
        self.addCleanup(self.lock_probe_patch.stop)

    def _qualify(self):
        with patch.object(guest_api, "_supported_environment", return_value=True):
            return guest_api.qualify_guest_apis()

    def test_unsupported_environment_rejects_without_constructing_preferences_or_journal(self):
        with patch.object(guest_api, "_supported_environment", return_value=False):
            with patch.object(guest_api.tempfile, "mkdtemp",
                              wraps=guest_api.tempfile.mkdtemp) as make_temp:
                report = guest_api.qualify_guest_apis()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["checks"]["environmentSupported"])
        self.assertIsNone(report["journalDirectory"])
        self.assertEqual(FakePreferences.constructors, 0)
        make_temp.assert_not_called()

    def test_environment_gate_requires_root_darwin_15_and_arm64(self):
        with (patch.object(guest_api.os, "geteuid", return_value=1000),
              patch.object(guest_api.sys, "platform", "darwin"),
              patch.object(guest_api.platform, "mac_ver", return_value=("15.0", "", "")),
              patch.object(guest_api.platform, "machine", return_value="arm64")):
            self.assertFalse(guest_api._supported_environment())
        with (patch.object(guest_api.os, "geteuid", return_value=0),
              patch.object(guest_api.sys, "platform", "darwin"),
              patch.object(guest_api.platform, "mac_ver", return_value=("15.0", "", "")),
              patch.object(guest_api.platform, "machine", return_value="arm64")):
            self.assertTrue(guest_api._supported_environment())

    def test_success_captures_writes_reopens_checks_lock_and_restores(self):
        before = FakePreferences.current
        report = self._qualify()
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["apiQualified"])
        self.assertFalse(report["effectiveDaemonQualified"])
        self.assertIsNone(report["failureCode"])
        self.assertEqual(report["savedValuePresent"], True)
        self.assertEqual(report["checks"], {name: True for name in guest_api.CHECKS})
        self.assertEqual(FakePreferences.current, before)
        self.assertTrue(Path(report["journalDirectory"]).is_dir())
        self.assertEqual((Path(report["journalDirectory"]) / "restored").read_bytes(), b"restored\n")
        self.assertEqual(report["sourceSha256"], {
            "guestApi": hashlib.sha256(Path(guest_api.__file__).read_bytes()).hexdigest(),
            "offlineCanary": hashlib.sha256(Path(canary.__file__).read_bytes()).hexdigest(),
            "softnetPreferences": hashlib.sha256(Path(softnet_preferences.__file__).read_bytes()).hexdigest(),
            "softnetRecovery": hashlib.sha256(Path(recovery.__file__).read_bytes()).hexdigest(),
        })
        self.assertNotIn("secret-do-not-report", repr(report))

    def test_absent_original_value_is_restored_and_reported_without_blob(self):
        FakePreferences.current = None
        report = self._qualify()
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["savedValuePresent"])
        self.assertIsNone(FakePreferences.current)
        self.assertTrue(report["checks"]["restoredMarkerVerified"])

    def test_error_after_capture_attempts_safe_restore_and_retains_journal(self):
        before = FakePreferences.current
        FakePreferences.fail_target_commit_once = True
        report = self._qualify()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["apiQualified"])
        self.assertTrue(report["checks"]["captureCompleted"])
        self.assertTrue(report["checks"]["restoreCompleted"])
        self.assertEqual(report["failureCode"], "target_write")
        self.assertEqual(FakePreferences.current, before)
        self.assertTrue(Path(report["journalDirectory"], "restored").is_file())

    def test_retry_restore_after_error_never_changes_failed_status_to_passed(self):
        verify = guest_api._verify_restoration
        attempts = 0

        def fail_once(report, directory, before):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError("injected verification failure")
            return verify(report, directory, before)

        with patch.object(guest_api, "_verify_restoration",
                          side_effect=fail_once) as attempt:
            report = self._qualify()
        self.assertEqual(attempt.call_count, 2)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["apiQualified"])
        self.assertEqual(report["failureCode"], "restore_and_readback")
        self.assertTrue(report["checks"]["restoreCompleted"])
        self.assertTrue(report["checks"]["restoredMarkerVerified"])

    def test_detectable_external_drift_is_not_overwritten_and_journal_is_retained(self):
        FakePreferences.external_change_on_target_read = True
        report = self._qualify()
        self.assertEqual(report["status"], "failed")
        self.assertTrue(report["checks"]["captureCompleted"])
        self.assertFalse(report["checks"]["restoreCompleted"])
        self.assertFalse(report["checks"]["restoredMarkerVerified"])
        self.assertEqual(plistlib.loads(FakePreferences.current), {"writtenBy": "outside-actor"})
        self.assertFalse(Path(report["journalDirectory"], "restored").exists())

    def test_capture_failure_does_not_attempt_restore(self):
        FakePreferences.fail_read_once = True
        with patch.object(guest_api.recovery, "restore") as restore:
            report = self._qualify()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["checks"]["captureCompleted"])
        self.assertFalse(report["checks"]["restoreCompleted"])
        journal = Path(report["journalDirectory"])
        self.assertTrue((journal / "reserved").is_file())
        self.assertFalse((journal / "snapshot.plist").exists())
        self.assertEqual(report["failureCode"], "capture")
        restore.assert_not_called()

    def test_lock_probe_uses_a_fixed_bounded_child_and_stable_lock_code(self):
        with patch.object(guest_api.canary, "_run_bounded", return_value=(b"", b"")) as run:
            self.assertTrue(self.real_lock_probe())
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], [sys.executable, "-I", "-c", guest_api.LOCK_PROBE])
        self.assertEqual(argv[4], str(Path(softnet_preferences.__file__).resolve().parent))
        self.assertEqual(run.call_args.kwargs["timeout"], 10)
        self.assertEqual(run.call_args.kwargs["output_limit"], 1024)
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"})
        with patch.object(guest_api.canary, "_run_bounded", return_value=(b"unexpected", b"")):
            self.assertFalse(self.real_lock_probe())
        with patch.object(guest_api.canary, "_run_bounded", return_value=(b"", b"unexpected")):
            self.assertFalse(self.real_lock_probe())
        with patch.object(guest_api.canary, "_run_bounded",
                          side_effect=guest_api.canary.CanaryError("bounded probe failed")):
            self.assertFalse(self.real_lock_probe())
        with patch.object(guest_api.canary, "_run_bounded", side_effect=OSError("spawn failed")):
            self.assertFalse(self.real_lock_probe())

    def test_lock_probe_rejects_nonbusy_systemconfiguration_errors(self):
        for status, expected_returncode in (("3002", 0), ("1003", 2), ("2002", 2)):
            module_dir = Path(self.temp.name) / f"fake-preferences-{status}"
            module_dir.mkdir()
            module_path = module_dir / "softnet_preferences.py"
            module_path.write_text(
                "class PreferencesError(Exception): pass\n"
                "class Preferences:\n"
                "    def __enter__(self):\n"
                f"        raise PreferencesError('preferences_lock_failed:{status}:failure')\n"
                "    def __exit__(self, *_): return False\n",
                encoding="utf-8",
            )
            with self.subTest(status=status):
                result = subprocess.run(  # nosec B603 -- fixed interpreter and inline fixture; no shell or external command.
                    [sys.executable, "-I", "-c", guest_api.LOCK_PROBE, str(module_dir)],
                    capture_output=True, check=False, timeout=3,
                )
                self.assertEqual(result.returncode, expected_returncode, result.stderr.decode())

    def test_cli_help_does_not_call_api(self):
        with patch.object(guest_api, "qualify_guest_apis") as qualify:
            qualify.return_value = {"status": "failed"}
            with patch("sys.stdout") as stdout:
                with self.assertRaises(SystemExit) as help_exit:
                    guest_api.main(["--help"])
            self.assertEqual(help_exit.exception.code, 0)
            stdout.write.assert_called()
            qualify.assert_not_called()

    def test_cli_rejects_unknown_arguments_before_api(self):
        with patch.object(guest_api, "qualify_guest_apis") as qualify:
            qualify.return_value = {"status": "failed"}
            with patch("sys.stderr") as stderr:
                with self.assertRaises(SystemExit) as unknown_exit:
                    guest_api.main(["--not-an-option"])
            self.assertEqual(unknown_exit.exception.code, 2)
            stderr.write.assert_called()
            qualify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
