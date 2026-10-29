"""Offline operator-disposition tests; never start Tart, Softnet, or touch host preferences."""

import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import dispose_softnet_failed_run as disposition  # noqa: E402
import softnet_recovery as recovery  # noqa: E402
import softnet_run_state as run_state  # noqa: E402


class Preferences:
    def __init__(self, current=b"original"):
        """Initialize a preference store with its current value."""
        self.current = current
        self.reads = 0

    def __enter__(self):
        """Return this preference store for use in a with statement."""
        return self

    def __exit__(self, *_args):
        """Leave the preference store unchanged after the with statement."""
        return False

    def read(self):
        self.reads += 1
        return self.current

    def equal(self, left, right):
        return left == right


class DispositionTests(unittest.TestCase):
    def setUp(self):
        self.account = SimpleNamespace(pw_uid=501, pw_gid=20)
        self.admission = {
            "vmName": "softnet-canary-" + "a" * 32,
            "macAddress": "02:00:00:00:00:01",
            "tartHome": "/private/tmp/tart-home",
        }
        self.digest = "d" * 64
        self.identity = {
            "vmName": self.admission["vmName"],
            "macAddress": self.admission["macAddress"],
            "admissionSha256": self.digest,
            "tartBinarySha256": disposition.controller.canary.TART_BINARY_SHA256,
            "softnetBinarySha256": disposition.controller.SOFTNET_SHA256,
        }
        self.prefs = Preferences()

    def run_observer(self, *, table=b"  1 /sbin/launchd\n", tart=b'{"Running":false,"State":"stopped"}',
                     config=b'{"os":"darwin","arch":"arm64","macAddress":"02:00:00:00:00:01","afterBoot":true}',
                     current=b"original", identity=None):
        def preferences_factory():
            return self.prefs
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY)
            try:
                with (
                    patch.object(disposition.controller, "_admission_record",
                                 return_value=(self.admission, self.account, "staff", self.digest)) as admission,
                    patch.object(disposition.controller, "_binary") as binary,
                    patch.object(disposition.controller, "_protected", return_value=Path(directory) / "config.json") as protected,
                    patch.object(disposition.controller.canary, "_hash_file",
                                 return_value=("e" * 64, len(config), config)),
                    patch.object(disposition.controller.canary, "_run_bounded",
                                 side_effect=[(tart, 0), (table, 0)]) as bounded,
                    patch.object(disposition.controller.recovery, "_directory", return_value=fd),
                    patch.object(disposition.controller.recovery, "_snapshot", return_value=(b"original", b"target")),
                    patch.object(disposition.subprocess, "Popen") as popen,
                ):
                    self.prefs.current = current
                    result = disposition._observe("/unused/admission", "/unused/run",
                                                  identity or self.identity,
                                                  preferences_factory=preferences_factory)
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass  # _observe closes its recovery directory descriptor.
        return result, (admission, binary, protected, bounded, popen)

    def test_observe_reads_only_saved_preferences_and_uses_admitted_owner_for_tart(self):
        result, (_, binary, protected, bounded, popen) = self.run_observer()
        self.assertEqual(result["vmStopped"], True)
        self.assertEqual(result["processesQuiet"], True)
        self.assertEqual(result["preferencesOriginal"], True)
        self.assertEqual(self.prefs.reads, 1)
        self.assertEqual(binary.call_args_list, [
            call(disposition.controller.TART, self.identity["tartBinarySha256"]),
            call(disposition.controller.SOFTNET, self.identity["softnetBinarySha256"]),
        ])
        self.assertEqual(protected.call_args.args[1], self.account.pw_uid)
        tart_call = bounded.call_args_list[0]
        self.assertEqual(tart_call.args[0], [str(disposition.controller.TART), "get",
                                            self.admission["vmName"], "--format", "json"])
        owner = tart_call.kwargs["popen"].keywords
        self.assertEqual(owner, {"user": self.account.pw_uid, "group": self.account.pw_gid,
                                 "extra_groups": []})
        self.assertEqual(tart_call.kwargs["env"], {
            **disposition.controller.ENV, "HOME": self.admission["tartHome"],
            "TART_HOME": self.admission["tartHome"], "TART_NO_AUTO_PRUNE": "1"})
        self.assertEqual(bounded.call_args_list[1].args[0],
                         ["/bin/ps", "-A", "-o", "pid=", "-o", "comm="])
        popen.assert_not_called()

    def test_observe_rejects_admission_identity_mismatch_before_commands(self):
        wrong = {**self.identity, "admissionSha256": "0" * 64}
        with patch.object(disposition.controller, "_admission_record",
                          return_value=(self.admission, self.account, "staff", self.digest)), \
             patch.object(disposition.controller, "_binary") as binary:
            with self.assertRaisesRegex(recovery.RecoveryError, "disposition_admission_mismatch"):
                disposition._observe("/unused", "/unused", wrong)
        binary.assert_not_called()

    def test_observe_rejects_vm_identity_and_running_or_inconsistent_state(self):
        cases = (
            (b'{"os":"darwin","arch":"arm64","macAddress":"02:00:00:00:00:02"}',
             b'{"Running":false,"State":"stopped"}', "vm_identity_mismatch"),
            (b'{"os":"darwin","arch":"arm64","macAddress":"02:00:00:00:00:01"}',
             b'{"Running":true,"State":"running"}', "vm_not_stopped"),
            (b'{"os":"darwin","arch":"arm64","macAddress":"02:00:00:00:00:01"}',
             b'{"Running":true,"State":"stopped"}', "vm_not_stopped"),
        )
        for config, tart, error in cases:
            with self.subTest(error=error, tart=tart):
                with self.assertRaisesRegex(recovery.RecoveryError, error):
                    self.run_observer(config=config, tart=tart)

    def test_observe_rejects_bad_process_table_and_live_tart_or_softnet(self):
        for table in (b"", b"not-a-pid /sbin/launchd", b"1 /usr/local/bin/tart", b"2 /opt/softnet"):
            with self.subTest(table=table):
                expected = "invalid_process_table" if table in (b"", b"not-a-pid /sbin/launchd") else "runtime_quiescence_unproven"
                with self.assertRaisesRegex(recovery.RecoveryError, expected):
                    self.run_observer(table=table)

    def test_observe_rejects_preference_drift(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "preference_drift"):
            self.run_observer(current=b"changed")
        self.assertEqual(self.prefs.reads, 1)

    def test_dispose_requires_root_macos_then_calls_state_with_fixed_root(self):
        for uid, platform in ((1000, "darwin"), (0, "linux")):
            with self.subTest(uid=uid, platform=platform), \
                 patch.object(disposition.os, "geteuid", return_value=uid), \
                 patch.object(disposition.sys, "platform", platform), \
                 patch.object(disposition.state, "dispose_failed_restored") as record:
                with self.assertRaisesRegex(recovery.RecoveryError, "root_macos_required"):
                    disposition.dispose("/admission", "run", "ticket")
                record.assert_not_called()
        with patch.object(disposition.os, "geteuid", return_value=0), \
             patch.object(disposition.sys, "platform", "darwin"), \
             patch.object(disposition.state, "dispose_failed_restored") as record:
            result = disposition.dispose("/admission", "run", "ticket")
        self.assertEqual(record.call_args.args[:3], (disposition.controller.STATE_ROOT, "run", "ticket"))
        self.assertEqual(result["historicalVmReapingProven"], False)
        self.assertEqual(result["qualified"], False)
        self.assertEqual(result["vmDeleted"], False)

    def test_dispose_records_receipt_through_real_state_with_private_fixture(self):
        uid = os.getuid()
        with tempfile.TemporaryDirectory(prefix="softnet-disposition-test-") as directory:
            root = Path(directory).resolve() / "state"
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            with patch.object(recovery, "OWNER_UID", uid), \
                 patch.object(recovery.os, "geteuid", return_value=uid):
                with run_state.State(root) as state:
                    run, run_id = state.begin(self.identity)
                fd = recovery._directory(run)
                try:
                    reserved = recovery._file(fd, "reserved", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                    os.close(reserved)
                    for name, data in (
                        ("snapshot.plist", plistlib.dumps(
                            {"version": 1, "present": False, "before": b"", "target": b"bplist00"},
                            fmt=plistlib.FMT_BINARY)),
                        ("restored", b"restored\n"),
                        ("launch.plist", plistlib.dumps(
                            {"vmName": self.identity["vmName"], "macAddress": self.identity["macAddress"]},
                            fmt=plistlib.FMT_BINARY)),
                        ("stop.plist", plistlib.dumps(
                            {"vmReaped": False, "helperReaped": True, "vmStopped": True},
                            fmt=plistlib.FMT_BINARY)),
                    ):
                        recovery._publish(fd, name, data)
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
                observation = {"observedAtUnixNs": time.time_ns(),
                               "vmStopped": True, "processesQuiet": True,
                               "preferencesOriginal": True}
                with patch.object(disposition, "_observe", return_value=observation), \
                     patch.object(disposition.controller, "STATE_ROOT", root), \
                     patch.object(disposition, "os", SimpleNamespace(geteuid=lambda: 0)), \
                     patch.object(disposition, "sys", SimpleNamespace(platform="darwin")):
                    result = disposition.dispose("/unused/admission", run_id, "ticket")
                receipt = plistlib.loads((run / "disposition.plist").read_bytes())
                self.assertEqual(receipt["observation"], observation)
                self.assertEqual(receipt["approvalReference"], "ticket")
                self.assertFalse(result["historicalVmReapingProven"])
                with run_state.State(root):
                    pass

    def test_main_requires_explicit_acknowledgment_and_reports_failure(self):
        args = ["--admission-dir", "/admission", "--run-id", "run", "--approval-reference", "ticket"]
        with patch.object(sys, "stderr"):
            with self.assertRaises(SystemExit) as error:
                disposition.main(args)
        self.assertEqual(error.exception.code, 2)
        args.append("--accept-historical-vm-reaping-unknown")
        with patch.object(disposition, "dispose", side_effect=RuntimeError("secret detail")), \
             patch.object(sys, "stderr") as stderr, patch.object(sys, "stdout") as stdout:
            self.assertEqual(disposition.main(args), 1)
        self.assertIn("softnet_disposition_failed",
                      "".join(str(arg) for call in stderr.write.call_args_list for arg in call.args))
        stdout.write.assert_not_called()

    def test_main_prints_success_only_after_disposition_returns(self):
        args = ["--admission-dir", "/admission", "--run-id", "run", "--approval-reference", "ticket",
                "--accept-historical-vm-reaping-unknown"]
        receipt = {"status": "failed-restored-disposition-recorded"}
        with patch.object(disposition, "dispose", return_value=receipt), \
             patch("builtins.print") as output:
            self.assertEqual(disposition.main(args), 0)
        self.assertEqual(json.loads(output.call_args.args[0]), receipt)


if __name__ == "__main__":
    unittest.main()
