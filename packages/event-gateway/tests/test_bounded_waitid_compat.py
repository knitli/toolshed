"""Darwin Python 3.9 compatibility tests for non-reaping waitid."""

import ctypes
import errno
import importlib.util
import os
from pathlib import Path
import signal
import subprocess  # nosec B404 -- tests invoke only fixed local Python code, with no shell or caller-controlled argv.
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "qualify_offline_macos_vm.py"

spec = importlib.util.spec_from_file_location("offline_macos_vm_waitid_compat", SCRIPT)
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)


class _PythonWithoutWaitid:
    def __getattr__(self, name):
        if name == "waitid":
            raise AttributeError(name)
        return getattr(os, name)


@unittest.skipUnless(sys.platform == "darwin", "Darwin libc waitid compatibility")
class DarwinWaitidCompatibilityTest(unittest.TestCase):
    def _spawn(self, code):
        return subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                close_fds=True, start_new_session=True)  # nosec B603 -- callers pass reviewed code literals only.

    def _stop_and_reap(self, process):
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
        process.stdout.close()
        process.stderr.close()

    def test_full_siginfo_layout_and_capability(self):
        self.assertEqual(ctypes.sizeof(canary._DarwinSiginfo), 104)
        self.assertTrue(canary._waitid_available())
        self.assertIsNotNone(canary._darwin_waitid_function())

    def test_exit_status_is_observed_without_reaping_then_reaped_once(self):
        process = self._spawn("raise SystemExit(7)")
        try:
            with patch.object(canary, "os", _PythonWithoutWaitid()):
                deadline = time.monotonic() + 3
                status = None
                while status is None and time.monotonic() < deadline:
                    status = canary._bounded_process_exit_status(process)
                    if status is None:
                        time.sleep(0.01)
                self.assertEqual(status, 7)
                self.assertIsNone(process.returncode, "WNOWAIT must keep the PID reserved")
            self.assertEqual(process.wait(timeout=3), 7)
        finally:
            self._stop_and_reap(process)

    def test_signaled_exit_is_observed_without_reaping(self):
        process = self._spawn("import time; time.sleep(30)")
        try:
            with patch.object(canary, "os", _PythonWithoutWaitid()):
                os.kill(process.pid, signal.SIGTERM)
                deadline = time.monotonic() + 3
                status = None
                while status is None and time.monotonic() < deadline:
                    status = canary._bounded_process_exit_status(process)
                    if status is None:
                        time.sleep(0.01)
                self.assertEqual(status, -signal.SIGTERM)
                self.assertIsNone(process.returncode, "signal observation must not reap the child")
            self.assertEqual(process.wait(timeout=3), -signal.SIGTERM)
        finally:
            self._stop_and_reap(process)

    def test_running_and_stopped_children_are_not_misreported_as_exited(self):
        process = self._spawn("import time; time.sleep(30)")
        try:
            with patch.object(canary, "os", _PythonWithoutWaitid()):
                self.assertIsNone(canary._bounded_process_exit_status(process))
                os.kill(process.pid, signal.SIGSTOP)
                self.assertIsNone(canary._bounded_process_exit_status(process))
                self.assertIsNone(process.returncode)
                os.kill(process.pid, signal.SIGCONT)
            os.killpg(process.pid, signal.SIGKILL)
            self.assertEqual(process.wait(timeout=3), -signal.SIGKILL)
        finally:
            self._stop_and_reap(process)

    def test_eintr_is_not_treated_as_exit(self):
        process = self._spawn("import time; time.sleep(30)")
        callback_type = ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ctypes.POINTER(canary._DarwinSiginfo), ctypes.c_int)

        @callback_type
        def interrupted(_idtype, _pid, _info, _options):
            ctypes.set_errno(errno.EINTR)
            return -1

        try:
            with patch.object(canary, "os", _PythonWithoutWaitid()), \
                    patch.object(canary, "_darwin_waitid_function", return_value=interrupted):
                with self.assertRaises(InterruptedError) as raised:
                    canary._waitid_no_reap(process.pid)
                self.assertEqual(raised.exception.errno, errno.EINTR)
                self.assertIsNone(process.returncode)
        finally:
            self._stop_and_reap(process)

    def test_vm_exit_wait_remains_bounded_under_eintr(self):
        process = self._spawn("import time; time.sleep(30)")
        callback_type = ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ctypes.POINTER(canary._DarwinSiginfo), ctypes.c_int)

        @callback_type
        def interrupted(_idtype, _pid, _info, _options):
            ctypes.set_errno(errno.EINTR)
            return -1

        try:
            with patch.object(canary, "os", _PythonWithoutWaitid()), \
                    patch.object(canary, "_darwin_waitid_function", return_value=interrupted):
                started = time.monotonic()
                with self.assertRaises(InterruptedError) as raised:
                    canary._wait_owned_vm_exit(process, 0.12)
                elapsed = time.monotonic() - started
                self.assertEqual(raised.exception.errno, errno.EINTR)
                self.assertGreaterEqual(elapsed, 0.10)
                self.assertLess(elapsed, 1)
                self.assertIsNone(process.returncode)
        finally:
            self._stop_and_reap(process)

    def test_runner_never_group_signals_when_identity_check_is_interrupted(self):
        real_popen = subprocess.Popen
        spawned = []
        group_signals = []

        def record_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process

        class _NoWaitidWithKillpgTrap(_PythonWithoutWaitid):
            def killpg(self, pid, sig):
                group_signals.append((pid, sig))
                raise AssertionError("group signal sent without a successful waitid identity check")

        callback_type = ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ctypes.POINTER(canary._DarwinSiginfo), ctypes.c_int)

        @callback_type
        def interrupted(_idtype, _pid, _info, _options):
            ctypes.set_errno(errno.EINTR)
            return -1

        try:
            with patch.object(canary, "os", _NoWaitidWithKillpgTrap()), \
                    patch.object(canary, "_darwin_waitid_function", return_value=interrupted), \
                    patch.object(canary.subprocess, "Popen", side_effect=record_popen):
                with self.assertRaisesRegex(canary.CanaryError, "tart_command_output_limit") as raised:
                    canary._run_bounded(
                        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100)"],
                        timeout=3, env=os.environ, output_limit=8)
                self.assertIn("process_group_identity_lost", raised.exception.cleanup_errors)
                self.assertEqual(raised.exception.unreaped_processes, (spawned[0],))
            self.assertEqual(group_signals, [])
        finally:
            for process in spawned:
                self._stop_and_reap(process)

    def test_stopped_notification_is_consumed_once_and_not_reported_as_exit(self):
        callback_type = ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ctypes.POINTER(canary._DarwinSiginfo), ctypes.c_int)
        calls = []

        @callback_type
        def stopped(_idtype, pid, info, options):
            calls.append(options)
            info.contents.si_pid = pid
            info.contents.si_code = canary._DARWIN_CLD_STOPPED
            info.contents.si_status = signal.SIGSTOP
            return 0

        with patch.object(canary, "os", _PythonWithoutWaitid()), \
                patch.object(canary, "_darwin_waitid_function", return_value=stopped):
            self.assertIsNone(canary._waitid_no_reap(12345))
        self.assertEqual(calls, [canary._DARWIN_WEXITED | canary._DARWIN_WNOHANG | canary._DARWIN_WNOWAIT,
                                 canary._DARWIN_WSTOPPED | canary._DARWIN_WNOHANG])

    @unittest.skipUnless(hasattr(os, "waitid"), "Python exposes native os.waitid")
    def test_native_waitid_path_does_not_report_stopped_child_as_exited(self):
        process = self._spawn("import time; time.sleep(30)")
        try:
            os.kill(process.pid, signal.SIGSTOP)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                stopped = os.waitid(os.P_PID, process.pid,
                                    os.WSTOPPED | os.WNOHANG | os.WNOWAIT)
                if stopped is not None and stopped.si_code == os.CLD_STOPPED:
                    break
                time.sleep(0.01)
            else:
                self.fail("child did not enter the stopped state before the deadline")

            with patch.object(canary, "_darwin_waitid_function",
                              side_effect=AssertionError("native os.waitid path expected")):
                self.assertIsNone(canary._bounded_process_exit_status(process))
            self.assertIsNone(process.returncode, "stopped-child observation must preserve the PID")
        finally:
            if process.returncode is None:
                try:
                    os.kill(process.pid, signal.SIGCONT)
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self._stop_and_reap(process)

    def test_bounded_runner_keeps_zero_nonzero_and_output_cap_semantics(self):
        real_popen = subprocess.Popen
        spawned = []
        command_processes = []

        def record_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            if args[0][0] == sys.executable:
                command_processes.append(process)
            return process

        with patch.object(canary, "os", _PythonWithoutWaitid()), \
                patch.object(canary.subprocess, "Popen", side_effect=record_popen):
            self.assertEqual(canary._run_bounded(
                [sys.executable, "-c", "print('ok')"], timeout=3, env=os.environ)[0], b"ok\n")
            with self.assertRaisesRegex(canary.CanaryError, "tart_command_failed"):
                canary._run_bounded([sys.executable, "-c", "raise SystemExit(7)"], timeout=3, env=os.environ)
            with tempfile.TemporaryDirectory() as directory:
                stdout_path = Path(directory) / "stdout.bin"
                stderr_path = Path(directory) / "stderr.bin"
                with self.assertRaisesRegex(canary.CanaryError, "tart_command_output_limit"):
                    canary._run_bounded(
                        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100)"],
                        timeout=3, env=os.environ, output_limit=8,
                        capture_paths=(stdout_path, stderr_path))
                self.assertEqual(stdout_path.read_bytes(), b"x" * 8)
                self.assertEqual(stderr_path.read_bytes(), b"")

        self.assertEqual(len(command_processes), 3)
        self.assertTrue(all(process.returncode is not None for process in spawned),
                        "all command/proof children must be reaped")
        self.assertEqual(command_processes[0].returncode, 0)
        self.assertEqual(command_processes[1].returncode, 7)
        self.assertIn(command_processes[2].returncode, (0, -signal.SIGKILL))


if __name__ == "__main__":
    unittest.main()
