"""Offline capture teardown tests; no executable or process is launched."""
import importlib.util
import io
from pathlib import Path
import signal
import subprocess
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location('capture_launcher', Path(__file__).with_name('launch.py'))
launch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launch)


class CaptureCleanupTests(unittest.TestCase):
    def exercise(self, *, timeout=False, pid=42123, pgid=42123, own_group=99, kill_error=None):
        process = MagicMock(pid=pid, returncode=None)
        process.stdout, process.stderr = io.BytesIO(), io.BytesIO()
        calls = 0

        def wait(**kwargs):
            nonlocal calls
            calls += 1
            if timeout and calls == 1:
                raise subprocess.TimeoutExpired('fixture', 1)
            process.returncode = 0
            return 0

        process.wait.side_effect = wait
        selector = MagicMock()
        selector.__enter__.return_value.get_map.return_value = {}
        state = {}
        with patch.object(launch.subprocess, 'Popen', return_value=process), \
                patch.object(launch.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(launch.os, 'getpgrp', return_value=own_group), \
                patch.object(launch.os, 'getpgid', return_value=pgid), \
                patch.object(launch.os, 'killpg', side_effect=kill_error) as kill:
            error = None
            try:
                launch.run_process([], None, {}, {'stdout': bytearray(b'{"status":"PASS"}'),
                                                'stderr': bytearray()}, state)
            except BaseException as caught:
                error = caught
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        return error, state, kill, process

    def test_successful_reaped_host_never_signalled(self):
        error, state, kill, process = self.exercise()
        self.assertIsNone(error)
        self.assertEqual(state['exitCode'], 0)
        kill.assert_not_called()
        self.assertEqual(process.wait.call_count, 1)

    def test_owned_unreaped_timeout_signalled_then_reaped(self):
        error, state, kill, process = self.exercise(timeout=True)
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        kill.assert_called_once_with(42123, signal.SIGKILL)
        self.assertEqual(process.wait.call_count, 2)
        self.assertEqual(state['exitCode'], 0)

    def test_wrong_or_unsafe_group_refused_without_losing_primary_failure(self):
        for values in ({'pgid': 123}, {'pid': 1}, {'pid': 0}, {'own_group': 42123}):
            with self.subTest(values=values):
                error, state, kill, process = self.exercise(timeout=True, **values)
                self.assertIsInstance(error, subprocess.TimeoutExpired)
                kill.assert_not_called()
                self.assertIn('unowned process group', state['cleanupFailure']['message'])
                self.assertEqual(process.wait.call_count, 1)

    def test_signal_failure_reported_without_losing_timeout(self):
        error, state, _, _ = self.exercise(timeout=True, kill_error=PermissionError('denied'))
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertEqual(state['cleanupFailure'], {'name': 'PermissionError', 'message': 'denied'})


if __name__ == '__main__':
    unittest.main()
