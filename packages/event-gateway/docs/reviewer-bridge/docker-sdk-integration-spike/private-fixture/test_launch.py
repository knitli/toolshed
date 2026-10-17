"""Offline capture teardown tests; no executable or process is launched."""
import hashlib
import importlib.util
import json
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
    def exercise(self, *, timeout=False, pid=42123, pgid=42123, own_group=99, kill_error=None, inventory_error=None):
        process = MagicMock(pid=pid, returncode=None)
        process.stdout, process.stderr = io.BytesIO(), io.BytesIO()
        signalled = []

        def signal_group(*args):
            self.assertIsNone(process.returncode)
            signalled.append(args)
            if kill_error:
                raise kill_error

        def wait(**kwargs):
            self.assertTrue(signalled, 'leader must remain unreaped until group cleanup')
            process.returncode = 0
            return 0

        process.wait.side_effect = wait
        selector = MagicMock()
        selector.__enter__.return_value.get_map.return_value = {}
        state = {}
        with patch.object(launch, 'await_unreaped_exit', side_effect=subprocess.TimeoutExpired('fixture', 1) if timeout else None), \
                patch.object(launch.subprocess, 'Popen', return_value=process), \
                patch.object(launch.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(launch, 'await_group_exit', side_effect=inventory_error), \
                patch.object(launch.os, 'waitid', return_value=None), \
                patch.object(launch.os, 'getpgrp', return_value=own_group), \
                patch.object(launch.os, 'getpgid', return_value=pgid), \
                patch.object(launch.os, 'killpg', side_effect=signal_group) as kill:
            error = None
            try:
                launch.run_process([], None, {}, {'stdout': bytearray(b'{"status":"PASS"}'),
                                                'stderr': bytearray()}, state)
            except BaseException as caught:
                error = caught
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        return error, state, kill, process

    def test_inventory_failure_preserves_primary_timeout(self):
        error, state, _, process = self.exercise(timeout=True, inventory_error=RuntimeError('inventory denied'))
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertEqual(state['cleanupFailure']['message'], 'inventory denied')
        process.wait.assert_not_called()

    def test_inventory_live_member_times_out(self):
        uid = launch.os.getuid()
        with patch.object(launch, 'group_snapshot', return_value=f'42124 42123 {uid} S\n'), \
                patch.object(launch.time, 'monotonic', side_effect=[0, 3]):
            with self.assertRaisesRegex(RuntimeError, 'Live process group'):
                launch.await_group_exit(MagicMock(pid=42123))

    def test_inventory_failure_refuses_cleanup(self):
        with patch.object(launch, 'group_snapshot', side_effect=RuntimeError('inventory denied')):
            with self.assertRaisesRegex(RuntimeError, 'inventory denied'):
                launch.await_group_exit(MagicMock(pid=42123))

    def test_inventory_accepts_only_exited_group_members(self):
        uid = launch.os.getuid()
        with patch.object(launch, 'group_snapshot', return_value=f'42123 42123 {uid} Z\n'), \
                patch.object(launch.os, 'waitid', return_value=object()):
            launch.await_group_exit(MagicMock(pid=42123))

    def test_inventory_rejects_malformed_or_wrong_identity(self):
        for row in ('bad', '1 88 0 Z', '1 42123 0 ?'):
            with self.subTest(row=row), patch.object(launch, 'group_snapshot', return_value=row):
                with self.assertRaises(RuntimeError):
                    launch.await_group_exit(MagicMock(pid=42123))

    def test_candidate_manifest_matches_all_local_inputs(self):
        root = Path(__file__).parent
        manifest = json.loads((root / 'manifest.json').read_text())
        for name, expected in manifest['files'].items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), expected)

    def test_exit_observer_does_not_reap_live_leader(self):
        process = MagicMock(pid=42123)
        with patch.object(launch.os, 'waitid', side_effect=[None, object()]) as observe, \
                patch.object(launch.time, 'sleep'):
            launch.await_unreaped_exit(process, launch.time.monotonic() + 1)
        self.assertEqual(observe.call_count, 2)
        process.wait.assert_not_called()
        process.poll.assert_not_called()

    def test_exited_leader_retains_ownership_without_darwin_pgid_query(self):
        process = MagicMock(pid=42123)
        with patch.object(launch.os, 'waitid', return_value=object()), \
                patch.object(launch.os, 'getpgrp', return_value=99), \
                patch.object(launch.os, 'getpgid') as query:
            launch.verify_owned_group(process)
        query.assert_not_called()

    def test_missing_observer_refused_before_spawn(self):
        with patch.object(launch.os, 'waitid', create=True):
            original = launch.os.waitid
            del launch.os.waitid
            try:
                with patch.object(launch.subprocess, 'Popen') as spawn:
                    with self.assertRaisesRegex(RuntimeError, 'non-reaping waitid'):
                        launch.run_process([], None, {}, {}, {})
                    spawn.assert_not_called()
            finally:
                launch.os.waitid = original

    def test_successful_unreaped_host_group_signalled_before_reap(self):
        error, state, kill, process = self.exercise()
        self.assertIsNone(error)
        self.assertEqual(state['exitCode'], 0)
        kill.assert_called_once_with(42123, signal.SIGKILL)
        self.assertEqual(process.wait.call_count, 1)

    def test_owned_unreaped_timeout_signalled_then_reaped(self):
        error, state, kill, process = self.exercise(timeout=True)
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        kill.assert_called_once_with(42123, signal.SIGKILL)
        self.assertEqual(process.wait.call_count, 1)
        self.assertEqual(state['exitCode'], 0)

    def test_wrong_or_unsafe_group_refused_without_losing_primary_failure(self):
        for values in ({'pgid': 123}, {'pid': 1}, {'pid': 0}, {'own_group': 42123}):
            with self.subTest(values=values):
                error, state, kill, process = self.exercise(timeout=True, **values)
                self.assertIsInstance(error, subprocess.TimeoutExpired)
                kill.assert_not_called()
                self.assertIn('unowned process group', state['cleanupFailure']['message'])
                self.assertEqual(process.wait.call_count, 0)

    def test_signal_failure_reported_without_losing_timeout(self):
        error, state, _, _ = self.exercise(timeout=True, kill_error=OSError('denied'))
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertEqual(state['cleanupFailure'], {'name': 'OSError', 'message': 'denied'})


if __name__ == '__main__':
    unittest.main()
