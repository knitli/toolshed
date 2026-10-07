"""Exercise proof-harness cleanup without loading its externally pinned SDK."""
import ast
import os
from pathlib import Path
import runpy
import signal
import subprocess  # nosec B404 - Only TimeoutExpired is used; process behavior is mocked.
import tempfile
import unittest
from unittest.mock import Mock, call


SOURCE = Path(__file__).resolve().parents[1] / 'docs/native-bridge/durable-restart-v3-qualify.py'


def load_cleanup(namespace, *, callback_finally=False):
    tree = ast.parse(SOURCE.read_text())
    name = 'restart_callback' if callback_finally else 'stop_process'
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
    if callback_finally:
        # Execute the actual cleanup block with resources already acquired.
        body = next(node.finalbody for node in function.body if isinstance(node, ast.Try) and node.finalbody)
        tree = ast.Module(body=body, type_ignores=[])
    else:
        tree = ast.Module(body=[function], type_ignores=[])
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'cleanup.py'
        path.write_text(ast.unparse(tree))
        return runpy.run_path(str(path), init_globals=namespace, run_name='cleanup_test').get(name)


class DurableRestartCleanupTests(unittest.TestCase):
    def stop_fixture(self, waits):
        process = Mock(pid=1234)
        process.wait.side_effect = waits
        operating_system = Mock()
        backend_alive = [True]

        def signal_group(pid, sig):
            if sig == signal.SIGKILL:
                backend_alive[0] = False

        operating_system.killpg.side_effect = signal_group
        clock = Mock()
        clock.monotonic.side_effect = range(0, 100, 10)
        namespace = {
            'os': operating_system, 'signal': signal, 'subprocess': subprocess,
            'time': clock, 'alive': lambda pid: backend_alive[0],
            'require': self.assertTrue,
        }
        return load_cleanup(namespace), process, operating_system

    def test_group_is_killed_when_leader_ignores_term(self):
        stop, process, operating_system = self.stop_fixture([
            subprocess.TimeoutExpired('tui', 5), 0,
        ])
        stop(process, 5678)
        self.assertEqual(operating_system.killpg.call_args_list, [
            call(1234, signal.SIGTERM), call(1234, signal.SIGKILL),
        ])
        operating_system.kill.assert_not_called()
        process.kill.assert_not_called()
        self.assertEqual(process.wait.call_count, 2)

    def test_group_is_killed_even_when_leader_has_exited(self):
        stop, process, operating_system = self.stop_fixture([0, 0])
        stop(process, 5678)
        self.assertEqual(operating_system.killpg.call_args_list, [
            call(1234, signal.SIGTERM), call(1234, signal.SIGKILL),
        ])
        operating_system.kill.assert_not_called()

    def test_callback_closes_fds_and_joins_thread_when_reaping_fails(self):
        master, slave = os.pipe()
        thread = Mock()
        bridge = Mock()
        failure = subprocess.TimeoutExpired('tui', 5)
        namespace = {
            'stop': Mock(), 'bridge': bridge, 'parent': None, 'child': Mock(),
            'second': Mock(), 'new_witness': {'backendPid': 5678},
            'stop_process': Mock(side_effect=failure), 'thread': thread,
            'slave': slave, 'master': master, 'os': os,
        }
        try:
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                load_cleanup(namespace, callback_finally=True)
            self.assertIs(caught.exception, failure)
            bridge.close.assert_called_once_with()
            thread.join.assert_called_once_with(timeout=1)
            for descriptor in (master, slave):
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            for descriptor in (master, slave):
                try:
                    os.close(descriptor)
                except OSError:
                    pass


if __name__ == '__main__':
    unittest.main()
