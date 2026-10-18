"""Mock-only diagnostic tests: no subprocess, native mapping, or function execution."""
import builtins
import contextlib
import ctypes
import copy
import errno
import json
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

BASE = Path(__file__).resolve().parents[1] / 'scripts'


def load(name):
    filename = {'child': 'hosted_map_execution_child.py', 'probe': 'probe_hosted_map_execution.py'}[name]
    spec = importlib.util.spec_from_file_location('diagnostic_' + name, BASE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


child = load('child')
probe = load('probe')


class ChildTests(unittest.TestCase):
    def test_exact_constant_return_bytes(self):
        self.assertEqual(child.STUB, b'\x40\x05\x80\x52\xc0\x03\x5f\xd6')
        self.assertEqual(child.DATA, child.STUB + bytes(65536 - 8))
        self.assertEqual(probe.STUB, child.STUB)
        self.assertEqual(probe.DATA, child.DATA)

    def test_mapping_transitions_use_mock_function_only(self):
        for operation, protection in [('private_r', 1), ('private_rw', 3),
                                      ('initial_rx', 5), ('r_to_rx', 1), ('rw_to_rx', 3)]:
            with self.subTest(operation=operation):
                libc = Mock()
                libc.mmap.return_value = 4096
                libc.mprotect.return_value = libc.munmap.return_value = 0
                function = Mock(return_value=42)
                factory = Mock(return_value=function)
                with patch.object(child.ctypes, 'CFUNCTYPE', return_value=factory) as cfun, \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(child.observe(7, operation, libc),
                                     {'stage': 'complete', 'status': 0, 'errno': 0})
                libc.mmap.assert_called_once_with(None, child.SIZE, protection, 2, 7, 0)
                libc.munmap.assert_called_once_with(4096, child.SIZE)
                if operation.endswith('_rx'):
                    cfun.assert_called_once_with(ctypes.c_int)
                    factory.assert_called_once_with(4096)
                    function.assert_called_once_with()
                else:
                    cfun.assert_not_called()
                if operation in ('r_to_rx', 'rw_to_rx'):
                    libc.mprotect.assert_called_once_with(4096, child.SIZE, 5)
                else:
                    libc.mprotect.assert_not_called()

    def test_denial_never_calls_function_and_unmaps_if_mapped(self):
        for stage in ('mmap', 'mprotect'):
            with self.subTest(stage=stage):
                libc = Mock()
                libc.mmap.return_value = child.MAP_FAILED if stage == 'mmap' else 4096
                libc.mprotect.return_value = -1
                libc.munmap.return_value = 0
                with patch.object(child.ctypes, 'CFUNCTYPE') as cfun:
                    result = child.observe(7, 'r_to_rx', libc)
                self.assertEqual(result['stage'], stage)
                self.assertEqual(result['status'], -1)
                cfun.assert_not_called()
                self.assertEqual(libc.munmap.call_count, int(stage == 'mprotect'))

    def test_script_entry_precedes_ctypes_import_failure(self):
        original_import = builtins.__import__

        def fail_ctypes(name, *args, **kwargs):
            if name == 'ctypes':
                raise ImportError('mock ctypes startup failure')
            return original_import(name, *args, **kwargs)

        output = io.StringIO()
        source = (BASE / 'hosted_map_execution_child.py').read_text()
        with patch.object(builtins, '__import__', side_effect=fail_ctypes), \
                contextlib.redirect_stderr(output):
            with self.assertRaisesRegex(ImportError, 'mock ctypes'):
                exec(compile(source, str(BASE / 'hosted_map_execution_child.py'), 'exec'), {'__name__': '__main__'})
        self.assertEqual(output.getvalue(), 'startup:script_entry\n')

    def test_control_read_never_loads_libc_or_observes_mappings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'mapping-data'
            path.write_bytes(child.DATA)
            path.chmod(0o600)
            output, diagnostics = io.StringIO(), io.StringIO()
            with patch.object(child.sys, 'argv', ['child.py', '--child', 'read']), \
                    patch.object(child.sys, 'platform', 'darwin'), \
                    patch.object(child.platform, 'machine', return_value='arm64'), \
                    patch.object(child.resource, 'setrlimit'), \
                    patch.object(child.Path, 'cwd', return_value=root), \
                    patch.object(child.ctypes, 'CDLL', side_effect=AssertionError('no native loader')), \
                    patch.object(child, 'observe', side_effect=AssertionError('no mapping observer')), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostics):
                child.main()
            self.assertEqual(diagnostics.getvalue(), ''.join('startup:' + phase + '\n'
                             for phase in probe.STARTUP_PHASES[3:]))
            values = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(values[-1], {'event': 'result', 'stage': 'read', 'status': 0, 'errno': 0})
            self.assertEqual(path.read_bytes(), child.DATA)
            # Execute the real entrypoint with the same inert fixture and mocked OS boundary.
            source = (BASE / 'hosted_map_execution_child.py').read_text()
            output, diagnostics = io.StringIO(), io.StringIO()
            with patch.object(child.sys, 'argv', ['child.py', '--child', 'read']), \
                    patch.object(child.sys, 'platform', 'darwin'), \
                    patch.object(child.platform, 'machine', return_value='arm64'), \
                    patch.object(child.resource, 'setrlimit'), \
                    patch.object(child.Path, 'cwd', return_value=root), \
                    patch.object(child.ctypes, 'CDLL', side_effect=AssertionError('no native loader')), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostics):
                exec(compile(source, str(BASE / 'hosted_map_execution_child.py'), 'exec'), {'__name__': '__main__'})
            self.assertEqual(probe.startup_trace(diagnostics.getvalue()), probe.STARTUP_PHASES)

    def test_child_host_gate_precedes_native_loading(self):
        with patch.object(child.sys, 'argv', ['child.py', '--child', 'initial_rx']), \
                patch.object(child.sys, 'platform', 'linux'), \
                patch.object(child.ctypes, 'CDLL') as cdll:
            with self.assertRaisesRegex(ValueError, 'fixed_arm64_child_only'):
                child.main()
            cdll.assert_not_called()


class SupervisorTests(unittest.TestCase):
    fixture = {'identity': [1, 2, 3], 'sha256': 'fixed-fixture-digest'}

    def receipt(self, values):
        return {'returncode': 0, 'cleanupConfirmed': True, 'cleanupError': None,
                'error': None, 'stderr': ''.join('startup:' + phase + '\n' for phase in probe.STARTUP_PHASES), 'stdout': '\n'.join(json.dumps(v) for v in
                    [{'event': 'input', **self.fixture}, *values])}

    def success(self, operation):
        return [{'event': 'calling', 'operation': operation},
                {'event': 'returned', 'operation': operation, 'value': 42},
                {'event': 'result', 'stage': 'complete', 'status': 0, 'errno': 0}]

    def matrix(self):
        result = {}
        for profile in probe.PROFILES:
            for operation in probe.OPERATIONS:
                if operation in probe.EXEC_OPERATIONS:
                    values = ([{'event': 'result', 'stage': 'mmap' if operation == 'initial_rx' else 'mprotect',
                                'status': -1, 'errno': errno.EPERM}]
                              if profile == 'denied' else self.success(operation))
                else:
                    values = [{'event': 'result', 'stage': 'read' if operation == 'read' else 'complete',
                               'status': 0, 'errno': 0}]
                result[profile + ':' + operation] = self.receipt(values)
        return result

    def test_startup_abort_retains_each_exact_prefix_without_passing(self):
        for count in range(len(probe.STARTUP_PHASES) + 1):
            with self.subTest(count=count):
                receipt = self.receipt([])
                receipt.update(returncode=-6, stdout='', stderr=''.join(
                    'startup:' + phase + '\n' for phase in probe.STARTUP_PHASES[:count]))
                self.assertEqual(probe.startup_trace(receipt['stderr']), probe.STARTUP_PHASES[:count])
                self.assertFalse(probe.healthy(receipt))
                self.assertEqual(probe.classify({'control_before:read': receipt}, self.fixture), 'INCONCLUSIVE')

    def test_only_complete_exact_startup_trace_can_pass_matrix(self):
        complete = self.receipt([])['stderr']
        bad_traces = ['', complete[:-1], complete + 'unknown\n', complete + complete,
                      'startup:script_entry\n' * 2, 'x' * (probe.LIMIT + 1)]
        lines = complete.splitlines(keepends=True)
        bad_traces.extend(''.join(lines[:index] + lines[index + 1:]) for index in range(len(lines)))
        bad_traces.extend(''.join(lines[:index] + [lines[index + 1], lines[index]] + lines[index + 2:])
                          for index in range(len(lines) - 1))
        for stderr in bad_traces:
            with self.subTest(stderr=stderr[:80]):
                receipts = self.matrix()
                receipts['control_before:read']['stderr'] = stderr
                self.assertFalse(probe.healthy(receipts['control_before:read']))
                self.assertEqual(probe.classify(receipts, self.fixture), 'INCONCLUSIVE')
                self.assertEqual(receipts['control_before:read']['stderr'], stderr)

    def test_fixed_startup_flag_schedules_only_existing_control_read(self):
        self.assertEqual(probe.fixture_cases(True), probe.fixture_cases()[:1])
        self.assertEqual(probe.fixture_cases(True)[0][0], 'control_before:read')
        self.assertEqual(probe.fixture_cases(True)[0][1][-2:], ['--child', 'read'])
        with patch.object(probe, 'run', return_value=1) as run:
            self.assertEqual(probe.main(['--startup-only']), 1)
            run.assert_called_once_with(startup_only=True)
            run.reset_mock()
            self.assertEqual(probe.main(['--go']), 1)
            run.assert_called_once_with(startup_only=False)
            run.reset_mock()
            for argv in ([], ['--startup-only', '--go'], ['--startup-only', 'read'], ['--startup-only=1']):
                with self.subTest(argv=argv), self.assertRaises(SystemExit):
                    probe.main(argv)
            run.assert_not_called()

    def test_successful_startup_run_never_qualifies_or_schedules_matrix(self):
        receipt = self.receipt([{'event': 'result', 'stage': 'read', 'status': 0, 'errno': 0}])
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory).resolve()
            env = {key: 'fixed' for key in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion')}
            env['RUNNER_TEMP'] = str(temp)
            with patch.dict(probe.os.environ, env, clear=True), \
                    patch.object(probe, 'ROOT', probe.ROOT), patch.object(probe, 'ENV', {}), \
                    patch.object(probe, 'admit'), patch.object(probe, 'file_record', return_value=self.fixture), \
                    patch.object(probe, 'tool_ancestry', return_value=[]), \
                    patch.object(probe, 'bounded', return_value=receipt) as bounded, \
                    patch.object(probe.subprocess, 'Popen', side_effect=AssertionError('no actual execution')):
                self.assertEqual(probe.run(startup_only=True), 1)
                bounded.assert_called_once_with(probe.fixture_cases(True)[0][1])
                result = json.loads((probe.ROOT / 'result.json').read_text())
                self.assertEqual(set(result['receipts']), {'control_before:read'})
                self.assertEqual(result['status'], 'INCONCLUSIVE')
                self.assertFalse(result['qualified'])
                self.assertTrue(result['fixtureRemoved'])

    def test_positive_controls_and_denial_matrix(self):
        receipts = self.matrix()
        self.assertEqual(len(receipts), 18)
        self.assertEqual(probe.classify(receipts, self.fixture), 'SYSCALL_AND_CONTROL_MATRIX_PASS')
        for name in receipts:
            with self.subTest(name=name):
                missing = copy.deepcopy(receipts)
                del missing[name]
                self.assertEqual(probe.classify(missing, self.fixture), 'INCONCLUSIVE')

    def test_bad_controls_are_inconclusive(self):
        for profile in ('control_before', 'control_after'):
            for operation in probe.EXEC_OPERATIONS:
                receipts = self.matrix()
                values = self.success(operation)
                values[1]['value'] = 41
                receipts[profile + ':' + operation] = self.receipt(values)
                self.assertEqual(probe.classify(receipts, self.fixture), 'INCONCLUSIVE')

    def test_denied_return_overrides_bad_controls_and_cleanup(self):
        for operation in probe.EXEC_OPERATIONS:
            for value in (42, 41):
                with self.subTest(operation=operation, value=value):
                    values = self.success(operation)
                    values[1]['value'] = value
                    receipt = self.receipt(values)
                    receipt.update(cleanupConfirmed=False, cleanupError='unreaped', returncode=-9, stderr='unexpected startup output')
                    self.assertEqual(probe.classify({'denied:' + operation: receipt}, self.fixture),
                                     'FAIL_EXECUTION_ALLOWED')

    def test_truncated_tail_cannot_erase_denied_execution(self):
        receipt = self.receipt(self.success('initial_rx')[:2])
        receipt['stdout'] += '\n{"event":"res'
        receipt.update(returncode=-9, error='TimeoutError: child_deadline')
        self.assertEqual(probe.classify({'denied:initial_rx': receipt}, self.fixture),
                         'FAIL_EXECUTION_ALLOWED')
        self.assertEqual(probe.events(receipt, self.fixture), [])

    def test_malformed_control_tail_cannot_pass(self):
        receipts = self.matrix()
        receipts['control_after:r_to_rx']['stdout'] += '\n{"event":"res'
        self.assertEqual(probe.classify(receipts, self.fixture), 'INCONCLUSIVE')

    def test_signal_timeout_and_unconfirmed_cleanup_are_inconclusive(self):
        for change in ({'returncode': -11}, {'error': 'TimeoutError: child_deadline'},
                       {'cleanupConfirmed': False, 'cleanupError': 'unreaped'}):
            receipts = self.matrix()
            receipts['denied:initial_rx'].update(change)
            self.assertEqual(probe.classify(receipts, self.fixture), 'INCONCLUSIVE')

    def test_fixture_identity_is_required_for_execution_evidence(self):
        receipt = self.receipt(self.success('initial_rx'))
        self.assertFalse(probe.returned(receipt, 'initial_rx', {'identity': [], 'sha256': 'other'}))

    def test_environment_is_closed(self):
        with patch.dict(probe.os.environ, {'CLOSED_ENV_SENTINEL': 'sentinel-value', 'PYTHONPATH': '/untrusted'}, clear=True):
            self.assertEqual(probe.closed_environment(), {
                'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                'HOME': str(probe.ROOT), 'TMPDIR': str(probe.ROOT)})

    def test_host_gate_rejects_every_missing_required_identity(self):
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
               'GITHUB_REPOSITORY_ID': '1058277548', 'GITHUB_REPOSITORY': 'knitli/knitli-site',
               'GITHUB_WORKFLOW_REF': 'knitli/knitli-site/.github/workflows/hosted-map-execution-diagnostic.yml@refs/heads/main',
               'GITHUB_REF': 'refs/heads/main',
               'GITHUB_REF_PROTECTED': 'true', 'GITHUB_RUN_ATTEMPT': '1',
               'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64',
               'GITHUB_SHA': 'a' * 40, 'GITHUB_WORKFLOW_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123',
               'ImageOS': 'macos', 'ImageVersion': 'test'}
        with patch.object(probe.platform, 'system', return_value='Darwin'), \
                patch.object(probe.platform, 'machine', return_value='arm64'), \
                patch.object(probe.sys, 'version_info', (3, 13, 14)), \
                contextlib.ExitStack() as symbols:
            for name in ('waitid', 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT'):
                symbols.enter_context(patch.object(probe.os, name, Mock(), create=True))
            probe.admit(env)
            for key in env:
                with self.subTest(key=key):
                    bad = dict(env)
                    del bad[key]
                    with self.assertRaises(ValueError):
                        probe.admit(bad)
            with patch.object(probe.platform, 'machine', return_value='x86_64'):
                with self.assertRaisesRegex(ValueError, 'runtime_identity'):
                    probe.admit(env)

    def test_cleanup_live_child_killed_and_reaped(self):
        process = Mock(returncode=None)
        with patch.object(probe, 'unreaped_exit', return_value=None), \
                patch.object(probe.time, 'monotonic', return_value=10):
            probe.cleanup_child(process, 12)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=2)

    def test_cleanup_exited_unreaped_child_only_reaped(self):
        process = Mock(returncode=None)
        with patch.object(probe, 'unreaped_exit', return_value=object()), \
                patch.object(probe.time, 'monotonic', return_value=10):
            probe.cleanup_child(process, 12)
        process.kill.assert_not_called()
        process.wait.assert_called_once_with(timeout=2)

    def test_cleanup_ownership_probe_error_still_reaps_and_raises(self):
        process = Mock(returncode=None)
        with patch.object(probe, 'unreaped_exit', side_effect=ValueError('ownership')), \
                patch.object(probe.time, 'monotonic', return_value=10):
            with self.assertRaisesRegex(RuntimeError, 'signal: ValueError: ownership'):
                probe.cleanup_child(process, 12)
        process.kill.assert_not_called()
        process.wait.assert_called_once_with(timeout=2)

    def test_profiles_have_exact_single_denial_delta(self):
        profiles = probe.profiles()
        self.assertEqual(set(profiles), set(probe.PROFILES))
        self.assertEqual(profiles['control_before'], profiles['control_after'])
        delta = '(deny file-map-executable (literal ' + json.dumps(str(probe.ROOT / 'mapping-data')) + '))\n'
        self.assertEqual(profiles['denied'], profiles['control_before'] + delta)

    def test_arbitrary_command_rejected_before_spawn(self):
        with patch.object(probe.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, 'command_not_fixed'):
                probe.bounded(['/bin/sh'])
            spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
