"""Mock-only diagnostic tests: no subprocess, native mapping, or function execution."""
import builtins
import contextlib
import ctypes
import copy
import errno
import hashlib
import json
import importlib.util
import io
import itertools
import sys
import runpy
from pathlib import Path
import tempfile
import types
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
    def test_site_marker_is_sys_only_and_darwin_only(self):
        original_import = builtins.__import__

        def sys_only(name, global_ns=None, *args, **kwargs):
            if global_ns and global_ns.get('__name__') == '__main__' and name != 'sys':
                raise ImportError('marker must exit before other imports')
            return original_import(name, global_ns, *args, **kwargs)

        for host, argv, expected in [('darwin', ['--startup-marker'], 'startup:site_startup_marker\n'),
                                     ('linux', ['--startup-marker'], ''),
                                     ('darwin', ['--startup-marker', 'extra'], 'startup:script_entry\n')]:
            output = io.StringIO()
            with self.subTest(host=host, argv=argv), patch.object(sys, 'platform', host), \
                    patch.object(sys, 'argv', ['child', *argv]), contextlib.redirect_stderr(output), \
                    patch.object(builtins, '__import__', side_effect=sys_only):
                with self.assertRaises((SystemExit, ImportError)) as stopped:
                    runpy.run_path(str(BASE / 'hosted_map_execution_child.py'), run_name='__main__')
            self.assertEqual(output.getvalue(), expected)
            if host == 'darwin' and argv == ['--startup-marker']:
                self.assertIsInstance(stopped.exception, SystemExit)
                self.assertEqual(stopped.exception.code, 0)

    def test_read_observer_never_accesses_native_mapping(self):
        libc = Mock()
        with patch.object(child.ctypes, 'CFUNCTYPE') as cfun, patch.object(child.ctypes, 'set_errno') as set_errno:
            self.assertEqual(child.observe(7, 'read', libc), {'stage': 'read', 'status': 0, 'errno': 0})
        self.assertEqual(libc.mock_calls, [])
        cfun.assert_not_called()
        set_errno.assert_not_called()

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
        with patch.object(builtins, '__import__', side_effect=fail_ctypes), \
                contextlib.redirect_stderr(output):
            with self.assertRaisesRegex(ImportError, 'mock ctypes'):
                runpy.run_path(str(BASE / 'hosted_map_execution_child.py'), run_name='__main__')
        self.assertEqual(output.getvalue(), 'startup:script_entry\n')

    def test_control_read_never_loads_libc_or_maps_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'mapping-data'
            path.write_bytes(child.DATA)
            path.chmod(0o600)
            for entrypoint in ('direct', 'script'):
                with self.subTest(entrypoint=entrypoint):
                    output, diagnostics = io.StringIO(), io.StringIO()
                    with patch.object(child.sys, 'argv', ['child.py', '--child', 'read']), \
                            patch.object(child.sys, 'platform', 'darwin'), \
                            patch.object(child.platform, 'machine', return_value='arm64'), \
                            patch.object(child.resource, 'setrlimit'), \
                            patch.object(child.Path, 'cwd', return_value=root), \
                            patch.object(child.ctypes, 'CDLL', side_effect=AssertionError('no native loader')), \
                            patch.object(child, 'observe', wraps=child.observe) as observer, \
                            contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostics):
                        if entrypoint == 'direct':
                            child.main()
                        else:
                            runpy.run_path(str(BASE / 'hosted_map_execution_child.py'), run_name='__main__')
                    if entrypoint == 'direct':
                        observer.assert_called_once()
                        self.assertEqual(observer.call_args.args[1:], ('read', None))
                    phases = probe.STARTUP_PHASES[3:] if entrypoint == 'direct' else probe.STARTUP_PHASES
                    self.assertEqual(diagnostics.getvalue(), ''.join('startup:' + phase + '\n' for phase in phases))
                    values = [json.loads(line) for line in output.getvalue().splitlines()]
                    self.assertEqual(values[-1], {'event': 'result', 'stage': 'read', 'status': 0, 'errno': 0})
                    self.assertEqual(path.read_bytes(), child.DATA)

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

    def test_site_startup_fixed_cases_and_no_default_widening(self):
        prefix = [probe.SANDBOX, '-f', str(probe.ROOT / 'control_before.sb'), probe.SAFE_PY, '-I', '-B']
        self.assertEqual(probe.site_startup_cases(), [
            ('site_startup:version', prefix + ['--version']),
            ('site_startup:enabled', prefix + [str(probe.CHILD), '--startup-marker']),
            ('site_startup:disabled', prefix + ['-S', str(probe.CHILD), '--startup-marker'])])
        self.assertEqual(len(probe.fixture_cases()), 18)
        self.assertEqual(len(probe.fixture_cases(True)), 1)
        with patch.object(probe, 'run', return_value=1) as run:
            self.assertEqual(probe.main(['--site-startup-only']), 1)
            run.assert_called_once_with(site_startup_only=True)
        for argv in (['--site-startup-only', 'extra'], ['--site-startup-only', '--go']):
            with self.assertRaises(SystemExit):
                probe.main(argv)
        with patch.object(probe.subprocess, 'Popen', side_effect=AssertionError('mock launch boundary')) as launch:
            for _, argv in probe.site_startup_cases():
                with self.assertRaisesRegex(AssertionError, 'mock launch boundary'):
                    probe.bounded(argv)
            self.assertEqual(launch.call_count, 3)
            for _, argv in probe.site_startup_cases():
                with self.assertRaisesRegex(ValueError, 'command_not_fixed'):
                    probe.bounded(argv + ['extra'])
            self.assertEqual(launch.call_count, 3)

    def assert_diagnostic_outcomes_and_cleanup(self, mode, cases, successful_outputs):
        for codes in itertools.product((0, -6), repeat=len(successful_outputs)):
            for unknown_cleanup in (None, *range(len(successful_outputs))):
                with self.subTest(codes=codes, unknown_cleanup=unknown_cleanup), tempfile.TemporaryDirectory() as directory:
                    env = {key: 'fixed' for key in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion')}
                    env['RUNNER_TEMP'] = str(Path(directory).resolve())
                    receipts = [dict(self.receipt([]), returncode=code,
                                     stdout=successful_outputs[index][0] if code == 0 else '',
                                     stderr=successful_outputs[index][1] if code == 0 else '',
                                     cleanupConfirmed=index != unknown_cleanup) for index, code in enumerate(codes)]
                    with patch.dict(probe.os.environ, env, clear=True), \
                            patch.object(probe, 'ROOT', probe.ROOT), patch.object(probe, 'ENV', {}), \
                            patch.object(probe, 'admit'), patch.object(probe, 'file_record', return_value=self.fixture), \
                            patch.object(probe, 'tool_ancestry', return_value=[]), \
                            patch.object(probe, 'bounded', side_effect=receipts) as bounded, \
                            patch.object(probe, 'crash_baseline', return_value=None) as baseline, \
                            patch.object(probe, 'classify', side_effect=AssertionError('diagnostic mode must not classify matrix')), \
                            patch.object(probe.subprocess, 'Popen', side_effect=AssertionError('no actual execution')):
                        self.assertEqual(probe.run(**{mode: True}), 1)
                        count = len(successful_outputs) if unknown_cleanup is None else unknown_cleanup + 1
                        self.assertEqual(bounded.call_count, count)
                        expected_kwargs = {'observe_launch': True} if mode == 'version_launch_only' else {}
                        self.assertEqual([call.kwargs for call in bounded.call_args_list], [expected_kwargs] * count)
                        if mode == 'version_launch_only':
                            baseline.assert_called_once_with('', probe.os.getuid())
                        else:
                            baseline.assert_not_called()
                        self.assertEqual([call.args[0] for call in bounded.call_args_list],
                                         [argv for _, argv in cases()][:count])
                        result = json.loads((probe.ROOT / 'result.json').read_text())
                        self.assertEqual(list(result['receipts']), [name for name, _ in cases()][:count])
                        self.assertEqual(list(result['receipts'].values()), receipts[:count])
                        self.assertIsNone(result['error'])
                        self.assertEqual(result['status'], 'INCONCLUSIVE')
                        self.assertIs(result['qualified'], False)
                        self.assertTrue(result['fixtureRemoved'])

    def test_site_startup_all_outcomes_and_cleanup_stop(self):
        self.assert_diagnostic_outcomes_and_cleanup('site_startup_only', probe.site_startup_cases,
                                                   [('Python 3.13.14\n', ''), ('', 'startup:site_startup_marker\n'),
                                                    ('', 'startup:site_startup_marker\n')])

    def test_version_launch_all_outcomes_and_cleanup_stop(self):
        self.assert_diagnostic_outcomes_and_cleanup('version_launch_only', probe.version_launch_cases,
                                                   [('Python 3.13.14\n', ''), ('Python 3.13.14\n', '')])

    def test_version_launch_malformed_output_never_promotes_success(self):
        self.assert_diagnostic_outcomes_and_cleanup('version_launch_only', probe.version_launch_cases,
                                                   [('SYSCALL_AND_CONTROL_MATRIX_PASS\n', 'unexpected stderr\n'),
                                                    ('wrong interpreter version\n', 'PASS\n')])

    def test_version_launch_fixed_boundary(self):
        cases = probe.version_launch_cases()
        self.assertEqual(cases, [
            ('version_launch:direct', [probe.SAFE_PY, '-I', '-B', '--version']),
            ('version_launch:sandboxed', probe.site_startup_cases()[0][1])])
        with patch.object(probe, 'run', return_value=1) as run:
            self.assertEqual(probe.main(['--version-launch-only']), 1)
            run.assert_called_once_with(version_launch_only=True)
        self.assertEqual(probe.attempt_cases(False, False, False), probe.fixture_cases())
        self.assertEqual(probe.attempt_cases(True, False, False), probe.fixture_cases(True))
        self.assertEqual(probe.attempt_cases(False, True, False), probe.site_startup_cases())
        self.assertEqual(probe.attempt_cases(False, False, True), cases)
        environment = probe.closed_environment()
        self.assertEqual(environment, {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                                       'HOME': str(probe.ROOT), 'TMPDIR': str(probe.ROOT)})
        with patch.object(probe, 'ENV', environment), \
                patch.object(probe.subprocess, 'Popen', side_effect=AssertionError('mock launch boundary')) as launch:
            for _, argv in cases:
                with self.assertRaisesRegex(AssertionError, 'mock launch boundary'):
                    probe.bounded(argv)
                launch.assert_called_with(argv, cwd=probe.ROOT, env=environment, stdin=probe.subprocess.DEVNULL,
                                          stdout=probe.subprocess.PIPE, stderr=probe.subprocess.PIPE,
                                          start_new_session=True, close_fds=True)
            for argv in ([probe.SAFE_PY, '-I', '-B', str(probe.CHILD)],
                         [probe.SAFE_PY, '-I', '-B', '-c', 'pass'],
                         cases[0][1] + ['extra'], cases[1][1] + ['extra']):
                with self.assertRaisesRegex(ValueError, 'command_not_fixed'):
                    probe.bounded(argv)
            self.assertEqual(launch.call_count, 2)
        for argv in (['--version-launch-only', 'extra'], ['--version-launch-only', '--go']):
            with self.assertRaises(SystemExit):
                probe.main(argv)

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
        root_read = '(allow file-read-data (literal "/"))'
        for content in profiles.values():
            self.assertEqual(content.splitlines().count(root_read), 1)
            self.assertNotIn('(allow file-read-data (subpath "/"))', content)
            self.assertNotIn('(allow file-read* (literal "/"))', content)
            self.assertNotIn('(allow file-read* (subpath "/"))', content)
        delta = '(deny file-map-executable (literal ' + json.dumps(str(probe.ROOT / 'mapping-data')) + '))\n'
        self.assertEqual(profiles['denied'], profiles['control_before'] + delta)

    def test_arbitrary_command_rejected_before_spawn(self):
        with patch.object(probe.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, 'command_not_fixed'):
                probe.bounded(['/bin/sh'])
            spawn.assert_not_called()


class CrashObservationTests(unittest.TestCase):
    incident = '12345678-1234-4234-8234-123456789abc'
    filename = 'Python-2026-10-18-010001.ips'

    def setUp(self):
        self.production_identity = probe.identity

        def fixture_identity(info):
            if not hasattr(info, 'st_flags'):
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                info = types.SimpleNamespace(**fields, st_flags=0)
            return self.production_identity(info)

        identity_patch = patch.object(probe, 'identity', side_effect=fixture_identity)
        identity_patch.start()
        self.addCleanup(identity_patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.folder = self.home / 'Library/Logs/DiagnosticReports'
        self.folder.mkdir(parents=True)
        self.uid = probe.os.getuid()
        self.receipt = {'returncode': -6, 'cleanupConfirmed': True,
                        'argv': probe.version_launch_cases()[0][1],
                        'launch': {'pid': 1234, 'parentPid': 123, 'uid': self.uid,
                                   'launchUtc': 1792285200.0, 'exitUtc': 1792285202.0,
                                   'launchMonotonic': 100.0, 'exitMonotonic': 102.0}}
        self.header = {'bug_type': '309', 'incident_id': self.incident}
        self.body = {'incident': self.incident, 'pid': 1234, 'parentPid': 123,
                     'procPath': probe.SAFE_PY, 'procName': 'Python', 'userID': self.uid,
                     'procLaunch': '2026-10-18 01:00:00.500 +0000',
                     'captureTime': '2026-10-18 01:00:01.500 +0000',
                     'termination': {'namespace': 'SIGNAL', 'code': 6},
                     'threads': [{'redactionSentinel': 'MUST_NOT_EXPORT'}], 'private': 'MUST_NOT_EXPORT'}

    def test_stat_fixture_preserves_flags_and_normalizes_only_absent_flags(self):
        fields = {'st_dev': 1, 'st_ino': 2, 'st_mode': 33152, 'st_uid': 501, 'st_gid': 20,
                  'st_size': 64, 'st_mtime_ns': 100, 'st_ctime_ns': 101}
        missing_flags = types.SimpleNamespace(**fields)
        with self.assertRaises(AttributeError):
            self.production_identity(missing_flags)
        self.assertEqual(probe.identity(missing_flags), [1, 2, 33152, 501, 20, 0, 64, 100, 101])
        for flags in (0, 64):
            info = types.SimpleNamespace(**fields, st_flags=flags)
            self.assertEqual(probe.identity(info), self.production_identity(info))
            self.assertEqual(probe.identity(info)[5], flags)
        del fields['st_ino']
        with self.assertRaises(AttributeError):
            probe.identity(types.SimpleNamespace(**fields))

    def raw(self, header=None, body=None):
        return (json.dumps(self.header if header is None else header) + '\n'
                + json.dumps(self.body if body is None else body)).encode()

    def assert_rejected(self, raw, receipt=None):
        try:
            observed = probe.crash_match(raw, self.receipt if receipt is None else receipt, self.uid)
        except ValueError:
            return
        self.assertIsNone(observed)

    def test_crash_match_exact_sanitized_provenance(self):
        for path, name, expected in ((probe.SAFE_PY, 'Python', 'python'),
                                     (probe.SAFE_PY, 'python3.13', 'python'),
                                     (probe.SANDBOX, 'sandbox-exec', 'sandbox-exec')):
            raw = self.raw(body={**self.body, 'procPath': path, 'procName': name})
            receipt = {**self.receipt, 'argv': probe.version_launch_cases()[1 if path == probe.SANDBOX else 0][1]}
            incident, result = probe.crash_match(raw, receipt, self.uid)
            self.assertEqual(incident, self.incident)
            self.assertEqual(result, {'status': 'matched', 'executableClass': expected,
                                     'terminationNamespace': 'SIGNAL', 'terminationCode': 6,
                                     'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
            self.assertNotIn('MUST_NOT_EXPORT', json.dumps(result))
        self.assertIsNotNone(probe.crash_match(self.raw(body={k: v for k, v in self.body.items() if k != 'userID'}),
                                              self.receipt, self.uid))

    def test_crash_match_direct_cannot_claim_launcher(self):
        raw = self.raw(body={**self.body, 'procPath': probe.SANDBOX, 'procName': 'sandbox-exec'})
        self.assert_rejected(raw)
        for argv in ([], self.receipt['argv'] + ['extra'], [probe.SAFE_PY, '-c', 'pass']):
            self.assert_rejected(self.raw(), {**self.receipt, 'argv': argv})

    def test_bounded_launch_observation_is_parent_owned(self):
        process = Mock(pid=1234, returncode=-6)
        selector = Mock()
        selector.get_map.return_value = {}
        with patch.object(probe.subprocess, 'Popen', return_value=process), \
                patch.object(probe.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(probe.os, 'set_blocking'), patch.object(probe, 'unreaped_exit', return_value=object()), \
                patch.object(probe, 'cleanup_child') as cleanup, patch.object(probe.os, 'getpid', return_value=123), \
                patch.object(probe.os, 'getuid', return_value=501), patch.object(probe.time, 'time', side_effect=[1000, 1002]), \
                patch.object(probe.time, 'monotonic', side_effect=[100, 101, 103]):
            receipt = probe.bounded(probe.version_launch_cases()[0][1], observe_launch=True)
        self.assertEqual(receipt['launch'], {'pid': 1234, 'parentPid': 123, 'uid': 501,
                                           'launchUtc': 1000, 'exitUtc': 1002,
                                           'launchMonotonic': 101, 'exitMonotonic': 103})
        self.assertTrue(receipt['cleanupConfirmed'])
        cleanup.assert_called_once_with(process, 110)

    def test_crash_match_rejects_identity_schema_and_clock_mismatch(self):
        changes = [('pid', 999), ('pid', True), ('parentPid', 999), ('parentPid', '123'),
                   ('procPath', '/untrusted/python'), ('procName', 'unrelated'), ('userID', self.uid + 1),
                   ('userID', True), ('incident', 'not-a-uuid'),
                   ('incident', '22345678-1234-4234-8234-123456789abc'),
                   ('procLaunch', '2026-10-18 00:59:59.999 +0000'),
                   ('captureTime', '2026-10-18 01:00:02.001 +0000'),
                   ('captureTime', '2026-10-18 01:00:00.001 +0000'),
                   ('termination', None), ('termination', {'namespace': 'SIGNAL', 'code': True}),
                   ('termination', {'namespace': 'SIGNAL', 'code': '6'})]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                self.assert_rejected(self.raw(body={**self.body, key: value}))
        for header in ({**self.header, 'bug_type': 309}, {**self.header, 'bug_type': '999'},
                       {**self.header, 'incident_id': 'not-a-uuid'}):
            self.assert_rejected(self.raw(header=header))
        for key, value in [('returncode', 0), ('cleanupConfirmed', False)]:
            self.assert_rejected(self.raw(), {**self.receipt, key: value})
        for key, value in [('pid', True), ('parentPid', True), ('uid', self.uid + 1),
                           ('exitMonotonic', 105.0), ('launchUtc', float('nan'))]:
            self.assert_rejected(self.raw(), {**self.receipt, 'launch': {**self.receipt['launch'], key: value}})

    def test_crash_match_rejects_noncanonical_json(self):
        raw = self.raw()
        for malformed in (b'', b'{}', raw + b'\n{}', raw + b' trailing',
                          raw.replace(b'"pid": 1234', b'"pid": 1234, "pid": 1234'),
                          raw.replace(b'"private": "MUST_NOT_EXPORT"', b'"private": NaN'),
                          raw.replace(b'"bug_type": "309"', b'"bug_type": "309", "bug_type": "309"')):
            with self.subTest(raw=malformed):
                self.assert_rejected(malformed)

    def collect(self, state, receipts=None):
        pair = {'version_launch:direct': self.receipt,
                'version_launch:sandboxed': {**self.receipt, 'returncode': 0}}
        with patch.object(probe.time, 'sleep') as sleep, patch.object(probe.time, 'monotonic', return_value=100):
            result = probe.crash_collect(state, pair if receipts is None else receipts)
        self.assertLessEqual(sleep.call_count, 1)
        if sleep.called:
            sleep.assert_called_once_with(29)
        return result

    def test_crash_collect_new_report_only_and_descriptor_closed(self):
        (self.folder / 'Python-2026-10-18-010000.ips').write_bytes(self.raw())
        state = probe.crash_baseline(str(self.home), self.uid)
        self.assertIsNotNone(state)
        descriptor = state['descriptor']
        (self.folder / self.filename).write_bytes(self.raw())
        result = self.collect(state)
        self.assertEqual(result['version_launch:direct']['status'], 'matched')
        self.assertEqual(result['version_launch:sandboxed'], {'status': 'unavailable'})
        with self.assertRaises(OSError):
            probe.os.fstat(descriptor)

    def test_crash_collect_caps_aliases_and_ambiguity(self):
        for case in ('symlink', 'hardlink', 'directory', 'oversize', 'too_many', 'aggregate', 'ambiguous', 'unrelated'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                home = Path(temp).resolve()
                folder = home / 'Library/Logs/DiagnosticReports'
                folder.mkdir(parents=True)
                state = probe.crash_baseline(str(home), self.uid)
                path = folder / self.filename
                if case == 'symlink':
                    target = home / 'target'
                    target.write_bytes(self.raw())
                    path.symlink_to(target)
                elif case == 'hardlink':
                    target = home / 'target'
                    target.write_bytes(self.raw())
                    probe.os.link(target, path)
                elif case == 'directory':
                    path.mkdir()
                elif case == 'oversize':
                    path.write_bytes(b'x' * (1024 * 1024 + 1))
                elif case == 'unrelated':
                    (folder / 'secret.ips').write_bytes(self.raw())
                else:
                    count = 5 if case == 'too_many' else 3 if case == 'aggregate' else 2
                    for index in range(count):
                        raw = self.raw(body={**self.body, 'private': 'x' * 800000}) if case == 'aggregate' else self.raw()
                        if case == 'ambiguous':
                            incident = f'{index + 1}2345678-1234-4234-8234-123456789abc'
                            raw = self.raw(header={**self.header, 'incident_id': incident}, body={**self.body, 'incident': incident})
                        (folder / f'Python-2026-10-18-01000{index}.ips').write_bytes(raw)
                self.assertEqual(self.collect(state)['version_launch:direct'], {'status': 'unavailable'})

    def test_crash_collect_rechecks_file_identity_and_owner(self):
        for change in ('owner', 'replaced', 'changed_after_read'):
            with self.subTest(change=change):
                path = self.folder / self.filename
                if path.exists():
                    path.unlink()
                state = probe.crash_baseline(str(self.home), self.uid)
                path.write_bytes(self.raw())
                real_stat = probe.os.stat
                real_fstat = probe.os.fstat
                calls = 0

                def changed_stat(*args, **kwargs):
                    nonlocal calls
                    value = real_stat(*args, **kwargs)
                    if kwargs.get('dir_fd') is not None:
                        calls += 1
                        if change == 'owner' or (change == 'replaced' and calls == 2):
                            fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
                            key = 'st_uid' if change == 'owner' else 'st_ino'
                            fields[key] += 1
                            return types.SimpleNamespace(**fields)
                    return value

                def changed_fstat(fd):
                    nonlocal calls
                    value = real_fstat(fd)
                    if fd != state['descriptor']:
                        calls += 1
                        if calls >= 3:
                            fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
                            fields['st_size'] += 1
                            return types.SimpleNamespace(**fields)
                    return value

                with patch.object(probe.os, 'stat', side_effect=changed_stat), \
                        patch.object(probe.os, 'fstat', side_effect=changed_fstat if change == 'changed_after_read' else real_fstat):
                    self.assertEqual(self.collect(state)['version_launch:direct'], {'status': 'unavailable'})

    def test_crash_collect_deadline_and_directory_replacement_reject(self):
        state = probe.crash_baseline(str(self.home), self.uid)
        (self.folder / self.filename).write_bytes(self.raw())
        pair = {key: self.receipt for key in ('version_launch:direct', 'version_launch:sandboxed')}
        with patch.object(probe.time, 'sleep'), patch.object(probe.time, 'monotonic', side_effect=[100, 130]):
            self.assertTrue(all(value == {'status': 'unavailable'} for value in probe.crash_collect(state, pair).values()))
        state = probe.crash_baseline(str(self.home), self.uid)
        self.folder.rename(self.folder.with_name('replaced'))
        self.folder.mkdir()
        (self.folder / self.filename).write_bytes(self.raw())
        self.assertEqual(self.collect(state)['version_launch:direct'], {'status': 'unavailable'})

    def test_crash_baseline_rejects_symlink_ancestor(self):
        with patch.object(probe.os, 'open') as opened:
            self.assertIsNone(probe.crash_baseline('/', self.uid))
            opened.assert_not_called()
        alias = self.home / 'alias'
        alias.symlink_to(self.home, target_is_directory=True)
        self.assertIsNone(probe.crash_baseline(str(alias), self.uid))

    def test_crash_baseline_rejects_wrong_home_owner(self):
        real_fstat = probe.os.fstat
        home_inode = self.home.stat().st_ino

        def wrong_owner(fd):
            value = real_fstat(fd)
            if value.st_ino == home_inode:
                fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
                fields['st_uid'] += 1
                return types.SimpleNamespace(**fields)
            return value

        with patch.object(probe.os, 'fstat', side_effect=wrong_owner):
            self.assertIsNone(probe.crash_baseline(str(self.home), self.uid))

    def test_crash_collect_rejects_post_read_entry_link_count(self):
        state = probe.crash_baseline(str(self.home), self.uid)
        (self.folder / self.filename).write_bytes(self.raw())
        real_stat = probe.os.stat
        calls = 0

        def changed_links(*args, **kwargs):
            nonlocal calls
            value = real_stat(*args, **kwargs)
            if kwargs.get('dir_fd') is not None:
                calls += 1
                if calls >= 2:
                    fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
                    fields['st_nlink'] = 2
                    return types.SimpleNamespace(**fields)
            return value

        with patch.object(probe.os, 'stat', side_effect=changed_links):
            self.assertEqual(self.collect(state)['version_launch:direct'], {'status': 'unavailable'})

    def test_crash_collect_close_failure_returns_unavailable(self):
        state = probe.crash_baseline(str(self.home), self.uid)
        (self.folder / self.filename).write_bytes(self.raw())
        real_close = probe.os.close

        def failed_close(fd):
            real_close(fd)
            if fd == state['descriptor']:
                raise OSError('synthetic directory close failure')

        with patch.object(probe.os, 'close', side_effect=failed_close):
            self.assertEqual(self.collect(state), {key: {'status': 'unavailable'} for key in probe.CRASH_CASES})

    def test_run_failure_paths_close_held_crash_descriptor(self):
        for failure in ('source_verification', 'spawn', 'fixture_cleanup', 'unexpected_cleanup', 'cancelled_cleanup'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                temp = Path(directory).resolve()
                state = probe.crash_baseline(str(self.home), self.uid)
                descriptor = state['descriptor']
                env = {key: 'fixed' for key in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion')}
                env.update(RUNNER_TEMP=str(temp), HOME=str(self.home))
                record = {'identity': [1, 2, 3], 'sha256': 'synthetic'}
                real_unlink = Path.unlink
                unexpected = (ValueError('synthetic unexpected cleanup') if failure == 'unexpected_cleanup'
                              else KeyboardInterrupt('synthetic cancellation') if failure == 'cancelled_cleanup' else None)

                def unlink(path, *args, **kwargs):
                    if unexpected is not None and path.name == 'mapping-data':
                        raise unexpected
                    if failure == 'fixture_cleanup' and path.name == 'mapping-data':
                        raise OSError('synthetic fixture cleanup failure')
                    return real_unlink(path, *args, **kwargs)

                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.dict(probe.os.environ, env, clear=True))
                    stack.enter_context(patch.object(probe, 'ROOT', probe.ROOT))
                    stack.enter_context(patch.object(probe, 'ENV', {}))
                    stack.enter_context(patch.object(probe, 'admit'))
                    baseline = stack.enter_context(patch.object(probe, 'crash_baseline', return_value=state))

                    def file_record(*args, **kwargs):
                        if failure == 'source_verification' and baseline.called:
                            raise ValueError('synthetic source verification failure')
                        return record

                    stack.enter_context(patch.object(probe, 'file_record', side_effect=file_record))
                    stack.enter_context(patch.object(probe, 'tool_ancestry', return_value=[]))
                    stack.enter_context(patch.object(Path, 'unlink', unlink))
                    stack.enter_context(patch.object(probe.time, 'sleep'))
                    spawn = stack.enter_context(patch.object(probe.subprocess, 'Popen', side_effect=OSError('synthetic spawn failure')))
                    if failure != 'spawn':
                        stack.enter_context(patch.object(probe, 'bounded', return_value=self.receipt))
                    collect = stack.enter_context(patch.object(probe, 'crash_collect', wraps=probe.crash_collect))
                    if unexpected is None:
                        self.assertEqual(probe.run(version_launch_only=True), 1)
                    else:
                        with self.assertRaises(type(unexpected)) as raised:
                            probe.run(version_launch_only=True)
                        self.assertIs(raised.exception, unexpected)
                        self.assertFalse((probe.ROOT / 'result.json').exists())
                    collect.assert_called_once()
                    self.assertIs(collect.call_args.args[0], state)
                    baseline.assert_called_once_with(str(self.home), self.uid)
                    if failure == 'spawn':
                        spawn.assert_called_once()
                    else:
                        spawn.assert_not_called()
                    result = json.loads((probe.ROOT / 'result.json').read_text()) if unexpected is None else None
                with self.assertRaises(OSError):
                    probe.os.fstat(descriptor)
                if unexpected is not None:
                    continue
                self.assertEqual(result['status'], 'INCONCLUSIVE')
                self.assertIs(result['qualified'], False)
                self.assertIn({'source_verification': 'synthetic source verification failure',
                               'spawn': 'synthetic spawn failure',
                               'fixture_cleanup': 'synthetic fixture cleanup failure'}[failure], result['error'])
                self.assertEqual(result['fixtureRemoved'], failure != 'fixture_cleanup')
                self.assertEqual(result['crashObservations'], {key: {'status': 'unavailable'} for key in probe.CRASH_CASES})

    def test_crash_collect_requires_both_cleanups_and_handles_no_baseline(self):
        self.assertEqual(self.collect(None), {key: {'status': 'unavailable'} for key in
                                             ('version_launch:direct', 'version_launch:sandboxed')})
        state = probe.crash_baseline(str(self.home), self.uid)
        (self.folder / self.filename).write_bytes(self.raw())
        pair = {'version_launch:direct': self.receipt,
                'version_launch:sandboxed': {**self.receipt, 'cleanupConfirmed': False}}
        self.assertEqual(self.collect(state, pair)['version_launch:direct'], {'status': 'unavailable'})
        self.assertIsNone(probe.crash_baseline(str(self.home / 'missing'), self.uid))


if __name__ == '__main__':
    unittest.main()
