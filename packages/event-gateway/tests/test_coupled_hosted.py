"""Hosted adapter checks; all process and kernel operations are mocked."""
from contextlib import nullcontext, redirect_stderr
from io import StringIO
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, mock_open, patch

PATH = Path(__file__).parents[1] / 'docs/native-bridge/coupled-workerd.py'
SPEC = importlib.util.spec_from_file_location('coupled_hosted', PATH)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class CoupledHostedTests(unittest.TestCase):
    def arguments(self):
        required = [arg for name in ('package', 'qualifier', 'binary', 'binary-sha', 'node',
                                    'cloud-source', 'esbuild', 'miniflare', 'output')
                    for arg in ('--' + name, 'unresolved')]
        return required + ['--installed', '--restart-native', '--restart-inflight', '--trusted-hosted-vm',
                           '--cloud-commit', 'a' * 40, '--model-port', '43125', '--entry-port', '43121',
                           '--loopback-port', '43122', '--broker-port', '43123']

    def test_hosted_mode_requires_exact_scope_before_resolution(self):
        argv = self.arguments()
        self.assertTrue(FIXTURE.inputs(argv).trusted_hosted_vm)
        for flag in ('--installed', '--restart-native', '--restart-inflight'):
            with self.subTest(flag=flag), redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                FIXTURE.inputs([value for value in argv if value != flag])
        for flag, invalid in (('--model-port', '43126'), ('--cloud-commit', 'bad')):
            changed = list(argv)
            changed[changed.index(flag) + 1] = invalid
            with self.subTest(flag=flag), redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                FIXTURE.inputs(changed)

    def test_optimized_hosted_execution_is_rejected(self):
        flags = SimpleNamespace(**{name: getattr(FIXTURE.sys.flags, name) for name in dir(FIXTURE.sys.flags)
                                   if not name.startswith('_') and not callable(getattr(FIXTURE.sys.flags, name))})
        flags.optimize = 1
        self.assertEqual(flags.ignore_environment, FIXTURE.sys.flags.ignore_environment)
        with patch.object(FIXTURE.sys, 'flags', flags), \
                redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            FIXTURE.inputs(self.arguments())

    def test_guard_before_every_native_launch_and_restore_after_failure(self):
        original = Mock(side_effect=lambda *a, **k: nullcontext('native'))
        launcher = SimpleNamespace(native_client=original)
        guard = Mock(side_effect=[{}, {}, AssertionError('no sandbox')])
        helper = SimpleNamespace(verify_trusted_hosted_network=guard)
        with patch.object(FIXTURE, 'args', SimpleNamespace(trusted_hosted_vm=True)):
            with FIXTURE.hosted_native_launches(launcher, helper):
                for _ in range(2):
                    with launcher.native_client(['codex'], Path('/synthetic'), receipt_version=3) as result:
                        self.assertEqual(result, 'native')
                with self.assertRaises(AssertionError):
                    with launcher.native_client(['codex'], Path('/synthetic')):
                        self.fail('native entered without containment')
            self.assertIs(launcher.native_client, original)
            self.assertEqual(guard.call_count, 3)
            self.assertEqual(original.call_count, 2)
            original.assert_called_with(['codex'], Path('/synthetic'), receipt_version=3)

    def test_main_loads_one_helper_and_checks_it_before_each_launch(self):
        events = []
        def guard():
            events.append('guard')
            if events.count('guard') == 4:
                raise AssertionError('containment changed')
            return {}
        helper = SimpleNamespace(verify_trusted_hosted_network=Mock(side_effect=guard),
                                 preflight_ports=Mock())
        def native(*values, **options):
            events.append('launch')
            return nullcontext('native')
        original = Mock(side_effect=native)
        launcher = SimpleNamespace(native_client=original, ThreadingHTTPServer=Mock())
        def qualify(*values, **options):
            for _ in range(3):
                with launcher.native_client():
                    pass
        launcher.qualify = Mock(side_effect=qualify)
        parsed = FIXTURE.inputs(self.arguments())
        for name in ('cloud_source', 'esbuild', 'miniflare'):
            setattr(parsed, name, str(PATH))
        broker = Mock()
        broker.stdout.readline.return_value = '{}'
        with patch.object(FIXTURE, 'args', parsed), \
                patch.object(FIXTURE, 'BINARY', SimpleNamespace(read_bytes=lambda: b'binary')), \
                patch.object(FIXTURE, 'BINARY_SHA', FIXTURE.hashlib.sha256(b'binary').hexdigest()), \
                patch.object(FIXTURE, 'load_module', side_effect=[helper, launcher]) as load, \
                patch('builtins.open', mock_open()), \
                patch.object(FIXTURE.subprocess, 'Popen', return_value=broker), \
                patch.object(FIXTURE.select, 'select', return_value=([broker.stdout], [], [])):
            with self.assertRaisesRegex(AssertionError, 'containment changed'):
                FIXTURE.main()
        self.assertEqual(load.call_count, 2)
        self.assertEqual(load.call_args_list[0].args,
                         ('coupled_hosted_guard', FIXTURE.HERE / 'three-session-workerd.py'))
        helper.preflight_ports.assert_called_once_with(parsed, ports=[43125, 43121, 43122, 43123])
        self.assertEqual(events, ['guard', 'guard', 'launch', 'guard', 'launch', 'guard'])
        self.assertIs(launcher.native_client, original)
        broker.terminate.assert_called_once()

    def test_shared_preflight_checks_exact_four_ports_and_rejects_faults(self):
        helper = FIXTURE.load_module('coupled_preflight_test', FIXTURE.HERE / 'three-session-workerd.py')
        parsed = FIXTURE.inputs(self.arguments())
        ports = [43125, 43121, 43122, 43123]
        with patch.object(helper, 'ephemeral_port_ranges', return_value=[(49152, 65535)]), \
                patch.object(helper, 'port_is_bindable', return_value=True) as probe:
            helper.preflight_ports(parsed, ports=ports)
            self.assertEqual([call.args[0] for call in probe.call_args_list], ports)
        for port in ports:
            with self.subTest(port=port), \
                    patch.object(helper, 'ephemeral_port_ranges', return_value=[(port, port)]), \
                    patch.object(helper, 'port_is_bindable') as probe:
                with self.assertRaisesRegex(AssertionError, 'ephemeral'):
                    helper.preflight_ports(parsed, ports=ports)
                probe.assert_not_called()
            with self.subTest(unavailable=port), \
                    patch.object(helper, 'ephemeral_port_ranges', return_value=[(49152, 65535)]), \
                    patch.object(helper, 'port_is_bindable', side_effect=lambda value: value != port):
                with self.assertRaisesRegex(AssertionError, 'unavailable'):
                    helper.preflight_ports(parsed, ports=ports)
        for invalid in ([43125] * 4, [True], [1023], [65536], ['43125'], [43125.0]):
            with self.subTest(invalid=invalid), patch.object(helper, 'port_is_bindable') as probe:
                with self.assertRaises(AssertionError):
                    helper.preflight_ports(parsed, ports=invalid)
                probe.assert_not_called()

    def test_default_launch_is_unchanged_and_restoration_survives_exception(self):
        original = Mock()
        launcher = SimpleNamespace(native_client=original)
        helper = SimpleNamespace(verify_trusted_hosted_network=Mock())
        with patch.object(FIXTURE, 'args', SimpleNamespace(trusted_hosted_vm=False)):
            with FIXTURE.hosted_native_launches(launcher, helper):
                self.assertIs(launcher.native_client, original)
            helper.verify_trusted_hosted_network.assert_not_called()
        with patch.object(FIXTURE, 'args', SimpleNamespace(trusted_hosted_vm=True)):
            with self.assertRaises(ValueError):
                with FIXTURE.hosted_native_launches(launcher, helper):
                    raise ValueError('fixture failure')
            self.assertIs(launcher.native_client, original)


if __name__ == '__main__':
    unittest.main()
