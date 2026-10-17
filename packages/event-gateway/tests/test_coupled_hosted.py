"""Hosted adapter checks; all process and kernel operations are mocked."""
from contextlib import nullcontext, redirect_stderr
from io import StringIO
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

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
        with patch.object(FIXTURE, 'args', SimpleNamespace(trusted_hosted_vm=True)), \
                patch.object(FIXTURE, 'hosted_guard', side_effect=[{}, {}, AssertionError('no sandbox')]) as guard:
            with FIXTURE.hosted_native_launches(launcher):
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

    def test_default_launch_is_unchanged_and_restoration_survives_exception(self):
        original = Mock()
        launcher = SimpleNamespace(native_client=original)
        with patch.object(FIXTURE, 'args', SimpleNamespace(trusted_hosted_vm=False)), \
                patch.object(FIXTURE, 'hosted_guard') as guard:
            with FIXTURE.hosted_native_launches(launcher):
                self.assertIs(launcher.native_client, original)
            guard.assert_not_called()
        with patch.object(FIXTURE, 'args', SimpleNamespace(trusted_hosted_vm=True)):
            with self.assertRaises(ValueError):
                with FIXTURE.hosted_native_launches(launcher):
                    raise ValueError('fixture failure')
            self.assertIs(launcher.native_client, original)


if __name__ == '__main__':
    unittest.main()
