"""Focused checks load harness definitions without launching its disposable services."""
import asyncio
import importlib.util
from pathlib import Path
import subprocess  # nosec B404 - Fixed interpreter runs only the repository harness parser.
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HARNESS = Path(__file__).resolve().parents[1] / "docs/native-bridge/coupled-workerd.py"
SPEC = importlib.util.spec_from_file_location("coupled_workerd", HARNESS)
COUPLED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COUPLED)


class CoupledWorkerdTests(unittest.TestCase):
    def test_conflicting_modes_rejected_before_artifact_resolution(self):
        required = [arg for name in ("package", "qualifier", "binary", "binary-sha", "node",
                                    "cloud-source", "esbuild", "miniflare", "output")
                    for arg in ("--" + name, "unresolved")]
        for flags, message in (
            (("--restart-native", "--terminal-no-start"), "are mutually exclusive"),
            (("--forget-terminal",), "requires --terminal-no-start"),
        ):
            with self.subTest(flags=flags):
                result = subprocess.run(  # nosec B603 - Fixed repository script and dummy args, no shell or user input.
                    [str(Path(sys.executable).resolve()), str(HARNESS), *required, *flags],
                    capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)
                self.assertNotIn("FileNotFoundError", result.stderr)

    def test_native_delay_is_bounded_and_requires_live_process(self):
        request = {"permitExpiresAt": 1000}

        async def cutoff(_):
            raise AssertionError("unbounded poll reached safety cutoff")

        for now, stopped in ((11, None), (1, 0)):
            with self.subTest(now=now, stopped=stopped):
                ticks = iter((0, now))
                with patch.object(COUPLED, "time", SimpleNamespace(monotonic=lambda: next(ticks), time_ns=lambda: 0)), \
                        patch.object(COUPLED, "asyncio", SimpleNamespace(sleep=cutoff)):
                    with self.assertRaisesRegex(AssertionError, "native delay fixture exceeded deadline or native process stopped"):
                        asyncio.run(COUPLED.wait_for_permit_expiry(request, SimpleNamespace(poll=lambda: stopped)))

    def test_restart_requires_death_and_every_identity_rotation(self):
        check = COUPLED.verify_native_restart
        witness = {key: i for i, key in enumerate(("clientId", "serverInstanceId", "backendPid", "threadId"))}
        new_witness = {key: value + 10 for key, value in witness.items()}
        old = SimpleNamespace(pid=1, poll=lambda: 0)
        new = SimpleNamespace(pid=2)
        launcher = SimpleNamespace(alive=lambda _: False)
        self.assertTrue(all(check(old, new, witness, new_witness, launcher).values()))
        for field in ("oldTui", "oldBackend", "pid", *witness):
            with self.subTest(field=field):
                changed = dict(new_witness)
                if field in witness:
                    changed[field] = witness[field]
                with self.assertRaisesRegex(AssertionError, "old native processes stopped and all restart identities rotated"):
                    check(SimpleNamespace(pid=1, poll=lambda: None if field == "oldTui" else 0),
                          SimpleNamespace(pid=1 if field == "pid" else 2), witness, changed,
                          SimpleNamespace(alive=lambda _: field == "oldBackend"))


class CoupledAdmissionTests(unittest.TestCase):
    def test_installed_preflight_runs_before_any_gateway_import(self):
        import builtins
        import runpy
        import tempfile

        original_import = builtins.__import__
        imported = []

        def guarded_import(name, *args, **kwargs):
            if name == 'event_gateway' or name.startswith('event_gateway.'):
                imported.append(name)
                raise AssertionError('gateway imported before installed preflight')
            return original_import(name, *args, **kwargs)

        # Non-isolated execution must fail at the shared interpreter check, even
        # when all executable and helper arguments resolve. Never starts children.
        with tempfile.TemporaryDirectory() as directory:
            values = {'package': directory, 'qualifier': str(HARNESS), 'binary': sys.executable,
                      'binary-sha': '0' * 64, 'node': sys.executable, 'cloud-source': directory,
                      'esbuild': directory, 'miniflare': directory, 'output': directory + '/proof.json'}
            argv = [str(HARNESS), '--installed', *[arg for name, value in values.items() for arg in ('--' + name, value)]]
            with patch.object(sys, 'argv', argv), patch('builtins.__import__', guarded_import), \
                    patch.object(sys, 'flags', SimpleNamespace(**{**{name: getattr(sys.flags, name)
                        for name in dir(sys.flags) if not name.startswith('_')}, 'isolated': 0})):
                with self.assertRaisesRegex(ValueError, 'qualification requires Python -I'):
                    runpy.run_path(str(HARNESS), run_name='__main__')
            self.assertEqual(imported, [])

    def test_fresh_native_witness_follows_cloud_challenge_and_precedes_attach(self):
        calls = []
        binding = {'threadId': 'selected'}
        evidence = {'observedAt': 'fresh', 'validUntilMonotonic': 123, 'witness': {'fresh': True}}

        class Native:
            def __init__(self, bridge):
                self.ready = False

            def binding(self):
                self.assert_ready()
                calls.append('binding')
                return binding

            def assert_ready(self):
                if not self.ready:
                    raise AssertionError('qualifier startup not acknowledged')

            def challenge(self, challenge_id, expected):
                self.assert_ready()
                self_test.assertEqual(calls, ['binding', 'cloud-challenge'])
                self_test.assertEqual((challenge_id, expected), ('issued', binding))
                calls.append('native-witness')
                return {'challengeId': challenge_id, **evidence}

        class Cloud:
            async def native_challenge(self, intent):
                self_test.assertEqual(intent, {'operation': 'attach', 'runtimeId': 'runtime',
                    'expectedRuntimeGeneration': None, 'expectedAttachmentGeneration': None,
                    'expectedNativeBinding': binding})
                calls.append('cloud-challenge')
                return {'challengeId': 'issued'}

            async def attach(self, intent, challenge, fresh):
                self_test.assertEqual(calls, ['binding', 'cloud-challenge', 'native-witness'])
                self_test.assertEqual(fresh, evidence)
                calls.append('attach')
                return {'status': 'attached'}

        self_test = self
        with patch.object(COUPLED, 'NativeClient', Native, create=True):
            result = asyncio.run(COUPLED.admit_runtime(Cloud(), object(), 'runtime'))
        self.assertEqual(calls, ['binding', 'cloud-challenge', 'native-witness', 'attach'])
        self.assertEqual(result['attached'], {'status': 'attached'})

    def test_model_listener_is_fixed_and_restored_on_failure(self):
        from unittest.mock import Mock
        factory = Mock(return_value='model')
        launcher = SimpleNamespace(ThreadingHTTPServer=factory)
        with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
            with COUPLED.fixed_model_port(launcher, 49731):
                self.assertEqual(launcher.ThreadingHTTPServer(('127.0.0.1', 0), 'handler'), 'model')
                factory.assert_called_once_with(('127.0.0.1', 49731), 'handler')
                with self.assertRaisesRegex(AssertionError, 'unexpected native model listener'):
                    launcher.ThreadingHTTPServer(('0.0.0.0', 0), 'handler')
                raise RuntimeError('fixture failure')
        self.assertIs(launcher.ThreadingHTTPServer, factory)

    def test_fixed_ports_fail_closed_before_artifacts(self):
        import io
        from contextlib import redirect_stderr
        required = [arg for name in ('package', 'qualifier', 'binary', 'binary-sha', 'node',
                                    'cloud-source', 'esbuild', 'miniflare', 'output')
                    for arg in ('--' + name, 'unresolved')]
        for options in (['--model-port', '0'], ['--entry-port', '49731'], ['--broker-port', '65536']):
            with self.subTest(options=options), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                COUPLED.inputs([*required, *options])
            self.assertEqual(error.exception.code, 2)
