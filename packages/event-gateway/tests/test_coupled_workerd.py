"""Focused checks load harness definitions without launching its disposable services."""
import asyncio
import importlib.util
from pathlib import Path
import subprocess  # nosec B404 - Fixed interpreter runs only the repository harness parser.
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


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
            (("--restart-inflight",), "requires --restart-native"),
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

    def test_default_restart_releases_response_and_waits_for_idle_before_stop(self):
        from contextlib import ExitStack, nullcontext
        import threading

        model = SimpleNamespace(release_primary=threading.Event(), request_counts={'primary': 1})
        old = SimpleNamespace(pid=101, args=['codex', '-C', '/fixture'], poll=lambda: None)
        receipt = {'status': 'inputRecorded'}
        bridge = Mock()
        bridge.receipt.return_value = receipt
        idle_checks = []

        def challenge():
            self.assertTrue(model.release_primary.is_set(), 'default response not released')
            idle_checks.append(True)
            return {'eligible': len(idle_checks) == 2}

        def stop(*_):
            self.assertEqual(len(idle_checks), 2, 'default did not wait for idle')
            self.assertTrue(model.release_primary.is_set())
            old.poll = lambda: 0

        bridge.challenge.side_effect = challenge
        replacement = Mock()
        launcher = SimpleNamespace(stop_process=stop, native_client=Mock(
            return_value=nullcontext((replacement, SimpleNamespace(pid=102), {'backendPid': 202}))))
        with ExitStack() as resources, patch.object(COUPLED, 'verify_native_restart'), \
                patch.object(COUPLED.time, 'time_ns', return_value=2000000):
            result = asyncio.run(COUPLED.restart_native(
                bridge, model, old, {'backendPid': 201}, launcher, resources,
                {'receiptVersion': 3, 'permitExpiresAt': 1}))
        self.assertIs(result[0], replacement)
        self.assertIs(result[-1], receipt)
        bridge.close.assert_called_once()
        launcher.native_client.assert_called_once_with(old.args, Path('/fixture'), receipt_version=3)

    def test_inflight_restart_stops_backend_before_releasing_model(self):
        from contextlib import ExitStack, nullcontext
        import threading

        events = []
        model = SimpleNamespace(release_primary=threading.Event(), request_counts={'primary': 1},
                                primary_response_state='held', primary_response_deadline=float('inf'))
        old = SimpleNamespace(pid=101, args=['codex', '-C', '/fixture'], poll=lambda: None)
        new = SimpleNamespace(pid=102)
        witness = {'backendPid': 201}
        receipt = {'status': 'inputRecorded'}
        bridge = Mock()
        bridge.receipt.return_value = receipt
        bridge.challenge.side_effect = AssertionError('must not wait for idle')

        def stop(*_):
            self.assertFalse(model.release_primary.is_set())
            events.append('stop')
            old.poll = lambda: 0

        def start(*_, **kwargs):
            self.assertTrue(model.release_primary.is_set())
            events.append('start')
            return nullcontext((Mock(), new, {'backendPid': 202}))

        launcher = SimpleNamespace(stop_process=stop, native_client=start, alive=lambda _: False)
        with ExitStack() as resources, patch.object(COUPLED, 'verify_native_restart'), \
                patch.object(COUPLED.time, 'time_ns', return_value=2000000):
            result = asyncio.run(COUPLED.restart_native(
                bridge, model, old, witness, launcher, resources,
                {'receiptVersion': 3, 'permitExpiresAt': 1}, inflight=True))
        self.assertEqual(events, ['stop', 'start'])
        self.assertIs(result[-1], receipt)
        bridge.challenge.assert_not_called()

    def test_inflight_restart_refuses_released_response_or_surviving_backend(self):
        import threading

        for released, backend_alive in ((True, False), (False, True)):
            with self.subTest(released=released, backend_alive=backend_alive):
                model = SimpleNamespace(release_primary=threading.Event(), request_counts={'primary': 1},
                                primary_response_state='held', primary_response_deadline=float('inf'))
                if released:
                    model.release_primary.set()
                old = SimpleNamespace(pid=101, args=['codex', '-C', '/fixture'], poll=lambda: None)
                bridge = Mock()
                bridge.receipt.return_value = {'status': 'inputRecorded'}
                launcher = Mock()
                launcher.alive.return_value = backend_alive
                launcher.stop_process.side_effect = lambda *_: setattr(old, 'poll', lambda: 0)
                resources = Mock()
                with patch.object(COUPLED.time, 'time_ns', return_value=2000000), \
                        self.assertRaisesRegex(AssertionError, 'held primary response|primary response must remain held|stop before releasing'):
                    asyncio.run(COUPLED.restart_native(
                        bridge, model, old, {'backendPid': 201}, launcher, resources,
                        {'receiptVersion': 3, 'permitExpiresAt': 1}, inflight=True))
                launcher.native_client.assert_not_called()
                resources.enter_context.assert_not_called()
                if not released:
                    self.assertFalse(model.release_primary.is_set())

    def test_inflight_restart_rejects_timeout_or_response_before_or_during_stop(self):
        from contextlib import ExitStack, nullcontext
        import threading

        for response_state in ('timed_out', 'responding', 'sent', 'deadline_expired'):
            for during_stop in (False, True):
                with self.subTest(response_state=response_state, during_stop=during_stop):
                    model = SimpleNamespace(release_primary=threading.Event(), request_counts={'primary': 1},
                                            primary_response_state='held', primary_response_deadline=float('inf'))
                    old = SimpleNamespace(pid=101, args=['codex', '-C', '/fixture'], poll=lambda: None)
                    bridge = Mock()
                    bridge.receipt.return_value = {'status': 'inputRecorded'}
                    launcher = Mock()
                    launcher.alive.return_value = False

                    def expire():
                        if response_state == 'deadline_expired':
                            model.primary_response_deadline = 0
                        else:
                            model.primary_response_state = response_state

                    def stop(*_):
                        old.poll = lambda: 0
                        if during_stop:
                            expire()

                    launcher.stop_process.side_effect = stop
                    launcher.native_client.return_value = nullcontext((Mock(), Mock(), {}))
                    if not during_stop:
                        expire()
                    with ExitStack() as resources, patch.object(COUPLED, 'verify_native_restart'), \
                            patch.object(COUPLED.time, 'time_ns', return_value=2000000), \
                            self.assertRaisesRegex(AssertionError, 'primary response.*held'):
                        asyncio.run(COUPLED.restart_native(
                            bridge, model, old, {'backendPid': 201}, launcher, resources,
                            {'receiptVersion': 3, 'permitExpiresAt': 1}, inflight=True))
                    launcher.native_client.assert_not_called()
                    self.assertFalse(model.release_primary.is_set())
                    self.assertEqual(launcher.stop_process.call_count, int(during_stop))

    def test_observed_recovery_requires_immutable_ack_watermark_and_released_capacity(self):
        import copy
        import json

        ack = {'status': 'observed', 'attemptId': 'original'}
        original = {'native_observed_ack': ack}
        envelope = {'sourceStateVersion': 'current'}
        settled = {'slots': [], 'budget': {'used': 1}, 'cloud': {
            'slot_intents': [], 'attempts': [{'state': 'observed', 'native_observed_ack_json': json.dumps(ack)}],
            'deliveries': [{'state': 'observed'}], 'native_claims': [{'state': 'observed'}],
            'manual_sources': [{'observed_source_state_version': 'current'}]}}
        COUPLED.require_observed_settlement(settled, original, envelope)
        mutations = (
            (lambda x: x.update(slots=[{}]), 'real slot drained'),
            (lambda x: x['cloud'].update(slot_intents=[{}]), 'real slot drained'),
            (lambda x: x['cloud']['attempts'][0].update(native_observed_ack_json='{}'), 'immutable cloud ACK'),
            (lambda x: x['cloud']['manual_sources'][0].update(observed_source_state_version='stale'), 'current watermark'),
            (lambda x: x['budget'].update(used=2), 'one fixture authority charge'),
        )
        for change, message in mutations:
            with self.subTest(message=message), self.assertRaisesRegex(AssertionError, message):
                altered = copy.deepcopy(settled)
                change(altered)
                COUPLED.require_observed_settlement(altered, original, envelope)
        for table in ('attempts', 'deliveries', 'native_claims'):
            with self.subTest(table=table), self.assertRaisesRegex(AssertionError, 'actual observed ' + table):
                altered = copy.deepcopy(settled)
                altered['cloud'][table][0]['state'] = 'submitted'
                COUPLED.require_observed_settlement(altered, original, envelope)

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
    def test_delivery_identity_and_signed_audience_match_actual_admission(self):
        # EventEnvelopeSchema has no nodeId: the signed audience carries it.
        envelope = {'runtimeId': 'runtime', 'runtimeGeneration': 2,
                    'nodeGeneration': 3, 'attachmentGeneration': 4}
        attached = {**envelope, 'nodeId': 'node'}
        signed = {'headers': {'x-event-audience': 'node'}}
        COUPLED.require_admitted_delivery(envelope, signed, attached, 'node')
        for key in envelope:
            with self.subTest(key=key), self.assertRaisesRegex(AssertionError, 'admitted identity'):
                COUPLED.require_admitted_delivery({**envelope, key: 'mismatch'}, signed, attached, 'node')
        for wrong_attached, wrong_signed in (
            ({**attached, 'nodeId': 'other'}, signed),
            (attached, {'headers': {'x-event-audience': 'other'}}),
        ):
            with self.subTest(attached=wrong_attached, signed=wrong_signed), \
                    self.assertRaisesRegex(AssertionError, 'admitted node'):
                COUPLED.require_admitted_delivery(envelope, wrong_signed, wrong_attached, 'node')

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

    def test_successful_installed_preflight_precedes_imports_and_retains_provenance(self):
        import builtins

        spec = importlib.util.spec_from_file_location('configured_coupled', HARNESS)
        configured = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(configured)
        package = HARNESS.parents[2]
        parsed = SimpleNamespace(package=str(package), qualifier=str(HARNESS),
            binary=sys.executable, binary_sha='0' * 64, node=sys.executable,
            output=str(package / 'unused-proof.json'), installed=True)
        events = []
        provenance = {'verified': 'wheel'}
        checks = SimpleNamespace(
            verified_python=Mock(side_effect=lambda: events.append('python')),
            verify_installed=Mock(side_effect=lambda _: events.append('wheel') or provenance),
            verified_executable=Mock(side_effect=lambda path: events.append('executable') or str(path)))
        original_import = builtins.__import__

        def record_import(name, *args, **kwargs):
            if name == 'event_gateway' or name.startswith('event_gateway.'):
                self.assertEqual(events[:4], ['python', 'wheel', 'executable', 'executable'])
                events.append('import')
            return original_import(name, *args, **kwargs)

        with patch.object(configured, 'load_module', return_value=checks), \
                patch('builtins.__import__', record_import):
            configured.configure(parsed)
        checks.verify_installed.assert_called_once_with(package / 'src/event_gateway')
        self.assertIn('import', events)
        self.assertIs(parsed.provenance, provenance)
        self.assertIsNotNone(configured.Gateway)
        self.assertEqual(configured.PACKAGE, package)

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
        factory = Mock(return_value='model')
        launcher = SimpleNamespace(ThreadingHTTPServer=factory)
        with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
            with COUPLED.fixed_model_port(launcher, 49731):
                self.assertEqual(launcher.ThreadingHTTPServer(('127.0.0.1', 0), 'handler'), 'model')
                factory.assert_called_once_with(('127.0.0.1', 49731), 'handler')
                with self.assertRaisesRegex(AssertionError, 'unexpected native model listener'):
                    launcher.ThreadingHTTPServer(('127.0.0.2', 0), 'handler')
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
