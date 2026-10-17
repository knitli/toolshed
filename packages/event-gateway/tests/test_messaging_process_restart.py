"""Opt-in SIGKILL/restart qualification across real Python, SQLite, HTTP and workerd."""
import asyncio
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import selectors
import shutil
import subprocess  # nosec B404 - Owned local Python child, fixed checked-in fixture, no shell.
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_messaging_workerd import (
    SETTINGS,
    _cleanup_fixture_process,
    _process_group_exists,
    _read_startup_handshake,
    fixture,
)

import test_messaging_workerd as workerd_fixture


CHILD = Path(__file__).parent / 'fixtures/messaging_process_child.py'


STDERR_LIMIT = 8000


def _drain_stderr(process, capture, stopped):
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            while not stopped.is_set():
                if not selector.select(0.05):
                    continue
                remaining = STDERR_LIMIT - len(capture['prefix'])
                chunk = os.read(process.stderr.fileno(), min(4096, remaining + 1))
                if not chunk:
                    return
                capture['prefix'].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    raise OverflowError('gateway child stderr exceeds 8000-byte limit')
    except BaseException as error:
        capture['error'] = error
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def gateway_child_config(ledger, address, seed, *, crash_expected=None):
    directory = ledger.parent
    native_log, http_log = directory / 'native-calls', directory / 'http-calls'
    native_log.touch(mode=0o600)
    http_log.touch(mode=0o600)
    config = directory / 'child.json'
    value = {'ledger': str(ledger), 'address': address, 'seed': seed,
             'nativeLog': str(native_log), 'httpLog': str(http_log)}
    if crash_expected is not None:
        value.update(crashMarker=str(directory / 'cloud-crash-injected'), crashExpected=crash_expected)
    config.write_text(json.dumps(value))
    return config, native_log, http_log


@contextmanager
def gateway_child(config_path, phase):
    directory = config_path.parent
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(directory), 'PYTHONDONTWRITEBYTECODE': '1',
                   'PYTHONPATH': os.pathsep.join((str(CHILD.parents[2] / 'src'), str(CHILD.parents[1])))}
    process = subprocess.Popen(  # nosec B603 - Explicit interpreter and fixed local fixture; no shell.
        [sys.executable, str(CHILD.resolve()), str(config_path), phase],
        cwd=directory, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    capture = {'prefix': bytearray(), 'error': None}
    stopped = threading.Event()
    drainer = threading.Thread(target=_drain_stderr, args=(process, capture, stopped),
                               name=f'gateway-stderr-{process.pid}', daemon=True)
    primary = None
    try:
        try:
            drainer.start()
            message = _read_startup_handshake(process.stdout, timeout=15, max_bytes=65536)
            yield process, message
        finally:
            _cleanup_fixture_process(process, sys.exc_info()[1])
    except BaseException as error:
        primary = error
        raise
    finally:
        if drainer.ident is not None:
            drainer.join(timeout=1)
            stopped.set()
            drainer.join(timeout=1)
        process.stderr.close()
        diagnostic = capture['error']
        if drainer.is_alive():
            diagnostic = TimeoutError('gateway stderr drainer did not stop')
        error = primary or diagnostic
        if error is not None:
            error.add_note('gateway child stderr: ' + capture['prefix'].decode('utf8', errors='replace'))
            if primary is not None and diagnostic is not None:
                primary.add_note(f'stderr capture also failed: {diagnostic}')
            if primary is None:
                raise error


class GatewayChildSafetyTests(unittest.TestCase):
    def test_stderr_overflow_is_bounded_kills_group_and_preserves_primary_error(self):
        for primary_failure in (False, True):
            with self.subTest(primary_failure=primary_failure), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / 'child.json'
                config.write_text('{}')
                child_script = Path(directory) / 'flood.py'
                child_script.write_text("import os, time\nos.write(1, b'{}\\n')\n"
                                        "while True: os.write(2, b'x' * 4096)\n")
                expected = RuntimeError if primary_failure else OverflowError
                with self.assertRaises(expected) as raised, patch.object(sys.modules[__name__], 'CHILD', child_script):
                    with gateway_child(config, 'restart') as (process, message):
                        self.assertEqual(message, {})
                        self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)
                        if primary_failure:
                            raise RuntimeError('original test failure')
                self.assertFalse(_process_group_exists(process.pid))
                self.assertTrue(process.stdout.closed)
                self.assertTrue(process.stderr.closed)
                self.assertFalse(any(thread.name == f'gateway-stderr-{process.pid}' for thread in threading.enumerate()))
                self.assertEqual(raised.exception.__notes__[0], 'gateway child stderr: ' + 'x' * STDERR_LIMIT)
                if primary_failure:
                    self.assertEqual(str(raised.exception), 'original test failure')
                    self.assertIn('stderr capture also failed:', raised.exception.__notes__[1])


@unittest.skipUnless(all(os.environ.get(key) for key in SETTINGS), 'requires explicit local workerd fixture paths')
class MessagingProcessRestartTests(unittest.TestCase):
    def assert_held(self, snapshot, seed):
        attempt = snapshot['attempt']
        self.assertEqual(snapshot['attemptCount'], 1)
        self.assertEqual(attempt['attempt_id'], seed['envelope']['attemptId'])
        self.assertEqual(attempt['envelope'], seed['envelope'])
        self.assertEqual(attempt['state'], 'held')
        self.assertEqual(snapshot['delivery']['status'], 'held')
        self.assertEqual(snapshot['pending'], [])
        self.assertEqual(snapshot['reconcilable'], [])
        self.assertEqual(snapshot['nativeCalls'], [])
        for field in ('native_request', 'started_receipt', 'input_recorded_receipt'):
            self.assertIsNone(attempt[field])

    def restart_cloud(self, address, transport):
        def workerd_pids():
            result = subprocess.run(  # nosec B603 - Fixed process inspection command; no shell.
                ['/usr/bin/pgrep', '-P', str(address['pid']), '-x', 'workerd'],
                capture_output=True, text=True, timeout=5, check=True)
            self.assertLess(len(result.stdout), 1024)
            pids = {int(value) for value in result.stdout.split()}
            self.assertTrue(pids)
            return pids

        before = workerd_pids()
        self.assertEqual(transport.fixture('/fixture/restart'), {'restarted': True})
        after = workerd_pids()
        self.assertTrue(before.isdisjoint(after), (before, after))
        for pid in before:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def crash_and_restart(self, phase, *, restart_cloud=False):
        with fixture() as (ledger, address, transport, seed):
            config, native_log, http_log = gateway_child_config(ledger, address, seed)
            expected_claims = 0 if phase == 'intent' else 1
            with gateway_child(config, phase) as (child, stopped):
                self.assertEqual(stopped['phase'], phase)
                self.assertEqual(stopped['pid'], child.pid)
                self.assertEqual(stopped['claims'], expected_claims)
                self.assertIsNone(child.poll())
                self.assert_held(stopped['snapshot'], seed)
                os.killpg(child.pid, signal.SIGKILL)
                self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
                self.assertFalse(_process_group_exists(child.pid))
                os.set_blocking(child.stdout.fileno(), False)
                self.assertEqual(os.read(child.stdout.fileno(), 1), b'')
            cloud = transport.fixture('/fixture/read')
            self.assertEqual(cloud['outboundCalls'], 0)
            self.assertEqual(len((cloud['budget'] or {}).get('wakes', [])), expected_claims)
            self.assertEqual(native_log.read_bytes(), b'')
            self.assertEqual(http_log.read_bytes(), b'called\n' * expected_claims)
            attempt = stopped['snapshot']['attempt']
            self.assertEqual(attempt['claim_uncertain'], int(phase != 'admission'))
            if phase == 'admission':
                self.assertEqual(attempt['admission']['status'], 'admitted')
            else:
                self.assertIsNone(attempt['admission'])
            if expected_claims:
                self.assertEqual(cloud['budget']['eventAttempts'][0]['attemptId'], seed['envelope']['attemptId'])
                self.assertEqual(cloud['attempts'][0]['attempt_id'], seed['envelope']['attemptId'])
                self.assertEqual(len(cloud['native_claims']), 1)
                self.assertIsNotNone(cloud['native_claims'][0]['permit_id'])
                if phase == 'admission':
                    self.assertEqual(cloud['native_claims'][0]['permit_id'], attempt['admission']['permitId'])
            else:
                self.assertTrue(all(row['permit_id'] is None for row in cloud['native_claims']))
            if restart_cloud:
                self.restart_cloud(address, transport)
                self.assertEqual(transport.fixture('/fixture/read'), cloud)
            with gateway_child(config, 'restart') as (restarted, recovered):
                self.assertEqual(recovered['phase'], 'restart')
                self.assertEqual(recovered['pid'], restarted.pid)
                self.assertNotEqual(recovered['pid'], stopped['pid'])
                self.assertEqual(restarted.wait(timeout=5), 0)
                self.assertFalse(_process_group_exists(restarted.pid))
                os.set_blocking(restarted.stdout.fileno(), False)
                self.assertEqual(os.read(restarted.stdout.fileno(), 1), b'')
            self.assert_held(recovered['before'], seed)
            self.assert_held(recovered['after'], seed)
            self.assertEqual(recovered['before']['attempt'], attempt)
            self.assertEqual(recovered['after']['attempt'], attempt)
            self.assertEqual(recovered['claims'], 0)
            self.assertEqual(recovered['repeated'], recovered['result'])
            if phase == 'admission':
                self.assertEqual(recovered['result'], attempt['admission'])
            else:
                self.assertEqual(recovered['result']['reason'], 'claim_outcome_unknown')
            self.assertEqual(http_log.read_bytes(), b'called\n' * expected_claims)
            self.assertEqual(native_log.read_bytes(), b'')
            self.assertEqual(transport.fixture('/fixture/read'), cloud)

    def test_kill_after_durable_intent_before_http(self):
        self.crash_and_restart('intent')

    def test_kill_after_cloud_admission_before_local_persistence(self):
        self.crash_and_restart('response')

    def test_kill_after_local_admission_commit(self):
        self.crash_and_restart('admission')

    def test_cloud_restart_preserves_uncertain_intent_without_resend(self):
        self.crash_and_restart('response', restart_cloud=True)

    def test_cloud_restart_preserves_committed_admission_and_shared_budget(self):
        self.crash_and_restart('admission', restart_cloud=True)

    def test_cloud_restart_preserves_consumer_and_routing_fences(self):
        for kind in (None, 'consumer', 'route'):
            with self.subTest(kind=kind), fixture() as (path, address, transport, seed):
                case = workerd_fixture.MessagingWorkerdTests()
                case.addCleanup = self.addCleanup
                gateway = case.gateway(path, address, transport, seed)
                if kind is not None:
                    transport.fixture('/fixture/change', {'kind': kind})
                cloud = transport.fixture('/fixture/read')
                self.restart_cloud(address, transport)
                self.assertEqual(transport.fixture('/fixture/read'), cloud)
                result = asyncio.run(gateway._claim_messaging_history(seed['envelope']['deliveryId']))
                cloud = transport.fixture('/fixture/read')
                if kind is None:
                    self.assertEqual(result['status'], 'admitted', transport.last_response)
                    self.assertEqual(len(cloud['budget']['wakes']), 1)
                    self.assertEqual(cloud['native_claims'][0]['permit_id'], result['permitId'])
                else:
                    self.assertEqual(result.get('reason'), 'claim_outcome_unknown')
                    self.assertIn(transport.last_response[0], (403, 409))
                    self.assertIn(json.loads(transport.last_response[1])['error'], ('denied', 'conflict'))
                    self.assertEqual((cloud['budget'] or {}).get('wakes', []), [])
                    self.assertTrue(all(row['permit_id'] is None for row in cloud['native_claims']))
                self.assertEqual(cloud['outboundCalls'], 0)
                self.assertEqual(transport.claims, 1)
                case.assert_inert(gateway, seed)

    def test_restart_proof_rejects_missing_restart_and_missing_persistence(self):
        for mutation in ('restart', 'persistence'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                broker = Path(directory) / workerd_fixture.BROKER.name
                source = workerd_fixture.BROKER.read_text()
                if mutation == 'restart':
                    original = "await mf.dispose();\n        if (stopping) throw new Error('fixture stopping');\n        mf = new Miniflare(options);"
                    self.assertIn(original, source)
                    source = source.replace(original, '')
                    expected = 'False is not true'
                else:
                    original = "resourcePersistencePath: join(process.env.HOME, 'durable-objects'),"
                    self.assertIn(original, source)
                    source = source.replace(original, '')
                    expected = '/fixture/read returned 500:.*no such table'
                broker.write_text(source)
                for name in ('messaging-workerd-worker.ts', 'messaging-workerd-inputs.json'):
                    shutil.copy(workerd_fixture.BROKER.with_name(name), broker.with_name(name))
                with (patch.object(workerd_fixture, 'BROKER', broker),
                      self.assertRaisesRegex(AssertionError, expected)):
                    self.crash_and_restart('admission', restart_cloud=True)
