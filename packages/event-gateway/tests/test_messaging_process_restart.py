"""Opt-in SIGKILL/restart qualification across real Python, SQLite, HTTP and workerd."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import selectors
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

    def crash_and_restart(self, phase):
        with fixture() as (ledger, address, transport, seed):
            directory = ledger.parent
            native_log, http_log = directory / 'native-calls', directory / 'http-calls'
            native_log.touch(mode=0o600)
            http_log.touch(mode=0o600)
            config = directory / 'child.json'
            config.write_text(json.dumps({'ledger': str(ledger), 'address': address, 'seed': seed,
                                          'nativeLog': str(native_log), 'httpLog': str(http_log)}))
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
