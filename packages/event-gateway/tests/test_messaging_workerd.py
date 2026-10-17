"""Opt-in real Python/HTTP/workerd Messaging admission, with no native execution."""
import asyncio
import base64
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess  # nosec B404 - Explicit local Node runs the checked-in disposable fixture.
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway.cloud import CloudClient, Credentials
from event_gateway.gateway import Gateway
from event_gateway.messaging_admission_v2 import ATTACHMENT_FIELDS
from event_gateway.store import Store


BROKER = Path(__file__).parent / 'fixtures/messaging-workerd-broker.mjs'
SETTINGS = ('FIXTURE_NODE', 'FIXTURE_CLOUD_SOURCE', 'FIXTURE_MINIFLARE')
STARTUP_HANDSHAKE_MAX_BYTES = 1024 * 1024


def _read_startup_handshake(stream, *, timeout=60, max_bytes=STARTUP_HANDSHAKE_MAX_BYTES):
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    data = bytearray()
    try:
        selector.register(stream, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError('workerd startup handshake deadline')
            chunk = os.read(stream.fileno(), min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                raise RuntimeError('workerd startup ended before handshake')
            data.extend(chunk)
            newline = data.find(b'\n')
            if newline >= 0:
                if newline > max_bytes:
                    raise ValueError('workerd startup handshake too large')
                if newline != len(data) - 1:
                    raise ValueError('unexpected bytes after workerd startup handshake')
                return json.loads(data[:newline])
            if len(data) > max_bytes:
                raise ValueError('workerd startup handshake too large')
    finally:
        selector.close()


def _process_group_exists(process_group):
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_for_process_group_exit(process, timeout):
    deadline = time.monotonic() + timeout
    while True:
        process.poll()
        if not _process_group_exists(process.pid):
            process.wait(timeout=0)
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def _stop_process_group(process, *, term_timeout=10, kill_timeout=5):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if _wait_for_process_group_exit(process, term_timeout):
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if not _wait_for_process_group_exit(process, kill_timeout):
        raise TimeoutError('workerd process group did not exit after SIGKILL')


def _cleanup_fixture_process(process, primary_error=None):
    errors = []
    try:
        _stop_process_group(process)
    except BaseException as error:
        errors.append(error)
    try:
        process.stdout.close()
    except BaseException as error:
        errors.append(error)
    if not errors:
        return
    if primary_error is not None:
        details = '; '.join(f'{type(error).__name__}: {error}' for error in errors)
        primary_error.add_note('fixture cleanup also failed: ' + details)
        return
    raise BaseExceptionGroup('fixture cleanup failed', errors)


class LoopbackTransport:
    """Real bounded HTTP, translating only the fixed synthetic origin to loopback."""

    def __init__(self, address):
        self.address = address
        self.claims = 0
        self.lose_reply = False
        self.break_proof = False
        self.last_response = None

    def post(self, path, body, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.address['port'], timeout=5)
        try:
            connection.request('POST', path, body, {**(headers or {}),
                'x-fixture-secret': self.address['secret'], 'content-type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(8193)
            if len(raw) > 8192:
                raise AssertionError('fixture response limit')
            return response.status, {'content-type': response.getheader('content-type')}, raw
        finally:
            connection.close()

    def fixture(self, path, value=None):
        status, _, raw = self.post(path, json.dumps(value or {}).encode())
        if status != 200:
            raise AssertionError(f'{path} returned {status}: {raw[:1024]!r}')
        return json.loads(raw)

    async def send(self, **wire):
        if (wire['url'] != 'https://events.test/v1/dispatch/claim' or wire['method'] != 'POST'
                or (wire['timeout'], wire['max_response_bytes'], wire['follow_redirects']) != (5, 8192, False)):
            raise AssertionError('unexpected outbound request')
        self.claims += 1
        headers = dict(wire['headers'])
        if self.lose_reply:
            headers['x-fixture-drop-reply'] = 'true'
        if self.break_proof:
            proof = json.loads(headers['x-event-node-proof'])
            proof['signature'] = 'A' * 86
            headers['x-event-node-proof'] = json.dumps(proof)
        response = await asyncio.to_thread(self.post, '/v1/dispatch/claim', wire['body'], headers)
        self.last_response = (response[0], response[2].decode())
        return response


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory() as directory:
        with open(Path(directory) / 'broker.log', 'w+') as log:
            environment = {key: str(Path(os.environ[key]).resolve(strict=True)) for key in SETTINGS}
            environment.update(PATH='/usr/bin:/bin', HOME=directory)
            process = subprocess.Popen(  # nosec B603 - Explicit executable, fixed script, no shell.
                [environment['FIXTURE_NODE'], str(BROKER.resolve())], cwd=BROKER.parent,
                env=environment, stdout=subprocess.PIPE, stderr=log, start_new_session=True)
            try:
                try:
                    address = _read_startup_handshake(process.stdout)
                except RuntimeError as error:
                    log.seek(0, os.SEEK_END)
                    log.seek(max(0, log.tell() - 8000))
                    raise AssertionError('workerd startup failed: ' + log.read(8000)) from error
                transport = LoopbackTransport(address)
                seed = transport.fixture('/fixture/seed', {'nodeId': str(uuid4()), 'runtimeId': str(uuid4())})
                yield Path(directory).resolve() / 'ledger', address, transport, seed
            finally:
                _cleanup_fixture_process(process, sys.exc_info()[1])


class FixtureSafetyTests(unittest.TestCase):
    def test_partial_startup_line_times_out_and_closes_selector(self):
        class PartialStream:
            def fileno(self):
                return 17

        class OneReadSelector:
            def __init__(self):
                self.readiness_checks = 0
                self.closed = False

            def register(self, stream, events):
                self.registration = (stream, events)

            def select(self, timeout):
                self.readiness_checks += 1
                return [(None, None)]

            def close(self):
                self.closed = True

        selector = OneReadSelector()
        with (self.assertRaisesRegex(TimeoutError, 'startup handshake deadline'),
              patch.object(selectors, 'DefaultSelector', return_value=selector),
              patch.object(os, 'read', return_value=b'{"port":'),
              patch.object(time, 'monotonic', side_effect=[0, 0, 2])):
            _read_startup_handshake(PartialStream(), timeout=1, max_bytes=64)
        self.assertEqual(selector.readiness_checks, 1)
        self.assertTrue(selector.closed)

    def test_cleanup_escalates_and_waits_for_remaining_process_group(self):
        group_alive = True
        signals = []
        waits = []

        def fake_killpg(process_group, sig):
            nonlocal group_alive
            self.assertEqual(process_group, 4242)
            if sig == signal.SIGTERM:
                signals.append(sig)
            elif sig == signal.SIGKILL:
                signals.append(sig)
                group_alive = False
            elif sig == 0:
                if not group_alive:
                    raise ProcessLookupError
            else:
                self.fail(f'unexpected signal check: {sig}')

        class LeaderExitedButChildRemains:
            pid = 4242

            def poll(self):
                return 0

            def wait(self, *, timeout):
                waits.append(timeout)
                return 0

        with patch.object(os, 'killpg', side_effect=fake_killpg):
            _stop_process_group(LeaderExitedButChildRemains(), term_timeout=0, kill_timeout=0)

        self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(waits, [0])

    def test_cleanup_failure_is_reported_without_replacing_startup_failure(self):
        closed = []
        primary = RuntimeError('startup failed')

        class Process:
            stdout = type('Stdout', (), {'close': lambda self: closed.append(True)})()

        def fail_during_cleanup():
            try:
                raise primary
            finally:
                _cleanup_fixture_process(Process(), sys.exc_info()[1])

        with (self.assertRaises(RuntimeError) as raised,
              patch.object(sys.modules[__name__], '_stop_process_group', side_effect=PermissionError('signal denied'))):
            fail_during_cleanup()

        self.assertIs(raised.exception, primary)
        self.assertEqual(raised.exception.__notes__, ['fixture cleanup also failed: PermissionError: signal denied'])
        self.assertEqual(closed, [True])


@unittest.skipUnless(all(os.environ.get(key) for key in SETTINGS), 'requires explicit local workerd fixture paths')
class MessagingWorkerdTests(unittest.IsolatedAsyncioTestCase):
    def gateway(self, path, address, transport, seed):
        event = seed['envelope']
        store = Store(path)
        self.addCleanup(store.close)
        mapping = {key: event[key] for key in ATTACHMENT_FIELDS}
        mapping.update(namespace=event['canonicalSubject']['namespace'], agentIncarnation=event['canonicalSubject']['agentIncarnation'],
                       leaseExpiresAt=time.time() + 120)
        if store.get_attachment(event['runtimeId']) is None:
            store.put_messaging_attachment(mapping)
        private = address['agentPrivateJwk']['d']
        key = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(private + '=='))

        async def credentials():
            return Credentials(address['accessToken'], address['agentToken'])

        native_calls = []

        def native_forbidden(*_):
            native_calls.append(True)
            self.fail('native adapter must never be constructed')

        client = CloudClient(origin='https://events.test', principal=event['principal'], agent=event['agent'],
                             node_id=event['nodeId'], node_generation=event['nodeGeneration'], private_key=key,
                             credentials=credentials, send=transport.send)
        gateway = Gateway(store, client, native_forbidden, audience=seed['audience'],
                          keys={seed['keyId']: address['transportPublicKey']})
        gateway.accept_messaging_v2(seed['body'].encode(), signature=seed['signature'], audience=seed['audience'],
                                    key_id=seed['keyId'], node_id=event['nodeId'], runtime_id=event['runtimeId'])
        gateway.fixture_native_calls = native_calls
        return gateway

    def assert_inert(self, gateway, seed):
        store = gateway.store
        self.assertEqual(gateway.fixture_native_calls, [])
        self.assertEqual(store.delivery(seed['envelope']['deliveryId'])['status'], 'held')
        self.assertEqual(store.list_pending(), [])
        self.assertEqual(store.list_reconcilable(), [])
        attempt = store.current_attempt(seed['envelope']['deliveryId'])
        self.assertEqual(attempt['state'], 'held')
        for name in ('native_request', 'started_receipt', 'input_recorded_receipt'):
            self.assertIsNone(attempt[name])

    async def test_signed_transport_real_claim_and_reopened_history_charge_once(self):
        with fixture() as (path, address, transport, seed):
            gateway = self.gateway(path, address, transport, seed)
            event = seed['envelope']
            admitted = await gateway._claim_messaging_history(event['deliveryId'])
            self.assertEqual(admitted['status'], 'admitted', transport.last_response)
            self.assertEqual(admitted['envelope'], event)
            cloud = transport.fixture('/fixture/read')
            self.assertEqual(cloud['outboundCalls'], 0)
            self.assertEqual(len(cloud['budget']['wakes']), 1)
            self.assertEqual(cloud['budget']['eventAttempts'][0]['attemptId'], event['attemptId'])
            self.assertEqual(cloud['native_claims'][0]['permit_id'], admitted['permitId'])
            self.assertEqual(cloud['attempts'][0]['attempt_id'], event['attemptId'])
            self.assert_inert(gateway, seed)
            gateway.store.close()
            gateway = self.gateway(path, address, transport, seed)
            self.assertEqual(await gateway._claim_messaging_history(event['deliveryId']), admitted)
            self.assertEqual(transport.claims, 1)
            self.assertEqual(transport.fixture('/fixture/read')['budget'], cloud['budget'])
            self.assert_inert(gateway, seed)

    async def test_lost_committed_http_reply_retains_uncertainty_without_resend(self):
        with fixture() as (path, address, transport, seed):
            gateway = self.gateway(path, address, transport, seed)
            transport.lose_reply = True
            result = await gateway._claim_messaging_history(seed['envelope']['deliveryId'])
            self.assertEqual(result.get('reason'), 'claim_outcome_unknown')
            cloud = transport.fixture('/fixture/read')
            self.assertEqual(cloud['outboundCalls'], 0)
            self.assertEqual(len(cloud['budget']['wakes']), 1)
            self.assertIsNotNone(cloud['native_claims'][0]['permit_id'])
            self.assertEqual(gateway.store.current_attempt(seed['envelope']['deliveryId'])['claim_uncertain'], 1)
            gateway.store.close()
            gateway = self.gateway(path, address, transport, seed)
            result = await gateway._claim_messaging_history(seed['envelope']['deliveryId'])
            self.assertEqual(result.get('reason'), 'claim_outcome_unknown')
            self.assertEqual(transport.claims, 1)
            self.assertEqual(transport.fixture('/fixture/read')['budget'], cloud['budget'])
            self.assert_inert(gateway, seed)

    async def test_route_key_and_source_revocation_never_fall_back_to_generic_budget(self):
        for kind in ('route', 'key', 'source'):
            with self.subTest(kind=kind), fixture() as (path, address, transport, seed):
                gateway = self.gateway(path, address, transport, seed)
                transport.fixture('/fixture/change', {'kind': kind})
                result = await gateway._claim_messaging_history(seed['envelope']['deliveryId'])
                self.assertEqual(result.get('reason'), 'claim_outcome_unknown')
                cloud = transport.fixture('/fixture/read')
                self.assertEqual(cloud['outboundCalls'], 0)
                self.assertIn(transport.last_response[0], (403, 409))
                self.assertIn(json.loads(transport.last_response[1])['error'], ('denied', 'conflict'))
                self.assertEqual((cloud['budget'] or {}).get('wakes', []), [])
                self.assertTrue(all(row['permit_id'] is None for row in cloud['native_claims']))
                self.assertEqual(transport.claims, 1)
                self.assert_inert(gateway, seed)

    async def test_invalid_node_proof_is_rejected_before_reservation(self):
        with fixture() as (path, address, transport, seed):
            gateway = self.gateway(path, address, transport, seed)
            transport.break_proof = True
            result = await gateway._claim_messaging_history(seed['envelope']['deliveryId'])
            self.assertEqual(result.get('reason'), 'claim_outcome_unknown')
            cloud = transport.fixture('/fixture/read')
            self.assertEqual(cloud['outboundCalls'], 0)
            self.assertEqual((cloud['budget'] or {}).get('wakes', []), [])
            self.assertTrue(all(row['permit_id'] is None for row in cloud['native_claims']))
            self.assertEqual(transport.last_response, (403, '{"error":"node_denied"}'))
            self.assert_inert(gateway, seed)
