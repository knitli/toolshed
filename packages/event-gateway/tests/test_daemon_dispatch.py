"""Production daemon orchestration through signed HTTP and durable restart."""

import asyncio
import copy
from contextlib import asynccontextmanager, closing, nullcontext
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway import client_runtime, daemon, launcher
from event_gateway.cloud import _iso
from event_gateway.security import SecurityError, load_or_create_signing_key, public_key_text, sign
from event_gateway.store import IDENTITY, Store
from test_gateway_integration import FIXTURE, InjectedBridge
from test_native_session_proxy import session_fixture, witness


class DaemonDispatchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.state = self.directory / 's'
        self.node_id = str(uuid.uuid4())
        self.transport_key = Ed25519PrivateKey.generate()
        self.envelope = copy.deepcopy(FIXTURE['original'])
        now = time.time()
        self.envelope.update(issuedAt=_iso(now), observedAt=_iso(now), expiresAt=_iso(now + 60))
        self.mapping = {key: self.envelope[key] for key in IDENTITY}
        thread = str(uuid.uuid4())
        self.bridge = InjectedBridge(self.state, thread)
        self.bridge.receipt_version = 3
        self.bridge.outcome = 'started'
        binding = {key: value for key, value in self.bridge.witness.items() if key != 'eligible'}
        binding.update(connectionId=str(uuid.uuid4()), backendPid=123)
        self.bridge.witness.update(binding)
        self.mapping.update(leaseExpiresAt=now + 600, nativeThreadId=thread,
                            nativeBinding=binding, sessionId=str(uuid.uuid4()), nodeId=self.node_id)
        with Store(self.state) as store:
            store.put_attachment(self.mapping)
        load_or_create_signing_key(self.state / 'node-key.pem')
        self.write_private('credentials.json', {'accessToken': 'test-access', 'agentToken': 'test-agent'})
        self.write_private('cloud.json', {
            'version': 1, 'origin': 'https://events.example.com',
            'principal': self.envelope['principal'], 'agent': self.envelope['agent'],
            'nodeId': self.node_id, 'nodeGeneration': self.envelope['nodeGeneration'],
            'credentialsFile': 'credentials.json',
        })
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        self.config = {'version': 1, 'cloudConfig': 'cloud.json', 'listenHost': '127.0.0.1',
                       'listenPort': self.port, 'transportKeys': {'test': public_key_text(self.transport_key)}}
        self.config_path = self.write_private('dispatch.json', self.config)
        self.admissions, self.acks, self.claims = {}, [], []
        self.drop_ack = self.receipt_unavailable = False
        self.item_id = str(uuid.uuid4())
        self.original_receipt = self.bridge.receipt

        def receipt(request):
            if self.receipt_unavailable:
                raise OSError('test receipt temporarily unavailable')
            self.original_receipt(request)
            return {'status': 'inputRecorded', 'turnId': request['clientUserMessageId'],
                    'itemId': self.item_id, 'replayed': True}

        self.bridge.receipt = receipt

    def write_private(self, name, value):
        path = self.directory / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def row(self, delivery_id=None):
        with closing(sqlite3.connect(self.state / 'ledger.sqlite')) as reader:
            reader.row_factory = sqlite3.Row
            result = reader.execute('SELECT * FROM deliveries WHERE id=?',
                                    (delivery_id or self.envelope['deliveryId'],)).fetchone()
            return dict(result) if result else None

    def attempt(self, attempt_id):
        with closing(sqlite3.connect(self.state / 'ledger.sqlite')) as reader:
            reader.row_factory = sqlite3.Row
            return dict(reader.execute('SELECT * FROM attempts WHERE attempt_id=?', (attempt_id,)).fetchone())

    async def cloud_send(self, **request):
        self.assertEqual(request['headers']['authorization'], 'Bearer test-agent')
        self.assertIn('x-event-node-proof', request['headers'])
        body = json.loads(request['body'])
        if request['url'].endswith('/v1/dispatch/claim'):
            self.claims.append(body)
            attempt = self.attempt(body['attemptId'])
            self.assertEqual(attempt['state'], 'claiming')
            if body['attemptId'] not in self.admissions:
                now = time.time()
                envelope = json.loads(attempt['envelope'])
                self.admissions[body['attemptId']] = {
                    'status': 'admitted', 'permitId': str(uuid.uuid4()), 'nodeId': self.node_id,
                    'permitIssuedAt': _iso(now), 'permitExpiresAt': _iso(now + 5),
                    'envelope': {**envelope, 'issuedAt': _iso(now), 'expiresAt': _iso(now + 60)},
                }
            value = self.admissions[body['attemptId']]
        elif request['url'].endswith('/v1/ack'):
            attempt = self.attempt(body['attemptId'])
            column = 'native_observed_ack' if body['status'] == 'observed' else 'native_ack'
            self.assertEqual(json.loads(attempt[column]), body)
            self.acks.append(request['body'])
            if self.drop_ack:
                raise TimeoutError('test committed acknowledgment response lost')
            value = {'status': body['status'], 'current': body['status'] == 'observed'}
        else:
            self.fail('Unexpected cloud operation')
        return 200, {'content-type': 'application/json'}, json.dumps(value).encode()

    @asynccontextmanager
    async def running(self, *, real_session=False):
        with patch.object(client_runtime, '_send_https', self.cloud_send), \
                (nullcontext() if real_session else
                 patch.object(daemon, 'SessionNativeBridge', return_value=self.bridge)), \
                patch.object(daemon, 'WORKER_INTERVAL', 0.02):
            task = asyncio.create_task(daemon.serve(self.state, dispatch_config=self.config_path))
            try:
                await self.until(lambda: (self.state / 'control.sock').exists() or task.done())
                if task.done():
                    await task
                yield task
            finally:
                task.cancel()
                result, = await asyncio.gather(task, return_exceptions=True)
                if not isinstance(result, asyncio.CancelledError) and result is not None:
                    raise result
        self.assertFalse((self.state / 'control.sock').exists())

    async def until(self, predicate):
        async with asyncio.timeout(4):
            while not predicate():
                await asyncio.sleep(0.01)

    async def deliver(self, envelope=None, *, audience=None, key_id='test', signature=None):
        body = json.dumps(envelope or self.envelope).encode()
        audience = self.node_id if audience is None else audience
        signature = sign(body, self.transport_key, audience) if signature is None else signature
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        try:
            writer.write((f'POST /v1/deliver HTTP/1.1\r\nContent-Type: application/json\r\n'
                          f'Content-Length: {len(body)}\r\nX-Event-Audience: {audience}\r\n'
                          f'X-Event-Key-Id: {key_id}\r\nX-Event-Signature: {signature}\r\n\r\n').encode() + body)
            await writer.drain()
            return await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()

    def starts(self):
        return [request for operation, request in self.bridge.calls if operation == 'start']

    def use_session(self, state, route):
        self.state = state
        self.mapping.update(route)
        with Store(self.state) as store:
            store.put_attachment(self.mapping)
        load_or_create_signing_key(self.state / 'node-key.pem')

    async def test_signed_listener_dispatches_through_real_session_proxy_and_reader(self):
        with session_fixture(witness()) as (state, route, client, _current, calls):
            self.use_session(state, route)
            async with self.running(real_session=True):
                self.assertIn(b'202 Result', await self.deliver())
                await self.until(lambda: self.row()['state'] == 'observed')
            self.assertEqual(calls.count('start'), 1)
            self.assertIn('receipt', calls)
            attempt = self.attempt(self.envelope['attemptId'])
            durable = json.loads(attempt['native_request'])
            self.assertEqual(client.bridge.attempts[durable['attemptId']],
                             {key: value for key, value in durable.items() if key != 'receiptVersion'})
            self.assertEqual(durable['threadId'], route['nativeThreadId'])
            self.assertEqual(durable['generation'], route['nativeBinding']['generation'])
            self.assertEqual(len(self.claims), 1)
            acknowledgments = [json.loads(value) for value in self.acks]
            self.assertEqual([value['status'] for value in acknowledgments], ['submitted', 'observed'])
            self.assertTrue(all(value['nativeCorrelation']['turnId'] == durable['clientUserMessageId']
                                for value in acknowledgments))

    async def test_daemon_restart_recovers_real_proxy_lost_reply_without_another_start(self):
        with session_fixture(witness()) as (state, route, client, current, calls):
            self.use_session(state, route)
            original = launcher._session_request
            committed, blocked_receipts = [], []

            def lose_reply(*args, **kwargs):
                command = args[2]['command']
                if command == 'nativeReceipt':
                    blocked_receipts.append(args[2])
                    raise OSError('test launcher receipt transport unavailable')
                result = original(*args, **kwargs)
                if command == 'nativeStart':
                    committed.append(result)
                    raise OSError('test proxy reply lost after native commit')
                return result

            with patch.object(launcher, '_session_request', side_effect=lose_reply):
                async with self.running(real_session=True):
                    self.assertIn(b'202 Result', await self.deliver())
                    await self.until(lambda: self.row()['state'] == 'ambiguous' and bool(blocked_receipts))
            self.assertEqual(calls.count('start'), 1)
            self.assertEqual(len(committed), 1)
            self.assertEqual(committed[0]['outcome']['status'], 'started')
            self.assertFalse(self.acks)
            before = self.attempt(self.envelope['attemptId'])['native_request']
            self.assertIn(self.envelope['attemptId'], client.bridge.attempts)
            current.update(eligible=False, threadId=str(uuid.uuid4()), generation=current['generation'] + 1)
            restart_calls = len(calls)
            async with self.running(real_session=True):
                await self.until(lambda: self.row()['state'] == 'observed')
            self.assertEqual(calls.count('start'), 1)
            self.assertTrue(calls[restart_calls:])
            self.assertTrue(all(operation == 'receipt' for operation in calls[restart_calls:]))
            after = self.attempt(self.envelope['attemptId'])
            self.assertEqual(after['native_request'], before)
            self.assertEqual(json.loads(after['input_recorded_receipt'])['outcome']['status'], 'inputRecorded')
            self.assertEqual([json.loads(value)['status'] for value in self.acks], ['submitted', 'observed'])
            self.assertEqual(len(self.claims), 1)

    async def test_authenticated_acceptance_dispatches_and_observes_without_manual_dispatch(self):
        async with self.running():
            status = await daemon.request(self.state, {'command': 'status'})
            self.assertTrue(status['automaticWakeEnabled'])
            self.assertEqual(status['dispatch'], {'listenerReady': True, 'workerRunning': True,
                                                'authorityConfigured': True, 'liveWakeVerified': False})
            self.assertIn(b'202 Result', await self.deliver())
            await self.until(lambda: self.row()['state'] == 'observed')
        self.assertEqual(len(self.starts()), 1)
        self.assertEqual(self.bridge.at_start[0][0], 'submitting')
        self.assertEqual(self.bridge.at_start[0][1]['clientUserMessageId'], self.starts()[0]['clientUserMessageId'])
        self.assertEqual([json.loads(value)['status'] for value in self.acks], ['submitted', 'observed'])

    async def test_invalid_transport_never_persists_or_claims(self):
        async with self.running():
            for kwargs in ({'audience': 'wrong-node'}, {'key_id': 'unknown'}, {'signature': 'invalid'}):
                self.assertIn(b'400 Result', await self.deliver(**kwargs))
            self.assertIsNone(self.row())
            self.assertFalse(self.claims)
            self.assertFalse(self.starts())

    async def test_unavailable_backlog_retries_after_selection_returns(self):
        self.bridge.witness['eligible'] = False
        async with self.running():
            self.assertIn(b'202 Result', await self.deliver())
            await self.until(lambda: bool(self.bridge.calls))
            self.assertEqual(self.row()['state'], 'queued')
            self.assertFalse(self.claims)
            self.bridge.witness['eligible'] = True
            await self.until(lambda: self.row()['state'] == 'observed')
        self.assertEqual(len(self.starts()), 1)

    async def test_restart_recovers_ambiguous_start_by_receipt_without_repeat(self):
        self.bridge.drop_start = self.receipt_unavailable = True
        async with self.running():
            await self.deliver()
            await self.until(lambda: self.row()['state'] == 'ambiguous')
        self.assertEqual(len(self.starts()), 1)
        self.receipt_unavailable = False
        async with self.running():
            await self.until(lambda: self.row()['state'] == 'observed')
        self.assertEqual(len(self.starts()), 1)
        self.assertTrue(any(operation == 'restore' for operation, _ in self.bridge.calls))

    async def test_restart_replays_persisted_ack_without_repeat_start(self):
        self.drop_ack = True
        async with self.running():
            await self.deliver()
            await self.until(lambda: bool(self.acks))
        original = self.acks[0]
        self.drop_ack = False
        async with self.running():
            await self.until(lambda: self.row()['state'] == 'observed')
        submitted = [value for value in self.acks if json.loads(value)['status'] == 'submitted']
        self.assertGreaterEqual(len(submitted), 2)
        self.assertTrue(all(value == original for value in submitted))
        self.assertEqual(len(self.starts()), 1)

    async def test_bind_failure_releases_store_and_leaves_no_control_socket(self):
        with socket.socket() as blocker:
            blocker.bind(('127.0.0.1', self.port))
            blocker.listen()
            with self.assertRaises(OSError):
                await daemon.serve(self.state, dispatch_config=self.config_path)
        self.assertFalse((self.state / 'control.sock').exists())
        with Store(self.state) as store:
            self.assertIsNotNone(store.get_attachment(self.mapping['runtimeId']))

    async def test_shutdown_drains_incomplete_http_and_control_handlers(self):
        async with self.running():
            reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
            control_reader, control_writer = await asyncio.open_unix_connection(self.state / 'control.sock')
            writer.write(b'POST /v1/deliver HTTP/1.1\r\n')
            control_writer.write(b'{')
            await writer.drain()
            await control_writer.drain()
            await asyncio.sleep(0.01)
        self.assertIn(b'408 Result', await reader.read())
        self.assertEqual(await control_reader.read(), b'')
        writer.close()
        control_writer.close()
        await writer.wait_closed()
        await control_writer.wait_closed()
        with Store(self.state) as store:
            self.assertEqual(store.list_pending(), [])

    async def test_dispatch_config_private_network_and_key_validation(self):
        for host in ('127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.0.1', '100.64.0.1', '::1', 'fd00::1'):
            with self.subTest(host=host):
                self.write_private('dispatch.json', {**self.config, 'listenHost': host})
                configured, cloud = daemon.load_dispatch_config(self.config_path, self.state)
                self.assertEqual(configured['listenHost'], host)
                self.assertEqual(cloud.node_id, self.node_id)
        invalid = [{'listenHost': host} for host in (
            '0.0.0.0', '::', '8.8.8.8', '169.254.1.1', 'fe80::1', 'ff02::1',
            '::ffff:127.0.0.1', 'fd00::1%en0', 'localhost', '192.0.2.1',
        )] + [{'version': True}, {'listenPort': True}, {'listenPort': 0}, {'listenPort': 65536},
             {'cloudConfig': '../cloud.json'}, {'cloudConfig': '/cloud.json'}, {'unexpected': 1},
             {'transportKeys': {}}, {'transportKeys': {'invalid key': public_key_text(self.transport_key)}},
             {'transportKeys': {'key': public_key_text(self.transport_key) + '='}},
             {'transportKeys': {str(index): public_key_text(self.transport_key) for index in range(17)}}]
        for override in invalid:
            with self.subTest(override=override):
                self.write_private('dispatch.json', {**self.config, **override})
                with self.assertRaisesRegex(SecurityError, 'invalid_dispatch_config'):
                    daemon.load_dispatch_config(self.config_path, self.state)
        self.config_path.write_text('{"version":1,"version":1}')
        with self.assertRaises(SecurityError):
            daemon.load_dispatch_config(self.config_path, self.state)
        self.write_private('dispatch.json', self.config).chmod(0o644)
        with self.assertRaises(SecurityError):
            daemon.load_dispatch_config(self.config_path, self.state)

    async def test_batch_failure_cancels_other_inflight_work(self):
        started, finished = asyncio.Event(), asyncio.Event()

        async def operation(delivery_id):
            if delivery_id == 'fail':
                await started.wait()
                raise RuntimeError('test unexpected worker failure')
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                finished.set()

        with self.assertRaises(ExceptionGroup):
            await daemon._work_batch(
                [{'deliveryId': 'fail'}, {'deliveryId': 'pending'}], 0, operation,
            )
        self.assertTrue(finished.is_set())

    async def test_rotating_batches_reach_queued_delivery_after_unavailable_oldest(self):
        rows = [{'deliveryId': str(index)} for index in range(9)]
        visited = []

        async def unavailable(delivery_id):
            visited.append(delivery_id)

        cursor = 0
        for _ in range(3):
            cursor = await daemon._work_batch(rows, cursor, unavailable)
        self.assertEqual(set(visited), {row['deliveryId'] for row in rows})


if __name__ == '__main__':
    unittest.main()
