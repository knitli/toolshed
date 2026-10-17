"""Real client claim history stays durable, single-send, and inert."""
import asyncio
import base64
import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway import messaging_admission_v2 as admission
from event_gateway import messaging_protocol_v2 as protocol
from event_gateway.cloud import CloudClient, CloudError, Credentials, _iso, canonical_node_proof
from event_gateway.gateway import Gateway
from event_gateway.store import RETENTION, Store, StoreError
from test_messaging_admission_v2 import FIXTURE, OTHER


class ClaimHistoryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = FIXTURE['nowMs'] / 1000
        self.path = Path(self.tmp.name).resolve() / 'private'
        self.store = Store(self.path, clock=lambda: self.now)
        self.addCleanup(lambda: self.store.close())
        self.event = copy.deepcopy(FIXTURE['envelope'])
        mapping = {key: self.event[key] for key in admission.ATTACHMENT_FIELDS}
        mapping.update(namespace='team/inbox', agentIncarnation=0, leaseExpiresAt=self.now + 60)
        self.store.put_messaging_attachment(mapping)
        self.store.accept(self.event)
        self.permit = dict(status='admitted', permitId=OTHER, nodeId=self.event['nodeId'],
                           permitIssuedAt='2026-10-17T12:00:30.000Z',
                           permitExpiresAt='2026-10-17T12:00:35.000Z', envelope=copy.deepcopy(self.event))
        self.key = Ed25519PrivateKey.generate()
        self.credentials = AsyncMock(return_value=Credentials('access-token', 'agent-token'))
        self.send = AsyncMock(return_value=self.response(self.permit))
        self.client = CloudClient(origin='https://events.example.com', principal=self.event['principal'],
                                  agent=self.event['agent'], node_id=self.event['nodeId'],
                                  node_generation=self.event['nodeGeneration'], private_key=self.key,
                                  credentials=self.credentials, send=self.send, clock=lambda: self.now)
        self.adapter = Mock()
        self.gateway = self.make_gateway()

    def make_gateway(self):
        return Gateway(self.store, self.client, self.adapter, audience='local', keys={}, clock=lambda: self.now)

    @staticmethod
    def response(value):
        return 200, {'content-type': 'application/json'}, json.dumps(value).encode()

    async def claim(self):
        return await self.gateway._claim_messaging_history(self.event['deliveryId'])

    async def stop_task(self, task):
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    def attempt(self):
        return self.store.current_attempt(self.event['deliveryId'])

    def reopen(self):
        self.store.close()
        self.store = Store(self.path, clock=lambda: self.now)
        self.gateway = self.make_gateway()

    def assert_inert(self):
        self.assertEqual(self.adapter.mock_calls, [])
        self.assertEqual(self.store.list_pending(), [])
        self.assertEqual(self.store.list_reconcilable(), [])
        row = self.attempt()
        self.assertEqual(row['state'], 'held')
        for key in ('native_request', 'started_receipt', 'input_recorded_receipt'):
            self.assertIsNone(row[key])
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0], 1)

    async def test_signed_request_sees_committed_intent_then_replays_admission_without_io(self):
        async def send(**request):
            self.assertFalse(self.store.db.in_transaction)
            with closing(sqlite3.connect(self.path / 'ledger.sqlite')) as independent:
                row = independent.execute('SELECT state,claim_uncertain,admission,envelope FROM attempts').fetchone()
            self.assertEqual(row[:3], ('held', 1, None))
            self.assertEqual(json.loads(row[3]), self.event)
            self.assertEqual(request['url'], 'https://events.example.com/v1/dispatch/claim')
            self.assertEqual(request['method'], 'POST')
            self.assertEqual(request['timeout'], 5)
            self.assertEqual(request['max_response_bytes'], 8192)
            self.assertIs(request['follow_redirects'], False)
            self.assertEqual(json.loads(request['body']), {key: self.event[key] for key in ('deliveryId', 'attemptId')})
            headers = request['headers']
            self.assertEqual(set(headers), {'content-type', 'cf-access-token', 'authorization', 'x-event-node-proof'})
            self.assertEqual(headers['content-type'], 'application/json')
            self.assertEqual(headers['cf-access-token'], 'access-token')
            self.assertEqual(headers['authorization'], 'Bearer agent-token')
            proof = json.loads(headers['x-event-node-proof'])
            self.assertEqual(proof['nodeId'], self.event['nodeId'])
            self.assertEqual(proof['nodeGeneration'], self.event['nodeGeneration'])
            signature = base64.urlsafe_b64decode(proof['signature'] + '==')
            self.key.public_key().verify(signature, canonical_node_proof(
                self.event['principal'], self.client.origin, '/v1/dispatch/claim', request['body'], proof))
            return self.response(self.permit)
        self.send.side_effect = send
        self.assertEqual(await self.claim(), self.permit)
        self.assertEqual(self.attempt()['admission'], self.permit)
        self.assertEqual(self.attempt()['claim_uncertain'], 0)
        self.assertEqual(self.attempt()['reserved_bytes'], 0)
        self.reopen()
        before = tuple(self.store.db.iterdump())
        self.assertEqual(await self.claim(), self.permit)
        self.assertEqual(tuple(self.store.db.iterdump()), before)
        self.send.assert_awaited_once()
        self.credentials.assert_awaited_once()
        self.assert_inert()

    def test_history_writer_requires_preexisting_intent(self):
        before = tuple(self.store.db.iterdump())
        with self.assertRaisesRegex(StoreError, 'invalid_transition'):
            self.store._record_messaging_admission_history(
                self.event['deliveryId'], self.permit, node_id=self.event['nodeId'],
            )
        self.assertIsNone(self.attempt())
        self.assertEqual(tuple(self.store.db.iterdump()), before)

    def test_begin_is_single_use_and_writer_fills_existing_intent(self):
        delivery = self.event['deliveryId']
        self.assertIsNotNone(self.store._begin_messaging_claim_history(delivery))
        self.assertIsNone(self.store._begin_messaging_claim_history(delivery))
        self.assertEqual(self.attempt()['claim_uncertain'], 1)
        self.assertIsNone(self.attempt()['admission'])
        self.assertEqual(self.store._record_messaging_admission_history(delivery, self.permit,
                         node_id=self.event['nodeId']), self.permit)
        self.assertEqual(self.attempt()['claim_uncertain'], 0)
        self.assert_inert()

    async def test_closed_over_budget_is_durable_and_never_resent(self):
        outcome = {'status': 'over_budget', 'budget': {'used': 10, 'remaining': 0, 'limit': 10, 'windowMs': 3600000}}
        self.send.return_value = self.response(outcome)
        self.assertEqual(await self.claim(), outcome)
        self.assertEqual(self.attempt()['evidence'], outcome)
        self.assertEqual(self.attempt()['reason'], 'over_budget')
        self.assertEqual(self.attempt()['claim_uncertain'], 0)
        self.store.detach(self.event['runtimeId'])
        self.now += RETENTION * 2
        self.store.cleanup()
        self.reopen()
        self.assertEqual(await self.claim(), outcome)
        self.send.assert_awaited_once()
        self.assert_inert()

    async def test_client_rejects_malformed_budget_and_oversize_redirect_responses(self):
        valid = {'status': 'over_budget', 'budget': {'used': 10, 'remaining': 0, 'limit': 10, 'windowMs': 3600000}}
        invalid = [dict(valid, extra=True)]
        for key, value in [('used', True), ('used', 9), ('remaining', 1), ('limit', 11), ('windowMs', 1)]:
            invalid.append(dict(valid, budget=dict(valid['budget'], **{key: value})))
        responses = [self.response(value) for value in invalid]
        responses += [(302, {'location': 'https://other.example'}, b''),
                      (200, {'content-type': 'application/json'}, b' ' * 8193)]
        for response in responses:
            with self.subTest(response=response[0:2]):
                self.send.return_value = response
                with self.assertRaises(CloudError):
                    await self.client.claim_messaging_history(self.event)

    async def test_client_rejects_each_configured_identity_mismatch_before_credentials(self):
        for key, value in [('principal', 'other@example.com'), ('agent', 'other'),
                           ('node_id', OTHER), ('node_generation', self.event['nodeGeneration'] + 1)]:
            with self.subTest(key=key), patch.object(self.client, key, value):
                with self.assertRaises(CloudError):
                    await self.client.claim_messaging_history(self.event)
        self.send.assert_not_awaited()
        self.credentials.assert_not_awaited()

    async def assert_unknown_survives(self):
        self.assertEqual(self.attempt()['claim_uncertain'], 1)
        self.assertIsNone(self.attempt()['admission'])
        self.store.detach(self.event['runtimeId'])
        self.now += RETENTION * 2
        self.store.cleanup()
        self.reopen()
        self.assertIsNotNone(self.store.delivery(self.event['deliveryId']))
        await self.claim()
        self.send.assert_awaited_once()
        self.assertEqual(self.attempt()['claim_uncertain'], 1)
        self.assert_inert()

    async def test_timeout_survives_restart_detach_and_retention_without_resend(self):
        self.send.side_effect = TimeoutError('transport timeout')
        await self.claim()
        await self.assert_unknown_survives()

    async def test_malformed_success_survives_restart_detach_and_retention_without_resend(self):
        self.send.return_value = self.response({'status': 'admitted'})
        await self.claim()
        await self.assert_unknown_survives()

    async def test_admission_write_failure_survives_restart_detach_and_retention_without_resend(self):
        with patch.object(self.store, '_record_messaging_admission_history', side_effect=sqlite3.OperationalError('disk')) as writer:
            await self.claim()
        writer.assert_called_once()
        await self.assert_unknown_survives()

    async def test_cancellation_survives_restart_detach_and_retention_without_resend(self):
        entered = asyncio.Event()
        async def blocked(**_):
            entered.set()
            await asyncio.Future()
        self.send.side_effect = blocked
        task = asyncio.create_task(self.claim())
        self.addAsyncCleanup(self.stop_task, task)
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await self.assert_unknown_survives()

    async def test_concurrent_calls_send_once(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def blocked(**_):
            entered.set()
            await release.wait()
            return self.response(self.permit)
        self.send.side_effect = blocked
        first = asyncio.create_task(self.claim())
        self.addAsyncCleanup(self.stop_task, first)
        await asyncio.wait_for(entered.wait(), 2)
        second = asyncio.create_task(self.claim())
        self.addAsyncCleanup(self.stop_task, second)
        await asyncio.sleep(0)
        release.set()
        await asyncio.wait_for(asyncio.gather(first, second), 2)
        self.send.assert_awaited_once()
        self.assertEqual(self.attempt()['admission'], self.permit)
        self.assert_inert()

    async def test_stale_unknown_history_still_consumes_row_capacity(self):
        self.send.side_effect = TimeoutError()
        await self.claim()
        self.store.detach(self.event['runtimeId'])
        self.now += RETENTION * 2
        self.store.cleanup()
        self.assert_history_capacity()

    def assert_history_capacity(self):
        self.store.max_rows = 1
        mapping = {key: self.event[key] for key in admission.ATTACHMENT_FIELDS}
        mapping.update(namespace='team/inbox', agentIncarnation=0, leaseExpiresAt=self.now + 60)
        mapping['attachmentGeneration'] += 1
        mapping['consumerGeneration'] += 1
        self.store.put_messaging_attachment(mapping)
        new = dict(self.event, eventId=OTHER, attachmentGeneration=mapping['attachmentGeneration'],
                   consumerGeneration=mapping['consumerGeneration'], issuedAt=_iso(self.now),
                   expiresAt=_iso(self.now + 60), observedAt=_iso(self.now - 1))
        new['deliveryId'] = protocol.derive_delivery_id(new)
        with self.assertRaisesRegex(StoreError, 'capacity'):
            self.store.accept(new)

    async def test_refusal_write_failure_retains_unknown_intent(self):
        outcome = {'status': 'over_budget', 'budget': {'used': 10, 'remaining': 0, 'limit': 10, 'windowMs': 3600000}}
        self.send.return_value = self.response(outcome)
        self.store.db.execute("CREATE TRIGGER fail_refusal BEFORE UPDATE OF evidence ON attempts BEGIN SELECT RAISE(ABORT, 'injected'); END")
        await self.claim()
        self.assertIsNone(self.attempt()['evidence'])
        await self.assert_unknown_survives()

    def test_refusal_writer_rejects_conflicting_outcomes(self):
        outcome = {'status': 'over_budget', 'budget': {'used': 10, 'remaining': 0, 'limit': 10, 'windowMs': 3600000}}
        delivery = self.event['deliveryId']
        self.store._begin_messaging_claim_history(delivery)
        self.store._record_messaging_claim_refusal(delivery, outcome)
        before = tuple(self.store.db.iterdump())
        conflicting = dict(outcome, budget=dict(outcome['budget'], used=11))
        with self.assertRaises(StoreError):
            self.store._record_messaging_claim_refusal(delivery, conflicting)
        with self.assertRaises(StoreError):
            self.store._record_messaging_admission_history(delivery, self.permit, node_id=self.event['nodeId'])
        self.assertEqual(tuple(self.store.db.iterdump()), before)

    async def test_begin_fence_and_capacity_failures_rollback_before_network(self):
        before = tuple(self.store.db.iterdump())
        for method, error in [('_matches', StoreError('attachment_fenced')),
                              ('_capacity', StoreError('capacity'))]:
            with self.subTest(method=method), patch.object(self.store, method, side_effect=error):
                with self.assertRaises(StoreError):
                    self.store._begin_messaging_claim_history(self.event['deliveryId'])
            self.assertEqual(tuple(self.store.db.iterdump()), before)
            self.assertIsNone(self.attempt())
        self.credentials.assert_not_awaited()
        self.send.assert_not_awaited()

    async def test_acquired_admission_survives_detach_retention_and_consumes_capacity(self):
        self.assertEqual(await self.claim(), self.permit)
        self.store.detach(self.event['runtimeId'])
        self.now += RETENTION * 2
        self.store.cleanup()
        self.reopen()
        self.assertEqual(await self.claim(), self.permit)
        self.assertEqual(self.attempt()['admission'], self.permit)
        self.assert_history_capacity()
        self.send.assert_awaited_once()
        self.assert_inert()

    async def test_detach_during_admitted_response_keeps_unknown_without_resend(self):
        async def detach_then_admit(**_):
            self.store.detach(self.event['runtimeId'])
            return self.response(self.permit)
        self.send.side_effect = detach_then_admit
        result = await self.claim()
        self.assertEqual(result['reason'], 'claim_outcome_unknown')
        self.assertEqual(self.store.delivery(self.event['deliveryId'])['status'], 'stale')
        await self.assert_unknown_survives()

    async def test_detach_during_refusal_preserves_closed_outcome_without_resend(self):
        outcome = {'status': 'over_budget', 'budget': {'used': 10, 'remaining': 0, 'limit': 10, 'windowMs': 3600000}}
        async def detach_then_refuse(**_):
            self.store.detach(self.event['runtimeId'])
            return self.response(outcome)
        self.send.side_effect = detach_then_refuse
        self.assertEqual(await self.claim(), outcome)
        self.assertEqual(self.attempt()['evidence'], outcome)
        self.assertEqual(self.attempt()['reason'], 'over_budget')
        self.assertEqual(self.attempt()['claim_uncertain'], 0)
        self.assertIsNone(self.attempt()['admission'])
        self.assertEqual(self.store.delivery(self.event['deliveryId'])['status'], 'stale')
        self.now += RETENTION * 2
        self.store.cleanup()
        self.reopen()
        before = tuple(self.store.db.iterdump())
        self.assertEqual(await self.claim(), outcome)
        self.assertEqual(tuple(self.store.db.iterdump()), before)
        self.send.assert_awaited_once()
        self.assert_inert()

    async def test_client_rejects_changed_timestamp_and_consumer_response_identity(self):
        changes = [('expiresAt', '2026-10-17T12:00:59.000Z'),
                   ('principal', 'other@example.com'), ('agent', 'other'),
                   ('nodeId', OTHER), ('runtimeId', OTHER),
                   ('nodeGeneration', self.event['nodeGeneration'] + 1),
                   ('runtimeGeneration', self.event['runtimeGeneration'] + 1),
                   ('routingGeneration', self.event['routingGeneration'] + 1),
                   ('canonicalSubject', dict(self.event['canonicalSubject'], agentIncarnation=1)),
                   ('consumerGeneration', self.event['consumerGeneration'] + 1)]
        for key, value in changes:
            with self.subTest(key=key):
                envelope = dict(self.event, **{key: value})
                if key == 'consumerGeneration':
                    envelope['attachmentGeneration'] = value
                envelope['deliveryId'] = protocol.derive_delivery_id(envelope)
                self.send.return_value = self.response(dict(self.permit, envelope=envelope))
                with self.assertRaises(CloudError) as caught:
                    await self.client.claim_messaging_history(self.event)
                self.assertTrue(caught.exception.ambiguous)
