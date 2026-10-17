"""Private admission history is inert, immutable, and transaction-fenced."""
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from event_gateway import messaging_admission_v2 as admission
from event_gateway import messaging_protocol_v2 as protocol
from event_gateway.gateway import Gateway
from event_gateway.store import Store, StoreError
from test_messaging_admission_v2 import FIXTURE, OTHER


class AdmissionHistoryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = FIXTURE['nowMs'] / 1000
        self.path = Path(self.tmp.name).resolve() / 'private'
        self.store = Store(self.path, clock=lambda: self.now)
        self.addCleanup(lambda: self.store.close())  # pylint: disable=unnecessary-lambda
        self.event = copy.deepcopy(FIXTURE['envelope'])
        mapping = {key: self.event[key] for key in admission.ATTACHMENT_FIELDS}
        mapping.update(namespace='team/inbox', agentIncarnation=0, leaseExpiresAt=self.now + 60)
        self.store.put_messaging_attachment(mapping)
        self.store.accept(self.event)
        self.store._begin_messaging_claim_history(self.event['deliveryId'])
        self.permit = dict(status='admitted', permitId=OTHER, nodeId=self.event['nodeId'],
                           permitIssuedAt='2026-10-17T12:00:30.000Z',
                           permitExpiresAt='2026-10-17T12:00:35.000Z', envelope=copy.deepcopy(self.event))

    def record(self, permit=None, **changes):
        return self.store._record_messaging_admission_history(
            self.event['deliveryId'], self.permit if permit is None else permit,
            node_id=changes.get('node_id', self.event['nodeId']))

    def snapshot(self):
        return tuple(self.store.db.iterdump())

    def test_expired_history_reopens_and_replays_without_rewriting(self):
        self.now += 10
        self.assertEqual(self.record(), self.permit)
        before = self.snapshot()
        self.assertEqual(self.record(), self.permit)
        self.assertEqual(self.snapshot(), before)
        self.store.close()
        self.store = Store(self.path, clock=lambda: self.now)
        attempt = self.store.current_attempt(self.event['deliveryId'])
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt['admission'], self.permit)
        self.assertEqual(attempt['envelope'], self.event)
        self.assertEqual(attempt['state'], 'held')
        self.assertEqual(attempt['reserved_bytes'], 0)
        attempt['admission']['permitId'] = self.event['nodeId']
        self.assertEqual(self.store.current_attempt(self.event['deliveryId'])['admission'], self.permit)
        self.assertEqual(self.record(), self.permit)
        self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(StoreError, 'admission_conflict'):
            self.record(dict(self.permit, permitId=self.event['nodeId']))
        self.assertEqual(self.snapshot(), before)

    def test_exact_attempt_envelope_and_complete_consumer_identity(self):
        before = self.snapshot()
        changes = [(key, OTHER if key.endswith('Id') else 'other')
                   for key in ('attemptId', 'runtimeId', 'nodeId', 'principal', 'agent')]
        changes += [(key, self.event[key] + 1) for key in
                    ('nodeGeneration', 'runtimeGeneration', 'attachmentGeneration',
                     'consumerGeneration', 'routingGeneration')]
        changes += [('canonicalSubject', dict(self.event['canonicalSubject'], namespace='other')),
                    ('canonicalSubject', dict(self.event['canonicalSubject'], agentIncarnation=1))]
        for key, value in changes:
            with self.subTest(key=key):
                envelope = dict(self.event, **{key: value})
                if key in ('attachmentGeneration', 'consumerGeneration'):
                    envelope['attachmentGeneration'] = envelope['consumerGeneration'] = value
                envelope['deliveryId'] = protocol.derive_delivery_id(envelope)
                with self.assertRaisesRegex(StoreError, 'invalid_admission'):
                    self.record(dict(self.permit, envelope=envelope))
                self.assertEqual(self.snapshot(), before)
        refreshed = dict(self.event, expiresAt='2026-10-17T12:00:59.000Z')
        with self.assertRaisesRegex(StoreError, 'invalid_admission'):
            self.record(dict(self.permit, envelope=refreshed))
        with self.assertRaisesRegex(StoreError, 'invalid_admission'):
            self.record(node_id=OTHER)
        self.assertEqual(self.snapshot(), before)

    def test_attachment_fence_is_inside_transaction_and_failure_rolls_back(self):
        before = self.snapshot()
        original = self.store._matches

        def expire_inside_transaction(envelope):
            self.assertTrue(self.store.db.in_transaction)
            mapping = self.store.get_attachment(envelope['runtimeId'])
            mapping['leaseExpiresAt'] = self.now
            self.store.db.execute('UPDATE attachments SET data=?',
                                  (protocol._json_bytes(mapping).decode(),))
            return original(envelope)
        with patch.object(self.store, '_matches', side_effect=expire_inside_transaction):
            with self.assertRaisesRegex(StoreError, 'attachment_fenced'):
                self.record()
        self.assertEqual(self.snapshot(), before)
        with patch.object(self.store, '_capacity', side_effect=StoreError('capacity')):
            with self.assertRaisesRegex(StoreError, 'capacity'):
                self.record()
        self.assertEqual(self.snapshot(), before)
        self.store.db.execute(
            "CREATE TRIGGER fail_history AFTER UPDATE OF admission ON attempts "
            "BEGIN SELECT RAISE(ABORT, 'injected history write failure'); END"
        )
        before = self.snapshot()
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'injected history write failure'):
            self.record()
        self.assertEqual(self.snapshot(), before)
        self.assertIsNone(self.store.current_attempt(self.event['deliveryId'])['admission'])
        self.assertEqual(self.store.current_attempt(self.event['deliveryId'])['claim_uncertain'], 1)

    async def test_history_never_enters_execution_ack_or_settlement(self):
        self.record()
        delivery_id, attempt_id = self.event['deliveryId'], self.event['attemptId']
        authority, adapter = Mock(), Mock()
        gateway = Gateway(self.store, authority, adapter, audience='local', keys={})
        before = self.snapshot()
        self.assertEqual((await gateway.dispatch(delivery_id))['status'], 'held')
        self.assertEqual((await gateway.reconcile(delivery_id))['status'], 'held')
        self.assertFalse(self.store.begin_claim(delivery_id))
        self.assertFalse(self.store.begin_submit(delivery_id))
        self.assertFalse(self.store.begin_native(delivery_id, attempt_id, {}))
        for operation in (
            lambda: self.store.record_admission(delivery_id, self.permit),
            lambda: self.store.record_started(delivery_id, attempt_id, {}),
            lambda: self.store.record_input_recorded(delivery_id, attempt_id, {}),
            lambda: self.store.persist_native_ack(delivery_id, attempt_id, {}),
            lambda: self.store.begin_settlement(delivery_id, attempt_id, {'type': 'local_not_submitted'}),
        ):
            with self.assertRaises(ValueError):
                operation()
        self.assertFalse(self.store.complete_settlement(delivery_id, attempt_id, {}))
        self.assertEqual(self.store.list_pending(), [])
        self.assertEqual(self.store.list_reconcilable(), [])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(authority.mock_calls, [])
        self.assertEqual(adapter.mock_calls, [])

    def test_detach_preserves_history_but_refuses_new_recording(self):
        self.record()
        self.store.detach(self.event['runtimeId'])
        before = self.snapshot()
        self.assertEqual(self.store.current_attempt(self.event['deliveryId'])['admission'], self.permit)
        self.assertEqual(self.store.delivery(self.event['deliveryId'])['status'], 'stale')
        with self.assertRaisesRegex(StoreError, 'invalid_transition'):
            self.record()
        self.assertEqual(self.snapshot(), before)
