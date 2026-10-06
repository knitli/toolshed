import asyncio
import copy
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway.codex import CodexAdapter, CodexError
from event_gateway.gateway import Gateway, Permit, Refused, identity
from event_gateway.security import SecurityError, sign
from event_gateway.store import Store, IDENTITY
from event_gateway.protocol import derive_delivery_id


FIXTURES = json.loads((Path(__file__).resolve().parents[1] / 'contracts/event-v1/protocol-v1.json').read_text())
NOW = 1791201630


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = NOW
        self.store = Store(Path(self.tmp.name).resolve() / 'private', clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.event = copy.deepcopy(FIXTURES['validEnvelopes'][0])
        self.mapping = {key: self.event[key] for key in IDENTITY}
        self.mapping['leaseExpiresAt'] = NOW + 3600
        self.store.put_attachment(self.mapping)
        self.key = Ed25519PrivateKey.generate()
        self.native_calls = 0
        self.check_calls = 0
        self.busy = False
        self.drop_response = False
        self.drop_ack = False
        self.ack_calls = 0
        self.after_admit = None
        self.after_check = None
        self.custom_submit = None
        self.receipt = {'status': 'unknown'}
        self.reconcile_calls = 0
        self.after_reconcile = None
        self.gateway = Gateway(self.store, self, lambda mapping: self,
                               audience='test-gateway', keys={'test': self.key.public_key()},
                               clock=lambda: self.now)

    def accept(self, body=None, **overrides):
        body = body or json.dumps(self.event).encode()
        args = {'signature': sign(body, self.key, 'test-gateway'),
                'audience': 'test-gateway', 'key_id': 'test'}
        args.update(overrides)
        return self.gateway.accept(body, **args)

    async def check(self):
        self.check_calls += 1
        if self.after_check:
            self.after_check(self.check_calls)
        return 'busy' if self.busy else 'available'

    async def admit(self, envelope):
        permit = Permit(envelope['deliveryId'], envelope['attemptId'], self.now,
                        self.now + 5, identity(envelope))
        if self.after_admit:
            self.after_admit()
        return permit

    async def submit(self, envelope):
        self.assertEqual(self.store.delivery(envelope['deliveryId'])['status'], 'submitting')
        self.native_calls += 1
        if self.custom_submit:
            return await self.custom_submit(envelope)
        if self.drop_response:
            raise TimeoutError()
        return {'submission_id': 'submission-1'}

    async def acknowledge(self, envelope, evidence):
        self.ack_calls += 1
        if self.drop_ack:
            raise OSError('injected lost ACK')

    async def reconcile(self, delivery_id, *, known_submission_id=None):
        self.reconcile_calls += 1
        if self.after_reconcile:
            self.after_reconcile()
        return self.receipt

    async def test_missing_native_mapping_is_bounded_unavailability(self):
        ident = self.accept()['deliveryId']
        self.gateway.adapter_factory = CodexAdapter
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.gateway.adapter_factory = lambda mapping: self
        await self.gateway.dispatch(ident)
        self.gateway.adapter_factory = CodexAdapter
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'submitted')
        self.assertEqual(self.native_calls, 1)

    async def test_authentication_and_current_attachment_before_dedup(self):
        self.accept()
        for args in ({'signature': ''}, {'audience': 'other'}, {'key_id': 'retired'}):
            with self.subTest(args=args), self.assertRaises((Refused, SecurityError)):
                self.accept(**args)
        self.store.detach(self.event['runtimeId'])
        with self.assertRaises(Refused):
            self.accept()
        self.assertEqual(self.native_calls, 0)

    async def test_busy_transport_expiry_then_fresh_admission(self):
        ident = self.accept()['deliveryId']
        self.busy = True
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.now += 120
        self.busy = False
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'submitted')
        await self.gateway.dispatch(ident)
        self.assertEqual(self.native_calls, 1)

    async def test_optional_consumer_generation_is_a_destination_fence(self):
        self.mapping['runtimeGeneration'] += 1
        self.mapping['consumerGeneration'] = 3
        self.store.put_attachment(self.mapping)
        self.event['runtimeGeneration'] += 1
        self.event['consumerGeneration'] = 4
        self.event['deliveryId'] = derive_delivery_id(self.event)
        with self.assertRaises(Refused):
            self.accept()
        self.assertIsNone(self.store.delivery(self.event['deliveryId']))
        self.event['consumerGeneration'] = 3
        self.event['deliveryId'] = derive_delivery_id(self.event)
        self.assertEqual(self.accept()['status'], 'queued')
        self.assertEqual(self.native_calls, 0)

    async def test_expired_permit_and_detach_across_await_do_not_submit(self):
        ident = self.accept()['deliveryId']
        self.after_admit = lambda: setattr(self, 'now', self.now + 6)
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.after_admit = None
        self.check_calls = 0
        self.after_check = lambda count: self.store.detach(self.event['runtimeId']) if count == 2 else None
        await self.gateway.dispatch(ident)
        self.assertEqual(self.native_calls, 0)

    async def test_post_admission_client_failure_stays_queued(self):
        ident = self.accept()['deliveryId']

        def fail_second_check(count):
            if count % 2 == 0:
                raise CodexError('native_transport_failed')

        self.after_check = fail_second_check
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.assertEqual(self.native_calls, 0)
        self.after_check = None
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'submitted')
        self.assertEqual(self.native_calls, 1)

    async def test_permit_expiry_during_final_client_check_is_fenced(self):
        ident = self.accept()['deliveryId']
        self.after_check = lambda count: setattr(self, 'now', self.now + 6) if count == 2 else None
        row = await self.gateway.dispatch(ident)
        self.assertEqual(row['reason'], 'admission_expired')
        self.assertEqual(row['status'], 'queued')
        self.assertEqual(self.native_calls, 0)

    async def test_submission_storage_capacity_stays_queued(self):
        ident = self.accept()['deliveryId']
        self.store.max_bytes = self.store._size() + 1
        row = await self.gateway.dispatch(ident)
        self.assertEqual(row['status'], 'queued')
        self.assertEqual(row['reason'], 'storage_capacity')
        self.assertEqual(self.native_calls, 0)
        self.store.max_bytes = 64 * 1024 * 1024
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'submitted')
        self.assertEqual(self.native_calls, 1)

    async def test_lost_native_response_is_ambiguous_and_never_replayed(self):
        ident = self.accept()['deliveryId']
        self.drop_response = True
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'ambiguous')
        await self.gateway.dispatch(ident)
        await self.gateway.reconcile(ident)
        await self.gateway.dispatch(ident)
        self.assertEqual(self.native_calls, 1)

    async def test_lost_cloud_ack_does_not_repeat_native_submission(self):
        ident = self.accept()['deliveryId']
        self.drop_ack = True
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'submitted')
        self.receipt = {'status': 'submitted', 'submission_id': 'submission-1'}
        await self.gateway.reconcile(ident)
        await self.gateway.dispatch(ident)
        self.assertEqual(self.native_calls, 1)

    async def test_submitted_ack_recovers_without_native_client(self):
        ident = self.accept()['deliveryId']
        self.drop_ack = True
        await self.gateway.dispatch(ident)
        self.now = self.mapping['leaseExpiresAt'] + 1
        self.drop_ack = False
        calls = self.ack_calls
        self.gateway.adapter_factory = lambda mapping: self.fail('expired client used')
        await self.gateway.reconcile(ident)
        self.assertEqual(self.ack_calls, calls + 1)
        self.assertFalse(self.store.native_receipt(ident)['ack_pending'])
        self.assertEqual(self.native_calls, 1)

    async def test_reconciliation_rejects_replacement_destination(self):
        ident = self.accept()['deliveryId']
        await self.gateway.dispatch(ident)
        self.mapping['consumerGeneration'] = 1
        self.store.put_attachment(self.mapping)
        self.receipt = {'status': 'observed', 'submission_id': 'submission-1', 'turn_id': 'turn-1'}
        calls = self.ack_calls
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'ambiguous')
        self.assertEqual(self.reconcile_calls, 0)
        self.assertEqual(self.ack_calls, calls)
        self.assertIsNone(self.store.native_receipt(ident)['turn_id'])

    async def test_reconciliation_fences_destination_changes_across_await(self):
        ident = self.accept()['deliveryId']
        await self.gateway.dispatch(ident)
        self.receipt = {'status': 'observed', 'submission_id': 'submission-1', 'turn_id': 'turn-1'}

        def transfer():
            self.mapping['consumerGeneration'] = 1
            self.store.put_attachment(self.mapping)

        self.after_reconcile = transfer
        calls = self.ack_calls
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'ambiguous')
        self.assertEqual(self.ack_calls, calls)
        self.assertIsNone(self.store.native_receipt(ident)['turn_id'])

    async def test_reconciliation_fences_lease_expiry_across_await(self):
        ident = self.accept()['deliveryId']
        await self.gateway.dispatch(ident)
        self.receipt = {'status': 'observed', 'submission_id': 'submission-1', 'turn_id': 'turn-1'}
        self.after_reconcile = lambda: setattr(self, 'now', self.mapping['leaseExpiresAt'] + 1)
        calls = self.ack_calls
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'submitted')
        self.assertEqual(self.ack_calls, calls)
        self.assertIsNone(self.store.native_receipt(ident)['turn_id'])

    async def test_malformed_observation_cannot_settle_ambiguous_delivery(self):
        ident = self.accept()['deliveryId']
        self.drop_response = True
        await self.gateway.dispatch(ident)
        self.receipt = {'status': 'observed', 'turn_id': '/private/session-path'}
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'ambiguous')

    async def test_observed_ack_loss_remains_durable_recovery_work(self):
        ident = self.accept()['deliveryId']
        await self.gateway.dispatch(ident)
        self.drop_ack = True
        self.receipt = {'status': 'observed', 'submission_id': 'submission-1', 'turn_id': 'turn-1'}
        await self.gateway.reconcile(ident)
        self.assertIn(ident, [row['deliveryId'] for row in self.store.list_reconcilable()])
        state_path = self.store.path
        self.store.close()
        self.store = Store(state_path, clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.gateway.store = self.store
        self.assertIn(ident, [row['deliveryId'] for row in self.store.list_reconcilable()])
        calls = self.ack_calls
        self.drop_ack = False
        await self.gateway.reconcile(ident)
        self.assertGreater(self.ack_calls, calls)
        self.assertEqual(self.native_calls, 1)

    async def test_cancelled_native_submission_is_retained_as_ambiguous(self):
        ident = self.accept()['deliveryId']
        entered = asyncio.Event()

        async def pending_submit(envelope):
            entered.set()
            await asyncio.Event().wait()

        self.custom_submit = pending_submit
        task = asyncio.create_task(self.gateway.dispatch(ident))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.store.delivery(ident)['status'], 'ambiguous')
        await self.gateway.dispatch(ident)
        self.assertEqual(self.native_calls, 1)

    async def test_detach_during_submit_preserves_successful_native_receipt(self):
        ident = self.accept()['deliveryId']

        async def detached_submit(envelope):
            self.store.detach(envelope['runtimeId'])
            return {'submission_id': 'submission-1'}

        self.custom_submit = detached_submit
        row = await self.gateway.dispatch(ident)
        self.assertEqual(row['status'], 'ambiguous')
        self.assertEqual(self.store.native_receipt(ident)['submission_id'], 'submission-1')
        await self.gateway.dispatch(ident)
        self.assertEqual(self.native_calls, 1)

    async def test_recovered_queue_receipt_is_retained_without_native_replay(self):
        ident = self.accept()['deliveryId']
        self.drop_response = True
        await self.gateway.dispatch(ident)
        self.receipt = {'status': 'submitted', 'submission_id': 'recovered-1'}
        await self.gateway.reconcile(ident)
        self.assertEqual(self.store.native_receipt(ident)['submission_id'], 'recovered-1')
        self.assertEqual(self.store.delivery(ident)['status'], 'ambiguous')
        self.receipt = {'status': 'observed', 'submission_id': 'recovered-1', 'turn_id': 'turn-1'}
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'observed')
        await self.gateway.dispatch(ident)
        self.assertEqual(self.native_calls, 1)

    async def test_conflicting_native_receipt_does_not_replace_persisted_evidence(self):
        ident = self.accept()['deliveryId']
        await self.gateway.dispatch(ident)
        self.receipt = {'status': 'observed', 'submission_id': 'different-submission', 'turn_id': 'turn-1'}
        await self.gateway.reconcile(ident)
        self.assertEqual(self.store.native_receipt(ident)['submission_id'], 'submission-1')
        self.assertNotEqual(self.store.delivery(ident)['status'], 'observed')


if __name__ == '__main__':
    unittest.main()
