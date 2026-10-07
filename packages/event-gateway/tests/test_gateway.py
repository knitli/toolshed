import asyncio
import copy
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway.cloud import _iso
from event_gateway.codex import CodexError
from event_gateway.gateway import Gateway, Refused
from event_gateway.native import EVENT_FIELDS, IDENTITY as NATIVE_IDENTITY, NativeBridgeAdapter
from event_gateway.protocol import _timestamp, derive_delivery_id
from event_gateway.security import SecurityError, sign
from event_gateway.store import Store, StoreError, IDENTITY, RETENTION


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / 'contracts/event-v1/protocol-v1.json').read_text())
CLOUD_FIXTURES = json.loads((ROOT / 'contracts/event-control-v1/fixtures.json').read_text())
NOW = 1791201630


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = NOW
        self.store = Store(Path(self.tmp.name).resolve() / 'private', clock=lambda: self.now)
        self.addCleanup(self.close_store)
        self.event = copy.deepcopy(FIXTURES['validEnvelopes'][0])
        self.mapping = {key: self.event[key] for key in IDENTITY}
        self.mapping.update(leaseExpiresAt=NOW + 3600, nativeThreadId=str(uuid.uuid4()))
        self.store.put_attachment(self.mapping)
        self.key = Ed25519PrivateKey.generate()
        self.claims, self.settlements, self.submissions, self.lookups, self.acknowledgments = [], [], [], [], []
        self.admissions = {}
        self.check_calls = 0
        self.busy = self.drop_claim = self.drop_settlement = self.drop_response = self.drop_acknowledgment = False
        self.after_check = self.after_claim = self.custom_submit = None
        self.outcome = 'started'
        self.recovered_outcome = 'unknown'
        self.item_id = str(uuid.uuid4())
        self.gateway = Gateway(self.store, self, lambda mapping: self,
                               audience='test-gateway', keys={'test': self.key.public_key()},
                               clock=lambda: self.now)

    def close_store(self):
        self.store.close()

    def accept(self, **overrides):
        body = json.dumps(self.event).encode()
        args = {'signature': sign(body, self.key, 'test-gateway'),
                'audience': 'test-gateway', 'key_id': 'test'}
        args.update(overrides)
        return self.gateway.accept(body, **args)

    def restart(self):
        path = self.store.path
        self.store.close()
        self.store = Store(path, clock=lambda: self.now)
        self.gateway.store = self.store

    async def check(self):
        self.check_calls += 1
        if self.after_check:
            self.after_check(self.check_calls)
        return 'busy' if self.busy else 'available'

    async def claim(self, envelope):
        self.claims.append(copy.deepcopy(envelope))
        if envelope['attemptId'] not in self.admissions:
            refreshed = dict(envelope, issuedAt=_iso(self.now), expiresAt=_iso(self.now + 60))
            self.admissions[envelope['attemptId']] = {
                'status': 'admitted', 'permitId': str(uuid.uuid4()), 'nodeId': str(uuid.uuid4()),
                'permitIssuedAt': _iso(self.now), 'permitExpiresAt': _iso(self.now + 5),
                'envelope': refreshed,
            }
        if self.after_claim:
            self.after_claim()
        if self.drop_claim:
            raise TimeoutError('lost claim response')
        return copy.deepcopy(self.admissions[envelope['attemptId']])

    async def prepare(self, admission):
        envelope = admission['envelope']
        return {'clientId': str(uuid.uuid4()), 'serverInstanceId': str(uuid.uuid4()),
                'serverGeneration': 1, 'threadId': self.mapping['nativeThreadId'], 'generation': 2,
                'clientUserMessageId': str(uuid.uuid4()), 'deliveryId': envelope['deliveryId'],
                'attemptId': envelope['attemptId'], 'permitId': admission['permitId'],
                'permitIssuedAt': _timestamp(admission['permitIssuedAt']),
                'permitExpiresAt': _timestamp(admission['permitExpiresAt']),
                'event': {key: envelope[key] for key in EVENT_FIELDS}}

    def receipt(self, request, status, *, replayed=False):
        outcome = {'status': status}
        if status in ('started', 'inputRecorded'):
            outcome.update(turnId=request['clientUserMessageId'], replayed=replayed)
            if status == 'inputRecorded':
                outcome['itemId'] = self.item_id
        elif status == 'terminalNotStarted':
            outcome.update(reason='busy', receiptId=str(uuid.uuid4()), replayed=replayed)
        elif status == 'notStarted':
            outcome.update(reason='busy')
        return {**{key: request[key] for key in NATIVE_IDENTITY}, 'outcome': outcome}

    async def submit(self, request):
        self.submissions.append(copy.deepcopy(request))
        if self.custom_submit:
            return await self.custom_submit(request)
        if self.drop_response:
            raise TimeoutError('lost native response')
        return self.receipt(request, self.outcome)

    async def reconcile(self, request):
        self.lookups.append(copy.deepcopy(request))
        return self.receipt(request, self.recovered_outcome, replayed=True)

    async def settle_no_start(self, admission, evidence):
        self.settlements.append((copy.deepcopy(admission), copy.deepcopy(evidence)))
        if self.drop_settlement:
            raise TimeoutError('lost settlement response')
        return {**{key: admission['envelope'][key] for key in ('deliveryId', 'attemptId', 'nodeGeneration')},
                'status': 'not_started', 'permitId': admission['permitId'], 'nodeId': admission['nodeId'],
                'evidence': evidence}

    async def acknowledge(self, envelope, acknowledgment):
        self.acknowledgments.append(copy.deepcopy(acknowledgment))
        attempt = self.store.current_attempt(acknowledgment['deliveryId'])
        # Explicit fake authority for the two native phases; no production parser bypass.
        observed = acknowledgment['status'] == 'observed'
        self.assertEqual(attempt['native_observed_ack' if observed else 'native_ack'], acknowledgment)
        if observed:
            self.assertEqual(attempt['ack_state'], 'submitted')
            self.assertIsNotNone(attempt['input_recorded_receipt'])
        self.assertEqual(envelope, attempt['admission']['envelope'])
        if self.drop_acknowledgment:
            self.drop_acknowledgment = False
            raise TimeoutError('lost ACK response')
        return {'status': acknowledgment['status'], 'current': False}

    async def test_input_only_recovery_orders_both_immutable_acks_across_lost_responses(self):
        ident = self.accept()['deliveryId']
        self.drop_response = True
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'ambiguous')
        original_attempt = self.store.current_attempt(ident)['attempt_id']
        self.recovered_outcome = 'inputRecorded'
        failures = {'submitted', 'observed'}
        acknowledge = self.acknowledge

        async def lose_each_phase_once(envelope, acknowledgment):
            result = await acknowledge(envelope, acknowledgment)
            phase = acknowledgment['status']
            if phase in failures:
                failures.remove(phase)
                raise TimeoutError('accepted ACK response lost')
            return result

        with patch.object(self, 'acknowledge', lose_each_phase_once):
            self.assertEqual((await self.gateway.reconcile(ident))['reason'], 'native_started_ack_pending')
            first = self.store.current_attempt(ident)
            self.assertIsNone(first['started_receipt'])
            self.assertEqual(first['input_recorded_receipt'], self.receipt(self.submissions[0], 'inputRecorded', replayed=True))
            self.assertIsNone(first['native_observed_ack'])
            self.assertIsNone(first['ack_state'])
            self.restart()
            self.now += 3601
            self.assertEqual((await self.gateway.reconcile(ident))['reason'], 'native_observed_ack_pending')
            pending = self.store.current_attempt(ident)
            self.assertEqual(pending['native_ack'], first['native_ack'])
            self.assertEqual(pending['ack_state'], 'submitted')
            self.assertGreater(pending['reserved_bytes'], 0)
            self.assertTrue(self.store.native_receipt(ident)['ack_pending'])
            self.restart()
            self.store.detach(self.mapping['runtimeId'])
            self.assertEqual((await self.gateway.reconcile(ident))['status'], 'observed')
        current = self.store.current_attempt(ident)
        self.assertIsNone(current['started_receipt'])
        self.assertEqual(current['input_recorded_receipt'], first['input_recorded_receipt'])
        self.assertEqual(current['native_ack'], first['native_ack'])
        self.assertEqual(current['native_observed_ack'], pending['native_observed_ack'])
        self.assertEqual(current['attempt_id'], original_attempt)
        self.assertEqual(current['native_observed_ack']['nativeCorrelation'], {
            'kind': 'native_input_recorded', 'permitId': current['admission']['permitId'],
            'turnId': self.submissions[0]['clientUserMessageId'], 'itemId': self.item_id})
        self.assertEqual(self.acknowledgments, [first['native_ack']] * 2 + [pending['native_observed_ack']] * 2)
        self.assertEqual(len(self.claims), 1)
        self.assertEqual(self.lookups, self.submissions)
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.settlements, [])
        self.assertEqual(current['reserved_bytes'], 0)
        self.assertFalse(self.store.native_receipt(ident)['ack_pending'])
        self.assertEqual(self.store.list_reconcilable(), [])

    async def test_registered_attempt_polls_core_without_lease_or_start_and_preserves_started(self):
        ident = self.accept()['deliveryId']
        await self.gateway.dispatch(ident)
        first = self.store.current_attempt(ident)
        checks = self.check_calls
        self.now += 3601
        self.busy = True
        self.recovered_outcome = 'inputRecorded'
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'observed')
        current = self.store.current_attempt(ident)
        self.assertEqual(current['started_receipt'], first['started_receipt'])
        self.assertEqual(current['native_ack'], first['native_ack'])
        self.assertEqual(current['input_recorded_receipt']['outcome']['itemId'], self.item_id)
        self.assertEqual(self.lookups, self.submissions)
        self.assertEqual(self.check_calls, checks)
        self.assertEqual(len(self.claims), 1)
        self.assertEqual(len(self.submissions), 1)
        self.restart()
        await self.gateway.reconcile(ident)
        await self.gateway.dispatch(ident)
        self.assertEqual(len(self.acknowledgments), 2)
        self.assertEqual(len(self.lookups), 1)
        self.assertEqual(len(self.submissions), 1)

    async def test_input_recovery_requires_mapping_and_full_valid_readonly_receipt(self):
        ident = self.accept()['deliveryId']
        self.drop_response = True
        await self.gateway.dispatch(ident)
        request = self.submissions[0]
        original = self.store.current_attempt(ident)['attempt_id']
        for mapping in (None, dict(self.mapping, nativeThreadId=str(uuid.uuid4())),
                        dict(self.mapping, attachmentGeneration=self.mapping['attachmentGeneration'] + 1)):
            with self.subTest(mapping=mapping), patch.object(self.store, 'get_attachment', return_value=mapping):
                self.assertEqual((await self.gateway.reconcile(ident))['status'], 'ambiguous')
        self.assertEqual(self.lookups, [])
        valid = self.receipt(request, 'inputRecorded', replayed=True)
        for invalid in (self.receipt(request, 'unknown'), self.receipt(request, 'started', replayed=False),
                        dict(valid, permitId=str(uuid.uuid4())),
                        dict(valid, outcome=dict(valid['outcome'], replayed=False)),
                        dict(valid, outcome=dict(valid['outcome'], itemId=request['clientUserMessageId']))):
            async def recover(_request):
                return invalid
            with self.subTest(receipt=invalid), patch.object(self, 'reconcile', recover):
                self.assertEqual((await self.gateway.reconcile(ident))['status'], 'ambiguous')
        current = self.store.current_attempt(ident)
        self.assertIsNone(current['input_recorded_receipt'])
        self.assertIsNone(current['native_ack'])
        self.assertIsNone(current['native_observed_ack'])
        self.assertEqual(current['attempt_id'], original)
        self.assertEqual(self.acknowledgments, [])
        self.assertEqual(len(self.claims), 1)
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.settlements, [])

    async def test_input_recorded_on_submit_cannot_ack_or_become_observed(self):
        ident = self.accept()['deliveryId']

        async def incorrect_start(request):
            return self.receipt(request, 'inputRecorded', replayed=True)
        self.custom_submit = incorrect_start
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'ambiguous')
        current = self.store.current_attempt(ident)
        self.assertIsNone(current['input_recorded_receipt'])
        self.assertIsNone(current['started_receipt'])
        self.assertEqual(self.acknowledgments, [])
        self.assertEqual(len(self.submissions), 1)

    async def test_authentication_and_current_attachment_before_dedup(self):
        self.accept()
        for args in ({'signature': ''}, {'audience': 'other'}, {'key_id': 'retired'}):
            with self.subTest(args=args), self.assertRaises((Refused, SecurityError)):
                self.accept(**args)
        self.store.detach(self.event['runtimeId'])
        with self.assertRaises(Refused):
            self.accept()
        self.assertEqual(self.claims, [])

    async def test_optional_consumer_generation_is_a_destination_fence(self):
        self.mapping['consumerGeneration'] = 3
        self.store.put_attachment(self.mapping)
        self.event['consumerGeneration'] = 4
        self.event['deliveryId'] = derive_delivery_id(self.event)
        with self.assertRaises(Refused):
            self.accept()
        self.assertIsNone(self.store.delivery(self.event['deliveryId']))
        self.event['consumerGeneration'] = 3
        self.event['deliveryId'] = derive_delivery_id(self.event)
        self.assertEqual(self.accept()['status'], 'queued')

    async def test_busy_transport_expiry_then_fresh_admission(self):
        ident = self.accept()['deliveryId']
        self.busy = True
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.assertEqual(self.claims, [])
        self.now += 120
        self.busy = False
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'submitted')
        self.assertEqual(self.store.current_attempt(ident)['admission']['envelope']['issuedAt'], _iso(self.now))
        await self.gateway.dispatch(ident)
        self.assertEqual(len(self.submissions), 1)

    async def test_claim_capacity_failure_stays_queued_without_authority_call(self):
        ident = self.accept()['deliveryId']
        self.store.max_bytes = self.store._size() + 1
        self.assertEqual((await self.gateway.dispatch(ident))['reason'], 'capacity')
        self.assertEqual(self.store.delivery(ident)['status'], 'queued')
        self.assertEqual(self.claims, [])
        self.store.max_bytes = 64 * 1024 * 1024
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'submitted')

    async def test_admission_persisted_before_post_admission_check(self):
        ident = self.accept()['deliveryId']
        witnessed = []
        self.after_check = lambda count: witnessed.append(self.store.current_attempt(ident)) if count == 2 else None
        await self.gateway.dispatch(ident)
        self.assertEqual(len(witnessed), 1)
        self.assertEqual(witnessed[0]['state'], 'admitted')
        self.assertEqual(witnessed[0]['admission'], self.admissions[self.event['attemptId']])

    async def test_native_request_writeahead_before_submit(self):
        ident = self.accept()['deliveryId']
        witnessed = []

        async def inspect(request):
            witnessed.append(self.store.current_attempt(ident))
            return self.receipt(request, 'started')

        self.custom_submit = inspect
        await self.gateway.dispatch(ident)
        self.assertEqual(len(witnessed), 1)
        self.assertEqual(witnessed[0]['state'], 'submitting')
        self.assertEqual(witnessed[0]['native_request'], self.submissions[0])

    async def _v3_ambiguous_bridge(self, *, lost_response=False):
        ident = self.accept()['deliveryId']
        witnessed = []
        owner = self

        class RecordingBridge:
            receipt_version = 3

            def challenge(self):
                return {'eligible': True, 'clientId': str(uuid.uuid4()),
                        'serverInstanceId': str(uuid.uuid4()), 'serverGeneration': 1,
                        'threadId': owner.mapping['nativeThreadId'], 'generation': 2}

            def start(self, request):
                owner.submissions.append(copy.deepcopy(request))
                durable = sqlite3.connect(f'file:{owner.store.path / "ledger.sqlite"}?mode=ro', uri=True)
                try:
                    state, request_json = durable.execute(
                        'SELECT state, native_request FROM attempts WHERE delivery_id=?', (ident,)).fetchone()
                    witnessed.append({'state': state, 'native_request': json.loads(request_json)})
                finally:
                    durable.close()
                if lost_response:
                    raise TimeoutError('lost native response')
                return {'status': 'unknown'}

            def restore_attempt(self, request):
                owner.lookups.append(('restore', copy.deepcopy(request)))

            def receipt(self, request):
                owner.lookups.append(('receipt', copy.deepcopy(request)))
                return owner.receipt(request, owner.recovered_outcome, replayed=True)['outcome']

        bridge = RecordingBridge()
        self.gateway.adapter_factory = lambda mapping: NativeBridgeAdapter(mapping, bridge)
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'ambiguous')
        self.assertEqual(len(witnessed), 1)
        self.assertEqual(witnessed[0]['state'], 'submitting')
        persisted = witnessed[0]['native_request']
        self.assertEqual(persisted.get('receiptVersion'), 3)
        self.assertEqual(self.submissions, [{k: v for k, v in persisted.items() if k != 'receiptVersion'}])
        self.restart()
        self.assertEqual(self.store.current_attempt(ident)['native_request'], persisted)
        return ident, bridge

    async def _assert_v3_restart_mode_fence(self, *, lost_response=False):
        ident, bridge = await self._v3_ambiguous_bridge(lost_response=lost_response)
        original = self.store.current_attempt(ident)
        bridge.receipt_version = 2
        for status in ('started', 'inputRecorded', 'terminalNotStarted'):
            self.recovered_outcome = status
            self.assertEqual((await self.gateway.reconcile(ident))['status'], 'ambiguous')
            current = self.store.current_attempt(ident)
            self.assertEqual(current['attempt_id'], original['attempt_id'])
            for field in ('started_receipt', 'input_recorded_receipt', 'receipt', 'native_ack', 'native_observed_ack'):
                self.assertIsNone(current[field])
        await self.gateway.dispatch(ident)
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.lookups, [])
        self.assertEqual(self.settlements, [])
        self.assertEqual(self.acknowledgments, [])
        bridge.receipt_version = 3
        self.recovered_outcome = 'inputRecorded'
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'observed')
        current = self.store.current_attempt(ident)
        self.assertEqual(current['input_recorded_receipt']['generation'], original['native_request']['generation'])
        self.assertEqual(current['ack_state'], 'observed')
        self.assertEqual([ack['status'] for ack in self.acknowledgments], ['submitted', 'observed'])
        self.assertEqual(self.lookups, [('restore', self.submissions[0]), ('receipt', self.submissions[0])])
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.settlements, [])

    async def test_v3_unknown_persists_mode_before_start_and_fences_restart(self):
        await self._assert_v3_restart_mode_fence()

    async def test_v3_lost_response_persists_mode_before_start_and_fences_restart(self):
        await self._assert_v3_restart_mode_fence(lost_response=True)

    async def test_v3_store_rejects_downgraded_receipts_without_adapter(self):
        ident, _bridge = await self._v3_ambiguous_bridge()
        attempt = self.store.current_attempt(ident)
        request = attempt['native_request']
        self.gateway.adapter_factory = lambda mapping: self
        for status, record in (('started', self.store.record_started),
                               ('inputRecorded', self.store.record_input_recorded),
                               ('terminalNotStarted', None)):
            with self.subTest(status=status):
                receipt = self.receipt(request, status, replayed=True)
                with self.assertRaises(StoreError):
                    if record:
                        record(ident, attempt['attempt_id'], receipt)
                    else:
                        self.store.begin_settlement(ident, attempt['attempt_id'],
                            {'type': 'native_terminal_no_start', 'receiptId': receipt['outcome']['receiptId']},
                            receipt=receipt)
                self.recovered_outcome = status
                self.assertEqual((await self.gateway.reconcile(ident))['status'], 'ambiguous')
        current = self.store.current_attempt(ident)
        for field in ('started_receipt', 'input_recorded_receipt', 'receipt', 'native_ack', 'native_observed_ack'):
            self.assertIsNone(current[field])
        self.assertEqual(current['attempt_id'], attempt['attempt_id'])
        self.assertEqual(self.settlements, [])
        self.assertEqual(self.acknowledgments, [])
        self.assertEqual(len(self.submissions), 1)

    async def test_post_admission_client_failure_settles_local_no_start(self):
        ident = self.accept()['deliveryId']

        def fail_second(count):
            if count == 2:
                raise CodexError('native_transport_failed')

        self.after_check = fail_second
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.settlements, [(self.admissions[self.event['attemptId']], {'type': 'local_not_submitted'})])
        self.assertNotEqual(self.store.delivery_envelope(ident)['attemptId'], self.event['attemptId'])

    async def test_permit_expiry_during_final_check_settles_without_submit(self):
        ident = self.accept()['deliveryId']
        self.after_check = lambda count: setattr(self, 'now', self.now + 6) if count == 2 else None
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.settlements[0][1], {'type': 'local_not_submitted'})

    async def test_claim_lease_renewal_preserves_native_admission(self):
        ident = self.accept()['deliveryId']
        renewed = dict(self.mapping, leaseExpiresAt=self.mapping['leaseExpiresAt'] + 3600)
        self.after_claim = lambda: self.store.put_attachment(renewed)
        row = await self.gateway.dispatch(ident)
        self.assertEqual(row['status'], 'submitted')
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.submissions[0]['attemptId'], self.event['attemptId'])
        self.assertEqual(self.store.current_attempt(ident)['admission'],
                         self.admissions[self.event['attemptId']])
        self.assertEqual(self.store.get_attachment(self.event['runtimeId']), renewed)
        self.assertEqual(self.settlements, [])

    async def test_expired_lease_allows_exact_terminal_lookup_and_stale_settlement(self):
        ident = self.accept()['deliveryId']
        self.drop_response = True
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'ambiguous')
        request = copy.deepcopy(self.submissions[0])
        self.now = self.mapping['leaseExpiresAt'] + 1
        self.recovered_outcome = 'terminalNotStarted'
        row = await self.gateway.reconcile(ident)
        self.assertEqual(row['status'], 'stale')
        self.assertEqual(self.lookups, [request])
        self.assertEqual(len(self.settlements), 1)
        self.assertEqual(self.settlements[0][0], self.admissions[self.event['attemptId']])
        self.assertEqual(self.settlements[0][1]['type'], 'native_terminal_no_start')
        retired = self.store.db.execute(
            'SELECT state,receipt,settlement FROM attempts WHERE attempt_id=?',
            (request['attemptId'],),
        ).fetchone()
        self.assertEqual(retired[0], 'settled')
        self.assertEqual(json.loads(retired[1])['outcome']['receiptId'],
                         self.settlements[0][1]['receiptId'])
        self.assertEqual(json.loads(retired[2])['status'], 'not_started')
        self.assertEqual(self.store.delivery_envelope(ident)['attemptId'], request['attemptId'])
        await self.gateway.dispatch(ident)
        self.assertEqual(self.submissions, [request])
        self.assertEqual(len(self.claims), 1)

    async def test_detach_after_claim_retires_without_submit(self):
        ident = self.accept()['deliveryId']
        self.after_claim = lambda: self.store.detach(self.event['runtimeId'])
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'stale')
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.settlements[0][1], {'type': 'local_not_submitted'})

    async def test_over_budget_claim_preserves_original_attempt_for_recovery(self):
        ident = self.accept()['deliveryId']

        async def over_budget(envelope):
            self.claims.append(copy.deepcopy(envelope))
            return copy.deepcopy(CLOUD_FIXTURES['overBudget'])

        with patch.object(self, 'claim', over_budget):
            row = await self.gateway.dispatch(ident)
        self.assertEqual(row['status'], 'claiming')
        self.assertEqual(row['reason'], 'over_budget')
        self.assertEqual(self.store.current_attempt(ident)['reason'], 'over_budget')
        self.restart()
        self.assertEqual(self.store.delivery(ident)['reason'], 'over_budget')
        with patch.object(self, 'claim', over_budget):
            row = await self.gateway.reconcile(ident)
        self.assertEqual(row['reason'], 'over_budget')
        self.assertEqual(self.claims, [self.event, self.event])
        self.assertEqual(self.store.current_attempt(ident)['envelope'], self.event)
        self.assertIsNone(self.store.current_attempt(ident)['admission'])
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.settlements, [])

    async def test_lost_claim_restarts_with_exact_original_then_retires(self):
        ident = self.accept()['deliveryId']
        self.drop_claim = True
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'claiming')
        self.restart()
        self.now += 120
        self.drop_claim = False
        await self.gateway.reconcile(ident)
        self.assertEqual(self.claims, [self.event, self.event])
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.settlements, [(self.admissions[self.event['attemptId']], {'type': 'local_not_submitted'})])
        self.assertEqual(self.store.delivery(ident)['status'], 'queued')
        self.assertNotEqual(self.store.delivery_envelope(ident)['attemptId'], self.event['attemptId'])

    async def test_lost_settlement_restarts_and_replays_only_settlement(self):
        ident = self.accept()['deliveryId']
        self.outcome, self.drop_settlement = 'terminalNotStarted', True
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'settlement_pending')
        pending = self.store.current_attempt(ident)
        self.restart()
        self.drop_settlement = False
        self.gateway.adapter_factory = lambda mapping: self.fail('settlement must not need a native client')
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'queued')
        self.assertEqual(self.settlements, [(pending['admission'], pending['evidence'])] * 2)
        self.assertEqual(len(self.claims), 1)
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.lookups, [])

    async def test_waiting_dispatch_reports_not_found_when_stale_delivery_pruned(self):
        ident = self.accept()['deliveryId']
        self.store.detach(self.event['runtimeId'])
        lock = asyncio.Lock()
        await lock.acquire()
        self.gateway._locks[self.event['runtimeId']] = lock
        task = asyncio.create_task(self.gateway.dispatch(ident))
        await asyncio.sleep(0)
        self.now += 2 * RETENTION
        try:
            self.assertEqual(self.store.cleanup(), 1)
        finally:
            lock.release()
        error = None
        try:
            await task
        except Exception as caught:
            error = caught
        self.assertIsInstance(error, Refused)
        self.assertEqual(error.code, 'not_found')
        self.assertEqual(self.claims, [])
        self.assertEqual(self.submissions, [])

    async def test_waiting_dispatch_refreshes_attempt_after_terminal_retirement(self):
        ident = self.accept()['deliveryId']
        self.outcome = 'terminalNotStarted'
        lock = asyncio.Lock()
        await lock.acquire()
        self.gateway._locks[self.event['runtimeId']] = lock
        tasks = [asyncio.create_task(self.gateway.dispatch(ident)) for _ in range(2)]
        await asyncio.sleep(0)
        lock.release()
        rows = await asyncio.gather(*tasks)
        self.assertEqual([row['status'] for row in rows], ['queued', 'queued'])
        self.assertEqual(len(self.submissions), 2)
        self.assertNotEqual(self.submissions[0]['attemptId'], self.submissions[1]['attemptId'])
        self.assertEqual([evidence['type'] for _, evidence in self.settlements],
                         ['native_terminal_no_start', 'native_terminal_no_start'])

    async def test_recovered_admission_clears_budget_reason_before_retirement(self):
        ident = self.accept()['deliveryId']
        self.assertTrue(self.store.begin_claim(ident))
        self.store.note_claim_budget(ident, self.event['attemptId'])
        with patch.object(self.store, 'begin_settlement', side_effect=StoreError('capacity')):
            await self.gateway.reconcile(ident)
        self.assertEqual(self.store.delivery(ident)['status'], 'admitted')
        self.assertIsNone(self.store.delivery(ident)['reason'])
        self.assertIsNone(self.store.current_attempt(ident)['reason'])
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.settlements, [])

    async def test_terminal_receipt_retires_then_allows_new_attempt(self):
        ident = self.accept()['deliveryId']
        self.outcome = 'terminalNotStarted'
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.assertEqual(self.settlements[0][1]['type'], 'native_terminal_no_start')
        retired = self.store.db.execute('SELECT receipt FROM attempts WHERE attempt_id=?', (self.event['attemptId'],)).fetchone()
        receipt = json.loads(retired[0])
        self.assertEqual(self.settlements[0][1]['receiptId'], receipt['outcome']['receiptId'])
        self.outcome = 'started'
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'submitted')
        self.assertNotEqual(self.submissions[0]['attemptId'], self.submissions[1]['attemptId'])
        self.assertEqual(self.submissions[0]['deliveryId'], self.submissions[1]['deliveryId'])

    async def test_started_receipt_gets_submitted_ack_and_never_restarts_native(self):
        ident = self.accept()['deliveryId']
        row = await self.gateway.dispatch(ident)
        self.assertEqual(row['status'], 'submitted')
        self.assertIsNone(row['reason'])
        attempt = self.store.current_attempt(ident)
        self.assertEqual(attempt['started_receipt'], self.receipt(self.submissions[0], 'started'))
        self.assertEqual(attempt['native_ack']['nativeCorrelation'], {
            'kind': 'native_turn_started', 'permitId': attempt['admission']['permitId'],
            'turnId': self.submissions[0]['clientUserMessageId'],
        })
        self.assertNotIn('submissionId', attempt['native_ack']['nativeCorrelation'])
        self.assertEqual(self.store.native_receipt(ident)['turn_id'], self.submissions[0]['clientUserMessageId'])
        self.assertIsNone(self.store.native_receipt(ident)['submission_id'])
        self.assertFalse(self.store.native_receipt(ident)['ack_pending'])
        self.assertEqual(len(self.acknowledgments), 1)
        self.restart()
        checks = self.check_calls
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'submitted')
        self.assertEqual(self.lookups, self.submissions)
        self.assertEqual(self.check_calls, checks)
        await self.gateway.dispatch(ident)
        self.assertEqual(self.settlements, [])
        self.assertEqual(len(self.acknowledgments), 1)
        self.assertEqual(len(self.submissions), 1)

    async def test_lost_native_ack_retries_exact_persisted_dto_after_restart(self):
        ident = self.accept()['deliveryId']
        self.drop_acknowledgment = True
        row = await self.gateway.dispatch(ident)
        self.assertEqual(row['reason'], 'native_started_ack_pending')
        persisted = self.store.current_attempt(ident)['native_ack']
        self.assertTrue(self.store.native_receipt(ident)['ack_pending'])
        self.restart()
        self.now += 3600
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'submitted')
        self.assertEqual(self.acknowledgments, [persisted, persisted])
        self.assertEqual(self.store.current_attempt(ident)['native_ack'], persisted)
        self.assertFalse(self.store.native_receipt(ident)['ack_pending'])
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.lookups, self.submissions)
        self.assertEqual(self.settlements, [])

    async def test_ack_storage_capacity_failure_keeps_receipt_and_sends_nothing(self):
        ident = self.accept()['deliveryId']
        record_started = self.store.record_started

        def record_then_fill(delivery_id, attempt_id, receipt):
            result = record_started(delivery_id, attempt_id, receipt)
            self.store.max_bytes = self.store._size()
            return result

        self.store.record_started = record_then_fill
        row = await self.gateway.dispatch(ident)
        self.assertEqual(self.acknowledgments, [])
        self.assertEqual(row['reason'], 'native_ack_persistence_pending')
        current = self.store.current_attempt(ident)
        self.assertIsNotNone(current['started_receipt'])
        self.assertIsNone(current['native_ack'])

    async def test_detach_after_ack_does_not_reopen_native_ack(self):
        ident = self.accept()['deliveryId']
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'submitted')
        self.store.detach(self.event['runtimeId'])
        self.gateway.adapter_factory = lambda mapping: self.fail('acknowledged start needs no native lookup')
        row = await self.gateway.reconcile(ident)
        self.assertEqual(len(self.acknowledgments), 1)
        self.assertEqual(row['status'], 'ambiguous')
        self.assertFalse(self.store.native_receipt(ident)['ack_pending'])

    async def test_ordinary_not_started_and_unknown_never_retire(self):
        ident = self.accept()['deliveryId']
        self.outcome = 'notStarted'
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'ambiguous')
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'ambiguous')
        await self.gateway.dispatch(ident)
        self.assertEqual(self.settlements, [])
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.store.delivery_envelope(ident)['attemptId'], self.event['attemptId'])

    async def test_malformed_and_mismatched_receipts_stay_unknown(self):
        ident = self.accept()['deliveryId']

        async def malformed(request):
            return {'outcome': {'status': 'started'}}

        self.custom_submit = malformed
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'ambiguous')

        async def mismatch(request):
            return dict(self.receipt(request, 'started', replayed=True), permitId=str(uuid.uuid4()))

        self.gateway.adapter_factory = lambda mapping: type('Lookup', (), {'reconcile': staticmethod(mismatch)})()
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'ambiguous')
        self.assertIsNone(self.store.current_attempt(ident)['started_receipt'])
        self.assertEqual(self.settlements, [])

    async def test_lost_native_response_restarts_read_only_then_recovers_terminal(self):
        ident = self.accept()['deliveryId']
        self.drop_response = True
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'ambiguous')
        self.restart()
        await self.gateway.dispatch(ident)
        self.recovered_outcome = 'terminalNotStarted'
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'queued')
        self.assertEqual(self.lookups, self.submissions)
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.settlements[0][1]['type'], 'native_terminal_no_start')

    async def test_detach_during_submit_preserves_authentic_positive(self):
        ident = self.accept()['deliveryId']

        async def detached(request):
            self.store.detach(self.event['runtimeId'])
            return self.receipt(request, 'started')

        self.custom_submit = detached
        self.assertEqual((await self.gateway.dispatch(ident))['status'], 'submitted')
        attempt = self.store.current_attempt(ident)
        self.assertEqual(attempt['started_receipt'], self.receipt(self.submissions[0], 'started'))
        self.assertEqual(self.store.native_receipt(ident)['turn_id'], self.submissions[0]['clientUserMessageId'])
        self.assertEqual(self.settlements, [])

    async def test_recovered_positive_is_immutable_and_never_resubmitted(self):
        ident = self.accept()['deliveryId']
        self.drop_response = True
        await self.gateway.dispatch(ident)
        self.restart()
        self.recovered_outcome = 'started'
        await self.gateway.reconcile(ident)
        receipt = self.receipt(self.submissions[0], 'started', replayed=True)
        self.assertEqual(self.store.current_attempt(ident)['started_receipt'], receipt)
        self.assertIsNone(self.store.delivery(ident)['reason'])
        self.assertFalse(self.store.native_receipt(ident)['ack_pending'])
        self.recovered_outcome = 'terminalNotStarted'
        await self.gateway.reconcile(ident)
        await self.gateway.dispatch(ident)
        self.assertEqual(self.store.current_attempt(ident)['started_receipt'], receipt)
        self.assertEqual(len(self.lookups), 2)
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.settlements, [])

    async def test_invalid_prepared_request_settles_local_without_submission(self):
        ident = self.accept()['deliveryId']

        async def invalid(admission):
            return {'permitId': admission['permitId']}

        with patch.object(self, 'prepare', invalid):
            self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.settlements[0][1], {'type': 'local_not_submitted'})

    async def test_v1_turn_id_is_rejected_before_native_submission(self):
        ident = self.accept()['deliveryId']
        prepare = self.prepare

        async def legacy_turn(admission):
            request = await prepare(admission)
            request['clientUserMessageId'] = str(uuid.uuid1())
            return request

        with patch.object(self, 'prepare', legacy_turn):
            self.assertEqual((await self.gateway.dispatch(ident))['status'], 'queued')
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.settlements[0][1], {'type': 'local_not_submitted'})

    async def test_reconciliation_rejects_replacement_destination(self):
        ident = self.accept()['deliveryId']
        self.drop_response = True
        await self.gateway.dispatch(ident)
        self.store.put_attachment(dict(self.mapping, consumerGeneration=1))
        self.recovered_outcome = 'started'
        self.assertEqual((await self.gateway.reconcile(ident))['reason'], 'attachment_fenced')
        self.assertEqual(self.lookups, [])
        self.assertIsNone(self.store.current_attempt(ident)['started_receipt'])

    async def test_cancelled_native_submission_is_retained_as_ambiguous(self):
        ident = self.accept()['deliveryId']
        entered = asyncio.Event()

        async def pending(request):
            entered.set()
            await asyncio.Event().wait()

        self.custom_submit = pending
        task = asyncio.create_task(self.gateway.dispatch(ident))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.store.delivery(ident)['status'], 'ambiguous')
        await self.gateway.dispatch(ident)
        self.assertEqual(len(self.submissions), 1)
        self.assertEqual(self.settlements, [])

    async def test_cancelled_post_admission_check_recovers_local_settlement(self):
        ident = self.accept()['deliveryId']
        entered = asyncio.Event()

        async def pending_check():
            self.check_calls += 1
            if self.check_calls == 2:
                entered.set()
                await asyncio.Event().wait()
            return 'available'

        with patch.object(self, 'check', pending_check):
            task = asyncio.create_task(self.gateway.dispatch(ident))
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(self.store.current_attempt(ident)['state'], 'admitted')
        self.restart()
        self.assertEqual((await self.gateway.reconcile(ident))['status'], 'queued')
        self.assertEqual(self.submissions, [])
        self.assertEqual(self.settlements[0][1], {'type': 'local_not_submitted'})


if __name__ == '__main__':
    unittest.main()
