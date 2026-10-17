"""Durable v2 metadata is authenticated, fenced, and never dispatchable."""
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway import messaging_admission_v2 as admission
from event_gateway import messaging_protocol_v2 as protocol
from event_gateway.gateway import Gateway
from event_gateway.security import sign
from event_gateway.store import Store, StoreError, IDENTITY
from event_gateway.protocol import derive_delivery_id
from test_messaging_admission_v2 import FIXTURE, OTHER


class MessagingJournalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = FIXTURE['nowMs'] / 1000
        self.path = Path(self.tmp.name).resolve() / 'private'
        self.store = Store(self.path, clock=lambda: self.now)
        # Resolve the store at cleanup because restart tests replace it.
        self.addCleanup(lambda: self.store.close())  # pylint: disable=unnecessary-lambda
        self.event = copy.deepcopy(FIXTURE['envelope'])
        self.mapping = {key: self.event[key] for key in admission.ATTACHMENT_FIELDS}
        self.mapping.update(namespace='team/inbox', agentIncarnation=0,
                            leaseExpiresAt=self.now + 60)
        self.key = Ed25519PrivateKey.generate()
        self.authority = Mock()
        self.adapter = Mock(side_effect=AssertionError('native adapter called'))
        self.gateway = Gateway(self.store, self.authority, self.adapter, audience='local',
                               keys={'test': self.key.public_key()}, clock=lambda: self.now)

    def accept(self, event=None, **changes):
        body = json.dumps(self.event if event is None else event).encode()
        args = dict(signature=sign(body, self.key, 'local'), audience='local', key_id='test',
                    node_id=self.event['nodeId'], runtime_id=self.event['runtimeId'])
        args.update(changes)
        return self.gateway.accept_messaging_v2(body, **args)

    def provision(self):
        self.store.put_messaging_attachment(self.mapping)

    def snapshot(self):
        return (self.store.db.execute('PRAGMA user_version').fetchone()[0],
                tuple(self.store.db.iterdump()))

    def test_v1_open_stays_four_v2_write_and_reopen_preserve_five(self):
        self.assertEqual(self.snapshot()[0], 4)
        self.store.close()
        self.store = Store(self.path, clock=lambda: self.now)
        self.assertEqual(self.snapshot()[0], 4)
        self.provision()
        self.assertEqual(self.snapshot()[0], 5)
        self.store.close()
        self.store = Store(self.path, clock=lambda: self.now)
        self.assertEqual(self.snapshot()[0], 5)
        self.assertEqual(self.store.get_attachment(self.event['runtimeId']), self.mapping)

    def test_authenticated_complete_envelope_is_held_and_not_pollable(self):
        self.provision()
        row = self.accept()
        self.assertEqual(row['status'], 'held')
        self.assertFalse(row['duplicate'])
        self.assertEqual(self.store.delivery_envelope(self.event['deliveryId']), self.event)
        self.assertEqual(self.store.list_pending(), [])
        self.assertEqual(self.store.list_reconcilable(), [])
        self.assertEqual(self.store.status()['counts'], {'held': 1})
        self.assertEqual(self.store.status()['pending'], 1)

    def test_invalid_authentication_has_zero_journal_writes(self):
        self.provision()
        before = self.snapshot()
        for changes in ({'signature': 'bad'}, {'audience': 'other'}, {'key_id': 'unknown'},
                        {'signature': sign(json.dumps(self.event).encode(),
                                           Ed25519PrivateKey.generate(), 'local')},
                        {'node_id': OTHER}, {'runtime_id': OTHER}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.accept(**changes)
            self.assertEqual(self.snapshot(), before)
        self.authority.assert_not_called()
        self.adapter.assert_not_called()

    def test_store_revalidates_digest_and_schema_without_residue(self):
        self.provision()
        before = self.snapshot()
        for changes in ({'deliveryId': 'dly_' + '0' * 64}, {'extra': 1},
                        {'nodeGeneration': True}, {'expiresAt': '2026-10-17T11:00:00.000Z'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.accept(dict(self.event, **changes))
            self.assertEqual(self.snapshot(), before)

    def test_refresh_attempt_and_timestamps_deduplicate_after_restart(self):
        self.provision()
        self.accept()
        self.store.close()
        self.store = Store(self.path, clock=lambda: self.now)
        refreshed = dict(self.event, attemptId=OTHER, issuedAt='2026-10-17T12:00:10.000Z',
                         expiresAt='2026-10-17T12:01:10.000Z')
        try:
            replay = self.store.accept(refreshed)
        except ValueError as exc:
            self.fail(f'Valid refreshed retry rejected: {exc}')
        self.assertTrue(replay['duplicate'])
        self.assertEqual(self.store.delivery_envelope(self.event['deliveryId']), self.event)
        self.assertEqual(self.store.status()['counts'], {'held': 1})

    def test_semantic_change_conflicts_without_replacing_original(self):
        self.provision()
        self.accept()
        before = self.snapshot()
        for changes in ({'sourceStateVersion': 'msg:' + 'b' * 64}, {'policyRevision': 2},
                        {'observedAt': '2026-10-17T11:59:46.000Z'}, {'eventReference': 'ref_' + OTHER}):
            with self.subTest(changes=changes):
                with self.assertRaises(StoreError) as caught:
                    self.store.accept(dict(self.event, **changes))
                self.assertEqual(caught.exception.code, 'conflict')
                self.assertEqual(self.snapshot(), before)

    def test_integral_floats_are_normalized_in_mapping_and_semantics(self):
        floating = {key: float(value) if isinstance(value, int) and not isinstance(value, bool) else value
                    for key, value in self.mapping.items()}
        try:
            self.store.put_messaging_attachment(floating)
        except ValueError as exc:
            self.fail(f'Valid integral floats rejected: {exc}')
        saved = self.store.get_attachment(self.event['runtimeId'])
        self.assertIs(type(saved['nodeGeneration']), int)
        self.assertIs(type(saved['agentIncarnation']), int)
        self.accept()
        event = {key: float(value) if isinstance(value, int) and not isinstance(value, bool) else value
                 for key, value in self.event.items()}
        event['canonicalSubject'] = dict(event['canonicalSubject'], agentIncarnation=0.0)
        try:
            replay = self.store.accept(event)
        except ValueError as exc:
            self.fail(f'Equivalent integral-float retry rejected: {exc}')
        self.assertTrue(replay['duplicate'])

    def test_every_attachment_tuple_field_fences_direct_accept(self):
        self.provision()
        for field in (*admission.ATTACHMENT_FIELDS, 'namespace', 'agentIncarnation'):
            mapping = dict(self.mapping)
            value = mapping[field]
            mapping[field] = value + 1 if isinstance(value, int) and not isinstance(value, bool) else (
                OTHER if field in ('nodeId', 'runtimeId') else 'other')
            with self.store.db:
                self.store.db.execute('UPDATE attachments SET data=?', (json.dumps(mapping),))
            before = self.snapshot()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.store.accept(self.event)
            self.assertEqual(self.snapshot(), before)

    def test_exact_metadata_dto_rejects_invalid_values_and_native_routes(self):
        before = self.snapshot()
        for changes in ({'nativeThreadId': OTHER}, {'extra': 1}, {'agentIncarnation': False},
                        {'nodeGeneration': 1.5}, {'nodeId': 'bad'}, {'namespace': ''},
                        {'leaseExpiresAt': self.now}, {'leaseExpiresAt': float('inf')},
                        {'leaseExpiresAt': 10**400}, {'leaseExpiresAt': True},
                        {'principal': 'invalid'}, {'nodeGeneration': False},
                        {'runtimeGeneration': 0}, {'routingGeneration': 2**53},
                        {'agentIncarnation': -1}, {'namespace': 'a' * 257}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.put_messaging_attachment(dict(self.mapping, **changes))
            self.assertEqual(self.snapshot(), before)
        for field in self.mapping:
            missing = dict(self.mapping)
            del missing[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.store.put_messaging_attachment(missing)
            self.assertEqual(self.snapshot(), before)

    def test_rotation_fences_held_and_cannot_reset_generations(self):
        self.provision()
        self.accept()
        rotated = dict(self.mapping, attachmentGeneration=4, consumerGeneration=4)
        self.store.put_messaging_attachment(rotated)
        self.assertEqual(self.store.delivery(self.event['deliveryId'])['status'], 'stale')
        before = self.snapshot()
        with self.assertRaises(StoreError):
            self.store.put_messaging_attachment(self.mapping)
        self.assertEqual(self.snapshot(), before)

    def test_detach_fences_held_and_same_generation_cannot_reattach(self):
        self.provision()
        self.accept()
        self.store.detach(self.event['runtimeId'])
        self.assertEqual(self.store.delivery(self.event['deliveryId'])['status'], 'stale')
        self.assertIsNone(self.store.get_attachment(self.event['runtimeId']))
        before = self.snapshot()
        with self.assertRaises(StoreError):
            self.provision()
        self.assertEqual(self.snapshot(), before)

    def test_v1_provisioning_cannot_accept_v2_metadata_or_downgrade(self):
        with self.assertRaises(ValueError):
            self.store.put_attachment(self.mapping)
        self.provision()
        before = self.snapshot()
        legacy = {key: self.mapping[key] for key in IDENTITY}
        legacy.update(leaseExpiresAt=self.now + 60, nativeThreadId=OTHER,
                      runtimeGeneration=3, attachmentGeneration=4)
        with self.assertRaises(ValueError):
            self.store.put_attachment(legacy)
        self.assertEqual(self.snapshot(), before)

    def test_messaging_writer_cannot_take_over_any_v1_attachment(self):
        routes = ({}, {'nativeThreadId': OTHER}, {
            'sessionId': OTHER, 'nativeThreadId': OTHER,
            'nativeBinding': {'clientId': OTHER, 'connectionId': OTHER, 'backendPid': 123,
                              'threadId': OTHER, 'generation': 2,
                              'serverInstanceId': OTHER, 'serverGeneration': 3},
        })
        for index, route in enumerate(routes):
            for detached in (False, True):
                self.store.close()
                self.store = Store(self.path / f'case-{index}-{detached}', clock=lambda: self.now)
                with self.subTest(route=route, detached=detached):
                    legacy = {key: self.mapping[key] for key in IDENTITY}
                    legacy.update(leaseExpiresAt=self.now + 60, **route)
                    self.store.put_attachment(legacy)
                    if detached:
                        self.store.detach(legacy['runtimeId'])
                    before = self.snapshot()
                    with self.assertRaises(StoreError) as caught:
                        self.provision()
                    self.assertEqual(caught.exception.code, 'invalid_attachment')
                    self.assertEqual(self.snapshot(), before)
                    self.assertEqual(self.snapshot()[0], 4)

    def test_same_event_id_coexists_in_v1_and_v2(self):
        self.provision()
        self.accept()
        fixture = Path(__file__).resolve().parents[1] / 'contracts/event-v1/protocol-v1.json'
        event = json.loads(fixture.read_text())['validEnvelopes'][0]
        event.update(eventId=self.event['eventId'], runtimeId=OTHER,
                     issuedAt=self.event['issuedAt'], expiresAt=self.event['expiresAt'])
        event['deliveryId'] = derive_delivery_id(event)
        mapping = {key: event[key] for key in IDENTITY}
        mapping.update(leaseExpiresAt=self.now + 60, nativeThreadId=OTHER)
        self.store.put_attachment(mapping)
        self.assertEqual(self.store.accept(event)['status'], 'queued')
        self.assertNotEqual(event['deliveryId'], self.event['deliveryId'])
        self.assertEqual(self.store.status()['counts'], {'held': 1, 'queued': 1})

    async def test_explicit_dispatch_reconcile_never_contact_external_authority(self):
        self.provision()
        self.accept()
        for state in ('held', 'queued', 'admitted', 'ambiguous'):
            with self.store.db:
                self.store.db.execute('UPDATE deliveries SET state=?', (state,))
            before = self.snapshot()
            self.assertEqual(self.store.list_pending(), [])
            self.assertEqual(self.store.list_reconcilable(), [])
            for method in (self.gateway.dispatch, self.gateway.reconcile):
                with self.subTest(state=state, method=method.__name__):
                    result = await method(self.event['deliveryId'])
                    self.assertEqual(result['reason'], 'messaging_v2_disabled')
                    self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.authority.mock_calls, [])
        self.adapter.assert_not_called()

    def test_store_active_entrypoints_refuse_artificially_queued_or_admitted_v2(self):
        self.provision()
        self.accept()
        delivery = self.event['deliveryId']
        permit = dict(status='admitted', permitId=OTHER, nodeId=self.event['nodeId'],
                      permitIssuedAt='2026-10-17T12:00:30.000Z',
                      permitExpiresAt='2026-10-17T12:00:35.000Z', envelope=self.event)
        for state in ('held', 'queued', 'admitted'):
            with self.store.db:
                self.store.db.execute('UPDATE deliveries SET state=?', (state,))
            before = self.snapshot()
            self.assertFalse(self.store.begin_claim(delivery))
            self.assertFalse(self.store.begin_submit(delivery))
            self.assertEqual(self.snapshot(), before)
        with self.store.db:
            self.store.db.execute(
                "INSERT INTO attempts (delivery_id,attempt_id,state,envelope,admission,reserved_bytes,updated) "
                "VALUES (?,?,'admitted',?,?,1000000,?)",
                (delivery, self.event['attemptId'], json.dumps(self.event), json.dumps(permit), self.now))
        before = self.snapshot()
        with patch('event_gateway.native.validate_request', return_value={}) as validate:
            self.assertFalse(self.store.begin_native(delivery, self.event['attemptId'], {}))
            validate.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        evidence = {'kind': 'not_started'}
        with self.store.db:
            self.store.db.execute("UPDATE attempts SET state='settlement_pending',evidence=?",
                                  (json.dumps(evidence),))
            self.store.db.execute("UPDATE deliveries SET state='settlement_pending'")
        result = {key: self.event[key] for key in ('deliveryId', 'attemptId', 'nodeGeneration')}
        result.update(status='not_started', permitId=OTHER, nodeId=self.event['nodeId'], evidence=evidence)
        before = self.snapshot()
        self.assertFalse(self.store.complete_settlement(delivery, self.event['attemptId'], result))
        self.assertEqual(self.snapshot(), before)

    def test_held_rows_consume_capacity_without_second_delivery_residue(self):
        self.store.max_rows = 1
        self.provision()
        self.accept()
        event = dict(self.event, eventId=OTHER)
        event['deliveryId'] = protocol.derive_delivery_id(event)
        before = self.snapshot()
        with self.assertRaises(StoreError) as caught:
            self.store.accept(event)
        self.assertEqual(caught.exception.code, 'capacity')
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.store.status()['blockedReason'], 'pending_capacity')

    def test_failed_first_mapping_write_rolls_back_schema_version(self):
        self.store.db.execute("CREATE TRIGGER fail_mapping BEFORE INSERT ON attachments BEGIN SELECT RAISE(ABORT, 'injected'); END")
        before = self.snapshot()
        with self.assertRaises((StoreError, sqlite3.Error)):
            self.provision()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.snapshot()[0], 4)

    def test_failed_delivery_write_leaves_no_delivery_or_attempt(self):
        self.provision()
        self.store.db.execute("CREATE TRIGGER fail_delivery BEFORE INSERT ON deliveries BEGIN SELECT RAISE(ABORT, 'injected'); END")
        before = self.snapshot()
        with self.assertRaises((StoreError, sqlite3.Error)):
            self.accept()
        self.assertEqual(self.snapshot(), before)

    def test_finish_cannot_manufacture_native_evidence_for_held(self):
        self.provision()
        self.accept()
        before = self.snapshot()
        for status, fields in (('submitted', {'submission_id': OTHER}),
                               ('observed', {'submission_id': OTHER, 'turn_id': OTHER}),
                               ('stale', {'turn_id': OTHER})):
            with self.subTest(status=status), self.assertRaises(StoreError):
                self.store.finish(self.event['deliveryId'], status, **fields)
            self.assertEqual(self.snapshot(), before)
        self.store.finish(self.event['deliveryId'], 'stale')
        self.assertEqual(self.store.delivery(self.event['deliveryId'])['status'], 'stale')

    def test_expired_held_retains_capacity_until_explicit_retirement(self):
        self.provision()
        self.accept()
        self.now += 1000000
        self.store.cleanup()
        self.assertEqual(self.store.status()['pending'], 1)
        self.assertEqual(self.store.delivery(self.event['deliveryId'])['status'], 'held')
        self.store.detach(self.event['runtimeId'])
        self.assertEqual(self.store.status()['pending'], 0)

    def test_first_delivery_upgrades_and_failed_write_rolls_back_version(self):
        # Model trusted mapping metadata staged in a schema4 journal.
        with self.store.db:
            self.store.db.execute('INSERT INTO attachments VALUES (?,?)',
                                  (self.event['runtimeId'], json.dumps(self.mapping)))
        self.store.db.execute("CREATE TRIGGER fail_delivery BEFORE INSERT ON deliveries BEGIN SELECT RAISE(ABORT, 'injected'); END")
        before = self.snapshot()
        with self.assertRaises((StoreError, sqlite3.Error)):
            self.accept()
        self.assertEqual(self.snapshot(), before)
        self.store.db.execute('DROP TRIGGER fail_delivery')
        self.accept()
        self.assertEqual(self.snapshot()[0], 5)

    def test_metadata_rotation_fences_and_incarnation_cannot_reset(self):
        self.provision()
        self.accept()
        rotated = dict(self.mapping, agentIncarnation=1, routingGeneration=5,
                       namespace='team/other', nodeId=OTHER)
        self.store.put_messaging_attachment(rotated)
        self.assertEqual(self.store.delivery(self.event['deliveryId'])['status'], 'stale')
        before = self.snapshot()
        with self.assertRaises(StoreError):
            self.store.put_messaging_attachment(dict(rotated, agentIncarnation=0, routingGeneration=6))
        self.assertEqual(self.snapshot(), before)

    def test_legacy_transfer_cannot_revoke_messaging_source(self):
        self.provision()
        target = {key: self.mapping[key] for key in IDENTITY}
        target.update(runtimeId=OTHER, runtimeGeneration=3, attachmentGeneration=4,
                      leaseExpiresAt=self.now + 60, nativeThreadId=OTHER)
        transfer = dict(sourceRuntimeId=self.event['runtimeId'], expectedRuntimeGeneration=2,
                        expectedAttachmentGeneration=3, runtimeGeneration=3, attachmentGeneration=4)
        before = self.snapshot()
        for method in (self.store.put_attachment, self.store.revoke_transfer_source):
            with self.subTest(method=method.__name__), self.assertRaises(StoreError):
                method(target, transfer=transfer)
            self.assertEqual(self.snapshot(), before)

    def test_active_v1_ingress_rejects_v2_and_v1_cannot_use_v2_mapping(self):
        self.provision()
        before = self.snapshot()
        body = json.dumps(self.event).encode()
        with self.assertRaises(ValueError):
            self.gateway.accept(body, signature=sign(body, self.key, 'local'),
                                audience='local', key_id='test')
        fixture = Path(__file__).resolve().parents[1] / 'contracts/event-v1/protocol-v1.json'
        legacy = json.loads(fixture.read_text())['validEnvelopes'][0]
        legacy.update({key: self.mapping[key] for key in IDENTITY})
        legacy.update(consumerGeneration=self.mapping['consumerGeneration'],
                      issuedAt=self.event['issuedAt'], expiresAt=self.event['expiresAt'])
        legacy['deliveryId'] = derive_delivery_id(legacy)
        with self.assertRaises(StoreError):
            self.store.accept(legacy)
        self.assertEqual(self.snapshot(), before)
