"""Separately opt-in in-flight workerd SIGKILL matrix; offline preparation is not qualification."""
import json
import asyncio
import base64
import importlib.util
from copy import deepcopy
import os
from pathlib import Path
import signal
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from event_gateway.cloud import CloudClient, CloudError, Credentials

import test_messaging_process_restart as process_fixture
from test_messaging_workerd import SETTINGS, fixture


def assert_reservation_budget(case, budget, attempt_id, *, charged):
    if budget is None:
        budget = {}
    case.assertIsInstance(budget, dict)
    if not charged:
        case.assertEqual(budget.get('eventAttempts', []), [])
        case.assertEqual(budget.get('wakes', []), [])
        case.assertIsNone(budget.get('pendingSince'))
        case.assertIsNone(budget.get('pendingToken'))
        return
    case.assertEqual(len(budget['eventAttempts']), 1)
    case.assertEqual(len(budget['wakes']), 1)
    record = budget['eventAttempts'][0]
    case.assertEqual(record['attemptId'], attempt_id)
    case.assertEqual(record['decision'], 'reserved')
    stamp = record['recordedAt']
    for value in (stamp, record['reservedAt'], budget['wakes'][0], budget['pendingSince']):
        case.assertIs(type(value), int)
        case.assertGreater(value, 0)
        case.assertEqual(value, stamp)
    case.assertEqual(budget['pendingToken'], 'event:' + attempt_id)


def assert_admission_permit(case, permit):
    case.assertIsInstance(permit, str)
    try:
        parsed = UUID(permit)
    except ValueError:
        case.fail('admission permit must be a nonempty valid UUID')
    case.assertEqual(str(parsed), permit)


class AbruptCrashSafetyTests(unittest.TestCase):
    def test_budget_oracle_accepts_empty_and_exact_reserved_ledgers(self):
        for budget in (None, {}, {'wakes': [], 'eventAttempts': [], 'pendingSince': None, 'pendingToken': None}):
            assert_reservation_budget(self, budget, 'attempt', charged=False)
        assert_reservation_budget(self, self.reserved_budget(), 'attempt', charged=True)

    def reserved_budget(self):
        stamp = 1700000000000
        return {'eventAttempts': [{'attemptId': 'attempt', 'decision': 'reserved',
                                   'recordedAt': stamp, 'reservedAt': stamp}],
                'wakes': [stamp], 'pendingSince': stamp, 'pendingToken': 'event:attempt'}

    def test_budget_oracle_rejects_partial_wrong_or_duplicate_reservations(self):
        for field, value in (('attemptId', 'other'), ('decision', 'over_budget'),
                             ('recordedAt', None), ('recordedAt', 1700000000001),
                             ('reservedAt', 1700000000001), ('reservedAt', True)):
            budget = self.reserved_budget()
            budget['eventAttempts'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                assert_reservation_budget(self, budget, 'attempt', charged=True)
        for field, value in (('wakes', []), ('wakes', [1700000000001]),
                             ('wakes', [1700000000000] * 2), ('eventAttempts', []),
                             ('eventAttempts', self.reserved_budget()['eventAttempts'] * 2),
                             ('pendingSince', None), ('pendingSince', 1700000000001),
                             ('pendingToken', 'event:other'), ('pendingToken', None)):
            budget = self.reserved_budget() | {field: deepcopy(value)}
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                assert_reservation_budget(self, budget, 'attempt', charged=True)
        for field, value in (('wakes', [1]), ('eventAttempts', [{}]),
                             ('pendingSince', 0), ('pendingToken', '')):
            with self.subTest(uncharged_field=field), self.assertRaises(AssertionError):
                assert_reservation_budget(self, {field: value}, 'attempt', charged=False)

    def test_permit_oracle_requires_a_nonempty_valid_uuid(self):
        assert_admission_permit(self, '68a4de23-85ef-48d9-9fbd-73937fc99852')
        for permit in (None, '', 'same-invalid-value', 1, True,
                       '68a4de23-85ef-48d9-9fbd-73937fc9985z'):
            with self.subTest(permit=permit), self.assertRaises(AssertionError):
                assert_admission_permit(self, permit)

    def test_kill_marker_rejects_wrong_missing_malformed_and_oversized_evidence(self):
        spec = importlib.util.spec_from_file_location('crash_marker_fixture', process_fixture.CHILD)
        child = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(child)
        expected = {'phase': 'after-reserve', 'brokerPid': 123}
        valid = expected | {'oldPid': 456}
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'marker'
            missing = child.read_crash_marker(marker, expected)
            self.assertIsNone(missing)
            marker.write_text(json.dumps(valid))
            self.assertEqual(child.read_crash_marker(marker, expected), valid)
            self.assertIsNone(missing)
            for value in (valid | {'phase': 'other'}, valid | {'brokerPid': 999},
                          valid | {'oldPid': True}, valid | {'oldPid': 0}, valid | {'extra': True}, []):
                marker.write_text(json.dumps(value))
                self.assertIsNone(child.read_crash_marker(marker, expected))
            for raw in ('not-json', json.dumps(valid) + ' ' * 1024):
                marker.write_text(raw)
                self.assertIsNone(child.read_crash_marker(marker, expected))

    def test_crash_fixture_requires_separate_opt_in_before_any_child(self):
        with (patch.dict(os.environ, {'FIXTURE_ABRUPT_CLOUD_CRASH': ''}),
              patch('test_messaging_workerd.subprocess.Popen') as spawn,
              self.assertRaisesRegex(RuntimeError, 'separate reviewed execution opt-in')):
            with fixture(abrupt_crash=True):
                self.fail('unreviewed fixture started')
        spawn.assert_not_called()

    def test_broker_pipe_drainer_caps_bytes_and_requests_owned_group_cleanup(self):
        process = Mock(pid=123)
        process.stderr.fileno.return_value = 17
        capture = {'prefix': bytearray(), 'error': None}
        selector = Mock()
        selector.select.return_value = [True]
        with (patch.object(process_fixture.selectors, 'DefaultSelector') as factory,
              patch.object(os, 'read', side_effect=[b'a' * 4096, b'b' * 3904, b'c']),
              patch.object(os, 'killpg') as kill):
            factory.return_value.__enter__.return_value = selector
            process_fixture._drain_stderr(process, capture, threading.Event())
        self.assertEqual(len(capture['prefix']), 8000)
        self.assertIsInstance(capture['error'], OverflowError)
        kill.assert_called_once_with(process.pid, signal.SIGKILL)


@unittest.skipUnless(all(os.environ.get(key) for key in SETTINGS)
                     and os.environ.get('FIXTURE_ABRUPT_CLOUD_CRASH') == 'reviewed',
                     'requires separately reviewed abrupt workerd crash execution')
class MessagingAbruptCloudCrashTests(unittest.TestCase):
    def test_unknown_commit_matrix_preserves_held_history_without_resend(self):
        cases = [(phase, None) for phase in ('before-reserve', 'after-reserve', 'after-admission')]
        cases += [(phase, change) for phase in ('before-reserve', 'after-reserve')
                  for change in ('consumer', 'route', 'source', 'key')]
        cases.append(('after-reserve', 'positive-replay'))
        for phase, change in cases:
            with self.subTest(phase=phase, change=change), fixture(abrupt_crash=True) as (ledger, address, transport, seed):
                broker = transport.broker_process
                self.assertEqual(broker.pid, address['pid'])
                self.assertIsNone(broker.poll())
                directory = ledger.parent
                native_log, http_log = directory / 'native-calls', directory / 'http-calls'
                native_log.touch(mode=0o600)
                http_log.touch(mode=0o600)
                config = directory / 'child.json'
                config.write_text(json.dumps({'ledger': str(ledger), 'address': address, 'seed': seed,
                                              'nativeLog': str(native_log), 'httpLog': str(http_log),
                                              'crashMarker': str(directory / 'cloud-crash-injected'),
                                              'crashExpected': {'phase': phase, 'brokerPid': broker.pid}}))
                initial_cloud = transport.fixture('/fixture/read')
                self.assertEqual(transport.fixture('/fixture/arm-crash', {'phase': phase}), {'armed': True})
                with process_fixture.gateway_child(config, 'restart') as (first, uncertain):
                    self.assertEqual(first.wait(timeout=5), 0)
                proof = transport.fixture('/fixture/crash-proof')
                self.assertIsNone(broker.poll())
                self.assertEqual(proof['phase'], phase)
                self.assertEqual(proof['brokerPid'], address['pid'])
                self.assertIs(proof['requestOpenAtKill'], True)
                self.assertEqual(uncertain['crashObservation'], {
                    'phase': phase, 'brokerPid': broker.pid, 'oldPid': proof['oldPid']})
                self.assertNotEqual(proof['oldPid'], proof['newPid'])
                self.assertEqual(proof['exitSignal'], 'SIGKILL')
                self.assertIsNone(proof['exitCode'])
                self.assertEqual((proof['spawnCount'], proof['killCount'], proof['restartCount']), (2, 1, 1))
                self.assertEqual(proof['storageBefore'], proof['storageAfter'])
                self.assertEqual(uncertain['claims'], 1)
                self.assertEqual(uncertain['result']['reason'], 'claim_outcome_unknown')
                self.assertEqual(uncertain['repeated'], uncertain['result'])
                process_fixture.MessagingProcessRestartTests.assert_held(self, uncertain['after'], seed)
                attempt = uncertain['after']['attempt']
                self.assertEqual(attempt['claim_uncertain'], 1)
                self.assertIsNone(attempt['admission'])

                cloud = transport.fixture('/fixture/read')
                expected_charges = int(phase != 'before-reserve')
                self.assertEqual(cloud['outboundCalls'], 0)
                assert_reservation_budget(self, cloud['budget'], seed['envelope']['attemptId'],
                                          charged=bool(expected_charges))
                self.assertEqual(cloud['message_attempts'],
                                 [{'attempt_id': seed['envelope']['attemptId']}] if expected_charges else [])
                self.assertEqual(len(cloud['attempts']), 1)
                self.assertEqual(len(cloud['native_claims']), 1)
                cloud_attempt, claim = cloud['attempts'][0], cloud['native_claims'][0]
                self.assertEqual(cloud_attempt['attempt_id'], seed['envelope']['attemptId'])
                self.assertEqual(claim['attempt_id'], seed['envelope']['attemptId'])
                self.assertEqual(cloud['deliveries'], initial_cloud['deliveries'])
                self.assertEqual(cloud['slot_intents'], initial_cloud['slot_intents'])
                if phase == 'after-admission':
                    self.assertEqual(claim['state'], 'admitted')
                    self.assertEqual(cloud_attempt['state'], 'admitted')
                    self.assertEqual(cloud_attempt['reservation_state'], 'reserved')
                    assert_admission_permit(self, claim['permit_id'])
                    self.assertEqual(claim['permit_id'], proof['admission']['permitId'])
                    self.assertEqual(cloud_attempt['permit_id'], claim['permit_id'])
                    self.assertEqual(proof['admission']['envelope']['attemptId'], seed['envelope']['attemptId'])
                else:
                    self.assertEqual(claim['state'], 'reserving')
                    self.assertEqual(cloud_attempt['state'], 'reserving')
                    self.assertEqual(cloud_attempt['reservation_state'], 'pending')
                    self.assertIsNone(claim['permit_id'])
                    self.assertIsNone(cloud_attempt['permit_id'])
                    self.assertIsNone(proof['admission'])

                self.assertEqual(transport.fixture('/fixture/recovery-alarm'), {'recovered': True})
                after_alarm = transport.fixture('/fixture/read')
                expected = deepcopy(cloud)
                expected_state = 'ambiguous' if phase == 'after-admission' else 'unknown'
                expected['attempts'][0]['state'] = expected_state
                expected['native_claims'][0]['state'] = expected_state
                if phase == 'after-admission':
                    expected['deliveries'][0]['state'] = 'ambiguous'
                else:
                    expected['attempts'][0]['reservation_state'] = 'unknown'
                self.assertEqual(after_alarm, expected)
                # Repeated real alarm is idempotent and cannot create another reservation or permit.
                transport.fixture('/fixture/recovery-alarm')
                self.assertEqual(transport.fixture('/fixture/read'), after_alarm)
                if change:
                    if change != 'positive-replay':
                        transport.fixture('/fixture/change', {'kind': change})
                    event = seed['envelope']

                    async def credentials():
                        return Credentials(address['accessToken'], address['agentToken'])

                    key = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(
                        address['agentPrivateJwk']['d'] + '=='))
                    client = CloudClient(origin='https://events.test', principal=event['principal'],
                                         agent=event['agent'], node_id=event['nodeId'],
                                         node_generation=event['nodeGeneration'], private_key=key,
                                         credentials=credentials, send=transport.send)
                    # Explicit same-attempt Cloud probe; the uncertain local gateway never resends.
                    if change == 'positive-replay':
                        admitted = asyncio.run(client.claim_messaging_history(event))
                        self.assertEqual(admitted['status'], 'admitted')
                        self.assertEqual(admitted['envelope']['attemptId'], event['attemptId'])
                        assert_admission_permit(self, admitted['permitId'])
                        expected = deepcopy(after_alarm)
                        expected['attempts'][0].update(state='admitted', reservation_state='reserved',
                                                       permit_id=admitted['permitId'])
                        expected['native_claims'][0].update(state='admitted', permit_id=admitted['permitId'])
                        self.assertEqual(transport.fixture('/fixture/read'), expected)
                        after_alarm = expected
                    else:
                        with self.assertRaises(CloudError):
                            asyncio.run(client.claim_messaging_history(event))
                        self.assertEqual(transport.last_response[0], 403 if change == 'key' else 409)
                        self.assertEqual(json.loads(transport.last_response[1])['error'],
                                         'denied' if change == 'key' else 'conflict')
                        self.assertEqual(transport.fixture('/fixture/read'), after_alarm)
                        print(json.dumps({'phase': phase, 'change': change,
                                          'httpStatus': transport.last_response[0],
                                          'error': json.loads(transport.last_response[1])['error']}), flush=True)
                    self.assertEqual(transport.claims, 1)
                cloud = after_alarm

                with process_fixture.gateway_child(config, 'restart') as (second, recovered):
                    self.assertNotEqual(second.pid, first.pid)
                    self.assertEqual(second.wait(timeout=5), 0)
                for snapshot in (recovered['before'], recovered['after']):
                    process_fixture.MessagingProcessRestartTests.assert_held(self, snapshot, seed)
                    self.assertEqual(snapshot['attempt'], attempt)
                self.assertEqual(recovered['claims'], 0)
                self.assertEqual(recovered['result'], uncertain['result'])
                self.assertEqual(recovered['repeated'], recovered['result'])
                self.assertEqual(http_log.read_bytes(), b'called\n')
                self.assertEqual(native_log.read_bytes(), b'')
                self.assertEqual(transport.fixture('/fixture/read'), cloud)
                self.assertEqual(transport.fixture('/fixture/crash-proof'), proof)
                self.assertIsNone(broker.poll())
