"""Prepared opt-in autonomous alarm proof; importing this module starts nothing."""
from copy import deepcopy
import os
import json
import time
import unittest
from unittest.mock import Mock, patch

import test_messaging_process_restart as process_fixture
from test_messaging_abrupt_cloud_crash import assert_admission_permit, assert_reservation_budget
from test_messaging_workerd import SETTINGS, LoopbackTransport, fixture


MODES = ('positive', 'no-super', 'delete-alarm')


def observe_completion(transport):
    """Only poll broker-owned memory; never dispatch a DO request while waiting."""
    deadline = time.monotonic() + 25
    while True:
        observation = transport.fixture('/fixture/autonomous-observation')
        if observation['completion'] is not None or observation['observationTimeout']:
            return observation
        if time.monotonic() >= deadline:
            raise TimeoutError('broker did not complete its autonomous observation window')
        time.sleep(0.05)


def diagnostic_after_observation(transport, observation, mode):
    completed = observation['completion'] is not None
    if not completed and not (observation['observationTimeout'] is True
                              and observation['elapsedSinceKillMs'] >= 25_000):
        raise AssertionError('diagnostic forbidden before autonomous observation finishes')
    cloud = transport.fixture('/fixture/read')
    if not completed and mode != 'delete-alarm':
        raise AssertionError('wake-on-access limitation: no autonomous completion within 25s; '
                             'first diagnostic state=' + json.dumps(cloud, sort_keys=True))
    return cloud


def recovered_state(barrier):
    state = deepcopy(barrier['state'])
    state['attempts'][0].update(state='unknown', reservation_state='unknown')
    state['native_claims'][0]['state'] = 'unknown'
    return state


class AutonomousAlarmSafetyTests(unittest.TestCase):
    def test_observation_http_timeout_is_one_second_and_claim_timeout_unchanged(self):
        transport = LoopbackTransport({'port': 1, 'secret': 'synthetic'})
        with patch('test_messaging_workerd.http.client.HTTPConnection') as factory:
            factory.return_value.getresponse.return_value.read.return_value = b'{}'
            for path, timeout in (('/fixture/autonomous-observation', 1), ('/v1/dispatch/claim', 5)):
                transport.post(path, b'{}')
                factory.assert_called_with('127.0.0.1', 1, timeout=timeout)
                factory.return_value.close.assert_called()

    def test_opt_in_rejected_before_starting_child(self):
        with (patch.dict(os.environ, {'FIXTURE_AUTONOMOUS_ALARM': ''}),
              patch('test_messaging_workerd.subprocess.Popen') as spawn,
              self.assertRaisesRegex(RuntimeError, 'matching execution opt-in')):
            with fixture(abrupt_crash=True, autonomous_alarm='positive'):
                self.fail('unapproved fixture started')
        spawn.assert_not_called()

    def test_observer_only_polls_memory_until_completion(self):
        transport = Mock()
        pending = {'completion': None, 'observationTimeout': False}
        completed = {'completion': {'state': {}}, 'observationTimeout': False}
        transport.fixture.side_effect = [pending, completed]
        with patch.object(time, 'sleep'), patch.object(time, 'monotonic', return_value=0):
            self.assertEqual(observe_completion(transport), completed)
        self.assertEqual([call.args for call in transport.fixture.call_args_list],
                         [('/fixture/autonomous-observation',)] * 2)

    def test_missing_completion_reports_first_diagnostic_only_after_full_timeout(self):
        transport = Mock()
        transport.fixture.return_value = {'state': 'reserving'}
        observation = {'completion': None, 'observationTimeout': True, 'elapsedSinceKillMs': 25_000}
        for mode in ('positive', 'no-super'):
            with self.subTest(mode=mode), self.assertRaisesRegex(
                    AssertionError, 'wake-on-access limitation:.*reserving'):
                diagnostic_after_observation(transport, observation, mode)
        self.assertEqual([call.args for call in transport.fixture.call_args_list],
                         [('/fixture/read',)] * 2)
        transport.reset_mock()
        for elapsed, expired in ((24_999, True), (25_000, False)):
            with self.subTest(elapsed=elapsed), self.assertRaisesRegex(AssertionError, 'diagnostic forbidden'):
                diagnostic_after_observation(transport, observation | {
                    'elapsedSinceKillMs': elapsed, 'observationTimeout': expired}, 'positive')
        transport.fixture.assert_not_called()

    def test_timeout_does_not_dispatch_diagnostic(self):
        transport = Mock()
        transport.fixture.return_value = {'completion': None, 'observationTimeout': False}
        with patch.object(time, 'monotonic', side_effect=[0, 25]), self.assertRaises(TimeoutError):
            observe_completion(transport)
        transport.fixture.assert_called_once_with('/fixture/autonomous-observation')


@unittest.skipUnless(all(os.environ.get(key) for key in SETTINGS)
                     and os.environ.get('FIXTURE_ABRUPT_CLOUD_CRASH') == 'reviewed'
                     and os.environ.get('FIXTURE_AUTONOMOUS_ALARM') in MODES,
                     'requires separately reviewed autonomous alarm execution')
class MessagingAutonomousAlarmTests(unittest.TestCase):
    def test_autonomous_recovery_and_falsification_controls(self):
        mode = os.environ['FIXTURE_AUTONOMOUS_ALARM']
        with fixture(abrupt_crash=True, autonomous_alarm=mode) as (ledger, address, transport, seed):
            broker = transport.broker_process
            config, native_log, http_log = process_fixture.gateway_child_config(
                ledger, address, seed, crash_expected={'phase': 'after-reserve', 'brokerPid': broker.pid})
            transport.fixture('/fixture/arm-crash', {'phase': 'after-reserve'})
            with process_fixture.gateway_child(config, 'restart') as (child, uncertain):
                self.assertEqual(child.wait(timeout=5), 0)
            observation = observe_completion(transport)
            cloud = diagnostic_after_observation(transport, observation, mode)
            proof, barrier, completion = (observation[key] for key in ('proof', 'barrier', 'completion'))
            self.assertIsNotNone(proof)
            self.assertIsNone(broker.poll())
            self.assertEqual(proof['brokerPid'], broker.pid)
            self.assertNotEqual(proof['oldPid'], proof['newPid'])
            self.assertEqual(proof['exitSignal'], 'SIGKILL')
            self.assertIsNone(proof['exitCode'])
            self.assertIs(proof['requestOpenAtKill'], True)
            self.assertEqual((proof['spawnCount'], proof['killCount'], proof['restartCount']), (2, 1, 1))
            self.assertEqual(proof['storageBefore'], proof['storageAfter'])
            attempt_id = seed['envelope']['attemptId']
            self.assertEqual(barrier['attemptId'], attempt_id)
            assert_admission_permit(self, barrier['instanceNonce'])
            self.assertIs(type(barrier['scheduledAlarm']), int)
            self.assertGreater(barrier['scheduledAlarm'], 0)
            before = barrier['state']
            self.assertEqual(len(before['attempts']), 1)
            self.assertEqual(len(before['native_claims']), 1)
            self.assertEqual(before['attempts'][0]['attempt_id'], attempt_id)
            self.assertEqual(before['attempts'][0]['state'], 'reserving')
            self.assertEqual(before['attempts'][0]['reservation_state'], 'pending')
            self.assertIsNone(before['attempts'][0]['permit_id'])
            self.assertEqual(before['native_claims'][0],
                             {'attempt_id': attempt_id, 'state': 'reserving', 'permit_id': None})
            if mode == 'delete-alarm':
                self.assertIsNone(completion)
                self.assertIs(observation['observationTimeout'], True)
                self.assertGreaterEqual(observation['elapsedSinceKillMs'], 25_000)
                expected = before
            else:
                self.assertIs(observation['observationTimeout'], False)
                self.assertEqual(completion['attemptId'], attempt_id)
                assert_admission_permit(self, completion['instanceNonce'])
                self.assertNotEqual(completion['instanceNonce'], barrier['instanceNonce'])
                self.assertGreaterEqual(completion['executedAt'], barrier['scheduledAlarm'])
                expected = recovered_state(barrier) if mode == 'positive' else before
                self.assertEqual(completion['state'], expected)
                if mode == 'no-super':
                    self.assertNotEqual(completion['state'], recovered_state(barrier))
            self.assertEqual({key: cloud[key] for key in expected}, expected)
            assert_reservation_budget(self, cloud['budget'], attempt_id, charged=True)
            self.assertEqual(cloud['message_attempts'], [{'attempt_id': attempt_id}])
            self.assertEqual(cloud['outboundCalls'], 0)
            process_fixture.MessagingProcessRestartTests.assert_held(self, uncertain['after'], seed)
            self.assertEqual(uncertain['claims'], 1)
            self.assertEqual(uncertain['result']['reason'], 'claim_outcome_unknown')
            self.assertEqual(uncertain['repeated'], uncertain['result'])
            self.assertEqual(uncertain['crashObservation'], {
                'phase': 'after-reserve', 'brokerPid': broker.pid, 'oldPid': proof['oldPid']})
            self.assertEqual(native_log.read_bytes(), b'')
            self.assertEqual(http_log.read_bytes(), b'called\n')
