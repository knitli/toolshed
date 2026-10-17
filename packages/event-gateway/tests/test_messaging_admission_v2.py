"""Real-signature and recovery-boundary checks for dormant v2 admission helpers."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway import messaging_admission_v2 as admission
from event_gateway import messaging_protocol_v2 as protocol
from event_gateway.security import SecurityError, sign

FIXTURE = json.loads((Path(__file__).resolve().parents[1] /
                     'contracts/messaging-v2/messaging-protocol-semantics-v2.json').read_text())
OTHER = '01234567-89ab-4def-8123-456789abcdef'


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.envelope = copy.deepcopy(FIXTURE['envelope'])
        self.now = FIXTURE['nowMs']
        self.key = Ed25519PrivateKey.generate()
        self.attachment = {key: self.envelope[key] for key in admission.ATTACHMENT_FIELDS}
        self.attachment.update(namespace='team/inbox', agentIncarnation=0,
                               leaseExpiresAt=self.now / 1000 + 60)
        self.permit = dict(status='admitted', permitId=OTHER, nodeId=self.envelope['nodeId'],
                           permitIssuedAt='2026-10-17T12:00:30.000Z',
                           permitExpiresAt='2026-10-17T12:00:35.000Z', envelope=self.envelope)

    def authenticate(self, body=None, **changes):
        body = protocol._json_bytes(self.envelope) if body is None else body
        args = dict(signature=sign(body, self.key, 'local'), audience='local',
                    expected_audience='local', public_key=self.key.public_key(),
                    node_id=self.envelope['nodeId'], attachment=self.attachment, now_ms=self.now)
        args.update(changes)
        return admission.validate_authenticated_envelope(body, **args)

    def recover(self, permit=None, expected=None, **changes):
        args = dict(now_ms=self.now, node_id=self.envelope['nodeId'])
        args.update(changes)
        return admission.validate_admission(self.permit if permit is None else permit,
                                            self.envelope if expected is None else expected, **args)

    def test_real_signature_authentication_before_parse(self):
        self.assertEqual(self.authenticate(), self.envelope)
        with patch.object(protocol, 'parse_envelope', side_effect=AssertionError('parsed')):
            for changes in ({'signature': 'bad'}, {'audience': 'other'},
                            {'public_key': Ed25519PrivateKey.generate().public_key()}):
                with self.subTest(changes=changes), self.assertRaises((SecurityError, protocol.MessagingProtocolError)):
                    self.authenticate(b'{malformed', **changes)
        body = protocol._json_bytes(self.envelope)
        with self.assertRaises(SecurityError):
            self.authenticate(body + b' ', signature=sign(body, self.key, 'local'))
        with self.assertRaises(SecurityError):
            self.authenticate(body, signature=sign(body, self.key, 'other'))

    def test_signed_decoder_and_bounds(self):
        body = protocol._json_bytes(self.envelope)
        for bad, code in ((body[:-1] + b',"schemaVersion":2}', 'duplicate_json_key'),
                          (b'[' * 80 + b']' * 80, 'invalid_json'),
                          (b' ' * 4097, 'message_too_large')):
            with self.subTest(code=code), self.assertRaises(protocol.MessagingProtocolError) as caught:
                self.authenticate(bad)
            self.assertEqual(caught.exception.code, code)

        class Bytes(bytes):
            pass
        with self.assertRaises(protocol.MessagingProtocolError):
            self.authenticate(Bytes(body))

    def test_current_attachment_and_node_fences(self):
        for key in (*admission.ATTACHMENT_FIELDS, 'namespace', 'agentIncarnation'):
            changed = dict(self.attachment)
            changed[key] = changed[key] + 1 if isinstance(changed[key], int) else 'other'
            with self.subTest(key=key), self.assertRaises(protocol.MessagingProtocolError):
                self.authenticate(attachment=changed)
        for changed in ({'node_id': OTHER}, {'attachment': None},
                        {'attachment': dict(self.attachment, leaseExpiresAt=self.now / 1000)},
                        {'attachment': dict(self.attachment, nodeGeneration=True)},
                        {'attachment': dict(self.attachment, agentIncarnation=False)}):
            with self.assertRaises(protocol.MessagingProtocolError):
                self.authenticate(**changed)
        changed = dict(self.attachment, nodeGeneration=1.0)
        self.assertEqual(self.authenticate(attachment=changed), self.envelope)
        self.envelope['deliveryId'] = 'dly_' + '0' * 64
        with self.assertRaises(protocol.MessagingProtocolError):
            self.authenticate()

    def test_invalid_clocks_and_versions(self):
        for now in (True, None, '1', float('nan'), float('inf'), -float('inf'), 10**400):
            with self.subTest(now=now):
                with self.assertRaises(protocol.MessagingProtocolError):
                    self.authenticate(now_ms=now)
                with self.assertRaises(protocol.MessagingProtocolError):
                    self.recover(now_ms=now)
        for version in (1, True):
            self.envelope['schemaVersion'] = version
            with self.assertRaises(protocol.MessagingProtocolError):
                self.authenticate()
            with self.assertRaises(protocol.MessagingProtocolError):
                self.recover()

    def test_expired_history_is_immutable_and_detached(self):
        result = self.recover(now_ms=self.now + 86400000)
        self.assertEqual(result, self.permit)
        result['envelope']['canonicalSubject']['namespace'] = 'changed'
        self.assertEqual(self.envelope['canonicalSubject']['namespace'], 'team/inbox')
        refreshed = dict(self.envelope, issuedAt='2026-10-17T12:00:10.000Z',
                         expiresAt='2026-10-17T12:01:10.000Z')
        self.assertEqual(self.recover(expected=refreshed), self.permit)

    def test_every_semantic_field_is_bound(self):
        for key, value in self.envelope.items():
            if key in ('issuedAt', 'expiresAt'):
                continue
            changed = copy.deepcopy(self.envelope)
            if isinstance(value, int):
                changed[key] += 1
            elif isinstance(value, dict):
                changed[key]['namespace'] = 'another/inbox'
            elif key in ('eventId', 'nodeId', 'runtimeId', 'attemptId'):
                changed[key] = OTHER
            elif key == 'sourceStateVersion':
                changed[key] = 'msg:' + 'b' * 64
            elif key == 'eventReference':
                changed[key] = 'ref_' + OTHER
            elif key == 'principal':
                changed[key] = 'other@example.com'
            elif key == 'observedAt':
                changed[key] = '2026-10-17T11:59:46.000Z'
            else:
                changed[key] = 'other'
            if key != 'deliveryId':
                changed['deliveryId'] = protocol.derive_delivery_id(changed) if protocol._identity(changed) else changed['deliveryId']
            with self.subTest(key=key), self.assertRaises(protocol.MessagingProtocolError):
                self.recover(permit=dict(self.permit, envelope=changed))
        for key, value in (('agentIncarnation', 1), ('agentIncarnation', False), ('messageId', OTHER), ('namespace', 'other')):
            changed = copy.deepcopy(self.envelope)
            changed['canonicalSubject'][key] = value
            with self.subTest(subject=key), self.assertRaises(protocol.MessagingProtocolError):
                self.recover(permit=dict(self.permit, envelope=changed))

    def test_permit_shape_timing_and_cross_binding(self):
        for changes in ({'extra': 1}, {'status': 'ready'}, {'permitId': True}, {'nodeId': OTHER},
                        {'permitIssuedAt': '2026-10-17T12:00:31.000Z', 'permitExpiresAt': '2026-10-17T12:00:36.000Z'},
                        {'permitExpiresAt': '2026-10-17T12:00:34.000Z'}, {'permitIssuedAt': None},
                        {'permitIssuedAt': '2026-10-17T11:59:55.000Z', 'permitExpiresAt': '2026-10-17T12:00:00.000Z'}):
            with self.subTest(changes=changes), self.assertRaises(protocol.MessagingProtocolError):
                self.recover(permit=dict(self.permit, **changes))
        for field in self.permit:
            missing = dict(self.permit)
            del missing[field]
            with self.subTest(missing=field), self.assertRaises(protocol.MessagingProtocolError):
                self.recover(permit=missing)
        outside = dict(self.permit, permitIssuedAt='2026-10-17T12:00:58.000Z',
                       permitExpiresAt='2026-10-17T12:01:03.000Z')
        with self.assertRaises(protocol.MessagingProtocolError):
            self.recover(permit=outside, now_ms=self.now + 60000)
        with self.assertRaises(protocol.MessagingProtocolError):
            self.recover(node_id=OTHER)
        for field in ('nodeGeneration', 'routingGeneration', 'policyRevision'):
            changed = dict(self.envelope, **{field: True})
            with self.assertRaises(protocol.MessagingProtocolError):
                self.recover(permit=dict(self.permit, envelope=changed))

    def test_ack_matching_uses_admitted_envelope_for_both_statuses(self):
        envelope = self.recover()['envelope']
        observed = copy.deepcopy(FIXTURE['acknowledgment'])
        submitted = copy.deepcopy(observed)
        submitted['status'] = 'submitted'
        submitted['nativeCorrelation'].update(kind='native_turn_started')
        del submitted['nativeCorrelation']['itemId']
        for ack in (submitted, observed):
            self.assertTrue(protocol.acknowledgment_matches_delivery(envelope, ack))
            for field in (*admission.ATTACHMENT_FIELDS, 'eventId', 'deliveryId', 'attemptId',
                          'deliveredSourceStateVersion', 'schemaVersion'):
                changed = dict(ack, **{field: True if isinstance(ack[field], int) else 'other'})
                with self.subTest(status=ack['status'], field=field):
                    self.assertFalse(protocol.acknowledgment_matches_delivery(envelope, changed))
        observed['nativeCorrelation']['itemId'] = observed['nativeCorrelation']['turnId']
        self.assertFalse(protocol.acknowledgment_matches_delivery(envelope, observed))
