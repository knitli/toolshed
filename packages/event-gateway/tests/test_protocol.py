import copy
import json
from pathlib import Path
import unittest

from event_gateway.protocol import (ProtocolError, parse_envelope, parse_acknowledgment,
    derive_delivery_id, matches_delivery_id, acknowledgment_matches_delivery,
    acknowledgment_advances_current_watermark, validate_runtime_profile)

FIXTURES = json.loads((Path(__file__).resolve().parents[1] / 'contracts/event-v1/protocol-v1.json').read_text())
NOW = 1791201630000  # 2026-10-05T12:00:30Z


class ProtocolTests(unittest.TestCase):
    def test_shared_vectors(self):
        for key, parser in [('Envelopes', parse_envelope), ('Acknowledgments', parse_acknowledgment)]:
            for value in FIXTURES['valid' + key]:
                self.assertEqual(parser(json.dumps(value).encode(), NOW), value)
            for case in FIXTURES['invalid' + key]:
                with self.subTest(case=case['case']), self.assertRaises(ProtocolError):
                    parser(json.dumps(case['value']).encode(), NOW)
        envelopes = {envelope['deliveryId']: envelope for envelope in FIXTURES['validEnvelopes']}
        for ack in FIXTURES['validAcknowledgments']:
            envelope = envelopes[ack['deliveryId']]
            self.assertTrue(matches_delivery_id(envelope))
            self.assertTrue(acknowledgment_matches_delivery(envelope, ack))
            self.assertEqual(acknowledgment_advances_current_watermark(envelope, ack, envelope['sourceStateVersion']), ack['status'] in ('observed', 'command_accepted'))
            for field in ['attemptId', 'runtimeGeneration', 'deliveredSourceStateVersion', 'consumerGeneration']:
                changed = dict(ack, **{field: 'different'})
                self.assertFalse(acknowledgment_matches_delivery(envelope, changed))

    def test_stock_assignment_is_closed_and_bound_to_ack(self):
        profile = {'profile': 'assigned_stock_client', 'client': 'codex',
                   'conversationId': '12345678-1234-4234-8234-123456789abc'}
        self.assertEqual(validate_runtime_profile(profile), profile)
        for changes in ({'client': 'other'}, {'conversationId': 'latest'},
                        {'conversationId': profile['conversationId'].upper()}, {'extra': True}):
            with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                validate_runtime_profile(dict(profile, **changes))
        original = FIXTURES['validEnvelopes'][0]
        envelope = dict(original, runtimeProfile=profile)
        ack = {key: envelope[key] for key in ('schemaVersion', 'eventId', 'deliveryId', 'attemptId',
               'principal', 'agent', 'runtimeId', 'nodeGeneration', 'runtimeGeneration',
               'attachmentGeneration')}
        ack.update(status='command_accepted', runtimeProfile=profile,
                   deliveredSourceStateVersion=envelope['sourceStateVersion'],
                   acknowledgedAt='2026-10-05T12:00:30.000Z')
        self.assertTrue(acknowledgment_advances_current_watermark(envelope, ack, envelope['sourceStateVersion']))
        self.assertFalse(acknowledgment_advances_current_watermark(envelope, ack, 'replacement'))
        self.assertFalse(acknowledgment_matches_delivery(original, ack))
        changed = dict(ack, runtimeProfile=dict(profile, conversationId='22345678-1234-4234-8234-123456789abc'))
        self.assertFalse(acknowledgment_matches_delivery(envelope, changed))
        self.assertFalse(acknowledgment_advances_current_watermark(envelope, dict(ack, status='observed'), envelope['sourceStateVersion']))

    def test_malformed_and_closed_schema(self):
        for body, code in [(b'{', 'invalid_json'), (b'{"a":1,"\\u0061":2}', 'duplicate_json_key'),
                           (b'{"nested":{"a":1,"a":2}}', 'duplicate_json_key'),
                           (b'NaN', 'invalid_json'), (b'\xff', 'invalid_json'),
                           (b' ' * 4097, 'message_too_large'), (b'[' * 34 + b'0' + b']' * 34, 'invalid_json')]:
            with self.subTest(body=body[:30]), self.assertRaises(ProtocolError) as caught:
                parse_envelope(body, NOW)
            self.assertEqual(str(caught.exception), code)
        original = FIXTURES['validEnvelopes'][0]
        for changes in [{'nodeGeneration': True}, {'nodeGeneration': 2**53}, {'policyRevision': 1.5},
                        {'comment': 'secret text'}, {'schemaVersion': True}, {'consumerGeneration': None},
                        {'issuedAt': '2026-10-05T12:00:00Z'}]:
            with self.subTest(changes=changes), self.assertRaises(ProtocolError) as caught:
                parse_envelope(json.dumps(dict(original, **changes)), NOW)
            self.assertNotIn('secret', str(caught.exception))

    def test_freshness_and_identity_boundaries(self):
        value = copy.deepcopy(FIXTURES['validEnvelopes'][0])
        parse_envelope(json.dumps(value), NOW + 60000)
        with self.assertRaisesRegex(ProtocolError, '^stale_message$'):
            parse_envelope(json.dumps(value), NOW + 60001)
        for changes in [{'expiresAt': value['issuedAt']}, {'expiresAt': '2026-10-05T12:01:00.001Z'},
                        {'observedAt': '2026-10-05T12:00:30.001Z'}]:
            with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                parse_envelope(json.dumps(dict(value, **changes)), NOW)
        ancient = dict(value, issuedAt='0000-01-01T00:00:00.001Z', expiresAt='0000-01-01T00:01:00.001Z', observedAt='0000-01-01T00:00:00.001Z')
        parse_envelope(json.dumps(ancient), -62167219170000)
        precise = {key: val.replace('.000Z', '.001Z') if isinstance(val, str) else val for key, val in value.items()}
        parse_envelope(json.dumps(precise), NOW)
        self.assertEqual(derive_delivery_id(dict(value, nodeGeneration=1.0)), value['deliveryId'])
        self.assertNotEqual(derive_delivery_id(dict(value, consumerGeneration=1)), value['deliveryId'])
        for invalid in [True, 0, 2**53, None]:
            with self.assertRaisesRegex(ProtocolError, '^invalid_delivery_identity$'):
                derive_delivery_id(dict(value, nodeGeneration=invalid))


if __name__ == '__main__':
    unittest.main()
