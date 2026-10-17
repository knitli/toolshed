"""Portable decoded-DTO cases shared with an independent Cloud-source run."""

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from event_gateway import messaging_protocol_v2 as protocol

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_PATH = PACKAGE / 'contracts/messaging-v2/messaging-protocol-semantics-v2.json'
FIXTURE = json.loads(FIXTURE_PATH.read_text())
ENVELOPE, ACK, NOW = FIXTURE['envelope'], FIXTURE['acknowledgment'], FIXTURE['nowMs']
OTHER = '01234567-89ab-4def-8123-456789abcdef'
GENERATIONS = ('nodeGeneration', 'runtimeGeneration', 'attachmentGeneration',
               'consumerGeneration', 'routingGeneration')


def decoded_cases():
    """All JSON-representable schema/freshness cases, for both language drivers."""
    result = []

    def add(kind, name, value, expected, now=NOW):
        result.append(dict(kind=kind, case=name, value=value, nowMs=now, expected=expected))

    for kind, base in [('envelope', ENVELOPE), ('acknowledgment', ACK)]:
        add(kind, 'portable-fixture', base, True)
        for field in base:
            changed = copy.deepcopy(base)
            del changed[field]
            add(kind, 'required-' + field, changed, False)
        for field in ('candidateGeneration', 'body', 'url', 'path', 'pid', 'prompt', 'sessionId'):
            add(kind, 'unknown-' + field, dict(base, **{field: 1}), False)
        for field in ('eventId', 'nodeId', 'runtimeId', 'attemptId'):
            for name, value in [('v4', OTHER), ('uppercase', OTHER.upper()),
                                ('v1', OTHER.replace('4def', '1def')), ('opaque', 'opaque-id'),
                                ('newline', OTHER + '\n'), ('nonascii', '界' * 36)]:
                add(kind, field + '-' + name, dict(base, **{field: value}), name == 'v4')
        for field in (*GENERATIONS, *(('policyRevision',) if kind == 'envelope' else ())):
            for value in (True, False, 0, -1, 1.5, 2**53, '1', None):
                add(kind, f'{field}-invalid-{value!r}', dict(base, **{field: value}), False)
            for name, value in [('safe-max', 2**53 - 1), ('integral-float', 4.0)]:
                changed = dict(base, **{field: value})
                if field in ('attachmentGeneration', 'consumerGeneration'):
                    changed.update(attachmentGeneration=value, consumerGeneration=value)
                add(kind, field + '-' + name, changed, True)
        for field, value in [('schemaVersion', 1), ('schemaVersion', True), ('schemaVersion', '2'),
                             ('principal', 'Adam@knitli.com'), ('principal', 'adâm@knitli.com'),
                             ('principal', 'a@Knitli.com'), ('principal', 'a..b@example.com'),
                             ('principal', 'a' * 65 + '@example.com'), ('principal', 'a@example.com\n'),
                             ('agent', 'bad agent'), ('agent', 'pilot\n'), ('agent', 'é'),
                             ('agent', 'x' * 33), ('deliveryId', 'dly_' + 'A' * 64)]:
            add(kind, f'invalid-{field}-{value!r}', dict(base, **{field: value}), False)
        add(kind, 'schema-version-integral-float', dict(base, schemaVersion=2.0), True)
        add(kind, 'consumer-attachment-mismatch', dict(base, consumerGeneration=4), False)
        source_field = 'sourceStateVersion' if kind == 'envelope' else 'deliveredSourceStateVersion'
        for value in ('msg:' + 'A' * 64, 'msg:' + 'a' * 63, 'manual-1', 'msg:' + 'a' * 64 + '\n'):
            add(kind, 'invalid-source-' + value, dict(base, **{source_field: value}), False)
        times = ('observedAt', 'issuedAt', 'expiresAt') if kind == 'envelope' else ('acknowledgedAt',)
        for field in times:
            for value in ('2026-10-17T12:00:00Z', '2026-10-17T12:00:00.000+00:00',
                          '2026-02-30T12:00:00.000Z', '2026-10-17T24:00:00.000Z',
                          '2026-10-17T12:00:00.000Z\n', '２０２６-10-17T12:00:00.000Z', 1, None):
                add(kind, f'noncanonical-{field}-{value!r}', dict(base, **{field: value}), False)
        for value in (None, [], 'not a decoded object', True, 2):
            add(kind, 'not-dto-' + repr(value), value, False)

    for field, value in [('source', 'manual'), ('eventKind', 'attention'), ('reasonCode', 'owner_canary'),
                         ('eventReference', OTHER), ('eventReference', 'ref_' + OTHER.upper())]:
        add('envelope', 'invalid-' + field, dict(ENVELOPE, **{field: value}), False)
    for name, patch_value, valid in [
            ('kind', {'kind': 'manual'}, False), ('extra', {'extra': 1}, False),
            ('message-id', {'messageId': 'bad'}, False), ('message-id-v4', {'messageId': OTHER}, True),
            ('namespace-empty', {'namespace': ''}, False), ('namespace-long', {'namespace': 'x' * 257}, False),
            ('namespace-nul', {'namespace': 'x\x00'}, False), ('namespace-del', {'namespace': 'x\x7f'}, False),
            ('namespace-bmp', {'namespace': '界' * 256}, True), ('namespace-astral', {'namespace': '😀' * 128}, True),
            ('namespace-astral-129', {'namespace': '😀' * 129}, True),
            ('namespace-astral-256', {'namespace': '😀' * 256}, True),
            ('namespace-astral-too-long', {'namespace': '😀' * 257}, False),
            ('namespace-surrogate-pair', {'namespace': '\ud83d\ude00' * 128}, True),
            ('namespace-surrogate-pair-256', {'namespace': '\ud83d\ude00' * 256}, True),
            ('namespace-surrogate-pair-too-long', {'namespace': '\ud83d\ude00' * 257}, False),
            ('namespace-unpaired-surrogate', {'namespace': '\ud800'}, True),
            ('namespace-unpaired-256', {'namespace': '\ud800' * 256}, True),
            ('namespace-unpaired-too-long', {'namespace': '\ud800' * 257}, False),
            ('namespace-line-separator', {'namespace': '\u2028\u2029'}, True),
            ('incarnation-zero', {'agentIncarnation': 0}, True), ('incarnation-max', {'agentIncarnation': 2**53 - 1}, True),
            *[(f'incarnation-invalid-{v!r}', {'agentIncarnation': v}, False) for v in (-1, 0.1, 2**53, True, False, None)],
    ]:
        add('envelope', name, dict(ENVELOPE, canonicalSubject=dict(ENVELOPE['canonicalSubject'], **patch_value)), valid)
    for field in ENVELOPE['canonicalSubject']:
        subject = dict(ENVELOPE['canonicalSubject'])
        del subject[field]
        add('envelope', 'required-subject-' + field, dict(ENVELOPE, canonicalSubject=subject), False)

    submitted = dict(ACK, status='submitted', nativeCorrelation={
        'kind': 'native_turn_started', 'permitId': OTHER, 'turnId': OTHER})
    add('acknowledgment', 'submitted-stage', submitted, True)
    for name, correlation in [
            ('legacy-queued', {'kind': 'queued', 'submissionId': 'queue-1'}),
            ('legacy-turn', {'kind': 'turn', 'submissionId': 'queue-1', 'turnId': 'turn-1'}),
            ('same-item-turn', dict(ACK['nativeCorrelation'], itemId=ACK['nativeCorrelation']['turnId'])),
            ('extra', dict(ACK['nativeCorrelation'], extra=True)),
            *[(field, dict(ACK['nativeCorrelation'], **{field: 'opaque'})) for field in ('permitId', 'turnId', 'itemId')],
    ]:
        add('acknowledgment', 'invalid-correlation-' + name, dict(ACK, nativeCorrelation=correlation), False)
    add('acknowledgment', 'observed-submitted-mismatch', dict(ACK, status='submitted'), False)
    add('acknowledgment', 'submitted-observed-mismatch', dict(submitted, status='observed'), False)
    for stage in (ACK, submitted):
        for field in stage['nativeCorrelation']:
            correlation = dict(stage['nativeCorrelation'])
            del correlation[field]
            add('acknowledgment', stage['status'] + '-required-correlation-' + field,
                dict(stage, nativeCorrelation=correlation), False)

    issued, expires = NOW - 30_000, NOW + 30_000
    for offset, valid in [(30_000, True), (30_001, False)]:
        add('envelope', f'expiration-skew-{offset}', ENVELOPE, valid, expires + offset)
        add('envelope', f'issued-skew-{offset}', ENVELOPE, valid, issued - offset)
    for value in ('2026-10-17T12:00:00.000Z', '2026-10-17T11:59:59.999Z', '2026-10-17T12:01:00.001Z'):
        add('envelope', 'invalid-lifetime-' + value, dict(ENVELOPE, expiresAt=value), False)
    add('envelope', 'observed-issued-boundary', dict(ENVELOPE, observedAt='2026-10-17T12:00:30.000Z'), True)
    add('envelope', 'observed-issued-past-boundary', dict(ENVELOPE, observedAt='2026-10-17T12:00:30.001Z'), False)
    add('envelope', 'observed-now-past-boundary', dict(ENVELOPE, observedAt='2026-10-17T12:00:00.001Z'), False, issued - 30_000)
    add('acknowledgment', 'ack-future-boundary', dict(ACK, acknowledgedAt='2026-10-17T12:01:00.000Z'), True)
    add('acknowledgment', 'ack-past-future-boundary', dict(ACK, acknowledgedAt='2026-10-17T12:01:00.001Z'), False)
    ancient = dict(ENVELOPE, observedAt='0000-01-01T00:00:00.001Z', issuedAt='0000-01-01T00:00:00.001Z', expiresAt='0000-01-01T00:01:00.001Z')
    add('envelope', 'year-zero', ancient, True, -62167219170000)
    return result


class MessagingProtocolV2Tests(unittest.TestCase):
    def test_all_decoded_portable_vectors(self):
        for case in decoded_cases():
            with self.subTest(kind=case['kind'], case=case['case']):
                validator = protocol.validate_envelope if case['kind'] == 'envelope' else protocol.validate_acknowledgment
                self.assertIs(validator(case['value'], case['nowMs']), case['expected'])

    def test_source_receipt_and_exact_fixture_bytes(self):
        receipt = json.loads((FIXTURE_PATH.parent / 'source-receipt.json').read_text())
        self.assertEqual(hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest(), receipt['fixture']['sha256'])
        self.assertEqual(receipt['purpose'], 'dormant_source_conformance_only')
        self.assertEqual(receipt['protocolVersion'], 2)
        self.assertFalse(receipt['trustedPolicyAdoption'])
        self.assertEqual(len(receipt['sourceCommit']), 40)
        self.assertTrue(all(len(file['sha256']) == 64 for file in receipt['sourceFiles']))

    def test_nonfinite_and_exact_numeric_types(self):
        for base, validator in [(ENVELOPE, protocol.validate_envelope), (ACK, protocol.validate_acknowledgment)]:
            for now in (True, False, None, '1', float('nan'), float('inf'), -float('inf'), 10**1000):
                # None is the documented current-clock default, tested with a controlled clock.
                if now is None:
                    with patch.object(protocol.time, 'time', return_value=NOW / 1000):
                        self.assertTrue(validator(base))
                    continue
                with self.subTest(now=repr(now)):
                    self.assertFalse(validator(base, now))
            for field in GENERATIONS:
                for value in (float('nan'), float('inf'), -float('inf'), 10**1000):
                    with self.subTest(field=field, value=repr(value)):
                        self.assertFalse(validator(dict(base, **{field: value}), NOW))
                        with self.assertRaisesRegex(protocol.MessagingProtocolError, '^invalid_delivery_identity$'):
                            protocol.derive_delivery_id(dict(base, **{field: value}))

    def test_versioned_digest_fixture_and_retry_stability(self):
        expected = 'dly_' + hashlib.sha256(FIXTURE['canonicalDeliveryIdentity'].encode()).hexdigest()
        self.assertEqual(expected, FIXTURE['expectedDigest'])
        self.assertEqual(protocol.derive_delivery_id(ENVELOPE), expected)
        self.assertTrue(protocol.matches_delivery_id(ENVELOPE))
        changed = dict(ENVELOPE, attemptId=OTHER, issuedAt='2026-10-17T12:00:00.001Z')
        self.assertEqual(protocol.derive_delivery_id(changed), expected)
        changed['canonicalSubject'] = dict(ENVELOPE['canonicalSubject'], namespace='界/😀')
        self.assertEqual(protocol.derive_delivery_id(changed), expected)
        self.assertEqual(protocol.derive_delivery_id(dict(ENVELOPE, nodeGeneration=1.0)), expected)
        self.assertFalse(protocol.matches_delivery_id(dict(ENVELOPE, deliveryId='dly_' + '0' * 64)))

    def test_every_digest_selector_is_fenced(self):
        for field in ('eventId', 'nodeId', 'runtimeId', *GENERATIONS):
            changed = dict(ENVELOPE)
            changed[field] = changed[field] + 1 if field in GENERATIONS else OTHER
            if field in ('attachmentGeneration', 'consumerGeneration'):
                changed.update(attachmentGeneration=4, consumerGeneration=4)
            with self.subTest(field=field):
                self.assertNotEqual(protocol.derive_delivery_id(changed), FIXTURE['expectedDigest'])
                self.assertFalse(protocol.matches_delivery_id(changed))
                del changed[field]
                with self.assertRaisesRegex(protocol.MessagingProtocolError, '^invalid_delivery_identity$'):
                    protocol.derive_delivery_id(changed)
                self.assertFalse(protocol.matches_delivery_id(changed))
        for invalid in (None, [], True, 'identity'):
            with self.assertRaisesRegex(protocol.MessagingProtocolError, '^invalid_delivery_identity$'):
                protocol.derive_delivery_id(invalid)

    def test_all_ack_selectors_are_exact_and_do_not_settle_work(self):
        self.assertTrue(protocol.acknowledgment_matches_delivery(ENVELOPE, ACK))
        submitted = dict(ACK, status='submitted', nativeCorrelation={'kind': 'native_turn_started', 'permitId': OTHER, 'turnId': OTHER})
        self.assertTrue(protocol.acknowledgment_matches_delivery(ENVELOPE, submitted))
        for field in ('schemaVersion', 'eventId', 'deliveryId', 'attemptId', 'principal', 'agent',
                      'nodeId', 'runtimeId', *GENERATIONS, 'deliveredSourceStateVersion'):
            changed = dict(ACK)
            if field in GENERATIONS:
                changed[field] += 1
                if field in ('attachmentGeneration', 'consumerGeneration'):
                    changed.update(attachmentGeneration=4, consumerGeneration=4)
            elif field == 'schemaVersion':
                changed[field] = 1
            elif field in ('eventId', 'attemptId', 'nodeId', 'runtimeId'):
                changed[field] = OTHER
            elif field == 'principal':
                changed[field] = 'other@example.com'
            elif field == 'agent':
                changed[field] = 'other'
            elif field == 'deliveryId':
                changed[field] = 'dly_' + '0' * 64
            else:
                changed[field] = 'msg:' + 'b' * 64
            with self.subTest(field=field):
                self.assertFalse(protocol.acknowledgment_matches_delivery(ENVELOPE, changed))
        for changed in (dict(ACK, nodeGeneration=True), dict(ACK, schemaVersion='2'), {}):
            self.assertFalse(protocol.acknowledgment_matches_delivery(ENVELOPE, changed))
        for field in GENERATIONS:
            left, right = dict(ENVELOPE), dict(ACK)
            del left[field]
            del right[field]
            self.assertFalse(protocol.acknowledgment_matches_delivery(left, right))
        self.assertFalse(protocol.acknowledgment_matches_delivery(None, None))
        before = copy.deepcopy((ENVELOPE, ACK))
        protocol.acknowledgment_matches_delivery(ENVELOPE, ACK)
        self.assertEqual((ENVELOPE, ACK), before)

    def test_compact_js_unicode_encoding_and_byte_boundary(self):
        # DTO validators deliberately accept no toJSON hooks or raw JSON input.
        self.assertEqual(protocol._json_bytes({'namespace': '界/😀/\ud800'}), b'{"namespace":"\xe7\x95\x8c/\xf0\x9f\x98\x80/\\ud800"}')
        self.assertEqual(protocol._json_bytes({'namespace': '\ud83d\ude00'}), protocol._json_bytes({'namespace': '😀'}))
        self.assertEqual(protocol._json_bytes([1.0, 2.0]), b'[1,2]')
        self.assertTrue(protocol._fits('x' * 4094))
        self.assertFalse(protocol._fits('x' * 4095))
        self.assertFalse(protocol._fits('界' * 1365))
        for validator, value in [(protocol.validate_envelope, ENVELOPE), (protocol.validate_acknowledgment, ACK)]:
            self.assertFalse(validator(json.dumps(value), NOW))
            self.assertFalse(validator(json.dumps(value).encode(), NOW))
            size = len(protocol._json_bytes(value))
            with patch.object(protocol, 'MAX_PROTOCOL_MESSAGE_BYTES', size):
                self.assertTrue(validator(value, NOW))
            with patch.object(protocol, 'MAX_PROTOCOL_MESSAGE_BYTES', size - 1):
                self.assertFalse(validator(value, NOW))


if __name__ == '__main__':
    unittest.main()
