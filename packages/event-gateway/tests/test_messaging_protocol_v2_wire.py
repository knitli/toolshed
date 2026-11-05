"""Raw Messaging v2 conformance with the unchanged shared strict JSON decoder."""

import hashlib
import json
from pathlib import Path
import subprocess  # nosec B404 - fixed-interpreter import-isolation test only
import sys
import unittest
from unittest.mock import patch

from event_gateway import messaging_protocol_v2 as protocol

CONTRACTS = Path(__file__).resolve().parents[1] / 'contracts/messaging-v2'
SEMANTICS = json.loads((CONTRACTS / 'messaging-protocol-semantics-v2.json').read_text())
NOW = SEMANTICS['nowMs']
ACTIVE_SOURCE_COMMIT = 'e954904603b3467e30bbeaf7446977b61fbcb9ef'
ACTIVE_SOURCE_FILES = {
    'apps/os/packages/event-runtime/src/messaging/protocol-v2.ts': '3f91122c7bd2d78d072ad51a9fb2fef4adfb99e3277bf4052196a54a74238193',
    'apps/os/packages/event-runtime/src/protocol.ts': 'b9927658cd80cfb52222bcc20ffe748acbea0c16da06f0f283b55c6046b9284d',
    'apps/os/packages/event-runtime/src/policy.ts': '2de281e76f796aa92b7809eff8039c74847bd0fd8303ef8453d408dcb39e15e3',
    'apps/os/packages/event-runtime/__tests__/fixtures/messaging-protocol-semantics-v2.json': (
        '0553380db6fbe8c9af557aea5847ce22cb52917da1daadb4491524e1f2cdf22f'
    ),
    'apps/os/packages/event-runtime/__tests__/fixtures/messaging-v2-wire.json': 'a66d74967f5470e193bfcb250cdc130fd22081b88c42b62c24fecf01d269f032',
    'apps/os/pnpm-lock.yaml': '62f84801e3d426df4a97a54bc48c1a547d9ae3f0205166cc92d9b7391e581549',
}


def _body(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('utf-8')


class MessagingProtocolV2WireTests(unittest.TestCase):
    """Exercise wire boundaries without enabling a gateway or native transport."""

    def test_shared_cloud_wire_vectors(self):
        fixture = json.loads((CONTRACTS / 'messaging-v2-wire.json').read_text())
        for case in fixture['cases']:
            with self.subTest(case=case['name']):
                parser = protocol.parse_envelope if case['kind'] == 'envelope' else protocol.parse_acknowledgment
                raw = bytes.fromhex(case['utf8Hex'])
                expected = case['expected']
                if expected['ok']:
                    parsed = parser(raw, case['nowMs'])
                    self.assertEqual(parsed, json.loads(raw))
                    if 'matchesAssignedStockEnvelope' in case:
                        self.assertEqual(
                            protocol.acknowledgment_matches_delivery(
                                SEMANTICS['assigned_stock_envelope'], parsed),
                            case['matchesAssignedStockEnvelope'])
                else:
                    with self.assertRaises(protocol.MessagingProtocolError) as raised:
                        parser(raw, case['nowMs'])
                    self.assertEqual(raised.exception.code, expected.get('pythonCode', expected.get('code')))
                try:
                    text = raw.decode('utf-8')
                except UnicodeDecodeError:
                    continue
                if expected['ok']:
                    self.assertEqual(parser(text, case['nowMs']), parsed)
                else:
                    with self.assertRaises(protocol.MessagingProtocolError) as raised:
                        parser(text, case['nowMs'])
                    self.assertEqual(raised.exception.code, expected.get('pythonCode', expected.get('code')))

    def test_wire_receipt_records_active_profile_provenance_but_is_not_authorizer(self):
        receipt = json.loads((CONTRACTS / 'wire-source-receipt.json').read_text())
        fixture = CONTRACTS / Path(receipt['fixture']['file']).name
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), receipt['fixture']['sha256'])
        self.assertEqual(receipt['purpose'], 'active_assigned_stock_v2_policy_adoption')
        self.assertTrue(receipt['trustedPolicyAdoption'])
        self.assertEqual(receipt['profile'], 'active-assigned-stock-v2')
        self.assertEqual(receipt['sourceCommit'], ACTIVE_SOURCE_COMMIT)
        self.assertEqual({entry['path']: entry['sha256'] for entry in receipt['sourceFiles']},
                         ACTIVE_SOURCE_FILES)
        self.assertEqual(receipt['fixture']['file'],
                         'apps/os/packages/event-runtime/__tests__/fixtures/messaging-v2-wire.json')
        self.assertEqual(receipt['protocolVersion'], 2)
        # The receipt records provenance; the trusted workflow's exact blob
        # hashes authorize the profile independently.

    def test_exact_raw_input_types_and_safe_errors(self):
        class StringSubclass(str):
            pass

        class BytesSubclass(bytes):
            pass

        invalid = [None, True, 1, {}, [], bytearray(b'{}'), memoryview(b'{}'),
                   StringSubclass('{}'), BytesSubclass(b'{}'), '\ud800',
                   b'{"private-value":"do-not-reflect"', b'\xff']
        for parser in (protocol.parse_envelope, protocol.parse_acknowledgment):
            for value in invalid:
                with self.subTest(parser=parser.__name__, value=repr(value)):
                    with self.assertRaises(protocol.MessagingProtocolError) as raised:
                        parser(value, NOW)
                    self.assertEqual(raised.exception.code, 'invalid_json')
                    self.assertEqual(str(raised.exception), 'invalid_json')
                    self.assertIsNone(raised.exception.__cause__)

    def test_raw_byte_limit_and_duplicate_key_are_causal(self):
        for kind, parser in [('envelope', protocol.parse_envelope),
                             ('acknowledgment', protocol.parse_acknowledgment)]:
            value = SEMANTICS[kind]
            raw = _body(value)
            self.assertEqual(parser(raw, NOW), value)
            padded = raw + b' ' * (protocol.MAX_PROTOCOL_MESSAGE_BYTES - len(raw))
            self.assertEqual(parser(padded, NOW), value)
            with self.assertRaisesRegex(protocol.MessagingProtocolError, '^message_too_large$'):
                parser(padded + b' ', NOW)
            duplicated = b'{"schemaVersion":2,' + raw[1:]
            with self.assertRaisesRegex(protocol.MessagingProtocolError, '^duplicate_json_key$'):
                parser(duplicated, NOW)
            self.assertEqual(parser(raw, NOW), value)

    def test_raw_freshness_clock_and_decoded_apis_remain_separate(self):
        for kind, parser, validator in [
                ('envelope', protocol.parse_envelope, protocol.validate_envelope),
                ('acknowledgment', protocol.parse_acknowledgment, protocol.validate_acknowledgment)]:
            value = SEMANTICS[kind]
            raw = _body(value)
            self.assertTrue(validator(value, NOW))
            self.assertFalse(validator(raw, NOW))
            with patch.object(protocol.time, 'time', return_value=NOW / 1000):
                self.assertEqual(parser(raw), value)
            for clock in (True, '1', float('nan'), float('inf'), 10**1000):
                with self.subTest(kind=kind, clock=repr(clock)):
                    with self.assertRaisesRegex(protocol.MessagingProtocolError, '^stale_message$'):
                        parser(raw, clock)

    def test_decoded_module_does_not_load_v1_schema(self):
        code = (
            'import sys; from event_gateway import messaging_protocol_v2; '
            'assert "event_gateway.protocol" not in sys.modules; '
            'assert "jsonschema" not in sys.modules'
        )
        # Only the current interpreter and literal test code; no shell or caller input.
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=False)  # nosec B603
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
