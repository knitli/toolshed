"""Raw Messaging v2 conformance with the unchanged shared strict JSON decoder."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from event_gateway import messaging_protocol_v2 as protocol

CONTRACTS = Path(__file__).resolve().parents[1] / 'contracts/messaging-v2'
SEMANTICS = json.loads((CONTRACTS / 'messaging-protocol-semantics-v2.json').read_text())
NOW = SEMANTICS['nowMs']


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

    def test_wire_fixture_provenance_is_not_policy_adoption(self):
        receipt = json.loads((CONTRACTS / 'wire-source-receipt.json').read_text())
        fixture = CONTRACTS / receipt['fixture']['file']
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), receipt['fixture']['sha256'])
        self.assertEqual(receipt['purpose'], 'dormant_source_conformance_only')
        self.assertFalse(receipt['trustedPolicyAdoption'])
        self.assertEqual(receipt['protocolVersion'], 2)
        self.assertTrue(all(len(entry['sha256']) == 64 for entry in receipt['sourceFiles']))

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
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
