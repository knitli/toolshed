"""Contract-derived offline fixtures, never a native monitor or wake proof."""

import copy
import json
from pathlib import Path
import shlex
import subprocess  # nosec B404 -- Fixed local shell exercises synthetic argv quoting.
import tempfile
import unittest
from unittest.mock import patch

from event_gateway.muse import MuseMonitorError, command_monitor, normalize_monitor


class MuseMonitorTests(unittest.TestCase):
    def test_validation_error_exposes_only_safe_code(self):
        with self.assertRaises(MuseMonitorError) as caught:
            normalize_monitor({'description': 'private description', 'ws': 'wss://private.test/#private-token'})
        self.assertEqual(caught.exception.code, 'invalid_muse_monitor')
        self.assertEqual(str(caught.exception), caught.exception.code)
        self.assertEqual(caught.exception.args, ('invalid_muse_monitor',))

    def test_reported_defaults_and_contract_provenance(self):
        contract = json.loads((Path(__file__).resolve().parents[1]
                               / 'docs/muse-ingress/owner-monitor-contract.json').read_text())
        self.assertFalse(contract['liveWakeProven'])
        self.assertEqual(contract['required'], ['description'])
        self.assertEqual(contract['exactlyOneOf'], ['command', 'ws'])
        actual = normalize_monitor({'description': 'Pending references', 'command': 'poll'})
        for key in ('persistent', 'timeout_ms', 'wake_delay_ms', 'show_lines'):
            self.assertEqual(actual[key], contract['properties'][key]['default'])
        self.assertEqual(actual['command'], 'poll')
        self.assertNotIn('receipt', actual)

    def test_numeric_bounds_match_owner_contract(self):
        contract = json.loads((Path(__file__).resolve().parents[1]
                               / 'docs/muse-ingress/owner-monitor-contract.json').read_text())
        base = {'description': 'Offline contract fixture', 'command': 'poll'}
        for key, minimum_key in (('timeout_ms', 'minimum'), ('wake_delay_ms', 'nonzeroMinimum')):
            rule = contract['properties'][key]
            minimum, maximum = rule[minimum_key], rule['maximum']
            for value, accepted in ((minimum, True), (maximum, True),
                                    (minimum - 1, False), (maximum + 1, False)):
                with self.subTest(key=key, value=value):
                    self.assert_contract_acceptance({**base, key: value}, accepted)
        self.assert_contract_acceptance(
            {**base, 'wake_delay_ms': 0}, contract['properties']['wake_delay_ms']['allowedZero'])

    def test_cross_field_constraints_match_owner_contract(self):
        contract = json.loads((Path(__file__).resolve().parents[1]
                               / 'docs/muse-ingress/owner-monitor-contract.json').read_text())
        timeout = contract['properties']['timeout_ms']
        self.assert_contract_acceptance(
            {'description': 'Offline contract fixture', 'command': 'poll', 'persistent': True,
             'timeout_ms': timeout['minimum']}, not timeout['persistentForbidden'])
        protocols = contract['properties']['ws_subprotocols']
        for source in ({'ws': 'wss://example.test/events'}, {'command': 'poll'}):
            with self.subTest(source=source):
                self.assert_contract_acceptance(
                    {'description': 'Offline contract fixture', **source, 'ws_subprotocols': ['fixture']},
                    'ws' in source or not protocols['wsOnly'])

    def assert_contract_acceptance(self, value, expected):
        try:
            result = normalize_monitor(value)
        except MuseMonitorError:
            self.assertFalse(expected, 'normalizer rejected a contract-permitted input')
        else:
            self.assertTrue(expected, 'normalizer accepted a contract-forbidden input')
            for key, item in value.items():
                self.assertEqual(result[key], item)

    def test_exactly_one_source_and_required_description(self):
        for value in ({}, {'command': 'poll'}, {'description': 'x'},
                      {'description': 'x', 'command': 'poll', 'ws': 'wss://example.test'},
                      {'description': 1, 'command': 'poll'}, {'description': 'x', 'command': 1},
                      {'description': 'x', 'command': 'poll', 'sessionId': 'untrusted'}, [], None):
            with self.subTest(value=value), self.assertRaises(MuseMonitorError):
                normalize_monitor(value)

    def test_boolean_and_integer_boundaries(self):
        base = {'description': 'x', 'command': 'poll'}
        for key in ('persistent', 'show_lines'):
            for value in (0, 1, None, 'false'):
                with self.subTest(key=key, value=value), self.assertRaises(MuseMonitorError):
                    normalize_monitor({**base, key: value})
        for key in ('timeout_ms', 'wake_delay_ms'):
            for value in (1000, 1800000):
                self.assertEqual(normalize_monitor({**base, key: value})[key], value)
            for value in (True, False, 1000.0, '1000', None, -1, 999, 1800001):
                with self.subTest(key=key, value=value), self.assertRaises(MuseMonitorError):
                    normalize_monitor({**base, key: value})
        self.assertEqual(normalize_monitor({**base, 'wake_delay_ms': 0})['wake_delay_ms'], 0)
        with self.assertRaises(MuseMonitorError):
            normalize_monitor({**base, 'timeout_ms': 0})

    def test_persistent_forbids_explicit_timeout_and_omits_default(self):
        base = {'description': 'x', 'command': 'poll', 'persistent': True}
        self.assertNotIn('timeout_ms', normalize_monitor(base))
        for value in (None, 300000, 1000):
            with self.assertRaises(MuseMonitorError):
                normalize_monitor({**base, 'timeout_ms': value})

    def test_websocket_protocol_tokens_are_unique_and_ws_only(self):
        base = {'description': 'x', 'ws': 'wss://example.test/events'}
        protocols = ["!#$%&'*+-.^_`|~0AZaz9", 'other']
        result = normalize_monitor({**base, 'ws_subprotocols': protocols})
        protocols.append('later')
        self.assertEqual(len(result['ws_subprotocols']), 2)
        for value in (['same', 'same'], ['has space'], ['a/b'], ['a:b'], [''], ['a\n'],
                      ['ümlaut'], [None], [{}], 'token', None):
            with self.subTest(value=value), self.assertRaises(MuseMonitorError):
                normalize_monitor({**base, 'ws_subprotocols': value})
        self.assertEqual(normalize_monitor({**base, 'ws_subprotocols': []})['ws_subprotocols'], [])
        with self.assertRaises(MuseMonitorError):
            normalize_monitor({'description': 'x', 'command': 'poll', 'ws_subprotocols': []})
        for url in (  # nosemgrep -- Offline invalid URL fixtures; no connection.
                'https://example.test', 'ws:', 'ws://', 'ws://[bad',  # nosemgrep -- Rejected offline inputs.
                'ws://example.test:99999'):  # nosemgrep -- Rejected offline input.
            with self.subTest(url=url), self.assertRaises(MuseMonitorError):
                normalize_monitor({**base, 'ws': url})
        self.assertEqual(normalize_monitor({**base, 'ws': 'ws://localhost:1234'})['ws'], 'ws://localhost:1234')

    def test_command_position_is_literal_in_real_posix_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            for executable in ('X=1', 'if', '!', "a'b"):
                path = Path(directory) / executable
                path.write_text("#!/bin/sh\nprintf '%s\\0' called \"$@\"\n")
                path.chmod(0o700)
                args = ['literal argument', '$(exit 9)', "a'b", '']
                command = command_monitor('Offline shell fixture', [executable, *args])['command']
                with self.subTest(executable=executable):
                    result = subprocess.run(  # nosec B603 -- Synthetic scripts in our private test directory.
                        ['/bin/sh', '-c', command], env={'PATH': directory},
                        check=False, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, b'called\0' + b''.join(arg.encode() + b'\0' for arg in args))

    def test_websocket_rejects_raw_fragments_including_empty_fragment(self):
        for url in ('wss://example.test/events#fragment', 'wss://example.test/events#',
                    'wss://example.test/events?cursor=1#'):
            with self.subTest(url=url), self.assertRaises(MuseMonitorError):
                normalize_monitor({'description': 'Offline URL fixture', 'ws': url})
        for url in ('wss://example.test/events', 'wss://example.test/events%23fragment',
                    'wss://example.test/events?cursor=%23'):
            with self.subTest(url=url):
                self.assertEqual(normalize_monitor({'description': 'Offline URL fixture', 'ws': url})['ws'], url)

    def test_websocket_rejects_raw_whitespace_and_controls_before_parsing(self):
        for character in (*map(chr, range(33)), '\x7f'):
            for url in (f'{character}wss://example.test/events',
                        f'wss://example.test/events{character}',
                        f'wss://example.test/ev{character}ents',
                        f'wss://exam{character}ple.test/events'):
                with self.subTest(url=url), patch('event_gateway.muse.urlsplit') as parse:
                    with self.assertRaises(MuseMonitorError):
                        normalize_monitor({'description': 'Offline URL fixture', 'ws': url})
                    parse.assert_not_called()

    def test_websocket_authority_shape_and_valid_ipv6(self):
        for url in ('wss://example\\.test/events', 'wss://[::1]trailing/events',
                    'wss://[::1]trailing:443/events'):
            with self.subTest(url=url), self.assertRaises(MuseMonitorError):
                normalize_monitor({'description': 'Offline URL fixture', 'ws': url})
        for url in ('wss://example.test:443/events?cursor=1', 'wss://[::1]/events',
                    'wss://[2001:db8::1]:443/events', 'wss://[::1]:/events',
                    'wss://example.test:/events'):
            with self.subTest(url=url):
                self.assertEqual(normalize_monitor({'description': 'Offline URL fixture', 'ws': url})['ws'], url)

    def test_websocket_rejects_userinfo_only_in_authority(self):
        for authority in ('@example.test', 'user@example.test', 'user:password@example.test',
                          ':password@example.test', ':@example.test', 'user:@[::1]'):
            with self.subTest(authority=authority), self.assertRaises(MuseMonitorError):
                normalize_monitor({'description': 'Offline URL fixture', 'ws': f'wss://{authority}/events'})
        for suffix in ('/events%40user', '/events?cursor=%40user', '/events@user?cursor=@next'):
            url = 'wss://example.test' + suffix
            with self.subTest(url=url):
                self.assertEqual(normalize_monitor({'description': 'Offline URL fixture', 'ws': url})['ws'], url)

    def test_raw_command_rejects_nul_and_preserves_shell_source(self):
        for command in ('\x00poll', 'poll\x00', 'printf "a\x00b"'):
            with self.subTest(command=command), self.assertRaises(MuseMonitorError):
                normalize_monitor({'description': 'Offline command fixture', 'command': command})
        for command in ('printf first\nprintf second', 'X=1; printf "%s" "$X" | cat',
                        "printf 'line\\nbreak'\n", '\tprintf done\n'):
            with self.subTest(command=command):
                result = normalize_monitor({'description': 'Offline command fixture', 'command': command})
                self.assertEqual(result['command'], command)

    def test_argv_is_quoted_without_execution_or_mutation(self):
        argv = ['/trusted/poll command', '--session', '$(touch /tmp/not-run)',
                "a'b", '; echo unsafe', '`whoami`', 'line\nbreak', '']
        before = copy.deepcopy(argv)
        with patch('subprocess.run', side_effect=AssertionError('must not execute')):
            result = command_monitor('Pending references', argv, wake_delay_ms=0)
        self.assertEqual(shlex.split(result['command']), argv)
        self.assertEqual(argv, before)
        self.assertEqual(result['wake_delay_ms'], 0)
        self.assertEqual(command_monitor('x', ('poll',))['command'], "'poll'")
        for value in ([], '', [''], ['poll', None], ['poll', 'bad\x00arg']):
            with self.subTest(value=value), self.assertRaises(MuseMonitorError):
                command_monitor('x', value)
        for options in ({'ws': 'wss://example.test'}, {'ws_subprotocols': []},
                        {'ws_subprotocols': ['private-token']}, {'command': 'other'}, {'sessionId': 'x'}):
            with patch('event_gateway.muse.normalize_monitor') as normalize, self.assertRaises(MuseMonitorError):
                command_monitor('x', ['poll'], **options)
            normalize.assert_not_called()


if __name__ == '__main__':
    unittest.main()
