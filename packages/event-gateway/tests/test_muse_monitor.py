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
        for url in ('https://example.test', 'ws:', 'ws://', 'ws://[bad',
                    'ws://example.test:99999'):  # nosemgrep -- Offline invalid URL; no connection.
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
        for options in ({'ws': 'wss://example.test'}, {'command': 'other'}, {'sessionId': 'x'}):
            with self.assertRaises(MuseMonitorError):
                command_monitor('x', ['poll'], **options)


if __name__ == '__main__':
    unittest.main()
