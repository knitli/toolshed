"""Keep the disposable observer's no-turn boundary in normal CI discovery."""
import asyncio
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class CodexBridgeSpikeTests(unittest.TestCase):
    def test_metadata_only_and_no_turn_or_approval_forwarding(self):
        path = Path(__file__).parents[1] / 'scripts' / 'observe_codex_bridge.py'
        spec = importlib.util.spec_from_file_location('observe_codex_bridge', path)
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        observer.check()

    def test_native_witness_fails_closed(self):
        path = Path(__file__).parents[1] / 'scripts' / 'observe_codex_bridge.py'
        spec = importlib.util.spec_from_file_location('observe_codex_bridge', path)
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        row = {'clientId': '11111111-1111-4111-8111-111111111111',
               'connectionId': '22222222-2222-4222-8222-222222222222',
               'threadId': '33333333-3333-4333-8333-333333333333',
               'backendPid': 123, 'generation': 0, 'sequence': 1,
               'eligible': True, 'cause': 'heartbeat'}
        witness = observer.Witness()
        witness.receive(json.dumps(row), 123, 10.0)
        self.assertEqual(witness.status(123, 10.999), (True, 'native'))
        self.assertEqual(witness.status(123, 11.0), (False, 'expired'))
        self.assertEqual(witness.status(456, 10.1), (False, 'unknown-backend'))
        self.assertEqual(witness.status(None, 10.1), (False, 'unknown-backend'))
        witness.eof()
        self.assertEqual(witness.status(123, 10.1), (False, 'eof'))
        for field, value in [('clientId', 'not-uuid'), ('generation', -1),
                             ('generation', True), ('eligible', 1), ('sequence', 0),
                             ('backendPid', True), ('cause', 'x' * 129),
                             ('prompt', 'SECRET')]:
            with self.subTest(field=field, value=value):
                witness = observer.Witness()
                witness.receive(json.dumps(row | {field: value}), 123, 10.0)
                self.assertEqual(witness.status(123, 10.1), (False, 'malformed'))
                self.assertIsNone(witness.row)
        for raw in [b'bad JSON', b'\xff', b'[]']:
            witness.receive(raw, 123, 10.0)
            self.assertEqual(witness.status(123, 10.1), (False, 'malformed'))
        witness = observer.Witness()
        witness.receive(json.dumps(row), 123, 10.0)
        witness.receive(json.dumps(row), 123, 10.1)
        self.assertEqual(witness.status(123, 10.1), (False, 'malformed'))
        witness.receive(json.dumps(row | {'sequence': 2, 'clientId': row['threadId']}), 123, 10.2)
        self.assertEqual(witness.status(123, 10.2), (False, 'malformed'))
        witness.receive(json.dumps(row | {'sequence': 2, 'threadId': None}), 123, 10.3)
        self.assertEqual(witness.status(123, 10.3), (False, 'unavailable'))
        witness.receive(json.dumps(row | {'sequence': 3, 'backendPid': None}), 123, 10.4)
        self.assertEqual(witness.status(123, 10.4), (False, 'unknown-backend'))
        self.assertTrue(observer.permitted('client', {'method': 'server/diagnostics'}))

    def test_native_fifo_limits_individual_frames_not_read_batches(self):
        path = Path(__file__).parents[1] / 'scripts' / 'observe_codex_bridge.py'
        spec = importlib.util.spec_from_file_location('observe_codex_bridge', path)
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        expected = [json.dumps({'sequence': i, 'cause': 'x' * 128}).encode()
                    for i in range(100)]
        stream = b'\n'.join(expected) + b'\n'
        pending, discarding, received = b'', False, []
        for offset in range(0, len(stream), 4096):
            pending, discarding, frames = observer.witness_frames(
                pending, stream[offset:offset + 4096], discarding)
            received.extend(frames)
            self.assertLessEqual(len(pending), 4096)
        self.assertEqual(received, expected)
        self.assertEqual((pending, discarding), (b'', False))
        # Oversized partial records revoke once, discard through newline, then recover.
        pending, discarding, frames = observer.witness_frames(b'x' * 4096, b'x', False)
        self.assertEqual((pending, discarding, frames), (b'', True, [b'']))
        self.assertEqual(observer.witness_frames(pending, b'x' * 4096, discarding),
                         (b'', True, []))
        self.assertEqual(observer.witness_frames(b'', b'tail\nvalid\n', True),
                         (b'', False, [b'valid']))
        self.assertEqual(observer.witness_frames(b'x' * 4096, b'x\nvalid\n', False),
                         (b'', False, [b'', b'valid']))

    def test_native_fifo_waits_for_writer_then_stops_at_eof(self):
        path = Path(__file__).parents[1] / 'scripts' / 'observe_codex_bridge.py'
        spec = importlib.util.spec_from_file_location('observe_codex_bridge', path)
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        states = []
        reads = [b'', b'{}\n', b'']

        def read(*_):
            self.assertTrue(reads, 'reader must stop after connected writer EOF')
            return reads.pop(0)

        async def no_sleep(_):
            pass

        with patch.object(observer.os, 'read', side_effect=read), \
                patch.object(observer.asyncio, 'sleep', side_effect=no_sleep):
            asyncio.run(observer.read_witness(
                123, lambda: 456, lambda: True,
                lambda witness, pid, now: states.append(witness.status(pid, now))))
        self.assertEqual(reads, [], 'reader must wait for the initial writer')
        self.assertEqual(states, [(False, 'eof'), (False, 'malformed'), (False, 'eof')])

    def test_observer_closes_logs_when_cleanup_fails(self):
        path = Path(__file__).parents[1] / 'scripts' / 'observe_codex_bridge.py'
        spec = importlib.util.spec_from_file_location('observe_codex_bridge', path)
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        opened = {}
        original_open = Path.open

        def tracked_open(path, *args, **kwargs):
            handle = original_open(path, *args, **kwargs)
            if path.name.endswith('.jsonl'):
                opened[path.name] = handle
            return handle

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(Path, 'open', tracked_open), \
                    patch.object(observer.subprocess, 'Popen', side_effect=RuntimeError('backend failed')), \
                    patch.object(observer.shutil, 'rmtree', side_effect=OSError('cleanup failed')):
                with self.assertRaisesRegex(OSError, 'cleanup failed'):
                    asyncio.run(observer.observe(Path('/unused'), Path(directory), Path('/unused')))
            try:
                self.assertEqual(set(opened), {'wire.jsonl', 'native.jsonl'})
                self.assertTrue(all(handle.closed for handle in opened.values()),
                                'both logs must close even when resource cleanup raises')
            finally:
                for handle in opened.values():
                    handle.close()
