"""Keep the disposable observer's no-turn boundary in normal CI discovery."""
import asyncio
import importlib.util
import json
from pathlib import Path
import socket
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

    def observer(self):
        path = Path(__file__).parents[1] / 'scripts' / 'observe_codex_bridge.py'
        spec = importlib.util.spec_from_file_location('observe_codex_bridge', path)
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        return observer

    def row(self, **changes):
        return json.dumps({'clientId': '11111111-1111-4111-8111-111111111111',
                           'connectionId': '22222222-2222-4222-8222-222222222222',
                           'threadId': '33333333-3333-4333-8333-333333333333',
                           'backendPid': 123, 'generation': 0, 'sequence': 1,
                           'eligible': True, 'cause': 'heartbeat', 'version': 1,
                           'nonce': 1} | changes).encode()

    def test_matching_challenge_and_absolute_freshness(self):
        witness = self.observer().Witness()
        self.assertEqual(json.loads(witness.challenge(10)), {'nonce': 1})
        self.assertIsNone(witness.challenge(10.1))
        witness.receive(self.row(), 123, 10.2)
        self.assertEqual(witness.status(123, 10.749), (True, 'native'))
        self.assertEqual(witness.status(456, 10.2), (False, 'unknown-backend'))
        self.assertEqual(witness.status(None, 10.2), (False, 'unknown-backend'))
        witness.challenge(10.3)
        self.assertEqual(witness.status(123, 10.750), (False, 'expired'))

    def test_unsolicited_and_replay_cannot_renew(self):
        for challenge, records in [(False, [self.row()]),
                                   (True, [self.row(nonce=2)]),
                                   (True, [self.row(), self.row(sequence=2)])]:
            witness = self.observer().Witness()
            if challenge:
                witness.challenge(10)
            for raw in records:
                witness.receive(raw, 123, 10.1)
            self.assertEqual(witness.status(123, 10.2), (False, 'unexpected-nonce'))
            self.assertTrue(witness.failed)
            self.assertIsNone(witness.challenge(11))

    def test_late_matching_response_drains_without_renewal(self):
        witness = self.observer().Witness()
        witness.challenge(10)
        self.assertEqual(witness.status(123, 10.75), (False, 'deadline'))
        self.assertIsNone(witness.challenge(11))
        witness.receive(self.row(), 123, 12)
        self.assertEqual(witness.status(123, 12), (False, 'deadline'))
        self.assertEqual(json.loads(witness.challenge(12)), {'nonce': 2})
        witness.receive(self.row(nonce=2, sequence=2, generation=1), 123, 12.1)
        self.assertEqual(witness.status(123, 12.1), (True, 'native'))

    def test_native_schema_fails_closed(self):
        for field, value in [('clientId', 'not-uuid'), ('generation', -1),
                             ('generation', True), ('generation', 2**64),
                             ('eligible', 1), ('sequence', 0), ('sequence', 2**64),
                             ('backendPid', True), ('backendPid', 2**32),
                             ('cause', 'x' * 129), ('prompt', 'SECRET'),
                             ('version', True), ('version', 2), ('nonce', True)]:
            with self.subTest(field=field, value=value):
                witness = self.observer().Witness()
                witness.challenge(10)
                witness.receive(self.row(**{field: value}), 123, 10.1)
                self.assertEqual(witness.status(123, 10.1), (False, 'malformed'))
                self.assertIsNone(witness.row)
        for raw in [b'bad JSON', b'\xff', b'[]', b'{"nonce":1,"nonce":1}',
                    b' ' * 2048 + self.row()]:
            witness = self.observer().Witness()
            witness.challenge(10)
            witness.receive(raw, 123, 10.1)
            self.assertEqual(witness.status(123, 10.1), (False, 'malformed'))

    def test_client_identity_and_sequence_are_stable(self):
        for changes in [{'clientId': '33333333-3333-4333-8333-333333333333', 'sequence': 2},
                        {'sequence': 1}]:
            witness = self.observer().Witness()
            witness.challenge(10)
            witness.receive(self.row(), 123, 10.1)
            witness.challenge(10.2)
            witness.receive(self.row(nonce=2, **changes), 123, 10.3)
            self.assertEqual(witness.status(123, 10.3), (False, 'malformed'))

    def test_native_stream_limits_individual_frames_not_read_batches(self):
        observer = self.observer()
        expected = [self.row(sequence=i) for i in range(1, 101)]
        stream = b'\n'.join(expected) + b'\n'
        pending, discarding, received = b'', False, []
        for offset in range(0, len(stream), 4096):
            pending, discarding, frames = observer.witness_frames(
                pending, stream[offset:offset + 4096], discarding)
            received.extend(frames)
            self.assertLessEqual(len(pending), 2047)
        self.assertEqual(received, expected)
        self.assertEqual((pending, discarding), (b'', False))
        self.assertEqual(observer.witness_frames(b'x' * 2047, b'\n', False),
                         (b'', False, [b'x' * 2047]))
        self.assertEqual(observer.witness_frames(b'x' * 2047, b'x', False),
                         (b'', True, [b'']))
        self.assertEqual(observer.witness_frames(b'', b'x' * 4096, True),
                         (b'', True, []))
        self.assertEqual(observer.witness_frames(b'', b'tail\nvalid\n', True),
                         (b'', False, [b'valid']))
        self.assertEqual(observer.witness_frames(b'x' * 2047, b'x\nvalid\n', False),
                         (b'', False, [b'', b'valid']))

    def test_socket_challenge_reply_and_eof(self):
        observer = self.observer()
        states = []

        async def run():
            parent, child = socket.socketpair()
            child.setblocking(False)

            async def respond():
                loop = asyncio.get_running_loop()
                challenge = json.loads(await loop.sock_recv(child, 128))
                await loop.sock_sendall(child, self.row(nonce=challenge['nonce']) + b'\n')
                await asyncio.sleep(.060)
                child.close()
            responder = asyncio.create_task(respond())
            await asyncio.wait_for(observer.read_witness(
                parent, lambda: 123, lambda: True,
                lambda witness, pid, now: states.append(witness.status(pid, now))), 1)
            await responder
            self.assertEqual(parent.fileno(), -1)
        asyncio.run(run())
        self.assertIn((True, 'native'), states)
        self.assertEqual(states[-1], (False, 'eof'))

    def test_coalesced_replay_revokes_same_read(self):
        observer = self.observer()
        states = []

        async def run():
            parent, child = socket.socketpair()
            child.setblocking(False)

            async def respond():
                loop = asyncio.get_running_loop()
                await loop.sock_recv(child, 128)
                await loop.sock_sendall(child, self.row() + b'\n' + self.row(sequence=2) + b'\n')
            responder = asyncio.create_task(respond())
            try:
                await asyncio.wait_for(observer.read_witness(
                    parent, lambda: 123, lambda: True,
                    lambda witness, pid, now: states.append(witness.status(pid, now))), .5)
                await responder
            finally:
                child.close()
        asyncio.run(run())
        self.assertEqual(states[-1], (False, 'unexpected-nonce'))

    def test_socket_silence_has_one_outstanding_challenge(self):
        observer = self.observer()
        states = []

        async def run():
            parent, child = socket.socketpair()
            child.setblocking(False)
            task = asyncio.create_task(observer.read_witness(
                parent, lambda: 123, lambda: True,
                lambda witness, pid, now: states.append(witness.status(pid, now))))
            await asyncio.sleep(.85)
            wire = child.recv(4096)
            self.assertEqual(wire, b'{"nonce":1}\n')
            child.close()
            await asyncio.wait_for(task, .2)
        asyncio.run(run())
        self.assertIn((False, 'deadline'), states)
        self.assertFalse(any(eligible for eligible, _ in states))

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
