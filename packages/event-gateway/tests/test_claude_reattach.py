"""Actual adapter subprocesses against a synthetic socket; never launch Claude."""
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import tempfile
import unittest
from uuid import uuid4
from unittest.mock import AsyncMock, Mock, patch

from event_gateway.claude import ClaudeSocketTransport, METADATA_FIELDS, event_frame

SCRIPT = Path(__file__).parents[1] / 'scripts/qualify_claude_socket.py'
SPEC = importlib.util.spec_from_file_location('claude_reattach_canary', SCRIPT)
CANARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANARY)


class ReattachTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/private/tmp' if Path('/private/tmp').is_dir() else '/tmp')
        self.root = Path(self.temp.name)
        self.path = self.root / 'inbox.sock'
        self.connections = 0
        self.frames = []
        self.handlers = set()
        self.received = asyncio.Event()
        self.server = await asyncio.start_unix_server(self.receive, self.path)
        self.path.chmod(0o600)
        info = self.path.stat()
        self.options = dict(socket_path=str(self.path), socket_identity=(info.st_dev, info.st_ino),
                            peer_pid=os.getpid(), session_id=str(uuid4()), token=secrets.token_urlsafe(32),
                            version='2.1.302', journal_dir=self.root / 'journal')
        fixtures = SCRIPT.parent.parent / 'contracts/event-v1/protocol-v1.json'
        envelope = json.loads(fixtures.read_text())['validEnvelopes'][1]
        self.old = {key: envelope[key] for key in METADATA_FIELDS}
        self.fresh = dict(self.old, eventId=str(uuid4()), deliveryId='dly_' + hashlib.sha256(b'fresh').hexdigest())
        self.records = []

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        if self.handlers:
            await asyncio.wait_for(asyncio.gather(*self.handlers), 2)
        self.temp.cleanup()

    async def receive(self, reader, writer):
        task = asyncio.current_task()
        self.handlers.add(task)
        self.connections += 1
        try:
            lines = [await reader.readline(), await reader.readline()]
            if any(lines):
                self.frames.append([json.loads(line) for line in lines if line])
            self.received.set()
        finally:
            writer.close()
            await writer.wait_closed()
            self.handlers.discard(task)

    def marker(self, metadata):
        message_id = event_frame(self.options['session_id'], metadata)['msg_id']
        return self.options['journal_dir'] / hashlib.sha256(
            f"{self.options['session_id']}:{message_id}".encode()).hexdigest()

    def record(self, kind, **fields):
        self.records.append((kind, fields))

    async def test_actual_crash_reattach_preserves_journal_and_sends_only_fresh(self):
        async def before_fresh():
            self.assertEqual(self.connections, 0)
            self.assertEqual(self.marker(self.old).read_bytes(), b'')
            self.assertEqual(stat.S_IMODE(self.marker(self.old).stat().st_mode), 0o600)
            info = self.path.stat()
            self.assertEqual((info.st_dev, info.st_ino), self.options['socket_identity'])
            self.assertEqual(self.options['peer_pid'], os.getpid())

        outcome, proof = await CANARY.adapter_reattach(
            self.options, self.old, self.fresh, before_fresh=before_fresh, record=self.record)
        await asyncio.wait_for(self.received.wait(), 2)
        self.assertEqual(outcome, {'status': 'unknown', 'reason': 'claude_write_unacknowledged'})
        self.assertEqual(self.connections, 1)
        self.assertEqual(self.frames, [[{'type': 'auth', 'token': self.options['token']},
                                       event_frame(self.options['session_id'], self.fresh)]])
        self.assertNotEqual(event_frame(self.options['session_id'], self.old)['uuid'],
                            event_frame(self.options['session_id'], self.fresh)['uuid'])
        self.assertEqual(set(self.options['journal_dir'].iterdir()), {self.marker(self.old), self.marker(self.fresh)})
        for marker in (self.marker(self.old), self.marker(self.fresh)):
            self.assertEqual(marker.read_bytes(), b'')
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        again = await ClaudeSocketTransport(**self.options).send(self.fresh)
        self.assertEqual(again, {'status': 'unknown', 'reason': 'claude_attempt_already_reserved'})
        self.assertEqual(self.connections, 1)
        self.assertNotIn(self.options['token'], json.dumps(proof))
        self.assertEqual(proof['oldReconciliation'], {'status': 'unknown', 'reason': 'claude_native_receipt_unavailable'})
        for key in ('oldRetrySuppressed', 'sameJournalMarkerRetained', 'adapterKilledAndReaped', 'adapterProcessReplaced'):
            self.assertIs(proof[key], True)
        for key in ('nativeProcessRestarted', 'nativeRestartQualified', 'postWriteAdapterCrashObserved', 'nativePostWriteRecoveryQualified'):
            self.assertIs(proof[key], False)
        self.assertEqual((proof['admission'], proof['delivery']), ('unknown', 'unknown'))
        self.assertEqual(proof['oldInputUuid'], event_frame(self.options['session_id'], self.old)['uuid'])
        self.assertEqual(proof['freshInputUuid'], event_frame(self.options['session_id'], self.fresh)['uuid'])

    async def test_postwrite_crash_suppresses_old_and_sends_distinct_fresh(self):
        async def before_fresh():
            await asyncio.wait_for(self.received.wait(), 2)
            self.assertEqual(self.connections, 1)
            self.assertEqual(self.frames, [[{'type': 'auth', 'token': self.options['token']},
                                           event_frame(self.options['session_id'], self.old)]])
            self.received.clear()
            self.assertEqual(self.marker(self.old).read_bytes(), b'')

        outcome, proof = await CANARY.adapter_reattach(
            self.options, self.old, self.fresh, crash_point='after-write-close-before-result',
            before_fresh=before_fresh, record=self.record)
        await asyncio.wait_for(self.received.wait(), 2)
        self.assertEqual(outcome, {'status': 'unknown', 'reason': 'claude_write_unacknowledged'})
        self.assertEqual(self.connections, 2)
        self.assertEqual(self.frames, [
            [{'type': 'auth', 'token': self.options['token']}, event_frame(self.options['session_id'], metadata)]
            for metadata in (self.old, self.fresh)])
        self.assertNotEqual(self.frames[0][1]['uuid'], self.frames[1][1]['uuid'])
        self.assertEqual(proof['crashPoint'], 'after-write-close-before-result')
        self.assertTrue(proof['postWriteAdapterCrashObserved'])
        self.assertFalse(proof['nativePostWriteRecoveryQualified'])
        self.assertEqual(proof['oldReconciliation'], {'status': 'unknown', 'reason': 'claude_native_receipt_unavailable'})
        self.assertTrue(proof['oldRetrySuppressed'])
        self.assertTrue(proof['adapterKilledAndReaped'])
        self.assertTrue(proof['sameJournalMarkerRetained'])
        self.assertEqual((proof['admission'], proof['delivery']), ('unknown', 'unknown'))
        self.assertFalse(proof['nativeProcessRestarted'])
        self.assertFalse(proof['nativeRestartQualified'])
        self.assertEqual(set(self.options['journal_dir'].iterdir()), {self.marker(self.old), self.marker(self.fresh)})
        for marker in (self.marker(self.old), self.marker(self.fresh)):
            self.assertEqual(marker.read_bytes(), b'')
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        duplicate = await ClaudeSocketTransport(**self.options).send(self.old)
        self.assertEqual(duplicate['reason'], 'claude_attempt_already_reserved')
        self.assertEqual(self.connections, 2)

    async def test_existing_old_reservation_refuses_without_connection(self):
        adapter = ClaudeSocketTransport(**self.options)
        adapter._reserve(event_frame(self.options['session_id'], self.old)['msg_id'])
        with self.assertRaises(CANARY.CanaryError):
            await CANARY.adapter_reattach(self.options, self.old, self.fresh)
        self.assertEqual(self.connections, 0)
        self.assertFalse(self.marker(self.fresh).exists())

    async def test_before_fresh_failure_never_connects(self):
        async def refuse():
            raise CANARY.CanaryError('fixture_before_fresh_refused')
        actors = []
        create = asyncio.create_subprocess_exec

        async def track(*args, **kwargs):
            actor = await create(*args, **kwargs)
            actors.append(actor)
            return actor

        with patch.object(CANARY.asyncio, 'create_subprocess_exec', side_effect=track):
            with self.assertRaisesRegex(CANARY.CanaryError, 'fixture_before_fresh_refused'):
                await CANARY.adapter_reattach(self.options, self.old, self.fresh, before_fresh=refuse)
        self.assertEqual(len(actors), 2)
        self.assertTrue(all(actor.returncode is not None for actor in actors))
        self.assertEqual(self.connections, 0)
        self.assertTrue(self.marker(self.old).exists())
        self.assertFalse(self.marker(self.fresh).exists())

    async def test_missing_or_timed_out_checkpoint_cleans_up_actor(self):
        for failure in (b'', TimeoutError()):
            with self.subTest(failure=type(failure).__name__):
                actor = Mock()
                actor.stdin.drain = AsyncMock()
                actor.stdout.readline = AsyncMock(return_value=failure if isinstance(failure, bytes) else b'')
                if isinstance(failure, Exception):
                    actor.stdout.readline.side_effect = failure
                with patch.object(CANARY.asyncio, 'create_subprocess_exec', AsyncMock(return_value=actor)), \
                     patch.object(CANARY, 'stop_child', AsyncMock()) as cleanup:
                    with self.assertRaises((CANARY.CanaryError, TimeoutError)):
                        await CANARY.adapter_reattach(self.options, self.old, self.fresh)
                    cleanup.assert_awaited_once_with(actor)
                self.assertEqual(self.connections, 0)

    async def test_wrong_peer_pid_refuses_before_authentication(self):
        options = dict(self.options, peer_pid=os.getpid() + 100000)
        with self.assertRaisesRegex(CANARY.CanaryError, 'reattach_fresh_write_unconfirmed'):
            await CANARY.adapter_reattach(options, self.old, self.fresh)
        await asyncio.wait_for(self.received.wait(), 2)
        self.assertEqual(self.connections, 1)
        self.assertEqual(self.frames, [])

    async def test_socket_replacement_before_fresh_refuses_without_wire(self):
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            async def replace():
                self.path.rename(self.root / 'original.sock')
                replacement.bind(str(self.path))
                replacement.listen(1)
                self.path.chmod(0o600)
                self.assertNotEqual(self.path.stat().st_ino, self.options['socket_identity'][1])
            with self.assertRaisesRegex(CANARY.CanaryError, 'reattach_actor_checkpoint_missing'):
                await CANARY.adapter_reattach(self.options, self.old, self.fresh, before_fresh=replace)
            self.assertEqual(self.connections, 0)
            self.assertEqual(self.frames, [])
            self.assertFalse(self.marker(self.fresh).exists())
        finally:
            replacement.close()

    async def test_real_actor_fsync_failure_never_connects(self):
        create = asyncio.create_subprocess_exec
        actors = []

        async def fail_fsync(*args, **kwargs):
            args = list(args)
            index = args.index('-c') + 1
            # Fault only the disposable actor; preserve production adapter code.
            args[index] = "import os; os.fsync=lambda fd: (_ for _ in ()).throw(OSError('fixture_fsync')); " + args[index]
            actor = await create(*args, **kwargs)
            actors.append(actor)
            return actor

        with patch.object(CANARY.asyncio, 'create_subprocess_exec', side_effect=fail_fsync):
            with self.assertRaisesRegex(CANARY.CanaryError, 'reattach_actor_checkpoint_missing'):
                await CANARY.adapter_reattach(self.options, self.old, self.fresh)
        self.assertEqual(len(actors), 1)
        self.assertIsNotNone(actors[0].returncode)
        self.assertEqual(self.connections, 0)
        self.assertFalse(self.marker(self.fresh).exists())

    async def test_cleanup_failure_invalidates_success(self):
        stop = CANARY.stop_child

        async def fail_after_stop(actor):
            await stop(actor)
            raise OSError('fixture_cleanup')

        with patch.object(CANARY, 'stop_child', side_effect=fail_after_stop) as cleanup:
            with self.assertRaisesRegex(CANARY.CanaryError, 'reattach_actor_cleanup_failed'):
                await CANARY.adapter_reattach(self.options, self.old, self.fresh)
        self.assertEqual(cleanup.await_count, 2)
        self.assertTrue(all(call.args[0].returncode is not None for call in cleanup.await_args_list))

    async def test_cleanup_failure_preserves_primary_error(self):
        actor = Mock()
        actor.stdin.drain = AsyncMock()
        actor.stdout.readline = AsyncMock(return_value=b'')
        with patch.object(CANARY.asyncio, 'create_subprocess_exec', AsyncMock(return_value=actor)), \
             patch.object(CANARY, 'stop_child', AsyncMock(side_effect=OSError('fixture_cleanup'))):
            with self.assertRaisesRegex(CANARY.CanaryError, 'reattach_actor_checkpoint_missing') as caught:
                await CANARY.adapter_reattach(self.options, self.old, self.fresh)
        self.assertIn('reattach_actor_cleanup_failed', caught.exception.__notes__)
        self.assertEqual(self.connections, 0)

    async def test_same_derived_uuid_is_refused(self):
        with self.assertRaises(CANARY.CanaryError):
            await CANARY.adapter_reattach(self.options, self.old, dict(self.old, eventId=str(uuid4())))
        self.assertEqual(self.connections, 0)


if __name__ == '__main__':
    unittest.main()
