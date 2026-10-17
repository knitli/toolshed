import asyncio
import contextlib
import io
import json
import os
import secrets
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch, AsyncMock, Mock
from uuid import uuid4

from event_gateway.claude import ClaudeError, ClaudeSocketTransport, METADATA_FIELDS, event_frame, main


class ClaudeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        root = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'  # nosec B108
        self.temp = tempfile.TemporaryDirectory(dir=root)
        self.path = Path(self.temp.name) / 'claude.sock'
        self.frames = []
        self.received = asyncio.Event()
        self.server = await asyncio.start_unix_server(self.receive, self.path)
        self.path.chmod(0o600)
        info = self.path.stat()
        self.options = dict(socket_path=str(self.path), socket_identity=(info.st_dev, info.st_ino),
                            peer_pid=os.getpid(), session_id=str(uuid4()), token=secrets.token_urlsafe(32),
                            version='2.1.302', journal_dir=Path(self.temp.name) / 'journal')
        fixtures = Path(__file__).parents[1] / 'contracts/event-v1/protocol-v1.json'
        self.envelopes = json.loads(fixtures.read_text())['validEnvelopes']
        self.event = {key: self.envelopes[1][key] for key in METADATA_FIELDS}

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.temp.cleanup()

    async def receive(self, reader, writer):
        try:
            for _ in range(2):
                line = await reader.readline()
                if not line:
                    return
                self.frames.append(json.loads(line))
            self.received.set()
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_wire_and_restart_no_replay(self):
        adapter = ClaudeSocketTransport(**self.options)
        result = await adapter.send(self.event)
        await asyncio.wait_for(self.received.wait(), 1)
        self.assertEqual(result, {'status': 'unknown', 'reason': 'claude_write_unacknowledged'})
        auth, frame = self.frames
        self.assertEqual(auth, {'type': 'auth', 'token': self.options['token']})
        self.assertEqual(frame['session_id'], self.options['session_id'])
        self.assertEqual(frame['msg_id'], event_frame(self.options['session_id'], self.event)['msg_id'])
        self.assertEqual(frame['uuid'], frame['msg_id'])
        self.assertEqual(frame['priority'], 'next')
        self.assertEqual(frame['msgV'], 1)
        self.assertNotIn('from', frame)
        self.assertNotIn('permission_mode', frame)
        again = await ClaudeSocketTransport(**self.options).send(self.event)
        self.assertEqual(again['reason'], 'claude_attempt_already_reserved')
        self.assertEqual(len(self.frames), 2)
        self.assertEqual(await adapter.check(), 'unavailable')
        self.assertEqual((await adapter.reconcile(self.event['deliveryId']))['status'], 'unknown')
        journal = list(self.options['journal_dir'].iterdir())
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0].read_bytes(), b'')
        self.assertEqual(journal[0].stat().st_mode & 0o777, 0o600)

    async def test_failed_send_is_not_replayed(self):
        adapter = ClaudeSocketTransport(**self.options)
        with patch('event_gateway.claude.asyncio.open_unix_connection', side_effect=OSError('private')):
            result = await adapter.send(self.event)
        self.assertEqual(result['reason'], 'claude_transport_unconfirmed')
        self.assertEqual((await adapter.send(self.event))['reason'], 'claude_attempt_already_reserved')
        self.assertEqual(self.frames, [])

    async def test_concurrent_send_reserves_once(self):
        one, two = ClaudeSocketTransport(**self.options), ClaudeSocketTransport(**self.options)
        results = await asyncio.gather(one.send(self.event), two.send(self.event))
        await asyncio.wait_for(self.received.wait(), 1)
        self.assertEqual(sorted(r['reason'] for r in results),
                         ['claude_attempt_already_reserved', 'claude_write_unacknowledged'])
        self.assertEqual(len(self.frames), 2)

    async def test_rotation_and_permissions_refuse_before_write(self):
        adapter = ClaudeSocketTransport(**self.options)
        adapter.socket_identity = (0, 0)
        with self.assertRaisesRegex(ClaudeError, 'claude_socket_changed'):
            await adapter.send(self.event)
        self.path.chmod(0o666)
        with self.assertRaisesRegex(ClaudeError, 'unsafe_claude_socket'):
            ClaudeSocketTransport(**self.options)
        self.assertEqual(self.frames, [])

    async def test_rotation_after_connect_cannot_write(self):
        adapter = ClaudeSocketTransport(**self.options)
        original = adapter._check_socket
        count = 0

        def check():
            nonlocal count
            count += 1
            if count == 2:
                raise ClaudeError('claude_socket_changed')
            original()

        with patch.object(adapter, '_check_socket', side_effect=check):
            result = await adapter.send(self.event)
        self.assertEqual(result['reason'], 'claude_transport_unconfirmed')
        self.assertEqual(self.frames, [])
        self.assertEqual((await adapter.send(self.event))['reason'], 'claude_attempt_already_reserved')

    async def test_validation(self):
        for override in ({'version': '2.1.303'}, {'session_id': 'wrong'}, {'token': chr(10)},
                         {'socket_identity': (True, 1)}, {'peer_pid': True}, {'peer_pid': 0}):
            with self.subTest(override=override), self.assertRaises(ClaudeError):
                ClaudeSocketTransport(**(self.options | override))
        for metadata in (self.event | {'content': 'run this'}, self.event | {'source': 4},
                         self.event | {'eventId': 'wrong'}, {}):
            with self.subTest(metadata=metadata), self.assertRaises(ClaudeError):
                event_frame(self.options['session_id'], metadata)

    async def test_cli_refuses_public_config_without_secrets(self):
        config = Path(self.temp.name) / 'config.json'
        config.write_text('{"token":"do-not-print-this"}')
        config.chmod(0o644)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(['--config', str(config), '--event', str(config)])
        self.assertEqual(result, 1)
        self.assertNotIn('do-not-print', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['status'], 'refused')

    async def test_cli_send_reports_unknown_and_does_not_leak(self):
        config = Path(self.temp.name) / 'binding.json'
        config.write_text(json.dumps({
            'version': 1, 'clientVersion': '2.1.302', 'socketPath': str(self.path),
            'socketDevice': self.options['socket_identity'][0],
            'socketInode': self.options['socket_identity'][1],
            'peerPid': self.options['peer_pid'],
            'sessionId': self.options['session_id'], 'token': self.options['token'],
            'journalDirectory': str(self.options['journal_dir']),
        }))
        config.chmod(0o600)
        event = Path(self.temp.name) / 'event.json'
        event.write_text(json.dumps(self.event))
        event.chmod(0o600)
        process = await asyncio.create_subprocess_exec(
            sys.executable, '-m', 'event_gateway.claude', '--config', str(config),
            '--event', str(event), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 5)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(stderr, b'')
        self.assertEqual(json.loads(stdout)['reason'], 'claude_write_unacknowledged')
        self.assertNotIn(self.options['token'].encode(), stdout)
        await asyncio.wait_for(self.received.wait(), 1)

    async def test_durability_failure_prevents_send(self):
        adapter = ClaudeSocketTransport(**self.options)
        with patch('event_gateway.claude.os.fsync', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(ClaudeError, 'claude_journal_unavailable'):
                await adapter.send(self.event)
        self.assertEqual(self.frames, [])
        self.assertEqual((await adapter.send(self.event))['reason'], 'claude_attempt_already_reserved')

    async def test_real_contract_subjects_and_required_readback_reference(self):
        for envelope in self.envelopes:
            metadata = {key: envelope[key] for key in METADATA_FIELDS}
            frame = event_frame(self.options['session_id'], metadata)
            body = json.loads(frame['message']['content'].split('\n', 1)[1])
            self.assertEqual(body['canonicalSubject'], envelope['canonicalSubject'])
            self.assertEqual(body['eventReference'], envelope['eventReference'])
        adapter = ClaudeSocketTransport(**self.options)
        malformed = [
            {key: value for key, value in self.event.items() if key != 'eventReference'},
            self.event | {'eventReference': 'https://not-an-authorized-reference'},
            self.event | {'canonicalSubject': self.event['canonicalSubject'] | {'prompt': 'run this'}},
            self.event | {'canonicalSubject': {'kind': 'manual', 'subjectId': 'wrong-source'}},
            self.event | {'source': 'unrecognized'},
            self.event | {'sourceStateVersion': ''},
        ]
        for metadata in malformed:
            with self.subTest(metadata=metadata), self.assertRaises(ClaudeError):
                await adapter.send(metadata)
        self.assertEqual(list(self.options['journal_dir'].iterdir()), [])
        self.assertEqual(self.frames, [])

    async def test_close_flushes_pending_bytes_without_aborting(self):
        adapter = ClaudeSocketTransport(**self.options)
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        with patch('event_gateway.claude.asyncio.open_unix_connection',
                   new=AsyncMock(return_value=(None, writer))), \
                patch('event_gateway.claude._peer_identity', return_value=(os.getpid(), os.getuid())):
            result = await adapter.send(self.event)
        self.assertEqual(result['reason'], 'claude_write_unacknowledged')
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()
        writer.transport.abort.assert_not_called()

    async def test_close_timeout_aborts_and_keeps_no_replay(self):
        adapter = ClaudeSocketTransport(**self.options)
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock(side_effect=TimeoutError)
        with patch('event_gateway.claude.asyncio.open_unix_connection',
                   new=AsyncMock(return_value=(None, writer))), \
                patch('event_gateway.claude._peer_identity', return_value=(os.getpid(), os.getuid())):
            result = await adapter.send(self.event)
        self.assertEqual(result['reason'], 'claude_transport_unconfirmed')
        writer.transport.abort.assert_called_once()
        self.assertEqual((await adapter.send(self.event))['reason'], 'claude_attempt_already_reserved')

    async def test_connected_wrong_peer_receives_no_bytes_even_with_restored_path(self):
        # The connection points elsewhere while both pathname checks still see the pinned inode.
        adapter = ClaudeSocketTransport(**self.options)
        writer = Mock()
        with patch('event_gateway.claude.asyncio.open_unix_connection',
                   new=AsyncMock(return_value=(None, writer))), \
                patch('event_gateway.claude._peer_identity', return_value=(os.getpid() + 1, os.getuid())):
            result = await adapter.send(self.event)
        self.assertEqual(result['reason'], 'claude_transport_unconfirmed')
        writer.write.assert_not_called()
        writer.transport.abort.assert_called_once()

    async def test_actual_path_swap_restore_cannot_release_auth_to_other_process(self):
        adapter = ClaudeSocketTransport(**self.options)
        saved = self.path.with_name('original.sock')
        original_connect = asyncio.open_unix_connection
        process = None

        async def swapped_connect(path):
            nonlocal process
            self.path.rename(saved)
            program = (
                'import socket,sys,os\n'
                'listener=socket.socket(socket.AF_UNIX)\n'
                'listener.bind(sys.argv[1]);os.chmod(sys.argv[1],0o600)\n'
                'listener.listen(1);print("ready",flush=True)\n'
                'connection,_=listener.accept()\n'
                'data=connection.recv(65536);print(len(data),flush=True)\n'
                'connection.close();listener.close()\n'
            )
            process = await asyncio.create_subprocess_exec(
                sys.executable, '-I', '-c', program, str(self.path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            self.assertEqual(await asyncio.wait_for(process.stdout.readline(), 2), b'ready\n')
            connection = await original_connect(path)
            self.path.unlink()
            saved.rename(self.path)
            return connection

        try:
            with patch('event_gateway.claude.asyncio.open_unix_connection', side_effect=swapped_connect):
                result = await adapter.send(self.event)
            self.assertEqual(result['reason'], 'claude_transport_unconfirmed')
            stdout, stderr = await asyncio.wait_for(process.communicate(), 2)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(stdout, b'0\n')
            self.assertEqual(stderr, b'')
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            if saved.exists():
                self.path.unlink(missing_ok=True)
                saved.rename(self.path)
