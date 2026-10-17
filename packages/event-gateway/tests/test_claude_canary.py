"""Canary verification tests never launch Claude or contact a provider."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch
from types import SimpleNamespace
from uuid import uuid4

SCRIPT = Path(__file__).parents[1] / 'scripts/qualify_claude_socket.py'
SPEC = importlib.util.spec_from_file_location('claude_canary', SCRIPT)
CANARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANARY)


def stream(*events):
    reader = asyncio.StreamReader()
    reader.feed_data(b''.join((json.dumps(event) + '\n').encode() for event in events))
    reader.feed_eof()
    return reader


class CanaryTests(unittest.IsolatedAsyncioTestCase):
    def test_closed_launch_has_no_inherited_provider_or_tools(self):
        root = Path('/private/tmp/disposable')
        key = secrets.token_urlsafe(32)
        environment = CANARY.child_environment(root, key)
        self.assertEqual(set(environment), {'PATH', 'HOME', 'CLAUDE_CONFIG_DIR', 'TMPDIR',
                                           'TERM', 'LANG', 'ANTHROPIC_API_KEY'})
        command = CANARY.child_command('/binary', root, 'session', 'model', 'marker')
        self.assertNotIn(key, command)
        self.assertIn('--bare', command)
        self.assertEqual(command[command.index('--tools') + 1], '')
        self.assertNotIn('--dangerously-skip-permissions', command)
        self.assertIn('--max-budget-usd', command)

    async def test_requires_assistant_and_result_in_exact_session(self):
        init = {'type': 'system', 'subtype': 'init', 'session_id': 's', 'tools': []}
        assistant = {'type': 'assistant', 'session_id': 's',
                     'message': {'content': [{'type': 'text', 'text': 'READY_nonce'}]}}
        result = {'type': 'result', 'session_id': 's', 'subtype': 'success',
                  'is_error': False, 'result': 'READY_nonce'}
        state = {'bytes': 0, 'initialized': False}
        await CANARY.completed_turn(stream(init, assistant, result), 's', 'READY_nonce', state)
        for events in ((init, result), (init, assistant | {'session_id': 'other'}, result),
                       (init, assistant, result | {'is_error': True}),
                       (init | {'tools': ['Bash']}, assistant, result),
                       (init, assistant | {'type': 'user'}, result)):
            with self.subTest(events=events), self.assertRaises(CANARY.CanaryError):
                await CANARY.completed_turn(stream(*events), 's', 'READY_nonce',
                                            {'bytes': 0, 'initialized': False})

    async def test_missing_or_malformed_output_never_becomes_proof(self):
        with self.assertRaises(CANARY.CanaryError):
            await CANARY.completed_turn(stream(), 's', 'WAKE', {'bytes': 0, 'initialized': False})
        reader = asyncio.StreamReader()
        reader.feed_data(b'private-error-text\n')
        with self.assertRaisesRegex(CANARY.CanaryError, '^invalid_client_output$'):
            await CANARY.completed_turn(reader, 's', 'WAKE', {'bytes': 0, 'initialized': False})

    async def test_start_failure_cleans_only_disposable_root_without_proof(self):
        parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'  # nosec B108
        root = Path(tempfile.mkdtemp(dir=parent)).resolve()
        with patch.object(CANARY.asyncio, 'create_subprocess_exec', new=AsyncMock(side_effect=OSError)):
            with self.assertRaises(OSError):
                await CANARY.canary('/binary', root, secrets.token_urlsafe(32), 'model')
        self.assertFalse(root.exists())

    def test_proof_publication_is_private_and_never_overwrites(self):
        parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'  # nosec B108
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            output = Path(temporary) / 'proof.json'
            CANARY.publish_proof(output, {'productionQualified': False})
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                CANARY.publish_proof(output, {'unexpected': True})
            self.assertEqual(json.loads(output.read_text()), {'productionQualified': False})
            self.assertEqual(os.listdir(temporary), ['proof.json'])

    async def test_shutdown_terminates_then_waits_and_kills_on_timeout(self):
        child = Mock(returncode=None)
        child.wait = AsyncMock(return_value=0)
        await CANARY.stop_child(child)
        child.terminate.assert_called_once()
        child.wait.assert_awaited_once()
        child.kill.assert_not_called()
        child = Mock(returncode=None)
        child.wait = AsyncMock(side_effect=[TimeoutError, 0])
        await CANARY.stop_child(child)
        child.kill.assert_called_once()
        self.assertEqual(child.wait.await_count, 2)

    async def test_late_wake_nonce_and_unconfirmed_shutdown_retains_root(self):
        parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'  # nosec B108
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            root = Path(temporary).resolve() / 'canary'
            root.mkdir(mode=0o700)
            child = Mock(returncode=None, pid=123)
            child.stdin.drain = AsyncMock()
            transport = Mock()
            transport.send = AsyncMock(return_value={'reason': 'claude_write_unacknowledged'})
            identifiers = [uuid4() for _ in range(5)]
            phases = []

            async def completed(_reader, _session, expected, _state):
                phases.append(expected)
                if len(phases) == 1:
                    self.assertEqual(generate.call_count, 2)
                else:
                    raise CANARY.CanaryError('no_native_proof_in_unit_test')

            async def idle(_seconds):
                self.assertEqual(generate.call_count, 2)

            with patch.object(CANARY, 'uuid4', side_effect=identifiers) as generate, \
                    patch.object(CANARY.asyncio, 'create_subprocess_exec', new=AsyncMock(return_value=child)) as create, \
                    patch.object(CANARY, 'completed_turn', side_effect=completed), \
                    patch.object(CANARY.asyncio, 'sleep', side_effect=idle), \
                    patch.object(CANARY.Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=1, st_ino=2)), \
                    patch.object(CANARY, 'child_peer_token', return_value=secrets.token_urlsafe(32)), \
                    patch.object(CANARY, 'ClaudeSocketTransport', return_value=transport), \
                    patch.object(CANARY, 'stop_child', new=AsyncMock(side_effect=TimeoutError)):
                with self.assertRaises(TimeoutError):
                    await CANARY.canary('/binary', root, secrets.token_urlsafe(32), 'model')
            wake = 'WAKE_' + identifiers[2].hex
            self.assertNotIn(wake, ' '.join(create.call_args.args))
            self.assertEqual(transport.send.call_args.args[0]['canonicalSubject']['subjectId'], wake)
            self.assertEqual(phases[1], wake)
            self.assertTrue(root.is_dir())
