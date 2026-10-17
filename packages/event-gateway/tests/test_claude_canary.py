"""Canary verification tests never launch Claude or contact a provider."""
import ast
import asyncio
from functools import partial
import importlib.util
import io
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
    def test_system_diagnostic_allowlist_exactly_matches_pinned_manifest(self):
        manifest = json.loads((SCRIPT.parent.parent / 'docs/claude-system-subtypes-2.1.302.json').read_text())
        expected = (set(manifest['schemaSubtypeOffsets']) - {'init', 'session_state_changed'}
                    | set(manifest['retainedConstructorSubtypeOffsets']))
        observer = next(node for node in ast.parse(SCRIPT.read_text()).body
                        if isinstance(node, ast.AsyncFunctionDef) and node.name == 'observe_busy_stdout')
        candidates = [node.test.comparators[0] for node in ast.walk(observer)
                      if isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                      and isinstance(node.test.left, ast.Name) and node.test.left.id == 'subtype'
                      and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.In)]
        self.assertEqual(len(candidates), 1)
        labels = ast.literal_eval(candidates[0])
        self.assertEqual(len(labels), len(set(labels)))
        self.assertEqual(set(labels), expected)

    def test_closed_launch_has_no_inherited_provider_or_tools(self):
        root = Path('/private/tmp/disposable')
        key = secrets.token_urlsafe(32)
        environment = CANARY.child_environment(root, key)
        self.assertEqual(set(environment), {'PATH', 'HOME', 'CLAUDE_CONFIG_DIR', 'TMPDIR',
                                           'TERM', 'LANG', 'ANTHROPIC_API_KEY', 'CLAUDE_CODE_TMPDIR'})
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
                with self.assertRaisesRegex(CANARY.CanaryError, '^no_native_proof_in_unit_test$') as raised:
                    await CANARY.canary('/binary', root, secrets.token_urlsafe(32), 'model')
            self.assertIn('child_cleanup_failed', raised.exception.__notes__)
            wake = 'WAKE_' + identifiers[2].hex
            self.assertNotIn(wake, ' '.join(create.call_args.args))
            self.assertEqual(transport.send.call_args.args[0]['canonicalSubject']['subjectId'], wake)
            self.assertEqual(phases[1], wake)
            self.assertTrue(root.is_dir())


class LocalProviderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.key = 'local-fixture-' + secrets.token_hex(24)
        self.provider = CANARY.LocalProvider(self.key, 'claude-local-fixture')
        self.ready = 'READY_' + uuid4().hex
        self.wake = 'WAKE_' + uuid4().hex
        self.request = {'model': 'claude-local-fixture', 'stream': True, 'tools': [],
                        'system': [{'type': 'text', 'text': self.ready}],
                        'messages': [{'role': 'user', 'content': 'Begin synthetic test.'}]}

    def test_real_request_required_for_late_wake_and_only_two_turns(self):
        first = self.provider.respond(self.request)
        self.assertIn(self.ready.encode(), first)
        self.assertNotIn(self.wake.encode(), first)
        with self.assertRaisesRegex(CANARY.CanaryError, 'wake_missing'):
            self.provider.respond(self.request)
        second = self.request | {'messages': [{'role': 'user', 'content': self.wake}]}
        self.assertIn(self.wake.encode(), self.provider.respond(second))
        with self.assertRaisesRegex(CANARY.CanaryError, 'turn_limit'):
            self.provider.respond(second)

    def test_rejects_tools_wrong_model_nonstream_and_early_wake(self):
        for change in ({'tools': [{'name': 'Bash'}]}, {'model': 'other'}, {'stream': False},
                       {'messages': [{'role': 'user', 'content': self.wake}]}):
            with self.subTest(change=change), self.assertRaises(CANARY.CanaryError):
                self.provider.respond(self.request | change)
        self.assertEqual(self.provider.turns, 0)

    def test_sse_order_and_text_are_anthropic_protocol(self):
        data = CANARY.synthetic_stream(self.ready, 'claude-local-fixture').decode()
        events = [json.loads(line[6:]) for line in data.splitlines() if line.startswith('data: ')]
        self.assertEqual([event['type'] for event in events], ['message_start', 'content_block_start',
            'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop'])
        self.assertEqual(events[2]['delta'], {'type': 'text_delta', 'text': self.ready})
        self.assertEqual(events[4]['delta']['stop_reason'], 'end_turn')

    def test_closed_local_environment_and_default_deny_profile(self):
        root = Path('/private/tmp/disposable')
        inherited_token = secrets.token_urlsafe(32)
        with patch.dict(os.environ, {'ANTHROPIC_AUTH_TOKEN': inherited_token, 'HTTPS_PROXY': 'http://owner'}):
            environment = CANARY.child_environment(root, self.key, 43231)
        self.assertEqual(environment['ANTHROPIC_BASE_URL'], 'http://127.0.0.1:43231')
        self.assertNotIn('ANTHROPIC_AUTH_TOKEN', environment)
        self.assertNotIn(inherited_token, environment.values())
        self.assertNotIn('HTTPS_PROXY', environment)
        self.assertEqual(environment['CLAUDE_CODE_TMPDIR'], str(root / 'tmp'))
        self.assertEqual(environment['TMPDIR'], environment['CLAUDE_CODE_TMPDIR'])
        with patch.object(CANARY.sys, 'platform', 'darwin'), patch.object(CANARY.Path, 'is_file', return_value=True):
            profile = CANARY.sandbox_profile('/pinned/binary', root, 43231)
            for port in (0, True, 49152, 65536):
                with self.assertRaises(CANARY.CanaryError):
                    CANARY.sandbox_profile('/pinned/binary', root, port)
        self.assertIn('(deny default)', profile)
        self.assertIn('(allow file-read* (literal "/"))', profile)
        self.assertNotIn('(subpath "/")', profile)
        self.assertNotIn('(allow default)', profile)
        self.assertIn('(allow system-socket (socket-domain AF_UNIX))', profile)
        self.assertNotIn('(allow system-socket)', profile)
        self.assertEqual(profile.count('remote tcp'), 1)
        self.assertNotIn('remote ip', profile)
        self.assertIn('localhost:43231', profile)
        self.assertNotIn('/Users/', profile)
        self.assertNotIn('(allow process-exec)', profile)
        self.assertIn('(allow mach-lookup (global-name "com.apple.system.logger"))', profile)
        self.assertNotIn('(allow mach-lookup)', profile)

    async def wire(self, headers=None, body=None, request_line='POST /v1/messages HTTP/1.1'):
        body = json.dumps(self.request).encode() if body is None else body
        supplied = {'Host': '127.0.0.1:43231', 'Content-Type': 'application/json',
                    'Content-Length': str(len(body)), 'X-Api-Key': self.key}
        supplied.update(headers or {})
        reader = asyncio.StreamReader()
        reader.feed_data((request_line + '\r\n' + ''.join(f'{key}: {value}\r\n' for key, value in supplied.items())
                          + '\r\n').encode() + body)
        reader.feed_eof()
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        await self.provider.handle(reader, writer)
        return writer

    async def test_bounded_http_emits_only_local_sse_and_closes(self):
        writer = await self.wire()
        self.assertFalse(self.provider.failure)
        self.assertIn(b'Content-Type: text/event-stream', writer.write.call_args.args[0])
        self.assertNotIn(self.key.encode(), writer.write.call_args.args[0])
        writer.close.assert_called_once()
        self.assertFalse(self.provider.tasks)

    async def test_http_rejects_auth_paths_encoding_limits_and_duplicate_headers(self):
        cases = [({'X-Api-Key': 'different'}, None, 'POST /v1/messages HTTP/1.1'),
                 ({'Authorization': 'Bearer owner'}, None, 'POST /v1/messages HTTP/1.1'),
                 ({'Content-Encoding': 'gzip'}, None, 'POST /v1/messages HTTP/1.1'),
                 ({'Transfer-Encoding': 'chunked'}, None, 'POST /v1/messages HTTP/1.1'),
                 ({'Content-Length': str(1024 * 1024 + 1)}, None, 'POST /v1/messages HTTP/1.1'),
                 ({'x-api-key': self.key}, None, 'POST /v1/messages HTTP/1.1'),
                 ({}, None, 'POST https://api.anthropic.com/v1/messages HTTP/1.1'),
                 ({}, b'bad-json', 'POST /v1/messages HTTP/1.1')]
        for headers, body, line in cases:
            self.provider = CANARY.LocalProvider(self.key, 'claude-local-fixture')
            with self.subTest(headers=headers, line=line):
                writer = await self.wire(headers, body, line)
                self.assertTrue(self.provider.failure)
                self.assertEqual(self.provider.turns, 0)
                writer.write.assert_not_called()

    async def test_hosted_guard_rejects_before_any_setup_or_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'unused'
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(CANARY.asyncio, 'create_subprocess_exec', new=AsyncMock()) as create:
                with self.assertRaises(CANARY.CanaryError):
                    await CANARY.canary('/binary', root, self.key, 'fixture', 43231, '123')
            create.assert_not_called()
            self.assertFalse(root.exists())

    async def test_hosted_failure_retains_scratch_for_vm_disposal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'canary'
            root.mkdir(mode=0o700)
            with patch.object(CANARY, 'admit_hosted_vm'), \
                    patch.object(CANARY, 'hosted_network_profile', return_value='(deny network*)'), \
                    patch.object(CANARY.asyncio, 'start_server', new=AsyncMock(side_effect=OSError)), \
                    patch.object(CANARY.asyncio, 'create_subprocess_exec', new=AsyncMock()) as create:
                with self.assertRaises(OSError):
                    await CANARY.canary('/binary', root, self.key, 'fixture', 43231, '123')
            create.assert_not_called()
            self.assertTrue((root / 'home').is_dir())

    async def test_late_provider_failure_during_close_refuses_proof_and_retains_hosted_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'canary'
            root.mkdir(mode=0o700)
            child = Mock(returncode=None, pid=123)
            child.stdin.drain = AsyncMock()
            transport = Mock()
            transport.send = AsyncMock(return_value={'reason': 'claude_write_unacknowledged'})
            provider = Mock(turns=2, failure=False)
            server = Mock()
            server.wait_closed = AsyncMock()

            async def finish_pending_request():
                provider.failure = True

            provider.close = AsyncMock(side_effect=finish_pending_request)
            with patch.object(CANARY, 'admit_hosted_vm'), \
                    patch.object(CANARY, 'hosted_network_profile', return_value='(deny network*)'), \
                    patch.object(CANARY, 'LocalProvider', return_value=provider), \
                    patch.object(CANARY.asyncio, 'start_server', new=AsyncMock(return_value=server)), \
                    patch.object(CANARY.asyncio, 'create_subprocess_exec', new=AsyncMock(return_value=child)), \
                    patch.object(CANARY, 'completed_turn', new=AsyncMock()), \
                    patch.object(CANARY.asyncio, 'sleep', new=AsyncMock()), \
                    patch.object(CANARY.Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=1, st_ino=2)), \
                    patch.object(CANARY, 'child_peer_token', return_value=secrets.token_urlsafe(32)), \
                    patch.object(CANARY, 'ClaudeSocketTransport', return_value=transport), \
                    patch.object(CANARY, 'stop_child', new=AsyncMock()) as stop:
                with self.assertRaisesRegex(CANARY.CanaryError, '^local_provider_incomplete$'):
                    await CANARY.canary('/never-executed', root, self.key, 'fixture', 43231, '123')
            stop.assert_awaited_once_with(child)
            server.close.assert_called_once()
            server.wait_closed.assert_awaited_once()
            provider.close.assert_awaited_once()
            self.assertTrue(root.is_dir())

    async def test_occupied_port_aborts_before_native_child_without_fallback(self):
        parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'  # nosec B108
        root = Path(tempfile.mkdtemp(dir=parent)).resolve()
        with patch.object(CANARY, 'sandbox_profile', return_value='(deny default)'), \
                patch.object(CANARY.asyncio, 'start_server', new=AsyncMock(side_effect=OSError)) as server, \
                patch.object(CANARY.asyncio, 'create_subprocess_exec', new=AsyncMock()) as create:
            with self.assertRaises(OSError):
                await CANARY.canary('/binary', root, self.key, 'claude-local-fixture', 43231)
        self.assertEqual(server.await_count, 1)
        self.assertEqual(server.call_args.args[1:], ('127.0.0.1', 43231))
        create.assert_not_called()
        self.assertFalse(root.exists())


class HostedVmTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.event = Path(self.temporary.name) / 'event.json'
        self.repository = {'id': 123, 'full_name': 'owner/private-fixture', 'private': True}
        self.event.write_text(json.dumps({'repository': self.repository}))
        self.environment = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_REF_PROTECTED': 'true', 'GITHUB_RUN_ATTEMPT': '1',
            'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64',
            'GITHUB_REPOSITORY_ID': '123', 'GITHUB_REPOSITORY': 'owner/private-fixture',
            'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '456', 'ImageOS': 'macos15', 'ImageVersion': '1',
            'GITHUB_EVENT_PATH': str(self.event)}
        for target, value in (('system', 'Darwin'), ('machine', 'arm64')):
            patcher = patch.object(CANARY.platform, target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_guard_rejects_missing_or_wrong_context_before_launch(self):
        CANARY.admit_hosted_vm(self.environment, '123')
        for key in self.environment:
            with self.subTest(missing=key), self.assertRaises(CANARY.CanaryError):
                CANARY.admit_hosted_vm({k: v for k, v in self.environment.items() if k != key}, '123')
        for change in ({'GITHUB_RUN_ATTEMPT': '2'}, {'GITHUB_EVENT_NAME': 'pull_request'},
                       {'RUNNER_ENVIRONMENT': 'self-hosted'}, {'GITHUB_REF_PROTECTED': 'false'},
                       {'GITHUB_REF': 'refs/heads/unreviewed'}, {'GITHUB_REPOSITORY_ID': '321'}):
            with self.subTest(change=change), self.assertRaises(CANARY.CanaryError):
                CANARY.admit_hosted_vm(self.environment | change, '123')

    def test_guard_rejects_public_mismatched_or_malformed_event(self):
        for change in ({'private': False}, {'private': 'true'}, {'id': 321}, {'full_name': 'other/repo'}):
            self.event.write_text(json.dumps({'repository': self.repository | change}))
            with self.subTest(change=change), self.assertRaises(CANARY.CanaryError):
                CANARY.admit_hosted_vm(self.environment, '123')
        self.event.write_text('not-json')
        with self.assertRaises(CANARY.CanaryError):
            CANARY.admit_hosted_vm(self.environment, '123')

    def test_hosted_profile_is_guarded_and_limited_to_fixture_network(self):
        with patch.dict(os.environ, self.environment, clear=True), \
                patch.object(CANARY.Path, 'is_file', return_value=True):
            profile = CANARY.hosted_network_profile(Path('/private/tmp/fixture'), 43231, '123')
        self.assertIn('(allow default)', profile)
        self.assertIn('(deny network*)', profile)
        self.assertEqual(profile.count('remote tcp'), 1)
        self.assertIn('localhost:43231', profile)
        self.assertIn('(literal "/private/tmp/fixture/inbox.sock")', profile)
        self.assertNotIn('(allow network*)', profile)
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(CANARY.CanaryError):
            CANARY.hosted_network_profile(Path('/private/tmp/fixture'), 43231, '123')

    def test_hosted_cli_requires_local_provider_and_explicit_repository(self):
        base = ['--binary', '/missing', '--model', 'fixture', '--private-output', '/missing/proof.json']
        for flags in (['--trusted-hosted-vm'], ['--hosted-repository-id', '123'],
                      ['--trusted-hosted-vm', '--hosted-repository-id', '123']):
            with self.subTest(flags=flags), patch.object(CANARY.asyncio, 'run') as run, \
                    patch.object(CANARY.sys, 'stderr'):
                self.assertEqual(CANARY.main(base + flags), 2)
                run.assert_not_called()


class BusyProbeTests(unittest.IsolatedAsyncioTestCase):
    """Synthetic protocol checks are not evidence of native client qualification."""

    def setUp(self):
        self.session = str(uuid4())
        self.key = 'local-fixture-' + secrets.token_hex(24)
        self.ready = 'READY_' + uuid4().hex
        self.busy = 'BUSY_' + uuid4().hex
        self.initial = {'type': 'user', 'session_id': self.session, 'uuid': str(uuid4()),
                        'message': {'role': 'user', 'content': 'Begin synthetic test.'}}
        from event_gateway.claude import event_frame
        self.frame = event_frame(self.session, {
            'eventId': str(uuid4()), 'deliveryId': 'dly_' + secrets.token_hex(32),
            'source': 'manual', 'sourceStateVersion': 'canary-1',
            'canonicalSubject': {'kind': 'manual', 'subjectId': self.busy},
            'eventReference': 'ref_' + str(uuid4())})

    def new_probe(self):
        return CANARY.BusyProbe(self.session, self.initial, self.ready)

    def state(self, state):
        return {'type': 'system', 'subtype': 'session_state_changed',
                'session_id': self.session, 'uuid': str(uuid4()), 'state': state}

    def assistant(self, marker):
        return {'type': 'assistant', 'session_id': self.session, 'uuid': str(uuid4()),
                'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': marker}]}}

    def result(self, marker):
        return {'type': 'result', 'session_id': self.session, 'uuid': str(uuid4()),
                'subtype': 'success', 'is_error': False, 'result': marker}

    def started(self, *, probe=None):
        probe = self.new_probe() if probe is None else probe
        probe.observe({'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []})
        probe.observe(self.state('running'))
        probe.provider_request(self.ready)
        probe.hold_response()
        return probe

    def released(self, replay=True, *, probe=None):
        probe = self.started(probe=probe)
        probe.prepare(self.frame)
        if replay:
            probe.observe(self.frame | {'isReplay': True})
        probe.sent()
        probe.release_response()
        return probe

    def complete_turns(self, probe):
        probe.observe(self.assistant(self.ready))
        probe.observe(self.result(self.ready))
        probe.provider_request(self.busy)
        probe.observe(self.assistant(self.busy))
        probe.observe(self.result(self.busy))

    def finish(self, probe):
        self.complete_turns(probe)
        probe.observe(self.state('idle'))

    def test_complete_synthetic_sequence_requires_final_idle(self):
        probe = self.released()
        self.complete_turns(probe)
        self.assertFalse(probe.complete.is_set())
        with self.assertRaises(CANARY.CanaryError):
            probe.proof()
        probe.observe(self.state('idle'))
        self.assertTrue(probe.complete.is_set())
        self.assertIsInstance(probe.proof(), dict)

    def ui_hint(self):
        return {'type': 'system', 'subtype': 'ui_invalidate', 'event': 'ui.render',
                'uuid': 'opaque-string', 'session_id': self.session}

    def test_passive_ui_hints_preserve_full_busy_progression(self):
        for optional in ({}, {'prompts_screened': True}, {'instances': []},
                         {'prompts_screened': True, 'instances': [
                             {'surface': 'chat', 'component': 'prompt', 'instance_id': 'one'}]}):
            with self.subTest(optional=optional):
                probe = self.new_probe()
                before = dict(probe.__dict__)
                probe.observe(self.ui_hint() | optional)
                self.assertEqual(probe.__dict__, before)
                self.assertEqual(probe.observations, [])
                self.assertFalse(probe.ready_to_send.is_set())
                self.assertFalse(probe.complete.is_set())
                probe = self.released(probe=probe)
                probe.observe(self.ui_hint() | optional)
                self.finish(probe)
                self.assertIsInstance(probe.proof(), dict)

    def test_passive_ui_hint_rejects_malformed_and_forged_fields(self):
        hint = self.ui_hint()
        malformed = [hint | change for change in (
            {'event': 'ui.other'}, {'event': None}, {'uuid': 17},
            {'prompts_screened': False}, {'prompts_screened': 1},
            {'instances': None}, {'instances': {}}, {'instances': [None]},
            {'instances': [{'surface': 'chat', 'component': 'prompt'}]},
            {'instances': [{'surface': 'chat', 'component': 'prompt', 'instance_id': 1}]},
            {'instances': [{'surface': 'chat', 'component': 'prompt', 'instance_id': 'one', 'state': 'running'}]},
            {'state': 'running'}, {'tools': []}, {'is_error': True},
            {'error': 'failure'}, {'unexpected': 'value'})]
        malformed += [{key: value for key, value in hint.items() if key != missing}
                      for missing in ('event', 'uuid')]
        for event in malformed:
            for initialized in (False, True):
                with self.subTest(event=event, initialized=initialized):
                    probe = self.new_probe()
                    probe.initialized = initialized
                    with self.assertRaisesRegex(CANARY.CanaryError, '^busy_native_ui_hint$'):
                        probe.observe(event)
                    self.assertFalse(probe.ready_to_send.is_set())
                    self.assertFalse(probe.complete.is_set())
        for change in ({'session_id': 'other'}, {'subtype': 'unknown'}, {'type': 'error'}):
            with self.subTest(change=change), self.assertRaises(CANARY.CanaryError):
                self.new_probe().observe(hint | change)

    def test_passive_ui_hint_does_not_replace_real_init_or_tools_validation(self):
        for event in (self.assistant(self.ready), self.result(self.ready)):
            probe = self.new_probe()
            probe.observe(self.ui_hint())
            with self.assertRaisesRegex(CANARY.CanaryError, '^busy_native_missing_init$'):
                probe.observe(event)
        for tools in (None, ['Bash'], {}):
            probe = self.new_probe()
            probe.observe(self.ui_hint())
            with self.assertRaisesRegex(CANARY.CanaryError, '^busy_native_init$'):
                probe.observe({'type': 'system', 'subtype': 'init',
                               'session_id': self.session, 'tools': tools})

    def test_preinit_running_preserves_observation_and_requires_init_and_hold(self):
        for hold_first in (False, True):
            with self.subTest(hold_first=hold_first):
                probe = self.new_probe()
                probe.observe(self.ui_hint())
                if hold_first:
                    probe.provider_request(self.ready)
                    probe.hold_response()
                event = self.state('running')
                with patch.object(CANARY.time, 'monotonic_ns', return_value=probe.started_ns + 17):
                    probe.observe(event)
                self.assertFalse(probe.initialized)
                self.assertFalse(probe.running)
                self.assertEqual(probe.running_turn, 0)
                self.assertFalse(probe.ready_to_send.is_set())
                self.assertIn(event['uuid'], probe.native_ids)
                observed = dict(probe.observations[-1])
                self.assertEqual(observed, {'kind': 'native_state', 'observedNs': 17,
                    'state': 'running', 'nativeUuid': event['uuid'], 'awaitingInit': True})
                with self.assertRaises(CANARY.CanaryError):
                    probe.prepare(self.frame)
                probe.observe({'type': 'system', 'subtype': 'init',
                               'session_id': self.session, 'tools': []})
                self.assertTrue(probe.initialized)
                self.assertTrue(probe.running)
                self.assertEqual(probe.running_turn, 1)
                self.assertEqual(probe.ready_to_send.is_set(), hold_first)
                if not hold_first:
                    probe.provider_request(self.ready)
                    probe.hold_response()
                self.assertTrue(probe.ready_to_send.is_set())
                probe.prepare(self.frame)
                probe.observe(self.frame | {'isReplay': True})
                probe.sent()
                probe.release_response()
                self.finish(probe)
                states = [item for item in probe.proof()['observations']
                          if item['kind'] == 'native_state' and item['state'] == 'running']
                self.assertEqual(states, [observed])
                probe.observe({'type': 'system', 'subtype': 'init',
                               'session_id': self.session, 'tools': []})
                self.assertFalse(probe.running)

    async def test_preinit_running_without_init_never_becomes_ready(self):
        probe = self.new_probe()
        probe.provider_request(self.ready)
        probe.hold_response()
        with self.assertRaisesRegex(CANARY.CanaryError, '^busy_native_stream_closed$'):
            await CANARY.observe_busy_stdout(stream(self.ui_hint(), self.state('running')), probe)
        self.assertFalse(probe.initialized)
        self.assertFalse(probe.running)
        self.assertFalse(probe.ready_to_send.is_set())
        self.assertFalse(probe.complete.is_set())
        with self.assertRaises(CANARY.CanaryError):
            probe.proof()

    def test_preinit_running_rejects_second_state_and_duplicate_ids(self):
        for state in ('idle', 'requires_action', 'running'):
            probe = self.new_probe()
            probe.observe(self.state('running'))
            with self.subTest(state=state), self.assertRaisesRegex(
                    CANARY.CanaryError, '^busy_native_preinit_order$'):
                probe.observe(self.state(state))
            self.assertFalse(probe.running)
            self.assertFalse(probe.ready_to_send.is_set())
        for initialized in (False, True):
            probe = self.new_probe()
            event = self.state('running')
            probe.observe(event)
            if initialized:
                probe.observe({'type': 'system', 'subtype': 'init',
                               'session_id': self.session, 'tools': []})
            with self.subTest(initialized=initialized), self.assertRaisesRegex(
                    CANARY.CanaryError, '^busy_native_duplicate$'):
                probe.observe(event)
        probe = self.new_probe()
        event = self.state('running')
        probe.observe(event)
        self.released(probe=probe)
        probe.observe(self.assistant(self.ready))
        with self.assertRaisesRegex(CANARY.CanaryError, '^busy_native_duplicate$'):
            probe.observe(self.result(self.ready) | {'uuid': event['uuid']})

    def test_preinit_running_rejects_malformed_schema_session_and_init(self):
        event = self.state('running')
        malformed = [event | change for change in (
            {'extra': True}, {'tools': []}, {'state': 'idle'}, {'state': None})]
        malformed += [{key: value for key, value in event.items() if key != missing}
                      for missing in ('uuid', 'state')]
        for value in malformed:
            with self.subTest(value=value), self.assertRaises(CANARY.CanaryError):
                self.new_probe().observe(value)
        for identity in (None, 1, 'malformed', event['uuid'].upper(), '{' + event['uuid'] + '}'):
            with self.subTest(identity=identity), self.assertRaises(CANARY.CanaryError):
                self.new_probe().observe(event | {'uuid': identity})
        with self.assertRaisesRegex(CANARY.CanaryError, '^busy_native_session_mismatch$'):
            self.new_probe().observe(event | {'session_id': str(uuid4())})
        for change in ({'tools': ['Bash']}, {'tools': None}, {'session_id': str(uuid4())}):
            probe = self.new_probe()
            probe.observe(event)
            with self.subTest(change=change), self.assertRaises(CANARY.CanaryError):
                probe.observe({'type': 'system', 'subtype': 'init',
                               'session_id': self.session, 'tools': []} | change)
            self.assertFalse(probe.initialized)
            self.assertFalse(probe.running)
            self.assertFalse(probe.ready_to_send.is_set())

    async def test_repeated_passive_ui_hints_remain_bounded_and_never_ready(self):
        hint = self.ui_hint()
        raw = (json.dumps(hint) + '\n').encode()
        for limit, reason in ((len(raw) * 10, 'busy_native_stream_closed'),
                              (len(raw) * 2, 'client_output_limit')):
            probe = self.new_probe()
            with patch.object(CANARY, 'MAX_STREAM_BYTES', limit), \
                    self.assertRaisesRegex(CANARY.CanaryError, '^' + reason + '$'):
                await CANARY.observe_busy_stdout(stream(*([hint] * 10)), probe)
            self.assertFalse(probe.initialized)
            self.assertFalse(probe.ready_to_send.is_set())
            self.assertFalse(probe.complete.is_set())
            self.assertEqual(probe.observations, [])
            with self.assertRaises(CANARY.CanaryError):
                probe.proof()
        reader = asyncio.StreamReader()
        reader.feed_data(raw * 10)
        probe = self.new_probe()
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(0.01):
                await CANARY.observe_busy_stdout(reader, probe)
        self.assertFalse(probe.initialized)
        self.assertFalse(probe.ready_to_send.is_set())
        self.assertFalse(probe.complete.is_set())
        self.assertEqual(probe.observations, [])

    def test_repeated_init_between_turns_preserves_final_idle_requirement(self):
        probe = self.released()
        probe.observe(self.assistant(self.ready))
        probe.observe(self.result(self.ready))
        probe.observe({'type': 'system', 'subtype': 'init',
                       'session_id': self.session, 'tools': []})
        probe.provider_request(self.busy)
        probe.observe(self.assistant(self.busy))
        probe.observe(self.result(self.busy))
        self.assertFalse(probe.complete.is_set())
        with self.assertRaises(CANARY.CanaryError):
            probe.proof()
        probe.observe(self.state('idle'))
        observations = probe.proof()['observations']
        self.assertEqual(sum(item['kind'] == 'native_init' for item in observations), 2)
        self.assertEqual(observations[-1]['state'], 'idle')

    def test_repeated_init_rejects_session_tools_and_excess_evidence(self):
        init = {'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []}
        for change in ({'session_id': str(uuid4())}, {'tools': ['Bash']}, {'tools': None}):
            with self.subTest(change=change):
                probe = self.released()
                probe.observe(self.assistant(self.ready))
                probe.observe(self.result(self.ready))
                count = len(probe.observations)
                with self.assertRaises(CANARY.CanaryError):
                    probe.observe(init | change)
                self.assertEqual(len(probe.observations), count)
                self.assertFalse(probe.complete.is_set())
        probe = self.new_probe()
        for _ in range(64):
            probe.observe(init)
        with self.assertRaisesRegex(CANARY.CanaryError, '^busy_evidence_limit$'):
            probe.observe(init)
        self.assertEqual(len(probe.observations), 64)
        self.assertFalse(probe.complete.is_set())

    def test_provider_hold_alone_cannot_open_native_running_barrier(self):
        probe = self.new_probe()
        probe.observe({'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []})
        probe.provider_request(self.ready)
        probe.hold_response()
        self.assertFalse(probe.ready_to_send.is_set())
        with self.assertRaises(CANARY.CanaryError):
            probe.prepare(self.frame)

    def test_running_alone_cannot_open_provider_hold_barrier(self):
        probe = self.new_probe()
        probe.observe({'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []})
        probe.observe(self.state('running'))
        self.assertFalse(probe.ready_to_send.is_set())
        with self.assertRaises(CANARY.CanaryError):
            probe.prepare(self.frame)

    def test_replay_requires_exact_uuid_content_session_and_boolean(self):
        changes = [{'uuid': str(uuid4())}, {'session_id': str(uuid4())},
                   {'message': {'role': 'user', 'content': self.busy}},
                   {'isReplay': False}, {'isReplay': 'true'}, {'uuid': None}]
        for change in changes:
            with self.subTest(change=change):
                probe = self.started()
                probe.prepare(self.frame)
                with self.assertRaises(CANARY.CanaryError):
                    probe.observe(self.frame | {'isReplay': True} | change)

    def test_replay_before_send_preparation_and_duplicate_replay_rejected(self):
        probe = self.started()
        with self.assertRaises(CANARY.CanaryError):
            probe.observe(self.frame | {'isReplay': True})
        probe = self.released()
        with self.assertRaises(CANARY.CanaryError):
            probe.observe(self.frame | {'isReplay': True})

    def test_missing_replay_cannot_produce_proof(self):
        probe = self.released(replay=False)
        try:
            self.finish(probe)
        except CANARY.CanaryError:
            pass
        with self.assertRaises(CANARY.CanaryError):
            probe.proof()

    def test_premature_output_or_idle_rejected_before_release(self):
        for message in (self.assistant(self.ready), self.result(self.ready), self.state('idle')):
            with self.subTest(message=message):
                probe = self.started()
                probe.prepare(self.frame)
                with self.assertRaises(CANARY.CanaryError):
                    probe.observe(message)

    def test_result_requires_assistant_order_success_and_valid_uuid(self):
        for message in (self.result(self.ready), self.assistant(self.busy), self.state('idle')):
            with self.subTest(message=message):
                probe = self.released()
                with self.assertRaises(CANARY.CanaryError):
                    probe.observe(message)
        for change in ({'uuid': None}, {'uuid': 'invalid'}, {'session_id': str(uuid4())},
                       {'subtype': 'error_during_execution'}, {'is_error': True}, {'result': self.busy}):
            with self.subTest(change=change):
                probe = self.released()
                probe.observe(self.assistant(self.ready))
                with self.assertRaises(CANARY.CanaryError):
                    probe.observe(self.result(self.ready) | change)

    def test_duplicate_result_and_early_second_provider_request_rejected(self):
        probe = self.released()
        probe.observe(self.assistant(self.ready))
        result = self.result(self.ready)
        probe.observe(result)
        with self.assertRaises(CANARY.CanaryError):
            probe.observe(result)
        probe = self.started()
        with self.assertRaises(CANARY.CanaryError):
            probe.provider_request(self.busy)

    def test_malformed_native_messages_never_produce_proof(self):
        for message in (None, [], {}, {'type': 'system', 'subtype': 'init',
                                     'session_id': self.session, 'tools': ['Bash']}):
            with self.subTest(message=message):
                probe = self.new_probe()
                with self.assertRaises(CANARY.CanaryError):
                    probe.observe(message)
                with self.assertRaises(CANARY.CanaryError):
                    probe.proof()

    def test_busy_cli_requires_local_provider_before_setup(self):
        with patch.object(CANARY.asyncio, 'run') as run, patch.object(CANARY.sys, 'stderr'), \
                patch.object(CANARY.Path, 'resolve') as resolve, \
                patch.object(CANARY.getpass, 'getpass') as prompt:
            self.assertEqual(CANARY.main(['--busy-probe', '--binary', '/missing', '--model', 'fixture',
                                         '--private-output', '/missing/proof.json']), 2)
        run.assert_not_called()
        resolve.assert_not_called()
        prompt.assert_not_called()

    def test_busy_instrumentation_is_opt_in_and_local_only(self):
        root = Path('/private/tmp/disposable')
        for enabled in (False, True):
            command = CANARY.child_command('/binary', root, self.session, 'fixture', 'nonce',
                                           busy_probe=enabled)
            environment = CANARY.child_environment(root, self.key, 43231, busy_probe=enabled)
            self.assertEqual('--replay-user-messages' in command, enabled)
            self.assertEqual('CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS' in environment, enabled)
        with self.assertRaises(CANARY.CanaryError):
            CANARY.child_environment(root, 'dummy', busy_probe=True)

    def test_release_requires_confirmed_send_and_native_barrier(self):
        for stage in ('new', 'held', 'prepared'):
            with self.subTest(stage=stage):
                probe = self.new_probe() if stage == 'new' else self.started()
                if stage == 'prepared':
                    probe.prepare(self.frame)
                with self.assertRaises(CANARY.CanaryError):
                    probe.release_response()
                self.assertFalse(probe.release.is_set())
        with self.assertRaises(CANARY.CanaryError):
            self.started().sent()

    def test_state_requires_exact_session_and_canonical_uuid(self):
        for change in ({'uuid': None}, {'uuid': 'malformed'}, {'session_id': str(uuid4())},
                       {'state': 'unexpected'}):
            with self.subTest(change=change):
                probe = self.new_probe()
                probe.observe({'type': 'system', 'subtype': 'init',
                               'session_id': self.session, 'tools': []})
                with self.assertRaises(CANARY.CanaryError):
                    probe.observe(self.state('running') | change)
                self.assertFalse(probe.ready_to_send.is_set())

    async def test_stdout_eof_malformed_and_limit_refuse_completion(self):
        for payload in (b'', b'not-json\n', b'null\n', b'[]\n', b'{}\n'):
            reader = asyncio.StreamReader()
            reader.feed_data(payload)
            reader.feed_eof()
            probe = self.new_probe()
            with self.subTest(payload=payload), self.assertRaises(CANARY.CanaryError):
                await CANARY.observe_busy_stdout(reader, probe)
            self.assertFalse(probe.complete.is_set())
        with patch.object(CANARY, 'MAX_STREAM_BYTES', 2), self.assertRaises(CANARY.CanaryError):
            await CANARY.observe_busy_stdout(stream({'type': 'system'}), self.new_probe())

    async def test_preinit_failure_diagnostic_is_sanitized_before_validation(self):
        secret = 'private-content-' + secrets.token_hex(16)
        events = [self.state('running'), self.initial, self.assistant(secret),
                  self.result(secret), {'type': secret, 'subtype': secret,
                                        'session_id': secret, 'content': secret}]
        for event in events:
            with self.subTest(event_type=event['type']):
                probe = self.new_probe()
                with patch.object(CANARY.time, 'monotonic_ns', return_value=probe.started_ns + 17), \
                        self.assertRaises(CANARY.CanaryError) as raised:
                    await CANARY.observe_busy_stdout(stream(event), probe)
                self.assertFalse(probe.ready_to_send.is_set())
                self.assertFalse(probe.complete.is_set())
                self.assertEqual(raised.exception.diagnostic, [{
                    'order': 1, 'observedNs': 17,
                    'eventType': event['type'] if event['type'] != secret else 'unknown',
                    'eventSubtype': event.get('subtype', 'unknown') if event.get('subtype') != secret else 'unknown',
                    'sessionId': self.session if event['session_id'] == self.session else None,
                    **({'state': 'running'} if event.get('subtype') == 'session_state_changed' else {})}])
                self.assertNotIn(secret, json.dumps(raised.exception.diagnostic))

    async def test_stdout_type_labels_diagnose_preinit_failure_without_admission(self):
        labels = ('active_goal', 'assistant', 'auth_status', 'autocompact_state',
                  'command_lifecycle', 'control_cancel_request', 'control_request',
                  'control_response', 'conversation_reset', 'keep_alive',
                  'prompt_suggestion', 'rate_limit_event', 'result', 'stream_event',
                  'system', 'tool_progress', 'tool_use_summary', 'transcript_mirror', 'user')
        secret = 'private-payload-' + secrets.token_hex(16)
        for kind in labels:
            probe = self.new_probe()
            probe.provider_request(self.ready)
            probe.hold_response()
            event = {'type': kind, 'subtype': secret, 'session_id': self.session,
                     'message': secret, 'request': {'subtype': secret},
                     'response': {'result': secret}, 'event': {'type': secret},
                     'value': secret, 'output': [secret], 'rate_limit_info': {secret: secret}}
            with self.subTest(kind=kind), self.assertRaisesRegex(
                    CANARY.CanaryError, '^busy_native_missing_init$') as raised:
                await CANARY.observe_busy_stdout(
                    stream(self.ui_hint(), self.state('running'), event), probe)
            diagnostic = raised.exception.diagnostic
            self.assertEqual([item['eventType'] for item in diagnostic], ['system', 'system', kind])
            self.assertEqual(diagnostic[-1]['eventSubtype'], 'unknown')
            self.assertEqual(diagnostic[-1]['sessionId'], self.session)
            self.assertNotIn(secret, json.dumps(diagnostic))
            self.assertFalse(probe.initialized)
            self.assertFalse(probe.running)
            self.assertFalse(probe.ready_to_send.is_set())
            self.assertFalse(probe.complete.is_set())

    async def test_unknown_stdout_types_never_export_arbitrary_values(self):
        secret = 'private_untrusted_discriminator_' + secrets.token_hex(16)
        values = (secret, secret * 100, 'control_request' + secret,
                  'CONTROL_REQUEST', 'control_request\n', None, {secret: secret},
                  [secret], True, 17, 1.5, 'bash_command', 'session_notice',
                  'queued_notification', 'set_expanded_view')
        for value in values:
            probe = self.new_probe()
            event = {'type': value, 'subtype': secret, 'session_id': self.session,
                     secret: secret, 'message': {secret: secret}}
            with self.subTest(value=value), self.assertRaisesRegex(
                    CANARY.CanaryError, '^busy_native_missing_init$') as raised:
                await CANARY.observe_busy_stdout(stream(event), probe)
            self.assertEqual(raised.exception.diagnostic[0]['eventType'], 'unknown')
            self.assertEqual(raised.exception.diagnostic[0]['eventSubtype'], 'unknown')
            self.assertNotIn(secret, json.dumps(raised.exception.diagnostic))
            self.assertFalse(probe.initialized)
            self.assertFalse(probe.running)
            self.assertFalse(probe.ready_to_send.is_set())
            self.assertFalse(probe.complete.is_set())

    async def test_failure_diagnostic_state_is_allowlisted_and_only_for_state_events(self):
        secret = 'private-state-' + secrets.token_hex(16)
        for state in ('running', 'idle', secret, None, {'content': secret}):
            probe = self.new_probe()
            with self.subTest(state=state), self.assertRaises(CANARY.CanaryError) as raised:
                await CANARY.observe_busy_stdout(stream(self.state(state)), probe)
            self.assertEqual(raised.exception.diagnostic[0]['state'],
                             state if state in ('running', 'idle') else 'unknown')
            self.assertNotIn(secret, json.dumps(raised.exception.diagnostic))
            self.assertFalse(probe.ready_to_send.is_set())
        for event in (self.initial | {'state': secret},
                      self.state('running') | {'type': 'result'},
                      self.state('running') | {'subtype': secret}):
            with self.subTest(event=event), self.assertRaises(CANARY.CanaryError) as raised:
                await CANARY.observe_busy_stdout(stream(event), self.new_probe())
            self.assertNotIn('state', raised.exception.diagnostic[0])
            self.assertNotIn(secret, json.dumps(raised.exception.diagnostic))

    async def test_failure_diagnostic_allowlists_subtypes_and_exact_session(self):
        subtypes = ('init', 'session_state_changed', 'success', 'error_during_execution',
                    'error_max_turns', 'error_max_budget_usd', 'error_during_result_validation')
        for subtype in subtypes:
            with self.subTest(subtype=subtype), self.assertRaises(CANARY.CanaryError) as raised:
                await CANARY.observe_busy_stdout(stream({'type': 'result', 'subtype': subtype,
                    'session_id': str(uuid4()), 'result': self.key}), self.new_probe())
            self.assertEqual(raised.exception.diagnostic[0]['eventSubtype'], subtype)
            self.assertIsNone(raised.exception.diagnostic[0]['sessionId'])
            self.assertNotIn(self.key, json.dumps(raised.exception.diagnostic))

    async def test_startup_system_discriminators_remain_rejected_and_payload_free(self):
        secret = 'private-startup-' + secrets.token_hex(16)
        manifest = json.loads((SCRIPT.parent.parent / 'docs/claude-system-subtypes-2.1.302.json').read_text())
        self.assertEqual(len(manifest['schemaSubtypeOffsets']), 64)
        subtypes = (set(manifest['schemaSubtypeOffsets']) - {'init', 'session_state_changed'}
                    | set(manifest['retainedConstructorSubtypeOffsets']))
        self.assertEqual(len(subtypes), 63)
        for subtype in sorted(subtypes):
            for initialized in (False, True):
                probe = self.new_probe()
                probe.initialized = initialized
                event = {'type': 'system', 'subtype': subtype, 'session_id': self.session,
                         'metadata': {secret: secret}, 'status': secret, 'hook_id': secret,
                         'hook_event': secret, 'message': secret, 'stdout': secret,
                         'stderr': secret, 'output': secret, 'exit_code': 17, 'content': secret, 'tasks': [secret],
                         'commands': [secret], 'title': secret, secret: secret}
                reason = ('busy_native_ui_hint' if subtype == 'ui_invalidate' else
                          'busy_native_premature_result' if initialized else 'busy_native_missing_init')
                with self.subTest(subtype=subtype, initialized=initialized), \
                        self.assertRaisesRegex(CANARY.CanaryError, '^' + reason + '$') as raised:
                    await CANARY.observe_busy_stdout(stream(event), probe)
                diagnostic = raised.exception.diagnostic[0]
                self.assertEqual(diagnostic['eventSubtype'], subtype)
                self.assertEqual(diagnostic['fieldShapes'], {
                    'subtype': 'string', 'metadata': 'object', 'status': 'string',
                    'hook_id': 'string', 'hook_event': 'string', 'message': 'string',
                    'stdout': 'string', 'stderr': 'string', 'output': 'string', 'exit_code': 'number'})
                self.assertNotIn(secret, json.dumps(diagnostic))
                self.assertNotIn('17', json.dumps(diagnostic['fieldShapes']))
                self.assertFalse(probe.ready_to_send.is_set())
                self.assertFalse(probe.complete.is_set())

    async def test_unknown_system_discriminator_shapes_are_fixed_and_bounded(self):
        secret = 'private-discriminator-' + secrets.token_hex(16)
        values = ((secret, 'string'), (secret * 100, 'string'),
                  ('informational' + secret, 'string'), (secret + 'commands_changed', 'string'),
                  ('INFORMATIONAL', 'string'), ('informational\\n', 'string'), (None, 'null'),
                  ({secret: secret}, 'object'), ([secret], 'array'),
                  (True, 'boolean'), (17, 'number'), (1.5, 'number'))
        for value, shape in values:
            probe = self.new_probe()
            event = {'type': 'system', 'session_id': self.session, 'subtype': value,
                     'message': {secret: secret}, secret: secret}
            with self.subTest(shape=shape), \
                    self.assertRaisesRegex(CANARY.CanaryError, '^busy_native_missing_init$') as raised:
                await CANARY.observe_busy_stdout(stream(event), probe)
            diagnostic = raised.exception.diagnostic[0]
            self.assertEqual(diagnostic['eventSubtype'], 'unknown')
            self.assertEqual(diagnostic['fieldShapes'], {
                'subtype': shape, 'metadata': 'absent', 'status': 'absent',
                'hook_id': 'absent', 'hook_event': 'absent', 'message': 'object',
                'stdout': 'absent', 'stderr': 'absent', 'output': 'absent', 'exit_code': 'absent'})
            self.assertLess(len(json.dumps(diagnostic)), 700)
            self.assertNotIn(secret, json.dumps(diagnostic))
        with self.assertRaises(CANARY.CanaryError) as raised:
            await CANARY.observe_busy_stdout(stream({'type': 'system', 'session_id': self.session}),
                                            self.new_probe())
        self.assertEqual(raised.exception.diagnostic[0]['fieldShapes']['subtype'], 'absent')
        for kind in ('user', 'assistant', 'result', secret):
            with self.subTest(kind=kind), self.assertRaises(CANARY.CanaryError) as raised:
                await CANARY.observe_busy_stdout(stream({'type': kind, 'subtype': 'hook_started',
                    'session_id': self.session}), self.new_probe())
            self.assertEqual(raised.exception.diagnostic[0]['eventSubtype'], 'unknown')
            self.assertNotIn('fieldShapes', raised.exception.diagnostic[0])

    async def test_startup_shape_diagnostic_preserves_eight_event_limit(self):
        init = {'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []}
        event = {'type': 'system', 'subtype': 'session_metadata', 'session_id': self.session,
                 'metadata': {'private-key': 'private-value'}}
        with self.assertRaisesRegex(CANARY.CanaryError, '^busy_native_premature_result$') as raised:
            await CANARY.observe_busy_stdout(stream(*([init] * 10), event), self.new_probe())
        diagnostic = raised.exception.diagnostic
        self.assertEqual([item['order'] for item in diagnostic], list(range(4, 12)))
        self.assertEqual(diagnostic[-1]['eventSubtype'], 'session_metadata')
        self.assertLess(len(json.dumps(diagnostic)), 4096)
        self.assertNotIn('private-', json.dumps(diagnostic))

    async def test_malformed_and_oversized_diagnostics_never_contain_raw_output(self):
        secret = ('private-output-' + secrets.token_hex(16)).encode()
        for payload in (secret + b'\n', secret * 2048 + b'\n', b'null\n', b'[]\n'):
            reader = asyncio.StreamReader(limit=len(payload) + 1)
            reader.feed_data(payload)
            reader.feed_eof()
            probe = self.new_probe()
            with self.subTest(size=len(payload)), self.assertRaises(CANARY.CanaryError) as raised:
                await CANARY.observe_busy_stdout(reader, probe)
            diagnostic = raised.exception.diagnostic
            self.assertEqual(len(diagnostic), 1)
            self.assertEqual(diagnostic[0], {'order': 1, 'observedNs': diagnostic[0]['observedNs'],
                'eventType': 'unknown', 'eventSubtype': 'unknown', 'sessionId': None})
            self.assertGreaterEqual(diagnostic[0]['observedNs'], 0)
            self.assertNotIn(secret.decode(), str(raised.exception) + json.dumps(diagnostic))
            self.assertFalse(probe.ready_to_send.is_set())
        with patch.object(CANARY, 'MAX_STREAM_BYTES', 2), self.assertRaises(CANARY.CanaryError) as raised:
            await CANARY.observe_busy_stdout(stream(self.initial), self.new_probe())
        self.assertEqual(raised.exception.diagnostic[0]['eventType'], 'unknown')
        self.assertIsNone(raised.exception.diagnostic[0]['sessionId'])

    async def test_eof_and_read_failure_preserve_only_actual_output_events(self):
        init = {'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []}
        secret = 'private-read-error-' + secrets.token_hex(16)
        for count in (0, 10):
            for ending in (b'', OSError(secret)):
                reader = Mock()
                reader.readline = AsyncMock(side_effect=[
                    *[(json.dumps(init) + '\n').encode()] * count, ending])
                probe = self.new_probe()
                reason = 'busy_native_stream_closed' if ending == b'' else 'busy_native_stream_failure'
                with self.subTest(count=count, ending=type(ending).__name__), \
                        self.assertRaisesRegex(CANARY.CanaryError, '^' + reason + '$') as raised:
                    await CANARY.observe_busy_stdout(reader, probe)
                diagnostic = raised.exception.diagnostic
                self.assertEqual([entry['order'] for entry in diagnostic],
                                 list(range(3, 11)) if count else [])
                self.assertTrue(all(entry['eventType'] == 'system' and entry['eventSubtype'] == 'init'
                                    and entry['sessionId'] == self.session for entry in diagnostic))
                self.assertNotIn(secret, str(raised.exception) + json.dumps(diagnostic))
                self.assertFalse(probe.ready_to_send.is_set())
                self.assertFalse(probe.complete.is_set())

    async def test_streamreader_limit_failure_has_no_output_diagnostic(self):
        secret = ('private-overlong-' + secrets.token_hex(16)).encode()
        reader = asyncio.StreamReader()
        reader.feed_data(secret * 2048 + b'\n')
        reader.feed_eof()
        probe = self.new_probe()
        with self.assertRaisesRegex(CANARY.CanaryError, '^busy_native_stream_failure$') as raised:
            await CANARY.observe_busy_stdout(reader, probe)
        self.assertEqual(raised.exception.diagnostic, [])
        self.assertNotIn(secret.decode(), str(raised.exception))
        self.assertFalse(probe.ready_to_send.is_set())

    async def test_failure_diagnostic_retains_only_last_eight_events(self):
        probe = self.new_probe()
        init = {'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []}
        with self.assertRaises(CANARY.CanaryError) as raised:
            await CANARY.observe_busy_stdout(stream(*([init] * 10), self.result(self.key)), probe)
        diagnostic = raised.exception.diagnostic
        self.assertEqual(len(diagnostic), 8)
        self.assertEqual([entry['order'] for entry in diagnostic], list(range(4, 12)))
        self.assertTrue(all(entry['eventSubtype'] == 'init' for entry in diagnostic[:-1]))
        self.assertEqual(diagnostic[-1]['eventType'], 'result')
        self.assertEqual([entry['observedNs'] for entry in diagnostic],
                         sorted(entry['observedNs'] for entry in diagnostic))
        self.assertNotIn(self.key, json.dumps(diagnostic))
        self.assertFalse(probe.ready_to_send.is_set())

    def test_main_prints_diagnostic_only_when_failure_carries_one(self):
        diagnostic = [{'order': 1, 'observedNs': 17, 'eventType': 'user',
                       'eventSubtype': 'unknown', 'sessionId': self.session}]
        for included in (False, True):
            error = CANARY.CanaryError('busy_native_missing_init')
            if included:
                error.diagnostic = diagnostic
            stderr = io.StringIO()
            with tempfile.TemporaryDirectory() as temporary:
                binary = Path(temporary) / 'client'
                binary.write_bytes(b'synthetic-client')

                async def fail(*args, **kwargs):
                    raise error
                with patch.object(CANARY, 'CLIENT_SHA256', CANARY.hashlib.sha256(binary.read_bytes()).hexdigest()), \
                        patch.object(CANARY, 'canary', side_effect=fail), \
                        patch.object(CANARY, 'ensure_private_directory'), \
                        patch.object(CANARY.tempfile, 'mkdtemp', return_value=temporary), \
                        patch.object(CANARY.sys, 'stderr', stderr):
                    self.assertEqual(CANARY.main(['--binary', str(binary), '--model', 'fixture',
                        '--local-provider', '--busy-probe', '--private-output',
                        str(Path(temporary) / 'proof.json')]), 2)
            output = json.loads(stderr.getvalue())
            self.assertEqual(output['reason'], 'busy_native_missing_init')
            self.assertFalse(output['productionQualified'])
            self.assertEqual('busyFailureDiagnostic' in output, included)
            if included:
                self.assertEqual(output['busyFailureDiagnostic'], diagnostic)

    async def test_waiter_prioritizes_provider_failure_over_ready_barrier(self):
        probe = self.started()
        probe.failed.set()
        observer = asyncio.create_task(asyncio.Event().wait())
        try:
            with self.assertRaisesRegex(CANARY.CanaryError, 'local_provider_incomplete'):
                await CANARY.wait_busy_witness(probe.ready_to_send, observer, probe)
        finally:
            observer.cancel()
            await asyncio.gather(observer, return_exceptions=True)

    def test_late_provider_failure_invalidates_completed_observations(self):
        probe = self.released()
        self.finish(probe)
        proof = probe.proof()
        self.assertEqual(proof['admission'], 'unknown')
        self.assertEqual(proof['delivery'], 'unknown')
        self.assertFalse(proof['restartQualified'])
        self.assertEqual(proof['sessionId'], self.session)
        self.assertEqual(proof['inputUuid'], self.frame['uuid'])
        probe.failed.set()
        with self.assertRaises(CANARY.CanaryError):
            probe.proof()

    async def test_busy_canary_late_failure_cleans_child_server_and_scratch(self):
        await self.run_busy_canary('late_failure')

    async def test_busy_canary_late_native_failure_retains_diagnostic_and_cleans_up(self):
        await self.run_busy_canary('late_native_failure')

    async def test_busy_canary_late_malformed_frame_retains_diagnostic_and_cleans_up(self):
        await self.run_busy_canary('late_malformed_frame')

    async def test_busy_canary_returns_ordered_observations_only_after_shutdown(self):
        await self.run_busy_canary('success')

    async def test_busy_canary_timeout_cleans_stalled_native_session(self):
        await self.run_busy_canary('timeout')

    async def test_busy_canary_timeout_cleans_held_response(self):
        diagnostic = io.StringIO()
        async with asyncio.timeout(5):
            with patch.object(CANARY.sys, 'stderr', diagnostic):
                await self.run_busy_canary('held_timeout')
        records = [json.loads(line) for line in diagnostic.getvalue().splitlines()]
        phases = [record['canaryPhase'] for record in records]
        self.assertLess(phases.index('run_timeout'), phases.index('closing_provider'))
        self.assertEqual(phases[-1], 'cleanup_complete')
        for record in records:
            self.assertEqual(set(record), {'canaryPhase', 'initialized', 'running',
                'providerRequests', 'responseHeld', 'responseReleased', 'witnessComplete'})
        for private in (self.key, self.session, self.ready, self.busy, self.initial['uuid'],
                        self.frame['message']['content']):
            self.assertNotIn(private, diagnostic.getvalue())

    async def test_busy_canary_held_timeout_waits_for_send_after_slow_startup(self):
        initialize = self.initialize_busy_provider

        async def slow_startup(*args):
            await initialize(*args)
            await asyncio.sleep(0.02)

        async with asyncio.timeout(5):
            with patch.object(self, 'initialize_busy_provider', side_effect=slow_startup):
                await self.run_busy_canary('held_timeout')

    async def run_busy_canary(self, scenario):
        parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'  # nosec B108
        root = Path(tempfile.mkdtemp(dir=parent)).resolve()
        reader = asyncio.StreamReader()
        child = Mock(returncode=None, pid=123, stdout=reader)
        server = Mock()
        server.wait_closed = AsyncMock()
        provider = Mock(turns=0, failure=False)
        pending = []
        generated = 0
        stopped = False
        real_timeout = asyncio.timeout
        held_timeout = real_timeout(None)

        def generate_uuid():
            nonlocal generated
            if generated >= 3:
                self.assertTrue(provider.probe.ready_to_send.is_set())
                self.assertTrue(provider.probe.running)
                self.assertTrue(provider.probe.held)
                self.assertFalse(provider.probe.release.is_set())
            generated += 1
            return uuid4()

        def make_provider(_key, _model, *, probe):
            provider.probe = probe
            self.session = probe.session_id
            self.ready = probe.ready_marker
            return provider

        def feed(*messages):
            reader.feed_data(b''.join((json.dumps(message) + '\n').encode() for message in messages))

        async def send(metadata):
            if scenario == 'held_timeout':
                # Expire the real run timeout only after reaching the held send.
                held_timeout.reschedule(asyncio.get_running_loop().time())
                await asyncio.Event().wait()
            self.assertTrue(provider.probe.running)
            self.assertFalse(provider.probe.release.is_set())
            pending.append(asyncio.create_task(self.finish_busy_native(provider, feed, CANARY.event_frame(self.session, metadata))))
            return {'reason': 'claude_write_unacknowledged'}

        async def stop(_child):
            nonlocal stopped
            stopped = True
            if scenario in ('late_native_failure', 'late_malformed_frame'):
                self.assertTrue(provider.probe.complete.is_set())
                if scenario == 'late_native_failure':
                    feed(self.result(self.key))
                else:
                    reader.feed_data(self.key.encode() + b'\n')
            reader.feed_eof()

        async def late_failure():
            provider.failure = True
            provider.probe.failed.set()

        child.stdin.drain = AsyncMock(side_effect=partial(self.initialize_busy_provider, scenario, feed, provider))
        provider.close = AsyncMock(side_effect=late_failure if scenario == 'late_failure' else None)
        transport = Mock(send=AsyncMock(side_effect=send))
        try:
            with patch.object(CANARY, 'uuid4', side_effect=generate_uuid), \
                    patch.object(CANARY, 'RUN_SECONDS', None if scenario == 'held_timeout' else 0.01 if scenario == 'timeout' else 1), \
                    patch.object(CANARY.asyncio, 'timeout', side_effect=lambda delay: held_timeout if delay is None else real_timeout(delay)), \
                    patch.object(CANARY, 'sandbox_profile', return_value='(deny default)'), \
                    patch.object(CANARY, 'LocalProvider', side_effect=make_provider), \
                    patch.object(CANARY.asyncio, 'start_server', new=AsyncMock(return_value=server)), \
                    patch.object(CANARY.asyncio, 'create_subprocess_exec', new=AsyncMock(return_value=child)), \
                    patch.object(CANARY.Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=1, st_ino=2)), \
                    patch.object(CANARY, 'child_peer_token', return_value=secrets.token_urlsafe(32)), \
                    patch.object(CANARY, 'ClaudeSocketTransport', return_value=transport), \
                    patch.object(CANARY, 'stop_child', new=AsyncMock(side_effect=stop)) as shutdown:
                async with real_timeout(5):
                    proof = await self.busy_scenario_outcome(scenario, root)
                if scenario == 'success':
                    self.assertTrue(stopped)
                    provider.close.assert_awaited_once()
                    self.assert_busy_proof(proof, child.pid)
            shutdown.assert_awaited_once_with(child)
            server.close.assert_called_once()
            server.wait_closed.assert_awaited_once()
            provider.close.assert_awaited_once()
            self.assert_busy_send_state(scenario, transport, provider.probe, generated)
            self.assertFalse(root.exists())
        finally:
            await asyncio.gather(*pending)

    async def initialize_busy_provider(self, scenario, feed, provider):
        if scenario == 'timeout':
            return
        feed({'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []},
             self.state('running'))
        provider.probe.provider_request(self.ready)
        provider.probe.hold_response()
        provider.turns = 1

    async def finish_busy_native(self, provider, feed, frame):
        await provider.probe.release.wait()
        feed(frame | {'isReplay': True}, self.assistant(self.ready), self.result(self.ready))
        self.busy = provider.probe.expected['marker']
        provider.probe.provider_request(self.busy)
        provider.turns = 2
        feed(self.assistant(self.busy), self.result(self.busy), self.state('idle'))

    async def busy_scenario_outcome(self, scenario, root):
        if scenario == 'success':
            return await CANARY.canary('/never-executed', root, self.key, 'fixture', 43231,
                                       busy_probe=True)
        if scenario in ('late_native_failure', 'late_malformed_frame'):
            code = ('busy_native_result_mismatch' if scenario == 'late_native_failure'
                    else 'invalid_client_output')
            with self.assertRaisesRegex(CANARY.CanaryError, '^' + code + '$') as raised:
                await CANARY.canary('/never-executed', root, self.key, 'fixture', 43231,
                                    busy_probe=True)
            diagnostic = raised.exception.diagnostic
            self.assertEqual(len(diagnostic), 8)
            last = diagnostic[-1]
            self.assertEqual(last['eventType'],
                             'result' if scenario == 'late_native_failure' else 'unknown')
            self.assertEqual(last['eventSubtype'],
                             'success' if scenario == 'late_native_failure' else 'unknown')
            self.assertEqual(last['sessionId'],
                             self.session if scenario == 'late_native_failure' else None)
            self.assertNotIn(self.key, str(raised.exception) + json.dumps(diagnostic))
        elif scenario in ('timeout', 'held_timeout'):
            with self.assertRaises(TimeoutError):
                await CANARY.canary('/never-executed', root, self.key, 'fixture', 43231,
                                    busy_probe=True)
        else:
            with self.assertRaisesRegex(CANARY.CanaryError, '^local_provider_incomplete$'):
                await CANARY.canary('/never-executed', root, self.key, 'fixture', 43231,
                                    busy_probe=True)
        return None

    def assert_busy_proof(self, proof, child_pid):
        witness = proof['busyProbe']
        self.assertEqual(witness['admission'], 'unknown')
        self.assertEqual(witness['delivery'], 'unknown')
        self.assertFalse(witness['restartQualified'])
        self.assertFalse(proof['productionQualified'])
        self.assertFalse(proof['nativeReceiptV3Proven'])
        self.assertEqual(witness['retainedChildPid'], child_pid)
        observations = witness['observations']
        timestamps = [item['observedNs'] for item in observations]
        self.assertEqual(timestamps, sorted(timestamps))
        self.assertGreaterEqual(timestamps[0], 0)
        kinds = [item['kind'] for item in observations]
        sequence = ['busy_input_prepared', 'socket_write_closed',
                    'initial_response_released', 'native_user_replay', 'native_assistant']
        positions = [kinds.index(kind) for kind in sequence]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(observations[-1]['kind'], 'native_state')
        self.assertEqual(observations[-1]['state'], 'idle')

    def assert_busy_send_state(self, scenario, transport, probe, generated):
        if scenario == 'timeout':
            transport.send.assert_not_awaited()
            self.assertEqual(generated, 3)
        else:
            if scenario == 'held_timeout':
                self.assertTrue(probe.held)
                self.assertFalse(probe.release.is_set())
                self.assertFalse(probe.complete.is_set())
            transport.send.assert_awaited_once()
            self.assertEqual(generated, 6)

    def test_optional_initial_replay_and_late_busy_replay_preserve_identity(self):
        probe = self.started()
        probe.observe(self.initial | {'isReplay': True})
        probe.prepare(self.frame)
        probe.sent()
        probe.release_response()
        probe.observe(self.assistant(self.ready))
        probe.observe(self.result(self.ready))
        probe.observe(self.frame | {'isReplay': True})
        probe.provider_request(self.busy)
        probe.observe(self.assistant(self.busy))
        probe.observe(self.result(self.busy))
        probe.observe(self.state('idle'))
        observations = probe.proof()['observations']
        replay = [item for item in observations if item['kind'] == 'native_user_replay']
        self.assertEqual([item['inputUuid'] for item in replay], [self.initial['uuid'], self.frame['uuid']])
        self.assertEqual([item['whileResponseHeld'] for item in replay], [True, False])

    async def test_provider_http_hold_outlives_parse_deadline(self):
        await self.run_held_provider('release')

    async def test_provider_http_write_has_separate_deadline(self):
        await self.run_held_provider('write_timeout')

    async def test_provider_close_cancels_held_response_without_writing(self):
        await self.run_held_provider('cancel')

    async def test_local_provider_cleanup_bounds_stalls_and_errors(self):
        for failure in ('provider_stall', 'server_stall', 'provider_error'):
            with self.subTest(failure=failure):
                baseline = asyncio.all_tasks()
                owned = asyncio.create_task(asyncio.Event().wait())
                server = Mock(wait_closed=AsyncMock())
                provider = Mock(tasks={owned}, close=AsyncMock())
                if failure == 'provider_stall':
                    provider.close.side_effect = asyncio.Event().wait
                elif failure == 'server_stall':
                    server.wait_closed.side_effect = asyncio.Event().wait
                else:
                    provider.close.side_effect = RuntimeError('private-provider-error')
                    aborted = asyncio.Event()
                    server.abort_clients.side_effect = aborted.set

                    async def finish_server_after_abort():
                        await aborted.wait()
                        server.shutdown_observed = True

                    server.shutdown_observed = False
                    server.wait_closed.side_effect = finish_server_after_abort
                try:
                    async with asyncio.timeout(5):
                        with patch.object(CANARY, 'CLEANUP_SECONDS', 0.02), \
                                patch.object(CANARY, 'ABORT_SECONDS', 0.02):
                            with self.assertRaisesRegex(CANARY.CanaryError, '^local_provider_cleanup_failed$'):
                                await CANARY.close_local_provider(server, provider)
                    server.close.assert_called_once()
                    server.abort_clients.assert_called_once()
                    server.wait_closed.assert_awaited_once()
                    if failure == 'provider_error':
                        self.assertTrue(server.shutdown_observed)
                    self.assertTrue(owned.cancelled())
                    self.assertFalse(asyncio.all_tasks() - baseline)
                finally:
                    owned.cancel()
                    await asyncio.gather(owned, return_exceptions=True)

    async def test_cleanup_failure_preserves_primary_timeout_and_reports_failure(self):
        diagnostic = io.StringIO()
        provider = Mock(tasks=set(), close=AsyncMock(side_effect=RuntimeError('private-provider-error')))
        server = Mock(wait_closed=AsyncMock())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'canary'
            root.mkdir(mode=0o700)
            async with asyncio.timeout(5):
                with patch.object(CANARY.sys, 'stderr', diagnostic), \
                        patch.object(CANARY, 'sandbox_profile', return_value='(deny default)'), \
                        patch.object(CANARY, 'LocalProvider', return_value=provider), \
                        patch.object(CANARY.asyncio, 'start_server', new=AsyncMock(return_value=server)), \
                        patch.object(CANARY.asyncio, 'create_subprocess_exec', new=AsyncMock(side_effect=TimeoutError)):
                    with self.assertRaises(TimeoutError):
                        await CANARY.canary('/never-executed', root, self.key, 'fixture', 43231, busy_probe=True)
        phases = [json.loads(line)['canaryPhase'] for line in diagnostic.getvalue().splitlines()]
        self.assertLess(phases.index('run_timeout'), phases.index('closing_provider'))
        self.assertEqual(phases[-1], 'cleanup_failed')
        self.assertNotIn('cleanup_complete', phases)
        self.assertNotIn('private-provider-error', diagnostic.getvalue())
        self.assertNotIn(self.key, diagnostic.getvalue())

    async def test_local_server_cleanup_cancels_held_connection_before_wait_closed(self):
        await self.run_local_server_cleanup(late_callback=False)

    async def test_local_server_cleanup_aborts_late_accepted_callback(self):
        await self.run_local_server_cleanup(late_callback=True)

    async def run_local_server_cleanup(self, *, late_callback):
        probe = self.new_probe()
        probe.observe({'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []})
        probe.observe(self.state('running'))
        provider = CANARY.LocalProvider('dummy-fixture', 'fixture', probe=probe)
        body = json.dumps({'model': 'fixture', 'stream': True, 'tools': [],
                           'system': [{'type': 'text', 'text': self.ready}],
                           'messages': [{'role': 'user', 'content': 'Begin synthetic test.'}]}).encode()
        server = writer = None
        accepted, start_handler = asyncio.Event(), asyncio.Event()
        handlers = set()

        async def handle(reader, writer):
            handlers.add(asyncio.current_task())
            accepted.set()
            if late_callback:
                await start_handler.wait()
            await provider.handle(reader, writer)

        close_provider = provider.close

        async def close_before_callback():
            await close_provider()
            start_handler.set()

        cleanup_bound = CANARY.CLEANUP_SECONDS + CANARY.ABORT_SECONDS + 1
        async with asyncio.timeout(cleanup_bound + 1):
            try:
                server = await asyncio.start_server(handle, '127.0.0.1', 0)
                port = server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection('127.0.0.1', port)
                writer.write((f'POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                              'Content-Type: application/json\r\nX-Api-Key: dummy-fixture\r\n'
                              f'Content-Length: {len(body)}\r\n\r\n').encode() + body)
                await writer.drain()
                await accepted.wait()
                if late_callback:
                    self.assertFalse(provider.tasks)
                    with patch.object(provider, 'close', side_effect=close_before_callback), \
                            patch.object(CANARY, 'CLEANUP_SECONDS', 0.05), \
                            patch.object(CANARY, 'ABORT_SECONDS', 0.05):
                        with self.assertRaisesRegex(CANARY.CanaryError, '^local_provider_cleanup_failed$'):
                            await CANARY.close_local_provider(server, provider)
                else:
                    await asyncio.wait_for(probe.ready_to_send.wait(), 1)
                    self.assertTrue(provider.tasks)
                    self.assertFalse(provider.failure)
                    await asyncio.wait_for(CANARY.close_local_provider(server, provider), cleanup_bound)
                self.assertTrue(probe.held)
                self.assertEqual(await reader.read(), b'')
                self.assertFalse(probe.release.is_set())
                self.assertFalse(provider.tasks)
                self.assertTrue(provider.failure)
                self.assertTrue(probe.failed.is_set())
                self.assertFalse(probe.complete.is_set())
            finally:
                start_handler.set()
                if server is not None:
                    server.close()
                    server.abort_clients()
                for task in handlers:
                    task.cancel()
                await asyncio.gather(*handlers, return_exceptions=True)
                await provider.close()
                if writer is not None:
                    writer.close()
                    await writer.wait_closed()
                if server is not None:
                    await server.wait_closed()

    async def run_held_provider(self, scenario):
        probe = self.new_probe()
        probe.observe({'type': 'system', 'subtype': 'init', 'session_id': self.session, 'tools': []})
        probe.observe(self.state('running'))
        provider = CANARY.LocalProvider('dummy-fixture', 'fixture', probe=probe)
        body = json.dumps({'model': 'fixture', 'stream': True, 'tools': [],
                           'system': [{'type': 'text', 'text': self.ready}],
                           'messages': [{'role': 'user', 'content': 'Begin synthetic test.'}]}).encode()
        reader = asyncio.StreamReader()
        reader.feed_data(('POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:43231\r\n'
                          'Content-Type: application/json\r\nX-Api-Key: dummy-fixture\r\n'
                          f'Content-Length: {len(body)}\r\n\r\n').encode() + body)
        reader.feed_eof()
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        if scenario == 'write_timeout':
            writer.drain.side_effect = asyncio.Event().wait
        with patch.object(CANARY, 'HTTP_IO_SECONDS', 0.01):
            task = asyncio.create_task(provider.handle(reader, writer))
            try:
                await asyncio.wait_for(probe.ready_to_send.wait(), 1)
                await asyncio.sleep(0.03)
                writer.write.assert_not_called()
                self.assertFalse(task.done())
                self.assertFalse(provider.failure)
                self.assertFalse(probe.failed.is_set())
                if scenario == 'cancel':
                    await asyncio.wait_for(provider.close(), 1)
                    writer.write.assert_not_called()
                else:
                    probe.prepare(self.frame)
                    probe.sent()
                    probe.release_response()
                    await asyncio.wait_for(asyncio.shield(task), 1)
                    self.assertIn(self.ready.encode(), writer.write.call_args.args[0])
                    self.assertNotIn(self.busy.encode(), writer.write.call_args.args[0])
                    writer.drain.assert_awaited_once()
                self.assertEqual(probe.requests, 1)
                self.assertEqual(provider.failure, scenario != 'release')
                self.assertEqual(probe.failed.is_set(), scenario != 'release')
                self.assertFalse(probe.complete.is_set())
                writer.close.assert_called_once()
                self.assertFalse(provider.tasks)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await provider.close()
