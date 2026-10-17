#!/usr/bin/env python3
"""Opt-in, dedicated-key Claude idle-wake canary. Never reads owner credentials."""

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import platform
import re
import secrets
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time
from uuid import UUID, uuid4

from event_gateway.claude import ClaudeSocketTransport, SUPPORTED_VERSION, event_frame
from event_gateway.client_runtime import _private_json
from event_gateway.security import ensure_private_directory

CLIENT_SHA256 = '5262ce9de86243fed0d21edc39b271555d56780d0112e2b194439fe1c6662d37'
RUN_SECONDS = 90
HTTP_IO_SECONDS = 5
MAX_STREAM_BYTES = 1024 * 1024


class CanaryError(RuntimeError):
    """Safe failure code without any child output or credential."""


def require(condition, code):
    """Fail closed without rendering arbitrary child data."""
    if not condition:
        raise CanaryError(code)


def child_command(binary, root, session_id, model, marker, *, busy_probe=False):
    """Fixed no-tools session, explicit configuration sources and spend guard."""
    return [str(binary), '--bare', '--print', '--verbose', '--input-format', 'stream-json',
            '--output-format', 'stream-json', '--tools', '', '--disable-slash-commands',
            *(['--replay-user-messages'] if busy_probe else []),
            '--setting-sources', '', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
            '--no-session-persistence', '--session-id', session_id,
            '--messaging-socket-path', str(root / 'inbox.sock'), '--model', model,
            '--max-budget-usd', '0.10', '--system-prompt',
            f'This is a synthetic no-tools transport test. For the initial input reply exactly READY_{marker}. '
            'For a synthetic event, reply exactly with its canonicalSubject.subjectId. '
            'Do not access any source or take any other action.']


def child_environment(root, key, local_port=None, *, busy_probe=False):
    """Only a deliberately supplied API key enters the fresh client environment."""
    require(not busy_probe or local_port is not None, 'busy_probe_requires_local_provider')
    result = {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'home'),
            'CLAUDE_CONFIG_DIR': str(root / 'config'), 'TMPDIR': str(root / 'tmp'),
            'CLAUDE_CODE_TMPDIR': str(root / 'tmp'),
            'TERM': 'dumb', 'LANG': 'en_US.UTF-8', 'ANTHROPIC_API_KEY': key}
    if local_port is not None:
        result.update(ANTHROPIC_BASE_URL=f'http://127.0.0.1:{local_port}',
                      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1', DISABLE_AUTOUPDATER='1')
    if busy_probe:
        # Experimental observation in this dummy-key disposable child only.
        result['CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS'] = '1'
    return result



def sandbox_profile(binary, root, port):
    """macOS child reads only runtime libraries and disposable state; local model only."""
    require(sys.platform == 'darwin' and Path('/usr/bin/sandbox-exec').is_file(),
            'local_provider_requires_macos_sandbox')
    require(type(port) is int and 1024 <= port < 49152, 'invalid_local_provider_port')
    def quote(value):
        return json.dumps(str(value))
    return '\n'.join([
        '(version 1)', '(deny default)', '(allow process-fork)',
        f'(allow process-exec (literal {quote(binary)}))',
        '(allow process-info*)', '(allow sysctl-read)',
        '(allow mach-lookup (global-name "com.apple.system.logger"))',
        '(allow ipc-posix-shm*)', '(allow file-read-metadata)',
        '(allow file-read* (literal "/"))',
        '(allow file-read* (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share") '
        '(subpath "/private/var/db/dyld") (literal "/dev/null") (literal "/dev/urandom") '
        '(literal "/dev/random") (literal "/private/etc/localtime"))',
        f'(allow file-read* (literal {quote(binary)}) (subpath {quote(root)}))',
        f'(allow file-write* (subpath {quote(root)}) (literal "/dev/null"))',
        '(allow system-socket (socket-domain AF_UNIX))',
        f'(allow network-outbound (remote tcp "localhost:{port}"))',
        f'(allow network-bind (local unix-socket (literal {quote(root / "inbox.sock")})))',
        f'(allow network-inbound (local unix-socket (literal {quote(root / "inbox.sock")})))',
    ]) + '\n'



def admit_hosted_vm(environment, repository_id):
    """Operational guard for reviewed code on a fresh private hosted VM, not attestation."""
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_REF': 'refs/heads/main', 'GITHUB_REF_PROTECTED': 'true',
                'GITHUB_RUN_ATTEMPT': '1', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64',
                'GITHUB_REPOSITORY_ID': repository_id}
    require(isinstance(repository_id, str) and repository_id.isdigit()
            and all(environment.get(key) == value for key, value in expected.items()),
            'hosted_vm_dispatch_required')
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'hosted_vm_platform_required')
    require(re.fullmatch(r'[0-9a-f]{40}', environment.get('GITHUB_SHA', ''))
            and environment.get('GITHUB_RUN_ID', '').isdigit()
            and environment.get('ImageOS') and environment.get('ImageVersion'),
            'hosted_vm_identity_required')
    try:
        with Path(environment['GITHUB_EVENT_PATH']).open('rb') as stream:
            data = stream.read(MAX_STREAM_BYTES + 1)
        require(len(data) <= MAX_STREAM_BYTES, 'hosted_vm_event_invalid')
        event = json.loads(data)
        repository = event['repository']
        require(repository['private'] is True and str(repository['id']) == repository_id
                and repository['full_name'] == environment.get('GITHUB_REPOSITORY'),
                'hosted_vm_private_repository_required')
    except (OSError, KeyError, TypeError, ValueError):
        raise CanaryError('hosted_vm_event_invalid') from None


def hosted_network_profile(root, port, repository_id):
    """VM is the filesystem/process boundary; Seatbelt limits the trusted child's network."""
    admit_hosted_vm(os.environ, repository_id)
    require(Path('/usr/bin/sandbox-exec').is_file(), 'local_provider_requires_macos_sandbox')
    require(type(port) is int and 1024 <= port < 49152, 'invalid_local_provider_port')
    socket_path = json.dumps(str(root / 'inbox.sock'))
    return '\n'.join([
        '(version 1)', '(allow default)', '(deny network*)',
        f'(allow network-outbound (remote tcp "localhost:{port}"))',
        f'(allow network-bind (local unix-socket (literal {socket_path})))',
        f'(allow network-inbound (local unix-socket (literal {socket_path})))',
    ]) + '\n'


def synthetic_stream(text, model):
    """Anthropic Messages SSE sequence; text comes only from the client's request."""
    events = [
        {'type': 'message_start', 'message': {'id': 'msg_local_fixture', 'type': 'message',
            'role': 'assistant', 'model': model, 'content': [], 'stop_reason': None,
            'stop_sequence': None, 'usage': {'input_tokens': 1, 'output_tokens': 0}}},
        {'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}},
        {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': text}},
        {'type': 'content_block_stop', 'index': 0},
        {'type': 'message_delta', 'delta': {'stop_reason': 'end_turn', 'stop_sequence': None},
         'usage': {'output_tokens': 1}},
        {'type': 'message_stop'},
    ]
    return ''.join(f"event: {value['type']}\ndata: {json.dumps(value)}\n\n" for value in events).encode()


class BusyProbe:
    """Observe one held-response experiment; never issue an admission receipt."""

    def __init__(self, session_id, initial, ready_marker):
        self.session_id, self.initial, self.ready_marker = session_id, initial, ready_marker
        self.ready_to_send, self.release, self.complete, self.failed = (asyncio.Event() for _ in range(4))
        self.initialized = self.running = self.held = self.sent_once = False
        self.expected = None
        self.requests = self.assistants = self.results = 0
        self.running_turn = 0
        self.replayed, self.native_ids, self.observations = set(), set(), []
        self.started_ns = time.monotonic_ns()

    def record(self, kind, **fields):
        require(len(self.observations) < 64, 'busy_evidence_limit')
        self.observations.append({'kind': kind, 'observedNs': time.monotonic_ns() - self.started_ns, **fields})

    def _ready(self):
        if self.initialized and self.running and self.held and not self.release.is_set():
            self.ready_to_send.set()

    def provider_request(self, marker):
        """Called only after bounded, authenticated request parsing, never to choose a response."""
        if self.requests == 0:
            require(marker == self.ready_marker, 'busy_initial_request_mismatch')
        else:
            require(self.requests == 1 and self.release.is_set() and self.expected is not None
                    and marker == self.expected['marker'], 'busy_followup_request_mismatch')
        self.requests += 1
        self.record('provider_request', turn=self.requests)

    def hold_response(self):
        require(self.requests == 1 and not self.held and not self.release.is_set(), 'busy_hold_order')
        self.held = True
        self.record('initial_response_held')
        self._ready()

    def prepare(self, frame):
        require(self.ready_to_send.is_set() and self.running and self.held
                and not self.release.is_set() and self.expected is None and self.results == 0,
                'busy_native_running_required')
        content = frame['message']['content']
        markers = re.findall(r'BUSY_[a-f0-9]{32}', content)
        require(frame['session_id'] == self.session_id and len(set(markers)) == 1,
                'busy_input_mismatch')
        self.expected = {'uuid': frame['uuid'], 'content': content, 'marker': markers[0]}
        self.record('busy_input_prepared', inputUuid=frame['uuid'],
                    contentSha256=hashlib.sha256(content.encode()).hexdigest())

    def sent(self):
        require(self.expected is not None and self.running and self.held and not self.sent_once
                and not self.release.is_set() and self.results == 0, 'busy_send_order')
        self.sent_once = True
        self.record('socket_write_closed', delivery='unknown')

    def release_response(self):
        require(self.sent_once and not self.release.is_set(), 'busy_release_order')
        self.record('initial_response_released')
        self.release.set()

    def observe(self, value):
        """Consume exact-session native stdout continuously, including during the hold."""
        require(isinstance(value, dict) and value.get('session_id') == self.session_id,
                'busy_native_session_mismatch')
        kind = value.get('type')
        if kind == 'system' and value.get('subtype') == 'init':
            # Headless stream-json can emit init again for each queued turn.
            require(value.get('tools') == [], 'busy_native_init')
            self.initialized = True
            self.record('native_init')
            return
        require(self.initialized, 'busy_native_missing_init')
        if kind == 'system' and value.get('subtype') == 'session_state_changed':
            identity = value.get('uuid')
            try:
                require(isinstance(identity, str) and str(UUID(identity)) == identity, 'busy_native_identity')
            except ValueError:
                raise CanaryError('busy_native_identity') from None
            require(identity not in self.native_ids, 'busy_native_duplicate')
            self.native_ids.add(identity)
            state = value.get('state')
            require(state in ('running', 'idle'), 'busy_native_state')
            if state == 'running':
                require(self.results < 2, 'busy_native_extra_turn')
                if not self.running:
                    self.running_turn = self.results + 1
                self.running = True
            else:
                require(not self.running or self.release.is_set() and self.results >= self.running_turn,
                        'busy_native_premature_idle')
                self.running = False
            self.record('native_state', state=state, nativeUuid=identity)
            self._ready()
            if state == 'idle' and self.results == 2:
                require(self.expected is not None and self.expected['uuid'] in self.replayed
                        and self.requests == 2, 'busy_witness_incomplete')
                self.complete.set()
            return
        if kind == 'user':
            identity = value.get('uuid')
            expected = self.initial if identity == self.initial.get('uuid') else None
            if self.expected is not None and identity == self.expected['uuid']:
                expected = {'message': {'role': 'user', 'content': self.expected['content']}}
            require(expected is not None and value.get('isReplay') is True
                    and value.get('parent_tool_use_id') is None
                    and value.get('message') == expected['message'] and identity not in self.replayed,
                    'busy_native_replay_mismatch')
            self.replayed.add(identity)
            self.record('native_user_replay', inputUuid=identity,
                        contentSha256=hashlib.sha256(expected['message']['content'].encode()).hexdigest(),
                        whileResponseHeld=not self.release.is_set(), admission='unknown')
            return
        require(self.release.is_set() and self.expected is not None, 'busy_native_premature_result')
        expected_text = self.ready_marker if self.results == 0 else self.expected['marker']
        if kind == 'assistant':
            message = value.get('message')
            parts = message.get('content') if isinstance(message, dict) else None
            require(self.results < 2 and self.assistants == self.results and isinstance(parts, list)
                    and all(isinstance(part, dict) and part.get('type') in ('text', 'thinking')
                            and isinstance(part.get('text', ''), str) for part in parts)
                    and ''.join(part.get('text', '') for part in parts if part['type'] == 'text').strip() == expected_text,
                    'busy_native_assistant_mismatch')
            if self.results == 1:
                require(self.expected['uuid'] in self.replayed and self.requests == 2, 'busy_witness_incomplete')
            self.assistants += 1
            self.record('native_assistant', turn=self.assistants)
        elif kind == 'result':
            require(self.results < 2 and self.assistants == self.results + 1 and value.get('subtype') == 'success'
                    and value.get('is_error') is False and isinstance(value.get('result'), str)
                    and value['result'].strip() == expected_text,
                    'busy_native_result_mismatch')
            identity = value.get('uuid')
            try:
                require(isinstance(identity, str) and str(UUID(identity)) == identity, 'busy_native_identity')
            except ValueError:
                raise CanaryError('busy_native_identity') from None
            require(identity not in self.native_ids, 'busy_native_duplicate')
            self.native_ids.add(identity)
            self.results += 1
            self.record('native_result', turn=self.results, nativeUuid=identity)
        else:
            raise CanaryError('busy_native_unexpected_message')

    def proof(self):
        require(self.complete.is_set() and not self.failed.is_set(), 'busy_witness_incomplete')
        return {'sessionId': self.session_id, 'inputUuid': self.expected['uuid'],
                'inputContentSha256': hashlib.sha256(self.expected['content'].encode()).hexdigest(),
                'admission': 'unknown', 'delivery': 'unknown', 'restartQualified': False,
                'timestamps': 'parent-monotonic-observation-nanoseconds',
                'observations': [dict(item) for item in self.observations]}


async def observe_busy_stdout(reader, probe):
    """One bounded reader owns stdout; failures retain only classified envelopes."""
    size = order = 0
    diagnostic = []
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                require(probe.complete.is_set(), 'busy_native_stream_closed')
                return
            value = None
            try:
                size += len(raw)
                require(size <= MAX_STREAM_BYTES, 'client_output_limit')
                try:
                    value = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise CanaryError('invalid_client_output') from None
            finally:
                order += 1
                envelope = value if isinstance(value, dict) else {}
                kind, subtype = envelope.get('type'), envelope.get('subtype')
                diagnostic.append({'order': order, 'observedNs': time.monotonic_ns() - probe.started_ns,
                    'eventType': kind if kind in ('system', 'user', 'assistant', 'result') else 'unknown',
                    'eventSubtype': subtype if subtype in ('init', 'session_state_changed', 'success',
                        'error_during_execution', 'error_max_turns', 'error_max_budget_usd',
                        'error_during_result_validation') else 'unknown',
                    'sessionId': probe.session_id if envelope.get('session_id') == probe.session_id else None})
                if kind == 'system' and subtype not in ('init', 'session_state_changed'):
                    # Fixed labels and JSON shapes identify startup failures without retaining payloads.
                    if subtype in (
                            'agents_killed', 'api_error', 'api_retry', 'away_summary', 'background_tasks_changed',
                            'cloud_session_delta', 'code_change_published', 'commands_changed', 'compact_boundary',
                            'control_request_progress', 'dev_intent', 'elicitation_complete',
                            'feedback_draft_queued', 'file_attachments_missing', 'file_snapshot', 'files_persisted',
                            'hook_progress', 'hook_response', 'hook_started', 'informational', 'init_milestone',
                            'instruction_size_warning', 'local_command_output', 'memory_recall', 'memory_saved',
                            'mirror_error', 'model_consent_fallback', 'model_fallback', 'model_refusal_fallback',
                            'model_refusal_no_fallback', 'notification', 'peer_message_hold',
                            'per_turn_effort_changed', 'permission_check_status', 'permission_denied',
                            'permission_retry', 'plugin_install', 'post_turn_summary', 'scheduled_task_fire',
                            'session_metadata', 'session_title_changed', 'status', 'stop_hook_summary',
                            'task_notification', 'task_progress', 'task_started', 'task_summary', 'task_updated',
                            'thinking', 'thinking_tokens', 'turn_duration', 'turn_handoff_available',
                            'turn_preempted', 'ui_focus', 'ui_invalidate', 'ui_log', 'ui_panes', 'ui_scroll',
                            'ui_status', 'ui_toast', 'upgrade_relay_marker', 'vcs_state_changed',
                            'worker_shutting_down'
                    ):
                        diagnostic[-1]['eventSubtype'] = subtype
                    shapes = {str: 'string', dict: 'object', list: 'array', type(None): 'null',
                              bool: 'boolean', int: 'number', float: 'number'}
                    diagnostic[-1]['fieldShapes'] = {
                        name: shapes.get(type(envelope[name]), 'unknown') if name in envelope else 'absent'
                        for name in ('subtype', 'metadata', 'status', 'hook_id', 'hook_event',
                                     'message', 'stdout', 'stderr', 'output', 'exit_code')}
                if kind == 'system' and subtype == 'session_state_changed':
                    state = envelope.get('state')
                    diagnostic[-1]['state'] = state if state in ('running', 'idle') else 'unknown'
                del diagnostic[:-8]
            probe.observe(value)
    except Exception as error:
        failure = error if isinstance(error, CanaryError) else CanaryError('busy_native_stream_failure')
        failure.diagnostic = diagnostic
        raise failure from None


async def wait_busy_witness(event, observer, probe):
    """No controller step may advance after native or provider observation fails."""
    reached = asyncio.create_task(event.wait())
    failed = asyncio.create_task(probe.failed.wait())
    try:
        done, _ = await asyncio.wait((reached, failed, observer), return_when=asyncio.FIRST_COMPLETED)
        require(failed not in done, 'local_provider_incomplete')
        if observer in done:
            await observer
            require(event.is_set(), 'busy_native_stream_closed')
    finally:
        reached.cancel()
        failed.cancel()
        await asyncio.gather(reached, failed, return_exceptions=True)


class LocalProvider:
    """Bounded local protocol fixture with no upstream connection or retained prompts."""
    def __init__(self, key, model, probe=None):
        self.key, self.model = key, model
        self.turns = 0
        self.failure = False
        self.tasks = set()
        self.probe = probe

    def respond(self, value):
        require(isinstance(value, dict) and value.get('stream') is True
                and value.get('model') == self.model and value.get('tools', []) == [],
                'local_provider_request_rejected')
        messages = value.get('messages')
        require(isinstance(messages, list) and messages and messages[-1].get('role') == 'user',
                'local_provider_request_rejected')
        require(self.turns < 2, 'local_provider_turn_limit')
        if self.turns == 0:
            text = json.dumps(value.get('system', []))
            candidates = re.findall(r'READY_[a-f0-9]{32}', text)
            require(len(set(candidates)) == 1 and 'WAKE_' not in json.dumps(value)
                    and 'BUSY_' not in json.dumps(value),
                    'local_provider_initial_marker_missing')
        else:
            # The nonce is never passed to this server by the canary controller.
            # It must arrive through the real client's subsequent model request.
            text = json.dumps(messages[-1].get('content'))
            candidates = re.findall(r'BUSY_[a-f0-9]{32}' if self.probe else r'WAKE_[a-f0-9]{32}', text)
            require(len(set(candidates)) == 1, 'local_provider_wake_missing')
        if self.probe:
            self.probe.provider_request(candidates[0])
        self.turns += 1
        return synthetic_stream(candidates[0], self.model)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            async with asyncio.timeout(HTTP_IO_SECONDS):
                header = await reader.readuntil(b'\r\n\r\n')
                require(len(header) <= 16384, 'local_provider_headers_limit')
                lines = header.decode('ascii').split('\r\n')
                require(lines[0] in ('POST /v1/messages HTTP/1.1', 'POST /v1/messages?beta=true HTTP/1.1'),
                        'local_provider_path_rejected')
                headers = {}
                for line in lines[1:-2]:
                    name, value = line.split(':', 1)
                    name = name.lower()
                    require(name not in headers, 'local_provider_duplicate_header')
                    headers[name] = value.strip()
                require(headers.get('x-api-key') == self.key and 'authorization' not in headers,
                        'local_provider_auth_rejected')
                require(headers.get('content-type', '').split(';')[0] == 'application/json'
                        and 'transfer-encoding' not in headers and 'content-encoding' not in headers,
                        'local_provider_encoding_rejected')
                length = int(headers.get('content-length', '0'))
                require(0 < length <= 1024 * 1024, 'local_provider_body_limit')
                value = json.loads(await reader.readexactly(length))
                body = self.respond(value)
            if self.probe and self.turns == 1:
                self.probe.hold_response()
                # The experiment owns this hold; the overall canary deadline and
                # provider.close() bound it, independently of HTTP I/O budgets.
                await self.probe.release.wait()
            async with asyncio.timeout(HTTP_IO_SECONDS):
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n'
                             b'Cache-Control: no-cache\r\nConnection: close\r\nContent-Length: '
                             + str(len(body)).encode() + b'\r\n\r\n' + body)
                await writer.drain()
        except (Exception, asyncio.CancelledError):
            self.failure = True
            if self.probe:
                self.probe.failed.set()
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (Exception, asyncio.CancelledError):
                writer.transport.abort()
            self.tasks.discard(task)

    async def close(self):
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


async def completed_turn(reader, session_id, expected, state):
    """Require native assistant text and a successful result, never an echoed prompt."""
    assistant_seen = False
    while True:
        raw = await reader.readline()
        require(raw, 'client_stream_closed')
        state['bytes'] += len(raw)
        require(state['bytes'] <= MAX_STREAM_BYTES, 'client_output_limit')
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise CanaryError('invalid_client_output') from None
        require(isinstance(value, dict), 'invalid_client_output')
        if value.get('type') == 'system' and value.get('subtype') == 'init':
            require(value.get('session_id') == session_id and value.get('tools') == [],
                    'client_session_or_tools_mismatch')
            state['initialized'] = True
        elif value.get('type') == 'assistant':
            require(state['initialized'] and value.get('session_id') == session_id,
                    'client_session_mismatch')
            message = value.get('message')
            require(isinstance(message, dict) and isinstance(message.get('content'), list),
                    'invalid_client_output')
            parts = message['content']
            require(all(isinstance(part, dict) and part.get('type') in ('text', 'thinking') for part in parts),
                    'unexpected_client_action')
            assistant_seen = ''.join(part.get('text', '') for part in parts if part['type'] == 'text').strip() == expected
        elif value.get('type') == 'result':
            require(value.get('session_id') == session_id and value.get('subtype') == 'success'
                    and value.get('is_error') is False and assistant_seen
                    and value.get('result', '').strip() == expected, 'turn_not_confirmed')
            return


def child_peer_token(root, pid):
    """Read only the exact generated inbox key for this retained disposable child."""
    socket_path = root / 'inbox.sock'
    name = f'{pid}.{hashlib.sha256(str(socket_path).encode()).hexdigest()}.key'
    key, _ = _private_json(root / 'config' / 'sessions' / name, 2048, 'child_inbox_key_unavailable')
    require(isinstance(key, dict) and isinstance(key.get('peerToken'), str), 'child_inbox_key_unavailable')
    return key['peerToken']


async def stop_child(child):
    """Terminate only the retained child and wait before deleting its private state."""
    if child.returncode is None:
        child.terminate()
        try:
            await asyncio.wait_for(child.wait(), 5)
        except TimeoutError:
            child.kill()
            await asyncio.wait_for(child.wait(), 5)


async def canary(binary, root, key, model, local_port=None, hosted_repository_id=None, *, busy_probe=False):
    """Run exactly two synthetic turns; every success criterion is observed."""
    require(not busy_probe or local_port is not None, 'busy_probe_requires_local_provider')
    if hosted_repository_id is not None:
        require(local_port is not None, 'hosted_vm_requires_local_provider')
        admit_hosted_vm(os.environ, hosted_repository_id)
    session_id, marker = str(uuid4()), uuid4().hex
    child = None
    server = provider = None
    observer = None
    observer_error = None
    initial = {'type': 'user', 'session_id': session_id,
               'message': {'role': 'user', 'content': 'Begin the synthetic transport test.'}}
    probe = None
    if busy_probe:
        initial['uuid'] = str(uuid4())
        probe = BusyProbe(session_id, initial, 'READY_' + marker)
    for name in ('home', 'config', 'tmp', 'work'):
        (root / name).mkdir(mode=0o700)
    try:
        async with asyncio.timeout(RUN_SECONDS):
            command = child_command(binary, root, session_id, model, marker, busy_probe=busy_probe)
            if local_port is not None:
                profile = root / 'child.sb'
                profile.write_text(hosted_network_profile(root, local_port, hosted_repository_id)
                                   if hosted_repository_id is not None
                                   else sandbox_profile(binary, root, local_port))
                provider = LocalProvider(key, model, probe=probe)
                server = await asyncio.start_server(provider.handle, '127.0.0.1', local_port,
                                                    limit=16384, reuse_address=False)
                command = ['/usr/bin/sandbox-exec', '-f', str(profile), *command]
            child = await asyncio.create_subprocess_exec(
                *command,
                env=child_environment(root, key, local_port, busy_probe=busy_probe), cwd=root / 'work',
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, close_fds=True, limit=65536)
            state = {'bytes': 0, 'initialized': False}
            if probe:
                observer = asyncio.create_task(observe_busy_stdout(child.stdout, probe))
            child.stdin.write((json.dumps(initial) + '\n').encode())
            await child.stdin.drain()
            if probe:
                await wait_busy_witness(probe.ready_to_send, observer, probe)
            else:
                await completed_turn(child.stdout, session_id, 'READY_' + marker, state)
                await asyncio.sleep(1)
            require(child.returncode is None, 'client_exited_before_wake')
            wake_marker = ('BUSY_' if probe else 'WAKE_') + uuid4().hex
            socket_path = root / 'inbox.sock'
            info = socket_path.lstat()
            require(stat.S_ISSOCK(info.st_mode), 'child_inbox_unavailable')
            transport = ClaudeSocketTransport(socket_path=str(socket_path),
                socket_identity=(info.st_dev, info.st_ino), peer_pid=child.pid,
                session_id=session_id, token=child_peer_token(root, child.pid),
                version=SUPPORTED_VERSION, journal_dir=root / 'journal')
            metadata = {'eventId': str(uuid4()), 'deliveryId': 'dly_' + hashlib.sha256(wake_marker.encode()).hexdigest(),
                        'source': 'manual', 'sourceStateVersion': 'canary-1',
                        'canonicalSubject': {'kind': 'manual', 'subjectId': wake_marker},
                        'eventReference': 'ref_' + str(uuid4())}
            if probe:
                probe.prepare(event_frame(session_id, metadata))
            outcome = await transport.send(metadata)
            require(outcome['reason'] == 'claude_write_unacknowledged', 'socket_write_unconfirmed')
            if probe:
                await wait_busy_witness(probe.ready_to_send, observer, probe)
                probe.sent()
                probe.release_response()
                await wait_busy_witness(probe.complete, observer, probe)
            else:
                await completed_turn(child.stdout, session_id, wake_marker, state)
            require(provider is None or provider.turns == 2 and not provider.failure,
                    'local_provider_incomplete')
            proof = {'schemaVersion': 1,
                    'modelProvider': 'local-synthetic' if provider else 'dedicated-remote-key',
                    'localProviderRequests': provider.turns if provider else None,
                    'containment': ('trusted-hosted-vm-network-only' if hosted_repository_id is not None
                                    else 'local-restrictive-seatbelt' if provider else 'dedicated-remote-key'),
                    'hostileSameUidIsolationProven': False,
                    'vmDisposalObserved': False,
                    'completeDescendantTerminationProven': False,
                    'scratchRetainedForVmDisposal': hosted_repository_id is not None,
                    'offHostNetworkDenied': provider is not None, 'scope': 'disposable-headless-idle-wake',
                    'clientSha256': CLIENT_SHA256, 'clientVersion': SUPPORTED_VERSION,
                    'readyTurnObserved': True, 'idleIntervalObserved': True,
                    'socketWriteClosedGracefully': True, 'matchingWakeTurnObserved': True,
                    'stdinWakeWritten': False, 'productionQualified': False,
                    'nativeReceiptV3Proven': False}
            if probe:
                proof.update(scope='disposable-headless-native-witness-busy-probe', idleIntervalObserved=False,
                             matchingWakeTurnObserved=False, matchingBusyTurnObserved=True)
                proof['busyProbe'] = probe.proof()
                proof['busyProbe']['retainedChildPid'] = child.pid
    finally:
        try:
            if child is not None:
                await stop_child(child)
        finally:
            if observer is not None:
                try:
                    await asyncio.wait_for(observer, 1)
                except CanaryError as error:
                    observer_error = error
                except (Exception, asyncio.CancelledError):
                    observer_error = CanaryError('busy_native_observation_failed')
            if server is not None:
                server.close()
                await server.wait_closed()
            if provider is not None:
                await provider.close()
        if hosted_repository_id is None:
            shutil.rmtree(root)
    # Pending requests can fail while the child/server/provider are shutting down.
    # Only settled provider state may authorize returning the selected proof.
    require(provider is None or provider.turns == 2 and not provider.failure,
            'local_provider_incomplete')
    if observer_error is not None:
        raise observer_error
    if probe:
        # Include any final observations drained while the retained child stopped.
        proof['busyProbe'] = probe.proof() | {'retainedChildPid': child.pid}
    return proof


def publish_proof(path, proof):
    """Atomically publish only complete boolean/hash proof without overwriting."""
    directory = ensure_private_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".canary-", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(proof, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.unlink(temporary)


def main(argv=None):
    """Prompt on the operator's terminal; no credential argument, file, or inheritance."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--model', required=True)
    parser.add_argument('--local-provider', action='store_true', help='Synthetic local SSE; no credential or spend')
    parser.add_argument('--busy-probe', action='store_true',
                        help='Experimental native state/replay observations; local synthetic provider only')
    parser.add_argument('--local-port', type=int, default=43231)
    parser.add_argument('--trusted-hosted-vm', action='store_true',
                        help='Reviewed client on a fresh private GitHub-hosted macOS VM only')
    parser.add_argument('--hosted-repository-id')
    parser.add_argument('--private-output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require(not args.busy_probe or args.local_provider, 'busy_probe_requires_local_provider')
        require(args.trusted_hosted_vm == (args.hosted_repository_id is not None),
                'hosted_vm_repository_id_required')
        if args.trusted_hosted_vm:
            require(args.local_provider, 'hosted_vm_requires_local_provider')
            admit_hosted_vm(os.environ, args.hosted_repository_id)
        require(args.local_provider or sys.stdin.isatty(), 'interactive_dedicated_key_required')
        binary = args.binary.resolve(strict=True)
        require(binary.is_file() and hashlib.sha256(binary.read_bytes()).hexdigest() == CLIENT_SHA256,
                'client_digest_mismatch')
        output = args.private_output.absolute()
        ensure_private_directory(output.parent)
        require(not os.path.lexists(output), 'proof_already_exists')
        key = ('local-fixture-' + secrets.token_hex(24)) if args.local_provider else getpass.getpass(
            'Dedicated canary API key (up to $0.10 client budget; hidden): ')
        require(bool(key) and not any(char.isspace() for char in key), 'invalid_dedicated_key')
        temp_root = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'  # nosec B108
        root = Path(tempfile.mkdtemp(prefix='cq-', dir=temp_root)).resolve()
        proof = asyncio.run(canary(binary, root, key, args.model,
                                  args.local_port if args.local_provider else None,
                                  args.hosted_repository_id if args.trusted_hosted_vm else None,
                                  busy_probe=args.busy_probe))
        publish_proof(output, proof)
        print(json.dumps({'canary': 'observed', 'productionQualified': False}))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error) if isinstance(error, CanaryError) else (
            'canary_timeout' if isinstance(error, TimeoutError) else 'canary_local_or_client_failure')
        failure = {'canary': 'incomplete', 'reason': reason, 'productionQualified': False}
        if isinstance(error, CanaryError) and hasattr(error, 'diagnostic'):
            failure['busyFailureDiagnostic'] = error.diagnostic
        print(json.dumps(failure), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
