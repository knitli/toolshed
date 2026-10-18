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
import signal
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
CLEANUP_SECONDS = 4
ABORT_SECONDS = 1
MAX_STREAM_BYTES = 1024 * 1024
# Claude 2.1.302's fresh-turn peer framing, pinned without copying native prose.
PEER_REPLAY_PREFIX_BYTES = 39
PEER_REPLAY_SUFFIX_BYTES = 547
PEER_REPLAY_PREFIX_SHA256 = '175c160f7750b0d6af1a569b23a6822b33e6d7bb6e5d27bc355c7a5edbf889bc'
PEER_REPLAY_SUFFIX_SHA256 = 'cf678e57e50d5b586186df5ef480e35a155feab2915acb2e0644c5a81484b881'


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


def validate_passive_ui_hint(value):
    """Validate the pinned UI invalidation schema without granting lifecycle evidence."""
    required = {'type', 'subtype', 'event', 'uuid', 'session_id'}
    optional = {'prompts_screened', 'instances'}
    require(required <= value.keys() <= required | optional
            and value['event'] == 'ui.render' and isinstance(value['uuid'], str),
            'busy_native_ui_hint')
    if 'prompts_screened' in value:
        require(value['prompts_screened'] is True, 'busy_native_ui_hint')
    if 'instances' in value:
        require(isinstance(value['instances'], list), 'busy_native_ui_hint')
        fields = {'surface', 'component', 'instance_id'}
        for instance in value['instances']:
            require(isinstance(instance, dict) and instance.keys() == fields
                    and all(isinstance(item, str) for item in instance.values()),
                    'busy_native_ui_hint')


def matches_peer_replay(message, expected_content):
    """Match only the pinned complete peer wrapper and unchanged input bytes."""
    if (not isinstance(message, dict) or message.keys() != {'role', 'content'}
            or message.get('role') != 'user' or not isinstance(message.get('content'), str)
            or not isinstance(expected_content, str)):
        return False
    try:
        content, expected = message['content'].encode('utf-8'), expected_content.encode('utf-8')
    except UnicodeEncodeError:
        return False
    prefix, suffix = PEER_REPLAY_PREFIX_BYTES, PEER_REPLAY_SUFFIX_BYTES
    return (len(content) == prefix + len(expected) + suffix
            and hashlib.sha256(content[:prefix]).hexdigest() == PEER_REPLAY_PREFIX_SHA256
            and content[prefix:-suffix] == expected
            and hashlib.sha256(content[-suffix:]).hexdigest() == PEER_REPLAY_SUFFIX_SHA256)


class BusyProbe:
    """Observe one held-response experiment; never issue an admission receipt."""

    def __init__(self, session_id, initial, ready_marker):
        self.session_id, self.initial, self.ready_marker = session_id, initial, ready_marker
        self.ready_to_send, self.release, self.complete, self.failed = (asyncio.Event() for _ in range(4))
        self.initialized = self.running = self.held = self.sent_once = False
        self.expected = None
        self.pending_preinit_running = None
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
        if kind == 'system' and value.get('subtype') == 'ui_invalidate':
            # A pinned fire-and-forget render hint may precede init. It cannot
            # initialize the session, mark it running, or satisfy a busy witness.
            validate_passive_ui_hint(value)
            return
        if kind == 'command_lifecycle':
            # The local transport queues these independently of query init.
            # They describe a command's fate, never session readiness/admission.
            required = {'type', 'command_uuid', 'state', 'uuid', 'session_id'}
            state = value.get('state')
            require(required <= value.keys() <= required | {'ran_ahead'}
                    and state in ('queued', 'started', 'completed', 'cancelled', 'discarded', 'refused')
                    and ('ran_ahead' not in value or value['ran_ahead'] is True and state == 'queued'),
                    'busy_native_command_lifecycle')
            command = value.get('command_uuid')
            require(isinstance(command, str) and (command == self.initial.get('uuid')
                    or self.expected is not None and command == self.expected['uuid']),
                    'busy_native_command_lifecycle')
            identity = value.get('uuid')
            try:
                require(isinstance(identity, str) and str(UUID(identity)) == identity, 'busy_native_identity')
            except ValueError:
                raise CanaryError('busy_native_identity') from None
            require(identity not in self.native_ids, 'busy_native_duplicate')
            if not self.initialized and state not in ('queued', 'started'):
                self.pending_preinit_running = None
                raise CanaryError('busy_native_preinit_terminal')
            require(state not in ('cancelled', 'discarded', 'refused'), 'busy_native_command_terminal')
            if state == 'completed':
                # Fresh turns complete after their result. Folded completion
                # cannot stand in for this fixture's required separate turn.
                turn = 1 if command == self.initial.get('uuid') else 2
                require(self.release.is_set() and self.results >= turn, 'busy_native_command_order')
            self.native_ids.add(identity)
            self.record('native_command_lifecycle', state=state)
            return
        if kind == 'system' and value.get('subtype') == 'init':
            # Headless stream-json can emit init again for each queued turn.
            require(value.get('tools') == [], 'busy_native_init')
            self.initialized = True
            self.record('native_init')
            if self.pending_preinit_running is not None:
                self.pending_preinit_running = None
                self.running = True
                self.running_turn = 1
                self._ready()
            return
        if not self.initialized and kind == 'system' and value.get('subtype') == 'session_state_changed':
            # The pinned native queue can drain one running notice before init.
            # Reserve its identity and observation time now; only actual init
            # may activate it, and a terminal command notice invalidates it.
            require(set(value) == {'type', 'subtype', 'session_id', 'uuid', 'state'},
                    'busy_native_state')
            identity = value.get('uuid')
            try:
                require(isinstance(identity, str) and str(UUID(identity)) == identity, 'busy_native_identity')
            except ValueError:
                raise CanaryError('busy_native_identity') from None
            require(identity not in self.native_ids, 'busy_native_duplicate')
            require(self.pending_preinit_running is None, 'busy_native_preinit_order')
            require(value.get('state') == 'running', 'busy_native_state')
            self.native_ids.add(identity)
            self.pending_preinit_running = identity
            self.record('native_state', state='running', nativeUuid=identity, awaitingInit=True)
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
            message_matches = expected is not None and value.get('message') == expected['message']
            if self.expected is not None and identity == self.expected['uuid']:
                expected = {'message': {'role': 'user', 'content': self.expected['content']}}
                message_matches = matches_peer_replay(value.get('message'), self.expected['content'])
            require(expected is not None and value.get('isReplay') is True
                    and value.get('parent_tool_use_id') is None
                    and message_matches and identity not in self.replayed,
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


class ReattachProbe:
    """Keep the original two-turn witness intact, then observe one fresh third turn."""

    def __init__(self, session_id, initial, ready_marker):
        self.busy = BusyProbe(session_id, initial, ready_marker)
        self.session_id, self.started_ns = session_id, self.busy.started_ns
        self.ready_to_send, self.release, self.failed = self.busy.ready_to_send, self.busy.release, self.busy.failed
        self.first_pair_complete = self.busy.complete
        self.complete = asyncio.Event()
        self.fresh = self.initial_busy_proof = None
        self.fresh_request = self.fresh_assistant = self.fresh_result = False
        self.fresh_running = self.fresh_idle = self.fresh_write = False

    @property
    def initialized(self):
        return self.busy.initialized

    @property
    def running(self):
        return self.busy.running if self.fresh is None else self.fresh_running

    @property
    def held(self):
        return self.busy.held

    @property
    def requests(self):
        return self.busy.requests + int(self.fresh_request)

    def record(self, kind, **fields):
        self.busy.record(kind, **fields)

    def hold_response(self):
        self.busy.hold_response()

    def prepare(self, frame):
        self.busy.prepare(frame)

    def sent(self):
        self.busy.sent()

    def release_response(self):
        self.busy.release_response()

    def provider_request(self, marker):
        if self.busy.requests < 2:
            self.busy.provider_request(marker)
            return
        require(self.fresh is not None and not self.fresh_request and marker == self.fresh['marker'],
                'reattach_fresh_request_mismatch')
        self.fresh_request = True
        self.record('provider_request', turn=3)

    def prepare_fresh(self, frame):
        require(self.first_pair_complete.is_set() and not self.failed.is_set() and not self.busy.running
                and self.fresh is None and frame['session_id'] == self.session_id,
                'reattach_old_turn_incomplete')
        content = frame['message']['content']
        markers = re.findall(r'FRESH_[a-f0-9]{32}', content)
        require(len(set(markers)) == 1 and frame['uuid'] not in self.busy.replayed
                and frame['uuid'] not in (self.busy.initial.get('uuid'), self.busy.expected['uuid']),
                'reattach_fresh_input_mismatch')
        self.fresh = {'uuid': frame['uuid'], 'content': content, 'marker': markers[0]}
        self.record('fresh_input_prepared', inputUuid=frame['uuid'],
                    contentSha256=hashlib.sha256(content.encode()).hexdigest())

    def fresh_sent(self):
        require(self.fresh is not None and not self.fresh_write, 'reattach_fresh_send_order')
        self.fresh_write = True
        self.record('fresh_socket_write_closed', delivery='unknown')
        self._complete()

    def _complete(self):
        if self.fresh_idle and self.fresh_write:
            require(self.fresh_request and self.fresh_assistant and self.fresh_result
                    and self.fresh['uuid'] in self.busy.replayed, 'reattach_fresh_witness_incomplete')
            self.complete.set()

    def _identity(self, value):
        identity = value.get('uuid')
        try:
            require(isinstance(identity, str) and str(UUID(identity)) == identity, 'busy_native_identity')
        except ValueError:
            raise CanaryError('busy_native_identity') from None
        require(identity not in self.busy.native_ids, 'busy_native_duplicate')
        self.busy.native_ids.add(identity)
        return identity

    def observe(self, value):
        if self.fresh is None:
            self.busy.observe(value)
            if self.first_pair_complete.is_set() and self.initial_busy_proof is None:
                self.initial_busy_proof = self.busy.proof()
            return
        require(isinstance(value, dict) and value.get('session_id') == self.session_id,
                'busy_native_session_mismatch')
        kind = value.get('type')
        if kind == 'system' and value.get('subtype') == 'ui_invalidate':
            validate_passive_ui_hint(value)
        elif kind == 'system' and value.get('subtype') == 'init':
            require(value.get('tools') == [], 'busy_native_init')
            self.record('native_init')
        elif kind == 'command_lifecycle':
            if value.get('command_uuid') != self.fresh['uuid']:
                self.busy.observe(value)
                return
            required = {'type', 'command_uuid', 'state', 'uuid', 'session_id'}
            state = value.get('state')
            require(required <= value.keys() <= required | {'ran_ahead'}
                    and state in ('queued', 'started', 'completed')
                    and ('ran_ahead' not in value or value['ran_ahead'] is True and state == 'queued')
                    and (state != 'completed' or self.fresh_result), 'reattach_fresh_command_lifecycle')
            self._identity(value)
            self.record('native_command_lifecycle', state=state)
        elif kind == 'system' and value.get('subtype') == 'session_state_changed':
            identity = self._identity(value)
            state = value.get('state')
            require(state in ('running', 'idle') and not self.fresh_idle, 'reattach_fresh_state')
            if state == 'running':
                require(not self.fresh_result, 'reattach_fresh_extra_turn')
                self.fresh_running = True
            else:
                require(self.fresh_running and self.fresh_result, 'reattach_fresh_premature_idle')
                self.fresh_running = False
                self.fresh_idle = True
            self.record('native_state', state=state, nativeUuid=identity)
            self._complete()
        elif kind == 'user':
            require(value.get('uuid') == self.fresh['uuid'] and value.get('isReplay') is True
                    and value.get('parent_tool_use_id') is None
                    and self.fresh['uuid'] not in self.busy.replayed
                    and matches_peer_replay(value.get('message'), self.fresh['content']),
                    'reattach_fresh_replay_mismatch')
            self.busy.replayed.add(self.fresh['uuid'])
            self.record('native_user_replay', inputUuid=self.fresh['uuid'],
                        contentSha256=hashlib.sha256(self.fresh['content'].encode()).hexdigest(),
                        whileResponseHeld=False, admission='unknown')
        elif kind == 'assistant':
            message = value.get('message')
            parts = message.get('content') if isinstance(message, dict) else None
            require(self.fresh_running and self.fresh_request and not self.fresh_assistant
                    and self.fresh['uuid'] in self.busy.replayed and isinstance(parts, list)
                    and all(isinstance(part, dict) and part.get('type') in ('text', 'thinking')
                            and isinstance(part.get('text', ''), str) for part in parts)
                    and ''.join(part.get('text', '') for part in parts if part['type'] == 'text').strip()
                    == self.fresh['marker'], 'reattach_fresh_assistant_mismatch')
            self.fresh_assistant = True
            self.record('native_assistant', turn=3)
        elif kind == 'result':
            require(self.fresh_running and self.fresh_assistant and not self.fresh_result
                    and value.get('subtype') == 'success' and value.get('is_error') is False
                    and isinstance(value.get('result'), str) and value['result'].strip() == self.fresh['marker'],
                    'reattach_fresh_result_mismatch')
            identity = self._identity(value)
            self.fresh_result = True
            self.record('native_result', turn=3, nativeUuid=identity)
        else:
            raise CanaryError('reattach_fresh_unexpected_message')

    def proof(self):
        require(self.complete.is_set() and not self.failed.is_set(), 'reattach_fresh_witness_incomplete')
        return {'sessionId': self.session_id, 'oldInputUuid': self.busy.expected['uuid'],
                'freshInputUuid': self.fresh['uuid'], 'freshContentSha256': hashlib.sha256(
                    self.fresh['content'].encode()).hexdigest(), 'admission': 'unknown', 'delivery': 'unknown',
                'nativeRestartQualified': False, 'timestamps': 'parent-monotonic-observation-nanoseconds',
                'observations': [dict(item) for item in self.busy.observations]}


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
                    # Diagnostic labels only: pinned 2.1.302 StdoutMessage at
                    # binary offset 214655727, including SDKMessage at 214409742.
                    # This list does not admit messages into the busy witness.
                    'eventType': kind if kind in (
                        'active_goal', 'assistant', 'auth_status', 'autocompact_state',
                        'command_lifecycle', 'control_cancel_request', 'control_request',
                        'control_response', 'conversation_reset', 'keep_alive',
                        'prompt_suggestion', 'rate_limit_event', 'result', 'stream_event',
                        'system', 'tool_progress', 'tool_use_summary', 'transcript_mirror', 'user'
                    ) else 'unknown',
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


class ReattachProvider(LocalProvider):
    """A separate three-request fixture; the existing two-turn provider is unchanged."""

    def respond(self, value):
        if self.turns < 2:
            return super().respond(value)
        require(self.turns == 2 and isinstance(value, dict) and value.get('stream') is True
                and value.get('model') == self.model and value.get('tools', []) == [],
                'reattach_provider_request_rejected')
        messages = value.get('messages')
        require(isinstance(messages, list) and messages and isinstance(messages[-1], dict)
                and messages[-1].get('role') == 'user', 'reattach_provider_request_rejected')
        candidates = re.findall(r'FRESH_[a-f0-9]{32}', json.dumps(messages[-1].get('content')))
        require(len(set(candidates)) == 1, 'reattach_provider_fresh_missing')
        self.probe.provider_request(candidates[0])
        self.turns += 1
        return synthetic_stream(candidates[0], self.model)


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


def adapter_actor_main():
    """Private pipe worker: exercise the real adapter journal in a separate process."""
    request = json.loads(sys.stdin.buffer.readline(16385))
    require(isinstance(request, dict) and set(request) == {'action', 'options', 'old', 'fresh'},
            'reattach_actor_request')
    options = request['options']
    options['socket_identity'] = tuple(options['socket_identity'])
    options['journal_dir'] = Path(options['journal_dir'])
    transport = ClaudeSocketTransport(**options)

    def emit(value):
        print(json.dumps(value), flush=True)

    if request['action'] in ('reserve', 'write'):
        reserve = transport._reserve

        def paused_reserve(delivery_id):
            # The original implementation has fsynced the file AND directory.
            require(reserve(delivery_id), 'reattach_old_already_reserved')
            emit({'checkpoint': 'reserved', 'messageUuid': delivery_id})
            # Parent kills this process without letting send() open a socket.
            sys.stdin.buffer.read(1)
            raise CanaryError('reattach_crash_barrier_released')

        if request['action'] == 'reserve':
            transport._reserve = paused_reserve
        else:
            open_connection = asyncio.open_unix_connection

            async def paused_open(*args, **kwargs):
                reader, writer = await open_connection(*args, **kwargs)
                wait_closed = writer.wait_closed

                async def paused_close():
                    # send() has already drained and closed the real writer.
                    await wait_closed()
                    emit({'checkpoint': 'write_closed',
                          'messageUuid': event_frame(options['session_id'], request['old'])['uuid']})
                    sys.stdin.buffer.read(1)
                    raise CanaryError('reattach_crash_barrier_released')

                writer.wait_closed = paused_close
                return reader, writer

            asyncio.open_unix_connection = paused_open
        asyncio.run(transport.send(request['old']))
        raise CanaryError('reattach_actor_survived')
    require(request['action'] == 'recover', 'reattach_actor_action')

    async def recover():
        reconciliation = await transport.reconcile(request['old']['deliveryId'])
        require(reconciliation == {'status': 'unknown', 'reason': 'claude_native_receipt_unavailable'},
                'reattach_reconcile_claimed_delivery')
        suppressed = await transport.send(request['old'])
        require(suppressed == {'status': 'unknown', 'reason': 'claude_attempt_already_reserved'},
                'reattach_old_not_quarantined')
        emit({'checkpoint': 'old_suppressed', 'reconciliation': reconciliation, 'outcome': suppressed})
        require(sys.stdin.buffer.read(1) == b'\n', 'reattach_fresh_not_authorized')
        emit({'checkpoint': 'fresh_sent', 'outcome': await transport.send(request['fresh'])})

    asyncio.run(recover())


async def adapter_reattach(options, abandoned, fresh, *, before_fresh=None, record=None,
                           crash_point='after-reservation-before-connect'):
    """Kill only a reserved adapter, then recover its journal against the same live peer."""
    old_frame = event_frame(options['session_id'], abandoned)
    fresh_frame = event_frame(options['session_id'], fresh)
    require(old_frame['uuid'] != fresh_frame['uuid'], 'reattach_requires_distinct_delivery')
    require(crash_point in ('after-reservation-before-connect', 'after-write-close-before-result'),
            'reattach_crash_point_invalid')
    post_write = crash_point == 'after-write-close-before-result'
    old_uuid = old_frame['uuid']
    journal = Path(options['journal_dir'])
    marker = journal / hashlib.sha256(f"{options['session_id']}:{old_uuid}".encode()).hexdigest()
    serialized = dict(options, socket_identity=list(options['socket_identity']), journal_dir=str(journal))
    actors = []

    def observe(kind, **fields):
        if record is not None:
            record(kind, **fields)

    async def start(action):
        payload = (json.dumps({'action': action, 'options': serialized,
                              'old': abandoned, 'fresh': fresh}) + '\n').encode()
        require(len(payload) <= 16384, 'reattach_actor_request_limit')
        package = Path(__file__).resolve().parent.parent
        actor = await asyncio.create_subprocess_exec(
            sys.executable, '-I', '-B', '-c',
            'import runpy,sys; from pathlib import Path; p=Path(sys.argv[1]); '
            'sys.path.insert(0,str(p/"src")); '
            'runpy.run_path(str(p/"scripts/qualify_claude_socket.py"))["adapter_actor_main"]()',
            str(package), env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, close_fds=True, limit=4096)
        actors.append(actor)
        actor.stdin.write(payload)
        await actor.stdin.drain()
        return actor

    async def checkpoint(actor):
        raw = await asyncio.wait_for(actor.stdout.readline(), 5)
        require(0 < len(raw) <= 4096, 'reattach_actor_checkpoint_missing')
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise CanaryError('reattach_actor_checkpoint_invalid') from None
        return value

    try:
        async with asyncio.timeout(20):
            first = await start('write' if post_write else 'reserve')
            require(await checkpoint(first) == {'checkpoint': 'write_closed' if post_write else 'reserved',
                                                'messageUuid': old_uuid},
                    'reattach_reservation_not_observed')
            info = marker.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o777 == 0o600
                    and info.st_uid == os.getuid() and info.st_size == 0,
                    'reattach_journal_marker_invalid')
            marker_identity = (info.st_dev, info.st_ino)
            observe('adapter_write_closed' if post_write else 'adapter_reservation_observed', inputUuid=old_uuid)
            first.kill()
            require(await asyncio.wait_for(first.wait(), 5) == -signal.SIGKILL,
                    'reattach_adapter_not_killed')
            observe('adapter_killed', adapterPid=first.pid)
            second = await start('recover')
            require(second.pid != first.pid, 'reattach_adapter_not_replaced')
            expected_suppressed = {'checkpoint': 'old_suppressed',
                'reconciliation': {'status': 'unknown', 'reason': 'claude_native_receipt_unavailable'},
                'outcome': {'status': 'unknown', 'reason': 'claude_attempt_already_reserved'}}
            require(await checkpoint(second) == expected_suppressed, 'reattach_old_not_quarantined')
            info = marker.lstat()
            require((info.st_dev, info.st_ino) == marker_identity and stat.S_ISREG(info.st_mode)
                    and info.st_size == 0 and info.st_mode & 0o777 == 0o600,
                    'reattach_journal_marker_changed')
            observe('adapter_old_suppressed', inputUuid=old_uuid, adapterPid=second.pid)
            if before_fresh is not None:
                await before_fresh()
            second.stdin.write(b'\n')
            await second.stdin.drain()
            second.stdin.close()
            fresh_result = await checkpoint(second)
            expected_outcome = {'status': 'unknown', 'reason': 'claude_write_unacknowledged'}
            require(fresh_result == {'checkpoint': 'fresh_sent', 'outcome': expected_outcome},
                    'reattach_fresh_write_unconfirmed')
            require(await asyncio.wait_for(second.wait(), 5) == 0
                    and await second.stdout.read(4097) == b'', 'reattach_actor_not_complete')
            return expected_outcome, {'crashPoint': crash_point,
                'adapterKilledAndReaped': True, 'adapterProcessReplaced': True,
                'oldInputUuid': old_uuid, 'freshInputUuid': fresh_frame['uuid'],
                'sameJournalMarkerRetained': True, 'oldRetrySuppressed': True,
                'oldReconciliation': expected_suppressed['reconciliation'],
                'admission': 'unknown', 'delivery': 'unknown', 'nativeProcessRestarted': False,
                'nativeRestartQualified': False, 'postWriteAdapterCrashObserved': post_write,
                'nativePostWriteRecoveryQualified': False}
    finally:
        primary_error = sys.exception()
        cleanup_failed = False
        for actor in actors:
            try:
                await stop_child(actor)
            except (Exception, asyncio.CancelledError):
                cleanup_failed = True
        if cleanup_failed:
            if primary_error is None:
                raise CanaryError('reattach_actor_cleanup_failed') from None
            primary_error.add_note('reattach_actor_cleanup_failed')


async def close_local_provider(server, provider):
    """Settle owned connections within five seconds, including abort cleanup."""
    if server is not None:
        server.close()

    owned = set()
    if provider is not None:
        owned.add(asyncio.create_task(provider.close()))
    server_waiter = None
    if server is not None:
        server_waiter = asyncio.create_task(server.wait_closed())
        owned.add(server_waiter)
    if not owned:
        return
    try:
        done, unfinished = await asyncio.wait(owned, timeout=CLEANUP_SECONDS,
                                             return_when=asyncio.FIRST_EXCEPTION)
        for task in done:
            task.result()
        if unfinished:
            raise TimeoutError
    except BaseException as error:
        if server is not None:
            server.abort_clients()
        owned.update(() if provider is None else provider.tasks)
        for task in owned:
            if task is not server_waiter:
                task.cancel()
        done, unfinished = await asyncio.wait(owned, timeout=ABORT_SECONDS)
        for task in done:
            if not task.cancelled():
                task.exception()
        # Do not await cancellation-resistant tasks beyond the cleanup budget.
        # Scratch remains retained after cleanup failure in every run mode.
        for task in unfinished:
            task.cancel()
            task.add_done_callback(lambda finished: None if finished.cancelled() else finished.exception())
        if unfinished:
            await asyncio.sleep(0)  # deliver cancellation without extending the wait budget
        if isinstance(error, asyncio.CancelledError):
            raise
        raise CanaryError('local_provider_cleanup_failed') from error


def report_progress(phase, *, probe=None):
    """Flush fixed lifecycle labels and bounded counters, never client payloads."""
    progress = {'canaryPhase': phase}
    if probe is not None:
        progress.update(initialized=probe.initialized, running=probe.running,
                        providerRequests=probe.requests, responseHeld=probe.held,
                        responseReleased=probe.release.is_set(), witnessComplete=probe.complete.is_set())
    print(json.dumps(progress), file=sys.stderr, flush=True)


def has_adapter_cleanup_failure(error):
    """Retain scratch when timeout conversion wraps an unconfirmed actor cleanup."""
    pending, seen = [error] if error is not None else [], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        if len(seen) == 16:
            return True  # Unusually deep causal state cannot justify deleting scratch.
        seen.add(id(current))
        if (str(current) == 'reattach_actor_cleanup_failed'
                or 'reattach_actor_cleanup_failed' in getattr(current, '__notes__', ())):
            return True
        pending.extend(link for link in (current.__cause__, current.__context__) if link is not None)
    return False


async def canary(binary, root, key, model, local_port=None, hosted_repository_id=None, *, busy_probe=False,
                 adapter_reattach_probe=False):
    """Run the selected bounded synthetic experiment; every success criterion is observed."""
    require(not busy_probe or local_port is not None, 'busy_probe_requires_local_provider')
    require(not adapter_reattach_probe or busy_probe and local_port is not None,
            'reattach_probe_requires_busy_local_provider')
    if hosted_repository_id is not None:
        require(local_port is not None, 'hosted_vm_requires_local_provider')
        admit_hosted_vm(os.environ, hosted_repository_id)
    session_id, marker = str(uuid4()), uuid4().hex
    child = None
    server = provider = None
    observer = None
    observer_error = None
    reattach_proof = None
    expected_turns = 3 if adapter_reattach_probe else 2
    initial = {'type': 'user', 'session_id': session_id,
               'message': {'role': 'user', 'content': 'Begin the synthetic transport test.'}}
    probe = None
    if busy_probe:
        initial['uuid'] = str(uuid4())
        probe = (ReattachProbe if adapter_reattach_probe else BusyProbe)(session_id, initial, 'READY_' + marker)
    for name in ('home', 'config', 'tmp', 'work'):
        (root / name).mkdir(mode=0o700)
    report_progress('preparing', probe=probe)
    try:
        async with asyncio.timeout(RUN_SECONDS):
            command = child_command(binary, root, session_id, model, marker, busy_probe=busy_probe)
            if local_port is not None:
                profile = root / 'child.sb'
                profile.write_text(hosted_network_profile(root, local_port, hosted_repository_id)
                                   if hosted_repository_id is not None
                                   else sandbox_profile(binary, root, local_port))
                provider = (ReattachProvider if adapter_reattach_probe else LocalProvider)(key, model, probe=probe)
                report_progress('provider_starting', probe=probe)
                server = await asyncio.start_server(provider.handle, '127.0.0.1', local_port,
                                                    limit=16384, reuse_address=False)
                command = ['/usr/bin/sandbox-exec', '-f', str(profile), *command]
            report_progress('child_spawning', probe=probe)
            child = await asyncio.create_subprocess_exec(
                *command,
                env=child_environment(root, key, local_port, busy_probe=busy_probe), cwd=root / 'work',
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, close_fds=True, limit=65536)
            report_progress('child_spawned', probe=probe)
            state = {'bytes': 0, 'initialized': False}
            if probe:
                observer = asyncio.create_task(observe_busy_stdout(child.stdout, probe))
            child.stdin.write((json.dumps(initial) + '\n').encode())
            await child.stdin.drain()
            report_progress('waiting_initial_witness', probe=probe)
            if probe:
                await wait_busy_witness(probe.ready_to_send, observer, probe)
            else:
                await completed_turn(child.stdout, session_id, 'READY_' + marker, state)
                await asyncio.sleep(1)
            report_progress('initial_witness_observed', probe=probe)
            require(child.returncode is None, 'client_exited_before_wake')
            wake_marker = ('BUSY_' if probe else 'WAKE_') + uuid4().hex
            socket_path = root / 'inbox.sock'
            info = socket_path.lstat()
            require(stat.S_ISSOCK(info.st_mode), 'child_inbox_unavailable')
            transport_options = dict(socket_path=str(socket_path),
                socket_identity=(info.st_dev, info.st_ino), peer_pid=child.pid,
                session_id=session_id, token=child_peer_token(root, child.pid),
                version=SUPPORTED_VERSION, journal_dir=root / 'journal')
            transport = ClaudeSocketTransport(**transport_options)
            metadata = {'eventId': str(uuid4()), 'deliveryId': 'dly_' + hashlib.sha256(wake_marker.encode()).hexdigest(),
                        'source': 'manual', 'sourceStateVersion': 'canary-1',
                        'canonicalSubject': {'kind': 'manual', 'subjectId': wake_marker},
                        'eventReference': 'ref_' + str(uuid4())}
            if probe:
                probe.prepare(event_frame(session_id, metadata))
            report_progress('socket_sending', probe=probe)
            if adapter_reattach_probe:
                fresh_marker = 'FRESH_' + uuid4().hex
                fresh = metadata | {'eventId': str(uuid4()),
                    'deliveryId': 'dly_' + hashlib.sha256(fresh_marker.encode()).hexdigest(),
                    'canonicalSubject': {'kind': 'manual', 'subjectId': fresh_marker},
                    'eventReference': 'ref_' + str(uuid4())}

                async def prepare_fresh():
                    require(child.returncode is None, 'client_exited_during_reattach')
                    # Reuse the retained native process and original socket binding.
                    transport._check_socket()
                    await wait_busy_witness(probe.ready_to_send, observer, probe)
                    probe.sent()
                    probe.release_response()
                    await wait_busy_witness(probe.first_pair_complete, observer, probe)
                    require(child.returncode is None, 'client_exited_during_reattach')
                    transport._check_socket()
                    probe.prepare_fresh(event_frame(session_id, fresh))

                outcome, reattach_proof = await adapter_reattach(transport_options, metadata, fresh,
                    before_fresh=prepare_fresh, record=probe.record,
                    crash_point='after-write-close-before-result')
                require(child.returncode is None, 'client_exited_during_reattach')
                transport._check_socket()
            else:
                outcome = await transport.send(metadata)
            report_progress('socket_sent', probe=probe)
            require(outcome['reason'] == 'claude_write_unacknowledged', 'socket_write_unconfirmed')
            if probe:
                if adapter_reattach_probe:
                    probe.fresh_sent()
                else:
                    await wait_busy_witness(probe.ready_to_send, observer, probe)
                    probe.sent()
                    probe.release_response()
                report_progress('waiting_final_witness', probe=probe)
                await wait_busy_witness(probe.complete, observer, probe)
            else:
                await completed_turn(child.stdout, session_id, wake_marker, state)
            require(provider is None or provider.turns == expected_turns and not provider.failure,
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
                proof['busyProbe'] = probe.initial_busy_proof if adapter_reattach_probe else probe.proof()
                proof['busyProbe']['retainedChildPid'] = child.pid
            if reattach_proof is not None:
                proof.update(scope='disposable-headless-same-live-session-adapter-reattach',
                             adapterReattach=reattach_proof, sameLiveSessionAdapterRecoveryObserved=True,
                             reattachProbe=probe.proof())
    except TimeoutError:
        report_progress('run_timeout', probe=probe)
        raise
    finally:
        primary_error = sys.exception()
        cleanup_failed = has_adapter_cleanup_failure(primary_error)
        report_progress('stopping_child', probe=probe)
        try:
            if child is not None:
                await stop_child(child)
        except (Exception, asyncio.CancelledError) as error:
            cleanup_failed = True
            report_progress('child_cleanup_failed', probe=probe)
            if primary_error is None:
                primary_error = error
                raise
            primary_error.add_note('child_cleanup_failed')
        finally:
            if observer is not None:
                try:
                    await asyncio.wait_for(observer, 1)
                except CanaryError as error:
                    observer_error = error
                except (Exception, asyncio.CancelledError):
                    observer_error = CanaryError('busy_native_observation_failed')
            report_progress('closing_provider', probe=probe)
            try:
                await close_local_provider(server, provider)
            except (Exception, asyncio.CancelledError):
                cleanup_failed = True
                report_progress('cleanup_failed', probe=probe)
                if primary_error is None:
                    raise
                primary_error.add_note('local_provider_cleanup_failed')
            else:
                if not cleanup_failed:
                    report_progress('cleanup_complete', probe=probe)
        if hosted_repository_id is None and not cleanup_failed:
            shutil.rmtree(root)
    # Pending requests can fail while the child/server/provider are shutting down.
    # Only settled provider state may authorize returning the selected proof.
    require(provider is None or provider.turns == expected_turns and not provider.failure,
            'local_provider_incomplete')
    if observer_error is not None:
        raise observer_error
    if probe:
        # Include any final observations drained while the retained child stopped.
        proof['busyProbe'] = (probe.initial_busy_proof if adapter_reattach_probe else probe.proof()) | {
            'retainedChildPid': child.pid}
        if adapter_reattach_probe:
            proof['reattachProbe'] = probe.proof() | {'retainedChildPid': child.pid}
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
    parser.add_argument('--adapter-reattach-probe', action='store_true',
                        help='Kill/restart only the adapter after write close; three synthetic turns')
    parser.add_argument('--local-port', type=int, default=43231)
    parser.add_argument('--trusted-hosted-vm', action='store_true',
                        help='Reviewed client on a fresh private GitHub-hosted macOS VM only')
    parser.add_argument('--hosted-repository-id')
    parser.add_argument('--private-output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require(not args.busy_probe or args.local_provider, 'busy_probe_requires_local_provider')
        require(not args.adapter_reattach_probe or args.busy_probe and args.local_provider,
                'reattach_probe_requires_busy_local_provider')
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
                                  busy_probe=args.busy_probe, adapter_reattach_probe=args.adapter_reattach_probe))
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
