#!/usr/bin/env python3
"""Opt-in, dedicated-key Claude idle-wake canary. Never reads owner credentials."""

import argparse
import asyncio
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from uuid import uuid4

from event_gateway.claude import ClaudeSocketTransport, SUPPORTED_VERSION
from event_gateway.client_runtime import _private_json
from event_gateway.security import ensure_private_directory

CLIENT_SHA256 = '5262ce9de86243fed0d21edc39b271555d56780d0112e2b194439fe1c6662d37'
RUN_SECONDS = 90
MAX_STREAM_BYTES = 1024 * 1024


class CanaryError(RuntimeError):
    """Safe failure code without any child output or credential."""


def require(condition, code):
    """Fail closed without rendering arbitrary child data."""
    if not condition:
        raise CanaryError(code)


def child_command(binary, root, session_id, model, marker):
    """Fixed no-tools session, explicit configuration sources and spend guard."""
    return [str(binary), '--bare', '--print', '--verbose', '--input-format', 'stream-json',
            '--output-format', 'stream-json', '--tools', '', '--disable-slash-commands',
            '--setting-sources', '', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
            '--no-session-persistence', '--session-id', session_id,
            '--messaging-socket-path', str(root / 'inbox.sock'), '--model', model,
            '--max-budget-usd', '0.10', '--system-prompt',
            f'This is a synthetic no-tools transport test. For the initial input reply exactly READY_{marker}. '
            'For a synthetic event, reply exactly with its canonicalSubject.subjectId. '
            'Do not access any source or take any other action.']


def child_environment(root, key):
    """Only a deliberately supplied API key enters the fresh client environment."""
    return {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'home'),
            'CLAUDE_CONFIG_DIR': str(root / 'config'), 'TMPDIR': str(root / 'tmp'),
            'TERM': 'dumb', 'LANG': 'en_US.UTF-8', 'ANTHROPIC_API_KEY': key}


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


async def canary(binary, root, key, model):
    """Run exactly two synthetic turns; every success criterion is observed."""
    session_id, marker = str(uuid4()), uuid4().hex
    child = None
    for name in ('home', 'config', 'tmp', 'work'):
        (root / name).mkdir(mode=0o700)
    try:
        async with asyncio.timeout(RUN_SECONDS):
            child = await asyncio.create_subprocess_exec(
                *child_command(binary, root, session_id, model, marker),
                env=child_environment(root, key), cwd=root / 'work',
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, close_fds=True, limit=65536)
            state = {'bytes': 0, 'initialized': False}
            initial = {'type': 'user', 'session_id': session_id,
                       'message': {'role': 'user', 'content': 'Begin the synthetic transport test.'}}
            child.stdin.write((json.dumps(initial) + '\n').encode())
            await child.stdin.drain()
            await completed_turn(child.stdout, session_id, 'READY_' + marker, state)
            await asyncio.sleep(1)
            require(child.returncode is None, 'client_exited_before_wake')
            wake_marker = 'WAKE_' + uuid4().hex
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
            outcome = await transport.send(metadata)
            require(outcome['reason'] == 'claude_write_unacknowledged', 'socket_write_unconfirmed')
            await completed_turn(child.stdout, session_id, wake_marker, state)
            return {'schemaVersion': 1, 'scope': 'disposable-headless-idle-wake',
                    'clientSha256': CLIENT_SHA256, 'clientVersion': SUPPORTED_VERSION,
                    'readyTurnObserved': True, 'idleIntervalObserved': True,
                    'socketWriteClosedGracefully': True, 'matchingWakeTurnObserved': True,
                    'stdinWakeWritten': False, 'productionQualified': False,
                    'nativeReceiptV3Proven': False}
    finally:
        if child is not None:
            await stop_child(child)
        shutil.rmtree(root)


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
    parser.add_argument('--private-output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require(sys.stdin.isatty(), 'interactive_dedicated_key_required')
        binary = args.binary.resolve(strict=True)
        require(binary.is_file() and hashlib.sha256(binary.read_bytes()).hexdigest() == CLIENT_SHA256,
                'client_digest_mismatch')
        output = args.private_output.absolute()
        ensure_private_directory(output.parent)
        require(not os.path.lexists(output), 'proof_already_exists')
        key = getpass.getpass('Dedicated canary API key (up to $0.10 client budget; hidden): ')
        require(bool(key) and not any(char.isspace() for char in key), 'invalid_dedicated_key')
        temp_root = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'  # nosec B108
        root = Path(tempfile.mkdtemp(prefix='cq-', dir=temp_root)).resolve()
        proof = asyncio.run(canary(binary, root, key, args.model))
        publish_proof(output, proof)
        print(json.dumps({'canary': 'observed', 'productionQualified': False}))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error) if isinstance(error, CanaryError) else (
            'canary_timeout' if isinstance(error, TimeoutError) else 'canary_local_or_client_failure')
        print(json.dumps({'canary': 'incomplete', 'reason': reason,
                          'productionQualified': False}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
