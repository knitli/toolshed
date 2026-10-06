"""Disposable stock-TUI observation, never a presence verifier. See codex-bridge-spike.md."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import pty
import shutil
import signal
import time
from uuid import UUID
import struct
import subprocess
import tempfile
import termios
import fcntl

from websockets.asyncio.client import unix_connect
from websockets.asyncio.server import unix_serve

# Only the no-turn methods needed by the observed 0.160.0 TUI are forwarded.
METHODS = frozenset('initialize initialized account/read config/read hooks/list model/list '
                   'configRequirements/read collaborationMode/list thread/start thread/read '
                   'thread/resume thread/list thread/loaded/list thread/turns/list thread/name/set '
                   'thread/unsubscribe skills/list plugin/list server/diagnostics'.split())


def permitted(direction, message):
    if direction == 'client':
        return message.get('method') in METHODS
    return not ('method' in message and 'id' in message)  # No server requests/approvals.


def metadata(message):
    params, result = message.get('params') or {}, message.get('result') or {}
    thread = params.get('thread') or result.get('thread') or {}
    return {'method': message.get('method'), 'rpcId': message.get('id'),
            'threadId': params.get('threadId') or params.get('thread_id') or thread.get('id')}


def check():
    assert metadata({'id': 1, 'result': {'thread': {'id': 't', 'prompt': 'SECRET'}}}) == {
        'method': None, 'rpcId': 1, 'threadId': 't'}
    assert permitted('client', {'method': 'thread/start'})
    for method in ['turn/start', 'thread/queue/start', 'thread/queue/add', 'config/batchWrite']:
        assert not permitted('client', {'method': method})
    assert not permitted('client', {'id': 1, 'result': {'approved': True}})
    assert not permitted('server', {'id': 1, 'method': 'item/commandExecution/requestApproval'})
    print('metadata and no-turn guard checks passed')


class Witness:
    """Disposable fail-closed observation lease, never production authority."""

    def __init__(self):
        self.row = None
        self.seen = 0.0
        self.client_id = None
        self.sequence = 0
        self.reason = 'unavailable'

    def receive(self, raw, backend_pid, now):
        self.row = None
        self.reason = 'malformed'
        try:
            row = json.loads(raw)
            fields = {'clientId', 'backendPid', 'connectionId', 'threadId',
                      'generation', 'eligible', 'sequence', 'cause'}
            if not isinstance(row, dict) or set(row) != fields:
                return
            for field in ('clientId', 'connectionId', 'threadId'):
                value = row[field]
                if value is None and field != 'clientId':
                    continue
                if not isinstance(value, str) or str(UUID(value)) != value:
                    return
            if (type(row['eligible']) is not bool
                    or type(row['generation']) is not int or row['generation'] < 0
                    or type(row['sequence']) is not int or row['sequence'] <= self.sequence
                    or not isinstance(row['cause'], str) or len(row['cause']) > 128
                    or (row['backendPid'] is not None and type(row['backendPid']) is not int)
                    or (self.client_id is not None and row['clientId'] != self.client_id)):
                return
            self.client_id = row['clientId']
            self.sequence = row['sequence']
            self.row, self.seen = row, now
            self.reason = 'native'
        except (ValueError, TypeError, UnicodeError):
            return
        self.status(backend_pid, now)

    def status(self, backend_pid, now):
        if self.row is None:
            return False, self.reason
        if backend_pid is None or self.row['backendPid'] != backend_pid:
            return False, 'unknown-backend'
        if now - self.seen >= 1.0:
            return False, 'expired'
        if self.row['connectionId'] is None or self.row['threadId'] is None:
            return False, 'unavailable'
        return self.row['eligible'], 'native'

    def eof(self):
        self.row = None
        self.reason = 'eof'


def witness_frames(pending, data, discarding):
    """Bound individual JSON lines; an empty frame revokes a malformed lease."""
    if discarding:
        if b'\n' not in data:
            return b'', True, []
        _, data = data.split(b'\n', 1)
    pending += data
    frames = []
    while b'\n' in pending:
        raw, pending = pending.split(b'\n', 1)
        frames.append(raw if len(raw) <= 4096 else b'')
    discarding = len(pending) > 4096
    if discarding:
        frames.append(b'')
        pending = b''
    return pending, discarding, frames


async def read_witness(descriptor, backend_pid, client_alive, emit):
    witness, pending, previous = Witness(), b'', None
    discarding = connected = False
    while True:
        pid, now = backend_pid(), time.monotonic()
        changed = False
        try:
            data = os.read(descriptor, 4096)
        except BlockingIOError:
            data = None
            connected = True  # A writer exists, but has no bytes ready.
        if data == b'':
            witness.eof()
            if connected or not client_alive():
                emit(witness, pid, now)
                return
            # A nonblocking FIFO reports EOF before the child opens its writer.
        elif data:
            connected = True
            pending, discarding, frames = witness_frames(pending, data, discarding)
            for raw in frames:
                witness.receive(raw, pid, now)
                emit(witness, pid, now)
                changed = True
        state = witness.status(pid, now)
        if state != previous and not changed:
            emit(witness, pid, now)
        previous = state
        await asyncio.sleep(.025)


async def observe(binary, root, client_binary=None):
    home = root / 'home'
    home.mkdir(mode=0o700)
    (home / 'config.toml').write_text(f'[projects.{json.dumps(str(root))}]\ntrust_level = "trusted"\n')
    flags = ['-c', 'check_for_update_on_startup=false', '-c', 'model_provider="bridge"',
             '-c', 'model_providers.bridge.name="Bridge observation"',
             '-c', 'model_providers.bridge.base_url="http://127.0.0.1:9"',
             '-c', 'model_providers.bridge.wire_api="responses"',
             '-c', 'model_providers.bridge.requires_openai_auth=false']
    env = {'PATH': os.defpath, 'HOME': str(root), 'CODEX_HOME': str(home), 'TERM': 'xterm-256color'}
    children, peers, ui, sockets = [], {}, {}, {}
    order = connection = 0
    owned_connections, fifo_paths, fifo_fds, tasks = set(), [], [], []
    back = None
    native_log = (root / 'native.jsonl').open('w') if client_binary else None
    log = (root / 'wire.jsonl').open('w')

    def record(channel, direction, message):
        nonlocal order
        order += 1
        row = {'order': order, 'connection': channel, 'direction': direction, **metadata(message)}
        log.write(json.dumps(row) + '\n')
        log.flush()
        print(json.dumps(row), flush=True)

    async def proxy(front):
        nonlocal connection
        connection += 1
        channel = connection
        record(channel, 'open', {})
        owned_connections.add(front)
        try:
            async with unix_connect(str((root / 'backend.sock').resolve()), max_size=4194304,
                                    max_queue=8) as back:
                async def pump(source, target, direction):
                    async for raw in source:
                        message = json.loads(raw)
                        record(channel, direction, message)
                        if not permitted(direction, message):
                            print('Blocked non-observation RPC; closing connection', flush=True)
                            return
                        await target.send(raw)
                tasks = [asyncio.create_task(pump(front, back, 'client')),
                         asyncio.create_task(pump(back, front, 'server'))]
                try:
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, TimeoutError):
            pass  # Expected while the dedicated backend is restarting.
        finally:
            owned_connections.discard(front)
            record(channel, 'close', {})

    async def backend():
        process = subprocess.Popen([str(binary), *flags, 'app-server', '--listen',
                                    f'unix://{root}/backend.sock'], env=env, cwd=root,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        children.append(process)
        async with asyncio.timeout(10):
            while not (root / 'backend.sock').exists():
                if process.poll() is not None:
                    raise RuntimeError('private backend exited')
                await asyncio.sleep(.05)
        socket = (root / 'backend.sock').resolve()
        stat = socket.stat()
        sockets[socket] = stat.st_dev, stat.st_ino
        return process

    def stop(process):
        if process.poll() is None:
            process.send_signal(signal.SIGCONT)
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

    def launch(name, thread):
        if name in peers:
            raise ValueError('use a new client name for each launch')
        child_env = dict(env)
        if client_binary:
            fifo = root / f'witness-{len(fifo_paths)}.fifo'
            os.mkfifo(fifo, 0o600)
            fifo_paths.append(fifo)
            descriptor = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            fifo_fds.append(descriptor)
            child_env['CODEX_SELECTION_WITNESS_PIPE'] = str(fifo)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 120, 0, 0))
        args = [] if thread == 'new' else ['resume', thread]
        process = subprocess.Popen([str(client_binary or binary), *flags, *args, '--remote',
                                    f'unix://{root}/proxy.sock', '--no-alt-screen', '-C', str(root)],
                                   env=child_env, cwd=root, stdin=slave, stdout=slave, stderr=slave,
                                   start_new_session=True)
        children.append(process)
        os.close(slave)
        os.set_blocking(master, False)
        peers[name] = process, master

        async def drain():
            # Bounded transient terminal state; never persist terminal transcripts.
            while process.poll() is None:
                try:
                    ui[name] = (ui.get(name, '') + os.read(master, 65536).decode(errors='replace'))[-24000:]
                except (BlockingIOError, OSError):
                    pass
                await asyncio.sleep(.05)
        tasks.append(asyncio.create_task(drain()))
        if client_binary:
            last_native_state = None

            def emit(witness, pid, now):
                nonlocal order, last_native_state
                order += 1
                eligible, reason = witness.status(pid, now)
                row = {'order': order, 'client': name, **(witness.row or {}),
                       'sinkEligible': eligible, 'sinkCause': reason, 'observedMonotonic': now}
                native_log.write(json.dumps(row) + '\n')
                native_log.flush()
                state = {key: value for key, value in row.items()
                         if key not in ('order', 'sequence', 'cause', 'observedMonotonic')}
                if row.get('cause') != 'heartbeat' or state != last_native_state:
                    print(json.dumps(row), flush=True)
                last_native_state = state

            tasks.append(asyncio.create_task(read_witness(
                descriptor, lambda: back.pid if back is not None and back.poll() is None else None,
                lambda: process.poll() is None, emit)))

    try:
        back = await backend()
        async with unix_serve(proxy, str(root / 'proxy.sock'), max_size=4194304, max_queue=8):
            print('Commands: launch NAME new|UUID; send NAME ESCAPED_KEYS; read NAME; '
                  'kill NAME; suspend NAME; continue NAME; disconnect; restart; mark CASE; quit', flush=True)
            while True:
                try:
                    parts = (await asyncio.to_thread(input)).split(' ', 2)
                except EOFError:
                    break
                try:
                    command = parts[0]
                    if command == 'quit':
                        break
                    if command == 'launch':
                        launch(parts[1], parts[2])
                    elif command == 'send':
                        os.write(peers[parts[1]][1], parts[2].encode().decode('unicode_escape').encode())
                    elif command == 'read':
                        print(repr(ui.pop(parts[1], '')), flush=True)
                    elif command == 'kill':
                        peers[parts[1]][0].kill()
                    elif command in ('suspend', 'continue'):
                        peers[parts[1]][0].send_signal(
                            signal.SIGSTOP if command == 'suspend' else signal.SIGCONT)
                    elif command == 'disconnect':
                        await asyncio.gather(*(connection.close() for connection in tuple(owned_connections)))
                    elif command == 'restart':
                        stop(back)
                        back = await backend()
                    elif command == 'mark':
                        record(0, parts[1], {})
                    else:
                        raise ValueError('unknown command')
                except (IndexError, KeyError, ValueError):
                    print('Invalid command or client name. Use: launch NAME new|UUID; '
                          'send NAME ESCAPED_KEYS; read NAME; kill NAME; suspend NAME; continue NAME; disconnect; restart; '
                          'mark CASE; quit', flush=True)
    finally:
        try:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for descriptor in fifo_fds:
                os.close(descriptor)
            for fifo in fifo_paths:
                fifo.unlink(missing_ok=True)
            for process in children:
                stop(process)
            for _, descriptor in peers.values():
                os.close(descriptor)
            for socket, identity in sockets.items():
                try:
                    stat = socket.stat()
                    if (stat.st_dev, stat.st_ino) == identity:
                        socket.unlink(missing_ok=True)
                except FileNotFoundError:
                    pass  # The owned backend may already have removed its socket.
            for alias in ('backend.sock', 'proxy.sock'):
                (root / alias).unlink(missing_ok=True)
            shutil.rmtree(home)
        finally:
            try:
                if native_log:
                    native_log.close()
            finally:
                log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--client-binary', type=Path)
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    if args.self_check:
        check()
    else:
        if not args.binary or not args.binary.is_absolute() or not args.binary.is_file():
            parser.error('--binary must be an absolute executable path')
        if args.client_binary and (not args.client_binary.is_absolute() or not args.client_binary.is_file()):
            parser.error('--client-binary must be an absolute executable path')
        scratch = Path(tempfile.mkdtemp(prefix='codex-bridge-', dir='/private/tmp' if Path('/private/tmp').exists() else '/tmp'))
        print(f'Private evidence: {scratch}', flush=True)
        print(f'Binary: {args.binary.resolve()} SHA256: {hashlib.sha256(args.binary.read_bytes()).hexdigest()}', flush=True)
        asyncio.run(observe(args.binary, scratch, args.client_binary))
