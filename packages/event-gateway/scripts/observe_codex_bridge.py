"""Disposable stock-TUI observation, never a presence verifier. See codex-bridge-spike.md."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import pty
import shutil
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
                   'thread/resume thread/list thread/loaded/list thread/turns/list '
                   'thread/unsubscribe skills/list plugin/list'.split())


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


async def observe(binary, root):
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
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

    def launch(name, thread):
        if name in peers:
            raise ValueError('use a new client name for each launch')
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 120, 0, 0))
        args = [] if thread == 'new' else ['resume', thread]
        process = subprocess.Popen([str(binary), *flags, *args, '--remote',
                                    f'unix://{root}/proxy.sock', '--no-alt-screen', '-C', str(root)],
                                   env=env, cwd=root, stdin=slave, stdout=slave, stderr=slave,
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
        asyncio.create_task(drain())

    try:
        back = await backend()
        async with unix_serve(proxy, str(root / 'proxy.sock'), max_size=4194304, max_queue=8):
            print('Commands: launch NAME new|UUID; send NAME ESCAPED_KEYS; read NAME; '
                  'kill NAME; restart; mark CASE; quit', flush=True)
            while True:
                try:
                    parts = (await asyncio.to_thread(input)).split(' ', 2)
                except EOFError:
                    break
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
                elif command == 'restart':
                    stop(back)
                    back = await backend()
                elif command == 'mark':
                    record(0, parts[1], {})
    finally:
        for process in children:
            stop(process)
        for _, descriptor in peers.values():
            os.close(descriptor)
        for socket, identity in sockets.items():
            if socket.exists():
                stat = socket.stat()
                if (stat.st_dev, stat.st_ino) == identity:
                    socket.unlink()
        for alias in ('backend.sock', 'proxy.sock'):
            (root / alias).unlink(missing_ok=True)
        shutil.rmtree(home)
        log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    if args.self_check:
        check()
    else:
        if not args.binary or not args.binary.is_absolute() or not args.binary.is_file():
            parser.error('--binary must be an absolute executable path')
        scratch = Path(tempfile.mkdtemp(prefix='codex-bridge-', dir='/private/tmp' if Path('/private/tmp').exists() else '/tmp'))
        print(f'Private evidence: {scratch}', flush=True)
        print(f'Binary: {args.binary.resolve()} SHA256: {hashlib.sha256(args.binary.read_bytes()).hexdigest()}', flush=True)
        asyncio.run(observe(args.binary, scratch))
