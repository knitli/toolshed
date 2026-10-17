"""Explicit opt-in only; independent Docker inventory/cleanup is required after every run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import subprocess  # nosec B404 - Fixed, hash-verified executables only; no shell.
import tempfile
import time

ROOT = Path('/private/tmp/reviewer-docker-sdk-integration-20261017')
NODE = Path('/Users/adampoulemanos/.local/share/mise/installs/node/24.21.0/bin/node')
DOCKER = Path('/usr/local/bin/docker')
DOCKER_REAL = Path('/Applications/Docker.app/Contents/Resources/bin/docker')
SANDBOX = Path('/usr/bin/sandbox-exec')
ADAPTER = Path('/private/tmp/reviewer-docker-sdk-adapter-20261017/adapter.mjs')
CHILD = ADAPTER.parent / 'fixture/protocol-child.py'
PROTOCOL = Path('/private/tmp/reviewer-sdk-process-protocol-20261017/frozen')
PINNED = {
    str(PROTOCOL / 'sdk.mjs'): '7b3577a1078660a3ec43471e6738c730ca1b172070ddcf3f9a9384bcb68bd3ca',
    str(PROTOCOL / 'reviewer-completion-driver.mjs'): '4ff7c66588d16f33f67ca89670b5efe4540170bf5708d28cea7b19a2d0298eee',
    str(CHILD): 'f5d7ae681045266d2b9f2d806beee8b07c0f527f4feffd523037076c3d9d4cd6',
}
LIMIT = 1024 * 1024
TIMEOUT = 240


def physical(path, directory=False, private=False):
    info = path.lstat()
    if path.resolve() != path or info.st_uid != os.getuid():
        raise RuntimeError('Nonphysical or unowned path: ' + str(path))
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise RuntimeError('Unexpected file type: ' + str(path))
    if info.st_mode & 0o022 or (private and stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError('Unsafe permissions: ' + str(path))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_inputs():
    if Path(__file__).resolve() != ROOT / 'launch.py':
        raise RuntimeError('Fixed launcher location required')
    physical(ROOT, directory=True, private=True)
    physical(ROOT / 'manifest.json')
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    if not {'launch.py', 'profile.sb', 'fixture.mjs'} <= set(manifest['files']):
        raise RuntimeError('Incomplete local file manifest')
    for name, expected in manifest['files'].items():
        path = ROOT / name
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise RuntimeError('Unsafe local manifest path')
        physical(path)
        if digest(path) != expected:
            raise RuntimeError('Local hash mismatch: ' + name)
    external = manifest['dependencies']
    if set(external) != set(PINNED) | {str(ADAPTER)}:
        raise RuntimeError('Unexpected external read closure')
    for name, expected in external.items():
        path = Path(name)
        physical(path)
        if expected != PINNED.get(name, expected) or digest(path) != expected:
            raise RuntimeError('External hash mismatch: ' + name)
    for key, path, real in [('node', NODE, NODE), ('docker', DOCKER, DOCKER_REAL),
                            ('sandbox', SANDBOX, SANDBOX)]:
        record = manifest[key]
        if record['path'] != str(path) or record.get('realpath', record['path']) != str(real) or path.resolve() != real:
            raise RuntimeError('Executable path drift: ' + key)
        info = real.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise RuntimeError('Unsafe executable: ' + key)
        if digest(real) != record['sha256']:
            raise RuntimeError('Executable hash drift: ' + key)
    socket = Path('/Users/adampoulemanos/.docker/run/docker.sock')
    info = socket.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or socket.resolve() != socket:
        raise RuntimeError('Untrusted Docker socket')
    return manifest


def run_process(argv, scratch, env, streams, state):
    process = None
    primary_failure = None
    try:
        process = subprocess.Popen(  # nosec B603 - Fixed hash-verified executable, closed argv/environment.
            argv, cwd=scratch, env=env, close_fds=True, shell=False,
            start_new_session=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + TIMEOUT
        total = 0
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError('Fixture timeout')
                for key, _ in selector.select(min(remaining, 1)):
                    part = os.read(key.fileobj.fileno(), min(4096, LIMIT - total + 1))
                    if not part:
                        selector.unregister(key.fileobj)
                        continue
                    available = LIMIT - total
                    streams[key.data].extend(part[:available])
                    total += min(len(part), available)
                    if len(part) > available:
                        raise RuntimeError('Aggregate output limit; capture truncated')
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code != 0:
            raise RuntimeError('Fixture failed: ' + str(code))
        result = json.loads(streams['stdout'])
        if not isinstance(result, dict) or result.get('status') != 'PASS':
            raise RuntimeError('Expected one PASS JSON document on stdout')
    except BaseException as error:
        primary_failure = error
        raise
    finally:
        if process is not None:
            try:
                try:
                    # An unreaped leader reserves its PID; never signal a reaped group ID.
                    if process.returncode is None:
                        if process.pid <= 1 or process.pid == os.getpgrp() or os.getpgid(process.pid) != process.pid:
                            raise RuntimeError('Refusing cleanup of unowned process group')
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=3)
                    state["exitCode"] = process.returncode
                finally:
                    process.stdout.close()
                    process.stderr.close()
            except BaseException as error:
                state["cleanupFailure"] = {"name": type(error).__name__, "message": str(error)[:1000]}
                if primary_failure is None:
                    raise


def cleanup_canary(canary, canary_status):
    boundary_error = None
    if canary is not None:
        try:
            if canary_status['beforeSha256'] is not None:
                physical(canary)
                canary_status['afterSha256'] = digest(canary)
                canary_status['preserved'] = canary_status['beforeSha256'] == canary_status['afterSha256']
                if not canary_status['preserved']:
                    raise RuntimeError('Outside-scratch canary changed')
        except BaseException as error:
            canary_status['verificationFailure'] = {'name': type(error).__name__, 'message': str(error)[:1000]}
            boundary_error = error
        finally:
            try:
                canary.unlink()
                canary_status['removed'] = True
            except BaseException as error:
                canary_status['cleanupFailure'] = {'name': type(error).__name__, 'message': str(error)[:1000]}
                if boundary_error is None:
                    boundary_error = error
    return boundary_error


def cleanup_socket(forbidden_listener, forbidden_socket, socket_status):
    boundary_error = None
    if forbidden_listener is not None:
        try:
            forbidden_listener.close()
            socket_status['closed'] = True
        except BaseException as error:
            socket_status['cleanupFailures'].append({'name': type(error).__name__, 'message': str(error)[:1000]})
            if boundary_error is None:
                boundary_error = error
    if socket_status['identity'] is not None:
        try:
            info = forbidden_socket.lstat()
            identity = {key: getattr(info, 'st_' + key) for key in ('dev', 'ino', 'mode', 'uid')}
            if identity != socket_status['identity'] or forbidden_socket.resolve() != forbidden_socket:
                raise RuntimeError('Forbidden socket identity changed; refusing unlink')
            forbidden_socket.unlink()
            socket_status['removed'] = True
        except BaseException as error:
            socket_status['cleanupFailures'].append({'name': type(error).__name__, 'message': str(error)[:1000]})
            if boundary_error is None:
                boundary_error = error
    return boundary_error


def main():
    if Path(__file__).absolute() != ROOT / 'launch.py' or Path(__file__).resolve() != ROOT / 'launch.py':
        raise RuntimeError('historical fixture path; rerender and qualify at new owned location')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    if not parser.parse_args().run:
        parser.error('explicit --run required after profile and manifest review')
    physical(ROOT, directory=True, private=True)
    os.umask(0o077)
    evidence = Path(tempfile.mkdtemp(prefix='capture-', dir=ROOT))
    print('Capture directory: ' + str(evidence), flush=True)
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    failure = None
    process_state = {"exitCode": None}
    scratch = None
    canary = None
    canary_status = {'beforeSha256': None, 'afterSha256': None, 'preserved': None,
                     'verificationFailure': None, 'cleanupFailure': None, 'removed': False}
    boundary_error = None
    forbidden_listener = None
    forbidden_socket = None
    socket_status = {'identity': None, 'closed': False, 'removed': False, 'cleanupFailures': []}
    try:
        verify_inputs()
        scratch = Path(tempfile.mkdtemp(prefix='scratch-', dir=ROOT))
        physical(scratch, directory=True, private=True)
        (scratch / 'fixture').mkdir(mode=0o755)
        (scratch / 'fixture').chmod(0o755)
        child = scratch / 'fixture/protocol-child.py'
        child.write_bytes(CHILD.read_bytes())
        child.chmod(0o644)
        if digest(child) != PINNED[str(CHILD)]:
            raise RuntimeError('Staged child hash mismatch')
        for name in ('tmp', 'claude', 'xdg', 'docker'):
            (scratch / name).mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(scratch), 'TMPDIR': str(scratch / 'tmp'),
               'CLAUDE_CONFIG_DIR': str(scratch / 'claude'), 'XDG_CONFIG_HOME': str(scratch / 'xdg'),
               'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'CLAUDE_CODE_DISABLE_AUTO_MEMORY': '1',
               'DISABLE_TELEMETRY': '1', 'DO_NOT_TRACK': '1', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
        canary_path = ROOT / ('canary-' + os.urandom(16).hex())
        canary_fd = os.open(canary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        canary = canary_path
        with os.fdopen(canary_fd, 'wb') as output:
            output.write(os.urandom(32))
        canary_status['beforeSha256'] = digest(canary)
        forbidden_socket = ROOT / ('forbidden-' + os.urandom(16).hex() + '.sock')
        if len(os.fsencode(forbidden_socket)) >= 104:
            raise RuntimeError('Forbidden Unix socket path exceeds Darwin limit')
        forbidden_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        forbidden_listener.bind(str(forbidden_socket))
        info = forbidden_socket.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or forbidden_socket.resolve() != forbidden_socket:
            raise RuntimeError('Untrusted forbidden socket identity')
        socket_status['identity'] = {key: getattr(info, 'st_' + key) for key in ('dev', 'ino', 'mode', 'uid')}
        forbidden_listener.listen(1)
        argv = [str(SANDBOX), '-f', str(ROOT / 'profile.sb'), '-D', 'SCRATCH=' + str(scratch),
                str(NODE), '--no-addons', str(ROOT / 'fixture.mjs'), str(scratch), str(canary), str(forbidden_socket)]
        run_process(argv, scratch, env, streams, process_state)
    except BaseException as error:
        failure = {'name': type(error).__name__, 'message': str(error)[:1000]}
        raise
    finally:
        boundary_error = cleanup_canary(canary, canary_status)
        socket_error = cleanup_socket(forbidden_listener, forbidden_socket, socket_status)
        if boundary_error is None:
            boundary_error = socket_error
        if failure is None and boundary_error is not None:
            failure = {'name': type(boundary_error).__name__, 'message': str(boundary_error)[:1000]}
            raise_after_capture = True
        else:
            raise_after_capture = False
        try:
            manifest_hash = digest(ROOT / 'manifest.json')
        except OSError:
            manifest_hash = None
        (evidence / 'stdout.bin').write_bytes(streams['stdout'])
        (evidence / 'stderr.bin').write_bytes(streams['stderr'])
        (evidence / 'capture.json').write_text(json.dumps({
            'exitCode': process_state['exitCode'], 'failure': failure, 'scratch': str(scratch),
            'cleanupFailure': process_state.get('cleanupFailure'),
            'aggregateBytes': sum(map(len, streams.values())), 'aggregateLimit': LIMIT,
            'timeoutSeconds': TIMEOUT, 'independentDockerCleanupRequired': True,
            'manifestSha256': manifest_hash, 'outsideScratchCanary': canary_status,
            'forbiddenUnixSocket': socket_status,
        }, indent=2) + '\n')
        if raise_after_capture:
            raise boundary_error
    print('Fixture passed; independent Docker inventory/cleanup remains required.')


if __name__ == '__main__':
    main()
