"""Dormant API-only process adapter. No CLI, activation, or credential discovery."""

import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import tempfile
import time

from transport import Response

NODE_SHA256 = 'e4b5a3af0e05c75de2eae013904145f40fe7fc2a6e6f17510128bf45cca4e79b'
CHILD = Path(__file__).with_name('child.mjs')
HEADER_LIMIT = 32768
BODY_LIMIT = 3 * 1024 * 1024
CLEANUP_RESERVE = 1.0


class Refused(ValueError):
    """Fixed failure text, never child stderr or request data."""


def _need(condition, code):
    if not condition:
        raise Refused(code)


def _pinned(path, digest):
    _need(path.is_file() and path.resolve(strict=True) == path, 'https_pin')
    with path.open('rb') as source:
        actual = hashlib.file_digest(source, 'sha256').hexdigest()
    _need(actual == digest, 'https_pin')


def _stop(process, deadline):
    # Never poll/wait/reap before this sole signal. An unreaped leader reserves
    # its PID even after exit, preventing a recycled process-group identity.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            raise Refused('https_cleanup') from None
    try:
        return process.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        raise Refused('https_cleanup') from None


def _run(command, payload, maximum, deadline):
    """Private offline-test seam. Production request supplies only pinned argv."""
    work_until = deadline - CLEANUP_RESERVE
    _need(time.monotonic() < work_until, 'https_deadline')
    _need(len(payload) <= 16384, 'https_input')
    output = bytearray()
    error_bytes = 0
    position = 0
    process = None
    status = None
    failure = None
    with tempfile.TemporaryDirectory(prefix='reviewer-https-') as directory:
        directory = str(Path(directory).resolve(strict=True))
        try:
            with selectors.DefaultSelector() as selector:
                process = subprocess.Popen(
                    command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, cwd=directory,
                    env={'HOME': directory, 'LANG': 'C', 'LC_ALL': 'C'},
                    start_new_session=True, close_fds=True,
                )
                for pipe, events in ((process.stdin, selectors.EVENT_WRITE),
                                     (process.stdout, selectors.EVENT_READ),
                                     (process.stderr, selectors.EVENT_READ)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, events)
                while selector.get_map():
                    remaining = work_until - time.monotonic()
                    _need(remaining > 0, 'https_deadline')
                    for key, _ in selector.select(min(remaining, 0.05)):
                        pipe = key.fileobj
                        if pipe is process.stdin:
                            try:
                                position += os.write(pipe.fileno(), payload[position:position + 4096])
                            except BrokenPipeError:
                                raise Refused('https_child') from None
                            if position == len(payload):
                                selector.unregister(pipe)
                                pipe.close()
                        else:
                            chunk = os.read(pipe.fileno(), 4096)
                            if not chunk:
                                selector.unregister(pipe)
                                pipe.close()
                            elif pipe is process.stderr:
                                error_bytes += len(chunk)
                                _need(error_bytes <= 4096, 'https_stderr_limit')
                            else:
                                _need(len(output) + len(chunk) <= 4 + HEADER_LIMIT + maximum, 'https_output_limit')
                                output.extend(chunk)
                                if len(output) >= 4:
                                    length = struct.unpack('!I', output[:4])[0]
                                    _need(0 < length <= HEADER_LIMIT, 'https_metadata_limit')
                                    _need(len(output) <= 4 + length + maximum, 'https_body_limit')
                # Pipe EOF is not process exit. Observe without reaping and keep
                # the leader reserved until cleanup has signalled its group.
                while True:
                    _need(time.monotonic() < work_until, 'https_deadline')
                    if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                        break
                    time.sleep(min(0.01, max(0, work_until - time.monotonic())))
        except BaseException as exc:
            failure = exc
        finally:
            if process is not None:
                try:
                    status = _stop(process, deadline)
                except (OSError, Refused):
                    if failure is None:
                        failure = Refused('https_cleanup')
                    elif isinstance(failure, (KeyboardInterrupt, SystemExit, Refused)):
                        failure.add_note('https_cleanup_failed')
                    else:
                        failure = Refused('https_child')
                        failure.add_note('https_cleanup_failed')
                finally:
                    for pipe in (process.stdin, process.stdout, process.stderr):
                        if pipe is not None:
                            pipe.close()
        if failure is not None:
            if isinstance(failure, (KeyboardInterrupt, SystemExit, Refused)):
                raise failure
            raise Refused('https_child') from None
    _need(time.monotonic() <= deadline, 'https_deadline')
    _need(status == 0 and error_bytes == 0, 'https_child')
    return bytes(output)


def _decode(raw, url, maximum):
    _need(len(raw) >= 4, 'https_frame')
    length = struct.unpack('!I', raw[:4])[0]
    _need(0 < length <= HEADER_LIMIT and len(raw) >= 4 + length, 'https_frame')

    def pairs(items):
        result = {}
        for name, value in items:
            _need(name not in result, 'https_frame')
            result[name] = value
        return result

    try:
        metadata = json.loads(raw[4:4 + length], object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused('https_frame') from None
    _need(type(metadata) is dict and set(metadata) == {'status', 'headers'}, 'https_frame')
    _need(type(metadata['status']) is int and 200 <= metadata['status'] <= 599, 'https_frame')
    headers = metadata['headers']
    _need(type(headers) is dict and len(headers) <= 64, 'https_frame')
    _need(all(type(k) is str and type(v) is str and len(k) <= 256 and len(v) <= 8192 for k, v in headers.items()), 'https_frame')
    body = raw[4 + length:]
    _need(len(body) <= maximum, 'https_body_limit')
    return Response(url, metadata['status'], headers, body)


def bind(node_path):
    """Trusted caller supplies a physical absolute runtime; no path discovery."""
    try:
        node = Path(node_path)
        _need(node.is_absolute(), 'https_pin')
    except (TypeError, ValueError):
        raise Refused('https_pin') from None

    def request(url, headers, maximum, deadline):
        return _request(node, url, headers, maximum, deadline)

    return request


def _request(node, url, headers, maximum, deadline):
    """Bound four-argument transport seam; never follows redirects."""
    try:
        _need(type(maximum) is int and 0 <= maximum <= BODY_LIMIT, 'https_input')
        _need(type(deadline) in (int, float) and time.monotonic() < deadline - CLEANUP_RESERVE, 'https_deadline')
        _need(type(url) is str and url.startswith('https://api.github.com/'), 'https_origin')
        _pinned(node, NODE_SHA256)
        manifest = json.loads(CHILD.with_name('pins.json').read_text())
        _pinned(CHILD, manifest['childSha256'])
        remaining = (deadline - CLEANUP_RESERVE - time.monotonic()) * 1000
        _need(0 < remaining <= 60000, 'https_deadline')
        payload = json.dumps({'url': url, 'headers': headers, 'maximum': maximum,
                              'remainingMs': remaining}, ensure_ascii=True).encode('ascii')
        raw = _run([str(node), str(CHILD)], payload, maximum, deadline)
        response = _decode(raw, url, maximum)
        _need(time.monotonic() <= deadline, 'https_deadline')
        return response
    except (OSError, TypeError, KeyError, ValueError) as exc:
        if isinstance(exc, Refused):
            raise
        raise Refused('https_input') from None
