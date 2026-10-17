#!/usr/bin/env python3
"""Prepare and signal an owner-started Muse monitor without invoking Muse."""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import sys
import tempfile
import time

DEADLINE_SECONDS = 90
MAX_FILE_BYTES = 1024


class CanaryError(ValueError):
    """A fixed error code without file contents."""


def _directory(path):
    """Open an explicitly supplied private directory without following symlinks."""
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise CanaryError('unsafe_directory')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise CanaryError('unsafe_directory')
    return fd


def _write(fd, name, value):
    """Reserve once, then publish complete bytes atomically for cooperative writers."""
    raw = json.dumps(value, separators=(',', ':')).encode()
    reservation = os.open('.' + name + '.reserved',
                          os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=fd)
    try:
        os.fsync(reservation)
    finally:
        os.close(reservation)
    os.fsync(fd)
    temporary = '.' + name + '.' + secrets.token_hex(16) + '.tmp'
    owned = False
    try:
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=fd)
        owned = True
        with os.fdopen(out, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('record_exists')
        # The persistent reservation excludes other cooperating writers. A hostile
        # same-UID actor can still race this check/rename; that is outside this fixture.
        os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        owned = False
        os.fsync(fd)
    finally:
        if owned:
            os.unlink(temporary, dir_fd=fd)
        # Never release the reservation, including after a failed or crashed write.


def _read(fd, name):
    """Read only a bounded private regular file from the pinned directory."""
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(source, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > MAX_FILE_BYTES):
            raise CanaryError('unsafe_record')
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise CanaryError('unsafe_record')
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise CanaryError('invalid_record') from None


def _manifest(fd):
    """Validate the nonsecret run identity without treating it as session authority."""
    value = _read(fd, 'manifest.json')
    if (not isinstance(value, dict) or set(value) != {'runId', 'marker', 'phase'}
            or not isinstance(value['runId'], str)
            or not re.fullmatch(r'[0-9a-f]{32}', value['runId'])
            or not isinstance(value['marker'], str)
            or not re.fullmatch(r'MUSE_CANARY_[0-9a-f]{32}', value['marker'])
            or value['phase'] not in ('idle', 'busy')):
        raise CanaryError('invalid_manifest')
    return value


def prepare(parent, phase='idle'):
    """Create a fresh run and return input for the owning session's native monitor."""
    if phase not in ('idle', 'busy'):
        raise CanaryError('invalid_phase')
    directory = Path(tempfile.mkdtemp(prefix='muse-canary-', dir=Path(parent).resolve()))
    fd = _directory(directory)
    try:
        _write(fd, 'manifest.json', {'runId': secrets.token_hex(16),
                                   'marker': 'MUSE_CANARY_' + secrets.token_hex(16), 'phase': phase})
    finally:
        os.close(fd)
    command = shlex.join([str(Path(sys.executable).resolve()), str(Path(__file__).resolve()),
                          'wait', '--directory', str(directory)])
    # Other values use the reported native defaults: timed 300000ms, show_lines false.
    return {'directory': str(directory), 'monitor': {
        'description': f'Disposable {phase} notification canary; no tools or source access',
        'command': command, 'wake_delay_ms': 0,
    }}


def trigger(directory):
    """Record a private trigger only after readiness; this is not a native receipt."""
    fd = _directory(directory)
    try:
        manifest = _manifest(fd)
        if _read(fd, 'ready.json') != {'runId': manifest['runId']}:
            raise CanaryError('not_ready')
        _write(fd, 'trigger.json', {'runId': manifest['runId']})
    finally:
        os.close(fd)


def wait(directory, *, clock=time.monotonic, pause=time.sleep, output=None):
    """Wait at most ninety seconds, emit one nonsecret JSON line, and exit."""
    # Startup claims the run even if it later crashes: restart cannot replay output.
    output = sys.stdout if output is None else output
    deadline = clock() + DEADLINE_SECONDS
    fd = _directory(directory)
    try:
        manifest = _manifest(fd)
        _write(fd, 'started.json', {'runId': manifest['runId']})
        # A trigger created before this process became ready must never fire it.
        try:
            os.stat('trigger.json', dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CanaryError('premature_trigger')
        _write(fd, 'ready.json', {'runId': manifest['runId']})
        while clock() < deadline:
            try:
                signal = _read(fd, 'trigger.json')
            except FileNotFoundError:
                pause(min(0.05, max(0, deadline - clock())))
                continue
            if signal != {'runId': manifest['runId']}:
                raise CanaryError('wrong_trigger')
            if clock() >= deadline:
                break
            output.write(json.dumps({'kind': 'muse-monitor-canary', **manifest}, separators=(',', ':')) + '\n')
            output.flush()
            return
        raise CanaryError('canary_timeout')
    finally:
        os.close(fd)


def main(argv=None):
    """Run only local fixture operations; never invoke the native monitor."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    create = commands.add_parser('prepare')
    create.add_argument('--parent', default=tempfile.gettempdir())
    create.add_argument('--phase', choices=('idle', 'busy'), default='idle')
    for name in ('wait', 'trigger'):
        command = commands.add_parser(name)
        command.add_argument('--directory', required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'prepare':
            print(json.dumps(prepare(args.parent, args.phase)))
        elif args.operation == 'trigger':
            trigger(args.directory)
        else:
            wait(args.directory)
        return 0
    except (CanaryError, OSError):
        print('muse_canary_refused', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
