"""Fixed bootpd recovery primitive; no helper launch or privileged CLI.

The future owning VM controller must stop/reap its helper before restore and
must keep an unfinished journal as a gate against starting another run.
"""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import plistlib
import secrets
import stat

import qualify_offline_macos_vm as canary
from softnet_preferences import Preferences

OWNER_UID = 0
MAX_BLOB = 1024 * 1024
MAX_RECORD = 2 * MAX_BLOB + 4096


class RecoveryError(RuntimeError):
    """Recovery refused; retain the journal for reconciliation."""


def _require(condition, message):
    if not condition:
        raise RecoveryError(message)


def _directory(directory):
    path = Path(directory)
    _require(path.is_absolute() and '..' not in path.parts, 'unsafe_directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, component in enumerate(path.parts[1:]):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            leaf = index == len(path.parts) - 2
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            _require(info.st_uid in (0, OWNER_UID)
                     and (not info.st_mode & 0o022 or sticky), 'unsafe_directory')
            if leaf:
                _require(info.st_uid == OWNER_UID and stat.S_IMODE(info.st_mode) == 0o700,
                         'unsafe_directory')
            canary._check_tart_acl(path, fd=fd)
        _require(len(path.parts) > 1, 'unsafe_directory')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _file(fd, name, flags):
    handle = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd, mode=0o600)
    try:
        info = os.fstat(handle)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER_UID
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                 and info.st_size <= MAX_RECORD, 'unsafe_record')
        canary._check_tart_acl(name, fd=handle)
        return handle
    except BaseException:
        os.close(handle)
        raise


@contextmanager
def _journal(directory, *, create=False):
    _require(os.geteuid() == OWNER_UID, 'root_required')
    fd = _directory(directory)
    lock = None
    try:
        flags = os.O_RDWR | (os.O_CREAT | os.O_EXCL if create else 0)
        lock = _file(fd, 'reserved', flags)
        _require(os.fstat(lock).st_size == 0, 'invalid_reservation')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if create:
            os.fsync(lock)
            os.fsync(fd)
        yield fd
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)


def _read(fd, name):
    handle = _file(fd, name, os.O_RDONLY)
    with os.fdopen(handle, 'rb') as stream:
        data = stream.read(MAX_RECORD + 1)
    _require(len(data) <= MAX_RECORD, 'oversized_record')
    return data


def _publish(fd, name, data):
    """Publish durable immutable records without replacing an existing name."""
    temporary = '.pending-' + secrets.token_hex(16)
    handle = _file(fd, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.fsync(fd)
    finally:
        os.unlink(temporary, dir_fd=fd)
        os.fsync(fd)


def _snapshot(fd, preferences):
    try:
        value = plistlib.loads(_read(fd, 'snapshot.plist'))
    except (ValueError, TypeError, OverflowError) as error:
        raise RecoveryError('invalid_snapshot') from error
    _require(isinstance(value, dict)
             and set(value) == {'version', 'present', 'before', 'target'}
             and type(value['version']) is int and value['version'] == 1
             and type(value['present']) is bool
             and type(value['before']) is bytes and type(value['target']) is bytes,
             'invalid_snapshot')
    before = value['before'] if value['present'] else None
    _require(value['present'] or value['before'] == b'', 'invalid_snapshot')
    for blob in (before, value['target']):
        if blob is not None:
            _require(len(blob) <= MAX_BLOB and blob.startswith(b'bplist00'), 'invalid_snapshot')
            preferences.validate(blob)
    _require(preferences.equal(value['target'], preferences.encode_target()), 'invalid_target')
    return before, value['target']


def capture(directory, *, preferences_factory=Preferences):
    """Durably save the complete typed value/absence before any helper may start.

    Directory must be fresh, root-owned 0700 and outside any VM being deleted.
    A failed capture consumes the directory: it never grants permission to launch.
    """
    with _journal(directory, create=True) as fd, preferences_factory() as preferences:
        before = preferences.read()
        target = preferences.encode_target()
        for blob in (before, target):
            if blob is not None:
                _require(len(blob) <= MAX_BLOB and blob.startswith(b'bplist00'), 'invalid_snapshot')
                preferences.validate(blob)
        record = {'version': 1, 'present': before is not None,
                  'before': before if before is not None else b'', 'target': target}
        _publish(fd, 'snapshot.plist', plistlib.dumps(record, fmt=plistlib.FMT_BINARY))


def restore(directory, *, preferences_factory=Preferences):
    """Recover only the known Softnet write or an already-restored value.

    Caller must have stopped/reaped the owned VM/helper. A fresh API session and
    lock classify ambiguous earlier commits; journals are never deleted here.
    """
    with _journal(directory) as fd, preferences_factory() as preferences:
        before, target = _snapshot(fd, preferences)
        try:
            _require(_read(fd, 'restored') == b'restored\n', 'invalid_completion')
            completed = True
        except FileNotFoundError:
            completed = False
        current = preferences.read()
        original = preferences.equal(current, before)
        _require(not completed or original, 'completed_preference_changed')
        _require(original or preferences.equal(current, target), 'preference_drift')
        if not original:
            preferences.write(before)
        # Reapply even if already original: an earlier commit may have succeeded
        # while ApplyChanges failed or the process died before application.
        preferences.commit_apply()
        preferences.synchronize()
        _require(preferences.equal(preferences.read(), before), 'restore_readback_mismatch')
        if not completed:
            _publish(fd, 'restored', b'restored\n')
