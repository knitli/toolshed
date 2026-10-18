"""Fixed arm64 constant-return diagnostic; only the hosted parent may launch it."""
# ruff: noqa: E402 -- Startup markers must precede extension-module imports.
import sys


def startup_phase(name):
    sys.stderr.write('startup:' + name + '\n')
    sys.stderr.flush()


if __name__ == '__main__':
    startup_phase('script_entry')
import ctypes
if __name__ == '__main__':
    startup_phase('ctypes_imported')
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import stat

if __name__ == '__main__':
    startup_phase('imports_complete')

STUB = bytes.fromhex('40058052c0035fd6')  # mov w0, #42; ret (little endian arm64)
SIZE = 65536
DATA = STUB + bytes(SIZE - len(STUB))
OPERATIONS = ('read', 'private_r', 'private_rw', 'initial_rx', 'r_to_rx', 'rw_to_rx')
MAP_FAILED = ctypes.c_void_p(-1).value


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def identity(info):
    return tuple(getattr(info, key, 0) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
                 'st_gid', 'st_flags', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def observe(fd, operation, libc):
    if operation not in OPERATIONS:
        raise ValueError('operation')
    if operation == 'read':
        return {'stage': 'read', 'status': 0, 'errno': 0}
    protection = 3 if operation in ('private_rw', 'rw_to_rx') else 5 if operation == 'initial_rx' else 1
    ctypes.set_errno(0)
    address = libc.mmap(None, SIZE, protection, 2, fd, 0)
    if address == MAP_FAILED:
        return {'stage': 'mmap', 'status': -1, 'errno': ctypes.get_errno()}
    try:
        if operation in ('r_to_rx', 'rw_to_rx'):
            ctypes.set_errno(0)
            status = libc.mprotect(address, SIZE, 5)
            if status != 0:
                return {'stage': 'mprotect', 'status': status, 'errno': ctypes.get_errno()}
        if operation in ('initial_rx', 'r_to_rx', 'rw_to_rx'):
            emit({'event': 'calling', 'operation': operation})
            # No writable mapping is modified, no syscall instructions, no callback arguments.
            # Deliberately no MAP_JIT, signing changes, entitlements or fallback.
            function = ctypes.CFUNCTYPE(ctypes.c_int)(address)
            value = function()
            emit({'event': 'returned', 'operation': operation, 'value': value})
            if value != 42:
                raise ValueError('unexpected_return_value')
        return {'stage': 'complete', 'status': 0, 'errno': 0}
    finally:
        if libc.munmap(address, SIZE) != 0:
            raise ValueError('unmap_failed')


def main():
    if (len(sys.argv) != 3 or sys.argv[1] != '--child' or sys.argv[2] not in OPERATIONS
            or sys.platform != 'darwin' or platform.machine() != 'arm64'):
        raise ValueError('fixed_arm64_child_only')
    startup_phase('platform_checked')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    startup_phase('limits_set')
    path = Path.cwd() / 'mapping-data'
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid():
        raise ValueError('fixture_identity')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError('fixture_changed')
        startup_phase('fixture_opened')
        data = bytearray()
        while len(data) <= SIZE:
            piece = os.read(fd, min(8192, SIZE + 1 - len(data)))
            if not piece:
                break
            data.extend(piece)
        if bytes(data) != DATA:
            raise ValueError('fixture_bytes')
        startup_phase('fixture_verified')
        emit({'event': 'input', 'identity': identity(before), 'sha256': hashlib.sha256(data).hexdigest()})
        libc = None
        if sys.argv[2] != 'read':
            libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
            libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
            libc.mmap.restype = ctypes.c_void_p
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            libc.mprotect.restype = ctypes.c_int
            libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.munmap.restype = ctypes.c_int
        result = observe(fd, sys.argv[2], libc)
        if identity(os.fstat(fd)) != identity(before) or identity(path.lstat()) != identity(before):
            raise ValueError('fixture_changed')
        emit({'event': 'result', **result})
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()
