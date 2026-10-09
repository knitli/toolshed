"""Qualification-only checks of an installed wheel against explicit trusted local source."""

import atexit
import base64
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from urllib.parse import urlsplit


_IMPORT_CACHE = None


class PreflightError(ValueError):
    """An artifact cannot support the requested qualification claim."""


def require(condition, message):
    if not condition:
        raise PreflightError(message)


def _owned(info, *, directory=False):
    sticky_root = directory and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
    return info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or sticky_root)


def _ancestors(path):
    require(path.is_absolute(), 'artifact path must be absolute')
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and _owned(info, directory=True), 'unsafe artifact ancestor')


def _read_regular(path, *, trusted_source=False):
    path = Path(path)
    if trusted_source:
        require(path.is_absolute() and not any(parent.is_symlink() for parent in path.parents), 'source path has symlink ancestor')
    else:
        _ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and _owned(info), 'unsafe artifact file')
        return stream.read()


def verified_executable(path):
    """Require a regular owned executable and non-writable, non-symlink ancestors."""
    path = Path(path)
    _ancestors(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and _owned(info) and info.st_mode & 0o111, 'unsafe executable')
    return str(path)


def verified_python():
    """Retain normal venv symlinks only after verifying their actual interpreter."""
    require(sys.flags.isolated, 'qualification requires Python -I')
    path = Path(sys.executable)
    _ancestors(path)
    info = path.lstat()
    require(info.st_uid in (0, os.getuid()), 'unsafe interpreter owner')
    verified_executable(path.resolve(strict=True))
    if sys.prefix != sys.base_prefix:
        prefix = Path(sys.prefix)
        require(path.parent.parent == prefix, 'interpreter outside current virtual environment')
        _read_regular(prefix / 'pyvenv.cfg')
    return str(path)


def _wheel_provenance(distribution):
    wheel = distribution.read_text('WHEEL')
    require(wheel is not None and 'Wheel-Version: ' in wheel, 'installed distribution is not a wheel')
    raw = distribution.read_text('direct_url.json')
    direct = json.loads(raw) if raw else None
    if direct is not None:
        require(isinstance(direct, dict) and 'dir_info' not in direct, 'editable or source-directory install')
        require(isinstance(direct.get('archive_info'), dict), 'wheel archive metadata missing')
        parsed = urlsplit(direct.get('url', ''))
        require(parsed.scheme in ('file', 'https') and parsed.path.endswith('.whl'), 'wheel archive URL invalid')
    return direct


def _source_files(package_source):
    source = Path(package_source)
    require(source.is_absolute() and source.name == 'event_gateway', 'expected explicit src/event_gateway source directory')
    require((source / '__init__.py').is_file(), 'package source missing')
    expected = {path.relative_to(source).as_posix(): path for path in source.rglob('*.py') if '__pycache__' not in path.parts}
    contracts = source.parent.parent / 'contracts' / 'event-v1'
    require(contracts.is_dir(), 'trusted package contracts missing')
    expected.update({('contracts/event-v1/' + path.relative_to(contracts).as_posix()): path
                     for path in contracts.rglob('*') if path.is_file()})
    return expected


def _installed_files(package_root):
    require(package_root.is_dir(), 'installed package missing')
    return {path.relative_to(package_root).as_posix() for path in package_root.rglob('*')
            if path.is_file() and '__pycache__' not in path.parts}


def _verify_files(distribution, expected, package_root):
    records = {str(path): path for path in distribution.files or ()}
    require(records and distribution.read_text('RECORD') is not None, 'wheel RECORD missing')
    require(_installed_files(package_root) == set(expected), 'installed package files differ from trusted source')
    hashes = {}
    for relative, source_path in sorted(expected.items()):
        name = 'event_gateway/' + relative
        record = records.get(name)
        require(record is not None and record.hash is not None and record.hash.mode == 'sha256', 'module missing SHA256 RECORD')
        installed = Path(distribution.locate_file(record))
        require(installed == package_root / relative, 'wheel module path mismatch')
        data = _read_regular(installed)
        digest = hashlib.sha256(data).digest()
        require(record.size == len(data), 'wheel RECORD size mismatch')
        require(record.hash.value == base64.urlsafe_b64encode(digest).rstrip(b'=').decode(), 'wheel RECORD digest mismatch')
        require(data == _read_regular(source_path, trusted_source=True), 'installed bytes differ from trusted package source')
        hashes[str(installed)] = digest.hex()
    return hashes


def _fresh_import_cache():
    global _IMPORT_CACHE
    # -I/-O still read installed pyc files; an empty private prefix forces verified source.
    temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    _ancestors(temporary_root / 'qualification-cache')
    _IMPORT_CACHE = tempfile.TemporaryDirectory(prefix='qualification-pycache-', dir=temporary_root)
    atexit.register(_IMPORT_CACHE.cleanup)
    sys.pycache_prefix = _IMPORT_CACHE.name
    sys.dont_write_bytecode = True
    return _IMPORT_CACHE.name


def verify_installed(package_source):
    """Verify before package imports; local operator-selected source is the trust anchor."""
    require(sys.flags.isolated, 'qualification requires Python -I')
    require(not any(name == 'event_gateway' or name.startswith('event_gateway.') for name in sys.modules), 'package imported before preflight')
    distribution = importlib.metadata.distribution('knitli-event-gateway')
    provenance = _wheel_provenance(distribution)
    expected = _source_files(package_source)
    package_root = Path(distribution.locate_file('event_gateway'))
    hashes = _verify_files(distribution, expected, package_root)
    spec = importlib.util.find_spec('event_gateway')
    require(spec is not None and spec.origin == str(package_root / '__init__.py'), 'package import path differs from verified wheel')
    require(list(spec.submodule_search_locations or ()) == [str(package_root)], 'package import search path differs from verified wheel')
    cache = _fresh_import_cache()
    return {'pycachePrefix': cache, 'version': distribution.version, 'directUrl': provenance, 'packageSource': str(package_source),
            'packageRoot': str(package_root), 'verifiedSha256': hashes}
