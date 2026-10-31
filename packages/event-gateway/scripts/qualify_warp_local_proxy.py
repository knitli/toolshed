#!/usr/bin/env python3
"""One guarded, recoverable WARP local-proxy transport qualification."""

import argparse
import asyncio
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import socket
import stat
import subprocess
import sys
import time
import uuid

CLI = Path('/usr/local/bin/warp-cli')
CLI_TARGET = Path('/Applications/Cloudflare WARP.app/Contents/Resources/warp-cli')
CLI_SHA256 = 'd02f8ade8a6fbd6161785e96ef52b151940b1fba6425ccb3cf0ba9e1d92d494b'
PYTHON = Path('/usr/bin/python3')
OWNER_UID = 501
PROXY_PORT = 40000
ORIGINAL_MODE = 'warp+doh'
PROXY_MODE = 'proxy'
WARP_DAEMON = Path('/Applications/Cloudflare WARP.app/Contents/Resources/CloudflareWARP')
GLOBAL_LOCK_PATH = Path('/private/tmp/knitli-warp-local-proxy-qualification.lock')
RECOVERY_SECONDS = 120
RECOVERY_RESERVE_SECONDS = 75
REQUEST_TIMEOUT_SECONDS = 5
PROXY_VERIFY_SECONDS = 8
POST_PROBE_MODE_READBACK_SECONDS = 5
TRIGGER_MARGIN_SECONDS = 2
WAIT_SECONDS = 10
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C'}
_canary_path = Path(__file__).with_name('qualify_offline_macos_vm.py')
_spec = importlib.util.spec_from_file_location('warp_qualification_bounded', _canary_path)
_canary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_canary)


class QualificationError(ValueError):
    """Stable, safe qualification refusal."""


def _need(ok, code):
    if not ok:
        raise QualificationError(code)


def _json_object(raw, code):
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, TypeError):
        raise QualificationError(code) from None
    _need(type(value) is dict, code)
    return value


def parse_status(raw):
    value = _json_object(raw, 'warp_status_invalid')
    _need(set(value) == {'status', 'reason'} and value['status'] == 'Connected'
          and value['reason'] == 'NetworkHealthy', 'warp_not_connected_healthy')
    return {'connected': True, 'healthy': True}


def parse_settings(raw):
    return _parse_settings(raw, allow_unknown=False)


def _parse_settings(raw, *, allow_unknown):
    value = _json_object(raw, 'warp_settings_invalid')
    settings, sources = value.get('settings'), value.get('sources')
    _need(type(settings) is dict and type(sources) is dict, 'warp_settings_invalid')
    mode = settings.get('operation_mode')
    if mode not in (ORIGINAL_MODE, PROXY_MODE):
        _need(allow_unknown and isinstance(mode, str) and re.fullmatch('[a-z0-9+.-]{1,32}', mode),
              'warp_mode_unknown')
    _need(settings.get('warp_tunnel_protocol') == 'masque'
          and settings.get('allow_mode_switch') is True, 'warp_policy_mismatch')
    _need(sources.get('operation_mode') == 'override'
          and sources.get('warp_tunnel_protocol') == 'network_policy'
          and sources.get('allow_mode_switch') == 'network_policy', 'warp_policy_source_mismatch')
    return {'mode': mode, 'protocol': 'masque', 'modeSwitchAllowed': True,
            'modeSource': sources['operation_mode'],
            'protocolSource': sources['warp_tunnel_protocol'],
            'modeSwitchSource': sources['allow_mode_switch']}


def _protected(path, *, directory=False, uid=None, exact_mode=None):
    uid = os.getuid() if uid is None else uid
    path = Path(path)
    _need(path.is_absolute() and '..' not in path.parts, 'unsafe_private_path')
    current = Path('/')
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current /= part
        info = current.lstat()
        leaf = index == len(parts) - 1
        sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        _need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, uid)
              and (not info.st_mode & 0o022 or (sticky and not leaf)), 'unsafe_private_path')
        _need(stat.S_ISDIR(info.st_mode) if (not leaf or directory) else stat.S_ISREG(info.st_mode),
              'unsafe_private_path')
    info = path.stat()
    if exact_mode is not None:
        _need(info.st_uid == uid and stat.S_IMODE(info.st_mode) == exact_mode, 'unsafe_private_mode')
    return path


def _write_new(path, payload, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _run(argv, *, timeout=5, runner=None, deadline=None):
    """Execute only caller-constructed fixed WARP argv, with the shared bounded reaper."""
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
        _need(timeout > 0, 'recovery_deadline_expired')
    if runner is not None:
        return runner(tuple(argv), timeout)
    try:
        out, _ = _canary._run_bounded(list(argv), timeout=timeout, env=ENV, output_limit=8192)
    except (OSError, _canary.CanaryError):
        raise QualificationError('warp_command_failed') from None
    return out


def _inspect(runner=None, *, allow_unknown=False, deadline=None):
    status = parse_status(_run([str(CLI), '--json', 'status'], runner=runner, deadline=deadline))
    settings_raw = _run([str(CLI), '--json', 'settings', 'list'], runner=runner, deadline=deadline)
    return {**status, **_parse_settings(settings_raw, allow_unknown=allow_unknown)}


def _read_mode(runner=None, *, deadline=None):
    raw = _run([str(CLI), '--json', 'settings', 'list'], runner=runner, deadline=deadline)
    value = _json_object(raw, 'warp_settings_invalid')
    settings = value.get('settings')
    _need(type(settings) is dict, 'warp_settings_invalid')
    mode = settings.get('operation_mode')
    _need(isinstance(mode, str) and re.fullmatch('[a-z0-9+.-]{1,32}', mode), 'warp_mode_unknown')
    return mode


def _global_lock(nonblocking=True, *, shared=False):
    path = GLOBAL_LOCK_PATH
    info = path.lstat() if path.exists() or path.is_symlink() else None
    if info is not None:
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
              and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, 'unsafe_global_lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        _need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
              'unsafe_global_lock')
        fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
                    | (fcntl.LOCK_NB if nonblocking else 0))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _cli_integrity(*, deadline=None):
    _need(CLI.is_absolute() and str(CLI) == '/usr/local/bin/warp-cli', 'warp_cli_path_invalid')
    link = CLI.lstat()
    _need(stat.S_ISLNK(link.st_mode) and link.st_uid == 0, 'warp_cli_untrusted')
    target = CLI.resolve(strict=True)
    _need(target == CLI_TARGET, 'warp_cli_target_mismatch')
    _protected(target)
    info = target.stat()
    _need(info.st_uid == 0 and not info.st_mode & 0o022 and os.access(CLI, os.X_OK), 'warp_cli_untrusted')
    version = _run([str(CLI), '--version'], deadline=deadline)
    _need(version.startswith(b'warp-cli 2026.8.2115.0\n'), 'warp_cli_version_mismatch')
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    _need(digest == CLI_SHA256, 'warp_cli_digest_mismatch')
    return digest


def _port_free():
    sock = socket.socket()
    try:
        sock.bind(('127.0.0.1', PROXY_PORT))
    except OSError:
        return False
    finally:
        sock.close()
    return True


def _proxy_listener_ready(runner=None, *, deadline=None):
    connect_timeout = 1 if deadline is None else min(1, deadline - time.monotonic())
    if connect_timeout <= 0:
        return False
    try:
        with socket.create_connection(('127.0.0.1', PROXY_PORT), timeout=connect_timeout):
            pass
    except OSError:
        return False
    try:
        pids = _run(['/usr/sbin/lsof', '-nP', '-t', '-iTCP:127.0.0.1:40000', '-sTCP:LISTEN'],
                    timeout=2, runner=runner, deadline=deadline).decode('ascii').splitlines()
        if len(pids) != 1 or not pids[0].isdigit():
            return False
        owner = _run(['/bin/ps', '-p', pids[0], '-o', 'uid='], timeout=2,
                     runner=runner, deadline=deadline).strip()
        executable = _run(['/bin/ps', '-p', pids[0], '-o', 'comm='],
                          timeout=2, runner=runner, deadline=deadline).strip()
        _protected(WARP_DAEMON)
        daemon = WARP_DAEMON.stat()
        return (_listener_identity_matches(owner, executable) and daemon.st_uid == 0
                and not daemon.st_mode & 0o022)
    except (QualificationError, UnicodeError):
        return False


def _listener_identity_matches(owner, executable):
    return owner == b'0' and executable == str(WARP_DAEMON).encode()


def _receipt(directory, name, data):
    _write_new(Path(directory) / name, (json.dumps(data, sort_keys=True) + '\n').encode())


def _remove_proxy_config(directory):
    path = Path(directory) / 'cloud-config.json'
    if path.exists() or path.is_symlink():
        _protected(path, exact_mode=0o600)
        path.unlink()


def _launchd_label_absent(label, *, deadline=None):
    timeout = 2 if deadline is None else min(2, deadline - time.monotonic())
    _need(timeout > 0, 'recovery_deadline_expired')
    try:
        result = subprocess.run(['/bin/launchctl', 'print', f'gui/{OWNER_UID}/{label}'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=ENV, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise QualificationError('launchd_state_unverified') from None
    if result.returncode == 0:
        return False
    message = (result.stdout + result.stderr)[:2048].decode('utf-8', errors='replace')
    if 'Could not find service' in message or 'Could not find specified service' in message:
        return True
    raise QualificationError('launchd_state_unverified')


def _safe_record(directory):
    path = _protected(Path(directory) / 'recovery.json', exact_mode=0o600)
    raw = path.read_bytes()
    _need(len(raw) <= 2048, 'recovery_record_size')
    value = _json_object(raw, 'recovery_record_invalid')
    expected = {'kind', 'ownerUid', 'originalMode', 'proxyMode', 'deadline', 'nonce', 'cliPath', 'recordSha256'}
    _need(set(value) == expected and value['kind'] == 'warp-local-proxy-recovery-v1'
          and value['ownerUid'] == OWNER_UID and value['originalMode'] == ORIGINAL_MODE
          and value['proxyMode'] == PROXY_MODE and value['cliPath'] == str(CLI)
          and type(value['deadline']) is int
          and int(time.time()) - RECOVERY_SECONDS <= value['deadline'] <= int(time.time()) + RECOVERY_SECONDS
          and isinstance(value['nonce'], str) and re.fullmatch('[0-9a-f]{32}', value['nonce']),
          'recovery_record_invalid')
    unsigned = dict(value)
    digest = unsigned.pop('recordSha256')
    _need(hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == digest,
          'recovery_record_digest_mismatch')
    return value, hashlib.sha256(raw).hexdigest()


def _persist_recovery_failure(directory, record, record_digest, code):
    path = Path(directory) / 'restoration-failed.json'
    failure = {'kind': 'warp-restoration-failed-v1', 'nonce': record['nonce'],
               'recordSha256': record_digest, 'code': code, 'at': int(time.time())}
    if path.exists():
        existing = _json_object(_protected(path, exact_mode=0o600).read_bytes(),
                                'recovery_failure_receipt_invalid')
        _need(existing.get('nonce') == record['nonce']
              and existing.get('recordSha256') == record_digest,
              'recovery_failure_receipt_mismatch')
        return
    _receipt(directory, 'restoration-failed.json', failure)


def _read_mode_until_deadline(directory, record, record_digest, runner, hard_deadline):
    last_code = 'warp_mode_read_unavailable'
    while time.monotonic() < hard_deadline:
        try:
            return _read_mode(runner, deadline=hard_deadline)
        except QualificationError as error:
            last_code = str(error) if re.fullmatch('[a-z0-9_]{1,64}', str(error)) else last_code
            if last_code == 'recovery_deadline_expired':
                break
            time.sleep(min(0.1, max(0, hard_deadline - time.monotonic())))
    _persist_recovery_failure(directory, record, record_digest, last_code)
    raise QualificationError(last_code)


def _restore_original_mode(directory, record, record_digest, runner, hard_deadline,
                           *, max_commands=3):
    """Restore only while a fresh, bounded read still sees the exact proxy mode."""
    restore_commands = 0
    issued = False
    while True:
        current = _read_mode_until_deadline(directory, record, record_digest, runner, hard_deadline)
        if current == record['originalMode']:
            return ('restored' if issued else 'already_original', current, restore_commands)
        if current != record['proxyMode']:
            return ('restore_skipped_external_change', current, restore_commands)
        if restore_commands >= max_commands:
            _persist_recovery_failure(directory, record, record_digest, 'warp_restore_command_failed')
            raise QualificationError('warp_restore_command_failed')
        restore_commands += 1
        issued = True
        try:
            _run([str(CLI), 'mode', record['originalMode']], runner=runner, deadline=hard_deadline)
        except QualificationError as error:
            if str(error) == 'recovery_deadline_expired':
                _persist_recovery_failure(directory, record, record_digest, str(error))
                raise
            # The command may have switched despite a transient CLI failure.
        settle_deadline = min(time.monotonic() + 5, hard_deadline)
        while time.monotonic() < settle_deadline:
            try:
                _inspect(runner, deadline=hard_deadline)
            except QualificationError:
                pass
            current = _read_mode_until_deadline(
                directory, record, record_digest, runner, hard_deadline)
            if current == record['originalMode']:
                return ('restored' if issued else 'already_original', current, restore_commands)
            if current != record['proxyMode']:
                return ('restore_skipped_external_change', current, restore_commands)
            time.sleep(min(0.1, max(0, settle_deadline - time.monotonic())))


def _restore_record(directory, runner=None, *, wait_deadline=False):
    """Independent LaunchAgent entrypoint; compare-before-restore and bounded deadline."""
    record, record_digest = _safe_record(directory)
    directory = Path(directory)
    deadline = record['deadline']
    hard_deadline = time.monotonic() + max(0, deadline - time.time())
    if hard_deadline <= time.monotonic():
        _persist_recovery_failure(directory, record, record_digest, 'recovery_deadline_expired')
        raise QualificationError('recovery_deadline_expired')
    if runner is None:
        try:
            _cli_integrity(deadline=hard_deadline)
        except QualificationError as error:
            code = str(error) if re.fullmatch('[a-z0-9_]{1,64}', str(error)) else 'warp_cli_unavailable'
            _persist_recovery_failure(directory, record, record_digest, code)
            raise
    recovery_lock = None
    if wait_deadline:
        current_mode = _read_mode_until_deadline(
            directory, record, record_digest, runner, hard_deadline)
        _need(current_mode == record['originalMode'], 'restorer_initial_mode_mismatch')
        recovery_trigger = hard_deadline - RECOVERY_RESERVE_SECONDS
        while recovery_lock is None and time.monotonic() < hard_deadline:
            try:
                recovery_lock = _global_lock(shared=True)
            except BlockingIOError:
                time.sleep(min(0.1, max(0, hard_deadline - time.monotonic())))
        if recovery_lock is None:
            _persist_recovery_failure(directory, record, record_digest, 'recovery_lock_deadline')
            raise QualificationError('recovery_lock_deadline')
        _receipt(directory, 'armed.json', {'nonce': record['nonce'], 'recordSha256': record_digest,
                                           'pid': os.getpid(), 'uid': os.geteuid(),
                                           'mode': current_mode})
        while time.monotonic() < recovery_trigger and not (directory / 'restore.request').exists():
            time.sleep(min(0.25, max(0, recovery_trigger - time.monotonic())))
    lock = os.open(directory / 'restore.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        lock_deadline = min(time.monotonic() + 20, hard_deadline)
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= lock_deadline:
                    _persist_recovery_failure(directory, record, record_digest, 'restore_lock_timeout')
                    raise QualificationError('restore_lock_timeout') from None
                time.sleep(0.05)
        result, final_mode, restore_commands = _restore_original_mode(
            directory, record, record_digest, runner, hard_deadline)
        healthy = False
        external_verified = False
        verification_deadline = min(time.monotonic() + 20, hard_deadline)
        while time.monotonic() < verification_deadline:
            if result == 'restore_skipped_external_change':
                observed = _read_mode_until_deadline(
                    directory, record, record_digest, runner, hard_deadline)
                if observed == record['originalMode']:
                    result = 'restored' if restore_commands else 'already_original'
                    final_mode = observed
                    continue
                if observed == record['proxyMode']:
                    remaining = 3 - restore_commands
                    if remaining <= 0:
                        break
                    result, final_mode, used = _restore_original_mode(
                        directory, record, record_digest, runner, hard_deadline,
                        max_commands=remaining)
                    restore_commands += used
                    continue
                confirmation = _read_mode_until_deadline(
                    directory, record, record_digest, runner, hard_deadline)
                if confirmation == observed:
                    final_mode = confirmation
                    external_verified = True
                    break
                final_mode = confirmation
                continue
            try:
                final = _inspect(runner, deadline=hard_deadline)
                final2 = _inspect(runner, deadline=hard_deadline)
                healthy = (final == final2 and final['mode'] == record['originalMode']
                           and final['connected'] and final['healthy'])
                if healthy:
                    final_mode = final2['mode']
                    break
                if final2['mode'] == record['proxyMode']:
                    remaining = 3 - restore_commands
                    if remaining <= 0:
                        break
                    result, final_mode, used = _restore_original_mode(
                        directory, record, record_digest, runner, hard_deadline,
                        max_commands=remaining)
                    restore_commands += used
            except QualificationError:
                current = _read_mode_until_deadline(
                    directory, record, record_digest, runner, hard_deadline)
                if current not in (record['originalMode'], record['proxyMode']):
                    result = 'restore_skipped_external_change'
                    final_mode = current
                    continue
                if current == record['proxyMode']:
                    remaining = 3 - restore_commands
                    if remaining <= 0:
                        break
                    result, final_mode, used = _restore_original_mode(
                        directory, record, record_digest, runner, hard_deadline,
                        max_commands=remaining)
                    restore_commands += used
            time.sleep(min(0.25, max(0, verification_deadline - time.monotonic())))
        if result == 'restore_skipped_external_change' and not external_verified:
            _persist_recovery_failure(directory, record, record_digest,
                                      'external_mode_readback_unstable')
            raise QualificationError('external_mode_readback_unstable')
        if result != 'restore_skipped_external_change' and not healthy:
            _persist_recovery_failure(directory, record, record_digest,
                                      'warp_restoration_readback_failed')
            raise QualificationError('warp_restoration_readback_failed')
        if time.monotonic() >= hard_deadline:
            _persist_recovery_failure(directory, record, record_digest, 'recovery_deadline_expired')
            raise QualificationError('recovery_deadline_expired')
        receipt = {'kind': 'warp-restoration-v1', 'nonce': record['nonce'],
                   'recordSha256': record_digest, 'result': result, 'finalMode': final_mode,
                   'finalHealthy': healthy, 'at': int(time.time())}
        receipt_path = directory / 'restoration.json'
        if receipt_path.exists():
            existing = _json_object(_protected(receipt_path, exact_mode=0o600).read_bytes(),
                                     'restoration_receipt_invalid')
            existing_result = existing.get('result')
            same_original = (existing_result in ('restored', 'already_original')
                             and receipt['result'] in ('restored', 'already_original')
                             and existing.get('finalMode') == record['originalMode']
                             and receipt['finalMode'] == record['originalMode']
                             and existing.get('finalHealthy') is True and receipt['finalHealthy'] is True)
            same_external = (existing_result == receipt['result'] == 'restore_skipped_external_change'
                             and existing.get('finalMode') == receipt['finalMode']
                             and existing.get('finalHealthy') is False and receipt['finalHealthy'] is False)
            _need(existing.get('nonce') == record['nonce']
                  and existing.get('recordSha256') == record_digest
                  and (same_original or same_external),
                  'restoration_receipt_mismatch')
            result = existing_result
            final_mode = existing['finalMode']
            healthy = existing['finalHealthy']
        else:
            _receipt(directory, 'restoration.json', receipt)
        _remove_proxy_config(directory)
        if wait_deadline:
            if time.monotonic() >= hard_deadline:
                _persist_recovery_failure(directory, record, record_digest, 'recovery_deadline_expired')
                raise QualificationError('recovery_deadline_expired')
            _need(result == 'restore_skipped_external_change' or healthy,
                  'independent_restorer_readback_failed')
            _receipt(directory, 'restorer-final.json', {'kind': 'warp-restorer-final-v1',
                      'nonce': record['nonce'], 'recordSha256': record_digest, 'pid': os.getpid(),
                      'result': result, 'finalMode': final_mode, 'finalHealthy': healthy,
                      'at': int(time.time())})
        return result
    finally:
        if recovery_lock is not None:
            os.close(recovery_lock)
        os.close(lock)


def _launch_agent(directory, nonce):
    label = 'com.knitli.eventgateway.warpqualifier.' + nonce
    agent_dir = Path.home() / 'Library' / 'LaunchAgents'
    _protected(agent_dir, directory=True)
    plist = agent_dir / (label + '.plist')
    _write_new(plist, plistlib.dumps({'Label': label, 'ProgramArguments': [str(PYTHON), str(Path(__file__).resolve()),
        '--restore-record', str(directory)], 'RunAtLoad': True, 'KeepAlive': False,
        'LimitLoadToSessionType': 'Aqua'}))
    _run(['/bin/launchctl', 'bootstrap', f'gui/{OWNER_UID}', str(plist)])
    _run(['/bin/launchctl', 'print', f'gui/{OWNER_UID}/{label}'])
    return label, plist


def _restorer_stopped(pid, label, plist, runner, *, deadline=None):
    if not _launchd_label_absent(label, deadline=deadline):
        _run(['/bin/launchctl', 'bootout', f'gui/{OWNER_UID}', str(plist)],
             runner=runner, deadline=deadline)
    end = time.monotonic() + 8 if deadline is None else min(time.monotonic() + 8, deadline)
    while time.monotonic() < end:
        if pid is None:
            process_gone = True
        else:
            try:
                os.kill(pid, 0)
                process_gone = False
            except ProcessLookupError:
                process_gone = True
        label_absent = _launchd_label_absent(label, deadline=deadline)
        if process_gone and label_absent:
            try:
                if plist.exists() or plist.is_symlink():
                    _protected(plist, exact_mode=0o600)
                    plist.unlink()
            except (OSError, QualificationError):
                return False
            return True
        time.sleep(0.1)
    return False


def _cleanup_failed_run(directory, runner, *, independent):
    record, digest = _safe_record(directory)
    hard_deadline = time.monotonic() + max(0, record['deadline'] - time.time())
    label = 'com.knitli.eventgateway.warpqualifier.' + record['nonce']
    plist = Path.home() / 'Library' / 'LaunchAgents' / (label + '.plist')
    armed_path = Path(directory) / 'armed.json'
    if not (Path(directory) / 'restore.request').exists():
        _write_new(Path(directory) / 'restore.request', b'restore\n')
    result = _restore_record(directory, runner)
    restoration = _json_object(_protected(Path(directory) / 'restoration.json', exact_mode=0o600).read_bytes(),
                               'restoration_receipt_invalid')
    if result == 'restore_skipped_external_change':
        external_mode = restoration.get('finalMode')
        _need(isinstance(external_mode, str)
              and external_mode not in (record['originalMode'], record['proxyMode']),
              'external_mode_not_preserved')
        hard_deadline = time.monotonic() + max(0, record['deadline'] - time.time())
        first = _read_mode_until_deadline(directory, record, digest, runner, hard_deadline)
        second = _read_mode_until_deadline(directory, record, digest, runner, hard_deadline)
        _need(first == second == external_mode and restoration.get('finalHealthy') is False,
              'external_mode_readback_unverified')
    else:
        after = _inspect(runner, deadline=hard_deadline)
        after2 = _inspect(runner, deadline=hard_deadline)
        _need(result in ('restored', 'already_original') and after == after2
              and after['mode'] == record['originalMode'], 'warp_failure_restore_unverified')
    armed = None
    if independent:
        end = time.monotonic() + min(RECOVERY_RESERVE_SECONDS,
                                     max(0, record['deadline'] - time.time()))
        while time.monotonic() < end and not armed_path.exists():
            time.sleep(0.05)
        if armed_path.exists():
            armed = _json_object(_protected(armed_path, exact_mode=0o600).read_bytes(),
                                 'armed_receipt_invalid')
            final_path = Path(directory) / 'restorer-final.json'
            end = time.monotonic() + min(RECOVERY_RESERVE_SECONDS,
                                         max(0, record['deadline'] - time.time()))
            while time.monotonic() < end and not final_path.exists():
                time.sleep(0.05)
            _need(final_path.exists(), 'independent_restorer_receipt_missing')
            final = _json_object(_protected(final_path, exact_mode=0o600).read_bytes(),
                                 'independent_restorer_receipt_invalid')
            expected_health = result != 'restore_skipped_external_change'
            _need(final.get('nonce') == record['nonce'] and final.get('recordSha256') == digest
                  and final.get('pid') == armed.get('pid') and final.get('result') == result
                  and final.get('finalHealthy') is expected_health
                  and final.get('finalMode') == restoration.get('finalMode'),
                  'independent_restorer_readback_unverified')
            _need(_restorer_stopped(final['pid'], label, plist, runner,
                                    deadline=time.monotonic() + max(0, record['deadline'] - time.time())),
                  'independent_restorer_shutdown_unverified')
        else:
            _need(_restorer_stopped(None, label, plist, runner,
                                    deadline=time.monotonic() + max(0, record['deadline'] - time.time())),
                  'restorer_shutdown_unverified')


def _arm(directory, original, runner=None, lock_fd=None):
    nonce = uuid.uuid4().hex
    deadline = int(time.time()) + RECOVERY_SECONDS
    unsigned = {'kind': 'warp-local-proxy-recovery-v1', 'ownerUid': OWNER_UID,
                'originalMode': original['mode'], 'proxyMode': PROXY_MODE,
                'deadline': deadline, 'nonce': nonce, 'cliPath': str(CLI)}
    record = {**unsigned, 'recordSha256': hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    _write_new(Path(directory) / 'recovery.json', (json.dumps(record, sort_keys=True) + '\n').encode())
    _need(lock_fd is not None, 'global_lock_missing')
    # Reserve the host globally; the parent and independent restorer then share
    # this lease, so no second parent can acquire the initial exclusive lock.
    fcntl.flock(lock_fd, fcntl.LOCK_SH)
    label, plist = _launch_agent(directory, nonce)
    # Agent's exact-input armed receipt is the mutation gate.
    armed = Path(directory) / 'armed.json'
    end = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < end and not armed.exists():
        time.sleep(0.05)
    _need(armed.exists(), 'restorer_not_armed')
    receipt = _json_object(_protected(armed, exact_mode=0o600).read_bytes(), 'armed_receipt_invalid')
    _need(set(receipt) == {'nonce', 'recordSha256', 'pid', 'uid', 'mode'}
          and receipt == {'nonce': nonce, 'recordSha256': hashlib.sha256(
              (json.dumps(record, sort_keys=True) + '\n').encode()).hexdigest(),
              'pid': receipt.get('pid'), 'uid': OWNER_UID, 'mode': original['mode']}
          and type(receipt['pid']) is int and receipt['pid'] > 1, 'armed_receipt_invalid')
    _need(record['deadline'] - int(time.time()) >= 15, 'recovery_deadline_too_close')
    return label, plist, record


def _copy_proxy_config(config_path, directory):
    source, value, raw, config_digest, node_binding_digest = _config_fingerprint(config_path)
    value['httpsTransport'] = 'warp-local-proxy'
    target = Path(directory) / 'cloud-config.json'
    _write_new(target, (json.dumps(value, sort_keys=True) + '\n').encode())
    return target, config_digest, node_binding_digest


def _config_fingerprint(config_path):
    source = _protected(config_path, exact_mode=0o600)
    raw = source.read_bytes()
    _need(len(raw) <= 4096, 'cloud_config_invalid')
    value = _json_object(raw, 'cloud_config_invalid')
    _need(value.get('httpsTransport', 'direct') == 'direct', 'cloud_transport_not_direct')
    identity = {key: value[key] for key in ('principal', 'agent', 'nodeId', 'nodeGeneration')}
    return (source, value, raw, hashlib.sha256(raw).hexdigest(), hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest())


async def _single_probe(config, state_dir, runtime_id, client_loader=None):
    if client_loader is None:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
        from event_gateway.client_runtime import load_cloud_client
        client_loader = load_cloud_client
    from event_gateway.cloud import CloudError
    client = client_loader(config, state_dir)
    started = time.monotonic_ns()
    observed_status = None
    send = client._send

    async def capture_status(**request):
        nonlocal observed_status
        response = await send(**request)
        observed_status = response[0]
        return response

    client._send = capture_status
    try:
        await client.runtime_status(runtime_id)
    except CloudError as error:
        ended = time.monotonic_ns()
        expected = error.code == 'native_binding_unqualified'
        return {'outcome': 'http_error', 'status': observed_status,
                'errorCode': error.code if re.fullmatch('[a-z0-9_]{1,64}', error.code) else 'other',
                'elapsedNs': max(0, ended - started), 'expectedGuard': expected,
                'applicationAdmitted': False if expected else None}
    ended = time.monotonic_ns()
    return {'outcome': 'response', 'status': observed_status, 'errorCode': None,
            'elapsedNs': max(0, ended - started), 'expectedGuard': False,
            'applicationAdmitted': False, 'responseShape': 'validated_runtime_status'}


def qualify(config_path, state_dir, runtime_id, evidence_root, *, runner=None,
            client_loader=None, arm=None, listener_check=None):
    """Run the fixed workflow. `runner`/`arm` are in-process test seams only."""
    _need(sys.platform == 'darwin' and platform.machine() == 'arm64' and os.geteuid() == OWNER_UID,
          'unsupported_host')
    _need(str(uuid.UUID(runtime_id)) == runtime_id.lower(), 'invalid_runtime_id')
    cli_digest = _cli_integrity() if runner is None else 'test-fixture'
    parent = _protected(evidence_root, directory=True)
    _need(parent.stat().st_uid == OWNER_UID and stat.S_IMODE(parent.stat().st_mode) == 0o700,
          'unsafe_evidence_root')
    try:
        lock_fd = _global_lock()
    except (OSError, BlockingIOError):
        raise QualificationError('qualification_already_active') from None
    directory = parent / ('warp-host-qualification-' + uuid.uuid4().hex)
    proxy_config = None
    label = plist = None
    try:
        os.mkdir(directory, 0o700)
        _protected(directory, directory=True, exact_mode=0o700)
        before = _inspect(runner)
        before2 = _inspect(runner)
        _need(before == before2 and before['mode'] == ORIGINAL_MODE, 'warp_baseline_changed')
        _need(_port_free(), 'warp_proxy_port_occupied')
        # Baseline proves the registered node is not admitted before transport testing.
        pre_config = Path(config_path)
        config_fingerprint = _config_fingerprint(pre_config)
        baseline = asyncio.run(_single_probe(pre_config, state_dir, runtime_id, client_loader))
        _need(baseline['expectedGuard'] and baseline['status'] == 409,
              'baseline_not_native_binding_guarded')
        _need(_config_fingerprint(pre_config)[3:] == config_fingerprint[3:],
              'cloud_config_changed_during_baseline')
        if arm is None:
            label, plist, record = _arm(directory, before, runner, lock_fd)
        else:
            label, plist, record = arm(directory, before, runner)
        hard_deadline = time.monotonic() + max(0, record['deadline'] - time.time())
        immediately_before = _inspect(runner, deadline=hard_deadline)
        _need(immediately_before == before, 'warp_baseline_changed')
        trigger_at = record['deadline'] - RECOVERY_RESERVE_SECONDS
        _need(time.time() + REQUEST_TIMEOUT_SECONDS + PROXY_VERIFY_SECONDS
              + POST_PROBE_MODE_READBACK_SECONDS + TRIGGER_MARGIN_SECONDS < trigger_at,
              'recovery_deadline_too_close')
        switch_started = time.time_ns()
        _run([str(CLI), 'mode', PROXY_MODE], runner=runner, deadline=hard_deadline)
        verify_deadline = time.monotonic() + PROXY_VERIFY_SECONDS
        switched = None
        while time.monotonic() < verify_deadline:
            try:
                observed = _inspect(runner, deadline=hard_deadline)
            except QualificationError:
                observed = None
            ready = (_proxy_listener_ready(runner, deadline=hard_deadline)
                     if listener_check is None else listener_check())
            if observed is not None and observed['mode'] == PROXY_MODE and ready:
                switched = observed
                break
            time.sleep(min(0.2, max(0, verify_deadline - time.monotonic())))
        _need(switched is not None, 'warp_proxy_mode_or_listener_unverified')
        switch_verified = time.time_ns()
        _need(time.time() + REQUEST_TIMEOUT_SECONDS + POST_PROBE_MODE_READBACK_SECONDS
              + TRIGGER_MARGIN_SECONDS < trigger_at,
              'recovery_deadline_too_close')
        proxy_config, config_digest, node_binding_digest = _copy_proxy_config(config_path, directory)
        _need(config_digest == config_fingerprint[3]
              and node_binding_digest == config_fingerprint[4], 'cloud_config_changed_before_probe')
        _need(time.time() + REQUEST_TIMEOUT_SECONDS + POST_PROBE_MODE_READBACK_SECONDS
              + TRIGGER_MARGIN_SECONDS < trigger_at,
              'recovery_deadline_too_close')
        try:
            probe = asyncio.run(_single_probe(proxy_config, state_dir, runtime_id, client_loader))
        finally:
            _remove_proxy_config(directory)
        _need(_config_fingerprint(pre_config)[3:] == config_fingerprint[3:],
              'cloud_config_changed_during_probe')
        _need(probe['expectedGuard'] and probe['status'] == 409,
              'authenticated_guard_not_observed')
        postprobe_deadline = time.monotonic() + max(0, trigger_at - time.time())
        _need(time.time() + POST_PROBE_MODE_READBACK_SECONDS + TRIGGER_MARGIN_SECONDS < trigger_at,
              'recovery_deadline_too_close')
        _need(_read_mode(runner, deadline=postprobe_deadline) == PROXY_MODE,
              'warp_proxy_mode_lost_during_probe')
        _need(time.time() < trigger_at, 'recovery_trigger_already_due')
        return _finish(directory, before, baseline, probe, cli_digest, label, plist, runner,
                       switch_started, switch_verified, config_digest, node_binding_digest,
                       require_independent=arm is None)
    except BaseException:
        if (directory / 'recovery.json').exists():
            try:
                _remove_proxy_config(directory)
                _cleanup_failed_run(directory, runner, independent=arm is None)
            except Exception:
                raise QualificationError('failure_cleanup_unverified') from None
        raise
    finally:
        os.close(lock_fd)


def _finish(directory, before, baseline, probe, cli_digest, label, plist, runner,
            switch_started, switch_verified, config_digest, node_binding_digest, *, require_independent):
    _write_new(directory / 'restore.request', b'restore\n')
    result = _restore_record(directory, runner)
    recovery, _ = _safe_record(directory)
    hard_deadline = time.monotonic() + max(0, recovery['deadline'] - time.time())
    after = _inspect(runner, deadline=hard_deadline)
    after2 = _inspect(runner, deadline=hard_deadline)
    _need(result in ('restored', 'already_original') and after == before == after2,
          'warp_restore_unverified')
    recovery, _ = _safe_record(directory)
    _need(time.time() <= recovery['deadline'], 'restoration_after_deadline')
    restoration = _json_object(_protected(directory / 'restoration.json', exact_mode=0o600).read_bytes(),
                               'restoration_receipt_invalid')
    _need(restoration.get('finalHealthy') is True and restoration.get('finalMode') == before['mode'],
          'warp_restorer_readback_unverified')
    if require_independent:
        independent = Path(directory) / 'restorer-final.json'
        recovery, _ = _safe_record(directory)
        end = time.monotonic() + min(RECOVERY_RESERVE_SECONDS,
                                     max(0, recovery['deadline'] - time.time()))
        while time.monotonic() < end and not independent.exists():
            time.sleep(0.05)
        receipt = _json_object(_protected(independent, exact_mode=0o600).read_bytes(),
                               'independent_restorer_receipt_missing')
        armed = _json_object(_protected(Path(directory) / 'armed.json', exact_mode=0o600).read_bytes(),
                             'armed_receipt_invalid')
        recovery, recovery_digest = _safe_record(directory)
        _need(receipt.get('kind') == 'warp-restorer-final-v1'
              and receipt.get('nonce') == recovery['nonce']
              and receipt.get('recordSha256') == recovery_digest
              and receipt.get('pid') == armed.get('pid')
              and type(receipt.get('pid')) is int and receipt['pid'] > 1 and receipt['pid'] != os.getpid()
              and receipt.get('result') == result and receipt.get('finalHealthy') is True
              and receipt.get('finalMode') == before['mode'], 'independent_restorer_readback_unverified')
        _need(_restorer_stopped(receipt['pid'], label, plist, runner,
                                deadline=time.monotonic() + max(0, recovery['deadline'] - time.time())),
              'independent_restorer_shutdown_unverified')
        _need(time.time() <= recovery['deadline'], 'restoration_after_deadline')
    else:
        try:
            plist.unlink()
        except OSError:
            pass
    receipt = {'kind': 'warp-local-proxy-host-qualification-v1', 'status': 'qualified_transport_only',
               'authenticatedTransportOnly': True, 'nodeProofValidated': False, 'fullyQualified': False,
               'applicationAdmitted': False, 'automaticTurns': False, 'warpCliSha256': cli_digest,
               'sourceSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'cloudConfigSha256': config_digest, 'nodeBindingSha256': node_binding_digest,
               'modeBefore': before['mode'], 'modeAfter': after['mode'],
               'warpBefore': before, 'warpAfter': after, 'proxyPort': PROXY_PORT,
               'proxyListenerVerified': True, 'baseline': baseline, 'probe': probe,
               'switchStartedAtUnixNs': switch_started, 'switchVerifiedAtUnixNs': switch_verified,
               'restoration': result, 'restorationReceipt': 'verified',
               'restorerExited': bool(require_independent), 'launchdLabelAbsent': bool(require_independent),
               'at': int(time.time())}
    _receipt(directory, 'qualification.json', receipt)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cloud-config', type=Path)
    parser.add_argument('--runtime-id')
    parser.add_argument('--evidence-root', type=Path)
    # Fixed internal LaunchAgent entrypoint; never accepts commands or executable paths.
    parser.add_argument('--restore-record', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.restore_record is not None:
            if (sys.platform != 'darwin' or os.geteuid() != OWNER_UID
                    or not args.restore_record.is_absolute()):
                raise QualificationError('unsupported_restorer_context')
            _restore_record(args.restore_record, wait_deadline=True)
            return 0
        _need(args.cloud_config and args.runtime_id and args.evidence_root,
              'missing_required_argument')
        state_dir = args.cloud_config.parent
        result = qualify(args.cloud_config, state_dir, args.runtime_id, args.evidence_root)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (QualificationError, OSError, ValueError) as error:
        code = str(error) if re.fullmatch('[a-z0-9_]{1,64}', str(error)) else 'qualification_failed'
        print(json.dumps({'status': 'failed', 'code': code, 'fullyQualified': False}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
