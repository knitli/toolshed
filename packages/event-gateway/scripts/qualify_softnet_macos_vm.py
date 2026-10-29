#!/usr/bin/env python3
"""Fixed, opt-in Softnet/Tart startup canary; installing/running it needs host approval.

A root supervisor owns recovery and Softnet; every Tart command runs as the
admitted nonroot user. This never stages inputs, compiles, promotes, or deletes VMs.
"""

import argparse
import base64
import ipaddress
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import grp
import re
import signal
import socket
import stat
import subprocess  # nosec B404 -- Fixed pinned executables; Tart drops to the admitted nonroot account.
import sys
import threading
import time

import qualify_offline_macos_vm as canary
import softnet_recovery as recovery
from softnet_preferences import Preferences
from softnet_run_state import State

TART = Path('/usr/local/libexec/knitli-event-qualification/tart-2.41.1/tart.app/Contents/MacOS/tart')
SOFTNET = Path('/usr/local/libexec/knitli-event-qualification/softnet-0.22.1/softnet')
STATE_ROOT = Path('/private/var/db/knitli-event-qualification/softnet-runs')
SOFTNET_SHA256 = '1584af036b6d6d11319b2a3766d1be212534c525e3805bc566180aec7a1b2a0e'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C'}
MEASUREMENT = {'configSha256', 'configBytes', 'diskSha256', 'diskBytes',
               'nvramSha256', 'nvramBytes'}
PUBLIC_PROBE_HOST = 'event-native-probe-83fc4c309835.knitli.workers.dev'
PUBLIC_PROBE_PATH = '/probe'
PUBLIC_PROBE_BODY_SHA256 = '773cdcdb36ecbdb7c720d4d135911f7d35252d862b10094f788d96a965b80600'
PUBLIC_PROBE_SOURCE = Path(__file__).with_name('softnet_public_probe_guest.py')
PUBLIC_PROBE_SOURCE_SHA256 = 'fffc23922911756d3e1364a9f5845400fb573155758e226f4e3989fa01a44f6b'
PUBLIC_PROBE_OUTPUT_LIMIT = 4096
PUBLIC_PROBE_TIMEOUT = 25
MAX_PUBLIC_PROBE_DNS_ANSWERS = 32
PUBLIC_PROBE_LOADER = (
    "import base64,sys; source=base64.b64decode(sys.argv[1],validate=True); "
    "sys.argv=[sys.argv[0]]+sys.argv[2:]; "
    "exec(compile(source,'<fixed-public-probe>','exec'))"
)


def _require(condition, code):
    if not condition:
        raise recovery.RecoveryError(code)


def _protected(path, uid, *, directory=False):
    """Validate fixed inputs without accepting symlinked/writable ancestry."""
    path = Path(path)
    _require(path.is_absolute() and '..' not in path.parts, 'unsafe_input_path')
    current = Path('/')
    for index, part in enumerate(path.parts[1:]):
        current /= part
        info = current.lstat()
        leaf = index == len(path.parts) - 2
        sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        _require(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, uid)
                 and (not info.st_mode & 0o022 or (sticky and not leaf)), 'unsafe_input_path')
        _require(stat.S_ISDIR(info.st_mode) if not leaf or directory else stat.S_ISREG(info.st_mode),
                 'unsafe_input_path')
        canary._check_tart_acl(current)
    _require(len(path.parts) > 1, 'unsafe_input_path')
    return path


def _binary(path, digest):
    _protected(path, 0)
    info = path.stat()
    _require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o555, 'unsafe_binary')
    measured, _ = canary._hash_file(path, maximum=128 * 1024**2, require_executable=True)
    _require(measured == digest, 'binary_digest_mismatch')


def _admission_record(root):
    """Validate the protected operator record and storage identity, before measurement."""
    fd = recovery._directory(root)
    try:
        raw = recovery._read(fd, 'admission.plist')
    finally:
        os.close(fd)
    value = plistlib.loads(raw)
    base_keys = {'kind', 'ownerUid', 'tartHome', 'vmName', 'macAddress', 'measurement'}
    probe_admission = isinstance(value, dict) and set(value) == base_keys | {'probeIPv4'}
    _require(isinstance(value, dict) and (set(value) == base_keys or probe_admission),
             'invalid_admission')
    _require(value['kind'] == ('softnet-public-probe-admission-v1' if probe_admission
                               else 'softnet-startup-admission-v1')
             and type(value['ownerUid']) is int and value['ownerUid'] > 0,
             'invalid_admission')
    if probe_admission:
        _require(isinstance(value['probeIPv4'], str), 'invalid_admission')
        try:
            probe_ip = ipaddress.ip_address(value['probeIPv4'])
        except (TypeError, ValueError):
            raise recovery.RecoveryError('invalid_admission') from None
        _require(isinstance(probe_ip, ipaddress.IPv4Address) and probe_ip.is_global,
                 'invalid_admission')
    _require(isinstance(value['vmName'], str)
             and re.fullmatch(r'softnet-canary-[0-9a-f]{32}', value['vmName'])
             and isinstance(value['macAddress'], str)
             and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value['macAddress'])
             and not int(value['macAddress'][:2], 16) & 1, 'invalid_admission')
    measurement = value['measurement']
    _require(isinstance(measurement, dict) and set(measurement) == MEASUREMENT,
             'invalid_admission')
    for name, item in measurement.items():
        _require((type(item) is int and 0 < item <= canary.MAX_DISK_BYTES) if name.endswith('Bytes')
                 else (isinstance(item, str) and re.fullmatch('[0-9a-f]{64}', item)), 'invalid_admission')
    _require(isinstance(value['tartHome'], str), 'invalid_admission')
    try:
        account = pwd.getpwuid(value['ownerUid'])
        group = grp.getgrgid(account.pw_gid)
    except KeyError as error:
        raise recovery.RecoveryError('unknown_owner_account') from error
    _require(account.pw_gid > 0, 'nonroot_group_required')
    home = _protected(value['tartHome'], account.pw_uid, directory=True)
    _require(home.stat().st_uid == account.pw_uid and stat.S_IMODE(home.stat().st_mode) == 0o700,
             'unsafe_tart_home')
    _require(root != home and root not in home.parents and home not in root.parents,
             'state_inside_vm_storage')
    vm = _protected(home / 'vms' / value['vmName'], account.pw_uid, directory=True)
    _require(not (vm / 'state').exists() and not (vm / 'state').is_symlink(), 'saved_vm_state')
    return value, account, group.gr_name, hashlib.sha256(raw).hexdigest()


def _admission(root):
    value, account, group, admission_digest = _admission_record(root)
    vm = Path(value['tartHome']) / 'vms' / value['vmName']
    measurement = value['measurement']
    config_raw = None
    for filename, prefix, maximum in (('config.json', 'config', canary.MAX_CONFIG_BYTES),
                                      ('disk.img', 'disk', canary.MAX_DISK_BYTES),
                                      ('nvram.bin', 'nvram', canary.MAX_CONFIG_BYTES * 1024)):
        path = _protected(vm / filename, account.pw_uid)
        measured = canary._hash_file(path, maximum=maximum, collect=prefix == 'config')
        digest, size = measured[:2]
        if prefix == 'config':
            config_raw = measured[2]
        _require((digest, size) == (measurement[prefix + 'Sha256'], measurement[prefix + 'Bytes']),
                 'vm_measurement_mismatch')
    config = json.loads(config_raw)
    _require(isinstance(config, dict) and config.get('os') == 'darwin' and config.get('arch') == 'arm64'
             and config.get('macAddress') == value['macAddress'], 'vm_identity_mismatch')
    _binary(TART, canary.TART_BINARY_SHA256)
    _binary(SOFTNET, SOFTNET_SHA256)
    return value, account, group, admission_digest


def _resolve_public_probe_ip(resolver=None):
    """Select one deterministic globally routable IPv4 answer for the fixed Worker."""
    resolver = socket.getaddrinfo if resolver is None else resolver
    try:
        answers = resolver(PUBLIC_PROBE_HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        raise recovery.RecoveryError('public_probe_dns_failed') from None
    _require(isinstance(answers, (list, tuple)) and 0 < len(answers) <= MAX_PUBLIC_PROBE_DNS_ANSWERS,
             'public_probe_dns_answer_count')
    addresses = set()
    for answer in answers:
        _require(isinstance(answer, tuple) and len(answer) == 5
                 and answer[0] == socket.AF_INET and answer[1] == socket.SOCK_STREAM
                 and isinstance(answer[4], tuple) and len(answer[4]) >= 2,
                 'public_probe_dns_answer_invalid')
        _require(isinstance(answer[4][0], str), 'public_probe_dns_answer_invalid')
        try:
            address = ipaddress.ip_address(answer[4][0])
        except (TypeError, ValueError):
            raise recovery.RecoveryError('public_probe_dns_answer_invalid') from None
        _require(isinstance(address, ipaddress.IPv4Address) and address.is_global,
                 'public_probe_dns_answer_not_global')
        addresses.add(address)
    _require(addresses, 'public_probe_dns_empty')
    return str(sorted(addresses, key=int)[0])


def _validate_public_probe_report(raw, destination):
    """Validate the guest's receipt; the response body is never retained."""
    _require(isinstance(raw, bytes) and 0 < len(raw) <= PUBLIC_PROBE_OUTPUT_LIMIT
             and raw.endswith(b'\n'), 'public_probe_report_size')
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError):
        raise recovery.RecoveryError('public_probe_report_invalid') from None
    expected = {'kind', 'method', 'host', 'path', 'destinationIPv4', 'port',
                'startedAtUnixNs', 'finishedAtUnixNs', 'tlsVerified',
                'gatewayContextVerified', 'expectedHostPosturePassed', 'status',
                'bodyBytes', 'bodySha256', 'verified', 'error'}
    _require(isinstance(report, dict) and set(report) == expected
             and report['kind'] == 'native-guest-public-probe-v1'
             and report['method'] == 'GET' and report['host'] == PUBLIC_PROBE_HOST
             and report['path'] == PUBLIC_PROBE_PATH and report['destinationIPv4'] == destination
             and type(report['port']) is int and report['port'] == 443
             and type(report['startedAtUnixNs']) is int and report['startedAtUnixNs'] > 0
             and type(report['finishedAtUnixNs']) is int
             and report['finishedAtUnixNs'] >= report['startedAtUnixNs']
             and report['finishedAtUnixNs'] - report['startedAtUnixNs'] <= 15_000_000_000
             and type(report['tlsVerified']) is bool
             and type(report['gatewayContextVerified']) is bool
             and type(report['expectedHostPosturePassed']) is bool
             and type(report['status']) is int and 0 <= report['status'] <= 599
             and type(report['bodyBytes']) is int and 0 <= report['bodyBytes'] <= 17
             and isinstance(report['bodySha256'], str)
             and re.fullmatch(r'[0-9a-f]{64}', report['bodySha256'])
             and type(report['verified']) is bool
             and isinstance(report['error'], str)
             and report['error'] in {'', 'total_timeout', 'transport_error',
                                     'gateway_context_invalid'}
             and (report['gatewayContextVerified'] or report['error'] != ''),
             'public_probe_report_invalid')
    expected_success = (report['tlsVerified'] and report['gatewayContextVerified']
                        and report['status'] == 200
                        and report['bodyBytes'] == 16
                        and report['bodySha256'] == PUBLIC_PROBE_BODY_SHA256
                        and report['error'] == '')
    _require(report['verified'] is expected_success, 'public_probe_report_inconsistent')
    return report


def _child_exited(process):
    _require(process.returncode is None, 'owned_child_already_reaped')
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def _group_quiet(pid):
    """Keep the child PID reserved while independently observing every group member."""
    raw, _ = canary._run_bounded(['/bin/ps', '-A', '-o', 'pid=', '-o', 'pgid=', '-o', 'stat='],
                                 timeout=5, env=ENV)
    leader = False
    quiet = True
    for line in raw.splitlines():
        fields = line.split()
        _require(len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit()
                 and re.fullmatch(rb'[A-Za-z+<NsEXLTWsl-]+', fields[2]), 'invalid_process_table')
        member, group = int(fields[0]), int(fields[1])
        if group == pid:
            leader |= member == pid
            quiet &= fields[2].startswith(b'Z')
    _require(leader, 'owned_group_identity_lost')
    return quiet


def _stop_owned(process, log_thread=None):
    """No poll/wait before the group is quiet: the unreaped leader reserves its PGID."""
    _require(process.returncode is None, 'owned_child_already_reaped')
    try:
        pgid = os.getpgid(process.pid)
        sid = os.getsid(process.pid)
    except ProcessLookupError:
        # Darwin cannot query a zombie's IDs, so prove its exit and reserved PGID without reaping it.
        _require(_child_exited(process), 'owned_group_identity_lost')
        _group_quiet(process.pid)
    else:
        _require(pgid == process.pid and sid == process.pid, 'owned_group_identity_lost')
        _child_exited(process)
    try:
        os.killpg(process.pid, signal.SIGINT)
    except (ProcessLookupError, PermissionError):
        pass
    canary._wait_owned_vm_exit(process, 2)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass  # The process-table proof below must still succeed, including on Darwin zombies.
    deadline = time.monotonic() + 5
    while not _group_quiet(process.pid):
        _require(time.monotonic() < deadline, 'owned_group_still_live')
        time.sleep(0.05)
    _require(_child_exited(process), 'owned_child_not_exited')
    if log_thread is not None:
        log_thread.join(timeout=2)
        _require(not log_thread.is_alive(), 'log_drainer_unjoined')
    process.wait(timeout=5)


def _record(directory, name, value):
    fd = recovery._directory(directory)
    try:
        recovery._publish(fd, name, plistlib.dumps(value, fmt=plistlib.FMT_BINARY))
    finally:
        os.close(fd)


def _start_logs(process, directory, failures):
    directory.mkdir(mode=0o700)
    result = {}

    def drain():
        try:
            canary._drain_tart_logs(process, failures, result, directory)
        except BaseException:
            failures.append('log_drainer_failed')

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    return thread


def _reap_children(vm, helper, threads, stop, failures):
    for key, process in (('vmReaped', vm), ('helperReaped', helper)):
        if process is not None:
            try:
                _stop_owned(process, log_thread=threads.get(process))
                stop[key] = True
            except BaseException:
                failures.append(key + '_unproven')
    for thread in threads.values():
        thread.join(timeout=2)
        if thread.is_alive():
            failures.append('log_drainer_unjoined')


def _exercise(run, admission, account, group, preferences_factory, *, public_probe_ip=None):
    env = {**ENV, 'HOME': admission['tartHome'], 'TART_HOME': admission['tartHome'],
           'TART_NO_AUTO_PRUNE': '1'}
    owner_popen = partial(subprocess.Popen, user=account.pw_uid, group=account.pw_gid, extra_groups=[])
    command = partial(canary._run_bounded, env=env, popen=owner_popen)
    vm_name = admission['vmName']
    raw, _ = command([str(TART), 'get', vm_name, '--format', 'json'], timeout=10)
    _require(canary._vm_stopped(raw), 'vm_not_stopped_before_capture')
    recovery.capture(run, preferences_factory=preferences_factory)
    vm = helper = None
    vm_attempted = False
    first = second = None
    threads = {}
    failures = []
    error = None
    stop = {'vmReaped': True, 'helperReaped': True, 'vmStopped': False}
    previous = canary._install_termination_handlers()
    try:
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        for endpoint in (first, second):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        _record(run, 'launch.plist', {'vmName': vm_name, 'macAddress': admission['macAddress']})
        stop['helperReaped'] = False
        helper_argv = [str(SOFTNET), '--vm-fd', '0', '--vm-mac-address', admission['macAddress']]
        if public_probe_ip is not None:
            helper_argv.append('--allow=out ' + public_probe_ip + '/32')
        helper_argv.extend(['--block=0.0.0.0/0', '--user', account.pw_name, '--group', group])
        helper = subprocess.Popen(
            helper_argv,
            stdin=first, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV,
            close_fds=True, start_new_session=True)  # nosec B603 -- Fixed root-owned digest-pinned helper and fixed flags.
        threads[helper] = _start_logs(helper, run / 'helper-logs', failures)
        first.close()
        first = None
        vm_attempted = True
        stop['vmReaped'] = stop['vmStopped'] = False
        vm = owner_popen(
            [str(TART), 'run', vm_name, f'--net-fd={second.fileno()}', '--no-clipboard',
             '--no-audio', '--no-usb-accessories', '--no-graphics'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, close_fds=True, pass_fds=(second.fileno(),), start_new_session=True)
        threads[vm] = _start_logs(vm, run / 'vm-logs', failures)
        second.close()
        second = None
        deadline = time.monotonic() + canary.VM_READY_TIMEOUT
        while True:
            _require(not failures and not _child_exited(helper) and not _child_exited(vm),
                     'owned_child_exited_or_log_failure')
            try:
                command([str(TART), 'exec', vm_name, '/usr/bin/true'],
                        timeout=canary.VM_READY_PROBE_TIMEOUT)
                break
            except canary.CanaryError as exc:
                if str(exc) not in {'tart_command_failed', 'tart_command_timeout'}:
                    raise
                _require(time.monotonic() < deadline, 'vm_readiness_timeout')
                time.sleep(canary.VM_READY_RETRY_INTERVAL)
        with preferences_factory() as preferences:
            _require(preferences.equal(preferences.read(), preferences.encode_target()),
                     'softnet_target_not_observed')
        _require(not failures and not _child_exited(helper) and not _child_exited(vm),
                 'owned_child_exited_or_log_failure')
        if public_probe_ip is not None:
            source = _protected(PUBLIC_PROBE_SOURCE, 0)
            source_bytes = source.read_bytes()
            _require(len(source_bytes) <= 64 * 1024
                     and hashlib.sha256(source_bytes).hexdigest() == PUBLIC_PROBE_SOURCE_SHA256,
                     'public_probe_source_digest_mismatch')
            stdout, _ = command(
                [str(TART), 'exec', vm_name, '/usr/bin/python3', '-I', '-c',
                 PUBLIC_PROBE_LOADER, base64.b64encode(source_bytes).decode('ascii'), public_probe_ip],
                timeout=PUBLIC_PROBE_TIMEOUT, output_limit=PUBLIC_PROBE_OUTPUT_LIMIT)
            report = _validate_public_probe_report(stdout, public_probe_ip)
            _record(run, 'probe.plist', report)
            _require(report['verified'], 'public_probe_result_failed')
    except BaseException as exc:
        error = exc
    finally:
        canary._ignore_termination_handlers(previous)
        try:
            for endpoint in (first, second):
                if endpoint is not None:
                    endpoint.close()
            if vm_attempted:
                try:
                    command([str(TART), 'stop', vm_name], timeout=15)
                except BaseException:
                    failures.append('vm_stop_command_failed')
            _reap_children(vm, helper, threads, stop, failures)
            try:
                raw, _ = command([str(TART), 'get', vm_name, '--format', 'json'], timeout=10)
                stop['vmStopped'] = canary._vm_stopped(raw)
            except BaseException:
                stop['vmStopped'] = False
            _record(run, 'stop.plist', stop)
            _require(all(stop.values()) and not failures, 'cleanup_unproven')
            recovery.restore(run, preferences_factory=preferences_factory)
        finally:
            canary._restore_termination_handlers(previous)
    if error is not None:
        raise error
    return stop


def qualify(admission_directory, *, public_probe=False, preferences_factory=Preferences):
    """Run the fixed startup canary or one fixed public-probe observation."""
    _require(os.geteuid() == 0 and sys.platform == 'darwin', 'root_macos_required')
    _require(sys.version_info >= (3, 13) and callable(getattr(os, 'waitid', None))
             and all(hasattr(os, name) for name in ('P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT')),
             'python_3_13_nonreaping_wait_required')
    root = Path(admission_directory)
    # Admission is root-only; no executable paths, guest commands, or helper flags are accepted.
    with State(STATE_ROOT) as state:
        admission, account, group, digest = _admission(root)
        probe_ip = None
        if public_probe:
            _require(admission['kind'] == 'softnet-public-probe-admission-v1',
                     'public_probe_admission_required')
            probe_ip = _resolve_public_probe_ip()
            _require(admission['probeIPv4'] == probe_ip, 'public_probe_admission_mismatch')
        else:
            _require(admission['kind'] == 'softnet-startup-admission-v1',
                     'public_probe_mode_required')
        identity = {'vmName': admission['vmName'], 'macAddress': admission['macAddress'],
                    'tartBinarySha256': canary.TART_BINARY_SHA256,
                    'softnetBinarySha256': SOFTNET_SHA256, 'admissionSha256': digest}
        if probe_ip is not None:
            identity['probeIPv4'] = probe_ip
        run, run_id = state.begin(identity)
        stop = _exercise(run, admission, account, group, preferences_factory,
                         public_probe_ip=probe_ip)
        state.complete(run, stop)
        return {'kind': 'softnet-public-probe-canary-v1' if probe_ip else 'softnet-startup-canary-v1',
                'runId': run_id, 'status': 'passed', 'qualified': False,
                'preferencesRestored': True, 'vmDeleted': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission-dir', type=Path, required=True)
    parser.add_argument('--public-probe', action='store_true')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(qualify(args.admission_dir, public_probe=args.public_probe), sort_keys=True))
    except (OSError, ValueError, RuntimeError):
        print('softnet_canary_failed; retain admission and run journal', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
