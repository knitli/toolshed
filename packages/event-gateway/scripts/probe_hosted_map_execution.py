"""Fixed mapped-code diagnostic for a reviewed hosted protected-main workflow."""
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import stat
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parent
ROOT = BASE / 'NOT-A-HOSTED-ATTEMPT'
CHILD = BASE / 'hosted_map_execution_child.py'
SAFE_PY = str(Path(sys.executable).resolve())
SANDBOX = '/usr/bin/sandbox-exec'
ENV = {}
LIMIT = 16384
SECONDS = 10
STUB = bytes.fromhex('40058052c0035fd6')
DATA = STUB + bytes(65536 - len(STUB))
OPERATIONS = ('read', 'private_r', 'private_rw', 'initial_rx', 'r_to_rx', 'rw_to_rx')
EXEC_OPERATIONS = OPERATIONS[3:]
PROFILES = ('control_before', 'denied', 'control_after')
STARTUP_PHASES = ('script_entry', 'ctypes_imported', 'imports_complete', 'platform_checked',
                  'limits_set', 'fixture_opened', 'fixture_verified')

def identity(info):
    return [getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                                         'st_flags', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]

def file_record(path, limit=16 * 1024 * 1024):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError('not_bounded_physical_file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(descriptor)) != identity(before):
            raise ValueError('file_changed')
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            data = os.read(descriptor, min(1024 * 1024, remaining))
            if not data:
                raise ValueError('short_file')
            digest.update(data)
            remaining -= len(data)
        if os.read(descriptor, 1) or identity(os.fstat(descriptor)) != identity(before):
            raise ValueError('file_changed')
    finally:
        os.close(descriptor)
    if identity(path.lstat()) != identity(before):
        raise ValueError('file_changed')
    return {'identity': identity(before), 'sha256': digest.hexdigest()}

def physical_ancestry_matches(observed, frozen):
    # Directories legitimately change size/timestamps as unrelated entries churn.
    # Keep their full observations, but bind the same physical objects and rights.
    return (len(observed) == len(frozen)
            and all(a['path'] == b['path'] and a['identity'][:6] == b['identity'][:6]
                    for a, b in zip(observed, frozen, strict=True)))

def tool_ancestry(path):
    records = []
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('tool_ancestor_alias')
        records.append({'path': str(parent), 'identity': identity(info)})
    return records

def unreaped_exit(process):
    if process.returncode is not None:
        raise ValueError('child_already_reaped')
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

def cleanup_child(process, deadline):
    # This is valid ONLY for the frozen synchronous mapping_child fixture: it
    # has no fork, subprocess, thread, shell, plugin, or variable payload. Its sole mapped callback is fixed mov w0,#42;ret.
    # sandbox-exec directly execs this fixed interpreter/script. No untrusted
    # tool or general process tree is admitted. Keep the direct child unreaped
    # until kill/reap; never signal a process group or a reaped PID.
    errors = []
    try:
        if unreaped_exit(process) is None:
            process.kill()
    except BaseException as error:
        errors.append('signal: ' + type(error).__name__ + ': ' + str(error))
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('cleanup_budget_expired')
        process.wait(timeout=remaining)
    except BaseException as error:
        errors.append('reap: ' + type(error).__name__ + ': ' + str(error))
    if errors:
        raise RuntimeError('; '.join(errors))

def bounded(argv):
    if argv not in [command for _, command in fixture_cases() + site_startup_cases()]:
        raise ValueError('command_not_fixed')
    deadline = time.monotonic() + SECONDS
    process = subprocess.Popen(argv, cwd=ROOT, env=dict(ENV), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = None
    primary = None
    cleanup_failure = None
    try:
        selector = selectors.DefaultSelector()
        for name in buffers:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - 2 - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('child_deadline')
            for key, _ in selector.select(min(remaining, 0.05)):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if sum(len(value) for value in buffers.values()) + len(chunk) > LIMIT:
                    raise ValueError('child_output_limit')
                buffers[key.data].extend(chunk)
        while unreaped_exit(process) is None:
            remaining = deadline - 2 - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('child_deadline')
            time.sleep(min(0.01, remaining))
    except BaseException as error:
        primary = error
    finally:
        try:
            cleanup_child(process, deadline)
        except BaseException as error:
            cleanup_failure = type(error).__name__ + ': ' + str(error)
        finally:
            resources = [process.stdout, process.stderr]
            if selector is not None:
                resources.insert(0, selector)
            for resource in resources:
                try:
                    resource.close()
                except BaseException as error:
                    detail = 'close: ' + type(error).__name__ + ': ' + str(error)
                    cleanup_failure = (cleanup_failure + '; ' if cleanup_failure else '') + detail
    return {'argv': argv, 'returncode': process.returncode,
            'error': type(primary).__name__ + ': ' + str(primary) if primary else None,
            'cleanupError': cleanup_failure, 'cleanupConfirmed': cleanup_failure is None,
            **{name: bytes(value).decode('utf-8', errors='replace') for name, value in buffers.items()}}


def write_new(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)

def admit(env):
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_REPOSITORY_ID': '1058277548', 'GITHUB_REPOSITORY': 'knitli/knitli-site',
                'GITHUB_WORKFLOW_REF': 'knitli/knitli-site/.github/workflows/hosted-map-execution-diagnostic.yml@refs/heads/main',
                'GITHUB_REF': 'refs/heads/main',
                'GITHUB_REF_PROTECTED': 'true', 'GITHUB_RUN_ATTEMPT': '1',
                'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64'}
    if any(env.get(key) != value for key, value in expected.items()):
        raise ValueError('hosted_protected_main_only')
    sha = env.get('GITHUB_SHA', '')
    if (len(sha) != 40 or any(c not in '0123456789abcdef' for c in sha)
            or env.get('GITHUB_WORKFLOW_SHA') != sha or not env.get('GITHUB_RUN_ID', '').isdigit()
            or not env.get('ImageOS') or not env.get('ImageVersion')):
        raise ValueError('hosted_identity')
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or sys.version_info[:3] != (3, 13, 14):
        raise ValueError('runtime_identity')
    if not all(hasattr(os, key) for key in ('waitid', 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT')):
        raise ValueError('nonreaping_wait_unavailable')


def closed_environment():
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': str(ROOT), 'TMPDIR': str(ROOT)}


def profiles():
    # Default-deny filesystem and network; trusted fresh VM runtime roots only.
    roots = (ROOT, Path(sys.base_prefix).resolve(), Path('/System'), Path('/usr/lib'),
             Path('/usr/share/locale'), Path('/Library/Apple'), Path('/private/etc'))

    def q(path):
        return json.dumps(str(path))
    control = '\n'.join([
        '(version 1)', '(deny default)', '(allow file-read-metadata)',
        '(allow file-read* ' + ' '.join('(subpath ' + q(p) + ')' for p in roots) +
        ' (literal ' + q(CHILD) + ') (literal "/dev/null") (literal "/dev/urandom"))',
        '(allow file-map-executable)',
        '(allow process-exec (literal ' + q(SAFE_PY) + '))',
        '(allow sysctl-read (sysctl-name "hw.machine") (sysctl-name "hw.ncpu") '
        '(sysctl-name "hw.activecpu") (sysctl-name "hw.logicalcpu") (sysctl-name "hw.physicalcpu"))',
    ]) + '\n'
    return {name: control + ('(deny file-map-executable (literal ' + q(ROOT / 'mapping-data') + '))\n'
                            if name == 'denied' else '') for name in PROFILES}


def fixture_cases(startup_only=False):
    cases = [(profile + ':' + operation,
             [SANDBOX, '-f', str(ROOT / (profile + '.sb')), SAFE_PY, '-I', '-B', str(CHILD), '--child', operation])
            for profile in PROFILES for operation in OPERATIONS]
    return cases[:1] if startup_only else cases


def site_startup_cases():
    prefix = [SANDBOX, '-f', str(ROOT / 'control_before.sb'), SAFE_PY, '-I', '-B']
    return [('site_startup:version', prefix + ['--version']),
            ('site_startup:enabled', prefix + [str(CHILD), '--startup-marker']),
            ('site_startup:disabled', prefix + ['-S', str(CHILD), '--startup-marker'])]


def events(receipt, fixture, *, complete_prefix=False):
    try:
        values = []
        for line in receipt['stdout'].splitlines():
            try:
                values.append(json.loads(line))
            except ValueError:
                if complete_prefix:
                    break
                return []
        expected = {'event': 'input', 'identity': fixture['identity'], 'sha256': fixture['sha256']}
        if not values or values[0] != expected:
            return []
        return values[1:]
    except (ValueError, KeyError, TypeError):
        return []


def returned(receipt, operation, fixture):
    # A later partial write must never erase an already emitted execution result.
    values = events(receipt, fixture, complete_prefix=True)
    return (len(values) >= 2 and values[0] == {'event': 'calling', 'operation': operation}
            and isinstance(values[1], dict) and set(values[1]) == {'event', 'operation', 'value'}
            and values[1]['event'] == 'returned' and values[1]['operation'] == operation
            and type(values[1]['value']) is int)


def startup_trace(stderr):
    if not isinstance(stderr, str) or len(stderr.encode('utf-8')) > LIMIT:
        return None
    lines = stderr.splitlines(keepends=True)
    expected = ['startup:' + phase + '\n' for phase in STARTUP_PHASES]
    if lines != expected[:len(lines)]:
        return None
    return STARTUP_PHASES[:len(lines)]


def healthy(receipt):
    return (receipt.get('returncode') == 0 and receipt.get('cleanupConfirmed') is True
            and receipt.get('error') is None and receipt.get('cleanupError') is None
            and startup_trace(receipt.get('stderr')) == STARTUP_PHASES)


def classify(receipts, fixture):
    # A demonstrated denied execution is decisive even when another control fails.
    for operation in EXEC_OPERATIONS:
        item = receipts.get('denied:' + operation)
        if item and returned(item, operation, fixture):
            return 'FAIL_EXECUTION_ALLOWED'
    if set(receipts) != {name for name, _ in fixture_cases()}:
        return 'INCONCLUSIVE'
    if not all(healthy(item) for item in receipts.values()):
        return 'INCONCLUSIVE'
    complete = {'event': 'result', 'stage': 'complete', 'status': 0, 'errno': 0}
    read = {'event': 'result', 'stage': 'read', 'status': 0, 'errno': 0}
    for profile in PROFILES:
        for operation in OPERATIONS:
            item = receipts[profile + ':' + operation]
            value = events(item, fixture)
            if operation not in EXEC_OPERATIONS:
                if value != [read if operation == 'read' else complete]:
                    return 'INCONCLUSIVE'
            elif profile != 'denied':
                if value != [{'event': 'calling', 'operation': operation},
                             {'event': 'returned', 'operation': operation, 'value': 42}, complete]:
                    return 'INCONCLUSIVE'
            else:
                stage = 'mmap' if operation == 'initial_rx' else 'mprotect'
                if (len(value) != 1 or value[0] not in
                    [{'event': 'result', 'stage': stage, 'status': -1, 'errno': error}
                     for error in (errno.EPERM, errno.EACCES)]):
                    return 'INCONCLUSIVE'
    return 'SYSCALL_AND_CONTROL_MATRIX_PASS'


def classify_attempt(receipts, fixture, site_startup_only):
    return 'INCONCLUSIVE' if site_startup_only else classify(receipts, fixture)


def stop_after_case(receipt, status, site_startup_only):
    if site_startup_only:
        return receipt['cleanupConfirmed'] is not True
    return status == 'FAIL_EXECUTION_ALLOWED' or not healthy(receipt)


def run(*, startup_only=False, site_startup_only=False):
    global ROOT, ENV
    admit(os.environ)
    temp = Path(os.environ['RUNNER_TEMP'])
    if not temp.is_absolute() or temp.resolve() != temp or any(p.is_symlink() for p in (temp, *temp.parents)):
        raise ValueError('runner_temp_physical')
    ROOT = temp / 'fixed-map-execution-attempt-v1'
    ROOT.mkdir(mode=0o700)  # One attempt; no retries or reuse.
    ENV = closed_environment()
    receipts = {}
    fixture = None
    status = 'INCONCLUSIVE'
    error = None
    removed = False
    frozen = {}
    try:
        for path in (Path(__file__).resolve(), CHILD, Path(SAFE_PY), Path(SANDBOX)):
            ancestry = tool_ancestry(path)
            frozen[str(path)] = (file_record(path, 32 * 1024 * 1024), ancestry)
        for name, content in profiles().items():
            write_new(ROOT / (name + '.sb'), content.encode())
        write_new(ROOT / 'mapping-data', DATA)
        fixture = file_record(ROOT / 'mapping-data')
        for path in (ROOT / 'mapping-data', *(ROOT / (name + '.sb') for name in PROFILES)):
            frozen[str(path)] = (file_record(path), tool_ancestry(path))
        for name, argv in (site_startup_cases() if site_startup_only else fixture_cases(startup_only)):
            for raw, (record, ancestry) in frozen.items():
                if (file_record(Path(raw), 32 * 1024 * 1024) != record
                        or not physical_ancestry_matches(tool_ancestry(Path(raw)), ancestry)):
                    raise ValueError('input_changed')
            receipts[name] = bounded(argv)
            for raw, (record, ancestry) in frozen.items():
                if (file_record(Path(raw), 32 * 1024 * 1024) != record
                        or not physical_ancestry_matches(tool_ancestry(Path(raw)), ancestry)):
                    raise ValueError('input_changed')
            status = classify_attempt(receipts, fixture, site_startup_only)
            if stop_after_case(receipts[name], status, site_startup_only):
                break
        status = classify_attempt(receipts, fixture, site_startup_only)
    except BaseException as caught:
        error = type(caught).__name__ + ': ' + str(caught)
        # Do not erase already observed denied execution on a later failure.
        status = 'FAIL_EXECUTION_ALLOWED' if fixture and classify_attempt(receipts, fixture, site_startup_only) == 'FAIL_EXECUTION_ALLOWED' else 'INCONCLUSIVE'
    finally:
        data_path = ROOT / 'mapping-data'
        try:
            if data_path.exists():
                data_path.unlink()  # Input is never modified by child; no recursive scratch deletion.
            removed = not os.path.lexists(data_path)
        except OSError as caught:
            error = (error or '') + '; fixture cleanup: ' + str(caught)
        if not removed and status != 'FAIL_EXECUTION_ALLOWED':
            status = 'INCONCLUSIVE'
    result = {'status': status, 'qualified': False, 'error': error, 'fixtureRemoved': removed,
              'claim': 'fixed synthetic mapped-code matrix only; CLT runtime remains unqualified',
              'runner': {key: os.environ[key] for key in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion')},
              'inputs': frozen, 'fixture': fixture, 'receipts': receipts}
    write_new(ROOT / 'result.json', (json.dumps(result, indent=2) + '\n').encode())
    return 0 if status == 'SYSCALL_AND_CONTROL_MATRIX_PASS' else 1


def main(argv):
    if argv == ['--site-startup-only']:
        return run(site_startup_only=True)
    if argv not in (['--go'], ['--startup-only']):
        raise SystemExit('Only separately approved hosted --go, --startup-only or --site-startup-only is supported')
    return run(startup_only=argv == ['--startup-only'])


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
