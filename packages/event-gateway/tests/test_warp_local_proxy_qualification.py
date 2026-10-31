import asyncio
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
import select
import tempfile
import time
import unittest
from contextlib import redirect_stdout
import io
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'qualify_warp_local_proxy.py'
SPEC = importlib.util.spec_from_file_location('warp_local_proxy_qualification', SCRIPT)
QUAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUAL)


def settings(mode='warp+doh'):
    return json.dumps({'settings': {'operation_mode': mode, 'warp_tunnel_protocol': 'masque',
                                    'allow_mode_switch': True, 'switch_locked': True},
                       'sources': {'operation_mode': 'override',
                                   'warp_tunnel_protocol': 'network_policy',
                                   'allow_mode_switch': 'network_policy', 'switch_locked': 'override'}}).encode()


class FakeWarp:
    def __init__(self, mode='warp+doh', *, disconnected_proxy=False):
        """Return deterministic settings and connectivity for the fake CLI."""
        self.mode = mode
        self.calls = []
        self.timeouts = []
        self.disconnected_proxy = disconnected_proxy

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        self.timeouts.append(timeout)
        if argv[1:3] == ('--json', 'status'):
            if self.disconnected_proxy and self.mode == 'proxy':
                return b'{"status":"Disconnected","reason":"NetworkDown"}'
            return b'{"status":"Connected","reason":"NetworkHealthy"}'
        if argv[1:4] == ('--json', 'settings', 'list'):
            return settings(self.mode)
        if argv[1:2] == ('mode',):
            self.mode = argv[2]
            return b''
        return b''


class GuardedClient:
    calls = 0
    transports = []
    statuses = []
    error_codes = []

    def __init__(self):
        """Consume queued response statuses and mapped error codes."""
        self.status = type(self).statuses.pop(0) if type(self).statuses else 409
        self.error_code = type(self).error_codes.pop(0) if type(self).error_codes else 'native_binding_unqualified'

    async def _send(self, **_):
        return self.status, {}, b''

    async def runtime_status(self, _runtime_id):
        type(self).calls += 1
        await self._send(method='POST', url='https://example.invalid/v1/runtimes/status',
                         headers={}, body=b'{}', timeout=5, max_response_bytes=8192,
                         follow_redirects=False)
        from event_gateway.cloud import CloudError
        raise CloudError(self.error_code)


class TimeoutClient(GuardedClient):
    async def runtime_status(self, _runtime_id):
        type(self).calls += 1
        raise TimeoutError('request_timeout')


def loader(config, _state):
    GuardedClient.transports.append(json.loads(Path(config).read_text()).get('httpsTransport', 'direct'))
    return GuardedClient()


def cloud_config():
    return {'version': 1, 'authMode': 'gateway', 'origin': 'https://example.invalid',
            'principal': 'test@example.invalid', 'agent': 'agent-test',
            'nodeId': '00000000-0000-0000-0000-000000000002', 'nodeGeneration': 1,
            'agentTokenProvider': {'nodePath': '/fixture/node', 'helperPath': '/fixture/helper'},
            'httpsTransport': 'direct'}


def temporary_directory():
    parent = Path('/private/tmp') if Path('/private/tmp').is_dir() else Path(tempfile.gettempdir()).resolve()
    return tempfile.TemporaryDirectory(dir=parent)


def fake_arm(directory, before, _runner):
    nonce = 'a' * 32
    unsigned = {'kind': 'warp-local-proxy-recovery-v1', 'ownerUid': QUAL.OWNER_UID,
                'originalMode': before['mode'], 'proxyMode': QUAL.PROXY_MODE,
                'deadline': int(time.time()) + QUAL.RECOVERY_SECONDS,
                'nonce': nonce, 'cliPath': str(QUAL.CLI)}
    record = {**unsigned, 'recordSha256': hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    QUAL._write_new(Path(directory) / 'recovery.json',
                    (json.dumps(record, sort_keys=True) + '\n').encode())
    return 'test.label', Path(directory) / 'test.plist', record


def rewrite_recovery_record(path, **updates):
    value = json.loads(Path(path).read_text())
    value.update(updates)
    unsigned = dict(value)
    unsigned.pop('recordSha256')
    value['recordSha256'] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    Path(path).write_text(json.dumps(value, sort_keys=True) + '\n')
    Path(path).chmod(0o600)
    return value


class QualificationTests(unittest.TestCase):
    def setUp(self):
        owner_patch = patch.object(QUAL, 'OWNER_UID', os.getuid())
        owner_patch.start()
        self.addCleanup(owner_patch.stop)

    def test_new_file_is_invisible_until_atomic_publication(self):
        import threading

        payload = b'complete-payload'
        entered_publication = threading.Event()
        allow_publication = threading.Event()
        outcomes = []
        real_link = QUAL.os.link

        def pause_before_link(source, destination, **kwargs):
            staged = Path(source)
            self.assertFalse(target.exists())
            self.assertEqual(staged.read_bytes(), payload)
            entered_publication.set()
            if not allow_publication.wait(timeout=2):
                raise AssertionError('publication barrier timed out')
            return real_link(source, destination, **kwargs)

        def write_file():
            try:
                QUAL._write_new(target, payload)
            except BaseException as error:
                outcomes.append(error)
            else:
                outcomes.append(None)

        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            target = directory / 'receipt.json'
            thread = threading.Thread(target=write_file)
            with patch.object(QUAL.os, 'link', side_effect=pause_before_link):
                thread.start()
                try:
                    self.assertTrue(entered_publication.wait(timeout=2))
                    self.assertFalse(target.exists())
                finally:
                    allow_publication.set()
                    thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(outcomes, [None])
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(list(directory.iterdir()), [target])

    def test_atomic_new_file_does_not_overwrite_raced_destination(self):
        payload = b'new-receipt'
        competitor = b'owner-created-receipt'
        real_link = QUAL.os.link

        def race_destination(source, destination, **kwargs):
            staged = Path(source)
            self.assertFalse(target.exists())
            self.assertEqual(staged.read_bytes(), payload)
            target.write_bytes(competitor)
            target.chmod(0o600)
            return real_link(source, destination, **kwargs)

        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            target = directory / 'receipt.json'
            with patch.object(QUAL.os, 'link', side_effect=race_destination):
                with self.assertRaises(FileExistsError):
                    QUAL._write_new(target, payload)
            self.assertEqual(target.read_bytes(), competitor)
            self.assertEqual(list(directory.iterdir()), [target])

    def test_failed_staged_write_removes_temporary_file(self):
        payload = b'partial-receipt-payload'
        real_fdopen = QUAL.os.fdopen

        class FailDuringWrite:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def write(self, value):
                self.stream.write(value[:5])
                raise OSError('injected staged write failure')

            def __getattr__(self, name):
                return getattr(self.stream, name)

        def fail_fdopen(fd, *args, **kwargs):
            return FailDuringWrite(real_fdopen(fd, *args, **kwargs))

        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            target = directory / 'receipt.json'
            with patch.object(QUAL.os, 'fdopen', side_effect=fail_fdopen):
                with self.assertRaisesRegex(OSError, 'injected staged write failure'):
                    QUAL._write_new(target, payload)
            self.assertFalse(target.exists())
            self.assertEqual(list(directory.iterdir()), [])

    def test_unresolved_bounded_command_cleanup_blocks_independent_recovery(self):
        class UnreapedProcess:
            pass

        fake_process = UnreapedProcess()
        cleanup_error = QUAL._canary.CanaryError('tart_command_timeout')
        cleanup_error.cleanup_errors = ('process_not_reaped_group_unverified',)
        cleanup_error.unreaped_processes = (fake_process,)
        bounded_calls = []
        recovery_fake = FakeWarp('warp+doh')

        def failed_bounded_command(argv, **kwargs):
            bounded_calls.append(tuple(argv))
            if len(bounded_calls) == 1:
                raise cleanup_error
            return recovery_fake(tuple(argv), kwargs['timeout']), b''

        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            record = fake_arm(directory, {'mode': 'warp+doh'}, None)[2]
            with patch.object(QUAL, '_cli_integrity'), \
                    patch.object(QUAL._canary, '_run_bounded', side_effect=failed_bounded_command):
                with self.assertRaisesRegex(QUAL.QualificationError,
                                            '^mode_command_cleanup_unverified$') as first:
                    QUAL._restore_record(directory)
                self.assertEqual(first.exception.cleanup_errors,
                                 ('process_not_reaped_group_unverified',))
                self.assertIs(first.exception.unreaped_processes[0], fake_process)
                marker_path = directory / 'command-cleanup-unresolved.json'
                original_marker = marker_path.read_bytes()
                marker = json.loads(original_marker)
                self.assertEqual(marker['kind'], 'warp-unresolved-command-cleanup-v1')
                self.assertEqual(marker['nonce'], record['nonce'])
                self.assertEqual(marker['recordSha256'],
                                 hashlib.sha256((directory / 'recovery.json').read_bytes()).hexdigest())
                self.assertEqual(marker['cleanupErrors'], ['process_not_reaped_group_unverified'])
                self.assertEqual(marker['unreapedProcessCount'], 1)
                active_path = directory / 'command-active.json'
                active_before_retry = active_path.read_bytes()
                active = json.loads(active_before_retry)
                self.assertEqual(active['kind'], 'warp-command-active-v1')
                self.assertEqual(active['nonce'], record['nonce'])

                # A later independent restorer sees the terminal marker before
                # starting another bounded CLI call or issuing a mode mutation.
                with self.assertRaisesRegex(QUAL.QualificationError,
                                            '^mode_command_cleanup_unverified$'):
                    QUAL._restore_record(directory)

            self.assertEqual(len(bounded_calls), 1)
            self.assertEqual(bounded_calls[0][1:], ('--json', 'settings', 'list'))
            self.assertEqual(marker_path.read_bytes(), original_marker)
            self.assertEqual(active_path.read_bytes(), active_before_retry)
            self.assertTrue((directory / 'recovery.json').exists())
            self.assertFalse((directory / 'restoration.json').exists())
            self.assertFalse((directory / 'restorer-final.json').exists())

    def test_metadata_free_bounded_command_error_remains_retryable(self):
        fake = FakeWarp('warp+doh')
        calls = []

        def transient_then_fake(argv, **kwargs):
            calls.append(tuple(argv))
            if len(calls) == 1:
                error = QUAL._canary.CanaryError('tart_command_timeout')
                error.cleanup_errors = ()
                raise error
            return fake(tuple(argv), kwargs['timeout']), b''

        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, None)
            with patch.object(QUAL, '_cli_integrity'), \
                    patch.object(QUAL._canary, '_run_bounded', side_effect=transient_then_fake):
                result = QUAL._restore_record(directory)
            receipt = json.loads((directory / 'restoration.json').read_text())
            self.assertEqual(result, 'already_original')
            self.assertTrue(receipt['finalHealthy'])
            self.assertEqual(receipt['finalMode'], 'warp+doh')
            self.assertGreater(len(calls), 1)
            self.assertFalse((directory / 'command-cleanup-unresolved.json').exists())
            self.assertFalse((directory / 'command-active.json').exists())

    def test_cli_integrity_accepts_exact_applications_admin_boundary(self):
        def metadata(app_gid=80, app_mode=0o775):
            def inspect(path):
                value = str(path)
                if value == '/Applications':
                    return SimpleNamespace(st_mode=stat.S_IFDIR | app_mode, st_uid=0, st_gid=app_gid)
                if value == str(QUAL.CLI):
                    return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)
                if value == str(QUAL.CLI_TARGET):
                    return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0)
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
            return inspect

        bounded_argv = []

        def bounded_runner(argv, **kwargs):
            bounded_argv.append(tuple(argv))
            return b'warp-cli 2026.8.2115.0\n', b''

        def verify(app_gid=80, app_mode=0o775):
            inspection = metadata(app_gid, app_mode)
            with patch.object(QUAL.Path, 'lstat', new=inspection), \
                    patch.object(QUAL.Path, 'stat', new=inspection), \
                    patch.object(QUAL.Path, 'resolve', new=lambda path, strict=False: QUAL.CLI_TARGET), \
                    patch.object(QUAL.Path, 'read_bytes', new=lambda path: b'cli-fixture'), \
                    patch.object(QUAL, '_check_path_acl', create=True), \
                    patch.object(QUAL, '_hash_open_cli', return_value=QUAL.CLI_SHA256, create=True), \
                    patch.object(QUAL._canary, '_run_bounded', side_effect=bounded_runner), \
                    patch.object(QUAL.os, 'access', return_value=True):
                return QUAL._cli_integrity()

        self.assertEqual(verify(), QUAL.CLI_SHA256)
        self.assertEqual(bounded_argv, [(str(QUAL.CLI_TARGET), '--version')])
        for gid, mode in ((81, 0o775), (80, 0o755), (80, 0o777)):
            with self.subTest(gid=gid, mode=oct(mode)), \
                    self.assertRaisesRegex(QUAL.QualificationError, '^unsafe_private_path$'):
                verify(gid, mode)

    def test_protected_rejects_mutating_acl(self):
        with temporary_directory() as tmp:
            target = Path(tmp) / 'private-file'
            target.write_text('fixture')
            target.chmod(0o600)

            def reject_target_acl(path, fd=None):
                if Path(path) == target:
                    raise QUAL._canary.CanaryError('mutating_acl')

            with patch.object(QUAL._canary, '_check_tart_acl', side_effect=reject_target_acl) as acl_check:
                with self.assertRaisesRegex(QUAL.QualificationError, '^unsafe_private_acl$'):
                    QUAL._protected(target, exact_mode=0o600)
            self.assertTrue(any(call.args[0] == target for call in acl_check.call_args_list))

    def test_cli_bundle_rejects_mutating_applications_acl(self):
        paths = [
            '/Applications',
            '/Applications/Cloudflare WARP.app',
            '/Applications/Cloudflare WARP.app/Contents',
            '/Applications/Cloudflare WARP.app/Contents/Resources',
            str(QUAL.CLI_TARGET),
        ]

        def inspect(path):
            value = str(path)
            if value == '/Applications':
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0, st_gid=80)
            leaf = value == paths[-1]
            return SimpleNamespace(st_mode=(stat.S_IFREG if leaf else stat.S_IFDIR) | 0o755,
                                   st_uid=0, st_gid=0)

        def deny_applications_acl(path, fd=None):
            if str(path) == '/Applications':
                raise QUAL._canary.CanaryError('mutating_acl')

        with patch.object(QUAL.Path, 'lstat', new=inspect), \
                patch.object(QUAL._canary, '_check_tart_acl', side_effect=deny_applications_acl):
            with self.assertRaisesRegex(QUAL.QualificationError, '^unsafe_private_acl$'):
                QUAL._protected_cli_target(QUAL.CLI_TARGET)

    def test_cli_hash_uses_the_opened_fd_for_metadata_and_content(self):
        payload = b'trusted-bundle-cli-fixture'
        real_open = QUAL.os.open
        real_fstat = QUAL.os.fstat
        real_stat = QUAL.os.stat
        real_read = QUAL.os.read
        opened = []
        fstat_fds = []
        read_fds = []
        stat_paths = []

        def root_owned(info, *, inode=None):
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0, st_size=info.st_size,
                                   st_dev=info.st_dev, st_ino=info.st_ino if inode is None else inode,
                                   st_mtime_ns=info.st_mtime_ns)

        with temporary_directory() as tmp:
            target = Path(tmp) / 'warp-cli'
            target.write_bytes(payload)
            target.chmod(0o755)

            def observed_open(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                opened.append(fd)
                return fd

            def observed_fstat(fd):
                fstat_fds.append(fd)
                return root_owned(real_fstat(fd))

            def observed_stat(path, *args, **kwargs):
                stat_paths.append(str(path))
                return root_owned(real_stat(path, *args, **kwargs))

            def observed_read(fd, count):
                read_fds.append(fd)
                return real_read(fd, count)

            with patch.object(QUAL.os, 'open', side_effect=observed_open), \
                    patch.object(QUAL.os, 'fstat', side_effect=observed_fstat), \
                    patch.object(QUAL.os, 'stat', side_effect=observed_stat), \
                    patch.object(QUAL.os, 'read', side_effect=observed_read), \
                    patch.object(QUAL, '_check_path_acl'):
                digest = QUAL._hash_open_cli(target)

        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
        self.assertEqual(len(opened), 1)
        self.assertEqual(set(fstat_fds), {opened[0]})
        self.assertEqual(set(read_fds), {opened[0]})
        self.assertEqual(stat_paths.count(str(target)), 2)

    def test_cli_hash_rejects_path_replacement_after_open(self):
        payload = b'trusted-bundle-cli-fixture'
        real_open = QUAL.os.open
        real_fstat = QUAL.os.fstat
        real_stat = QUAL.os.stat
        opened = []
        target_stat_calls = 0

        def root_owned(info, *, inode=None):
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0, st_size=info.st_size,
                                   st_dev=info.st_dev, st_ino=info.st_ino if inode is None else inode,
                                   st_mtime_ns=info.st_mtime_ns)

        with temporary_directory() as tmp:
            target = Path(tmp) / 'warp-cli'
            target.write_bytes(payload)
            target.chmod(0o755)

            def observed_open(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                opened.append(fd)
                return fd

            def observed_fstat(fd):
                return root_owned(real_fstat(fd))

            def replaced_stat(path, *args, **kwargs):
                nonlocal target_stat_calls
                info = real_stat(path, *args, **kwargs)
                if str(path) != str(target):
                    return info
                target_stat_calls += 1
                return root_owned(info, inode=info.st_ino + (target_stat_calls > 1))

            with patch.object(QUAL.os, 'open', side_effect=observed_open), \
                    patch.object(QUAL.os, 'fstat', side_effect=observed_fstat), \
                    patch.object(QUAL.os, 'stat', side_effect=replaced_stat), \
                    patch.object(QUAL, '_check_path_acl'):
                with self.assertRaisesRegex(QUAL.QualificationError, '^warp_cli_changed_during_read$'):
                    QUAL._hash_open_cli(target)

        self.assertEqual(len(opened), 1)
        self.assertEqual(target_stat_calls, 2)

    def test_real_bounded_runner_uses_target_and_fixture_runner_keeps_cli(self):
        bounded_argv = []

        def bounded_runner(argv, **kwargs):
            bounded_argv.append(tuple(argv))
            return b'fixture-output', b''

        with patch.object(QUAL._canary, '_run_bounded', side_effect=bounded_runner):
            self.assertEqual(QUAL._run([str(QUAL.CLI), '--version']), b'fixture-output')
        self.assertEqual(bounded_argv, [(str(QUAL.CLI_TARGET), '--version')])

        injected = []

        def fixture_runner(argv, timeout):
            injected.append((argv, timeout))
            return b'fixture'

        self.assertEqual(QUAL._run([str(QUAL.CLI), '--version'], runner=fixture_runner), b'fixture')
        self.assertEqual(injected[0][0], (str(QUAL.CLI), '--version'))

    def test_command_active_fence_precedes_runner_and_clears_on_success(self):
        fake = FakeWarp('warp+doh')
        observed = []

        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            record = fake_arm(directory, {'mode': 'warp+doh'}, fake)[2]
            record_digest = hashlib.sha256((directory / 'recovery.json').read_bytes()).hexdigest()

            def inspect_fence_before_command(argv, timeout):
                active_path = directory / 'command-active.json'
                self.assertTrue(active_path.exists())
                active = json.loads(active_path.read_text())
                self.assertEqual(active['kind'], 'warp-command-active-v1')
                self.assertEqual(active['nonce'], record['nonce'])
                self.assertEqual(active['recordSha256'], record_digest)
                self.assertRegex(active['commandId'], r'^[0-9a-f]{32}$')
                expected = hashlib.sha256(json.dumps(
                    argv, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
                self.assertEqual(active['commandSha256'], expected)
                observed.append(active['commandId'])
                return fake(argv, timeout)

            result = QUAL._restore_record(directory, inspect_fence_before_command)
            self.assertEqual(result, 'already_original')
            self.assertGreater(len(observed), 1)
            self.assertEqual(len(observed), len(set(observed)))
            self.assertFalse((directory / 'command-active.json').exists())
            self.assertTrue(json.loads((directory / 'restoration.json').read_text())['finalHealthy'])

    def test_active_fence_publication_failure_prevents_bounded_call(self):
        real_write_new = QUAL._write_new
        bounded_calls = []

        def fake_bounded_command(argv, **kwargs):
            argv = tuple(argv)
            bounded_calls.append(argv)
            if argv[1:3] == ('--json', 'status'):
                return b'{"status":"Connected","reason":"NetworkHealthy"}', b''
            if argv[1:4] == ('--json', 'settings', 'list'):
                return settings('warp+doh'), b''
            return b'', b''

        def reject_active_fence(path, payload, mode=0o600):
            if Path(path).name == 'command-active.json':
                raise OSError('injected command fence publication failure')
            return real_write_new(path, payload, mode)

        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, None)
            with patch.object(QUAL, '_cli_integrity'), \
                    patch.object(QUAL, '_write_new', side_effect=reject_active_fence), \
                    patch.object(QUAL._canary, '_run_bounded', side_effect=fake_bounded_command):
                with self.assertRaisesRegex(OSError, 'injected command fence publication failure'):
                    QUAL._restore_record(directory)
            self.assertEqual(bounded_calls, [])
            self.assertFalse((directory / 'command-active.json').exists())
            self.assertFalse((directory / 'restoration.json').exists())
            self.assertFalse((directory / 'restorer-final.json').exists())

    def test_terminal_marker_write_failure_retains_fence_and_blocks_independent_retry(self):
        class UnreapedProcess:
            pass

        fake_process = UnreapedProcess()
        cleanup_error = QUAL._canary.CanaryError('tart_command_timeout')
        cleanup_error.cleanup_errors = ('process_not_reaped_group_unverified',)
        cleanup_error.unreaped_processes = (fake_process,)
        bounded_calls = []

        def fail_once_then_healthy(argv, **kwargs):
            argv = tuple(argv)
            bounded_calls.append(argv)
            if len(bounded_calls) == 1:
                raise cleanup_error
            if argv[1:3] == ('--json', 'status'):
                output = b'{"status":"Connected","reason":"NetworkHealthy"}'
            elif argv[1:4] == ('--json', 'settings', 'list'):
                output = settings('warp+doh')
            else:
                output = b''
            return output, b''

        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, None)
            with patch.object(QUAL, '_cli_integrity'), \
                    patch.object(QUAL._canary, '_run_bounded', side_effect=fail_once_then_healthy), \
                    patch.object(QUAL, '_persist_command_cleanup_failure',
                                 side_effect=OSError('injected terminal marker publication failure'), create=True), \
                    patch.object(QUAL, 'hasattr', side_effect=lambda _value, _name: False, create=True):
                with self.assertRaisesRegex(QUAL.QualificationError,
                                            '^mode_command_cleanup_unverified$') as first:
                    QUAL._restore_record(directory)
                self.assertEqual(first.exception.cleanup_errors,
                                 ('process_not_reaped_group_unverified',))
                active_path = directory / 'command-active.json'
                active_before_retry = active_path.read_bytes()
                self.assertEqual(json.loads(active_before_retry)['kind'], 'warp-command-active-v1')
                self.assertFalse((directory / 'command-cleanup-unresolved.json').exists())

                with self.assertRaisesRegex(QUAL.QualificationError,
                                            '^mode_command_cleanup_unverified$'):
                    QUAL._restore_record(directory)

            self.assertEqual(len(bounded_calls), 1)
            self.assertEqual(active_path.read_bytes(), active_before_retry)
            self.assertFalse((directory / 'restoration.json').exists())
            self.assertFalse((directory / 'restorer-final.json').exists())

    def test_real_settings_output_uses_larger_bounded_cap_only_for_settings(self):
        value = json.loads(settings('warp+doh'))
        value['settings']['host_extension'] = 'x' * 22000
        large_settings = json.dumps(value, separators=(',', ':')).encode()
        self.assertGreater(len(large_settings), 8192)
        self.assertLess(len(large_settings), 64 * 1024)
        outputs = {
            ('--json', 'settings', 'list'): large_settings,
            ('--json', 'status'): b'{"status":"Connected","reason":"NetworkHealthy"}',
            ('--version',): b'warp-cli 2026.8.2115.0\n',
        }
        observed = []

        def bounded_fixture(argv, *, timeout, env, output_limit):
            argv = tuple(argv)
            observed.append((argv, output_limit))
            payload = outputs[argv[1:]]
            if len(payload) > output_limit:
                error = QUAL._canary.CanaryError('tart_command_output_limit')
                error.cleanup_errors = ()
                raise error
            return payload, b''

        with patch.object(QUAL._canary, '_run_bounded', side_effect=bounded_fixture):
            raw_settings = QUAL._run([str(QUAL.CLI), '--json', 'settings', 'list'])
            status = QUAL._run([str(QUAL.CLI), '--json', 'status'])
            version = QUAL._run([str(QUAL.CLI), '--version'])

        self.assertEqual(len(raw_settings), len(large_settings))
        self.assertEqual(QUAL.parse_settings(raw_settings)['mode'], 'warp+doh')
        self.assertTrue(QUAL.parse_status(status)['healthy'])
        self.assertTrue(version.startswith(b'warp-cli '))
        self.assertEqual([limit for _argv, limit in observed], [64 * 1024, 8192, 8192])
        self.assertEqual(observed[0][0], (str(QUAL.CLI_TARGET), '--json', 'settings', 'list'))

    def test_structured_status_and_settings_are_strict(self):
        self.assertEqual(QUAL.parse_status(b'{"status":"Connected","reason":"NetworkHealthy"}')['healthy'], True)
        self.assertEqual(QUAL.parse_settings(settings())['mode'], 'warp+doh')
        for raw in (b'Connected', b'{"status":"Connected"}',
                    b'{"status":"Connected","reason":"NetworkDown"}'):
            with self.subTest(raw=raw), self.assertRaises(QUAL.QualificationError):
                QUAL.parse_status(raw)
        for mode in ('WarpWithDnsOverHttps', 'warp', 'proxy\nwarp+doh'):
            with self.subTest(mode=mode), self.assertRaises(QUAL.QualificationError):
                QUAL.parse_settings(settings(mode))

    def test_policy_mismatch_fails_closed(self):
        value = json.loads(settings())
        value['sources']['operation_mode'] = 'network_policy'
        with self.assertRaises(QUAL.QualificationError):
            QUAL.parse_settings(json.dumps(value).encode())

    def test_proxy_listener_identity_requires_root_warp_daemon_path(self):
        expected = str(QUAL.WARP_DAEMON).encode()
        self.assertTrue(QUAL._listener_identity_matches(b'0', expected))
        self.assertFalse(QUAL._listener_identity_matches(b'501', expected))
        self.assertFalse(QUAL._listener_identity_matches(b'0', b'/usr/bin/python3'))

    def test_host_uid_mismatch_refuses_before_cli_inspection(self):
        fake = FakeWarp()
        actual_uid = os.getuid()
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            with patch.object(QUAL, 'OWNER_UID', actual_uid + 1), \
                    patch.object(QUAL.sys, 'platform', 'darwin'), \
                    patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=actual_uid):
                with self.assertRaisesRegex(QUAL.QualificationError, 'unsupported_host'):
                    QUAL.qualify('/ignored', '/ignored', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=loader)
        self.assertFalse(fake.calls)

    def test_baseline_failure_never_arms_or_switches(self):
        fake = FakeWarp('proxy')
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_port_free', return_value=True):
                with self.assertRaises(QUAL.QualificationError):
                    QUAL.qualify('/ignored', '/ignored', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=loader, arm=lambda *_: self.fail('armed'))
        self.assertFalse(any(call[1:2] == ('mode',) for call in fake.calls))

    def test_non_direct_config_refuses_before_baseline_or_arm(self):
        fake = FakeWarp()
        client_calls = []
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            config = cloud_config()
            config['httpsTransport'] = 'warp-local-proxy'
            path = root / 'cloud.json'
            path.write_text(json.dumps(config))
            path.chmod(0o600)

            def record_loader(*_):
                client_calls.append(True)
                return GuardedClient()
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), patch.object(QUAL, '_port_free', return_value=True):
                with self.assertRaisesRegex(QUAL.QualificationError, 'cloud_transport_not_direct'):
                    QUAL.qualify(path, root, '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=record_loader, arm=lambda *_: self.fail('armed'))
        self.assertFalse(client_calls)
        self.assertFalse(any(call[1:2] == ('mode',) for call in fake.calls))

    def test_config_mutation_during_baseline_refuses_before_arm(self):
        fake = FakeWarp()
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            path = root / 'cloud.json'
            path.write_text(json.dumps(cloud_config()))
            path.chmod(0o600)

            def mutating_loader(config_path, _state):
                value = json.loads(Path(config_path).read_text())
                value['nodeGeneration'] = 9
                Path(config_path).write_text(json.dumps(value))
                Path(config_path).chmod(0o600)
                return GuardedClient()
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), patch.object(QUAL, '_port_free', return_value=True):
                with self.assertRaisesRegex(QUAL.QualificationError, 'cloud_config_changed_during_baseline'):
                    QUAL.qualify(path, root, '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=mutating_loader, arm=lambda *_: self.fail('armed'))
        self.assertFalse(any(call[1:2] == ('mode',) for call in fake.calls))

    def test_cli_uses_cloud_config_parent_for_original_node_key(self):
        with temporary_directory() as tmp:
            root = Path(tmp)
            config = root / 'cloud.json'
            output = io.StringIO()
            args = ['--cloud-config', str(config), '--runtime-id', '00000000-0000-0000-0000-000000000001',
                    '--evidence-root', str(root)]
            with patch.object(QUAL, 'qualify', return_value={'status': 'fixture'}) as run, \
                    redirect_stdout(output):
                self.assertEqual(QUAL.main(args), 0)
            self.assertEqual(run.call_args.args[1], root)
            self.assertIn('fixture', output.getvalue())

    def test_one_proxy_probe_and_conditional_restore(self):
        fake = FakeWarp()
        GuardedClient.calls = 0
        GuardedClient.transports = []
        GuardedClient.statuses = [409, 409]
        GuardedClient.error_codes = ['native_binding_unqualified', 'native_binding_unqualified']
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            config = root / 'cloud.json'
            config.write_text(json.dumps(cloud_config()))
            config.chmod(0o600)
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_port_free', return_value=True):
                result = QUAL.qualify(config, root / 'state', '00000000-0000-0000-0000-000000000001', root,
                                      runner=fake, client_loader=loader, arm=fake_arm,
                                      listener_check=lambda: True)
            self.assertEqual(result['status'], 'qualified_transport_only')
            self.assertFalse(result['nodeProofValidated'])
            self.assertFalse(result['fullyQualified'])
            self.assertEqual(result['probe']['status'], 409)
            self.assertEqual(GuardedClient.calls, 2)
            self.assertEqual(GuardedClient.transports, ['direct', 'warp-local-proxy'])
            self.assertEqual([call[2] for call in fake.calls if call[1:2] == ('mode',)], ['proxy', 'warp+doh'])
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertEqual(json.loads(config.read_text()), cloud_config())

    def test_proxy_guard_requires_http_409_and_matching_error_code(self):
        for proxy_status, proxy_error in ((200, 'native_binding_unqualified'),
                                          (409, 'node_denied')):
            with self.subTest(status=proxy_status, error=proxy_error):
                fake = FakeWarp()
                GuardedClient.calls = 0
                GuardedClient.statuses = [409, proxy_status]
                GuardedClient.error_codes = ['native_binding_unqualified', proxy_error]
                with temporary_directory() as tmp:
                    root = Path(tmp)
                    root.chmod(0o700)
                    config = root / 'cloud.json'
                    config.write_text(json.dumps(cloud_config()))
                    config.chmod(0o600)
                    with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                            patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                            patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                            patch.object(QUAL, '_port_free', return_value=True):
                        with self.assertRaisesRegex(QUAL.QualificationError, 'authenticated_guard_not_observed'):
                            QUAL.qualify(config, root / 'state', '00000000-0000-0000-0000-000000000001', root,
                                         runner=fake, client_loader=loader, arm=fake_arm,
                                         listener_check=lambda: True)
                    self.assertEqual(fake.mode, 'warp+doh')
                    self.assertEqual(GuardedClient.calls, 2)
                    self.assertFalse(list(root.glob('warp-host-qualification-*/qualification.json')))

    def test_proxy_cancellation_restores_once_without_retry(self):
        class CancelledClient(GuardedClient):
            async def runtime_status(self, _runtime_id):
                type(self).calls += 1
                raise asyncio.CancelledError()

        fake = FakeWarp()
        GuardedClient.calls = 0
        GuardedClient.statuses = [409]
        GuardedClient.error_codes = ['native_binding_unqualified']
        CancelledClient.calls = 0

        def loader_for_cancel(config_path, _state):
            transport = json.loads(Path(config_path).read_text()).get('httpsTransport', 'direct')
            GuardedClient.transports.append(transport)
            return GuardedClient() if transport == 'direct' else CancelledClient()

        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            config = root / 'cloud.json'
            config.write_text(json.dumps(cloud_config()))
            config.chmod(0o600)
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_port_free', return_value=True):
                with self.assertRaises(asyncio.CancelledError):
                    QUAL.qualify(config, root / 'state', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=loader_for_cancel, arm=fake_arm,
                                 listener_check=lambda: True)
            self.assertEqual(CancelledClient.calls, 1)
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertEqual([call[2] for call in fake.calls if call[1:2] == ('mode',)], ['proxy', 'warp+doh'])

    def test_proxy_config_identity_drift_is_refused_and_restored(self):
        fake = FakeWarp()
        GuardedClient.calls = 0
        GuardedClient.statuses = [409, 409]
        GuardedClient.error_codes = ['native_binding_unqualified', 'native_binding_unqualified']
        calls = 0

        def mutating_loader(config_path, _state):
            nonlocal calls
            calls += 1
            transport = json.loads(Path(config_path).read_text()).get('httpsTransport', 'direct')
            if transport == 'warp-local-proxy':
                changed = json.loads(config.read_text())
                changed['nodeGeneration'] = 7
                config.write_text(json.dumps(changed))
                config.chmod(0o600)
            GuardedClient.transports.append(transport)
            return GuardedClient()

        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            config = root / 'cloud.json'
            config.write_text(json.dumps(cloud_config()))
            config.chmod(0o600)
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_port_free', return_value=True):
                with self.assertRaisesRegex(QUAL.QualificationError, 'cloud_config_changed_during_probe'):
                    QUAL.qualify(config, root / 'state', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=mutating_loader, arm=fake_arm,
                                 listener_check=lambda: True)
            self.assertEqual(calls, 2)
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertEqual(json.loads(config.read_text())['nodeGeneration'], 7)

    def test_failed_probe_uses_independent_cleanup_seam(self):
        fake = FakeWarp()
        GuardedClient.calls = 0
        GuardedClient.statuses = [409]
        GuardedClient.error_codes = ['native_binding_unqualified']
        TimeoutClient.calls = 0


        def loader_for_timeout(config_path, _state):
            transport = json.loads(Path(config_path).read_text()).get('httpsTransport', 'direct')
            return GuardedClient() if transport == 'direct' else TimeoutClient()

        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            config = root / 'cloud.json'
            config.write_text(json.dumps(cloud_config()))
            config.chmod(0o600)

            def arm_without_launchd(directory, before, runner, _lock_fd):
                return fake_arm(directory, before, runner)
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_port_free', return_value=True), \
                    patch.object(QUAL, 'RECOVERY_RESERVE_SECONDS', 0), \
                    patch.object(QUAL, '_arm', side_effect=arm_without_launchd), \
                    patch.object(QUAL, '_restorer_stopped', return_value=True) as stopped, \
                    patch.object(QUAL, '_cleanup_failed_run', wraps=QUAL._cleanup_failed_run) as cleanup:
                with self.assertRaises(TimeoutError):
                    QUAL.qualify(config, root / 'state', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=loader_for_timeout,
                                 listener_check=lambda: True)
            self.assertTrue(cleanup.call_args.kwargs['independent'])
            self.assertTrue(stopped.called)
            self.assertEqual(TimeoutClient.calls, 1)
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertEqual([call[2] for call in fake.calls if call[1:2] == ('mode',)], ['proxy', 'warp+doh'])

    def test_recovery_reserve_includes_probe_timeout(self):
        fake = FakeWarp()
        GuardedClient.calls = 0
        GuardedClient.statuses = [409]
        GuardedClient.error_codes = ['native_binding_unqualified']

        def arm_short_deadline(directory, before, runner):
            label, plist, record = fake_arm(directory, before, runner)
            record = rewrite_recovery_record(Path(directory) / 'recovery.json',
                deadline=int(time.time()) + QUAL.RECOVERY_RESERVE_SECONDS
                + QUAL.REQUEST_TIMEOUT_SECONDS + QUAL.PROXY_VERIFY_SECONDS
                + QUAL.POST_PROBE_MODE_READBACK_SECONDS + QUAL.TRIGGER_MARGIN_SECONDS - 1)
            return label, plist, record

        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            config = root / 'cloud.json'
            config.write_text(json.dumps(cloud_config()))
            config.chmod(0o600)
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_port_free', return_value=True):
                with self.assertRaisesRegex(QUAL.QualificationError, 'recovery_deadline_too_close'):
                    QUAL.qualify(config, root / 'state', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=loader, arm=arm_short_deadline,
                                 listener_check=lambda: True)
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertEqual(GuardedClient.calls, 1)
            self.assertFalse(any(call[1:2] == ('mode',) for call in fake.calls))

    def test_global_shared_lease_blocks_another_process_across_evidence_roots(self):
        if not hasattr(os, 'fork'):
            self.skipTest('requires POSIX flock and fork')
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            first_evidence_root = root / 'evidence-a'
            second_evidence_root = root / 'evidence-b'
            first_evidence_root.mkdir(mode=0o700)
            second_evidence_root.mkdir(mode=0o700)
            lock_path = root / 'host-global.lock'
            read_fd, write_fd = os.pipe()
            with patch.object(QUAL, 'GLOBAL_LOCK_PATH', lock_path):
                parent_lease = QUAL._global_lock(shared=True)
                pid = os.fork()
                if pid == 0:
                    os.close(read_fd)
                    try:
                        try:
                            fd = QUAL._global_lock(nonblocking=True)
                        except BlockingIOError:
                            os.write(write_fd, b'blocked')
                        else:
                            os.close(fd)
                            os.write(write_fd, b'acquired')
                    finally:
                        os.close(write_fd)
                    os._exit(0)
                os.close(write_fd)
                try:
                    ready, _, _ = select.select([read_fd], [], [], 3)
                    observed = os.read(read_fd, 32) if ready else b'timeout'
                    _, status = os.waitpid(pid, 0)
                finally:
                    os.close(read_fd)
                    os.close(parent_lease)
            self.assertNotEqual(first_evidence_root, second_evidence_root)
            self.assertEqual(observed, b'blocked')
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            with patch.object(QUAL, 'GLOBAL_LOCK_PATH', lock_path):
                released = QUAL._global_lock(nonblocking=True)
                os.close(released)

    def test_restore_skips_unknown_external_mode(self):
        fake = FakeWarp('warp+doh')
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            fake.mode = 'warp'
            result = QUAL._restore_record(directory, fake)
            self.assertEqual(result, 'restore_skipped_external_change')
            self.assertEqual(fake.mode, 'warp')
            self.assertFalse(any(call[1:2] == ('mode',) for call in fake.calls))

    def test_restore_is_idempotent_after_parent_and_agent_race(self):
        fake = FakeWarp('proxy')
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            self.assertEqual(QUAL._restore_record(directory, fake), 'restored')
            self.assertEqual(QUAL._restore_record(directory, fake), 'restored')
            self.assertEqual([call[2] for call in fake.calls if call[1:2] == ('mode',)], ['warp+doh'])

    def test_symlinked_recovery_input_is_rejected(self):
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            actual = directory / 'actual.json'
            actual.write_text('{}')
            actual.chmod(0o600)
            (directory / 'recovery.json').symlink_to(actual)
            with self.assertRaises(QUAL.QualificationError):
                QUAL._safe_record(directory)

    def test_recovery_input_with_unsafe_mode_is_rejected(self):
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, None)
            (directory / 'recovery.json').chmod(0o644)
            with self.assertRaisesRegex(QUAL.QualificationError, 'unsafe_private_mode'):
                QUAL._safe_record(directory)

    def test_expired_or_overlong_recovery_deadline_is_rejected(self):
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, None)
            path = directory / 'recovery.json'
            value = json.loads(path.read_text())
            value['deadline'] = int(time.time()) + 2 * QUAL.RECOVERY_SECONDS
            unsigned = dict(value)
            unsigned.pop('recordSha256')
            value['recordSha256'] = hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            with self.assertRaises(QUAL.QualificationError):
                QUAL._safe_record(directory)

    def test_genuinely_expired_recovery_deadline_with_valid_digest_is_rejected(self):
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, None)
            path = directory / 'recovery.json'
            rewrite_recovery_record(path, deadline=int(time.time()) - QUAL.RECOVERY_SECONDS - 1)
            with self.assertRaisesRegex(QUAL.QualificationError, 'recovery_record_invalid'):
                QUAL._safe_record(directory)

    def test_disconnected_proxy_restores_by_mode_then_verifies_health(self):
        fake = FakeWarp('proxy', disconnected_proxy=True)
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            result = QUAL._restore_record(directory, fake)
            self.assertEqual(result, 'restored')
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertEqual([call[2] for call in fake.calls if call[1:2] == ('mode',)], ['warp+doh'])
            receipt = json.loads((directory / 'restoration.json').read_text())
            self.assertTrue(receipt['finalHealthy'])
            self.assertEqual(receipt['finalMode'], 'warp+doh')

    def test_independent_restorer_retries_transient_deadline_mode_read(self):
        class FlakySettingsWarp(FakeWarp):
            def __init__(self):
                super().__init__()
                self.settings_reads = 0

            def __call__(self, argv, timeout):
                if argv[1:4] == ('--json', 'settings', 'list'):
                    self.settings_reads += 1
                    if self.settings_reads == 2:
                        self.calls.append(argv)
                        self.timeouts.append(timeout)
                        error = QUAL._canary.CanaryError('warp_command_timeout')
                        error.cleanup_errors = ()
                        raise error
                return super().__call__(argv, timeout)

        fake = FlakySettingsWarp()
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            # Model the parent's handoff so older implementations don't wait
            # until their reserve-trigger time before reaching the flaky read.
            (directory / 'restore.request').touch()
            real_global_lock = QUAL._global_lock

            def after_parent_switch(*, nonblocking=True, shared=False):
                fake.mode = 'proxy'
                return real_global_lock(nonblocking=nonblocking, shared=shared)

            with patch.object(QUAL, 'GLOBAL_LOCK_PATH', directory / 'global.lock'), \
                    patch.object(QUAL, 'RECOVERY_RESERVE_SECONDS', 0), \
                    patch.object(QUAL, '_global_lock', side_effect=after_parent_switch):
                result = QUAL._restore_record(directory, fake, wait_deadline=True)

            self.assertEqual(result, 'restored')
            self.assertGreaterEqual(fake.settings_reads, 3)
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertTrue((directory / 'armed.json').exists())
            final = json.loads((directory / 'restorer-final.json').read_text())
            self.assertTrue(final['finalHealthy'])
            self.assertEqual(final['finalMode'], 'warp+doh')

    def test_independent_restorer_waits_for_restore_lock_within_shared_deadline(self):
        class AdvancingClock:
            def __init__(self):
                self.elapsed = 0.0

            def monotonic(self):
                return self.elapsed

            def sleep(self, seconds):
                self.elapsed += seconds

        clock = AdvancingClock()
        fake = FakeWarp('proxy')
        real_flock = QUAL.fcntl.flock
        real_open = QUAL.os.open
        restore_lock_fds = set()
        lock_acquired_at = []

        def record_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if Path(path).name == 'restore.lock':
                restore_lock_fds.add(fd)
            return fd

        def parent_holds_restore_lock(fd, operation):
            if fd in restore_lock_fds and operation == (QUAL.fcntl.LOCK_EX | QUAL.fcntl.LOCK_NB):
                if clock.elapsed < 25:
                    raise BlockingIOError
                lock_acquired_at.append(clock.elapsed)
            return real_flock(fd, operation)

        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            with patch.object(QUAL.time, 'monotonic', side_effect=clock.monotonic), \
                    patch.object(QUAL.time, 'sleep', side_effect=clock.sleep), \
                    patch.object(QUAL.os, 'open', side_effect=record_open), \
                    patch.object(QUAL.fcntl, 'flock', side_effect=parent_holds_restore_lock):
                result = QUAL._restore_record(directory, fake)

            receipt = json.loads((directory / 'restoration.json').read_text())
            self.assertEqual(result, 'restored')
            self.assertEqual(receipt['result'], 'restored')
            self.assertEqual(receipt['finalMode'], 'warp+doh')
            self.assertTrue(receipt['finalHealthy'])
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertEqual(len(lock_acquired_at), 1)
            self.assertGreaterEqual(lock_acquired_at[0], 25)
            self.assertLess(clock.elapsed, QUAL.RECOVERY_SECONDS)
            self.assertFalse((directory / 'restoration-failed.json').exists())

    def test_restoration_receipt_tracks_delayed_mode_flip_during_health_readback(self):
        class DelayedModeWarp(FakeWarp):
            def __init__(self):
                super().__init__('proxy')
                self.restore_pending = False
                self.health_reads = 0

            def __call__(self, argv, timeout):
                if argv[1:2] == ('mode',) and argv[2] == 'warp+doh':
                    self.calls.append(argv)
                    self.timeouts.append(timeout)
                    self.restore_pending = True
                    return b''
                if argv[1:3] == ('--json', 'status') and self.restore_pending:
                    self.health_reads += 1
                    if self.health_reads >= 2:
                        self.mode = 'warp+doh'
                        self.restore_pending = False
                return super().__call__(argv, timeout)

        fake = DelayedModeWarp()
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            self.assertEqual(QUAL._restore_record(directory, fake), 'restored')
            receipt = json.loads((directory / 'restoration.json').read_text())
            self.assertTrue(receipt['finalHealthy'])
            self.assertEqual(receipt['finalMode'], 'warp+doh')
            self.assertEqual(fake.mode, 'warp+doh')

    def test_external_mode_reverting_to_proxy_resumes_conditional_restore(self):
        class ExternalThenProxyWarp(FakeWarp):
            def __init__(self):
                super().__init__('warp')
                self.settings_reads = 0

            def __call__(self, argv, timeout):
                if argv[1:4] == ('--json', 'settings', 'list'):
                    self.settings_reads += 1
                    if self.settings_reads == 2:
                        self.mode = 'proxy'
                return super().__call__(argv, timeout)

        fake = ExternalThenProxyWarp()
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            result = QUAL._restore_record(directory, fake)
            receipt = json.loads((directory / 'restoration.json').read_text())
            self.assertEqual(result, 'restored')
            self.assertEqual(receipt['result'], 'restored')
            self.assertEqual(receipt['finalMode'], 'warp+doh')
            self.assertTrue(receipt['finalHealthy'])
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertEqual([call[2] for call in fake.calls if call[1:2] == ('mode',)], ['warp+doh'])

    def test_third_mode_during_health_verification_requires_stable_double_read(self):
        class ThirdModeDuringHealthWarp(FakeWarp):
            def __init__(self):
                super().__init__('proxy')
                self.restore_requested = False
                self.status_reads_after_restore = 0
                self.observed_modes = []

            def __call__(self, argv, timeout):
                if argv[1:2] == ('mode',) and argv[2] == 'warp+doh':
                    self.calls.append(argv)
                    self.timeouts.append(timeout)
                    self.mode = 'warp+doh'
                    self.restore_requested = True
                    return b''
                if argv[1:3] == ('--json', 'status') and self.restore_requested:
                    self.status_reads_after_restore += 1
                    if self.status_reads_after_restore == 2:
                        self.mode = 'warp'
                if argv[1:4] == ('--json', 'settings', 'list'):
                    self.observed_modes.append(self.mode)
                return super().__call__(argv, timeout)

        fake = ThirdModeDuringHealthWarp()
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            result = QUAL._restore_record(directory, fake)
            receipt = json.loads((directory / 'restoration.json').read_text())
            self.assertEqual(result, 'restore_skipped_external_change')
            self.assertEqual(receipt['result'], 'restore_skipped_external_change')
            self.assertEqual(receipt['finalMode'], 'warp')
            self.assertFalse(receipt['finalHealthy'])
            self.assertGreaterEqual(fake.observed_modes.count('warp'), 4)
            self.assertEqual(fake.mode, 'warp')
            self.assertEqual([call[2] for call in fake.calls if call[1:2] == ('mode',)], ['warp+doh'])

    def test_expired_recovery_record_preserves_state_without_warp_commands(self):
        fake = FakeWarp('proxy')
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            record = rewrite_recovery_record(directory / 'recovery.json', deadline=int(time.time()) - 1)
            original_bytes = (directory / 'recovery.json').read_bytes()
            with self.assertRaisesRegex(QUAL.QualificationError, 'recovery_deadline_expired'):
                QUAL._restore_record(directory, fake)
            self.assertFalse(fake.calls)
            self.assertEqual((directory / 'recovery.json').read_bytes(), original_bytes)
            failed = json.loads((directory / 'restoration-failed.json').read_text())
            self.assertEqual(failed['kind'], 'warp-restoration-failed-v1')
            self.assertEqual(failed['nonce'], record['nonce'])
            self.assertEqual(failed['recordSha256'], hashlib.sha256(original_bytes).hexdigest())
            self.assertEqual(failed['code'], 'recovery_deadline_expired')

    def test_failed_probe_preserves_owner_selected_third_mode(self):
        fake = FakeWarp()
        GuardedClient.calls = 0
        GuardedClient.statuses = [409]
        GuardedClient.error_codes = ['native_binding_unqualified']
        TimeoutClient.calls = 0

        class ExternalModeTimeoutClient(TimeoutClient):
            async def runtime_status(self, _runtime_id):
                type(self).calls += 1
                fake.mode = 'warp'
                raise TimeoutError('request_timeout')

        def loader_for_timeout(config_path, _state):
            transport = json.loads(Path(config_path).read_text()).get('httpsTransport', 'direct')
            return GuardedClient() if transport == 'direct' else ExternalModeTimeoutClient()

        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            config = root / 'cloud.json'
            config.write_text(json.dumps(cloud_config()))
            config.chmod(0o600)

            def arm_without_launchd(directory, before, runner, _lock_fd):
                return fake_arm(directory, before, runner)

            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_port_free', return_value=True), \
                    patch.object(QUAL, 'RECOVERY_RESERVE_SECONDS', 0), \
                    patch.object(QUAL, '_arm', side_effect=arm_without_launchd), \
                    patch.object(QUAL, '_restorer_stopped', return_value=True) as stopped:
                with self.assertRaises(TimeoutError):
                    QUAL.qualify(config, root / 'state', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=loader_for_timeout,
                                 listener_check=lambda: True)

            self.assertTrue(stopped.called)
            self.assertEqual(fake.mode, 'warp')
            self.assertEqual([call[2] for call in fake.calls if call[1:2] == ('mode',)], ['proxy'])
            self.assertFalse(list(root.glob('warp-host-qualification-*/qualification.json')))

    def test_recovery_cli_commands_are_clamped_to_record_deadline(self):
        fake = FakeWarp('proxy')
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, fake)
            rewrite_recovery_record(directory / 'recovery.json', deadline=int(time.time()) + 3)
            self.assertEqual(QUAL._restore_record(directory, fake), 'restored')
            self.assertTrue(fake.timeouts)
            self.assertTrue(all(0 < timeout <= 3 for timeout in fake.timeouts))

    def test_occupied_proxy_port_fails_before_arming_or_switching(self):
        fake = FakeWarp()
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_port_free', return_value=False):
                with self.assertRaises(QUAL.QualificationError):
                    QUAL.qualify('/ignored', '/ignored', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=loader, arm=lambda *_: self.fail('armed'))
        self.assertFalse(any(call[1:2] == ('mode',) for call in fake.calls))

    def test_overlapping_run_refuses_before_inspection(self):
        fake = FakeWarp()
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_global_lock', side_effect=BlockingIOError):
                with self.assertRaises(QUAL.QualificationError):
                    QUAL.qualify('/ignored', '/ignored', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=loader)
        self.assertFalse(fake.calls)

    def test_proxy_timeout_restores_without_retry(self):
        fake = FakeWarp()
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            config = root / 'cloud.json'
            config.write_text(json.dumps(cloud_config()))
            config.chmod(0o600)

            def loader_for_timeout(config_path, state_dir):
                transport = json.loads(Path(config_path).read_text()).get('httpsTransport', 'direct')
                return GuardedClient() if transport == 'direct' else TimeoutClient()
            TimeoutClient.calls = 0
            with patch.object(QUAL, '_check_path_acl'), patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
                    patch.object(QUAL.os, 'geteuid', return_value=QUAL.OWNER_UID), \
                    patch.object(QUAL, 'GLOBAL_LOCK_PATH', root / 'global.lock'), \
                    patch.object(QUAL, '_port_free', return_value=True):
                with self.assertRaises(TimeoutError):
                    QUAL.qualify(config, root / 'state', '00000000-0000-0000-0000-000000000001', root,
                                 runner=fake, client_loader=loader_for_timeout, arm=fake_arm,
                                 listener_check=lambda: True)
            self.assertEqual(TimeoutClient.calls, 1)
            self.assertEqual(fake.mode, 'warp+doh')
            self.assertEqual([call[2] for call in fake.calls if call[1:2] == ('mode',)], ['proxy', 'warp+doh'])

    def test_bad_recovery_digest_fails_before_switch(self):
        with temporary_directory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            fake_arm(directory, {'mode': 'warp+doh'}, None)
            path = directory / 'recovery.json'
            value = json.loads(path.read_text())
            value['nonce'] = 'b' * 32
            path.write_text(json.dumps(value))
            with self.assertRaises(QUAL.QualificationError):
                QUAL._restore_record(directory, FakeWarp())


if __name__ == '__main__':
    unittest.main()
