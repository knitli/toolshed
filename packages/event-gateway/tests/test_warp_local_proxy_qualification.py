import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
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

    def test_baseline_failure_never_arms_or_switches(self):
        fake = FakeWarp('proxy')
        with temporary_directory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
                    with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
            with patch.object(QUAL.sys, 'platform', 'darwin'), patch.object(QUAL.platform, 'machine', return_value='arm64'), \
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
