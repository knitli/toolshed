"""Mock-only preflight: never invokes Docker or the container child."""
import copy
import json
import os
import stat
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import supervisor as s

CID = 'a' * 64
NAME = 'reviewer-isolation-' + 'b' * 32
ENV_SENTINEL = 'boundary-test-value'
CANARY = Path('/private/owned/canary')


def inspected():
    return {'Id': CID, 'Image': s.IMAGE, 'Name': '/' + NAME,
            'State': {'Status': 'created', 'Running': False, 'Pid': 0},
            'Config': {'Labels': {'reviewer.fixture': NAME}, 'User': '65532:65532',
                       'Entrypoint': ['python3'], 'Cmd': ['-I', '-B', '/fixture/child.py', str(CANARY)], 'Env': ['PATH=/usr/bin']},
            'Mounts': [{'Type': 'bind', 'Source': str(s.FIXTURE), 'Destination': '/fixture', 'RW': False}],
            'HostConfig': {'NetworkMode': 'none', 'Privileged': False, 'ReadonlyRootfs': True,
                           'PidsLimit': 32, 'Memory': 134217728, 'MemorySwap': 134217728, 'NanoCpus': 1000000000,
                           'IpcMode': 'private', 'PublishAllPorts': False, 'PidMode': '', 'CapDrop': ['ALL'],
                           'SecurityOpt': ['no-new-privileges:true'], 'Tmpfs': {'/work': s.TMPFS},
                           'LogConfig': {'Type': 'none'}, 'RestartPolicy': {'Name': 'no'}}}


class Tests(unittest.TestCase):
    def test_valid_inspect_and_every_boundary_mutation(self):
        base = inspected()
        s.validate_inspect(base, CID, CANARY, NAME)
        mutations = [
            ('Image', 'wrong'), ('Name', '/other'),
            ('HostConfig.NetworkMode', 'host'), ('HostConfig.Privileged', True),
            ('HostConfig.ReadonlyRootfs', False), ('HostConfig.PidMode', 'host'),
            ('HostConfig.PidsLimit', 0), ('HostConfig.Memory', 0), ('HostConfig.MemorySwap', -1),
            ('HostConfig.NanoCpus', 0), ('HostConfig.IpcMode', 'host'), ('HostConfig.PublishAllPorts', True),
            ('HostConfig.CapDrop', []), ('HostConfig.CapAdd', ['SYS_ADMIN']),
            ('HostConfig.SecurityOpt', []), ('HostConfig.Tmpfs', {}),
            ('HostConfig.LogConfig.Type', 'json-file'), ('HostConfig.RestartPolicy.Name', 'always'),
            ('HostConfig.Devices', ['device']), ('HostConfig.DeviceRequests', ['gpu']),
            ('HostConfig.VolumesFrom', ['foreign']), ('HostConfig.PortBindings', {'1': '1'}),
            ('Config.User', '0'), ('Config.Entrypoint', ['sh']), ('Config.Cmd', ['other']),
            ('Config.Env', ['GH_TOKEN=' + ENV_SENTINEL]), ('Config.Labels.reviewer.fixture', 'other'),
            ('Mounts', []), ('State.Running', True), ('State.Status', 'running'),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(base)
                if path == 'Config.Labels.reviewer.fixture':
                    changed['Config']['Labels']['reviewer.fixture'] = value
                else:
                    keys = path.split('.')
                    node = changed
                    for key in keys[:-1]:
                        node = node[key]
                    node[keys[-1]] = value
                with self.assertRaises(RuntimeError):
                    s.validate_inspect(changed, CID, CANARY, NAME)
        for mutation in ({'RW': True}, {'Source': '/home'}, {'Destination': '/var/run/docker.sock'}):
            changed = copy.deepcopy(base)
            changed['Mounts'][0].update(mutation)
            with self.assertRaises(RuntimeError):
                s.validate_inspect(changed, CID, CANARY, NAME)

    def test_child_result_missing_false_wrong_pid_refused(self):
        result = {'checks': dict.fromkeys(s.CHECKS, True), 'init_pid': 1, 'descendant_pid': 2}
        s.validate_report(json.dumps(result))
        for key in s.CHECKS:
            bad = copy.deepcopy(result)
            bad['checks'][key] = False
            with self.assertRaises(RuntimeError):
                s.validate_report(json.dumps(bad))
        result['init_pid'] = 30
        with self.assertRaises(RuntimeError):
            s.validate_report(json.dumps(result))

    def test_cleanup_requires_authoritative_stop_and_removal(self):
        calls = []
        count = 0

        def invoke(args):
            nonlocal count
            calls.append(args)
            if args[0] == 'inspect':
                count += 1
                return json.dumps([{'Id': CID, 'State': {'Running': count == 1, 'Pid': 9 if count == 1 else 0}}]).encode()
            return b''
        s.cleanup(CID, invoke)
        self.assertIn(['kill', CID], calls)
        self.assertIn(['rm', '--force', CID], calls)
        self.assertEqual(calls[-1][0:2], ['container', 'ls'])

    def test_cleanup_errors_still_attempt_removal_and_cannot_pass(self):
        for failure in ('inspect', 'kill', 'running', 'rm', 'remaining'):
            calls = []
            count = 0

            def invoke(args):
                nonlocal count
                calls.append(args)
                if args[0] == failure:
                    raise RuntimeError('mock lost response')
                if args[0] == 'inspect':
                    count += 1
                    running = count == 1 or failure == 'running'
                    return json.dumps([{'Id': CID, 'State': {'Running': running, 'Pid': 9 if running else 0}}]).encode()
                if args[0] == 'container' and failure == 'remaining':
                    return CID.encode()
                return b''
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                s.cleanup(CID, invoke)
            self.assertIn(['rm', '--force', CID], calls)
            self.assertEqual(calls[-1][0:2], ['container', 'ls'])

    def test_create_lost_response_recovery_requires_exact_label(self):
        def invoke(args):
            return (CID + '\n').encode() if args[0] == 'container' else json.dumps([inspected()]).encode()
        self.assertEqual(s.recover_owned(NAME, invoke), CID)
        bad = inspected()
        bad['Config']['Labels']['reviewer.fixture'] = 'other'
        with self.assertRaises(RuntimeError):
            s.recover_owned(NAME, lambda args: (CID + '\n').encode() if args[0] == 'container' else json.dumps([bad]).encode())
        self.assertIsNone(s.recover_owned(NAME, lambda args: b''))

    def test_command_plan_has_only_owned_readonly_bind_and_no_pull(self):
        args = s.create_args(NAME, Path('/owned/cid'), CANARY)
        self.assertIn('--pull=never', args)
        self.assertIn(s.IMAGE, args)
        self.assertEqual(args.count('--mount'), 1)
        self.assertEqual(args[args.index('--mount') + 1], f'type=bind,src={s.FIXTURE},dst=/fixture,readonly')
        self.assertFalse(any('privileged' in arg or 'docker.sock' in arg for arg in args))

    def test_client_environment_excludes_host_canary_and_credentials(self):
        overrides = dict.fromkeys(('GH_TOKEN', 'ANTHROPIC_API_KEY', 'HOST_CANARY',
                                  'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
                                  'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY', 'DOCKER_AUTH_CONFIG'), ENV_SENTINEL)
        overrides.update(HOME='/host', PATH='/untrusted/bin')
        with patch.dict(s.os.environ, overrides, clear=True):
            self.assertEqual(s.docker_env(), {'HOME': str(Path.home()), 'PATH': '/usr/bin:/bin'})


class LocalDockerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = Path(self.temp.name).resolve()
        self.socket = self.host / '.docker/run/docker.sock'
        self.socket_stat = os.stat_result((stat.S_IFSOCK | 0o600, 7, 8, 1, os.getuid(), os.getgid(), 0, 0, 0, 0))
        real_lstat = Path.lstat

        def lstat(path, *args, **kwargs):
            if path == self.socket:
                return self.socket_stat
            return real_lstat(path, *args, **kwargs)
        self.home_patch = patch.object(Path, 'home', return_value=self.host)
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)
        self.stat_patch = patch.object(Path, 'lstat', lstat)
        self.stat_patch.start()
        self.addCleanup(self.stat_patch.stop)
        popen_patch = patch.object(s.subprocess, 'Popen')
        self.popen = popen_patch.start()
        self.addCleanup(popen_patch.stop)

    def client(self):
        return s.LocalDocker(self.host, NAME)

    def test_remote_overrides_scrubbed_and_every_invocation_pinned(self):
        overrides = dict.fromkeys(('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
                                  'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY', 'DOCKER_AUTH_CONFIG',
                                  'GH_TOKEN', 'ANTHROPIC_API_KEY'), ENV_SENTINEL)
        overrides['DOCKER_HOST'] = 'tcp://untrusted.invalid:2375'
        with patch.dict(s.os.environ, overrides):
            client = self.client()
            client.start(['image', 'inspect', s.IMAGE])
            client.adopt(CID)
            client.start(['kill', CID])
        self.assertEqual((self.host / 'docker-config').stat().st_mode & 0o777, 0o700)
        self.assertEqual(list((self.host / 'docker-config').iterdir()), [])
        for call in self.popen.call_args_list:
            self.assertEqual(call.args[0][:4], [s.DOCKER, '--host=unix://' + str(self.socket),
                                              '--config', str(self.host / 'docker-config')])
            self.assertEqual(call.kwargs['env'], {'PATH': '/usr/bin:/bin', 'HOME': str(self.host)})
        self.assertEqual(self.popen.call_count, 2)

    def test_invalid_socket_rejected_before_config_or_process(self):
        for mode, uid in ((stat.S_IFREG, os.getuid()), (stat.S_IFLNK, os.getuid()),
                          (stat.S_IFSOCK, os.getuid() + 1)):
            with self.subTest(mode=mode, uid=uid):
                self.socket_stat = os.stat_result((mode | 0o600, 7, 8, 1, uid, os.getgid(), 0, 0, 0, 0))
                with self.assertRaises(RuntimeError):
                    self.client()
                self.assertFalse((self.host / 'docker-config').exists())
        self.popen.assert_not_called()

    def test_socket_identity_rechecked_before_every_process(self):
        client = self.client()
        client.start(['image', 'inspect', s.IMAGE])
        self.socket_stat = os.stat_result((stat.S_IFSOCK | 0o600, 9, 8, 1, os.getuid(), os.getgid(), 0, 0, 0, 0))
        with self.assertRaises(RuntimeError):
            client.start(['image', 'inspect', s.IMAGE])
        self.assertEqual(self.popen.call_count, 1)

    def test_command_allowlist_rejects_mutations_and_foreign_targets(self):
        client = self.client()
        exact_create = s.create_args(NAME, self.host / 'container.cid', self.host / 'host-canary')
        client.start(exact_create)
        client.start(['inspect', CID])
        for args in (['kill', CID], ['rm', '--force', CID], ['start', '--attach', CID]):
            with self.assertRaises(RuntimeError):
                client.start(args)
        client.adopt(CID)
        self.popen.reset_mock()
        bad_create = exact_create.copy()
        bad_create[bad_create.index('--network=none')] = '--network=host'
        bad_name = exact_create.copy()
        bad_name[bad_name.index('--name') + 1] = 'foreign'
        bad_path = exact_create.copy()
        bad_path[bad_path.index('--cidfile') + 1] = '/foreign/container.cid'
        for args in (['system', 'prune'], ['exec', CID, 'sh'], ['--host=tcp://remote', 'info'],
                     ['inspect', 'short'], ['inspect', NAME], ['kill', 'c' * 64],
                     ['rm', '--force', 'c' * 64], ['start', '--attach', 'c' * 64],
                     ['kill', CID, 'c' * 64], ['container', 'ls'],
                     ['container', 'ls', '--all', '--no-trunc', '--filter', 'name=foreign', '--format', '{{.ID}}'],
                     ['container', 'ls', '--all', '--no-trunc', '--filter', 'id=' + 'c' * 64, '--format', '{{.ID}}'],
                     exact_create + ['--privileged'], bad_create, bad_name, bad_path):
            with self.subTest(args=args), self.assertRaises(RuntimeError):
                client.start(args)
        self.popen.assert_not_called()
        with self.assertRaises(RuntimeError):
            client.adopt('c' * 64)

    def test_invalid_names_and_noncanonical_adoption_rejected(self):
        for name in ('foreign', NAME.upper(), NAME + '0'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                s.LocalDocker(self.host, name)
        client = self.client()
        for cid in ('abc', CID.upper(), CID + '\n', NAME):
            with self.subTest(cid=cid), self.assertRaises(RuntimeError):
                client.adopt(cid)
        self.popen.assert_not_called()

    def test_host_permissions_and_existing_config_rejected(self):
        self.host.chmod(0o755)
        with self.assertRaises(RuntimeError):
            self.client()
        self.host.chmod(0o700)
        (self.host / 'docker-config').mkdir(mode=0o700)
        with self.assertRaises((RuntimeError, FileExistsError)):
            self.client()
        self.popen.assert_not_called()

    def test_daemon_identity_requires_nonempty_id(self):
        client = self.client()
        with patch.object(client, 'command', return_value=b'daemon-id\n') as command:
            self.assertEqual(client.daemon_identity(), 'daemon-id')
            command.assert_called_once_with(['info', '--format', '{{.ID}}'])
        with patch.object(client, 'command', return_value=b' \n'):
            with self.assertRaises(RuntimeError):
                client.daemon_identity()
        self.popen.assert_not_called()

    def test_failed_command_retains_bounded_diagnostic_and_closes_client(self):
        client = self.client()
        process = self.popen.return_value
        process.wait.return_value = 125
        output = b'fixture error\x1b[31m\n' + b'x' * (s.DIAGNOSTIC_LIMIT + 1)
        with patch.object(s, 'read_bounded', return_value=output), \
                patch.object(s, 'finish_client') as finish, \
                self.assertRaises(RuntimeError) as caught:
            client.command(['image', 'inspect', s.IMAGE])
        prefix, raw = str(caught.exception).split(': ', 1)
        self.assertEqual(prefix, 'docker image failed')
        detail = json.loads(raw)
        self.assertEqual(detail, {
            'exitCode': 125, 'outputBytes': len(output),
            'outputSha256': s.hashlib.sha256(output).hexdigest(),
            'outputPrefix': output[:s.DIAGNOSTIC_LIMIT].decode(), 'truncated': True,
        })
        self.assertNotIn('\x1b', str(caught.exception))
        self.assertNotIn(str(self.host), str(caught.exception))
        finish.assert_called_once_with(process)

    def test_successful_command_returns_output_without_diagnostic(self):
        client = self.client()
        process = self.popen.return_value
        process.wait.return_value = 0
        with patch.object(s, 'read_bounded', return_value=b'fixture output'), \
                patch.object(s, 'finish_client') as finish:
            self.assertEqual(client.command(['info', '--format', '{{.ID}}']), b'fixture output')
        finish.assert_called_once_with(process)

    def test_boolean_pids_rejected(self):
        for key in ('init_pid', 'descendant_pid'):
            report = {'checks': dict.fromkeys(s.CHECKS, True), 'init_pid': 1, 'descendant_pid': 2}
            report[key] = True
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                s.validate_report(json.dumps(report))


class RunOwnershipTests(unittest.TestCase):
    def run_case(self, failure):
        with patch.object(s, 'LocalDocker') as constructor, patch.object(s, 'cleanup') as cleanup, \
                patch('builtins.print') as output:
            docker = constructor.return_value
            docker.daemon_identity.return_value = 'mock-daemon'
            created = False
            inspected_once = False

            def invoke(args):
                nonlocal created, inspected_once
                host, name = constructor.call_args.args
                if args[0] == 'image':
                    return json.dumps([{'Id': s.IMAGE, 'Os': 'linux', 'Architecture': 'arm64'}]).encode()
                if args[0] == 'create':
                    (host / 'container.cid').write_text(CID)
                    created = True
                    return CID.encode()
                if args[0] == 'container':
                    self.assertEqual(args, ['container', 'ls', '--all', '--no-trunc', '--filter',
                                            f'name=^/{name}$', '--format', '{{.ID}}'])
                    return CID.encode() if created else b''
                self.assertEqual(args, ['inspect', CID])
                if failure == 'unavailable' and not inspected_once:
                    inspected_once = True
                    raise RuntimeError('initial inspection unavailable')
                value = inspected()
                value['Name'] = '/' + name
                value['Config']['Labels']['reviewer.fixture'] = name
                value['Config']['Cmd'][-1] = str(host / 'host-canary')
                if failure == 'Id':
                    value['Id'] = 'c' * 64
                elif failure == 'Name':
                    value['Name'] = '/foreign'
                elif failure == 'label':
                    value['Config']['Labels']['reviewer.fixture'] = 'foreign'
                elif failure == 'config':
                    value['HostConfig']['NetworkMode'] = 'host'
                return json.dumps([value]).encode()

            docker.command.side_effect = invoke
            self.assertEqual(s.run(), 1)
            docker.start.assert_not_called()
            self.assertEqual(json.loads(output.call_args.args[0])['status'], 'FAIL')
            if failure in ('Id', 'Name', 'label'):
                docker.adopt.assert_not_called()
                cleanup.assert_not_called()
            else:
                docker.adopt.assert_called_once_with(CID)
                cleanup.assert_called_once_with(CID, docker.command)
            return docker

    def test_foreign_inspection_never_adopts_or_cleans(self):
        for failure in ('Id', 'Name', 'label'):
            with self.subTest(failure=failure):
                self.run_case(failure)

    def test_owned_bad_config_is_cleaned_without_start(self):
        self.run_case('config')

    def test_unavailable_initial_inspection_recovers_exact_owned_container(self):
        docker = self.run_case('unavailable')
        self.assertEqual(sum(call.args[0][0] == 'container' for call in docker.command.call_args_list), 2)
        self.assertEqual(sum(call.args[0][0] == 'inspect' for call in docker.command.call_args_list), 2)


if __name__ == '__main__':
    unittest.main()
