"""Mock-only preflight: never invokes Docker or the container child."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import supervisor as s

CID = 'a' * 64
NAME = 'reviewer-isolation-test'
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
            ('Config.Env', ['GH_TOKEN=synthetic']), ('Config.Labels.reviewer.fixture', 'other'),
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
        with patch.dict(s.os.environ, {'HOME': '/host', 'PATH': '/bin', 'GH_TOKEN': 'synthetic', 'ANTHROPIC_API_KEY': 'synthetic', 'HOST_CANARY': 'synthetic'}, clear=True):
            self.assertEqual(s.docker_env(), {'HOME': '/host', 'PATH': '/bin'})


if __name__ == '__main__':
    unittest.main()
