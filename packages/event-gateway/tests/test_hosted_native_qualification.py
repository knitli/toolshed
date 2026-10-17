"""No native processes or sandbox probes are launched by these tests."""
import copy
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess  # nosec B404 - mocked providers and fixed Git commands in disposable test repositories.
import tempfile
from types import SimpleNamespace
import unittest
from uuid import uuid4
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / 'scripts/run_hosted_native_qualification.py'
SPEC = importlib.util.spec_from_file_location('hosted_native', SCRIPT)
HOSTED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOSTED)
ENV = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
       'GITHUB_REF': 'refs/heads/main', 'GITHUB_REF_PROTECTED': 'true', 'GITHUB_RUN_ATTEMPT': '1',
       'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64',
       'GITHUB_REPOSITORY_ID': '123', 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '42',
       'ImageOS': 'macos15', 'ImageVersion': 'test', 'GH_TOKEN': str(uuid4())}


def busy_attach_evidence():
    old = {key: str(uuid4()) for key in ('clientId', 'connectionId', 'threadId', 'serverInstanceId')}
    old.update(backendPid=42, generation=1, serverGeneration=1)
    binding = {**old, 'generation': 2}
    mapping = {'runtimeId': str(uuid4()), 'sessionId': str(uuid4()), 'nativeBinding': binding,
               'runtimeGeneration': 4, 'attachmentGeneration': 5}
    result = {'productionCliPath': True, 'remoteStatus': 'attached', 'localStatus': 'current',
              'runtimeGenerationBefore': 3, 'runtimeGenerationAfter': 4,
              'attachmentGenerationBefore': 4, 'attachmentGenerationAfter': 5,
              'coreBusyBeforeAndAfter': True, 'coreBusyDuringAttach': True, 'c1HistoryAndChargesUnchanged': True}
    history = {'localDelivery': {'state': 'observed', 'ack_state': 'observed'},
               'localAttempts': [{'state': 'observed', 'native_observed_ack': 'ack', 'reserved_bytes': 0}],
               'workerdAttempts': [{'state': 'observed'}], 'workerdClaims': [{'attempt_id': 'c1'}],
               'receiptStatuses': ['inputRecorded'], 'nativeStarts': [{'attemptId': 'c1'}],
               'cloudHistory': {key: [] for key in ('attempts', 'deliveries', 'native_claims',
                    'native_correlations', 'manual_sources', 'slot_intents', 'no_start_settlements')},
               'slots': [], 'budget': {'used': 0, 'remaining': 10, 'limit': 10, 'windowMs': 3600000}}
    observations = []
    for nonce in (3, 4, 5):
        challenge = str(uuid4())
        observations.append({'request': {'command': 'challenge', 'challengeId': challenge,
                                         'expectedBinding': binding},
                             'response': {'challengeId': challenge, 'observedAt': '2026-10-17T08:00:00.000Z',
                                          'validUntilMonotonic': float(nonce) + 0.5,
                                          'witness': {**binding, 'version': 2, 'nonce': nonce, 'sequence': nonce,
                                                      'cause': 'heartbeat', 'leaseMs': 750, 'eligible': True,
                                                      'nativeCoreTurnState': 'busy'}},
                             'receivedAt': float(nonce), 'checkedAt': float(nonce) + 0.1})
    observations[1].update(session='C', sessionId=mapping['sessionId'])
    row = {'before': history, 'after': copy.deepcopy(history), 'bindingBefore': old, 'mapping': mapping,
           'busyEvidence': observations, 'preAttachNonces': [1, 2, 3], 'holdDeadline': 60.0, 'result': copy.deepcopy(result),
           'attachRequest': {'operation': 'attach', 'runtimeId': mapping['runtimeId'],
                             'sessionId': mapping['sessionId'], 'expectedRuntimeGeneration': 3,
                             'expectedAttachmentGeneration': 4, 'expectedNativeBinding': binding,
                             'challengeId': observations[1]['request']['challengeId']}}
    row['attachArgv'] = ['--state-dir', '/fixture', 'attach', '--runtime-id', mapping['runtimeId'],
                         '--session-id', mapping['sessionId'], '--cloud-config', '/fixture/cloud.json',
                         '--expected-runtime-generation', '3', '--expected-attachment-generation', '4']
    identities = {field: hashlib.sha256(value.encode()).hexdigest() for field, value in (
        ('runtimeSha256', mapping['runtimeId']), ('sessionSha256', mapping['sessionId']),
        ('threadSha256', binding['threadId']))}
    return result, row, identities


def attach_archive(row):
    hold = {'kind': 'providerHoldStarted', 'value': {'session': 'C', 'phase': 'initial',
            'startedAt': 0.0, 'holdDeadline': 60.0}}
    return ('\n'.join(json.dumps(item) for item in (hold, {'kind': 'busyFixtureAttach', 'value': row})) + '\n').encode()


def c2_archive(row):
    records = [json.loads(line) for line in attach_archive(row).splitlines()]
    delivery = '00000000-0000-4000-8000-000000000002'
    binding = row['mapping']['nativeBinding']
    for phase, nonce in (('initial', 6), ('post-restart', 7)):
        observation = copy.deepcopy(row['busyEvidence'][-1])
        challenge = str(uuid4())
        observation['request']['challengeId'] = challenge
        observation['response'].update(challengeId=challenge, validUntilMonotonic=nonce + .5)
        observation['response']['witness'].update(nonce=nonce, sequence=nonce)
        observation.update(receivedAt=float(nonce), checkedAt=nonce + .1,
                           session='C', sessionId=row['mapping']['sessionId'])
        records.append({'kind': 'c2CoreBusy', 'value': {
            'deliveryId': delivery, 'binding': binding, 'phase': phase, 'checkedAt': nonce + .2,
            'observations': [observation], 'evidenceError': None,
            'status': 'queued', 'reason': 'client_unavailable_or_busy'}})
        if phase == 'initial':
            records.append({'kind': 'c2BusyRestart', 'value': {
                'deliveryId': delivery, 'binding': binding, 'checkedAt': 6.5, 'evidenceError': None}})
    return records


def busy_archive(row):
    return ('\n'.join(json.dumps(item) for item in c2_archive(row)) + '\n').encode()


def c2_proof(result, identities):
    return {'busyFixtureAttach': result, 'nativeCliSessions': {'C': identities},
            'busyC': {'busyDispatchCount': 2, 'deliverySha256': hashlib.sha256(
                b'00000000-0000-4000-8000-000000000002').hexdigest()},
            'busyDeliveryRestart': {'busyDispatchCountAfterRestart': 1},
            'privateEvidence': {'coreBusyNonces': 7}}


class HostedNativeTests(unittest.TestCase):
    def test_admission_rejects_non_hosted_or_automatic_attempts(self):
        with patch.object(HOSTED.platform, 'system', return_value='Darwin'), \
                patch.object(HOSTED.platform, 'machine', return_value='arm64'):
            HOSTED.admit(ENV, '123')
            for key, value in [('RUNNER_ENVIRONMENT', 'self-hosted'), ('GITHUB_RUN_ATTEMPT', '2'),
                               ('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REF', 'refs/heads/candidate'),
                               ('GITHUB_REPOSITORY_ID', '456'), ('GITHUB_REF_PROTECTED', 'false'), ('ImageVersion', '')]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    HOSTED.admit({**ENV, key: value}, '123')

    def test_command_preserves_installed_verification_and_selects_hosted_network_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(package_root=str(root), python=str(root / 'venv/bin/python'),
                                   binary=str(root), binary_sha256='b' * 64, node=str(root),
                                   cloud_source=str(root), cloud_commit='c' * 40,
                                   esbuild=str(root), miniflare=str(root))
            argv = HOSTED.command(args, root / 'network.sb', root)
            self.assertEqual(argv[:3], ['/usr/bin/sandbox-exec', '-f', str(root / 'network.sb')])
            self.assertIn('-I', argv)
            self.assertNotIn('--outer-contained', argv)
            self.assertEqual(argv[-4:], ['--model-ports', '43125', '43126', '43127'])
            fixture_path = SCRIPT.parents[1] / 'docs/native-bridge/three-session-workerd.py'
            spec = importlib.util.spec_from_file_location('hosted_fixture_cli', fixture_path)
            fixture = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(fixture)
            with patch('sys.argv', argv[6:]):
                parsed = fixture.cli()
            self.assertEqual(parsed.model_ports, [43125, 43126, 43127])
            self.assertFalse(parsed.outer_contained)
            self.assertTrue(parsed.trusted_hosted_vm)

    def test_policy_has_only_seven_fixed_tcp_endpoints(self):
        profile = HOSTED.network_profile()
        self.assertIn('(deny network*)', profile)
        self.assertNotIn('remote ip', profile)
        endpoints = re.findall(r'\((local|remote) tcp "([^"]+)"\)', profile)
        self.assertEqual(len(endpoints), 21)
        self.assertEqual({endpoint for _, endpoint in endpoints},
                         {f'localhost:{port}' for port in HOSTED.PORTS})
        self.assertEqual(profile.count('(allow network-bind '), 7)

    def arguments(self, root):
        binary = root / 'codex'
        binary.write_bytes(b'native fixture')
        return SimpleNamespace(repository_id='123', binary_sha256=HOSTED.sha(binary), binary=str(binary),
                               package_root=str(SCRIPT.parents[1]), cloud_commit='c' * 40,
                               output_dir=str(root / 'output'))

    def test_conjoined_result_requires_both_verified_scenarios_and_cleanup(self):
        for fault in (None, 'first-exit', 'first-proof', 'cleanup', 'second-proof', 'timeout', 'verifier-key', 'verifier-type', 'verifier-index'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = self.arguments(root)
                evidence = []

                def execute(*values, **options):
                    self.assertEqual(values[0], ['fixture'])
                    self.assertEqual(set(options['env']), {'PATH', 'HOME', 'TMPDIR', 'TERM', 'LANG'})
                    self.assertEqual(options['umask'], 0o077)
                    self.assertEqual(options['timeout'], 240)
                    self.assertTrue(options['close_fds'])
                    evidence.append('execute')
                    if fault == 'timeout':
                        raise subprocess.TimeoutExpired('fixture', 240)
                    return SimpleNamespace(returncode=7 if fault == 'first-exit' else 0)

                def verify(_args, scenario, _destination):
                    evidence.append(scenario)
                    errors = {'verifier-key': KeyError, 'verifier-type': TypeError, 'verifier-index': IndexError}
                    if fault in errors:
                        raise errors[fault]('synthetic verifier defect')
                    if fault == ('first-proof' if scenario == 'three-session' else 'second-proof'):
                        raise ValueError('invalid proof')
                    return {'scenario': scenario, 'proofSha256': 'd' * 64, 'semanticChecksPassed': True}

                port_checks = [None, OSError('occupied')] if fault == 'cleanup' else [None] * 4
                with patch.dict(os.environ, ENV, clear=True), patch.object(HOSTED, 'admit'), \
                        patch.object(HOSTED, 'cloud_identity'), patch.object(HOSTED, 'ports_released', side_effect=port_checks), \
                        patch.object(HOSTED, 'command', return_value=['fixture']), \
                        patch.object(HOSTED, 'recovery_command', return_value=['fixture']), \
                        patch.object(HOSTED, 'verify_proof', side_effect=verify), \
                        patch.object(HOSTED.tempfile, 'mkdtemp', return_value=str(root)), \
                        patch.object(HOSTED.subprocess, 'run', side_effect=execute):
                    self.assertEqual(HOSTED.run(args), 0 if fault is None else 1)
                    with self.assertRaises(FileExistsError):
                        HOSTED.run(args)
                result = json.loads((root / 'output/hosted-result.json').read_text())
                self.assertEqual(result['outcome'], 'FIXTURE_COMPLETED_PENDING_INDEPENDENT_VERIFICATION' if fault is None else 'INCOMPLETE')
                self.assertFalse(result['nativePromoted'])
                self.assertFalse(result['vmDisposalObserved'])
                for name in ('network.sb', 'hosted-result.json', 'three-session/fixture.log'):
                    self.assertEqual((root / 'output' / name).stat().st_mode & 0o777, 0o600)
                if (root / 'output/native-recovery/fixture.log').exists():
                    self.assertEqual((root / 'output/native-recovery/fixture.log').stat().st_mode & 0o777, 0o600)
                if fault == 'first-exit':
                    self.assertEqual(result['scenarioExecutions'], [{'scenario': 'three-session', 'returncode': 7}])
                if fault in ('verifier-key', 'verifier-type', 'verifier-index'):
                    self.assertEqual(
                        result['failure']['exceptionType'],
                        {'verifier-key': 'KeyError', 'verifier-type': 'TypeError', 'verifier-index': 'IndexError'}[fault],
                    )
                    self.assertEqual(result['failure']['scenario'], 'three-session')
                    self.assertTrue(result['failure']['frames'])
                    self.assertEqual(result['reason'], 'verifier_error')
                    self.assertNotIn('synthetic verifier defect', json.dumps(result))
                if fault is None:
                    self.assertEqual(result['scenarioExecutions'], [{'scenario': name, 'returncode': 0} for name in ('three-session', 'native-recovery')])
                    self.assertEqual(evidence, ['execute', 'three-session', 'execute', 'native-recovery'])
                elif fault != 'second-proof':
                    self.assertLessEqual(evidence.count('execute'), 1)

    def test_bounded_evidence_open_cannot_follow_a_late_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, other = root / 'proof', root / 'other'
            evidence.write_bytes(b'original')
            other.write_bytes(b'substituted')
            original_open = Path.open

            def swapped_open(path, *args, **kwargs):
                if path == evidence:
                    evidence.unlink()
                    evidence.symlink_to(other)
                return original_open(path, *args, **kwargs)

            with patch.object(Path, 'open', swapped_open):
                self.assertEqual(HOSTED.read_bounded(evidence, 32), b'original')

    def test_bounded_evidence_rejects_nonregular_open_descriptor_and_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'proof'
            path.write_bytes(b'12345')
            with self.assertRaises(ValueError):
                HOSTED.read_bounded(path, 4)
            reader, writer = os.pipe()
            try:
                with patch.object(HOSTED.os, 'open', return_value=os.dup(reader)), self.assertRaises(ValueError):
                    HOSTED.read_bounded(path, 32)
            finally:
                os.close(reader)
                os.close(writer)
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises((OSError, ValueError)):
                HOSTED.read_bounded(link, 32)

    def test_empty_json_or_missing_proof_is_never_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root)
            for scenario in ('three-session', 'native-recovery'):
                with self.assertRaises(OSError):
                    HOSTED.verify_proof(args, scenario, root)
                (root / 'proof.json').write_text('{}')
                with self.assertRaises(KeyError):
                    HOSTED.verify_proof(args, scenario, root)
                (root / 'proof.json').unlink()

    def test_recovery_command_keeps_assertions_and_fixed_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(package_root=str(SCRIPT.parents[1]), python=str(root / 'python'),
                                   binary=str(root), binary_sha256='b' * 64, node=str(root),
                                   cloud_source=str(root), cloud_commit='c' * 40, esbuild=str(root), miniflare=str(root))
            argv = HOSTED.recovery_command(args, root / 'network.sb', root)
            self.assertEqual(argv[4:6], ['-I', '-B'])
            self.assertNotIn('-O', argv)
            for flag in ('--installed', '--restart-native', '--restart-inflight', '--trusted-hosted-vm'):
                self.assertIn(flag, argv)
            self.assertEqual(argv[-8:], ['--entry-port', '43121', '--loopback-port', '43122', '--broker-port', '43123', '--model-port', '43125'])

    def test_port_probe_fails_closed_without_retry(self):
        from unittest.mock import MagicMock
        listener = MagicMock()
        listener.__enter__.return_value = listener
        listener.bind.side_effect = OSError('occupied')
        with patch.object(HOSTED.socket, 'socket', return_value=listener) as factory, self.assertRaises(OSError):
            HOSTED.ports_released()
        self.assertEqual(factory.call_count, 1)

    def test_port_probe_holds_both_families_for_every_fixed_port(self):
        from unittest.mock import MagicMock
        listeners = []

        def create(family, kind):
            self.assertEqual(kind, HOSTED.socket.SOCK_STREAM)
            listener = MagicMock()
            listener.__enter__.return_value = listener

            def bind(address):
                self.assertTrue(all(not prior.__exit__.called for prior in listeners))
                self.assertEqual(address[0], '127.0.0.1' if family == HOSTED.socket.AF_INET else '::1')
            listener.bind.side_effect = bind
            listeners.append(listener)
            return listener

        with patch.object(HOSTED.socket, 'socket', side_effect=create) as factory:
            HOSTED.ports_released()
        self.assertEqual(factory.call_count, 14)
        for index, listener in enumerate(listeners):
            listener.bind.assert_called_once_with(('127.0.0.1' if index < 7 else '::1', HOSTED.PORTS[index % 7]))
            listener.setsockopt.assert_any_call(HOSTED.socket.SOL_SOCKET, HOSTED.socket.SO_REUSEADDR, 1)
            if index >= 7:
                listener.setsockopt.assert_any_call(HOSTED.socket.IPPROTO_IPV6, HOSTED.socket.IPV6_V6ONLY, 1)
            listener.__exit__.assert_called_once()

    def test_cloud_revision_and_source_root_are_verified_before_native(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'cloud'
            source = root / 'apps/os/packages/event-runtime/src'
            source.mkdir(parents=True)
            root = root.resolve()
            args = SimpleNamespace(cloud_source=str(source), cloud_commit='a' * 40)
            for response in (str(root) + '\n' + 'a' * 40 + '\n', str(root) + '\n' + 'b' * 40 + '\n', '/other\n' + 'a' * 40 + '\n'):
                with patch.object(HOSTED.subprocess, 'run', side_effect=lambda argv, **_kwargs:
                                  SimpleNamespace(stdout=response if 'rev-parse' in argv else '')) as run:
                    if response == str(root) + '\n' + args.cloud_commit + '\n':
                        HOSTED.cloud_identity(args, {'HOME': str(root)})
                    else:
                        with self.assertRaises(ValueError):
                            HOSTED.cloud_identity(args, {'HOME': str(root)})
                    self.assertEqual(run.call_args.args[0][0], '/usr/bin/git')
                    self.assertEqual(run.call_args.kwargs['timeout'], 10)

    def test_cloud_identity_rejects_tracked_staged_and_untracked_source_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'cloud'
            source = root / 'apps/os/packages/event-runtime/src'
            source.mkdir(parents=True)
            entry = source / 'index.ts'
            entry.write_text('export {};\n')
            (root / '.gitignore').write_text('ignored.ts\nnode_modules/\n')

            def git(*arguments):
                # Fixed executable and test-owned arguments; no shell or external input.
                return subprocess.run(['/usr/bin/git', '-C', str(root), *arguments], check=True,  # nosec B603
                                      capture_output=True, text=True).stdout.strip()
            git('init', '-q')
            git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'synthetic source')
            args = SimpleNamespace(cloud_source=str(source), cloud_commit=git('rev-parse', 'HEAD'))
            HOSTED.cloud_identity(args, {'PATH': '/usr/bin:/bin', 'HOME': str(root)})
            for change in ('working-tree', 'index', 'untracked', 'ignored'):
                with self.subTest(change=change):
                    target = entry if change in ('working-tree', 'index') else source / ('ignored.ts' if change == 'ignored' else 'new.ts')
                    target.write_text('export const changed = true;\n')
                    if change == 'index':
                        git('add', str(entry))
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        HOSTED.cloud_identity(args, {'PATH': '/usr/bin:/bin', 'HOME': str(root)})
                    git('reset', '--hard', '-q', 'HEAD')
                    if target != entry:
                        target.unlink()

    def test_native_recovery_proof_checks_reject_mutated_causality_and_identity(self):
        import copy
        package = SCRIPT.parents[1].resolve()
        fixture = package / 'docs/native-bridge'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root)
            cloud = root / 'cloud/apps/os/packages/event-runtime/src'
            cloud.mkdir(parents=True)
            source = cloud / 'index.ts'
            source.write_text('export {};')
            args.cloud_source = str(cloud)
            proof = json.loads((fixture / 'coupled-workerd-recovery-proof.json').read_text())
            proof.update(binarySha256=args.binary_sha256, cloudSourceCommit=args.cloud_commit,
                         nativeInFlightRestartProven=True, installedPackage=True,
                         interruptedTurnCompletionProven=False)
            proof['executionContainment'] = {'mode': 'trusted-hosted-vm-network-sandbox',
                'kernelSandboxActive': True, 'defaultNetworkDenied': True,
                'filesystemIsolationProven': False, 'vmDisposalObserved': False}
            proof['restart']['stoppedBeforeHeldModelResponseReleased'] = True
            proof['restart']['processChecks'] = {key: True for key in ('oldTuiStopped', 'oldBackendStopped',
                'tuiPidRotated', 'clientIdRotated', 'serverInstanceIdRotated', 'backendPidRotated', 'threadIdRotated')}
            proof['fixturePorts'] = {'model': 43125, 'entry': 43121, 'loopback': 43122, 'broker': 43123}
            required = [fixture / name for name in ('coupled-workerd.py', 'coupled-workerd-broker.mjs',
                        'coupled-workerd-worker.ts', 'coupled-workerd-source-hashes.mjs',
                        'qualification-installed.py', 'three-session-workerd.py')]
            required.append(package / 'scripts/qualify_native_bridge.py')
            proof['sourceSha256'] = {str(path): HOSTED.sha(path) for path in required}
            proof['cloudBundle'] = {'inputs': {str(source): HOSTED.sha(source)}}
            mutations = [None,
                lambda d: d.update(binarySha256='0' * 64),
                lambda d: d.update(nativeInFlightRestartProven=False),
                lambda d: d['restart'].update(stoppedBeforeHeldModelResponseReleased=False),
                lambda d: d['restart']['processChecks'].update(oldBackendStopped=False),
                lambda d: d['restart'].update(newPid=d['restart']['oldPid']),
                lambda d: d['fullInputRecordedReceipt'].update(attemptId='wrong'),
                lambda d: d['fullInputRecordedReceipt']['outcome'].update(itemId='wrong'),
                lambda d: (d['nativeRequest'].update(attemptId=str(uuid4())),
                           d['fullInputRecordedReceipt'].update(attemptId=d['nativeRequest']['attemptId'])),
                lambda d: d['nativeRequest'].update(receiptVersion=2),
                lambda d: d['settled']['cloud']['attempts'][0].update(permit_id=str(uuid4())),
                lambda d: d['settled']['cloud']['native_claims'][0].update(attempt_id=str(uuid4())),
                lambda d: d['settled']['cloud']['deliveries'][0].update(event_id=str(uuid4())),
                lambda d: d['settled']['cloud']['attempts'][0].update(native_observed_ack_json='{}'),
                lambda d: d['fixtureAdmission']['attached']['nativeBinding'].update(clientId=str(uuid4())),
                lambda d: d['wire'][1].update(body=json.dumps({**json.loads(d['wire'][1]['body']), 'attemptId': str(uuid4())})),
                lambda d: d['wire'][-1]['proof'].update(nonce=d['wire'][-2]['proof']['nonce']),
                lambda d: d['sourceSha256'].update({str(required[0]): '0' * 64}),
                lambda d: d['cloudBundle']['inputs'].update({str(source): '0' * 64}),
                lambda d: d['cloudBundle'].update(inputs={'../cloud/apps/os/packages/event-runtime/src/index.ts': HOSTED.sha(source)}),
                lambda d: d['settled']['slots'].append({'state': 'reserved'}),
                lambda d: d['fixturePorts'].update(model=43126)]
            for index, mutate in enumerate(mutations):
                with self.subTest(index=index):
                    candidate = copy.deepcopy(proof)
                    if mutate:
                        mutate(candidate)
                    (root / 'proof.json').write_text(json.dumps(candidate))
                    if mutate:
                        with self.assertRaises(ValueError):
                            HOSTED.verify_proof(args, 'native-recovery', root)
                    else:
                        self.assertTrue(HOSTED.verify_proof(args, 'native-recovery', root)['semanticChecksPassed'])

    def test_c2_dispatch_evidence_is_required_after_busy_attach(self):
        result, row, identities = busy_attach_evidence()
        proof = c2_proof(result, identities)
        with self.assertRaises(ValueError):
            HOSTED.verify_busy_attach(proof, attach_archive(row))

    def test_c2_dispatch_archive_rejects_causal_forgery(self):
        result, row, identities = busy_attach_evidence()
        proof = c2_proof(result, identities)
        records = c2_archive(row)
        mutations = {
            'missing_initial': lambda p, r: r.pop(2),
            'missing_post_restart': lambda p, r: r.pop(4),
            'missing_restart': lambda p, r: r.pop(3),
            'duplicate_restart': lambda p, r: r.append(copy.deepcopy(r[3])),
            'wrong_public_delivery': lambda p, r: p['busyC'].update(deliverySha256='0' * 64),
            'wrong_session': lambda p, r: r[4]['value']['observations'][0].update(session='B'),
            'wrong_session_id': lambda p, r: r[4]['value']['observations'][0].update(sessionId=str(uuid4())),
            'wrong_phase': lambda p, r: r[4]['value'].update(phase='initial'),
            'wrong_delivery': lambda p, r: r[4]['value'].update(deliveryId=str(uuid4())),
            'wrong_binding': lambda p, r: r[4]['value']['binding'].update(generation=99),
            'missing_witness': lambda p, r: r[4]['value'].update(observations=[]),
            'idle': lambda p, r: r[4]['value']['observations'][0]['response']['witness'].update(nativeCoreTurnState='idle'),
            'expired': lambda p, r: r[4]['value']['observations'][0]['response'].update(validUntilMonotonic=7.0),
            'bool_nonce': lambda p, r: r[4]['value']['observations'][0]['response']['witness'].update(nonce=True),
            'reused_attach_nonce': lambda p, r: r[4]['value']['observations'][0]['response']['witness'].update(nonce=4),
            'reused_dispatch_nonce': lambda p, r: r[4]['value']['observations'][0]['response']['witness'].update(nonce=6),
            'wrong_challenge': lambda p, r: r[4]['value']['observations'][0]['request'].update(challengeId=str(uuid4())),
            'sticky_error': lambda p, r: r[2]['value'].update(evidenceError='invalid witness'),
            'restart_error': lambda p, r: r[3]['value'].update(evidenceError='invalid witness'),
            'wrong_status': lambda p, r: r[4]['value'].update(status='submitted'),
            'wrong_reason': lambda p, r: r[4]['value'].update(reason='unqualified'),
            'outside_hold': lambda p, r: r[4]['value'].update(checkedAt=60.0),
            'restart_after_dispatch': lambda p, r: r[3]['value'].update(checkedAt=8.0),
            'nonfinite_restart': lambda p, r: r[3]['value'].update(checkedAt=float('nan')),
            'wrong_total': lambda p, r: p['busyC'].update(busyDispatchCount=3),
            'wrong_post_total': lambda p, r: p['busyDeliveryRestart'].update(busyDispatchCountAfterRestart=2),
            'wrong_nonce_count': lambda p, r: p['privateEvidence'].update(coreBusyNonces=8),
            'bool_count': lambda p, r: p['busyDeliveryRestart'].update(busyDispatchCountAfterRestart=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                candidate, archive = copy.deepcopy(proof), copy.deepcopy(records)
                mutate(candidate, archive)
                evidence = '\n'.join(json.dumps(record) for record in archive).encode()
                with self.assertRaisesRegex(ValueError, 'Busy attach evidence mismatch'):
                    HOSTED.verify_busy_attach(candidate, evidence)

    def test_busy_attach_rejects_primitive_argv_and_original_hold_forgery(self):
        result, row, identities = busy_attach_evidence()
        proof = c2_proof(result, identities)
        HOSTED.verify_busy_attach(proof, busy_archive(row))
        changes = {
            'witness_bool': lambda r: r['busyEvidence'][1]['response']['witness'].update(serverGeneration=True),
            'request_bool': lambda r: r['busyEvidence'][1]['request'].update(
                expectedBinding={**r['mapping']['nativeBinding'], 'serverGeneration': True}),
            'attach_binding_bool': lambda r: r['attachRequest'].update(
                expectedNativeBinding={**r['mapping']['nativeBinding'], 'serverGeneration': True}),
            'truncated_argv': lambda r: r.update(attachArgv=['attach', '--expected-runtime-generation', '999']),
            'wrong_argv_cas': lambda r: r['attachArgv'].__setitem__(10, '999'),
            'wrong_argv_runtime': lambda r: r['attachArgv'].__setitem__(4, 'other'),
            'wrong_argv_session': lambda r: r['attachArgv'].__setitem__(6, 'other'),
            'inflated_deadline': lambda r: r.update(holdDeadline=1e9),
        }
        for name, mutate in changes.items():
            with self.subTest(mutation=name):
                private = copy.deepcopy(row)
                mutate(private)
                with self.assertRaisesRegex(ValueError, 'Busy attach evidence mismatch'):
                    HOSTED.verify_busy_attach(proof, busy_archive(private))
        for fault in ('missing', 'duplicate', 'reordered', 'extended', 'late_start', 'wrong_phase'):
            with self.subTest(hold=fault):
                records = [json.loads(line) for line in busy_archive(row).splitlines()]
                if fault == 'missing':
                    records.pop(0)
                elif fault == 'duplicate':
                    records.insert(0, copy.deepcopy(records[0]))
                elif fault == 'reordered':
                    records.reverse()
                elif fault == 'extended':
                    records[0]['value']['holdDeadline'] = records[1]['value']['holdDeadline'] = 1e9
                elif fault == 'late_start':
                    records[0]['value']['startedAt'] = 3.05
                else:
                    records[0]['value']['phase'] = 'C3'
                evidence = '\n'.join(json.dumps(record) for record in records).encode()
                with self.assertRaisesRegex(ValueError, 'Busy attach evidence mismatch'):
                    HOSTED.verify_busy_attach(proof, evidence)

    def test_busy_attach_verifier_rejects_falsified_private_evidence(self):
        result, row, identities = busy_attach_evidence()
        proof = c2_proof(result, identities)
        HOSTED.verify_busy_attach(proof, busy_archive(row))
        mutations = {
            'missing_public_section': lambda p, r: p.pop('busyFixtureAttach'),
            'not_cli': lambda p, r: p['busyFixtureAttach'].update(productionCliPath=False),
            'cli_not_busy': lambda p, r: p['busyFixtureAttach'].update(coreBusyDuringAttach=False),
            'false_unchanged': lambda p, r: p['busyFixtureAttach'].update(c1HistoryAndChargesUnchanged=False),
            'bad_runtime_cas': lambda p, r: p['busyFixtureAttach'].update(runtimeGenerationAfter=3),
            'bool_generation': lambda p, r: p['busyFixtureAttach'].update(attachmentGenerationBefore=True),
            'local_not_committed': lambda p, r: p['busyFixtureAttach'].update(localStatus='stale'),
            'private_result_disagrees': lambda p, r: r['result'].update(remoteStatus='denied'),
            'changed_ack': lambda p, r: r['after']['localAttempts'][0].update(native_observed_ack='other'),
            'changed_budget': lambda p, r: r['after']['budget'].update(used=1),
            'changed_slots': lambda p, r: r['after']['slots'].append({'state': 'reserved'}),
            'changed_correlations': lambda p, r: r['after']['cloudHistory']['native_correlations'].append({}),
            'missing_cloud_history': lambda p, r: (r['before'].pop('cloudHistory'), r['after'].pop('cloudHistory')),
            'missing_slot_intents': lambda p, r: (r['before']['cloudHistory'].pop('slot_intents'),
                                                  r['after']['cloudHistory'].pop('slot_intents')),
            'reservation_not_released': lambda p, r: [h['localAttempts'][0].update(reserved_bytes=1)
                                                      for h in (r['before'], r['after'])],
            'ack_not_observed': lambda p, r: [h['localDelivery'].update(ack_state='pending')
                                              for h in (r['before'], r['after'])],
            'duplicate_start': lambda p, r: [h['nativeStarts'].append({'attemptId': 'c1'})
                                            for h in (r['before'], r['after'])],
            'mapping_cas_mismatch': lambda p, r: r['mapping'].update(runtimeGeneration=3),
            'wrong_session_identity': lambda p, r: p['nativeCliSessions']['C'].update(sessionSha256='f' * 64),
            'native_generation_rollback': lambda p, r: r['bindingBefore'].update(generation=3),
            'changed_native_identity': lambda p, r: r['bindingBefore'].update(backendPid=43),
            'missing_cli_observation': lambda p, r: r['busyEvidence'].pop(1),
            'cli_idle': lambda p, r: r['busyEvidence'][1]['response']['witness'].update(nativeCoreTurnState='idle'),
            'cli_ineligible': lambda p, r: r['busyEvidence'][1]['response']['witness'].update(eligible=False),
            'hold_expired': lambda p, r: r.update(holdDeadline=5.0),
            'expired_on_check': lambda p, r: r['busyEvidence'][1].update(checkedAt=4.6),
            'nonfinite_check': lambda p, r: r['busyEvidence'][1].update(checkedAt=float('nan')),
            'expired_post': lambda p, r: r['busyEvidence'][2]['response'].update(validUntilMonotonic=5.0),
            'post_reuses_first_nonce': lambda p, r: r['busyEvidence'][2]['response']['witness'].update(nonce=1),
            'cli_reuses_second_nonce': lambda p, r: r['busyEvidence'][1]['response']['witness'].update(nonce=2),
            'duplicate_witness_nonce': lambda p, r: r['busyEvidence'][2]['response']['witness'].update(nonce=4),
            'missing_prior_nonces': lambda p, r: r.update(preAttachNonces=[3]),
            'challenge_mismatch': lambda p, r: r['busyEvidence'][1]['response'].update(challengeId=str(uuid4())),
            'wrong_witness_binding': lambda p, r: r['busyEvidence'][1]['response']['witness'].update(generation=99),
            'wrong_cli_session': lambda p, r: r['busyEvidence'][1].update(sessionId=str(uuid4())),
            'wrong_attach_operation': lambda p, r: r['attachRequest'].update(operation='status'),
            'wrong_attach_cas': lambda p, r: r['attachRequest'].update(expectedAttachmentGeneration=99),
            'wrong_attach_runtime': lambda p, r: r['attachRequest'].update(runtimeId=str(uuid4())),
            'wrong_attach_challenge': lambda p, r: r['attachRequest'].update(challengeId=str(uuid4())),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                candidate, private = copy.deepcopy(proof), copy.deepcopy(row)
                mutate(candidate, private)
                if name in ('not_cli', 'cli_not_busy', 'false_unchanged', 'bad_runtime_cas',
                            'bool_generation', 'local_not_committed'):
                    private['result'] = copy.deepcopy(candidate['busyFixtureAttach'])
                with self.assertRaisesRegex(ValueError, 'Busy attach evidence mismatch'):
                    HOSTED.verify_busy_attach(candidate, busy_archive(private))
        for evidence in (b'{"kind":"archive","value":{}}\n', busy_archive(row) * 2):
            with self.subTest(archive=evidence[:20]), self.assertRaises(ValueError):
                HOSTED.verify_busy_attach(proof, evidence)

    def test_three_session_proof_requires_private_evidence_and_expected_outcomes(self):
        import copy
        package = SCRIPT.parents[1].resolve()
        fixture = package / 'docs/native-bridge'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root)
            companion = root / 'codex-code-mode-host'
            companion.write_bytes(b'companion')
            cloud = root / 'cloud/apps/os/packages/event-runtime/src'
            cloud.mkdir(parents=True)
            source = cloud / 'index.ts'
            source.write_text('export {};')
            args.cloud_source = str(cloud)
            evidence = b'{"fixture":true}\n'
            (root / 'proof.private-evidence.jsonl').write_bytes(evidence)
            (root / 'proof.private-causal.json').write_text(json.dumps({'nonReuse': True,
                'sourceNonceSha256': {'C1': 'a' * 64, 'C3': 'b' * 64}}))
            proof = {'result': 'PASS', 'productionAdmissionProven': False, 'realModelCalls': 0,
                'cloudSourceCommit': args.cloud_commit, 'qualification': 'controlled-three-real-cli-production-daemon-workerd',
                'nativeBinarySha256': args.binary_sha256, 'codeModeHostSha256': HOSTED.sha(companion),
                'executionContainment': {'mode': 'trusted-hosted-vm-network-sandbox',
                    'kernelSandboxActive': True, 'defaultNetworkDenied': True,
                    'filesystemIsolationProven': False, 'vmDisposalObserved': False},
                'nativeCliSessions': {label: {**{key: str(index) * 64 for key in ('runtimeSha256', 'sessionSha256', 'threadSha256')},
                    'nativeStartCount': 2 if label == 'C' else 1, 'initiallySelectedIdle': True}
                    for index, label in enumerate(('A', 'B', 'C'), 1)},
                'nativeProcessCleanup': {label: {key: True for key in ('launcherExited', 'processGroupClosed',
                    'backendStopped', 'controlSocketRemoved')} for label in ('A', 'B', 'C')},
                'brokerCleanup': {'ownedProcessGroupClosed': True, 'loopbackPortsClosed': True},
                'controlledAssertions': {key: True for key in ('threeIndependentAttachments',
                    'aOnlyAndBOnlySessionIsolation', 'busyDeliveryRemainsDurableWithoutStart',
                    'changedBindingRequiresExplicitAttach', 'oldGenerationDeliveryFencedWithoutStart',
                    'newGenerationDeliverySettledExactlyOnce', 'observedAckReplayLeavesWorkerdStateUnchanged',
                    'exactObservedAckRetryAfterDaemonRestart')},
                'observedAckRestart': {'daemonRestarted': True, 'firstReplyLostAfterWorkerdCommit': True,
                    'ackBodyBytesIdentical': True, 'proofNonceChanged': True, 'nativeProcessRestarted': False,
                    'nativeStartCount': 1},
                'busyC': {'nativeClaimCreated': False, 'nativeStartWhileBusy': False},
                'busyDeliveryRestart': {'queuedAfterBusyRestart': True},
                'postAttachC3': {'nativeStartCount': 1, 'workerdClaimCount': 1, 'localState': 'observed'},
                'sourceSha256': {key: HOSTED.sha(fixture / name) for key, name in {
                    'runner': 'three-session-workerd.py', 'workerFixture': 'coupled-workerd-worker.ts',
                    'broker': 'coupled-workerd-broker.mjs', 'nativeHostQualifier': 'native-host-launcher-qualification.py',
                    'launcherSmoke': 'native-release-launcher-smoke.py', 'installedPreflight': 'qualification-installed.py'}.items()},
                'privateEvidence': {'bytes': len(evidence), 'sha256': __import__('hashlib').sha256(evidence).hexdigest()},
                'privateCausal': {'bytes': (root / 'proof.private-causal.json').stat().st_size,
                                  'sha256': HOSTED.sha(root / 'proof.private-causal.json')},
                'workerdInputsSha256': {str(source.relative_to(cloud.parents[2])): HOSTED.sha(source)}}
            busy_result, busy_row, identities = busy_attach_evidence()
            proof['busyFixtureAttach'] = busy_result
            proof['nativeCliSessions']['C'].update(identities)
            evidence = busy_archive(busy_row)
            (root / 'proof.private-evidence.jsonl').write_bytes(evidence)
            proof['privateEvidence'] = {'bytes': len(evidence), 'sha256': hashlib.sha256(evidence).hexdigest(), 'coreBusyNonces': 7}
            proof['busyC'].update(c2_proof(busy_result, identities)['busyC'])
            proof['busyDeliveryRestart']['busyDispatchCountAfterRestart'] = 1
            for field in (None, 'proofNonceChanged', 'ackBodyBytesIdentical', 'busyFixtureAttach'):
                candidate = copy.deepcopy(proof)
                if field == 'busyFixtureAttach':
                    del candidate[field]
                elif field:
                    candidate['observedAckRestart'][field] = False
                (root / 'proof.json').write_text(json.dumps(candidate))
                if field:
                    with self.assertRaises(ValueError):
                        HOSTED.verify_proof(args, 'three-session', root)
                else:
                    self.assertTrue(HOSTED.verify_proof(args, 'three-session', root)['semanticChecksPassed'])
            (root / 'proof.json').write_text(json.dumps(proof))
            aliases = root / 'bin'
            aliases.mkdir()
            (aliases / 'codex').symlink_to(root / 'codex')
            args.binary = str(aliases / 'codex')
            self.assertTrue(HOSTED.verify_proof(args, 'three-session', root)['semanticChecksPassed'])
            (root / 'proof.private-evidence.jsonl').write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                HOSTED.verify_proof(args, 'three-session', root)
            (root / 'proof.private-evidence.jsonl').write_bytes(evidence)
            causal_path = root / 'proof.private-causal.json'
            causal_path.write_text(json.dumps({'nonReuse': True, 'sourceNonceSha256': {'C1': 'c' * 64, 'C3': 'd' * 64}}))
            with self.assertRaisesRegex(ValueError, 'private causal evidence mismatch'):
                HOSTED.verify_proof(args, 'three-session', root)
            causal_path.write_text(json.dumps({'nonReuse': True, 'sourceNonceSha256': {'C1': 'short', 'C3': 'different'}}))
            proof['privateCausal'] = {'bytes': causal_path.stat().st_size, 'sha256': HOSTED.sha(causal_path)}
            (root / 'proof.json').write_text(json.dumps(proof))
            with self.assertRaisesRegex(ValueError, 'causal nonce evidence mismatch'):
                HOSTED.verify_proof(args, 'three-session', root)


if __name__ == '__main__':
    unittest.main()
