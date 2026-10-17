"""No native processes or sandbox probes are launched by these tests."""
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess  # nosec B404 - every process invocation in these tests is mocked.
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
        for fault in (None, 'first-exit', 'first-proof', 'cleanup', 'second-proof', 'timeout'):
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
                if fault is None:
                    self.assertEqual(evidence, ['execute', 'three-session', 'execute', 'native-recovery'])
                elif fault != 'second-proof':
                    self.assertLessEqual(evidence.count('execute'), 1)

    def test_empty_json_or_missing_proof_is_never_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root)
            for scenario in ('three-session', 'native-recovery'):
                with self.assertRaises(ValueError):
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
                return subprocess.run(['/usr/bin/git', '-C', str(root), *arguments], check=True,
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
            for field in (None, 'proofNonceChanged', 'ackBodyBytesIdentical'):
                candidate = copy.deepcopy(proof)
                if field:
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
