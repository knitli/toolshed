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
       'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ATTEMPT': '1',
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
                               ('GITHUB_REPOSITORY_ID', '456'), ('ImageVersion', '')]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    HOSTED.admit({**ENV, key: value}, '123')

    def test_command_preserves_installed_verification_and_native_sandbox(self):
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

    def test_policy_has_only_seven_fixed_tcp_endpoints(self):
        profile = HOSTED.network_profile()
        self.assertIn('(deny network*)', profile)
        self.assertNotIn('remote ip', profile)
        endpoints = re.findall(r'\((local|remote) tcp "([^"]+)"\)', profile)
        self.assertEqual(len(endpoints), 21)
        self.assertEqual({endpoint for _, endpoint in endpoints},
                         {f'localhost:{port}' for port in HOSTED.PORTS})
        self.assertEqual(profile.count('(allow network-bind '), 7)

    def test_failed_launch_nonzero_and_missing_proof_remain_incomplete(self):
        for outcome in (OSError('private error'), SimpleNamespace(returncode=7), SimpleNamespace(returncode=0)):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = SimpleNamespace(repository_id='123', binary_sha256='b' * 64,
                                       cloud_commit='c' * 40, output_dir=str(root / 'output'))
                effect = {'side_effect': outcome} if isinstance(outcome, OSError) else {'return_value': outcome}
                with patch.dict(os.environ, ENV, clear=True), patch.object(HOSTED, 'admit'), \
                        patch.object(HOSTED, 'command', return_value=['fixture']), \
                        patch.object(HOSTED.tempfile, 'mkdtemp', return_value=str(root)), \
                        patch.object(HOSTED.subprocess, 'run', **effect):
                    self.assertEqual(HOSTED.run(args), 1)
                result = json.loads((root / 'output/hosted-result.json').read_text())
                self.assertEqual(result['outcome'], 'INCOMPLETE')
                for name in ('network.sb', 'fixture.log', 'hosted-result.json'):
                    self.assertEqual((root / 'output' / name).stat().st_mode & 0o777, 0o600)

    def test_timeout_retains_incomplete_evidence_and_closed_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(repository_id='123', binary_sha256='b' * 64,
                                   cloud_commit='c' * 40, output_dir=str(root / 'output'))
            with patch.dict(os.environ, ENV, clear=True), patch.object(HOSTED, 'admit'), \
                    patch.object(HOSTED, 'command', return_value=['fixture']), \
                    patch.object(HOSTED.tempfile, 'mkdtemp', return_value=str(root)), \
                    patch.object(HOSTED.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixture', 240)) as run:
                self.assertEqual(HOSTED.run(args), 1)
                kwargs = run.call_args.kwargs
                self.assertEqual(set(kwargs['env']), {'PATH', 'HOME', 'TMPDIR', 'TERM', 'LANG'})
                self.assertTrue(kwargs['close_fds'])
                self.assertEqual(kwargs['timeout'], 240)
            result = json.loads((root / 'output/hosted-result.json').read_text())
            self.assertEqual(result['outcome'], 'INCOMPLETE')
            self.assertFalse(result['vmDisposalObserved'])
            self.assertFalse(result['completeDescendantTerminationProven'])
            self.assertTrue(root.is_dir())

    def test_completion_is_not_pass_and_output_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(repository_id='123', binary_sha256='b' * 64,
                                   cloud_commit='c' * 40, output_dir=str(root / 'output'))

            def complete(*_args, **_kwargs):
                (root / 'output/proof.json').write_text('{}')
                return SimpleNamespace(returncode=0)

            with patch.dict(os.environ, ENV, clear=True), patch.object(HOSTED, 'admit'), \
                    patch.object(HOSTED, 'command', return_value=['fixture']), \
                    patch.object(HOSTED.tempfile, 'mkdtemp', return_value=str(root)), \
                    patch.object(HOSTED.subprocess, 'run', side_effect=complete):
                self.assertEqual(HOSTED.run(args), 0)
                with self.assertRaises(FileExistsError):
                    HOSTED.run(args)
            result = json.loads((root / 'output/hosted-result.json').read_text())
            self.assertEqual(result['outcome'], 'FIXTURE_COMPLETED_PENDING_INDEPENDENT_VERIFICATION')
            self.assertFalse(result['nativePromoted'])


if __name__ == '__main__':
    unittest.main()
