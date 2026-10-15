"""Paired install ordering and preservation using synthetic artifacts only."""

import base64
import csv
from contextlib import ExitStack
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import tomllib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from test_native_ci_provenance import FakeAPI, MAIN, archive_bytes, launcher

SPEC = importlib.util.spec_from_file_location('paired_install', Path(__file__).parents[1] / 'scripts/install_paired_client.py')
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


def wheel_bytes(payload, project, changes=None):
    info = project['name'].replace('-', '_') + '-' + project['version'] + '.dist-info/'
    files = dict(payload)
    files[info + 'METADATA'] = ('Metadata-Version: 2.3\nName: ' + project['name'] + '\nVersion: '
                              + project['version'] + '\nRequires-Python: ' + project['requires-python'] + '\n'
                              + ''.join('Requires-Dist: ' + value + '\n' for value in project['dependencies'])).encode()
    files[info + 'WHEEL'] = b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
    files[info + 'entry_points.txt'] = b'[console_scripts]\nknitli-event-gateway = event_gateway.cli:main\n'
    files.update(changes or {})
    output = io.StringIO()
    writer = csv.writer(output)
    for name, data in files.items():
        writer.writerow((name, 'sha256=' + base64.urlsafe_b64encode(INSTALL.hashlib.sha256(data).digest()).rstrip(b'=').decode(), len(data)))
    writer.writerow((info + 'RECORD', '', ''))
    files[info + 'RECORD'] = output.getvalue().encode()
    return archive_bytes(list(files.items()))


class InstallAPI(FakeAPI):
    def __init__(self):
        """Serve immutable main release data and synthetic native CI metadata."""
        super().__init__()
        self.project = tomllib.loads((INSTALL.ROOT / 'pyproject.toml').read_text())['project']
        self.payload = {'event_gateway/__init__.py': b'raise RuntimeError("never import candidate")\n',
                        'event_gateway/launcher.py': launcher(self.selected['binarySha256'], self.selected['codeModeHostSha256']),
                        'event_gateway/contracts/event-v1/protocol.json': b'{}'}
        self.source_tree = []
        for name, value in self.payload.items():
            relative = name.removeprefix('event_gateway/')
            path = INSTALL.PREFIX + (relative if relative.startswith('contracts/') else 'src/event_gateway/' + relative)
            self.blobs[path, MAIN] = value
            self.source_tree.append({'path': path, 'type': 'blob', 'mode': '100644'})
        for path in (INSTALL.SELF, 'scripts/verify_native_ci_provenance.py', INSTALL.HELPER, 'pyproject.toml', 'uv.lock'):
            self.blobs[INSTALL.PREFIX + path, MAIN] = (INSTALL.ROOT / path).read_bytes()
        self.blobs[INSTALL.V.PROVENANCE, MAIN] = json.dumps(self.selected).encode()
        self.protected = True

    def request(self, endpoint, payload=None):
        if endpoint == '':
            return {'id': INSTALL.V.REPOSITORY_ID}
        if endpoint == 'branches/main':
            return {'protected': self.protected, 'commit': {'sha': MAIN}}
        if endpoint == f'git/trees/{MAIN}?recursive=1':
            return {'truncated': False, 'tree': self.source_tree}
        return super().request(endpoint, payload)


class PairedInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.destination = self.root / 'fresh'
        self.existing = self.root / 'existing-client'
        self.existing.write_bytes(b'keep working installation')
        self.api = InstallAPI()
        self.wheel = self.root / 'knitli_event_gateway-0.1.0-py3-none-any.whl'
        self.wheel.write_bytes(wheel_bytes(self.api.payload, self.api.project))
        self.artifact = self.root / 'native.zip'
        self.artifact.write_bytes(self.api.archive)

    def preflight(self):
        return INSTALL.preflight(self.api, self.wheel, self.artifact, self.destination)

    def unchanged(self):
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.existing.read_bytes(), b'keep working installation')

    def test_full_preflight_reads_no_candidate_code_and_creates_nothing(self):
        before = sorted(self.root.iterdir())
        plan = self.preflight()
        self.assertEqual(plan['main'], MAIN)
        self.assertEqual(sorted(self.root.iterdir()), before)
        self.assertIn('cryptography==50.0.2 --hash=sha256:', plan['requirements'])
        self.assertIn('pycparser==3.0', plan['requirements'])
        self.assertNotIn('ruff', plan['requirements'])

    def test_old_recipe_is_rejected_even_with_unchanged_matching_pins(self):
        path = INSTALL.V.INPUTS['patchSha256']
        self.api.blobs[path, MAIN] = b'new Core-idle recipe'
        with self.assertRaisesRegex(ValueError, 'native_recipe_not_current'):
            self.preflight()
        self.unchanged()

    def test_mismatched_pair_policy_metadata_and_artifact_fail_before_writes(self):
        cases = ('pair', 'policy', 'artifact', 'run', 'protected')
        for case in cases:
            with self.subTest(case=case):
                self.api = InstallAPI()
                self.artifact.write_bytes(self.api.archive)
                if case == 'pair':
                    self.api.selected['binarySha256'] = 'f' * 64
                    self.api.blobs[INSTALL.V.PROVENANCE, MAIN] = json.dumps(self.api.selected).encode()
                elif case == 'policy':
                    self.api.blobs[INSTALL.PREFIX + INSTALL.SELF, MAIN] = b'untrusted policy'
                elif case == 'artifact':
                    self.artifact.write_bytes(b'changed')
                elif case == 'run':
                    self.api.run['head_sha'] = 'f' * 40
                else:
                    self.api.protected = False
                with self.assertRaises(ValueError):
                    self.preflight()
                self.unchanged()

    def test_consistent_record_cannot_authorize_changed_or_extra_wheel_payload(self):
        for change in ({'event_gateway/__init__.py': b'wrong'}, {'../outside': b'escape'}, {'evil.pth': b'import evil'}):
            with self.subTest(change=change):
                self.wheel.write_bytes(wheel_bytes(self.api.payload, self.api.project, change))
                with self.assertRaises(ValueError):
                    self.preflight()
                self.unchanged()

    def test_duplicate_zip_member_is_refused(self):
        data = archive_bytes([('duplicate', b'a'), ('duplicate', b'b')])
        with self.assertRaisesRegex(ValueError, 'duplicate_wheel_member'):
            INSTALL.wheel_payload(data, self.api.payload, self.api.project)

    def test_existing_and_symlink_destinations_are_never_touched(self):
        for path in (self.existing, self.root / 'broken-link'):
            if path != self.existing:
                path.symlink_to(self.root / 'missing')
            with self.assertRaisesRegex(ValueError, 'destination_already_exists'):
                INSTALL.preflight(self.api, self.wheel, self.artifact, path)
        self.unchanged()

    def test_success_orders_mock_install_copy_and_verification_before_handoff(self):
        plan = self.preflight()
        events = []

        def installer(destination, wheel, requirements, wheel_sha256):
            self.assertFalse((destination / 'native').exists())
            self.assertEqual(wheel.read_bytes(), plan['wheel'])
            self.assertIn('--hash=sha256:', requirements.read_text())
            events.append('install')

        def verify(destination, source, helper, selected):
            self.assertEqual(INSTALL.V.digest((destination / 'native/codex').read_bytes()), selected['binarySha256'])
            self.assertEqual((source / 'src/event_gateway/launcher.py').read_bytes(), self.api.payload['event_gateway/launcher.py'])
            self.assertEqual(helper.read_bytes(), (INSTALL.ROOT / INSTALL.HELPER).read_bytes())
            events.append('verify')
        with patch.object(INSTALL, 'install_wheel', side_effect=installer), patch.object(INSTALL, 'verify_destination', side_effect=verify):
            result = INSTALL.install(plan)
        self.assertEqual(events, ['install', 'verify'])
        self.assertEqual(result['sourceRevision'], MAIN)
        self.assertEqual(self.existing.read_bytes(), b'keep working installation')

    def test_input_swap_before_creation_refused(self):
        plan = self.preflight()
        self.artifact.write_bytes(b'changed')
        with self.assertRaises(ValueError), patch.object(INSTALL, 'install_wheel') as installer:
            INSTALL.install(plan)
        installer.assert_not_called()
        self.unchanged()

    def test_install_and_postcheck_failure_cleanup_owned_destination(self):
        for stage in ('install_wheel', 'verify_destination'):
            with self.subTest(stage=stage):
                plan = self.preflight()
                with patch.object(INSTALL, 'install_wheel'), patch.object(INSTALL, 'verify_destination'), \
                        patch.object(INSTALL, stage, side_effect=RuntimeError('injected failure')):
                    with self.assertRaisesRegex(RuntimeError, 'injected failure'):
                        INSTALL.install(plan)
                self.unchanged()

    def test_cleanup_preserves_replaced_destination(self):
        plan = self.preflight()

        def replace(destination, wheel, requirements, wheel_sha256):
            destination.rename(self.root / 'original-owned')
            destination.mkdir()
            (destination / 'replacement').write_text('keep')
            raise RuntimeError('replacement')
        with patch.object(INSTALL, 'install_wheel', side_effect=replace), self.assertRaises(RuntimeError):
            INSTALL.install(plan)
        self.assertEqual((self.destination / 'replacement').read_text(), 'keep')

    def test_locked_dependencies_reject_ambiguity_marker_and_nonregistry(self):
        data = (INSTALL.ROOT / 'uv.lock').read_text()
        for changed in (data + '\n[[package]]\nname="attrs"\nversion="1"\n',
                        data.replace("implementation_name != 'PyPy'", "python_version < '3.14'"),
                        data.replace('registry = "https://pypi.org/simple"', 'registry = "https://evil.invalid"')):
            with self.assertRaises(ValueError):
                INSTALL.locked_requirements(changed.encode(), self.api.project)

    def test_installer_uses_hash_locked_no_dependency_resolution_and_fixed_index(self):
        requirements = self.root / 'requirements.txt'
        requirements.write_text('fixture==1 --hash=sha256:' + 'a' * 64)
        with patch.object(INSTALL.venv, 'EnvBuilder') as builder, patch.object(INSTALL.subprocess, 'run') as run:
            INSTALL.install_wheel(self.root, self.wheel, requirements, INSTALL.V.digest(self.wheel.read_bytes()))
        builder.assert_called_once_with(with_pip=True)
        self.assertEqual(run.call_count, 3)
        for call in run.call_args_list[:2]:
            command = call.args[0]
            for flag in ('--require-hashes', '--no-deps', '--only-binary=:all:', '--isolated'):
                self.assertIn(flag, command)
            self.assertEqual(command[command.index('--index-url') + 1], 'https://pypi.org/simple')
            self.assertNotIn('GITHUB_TOKEN', call.kwargs['env'])

    def test_main_movement_during_preflight_refuses_without_creation(self):
        request = self.api.request
        reads = []

        def moving(endpoint, payload=None):
            result = request(endpoint, payload)
            if endpoint == 'branches/main':
                reads.append(endpoint)
                if len(reads) == 2:
                    result['commit']['sha'] = 'f' * 40
            return result
        with patch.object(self.api, 'request', side_effect=moving):
            with self.assertRaisesRegex(ValueError, 'main_changed_during_preflight'):
                self.preflight()
        self.unchanged()

    def test_artifact_swap_during_install_never_hands_off(self):
        plan = self.preflight()

        def swap(*args):
            self.artifact.write_bytes(archive_bytes([('codex', b'changed'), ('codex-code-mode-host', b'changed')]))
        with patch.object(INSTALL, 'install_wheel', side_effect=swap), patch.object(INSTALL, 'verify_destination') as verify:
            with self.assertRaisesRegex(ValueError, 'copied_native_hash_mismatch'):
                INSTALL.install(plan)
        verify.assert_not_called()
        self.unchanged()

    def test_wheel_dependency_and_entrypoint_metadata_must_match_main(self):
        prefix = 'knitli_event_gateway-0.1.0.dist-info/'
        changes = ({prefix + 'entry_points.txt': b'[console_scripts]\nknitli-event-gateway=evil:run\n'},
                   {prefix + 'METADATA': b'Name: knitli-event-gateway\nVersion: 0.1.0\nRequires-Python: >=3.13\nRequires-Dist: evil\n'})
        for change in changes:
            with self.subTest(change=change):
                self.wheel.write_bytes(wheel_bytes(self.api.payload, self.api.project, change))
                with self.assertRaises(ValueError):
                    self.preflight()
                self.unchanged()

    def test_actual_postcheck_verifies_source_and_record_before_launcher_import(self):
        # A hand-built interpreter fixture exercises the real child without pip or native execution.
        destination = self.destination
        binary_directory = destination / 'bin'
        binary_directory.mkdir(parents=True)
        interpreter = Path(sys._base_executable).resolve()
        (binary_directory / 'python').symlink_to(interpreter)
        (destination / 'pyvenv.cfg').write_text(
            f'home = {interpreter.parent}\ninclude-system-site-packages = false\nversion = {sys.version.split()[0]}\n',
        )
        entrypoint = binary_directory / 'knitli-event-gateway'
        entrypoint.write_text('#!/bin/sh\nexit 99\n')
        entrypoint.chmod(0o700)
        site = destination / f'lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages'
        package = site / 'event_gateway'
        package.mkdir(parents=True)
        info = site / 'knitli_event_gateway-0.1.0.dist-info'
        info.mkdir()
        (info / 'METADATA').write_text('Name: knitli-event-gateway\nVersion: 0.1.0\n')
        (info / 'WHEEL').write_text('Wheel-Version: 1.0\nRoot-Is-Purelib: true\n')
        marker = self.root / 'launcher-imported'
        files = {'__init__.py': b'', 'contracts/event-v1/protocol.json': b'{}',
                 'launcher.py': (f'from pathlib import Path\nPath({str(marker)!r}).write_text("imported")\n'
                                 'def qualified_binary(binary, digest):\n'
                                 '    assert digest == "fixture-native-digest"\n').encode()}
        source = destination / '.paired-source'
        for name, data in files.items():
            approved = source / (name if name.startswith('contracts/') else 'src/event_gateway/' + name)
            approved.parent.mkdir(parents=True, exist_ok=True)
            approved.write_bytes(data)
            installed = package / name
            installed.parent.mkdir(parents=True, exist_ok=True)
            installed.write_bytes(data)
        helper = source / 'qualification-installed.py'
        helper.write_bytes((INSTALL.ROOT / INSTALL.HELPER).read_bytes())

        def write_record():
            output = io.StringIO()
            writer = csv.writer(output)
            for name in files:
                data = (package / name).read_bytes()
                digest = base64.urlsafe_b64encode(INSTALL.hashlib.sha256(data).digest()).rstrip(b'=').decode()
                writer.writerow(('event_gateway/' + name, 'sha256=' + digest, len(data)))
            writer.writerow((info.name + '/RECORD', '', ''))
            (info / 'RECORD').write_text(output.getvalue())

        write_record()
        INSTALL.verify_destination(destination, source, helper, {'binarySha256': 'fixture-native-digest'})
        self.assertEqual(marker.read_text(), 'imported')
        marker.unlink()
        (package / 'launcher.py').write_bytes(files['launcher.py'] + b'\n# tampered installed payload\n')
        for rewrite_record in (False, True):
            with self.subTest(rewrite_record=rewrite_record):
                if rewrite_record:
                    write_record()
                with self.assertRaises(subprocess.CalledProcessError):
                    INSTALL.verify_destination(destination, source, helper, {'binarySha256': 'fixture-native-digest'})
                self.assertFalse(marker.exists(), 'unverified launcher must never be imported')

    def test_parent_swap_cannot_redirect_creation_or_cleanup(self):
        safe = self.root / 'safe'
        safe.mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        self.destination = safe / 'fresh'
        plan = self.preflight()
        original_mkdir = INSTALL.os.mkdir

        def swap(path, mode=0o777, *, dir_fd=None):
            if path == 'fresh' and dir_fd is not None:
                safe.rename(self.root / 'moved-safe')
                safe.symlink_to(outside, target_is_directory=True)
            return original_mkdir(path, mode, dir_fd=dir_fd)

        with patch.object(INSTALL.os, 'mkdir', side_effect=swap), patch.object(INSTALL, 'install_wheel') as installer:
            with self.assertRaises((FileNotFoundError, ValueError)):
                INSTALL.install(plan)
        installer.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(list((self.root / 'moved-safe').iterdir()), [])
        self.assertEqual(self.existing.read_bytes(), b'keep working installation')

    def test_cli_prerequisites_refuse_before_preflight_or_install(self):
        defaults = {'platform': 'darwin', 'version_info': (3, 13),
                    'flags': SimpleNamespace(isolated=1), 'implementation': SimpleNamespace(name='cpython')}
        faults = ({'platform': 'linux'}, {'version_info': (3, 12)}, {'flags': SimpleNamespace(isolated=0)},
                  {'implementation': SimpleNamespace(name='pypy')}, {'machine': 'x86_64'}, {'token': ''})
        for fault in faults:
            with self.subTest(fault=fault), ExitStack() as stack:
                runtime = {**defaults, **{key: value for key, value in fault.items() if key in defaults}}
                for name, value in runtime.items():
                    stack.enter_context(patch.object(INSTALL.sys, name, value))
                stack.enter_context(patch.object(INSTALL.sys, 'argv', [
                    'install_paired_client.py', '--wheel', str(self.wheel), '--native-artifact', str(self.artifact),
                    '--destination', str(self.destination),
                ]))
                stack.enter_context(patch.object(INSTALL.platform, 'machine', return_value=fault.get('machine', 'arm64')))
                stack.enter_context(patch.dict(INSTALL.os.environ, {'GITHUB_TOKEN': fault.get('token', 'fixture-token')}))
                preflight = stack.enter_context(patch.object(INSTALL, 'preflight'))
                install = stack.enter_context(patch.object(INSTALL, 'install'))
                with self.assertRaises(ValueError):
                    INSTALL.main()
                preflight.assert_not_called()
                install.assert_not_called()
                self.unchanged()

    def test_offline_synthetic_install_runs_real_pip_postcheck_and_handoff(self):
        self.api.project['dependencies'] = []
        self.api.payload['event_gateway/__init__.py'] = b''
        marker = self.root / 'synthetic-launcher-imported'
        code = (f'QUALIFIED_SHA256 = {self.api.selected["binarySha256"]!r}\n'
                f'QUALIFIED_CODE_MODE_HOST_SHA256 = {self.api.selected["codeModeHostSha256"]!r}\n'
                f'from pathlib import Path\nPath({str(marker)!r}).write_text("verified")\n'
                'def qualified_binary(binary, digest):\n    assert digest == QUALIFIED_SHA256\n')
        self.api.payload['event_gateway/launcher.py'] = code.encode()
        for name in ('__init__.py', 'launcher.py'):
            self.api.blobs[INSTALL.PREFIX + 'src/event_gateway/' + name, MAIN] = self.api.payload['event_gateway/' + name]
        project = (INSTALL.ROOT / 'pyproject.toml').read_text()
        start = project.index('dependencies = [')
        end = project.index(']', start) + 1
        self.api.blobs[INSTALL.PREFIX + 'pyproject.toml', MAIN] = (project[:start] + 'dependencies = []' + project[end:]).encode()
        self.api.blobs[INSTALL.PREFIX + 'uv.lock', MAIN] = (
            'version = 1\n[[package]]\nname = "knitli-event-gateway"\nversion = "0.1.0"\ndependencies = []\n'
        ).encode()
        self.wheel.write_bytes(wheel_bytes(self.api.payload, self.api.project))
        plan = self.preflight()
        self.assertEqual(plan['requirements'].strip(), '')
        real_run = subprocess.run
        pip_calls = []
        deny_network = ('import runpy, socket, sys\n'
                        'def deny(*args, **kwargs): raise RuntimeError("network forbidden in offline fixture")\n'
                        'socket.create_connection = deny\nsocket.socket.connect = deny\n'
                        'sys.argv = ["pip", *sys.argv[1:]]\nrunpy.run_module("pip", run_name="__main__")\n')

        def offline_run(command, *args, **kwargs):
            if isinstance(command, list) and command[1:4] == ['-I', '-m', 'pip']:
                pip_calls.append(command)
                command = [command[0], '-I', '-c', deny_network, *command[4:]]
            return real_run(command, *args, **kwargs)

        with patch.object(INSTALL.subprocess, 'run', side_effect=offline_run):
            result = INSTALL.install(plan)
        self.assertEqual(len(pip_calls), 3)
        self.assertEqual(marker.read_text(), 'verified')
        self.assertEqual(result['environment'], str(self.destination))
        self.assertEqual(INSTALL.V.digest((self.destination / 'native/codex').read_bytes()), result['binarySha256'])
        self.assertEqual(self.existing.read_bytes(), b'keep working installation')
