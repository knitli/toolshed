"""Paired install ordering and preservation using synthetic artifacts only."""

import base64
import csv
from contextlib import ExitStack
import importlib.util
import io
import json
import shutil
import sys
from pathlib import Path
import tempfile
import tomllib
import unittest
import zipfile
from types import SimpleNamespace
import urllib.error
from uuid import uuid4
from unittest.mock import patch

from test_native_ci_provenance import BUILD, FakeAPI, MAIN, archive_bytes, launcher
from test_native_ci_provenance_v2 import DOCS, V2API

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
    def __init__(self, family=None):
        """Serve immutable main release data and synthetic native CI metadata."""
        super().__init__()
        if family is not None:
            self.__dict__.update(vars(V2API(family)))
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
        for path in (INSTALL.SELF, 'scripts/verify_native_ci_provenance.py', 'scripts/native_recipe_registry.py', INSTALL.HELPER, 'pyproject.toml', 'uv.lock'):
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
        if endpoint == f"actions/runs/{self.selected['runId']}/attempts/{self.selected['runAttempt']}":
            return self.run
        if endpoint == f"actions/artifacts/{self.selected['artifactId']}":
            return self.artifact
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

    def test_enrollment_preflight_authenticates_wheel_without_native_release_queries(self):
        self.api.calls.clear()
        plan = INSTALL.preflight(self.api, self.wheel, None, self.destination, enrollment_only=True)
        self.assertTrue(plan['enrollment_only'])
        self.assertIsNone(plan['selected'])
        self.assertIsNone(plan['artifact'])
        self.assertFalse(any(call in ('actions/workflows/event-native-build.yml',
                                      f"actions/runs/{self.api.selected['runId']}/attempts/{self.api.selected['runAttempt']}",
                                      f"actions/artifacts/{self.api.selected['artifactId']}")
                             for call in self.api.calls))
        self.assertNotIn((INSTALL.V.PROVENANCE, MAIN), self.api.calls)
        self.unchanged()

    def test_enrollment_preflight_rejects_native_artifact_profile_mixing(self):
        with self.assertRaisesRegex(ValueError, 'native_artifact_not_allowed_for_enrollment_only'):
            INSTALL.preflight(self.api, self.wheel, self.artifact, self.destination, enrollment_only=True)
        self.unchanged()

    def test_enrollment_preflight_rejects_invalid_wheel_before_creation(self):
        self.wheel.write_bytes(b'not a wheel')
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            INSTALL.preflight(self.api, self.wheel, None, self.destination, enrollment_only=True)
        self.unchanged()

    def test_paired_preflight_requires_native_artifact(self):
        with self.assertRaisesRegex(ValueError, 'native_artifact_required'):
            INSTALL.preflight(self.api, self.wheel, None, self.destination)
        self.unchanged()

    def test_registered_legacy_build_accepts_current_shared_input_drift(self):
        for name in ('builderSha256', 'producerSha256', 'workflowSha256'):
            self.api.blobs[INSTALL.V.INPUTS[name], MAIN] += b'\n# current shared inputs\n'
        plan = self.preflight()
        self.assertEqual(plan['inputs'], {name: INSTALL.V.digest(self.api.blobs[path, BUILD])
                                          for name, path in INSTALL.V.INPUTS.items()})
        self.unchanged()

    def test_unregistered_legacy_build_tuple_is_rejected_before_writes(self):
        for name, path in INSTALL.V.INPUTS.items():
            with self.subTest(input=name):
                self.api = InstallAPI()
                self.api.blobs[path, BUILD] += b'\nchanged'
                with self.assertRaises(ValueError):
                    self.preflight()
                self.unchanged()

    def test_promoted_legacy_recipe_404_has_actionable_paired_release_error(self):
        self.api = InstallAPI()
        promoted = '7ff224a1fc8a9923e33aeafbd66cfa65efdc8bea'
        current_launcher = (INSTALL.ROOT / 'src/event_gateway/launcher.py').read_bytes()
        pins = INSTALL.V.pins(current_launcher)
        self.api.payload['event_gateway/launcher.py'] = current_launcher
        self.api.blobs[INSTALL.PREFIX + 'src/event_gateway/launcher.py', MAIN] = current_launcher
        self.wheel.write_bytes(wheel_bytes(self.api.payload, self.api.project))
        self.api.selected.update(
            headSha=promoted,
            runId=38273438173,
            runAttempt=1,
            artifactId=11758567975,
            binarySha256=pins['QUALIFIED_SHA256'],
            codeModeHostSha256=pins['QUALIFIED_CODE_MODE_HOST_SHA256'],
        )
        self.api.run.update(id=38273438173, run_attempt=1, head_sha=promoted)
        self.api.artifact.update(id=11758567975, name='native-client-38273438173-1')
        self.api.artifact['workflow_run'].update(id=38273438173, head_sha=promoted)
        self.api.comparison['headTarget']['oid'] = promoted
        self.api.blobs[INSTALL.V.PROVENANCE, 'a' * 40] = json.dumps(self.api.selected).encode()
        self.api.blobs[INSTALL.V.PROVENANCE, MAIN] = json.dumps(self.api.selected).encode()
        original_blob = self.api.blob
        missing_manifest = INSTALL.V.INPUTS['sourceManifestSha256']

        def promoted_blobs(path, revision):
            if revision == promoted:
                if path == missing_manifest:
                    raise urllib.error.HTTPError(
                        'https://api.github.test/missing-native-manifest', 404, 'Not Found', {}, None,
                    )
                return original_blob(path, BUILD)
            return original_blob(path, revision)

        with patch.object(self.api, 'blob', side_effect=promoted_blobs), \
                patch.object(INSTALL, 'install_wheel') as installer:
            with self.assertRaisesRegex(
                    ValueError,
                    'consumer_native_pair_mismatch: promoted native recipe unavailable or unverified; '
                    'keep previous working client until paired release is promoted') as caught:
                self.preflight()
        self.assertIsInstance(caught.exception.__cause__, urllib.error.HTTPError)
        self.assertEqual(caught.exception.__cause__.code, 404)
        installer.assert_not_called()
        self.unchanged()

    def test_recipe_resolution_auth_and_transport_errors_are_preserved(self):
        failures = (
            urllib.error.HTTPError('https://api.github.test/recipe', 403, 'Forbidden', {}, None),
            urllib.error.HTTPError('https://api.github.test/recipe', 429, 'Rate limited', {}, None),
            OSError('transport unavailable'),
        )
        for error in failures:
            with self.subTest(error=type(error).__name__, code=getattr(error, 'code', None)):
                with patch.object(INSTALL.V, 'resolve_build_inputs', side_effect=error):
                    with self.assertRaises(type(error)) as caught:
                        self.preflight()
                self.assertIs(caught.exception, error)
                self.unchanged()

    def test_unverified_recipe_has_actionable_paired_release_error(self):
        error = ValueError('native_ci_provenance_verification_failed')
        with patch.object(INSTALL.V, 'resolve_build_inputs', side_effect=error):
            with self.assertRaisesRegex(
                    ValueError, 'consumer_native_pair_mismatch:.*keep previous working client') as caught:
                self.preflight()
        self.assertIs(caught.exception.__cause__, error)
        self.unchanged()

    def select_v2(self, family):
        self.api = InstallAPI(family)
        self.wheel.write_bytes(wheel_bytes(self.api.payload, self.api.project))
        self.artifact.write_bytes(self.api.archive)

    def test_both_v2_families_pass_real_composed_preflight_without_writes(self):
        for family in ('core-idle-v1', 'terminal-query-v1'):
            with self.subTest(family=family):
                self.select_v2(family)
                before = sorted(self.root.iterdir())
                plan = self.preflight()
                self.assertEqual(plan['selected']['recipe']['family'], family)
                self.assertEqual(plan['inputs'], {name: INSTALL.V.digest(self.api.blobs[path, BUILD])
                                                  for name, path in self.api.paths.items()})
                self.assertEqual(sorted(self.root.iterdir()), before)
                self.unchanged()

    def test_v2_local_registry_must_exist_and_match_protected_main(self):
        original = INSTALL.read_file
        registry = INSTALL.ROOT / 'scripts/native_recipe_registry.py'
        for family in ('core-idle-v1', 'terminal-query-v1'):
            for missing in (False, True):
                with self.subTest(family=family, missing=missing):
                    self.select_v2(family)

                    def read(path, limit):
                        if path == registry:
                            if missing:
                                raise FileNotFoundError(path)
                            return b'altered registry'
                        return original(path, limit)

                    with patch.object(INSTALL, 'read_file', side_effect=read):
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            self.preflight()
                    self.unchanged()

    def test_v2_protected_assets_must_exist_and_match_registry(self):
        for family in ('core-idle-v1', 'terminal-query-v1'):
            recipe = INSTALL.V.R.recipe(family, 1)
            for asset in (recipe.manifest, *recipe.parents, *recipe.ordered_patches):
                for missing in (False, True):
                    with self.subTest(family=family, asset=asset.path, missing=missing):
                        self.select_v2(family)
                        key = (DOCS + asset.path, MAIN)
                        if missing:
                            del self.api.blobs[key]
                        else:
                            self.api.blobs[key] += b'changed'
                        with self.assertRaises((ValueError, KeyError)):
                            self.preflight()
                        self.unchanged()

    def test_v2_local_recipe_assets_must_exist_and_match_registry(self):
        for family in ('core-idle-v1', 'terminal-query-v1'):
            recipe = INSTALL.V.R.recipe(family, 1)
            for asset in (recipe.manifest, *recipe.parents, *recipe.ordered_patches):
                for missing in (False, True):
                    with self.subTest(family=family, asset=asset.path, missing=missing):
                        self.select_v2(family)
                        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
                            docs = Path(temporary) / 'docs'
                            shutil.copytree(INSTALL.V.R.DOCS, docs)
                            target = docs / asset.path
                            if missing:
                                target.unlink()
                            else:
                                target.write_bytes(b'altered asset')
                            with patch.object(INSTALL.V.R, 'DOCS', docs):
                                with self.assertRaises(ValueError):
                                    self.preflight()
                        self.unchanged()

    def test_v2_main_movement_refuses_before_writes(self):
        for family in ('core-idle-v1', 'terminal-query-v1'):
            with self.subTest(family=family):
                self.select_v2(family)
                self.test_main_movement_during_preflight_refuses_without_creation()

    def test_v2_upstream_and_consumer_pin_mismatch_fail_before_writes(self):
        for family in ('core-idle-v1', 'terminal-query-v1'):
            for fault in ('upstream', 'pin', 'ancestry'):
                with self.subTest(family=family, fault=fault):
                    self.select_v2(family)
                    if fault == 'upstream':
                        self.api.receipt['build']['upstreamCommit'] = '0' * 40
                        self.api.replace_receipt(self.api.receipt)
                        self.artifact.write_bytes(self.api.archive)
                    elif fault == 'pin':
                        self.api.selected['codeModeHostSha256'] = '0' * 64
                    else:
                        self.api.comparison['baseTarget']['oid'] = '0' * 40
                    self.api.blobs[INSTALL.V.PROVENANCE, MAIN] = json.dumps(self.api.selected).encode()
                    with self.assertRaises(ValueError):
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

    def test_enrollment_postcheck_failure_cleans_only_new_destination(self):
        plan = INSTALL.preflight(self.api, self.wheel, None, self.destination, enrollment_only=True)

        def install_fake(destination, wheel, requirements, wheel_sha256):
            (destination / 'bin').mkdir()
            (destination / 'bin/knitli-event-gateway').write_text('#!/bin/sh\nexit 1\n')
            (destination / 'bin/knitli-event-gateway').chmod(0o700)

        with patch.object(INSTALL, 'install_wheel', side_effect=install_fake), \
                patch.object(INSTALL, 'verify_enrollment_destination', side_effect=RuntimeError('postcheck failed')):
            with self.assertRaisesRegex(RuntimeError, 'postcheck failed'):
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
        runtime = self.root / 'runtime'
        (runtime / 'bin').mkdir(parents=True)
        interpreter = runtime / 'bin/python3.13'
        shutil.copy2(Path(sys._base_executable).resolve(), interpreter)
        interpreter.chmod(0o755)
        (runtime / 'lib').symlink_to(Path(sys._base_executable).resolve().parent.parent / 'lib',
                                     target_is_directory=True)
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
                with self.assertRaises(INSTALL.subprocess.CalledProcessError):
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
        flags = {name: getattr(sys.flags, name) for name in dir(sys.flags) if not name.startswith('_')}
        implementation = vars(sys.implementation)
        defaults = {'platform': 'darwin', 'version_info': (3, 13),
                    'flags': SimpleNamespace(**{**flags, 'isolated': 1}),
                    'implementation': SimpleNamespace(**{**implementation, 'name': 'cpython'})}
        faults = ({'platform': 'linux'}, {'version_info': (3, 12)},
                  {'flags': SimpleNamespace(**{**flags, 'isolated': 0})},
                  {'implementation': SimpleNamespace(**{**implementation, 'name': 'pypy'})},
                  {'machine': 'x86_64'}, {'unauthenticated': True})
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
                stack.enter_context(patch.dict(INSTALL.os.environ, {'GITHUB_TOKEN': uuid4().hex}))
                if fault.get('unauthenticated'):
                    INSTALL.os.environ.pop('GITHUB_TOKEN', None)
                preflight = stack.enter_context(patch.object(INSTALL, 'preflight'))
                install = stack.enter_context(patch.object(INSTALL, 'install'))
                with self.assertRaises(ValueError):
                    INSTALL.main()
                preflight.assert_not_called()
                install.assert_not_called()
                self.unchanged()

    def test_cli_rejects_missing_or_mixed_native_artifact_before_preflight(self):
        flags = {name: getattr(sys.flags, name) for name in dir(sys.flags) if not name.startswith('_')}
        implementation = vars(sys.implementation)
        for profile in (['--wheel', str(self.wheel), '--destination', str(self.destination)],
                        ['--wheel', str(self.wheel), '--destination', str(self.destination),
                         '--enrollment-only', '--native-artifact', str(self.artifact)]):
            with self.subTest(profile=profile), ExitStack() as stack:
                stack.enter_context(patch.object(INSTALL.sys, 'platform', 'darwin'))
                stack.enter_context(patch.object(INSTALL.sys, 'version_info', (3, 13)))
                stack.enter_context(patch.object(INSTALL.sys, 'flags', SimpleNamespace(**{**flags, 'isolated': 1})))
                stack.enter_context(patch.object(INSTALL.sys, 'implementation', SimpleNamespace(**{**implementation, 'name': 'cpython'})))
                stack.enter_context(patch.object(INSTALL.platform, 'machine', return_value='arm64'))
                stack.enter_context(patch.dict(INSTALL.os.environ, {'GITHUB_TOKEN': uuid4().hex}))
                stack.enter_context(patch.object(INSTALL.sys, 'argv', ['install_paired_client.py', *profile]))
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
        real_run = INSTALL.subprocess.run
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

    def test_offline_enrollment_install_restricts_console_entrypoint_without_native_files(self):
        self.api.project['dependencies'] = []
        self.api.payload['event_gateway/__init__.py'] = b''
        self.api.payload['event_gateway/cli.py'] = (
            b'import argparse\n'
            b'def enrollment_main(argv=None):\n'
            b'    parser = argparse.ArgumentParser(prog="knitli-event-gateway")\n'
            b'    commands = parser.add_subparsers(dest="command", required=True)\n'
            b'    commands.add_parser("status")\n'
            b'    commands.add_parser("enroll")\n'
            b'    parser.parse_args(argv)\n'
            b'    return 0\n'
            b'def main(argv=None):\n'
            b'    parser = argparse.ArgumentParser(prog="knitli-event-gateway")\n'
            b'    commands = parser.add_subparsers(dest="command", required=True)\n'
            b'    commands.add_parser("status")\n'
            b'    commands.add_parser("enroll")\n'
            b'    commands.add_parser("launch")\n'
            b'    parser.parse_args(argv)\n'
            b'    return 0\n'
        )
        marker = self.root / 'enrollment-launcher-imported'
        self.api.payload['event_gateway/launcher.py'] = (
            f'from pathlib import Path\nPath({str(marker)!r}).write_text("imported")\n'.encode()
        )
        for name, value in self.api.payload.items():
            relative = name.removeprefix('event_gateway/')
            path = INSTALL.PREFIX + (relative if relative.startswith('contracts/') else 'src/event_gateway/' + relative)
            self.api.blobs[path, MAIN] = value
            if not any(item['path'] == path for item in self.api.source_tree):
                self.api.source_tree.append({'path': path, 'type': 'blob', 'mode': '100644'})
        project = (INSTALL.ROOT / 'pyproject.toml').read_text()
        start = project.index('dependencies = [')
        end = project.index(']', start) + 1
        self.api.blobs[INSTALL.PREFIX + 'pyproject.toml', MAIN] = (project[:start] + 'dependencies = []' + project[end:]).encode()
        self.api.blobs[INSTALL.PREFIX + 'uv.lock', MAIN] = (
            'version = 1\n[[package]]\nname = "knitli-event-gateway"\nversion = "0.1.0"\ndependencies = []\n'
        ).encode()
        self.wheel.write_bytes(wheel_bytes(self.api.payload, self.api.project))
        plan = INSTALL.preflight(self.api, self.wheel, None, self.destination, enrollment_only=True)
        real_run = INSTALL.subprocess.run

        def offline_run(command, *args, **kwargs):
            if isinstance(command, list) and command[1:4] == ['-I', '-m', 'pip']:
                command = [command[0], '-I', '-c',
                           'import runpy, socket, sys\n'
                           'def deny(*args, **kwargs): raise RuntimeError("network forbidden in offline fixture")\n'
                           'socket.create_connection = deny\nsocket.socket.connect = deny\n'
                           'sys.argv = ["pip", *sys.argv[1:]]\nrunpy.run_module("pip", run_name="__main__")\n',
                           *command[4:]]
            return real_run(command, *args, **kwargs)

        with patch.object(INSTALL.subprocess, 'run', side_effect=offline_run):
            result = INSTALL.install(plan)
        command = Path(result['command'])
        self.assertEqual(result['profile'], 'enrollment-only')
        self.assertFalse((self.destination / 'native').exists())
        self.assertFalse(marker.exists())
        self.assertEqual(command.read_bytes(), INSTALL.enrollment_entrypoint(self.destination))
        help_result = INSTALL.subprocess.run([str(command), '--help'], capture_output=True, text=True)
        launch_result = INSTALL.subprocess.run([str(command), 'launch'], capture_output=True, text=True)
        self.assertEqual(help_result.returncode, 0)
        self.assertNotIn('launch', help_result.stdout)
        self.assertNotEqual(launch_result.returncode, 0, launch_result.stdout + launch_result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(self.existing.read_bytes(), b'keep working installation')

    def test_identity_failure_rolls_back_only_new_empty_destination(self):
        plan = self.preflight()
        original_stat = INSTALL.os.stat

        def interrupted(path, *args, **kwargs):
            if path == self.destination.name and kwargs.get('dir_fd') is not None:
                raise InterruptedError('identity lookup interrupted')
            return original_stat(path, *args, **kwargs)

        with patch.object(INSTALL.os, 'stat', side_effect=interrupted), patch.object(INSTALL, 'install_wheel') as installer:
            with self.assertRaisesRegex(InterruptedError, 'identity lookup interrupted'):
                INSTALL.install(plan)
        installer.assert_not_called()
        self.unchanged()
        self.destination.mkdir()
        with self.assertRaises(FileExistsError):
            INSTALL.create_destination(self.destination)
        self.assertTrue(self.destination.is_dir(), 'creation failure must preserve existing entry')
