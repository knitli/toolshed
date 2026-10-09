"""Reject altered qualification artifacts before any gateway code can execute."""

import base64
import csv
import hashlib
import importlib.metadata
import importlib._bootstrap_external
import importlib.util
import io
import json
from pathlib import Path
import subprocess  # nosec B404 - Disposable isolated regression child with fixed Python code.
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HELPER = Path(__file__).resolve().parents[1] / 'docs/native-bridge/qualification-installed.py'
SPEC = importlib.util.spec_from_file_location('qualification_installed', HELPER)
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)


class InstalledQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qualification-guard-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'project/src/event_gateway'
        self.source.mkdir(parents=True)
        self.site = self.root / 'site'
        self.package = self.site / 'event_gateway'
        self.package.mkdir(parents=True)
        self.info = self.site / 'knitli_event_gateway-0.1.0.dist-info'
        self.info.mkdir()
        self.files = {'__init__.py': b'raise RuntimeError("must not import during verification")\n',
                      'native_reader.py': b'VALUE = 1\n', 'contracts/event-v1/protocol.json': b'{"version":1}\n'}
        for name, data in self.files.items():
            source = self.source / name if not name.startswith('contracts/') else self.root / 'project' / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(data)
            installed = self.package / name
            installed.parent.mkdir(parents=True, exist_ok=True)
            installed.write_bytes(data)
        (self.info / 'METADATA').write_text('Name: knitli-event-gateway\nVersion: 0.1.0\n')
        (self.info / 'WHEEL').write_text('Wheel-Version: 1.0\nRoot-Is-Purelib: true\n')
        self.write_record()
        self.distribution = importlib.metadata.PathDistribution(self.info)
        runtime = SimpleNamespace(flags=SimpleNamespace(isolated=1), modules={})
        runtime_patch = patch.object(qualification, 'sys', runtime)
        runtime_patch.start()
        self.addCleanup(runtime_patch.stop)
        distribution_patch = patch.object(qualification.importlib.metadata, 'distribution', return_value=self.distribution)
        distribution_patch.start()
        self.addCleanup(distribution_patch.stop)
        self.spec = SimpleNamespace(origin=str(self.package / '__init__.py'), submodule_search_locations=[str(self.package)])
        spec_patch = patch.object(qualification.importlib.util, 'find_spec', return_value=self.spec)
        spec_patch.start()
        self.addCleanup(spec_patch.stop)

    def write_record(self):
        text = io.StringIO()
        writer = csv.writer(text)
        for name in self.files:
            data = (self.package / name).read_bytes()
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
            writer.writerow(('event_gateway/' + name, 'sha256=' + digest, len(data)))
        writer.writerow((self.info.name + '/RECORD', '', ''))
        (self.info / 'RECORD').write_text(text.getvalue())

    def verify(self):
        return qualification.verify_installed(str(self.source))

    def test_valid_wheel_checks_modules_and_contracts_without_importing(self):
        proof = self.verify()
        self.assertEqual(len(proof['verifiedSha256']), 3)
        self.assertIn(str(self.package / 'contracts/event-v1/protocol.json'), proof['verifiedSha256'])
        self.assertIsNone(proof['directUrl'])

    def test_rejects_wrong_import_path_before_execution(self):
        self.spec.origin = str(self.source / '__init__.py')
        with self.assertRaisesRegex(qualification.PreflightError, 'import path'):
            self.verify()

    def test_rejects_editable_and_source_archive_provenance(self):
        cases = (({'url': self.source.as_uri(), 'dir_info': {'editable': True}}, 'editable or source-directory install'),
                 ({'url': 'https://example.invalid/package.whl'}, 'wheel archive metadata missing'),
                 ({'url': 'https://example.invalid/source.tar.gz', 'archive_info': {}}, 'wheel archive URL invalid'))
        for value, error in cases:
            with self.subTest(value=value):
                (self.info / 'direct_url.json').write_text(json.dumps(value))
                with self.assertRaisesRegex(qualification.PreflightError, error):
                    self.verify()

    def test_rejects_mutated_module_and_contract_even_with_updated_record(self):
        for name in ('native_reader.py', 'contracts/event-v1/protocol.json'):
            with self.subTest(name=name):
                target = self.package / name
                original = target.read_bytes()
                target.write_bytes(original + b'\n')
                with self.assertRaisesRegex(qualification.PreflightError, 'RECORD'):
                    self.verify()
                self.write_record()
                with self.assertRaisesRegex(qualification.PreflightError, 'trusted package source'):
                    self.verify()
                target.write_bytes(original)
                self.write_record()

    def test_rejects_unlisted_module_and_premature_import(self):
        extra = self.package / 'unlisted.py'
        extra.write_text('raise RuntimeError("unverified")\n')
        with self.assertRaisesRegex(qualification.PreflightError, 'files differ'):
            self.verify()
        extra.unlink()
        qualification.sys.modules['event_gateway'] = object()
        with self.assertRaisesRegex(qualification.PreflightError, 'imported before'):
            self.verify()

    def test_executable_rejects_symlinks_and_writable_ancestors(self):
        executable = self.root / 'node'
        executable.write_bytes(b'qualification fixture')
        executable.chmod(0o700)
        self.assertEqual(qualification.verified_executable(executable), str(executable))
        executable.chmod(0o777)
        with self.assertRaises(qualification.PreflightError):
            qualification.verified_executable(executable)
        executable.chmod(0o700)
        with self.assertRaises(qualification.PreflightError):
            qualification.verified_executable(self.root)
        alias = self.root / 'alias'
        alias.symlink_to(executable)
        with self.assertRaises(qualification.PreflightError):
            qualification.verified_executable(alias)
        self.root.chmod(0o777)
        with self.assertRaisesRegex(qualification.PreflightError, 'ancestor'):
            qualification.verified_executable(executable)
        self.root.chmod(0o700)

    def test_valid_stale_bytecode_cannot_bypass_verified_source(self):
        source = self.source / '__init__.py'
        installed = self.package / '__init__.py'
        source.write_text('VALUE = 1\n')
        installed.write_bytes(source.read_bytes())
        self.write_record()
        pyc = Path(importlib.util.cache_from_source(str(installed), optimization='1'))
        pyc.parent.mkdir(exist_ok=True)
        code = compile('VALUE = 2\n', str(installed), 'exec')
        poisoned = importlib._bootstrap_external._code_to_timestamp_pyc(code, int(installed.stat().st_mtime), installed.stat().st_size)
        pyc.write_bytes(poisoned)
        program = r"""import gc, importlib.metadata, importlib.util, sys
from pathlib import Path
from unittest.mock import patch
site, source, helper, checked = sys.argv[1:]
sys.path.insert(0, site)
if checked == 'true':
    spec = importlib.util.spec_from_file_location('qualification_installed', helper)
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    distribution = importlib.metadata.PathDistribution(Path(site) / 'knitli_event_gateway-0.1.0.dist-info')
    with patch.object(importlib.metadata, 'distribution', return_value=distribution):
        proof = checks.verify_installed(source)
    del checks
    gc.collect()
    if not Path(proof['pycachePrefix']).is_dir():
        raise RuntimeError('private import cache lost its lifetime owner')
import event_gateway
print(event_gateway.VALUE)
"""
        for checked, expected in (('false', '2'), ('true', '1')):
            result = subprocess.run(  # nosec B603 - Fixed isolated regression child; arguments are private fixture paths.
                [sys.executable, '-I', '-O', '-c', program, str(self.site), str(self.source), str(HELPER), checked],
                check=True, capture_output=True, text=True,
            )
            self.assertEqual(result.stdout.strip(), expected)

    def test_requires_isolated_interpreter(self):
        qualification.sys.flags.isolated = 0
        with self.assertRaisesRegex(qualification.PreflightError, 'Python -I'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
