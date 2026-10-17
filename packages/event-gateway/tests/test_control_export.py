"""The control exporter authenticates every source before evaluating schemas."""
import hashlib
import json
from pathlib import Path
import re
import shutil

# Test-only subprocesses invoke fixed git/node source-pin probes.
import subprocess  # nosec B404
import tempfile
import unittest


PACKAGE = Path(__file__).resolve().parents[1]
EXPORTER = PACKAGE / 'contracts/event-control-v1/export.mjs'
NEW_SOURCES = ('github/host-storage-version.ts', 'messaging/protocol-v2.ts')


class ControlExportTests(unittest.TestCase):
    def test_new_sources_are_checked_before_evaluation(self):
        source = EXPORTER.read_text()
        names = re.findall(r"'([^']+)'", source.split('const names = [', 1)[1].split('];', 1)[0])
        for name in NEW_SOURCES:
            self.assertIn(name, names)
        git = shutil.which("git")
        node = shutil.which("node")
        self.assertIsNotNone(git, "git is required for the source pin test")
        self.assertIsNotNone(node, "node is required for the source pin test")
        # Resolved executables, fixed arguments, no shell; inspect this checkout only.
        git_dir = subprocess.check_output(  # nosec B603
            [git, '-C', str(PACKAGE), 'rev-parse', '--absolute-git-dir'], text=True).strip()
        revision = subprocess.check_output(  # nosec B603
            [git, '-C', str(PACKAGE), 'rev-parse', 'HEAD'], text=True).strip()
        with tempfile.TemporaryDirectory(prefix='control-export-test-') as directory:
            root = Path(directory).resolve()
            (root / '.git').write_text(f'gitdir: {git_dir}\n')
            os_root = root / 'apps/os'
            base = os_root / 'packages/event-runtime/src'
            output = root / 'candidate'
            output.mkdir()
            shutil.copyfile(EXPORTER, output / 'export.mjs')
            zod = root / 'zod'
            zod.mkdir()
            (zod / 'package.json').write_text('{"version":"test"}')
            (zod / 'index.mjs').write_text("throw Error('SCHEMA_EVALUATED');\n")
            sources = {}
            for name in names:
                path = (base / name).resolve()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("throw Error('SCHEMA_EVALUATED');\n")
                sources[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest = {'revision': revision, 'zodVersion': 'test', 'sources': sources}
            pin = output / 'manifest.json'
            pin.write_text(json.dumps(manifest))

            def run():
                # Resolved executable, fixed arguments, no shell; owned disposable fixture.
                return subprocess.run(  # nosec B603
                    [node, str(output / 'export.mjs'), str(os_root),
                     str(zod / 'index.mjs'), '--check'],
                    text=True, capture_output=True, check=False, timeout=10)

            # Matching pins reach evaluation, so the negative checks cannot pass vacuously.
            result = run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('SCHEMA_EVALUATED', result.stderr)
            for name in NEW_SOURCES:
                path = base / name
                original = path.read_bytes()
                key = path.relative_to(root).as_posix()
                for mutation in ('changed', 'missing-file', 'missing-pin'):
                    with self.subTest(source=name, mutation=mutation):
                        if mutation == 'changed':
                            path.write_bytes(original + b'\n')
                        elif mutation == 'missing-file':
                            path.unlink()
                        else:
                            pin.write_text(json.dumps({**manifest, 'sources': {
                                k: v for k, v in sources.items() if k != key}}))
                        result = run()
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn('SCHEMA_EVALUATED', result.stderr)
                        self.assertIn('ENOENT' if mutation == 'missing-file'
                                      else 'source pin mismatch before evaluation', result.stderr)
                        path.write_bytes(original)
                        pin.write_text(json.dumps(manifest))


if __name__ == '__main__':
    unittest.main()
