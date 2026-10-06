import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class ContractScriptTests(unittest.TestCase):
    def test_bad_manifest_exits_cleanly(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/sync_contract.py'
        spec = importlib.util.spec_from_file_location('sync_contract', script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            dest = Path(directory)
            for content in (None, '', '{', '{}', 'null', '[]'):
                with self.subTest(content=content):
                    manifest = dest / 'manifest.json'
                    if content is not None:
                        manifest.write_text(content)
                    error = io.StringIO()
                    with patch.object(module, 'DEST', dest), patch('sys.argv', ['sync_contract.py', '--check']):
                        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as caught:
                            module.main()
                    self.assertEqual(caught.exception.code, 1)
                    self.assertEqual(error.getvalue(), 'contract verification or export failed\n')


if __name__ == '__main__':
    unittest.main()
