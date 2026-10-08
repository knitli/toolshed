import json
from pathlib import Path
import subprocess  # nosec B404 - Fixed interpreter and owned semantic fixture, no shell.
import sys
import tempfile
import unittest


class SemanticVectorScriptTests(unittest.TestCase):
    def test_optimized_driver_rejects_wrong_verdict(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/check_semantic_vectors.py'
        vectors = {'schemaVersion': 1, 'rawCases': [
            {'case': 'invalid-json', 'kind': 'envelope', 'raw': '{', 'nowMs': 0, 'expectedError': None},
        ], 'digestCases': [], 'bindingCases': []}
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'vectors.json'
            corpus.write_text(json.dumps(vectors))
            result = subprocess.run(  # nosec B603 - Fixed interpreter and synthetic corpus path.
                [sys.executable, '-O', str(script), str(corpus)],
                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('invalid-json', result.stderr)


if __name__ == '__main__':
    unittest.main()
