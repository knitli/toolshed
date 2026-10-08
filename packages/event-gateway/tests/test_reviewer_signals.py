"""The offline proof must reject mismatches even when Python is optimized."""

import json
from pathlib import Path
import subprocess  # nosec B404 - Fixed interpreter and owned offline replay fixture, no shell.
import sys
import tempfile
import unittest


class ReviewerSignalTests(unittest.TestCase):
    def test_optimized_replay_rejects_wrong_expectation(self):
        package = Path(__file__).resolve().parents[1]
        script = package / "scripts/replay_reviewer_signals.py"
        fixture = json.loads((package / "docs/reviewer-signals/replay.json").read_text())
        fixture["cases"][0]["expected"]["round_complete"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong-expectation.json"
            path.write_text(json.dumps(fixture))
            result = subprocess.run(  # nosec B603 - Fixed interpreter and synthetic fixture path.
                [sys.executable, "-O", str(script), str(path)],
                capture_output=True, text=True, check=False, timeout=10,
            )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("AssertionError", result.stderr)
        self.assertIn(fixture["cases"][0]["name"], result.stderr)
        self.assertNotIn("PASS:", result.stdout)


if __name__ == "__main__":
    unittest.main()
