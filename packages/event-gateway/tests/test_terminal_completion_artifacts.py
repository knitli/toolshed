"""Reject unqualified native sources before running the proof tool."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "docs/native-bridge/terminal-completion-spike/reproduce.py"
)


class TerminalCompletionArtifactTests(unittest.TestCase):
    def test_source_mismatch_rejects_before_tool_execution(self):
        manifest = json.loads(SOURCE.with_name("manifest.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            expected = {}
            for relative in manifest["fileSha256"]:
                source = checkout / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(b"qualified fixture source")
                expected[relative] = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(len(expected), 11)
            (checkout / next(iter(expected))).write_bytes(b"unqualified changed source")
            runner = root / "reproduce.py"
            runner.write_bytes(SOURCE.read_bytes())
            runner.with_name("manifest.json").write_text(
                json.dumps({"fileSha256": expected})
            )
            marker = root / "tool-ran"

            def fake_just(*args, **kwargs):
                marker.touch()
                raise AssertionError("test process ran before source validation")

            with (
                patch.dict(
                    os.environ,
                    {
                        "CODEX_SPIKE_ROOT": str(checkout),
                        "SPIKE_PROOF_DIR": str(root / "proof"),
                        "JUST_BIN": "fake-just",
                    },
                ),
                patch("subprocess.run", side_effect=fake_just),
                patch("resource.setrlimit"),
            ):
                with self.assertRaisesRegex(RuntimeError, "source manifest mismatch"):
                    runpy.run_path(str(runner), run_name="__main__")
            self.assertFalse(marker.exists())
