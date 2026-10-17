"""Exercise proof source closure, result redaction, and recovery paths offline."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "docs/native-bridge/terminal-completion-spike/reproduce.py"
)
HISTORICAL = SOURCE.parent.parent / "native-core-idle-v1-source-manifest.json"


class ToolReached(Exception):
    pass


class TerminalCompletionArtifactTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.checkout = self.root / "checkout"
        self.runner = self.root / "artifacts" / "spike" / "reproduce.py"
        self.runner.parent.mkdir(parents=True)
        self.runner.write_bytes(SOURCE.read_bytes())
        self.manifests = []
        for original, target in [
            (HISTORICAL, self.runner.parent.parent / HISTORICAL.name),
            (SOURCE.with_name("manifest.json"), self.runner.with_name("manifest.json")),
        ]:
            entries = json.loads(original.read_text())["fileSha256"]
            expected = {}
            for relative in entries:
                source = self.checkout / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(b"qualified fixture source")
                expected[relative] = hashlib.sha256(source.read_bytes()).hexdigest()
            target.write_text(json.dumps({"fileSha256": expected}))
            self.manifests.append(expected)
        self.tool = self.root / "owner-selected-tool"
        self.tool.write_text("#!/bin/sh\nexit 0\n")
        self.tool.chmod(0o700)
        self.marker = self.root / "tool-ran"
        self.proof = self.root / "proof"

    def execute(self, tool):
        with (
            patch.dict(
                os.environ,
                {
                    "CODEX_SPIKE_ROOT": str(self.checkout),
                    "SPIKE_PROOF_DIR": str(self.proof),
                    "JUST_BIN": str(self.tool),
                },
            ),
            patch("subprocess.run", side_effect=tool),
            patch("resource.setrlimit"),
        ):
            runpy.run_path(str(self.runner), run_name="__main__")

    def test_qualified_sources_then_both_manifest_mutations(self):
        self.assertEqual([len(m) for m in self.manifests], [57, 11])

        def stop_at_tool(*args, **kwargs):
            self.marker.touch()
            raise ToolReached()

        with self.assertRaises(ToolReached):
            self.execute(stop_at_tool)
        self.assertTrue(self.marker.exists())
        self.marker.unlink()
        historical, final = self.manifests
        for index, relative in enumerate(
            [next(iter(final)), "codex-rs/core/src/tasks/mod.rs"]
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, historical | final)
                if index == 1:
                    self.assertNotIn(relative, final)
                source = self.checkout / relative
                qualified = source.read_bytes()
                source.write_bytes(b"unqualified changed source")
                self.proof = self.root / f"rejected-{index}"
                with self.assertRaisesRegex(RuntimeError, "source manifest mismatch"):
                    self.execute(stop_at_tool)
                self.assertFalse(self.marker.exists())
                source.write_bytes(qualified)

    def test_results_redact_paths_before_serialization(self):
        calls = 0

        def fake_tool(cmd, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ToolReached()
            self.assertEqual(cmd[0], str(self.tool))
            self.assertTrue(
                kwargs["env"]["EVENT_TERMINAL_CORE_FIXTURE"].startswith(str(self.proof))
            )
            kwargs["stdout"].write("1 passed\n")
            return SimpleNamespace(returncode=0)

        with self.assertRaises(ToolReached):
            self.execute(fake_tool)
        raw = (self.proof / "results.json").read_text()
        self.assertNotIn(str(self.root), raw)
        row = json.loads(raw)[0]
        self.assertEqual(row["command"][0], "just")
        self.assertEqual(
            row["env"]["EVENT_TERMINAL_CORE_FIXTURE"], "$PROOF_DIR/core-normal.json"
        )
        self.assertEqual(row["log"], "core-normal.log")

    def test_sqlite_recovery_encodes_question_and_fragment(self):
        home = self.root / "proof ? # folder"
        home.mkdir()
        database = home / "state_fixture.sqlite"
        with sqlite3.connect(database) as db:
            db.execute(
                "CREATE TABLE native_turn_start_receipts (attempt_id TEXT, turn_id TEXT, terminal_status TEXT, terminal_receipt_id TEXT)"
            )
            db.execute(
                "INSERT INTO native_turn_start_receipts VALUES ('attempt', 'turn', 'completed', 'receipt')"
            )
        before = set(self.root.rglob("*"))
        terminal_rows = runpy.run_path(str(self.runner))["terminal_rows"]
        self.assertEqual(
            terminal_rows(home), [("attempt", "turn", "completed", "receipt")]
        )
        self.assertEqual(before, set(self.root.rglob("*")))

    def test_invalid_owner_tool_rejected_before_launch(self):
        self.tool.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "absolute existing executable"):
            self.execute(lambda *args, **kwargs: self.fail("invalid tool launched"))
