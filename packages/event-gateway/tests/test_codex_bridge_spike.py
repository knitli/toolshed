"""Keep the disposable observer's no-turn boundary in normal CI discovery."""
import importlib.util
from pathlib import Path
import unittest


class CodexBridgeSpikeTests(unittest.TestCase):
    def test_metadata_only_and_no_turn_or_approval_forwarding(self):
        path = Path(__file__).parents[1] / 'scripts' / 'observe_codex_bridge.py'
        spec = importlib.util.spec_from_file_location('observe_codex_bridge', path)
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        observer.check()
