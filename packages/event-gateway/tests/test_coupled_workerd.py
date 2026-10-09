"""Focused checks load harness definitions without launching its disposable services."""
import asyncio
import importlib.util
from pathlib import Path
import subprocess  # nosec B404 - Fixed interpreter runs only the repository harness parser.
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HARNESS = Path(__file__).resolve().parents[1] / "docs/native-bridge/coupled-workerd.py"
SPEC = importlib.util.spec_from_file_location("coupled_workerd", HARNESS)
COUPLED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COUPLED)


class CoupledWorkerdTests(unittest.TestCase):
    def test_conflicting_modes_rejected_before_artifact_resolution(self):
        required = [arg for name in ("package", "qualifier", "binary", "binary-sha", "node",
                                    "cloud-source", "esbuild", "miniflare", "output")
                    for arg in ("--" + name, "unresolved")]
        for flags, message in (
            (("--restart-native", "--terminal-no-start"), "are mutually exclusive"),
            (("--forget-terminal",), "requires --terminal-no-start"),
        ):
            with self.subTest(flags=flags):
                result = subprocess.run(  # nosec B603 - Fixed repository script and dummy args, no shell or user input.
                    [str(Path(sys.executable).resolve()), str(HARNESS), *required, *flags],
                    capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)
                self.assertNotIn("FileNotFoundError", result.stderr)

    def test_native_delay_is_bounded_and_requires_live_process(self):
        request = {"permitExpiresAt": 1000}

        async def cutoff(_):
            raise AssertionError("unbounded poll reached safety cutoff")

        for now, stopped in ((11, None), (1, 0)):
            with self.subTest(now=now, stopped=stopped):
                ticks = iter((0, now))
                with patch.object(COUPLED, "time", SimpleNamespace(monotonic=lambda: next(ticks), time_ns=lambda: 0)), \
                        patch.object(COUPLED, "asyncio", SimpleNamespace(sleep=cutoff)):
                    with self.assertRaisesRegex(AssertionError, "native delay fixture exceeded deadline or native process stopped"):
                        asyncio.run(COUPLED.wait_for_permit_expiry(request, SimpleNamespace(poll=lambda: stopped)))

    def test_restart_requires_death_and_every_identity_rotation(self):
        check = COUPLED.verify_native_restart
        witness = {key: i for i, key in enumerate(("clientId", "serverInstanceId", "backendPid", "threadId"))}
        new_witness = {key: value + 10 for key, value in witness.items()}
        old = SimpleNamespace(pid=1, poll=lambda: 0)
        new = SimpleNamespace(pid=2)
        launcher = SimpleNamespace(alive=lambda _: False)
        self.assertTrue(all(check(old, new, witness, new_witness, launcher).values()))
        for field in ("oldTui", "oldBackend", "pid", *witness):
            with self.subTest(field=field):
                changed = dict(new_witness)
                if field in witness:
                    changed[field] = witness[field]
                with self.assertRaisesRegex(AssertionError, "old native processes stopped and all restart identities rotated"):
                    check(SimpleNamespace(pid=1, poll=lambda: None if field == "oldTui" else 0),
                          SimpleNamespace(pid=1 if field == "pid" else 2), witness, changed,
                          SimpleNamespace(alive=lambda _: field == "oldBackend"))
