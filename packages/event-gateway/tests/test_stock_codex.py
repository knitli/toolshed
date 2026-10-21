import asyncio
from pathlib import Path
import tempfile
from threading import Event
import unittest
from unittest.mock import AsyncMock, patch
import uuid

from event_gateway.stock_codex import (
    StockCodexAdapter, StockCodexError, StockCodexPreflightCancelled,
)


THREAD = "abcdefab-cdef-4abc-8def-abcdefabcdef"
REFERENCE = "ref_22222222-2222-4222-8222-222222222222"


class StockCodexTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.binary = Path(self.tmp.name) / "codex"
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)

    def test_assignment_and_reference_are_canonical_and_bounded(self):
        for value in (None, "not-a-uuid", THREAD.upper()):
            with self.subTest(value=value), self.assertRaisesRegex(StockCodexError, "invalid_assignment"):
                StockCodexAdapter(value, "/usr/bin/codex")
        adapter = StockCodexAdapter(THREAD, "/usr/bin/codex")
        for value in (None, "", REFERENCE + "x", "ref_" + str(uuid.uuid4()).upper()):
            with self.subTest(value=value), self.assertRaisesRegex(StockCodexError, "invalid_event_reference"):
                asyncio.run(adapter.submit(value))

    async def test_uses_stock_cli_exact_thread_and_returns_only_command_acceptance(self):
        process = type("Process", (), {"wait": AsyncMock(return_value=0)})()
        order = []

        def before_start():
            order.append("fenced")

        async def create_process(*args, **kwargs):
            order.append("spawn")
            return process

        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn:
            spawn.side_effect = create_process
            result = await StockCodexAdapter(THREAD, str(self.binary)).submit(
                REFERENCE, before_start=before_start)
        self.assertEqual(result, {"status": "command_accepted"})
        self.assertEqual(order, ["fenced", "spawn"])
        self.assertEqual(spawn.await_count, 1)
        self.assertEqual(spawn.call_args.args,
                         (str(self.binary), "queue", "--thread", THREAD,
                          "--message", REFERENCE))
        self.assertEqual(spawn.call_args.kwargs["stdin"], asyncio.subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["stdout"], asyncio.subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["stderr"], asyncio.subprocess.DEVNULL)

    async def test_missing_binary_is_a_safe_no_start_without_spawn_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / "missing-codex")
            before_start = unittest.mock.Mock()
            with patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
                with self.assertRaisesRegex(StockCodexError, "client_not_started") as caught:
                    await StockCodexAdapter(THREAD, binary).submit(
                        REFERENCE, before_start=before_start)
            self.assertEqual(caught.exception.code, "client_not_started")
            self.assertEqual(str(caught.exception), "client_not_started")
            before_start.assert_not_called()
            spawn.assert_not_awaited()

    async def test_non_executable_binary_is_a_safe_no_start_without_spawn_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "codex"
            binary.write_text("not executable")
            binary.chmod(0o600)
            with patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
                with self.assertRaisesRegex(StockCodexError, "client_not_started") as caught:
                    await StockCodexAdapter(THREAD, str(binary)).submit(REFERENCE)
            self.assertEqual(caught.exception.code, "client_not_started")
            spawn.assert_not_awaited()

    async def test_blocked_binary_preflight_does_not_stall_event_loop(self):
        loop = asyncio.get_running_loop()
        preflight_started = asyncio.Event()
        release_preflight = Event()
        loop_progressed = asyncio.Event()

        def blocked_preflight(_binary):
            loop.call_soon_threadsafe(preflight_started.set)
            if not release_preflight.wait(timeout=3):
                raise AssertionError("test did not release binary preflight")
            return True

        process = type("Process", (), {"wait": AsyncMock(return_value=0)})()
        with patch("event_gateway.stock_codex._binary_is_executable",
                   side_effect=blocked_preflight), \
                patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn:
            submit = asyncio.create_task(
                StockCodexAdapter(THREAD, str(self.binary)).submit(REFERENCE))

            async def mark_loop_progress():
                loop_progressed.set()

            try:
                await asyncio.wait_for(preflight_started.wait(), timeout=1)
                asyncio.create_task(mark_loop_progress())
                await asyncio.wait_for(loop_progressed.wait(), timeout=1)
                spawn.assert_not_awaited()
            finally:
                release_preflight.set()
                result = await submit
            self.assertEqual(result, {"status": "command_accepted"})
            spawn.assert_awaited_once()

    async def test_cancelled_binary_preflight_is_known_no_start(self):
        loop = asyncio.get_running_loop()
        preflight_started = asyncio.Event()
        release_preflight = Event()
        preflight_finished = Event()

        def blocked_preflight(_binary):
            loop.call_soon_threadsafe(preflight_started.set)
            release_preflight.wait(timeout=3)
            preflight_finished.set()
            return True

        with patch("event_gateway.stock_codex._binary_is_executable",
                   side_effect=blocked_preflight), \
                patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            submit = asyncio.create_task(
                StockCodexAdapter(THREAD, str(self.binary)).submit(REFERENCE))
            try:
                await asyncio.wait_for(preflight_started.wait(), timeout=1)
                submit.cancel()
                with self.assertRaises(StockCodexPreflightCancelled):
                    await submit
            finally:
                release_preflight.set()
                self.assertTrue(await asyncio.to_thread(preflight_finished.wait, 1))
            spawn.assert_not_awaited()

    async def test_oserror_from_process_creation_is_ambiguous(self):
        error = OSError(2, "No such file or directory", "/secret/path/codex")
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(side_effect=error)):
            with self.assertRaisesRegex(StockCodexError, "command_outcome_unknown") as caught:
                await StockCodexAdapter(THREAD, str(self.binary)).submit(REFERENCE)
        self.assertEqual(caught.exception.code, "command_outcome_unknown")
        self.assertEqual(str(caught.exception), "command_outcome_unknown")
        self.assertIsNone(caught.exception.__cause__)

    async def test_nonzero_exit_is_unknown_and_never_claims_acceptance(self):
        process = type("Process", (), {"wait": AsyncMock(return_value=1)})()
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
            with self.assertRaisesRegex(StockCodexError, "command_outcome_unknown"):
                await StockCodexAdapter(THREAD, str(self.binary)).submit(REFERENCE)

    async def test_timeout_kills_process_and_preserves_unknown_outcome(self):
        process = type("Process", (), {
            "wait": AsyncMock(side_effect=[TimeoutError, 0]), "kill": unittest.mock.Mock(),
        })()
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)), \
                patch("event_gateway.stock_codex.COMMAND_TIMEOUT", 0.001):
            with self.assertRaisesRegex(StockCodexError, "command_outcome_unknown"):
                await StockCodexAdapter(THREAD, str(self.binary)).submit(REFERENCE)
        process.kill.assert_called_once_with()

    async def test_cancel_after_launch_kills_and_reaps_without_claiming_outcome(self):
        started = asyncio.Event()
        calls = 0

        async def wait(_process):
            nonlocal calls
            calls += 1
            started.set()
            if calls == 1:
                await asyncio.Future()
            return 0

        process = type("Process", (), {"wait": wait, "kill": unittest.mock.Mock()})()
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
            task = asyncio.create_task(StockCodexAdapter(THREAD, str(self.binary)).submit(REFERENCE))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        process.kill.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
