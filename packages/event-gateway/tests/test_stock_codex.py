import asyncio
import unittest
from unittest.mock import AsyncMock, patch
import uuid

from event_gateway.stock_codex import StockCodexAdapter, StockCodexError


THREAD = "abcdefab-cdef-4abc-8def-abcdefabcdef"
REFERENCE = "ref_22222222-2222-4222-8222-222222222222"


class StockCodexTests(unittest.IsolatedAsyncioTestCase):
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
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn:
            result = await StockCodexAdapter(THREAD, "/opt/bin/codex").submit(REFERENCE)
        self.assertEqual(result, {"status": "command_accepted"})
        self.assertEqual(spawn.call_args.args,
                         ("/opt/bin/codex", "queue", "--thread", THREAD,
                          "--message", REFERENCE))
        self.assertEqual(spawn.call_args.kwargs["stdin"], asyncio.subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["stdout"], asyncio.subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["stderr"], asyncio.subprocess.DEVNULL)

    async def test_nonzero_exit_is_unknown_and_never_claims_acceptance(self):
        process = type("Process", (), {"wait": AsyncMock(return_value=1)})()
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
            with self.assertRaisesRegex(StockCodexError, "command_outcome_unknown"):
                await StockCodexAdapter(THREAD, "/usr/bin/codex").submit(REFERENCE)

    async def test_timeout_kills_process_and_preserves_unknown_outcome(self):
        process = type("Process", (), {
            "wait": AsyncMock(side_effect=[TimeoutError, 0]), "kill": unittest.mock.Mock(),
        })()
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)), \
                patch("event_gateway.stock_codex.COMMAND_TIMEOUT", 0.001):
            with self.assertRaisesRegex(StockCodexError, "command_outcome_unknown"):
                await StockCodexAdapter(THREAD, "/usr/bin/codex").submit(REFERENCE)
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
            task = asyncio.create_task(StockCodexAdapter(THREAD, "/usr/bin/codex").submit(REFERENCE))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        process.kill.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
