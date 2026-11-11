import asyncio
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
RUNTIME_ID = "123e4567-e89b-42d3-a456-426614174000"
CONVERSATION_ID = "123e4567-e89b-42d3-a456-426614174001"
EVENT_ID = "123e4567-e89b-42d3-a456-426614174002"
ATTEMPT_ID = "123e4567-e89b-42d3-a456-426614174003"
TOKEN = "one-shot-receipt-token-value-0123456789"
DELIVERY_ID = "dly_" + "a" * 64


class ClaudeChannelStdioTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.state_dir = Path(self.temp.name)
        os.chmod(self.state_dir, 0o700)
        self.commands = []
        self.poll_count = 0
        self.register_failures_remaining = 0

        async def control(reader, writer):
            try:
                value = json.loads(await reader.readline())
                self.commands.append(value)
                command = value["command"]
                if command == "claude-register":
                    if self.register_failures_remaining:
                        self.register_failures_remaining -= 1
                        result = {"registered": False}
                    else:
                        result = {
                            "registered": True, "runtimeId": RUNTIME_ID,
                            "nodeId": EVENT_ID, "nodeGeneration": 1, "runtimeGeneration": 2,
                            "attachmentGeneration": 3, "consumerGeneration": 4,
                        }
                elif command == "claude-poll":
                    self.poll_count += 1
                    result = {"delivery": self._delivery()} if self.poll_count == 1 else {"delivery": None}
                elif command == "claude-client-reported":
                    result = {"recorded": value["receiptToken"] == TOKEN}
                else:
                    result = {"reason": "unsupported_command"}
                writer.write(json.dumps(result).encode() + b"\n")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        self.control_server = await asyncio.start_unix_server(control, path=self.state_dir / "control.sock")
        os.chmod(self.state_dir / "control.sock", 0o600)
        self.process = None

    async def asyncTearDown(self):
        if self.process is not None and self.process.returncode is None:
            self.process.kill()
            await self.process.wait()
        self.control_server.close()
        await self.control_server.wait_closed()
        self.temp.cleanup()

    def _delivery(self):
        return {
            "eventId": EVENT_ID, "deliveryId": DELIVERY_ID, "attemptId": ATTEMPT_ID,
            "principal": "owner", "agent": "agent", "runtimeId": RUNTIME_ID,
            "nodeGeneration": 1, "runtimeGeneration": 2, "attachmentGeneration": 3,
            "consumerGeneration": 4, "sourceStateVersion": "manual-5",
            "eventReference": "ref_" + EVENT_ID,
            "runtimeProfile": {"profile": "assigned_stock_client", "client": "claude",
                               "conversationId": CONVERSATION_ID}, "nodeId": EVENT_ID,
            "conversationId": CONVERSATION_ID, "receiptToken": TOKEN,
        }

    async def _start_server(self):
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        self.process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "event_gateway.claude_channel",
            "--state-dir", str(self.state_dir), "--runtime-id", RUNTIME_ID,
            "--conversation-id", CONVERSATION_ID,
            cwd=ROOT, env=env,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def _send(self, value):
        self.process.stdin.write(json.dumps(value).encode() + b"\n")
        await self.process.stdin.drain()

    async def _read(self):
        line = await asyncio.wait_for(self.process.stdout.readline(), timeout=3)
        self.assertTrue(line, "channel server closed stdout unexpectedly")
        return json.loads(line)

    async def _read_id(self, request_id):
        while True:
            frame = await self._read()
            if frame.get("id") == request_id:
                return frame

    async def _initialize(self):
        await self._send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "claude-conformance-fixture", "version": "2.1.322"},
            },
        })
        result = await self._read()
        self.assertEqual(result["id"], 1)
        self.assertEqual(result["result"]["protocolVersion"], "2025-11-25")
        experimental = result["result"]["capabilities"]["experimental"]
        self.assertEqual(experimental["claude/channel"], {})
        self.assertNotIn("claude/channel/permission", experimental)
        self.assertIn("tools", result["result"]["capabilities"])
        self.assertIn("does not select or start sessions", result["result"]["instructions"])
        await self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    async def test_sdk_stdio_initializes_registers_emits_once_and_records_explicit_callback(self):
        await self._start_server()
        await self._initialize()
        self.assertEqual(self.commands, [], "polling must wait for tool-list readiness")
        await self._send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        frames = []
        while not any(frame.get("id") == 2 for frame in frames) or not any(
            frame.get("method") == "notifications/claude/channel" for frame in frames
        ):
            frames.append(await self._read())
        listed = next(frame["result"]["tools"] for frame in frames if frame.get("id") == 2)
        self.assertEqual([tool["name"] for tool in listed], ["client_reported"])
        tool = listed[0]
        self.assertEqual(set(tool["inputSchema"]["properties"]), {"deliveryId", "attemptId", "receiptToken"})
        self.assertEqual(set(tool["inputSchema"]["required"]), {"deliveryId", "attemptId", "receiptToken"})
        self.assertFalse(tool["inputSchema"]["additionalProperties"])

        event = next(frame for frame in frames if frame.get("method") == "notifications/claude/channel")
        self.assertEqual(set(event.get("params", {})), {"content", "meta"}, event)
        body = json.loads(event["params"]["content"])
        self.assertEqual(body["event"], "ref_" + EVENT_ID)
        self.assertEqual(body["receiptToken"], TOKEN)
        self.assertNotIn(TOKEN, json.dumps(event["params"]["meta"]))
        self.assertEqual(self.commands[0], {
            "command": "claude-register", "runtimeId": RUNTIME_ID,
            "conversationId": CONVERSATION_ID,
        })
        self.assertEqual(self.commands[1]["command"], "claude-poll")
        with self.assertRaises(asyncio.TimeoutError, msg="duplicate channel notification emitted"):
            await asyncio.wait_for(self.process.stdout.readline(), timeout=0.7)
        self.assertEqual(sum(frame.get("method") == "notifications/claude/channel" for frame in frames), 1)

        await self._send({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "client_reported", "arguments": {
                "deliveryId": DELIVERY_ID, "attemptId": ATTEMPT_ID, "receiptToken": TOKEN,
            }},
        })
        callback = await self._read_id(3)
        self.assertEqual(callback["id"], 3)
        self.assertEqual(json.loads(callback["result"]["content"][0]["text"]), {
            "recorded": True, "reason": None,
        })
        self.assertIn({
            "command": "claude-client-reported", "runtimeId": RUNTIME_ID,
            "conversationId": CONVERSATION_ID, "deliveryId": DELIVERY_ID,
            "attemptId": ATTEMPT_ID, "receiptToken": TOKEN,
        }, self.commands)

        self.process.stdin.close()
        await asyncio.wait_for(self.process.wait(), timeout=3)
        polls_at_exit = self.poll_count
        await asyncio.sleep(0.6)
        self.assertEqual(self.poll_count, polls_at_exit, "polling survived stdio shutdown")
        lock = next(self.state_dir.glob(".claude-channel-*.lock"))
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    async def test_transient_registration_failure_retries_before_polling(self):
        self.register_failures_remaining = 1
        await self._start_server()
        await self._initialize()
        await self._send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listed = await self._read_id(2)
        self.assertEqual([tool["name"] for tool in listed["result"]["tools"]], ["client_reported"])

        frames = []
        while not any(frame.get("method") == "notifications/claude/channel" for frame in frames):
            frames.append(await self._read())
        commands = [value["command"] for value in self.commands]
        self.assertGreaterEqual(commands.count("claude-register"), 2)
        self.assertLess(commands.index("claude-register"), commands.index("claude-poll"))
        self.assertEqual(self.register_failures_remaining, 0)

    async def test_callback_mismatch_is_refused_without_echoing_receipt_token(self):
        await self._start_server()
        await self._initialize()
        await self._send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        frames = []
        while not any(frame.get("id") == 2 for frame in frames):
            frames.append(await self._read())
        while not any(value["command"] == "claude-poll" for value in self.commands):
            await asyncio.sleep(0.01)
        await self._send({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "client_reported", "arguments": {
                "deliveryId": DELIVERY_ID, "attemptId": ATTEMPT_ID, "receiptToken": "x" * 40,
            }},
        })
        callback = await self._read_id(3)
        response = callback["result"]["content"][0]["text"]
        self.assertEqual(json.loads(response), {"recorded": False, "reason": "refused"})
        self.assertNotIn("x" * 40, response)
        self.assertIn("claude-client-reported", [value["command"] for value in self.commands])

        self.process.stdin.close()
        await asyncio.wait_for(self.process.wait(), timeout=3)

    async def test_second_server_cannot_poll_the_same_assignment(self):
        from event_gateway.claude_channel import _assignment_lock

        first = _assignment_lock(self.state_dir, RUNTIME_ID, CONVERSATION_ID)
        first.__enter__()
        try:
            with self.assertRaises(BlockingIOError):
                with _assignment_lock(self.state_dir, RUNTIME_ID, CONVERSATION_ID):
                    self.fail("duplicate assignment lock was acquired")
        finally:
            first.__exit__(None, None, None)

    async def test_routed_messaging_delivery_accepts_its_source_version_contract(self):
        from event_gateway.claude_channel import _delivery

        delivery = self._delivery()
        delivery.update(
            routingGeneration=6, namespace="work", agentIncarnation=0,
            sourceStateVersion="msg:" + "b" * 64,
        )
        self.assertIs(_delivery(delivery, RUNTIME_ID, CONVERSATION_ID), delivery)
        for invalid in (EVENT_ID, -1, True):
            self.assertIsNone(_delivery({**delivery, "agentIncarnation": invalid}, RUNTIME_ID, CONVERSATION_ID))
        delivery["sourceStateVersion"] = "bad token"
        self.assertIsNone(_delivery(delivery, RUNTIME_ID, CONVERSATION_ID),
                          "invalid routed source version accepted")


if __name__ == "__main__":
    unittest.main()
