import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from event_gateway.agent_credentials import AgentTokenProvider
from event_gateway.cloud import CloudError


class AgentTokenProviderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.node = root / "node-stub"
        self.helper = root / "helper.js"
        self.helper.write_text("synthetic helper marker")

    def provider(self, script):
        self.node.write_text("#!/bin/sh\n" + script)
        self.node.chmod(0o700)
        return AgentTokenProvider(str(self.node), str(self.helper),
                                 origin="https://events.example.com", agent="codex")

    async def test_invokes_fixed_arguments_and_returns_only_bare_token_each_call(self):
        counter = Path(self.tmp.name) / "counter"
        provider = self.provider(
            'test "$2 $3 $4 $5 $6" = "header --audience https://events.example.com --agent codex" || exit 3\n'
            f'n=0; test ! -e "{counter}" || n=$(cat "{counter}")\n'
            f'n=$((n + 1)); printf "%s" "$n" > "{counter}"\n'
            'printf \'{"X-Knitli-Agent-Token":"aaa.bbb.sig%s"}\\n\' "$n"\n')
        self.assertEqual(await provider(), "aaa.bbb.sig1")
        self.assertEqual(await provider(), "aaa.bbb.sig2")

    async def test_rejects_duplicate_keys_and_non_token_output(self):
        for output in (
            '{"X-Knitli-Agent-Token":"aaa.bbb.ccc","X-Knitli-Agent-Token":"ddd.eee.fff"}',
            '{"X-Knitli-Agent-Token":"Bearer aaa.bbb.ccc"}',
            '{"X-Knitli-Agent-Token":"aaa.bbb.ccc","extra":true}',
        ):
            with self.subTest(output=output):
                provider = self.provider("printf '%s\\n' " + json.dumps(output) + "\n")
                with self.assertRaises(CloudError) as caught:
                    await provider()
                self.assertEqual(caught.exception.code, "credentials_unavailable")
                self.assertEqual(str(caught.exception), "credentials_unavailable")

    async def test_rejects_oversized_output_and_times_out(self):
        provider = self.provider("head -c 8193 /dev/zero\n")
        with self.assertRaisesRegex(CloudError, "credentials_unavailable"):
            await provider()
        pidfile = Path(self.tmp.name) / "timed-out-pid"
        provider = self.provider(f'echo $$ > "{pidfile}"\nexec sleep 5\n')
        with self.assertRaises(CloudError) as caught:
            await provider()
        self.assertEqual(caught.exception.code, "credentials_timeout")
        self.assert_child_reaped(pidfile)

    async def test_cancellation_kills_and_reaps_child(self):
        pidfile = Path(self.tmp.name) / "cancelled-pid"
        provider = self.provider(f'echo $$ > "{pidfile}"\nexec sleep 5\n')
        request = asyncio.create_task(provider())
        await self.wait_for_pidfile(pidfile)
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request
        self.assert_child_reaped(pidfile)

    async def test_deadline_includes_subprocess_startup(self):
        provider = self.provider("exit 0\n")

        async def stalled_spawn(*_args, **_kwargs):
            await asyncio.sleep(5)

        with patch("event_gateway.agent_credentials.asyncio.create_subprocess_exec", new=stalled_spawn):
            with self.assertRaisesRegex(CloudError, "^credentials_timeout$"):
                await provider()

    async def test_helper_failure_never_exposes_output(self):
        provider = self.provider("printf 'private-token'; printf 'private-key' >&2; exit 1\n")
        with self.assertRaisesRegex(CloudError, "^credentials_unavailable$") as caught:
            await provider()
        self.assertNotIn("private", repr(caught.exception))

    async def wait_for_pidfile(self, path):
        deadline = asyncio.get_running_loop().time() + 1
        while not path.exists() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.01)
        self.assertTrue(path.exists())

    def assert_child_reaped(self, pidfile):
        pid = int(pidfile.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    async def test_rejects_malformed_constructor_values_safely(self):
        for node, origin in ((str(Path(self.tmp.name) / "bad\0node"), "https://events.example.com"),
                             (str(self.node), 3)):
            with self.subTest(node=node, origin=origin), self.assertRaises(CloudError) as caught:
                AgentTokenProvider(node, str(self.helper), origin=origin, agent="codex")
            self.assertEqual(str(caught.exception), "credentials_unavailable")

    async def test_strips_node_preload_environment(self):
        provider = self.provider(
            'test -z "${NODE_OPTIONS+x}${NODE_PATH+x}" || exit 3\n'
            "printf '%s\\n' '{\"X-Knitli-Agent-Token\":\"aaa.bbb.ccc\"}'\n")
        os.environ["NODE_OPTIONS"] = "--require secret"
        os.environ["NODE_PATH"] = "/secret"
        try:
            self.assertEqual(await provider(), "aaa.bbb.ccc")
        finally:
            os.environ.pop("NODE_OPTIONS", None)
            os.environ.pop("NODE_PATH", None)

