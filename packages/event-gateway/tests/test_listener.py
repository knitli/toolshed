import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from event_gateway.listener import Listener
from event_gateway.security import SecurityError


class ListenerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.accepted = 0
        self.reject_signature = False
        self.listener = Listener(self, deadline=0.1, concurrency=1)
        self.server = await self.listener.start('127.0.0.1', 0)
        self.addAsyncCleanup(self.close_server)

    async def close_server(self):
        self.server.close()
        await self.server.wait_closed()

    def accept(self, body, **kwargs):
        if self.reject_signature:
            raise SecurityError('invalid_signature')
        self.accepted += 1
        return {'status': 'queued'}

    async def connect(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.server.sockets[0].getsockname()[1])
        self.addAsyncCleanup(self.close_writer, writer)
        return reader, writer

    async def close_writer(self, writer):
        writer.close()
        await writer.wait_closed()

    async def request(self, raw):
        reader, writer = await self.connect()
        writer.write(raw)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), 1)

    async def test_accept_signature_errors_and_duplicate_framing(self):
        raw = b'POST /v1/deliver HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}'
        self.assertIn(b'202 Result', await self.request(raw))
        self.reject_signature = True
        self.assertIn(b'invalid_signature', await self.request(raw))
        self.reject_signature = False
        for extra in (b'content-length: 2\r\n', b'Transfer-Encoding: chunked\r\n'):
            self.assertIn(b'400 Result', await self.request(raw.replace(b'\r\n\r\n', b'\r\n' + extra + b'\r\n')))
        self.assertEqual(self.accepted, 1)

    async def test_header_deadline_is_absolute_despite_progress(self):
        loop = asyncio.get_running_loop()
        now = loop.time()
        reader = asyncio.StreamReader()
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())

        async def settle():
            # Run ready tasks and timers without depending on wall-clock scheduling.
            for _ in range(10):
                await asyncio.sleep(0)

        with patch.object(loop, "time", side_effect=lambda: now):
            task = asyncio.create_task(self.listener.handle(reader, writer))
            try:
                reader.feed_data(b'POST /v1/deliver HTTP/1.1\r\nX: ')
                await settle()
                self.assertFalse(task.done())
                now += 0.06
                reader.feed_data(b'a')
                await settle()
                self.assertFalse(task.done())
                now += 0.05
                await settle()
                self.assertTrue(task.done(), "header progress must not restart the deadline")
                await task
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        self.assertIn(b'408 Result', b''.join(call.args[0] for call in writer.write.call_args_list))
        self.assertEqual(self.accepted, 0)
        self.assertEqual(self.listener.active, 0)

    async def test_body_deadline_and_concurrency(self):
        reader, writer = await self.connect()
        writer.write(b'POST /v1/deliver HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{')
        await writer.drain()
        await asyncio.sleep(0.01)
        self.assertIn(b'503 Result', await self.request(b''))
        self.assertIn(b'408 Result', await asyncio.wait_for(reader.read(), 1))
        self.assertEqual(self.accepted, 0)

    async def test_unterminated_oversized_header_rejected_before_deadline(self):
        self.listener.deadline = 2
        reader, writer = await self.connect()
        writer.write(b'POST /v1/deliver HTTP/1.1\r\nX: ' + b'a' * 9000)
        await writer.drain()
        self.assertIn(b'400 Result', await asyncio.wait_for(reader.read(), 0.5))
        self.assertEqual(self.accepted, 0)


if __name__ == '__main__':
    unittest.main()
