import asyncio
import unittest

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
        reader, writer = await self.connect()
        writer.write(b'POST /v1/deliver HTTP/1.1\r\nX: ')
        await writer.drain()
        await asyncio.sleep(0.06)
        writer.write(b'a')
        await writer.drain()
        self.assertIn(b'408 Result', await asyncio.wait_for(reader.read(), 0.08))
        self.assertEqual(self.accepted, 0)

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
