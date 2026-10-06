"""Bounded one-request HTTP transport; no keepalive, chunking, or redirects."""

import asyncio
import json

from .gateway import Refused
from .protocol import ProtocolError
from .security import SecurityError
from .store import StoreError


class Listener:
    def __init__(self, gateway, *, deadline=5, concurrency=8):
        """Bound request processing by absolute time and concurrency."""
        self.gateway, self.deadline = gateway, deadline
        self.concurrency, self.active = concurrency, 0

    async def handle(self, reader, writer):
        if self.active >= self.concurrency:
            await self._reply(writer, 503, {"reason": "listener_capacity"})
            return
        self.active += 1
        try:
            async with asyncio.timeout(self.deadline):
                head = await reader.readuntil(b"\r\n\r\n")
                if len(head) > 8192:
                    raise Refused("headers_too_large")
                lines = head.decode("ascii").split("\r\n")
                if lines[0] != "POST /v1/deliver HTTP/1.1":
                    raise Refused("invalid_request")
                headers = {}
                for line in lines[1:-2]:
                    key, value = line.split(":", 1)
                    key = key.lower()
                    if key in headers or not key or key.strip() != key:
                        raise Refused("invalid_headers")
                    headers[key] = value.strip()
                if (
                    "transfer-encoding" in headers
                    or headers.get("content-type") != "application/json"
                    or not headers.get("content-length", "").isdigit()
                ):
                    raise Refused("invalid_framing")
                length = int(headers["content-length"])
                if length > 4096:
                    raise Refused("message_too_large")
                body = await reader.readexactly(length)
                result = self.gateway.accept(
                    body,
                    signature=headers.get("x-event-signature", ""),
                    audience=headers.get("x-event-audience", ""),
                    key_id=headers.get("x-event-key-id", ""),
                )
                await self._reply(writer, 202, result)
        except TimeoutError:
            await self._reply(writer, 408, {"reason": "request_deadline"})
        except (Refused, ProtocolError, SecurityError, StoreError) as error:
            await self._reply(
                writer,
                409 if isinstance(error, StoreError) else 400,
                {"reason": error.code},
            )
        except (
            ValueError,
            UnicodeError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
        ):
            await self._reply(writer, 400, {"reason": "invalid_request"})
        finally:
            self.active -= 1
            writer.close()
            await writer.wait_closed()

    @staticmethod
    async def _reply(writer, status, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        writer.write(
            f"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        try:
            await asyncio.wait_for(writer.drain(), 1)
        except (TimeoutError, ConnectionError):
            pass
        if status == 503:
            writer.close()
            await writer.wait_closed()
