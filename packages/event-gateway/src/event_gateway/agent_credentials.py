"""Bounded adapter for the local agent-token helper."""

import asyncio
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from .cloud import CloudError
from .protocol import ProtocolError, _pairs

_MAX_OUTPUT = 8192
_MAX_TOKEN = 4096


def _reject_constant(_):
    raise ValueError


def _path(value, *, executable):
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise CloudError("credentials_unavailable")
    path = Path(value)
    try:
        info = path.stat()
        if (path.is_symlink() or not stat.S_ISREG(info.st_mode)
                or (executable and not os.access(path, os.X_OK))):
            raise CloudError("credentials_unavailable")
    except (OSError, ValueError):
        raise CloudError("credentials_unavailable") from None
    return str(path)


def _identity(origin, agent):
    if not isinstance(origin, str) or not isinstance(agent, str):
        raise CloudError("credentials_unavailable")
    try:
        parsed = urlsplit(origin)
        if (not isinstance(origin, str) or parsed.scheme != "https" or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path
                or origin != f"https://{parsed.hostname}"
                or not re.fullmatch(r"[a-z0-9-]{1,32}", agent)):
            raise ValueError
    except (TypeError, ValueError):
        raise CloudError("credentials_unavailable") from None
    return origin


async def _read_bounded(stream):
    output = bytearray()
    while True:
        chunk = await stream.read(min(1024, _MAX_OUTPUT + 1 - len(output)))
        if not chunk:
            return bytes(output)
        output.extend(chunk)
        if len(output) > _MAX_OUTPUT:
            raise CloudError("credentials_unavailable")


async def _reap(process):
    if process is not None:
        if process.returncode is None:
            process.kill()
        await process.wait()


class AgentTokenProvider:
    """Invoke the configured helper once per request and return its bare JWT."""

    def __init__(self, node_path, helper_path, *, origin, agent):
        self.node_path = _path(node_path, executable=True)
        self.helper_path = _path(helper_path, executable=False)
        self.origin = _identity(origin, agent)
        self.agent = agent

    async def __call__(self):
        command = (self.node_path, self.helper_path, "header", "--audience", self.origin,
                   "--agent", self.agent)
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"NODE_OPTIONS", "NODE_PATH"}}
        process = None
        try:
            async with asyncio.timeout(2):
                process = await asyncio.create_subprocess_exec(
                    *command, stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                    env=environment,
                )
                output = await _read_bounded(process.stdout)
                if await process.wait() != 0:
                    raise CloudError("credentials_unavailable")
            value = json.loads(output.decode("utf-8"), object_pairs_hook=_pairs,
                               parse_constant=_reject_constant)
            if (not isinstance(value, dict) or set(value) != {"X-Knitli-Agent-Token"}
                    or not isinstance(value["X-Knitli-Agent-Token"], str)):
                raise ValueError
            token = value["X-Knitli-Agent-Token"]
            if (not 1 <= len(token) <= _MAX_TOKEN or re.search(r"\s", token)
                    or token.startswith("Bearer ")
                    or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)):
                raise ValueError
            return token
        except TimeoutError:
            raise CloudError("credentials_timeout") from None
        except CloudError:
            raise
        except (OSError, UnicodeError, ValueError, RecursionError, ProtocolError):
            raise CloudError("credentials_unavailable") from None
        finally:
            await _reap(process)
