"""Private local control daemon. This stage cannot enable automatic dispatch."""
import asyncio
import json
import os
from pathlib import Path
import signal
import stat

from .store import Store


BLOCKERS = ["native_client_binding_unavailable", "cloud_authority_not_integrated"]


def status(store):
    return {"stage": "foundation", "automaticWakeEnabled": False,
            "blockers": BLOCKERS, "store": store.status()}


async def serve(state_dir):
    with Store(state_dir) as store:
        path = Path(state_dir) / "control.sock"
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("unsafe_control_socket")
            # Writer lock proves no other gateway owns this socket.
            path.unlink()
        active = 0

        async def control(reader, writer):
            nonlocal active
            if active >= 8:
                writer.close()
                await writer.wait_closed()
                return
            active += 1
            try:
                async with asyncio.timeout(5):
                    line = await reader.readline()
                    if len(line) > 4096:
                        raise ValueError("request_too_large")
                    request = json.loads(line)
                    if request == {"command": "status"}:
                        result = status(store)
                    elif (isinstance(request, dict)
                          and set(request) == {"command", "runtimeId"}
                          and request["command"] == "detach"
                          and isinstance(request["runtimeId"], str)):
                        store.detach(request["runtimeId"])
                        result = {"detached": True}
                    else:
                        result = {"reason": "unsupported_command"}
                    writer.write(json.dumps(result).encode() + b"\n")
                    await writer.drain()
            except (ValueError, TimeoutError):
                pass
            finally:
                active -= 1
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_unix_server(control, path=path, limit=4096)
        os.chmod(path, 0o600)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        try:
            async with server:
                await stop.wait()
        finally:
            server.close()
            await server.wait_closed()
            path.unlink(missing_ok=True)
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(sig)


async def request(state_dir, value):
    path = Path(state_dir) / "control.sock"
    info = path.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("unsafe_control_socket")
    async with asyncio.timeout(5):
        reader, writer = await asyncio.open_unix_connection(path, limit=8192)
        try:
            writer.write(json.dumps(value).encode() + b"\n")
            await writer.drain()
            return json.loads(await reader.readline())
        finally:
            writer.close()
            await writer.wait_closed()
