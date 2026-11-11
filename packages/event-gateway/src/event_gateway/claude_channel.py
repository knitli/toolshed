"""Claude Code MCP channel adapter for one explicitly assigned conversation."""

import argparse
import asyncio
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server

from .cloud import _generation, _uuid
from .daemon import request
from .messaging_protocol_v2 import _code_points, _integer


_MAX_CONTROL_FRAME = 8192
_POLL_INTERVAL = 0.5
_DELIVERY_FIELDS = {
    "eventId", "deliveryId", "attemptId", "principal", "agent", "runtimeId",
    "nodeGeneration", "runtimeGeneration", "attachmentGeneration", "consumerGeneration",
    "sourceStateVersion", "eventReference", "runtimeProfile", "nodeId", "conversationId",
    "receiptToken",
}
_ROUTED_DELIVERY_FIELDS = _DELIVERY_FIELDS | {
    "routingGeneration", "namespace", "agentIncarnation", "messageId",
}
_ID_RE = re.compile(r"dly_[0-9a-f]{64}\Z")
_EVENT_REFERENCE_RE = re.compile(
    r"ref_[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_SOURCE_STATE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,256}\Z")


def _text(value):
    return isinstance(value, str) and 0 < len(value) <= 512 and "\x00" not in value


def _valid_route(value):
    if "routingGeneration" not in value:
        return True
    namespace = value["namespace"]
    return (
        _generation(value["routingGeneration"])
        and isinstance(namespace, str)
        and 1 <= _code_points(namespace) <= 256
        and not re.search(r"[\x00-\x1f\x7f]", namespace)
        and _integer(value["agentIncarnation"], 0)
        and _uuid(value["messageId"])
    )


def _delivery(value, runtime_id, conversation_id):
    if not isinstance(value, dict):
        return None
    keys = set(value)
    if keys not in (_DELIVERY_FIELDS, _ROUTED_DELIVERY_FIELDS):
        return None
    if (not _uuid(value["eventId"]) or not isinstance(value["deliveryId"], str)
            or not _ID_RE.fullmatch(value["deliveryId"]) or not _uuid(value["attemptId"])
            or value["runtimeId"] != runtime_id or value["conversationId"] != conversation_id
            or not _uuid(value["nodeId"])
            or not isinstance(value["eventReference"], str)
            or not _EVENT_REFERENCE_RE.fullmatch(value["eventReference"])
            or value["runtimeProfile"] != {
                "profile": "assigned_stock_client", "client": "claude",
                "conversationId": conversation_id,
            }
            or not isinstance(value["receiptToken"], str)
            or not _TOKEN_RE.fullmatch(value["receiptToken"])):
        return None
    for name in ("principal", "agent"):
        if not _text(value[name]):
            return None
    for name in ("nodeGeneration", "runtimeGeneration", "attachmentGeneration", "consumerGeneration"):
        if not _generation(value[name]):
            return None
    source_version = value["sourceStateVersion"]
    if not isinstance(source_version, str) or not _SOURCE_STATE_RE.fullmatch(source_version):
        return None
    if not _valid_route(value):
        return None
    return value


def _tool():
    return types.Tool(
        name="client_reported",
        description=("Report that this configured Claude conversation received the event. "
                     "Call only for an event actually handled in this conversation."),
        inputSchema={
            "type": "object",
            "properties": {
                "deliveryId": {"type": "string", "minLength": 68, "maxLength": 68,
                               "pattern": "^dly_[0-9a-f]{64}$"},
                "attemptId": {"type": "string", "format": "uuid"},
                "receiptToken": {"type": "string", "minLength": 32, "maxLength": 256,
                                 "pattern": "^[A-Za-z0-9_-]+$"},
            },
            "required": ["deliveryId", "attemptId", "receiptToken"],
            "additionalProperties": False,
        },
    )


async def _register(state_dir, runtime_id, conversation_id):
    try:
        result = await request(state_dir, {
            "command": "claude-register", "runtimeId": runtime_id,
            "conversationId": conversation_id,
        })
        return (isinstance(result, dict) and result.get("registered") is True
                and result.get("runtimeId") == runtime_id)
    except Exception:
        return False


async def _next_delivery(state_dir, runtime_id, conversation_id):
    result = await request(state_dir, {
        "command": "claude-poll", "runtimeId": runtime_id,
        "conversationId": conversation_id,
    })
    if not isinstance(result, dict) or set(result) != {"delivery"}:
        return None
    return _delivery(result["delivery"], runtime_id, conversation_id)


def _notification(delivery):
    body = {
        "event": delivery["eventReference"],
        "deliveryId": delivery["deliveryId"],
        "attemptId": delivery["attemptId"],
        "receiptToken": delivery["receiptToken"],
    }
    if "routingGeneration" in delivery:
        body["messageId"] = delivery["messageId"]
    notice = types.Notification[dict[str, Any], str](
        method="notifications/claude/channel",
        params={
            "content": json.dumps(body, ensure_ascii=False, separators=(",", ":")),
            "meta": {
                "delivery_id": delivery["deliveryId"],
                "attempt_id": delivery["attemptId"],
            },
        },
    )
    return notice if len(notice.model_dump_json(exclude_none=True).encode("utf-8")) <= _MAX_CONTROL_FRAME else None


async def _poll(state_dir, runtime_id, conversation_id, session):
    while True:
        try:
            delivery = await _next_delivery(state_dir, runtime_id, conversation_id)
            notice = _notification(delivery) if delivery is not None else None
            if notice is None:
                await asyncio.sleep(_POLL_INTERVAL)
                continue
            # A claimed event is one-shot even if writing this notification fails.
            await session.send_notification(notice)
        except asyncio.CancelledError:
            raise
        except Exception:
            await asyncio.sleep(_POLL_INTERVAL)


def _callback_result(recorded):
    return [types.TextContent(type="text", text=json.dumps(
        {"recorded": recorded, "reason": None if recorded else "refused"},
        separators=(",", ":"),
    ))]


async def _client_reported(state_dir, runtime_id, conversation_id, arguments):
    if not isinstance(arguments, dict):
        return _callback_result(False)
    if (set(arguments) != {"deliveryId", "attemptId", "receiptToken"}
            or not isinstance(arguments.get("deliveryId"), str)
            or not _ID_RE.fullmatch(arguments["deliveryId"])
            or not _uuid(arguments.get("attemptId"))
            or not isinstance(arguments.get("receiptToken"), str)
            or not _TOKEN_RE.fullmatch(arguments["receiptToken"])):
        return [types.TextContent(type="text", text='{"recorded":false,"reason":"invalid_arguments"}')]
    try:
        result = await request(state_dir, {
            "command": "claude-client-reported", "runtimeId": runtime_id,
            "conversationId": conversation_id, **arguments,
        })
    except Exception:
        result = None
    return _callback_result(isinstance(result, dict) and result.get("recorded") is True)


def create_server(state_dir: Path, runtime_id: str, conversation_id: str):
    server = Server(
        "knitli-event-gateway", version="0.1.0",
        instructions=("This channel is operator-bound to one existing Claude conversation; it does not select or start sessions. "
                      "Incoming event JSON contains an event reference and one-use receipt token. Call client_reported "
                      "with deliveryId, attemptId, and receiptToken only when this conversation receives the event. "
                      "Do not repeat the token elsewhere. This reports client receipt, not completed work."),
    )
    poll_task = None
    registered = False

    async def register_and_poll(session):
        nonlocal registered
        while not registered:
            registered = await _register(state_dir, runtime_id, conversation_id)
            if not registered:
                await asyncio.sleep(_POLL_INTERVAL)
        await _poll(state_dir, runtime_id, conversation_id, session)

    @server.list_tools()
    async def list_tools():
        nonlocal poll_task
        if poll_task is None:
            # Registration is retried in this one task; no event polling or
            # callback acceptance is enabled until the assignment is accepted.
            poll_task = asyncio.create_task(register_and_poll(server.request_context.session))
        return [_tool()]

    @server.call_tool()
    async def call_tool(name, arguments):
        if name != "client_reported" or not registered:
            return _callback_result(False)
        return await _client_reported(state_dir, runtime_id, conversation_id, arguments)

    async def run():
        with _assignment_lock(state_dir, runtime_id, conversation_id):
            try:
                async with stdio_server() as (read_stream, write_stream):
                    await server.run(
                        read_stream, write_stream,
                        server.create_initialization_options(
                            notification_options=NotificationOptions(),
                            experimental_capabilities={"claude/channel": {}},
                        ),
                    )
            finally:
                if poll_task is not None:
                    poll_task.cancel()
                    await asyncio.gather(poll_task, return_exceptions=True)

    return run


@contextmanager
def _assignment_lock(state_dir: Path, runtime_id: str, conversation_id: str):
    info = state_dir.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("unsafe_state_directory")
    key = hashlib.sha256(f"{runtime_id}:{conversation_id}".encode()).hexdigest()
    path = state_dir / f".claude-channel-{key}.lock"
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("unsafe_assignment_lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


async def _run(state_dir: Path, runtime_id: str, conversation_id: str):
    await create_server(state_dir, runtime_id, conversation_id)()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="claude-channel")
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--conversation-id", required=True)
    args = parser.parse_args(argv)
    if not _uuid(args.runtime_id) or not _uuid(args.conversation_id):
        parser.error("runtime-id and conversation-id must be UUIDs")
    try:
        asyncio.run(_run(args.state_dir, args.runtime_id, args.conversation_id))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
