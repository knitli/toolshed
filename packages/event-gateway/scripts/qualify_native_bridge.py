"""Experimental private-FD qualification; synthetic events and loopback mock model only."""

import argparse
from copy import deepcopy
from contextlib import contextmanager
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import threading
import time
from uuid import uuid4

from event_gateway.native_reader import (
    BridgeError as BridgeError,
    IDENTITY as IDENTITY,
    NativeBridge as NativeBridge,
    require as require,
    unique,
)


def synthetic_request(witness):
    now = time.time_ns() // 1_000_000
    return {
        **{
            key: witness[key]
            for key in (
                "clientId",
                "generation",
                "serverInstanceId",
                "serverGeneration",
                "threadId",
            )
        },
        "attemptId": str(uuid4()),
        "deliveryId": "dly_" + uuid4().hex + uuid4().hex,
        "clientUserMessageId": str(uuid4()),
        "permitId": str(uuid4()),
        "permitIssuedAt": now,
        "permitExpiresAt": now + 5000,
        "event": {
            "eventId": str(uuid4()),
            "source": "manual",
            "sourceStateVersion": "qualification-1",
            "canonicalSubject": {"kind": "manual", "subjectId": "native-qualification"},
            "eventReference": "ref_" + str(uuid4()),
        },
    }


TITLE_SCHEMA = {
    "type": "object",
    "properties": {"title": {"type": "string", "minLength": 1, "maxLength": 36}},
    "required": ["title"],
    "additionalProperties": False,
}


class MockModel(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if self.path != "/responses" or not 0 < size <= 4 * 1024 * 1024:
            self.send_error(400)
            return
        kind = "unknown"
        try:
            request = json.loads(self.rfile.read(size), object_pairs_hook=unique)
            if isinstance(request, dict) and request.get("model") == "mock-model":
                text = request.get("text") or {}
                if isinstance(text, dict):
                    output_format = text.get("format")
                    if output_format is None:
                        kind = "primary"
                    elif output_format == {
                        "type": "json_schema",
                        "strict": True,
                        "name": "codex_output_schema",
                        "schema": TITLE_SCHEMA,
                    }:
                        kind = "title"
            del (
                request
            )  # Never retain prompts; only request classes/counts become evidence.
        except (ValueError, TypeError, RecursionError):
            pass
        self.server.model_requests += 1
        self.server.request_counts[kind] += 1
        if kind == "unknown":
            self.send_error(400)
            return
        release = getattr(self.server, "release_primary", None)
        if kind == "primary" and self.server.request_counts["primary"] == 1 and release is not None:
            if not release.wait(30):
                self.send_error(504)
                return
        response_text = (
            '{"title":"Qualify native bridge"}'
            if kind == "title"
            else "Synthetic qualification complete."
        )
        item = {
            "id": "msg_mock",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": response_text}],
        }
        events = [
            {"type": "response.created", "response": {"id": "resp_mock"}},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
            {
                "type": "response.completed",
                "response": {
                    "id": "resp_mock",
                    "status": "completed",
                    "output": [item],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                },
            },
        ]
        payload = "".join(
            "data: " + json.dumps(event) + "\n\n" for event in events
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def qualify_terminal_retry(bridge, server, process, witness):
    """Native-only proof; distinct synthetic permits do not prove cloud settlement."""
    rejected = synthetic_request(witness)
    rejected["permitIssuedAt"] -= 10_000
    rejected["permitExpiresAt"] -= 10_000
    try:
        terminal = bridge.start(rejected)
        require(terminal["status"] == "terminalNotStarted"
                and terminal["reason"] == "permitExpired")
        require(server.model_requests == 0
                and all(count == 0 for count in server.request_counts.values()))
        # Refresh after the terminal reply; its round trip can consume the lease.
        available = bridge.challenge()
        require(available["eligible"])
        first = synthetic_request(available)
        started = bridge.start(first)
        require(started["status"] == "started")
        deadline = time.monotonic() + 10
        while not server.request_counts["primary"] and time.monotonic() < deadline:
            time.sleep(0.01)
        require(server.request_counts["primary"] == 1
                and server.request_counts["unknown"] == 0)
        require(bridge.receipt(rejected) == {**terminal, "replayed": True})
    finally:
        server.release_primary.set()
    deadline = time.monotonic() + 10
    while True:
        renewed = bridge.challenge()
        if renewed["eligible"]:
            break
        require(process.poll() is None and time.monotonic() < deadline)
        time.sleep(0.05)
    retry = synthetic_request(renewed)
    retry["deliveryId"], retry["event"] = rejected["deliveryId"], deepcopy(rejected["event"])
    require(retry["threadId"] == rejected["threadId"]
            and all(retry[key] != rejected[key]
                    for key in ("attemptId", "permitId", "clientUserMessageId")))
    retried = bridge.start(retry)
    require(retried["status"] == "started")
    for request, outcome in ((first, started), (retry, retried)):
        require(bridge.receipt(request) == {**outcome, "replayed": True})
    require(bridge.receipt(rejected) == {**terminal, "replayed": True})
    deadline = time.monotonic() + 10
    while server.request_counts["primary"] < 2 and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(2)
    require(server.request_counts["primary"] == 2
            and server.request_counts["title"] <= 2
            and server.request_counts["unknown"] == 0 and process.poll() is None)
    return {
        "qualification": "synthetic-native-terminal-retry", "nativeOnly": True,
        "cloudSettlementProven": False, "outcome": retried["status"],
        "terminalReason": terminal["reason"], "terminalReceiptId": terminal["receiptId"],
        "exactTerminalReceiptRecovered": True, "exactReceiptRecovered": True,
        "busyRefusalProven": False, "retainedTerminalRecoveredWhileBusy": True,
        "retriedDeliverySame": retry["deliveryId"] == rejected["deliveryId"],
        "retryAttemptDistinct": retry["attemptId"] != rejected["attemptId"],
        "retryPermitDistinct": retry["permitId"] != rejected["permitId"],
        "retryMessageDistinct": retry["clientUserMessageId"] != rejected["clientUserMessageId"],
        "mockModelRequests": server.model_requests,
        "primaryModelRequests": server.request_counts["primary"],
        "titleModelRequests": server.request_counts["title"],
        "unknownModelRequests": server.request_counts["unknown"], "realModelCalls": 0,
    }


def qualify_input_recorded(bridge, server, process, witness):
    """Core input observation is native-only; Started remains registration only."""
    request = synthetic_request(witness)
    try:
        require(bridge.start(request)["status"] == "started")
        deadline = time.monotonic() + 10
        while True:
            require(process.poll() is None and time.monotonic() < deadline)
            recorded = bridge.receipt(request)
            if recorded["status"] == "inputRecorded":
                break
            require(recorded["status"] == "started")
            time.sleep(0.05)
        deadline = time.monotonic() + 10
        while not server.request_counts["primary"] and time.monotonic() < deadline:
            time.sleep(0.01)
        busy = bridge.challenge()
        require(busy["eligible"] is False)
        # Read-only recovery needs neither a fresh lease nor a live permit.
        deadline = time.monotonic() + 10
        while time.time_ns() // 1_000_000 <= request["permitExpiresAt"]:
            require(process.poll() is None and time.monotonic() < deadline)
            time.sleep(0.05)
        require(bridge.receipt(request) == recorded)
        require(bridge.receipt(request) == recorded)
        require(server.request_counts["primary"] == 1
                and server.request_counts["title"] <= 1
                and server.request_counts["unknown"] == 0
                and server.model_requests == sum(server.request_counts.values())
                and process.poll() is None)
        return {
            "qualification": "synthetic-native-input-recorded", "nativeOnly": True,
            "cloudSettlementProven": False, "outcome": recorded["status"],
            "turnId": recorded["turnId"], "itemId": recorded["itemId"],
            "threadId": witness["threadId"], "exactReceiptRecovered": True,
            "recoveredWhileIneligibleAfterPermitExpiry": True,
            "mockModelRequests": server.model_requests,
            "primaryModelRequests": server.request_counts["primary"],
            "titleModelRequests": server.request_counts["title"],
            "unknownModelRequests": server.request_counts["unknown"], "realModelCalls": 0,
        }
    finally:
        server.release_primary.set()


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Denied visibility cannot establish that a tracked process has stopped.
        return True


def stop_process(process, backend_pid):
    # Remember completed cleanup on this owned Popen object: later PID reuse must
    # never turn a context finalizer into a signal to a different process group.
    if getattr(process, "_native_group_stopped", False) is True:
        return
    if process.poll() is not None and backend_pid is not None and not alive(backend_pid):
        process._native_group_stopped = True
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The leader may exit while a descendant survives SIGTERM.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    if backend_pid is None:
        process._native_group_stopped = True
        return
    deadline = time.monotonic() + 5
    while alive(backend_pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    require(not alive(backend_pid))
    process._native_group_stopped = True


@contextmanager
def native_client(args, root, *, receipt_version=2):
    """Own a disposable native process group and private channel, never a user client."""
    env = {
        "PATH": os.defpath,
        "HOME": str(root),
        "CODEX_HOME": str(root / "codex-home"),
        "TERM": "xterm-256color",
    }
    if receipt_version == 3:
        env["CODEX_NATIVE_BRIDGE_RECEIPT_VERSION"] = "3"
    parent = child = master = slave = None
    process = None
    bridge = None
    witness = None
    stop = threading.Event()
    drain_thread = None

    def drain():
        while not stop.is_set():
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                    if not data:
                        break
                    if b"\x1b[6n" in data:
                        os.write(master, b"\x1b[1;1R")
                except OSError:
                    break

    try:
        parent, child = socket.socketpair()
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        env["CODEX_NATIVE_BRIDGE_FD"] = str(child.fileno())
        bridge = NativeBridge(parent, receipt_version=receipt_version)
        process = subprocess.Popen(
            args,
            env=env,
            cwd=root,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            pass_fds=(child.fileno(),),
            start_new_session=True,
        )
        child.close()
        os.close(slave)
        slave = None
        drain_thread = threading.Thread(target=drain, daemon=True)
        drain_thread.start()
        # Synchronize startup only; this old response grants no witness or eligibility.
        bridge.exchange({}, 30)
        deadline = time.monotonic() + 30
        while True:
            witness = bridge.challenge()
            if witness["serverInstanceId"] is not None and witness["threadId"] is not None:
                break
            require(process.poll() is None and time.monotonic() < deadline)
            time.sleep(0.1)
        yield bridge, process, witness
    finally:
        stop.set()
        if bridge is not None:
            bridge.close()
        elif parent is not None:
            parent.close()
        if child is not None:
            child.close()
        try:
            if process is not None:
                stop_process(process, witness['backendPid'] if witness else None)
        finally:
            if drain_thread is not None:
                drain_thread.join(timeout=1)
            if slave is not None:
                os.close(slave)
            if master is not None:
                os.close(master)


def qualify(binary, *, terminal_retry=False, input_recorded=False, receipt_version=2):
    """Launch only a disposable TUI; never inherit auth, configuration, or proxy settings."""
    require(type(receipt_version) is int and receipt_version in (2, 3))
    require(not (terminal_retry and input_recorded))
    binary = Path(binary).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="native-qualification-") as directory:
        root = Path(directory)
        home = root / "codex-home"
        home.mkdir(mode=0o700)
        (home / "config.toml").write_text(
            f'[projects.{json.dumps(str(root))}]\ntrust_level = "trusted"\n'
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), MockModel)
        server.model_requests = 0
        server.request_counts = {"primary": 0, "title": 0, "unknown": 0}
        if terminal_retry or input_recorded:
            server.release_primary = threading.Event()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        flags = [
            "--no-daemon",
            "-c",
            "check_for_update_on_startup=false",
            "-c",
            'model_provider="qualification"',
            "-c",
            'model_providers.qualification.name="Synthetic qualification"',
            "-c",
            f'model_providers.qualification.base_url="http://127.0.0.1:{server.server_port}"',
            "-c",
            'model_providers.qualification.wire_api="responses"',
            "-c",
            "model_providers.qualification.requires_openai_auth=false",
            "-c",
            'model="mock-model"',
            "-c",
            "analytics.enabled=false",
            "-c",
            "feedback.enabled=false",
            "-c",
            'otel.exporter="none"',
            "-c",
            'otel.trace_exporter="none"',
            "-c",
            'otel.metrics_exporter="none"',
            "--no-alt-screen",
            "-C",
            str(root),
        ]
        try:
            with native_client([str(binary), *flags], root, receipt_version=receipt_version) as (bridge, process, witness):
                deadline = time.monotonic() + 30
                while not witness['eligible']:
                    require(process.poll() is None and time.monotonic() < deadline)
                    time.sleep(0.1)
                    witness = bridge.challenge()
                require(server.model_requests == 0)
                if input_recorded:
                    return qualify_input_recorded(bridge, server, process, witness)
                if terminal_retry:
                    return qualify_terminal_retry(bridge, server, process, witness)
                request = synthetic_request(witness)
                outcome = bridge.start(request)
                require(outcome["status"] == "started")
                deadline = time.monotonic() + 10
                while not server.request_counts["primary"] and time.monotonic() < deadline:
                    time.sleep(0.05)
                require(server.request_counts["primary"] == 1)
                # Keep the mock alive after its response to detect unintended follow-up sampling.
                time.sleep(2)
                require(
                    server.request_counts["primary"] == 1
                    and server.request_counts["title"] <= 1
                    and server.request_counts["unknown"] == 0
                    and process.poll() is None
                )
                recovered = bridge.receipt(request)
                require(
                    recovered
                    == {"status": "started", "turnId": outcome["turnId"], "replayed": True}
                )
                require(
                    server.request_counts["primary"] == 1
                    and server.request_counts["title"] <= 1
                    and server.request_counts["unknown"] == 0
                )
                return {
                    "qualification": "synthetic-native-start",
                    "outcome": outcome["status"],
                    "turnId": outcome["turnId"],
                    "threadId": witness["threadId"],
                    "mockModelRequests": server.model_requests,
                    "primaryModelRequests": server.request_counts["primary"],
                    "titleModelRequests": server.request_counts["title"],
                    "unknownModelRequests": server.request_counts["unknown"],
                    "exactReceiptRecovered": True,
                    "realModelCalls": 0,
                }
        finally:
            if terminal_retry or input_recorded:
                server.release_primary.set()
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--receipt-version", type=int, choices=(2, 3), default=2)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--input-recorded", action="store_true",
                       help="Prove native Core input observation through read-only receipts")
    modes.add_argument("--terminal-retry", action="store_true",
                        help="Prove native terminal refusal/retry; does not prove cloud settlement")
    args = parser.parse_args()
    try:
        print(json.dumps(qualify(args.binary, terminal_retry=args.terminal_retry,
                                 input_recorded=args.input_recorded,
                                 receipt_version=args.receipt_version), sort_keys=True))
    except (BridgeError, OSError, subprocess.SubprocessError):
        print(
            json.dumps(
                {"qualification": "failed", "reason": "native-bridge-unqualified"}
            )
        )
        raise SystemExit(1) from None
