"""Experimental private-FD qualification; synthetic events and loopback mock model only."""

import argparse
from copy import deepcopy
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pty
import re
import select
import socket
import struct
import subprocess
import tempfile
import termios
import threading
import time
from uuid import UUID, uuid4

MAX_FRAME = 4096
WITNESS_SECONDS = 0.750
START_SECONDS = 2.0
NOT_STARTED_REASONS = frozenset(
    (
        "busy serverDraining selectionExpired selectionChanged permitExpired "
        "permitInvalid duplicateConflict receiptCapacity connectionClosed threadUnavailable inputInvalid"
    ).split()
)
TERMINAL_REASONS = NOT_STARTED_REASONS - {"permitInvalid", "duplicateConflict", "receiptCapacity"}
IDENTITY = (
    "clientId",
    "serverInstanceId",
    "serverGeneration",
    "threadId",
    "attemptId",
    "deliveryId",
    "clientUserMessageId",
    "permitId",
    "permitIssuedAt",
    "permitExpiresAt",
)
WITNESS_FIELDS = set(
    (
        "version nonce clientId backendPid connectionId threadId generation "
        "eligible sequence cause serverInstanceId serverGeneration leaseMs"
    ).split()
)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
EVENT_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)


class BridgeError(ValueError):
    """Sanitized transport/schema failure; never contains frame contents."""


def require(condition):
    if not condition:
        raise BridgeError("invalid bridge frame or state")


def uint(value, maximum=2**64 - 1, minimum=0):
    return type(value) is int and minimum <= value <= maximum


def uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def validate_start(start):
    require(
        isinstance(start, dict)
        and set(start) == set(IDENTITY) | {"generation", "event"}
    )
    for key in ("clientId", "serverInstanceId", "threadId", "clientUserMessageId"):
        require(uuid(start[key]))
    for key in ("generation", "serverGeneration", "permitIssuedAt", "permitExpiresAt"):
        require(uint(start[key]))
    require(start["permitExpiresAt"] - start["permitIssuedAt"] == 5000)
    require(
        isinstance(start["attemptId"], str) and EVENT_UUID.fullmatch(start["attemptId"])
    )
    require(
        isinstance(start["deliveryId"], str)
        and re.fullmatch(r"dly_[0-9a-f]{64}", start["deliveryId"])
    )
    require(
        isinstance(start["permitId"], str) and IDENTIFIER.fullmatch(start["permitId"])
    )
    event = start["event"]
    require(
        isinstance(event, dict)
        and set(event)
        == {
            "eventId",
            "source",
            "sourceStateVersion",
            "canonicalSubject",
            "eventReference",
        }
    )
    require(
        isinstance(event["eventId"], str) and EVENT_UUID.fullmatch(event["eventId"])
    )
    require(
        isinstance(event["eventReference"], str)
        and event["eventReference"].startswith("ref_")
        and EVENT_UUID.fullmatch(event["eventReference"][4:])
    )
    require(
        isinstance(event["sourceStateVersion"], str)
        and IDENTIFIER.fullmatch(event["sourceStateVersion"])
    )
    subject = event["canonicalSubject"]
    require(isinstance(subject, dict))
    if event["source"] == "manual":
        require(set(subject) == {"kind", "subjectId"} and subject["kind"] == "manual")
        require(
            isinstance(subject["subjectId"], str)
            and IDENTIFIER.fullmatch(subject["subjectId"])
        )
    else:
        require(
            event["source"] == "github"
            and set(subject) == {"kind", "repositoryId", "pullRequestNumber"}
            and subject["kind"] == "github_pr"
        )
        require(
            isinstance(subject["repositoryId"], str)
            and re.fullmatch(r"[1-9][0-9]{0,19}", subject["repositoryId"])
        )
        require(uint(subject["pullRequestNumber"], 2**53 - 1, 1))


class NativeBridge:
    """One synchronous request at a time. Start attempts are never resent, even after refusal."""

    def __init__(self, channel, *, receipt_version=2):
        require(type(receipt_version) is int and receipt_version in (2, 3))
        self.receipt_version = receipt_version
        require(channel.family == socket.AF_UNIX and channel.type == socket.SOCK_STREAM)
        channel.getpeername()
        channel.set_inheritable(False)
        self.channel = channel
        self.nonce = self.sequence = 0
        self.client_id = self.witness = None
        self.valid_until = 0
        self.closed = False
        self.exchange_lock = threading.Lock()
        self.attempts, self.deliveries, self.messages = {}, {}, set()
        self.terminal_attempts = set()

    def close(self):
        self.closed = True
        self.witness = None
        self.channel.close()

    def exchange(self, body, seconds):
        require(self.exchange_lock.acquire(blocking=False))
        try:
            return self._exchange(body, seconds)
        finally:
            self.exchange_lock.release()

    def _exchange(self, body, seconds):
        require(not self.closed and self.nonce < 2**64 - 1)
        self.nonce += 1
        frame = (
            json.dumps(
                {"nonce": self.nonce, **body}, separators=(",", ":"), allow_nan=False
            ).encode()
            + b"\n"
        )
        require(len(frame) <= MAX_FRAME)
        deadline = time.monotonic() + seconds
        try:
            self.channel.settimeout(max(0.000001, deadline - time.monotonic()))
            self.channel.sendall(frame)
            data = bytearray()
            while b"\n" not in data:
                remaining = deadline - time.monotonic()
                require(remaining > 0 and len(data) < MAX_FRAME)
                self.channel.settimeout(remaining)
                chunk = self.channel.recv(MAX_FRAME + 1 - len(data))
                require(bool(chunk))
                data.extend(chunk)
            require(
                len(data) <= MAX_FRAME and data[-1:] == b"\n" and data.count(b"\n") == 1
            )
            require(time.monotonic() < deadline)
            row = json.loads(
                data, object_pairs_hook=unique, parse_constant=lambda _: require(False)
            )
            require(
                isinstance(row, dict)
                and type(row.get("version")) is int
                and row["version"] == (self.receipt_version if "start" in body or "receipt" in body else 2)
                and type(row.get("nonce")) is int
                and row["nonce"] == self.nonce
            )
            return row
        except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
            self.close()
            raise BridgeError("bridge exchange failed") from None

    def challenge(self):
        issued = time.monotonic()
        self.witness = None
        try:
            row = self.exchange({}, WITNESS_SECONDS)
            require(set(row) == WITNESS_FIELDS)
            require(uuid(row["clientId"]) and self.client_id in (None, row["clientId"]))
            for key in ("connectionId", "threadId", "serverInstanceId"):
                require(row[key] is None or uuid(row[key]))
            require(row["backendPid"] is None or uint(row["backendPid"], 2**32 - 1, 1))
            require(
                uint(row["generation"])
                and uint(row["sequence"], minimum=self.sequence + 1)
            )
            require(
                type(row["eligible"]) is bool
                and isinstance(row["cause"], str)
                and len(row["cause"]) <= 128
            )
            for key in ("serverGeneration", "leaseMs"):
                require(row[key] is None or uint(row[key]))
            if row["eligible"]:
                require(
                    all(
                        row[key] is not None
                        for key in (
                            "backendPid",
                            "connectionId",
                            "threadId",
                            "serverInstanceId",
                            "serverGeneration",
                            "leaseMs",
                        )
                    )
                    and row["leaseMs"] > 0
                )
            self.sequence, self.client_id = row["sequence"], row["clientId"]
            self.witness = row
            self.valid_until = min(
                issued + WITNESS_SECONDS, issued + (row["leaseMs"] or 0) / 1000
            )
            return dict(row)
        except (ValueError, TypeError):
            self.close()
            raise BridgeError("invalid witness") from None

    def start(self, request):
        validate_start(request)
        require(
            not self.closed
            and self.witness is not None
            and self.witness["eligible"]
            and time.monotonic() < self.valid_until
        )
        for key in (
            "clientId",
            "generation",
            "serverInstanceId",
            "serverGeneration",
            "threadId",
        ):
            require(request[key] == self.witness[key])
        for key, seen in (
            ("attemptId", self.attempts),
            ("clientUserMessageId", self.messages),
        ):
            require(request[key] not in seen)
        self._check_delivery(request)
        require(
            len(
                json.dumps(
                    {"nonce": self.nonce + 1, "start": request}, separators=(",", ":")
                ).encode()
            )
            + 1
            <= MAX_FRAME
        )
        self.attempts[request["attemptId"]] = deepcopy(request)
        self.deliveries[request["deliveryId"]] = request["attemptId"]
        self.messages.add(request["clientUserMessageId"])
        return self._receipt_exchange("start", request)

    def _check_delivery(self, request):
        previous = self.deliveries.get(request["deliveryId"])
        if previous is not None:
            require(previous in self.terminal_attempts)
            require(all(
                attempt["permitId"] != request["permitId"]
                for attempt in self.attempts.values()
                if attempt["deliveryId"] == request["deliveryId"]
            ))

    def restore_attempt(self, request):
        """Restore durable identity for read-only recovery, consuming start-once IDs."""
        validate_start(request)
        require(not self.closed)
        previous = self.attempts.get(request["attemptId"])
        if previous is not None:
            require(previous == request)
            return
        require(request["clientUserMessageId"] not in self.messages)
        self._check_delivery(request)
        self.attempts[request["attemptId"]] = deepcopy(request)
        self.deliveries[request["deliveryId"]] = request["attemptId"]
        self.messages.add(request["clientUserMessageId"])

    def receipt(self, request):
        """Read-only exact receipt recovery; never sends an event or renews a witness."""
        validate_start(request)
        require(not self.closed and request == self.attempts.get(request["attemptId"]))
        return self._receipt_exchange("receipt", request)

    def _receipt_exchange(self, operation, request):
        try:
            row = self.exchange({operation: request}, START_SECONDS)
            require(set(row) == {"version", "nonce", "receipt"})
            receipt = row["receipt"]
            identity = IDENTITY + (("generation",) if self.receipt_version == 3 else ())
            require(
                isinstance(receipt, dict)
                and set(receipt) == set(identity) | {"outcome"}
            )
            for key in identity:
                require(
                    type(receipt[key]) is type(request[key])
                    and receipt[key] == request[key]
                )
            outcome = receipt["outcome"]
            require(isinstance(outcome, dict))
            if outcome.get("status") == "started":
                require(
                    set(outcome) == {"status", "turnId", "replayed"}
                    and uuid(outcome["turnId"])
                    and outcome["turnId"] == request["clientUserMessageId"]
                    and type(outcome["replayed"]) is bool
                )
                require(operation == "start" or outcome["replayed"])
            elif outcome.get("status") == "inputRecorded":
                require(
                    operation == "receipt"
                    and set(outcome) == {"status", "turnId", "itemId", "replayed"}
                    and uuid(outcome["turnId"])
                    and outcome["turnId"] == request["clientUserMessageId"]
                    and uuid(outcome["itemId"])
                    and outcome["itemId"] != request["clientUserMessageId"]
                    and outcome["replayed"] is True
                )
            elif outcome.get("status") == "terminalNotStarted":
                require(
                    set(outcome) == {"status", "reason", "receiptId", "replayed"}
                    and isinstance(outcome["reason"], str)
                    and outcome["reason"] in TERMINAL_REASONS
                    and uuid(outcome["receiptId"])
                    and UUID(outcome["receiptId"]).version in (4, 7)
                    and type(outcome["replayed"]) is bool
                    and (operation == "start" or outcome["replayed"])
                )
            elif outcome.get("status") == "notStarted":
                require(
                    operation == "start"
                    and set(outcome) == {"status", "reason"}
                    and isinstance(outcome["reason"], str)
                    and outcome["reason"] in NOT_STARTED_REASONS
                )
            else:
                require(outcome == {"status": "unknown"})
            self.terminal_attempts.discard(request["attemptId"])
            if outcome["status"] == "terminalNotStarted":
                self.terminal_attempts.add(request["attemptId"])
            return dict(outcome)
        except (ValueError, TypeError, KeyError):
            self.close()
            return {"status": "unknown"}


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
        parent, child = socket.socketpair()
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        flags = [
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
        env = {
            "PATH": os.defpath,
            "HOME": str(root),
            "CODEX_HOME": str(home),
            "TERM": "xterm-256color",
            "CODEX_NATIVE_BRIDGE_FD": str(child.fileno()),
        }
        if receipt_version == 3:
            env["CODEX_NATIVE_BRIDGE_RECEIPT_VERSION"] = "3"
        process = None
        bridge = NativeBridge(parent, receipt_version=receipt_version)
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
            process = subprocess.Popen(
                [str(binary), *flags],
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
                if witness["eligible"]:
                    break
                require(process.poll() is None and time.monotonic() < deadline)
                time.sleep(0.1)
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
            stop.set()
            bridge.close()
            child.close()
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if drain_thread is not None:
                drain_thread.join(timeout=1)
            if slave is not None:
                os.close(slave)
            os.close(master)
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
