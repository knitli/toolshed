"""Private socket reader for an explicitly supplied native client; never launches one."""

# The caller owns client qualification and supplies a connected private AF_UNIX
# stream. Closing this reader closes that stream. Version 3 permits exact durable
# receipt recovery; recovery never grants selection or permission to start.

from copy import deepcopy
import json
import re
import socket
import threading
import time
from uuid import UUID

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
    # Wire integers must reject booleans and caller-defined integer subclasses.
    return type(value) is int and minimum <= value <= maximum  # pylint: disable=unidiomatic-typecheck


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
        """Own the supplied private stream in explicit v2 or durable v3 mode."""
        require(type(receipt_version) is int and receipt_version in (2, 3))  # pylint: disable=unidiomatic-typecheck
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
                and type(row.get("version")) is int  # pylint: disable=unidiomatic-typecheck
                and row["version"] == (self.receipt_version if "start" in body or "receipt" in body else 2)
                and type(row.get("nonce")) is int  # pylint: disable=unidiomatic-typecheck
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
                type(row["eligible"]) is bool  # pylint: disable=unidiomatic-typecheck
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
                    type(receipt[key]) is type(request[key])  # pylint: disable=unidiomatic-typecheck
                    and receipt[key] == request[key]
                )
            outcome = receipt["outcome"]
            require(isinstance(outcome, dict))
            if outcome.get("status") == "started":
                require(
                    set(outcome) == {"status", "turnId", "replayed"}
                    and uuid(outcome["turnId"])
                    and outcome["turnId"] == request["clientUserMessageId"]
                    and type(outcome["replayed"]) is bool  # pylint: disable=unidiomatic-typecheck
                )
                require(operation == "start" or outcome["replayed"])
            elif outcome.get("status") == "inputRecorded":
                require(
                    operation == "receipt"
                    and set(outcome) == {"status", "turnId", "itemId", "replayed"}
                    and isinstance(outcome["turnId"], str)
                    and EVENT_UUID.fullmatch(outcome["turnId"])
                    and outcome["turnId"] == request["clientUserMessageId"]
                    and isinstance(outcome["itemId"], str)
                    and EVENT_UUID.fullmatch(outcome["itemId"])
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
                    and type(outcome["replayed"]) is bool  # pylint: disable=unidiomatic-typecheck
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
