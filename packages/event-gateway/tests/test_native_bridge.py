"""Socketpair causal checks; no native binary, account, model, or service access."""

import contextlib
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import socket
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

path = Path(__file__).parents[1] / "scripts" / "qualify_native_bridge.py"
spec = importlib.util.spec_from_file_location("qualify_native_bridge", path)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def witness(nonce=1, **changes):
    return {
        "version": 2,
        "nonce": nonce,
        "clientId": str(uuid4()),
        "backendPid": 123,
        "connectionId": str(uuid4()),
        "threadId": str(uuid4()),
        "generation": 2,
        "eligible": True,
        "sequence": 1,
        "cause": "heartbeat",
        "serverInstanceId": str(uuid4()),
        "serverGeneration": 1,
        "leaseMs": 750,
        **changes,
    }


def send(channel, row):
    channel.sendall(json.dumps(row, separators=(",", ":")).encode() + b"\n")


def receive(channel):
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = channel.recv(1)
        if not chunk:
            return None
        data.extend(chunk)
    return json.loads(data)


@contextlib.contextmanager
def peer(handler):
    parent, child = socket.socketpair()
    child.settimeout(2)
    errors = []

    def run():
        try:
            handler(child)
        except BaseException as error:
            errors.append(error)
        finally:
            child.close()

    thread = threading.Thread(target=run)
    thread.start()
    client = native.NativeBridge(parent)
    try:
        yield client
    finally:
        client.close()
        thread.join(3)
        assert not thread.is_alive(), "peer must terminate"
        if errors:
            raise errors[0]


class NativeBridgeTests(unittest.TestCase):
    def test_exact_start_receipt_and_no_replay(self):
        for outcome in ("started", "notStarted", "unknown"):
            with self.subTest(outcome=outcome):
                requests = []

                def handler(channel):
                    challenge = receive(channel)
                    self.assertEqual(challenge, {"nonce": 1})
                    binding = witness()
                    send(channel, binding)
                    row = receive(channel)
                    if row is None:
                        return
                    requests.append(row)
                    request = row["start"]
                    result = {"status": outcome}
                    if outcome == "started":
                        result.update(
                            turnId=request["clientUserMessageId"], replayed=False
                        )
                    elif outcome == "notStarted":
                        result["reason"] = "busy"
                    send(
                        channel,
                        {
                            "version": 2,
                            "nonce": row["nonce"],
                            "receipt": {
                                **{key: request[key] for key in native.IDENTITY},
                                "outcome": result,
                            },
                        },
                    )
                    lookup = receive(channel)
                    if lookup is None:
                        return
                    self.assertEqual(lookup, {"nonce": 3, "receipt": request})
                    send(
                        channel,
                        {
                            "version": 2,
                            "nonce": 3,
                            "receipt": {
                                **{key: request[key] for key in native.IDENTITY},
                                "outcome": (
                                    {"status": "unknown"}
                                    if outcome == "notStarted"
                                    else {
                                        "status": "started",
                                        "turnId": request["clientUserMessageId"],
                                        "replayed": True,
                                    }
                                ),
                            },
                        },
                    )
                    self.assertEqual(receive(channel), {"nonce": 4})
                    send(channel, {**binding, "nonce": 4, "sequence": 2})
                    self.assertIsNone(
                        receive(channel), "a completed attempt must not be resent"
                    )

                with peer(handler) as client:
                    request = native.synthetic_request(client.challenge())
                    with patch.object(
                        client, "_receipt_exchange", return_value={"status": "unknown"}
                    ) as exchange:
                        with self.assertRaises(native.BridgeError):
                            client.receipt(request)
                        exchange.assert_not_called()
                    self.assertEqual(client.start(request)["status"], outcome)
                    original = deepcopy(request)
                    for container, key, value in (
                        (request, "generation", request["generation"] + 1),
                        (request, "attemptId", str(uuid4())),
                        (request, "permitId", "another-permit"),
                        (request["event"], "sourceStateVersion", "changed"),
                        (request["event"]["canonicalSubject"], "subjectId", "changed"),
                    ):
                        previous = container[key]
                        container[key] = value
                        with self.subTest(receipt_field=key):
                            with patch.object(
                                client,
                                "_receipt_exchange",
                                return_value={"status": "unknown"},
                            ) as exchange:
                                with self.assertRaises(native.BridgeError):
                                    client.receipt(request)
                                exchange.assert_not_called()
                        container[key] = previous
                    self.assertEqual(request, original)
                    client.valid_until = (
                        0  # Read-only lookup works after witness expiry.
                    )
                    self.assertEqual(
                        client.receipt(request),
                        (
                            {"status": "unknown"}
                            if outcome == "notStarted"
                            else {
                                "status": "started",
                                "turnId": request["clientUserMessageId"],
                                "replayed": True,
                            }
                        ),
                    )
                    renewed = client.challenge()
                    self.assertTrue(renewed["eligible"])
                    self.assertGreater(client.valid_until, time.monotonic())
                    with self.assertRaises(native.BridgeError):
                        client.start(request)
                    # Isolate each retained identity: the other two are fresh.
                    for reused in ("attemptId", "deliveryId", "clientUserMessageId"):
                        candidate = native.synthetic_request(renewed)
                        candidate[reused] = request[reused]
                        with (
                            self.subTest(reused=reused),
                            self.assertRaises(native.BridgeError),
                        ):
                            client.start(candidate)
                self.assertEqual(len(requests), 1)
                self.assertEqual(set(requests[0]), {"nonce", "start"})
                self.assertNotIn("input", requests[0]["start"])

    def test_lost_mismatched_malformed_late_receipt_stays_unknown(self):
        for fault in (
            "eof",
            "identity",
            "nonce",
            "duplicate",
            "oversize",
            "deadline",
            "deep",
            "readonly-replayed-false",
        ):
            with self.subTest(fault=fault):
                requests = []

                def handler(channel):
                    receive(channel)
                    send(channel, witness())
                    row = receive(channel)
                    requests.append(row)
                    request = row["start"]
                    reply = {
                        "version": 2,
                        "nonce": row["nonce"],
                        "receipt": {
                            **{key: request[key] for key in native.IDENTITY},
                            "outcome": {
                                "status": "started",
                                "turnId": request["clientUserMessageId"],
                                "replayed": False,
                            },
                        },
                    }
                    if fault == "readonly-replayed-false":
                        send(
                            channel,
                            {
                                **reply,
                                "receipt": {
                                    **reply["receipt"],
                                    "outcome": {"status": "unknown"},
                                },
                            },
                        )
                        self.assertEqual(
                            receive(channel), {"nonce": 3, "receipt": request}
                        )
                        reply["nonce"] = 3
                    if fault == "eof":
                        return
                    if fault == "identity":
                        reply["receipt"]["attemptId"] = str(uuid4())
                    if fault == "nonce":
                        reply["nonce"] += 1
                    if fault == "duplicate":
                        channel.sendall(b'{"version":2,"version":2}\n')
                    elif fault == "deep":
                        channel.sendall(b"[" * 1500 + b"]" * 1500 + b"\n")
                    elif fault == "oversize":
                        channel.sendall(b"x" * 4096)
                    elif fault == "deadline":
                        time.sleep(0.05)
                    else:
                        send(channel, reply)
                    try:
                        self.assertIsNone(receive(channel))
                    except ConnectionResetError:
                        pass

                with (
                    peer(handler) as client,
                    patch.object(native, "START_SECONDS", 0.025),
                ):
                    request = native.synthetic_request(client.challenge())
                    self.assertEqual(client.start(request), {"status": "unknown"})
                    if fault == "readonly-replayed-false":
                        self.assertEqual(client.receipt(request), {"status": "unknown"})
                    self.assertTrue(client.closed)
                    with self.assertRaises(native.BridgeError):
                        client.start(request)
                self.assertEqual(len(requests), 1)

    def test_unfresh_or_unbound_witness_never_writes_start(self):
        for changes in (
            {"eligible": False},
            {"nonce": 2},
            {"version": 1},
            {"serverGeneration": True},
            {"serverInstanceId": None},
            {"sequence": 0},
            {"prompt": "forbidden"},
        ):
            with self.subTest(changes=changes):

                def handler(channel):
                    receive(channel)
                    send(channel, witness(**changes))
                    self.assertIsNone(receive(channel))

                with peer(handler) as client:
                    if changes == {"eligible": False}:
                        request = native.synthetic_request(client.challenge())
                        with self.assertRaises(native.BridgeError):
                            client.start(request)
                    else:
                        with self.assertRaises(native.BridgeError):
                            client.challenge()

        def handler(channel):
            receive(channel)
            send(channel, witness())
            self.assertIsNone(receive(channel))

        with peer(handler) as client:
            request = native.synthetic_request(client.challenge())
            client.valid_until = time.monotonic() - 0.01
            with self.assertRaises(native.BridgeError):
                client.start(request)

    def test_arbitrary_input_invalid_event_and_binding_mismatch_are_local_refusals(
        self,
    ):
        def handler(channel):
            receive(channel)
            send(channel, witness())
            self.assertIsNone(receive(channel))

        with peer(handler) as client:
            request = native.synthetic_request(client.challenge())
            for key, value in [
                ("input", "forbidden"),
                ("generation", 999),
                ("serverInstanceId", str(uuid4())),
                ("permitIssuedAt", True),
                ("deliveryId", "not-a-delivery"),
                ("permitExpiresAt", request["permitIssuedAt"] + 4999),
            ]:
                with self.subTest(key=key), self.assertRaises(native.BridgeError):
                    client.start({**request, key: value})
            with self.assertRaises(native.BridgeError):
                client.start(
                    {**request, "event": {**request["event"], "source": "github"}}
                )
            self.assertEqual(client.attempts, {})

    def test_fragmented_frame_and_absolute_witness_deadline(self):
        warmup = witness()

        def startup(channel):
            self.assertEqual(receive(channel), {"nonce": 1})
            time.sleep(0.025)
            send(channel, warmup)
            self.assertEqual(receive(channel), {"nonce": 2})
            send(channel, {**warmup, "nonce": 2, "sequence": 2})
            self.assertIsNone(receive(channel))

        with peer(startup) as client, patch.object(native, "WITNESS_SECONDS", 0.01):
            client.exchange(
                {}, 0.5
            )  # Older than freshness; startup synchronization only.
            self.assertIsNone(client.witness)
            self.assertIsNone(client.client_id)
            self.assertEqual(client.valid_until, 0)
            with self.assertRaises(native.BridgeError):
                client.start(native.synthetic_request(warmup))
            self.assertTrue(client.challenge()["eligible"])

        row = witness()

        def handler(channel):
            receive(channel)
            data = json.dumps(row).encode() + b"\n"
            channel.sendall(data[:7])
            time.sleep(0.01)
            channel.sendall(data[7:])
            self.assertIsNone(receive(channel))

        before = time.monotonic()
        with peer(handler) as client:
            self.assertEqual(client.challenge(), row)
            self.assertLessEqual(client.valid_until, before + 0.8)

    def test_loopback_mock_returns_synthetic_sse(self):
        import http.client

        server = native.ThreadingHTTPServer(("127.0.0.1", 0), native.MockModel)
        server.model_requests = 0
        server.request_counts = {"primary": 0, "title": 0, "unknown": 0}
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=2
            )
            connection.request(
                "POST", "/responses", body=b'{"model":"mock-model","input":[]}'
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn(b"response.completed", response.read())
            self.assertEqual(server.model_requests, 1)
            self.assertEqual(
                server.request_counts, {"primary": 1, "title": 0, "unknown": 0}
            )
            title = {
                "model": "mock-model",
                "input": [],
                "text": {
                    "format": {
                        "type": "json_schema",
                        "strict": True,
                        "name": "codex_output_schema",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "title": {
                                    "type": "string",
                                    "minLength": 1,
                                    "maxLength": 36,
                                }
                            },
                            "required": ["title"],
                            "additionalProperties": False,
                        },
                    }
                },
            }
            connection.request("POST", "/responses", body=json.dumps(title))
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn(b"Qualify native bridge", response.read())
            title["text"]["format"]["schema"]["additionalProperties"] = True
            connection.request("POST", "/responses", body=json.dumps(title))
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
            self.assertEqual(
                server.request_counts, {"primary": 1, "title": 1, "unknown": 1}
            )
            self.assertEqual(server.model_requests, 3)
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


if __name__ == "__main__":
    unittest.main()
