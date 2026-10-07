"""Socketpair causal checks; no native binary, account, model, or service access."""

import contextlib
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import runpy
import socket
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
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
        if thread.is_alive():
            raise AssertionError("peer must terminate")
        if errors:
            raise errors[0]


class NativeBridgeTests(unittest.TestCase):
    def test_input_recorded_closed_schema_and_readonly_operation(self):
        request = native.synthetic_request(witness())
        valid = {"status": "inputRecorded", "turnId": request["clientUserMessageId"],
                 "itemId": str(uuid4()), "replayed": True}
        cases = [(valid, "receipt", True), (valid, "start", False)]
        cases += [(dict(valid, **change), "receipt", False) for change in (
            {"turnId": str(uuid4())}, {"turnId": valid["turnId"].upper()},
            {"itemId": request["clientUserMessageId"]}, {"itemId": "bad"},
            {"itemId": valid["itemId"].upper()}, {"itemId": 1},
            {"replayed": 1}, {"replayed": False}, {"extra": True})]
        cases += [({k: v for k, v in valid.items() if k != field}, "receipt", False)
                  for field in valid]
        for outcome, operation, accepted in cases:
            with self.subTest(outcome=outcome, operation=operation):
                parent, child = socket.socketpair()
                client = native.NativeBridge(parent)
                try:
                    with patch.object(client, "exchange", return_value={
                        "version": 2, "nonce": 1, "receipt": {
                            **{key: request[key] for key in native.IDENTITY}, "outcome": outcome}}):
                        self.assertEqual(client._receipt_exchange(operation, request),
                                         outcome if accepted else {"status": "unknown"})
                    self.assertEqual(client.closed, not accepted)
                finally:
                    client.close()
                    child.close()

    def test_input_recorded_qualification_requires_stable_observation_without_restart(self):
        for fault in (None, "unknown", "terminalNotStarted", "started", "item_changed",
                      "extra_primary", "unknown_model", "extra_title", "eligible", "stopped"):
            with self.subTest(fault=fault):
                server = SimpleNamespace(release_primary=threading.Event(), model_requests=1,
                                         request_counts={"primary": 1, "title": 0, "unknown": 0})
                request, recorded, lookups = {}, {}, []
                clock = [0.0]

                def sleep(seconds):
                    clock[0] += seconds

                def start(value):
                    request.update(deepcopy(value))
                    recorded.update(status="inputRecorded", turnId=value["clientUserMessageId"],
                                    itemId=str(uuid4()), replayed=True)
                    return {"status": "started", "turnId": value["clientUserMessageId"],
                            "replayed": False}

                def receipt(value):
                    self.assertEqual(value, request)
                    self.assertFalse(server.release_primary.is_set())
                    lookups.append(deepcopy(value))
                    if fault in ("unknown", "terminalNotStarted", "started"):
                        return {"status": fault}
                    if len(lookups) > 1:
                        self.assertGreater(clock[0] * 1000, request["permitExpiresAt"])
                        if fault == "item_changed":
                            return dict(recorded, itemId=str(uuid4()))
                    return dict(recorded)

                if fault in ("extra_primary", "unknown_model", "extra_title"):
                    server.request_counts[{"extra_primary": "primary", "unknown_model": "unknown",
                                           "extra_title": "title"}[fault]] += 2
                    server.model_requests += 2
                bridge = SimpleNamespace(start=Mock(side_effect=start), receipt=Mock(side_effect=receipt),
                                         challenge=Mock(return_value={"eligible": fault == "eligible"}))
                process = Mock(poll=lambda: 1 if fault == "stopped" else None)
                with patch.object(native.time, "sleep", side_effect=sleep), \
                     patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), \
                     patch.object(native.time, "time_ns", side_effect=lambda: int(clock[0] * 1e9)):
                    if fault:
                        with self.assertRaises(native.BridgeError):
                            native.qualify_input_recorded(bridge, server, process, witness())
                    else:
                        result = native.qualify_input_recorded(bridge, server, process, witness())
                        self.assertEqual(result["outcome"], "inputRecorded")
                        self.assertEqual(result["itemId"], recorded["itemId"])
                        self.assertEqual(result["primaryModelRequests"], 1)
                        self.assertEqual(result["realModelCalls"], 0)
                        self.assertEqual(lookups, [request] * 3)
                        bridge.challenge.assert_called_once_with()
                bridge.start.assert_called_once()
                self.assertTrue(server.release_primary.is_set())
                self.assertLessEqual(clock[0], 10.1)

    def test_terminal_retry_qualification_preserves_delivery_and_exact_receipts(self):
        initial = witness()
        renewed = dict(initial, generation=3, sequence=2)
        server = SimpleNamespace(release_primary=threading.Event(), model_requests=0,
                                 request_counts={'primary': 0, 'title': 0, 'unknown': 0})
        requests, lookups, outcomes = [], [], {}

        def start(request):
            requests.append(deepcopy(request))
            if len(requests) == 1:
                self.assertLessEqual(request['permitExpiresAt'], time.time_ns() // 1_000_000,
                                     'the first attempt must use an already expired permit')
            if request['permitExpiresAt'] <= time.time_ns() // 1_000_000:
                self.assertEqual(request['permitExpiresAt'] - request['permitIssuedAt'], 5000)
                self.assertEqual(server.model_requests, 0)
                self.assertFalse(server.release_primary.is_set())
                outcome = {'status': 'terminalNotStarted', 'reason': 'permitExpired',
                           'receiptId': str(uuid4()), 'replayed': False}
            else:
                server.request_counts['primary'] += 1
                server.model_requests += 1
                outcome = {'status': 'started', 'turnId': request['clientUserMessageId'],
                           'replayed': False}
            outcomes[request['attemptId']] = outcome
            return outcome

        def receipt(request):
            if not lookups:
                self.assertEqual(server.request_counts['primary'], 1)
                self.assertFalse(server.release_primary.is_set())
            lookups.append(deepcopy(request))
            self.assertIn(request, requests)
            return {**outcomes[request['attemptId']], 'replayed': True}

        def challenge():
            self.assertEqual(server.release_primary.is_set(), len(requests) == 2)
            return renewed

        bridge = SimpleNamespace(start=start, receipt=receipt, challenge=Mock(side_effect=challenge))
        with patch.object(native.time, 'sleep'):
            result = native.qualify_terminal_retry(bridge, server, Mock(poll=lambda: None), initial)
        self.assertEqual(len(requests), 3)
        rejected, first, retry = requests
        self.assertNotEqual(first['deliveryId'], rejected['deliveryId'])
        self.assertEqual(first['generation'], renewed['generation'])
        self.assertEqual(retry['generation'], renewed['generation'])
        self.assertEqual(retry['deliveryId'], rejected['deliveryId'])
        self.assertEqual(retry['event'], rejected['event'])
        for field in ('attemptId', 'permitId', 'clientUserMessageId'):
            self.assertEqual(len({request[field] for request in requests}), 3)
        self.assertEqual(lookups, [rejected, first, retry, rejected])
        self.assertEqual(bridge.challenge.call_count, 2)
        self.assertEqual(result['qualification'], 'synthetic-native-terminal-retry')
        self.assertTrue(result['nativeOnly'])
        self.assertFalse(result['cloudSettlementProven'])
        self.assertFalse(result['busyRefusalProven'])
        self.assertTrue(result['retainedTerminalRecoveredWhileBusy'])
        self.assertEqual(result['primaryModelRequests'], 2)
        self.assertEqual(result['unknownModelRequests'], 0)
        self.assertTrue(result['exactTerminalReceiptRecovered'])
        self.assertTrue(result['exactReceiptRecovered'])

    def test_terminal_retry_refuses_uncertain_proof_and_releases_held_primary(self):
        for fault in ('unknown', 'notStarted', 'wrong_reason', 'wrong_receipt', 'start_error'):
            with self.subTest(fault=fault):
                terminal = {'status': 'terminalNotStarted', 'reason': 'permitExpired',
                            'receiptId': str(uuid4()), 'replayed': False}
                if fault in ('unknown', 'notStarted'):
                    terminal['status'] = fault
                elif fault == 'wrong_reason':
                    terminal['reason'] = 'busy'
                server = SimpleNamespace(release_primary=threading.Event(), model_requests=0,
                                         request_counts={'primary': 0, 'title': 0, 'unknown': 0})

                def start(request):
                    if request['permitExpiresAt'] <= time.time_ns() // 1_000_000:
                        return terminal
                    if fault == 'start_error':
                        raise native.BridgeError()
                    server.request_counts['primary'] += 1
                    server.model_requests += 1
                    return {'status': 'started', 'turnId': request['clientUserMessageId'],
                            'replayed': False}
                recovered = {**terminal, 'replayed': True}
                if fault == 'wrong_receipt':
                    recovered['receiptId'] = str(uuid4())
                bridge = SimpleNamespace(start=Mock(side_effect=start),
                                         receipt=Mock(return_value=recovered),
                                         challenge=Mock(return_value=witness()))
                with self.assertRaises(native.BridgeError), patch.object(native.time, 'sleep'):
                    native.qualify_terminal_retry(bridge, server, Mock(poll=lambda: None), witness())
                self.assertTrue(server.release_primary.is_set())
                expected_starts = 2 if fault in ('wrong_receipt', 'start_error') else 1
                self.assertEqual(bridge.start.call_count, expected_starts)
                self.assertEqual(bridge.challenge.call_count, expected_starts - 1)

    def test_mock_primary_hold_precedes_response_and_times_out_closed(self):
        body = b'{"model":"mock-model","input":[]}'
        for released in (True, False):
            with self.subTest(released=released):
                calls = []
                release = Mock(wait=lambda timeout: calls.append(('wait', timeout)) or released)
                server = SimpleNamespace(release_primary=release, model_requests=0,
                                         request_counts={'primary': 0, 'title': 0, 'unknown': 0})
                handler = SimpleNamespace(
                    path='/responses', headers={'Content-Length': str(len(body))},
                    rfile=io.BytesIO(body), wfile=io.BytesIO(), server=server,
                    send_response=lambda status: calls.append(('response', status)),
                    send_error=lambda status: calls.append(('error', status)),
                    send_header=Mock(), end_headers=Mock())
                native.MockModel.do_POST(handler)
                self.assertEqual(calls, [('wait', 30), ('response', 200) if released else ('error', 504)])
                if released:
                    self.assertIn(b'response.completed', handler.wfile.getvalue())
                    handler.rfile = io.BytesIO(body)
                    native.MockModel.do_POST(handler)
                    self.assertEqual(calls, [('wait', 30), ('response', 200), ('response', 200)])
                else:
                    self.assertEqual(handler.wfile.getvalue(), b'')
                    handler.end_headers.assert_not_called()

    def test_terminal_receipt_schema_identity_and_recovery(self):
        request = native.synthetic_request(witness())
        valid = {"status": "terminalNotStarted", "reason": "busy",
                 "receiptId": str(uuid4()), "replayed": True}
        cases = [(dict(valid, reason=reason), None, True) for reason in
                 "busy serverDraining selectionExpired selectionChanged permitExpired connectionClosed threadUnavailable inputInvalid".split()]
        cases.append((dict(valid, receiptId="00000000-0000-7000-8000-000000000000"), None, True))
        cases += [(dict(valid, **change), None, False) for change in (
            {"reason": "permitInvalid"}, {"reason": "duplicateConflict"},
            {"reason": "receiptCapacity"}, {"receiptId": "bad"},
            {"receiptId": "00000000-0000-1000-8000-000000000000"},
            {"receiptId": "00000000-0000-5000-8000-000000000000"},
            {"replayed": 1}, {"replayed": False}, {"extra": True})]
        cases += [({key: value for key, value in valid.items() if key != field}, None, False)
                  for field in valid]
        cases += [(valid, key, False) for key in native.IDENTITY]
        for outcome, mismatch, accepted in cases:
            with self.subTest(outcome=outcome, mismatch=mismatch):
                parent, child = socket.socketpair()
                client = native.NativeBridge(parent)
                try:
                    client.restore_attempt(request)
                    receipt = {key: request[key] for key in native.IDENTITY}
                    if mismatch:
                        receipt[mismatch] = None
                    with patch.object(
                        client, "exchange", return_value={
                            "version": 2, "nonce": 1,
                            "receipt": {**receipt, "outcome": outcome},
                        },
                    ):
                        self.assertEqual(client.receipt(request), outcome if accepted else {"status": "unknown"})
                    self.assertEqual(client.closed, not accepted)
                finally:
                    client.close()
                    child.close()

    def test_restore_is_readonly_exact_and_consumes_start_once(self):
        binding = witness()
        request = native.synthetic_request(binding)

        def handler(channel):
            row = receive(channel)
            self.assertEqual(row, {"nonce": 1, "receipt": request})
            send(channel, {"version": 2, "nonce": 1, "receipt": {
                **{key: request[key] for key in native.IDENTITY},
                "outcome": {"status": "unknown"}}})
            self.assertIsNone(receive(channel))
        with peer(handler) as client:
            client.restore_attempt(request)
            client.restore_attempt(deepcopy(request))
            changed = deepcopy(request)
            changed["event"]["sourceStateVersion"] = "changed"
            with self.assertRaises(native.BridgeError):
                client.restore_attempt(changed)
            request["event"]["sourceStateVersion"] = "changed"
            self.assertNotEqual(client.attempts[request["attemptId"]], request)
            request["event"]["sourceStateVersion"] = "qualification-1"
            self.assertEqual(client.receipt(request), {"status": "unknown"})
            client.witness, client.valid_until = binding, time.monotonic() + 1
            with self.assertRaises(native.BridgeError):
                client.start(request)
            for reused in ("deliveryId", "clientUserMessageId"):
                candidate = native.synthetic_request(binding)
                candidate[reused] = request[reused]
                with self.assertRaises(native.BridgeError):
                    client.restore_attempt(candidate)

    def test_delivery_retry_requires_terminal_proof_and_distinct_permit(self):
        binding = witness()
        for status in ("unknown", "started", "terminalNotStarted"):
            with self.subTest(status=status):
                parent, child = socket.socketpair()
                client = native.NativeBridge(parent)
                try:
                    client.witness, client.valid_until = binding, time.monotonic() + 1
                    request = native.synthetic_request(binding)
                    outcome = {"status": status}
                    if status == "started":
                        outcome.update(turnId=request["clientUserMessageId"], replayed=False)
                    elif status == "terminalNotStarted":
                        outcome.update(reason="busy", receiptId=str(uuid4()), replayed=False)
                    with patch.object(client, "exchange", return_value={
                        "version": 2, "nonce": 1, "receipt": {
                            **{key: request[key] for key in native.IDENTITY}, "outcome": outcome}}):
                        self.assertEqual(client.start(request), outcome)
                    candidate = native.synthetic_request(binding)
                    candidate["deliveryId"] = request["deliveryId"]
                    with patch.object(client, "_receipt_exchange", return_value={"status": "unknown"}) as exchange:
                        if status == "terminalNotStarted":
                            fresh_permit = candidate["permitId"]
                            candidate["permitId"] = request["permitId"]
                            with self.assertRaises(native.BridgeError):
                                client.start(candidate)
                            exchange.assert_not_called()
                            candidate["permitId"] = fresh_permit
                            self.assertEqual(client.start(candidate), {"status": "unknown"})
                            self.assertEqual(exchange.call_count, 1)
                            third = native.synthetic_request(binding)
                            third["deliveryId"] = request["deliveryId"]
                            with self.assertRaises(native.BridgeError):
                                client.start(third)
                        else:
                            with self.assertRaises(native.BridgeError):
                                client.start(candidate)
                            exchange.assert_not_called()
                finally:
                    client.close()
                    child.close()

    def test_helper_probe_rejects_unrecognized_binary_before_launch(self):
        probe = Path(__file__).parents[1] / "scripts" / "probe_native_helper_lifecycle.py"
        for args in ([], [sys.executable]):
            with self.subTest(args=args), patch("sys.argv", [str(probe), *args]):
                with patch(
                    "subprocess.Popen",
                    side_effect=AssertionError("unrecognized binary reached launch"),
                ) as launch:
                    with self.assertRaises(ValueError):
                        runpy.run_path(str(probe))
                    launch.assert_not_called()

    def test_exact_start_receipt_and_no_replay(self):
        for outcome, reason in (
            ("started", None),
            ("notStarted", "busy"),
            ("notStarted", "connectionClosed"),
            ("unknown", None),
        ):
            with self.subTest(outcome=outcome, reason=reason):
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
                        result["reason"] = reason
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
                    response = client.start(request)
                    self.assertEqual(response["status"], outcome)
                    if reason is not None:
                        self.assertEqual(response, {"status": outcome, "reason": reason})
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

                def invalid_witness_peer(channel):
                    receive(channel)
                    send(channel, witness(**changes))
                    self.assertIsNone(receive(channel))

                with peer(invalid_witness_peer) as client:
                    if changes == {"eligible": False}:
                        request = native.synthetic_request(client.challenge())
                        with self.assertRaises(native.BridgeError):
                            client.start(request)
                    else:
                        with self.assertRaises(native.BridgeError):
                            client.challenge()

        def expired_witness_peer(channel):
            receive(channel)
            send(channel, witness())
            self.assertIsNone(receive(channel))

        with peer(expired_witness_peer) as client:
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
