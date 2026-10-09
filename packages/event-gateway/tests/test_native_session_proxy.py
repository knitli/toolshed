"""Real private-socket routing through the launcher-owned native reader."""

import asyncio
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, call, patch
from uuid import uuid4

from event_gateway import launcher
from event_gateway.native import NativeBridgeAdapter, NativeError, SessionNativeBridge
from test_native_bridge import native, peer, receive, send, witness


@contextmanager
def session_fixture(row):
    calls = []
    current = dict(row)
    recorded = {}
    item_ids = {}

    def handle(channel):
        sequence = 0
        while (message := receive(channel)) is not None:
            sequence += 1
            operation = next((key for key in ("start", "receipt") if key in message), "challenge")
            calls.append(operation)
            if operation == "challenge":
                send(channel, {**current, "nonce": message["nonce"], "sequence": sequence})
                continue
            request = message[operation]
            if operation == "start":
                recorded[request["attemptId"]] = deepcopy(request)
                item_ids[request["attemptId"]] = str(uuid4())
                outcome = {"status": "started", "turnId": request["clientUserMessageId"], "replayed": False}
            elif recorded.get(request["attemptId"]) == request:
                outcome = {"status": "inputRecorded", "turnId": request["clientUserMessageId"],
                           "itemId": item_ids[request["attemptId"]], "replayed": True}
            else:
                outcome = {"status": "unknown"}
            send(channel, {"version": 3, "nonce": message["nonce"], "receipt": {
                **{key: request[key] for key in (*native.IDENTITY, "generation")}, "outcome": outcome,
            }})

    with peer(handle, receipt_version=3) as bridge:
        client = launcher.NativeClient(bridge)
        client.ready = True
        with tempfile.TemporaryDirectory(prefix="nsp-", dir=Path("/tmp").resolve()) as directory:  # nosec B108 - Random 0700 child; short AF_UNIX path.
            state = Path(directory)
            state.chmod(0o700)
            session = str(uuid4())
            path = launcher.session_path(state, session)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(8)
            listener.settimeout(0.05)
            stop = threading.Event()
            thread = threading.Thread(target=launcher._control, args=(listener, client, stop))
            thread.start()
            mapping = {"sessionId": session, "nativeThreadId": row["threadId"],
                       "nativeBinding": launcher._binding(row)}
            try:
                yield state, mapping, client, current, calls
            finally:
                stop.set()
                listener.close()
                thread.join(3)
                if thread.is_alive():
                    raise AssertionError("control thread must terminate")


class NativeSessionProxyTests(unittest.TestCase):
    def test_intervening_readonly_status_rechecks_start_and_recovery_survives_daemon_restart(self):
        row = witness()
        with session_fixture(row) as (state, mapping, _client, current, calls):
            adapter = NativeBridgeAdapter(mapping, SessionNativeBridge(state, mapping))
            self.assertEqual(asyncio.run(adapter.check()), "available")
            self.assertEqual(launcher.session_status(state, mapping["sessionId"])["selection"], "selected")
            request = {**native.synthetic_request(row), "receiptVersion": 3}
            # The launcher has committed the Start; only its client-facing reply is lost.
            original = launcher._session_request

            def lost_reply(*args, **kwargs):
                original(*args, **kwargs)
                raise OSError("lost proxy reply")

            with patch.object(launcher, "_session_request", side_effect=lost_reply), self.assertRaises(NativeError):
                asyncio.run(adapter.submit(request))
            self.assertEqual(calls.count("start"), 1)
            current.update(eligible=False, threadId=str(uuid4()), generation=row["generation"] + 1)
            restarted = NativeBridgeAdapter(mapping, SessionNativeBridge(state, mapping))
            recovered = asyncio.run(restarted.reconcile(request))
            self.assertEqual(recovered["outcome"]["status"], "inputRecorded")
            self.assertEqual(recovered["generation"], request["generation"])
            self.assertEqual(asyncio.run(restarted.reconcile(request)), recovered)
            self.assertEqual(calls.count("start"), 1)
            self.assertEqual(calls[-1], "receipt")
            current.update(row)
            with self.assertRaises(NativeError):
                asyncio.run(restarted.submit(request))
            self.assertEqual(calls.count("start"), 1)

    def test_changed_complete_binding_cannot_start(self):
        for field in launcher.BINDING_FIELDS:
            row = witness()
            with self.subTest(field=field), session_fixture(row) as (state, mapping, _client, current, calls):
                proxy = SessionNativeBridge(state, mapping)
                proxy.challenge()
                current[field] = current[field] + 1 if isinstance(current[field], int) else str(uuid4())
                if field == "clientId":
                    with self.assertRaises(NativeError):
                        proxy.start(native.synthetic_request(row))
                else:
                    outcome = proxy.start(native.synthetic_request(row))
                    self.assertEqual(outcome, {"status": "notStarted", "reason": "selectionChanged"})
                self.assertNotIn("start", calls)

    def test_proxy_rejects_mismatched_echo_and_incomplete_routes(self):
        row = witness()
        mapping = {"sessionId": str(uuid4()), "nativeThreadId": row["threadId"],
                   "nativeBinding": launcher._binding(row)}
        for key in mapping:
            with self.subTest(key=key), self.assertRaises(NativeError):
                SessionNativeBridge("unused", {k: v for k, v in mapping.items() if k != key})
        proxy = SessionNativeBridge("unused", mapping)
        request = native.synthetic_request(row)
        reply = {**{key: request[key] for key in (*native.IDENTITY, "generation")},
                 "outcome": {"status": "unknown"}}
        for key in (*native.IDENTITY, "generation"):
            with self.subTest(key=key), patch.object(launcher, "session_native_operation", return_value={**reply, key: None}):
                with self.assertRaises(NativeError):
                    proxy.receipt(request)
        bad = {**request, "generation": request["generation"] + 1}
        with patch.object(launcher, "session_native_operation") as send_operation, self.assertRaises(NativeError):
            proxy.start(bad)
        send_operation.assert_not_called()

    def test_native_frames_fail_closed_and_preserve_status_limit(self):
        row = witness()
        with session_fixture(row) as (state, mapping, _client, _current, calls):
            body = json.dumps(native.synthetic_request(row), separators=(",", ":")).encode() + b"\n"
            header = {"command": "nativeStart", "expectedBinding": mapping["nativeBinding"],
                      "deadlineMonotonic": time.monotonic() + 5}
            encoded = json.dumps(header, separators=(",", ":")).encode() + b"\n"
            malformed = [
                encoded + body.replace(b'"generation":2', b'"generation":2,"generation":2'),
                encoded + b"x" * 4096,
                encoded + body + b"{}\n",
                encoded + b"[" * 1500 + b"]" * 1500 + b"\n",
                b'{"command":[]}\n',
                json.dumps({**header, "deadlineMonotonic": 0}).encode() + b"\n" + body,
                json.dumps({**header, "deadlineMonotonic": True}).encode() + b"\n" + body,
                b'{"command":"status","padding":"' + b"x" * 1100 + b'"}\n',
            ]
            for payload in malformed:
                with self.subTest(payload=payload[:80]), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                    channel.settimeout(2)
                    channel.connect(str(launcher.session_path(state, mapping["sessionId"])))
                    channel.sendall(payload)
                    try:
                        channel.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass  # The server can reject an oversized header before the write half closes.
                    try:
                        response = channel.recv(4096)
                    except ConnectionResetError:
                        response = b""
                    if response:
                        self.assertIn("reason", json.loads(response))
            self.assertNotIn("start", calls)
            self.assertEqual(launcher.session_status(state, mapping["sessionId"])["selection"], "selected")

    def test_full_binding_is_checked_even_with_injected_bridge(self):
        row = witness()
        mapping = {"sessionId": str(uuid4()), "nativeThreadId": row["threadId"],
                   "nativeBinding": launcher._binding(row)}

        class Bridge:
            receipt_version = 3

            def challenge(self):
                return row

        adapter = NativeBridgeAdapter(mapping, Bridge())
        self.assertEqual(asyncio.run(adapter.check()), "available")
        for field in ("connectionId", "backendPid", "generation"):
            original = row[field]
            row[field] = original + 1 if isinstance(original, int) else str(uuid4())
            with self.subTest(field=field):
                self.assertEqual(asyncio.run(adapter.check()), "unavailable")
            row[field] = original

    def test_native_frame_drip_keeps_absolute_deadline(self):
        row = witness()
        header = {"command": "nativeStart", "expectedBinding": launcher._binding(row),
                  "deadlineMonotonic": 1}
        channel = Mock()
        channel.recv.return_value = b"{"
        client = Mock()
        with patch.object(launcher.time, "monotonic", side_effect=[0.2, 0.6, 1.2]):
            with self.assertRaises(TimeoutError):
                launcher._native_control(channel, client, header, b"", 0)
        self.assertEqual(channel.recv.call_count, 2)
        self.assertEqual(channel.settimeout.call_args_list, [call(0.8), call(0.4)])
        client.native_operation.assert_not_called()

    def test_native_start_and_receipt_hold_client_lock_for_entire_sequence(self):
        row = witness()
        request = native.synthetic_request(row)
        bridge = Mock(receipt_version=3, valid_until=float("inf"))
        client = launcher.NativeClient(bridge)
        client.ready = True
        seen = []

        def locked(name, result):
            def run(*_):
                self.assertFalse(client.lock.acquire(blocking=False))
                seen.append(name)
                return result
            return run

        bridge.challenge.side_effect = locked("challenge", row)
        bridge.start.side_effect = locked("start", {"status": "unknown"})
        bridge.restore_attempt.side_effect = locked("restore", None)
        bridge.receipt.side_effect = locked("receipt", {"status": "unknown"})
        for command in ("nativeStart", "nativeReceipt"):
            client.native_operation(command, launcher._binding(row), request, time.monotonic() + 1)
        self.assertEqual(seen, ["challenge", "start", "restore", "receipt"])
        self.assertFalse(client.lock.locked())


if __name__ == "__main__":
    unittest.main()
