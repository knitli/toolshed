"""Explicit launch, local binding challenges, and read-only presence checks."""

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import signal
import socket
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, Mock, call, patch
from uuid import uuid4

from event_gateway import launcher
from test_native_bridge import peer, receive, send, witness


class LauncherTests(unittest.TestCase):
    def test_native_numeric_fields_reject_booleans(self):
        row = witness()
        for field in ("version", "nonce", "backendPid", "generation",
                      "serverGeneration", "sequence", "leaseMs"):
            for value in (True, False):
                with self.subTest(field=field, value=value):
                    self.assertFalse(launcher._valid_native_witness({**row, field: value}))
        binding = launcher._binding(row)
        challenge_id = str(uuid4())
        for deadline in (True, False):
            with (self.subTest(deadline=deadline),
                  patch.object(launcher, "_session_request", return_value={
                      "challengeId": challenge_id,
                      "observedAt": "2026-10-09T12:00:00.000Z",
                      "validUntilMonotonic": deadline, "witness": row,
                  }), patch.object(launcher.time, "monotonic", return_value=0.5),
                  self.assertRaisesRegex(launcher.LaunchError, "invalid_client_challenge")):
                launcher.session_challenge("unused", str(uuid4()), challenge_id, binding)

    def test_startup_is_not_selection_and_resume_requires_fresh_exact_thread(self):
        row = witness()
        bridge = Mock()
        bridge.valid_until = float("inf")
        bridge.exchange.return_value = row
        bridge.challenge_readonly.side_effect = [row, {**row, "threadId": str(uuid4())}, row]
        client = launcher.NativeClient(bridge, expected_thread=row["threadId"])
        self.assertEqual(client.status()["selection"], "unavailable")
        bridge.challenge_readonly.assert_not_called()
        client.synchronize()
        bridge.exchange.assert_called_once_with({}, 30)
        bridge.challenge_readonly.assert_not_called()
        self.assertEqual(client.status()["threadId"], row["threadId"])
        self.assertEqual(client.status()["selection"], "unavailable")
        self.assertEqual(client.status()["selection"], "selected")
        self.assertEqual(bridge.challenge_readonly.call_count, 3)
        bridge.start.assert_not_called()

    def test_binding_preflight_and_fresh_challenge_use_exact_live_selection(self):
        row = witness(leaseMs=5000)
        bridge = Mock()
        bridge.valid_until = time.monotonic() + 1
        bridge.challenge_readonly.return_value = row
        bridge.challenge.return_value = row
        client = launcher.NativeClient(bridge, expected_thread=row["threadId"])
        with self.assertRaisesRegex(launcher.LaunchError, "native_client_not_ready"):
            client.binding()
        client.synchronize()
        binding = {key: row[key] for key in launcher.BINDING_FIELDS}
        self.assertEqual(client.binding(), binding)
        self.assertTrue(launcher._valid_native_witness(row))
        challenge_id = str(uuid4())
        challenge = client.challenge(challenge_id, binding)
        self.assertEqual(challenge["challengeId"], challenge_id)
        self.assertEqual(challenge["witness"], row)
        self.assertTrue(challenge["observedAt"].endswith("Z"))
        self.assertGreater(challenge["validUntilMonotonic"], time.monotonic())
        self.assertEqual(bridge.challenge_readonly.call_count, 1)
        bridge.challenge.assert_called_once_with()
        bridge.start.assert_not_called()

    def test_challenge_ipc_latency_consumes_original_witness_lease(self):
        row = witness(leaseMs=750)
        channel, remote = socket.socketpair()
        self.addCleanup(channel.close)
        self.addCleanup(remote.close)
        bridge = launcher.NativeBridge(channel, receipt_version=3)
        client = launcher.NativeClient(bridge)
        client.ready = True
        clock = [1000.0, 10.0]

        def delayed_exchange(*_args):
            clock[0] += 0.4
            clock[1] += 0.4
            return row

        with (patch.object(launcher.time, "time", side_effect=lambda: clock[0]),
              patch.object(launcher.time, "monotonic", side_effect=lambda: clock[1]),
              patch.object(bridge, "exchange", side_effect=delayed_exchange)):
            result = client.challenge(str(uuid4()), launcher._binding(row))
        self.assertEqual(result["observedAt"], "1970-01-01T00:16:40.000Z")
        self.assertEqual(result["validUntilMonotonic"], 10.75)
        self.assertAlmostEqual(result["validUntilMonotonic"] - clock[1], 0.35)

    def test_fresh_challenge_rejects_changed_or_expired_binding(self):
        row = witness()
        bridge = Mock()
        bridge.valid_until = time.monotonic() + 1
        bridge.challenge.return_value = row
        client = launcher.NativeClient(bridge)
        client.synchronize()
        expected = {key: row[key] for key in launcher.BINDING_FIELDS}
        changed = {**expected, "threadId": str(uuid4())}
        with self.assertRaisesRegex(launcher.LaunchError, "native_binding_changed"):
            client.challenge(str(uuid4()), changed)
        bridge.valid_until = 0
        with self.assertRaisesRegex(launcher.LaunchError, "native_binding_changed"):
            client.challenge(str(uuid4()), expected)
        self.assertFalse(launcher._valid_native_witness({**row, "sequence": 2**53}))
        self.assertFalse(launcher._valid_native_witness({**row, "generation": 2**53}))

    def test_session_challenge_is_correlated_and_uses_private_session_socket(self):
        row = witness(leaseMs=5000)
        binding = {key: row[key] for key in launcher.BINDING_FIELDS}
        challenge_id = str(uuid4())
        response = {
            "challengeId": challenge_id,
            "observedAt": "2026-10-09T12:00:00.000Z",
            "validUntilMonotonic": time.monotonic() + 0.5,
            "witness": row,
        }
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            state.chmod(0o700)
            endpoint = Mock()
            endpoint.lstat.return_value = Mock(
                st_mode=stat.S_IFSOCK | 0o600, st_uid=launcher.os.getuid(),
            )
            channel = MagicMock()
            channel.__enter__.return_value = channel
            channel.recv.return_value = json.dumps(response).encode() + b"\n"
            with (
                patch.object(launcher, "session_path", return_value=endpoint),
                patch.object(launcher.socket, "socket", return_value=channel),
            ):
                self.assertEqual(
                    launcher.session_challenge(state, str(uuid4()), challenge_id, binding),
                    {key: response[key] for key in ("observedAt", "validUntilMonotonic", "witness")},
                )
            request = json.loads(channel.sendall.call_args.args[0])
            self.assertEqual(request, {
                "command": "challenge", "challengeId": challenge_id,
                "expectedBinding": binding,
            })

            channel.recv.return_value = json.dumps({**response, "challengeId": "other"}).encode() + b"\n"
            with (
                patch.object(launcher, "session_path", return_value=endpoint),
                patch.object(launcher.socket, "socket", return_value=channel),
                self.assertRaisesRegex(launcher.LaunchError, "invalid_client_challenge"),
            ):
                launcher.session_challenge(state, str(uuid4()), challenge_id, binding)

    def test_real_reader_rejects_malformed_and_repeated_sequence(self):
        for changes in ({"eligible": "yes"}, {"leaseMs": 0}, {"sequence": 1}):
            row = witness()

            def handle(channel):
                self.assertEqual(receive(channel), {"nonce": 1})
                send(channel, row)
                self.assertEqual(receive(channel), {"nonce": 2})
                send(channel, {**row, "nonce": 2})
                self.assertEqual(receive(channel), {"nonce": 3})
                send(channel, {**row, "nonce": 3, "sequence": 2, **changes})
                self.assertIsNone(receive(channel))

            with self.subTest(changes=changes), peer(handle, receipt_version=3) as bridge:
                client = launcher.NativeClient(bridge)
                client.synchronize()
                self.assertEqual(client.status()["selection"], "selected")
                self.assertEqual(client.status()["selection"], "unavailable")
                self.assertTrue(bridge.closed)

    def test_ineligible_witness_and_failed_challenge_remain_unattached(self):
        bridge = Mock()
        bridge.valid_until = float("inf")
        bridge.challenge_readonly.side_effect = [witness(eligible=False), None, ValueError("invalid")]
        client = launcher.NativeClient(bridge)
        client.synchronize()
        for _ in range(3):
            status = client.status()
            self.assertEqual(status["selection"], "unavailable")
            self.assertFalse(status["attached"])
            self.assertFalse(status["automaticWakeEnabled"])
        bridge.start.assert_not_called()

    def test_real_reader_short_lease_cannot_publish_expired_selection(self):
        row = witness(leaseMs=1)

        def handle(channel):
            self.assertEqual(receive(channel), {"nonce": 1})
            send(channel, row)
            self.assertEqual(receive(channel), {"nonce": 2})
            send(channel, {**row, "nonce": 2})
            self.assertIsNone(receive(channel))

        with peer(handle, receipt_version=3) as bridge:
            client = launcher.NativeClient(bridge)
            client.synchronize()
            challenge = bridge.challenge_readonly

            def delayed_result():
                result = challenge()
                time.sleep(0.02)
                return result

            with patch.object(bridge, "challenge_readonly", side_effect=delayed_result):
                self.assertEqual(client.status()["selection"], "unavailable")

    def test_status_rejects_unsafe_state_before_connecting(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            for mode in (0o755, 0o777):
                state.chmod(mode)
                with self.subTest(mode=mode), patch.object(launcher.socket, "socket") as connect:
                    with self.assertRaisesRegex(launcher.LaunchError, "unsafe_client_state"):
                        launcher.session_status(state, str(uuid4()))
                    connect.assert_not_called()
            state.chmod(0o700)
            alias = state / "alias"
            alias.symlink_to(state, target_is_directory=True)
            with self.assertRaisesRegex(launcher.LaunchError, "unsafe_client_state"):
                launcher.session_status(alias, str(uuid4()))
            with patch.object(launcher.os, "getuid", return_value=state.stat().st_uid + 1):
                with self.assertRaisesRegex(launcher.LaunchError, "unsafe_client_state"):
                    launcher.session_status(state, str(uuid4()))

    def test_control_drip_does_not_extend_absolute_deadline(self):
        channel = MagicMock()
        channel.recv.return_value = b"{"
        listener = Mock()
        listener.accept.side_effect = [(channel, None), OSError("closed")]
        client = Mock()
        with patch.object(launcher.time, "monotonic", side_effect=[0, 0.5, 1.5, 2.5]):
            launcher._control(listener, client, threading.Event())
        self.assertEqual(channel.recv.call_count, 2)
        self.assertEqual(channel.settimeout.call_args_list, [call(1.5), call(0.5)])
        client.status.assert_not_called()
        channel.sendall.assert_not_called()

    def test_status_client_drip_does_not_extend_absolute_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            state.chmod(0o700)
            endpoint = Mock()
            endpoint.lstat.return_value = Mock(
                st_mode=stat.S_IFSOCK | 0o600, st_uid=launcher.os.getuid(),
            )
            channel = MagicMock()
            channel.__enter__.return_value = channel
            channel.recv.return_value = b"{"
            with (
                patch.object(launcher, "session_path", return_value=endpoint),
                patch.object(launcher.socket, "socket", return_value=channel),
                patch.object(launcher.time, "monotonic", side_effect=[0, 0.1, 0.2, 0.3, 1, 2.1]),
                self.assertRaisesRegex(TimeoutError, "client_status_timeout"),
            ):
                launcher.session_status(state, str(uuid4()))
            self.assertEqual(channel.recv.call_count, 2)
            self.assertEqual(list(state.iterdir()), [])

    def test_environment_injection_and_unknown_digest_are_rejected(self):
        for key in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "CODEX_NATIVE_BRIDGE_FD",
                    "CODEX_NATIVE_BRIDGE_RECEIPT_VERSION", "CODEX_SELECTION_WITNESS_FD",
                    "CODEX_BRIDGE_ADOPTION_PROBE"):
            with self.subTest(key=key), self.assertRaisesRegex(launcher.LaunchError, "unsafe_launch_environment"):
                launcher.launch_environment({key: ""})
        original = {"HOME": "/owner", "CODEX_HOME": "/explicit"}
        self.assertEqual(launcher.launch_environment(original), original)
        with self.assertRaisesRegex(launcher.LaunchError, "unqualified_native_binary"):
            launcher.qualified_binary("/does/not/exist", "f" * 64)

    def test_control_accepts_only_bounded_exact_status(self):
        row = witness()
        binding = {key: row[key] for key in launcher.BINDING_FIELDS}
        challenge_id = str(uuid4())
        for payload in (
            b'{"command":"status"}\n',
            b'{"command":"binding"}\n',
            json.dumps({"command": "challenge", "challengeId": challenge_id,
                        "expectedBinding": binding}, separators=(",", ":")).encode() + b"\n",
            b'{"command":"start"}\n',
            b'{"command":"status","command":"start"}\n',
            b'{"command":"status"}\n{"command":"start"}\n',
            b"x" * 1024,
        ):
            with self.subTest(payload=payload):
                response = None
                channel = MagicMock()
                channel.recv.return_value = payload
                listener = Mock()
                listener.accept.side_effect = [(channel, None), OSError("closed")]
                client = Mock()
                client.status.return_value = {"selection": "unavailable"}
                client.binding.return_value = binding
                client.challenge.return_value = {
                    "challengeId": challenge_id,
                    "observedAt": "2026-10-09T12:00:00.000Z",
                    "validUntilMonotonic": time.monotonic() + 5,
                    "witness": row,
                }
                launcher._control(listener, client, threading.Event())
                if payload in (b'{"command":"status"}\n', b'{"command":"binding"}\n') or payload.startswith(b'{"command":"challenge"'):
                    response = json.loads(channel.sendall.call_args.args[0])
                if payload == b'{"command":"status"}\n':
                    self.assertEqual(response, client.status.return_value)
                    client.status.assert_called_once_with()
                elif payload == b'{"command":"binding"}\n':
                    self.assertEqual(response, binding)
                    client.binding.assert_called_once_with()
                elif payload.startswith(b'{"command":"challenge"'):
                    self.assertEqual(response, client.challenge.return_value)
                    client.challenge.assert_called_once_with(challenge_id, binding)
                elif payload == b'{"command":"start"}\n':
                    response = json.loads(channel.sendall.call_args.args[0])
                    self.assertEqual(response, {"reason": "unsupported_command"})
                    client.status.assert_not_called()
                    client.binding.assert_not_called()
                    client.challenge.assert_not_called()
                else:
                    channel.sendall.assert_not_called()
                    client.status.assert_not_called()
                    client.binding.assert_not_called()
                    client.challenge.assert_not_called()
                channel.recv.assert_called_once_with(1024)
                client.start.assert_not_called()

    def test_binary_file_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary = root / "codex"
            binary.write_bytes(b"qualified fixture")
            binary.chmod(0o700)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            with patch.object(launcher, "QUALIFIED_SHA256", digest):
                self.assertEqual(launcher.qualified_binary(binary, digest), binary)
                with self.assertRaises(FileNotFoundError):
                    launcher.qualified_binary(root / "missing", digest)
                alias = root / "alias"
                alias.symlink_to(binary)
                with self.assertRaisesRegex(launcher.LaunchError, "unsafe_native_binary"):
                    launcher.qualified_binary(alias, digest)
                binary.chmod(0o722)
                with self.assertRaisesRegex(launcher.LaunchError, "unsafe_native_binary"):
                    launcher.qualified_binary(binary, digest)
                binary.chmod(0o700)
                binary.write_bytes(b"changed")
                with self.assertRaisesRegex(launcher.LaunchError, "native_binary_hash_mismatch"):
                    launcher.qualified_binary(binary, digest)

    def test_promoted_digest_requires_both_reviewed_pin_and_opened_binary_hash(self):
        promoted = "362074bba4d43bbcc7e1e4162f67f8439106ef388670899309effd75cca65f27"
        superseded = "9e99dd87bf932bc6960fd2ff9c60fc9af73f19667323562483e10f86b17042f5"
        unqualified_v2 = "9888c1f1631fee081d797189ea4c18809ce3fcac6c44cef4af291da1e263ae78"
        retired = "d82007ca79c2d73cfdf811bcb5efe949831c2652b3114b836f5eefea9f269c02"
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory).resolve() / "codex"
            binary.write_bytes(b"release digest fixture")
            binary.chmod(0o700)
            for supplied, actual, error in (
                (superseded, superseded, "unqualified_native_binary"),
                (superseded, promoted, "unqualified_native_binary"),
                (promoted, superseded, "native_binary_hash_mismatch"),
                (unqualified_v2, unqualified_v2, "unqualified_native_binary"),
                (unqualified_v2, promoted, "unqualified_native_binary"),
                (promoted, unqualified_v2, "native_binary_hash_mismatch"),
                (retired, retired, "unqualified_native_binary"),
                (retired, promoted, "unqualified_native_binary"),
                (promoted, retired, "native_binary_hash_mismatch"),
                (promoted, promoted, None),
            ):
                def file_digest(stream, algorithm):
                    self.assertEqual(algorithm, "sha256")
                    self.assertTrue(stat.S_ISREG(launcher.os.fstat(stream.fileno()).st_mode))
                    self.assertEqual(stream.read(), b"release digest fixture")
                    return Mock(hexdigest=Mock(return_value=actual))

                with self.subTest(supplied=supplied, actual=actual), patch.object(
                    launcher.hashlib, "file_digest", side_effect=file_digest,
                ) as digest:
                    if error:
                        with self.assertRaisesRegex(launcher.LaunchError, error):
                            launcher.qualified_binary(binary, supplied)
                    else:
                        self.assertEqual(launcher.qualified_binary(binary, supplied), binary)
                    self.assertEqual(digest.call_count, int(supplied == promoted))

    def test_exit_observer_never_reaps(self):
        stop = Mock()
        stop.is_set.return_value = False
        with patch.object(launcher.os, "waitid", side_effect=[None, object()]) as waitid:
            launcher._watch_child(12345, stop)
        expected = call(launcher.os.P_PID, 12345,
                        launcher.os.WEXITED | launcher.os.WNOHANG | launcher.os.WNOWAIT)
        self.assertEqual(waitid.call_args_list, [expected, expected])
        stop.wait.assert_called_once_with(0.1)
        stop.set.assert_called_once_with()

    def test_cleanup_signals_once_before_reaping_and_closes_partial_spawn(self):
        for scenario in ("normal", "spawn_failure", "exited_eperm", "running_eperm",
                         "wait_timeout", "worker_start_failure"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                root = Path(directory)
                listener, parent, child, bridge, process = [Mock() for _ in range(5)]
                child.fileno.return_value = 21
                process.pid = 12345
                process.returncode = 0
                events = []
                process.wait.side_effect = lambda **_: events.append("wait")
                replacements = {
                    "qualified_binary": Path("/qualified/codex"),
                    "ensure_private_directory": None,
                    "socket.socket": listener,
                    "socket.socketpair": (parent, child),
                    "NativeBridge": bridge,
                    "pty.openpty": (22, 23),
                    "os.isatty": True,
                    "os.chmod": None,
                    "os.close": None,
                    "threading.Thread": Mock(),
                    "signal.signal": signal.SIG_DFL,
                    "run_terminal": None,
                }
                mocks = {name: stack.enter_context(patch("event_gateway.launcher." + name, return_value=value))
                         for name, value in replacements.items()}
                stack.enter_context(patch.dict(launcher.os.environ, {}, clear=True))
                stack.enter_context(patch("builtins.print"))
                kill = stack.enter_context(patch.object(launcher.os, "killpg", side_effect=lambda *_: events.append("kill")))
                waitid = stack.enter_context(patch.object(launcher.os, "waitid", return_value=None))
                spawn = stack.enter_context(patch.object(launcher.subprocess, "Popen", return_value=process))
                unlink = stack.enter_context(patch.object(Path, "unlink"))
                if scenario == "spawn_failure":
                    spawn.side_effect = OSError("spawn failed")
                    with self.assertRaises(OSError):
                        launcher.launch(root, "/qualified/codex", launcher.QUALIFIED_SHA256, root)
                    kill.assert_not_called()
                    process.wait.assert_not_called()
                elif scenario in ("wait_timeout", "worker_start_failure"):
                    if scenario == "wait_timeout":
                        process.wait.side_effect = launcher.subprocess.TimeoutExpired("private arguments", 5)
                        expected = "native_process_cleanup_timeout"
                    else:
                        started, unstarted = Mock(), Mock()
                        unstarted.start.side_effect = RuntimeError("private thread failure")
                        unstarted.join.side_effect = RuntimeError("cannot join thread before it is started")
                        mocks["threading.Thread"].side_effect = [started, unstarted]
                        expected = "native_worker_start_failed"
                    with self.assertRaises(launcher.LaunchError) as raised:
                        launcher.launch(root, "/qualified/codex", launcher.QUALIFIED_SHA256, root)
                    self.assertEqual(str(raised.exception), expected)
                    self.assertTrue(raised.exception.__suppress_context__)
                    kill.assert_called_once_with(process.pid, signal.SIGKILL)
                    process.wait.assert_called_once_with(timeout=5)
                    if scenario == "worker_start_failure":
                        started.join.assert_called_once_with(timeout=1)
                        unstarted.join.assert_not_called()
                elif scenario in ("exited_eperm", "running_eperm"):
                    kill.side_effect = PermissionError("group denied")
                    if scenario == "exited_eperm":
                        waitid.return_value = object()
                        self.assertEqual(launcher.launch(root, "/qualified/codex", launcher.QUALIFIED_SHA256, root), 0)
                        process.wait.assert_called_once_with(timeout=5)
                    else:
                        with self.assertRaises(PermissionError):
                            launcher.launch(root, "/qualified/codex", launcher.QUALIFIED_SHA256, root)
                        process.wait.assert_not_called()
                    waitid.assert_called_once_with(launcher.os.P_PID, process.pid,
                                                  launcher.os.WEXITED | launcher.os.WNOHANG | launcher.os.WNOWAIT)
                else:
                    self.assertEqual(launcher.launch(root, "/qualified/codex", launcher.QUALIFIED_SHA256, root), 0)
                    self.assertEqual(spawn.call_args.args[0],
                                     ["/qualified/codex", "--no-daemon", "--no-alt-screen", "-C", str(root.resolve())])
                    self.assertEqual(events, ["kill", "wait"])
                    kill.assert_called_once_with(process.pid, signal.SIGKILL)
                    process.poll.assert_not_called()
                    self.assertEqual(spawn.call_args.kwargs["pass_fds"], (21,))
                    self.assertEqual(spawn.call_args.kwargs["env"]["CODEX_NATIVE_BRIDGE_RECEIPT_VERSION"], "3")
                bridge.close.assert_called_once_with()
                listener.close.assert_called_once_with()
                child.close.assert_called()
                self.assertIn(call(22), mocks["os.close"].call_args_list)
                self.assertIn(call(23), mocks["os.close"].call_args_list)
                unlink.assert_called_once_with(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
