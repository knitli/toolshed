"""Explicit launch and read-only presence checks; no native process is started."""

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import signal
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
    def test_startup_is_not_selection_and_resume_requires_fresh_exact_thread(self):
        row = witness()
        bridge = Mock()
        bridge.valid_until = float("inf")
        bridge.exchange.return_value = row
        bridge.challenge.side_effect = [row, {**row, "threadId": str(uuid4())}, row]
        client = launcher.NativeClient(bridge, expected_thread=row["threadId"])
        self.assertEqual(client.status()["selection"], "unavailable")
        bridge.challenge.assert_not_called()
        client.synchronize()
        bridge.exchange.assert_called_once_with({}, 30)
        bridge.challenge.assert_not_called()
        self.assertEqual(client.status()["threadId"], row["threadId"])
        self.assertEqual(client.status()["selection"], "unavailable")
        self.assertEqual(client.status()["selection"], "selected")
        self.assertEqual(bridge.challenge.call_count, 3)
        bridge.start.assert_not_called()

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
        bridge.challenge.side_effect = [witness(eligible=False), ValueError("invalid")]
        client = launcher.NativeClient(bridge)
        client.synchronize()
        for _ in range(2):
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
            challenge = bridge.challenge

            def delayed_result():
                result = challenge()
                time.sleep(0.02)
                return result

            with patch.object(bridge, "challenge", side_effect=delayed_result):
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
        for payload in (b'{"command":"status"}\n', b'{"command":"start"}\n',
                        b'{"command":"status"}\n{"command":"start"}\n', b"x" * 128):
            with self.subTest(payload=payload):
                channel = MagicMock()
                channel.recv.return_value = payload
                listener = Mock()
                listener.accept.side_effect = [(channel, None), OSError("closed")]
                client = Mock()
                client.status.return_value = {"selection": "unavailable"}
                launcher._control(listener, client, threading.Event())
                response = json.loads(channel.sendall.call_args.args[0])
                if payload == b'{"command":"status"}\n':
                    self.assertEqual(response, client.status.return_value)
                    client.status.assert_called_once_with()
                else:
                    self.assertEqual(response, {"reason": "unsupported_command"})
                    client.status.assert_not_called()
                channel.recv.assert_called_once_with(128)
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
        for scenario in ("normal", "spawn_failure", "exited_eperm", "running_eperm"):
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
                if scenario == "spawn_failure":
                    spawn.side_effect = OSError("spawn failed")
                    with self.assertRaises(OSError):
                        launcher.launch(root, "/qualified/codex", launcher.QUALIFIED_SHA256, root)
                    kill.assert_not_called()
                    process.wait.assert_not_called()
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


if __name__ == "__main__":
    unittest.main()
