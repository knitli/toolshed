"""Terminal forwarding preserves input bytes and restores the owner terminal."""

import errno
from contextlib import ExitStack
import threading
import unittest
from unittest.mock import patch

from event_gateway import native_terminal


class NativeTerminalTests(unittest.TestCase):
    def test_stopped_partial_writes_finish_available_tail(self):
        stopped = threading.Event()
        stopped.set()
        with (
            patch.object(native_terminal.os, "write", side_effect=[2, 2]) as write,
            patch.object(native_terminal.select, "select") as ready,
        ):
            self.assertTrue(native_terminal._write_all(12, b"tail", stopped))
            self.assertEqual([item.args for item in write.call_args_list],
                             [(12, b"tail"), (12, b"il")])
            ready.assert_not_called()

    def test_stopped_backpressure_returns_without_waiting(self):
        stopped = threading.Event()
        stopped.set()
        with (
            patch.object(native_terminal.os, "write", side_effect=BlockingIOError()) as write,
            patch.object(native_terminal.select, "select") as ready,
        ):
            self.assertFalse(native_terminal._write_all(12, b"tail", stopped))
            write.assert_called_once_with(12, b"tail")
            ready.assert_not_called()

    def test_partial_writes_preserve_bytes_and_wait_without_busy_looping(self):
        with (
            patch.object(native_terminal.os, "write", side_effect=[2, BlockingIOError(), 3]) as write,
            patch.object(native_terminal.select, "select", return_value=([], [12], [])) as ready,
        ):
            self.assertTrue(native_terminal._write_all(12, b"hello", threading.Event()))
            self.assertEqual([item.args for item in write.call_args_list],
                             [(12, b"hello"), (12, b"llo"), (12, b"llo")])
            ready.assert_called_once_with([], [12], [], 0.1)

    def test_stop_drains_output_without_reading_input(self):
        stopped = threading.Event()
        stopped.set()
        with ExitStack() as stack:
            for name, value in (
                ("sys.stdin.fileno", 10), ("sys.stdout.fileno", 11),
                ("os.isatty", True), ("termios.tcgetattr", ["saved"]),
                ("os.get_blocking", True), ("os.set_blocking", None),
                ("termios.tcsetattr", None), ("tty.setraw", None),
                ("signal.getsignal", "handler"), ("signal.signal", None),
                ("fcntl.ioctl", b"\0" * 8),
            ):
                stack.enter_context(patch("event_gateway.native_terminal." + name, return_value=value))
            ready = stack.enter_context(patch.object(native_terminal.select, "select", side_effect=[
                ([12], [], []), ([], [], []),
            ]))
            read = stack.enter_context(patch.object(native_terminal.os, "read", return_value=b"tail"))
            write = stack.enter_context(patch.object(native_terminal.os, "write", return_value=4))
            native_terminal.run_terminal(12, stop_event=stopped)
            read.assert_called_once_with(12, 4096)
            write.assert_called_once_with(11, b"tail")
            self.assertTrue(all(item.args == ([12], [], [], 0) for item in ready.call_args_list))

    def test_forward_and_restore_after_pty_eof(self):
        with (
            patch.object(native_terminal.sys.stdin, "fileno", return_value=10),
            patch.object(native_terminal.sys.stdout, "fileno", return_value=11),
            patch.object(native_terminal.os, "isatty", return_value=True),
            patch.object(native_terminal.os, "get_blocking", side_effect=[False, True]),
            patch.object(native_terminal.os, "set_blocking") as blocking,
            patch.object(native_terminal.termios, "tcgetattr", return_value=["saved"]),
            patch.object(native_terminal.termios, "tcsetattr") as restore,
            patch.object(native_terminal.tty, "setraw"),
            patch.object(native_terminal.signal, "getsignal", return_value="handler"),
            patch.object(native_terminal.signal, "signal") as signals,
            patch.object(native_terminal.fcntl, "ioctl", return_value=b"\0" * 8),
            patch.object(native_terminal.select, "select", side_effect=[
                ([12, 10], [], []), ([12], [], []),
            ]),
            patch.object(native_terminal.os, "read", side_effect=[
                b"screen", b"\x03", OSError(errno.EIO, "PTY closed"),
            ]),
            patch.object(native_terminal.os, "write", side_effect=lambda fd, data: len(data)) as write,
        ):
            native_terminal.run_terminal(12, stop_event=threading.Event())
            self.assertEqual([call.args for call in write.call_args_list], [(11, b"screen"), (12, b"\x03")])
            restore.assert_called_once_with(10, native_terminal.termios.TCSANOW, ["saved"])
            self.assertEqual([item.args for item in blocking.call_args_list],
                             [(12, False), (11, False), (12, False), (11, True)])
            self.assertEqual(signals.call_args.args, (native_terminal.signal.SIGWINCH, "handler"))


if __name__ == "__main__":
    unittest.main()
