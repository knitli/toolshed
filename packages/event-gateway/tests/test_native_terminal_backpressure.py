"""Real PTY pressure must not prevent stop or terminal-mode restoration."""

import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import time
import tty
import unittest

from event_gateway import native_terminal


WORKER = r'''
import json, os, signal, sys, termios, threading
from event_gateway.native_terminal import run_terminal
master, status = map(int, sys.argv[1:])
before = termios.tcgetattr(0)
blocking = (os.get_blocking(master), os.get_blocking(1))
stop = threading.Event()
def stopped(*_):
    stop.set()
    os.write(status, b"STOPPED\n")
signal.signal(signal.SIGTERM, stopped)
os.write(status, b"READY\n")
run_terminal(master, stop_event=stop)
after = termios.tcgetattr(0)
# Darwin marks pending input when restoring canonical mode; this is kernel
# queue state, not a changed terminal setting. Compare every other bit/value.
before[3] &= ~getattr(termios, "PENDIN", 0)
after[3] &= ~getattr(termios, "PENDIN", 0)
result = dict(restored=after == before,
              blocking_restored=(os.get_blocking(master), os.get_blocking(1)) == blocking)
os.write(status, b"DONE " + json.dumps(result).encode() + b"\n")
'''


class NativeTerminalBackpressureTests(unittest.TestCase):
    def test_stop_under_unread_native_input_and_stdout_pressure(self):
        for direction in ("input", "output"):
            with self.subTest(direction=direction):
                outer_master, outer_slave = pty.openpty()
                native_master, native_slave = pty.openpty()
                status_read, status_write = os.pipe()
                descriptors = (outer_master, outer_slave, native_master, native_slave,
                               status_read, status_write)
                process = None
                received = bytearray()

                def read_until(marker, seconds=2):
                    deadline = time.monotonic() + seconds
                    while marker not in received and time.monotonic() < deadline:
                        if select.select([status_read], [], [], 0.05)[0]:
                            data = os.read(status_read, 4096)
                            if not data:
                                break
                            received.extend(data)
                    self.assertIn(marker, received, f"{direction} pressure: {received!r}")

                try:
                    tty.setraw(native_slave)
                    environment = dict(os.environ)
                    environment["PYTHONPATH"] = str(Path(native_terminal.__file__).resolve().parents[1])
                    process = subprocess.Popen(
                        [sys.executable, "-c", WORKER, str(native_master), str(status_write)],
                        stdin=outer_slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        pass_fds=(native_master, status_write), env=environment,
                    )
                    read_until(b"READY\n")
                    destination = outer_master if direction == "input" else native_slave
                    os.set_blocking(destination, False)
                    deadline = time.monotonic() + 0.5
                    written = 0
                    while time.monotonic() < deadline:
                        if select.select([], [destination], [], 0.01)[1]:
                            try:
                                written += os.write(destination, b"x" * 4096)
                            except BlockingIOError:
                                pass
                    self.assertGreaterEqual(written, 1024)
                    process.send_signal(signal.SIGTERM)
                    read_until(b"STOPPED\n")
                    read_until(b"DONE ")
                    self.assertEqual(process.wait(timeout=2), 0)
                    result = json.loads(received.split(b"DONE ", 1)[1].splitlines()[0])
                    self.assertTrue(result["restored"], repr(result))
                    self.assertTrue(result["blocking_restored"])
                finally:
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=2)
                        process.stdout.close()
                        process.stderr.close()
                    for fd in descriptors:
                        os.close(fd)


if __name__ == "__main__":
    unittest.main()
