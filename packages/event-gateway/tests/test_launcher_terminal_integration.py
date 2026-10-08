"""Real PTYs and a private mock child; no Codex binary or model is involved."""

import errno
import fcntl
import hashlib
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess  # nosec B404 - Fixed interpreter and owned temporary mock child, no shell.
import sys
import tempfile
import termios
import time
import unittest
from uuid import uuid4

from event_gateway import launcher
from event_gateway.launcher import session_status


CHILD = r'''
import json
import os
import signal
import socket
import sys
import threading
import tty

channel = socket.socket(fileno=int(os.environ.pop("CODEX_NATIVE_BRIDGE_FD")))
assert os.environ["CODEX_NATIVE_BRIDGE_RECEIPT_VERSION"] == "3"
thread_id = sys.argv[sys.argv.index("resume") + 1]
identity = "11111111-1111-4111-8111-111111111111"

def bridge():
    stream = channel.makefile("rwb", buffering=0)
    sequence = 0
    while line := stream.readline():
        request = json.loads(line)
        assert set(request) == {"nonce"}, "status must never start a turn"
        sequence += 1
        row = dict(version=2, nonce=request["nonce"], clientId=identity,
                   backendPid=os.getpid(), connectionId=identity, threadId=thread_id,
                   generation=1, eligible=True, sequence=sequence, cause="mock",
                   serverInstanceId=identity, serverGeneration=1, leaseMs=750)
        stream.write(json.dumps(row).encode() + b"\n")

threading.Thread(target=bridge, daemon=True).start()
terminal = os.open("/dev/tty", os.O_RDWR)
assert os.tcgetpgrp(terminal) == os.getpgrp(), "child must own foreground tty"
os.close(terminal)
tty.setraw(0)
def resized(*_):
    size = os.get_terminal_size(0)
    print(f"MOCK_RESIZE:{size.lines}x{size.columns}", flush=True)
signal.signal(signal.SIGWINCH, resized)
print("MOCK_CONTROLLING_TTY_READY", flush=True)
data = bytearray()
while len(data) < 5:
    data.extend(os.read(0, 5 - len(data)))
assert bytes(data) == b"ping\x03", repr(data)
print("MOCK_INPUT_HEX:" + data.hex(), flush=True)
'''


class LauncherTerminalIntegrationTests(unittest.TestCase):
    def test_owned_child_terminal_input_status_and_cleanup(self):
        temporary_root = "/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"  # nosec B108 - Secure TemporaryDirectory; short root keeps AF_UNIX paths valid.
        with tempfile.TemporaryDirectory(prefix="evlaunch-", dir=temporary_root) as directory:
            root = Path(directory)
            binary = root / "mock-codex"
            binary.write_text("#!" + sys.executable + "\n" + CHILD)
            binary.chmod(0o700)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            state = root / "state"
            thread_id = str(uuid4())
            script = (
                "from pathlib import Path; from event_gateway import launcher; "
                f"launcher.QUALIFIED_SHA256={digest!r}; "
                f"raise SystemExit(launcher.launch(Path({str(state)!r}), {str(binary)!r}, "
                f"{digest!r}, {str(root)!r}, resume={thread_id!r}))"
            )
            environment = dict(os.environ)
            # Preserve whichever package this interpreter loaded, including an
            # installed wheel when this test runs from outside the checkout.
            environment["PYTHONPATH"] = str(Path(launcher.__file__).resolve().parents[1])
            master, slave = pty.openpty()
            process = None
            output = bytearray()

            def read_until(marker):
                deadline = time.monotonic() + 10
                while marker not in output:
                    self.assertLess(time.monotonic(), deadline, output.decode(errors="replace"))
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            chunk = b""
                        self.assertTrue(chunk, output.decode(errors="replace"))
                        output.extend(chunk)

            try:
                process = subprocess.Popen(  # nosec B603 - Fixed interpreter and test-owned literal script, no shell.
                    [sys.executable, "-c", script], env=environment,
                    stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                )
                os.close(slave)
                slave = None
                read_until(b"MOCK_CONTROLLING_TTY_READY")
                match = re.search(rb"Local Codex session: ([0-9a-f-]{36})", output)
                self.assertIsNotNone(match, output.decode(errors="replace"))
                session_id = match.group(1).decode()
                deadline = time.monotonic() + 5
                while True:
                    status = session_status(state, session_id)
                    if status["selection"] == "selected":
                        break
                    self.assertLess(time.monotonic(), deadline, status)
                    time.sleep(0.02)
                self.assertEqual(status["threadId"], thread_id)
                self.assertFalse(status["attached"])
                self.assertFalse(status["automaticWakeEnabled"])
                self.assertEqual(status["receiptVersion"], 3)
                fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 47, 131, 0, 0))
                os.kill(process.pid, signal.SIGWINCH)
                read_until(b"MOCK_RESIZE:47x131")
                os.write(master, b"ping\x03")
                read_until(b"MOCK_INPUT_HEX:70696e6703")
                deadline = time.monotonic() + 10
                while process.poll() is None:
                    self.assertLess(time.monotonic(), deadline, output.decode(errors="replace"))
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            output.extend(os.read(master, 65536))
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                self.assertEqual(process.returncode, 0, output.decode(errors="replace"))
                self.assertEqual(list(state.glob("c-*.sock")), [])
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                os.close(master)
                if slave is not None:
                    os.close(slave)


if __name__ == "__main__":
    unittest.main()
