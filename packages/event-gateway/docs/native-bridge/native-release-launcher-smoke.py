"""Exercise installed foreground launcher with a real PTY and disposable config."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4
from event_gateway.launcher import (
    LaunchError,
    QUALIFIED_SHA256,
    qualified_binary,
    session_status,
    session_binding,
    session_challenge,
)


def require(condition, message="foreground qualification check failed"):
    if not condition:
        raise AssertionError(message)


parser = argparse.ArgumentParser()
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
require(qualified_binary(args.binary, QUALIFIED_SHA256) == args.binary)


class Model(BaseHTTPRequestHandler):
    def do_POST(self):
        self.server.calls += 1
        self.send_error(500)

    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
server.calls = 0
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix="nr-", dir="/private/tmp") as directory:
        root = Path(directory)
        home = root / "codex-home"
        home.mkdir(mode=448)
        state = root / "state"
        (home / "config.toml").write_text(
            f'check_for_update_on_startup=false\nmodel="mock-model"\nmodel_provider="qualification"\n[model_providers.qualification]\nname="Synthetic qualification"\nbase_url="http://127.0.0.1:{server.server_port}"\nwire_api="responses"\nrequires_openai_auth=false\n[analytics]\nenabled=false\n[feedback]\nenabled=false\n[otel]\nexporter="none"\ntrace_exporter="none"\nmetrics_exporter="none"\n[projects.{json.dumps(str(root))}]\ntrust_level="trusted"\n'
        )
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        argv = [
            sys.executable,
            "-I",
            "-m",
            "event_gateway.cli",
            "--state-dir",
            str(state),
            "launch",
            "--codex-binary",
            str(args.binary),
            "--binary-sha256",
            QUALIFIED_SHA256,
            "--cwd",
            str(root),
        ]
        process = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            cwd=root,
            start_new_session=True,
            env={
                "PATH": os.defpath,
                "HOME": str(root),
                "CODEX_HOME": str(home),
                "TERM": "xterm-256color",
            },
        )
        os.close(slave)
        tail = bytearray()
        backend_pid = None
        try:
            deadline = time.monotonic() + 45
            while True:
                require(process.poll() is None, tail.decode(errors="replace"))
                require(time.monotonic() < deadline, tail.decode(errors="replace"))
                if select.select([master], [], [], 0.1)[0]:
                    data = os.read(master, 65536)
                    tail.extend(data)
                    del tail[:-16384]
                    if b"\x1b[6n" in data:
                        os.write(master, b"\x1b[1;1R")
                sockets = list(state.glob("c-*.sock")) if state.exists() else []
                if not sockets:
                    continue
                session = sockets[0].name[2:-5]
                try:
                    status = session_status(state, session)
                except (ConnectionRefusedError, FileNotFoundError):
                    continue
                if status["selection"] != "selected":
                    continue
                try:
                    binding = session_binding(state, session)
                    challenge = session_challenge(state, session, str(uuid4()), binding)
                except LaunchError:
                    continue
                if binding["threadId"] == status["threadId"]:
                    break
            require(status["selection"] == "selected")
            require(binding["threadId"] == status["threadId"])
            backend_pid = binding["backendPid"]
            require(challenge["witness"]["eligible"])
            require(
                all(
                    challenge["witness"][key] == value for key, value in binding.items()
                )
            )
            require(time.monotonic() < challenge["validUntilMonotonic"])
            require(
                status["automaticWakeEnabled"] is False and status["attached"] is False
            )
            require(server.calls == 0)
            os.write(master, b"/quit")
            time.sleep(0.2)
            os.write(master, b"\r")
            deadline = time.monotonic() + 15
            while process.poll() is None:
                require(time.monotonic() < deadline, "foreground quit timed out")
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        tail.extend(os.read(master, 65536))
                    except OSError:
                        break
            code = process.wait(timeout=5)
            require(code == 0, f"foreground launcher exited {code}")
            require(server.calls == 0, "unexpected model request during cleanup")
            require(not sockets[0].exists())
            try:
                os.kill(backend_pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError("backend survived foreground launcher cleanup")
            proof = {
                "result": "PASS",
                "binarySha256": QUALIFIED_SHA256,
                "python": sys.executable,
                "argv": argv,
                "installedLauncherSha256": hashlib.sha256(
                    Path(
                        __import__("event_gateway.launcher", fromlist=["x"]).__file__
                    ).read_bytes()
                ).hexdigest(),
                "qualifiedBinaryAccepted": True,
                "foregroundPtyLaunch": True,
                "status": status,
                "binding": binding,
                "freshChallengeCorrelated": True,
                "syntheticModelRequests": server.calls,
                "realModelCalls": 0,
                "controlSocketRemoved": True,
                "backendStopped": True,
                "terminationExitCode": code,
            }
            args.output.write_text(json.dumps(proof, indent=2) + "\n")
            print(json.dumps(proof))
        except Exception:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    tail.extend(os.read(master, 65536))
                except OSError:
                    pass
            print(tail.decode(errors="replace"), file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            os.close(master)
finally:
    server.shutdown()
    server.server_close()
