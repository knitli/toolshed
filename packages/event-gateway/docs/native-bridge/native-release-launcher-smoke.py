"""Exercise installed foreground launcher with a real PTY and disposable config."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess  # nosec B404 - Launches only the verified isolated interpreter and qualified native candidate.
import sys
import tempfile
import termios
import threading
import time
from uuid import uuid4


def require(condition, message="foreground qualification check failed"):
    if not condition:
        raise AssertionError(message)


def installed_preflight(package_source):
    require(sys.flags.isolated, "qualification requires Python -I")
    path = Path(__file__).with_name("qualification-installed.py")
    spec = importlib.util.spec_from_file_location("qualification_installed", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    proof = helper.verify_installed(package_source)
    proof["preflightSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    helper.verified_python()
    return proof


class Model(BaseHTTPRequestHandler):
    def do_POST(self):
        self.server.calls += 1
        self.send_error(500)

    def log_message(self, *_):
        pass


def write_config(root, port):
    home = root / "codex-home"
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text(
        'check_for_update_on_startup=false\nmodel="mock-model"\nmodel_provider="qualification"\n'
        '[model_providers.qualification]\nname="Synthetic qualification"\n'
        f'base_url="http://127.0.0.1:{port}"\nwire_api="responses"\nrequires_openai_auth=false\n'
        "[analytics]\nenabled=false\n[feedback]\nenabled=false\n"
        '[otel]\nexporter="none"\ntrace_exporter="none"\nmetrics_exporter="none"\n'
        f'[projects.{json.dumps(str(root))}]\ntrust_level="trusted"\n'
    )
    return home


def stop_launcher(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


@contextmanager
def foreground_process(root, home, argv):
    master, slave = pty.openpty()
    process = None
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        process = subprocess.Popen(  # nosec B603 - argv uses verified Python, isolated imports and a digest-qualified candidate.
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
        slave = None
        yield process, master
    finally:
        try:
            stop_launcher(process)
        finally:
            if slave is not None:
                os.close(slave)
            os.close(master)


def drain(master, tail):
    if not select.select([master], [], [], 0.1)[0]:
        return
    try:
        data = os.read(master, 65536)
    except OSError:
        return
    cursor_query = b"\x1b[6n" in bytes(tail[-3:]) + data
    tail.extend(data)
    del tail[:-16384]
    if cursor_query:
        os.write(master, b"\x1b[1;1R")


def current_selection(launcher, state):
    sockets = list(state.glob("c-*.sock")) if state.exists() else []
    if not sockets:
        return None
    require(len(sockets) == 1, "unexpected extra client socket")
    session = sockets[0].name[2:-5]
    try:
        status = launcher.session_status(state, session)
        if status["selection"] != "selected":
            return None
        binding = launcher.session_binding(state, session)
        challenge = launcher.session_challenge(state, session, str(uuid4()), binding)
    except (ConnectionRefusedError, FileNotFoundError, launcher.LaunchError):
        return None
    if binding["threadId"] != status["threadId"]:
        return None
    return sockets[0], status, binding, challenge


def wait_selection(launcher, state, process, master, tail):
    deadline = time.monotonic() + 45
    while True:
        require(process.poll() is None, tail.decode(errors="replace"))
        require(time.monotonic() < deadline, tail.decode(errors="replace"))
        drain(master, tail)
        selection = current_selection(launcher, state)
        if selection is not None:
            return selection


def check_selection(status, binding, challenge):
    require(status["selection"] == "selected")
    require(binding["threadId"] == status["threadId"])
    require(challenge["witness"]["eligible"])
    require(all(challenge["witness"][key] == value for key, value in binding.items()))
    require(time.monotonic() < challenge["validUntilMonotonic"])
    require(status["automaticWakeEnabled"] is False and status["attached"] is False)


def quit_foreground(process, master, tail, socket_path, backend_pid):
    os.write(master, b"/quit")
    time.sleep(0.2)
    os.write(master, b"\r")
    deadline = time.monotonic() + 15
    while process.poll() is None:
        require(time.monotonic() < deadline, "foreground quit timed out")
        drain(master, tail)
    code = process.wait(timeout=5)
    require(code == 0, f"foreground launcher exited {code}")
    require(not socket_path.exists())
    try:
        os.kill(backend_pid, 0)
    except ProcessLookupError:
        return code
    raise AssertionError("backend survived foreground launcher cleanup")


def qualify(args, launcher, server):
    require(
        launcher.qualified_binary(args.binary, launcher.QUALIFIED_SHA256) == args.binary
    )
    # Unix socket paths must fit macOS's 104-byte limit even with its long default TMPDIR.
    temporary_root = Path("/tmp").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nr-", dir=temporary_root) as directory:
        root = Path(directory)
        state = root / "state"
        home = write_config(root, server.server_port)
        child_cache = root / "child-pycache"
        child_cache.mkdir(mode=0o700)
        require(not any(child_cache.iterdir()), "child import cache must start empty")
        argv = [
            sys.executable,
            "-I",
            "-B",
            "-X",
            f"pycache_prefix={child_cache}",
            "-m",
            "event_gateway.cli",
            "--state-dir",
            str(state),
            "launch",
            "--codex-binary",
            str(args.binary),
            "--binary-sha256",
            launcher.QUALIFIED_SHA256,
            "--cwd",
            str(root),
        ]
        tail = bytearray()
        with foreground_process(root, home, argv) as (process, master):
            try:
                socket_path, status, binding, challenge = wait_selection(
                    launcher, state, process, master, tail
                )
                check_selection(status, binding, challenge)
                require(server.calls == 0)
                code = quit_foreground(
                    process, master, tail, socket_path, binding["backendPid"]
                )
                require(server.calls == 0, "unexpected model request during cleanup")
                require(not any(child_cache.iterdir()), "child wrote unexpected bytecode")
            except Exception:
                drain(master, tail)
                print(tail.decode(errors="replace"), file=sys.stderr)
                raise
        return {
            "result": "PASS",
            "binarySha256": launcher.QUALIFIED_SHA256,
            "python": sys.executable,
            "argv": argv,
            "installedLauncherSha256": hashlib.sha256(
                Path(launcher.__file__).read_bytes()
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
            "childBytecodeCacheFreshAndEmpty": True,
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--package-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    provenance = installed_preflight(args.package_source)
    launcher = importlib.import_module("event_gateway.launcher")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    server.calls = 0
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        proof = qualify(args, launcher, server)
        proof["installedPackagePreflight"] = provenance
        args.output.write_text(json.dumps(proof, indent=2) + "\n")
        print(json.dumps(proof))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
