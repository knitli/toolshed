"""Explicit foreground Codex launcher with read-only, session-local presence."""

import hashlib
import fcntl
import json
import os
from pathlib import Path
import pty
import signal
import socket
import stat
import subprocess  # nosec B404 - only the explicitly qualified executable is launched
import threading
import termios
import time
from uuid import uuid4

from .native_reader import NativeBridge, uuid
from .native_terminal import run_terminal
from .security import ensure_private_directory

# Exact executable used by the committed durable-v3 packaged recovery proof.
QUALIFIED_SHA256 = "0fb3a5de06ab2ccb8dcc20c11cb71cad1f0c1b85fbfa3a5c6fd16ca1f57d22de"


def _claim_terminal():
    # Popen has performed setsid before this callback. Launch happens before
    # this module creates any threads; fd 0 is the already opened PTY slave.
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class LaunchError(ValueError):
    """A bounded failure code, never child output or configuration."""


def launch_environment(environment):
    """Keep user Codex configuration, refusing injected native/loader authority."""
    if any(key.startswith(("LD_", "DYLD_", "CODEX_NATIVE_BRIDGE_", "CODEX_BRIDGE_ADOPTION_"))
           or key == "CODEX_SELECTION_WITNESS_FD" for key in environment):
        raise LaunchError("unsafe_launch_environment")
    return dict(environment)


def qualified_binary(binary, digest):
    """Require an explicit regular executable matching the reviewed prototype."""
    binary = Path(binary)
    if not binary.is_absolute() or digest != QUALIFIED_SHA256:
        raise LaunchError("unqualified_native_binary")
    if any(part.is_symlink() for part in (binary, *binary.parents)):
        raise LaunchError("unsafe_native_binary")
    for directory in binary.parents:
        info = directory.stat()
        # A root-owned sticky temporary directory cannot let another user
        # replace our owned entry; other writable ancestors are not accepted.
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (info.st_uid not in (0, os.getuid())
                or (info.st_mode & 0o022 and not sticky_root)):
            raise LaunchError("unsafe_native_binary")
    with binary.open("rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022
                or info.st_uid not in (0, os.getuid()) or not info.st_mode & 0o111):
            raise LaunchError("unsafe_native_binary")
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            raise LaunchError("native_binary_hash_mismatch")
    return binary


def session_path(state_dir, session_id):
    if not uuid(session_id):
        raise LaunchError("invalid_session_id")
    return Path(state_dir) / ("c-" + session_id + ".sock")


def session_status(state_dir, session_id):
    """Query one explicitly identified live launcher; never discover clients."""
    state_dir = Path(state_dir).absolute()
    if any(part.is_symlink() for part in (state_dir, *state_dir.parents)):
        raise LaunchError("unsafe_client_state")
    directory = state_dir.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
            or stat.S_IMODE(directory.st_mode) != 0o700):
        raise LaunchError("unsafe_client_state")
    path = session_path(state_dir, session_id)
    info = path.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise LaunchError("unsafe_client_socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        deadline = time.monotonic() + 2
        _remaining(channel, deadline)
        channel.connect(str(path))
        _remaining(channel, deadline)
        channel.sendall(b'{"command":"status"}\n')
        data = bytearray()
        while b"\n" not in data and len(data) <= 4096:
            _remaining(channel, deadline)
            chunk = channel.recv(4097 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 4096 or not data.endswith(b"\n"):
            raise LaunchError("invalid_client_status")
        return json.loads(data)


def _remaining(channel, deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("client_status_timeout")
    channel.settimeout(seconds)


class NativeClient:
    """Own one private v3 bridge; presence does not attach or admit a runtime."""

    def __init__(self, bridge, *, expected_thread=None):
        """Track one explicit bridge and optional exact resume selection."""
        if expected_thread is not None and not uuid(expected_thread):
            raise LaunchError("invalid_resume_thread")
        self.bridge = bridge
        self.expected_thread = expected_thread
        self.ready = False
        self.lock = threading.Lock()

    def synchronize(self):
        # Startup response is deliberately discarded; it grants no selection.
        with self.lock:
            self.bridge.exchange({}, 30)
            self.ready = True

    def status(self):
        value = {"automaticWakeEnabled": False, "attached": False,
                 "receiptVersion": 3, "selection": "unavailable"}
        if not self.ready:
            return value
        with self.lock:
            try:
                witness = self.bridge.challenge_readonly()
            except ValueError:
                return value
        if witness is not None and witness["eligible"] and time.monotonic() < self.bridge.valid_until and (
                self.expected_thread is None or witness["threadId"] == self.expected_thread):
            value.update(selection="selected", threadId=witness["threadId"],
                         clientId=witness["clientId"],
                         serverInstanceId=witness["serverInstanceId"],
                         serverGeneration=witness["serverGeneration"],
                         generation=witness["generation"])
        return value


def _control(listener, client, stop):
    while not stop.is_set():
        try:
            channel, _ = listener.accept()
        except TimeoutError:
            continue
        except OSError:
            return
        with channel:
            deadline = time.monotonic() + 2
            try:
                data = bytearray()
                while b"\n" not in data and len(data) < 128:
                    _remaining(channel, deadline)
                    chunk = channel.recv(128 - len(data))
                    if not chunk:
                        break
                    data.extend(chunk)
                value = (client.status() if bytes(data) == b'{"command":"status"}\n'
                         else {"reason": "unsupported_command"})
                _remaining(channel, deadline)
                channel.sendall(json.dumps(value).encode() + b"\n")
            except (OSError, ValueError):
                pass


def _watch_child(pid, stop):
    # Observe exit without reaping: the owned PID must stay reserved until the
    # cleanup signal. PTY EOF alone is not reliable for an unreaped macOS child.
    while not stop.is_set():
        try:
            result = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            # Cleanup may already have reaped after stop was set.
            stop.set()
            return
        if result is not None:
            stop.set()
            return
        stop.wait(0.1)


def launch(state_dir, binary, digest, cwd, *, resume=None):
    """Run a visible native TUI; expose only read-only per-session status."""
    if threading.current_thread() is not threading.main_thread() or threading.active_count() != 1:
        raise LaunchError("launch_requires_single_thread")
    if not os.isatty(0) or not os.isatty(1):
        raise LaunchError("interactive_terminal_required")
    env = launch_environment(os.environ)
    if resume is not None and not uuid(resume):
        raise LaunchError("invalid_resume_thread")
    cwd = Path(cwd).resolve(strict=True)
    if not cwd.is_dir():
        raise LaunchError("invalid_client_directory")
    ensure_private_directory(state_dir)
    session_id = str(uuid4())
    path = session_path(state_dir, session_id)
    parent = child = listener = bridge = process = None
    master = slave = None
    workers = []
    stop = threading.Event()
    interrupted = threading.Event()
    startup_failed = threading.Event()
    previous = {}

    def stop_launch(signum, _frame):
        if signum == signal.SIGINT:
            interrupted.set()
        stop.set()

    def check_stop():
        if stop.is_set():
            if interrupted.is_set():
                raise KeyboardInterrupt
            raise LaunchError("native_launch_interrupted")

    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[sig] = signal.signal(sig, stop_launch)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(4)
        listener.settimeout(0.2)
        parent, child = socket.socketpair()
        bridge = NativeBridge(parent, receipt_version=3)
        master, slave = pty.openpty()
        env.update(CODEX_NATIVE_BRIDGE_FD=str(child.fileno()),
                   CODEX_NATIVE_BRIDGE_RECEIPT_VERSION="3")
        binary = qualified_binary(binary, digest)
        check_stop()
        command = [str(binary), "--no-alt-screen", "-C", str(cwd)]
        if resume:
            command += ["resume", resume]
        process = subprocess.Popen(  # nosec B603 - qualified absolute native executable
            command, env=env, cwd=cwd, stdin=slave, stdout=slave, stderr=slave,
            pass_fds=(child.fileno(),), start_new_session=True,
            preexec_fn=_claim_terminal,
        )
        check_stop()
        child.close()
        os.close(slave)
        slave = None
        client = NativeClient(bridge, expected_thread=resume)

        def synchronize():
            try:
                client.synchronize()
            except (OSError, ValueError):
                startup_failed.set()
                stop.set()

        for target, arguments in (
            (synchronize, ()), (_control, (listener, client, stop)),
            (_watch_child, (process.pid, stop)),
        ):
            worker = threading.Thread(target=target, args=arguments, daemon=True)
            workers.append(worker)
            worker.start()
        print("Local Codex session: " + session_id + " (automatic delivery disabled)", flush=True)
        run_terminal(master, stop_event=stop)
    finally:
        stop.set()
        try:
            if bridge is not None:
                bridge.close()
            elif parent is not None:
                parent.close()
            if child is not None:
                child.close()
            if listener is not None:
                listener.close()
            # No poll/wait occurs before this sole group signal: the unreaped child
            # retains its PID, preventing reuse from targeting another process group.
            try:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        # Darwin can return EPERM for a zombie-only group. Keep
                        # the child unreaped while checking this exact identity;
                        # a still-running leader remains a cleanup failure.
                        exited = os.waitid(os.P_PID, process.pid,
                                           os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        if exited is None:
                            raise
                    process.wait(timeout=5)
            finally:
                for worker in workers:
                    worker.join(timeout=1)
                for fd in (master, slave):
                    if fd is not None:
                        os.close(fd)
                path.unlink(missing_ok=True)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    if interrupted.is_set():
        raise KeyboardInterrupt
    if startup_failed.is_set():
        raise LaunchError("native_bridge_startup_failed")
    return process.returncode if process.returncode >= 0 else 128 - process.returncode
