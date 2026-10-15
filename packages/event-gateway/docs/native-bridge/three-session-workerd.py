#!/usr/bin/env python3
"""Run three isolated real Codex CLIs through the production daemon and local workerd."""

import argparse
import asyncio
import base64
import ctypes
from contextlib import ExitStack, closing, contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
from functools import partial, partialmethod
import http.client
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import select
import signal
import socket
import sqlite3
import stat
import subprocess  # nosec B404 - launches only the supplied Node fixture broker.
import sys
import tempfile
import threading
import time
import warnings
from types import SimpleNamespace
from uuid import uuid4


HERE = Path(__file__).resolve().parent
PRINCIPAL = "qualification@example.com"
AGENT = "pilot"
ORIGIN = "https://events.example.com"
FIXTURE_ACCESS = "fixture-access"
FIXTURE_AGENT = "fixture-agent"
GATEWAY_TEMP_PREFIX = "three-gateway-"
# tempfile adds eight ASCII characters; launcher.session_path uses c-<UUID>.sock.
DARWIN_SOCKET_PATH_BYTES = 104
GATEWAY_SOCKET_SUFFIX = f"/{GATEWAY_TEMP_PREFIX}{'x' * 8}/state/c-{'0' * 36}.sock"
DARWIN_TEMP_ROOT_BYTES = DARWIN_SOCKET_PATH_BYTES - 1 - len(GATEWAY_SOCKET_SUFFIX.encode("ascii"))

args = None
binary = node = cloud_source = package_source = None
launcher = daemon = client_runtime = gateway_cli = Store = CloudClient = Credentials = None
SessionNativeBridge = private_key_type = serialization = None
smoke = host_qualifier = installed_helper = installed_proof = None
identity_fields = ()


def require(value, message):
    if not value:
        raise AssertionError(message)


def require_all(message, *conditions):
    require(all(conditions), message)


def is_exact_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def require_fixture_port(port):
    require(is_exact_int(port) and 1024 <= port <= 65535,
            "workerd fixture port outside range")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "fixture module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else str(value).encode()).hexdigest()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class ModelProvider(BaseHTTPRequestHandler):
    """Local deterministic provider; it never forwards a request off this host."""

    def log_message(self, *_):
        pass

    def do_POST(self):
        with self.server.request_lock:
            self.server.active_requests += 1
        try:
            self._respond()
        finally:
            with self.server.request_lock:
                self.server.active_requests -= 1

    def _respond(self):
        try:
            require(self.path == "/v1/responses", "unexpected model endpoint")
            require(not self.headers.get("Authorization"), "unexpected model credentials")
            size = int(self.headers["Content-Length"])
            require(0 < size < 4_000_000, "model request outside bound")
            request = json.loads(self.rfile.read(size))
            if getattr(self.server, "evidence", None):
                self.server.evidence("providerRequest", {"phase": self.server.phase, "request": request})
            qualifier = self.server.qualifier
            kind = qualifier.request_kind(request)
            with self.server.request_lock:
                self.server.requests.append(kind)
                if kind == "main":
                    self.server.main_requests.append(request)
                    self.server.turn_main_requests.append(request)
                    require(len(self.server.turn_main_requests) <= 2, "extra main request")
                else:
                    self.server.turn_title_count += 1
                    require(self.server.turn_title_count == 1, "extra title request")
                main_requests = len(self.server.turn_main_requests)
            with self.server.hold_lock:
                hold = kind == "main" and self.server.hold_next
                self.server.hold_next = False if hold else self.server.hold_next
                if hold:
                    self.server.hold_deadline = time.monotonic() + 60
                    self.server.hold_state = "held"
                    self.server.hold_started.set()
            if hold:
                released = self.server.release_hold.wait(60)
                with self.server.hold_lock:
                    self.server.hold_state = "released" if released else "timed_out"
                require(released, "controlled model hold expired")
            if kind == "title":
                item = {"type": "message", "role": "assistant", "id": "three-title",
                        "content": [{"type": "output_text", "text": '{"title":"Controlled event"}'}]}
                events = [{"type": "response.output_item.done", "item": item},
                          qualifier.completed("three-title")]
            elif main_requests == 1:
                item = {"type": "custom_tool_call", "call_id": qualifier.CALL_ID,
                        "name": "exec", "input": self.server.program}
                events = [{"type": "response.created", "response": {"id": "three-main-" + str(main_requests)}},
                          {"type": "response.output_item.done", "item": item},
                          qualifier.completed("three-main-" + str(main_requests))]
            else:
                qualifier.verify_output(self.server.turn_main_requests, self.server.nonce)
                identity = "three-main-" + str(main_requests)
                item = {"type": "message", "role": "assistant", "id": identity,
                        "content": [{"type": "output_text", "text": "Offline read completed."}]}
                events = [{"type": "response.output_item.done", "item": item},
                          qualifier.completed(identity)]
            payload = "".join("data: " + json.dumps(event) + "\n\n" for event in events).encode()
            if getattr(self.server, "evidence", None):
                self.server.evidence("providerResponse", {"phase": self.server.phase, "events": events})
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            if kind == "main" and main_requests == 2:
                with self.server.request_lock:
                    self.server.turn_verified = True
        except Exception as error:
            with self.server.request_lock:
                self.server.errors.append({"type": type(error).__name__, "message": str(error)[:160],
                                           "phase": self.server.phase,
                                           "kind": locals().get("kind"),
                                           "mainCount": len(self.server.main_requests),
                                           "turnMainCount": len(self.server.turn_main_requests)})
            self.send_error(500)


def stop_model(server, thread):
    server.release_hold.set()
    server.shutdown()
    server.server_close()
    thread.join(5)
    require(not thread.is_alive(), "model fixture did not stop")


def model_idle(server):
    with server.request_lock:
        return server.active_requests == 0


def require_model_held(server):
    with server.hold_lock:
        require(server.hold_state == "held" and time.monotonic() < server.hold_deadline
                and server.hold_started.is_set() and not server.release_hold.is_set(),
                "primary model response is no longer held")


def require_model_turn_complete(server):
    with server.request_lock:
        require(server.active_requests == 0 and server.turn_verified
                and len(server.turn_main_requests) == 2 and not server.errors,
                "source-read turn must complete successfully with exactly two main requests")


def private_temp_root():
    root = Path(os.environ["TMPDIR"]).resolve(strict=True)
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o077, "fixture TMPDIR must be private and owned")
    installed_helper._ancestors(root / "scratch")
    if sys.platform == "darwin":
        require(len(os.fsencode(root)) <= DARWIN_TEMP_ROOT_BYTES,
                f"fixture TMPDIR resolved path must be at most {DARWIN_TEMP_ROOT_BYTES} bytes "
                "for macOS Unix sockets")
    return root


def verify_outer_containment(scratch):
    import pwd

    require(sys.platform == "darwin", "outer containment requires macOS kernel checks")
    library = ctypes.CDLL("/usr/lib/libsandbox.1.dylib", use_errno=True)
    check = library.sandbox_check
    check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    check.restype = ctypes.c_int
    quiet = ctypes.c_int.in_dll(library, "SANDBOX_CHECK_NO_REPORT").value
    require(quiet > 0 and quiet & 1 == 0, "sandbox no-report flag invalid")

    def query(operation, path=None):
        ctypes.set_errno(0)
        arguments = (os.getpid(), operation, quiet if path is None else quiet | 1)
        result = check(*arguments, ctypes.c_char_p(os.fsencode(path))) if path is not None else check(*arguments)
        require(result in (0, 1) and ctypes.get_errno() == 0, "sandbox permission query failed")
        return result

    ctypes.set_errno(0)
    require(check(os.getpid(), None, 0) == 1 and ctypes.get_errno() == 0,
            "outer containment requires an active kernel sandbox")
    owner_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    owner_roots = (owner_home, owner_home / ".codex", Path(sys.prefix).parent / "codex-home")
    require(all(root.is_absolute() and not root.is_relative_to(scratch) for root in owner_roots),
            "owner state must be outside fixture scratch")
    require(all(root.is_dir() for root in owner_roots) and Path("/private/tmp").is_dir(),
            "containment denial probes require existing directories")
    with tempfile.NamedTemporaryFile(prefix="outer-containment-", dir=scratch) as probe:
        probe.write(b"synthetic containment probe\n")
        probe.flush()
        for operation in (b"file-read-data", b"file-write-create", b"file-write-data"):
            require(query(operation, probe.name) == 0, "outer sandbox refused owned scratch control")
        for root in owner_roots:
            require(query(b"file-read-data", root) == 1, "outer sandbox permits owner-state reads")
        outside_probe = Path("/private/tmp") / f"event-three-denied-{uuid4()}"
        require(not outside_probe.is_relative_to(scratch), "write denial probe must be outside scratch")
        require(query(b"file-write-create", outside_probe) == 1,
                "outer sandbox permits writes outside fixture scratch")
        # NONE tests default denial; address-specific exceptions require an independent profile audit.
        for operation in (b"network-outbound", b"network-inbound"):
            require(query(operation) == 1, "outer sandbox permits unqualified network access")
    return {"mode": "verified-outer-sandbox", "kernelSandboxActive": True,
            "scratchReadWriteAllowed": True, "ownerStateRootReadDenied": True,
            "outsideScratchProbeWriteDenied": True, "defaultNetworkDenied": True,
            "addressSpecificPolicyRequiresIndependentAudit": True}


def native_launch_argv(profile, cache, state, root):
    argv = host_qualifier.launch_argv(profile, cache, state, binary, root)
    if args.outer_contained:
        verify_outer_containment(private_temp_root())
        require(argv[:3] == ["/usr/bin/sandbox-exec", "-f", str(profile)]
                and len(argv) > 3 and argv[3] == sys.executable,
                "native sandbox launch prefix changed")
        return argv[3:]
    return argv


def free_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def private_json(path, value):
    raw = (json.dumps(value, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


@contextmanager
def evidence_archive(path):
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor, evidence = None, None
    try:
        descriptor = os.open(path.name, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        evidence = SimpleNamespace(fd=descriptor, directory_fd=directory, path=path,
                                   identity=os.fstat(descriptor), directory_identity=os.fstat(directory),
                                   lock=threading.Condition(), size=0, sealed=False, failed=False,
                                   closing=False, active=0, drained=False)
        record_evidence(SimpleNamespace(evidence=evidence), "archive", {"version": 1})
        yield evidence
    finally:
        if evidence is not None:
            with evidence.lock:
                evidence.sealed = True
                os.close(descriptor)
        elif descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def verify_evidence(evidence):
    opened, named = os.fstat(evidence.fd), evidence.path.lstat()
    parent = evidence.path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and (parent.st_dev, parent.st_ino)
            == (evidence.directory_identity.st_dev, evidence.directory_identity.st_ino),
            "private evidence directory changed")
    require(all(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.getuid() and info.st_nlink == 1
                and (info.st_dev, info.st_ino) == (evidence.identity.st_dev, evidence.identity.st_ino)
                and info.st_size == evidence.size for info in (opened, named)),
            "private evidence changed")


def record_evidence(ctx, kind, value):
    raw = (json.dumps({"kind": kind, "value": value}, separators=(",", ":")) + "\n").encode()
    evidence = ctx.evidence
    with evidence.lock:
        require(not evidence.sealed, "private evidence is sealed")
        try:
            require(len(raw) <= 4_100_000 and evidence.size + len(raw) <= 64 * 1024 * 1024,
                    "private evidence exceeds bounded archive")
            verify_evidence(evidence)
            remaining = memoryview(raw)
            while remaining:
                written = os.write(evidence.fd, remaining)
                require(written > 0, "private evidence write made no progress")
                evidence.size += written
                remaining = remaining[written:]
        except BaseException:
            evidence.failed = True
            raise


def sync_evidence(ctx):
    evidence = ctx.evidence
    with evidence.lock:
        verify_evidence(evidence)
        os.fsync(evidence.fd)
        os.fsync(evidence.directory_fd)
        verify_evidence(evidence)


def seal_evidence(ctx):
    evidence = ctx.evidence
    with evidence.lock:
        require(evidence.drained and evidence.active == 0 and not evidence.failed,
                "private evidence observers are not settled")
        evidence.sealed = True
        sync_evidence(ctx)
        os.lseek(evidence.fd, 0, os.SEEK_SET)
        hasher = hashlib.sha256()
        while chunk := os.read(evidence.fd, 1024 * 1024):
            hasher.update(chunk)
        verify_evidence(evidence)
        return {"sha256": hasher.hexdigest(), "bytes": evidence.size}


async def drain_native_observers(ctx):
    with ctx.evidence.lock:
        ctx.evidence.closing = True
        if ctx.evidence.drained:
            return
    # Cancellation does not stop to_thread work, including callers outside the inner observer.
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        await asyncio.get_running_loop().shutdown_default_executor(timeout=30)
    with ctx.evidence.lock:
        require(ctx.evidence.active == 0, "native observers did not drain")
        ctx.evidence.drained = True


def snapshot_evidence(ctx, stage):
    record_evidence(ctx, "checkpoint", stage)
    database = ctx.state / "ledger.sqlite"
    missing = []
    if database.exists():
        with closing(sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True, timeout=3)) as db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN")
            present = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name IN ('attachments', 'deliveries', 'attempts')",
            )}
            for table, query in (("attachments", "SELECT * FROM attachments"),
                                 ("deliveries", "SELECT * FROM deliveries"),
                                 ("attempts", "SELECT * FROM attempts")):
                if table not in present:
                    missing.append(table)
                    record_evidence(ctx, "missingLedgerTable", {"stage": stage, "table": table})
                    continue
                rows = db.execute(query).fetchmany(4097)
                require(len(rows) <= 4096, "private database snapshot exceeds row bound")
                record_evidence(ctx, "database", {"stage": stage, "table": table,
                                                "rows": [dict(row) for row in rows]})
    else:
        missing = ["attachments", "deliveries", "attempts"]
        record_evidence(ctx, "missingLedgerDatabase", {"stage": stage, "tables": missing})
    ctx.fixture("/fixture/read")
    return missing


def post(address, secret, path, body=None, headers=None, *, limit=65_536):
    connection = http.client.HTTPConnection("127.0.0.1", address, timeout=8)
    try:
        raw = body if isinstance(body, bytes) else json.dumps(body or {}, separators=(",", ":")).encode()
        request_headers = {
            "x-fixture-secret": secret,
            "cf-access-token": FIXTURE_ACCESS,
            "authorization": "Bearer " + FIXTURE_AGENT,
            "content-type": "application/json",
        }
        if headers:
            request_headers.update(headers)
        connection.request("POST", path, raw, request_headers)
        response = connection.getresponse()
        payload = response.read(limit + 1)
        require(len(payload) <= limit, "fixture response outside bound")
        return response.status, {"content-type": response.getheader("content-type") or ""}, payload
    finally:
        connection.close()


def start_broker():
    broker_log = tempfile.TemporaryFile()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": tempfile.gettempdir(),
        "TMPDIR": tempfile.gettempdir(),
        "TMP": tempfile.gettempdir(),
        "TEMP": tempfile.gettempdir(),
        "FIXTURE_CLOUD_SOURCE": str(cloud_source),
        "FIXTURE_THREE_SESSION_CANARY": "true",
        "FIXTURE_ESBUILD": str(Path(args.esbuild).resolve(strict=True)),
        "FIXTURE_MINIFLARE": str(Path(args.miniflare).resolve(strict=True)),
        "FIXTURE_ENTRY_PORT": str(args.entry_port),
        "FIXTURE_LOOPBACK_PORT": str(args.loopback_port),
        "FIXTURE_BROKER_PORT": str(args.broker_port),
    }
    process = subprocess.Popen(  # nosec B603 - explicit verified Node, fixed broker, closed fixture environment.
        [str(node), str(HERE / "coupled-workerd-broker.mjs")], cwd=tempfile.gettempdir(),
        env=env, stdout=subprocess.PIPE, stderr=broker_log, text=True, start_new_session=True,
    )
    try:
        require(process.stdout is not None and select.select([process.stdout], [], [], 30)[0],
                "workerd fixture startup timed out")
        address = json.loads(process.stdout.readline())
        require(is_exact_int(address.get("port")) and isinstance(address.get("secret"), str),
                "workerd fixture handshake invalid")
        require_fixture_port(address["port"])
        require(address["port"] == args.broker_port and address["secret"],
                "workerd fixture handshake did not match the requested broker endpoint")
        return process, broker_log, address
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        broker_log.flush()
        broker_log.seek(0)
        detail = broker_log.read().decode(errors="replace")[-2048:]
        broker_log.close()
        raise RuntimeError("workerd fixture startup failed: " + detail)


def port_is_closed(port):
    require_fixture_port(port)
    probe = socket.socket()
    probe.settimeout(0.25)
    try:
        probe.connect(("127.0.0.1", port))
        return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False
    finally:
        probe.close()


def process_group_members(group_id):
    require(is_exact_int(group_id) and group_id > 1, "process group ID outside range")
    if sys.platform == "darwin":
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_pids = library.proc_listallpids
        list_pids.argtypes = [ctypes.c_void_p, ctypes.c_int]
        list_pids.restype = ctypes.c_int
        count = list_pids(None, 0)
        require(0 < count < 100000, "Darwin process count outside range")
        capacity = min(count + 128, 100000)
        for attempt in range(3):
            pids = (ctypes.c_int * capacity)()
            count = list_pids(pids, ctypes.sizeof(pids))
            require(0 < count <= capacity, "Darwin process listing count outside range")
            if count < capacity:
                break
            require(attempt < 2 and capacity < 100000, "Darwin process listing saturated")
            capacity = min(capacity * 2, 100000)
        # PID 0 is the kernel; vanished processes are the only acceptable lookup failure.
        positive_pids = [pid for pid in pids[:count] if pid > 0]
        require(all(pid >= 0 for pid in pids[:count]) and os.getpid() in positive_pids
                and len(set(positive_pids)) == len(positive_pids),
                "Darwin process listing was malformed or incomplete")
        members = []
        for pid in positive_pids:
            try:
                process_group_id = os.getpgid(pid)
            except ProcessLookupError:
                continue
            if process_group_id == group_id:
                members.append(pid)
        return members
    result = subprocess.run(  # nosec B603 - fixed system ps executable and fixed output-only arguments.
        ["/bin/ps", "-axo", "pgid=,pid="], check=True, capture_output=True,
        text=True, timeout=5,
    )
    require(isinstance(result.stdout, str) and result.stdout.strip(),
            "process listing was empty or malformed")
    members = []
    for line in result.stdout.splitlines():
        fields = line.split()
        require(len(fields) == 2 and all(field.isascii() and field.isdecimal() for field in fields),
                "process listing row was malformed")
        process_group_id, process_id = map(int, fields)
        require(process_group_id >= 0 and process_id > 0,
                "process listing row was outside range")
        if process_group_id == group_id:
            members.append(process_id)
    return members


def process_is_running(pid):
    if not is_exact_int(pid) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def verify_native_cleanup(process, state, observations, result):
    unexpected_members = process_group_members(process.pid)
    if unexpected_members:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and process_group_members(process.pid):
            time.sleep(0.05)
        if process_group_members(process.pid):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and process_group_members(process.pid):
            time.sleep(0.05)
    members_after_cleanup = process_group_members(process.pid)
    backend_pid = observations.get("backendPid")
    socket_path = observations.get("socketPath")
    backend_stopped = (is_exact_int(backend_pid) and backend_pid > 1
                       and not process_is_running(backend_pid))
    socket_owned = False
    if isinstance(socket_path, Path):
        try:
            socket_path.parent.resolve(strict=True).relative_to(state.resolve(strict=True))
            socket_owned = True
        except (OSError, ValueError):
            pass
    socket_removed = (socket_owned and not socket_path.exists() and not socket_path.is_symlink())
    result.update({
        "launcherExited": process.poll() is not None,
        "processGroupClosed": not members_after_cleanup,
        "unexpectedGroupMembersAfterLauncherExit": len(unexpected_members),
        "backendStopped": backend_stopped,
        "controlSocketRemoved": socket_removed,
        "boundedGroupCleanupUsed": bool(unexpected_members),
    })
    require(process.poll() is not None and not unexpected_members and not members_after_cleanup
            and backend_stopped and socket_removed,
            "native CLI cleanup failed: launcherExited=" + str(process.poll() is not None)
            + " initialGroupMembers=" + str(len(unexpected_members))
            + " remainingGroupMembers=" + str(len(members_after_cleanup))
            + " backendStopped=" + str(backend_stopped)
            + " controlSocketRemoved=" + str(socket_removed))


def stop_broker(process, broker_log):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    ports = (args.entry_port, args.loopback_port, args.broker_port)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not process_group_members(process.pid) and all(port_is_closed(port) for port in ports):
            break
        time.sleep(0.05)
    members = process_group_members(process.pid)
    ports_closed = all(port_is_closed(port) for port in ports)
    broker_log.flush()
    broker_log.seek(0)
    detail = broker_log.read().decode(errors="replace")[-2048:]
    broker_log.close()
    accepted_signal_codes = (-signal.SIGTERM, 128 + signal.SIGTERM)
    require(process.returncode in (0,) + accepted_signal_codes and not members and ports_closed,
            "workerd fixture cleanup failed: exit=" + str(process.returncode)
            + " ownedGroupMembers=" + str(len(members)) + " portsClosed=" + str(ports_closed)
            + " " + detail)
    return {"exitCode": process.returncode,
            "intentionalTermAccepted": process.returncode in accepted_signal_codes,
            "ownedProcessGroupClosed": True, "loopbackPortsClosed": True}


def configure(parsed):
    global args, binary, node, cloud_source, package_source, launcher, daemon, client_runtime, gateway_cli
    global Store, CloudClient, Credentials, SessionNativeBridge
    global private_key_type, serialization, smoke, host_qualifier, installed_helper, installed_proof
    global identity_fields
    args = parsed
    output_path = Path(parsed.output)
    require(output_path.is_absolute() and output_path.name not in ("", ".", ".."),
            "proof output must be an absolute file path")
    output_parent = output_path.parent.resolve(strict=True)
    require(output_parent.is_dir(), "proof output parent must be an existing directory")
    output_path = output_parent / output_path.name
    sidecar_path = output_path.with_name(output_path.stem + ".private-causal.json")
    for candidate, description in ((output_path, "proof output"),
                                   (sidecar_path, "private causal sidecar"),
                                   (output_path.with_suffix(".private-evidence.jsonl"), "private evidence")):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        require(False, description + " must be new and must not be a symlink")
    parsed.output = str(output_path)
    require(sys.version_info >= (3, 13), "controlled acceptance requires Python 3.13+")
    package_source = Path(parsed.package_source).resolve(strict=True)
    require(package_source.name == "event_gateway", "package source must end at src/event_gateway")
    package_root = package_source.parents[1]
    installed_helper = load_module(
        "three_session_installed", package_root / "docs/native-bridge/qualification-installed.py",
    )
    installed_helper.verified_python()
    installed_proof = installed_helper.verify_installed(package_source)
    node = Path(installed_helper.verified_executable(parsed.node))
    binary = Path(parsed.binary).resolve(strict=True)
    cloud_source = Path(parsed.cloud_source).resolve(strict=True)
    require(cloud_source.is_dir()
            and cloud_source.parts[-5:] == ("apps", "os", "packages", "event-runtime", "src"),
            "cloud source must end at apps/os/packages/event-runtime/src")
    cloud_checkout = cloud_source.parents[4]
    require((cloud_checkout / ".git").exists(), "cloud source must be inside a Git checkout")
    git = Path("/usr/bin/git")
    require(git.is_file() and os.access(git, os.X_OK), "system git unavailable")
    git_probe = subprocess.run(  # nosec B603 - fixed read-only git command and validated checkout path.
        [str(git), "-C", str(cloud_checkout), "rev-parse", "--show-toplevel", "--verify", "HEAD"],
        check=True, capture_output=True, text=True, timeout=10,
        env={"PATH": "/usr/bin:/bin", "HOME": tempfile.gettempdir(),
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
             "GIT_OPTIONAL_LOCKS": "0"},
    )
    git_lines = git_probe.stdout.splitlines()
    require(len(git_lines) == 2, "Git checkout readback was malformed")
    git_root = Path(git_lines[0]).resolve(strict=True)
    require(git_root == cloud_checkout, "cloud source is not the supplied Git checkout")
    revision = git_lines[1].strip()
    require(revision == parsed.cloud_commit, "cloud source commit differs from proof input")
    require(len(set((parsed.entry_port, parsed.loopback_port, parsed.broker_port))) == 3,
            "workerd fixture ports must be distinct")
    for port in (parsed.entry_port, parsed.loopback_port, parsed.broker_port):
        require_fixture_port(port)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from event_gateway import client_runtime, cli as gateway_cli, daemon, launcher
    from event_gateway.cloud import CloudClient, Credentials
    from event_gateway.native import SessionNativeBridge
    from event_gateway.store import IDENTITY, Store

    require(launcher.QUALIFIED_SHA256 == parsed.binary_sha256, "installed launcher pin differs from candidate")
    launcher.qualified_binary(binary, parsed.binary_sha256)
    host = binary.with_name("codex-code-mode-host")
    require(hashlib.sha256(host.read_bytes()).hexdigest() == launcher.QUALIFIED_CODE_MODE_HOST_SHA256,
            "code mode host pin mismatch")
    from event_gateway import __file__ as installed_package
    require(Path(installed_package).resolve().is_relative_to(Path(sys.prefix).resolve()),
            "production package must come from the verified private wheel environment")

    host_qualifier = load_module(
        "three_session_host_qualifier", package_root / "docs/native-bridge/native-host-launcher-qualification.py",
    )
    smoke = host_qualifier.verified_helper("native-release-launcher-smoke.py")
    private_key_type, serialization = Ed25519PrivateKey, serialization
    identity_fields = IDENTITY


def make_model(stack, hold=False):
    # Each provider owns its verifier globals; C3 cannot change A/B's call identity.
    qualifier = load_module("three_session_model_qualifier", host_qualifier.__file__)
    qualifier.CALL_ID = "three-session-source-read-" + uuid4().hex
    server = ThreadingHTTPServer(("127.0.0.1", 0), ModelProvider)
    # server_close must join handlers before the archive receives its final hash.
    server.daemon_threads = False
    server.qualifier = qualifier
    server.evidence = None
    server.requests = []
    server.main_requests = []
    server.turn_main_requests = []
    server.turn_title_count = 0
    server.turn_verified = False
    server.phase = "initial"
    server.errors = []
    server.request_lock = threading.Lock()
    server.active_requests = 0
    server.hold_lock = threading.Lock()
    server.hold_next = hold
    server.hold_state = "idle"
    server.hold_deadline = 0
    server.hold_started = threading.Event()
    server.release_hold = threading.Event()
    if not hold:
        server.release_hold.set()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(stop_model, server, thread)
    return server


def wait_shared_selection(state, process, master, tail, known_sockets):
    deadline = time.monotonic() + 45
    while True:
        require(process.poll() is None, tail.decode(errors="replace"))
        require(time.monotonic() < deadline, tail.decode(errors="replace"))
        smoke.drain(master, tail)
        created = sorted(path for path in state.glob("c-*.sock")
                         if path.name not in known_sockets)
        require(len(created) <= 1, "one CLI created multiple native client sockets")
        if not created:
            continue
        socket_path = created[0]
        session_id = socket_path.name[2:-5]
        try:
            status = launcher.session_status(state, session_id)
            if status["selection"] != "selected":
                continue
            binding = launcher.session_binding(state, session_id)
            if binding["threadId"] != status["threadId"]:
                continue
            challenge = launcher.session_challenge(state, session_id, str(uuid4()), binding)
        except (ConnectionRefusedError, FileNotFoundError, launcher.LaunchError):
            continue
        smoke.check_selection(status, binding, challenge)
        return socket_path, status, binding, challenge


def start_pty_pump(stack, master, tail):
    stop = threading.Event()
    stats = {"bytesRead": 0, "readCount": 0}

    def pump():
        while not stop.is_set():
            try:
                count = smoke.drain(master, tail) or 0
            except OSError:
                return
            if count:
                stats["bytesRead"] += count
                stats["readCount"] += 1

    thread = threading.Thread(target=pump, name="three-session-pty-pump", daemon=True)
    thread.start()

    def stop_pump():
        stop.set()
        thread.join(2)
        require(not thread.is_alive(), "native PTY output pump did not stop")

    stack.callback(stop_pump)
    return stats


def native_session(stack, label, ctx, *, hold=False):
    temporary = tempfile.TemporaryDirectory(prefix="three-native-", dir=private_temp_root())
    root = Path(temporary.name)
    root.chmod(0o700)
    stack.callback(temporary.cleanup)
    # ExitStack joins the provider, persists its last records, then removes native scratch.
    stack.callback(sync_evidence, ctx)
    provider = make_model(stack, hold=hold)
    provider.evidence = lambda kind, value: record_evidence(ctx, kind, {"session": label, **value})
    provider.nonce = "three-session-source-" + label.lower() + "-" + uuid4().hex
    provider.source_nonce_sha256 = digest(provider.nonce)
    source = root / "fixture-source.txt"
    source.write_text(provider.nonce + "\n")
    provider.source_path = source
    provider.program = host_qualifier.source_program(source)
    home = smoke.write_config(root, provider.server_port)
    config = home / "config.toml"
    data = config.read_text().replace('model="mock-astra"', 'model="mock-model"')
    data = data.replace(f':{provider.server_port}"', f':{provider.server_port}/v1"')
    data = 'approval_policy="never"\nsandbox_mode="danger-full-access"\n' + data
    data += "\n[features]\ncode_mode_only=true\ncode_mode_host=true\napps=false\n"
    config.write_text(data)
    profile = root / "offline.sb"
    profile.write_text(host_qualifier.sandbox_profile(provider.server_port))
    cache = root / "child-cache"
    cache.mkdir(mode=0o700)
    state = Path(ctx.state)
    argv = native_launch_argv(profile, cache, state, root)
    known_sockets = {path.name for path in state.glob("c-*.sock")}
    observations = {}
    cleanup_result = {}
    # Registered before entering the foreground context so ExitStack verifies
    # state only after the launcher has received its bounded shutdown.
    process = None

    def check_native_cleanup():
        require(process is not None, "native launcher did not start")
        verify_native_cleanup(process, state, observations, cleanup_result)

    stack.callback(check_native_cleanup)
    process, master = stack.enter_context(smoke.foreground_process(root, home, argv))
    tail = bytearray()
    socket_path, status, binding, _ = wait_shared_selection(
        state, process, master, tail, known_sockets,
    )
    initially_selected_idle = (status["selection"] == "selected"
                               and status["automaticWakeEnabled"] is False
                               and status["attached"] is False)
    pty_pump_stats = start_pty_pump(stack, master, tail)
    session_id = socket_path.name[2:-5]
    observations.update({"backendPid": binding.get("backendPid"), "socketPath": socket_path})
    route = {"sessionId": session_id, "nativeThreadId": binding["threadId"], "nativeBinding": binding}
    bridge = SessionNativeBridge(state, route)
    return {
        "label": label, "root": root, "state": state, "provider": provider, "process": process,
        "master": master, "tail": tail, "socket": socket_path, "sessionId": session_id,
        "binding": binding, "route": route, "bridge": bridge,
        "ptyPumpStats": pty_pump_stats,
        "processCleanup": cleanup_result,
        "initiallySelectedIdle": initially_selected_idle,
    }


async def credentials():
    return Credentials(FIXTURE_ACCESS, FIXTURE_AGENT)


async def admit_runtime(cloud, session, runtime_id):
    binding = await asyncio.to_thread(launcher.session_binding, session["state"], session["sessionId"])
    intent = {
        "operation": "attach", "runtimeId": runtime_id,
        "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
        "expectedNativeBinding": binding,
    }
    challenge = await cloud.native_challenge(intent)
    evidence = await asyncio.to_thread(
        launcher.session_challenge, session["state"], session["sessionId"], challenge["challengeId"], binding,
    )
    attached = await cloud.attach(intent, challenge, evidence)
    require(attached["nativeBinding"] == binding, "workerd attached a different native binding")
    return {"intent": intent, "challenge": challenge, "evidence": evidence, "attached": attached}


def listener_delivery(port, signed):
    body = signed["body"].encode()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request("POST", "/v1/deliver", body, signed["headers"])
        response = connection.getresponse()
        payload = response.read(8193)
        require(len(payload) <= 8192, "listener response outside bound")
        return response.status, payload
    finally:
        connection.close()


def db_delivery(state, delivery_id):
    db_path = Path(state) / "ledger.sqlite"
    uri = "file:" + str(db_path) + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
        db.execute("PRAGMA busy_timeout=3000")
        row = db.execute("SELECT state FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
        attempt = db.execute("SELECT state FROM attempts WHERE delivery_id=?", (delivery_id,)).fetchone()
        return {"state": row[0] if row else None, "attemptState": attempt[0] if attempt else None}


def db_delivery_history(state, delivery_id):
    db_path = Path(state) / "ledger.sqlite"
    uri = "file:" + str(db_path) + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
        db.execute("PRAGMA busy_timeout=3000")
        db.row_factory = sqlite3.Row
        delivery = db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
        attempts = db.execute(
            "SELECT * FROM attempts WHERE delivery_id=? ORDER BY attempt_id", (delivery_id,),
        ).fetchall()
        return {
            "delivery": dict(delivery) if delivery is not None else None,
            "attempts": [dict(row) for row in attempts],
        }


def db_delivery_envelope_sha256(state, delivery_id):
    db_path = Path(state) / "ledger.sqlite"
    uri = "file:" + str(db_path) + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
        db.execute("PRAGMA busy_timeout=3000")
        row = db.execute("SELECT envelope FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
        return digest(row[0]) if row else None


def db_delivery_reason(state, delivery_id):
    db_path = Path(state) / "ledger.sqlite"
    uri = "file:" + str(db_path) + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
        db.execute("PRAGMA busy_timeout=3000")
        row = db.execute("SELECT state,reason FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
        return {"state": row[0], "reason": row[1]} if row else None


def run_cli_capture(argv):
    output = StringIO()
    with redirect_stdout(output), redirect_stderr(output):
        code = gateway_cli.main(argv)
    raw = output.getvalue()
    try:
        result = json.loads(raw)
    except ValueError:
        result = {"unparsedOutputSha256": digest(raw)}
    return code, result


def attempts_for(readback, attempt_id):
    return [row for row in readback["cloud"]["attempts"] if row.get("attempt_id") == attempt_id]


def native_claims_for(readback, attempt_id):
    return [row for row in readback["cloud"]["native_claims"] if row.get("attempt_id") == attempt_id]


def assert_c1_settled(local_delivery, local_attempts, workerd_attempts, workerd_claims,
                      receipt_statuses):
    require(isinstance(local_delivery, dict) and local_delivery.get("state") == "observed",
            "C1 local delivery was not observed before fixture attach")
    require(len(local_attempts) == 1 and local_attempts[0].get("state") == "observed",
            "C1 local attempt was not uniquely observed before fixture attach")
    require(len(workerd_attempts) == 1 and workerd_attempts[0].get("state") == "observed",
            "C1 Workerd attempt was not uniquely observed before fixture attach")
    require(len(workerd_claims) == 1, "C1 Workerd claim was not unique before fixture attach")
    require(receipt_statuses == ["inputRecorded"],
            "C1 native receipt was not inputRecorded before fixture attach")


HISTORY_SAFE_FIELDS = frozenset((
    "state", "ack_state", "reason", "status", "outcome", "created", "updated",
    "retain_until", "reserved_bytes", "fenced", "attemptstate", "receiptstatuses",
))


def history_value(field, value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if field.lower() in HISTORY_SAFE_FIELDS and len(value) <= 80:
            return value
        return {"sha256": digest(value), "characters": len(value)}
    encoded = json.dumps(value, sort_keys=True, default=str).encode()
    return {"type": type(value).__name__, "sha256": digest(encoded), "bytes": len(encoded)}


def history_changes(before, after, path="root", field="", changes=None):
    changes = [] if changes is None else changes
    if before == after or len(changes) >= 32:
        return changes
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() | after.keys(), key=str):
            if len(changes) >= 32:
                break
            child_path = (path + "." + str(key))[:160]
            if key not in before or key not in after:
                changes.append({"field": child_path, "beforePresent": key in before,
                                "afterPresent": key in after})
            else:
                history_changes(before[key], after[key], child_path, str(key), changes)
        return changes
    if isinstance(before, list) and isinstance(after, list):
        if len(before) != len(after):
            changes.append({"field": (path + ".length")[:160],
                            "before": len(before), "after": len(after)})
        for index, (old, new) in enumerate(zip(before[:32], after[:32])):
            if len(changes) >= 32:
                break
            history_changes(old, new, (path + "[" + str(index) + "]")[:160], field, changes)
        return changes
    changes.append({"field": path[:160], "before": history_value(field, before),
                    "after": history_value(field, after)})
    return changes


def assert_c1_history_unchanged(before, after):
    require(isinstance(before, dict) and isinstance(after, dict) and before == after,
            "C1 history changed during fixture attach; private bounded field diff="
            + json.dumps(history_changes(before, after), sort_keys=True))


def ack_replay_matches(first_ack, retries):
    if len(retries) < 2:
        return False
    last_retry = retries[-1]
    return (first_ack["bodySha256"] == last_retry["bodySha256"]
            and first_ack["proofNonceSha256"] != last_retry["proofNonceSha256"])


def has_attempt_state(rows, states):
    return bool(rows) and rows[0].get("state") in states


def attachment_matches_current(mapping, status, previous, binding, session_id):
    return (mapping is not None and status.get("status") == "present"
            and status.get("runtimeGeneration") == previous["runtimeGeneration"] + 1
            and status.get("attachmentGeneration") == previous["attachmentGeneration"] + 1
            and mapping.get("runtimeGeneration") == status.get("runtimeGeneration")
            and mapping.get("attachmentGeneration") == status.get("attachmentGeneration")
            and mapping.get("nativeBinding") == binding
            and mapping.get("sessionId") == session_id)


def c3_settled_once(attempts, claims, starts, total_starts, expected_total):
    return (len(attempts) == 1 and attempts[0].get("state") == "observed"
            and len(claims) == 1 and len(starts) == 1 and total_starts == expected_total)


def pty_drained(row):
    return row["bytesRead"] > 0 and row["readCount"] > 0


TRANSPORT_ATTEMPT_FIELDS = ("state", "reservation_state", "transport_status", "permit_id",
                           "submission_id", "turn_id")


def transport_attempt_snapshot(rows):
    if len(rows) != 1:
        return None
    return {key: rows[0].get(key) for key in TRANSPORT_ATTEMPT_FIELDS}


async def wait_until(predicate, message, timeout=25):
    deadline = time.monotonic() + timeout
    while not predicate():
        require(time.monotonic() < deadline, message)
        await asyncio.sleep(0.05)


async def wait_stable_session_binding(session, provider, *, minimum_turn_main_requests, timeout=30):
    deadline = time.monotonic() + timeout
    previous = None
    stable_observations = 0
    while time.monotonic() < deadline:
        try:
            status, binding = await asyncio.gather(
                asyncio.to_thread(launcher.session_status, session["state"], session["sessionId"]),
                asyncio.to_thread(launcher.session_binding, session["state"], session["sessionId"]),
            )
        except (OSError, ValueError, TimeoutError, launcher.LaunchError):
            await asyncio.sleep(0.25)
            previous = None
            stable_observations = 0
            continue
        activity = (len(provider.requests), len(provider.turn_main_requests),
                    provider.turn_title_count, len(provider.errors))
        observation = (binding, activity)
        settled = (status.get("selection") == "selected" and model_idle(provider)
                   and len(provider.turn_main_requests) >= minimum_turn_main_requests)
        if settled and previous == observation:
            stable_observations += 1
            if stable_observations >= 8:
                require_model_turn_complete(provider)
                return binding
        else:
            stable_observations = 0
        previous = observation
        await asyncio.sleep(0.25)
    raise AssertionError("native binding/model activity did not stabilize after completed turn")


def fixture(ctx, path, body=None):
    status, _, raw = post(ctx.address["port"], ctx.fixture_secret, path, body)
    require(status == 200, "workerd fixture rejected " + path)
    value = json.loads(raw)
    record_evidence(ctx, "cloudFixture", {"path": path, "response": value})
    return value


async def send(ctx, **request):
    require(request["method"] == "POST" and request["url"].startswith(ORIGIN + "/"),
            "CloudClient left the closed fixture origin")
    require((request["timeout"], request["max_response_bytes"], request["follow_redirects"])
            == (5, 8192, False), "CloudClient request limits changed")
    path = request["url"].removeprefix(ORIGIN)
    body = json.loads(request["body"])
    proof = json.loads(request["headers"]["x-event-node-proof"])
    response = await asyncio.to_thread(
        post, ctx.address["port"], ctx.fixture_secret, path, request["body"], request["headers"], limit=8192,
    )
    record_evidence(ctx, "cloudWire", {"path": path, "request": body,
                                      "proof": proof, "status": response[0],
                                      "response": response[2].decode(errors="replace")})
    response_summary = None
    if path == "/v1/runtimes/status":
        try:
            value = json.loads(response[2])
            native_binding = value.get("nativeBinding") if isinstance(value, dict) else None
            response_summary = {
                "keys": sorted(value) if isinstance(value, dict) else None,
                "status": value.get("status") if isinstance(value, dict) else None,
                "generationValues": (
                    {key: value.get(key) for key in
                     ("runtimeGeneration", "nodeGeneration", "attachmentGeneration")}
                    if isinstance(value, dict) else None
                ),
                "bindingKeys": sorted(native_binding) if isinstance(native_binding, dict) else None,
            }
        except (TypeError, ValueError):
            response_summary = {"parse": "failed"}
    ctx.wire_evidence.append({
        "path": path, "bodySha256": digest(request["body"]), "responseStatus": response[0],
        "proofNonceSha256": digest(proof["nonce"]),
        "ackStatus": body.get("status") if path == "/v1/ack" else None,
        "deliverySha256": digest(body["deliveryId"]) if "deliveryId" in body else None,
        "responseSummary": response_summary,
    })
    if (path == "/v1/ack" and body.get("status") == "observed"
            and body.get("deliveryId") == ctx.transport["targetDelivery"] and response[0] == 200):
        if not ctx.transport["firstLost"]:
            ctx.transport["firstLost"] = True
            result = json.loads(response[2])
            require(result.get("status") == "observed", "workerd did not commit observed ACK before loss")
            ctx.transport["lostReply"].set()
            raise TimeoutError("controlled lost reply after workerd commit")
        if ctx.transport["pauseRetry"]:
            ctx.transport["retryWaiting"].set()
            await ctx.transport["allowRetry"].wait()
    return response


def observe_session_request(ctx, state_dir, session_id, message, *, native_request=None):
    with ctx.evidence.lock:
        require(not ctx.evidence.closing and not ctx.evidence.sealed, "native observers are closed")
        if message.get("command") == "nativeStart":
            label = ctx.session_labels.get(session_id)
            require(label in ctx.start_calls, "native Start came from an unknown session")
            require(sum(map(len, ctx.start_calls.values())) < 4, "four native Start attempt cap exhausted")
            request = native_request or {}
            ctx.start_calls[label].append({
                "eventId": request.get("event", {}).get("eventId"),
                "attemptId": request.get("attemptId"), "threadId": request.get("threadId"),
            })
        ctx.evidence.active += 1
    try:
        return record_session_request(ctx, state_dir, session_id, message, native_request=native_request)
    finally:
        with ctx.evidence.lock:
            ctx.evidence.active -= 1


def record_session_request(ctx, state_dir, session_id, message, *, native_request=None):
    label = ctx.session_labels.get(session_id)
    if message.get("command") == "challenge" and label in ctx.challenge_calls:
        ctx.challenge_calls[label] += 1
    try:
        result = ctx.original_session_request(state_dir, session_id, message, native_request=native_request)
    except Exception as error:
        record_evidence(ctx, "nativeError", {"session": label, "request": message,
                                            "nativeRequest": native_request, "error": str(error)[:160]})
        if message.get("command") == "nativeReceipt" and label in ctx.receipt_errors:
            ctx.receipt_errors[label].append(getattr(error, "code", str(error)))
        raise
    row = {"session": label, "sessionId": session_id, "request": message, "nativeRequest": native_request,
           "response": result, "receivedAt": time.monotonic()}
    record_evidence(ctx, "nativeExchange", row)
    if message.get("command") == "nativeReceipt" and label in ctx.receipt_calls:
        ctx.receipt_calls[label].append(result.get("outcome", {}).get("status"))
    return result


def observe_list_pending(store, ctx):
    rows = ctx.original_list_pending(store)
    ctx.pending_scans.append(len(rows))
    return rows


def observe_list_reconcilable(store, ctx):
    rows = ctx.original_list_reconcilable(store)
    ctx.reconcilable_scans.append([row.get("state") for row in rows])
    return rows


async def observe_dispatch(gateway, ctx, delivery_id):
    label = ctx.dispatch_labels.get(delivery_id, "unlabeled")
    ctx.dispatch_calls.append(label)
    try:
        result = await ctx.original_dispatch(gateway, delivery_id)
    except Exception as error:
        ctx.dispatch_errors.append(type(error).__name__)
        raise
    ctx.dispatch_results.append({"delivery": label, "status": result.get("status"),
                             "reason": result.get("reason")})
    if label == "A" and result.get("status") == "submitted":
        ctx.submission_returned.set()
    return result


async def observe_reconcile(gateway, ctx, delivery_id):
    result = await ctx.original_reconcile(gateway, delivery_id)
    ctx.reconcile_results.append({"status": result.get("status"), "reason": result.get("reason")})
    return result


async def observe_adapter_check(adapter, ctx):
    try:
        result = await ctx.original_adapter_check(adapter)
    except Exception as error:
        ctx.adapter_checks.append({"result": "error", "error": type(error).__name__,
                               "code": getattr(error, "code", str(error))})
        raise
    ctx.adapter_checks.append({"result": result,
                           "eligible": adapter.witness.get("eligible") if adapter.witness else None,
                           "threadMatches": (adapter.witness.get("threadId") == adapter.thread_id
                                             if adapter.witness else None)})
    return result


async def observe_adapter_reconcile(adapter, ctx, request):
    try:
        result = await ctx.original_adapter_reconcile(adapter, request)
    except Exception as error:
        ctx.adapter_receipts.append({"result": "error", "error": type(error).__name__,
                                 "code": getattr(error, "code", str(error))})
        raise
    ctx.adapter_receipts.append({"result": result.get("outcome", {}).get("status")})
    return result


def observe_bridge_challenge(bridge, ctx):
    try:
        witness = ctx.original_bridge_challenge(bridge)
    except Exception as error:
        ctx.bridge_challenge_observations.append({"result": "error",
                                              "error": type(error).__name__,
                                              "code": getattr(error, "code", str(error))})
        raise
    ctx.bridge_challenge_observations.append({"result": "witness",
                                          "eligible": witness.get("eligible")})
    return witness


async def initialize_runtime(ctx, resources):
    for label in ("A", "B", "C"):
        session = native_session(resources, label, ctx, hold=False)
        ctx.sessions[label] = session
        ctx.session_labels[session["sessionId"]] = label
    require(len({session["sessionId"] for session in ctx.sessions.values()}) == 3,
            "three native sessions did not receive distinct session IDs")
    for field in ("clientId", "threadId"):
        require(len({session["binding"][field] for session in ctx.sessions.values()}) == 3,
                "three native sessions did not receive distinct " + field + " values")
    ctx.all_initially_selected_idle = all(
        session["initiallySelectedIdle"] for session in ctx.sessions.values()
    )
    require(ctx.all_initially_selected_idle,
            "one or more native sessions were not selected and idle before delivery")

    ctx.runtime_ids = {label: str(uuid4()) for label in ctx.sessions}
    ctx.attached = {}
    for label, session in ctx.sessions.items():
        try:
            ctx.attached[label] = await admit_runtime(ctx.admission_cloud, session, ctx.runtime_ids[label])
        except Exception as error:
            readback = ctx.fixture("/fixture/admission")
            stored_clients = []
            for row in readback["native_runtime_bindings"]:
                try:
                    stored_clients.append(digest(json.loads(row["binding_json"])["clientId"]))
                except (KeyError, TypeError, ValueError):
                    stored_clients.append("invalid")
            raise AssertionError("native runtime attach failed: " + json.dumps({
                "label": label,
                "code": getattr(error, "code", type(error).__name__),
                "sessionCount": len(ctx.sessions),
                "distinctClientHashes": len({digest(value["binding"]["clientId"])
                                               for value in ctx.sessions.values()}),
                "distinctThreadHashes": len({digest(value["binding"]["threadId"])
                                              for value in ctx.sessions.values()}),
                "clientHashes": {name: digest(value["binding"]["clientId"])
                                 for name, value in ctx.sessions.items()},
                "storedClientHashes": stored_clients,
                "persistedRuntimeCount": len(readback["runtimes"]),
            }, sort_keys=True)) from None
    ctx.admission_readback = ctx.fixture("/fixture/admission")
    require_all("workerd did not persist three independent native attachments",
                len(ctx.admission_readback["runtimes"]) == 3,
                len(ctx.admission_readback["native_runtime_bindings"]) == 3)

    ctx.deliveries = {}
    for label, session in ctx.sessions.items():
        delivery = ctx.fixture("/fixture/setup", {
            "runtimeId": ctx.runtime_ids[label], "nodeId": ctx.node_id,
            "transportPrivateKey": b64(ctx.transport_key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )),
            "subjectId": "three-session-route-" + label.lower(),
        })
        envelope = delivery["envelope"]
        mapping = {key: envelope[key] for key in identity_fields}
        current = ctx.attached[label]["attached"]
        mapping.update({
            "nativeThreadId": current["nativeBinding"]["threadId"],
            "nativeBinding": current["nativeBinding"],
            "sessionId": session["sessionId"],
            "leaseExpiresAt": datetime.fromisoformat(
                current["leaseUntil"].replace("Z", "+00:00")
            ).timestamp(),
        })
        require(all(mapping[key] == envelope[key] for key in identity_fields),
                "signed delivery differs from admitted attachment")
        ctx.deliveries[label] = {"envelope": envelope, "signed": delivery["signedDelivery"],
                             "mapping": mapping}
        ctx.dispatch_labels[envelope["deliveryId"]] = label

    pem = ctx.node_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path = ctx.state / "node-key.pem"
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(pem)
    private_json(ctx.state / "credentials.json", {"accessToken": FIXTURE_ACCESS,
                                               "agentToken": FIXTURE_AGENT})
    private_json(ctx.state / "cloud.json", {
        "version": 1, "origin": ORIGIN, "principal": PRINCIPAL, "agent": AGENT,
        "nodeId": ctx.node_id, "nodeGeneration": 1, "credentialsFile": "credentials.json",
    })
    with Store(ctx.state) as store:
        for label in ("A", "B", "C"):
            store.put_attachment(ctx.deliveries[label]["mapping"])
    ctx.listen_port = free_port()
    private_json(ctx.state / "dispatch.json", {
        "version": 1, "cloudConfig": "cloud.json", "listenHost": "127.0.0.1",
        "listenPort": ctx.listen_port,
        "transportKeys": {"fixture-transport": b64(ctx.transport_key.public_key().public_bytes_raw())},
    })


async def start_daemon(ctx):
    task = asyncio.create_task(daemon.serve(ctx.state, dispatch_config=ctx.state / "dispatch.json"))
    await wait_until(lambda: (ctx.state / "control.sock").exists() or task.done(),
                     "production daemon startup timed out")
    if task.done():
        await task
    status = await daemon.request(ctx.state, {"command": "status"})
    require(status["automaticWakeEnabled"] is True
            and status["dispatch"]["listenerReady"]
            and status["dispatch"]["workerRunning"],
            "production daemon dispatch path not ready")
    return task


async def stop_daemon(ctx, task):
    task.cancel()
    result, = await asyncio.gather(task, return_exceptions=True)
    require(isinstance(result, asyncio.CancelledError), "production daemon exited unexpectedly")
    await wait_until(lambda: not (ctx.state / "control.sock").exists(),
                     "production daemon control socket survived stop")


async def deliver(ctx, label, delivery):
    status, raw = await asyncio.to_thread(listener_delivery, ctx.listen_port, delivery["signed"])
    require(status == 202, "production listener refused signed " + label + " delivery")
    return json.loads(raw)


async def wait_observed(ctx, label):
    delivery_id = ctx.deliveries[label]["envelope"]["deliveryId"]
    await wait_until(lambda: db_delivery(ctx.state, delivery_id)["state"] == "observed",
                     label + " delivery did not reach observed state")
    cloud = ctx.fixture("/fixture/read")
    attempt_id = ctx.deliveries[label]["envelope"]["attemptId"]
    observed = attempts_for(cloud, attempt_id)
    require(len(observed) == 1 and observed[0]["state"] == "observed",
            label + " delivery missing observed Workerd attempt")
    return cloud


async def run_ab_routes(ctx):
    # Configure A's observed reply loss to stop the first daemon after commit.
    ctx.transport.update(targetDelivery=ctx.deliveries["A"]["envelope"]["deliveryId"], pauseRetry=True)
    ctx.daemon_task = await ctx.start_daemon()
    await ctx.deliver("A-only", ctx.deliveries["A"])
    await wait_until(ctx.submission_returned.is_set,
                     "production daemon did not submit A's idle-session event")
    await ctx.stop_daemon(ctx.daemon_task)
    ctx.daemon_task = None
    await wait_until(lambda: ctx.sessions["A"]["process"].poll() is None
                     and len(ctx.sessions["A"]["provider"].main_requests) >= 2
                     and launcher.session_status(ctx.sessions["A"]["state"], ctx.sessions["A"]["sessionId"])
                     .get("selection") == "selected",
                     "A's native input did not finish while the daemon was stopped")
    ctx.daemon_task = await ctx.start_daemon()
    try:
        await wait_until(ctx.transport["lostReply"].is_set,
                         "workerd observed-ACK reply was not deliberately lost")
    except AssertionError as error:
        local = db_delivery(ctx.state, ctx.deliveries["A"]["envelope"]["deliveryId"])
        cloud = ctx.fixture("/fixture/read")["cloud"]
        try:
            dispatch_status = await daemon.request(ctx.state, {"command": "status"})
        except Exception as status_error:
            dispatch_status = {"controlError": type(status_error).__name__}
        diagnostic = {
            "nativeStarts": {label: len(ctx.start_calls[label]) for label in ctx.start_calls},
            "challengeRequests": ctx.challenge_calls,
            "wirePaths": [row["path"] for row in ctx.wire_evidence[-24:]],
            "localDelivery": local,
            "cloudRows": {table: len(cloud[table]) for table in
                          ("attempts", "deliveries", "native_claims", "slot_intents")},
            "providerRequests": len(ctx.sessions["A"]["provider"].requests),
            "providerKinds": list(ctx.sessions["A"]["provider"].requests),
            "providerErrors": list(ctx.sessions["A"]["provider"].errors),
            "dispatchStatus": dispatch_status.get("dispatch"),
            "pendingScans": ctx.pending_scans[-16:],
            "reconcilableScans": ctx.reconcilable_scans[-8:],
            "reconcileResults": ctx.reconcile_results[-8:],
            "receiptCalls": {label: calls[-12:] for label, calls in ctx.receipt_calls.items()},
            "receiptErrors": {label: calls[-12:] for label, calls in ctx.receipt_errors.items()},
            "adapterReceipts": ctx.adapter_receipts[-12:],
            "dispatchCallCount": len(ctx.dispatch_calls),
            "dispatchResults": ctx.dispatch_results[-8:],
            "dispatchErrors": ctx.dispatch_errors[-8:],
            "adapterChecks": ctx.adapter_checks[-12:],
            "bridgeChallenges": ctx.bridge_challenge_observations[-12:],
            "daemonTaskDone": ctx.daemon_task.done(),
            "daemonTaskError": (type(ctx.daemon_task.exception()).__name__
                                if ctx.daemon_task.done() and ctx.daemon_task.exception() else None),
            "sessionStates": {label: {
                "selection": launcher.session_status(session["state"], session["sessionId"]).get("selection"),
                "attached": launcher.session_status(session["state"], session["sessionId"]).get("attached"),
            } for label, session in ctx.sessions.items()},
        }
        raise AssertionError(str(error) + "; bounded diagnostic="
                             + json.dumps(diagnostic, sort_keys=True)) from None
    await wait_until(ctx.transport["retryWaiting"].is_set,
                     "daemon did not retry exact observed ACK")
    ctx.state_before_replay = ctx.fixture("/fixture/read")
    ctx.first_ack = [row for row in ctx.wire_evidence if row["path"] == "/v1/ack"
                 and row["ackStatus"] == "observed"
                 and row["deliverySha256"] == digest(ctx.transport["targetDelivery"])][0]
    await ctx.stop_daemon(ctx.daemon_task)
    ctx.daemon_task = None
    ctx.transport["pauseRetry"] = False
    ctx.transport["allowRetry"].set()
    ctx.daemon_task = await ctx.start_daemon()
    await wait_until(lambda: db_delivery(ctx.state, ctx.deliveries["A"]["envelope"]["deliveryId"])["state"]
                     == "observed", "A ACK was not recovered after daemon restart")
    ctx.state_after_replay = await ctx.wait_observed("A")
    ctx.second_acks = [row for row in ctx.wire_evidence if row["path"] == "/v1/ack"
                    and row["ackStatus"] == "observed"
                    and row["deliverySha256"] == digest(ctx.transport["targetDelivery"])]
    require(ack_replay_matches(ctx.first_ack, ctx.second_acks),
            "daemon restart did not replay identical ACK bytes with fresh proof")
    require(ctx.state_after_replay == ctx.state_before_replay,
            "observed-ACK replay changed committed Workerd state")
    require_all("A-only delivery escaped its native session",
                len(ctx.start_calls["A"]) == 1, not ctx.start_calls["B"], not ctx.start_calls["C"])
    ctx.a_route_counts = {label: len(ctx.start_calls[label]) for label in ctx.start_calls}

    await ctx.deliver("B-only", ctx.deliveries["B"])
    await ctx.wait_observed("B")
    require_all("B-only delivery escaped its native session",
                len(ctx.start_calls["A"]) == 1, len(ctx.start_calls["B"]) == 1,
                not ctx.start_calls["C"])
    ctx.b_route_counts = {label: len(ctx.start_calls[label]) for label in ctx.start_calls}
    for label in ("A", "B"):
        await wait_stable_session_binding(ctx.sessions[label], ctx.sessions[label]["provider"],
                                          minimum_turn_main_requests=2)


async def run_busy_stage(ctx):
    # C's first controlled turn holds its local model request open. A second
    # signed delivery must remain locally queued without a claim or native Start.
    c_first = ctx.fixture("/fixture/setup", {
        "runtimeId": ctx.runtime_ids["C"], "nodeId": ctx.node_id,
        "transportPrivateKey": b64(ctx.transport_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )),
        "subjectId": "three-session-c-busy-first",
    })
    ctx.c_first_envelope = c_first["envelope"]
    ctx.dispatch_labels[ctx.c_first_envelope["deliveryId"]] = "C-busy-first"
    c_first_signed = c_first["signedDelivery"]
    c_second = ctx.fixture("/fixture/setup", {
        "runtimeId": ctx.runtime_ids["C"], "nodeId": ctx.node_id,
        "transportPrivateKey": b64(ctx.transport_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )),
        "subjectId": "three-session-c-busy-second",
    })
    ctx.c_second_envelope = c_second["envelope"]
    ctx.dispatch_labels[ctx.c_second_envelope["deliveryId"]] = "C-busy-second"
    c_second_signed = c_second["signedDelivery"]
    c_second_transport_rows = attempts_for(ctx.fixture("/fixture/read"), ctx.c_second_envelope["attemptId"])
    ctx.c_second_transport_baseline = transport_attempt_snapshot(c_second_transport_rows)
    require(ctx.c_second_transport_baseline == {
        "state": "created", "reservation_state": "none", "transport_status": "sending",
        "permit_id": None, "submission_id": None, "turn_id": None,
    }, "fixture did not create the expected unreserved C2 transport-attempt baseline")
    with ctx.sessions["C"]["provider"].hold_lock:
        ctx.sessions["C"]["provider"].hold_next = True
        ctx.sessions["C"]["provider"].hold_started.clear()
        ctx.sessions["C"]["provider"].release_hold.clear()
    c_first_status, _ = await asyncio.to_thread(listener_delivery, ctx.listen_port, c_first_signed)
    require(c_first_status == 202, "production listener refused C busy-first delivery")
    await wait_until(ctx.sessions["C"]["provider"].hold_started.is_set,
                     "C native CLI did not enter the controlled busy state")
    require_model_held(ctx.sessions["C"]["provider"])
    c_first_id = ctx.c_first_envelope["deliveryId"]
    await wait_until(lambda: db_delivery(ctx.state, c_first_id)["attemptState"] in
                     ("submitted", "observed"), "C busy-first event did not reach native Start")
    c_first_cloud = ctx.fixture("/fixture/read")
    c_first_attempts = attempts_for(c_first_cloud, ctx.c_first_envelope["attemptId"])
    require(has_attempt_state(c_first_attempts, ("submitted", "observed")),
            "C busy-first event did not persist in Workerd")
    ctx.starts_before_busy_delivery = len(ctx.start_calls["C"])
    require(ctx.starts_before_busy_delivery == 1, "C busy-first event did not issue exactly one native Start")
    status, _ = await asyncio.to_thread(listener_delivery, ctx.listen_port, c_second_signed)
    require(status == 202, "production listener refused C busy delivery")
    await wait_until(lambda: db_delivery(ctx.state, ctx.c_second_envelope["deliveryId"])["state"] == "queued",
                     "C busy delivery was not durably queued")
    ctx.c_second_envelope_sha256 = db_delivery_envelope_sha256(
        ctx.state, ctx.c_second_envelope["deliveryId"],
    )
    require(ctx.c_second_envelope_sha256 is not None,
            "queued C2 envelope was unavailable for immutability check")

    try:
        await wait_until(lambda: bool(ctx.c_second_busy_dispositions()),
                         "production dispatch did not return C's busy disposition", timeout=10)
    except AssertionError as error:
        cloud = ctx.fixture("/fixture/read")
        diagnostic = {
            "cSecondDispatchCalls": ctx.dispatch_calls.count("C-busy-second"),
            "cSecondDispatchResults": [row for row in ctx.dispatch_results
                                        if row["delivery"] == "C-busy-second"][-8:],
            "localDelivery": db_delivery(ctx.state, ctx.c_second_envelope["deliveryId"]),
            "attemptCount": len(attempts_for(cloud, ctx.c_second_envelope["attemptId"])),
            "claimCount": len(native_claims_for(cloud, ctx.c_second_envelope["attemptId"])),
            "nativeStartCount": len(ctx.start_calls["C"]),
            "providerRequests": len(ctx.sessions["C"]["provider"].requests),
            "providerErrors": list(ctx.sessions["C"]["provider"].errors),
            "daemonTaskDone": ctx.daemon_task.done(),
        }
        raise AssertionError(str(error) + "; bounded diagnostic="
                             + json.dumps(diagnostic, sort_keys=True)) from None
    await asyncio.sleep(1.5)
    c_second_cloud = ctx.fixture("/fixture/read")
    c_second_local = db_delivery(ctx.state, ctx.c_second_envelope["deliveryId"])
    c_second_attempts = attempts_for(c_second_cloud, ctx.c_second_envelope["attemptId"])
    c_second_claims = native_claims_for(c_second_cloud, ctx.c_second_envelope["attemptId"])
    c_second_transport_after_busy = transport_attempt_snapshot(c_second_attempts)
    c_second_start_calls = [start for label in ctx.start_calls
                            for start in ctx.start_calls[label]
                            if start["attemptId"] == ctx.c_second_envelope["attemptId"]]
    busy_assertions = {
        "localDelivery": c_second_local,
        "busyDispositions": ctx.c_second_busy_dispositions()[-4:],
        "transportAttemptCount": len(c_second_attempts),
        "transportAttemptBaseline": ctx.c_second_transport_baseline,
        "transportAttemptAfterBusy": c_second_transport_after_busy,
        "claimCount": len(c_second_claims),
        "nativeStartCount": len(c_second_start_calls),
        "totalCStarts": len(ctx.start_calls["C"]),
        "expectedCStarts": ctx.starts_before_busy_delivery,
    }
    require_all(
        "C busy delivery did not remain queued after production returned busy; diagnostic="
        + json.dumps(busy_assertions, sort_keys=True),
        c_second_local == {"state": "queued", "attemptState": None},
        bool(ctx.c_second_busy_dispositions()),
        db_delivery_envelope_sha256(ctx.state, ctx.c_second_envelope["deliveryId"])
        == ctx.c_second_envelope_sha256,
        c_second_transport_after_busy == ctx.c_second_transport_baseline,
        not c_second_claims, not c_second_start_calls,
        len(ctx.start_calls["C"]) == ctx.starts_before_busy_delivery,
    )
    require_model_held(ctx.sessions["C"]["provider"])
    await ctx.stop_daemon(ctx.daemon_task)
    ctx.daemon_task = None
    require_model_held(ctx.sessions["C"]["provider"])
    require_all(
        "stopping the daemon did not retain C's queue while its native turn stayed busy",
        db_delivery(ctx.state, ctx.c_second_envelope["deliveryId"])
        == {"state": "queued", "attemptState": None},
        db_delivery_envelope_sha256(ctx.state, ctx.c_second_envelope["deliveryId"])
        == ctx.c_second_envelope_sha256,
        ctx.sessions["C"]["provider"].hold_started.is_set(),
        not ctx.sessions["C"]["provider"].release_hold.is_set(),
        len(ctx.start_calls["C"]) == ctx.starts_before_busy_delivery,
    )
    ctx.busy_result_count = len(ctx.c_second_busy_dispositions())
    ctx.daemon_task = await ctx.start_daemon()
    await wait_until(lambda: len(ctx.c_second_busy_dispositions()) > ctx.busy_result_count,
                     "restarted daemon did not observe C still busy", timeout=10)
    await asyncio.sleep(1.0)
    c_second_cloud_after_restart = ctx.fixture("/fixture/read")
    c_second_attempts_after_restart = attempts_for(
        c_second_cloud_after_restart, ctx.c_second_envelope["attemptId"],
    )
    c_second_transport_after_restart = transport_attempt_snapshot(c_second_attempts_after_restart)
    require_model_held(ctx.sessions["C"]["provider"])
    require_all(
        "restarted busy delivery did not remain queued without cloud or native start",
        db_delivery(ctx.state, ctx.c_second_envelope["deliveryId"])
        == {"state": "queued", "attemptState": None},
        db_delivery_envelope_sha256(ctx.state, ctx.c_second_envelope["deliveryId"])
        == ctx.c_second_envelope_sha256,
        c_second_transport_after_restart == ctx.c_second_transport_baseline,
        not native_claims_for(c_second_cloud_after_restart, ctx.c_second_envelope["attemptId"]),
        len(ctx.start_calls["C"]) == ctx.starts_before_busy_delivery,
    )
    await ctx.stop_daemon(ctx.daemon_task)
    ctx.daemon_task = None
    require_model_held(ctx.sessions["C"]["provider"])
    ctx.sessions["C"]["provider"].release_hold.set()
    ctx.current_binding = await wait_stable_session_binding(
        ctx.sessions["C"], ctx.sessions["C"]["provider"],
        minimum_turn_main_requests=2, timeout=75,
    )
    ctx.same_binding_after_turn = ctx.current_binding == ctx.sessions["C"]["binding"]
    queued_while_stopped = db_delivery(ctx.state, ctx.c_second_envelope["deliveryId"])
    require(queued_while_stopped["state"] == "queued",
            "C busy delivery did not remain queued while the daemon was stopped")
    require(not ctx.same_binding_after_turn,
            "controlled C turn did not rotate its native binding for explicit reattachment")


async def run_fixture_attach(ctx):
    # A changed native identity cannot inherit C2. Use the normal CLI
    # attach path with Workerd's current generations and fresh native
    # challenge while the daemon is stopped; Store fences the old queue.
    c_first_id = ctx.c_first_envelope["deliveryId"]
    ctx.c_first_before_attach = db_delivery(ctx.state, c_first_id)
    c_first_local_history_before_attach = db_delivery_history(ctx.state, c_first_id)
    c_first_workerd_before_attach = ctx.fixture("/fixture/read")
    ctx.c_first_attempts_before_attach = attempts_for(
        c_first_workerd_before_attach, ctx.c_first_envelope["attemptId"],
    )
    ctx.c_first_claims_before_attach = native_claims_for(
        c_first_workerd_before_attach, ctx.c_first_envelope["attemptId"],
    )
    ctx.c_first_receipts_before_attach = list(ctx.receipt_calls["C"])
    assert_c1_settled(
        c_first_local_history_before_attach["delivery"],
        c_first_local_history_before_attach["attempts"],
        ctx.c_first_attempts_before_attach, ctx.c_first_claims_before_attach,
        ctx.c_first_receipts_before_attach,
    )
    c_first_history_before_attach = {
        "localDelivery": c_first_local_history_before_attach["delivery"],
        "localAttempts": c_first_local_history_before_attach["attempts"],
        "workerdAttempts": ctx.c_first_attempts_before_attach,
        "workerdClaims": ctx.c_first_claims_before_attach,
        "receiptStatuses": ctx.c_first_receipts_before_attach,
    }
    with Store(ctx.state) as store:
        c_mapping_before_attach = store.get_attachment(ctx.runtime_ids["C"])
    require(c_mapping_before_attach is not None,
            "C local attachment was missing before fixture attach")
    require(c_mapping_before_attach["nativeBinding"] == ctx.sessions["C"]["binding"],
            "C local attachment did not retain its original binding before fixture attach")
    ctx.changed_binding_fields = sorted(
        key for key, value in ctx.current_binding.items()
        if c_mapping_before_attach["nativeBinding"].get(key) != value
    )
    require(bool(ctx.changed_binding_fields), "C native binding changed without any field delta")
    try:
        ctx.c_status_before_attach = await ctx.admission_cloud.runtime_status(ctx.runtime_ids["C"])
    except Exception as error:
        raise AssertionError("runtime status readback failed before fixture attach: "
                             + json.dumps({"error": type(error).__name__,
                                           "wire": ctx.wire_evidence[-1:]}, sort_keys=True)) from None
    require_all("fixture runtime status did not report the stored qualified C attachment",
                ctx.c_status_before_attach["status"] == "present",
                ctx.c_status_before_attach["storedQualified"] is True)
    attach_argv = [
        "--state-dir", str(ctx.state), "attach",
        "--runtime-id", ctx.runtime_ids["C"],
        "--session-id", ctx.sessions["C"]["sessionId"],
        "--cloud-config", str(ctx.state / "cloud.json"),
        "--expected-runtime-generation", str(ctx.c_status_before_attach["runtimeGeneration"]),
        "--expected-attachment-generation", str(ctx.c_status_before_attach["attachmentGeneration"]),
    ]
    attach_exit, ctx.attach_result = await asyncio.to_thread(run_cli_capture, attach_argv)
    require_all("production attach CLI did not commit and persist the fixture binding",
                attach_exit == 0, ctx.attach_result.get("remoteStatus") == "attached",
                ctx.attach_result.get("localStatus") == "current")
    ctx.c_status_after_attach = await ctx.admission_cloud.runtime_status(ctx.runtime_ids["C"])
    with Store(ctx.state) as store:
        ctx.c_mapping_after_attach = store.get_attachment(ctx.runtime_ids["C"])
    attached_current = attachment_matches_current(
        ctx.c_mapping_after_attach, ctx.c_status_after_attach, ctx.c_status_before_attach,
        ctx.current_binding, ctx.sessions["C"]["sessionId"],
    )
    require(attached_current,
            "production attach CLI mapping mismatch: "
            + json.dumps({
                "exit": attach_exit,
                "remoteStatus": ctx.attach_result.get("remoteStatus"),
                "localStatus": ctx.attach_result.get("localStatus"),
                "statusBefore": {key: ctx.c_status_before_attach.get(key) for key in
                                 ("status", "runtimeGeneration", "attachmentGeneration")},
                "statusAfter": {key: ctx.c_status_after_attach.get(key) for key in
                                ("status", "runtimeGeneration", "attachmentGeneration")},
                "mappingAfter": ({"runtimeGeneration": ctx.c_mapping_after_attach.get("runtimeGeneration"),
                                  "attachmentGeneration": ctx.c_mapping_after_attach.get("attachmentGeneration"),
                                  "bindingMatches": ctx.c_mapping_after_attach.get("nativeBinding")
                                  == ctx.current_binding,
                                  "sessionMatches": ctx.c_mapping_after_attach.get("sessionId")
                                  == ctx.sessions["C"]["sessionId"]}
                                 if ctx.c_mapping_after_attach else None),
            }, sort_keys=True))
    ctx.c_second_after_attach = db_delivery(ctx.state, ctx.c_second_envelope["deliveryId"])
    ctx.c_second_after_attach_reason = db_delivery_reason(ctx.state, ctx.c_second_envelope["deliveryId"])
    ctx.c_second_envelope_after_attach_sha256 = db_delivery_envelope_sha256(
        ctx.state, ctx.c_second_envelope["deliveryId"],
    )
    ctx.c_second_cloud_after_attach = ctx.fixture("/fixture/read")
    ctx.c_second_transport_after_attach = transport_attempt_snapshot(
        attempts_for(ctx.c_second_cloud_after_attach, ctx.c_second_envelope["attemptId"]),
    )
    require_all("explicit attach did not fence old-generation C2 without a claim or native Start",
                ctx.c_second_after_attach == {"state": "stale", "attemptState": None},
                ctx.c_second_after_attach_reason == {"state": "stale", "reason": "attachment_detached"},
                ctx.c_second_transport_after_attach == ctx.c_second_transport_baseline,
                ctx.c_second_envelope_after_attach_sha256 == ctx.c_second_envelope_sha256,
                not native_claims_for(ctx.c_second_cloud_after_attach, ctx.c_second_envelope["attemptId"]),
                len(ctx.start_calls["C"]) == ctx.starts_before_busy_delivery)
    ctx.c_second_restart_disposition = "stale_after_explicit_fixture_attach"
    ctx.c_first_after_attach = db_delivery(ctx.state, c_first_id)
    c_first_local_history_after_attach = db_delivery_history(ctx.state, c_first_id)
    c_first_workerd_after_attach = ctx.fixture("/fixture/read")
    ctx.c_first_attempts_after_attach = attempts_for(
        c_first_workerd_after_attach, ctx.c_first_envelope["attemptId"],
    )
    ctx.c_first_claims_after_attach = native_claims_for(
        c_first_workerd_after_attach, ctx.c_first_envelope["attemptId"],
    )
    ctx.c_first_receipts_after_attach = list(ctx.receipt_calls["C"])
    assert_c1_settled(
        c_first_local_history_after_attach["delivery"],
        c_first_local_history_after_attach["attempts"],
        ctx.c_first_attempts_after_attach, ctx.c_first_claims_after_attach,
        ctx.c_first_receipts_after_attach,
    )
    c_first_history_after_attach = {
        "localDelivery": c_first_local_history_after_attach["delivery"],
        "localAttempts": c_first_local_history_after_attach["attempts"],
        "workerdAttempts": ctx.c_first_attempts_after_attach,
        "workerdClaims": ctx.c_first_claims_after_attach,
        "receiptStatuses": ctx.c_first_receipts_after_attach,
    }
    assert_c1_history_unchanged(c_first_history_before_attach, c_first_history_after_attach)


async def run_post_attach_c3(ctx):
    # Reuse C's real CLI session with a fresh fixture nonce; its prior
    # C1 conversation already contains the first nonce by design.
    require_model_turn_complete(ctx.sessions["C"]["provider"])
    ctx.c1_source_nonce_sha256 = ctx.sessions["C"]["provider"].source_nonce_sha256
    ctx.sessions["C"]["provider"].nonce = "three-session-source-c-after-attach-" + uuid4().hex
    ctx.c3_source_nonce_sha256 = digest(ctx.sessions["C"]["provider"].nonce)
    require(ctx.c3_source_nonce_sha256 != ctx.c1_source_nonce_sha256,
            "post-attach source nonce was reused")
    ctx.sessions["C"]["provider"].source_nonce_sha256 = ctx.c3_source_nonce_sha256
    ctx.sessions["C"]["provider"].source_path.write_text(
        ctx.sessions["C"]["provider"].nonce + "\n",
    )
    ctx.sessions["C"]["provider"].turn_main_requests.clear()
    ctx.sessions["C"]["provider"].turn_title_count = 0
    ctx.sessions["C"]["provider"].turn_verified = False
    ctx.sessions["C"]["provider"].phase = "post-attach"
    qualifier = load_module("three_session_c3_qualifier", host_qualifier.__file__)
    qualifier.CALL_ID = "three-session-source-read-" + uuid4().hex
    ctx.sessions["C"]["provider"].qualifier = qualifier
    c_third = ctx.fixture("/fixture/setup", {
        "runtimeId": ctx.runtime_ids["C"], "nodeId": ctx.node_id,
        "transportPrivateKey": b64(ctx.transport_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )),
        "subjectId": "three-session-c-after-attach",
    })
    c_third_envelope = c_third["envelope"]
    ctx.dispatch_labels[c_third_envelope["deliveryId"]] = "C-after-attach"
    ctx.daemon_task = await ctx.start_daemon()
    c_third_status, _ = await asyncio.to_thread(
        listener_delivery, ctx.listen_port, c_third["signedDelivery"],
    )
    require(c_third_status == 202, "production listener refused C delivery after fixture attach")
    await wait_until(
        lambda: db_delivery(ctx.state, c_third_envelope["deliveryId"])["state"] == "observed",
        "new C delivery did not settle after explicit fixture attach", timeout=30,
    )
    c_third_workerd = ctx.fixture("/fixture/read")
    ctx.c_third_attempts = attempts_for(c_third_workerd, c_third_envelope["attemptId"])
    ctx.c_third_claims = native_claims_for(c_third_workerd, c_third_envelope["attemptId"])
    ctx.c_third_start_calls = [start for label in ctx.start_calls for start in ctx.start_calls[label]
                           if start["attemptId"] == c_third_envelope["attemptId"]]
    require(c3_settled_once(ctx.c_third_attempts, ctx.c_third_claims, ctx.c_third_start_calls,
                            len(ctx.start_calls["C"]), ctx.starts_before_busy_delivery + 1),
            "new-generation C delivery did not claim, start, and settle exactly once")
    c_binding_after_third = await wait_stable_session_binding(
        ctx.sessions["C"], ctx.sessions["C"]["provider"],
        minimum_turn_main_requests=2, timeout=45,
    )
    ctx.c_binding_fields_after_third = sorted(
        key for key, value in c_binding_after_third.items()
        if ctx.c_mapping_after_attach["nativeBinding"].get(key) != value
    )
    await ctx.stop_daemon(ctx.daemon_task)
    ctx.daemon_task = None


def build_proof(ctx):
    for session in ctx.sessions.values():
        require_model_turn_complete(session["provider"])
    pty_drain = {
        label: {"bytesRead": session["ptyPumpStats"]["bytesRead"],
                "readCount": session["ptyPumpStats"]["readCount"]}
        for label, session in ctx.sessions.items()
    }
    require(all(pty_drained(row) for row in pty_drain.values()),
            "one or more native CLI PTYs were not drained during the acceptance run")
    summaries = {
        label: {
            "runtimeSha256": digest(ctx.runtime_ids[label]),
            "sessionSha256": digest(ctx.sessions[label]["sessionId"]),
            "threadSha256": digest(ctx.sessions[label]["binding"]["threadId"]),
            "nativeStartCount": len(ctx.start_calls[label]),
        "initiallySelectedIdle": ctx.sessions[label]["initiallySelectedIdle"],
        }
        for label in ctx.sessions
    }
    provider_errors = {label: list(session["provider"].errors)
                       for label, session in ctx.sessions.items()}
    require(not any(provider_errors.values()),
            "synthetic provider rejected a CLI request: "
            + json.dumps(provider_errors, sort_keys=True))
    package_files = {
        str(Path(path).relative_to(ctx.installed_proof["packageRoot"])): file_digest
        for path, file_digest in ctx.installed_proof["verifiedSha256"].items()
    }
    cloud_root = ctx.cloud_source.parents[2]
    workerd_inputs = {}
    for path, file_digest in ctx.address["bundle"]["inputs"].items():
        source = Path(path).resolve(strict=True)
        try:
            relative = source.relative_to(cloud_root)
        except ValueError:
            continue
        workerd_inputs[str(relative)] = file_digest
    ctx.proof = {
        "result": "PASS",
        "qualification": "controlled-three-real-cli-production-daemon-workerd",
        "candidateStatus": "explicit-installed-artifacts-verified-against-source",
        "executionContainment": ctx.containment,
        "productionAdmissionProven": False,
        "liveMeshProven": False,
        "liveOwnerAccessProven": False,
        "liveManualCanaryProven": False,
        "nativeBinarySha256": ctx.args.binary_sha256,
        "codeModeHostSha256": launcher.QUALIFIED_CODE_MODE_HOST_SHA256,
        "installedPackageFilesSha256": package_files,
        "cloudSourceCommit": ctx.args.cloud_commit,
        "workerdBundleSha256": ctx.address["bundle"]["sha256"],
        "workerdInputsSha256": workerd_inputs,
        "productionEntrypoints": ["event_gateway.daemon.serve", "event_gateway.listener.Listener",
                                  "event_gateway.native.SessionNativeBridge", "event_gateway.gateway.Gateway"],
        "nativeCliSessions": summaries,
        "nativePtyDrain": pty_drain,
        "nativeProcessCleanup": {label: session["processCleanup"]
                                  for label, session in ctx.sessions.items()},
        "controlledModelRequests": {label: len(ctx.sessions[label]["provider"].requests)
                                     for label in ctx.sessions},
        "admissionReadback": {"runtimes": len(ctx.admission_readback["runtimes"]),
                               "nativeBindings": len(ctx.admission_readback["native_runtime_bindings"])},
        "idleDispatch": {"allThreeInitiallySelectedAndIdle": ctx.all_initially_selected_idle,
                         "eventTriggeredNativeInput": True,
                         "liveUserWakeQualified": False},
        "routing": {"AOnly": {"AStarts": ctx.a_route_counts["A"], "BStarts": ctx.a_route_counts["B"],
                               "CStarts": ctx.a_route_counts["C"], "observed": True},
                    "BOnly": {"AStarts": ctx.b_route_counts["A"], "BStarts": ctx.b_route_counts["B"],
                               "CStarts": ctx.b_route_counts["C"], "observed": True}},
        "busyC": {"dispatchEligible": not bool(ctx.c_second_busy_dispositions()),
                  "listenerAccepted": True,
                  "localStateWhileBusy": "queued", "transportAttemptUnchanged": True,
                  "nativeClaimCreated": False,
                  "nativeStartWhileBusy": False,
                  "productionBusyDisposition": "client_unavailable_or_busy",
                  "busyDispatchCount": len(ctx.c_second_busy_dispositions())},
        "sourceNonceTransition": {"firstDelivery": "C1", "freshDelivery": "C3",
                                  "nonReuse": True},
        "busyDeliveryRestart": {"queuedWhileDaemonStopped": True,
                                 "restartedWhileNativeTurnBusy": True,
                                 "queuedAfterBusyRestart": True,
                                 "transportAttemptUnchanged": True,
                                 "nativeClaimCreated": False,
                                 "busyDispatchCountAfterRestart": len(ctx.c_second_busy_dispositions())
                                 - ctx.busy_result_count,
                                 "bindingUnchangedAfterFirstTurn": ctx.same_binding_after_turn,
                                 "disposition": ctx.c_second_restart_disposition,
                                 "nativeStartCountAtRestart": ctx.starts_before_busy_delivery},
        "explicitFixtureAttach": {
            "productionCliPath": True, "syntheticFixtureAuthority": True,
            "remoteStatus": ctx.attach_result.get("remoteStatus"),
            "localStatus": ctx.attach_result.get("localStatus"),
            "runtimeGenerationBefore": ctx.c_status_before_attach["runtimeGeneration"],
            "runtimeGenerationAfter": ctx.c_status_after_attach["runtimeGeneration"],
            "attachmentGenerationBefore": ctx.c_status_before_attach["attachmentGeneration"],
            "attachmentGenerationAfter": ctx.c_status_after_attach["attachmentGeneration"],
            "bindingChangedFields": ctx.changed_binding_fields,
            "storedBindingMatchesCurrentSession": True,
            "c1SettledBeforeAttach": True,
            "c1HistoryUnchangedThroughAttach": True,
            "c1LocalBefore": ctx.c_first_before_attach,
            "c1LocalAfter": ctx.c_first_after_attach,
            "c1WorkerdAttemptStatesBefore": sorted(
                row["state"] for row in ctx.c_first_attempts_before_attach
            ),
            "c1WorkerdAttemptStatesAfter": sorted(
                row["state"] for row in ctx.c_first_attempts_after_attach
            ),
            "c1WorkerdClaimCountsBeforeAfter": [len(ctx.c_first_claims_before_attach),
                                                len(ctx.c_first_claims_after_attach)],
            "c1NativeReceiptStatusesBeforeAttach": ctx.c_first_receipts_before_attach[-8:],
            "c2LocalAfter": ctx.c_second_after_attach,
            "c2FenceReason": ctx.c_second_after_attach_reason["reason"],
            "c2TransportAttemptUnchanged":
                ctx.c_second_transport_after_attach == ctx.c_second_transport_baseline,
            "c2EnvelopeImmutableThroughFence":
                ctx.c_second_envelope_after_attach_sha256 == ctx.c_second_envelope_sha256,
            "c2ClaimCountAfter": len(native_claims_for(
                ctx.c_second_cloud_after_attach, ctx.c_second_envelope["attemptId"],
            )),
            "c2NativeStartCountAfter": len([start for start in ctx.start_calls["C"]
                if start["attemptId"] == ctx.c_second_envelope["attemptId"]]),
        },
        "postAttachC3": {"listenerAccepted": True, "localState": "observed",
                         "workerdAttemptCount": len(ctx.c_third_attempts),
                         "workerdAttemptState": ctx.c_third_attempts[0]["state"],
                         "workerdClaimCount": len(ctx.c_third_claims),
                         "nativeStartCount": len(ctx.c_third_start_calls),
                         "exactlyOneStartOnC": len(ctx.start_calls["C"])
                         == ctx.starts_before_busy_delivery + 1,
                         "bindingChangedAfterCompletedTurn": bool(ctx.c_binding_fields_after_third),
                         "changedBindingFields": ctx.c_binding_fields_after_third},
        "observedAckRestart": {"daemonRestarted": True, "nativeProcessRestarted": False,
                                "firstReplyLostAfterWorkerdCommit": True,
                                "ackBodyBytesIdentical": True, "proofNonceChanged": True,
                                "nativeStartCount": len(ctx.start_calls["A"])},
        "fixtureBoundaries": ["synthetic Access and Messaging identity/budget",
                              "fixture owner manual publication",
                              "fixture queue and queue metrics", "loopback transport instead of Mesh",
                              "synthetic local model provider"],
        "controlledAssertions": {"threeIndependentAttachments": True,
                                  "aOnlyAndBOnlySessionIsolation": True,
                                  "busyDeliveryRemainsDurableWithoutStart": True,
                                  "changedBindingRequiresExplicitAttach": True,
                                  "oldGenerationDeliveryFencedWithoutStart": True,
                                  "newGenerationDeliverySettledExactlyOnce": True,
                                  "observedAckReplayLeavesWorkerdStateUnchanged": True,
                                  "exactObservedAckRetryAfterDaemonRestart": True},
        "sourceSha256": {
            "runner": digest(HERE.joinpath("three-session-workerd.py").read_bytes()),
            "workerFixture": digest(HERE.joinpath("coupled-workerd-worker.ts").read_bytes()),
            "broker": digest(HERE.joinpath("coupled-workerd-broker.mjs").read_bytes()),
            "nativeHostQualifier": digest(Path(host_qualifier.__file__).read_bytes()),
            "launcherSmoke": digest(Path(smoke.__file__).read_bytes()),
            "installedPreflight": digest(Path(installed_helper.__file__).read_bytes()),
        },
        "cloudWireCount": len(ctx.wire_evidence),
        "realModelCalls": 0,
        "evidenceNote": "Public IDs are SHA-256 only; raw wire bodies and native mappings remain in the private mode-0600 evidence archive.",
    }
    encoded = json.dumps(ctx.proof, sort_keys=True)
    require_all("proof output contains a credential or native mapping",
                FIXTURE_ACCESS not in encoded,
                FIXTURE_AGENT not in encoded,
                '"nativeBinding":' not in encoded,
                '"transportPrivateKey":' not in encoded)
    require(len(encoded.encode()) <= 32_768, "proof exceeds fixed metadata bound")
    ctx.private_nonce_record = {
        "sourceNonceSha256": {"C1": ctx.c1_source_nonce_sha256, "C3": ctx.c3_source_nonce_sha256},
        "nonReuse": ctx.c1_source_nonce_sha256 != ctx.c3_source_nonce_sha256,
    }
    return ctx.proof, ctx.private_nonce_record


def c_second_busy_dispositions(ctx):
    return [row for row in ctx.dispatch_results
            if row["delivery"] == "C-busy-second"
            and row["reason"] == "client_unavailable_or_busy"]


async def cleanup_scenario(ctx):
    if ctx.daemon_task is not None:
        ctx.daemon_task.cancel()
        await asyncio.gather(ctx.daemon_task, return_exceptions=True)
    if "C" in ctx.sessions:
        ctx.sessions["C"]["provider"].release_hold.set()
    try:
        await drain_native_observers(ctx)
    finally:
        restore_observers(ctx)
        finish_scenario_cleanup(ctx)


def finish_scenario_cleanup(ctx):
    cleanup_error = None
    try:
        broker_cleanup = stop_broker(ctx.broker, ctx.broker_log)
        if ctx.proof is not None:
            ctx.proof["brokerCleanup"] = broker_cleanup
    except AssertionError as error:
        cleanup_error = error
    if cleanup_error is not None and sys.exc_info()[0] is None:
        raise cleanup_error
    if cleanup_error is not None:
        print(str(cleanup_error), file=sys.stderr)
    if ctx.private_nonce_record is not None:
        private_path = Path(ctx.args.output).with_name(Path(ctx.args.output).stem + ".private-causal.json")
        try:
            private_json(private_path, ctx.private_nonce_record)
        except OSError as error:
            if cleanup_error is None:
                raise AssertionError("private nonce causal record unavailable: "
                                     + type(error).__name__) from None
            print("private nonce causal record unavailable: " + type(error).__name__,
                  file=sys.stderr)
    if ctx.state_root.exists():
        import shutil
        shutil.rmtree(ctx.state_root)


def restore_observers(ctx):
    client_runtime._send_https = ctx.original_send_https
    launcher._session_request = ctx.original_session_request
    Store.list_pending = ctx.original_list_pending
    Store.list_reconcilable = ctx.original_list_reconcilable
    daemon.Gateway.dispatch = ctx.original_dispatch
    daemon.Gateway.reconcile = ctx.original_reconcile
    daemon.NativeBridgeAdapter.check = ctx.original_adapter_check
    daemon.NativeBridgeAdapter.reconcile = ctx.original_adapter_reconcile
    SessionNativeBridge.challenge = ctx.original_bridge_challenge


async def run_scenario():
    temporary_root = private_temp_root()
    containment = (verify_outer_containment(temporary_root) if args.outer_contained
                   else {"mode": "per-native-profile"})
    evidence_path = Path(args.output).with_suffix(".private-evidence.jsonl")
    with evidence_archive(evidence_path) as evidence:
        broker, broker_log, address = start_broker()
        proof = None
        private_nonce_record = None
        state_root = Path(tempfile.mkdtemp(prefix=GATEWAY_TEMP_PREFIX, dir=temporary_root))
        state_root.chmod(0o700)
        state = state_root / "state"
        state.mkdir(mode=0o700)
        node_key = private_key_type.generate()
        transport_key = private_key_type.generate()
        node_id = str(uuid4())
        transport = {"firstLost": False, "pauseRetry": False, "retryWaiting": asyncio.Event(),
                     "allowRetry": asyncio.Event(), "lostReply": asyncio.Event(), "targetDelivery": None}
        wire_evidence = []
        sessions = {}
        daemon_task = None
        start_calls = {label: [] for label in ("A", "B", "C")}
        challenge_calls = {label: 0 for label in ("A", "B", "C")}
        session_labels = {}
        original_session_request = launcher._session_request
        original_list_pending = Store.list_pending
        original_list_reconcilable = Store.list_reconcilable
        original_dispatch = daemon.Gateway.dispatch
        original_reconcile = daemon.Gateway.reconcile
        original_adapter_check = daemon.NativeBridgeAdapter.check
        original_adapter_reconcile = daemon.NativeBridgeAdapter.reconcile
        original_bridge_challenge = SessionNativeBridge.challenge
        original_send_https = client_runtime._send_https
        pending_scans = []
        reconcilable_scans = []
        receipt_calls = {label: [] for label in ("A", "B", "C")}
        receipt_errors = {label: [] for label in ("A", "B", "C")}
        adapter_receipts = []
        reconcile_results = []
        submission_returned = asyncio.Event()
        dispatch_calls = []
        dispatch_results = []
        dispatch_labels = {}
        dispatch_errors = []
        adapter_checks = []
        bridge_challenge_observations = []
        fixture_secret = address["secret"]
        ctx = SimpleNamespace(**locals())
        ctx.args = args
        ctx.installed_proof = installed_proof
        ctx.cloud_source = cloud_source
        ctx.fixture = partial(fixture, ctx)
        ctx.send = partial(send, ctx)
        ctx.start_daemon = partial(start_daemon, ctx)
        ctx.stop_daemon = partial(stop_daemon, ctx)
        ctx.deliver = partial(deliver, ctx)
        ctx.wait_observed = partial(wait_observed, ctx)
        ctx.c_second_busy_dispositions = partial(c_second_busy_dispositions, ctx)
        client_runtime._send_https = ctx.send
        launcher._session_request = partial(observe_session_request, ctx)
        Store.list_pending = partialmethod(observe_list_pending, ctx)
        Store.list_reconcilable = partialmethod(observe_list_reconcilable, ctx)
        daemon.Gateway.dispatch = partialmethod(observe_dispatch, ctx)
        daemon.Gateway.reconcile = partialmethod(observe_reconcile, ctx)
        daemon.NativeBridgeAdapter.check = partialmethod(observe_adapter_check, ctx)
        daemon.NativeBridgeAdapter.reconcile = partialmethod(observe_adapter_reconcile, ctx)
        SessionNativeBridge.challenge = partialmethod(observe_bridge_challenge, ctx)
        try:
            challenge = ctx.fixture("/fixture/challenge", {
                "nodeId": node_id,
                "publicKey": {"kty": "OKP", "crv": "Ed25519",
                              "x": b64(node_key.public_key().public_bytes_raw())},
                "meshIp": "100.96.0.1", "meshPort": 8789, "agents": [AGENT],
            })
            ctx.fixture("/v1/nodes/complete", {
                "challengeId": challenge["challengeId"],
                "signature": b64(node_key.sign(challenge["signingPayload"].encode())),
            })
            ctx.admission_cloud = CloudClient(
                origin=ORIGIN, principal=PRINCIPAL, agent=AGENT, node_id=node_id,
                node_generation=1, private_key=node_key, credentials=credentials, send=ctx.send,
            )
            with ExitStack() as resources:
                stage = "initialize"
                try:
                    await initialize_runtime(ctx, resources)
                    for stage, action in (("ab", run_ab_routes), ("busy", run_busy_stage),
                                          ("attach", run_fixture_attach), ("c3", run_post_attach_c3)):
                        await action(ctx)
                        require(not snapshot_evidence(ctx, stage), "checkpoint ledger is incomplete")
                finally:
                    # Persist while native scratch and the broker still exist, including failed stages.
                    try:
                        if ctx.daemon_task is not None:
                            await ctx.stop_daemon(ctx.daemon_task)
                            ctx.daemon_task = None
                    finally:
                        failed = sys.exc_info()[0] is not None
                        if "C" in ctx.sessions:
                            ctx.sessions["C"]["provider"].release_hold.set()
                        await drain_native_observers(ctx)
                        try:
                            missing = snapshot_evidence(ctx, "exit:" + stage)
                            require(failed or not missing, "exit checkpoint ledger is incomplete")
                        finally:
                            if not ctx.evidence.failed:
                                sync_evidence(ctx)
            ctx.proof, ctx.private_nonce_record = build_proof(ctx)
            ctx.proof["privateEvidence"] = seal_evidence(ctx)
            return ctx.proof
        finally:
            await cleanup_scenario(ctx)


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package-source", "binary", "binary-sha256", "node", "cloud-source",
                 "esbuild", "miniflare", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--outer-contained", action="store_true",
                        help="Verify an independently audited outer macOS sandbox instead of nesting native profiles")
    parser.add_argument("--cloud-commit", required=True)
    parser.add_argument("--entry-port", type=int, default=49732)
    parser.add_argument("--loopback-port", type=int, default=49733)
    parser.add_argument("--broker-port", type=int, default=49734)
    return parser.parse_args()


def main():
    parsed = cli()
    configure(parsed)
    output = Path(parsed.output)
    target = output.parent.resolve(strict=True) / output.name
    require(not target.exists() and not target.is_symlink(), "proof output already exists")
    proof = asyncio.run(run_scenario())
    encoded = (json.dumps(proof, indent=2) + "\n").encode()
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"result": "PASS", "proof": str(target),
                      "productionAdmissionProven": False, "nativeCliSessions": 3}))


if __name__ == "__main__":
    main()
