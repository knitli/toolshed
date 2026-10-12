#!/usr/bin/env python3
"""Run three isolated real Codex CLIs through the production daemon and local workerd."""

import argparse
import asyncio
import base64
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
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
import subprocess  # nosec B404 - launches only the supplied Node fixture broker.
import sys
import tempfile
import threading
import time
from uuid import uuid4


HERE = Path(__file__).resolve().parent
PRINCIPAL = "qualification@example.com"
AGENT = "pilot"
ORIGIN = "https://events.example.com"
FIXTURE_ACCESS = "fixture-access"
FIXTURE_AGENT = "fixture-agent"

args = None
binary = node = cloud_source = package_source = None
launcher = daemon = client_runtime = gateway_cli = Store = CloudClient = Credentials = None
SessionNativeBridge = private_key_type = serialization = None
smoke = host_qualifier = installed_helper = installed_proof = None
identity_fields = ()


def require(value, message):
    if not value:
        raise AssertionError(message)


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
            kind = host_qualifier.request_kind(request)
            self.server.requests.append(kind)
            if kind == "main":
                self.server.main_requests.append(request)
                self.server.turn_main_requests.append(request)
            main_requests = len(self.server.turn_main_requests)
            with self.server.hold_lock:
                hold = self.server.hold_next
                self.server.hold_next = False if hold else self.server.hold_next
            if hold:
                self.server.hold_started.set()
                require(self.server.release_hold.wait(60), "controlled model hold expired")
            if kind == "title":
                self.server.turn_title_count += 1
                require(self.server.turn_title_count == 1, "extra title request")
                item = {"type": "message", "role": "assistant", "id": "three-title",
                        "content": [{"type": "output_text", "text": '{"title":"Controlled event"}'}]}
                events = [{"type": "response.output_item.done", "item": item},
                          host_qualifier.completed("three-title")]
            elif main_requests % 2 == 1:
                item = {"type": "custom_tool_call", "call_id": host_qualifier.CALL_ID,
                        "name": "exec", "input": self.server.program}
                events = [{"type": "response.created", "response": {"id": "three-main-" + str(main_requests)}},
                          {"type": "response.output_item.done", "item": item},
                          host_qualifier.completed("three-main-" + str(main_requests))]
            else:
                host_qualifier.verify_output(self.server.turn_main_requests[-2:], self.server.nonce)
                identity = "three-main-" + str(main_requests)
                item = {"type": "message", "role": "assistant", "id": identity,
                        "content": [{"type": "output_text", "text": "Offline read completed."}]}
                events = [{"type": "response.output_item.done", "item": item},
                          host_qualifier.completed(identity)]
            payload = "".join("data: " + json.dumps(event) + "\n\n" for event in events).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as error:
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


def free_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def private_json(path, value):
    raw = (json.dumps(value, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


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
        require(type(address.get("port")) is int and isinstance(address.get("secret"), str),
                "workerd fixture handshake invalid")
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
    result = subprocess.run(
        ["/bin/ps", "-axo", "pgid=,pid="], check=True, capture_output=True,
        text=True, timeout=5,
    )
    members = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].isdigit() and fields[1].isdigit() \
                and int(fields[0]) == group_id:
            members.append(int(fields[1]))
    return members


def process_is_running(pid):
    if type(pid) is not int or pid <= 1:
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
    backend_stopped = type(backend_pid) is int and not process_is_running(backend_pid)
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
    require(cloud_source.name == "src" and cloud_source.parent.name == "event-runtime",
            "cloud source must end at apps/os/packages/event-runtime/src")
    output_path = Path(parsed.output)
    require(output_path.is_absolute() and output_path.parent.resolve(strict=True).is_dir(),
            "output must be absolute and its parent must exist")
    require(not output_path.is_symlink() and not output_path.exists(), "proof output must be new")
    git = Path("/usr/bin/git")
    require(git.is_file() and os.access(git, os.X_OK), "system git unavailable")
    revision = subprocess.run(
        [str(git), "-C", str(cloud_source), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    require(revision == parsed.cloud_commit, "cloud source commit differs from proof input")
    require(len(set((parsed.entry_port, parsed.loopback_port, parsed.broker_port))) == 3,
            "workerd fixture ports must be distinct")
    require(all(1024 <= value <= 65535 for value in (parsed.entry_port, parsed.loopback_port, parsed.broker_port)),
            "workerd fixture port outside range")

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
    server = ThreadingHTTPServer(("127.0.0.1", 0), ModelProvider)
    server.requests = []
    server.main_requests = []
    server.turn_main_requests = []
    server.turn_title_count = 0
    server.phase = "initial"
    server.errors = []
    server.request_lock = threading.Lock()
    server.active_requests = 0
    server.hold_lock = threading.Lock()
    server.hold_next = hold
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


def native_session(stack, label, shared_state, *, hold=False):
    temporary = tempfile.TemporaryDirectory(prefix="three-native-", dir="/private/tmp")
    root = Path(temporary.name)
    root.chmod(0o700)
    stack.callback(temporary.cleanup)
    provider = make_model(stack, hold=hold)
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
    state = Path(shared_state)
    argv = host_qualifier.launch_argv(profile, cache, state, binary, root)
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
    socket_path, status, binding, challenge = wait_shared_selection(
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
    with sqlite3.connect(uri, uri=True, timeout=3) as db:
        db.execute("PRAGMA busy_timeout=3000")
        row = db.execute("SELECT state FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
        attempt = db.execute("SELECT state FROM attempts WHERE delivery_id=?", (delivery_id,)).fetchone()
        return {"state": row[0] if row else None, "attemptState": attempt[0] if attempt else None}


def db_delivery_envelope_sha256(state, delivery_id):
    db_path = Path(state) / "ledger.sqlite"
    uri = "file:" + str(db_path) + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=3) as db:
        db.execute("PRAGMA busy_timeout=3000")
        row = db.execute("SELECT envelope FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
        return digest(row[0]) if row else None


def db_delivery_reason(state, delivery_id):
    db_path = Path(state) / "ledger.sqlite"
    uri = "file:" + str(db_path) + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=3) as db:
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
                return binding
        else:
            stable_observations = 0
        previous = observation
        await asyncio.sleep(0.25)
    raise AssertionError("native binding/model activity did not stabilize after completed turn")


async def run_scenario():
    broker, broker_log, address = start_broker()
    proof = None
    private_nonce_record = None
    state_root = Path(tempfile.mkdtemp(prefix="three-gateway-", dir="/private/tmp"))
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

    def fixture(path, body=None):
        status, _, raw = post(address["port"], fixture_secret, path, body)
        require(status == 200, "workerd fixture rejected " + path)
        return json.loads(raw)

    async def send(**request):
        nonlocal transport
        require(request["method"] == "POST" and request["url"].startswith(ORIGIN + "/"),
                "CloudClient left the closed fixture origin")
        require((request["timeout"], request["max_response_bytes"], request["follow_redirects"])
                == (5, 8192, False), "CloudClient request limits changed")
        path = request["url"].removeprefix(ORIGIN)
        body = json.loads(request["body"])
        proof = json.loads(request["headers"]["x-event-node-proof"])
        response = await asyncio.to_thread(
            post, address["port"], fixture_secret, path, request["body"], request["headers"], limit=8192,
        )
        response_summary = None
        if path == "/v1/runtimes/status":
            try:
                value = json.loads(response[2])
                native_binding = value.get("nativeBinding") if isinstance(value, dict) else None
                response_summary = {
                    "keys": sorted(value) if isinstance(value, dict) else None,
                    "status": value.get("status") if isinstance(value, dict) else None,
                    "generationValues": {key: value.get(key) for key in
                                         ("runtimeGeneration", "nodeGeneration", "attachmentGeneration")}
                                        if isinstance(value, dict) else None,
                    "bindingKeys": sorted(native_binding) if isinstance(native_binding, dict) else None,
                }
            except (TypeError, ValueError):
                response_summary = {"parse": "failed"}
        wire_evidence.append({
            "path": path, "bodySha256": digest(request["body"]), "responseStatus": response[0],
            "proofNonceSha256": digest(proof["nonce"]),
            "ackStatus": body.get("status") if path == "/v1/ack" else None,
            "deliverySha256": digest(body["deliveryId"]) if "deliveryId" in body else None,
            "responseSummary": response_summary,
        })
        if (path == "/v1/ack" and body.get("status") == "observed"
                and body.get("deliveryId") == transport["targetDelivery"] and response[0] == 200):
            if not transport["firstLost"]:
                transport["firstLost"] = True
                result = json.loads(response[2])
                require(result.get("status") == "observed", "workerd did not commit observed ACK before loss")
                transport["lostReply"].set()
                raise TimeoutError("controlled lost reply after workerd commit")
            if transport["pauseRetry"]:
                transport["retryWaiting"].set()
                await transport["allowRetry"].wait()
        return response

    def observe_session_request(state_dir, session_id, message, *, native_request=None):
        label = session_labels.get(session_id)
        if message.get("command") == "challenge" and label in challenge_calls:
            challenge_calls[label] += 1
        if message.get("command") == "nativeStart":
            require(label in start_calls, "native Start came from an unknown session")
            request_value = native_request or {}
            start_calls[label].append({
                "eventId": request_value.get("event", {}).get("eventId"),
                "attemptId": request_value.get("attemptId"),
                "threadId": request_value.get("threadId"),
            })
        try:
            result = original_session_request(state_dir, session_id, message, native_request=native_request)
        except Exception as error:
            if message.get("command") == "nativeReceipt" and label in receipt_errors:
                receipt_errors[label].append(getattr(error, "code", str(error)))
            raise
        if message.get("command") == "nativeReceipt" and label in receipt_calls:
            receipt_calls[label].append(result.get("outcome", {}).get("status"))
        return result

    def observe_list_pending(store):
        rows = original_list_pending(store)
        pending_scans.append(len(rows))
        return rows

    def observe_list_reconcilable(store):
        rows = original_list_reconcilable(store)
        reconcilable_scans.append([row.get("state") for row in rows])
        return rows

    async def observe_dispatch(gateway, delivery_id):
        label = dispatch_labels.get(delivery_id, "unlabeled")
        dispatch_calls.append(label)
        try:
            result = await original_dispatch(gateway, delivery_id)
        except Exception as error:
            dispatch_errors.append(type(error).__name__)
            raise
        dispatch_results.append({"delivery": label, "status": result.get("status"),
                                 "reason": result.get("reason")})
        if label == "A" and result.get("status") == "submitted":
            submission_returned.set()
        return result

    async def observe_reconcile(gateway, delivery_id):
        result = await original_reconcile(gateway, delivery_id)
        reconcile_results.append({"status": result.get("status"), "reason": result.get("reason")})
        return result

    async def observe_adapter_check(adapter):
        try:
            result = await original_adapter_check(adapter)
        except Exception as error:
            adapter_checks.append({"result": "error", "error": type(error).__name__,
                                   "code": getattr(error, "code", str(error))})
            raise
        adapter_checks.append({"result": result,
                               "eligible": adapter.witness.get("eligible") if adapter.witness else None,
                               "threadMatches": (adapter.witness.get("threadId") == adapter.thread_id
                                                 if adapter.witness else None)})
        return result

    async def observe_adapter_reconcile(adapter, request):
        try:
            result = await original_adapter_reconcile(adapter, request)
        except Exception as error:
            adapter_receipts.append({"result": "error", "error": type(error).__name__,
                                     "code": getattr(error, "code", str(error))})
            raise
        adapter_receipts.append({"result": result.get("outcome", {}).get("status")})
        return result

    def observe_bridge_challenge(bridge):
        try:
            witness = original_bridge_challenge(bridge)
        except Exception as error:
            bridge_challenge_observations.append({"result": "error",
                                                  "error": type(error).__name__,
                                                  "code": getattr(error, "code", str(error))})
            raise
        bridge_challenge_observations.append({"result": "witness",
                                              "eligible": witness.get("eligible")})
        return witness

    launcher._session_request = observe_session_request
    Store.list_pending = observe_list_pending
    Store.list_reconcilable = observe_list_reconcilable
    daemon.Gateway.dispatch = observe_dispatch
    daemon.Gateway.reconcile = observe_reconcile
    daemon.NativeBridgeAdapter.check = observe_adapter_check
    daemon.NativeBridgeAdapter.reconcile = observe_adapter_reconcile
    SessionNativeBridge.challenge = observe_bridge_challenge
    client_runtime._send_https = send
    try:
        challenge = fixture("/fixture/challenge", {
            "nodeId": node_id,
            "publicKey": {"kty": "OKP", "crv": "Ed25519",
                          "x": b64(node_key.public_key().public_bytes_raw())},
            "meshIp": "100.96.0.1", "meshPort": 8789, "agents": [AGENT],
        })
        fixture("/v1/nodes/complete", {
            "challengeId": challenge["challengeId"],
            "signature": b64(node_key.sign(challenge["signingPayload"].encode())),
        })
        admission_cloud = CloudClient(
            origin=ORIGIN, principal=PRINCIPAL, agent=AGENT, node_id=node_id,
            node_generation=1, private_key=node_key, credentials=credentials, send=send,
        )

        with ExitStack() as resources:
            for label in ("A", "B", "C"):
                session = native_session(resources, label, state, hold=False)
                sessions[label] = session
                session_labels[session["sessionId"]] = label
            require(len({session["sessionId"] for session in sessions.values()}) == 3,
                    "three native sessions did not receive distinct session IDs")
            for field in ("clientId", "threadId"):
                require(len({session["binding"][field] for session in sessions.values()}) == 3,
                        "three native sessions did not receive distinct " + field + " values")
            all_initially_selected_idle = all(
                session["initiallySelectedIdle"] for session in sessions.values()
            )
            require(all_initially_selected_idle,
                    "one or more native sessions were not selected and idle before delivery")

            runtime_ids = {label: str(uuid4()) for label in sessions}
            attached = {}
            for label, session in sessions.items():
                try:
                    attached[label] = await admit_runtime(admission_cloud, session, runtime_ids[label])
                except Exception as error:
                    readback = fixture("/fixture/admission")
                    stored_clients = []
                    for row in readback["native_runtime_bindings"]:
                        try:
                            stored_clients.append(digest(json.loads(row["binding_json"])["clientId"]))
                        except (KeyError, TypeError, ValueError):
                            stored_clients.append("invalid")
                    raise AssertionError("native runtime attach failed: " + json.dumps({
                        "label": label,
                        "code": getattr(error, "code", type(error).__name__),
                        "sessionCount": len(sessions),
                        "distinctClientHashes": len({digest(value["binding"]["clientId"])
                                                       for value in sessions.values()}),
                        "distinctThreadHashes": len({digest(value["binding"]["threadId"])
                                                      for value in sessions.values()}),
                        "clientHashes": {name: digest(value["binding"]["clientId"])
                                         for name, value in sessions.items()},
                        "storedClientHashes": stored_clients,
                        "persistedRuntimeCount": len(readback["runtimes"]),
                    }, sort_keys=True)) from None
            admission_readback = fixture("/fixture/admission")
            require(len(admission_readback["runtimes"]) == 3
                    and len(admission_readback["native_runtime_bindings"]) == 3,
                    "workerd did not persist three independent native attachments")

            deliveries = {}
            for label, session in sessions.items():
                delivery = fixture("/fixture/setup", {
                    "runtimeId": runtime_ids[label], "nodeId": node_id,
                    "transportPrivateKey": b64(transport_key.private_bytes(
                        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )),
                    "subjectId": "three-session-route-" + label.lower(),
                })
                envelope = delivery["envelope"]
                mapping = {key: envelope[key] for key in identity_fields}
                current = attached[label]["attached"]
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
                deliveries[label] = {"envelope": envelope, "signed": delivery["signedDelivery"],
                                     "mapping": mapping}
                dispatch_labels[envelope["deliveryId"]] = label

            pem = node_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            key_path = state / "node-key.pem"
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(pem)
            private_json(state / "credentials.json", {"accessToken": FIXTURE_ACCESS,
                                                       "agentToken": FIXTURE_AGENT})
            private_json(state / "cloud.json", {
                "version": 1, "origin": ORIGIN, "principal": PRINCIPAL, "agent": AGENT,
                "nodeId": node_id, "nodeGeneration": 1, "credentialsFile": "credentials.json",
            })
            with Store(state) as store:
                for label in ("A", "B", "C"):
                    store.put_attachment(deliveries[label]["mapping"])
            listen_port = free_port()
            private_json(state / "dispatch.json", {
                "version": 1, "cloudConfig": "cloud.json", "listenHost": "127.0.0.1",
                "listenPort": listen_port,
                "transportKeys": {"fixture-transport": b64(transport_key.public_key().public_bytes_raw())},
            })

            async def start_daemon():
                task = asyncio.create_task(daemon.serve(state, dispatch_config=state / "dispatch.json"))
                await wait_until(lambda: (state / "control.sock").exists() or task.done(),
                                 "production daemon startup timed out")
                if task.done():
                    await task
                status = await daemon.request(state, {"command": "status"})
                require(status["automaticWakeEnabled"] is True
                        and status["dispatch"]["listenerReady"]
                        and status["dispatch"]["workerRunning"],
                        "production daemon dispatch path not ready")
                return task

            async def stop_daemon(task):
                task.cancel()
                result, = await asyncio.gather(task, return_exceptions=True)
                require(isinstance(result, asyncio.CancelledError), "production daemon exited unexpectedly")
                await wait_until(lambda: not (state / "control.sock").exists(),
                                 "production daemon control socket survived stop")

            async def deliver(label, delivery):
                status, raw = await asyncio.to_thread(listener_delivery, listen_port, delivery["signed"])
                require(status == 202, "production listener refused signed " + label + " delivery")
                return json.loads(raw)

            async def wait_observed(label):
                delivery_id = deliveries[label]["envelope"]["deliveryId"]
                await wait_until(lambda: db_delivery(state, delivery_id)["state"] == "observed",
                                 label + " delivery did not reach observed state")
                cloud = fixture("/fixture/read")
                attempt_id = deliveries[label]["envelope"]["attemptId"]
                observed = attempts_for(cloud, attempt_id)
                require(len(observed) == 1 and observed[0]["state"] == "observed",
                        label + " delivery missing observed Workerd attempt")
                return cloud

            # Configure A's observed reply loss to stop the first daemon after commit.
            transport.update(targetDelivery=deliveries["A"]["envelope"]["deliveryId"], pauseRetry=True)
            daemon_task = await start_daemon()
            await deliver("A-only", deliveries["A"])
            await wait_until(lambda: submission_returned.is_set(),
                             "production daemon did not submit A's idle-session event")
            await stop_daemon(daemon_task)
            daemon_task = None
            await wait_until(lambda: sessions["A"]["process"].poll() is None
                             and len(sessions["A"]["provider"].main_requests) >= 2
                             and launcher.session_status(sessions["A"]["state"], sessions["A"]["sessionId"])
                             .get("selection") == "selected",
                             "A's native input did not finish while the daemon was stopped")
            daemon_task = await start_daemon()
            try:
                await wait_until(lambda: transport["lostReply"].is_set(),
                                 "workerd observed-ACK reply was not deliberately lost")
            except AssertionError as error:
                local = db_delivery(state, deliveries["A"]["envelope"]["deliveryId"])
                cloud = fixture("/fixture/read")["cloud"]
                try:
                    dispatch_status = await daemon.request(state, {"command": "status"})
                except Exception as status_error:
                    dispatch_status = {"controlError": type(status_error).__name__}
                diagnostic = {
                    "nativeStarts": {label: len(start_calls[label]) for label in start_calls},
                    "challengeRequests": challenge_calls,
                    "wirePaths": [row["path"] for row in wire_evidence[-24:]],
                    "localDelivery": local,
                    "cloudRows": {table: len(cloud[table]) for table in
                                  ("attempts", "deliveries", "native_claims", "slot_intents")},
                    "providerRequests": len(sessions["A"]["provider"].requests),
                    "providerKinds": list(sessions["A"]["provider"].requests),
                    "providerErrors": list(sessions["A"]["provider"].errors),
                    "dispatchStatus": dispatch_status.get("dispatch"),
                    "pendingScans": pending_scans[-16:],
                    "reconcilableScans": reconcilable_scans[-8:],
                    "reconcileResults": reconcile_results[-8:],
                    "receiptCalls": {label: calls[-12:] for label, calls in receipt_calls.items()},
                    "receiptErrors": {label: calls[-12:] for label, calls in receipt_errors.items()},
                    "adapterReceipts": adapter_receipts[-12:],
                    "dispatchCallCount": len(dispatch_calls),
                    "dispatchResults": dispatch_results[-8:],
                    "dispatchErrors": dispatch_errors[-8:],
                    "adapterChecks": adapter_checks[-12:],
                    "bridgeChallenges": bridge_challenge_observations[-12:],
                    "daemonTaskDone": daemon_task.done(),
                    "daemonTaskError": (type(daemon_task.exception()).__name__
                                        if daemon_task.done() and daemon_task.exception() else None),
                    "sessionStates": {label: {
                        "selection": launcher.session_status(session["state"], session["sessionId"]).get("selection"),
                        "attached": launcher.session_status(session["state"], session["sessionId"]).get("attached"),
                    } for label, session in sessions.items()},
                }
                raise AssertionError(str(error) + "; bounded diagnostic="
                                     + json.dumps(diagnostic, sort_keys=True)) from None
            await wait_until(lambda: transport["retryWaiting"].is_set(),
                             "daemon did not retry exact observed ACK")
            state_before_replay = fixture("/fixture/read")
            first_ack = [row for row in wire_evidence if row["path"] == "/v1/ack"
                         and row["ackStatus"] == "observed"
                         and row["deliverySha256"] == digest(transport["targetDelivery"])][0]
            await stop_daemon(daemon_task)
            daemon_task = None
            transport["pauseRetry"] = False
            transport["allowRetry"].set()
            daemon_task = await start_daemon()
            await wait_until(lambda: db_delivery(state, deliveries["A"]["envelope"]["deliveryId"])["state"]
                             == "observed", "A ACK was not recovered after daemon restart")
            state_after_replay = await wait_observed("A")
            second_acks = [row for row in wire_evidence if row["path"] == "/v1/ack"
                            and row["ackStatus"] == "observed"
                            and row["deliverySha256"] == digest(transport["targetDelivery"])]
            require(len(second_acks) >= 2 and first_ack["bodySha256"] == second_acks[-1]["bodySha256"]
                    and first_ack["proofNonceSha256"] != second_acks[-1]["proofNonceSha256"],
                    "daemon restart did not replay identical ACK bytes with fresh proof")
            require(state_after_replay == state_before_replay,
                    "observed-ACK replay changed committed Workerd state")
            require(len(start_calls["A"]) == 1 and not start_calls["B"] and not start_calls["C"],
                    "A-only delivery escaped its native session")
            a_route_counts = {label: len(start_calls[label]) for label in start_calls}

            await deliver("B-only", deliveries["B"])
            await wait_observed("B")
            require(len(start_calls["A"]) == 1 and len(start_calls["B"]) == 1
                    and not start_calls["C"], "B-only delivery escaped its native session")
            b_route_counts = {label: len(start_calls[label]) for label in start_calls}

            # C's first controlled turn holds its local model request open. A second
            # signed delivery must remain locally queued without a claim or native Start.
            c_first = fixture("/fixture/setup", {
                "runtimeId": runtime_ids["C"], "nodeId": node_id,
                "transportPrivateKey": b64(transport_key.private_bytes(
                    serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )),
                "subjectId": "three-session-c-busy-first",
            })
            c_first_envelope = c_first["envelope"]
            dispatch_labels[c_first_envelope["deliveryId"]] = "C-busy-first"
            c_first_signed = c_first["signedDelivery"]
            c_second = fixture("/fixture/setup", {
                "runtimeId": runtime_ids["C"], "nodeId": node_id,
                "transportPrivateKey": b64(transport_key.private_bytes(
                    serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )),
                "subjectId": "three-session-c-busy-second",
            })
            c_second_envelope = c_second["envelope"]
            dispatch_labels[c_second_envelope["deliveryId"]] = "C-busy-second"
            c_second_signed = c_second["signedDelivery"]
            c_second_transport_rows = attempts_for(fixture("/fixture/read"), c_second_envelope["attemptId"])
            c_second_transport_baseline = transport_attempt_snapshot(c_second_transport_rows)
            require(c_second_transport_baseline == {
                "state": "created", "reservation_state": "none", "transport_status": "sending",
                "permit_id": None, "submission_id": None, "turn_id": None,
            }, "fixture did not create the expected unreserved C2 transport-attempt baseline")
            sessions["C"]["provider"].hold_next = True
            sessions["C"]["provider"].release_hold.clear()
            c_first_status, _ = await asyncio.to_thread(listener_delivery, listen_port, c_first_signed)
            require(c_first_status == 202, "production listener refused C busy-first delivery")
            await wait_until(lambda: sessions["C"]["provider"].hold_started.is_set(),
                             "C native CLI did not enter the controlled busy state")
            c_first_id = c_first_envelope["deliveryId"]
            await wait_until(lambda: db_delivery(state, c_first_id)["attemptState"] in
                             ("submitted", "observed"), "C busy-first event did not reach native Start")
            c_first_cloud = fixture("/fixture/read")
            c_first_attempts = attempts_for(c_first_cloud, c_first_envelope["attemptId"])
            require(c_first_attempts and c_first_attempts[0]["state"] in ("submitted", "observed"),
                    "C busy-first event did not persist in Workerd")
            starts_before_busy_delivery = len(start_calls["C"])
            require(starts_before_busy_delivery == 1, "C busy-first event did not issue exactly one native Start")
            status, raw = await asyncio.to_thread(listener_delivery, listen_port, c_second_signed)
            require(status == 202, "production listener refused C busy delivery")
            await wait_until(lambda: db_delivery(state, c_second_envelope["deliveryId"])["state"] == "queued",
                             "C busy delivery was not durably queued")
            c_second_envelope_sha256 = db_delivery_envelope_sha256(
                state, c_second_envelope["deliveryId"],
            )
            require(c_second_envelope_sha256 is not None,
                    "queued C2 envelope was unavailable for immutability check")
            def c_second_busy_dispositions():
                return [row for row in dispatch_results
                        if row["delivery"] == "C-busy-second"
                        and row["reason"] == "client_unavailable_or_busy"]

            try:
                await wait_until(lambda: bool(c_second_busy_dispositions()),
                                 "production dispatch did not return C's busy disposition", timeout=10)
            except AssertionError as error:
                cloud = fixture("/fixture/read")
                diagnostic = {
                    "cSecondDispatchCalls": dispatch_calls.count("C-busy-second"),
                    "cSecondDispatchResults": [row for row in dispatch_results
                                                if row["delivery"] == "C-busy-second"][-8:],
                    "localDelivery": db_delivery(state, c_second_envelope["deliveryId"]),
                    "attemptCount": len(attempts_for(cloud, c_second_envelope["attemptId"])),
                    "claimCount": len(native_claims_for(cloud, c_second_envelope["attemptId"])),
                    "nativeStartCount": len(start_calls["C"]),
                    "providerRequests": len(sessions["C"]["provider"].requests),
                    "providerErrors": list(sessions["C"]["provider"].errors),
                    "daemonTaskDone": daemon_task.done(),
                }
                raise AssertionError(str(error) + "; bounded diagnostic="
                                     + json.dumps(diagnostic, sort_keys=True)) from None
            await asyncio.sleep(1.5)
            c_second_cloud = fixture("/fixture/read")
            c_second_local = db_delivery(state, c_second_envelope["deliveryId"])
            c_second_attempts = attempts_for(c_second_cloud, c_second_envelope["attemptId"])
            c_second_claims = native_claims_for(c_second_cloud, c_second_envelope["attemptId"])
            c_second_transport_after_busy = transport_attempt_snapshot(c_second_attempts)
            c_second_start_calls = [start for label in start_calls
                                    for start in start_calls[label]
                                    if start["attemptId"] == c_second_envelope["attemptId"]]
            busy_assertions = {
                "localDelivery": c_second_local,
                "busyDispositions": c_second_busy_dispositions()[-4:],
                "transportAttemptCount": len(c_second_attempts),
                "transportAttemptBaseline": c_second_transport_baseline,
                "transportAttemptAfterBusy": c_second_transport_after_busy,
                "claimCount": len(c_second_claims),
                "nativeStartCount": len(c_second_start_calls),
                "totalCStarts": len(start_calls["C"]),
                "expectedCStarts": starts_before_busy_delivery,
            }
            require(c_second_local == {"state": "queued", "attemptState": None}
                    and bool(c_second_busy_dispositions())
                    and db_delivery_envelope_sha256(state, c_second_envelope["deliveryId"])
                    == c_second_envelope_sha256
                    and c_second_transport_after_busy == c_second_transport_baseline
                    and not c_second_claims
                    and not c_second_start_calls
                    and len(start_calls["C"]) == starts_before_busy_delivery,
                    "C busy delivery did not remain queued after production returned busy; diagnostic="
                    + json.dumps(busy_assertions, sort_keys=True))
            await stop_daemon(daemon_task)
            daemon_task = None
            require(db_delivery(state, c_second_envelope["deliveryId"])
                    == {"state": "queued", "attemptState": None}
                    and db_delivery_envelope_sha256(state, c_second_envelope["deliveryId"])
                    == c_second_envelope_sha256
                    and sessions["C"]["provider"].hold_started.is_set()
                    and not sessions["C"]["provider"].release_hold.is_set()
                    and len(start_calls["C"]) == starts_before_busy_delivery,
                    "stopping the daemon did not retain C's queue while its native turn stayed busy")
            busy_result_count = len(c_second_busy_dispositions())
            daemon_task = await start_daemon()
            await wait_until(lambda: len(c_second_busy_dispositions()) > busy_result_count,
                             "restarted daemon did not observe C still busy", timeout=10)
            await asyncio.sleep(1.0)
            c_second_cloud_after_restart = fixture("/fixture/read")
            c_second_attempts_after_restart = attempts_for(
                c_second_cloud_after_restart, c_second_envelope["attemptId"],
            )
            c_second_transport_after_restart = transport_attempt_snapshot(c_second_attempts_after_restart)
            require(db_delivery(state, c_second_envelope["deliveryId"])
                    == {"state": "queued", "attemptState": None}
                    and db_delivery_envelope_sha256(state, c_second_envelope["deliveryId"])
                    == c_second_envelope_sha256
                    and c_second_transport_after_restart == c_second_transport_baseline
                    and not native_claims_for(c_second_cloud_after_restart, c_second_envelope["attemptId"])
                    and len(start_calls["C"]) == starts_before_busy_delivery,
                    "restarted busy delivery did not remain queued without cloud or native start")
            await stop_daemon(daemon_task)
            daemon_task = None
            sessions["C"]["provider"].release_hold.set()
            current_binding = await wait_stable_session_binding(
                sessions["C"], sessions["C"]["provider"],
                minimum_turn_main_requests=2, timeout=75,
            )
            same_binding_after_turn = current_binding == sessions["C"]["binding"]
            queued_while_stopped = db_delivery(state, c_second_envelope["deliveryId"])
            require(queued_while_stopped["state"] == "queued",
                    "C busy delivery did not remain queued while the daemon was stopped")
            require(not same_binding_after_turn,
                    "controlled C turn did not rotate its native binding for explicit reattachment")

            # A changed native identity cannot inherit C2. Use the normal CLI
            # attach path with Workerd's current generations and fresh native
            # challenge while the daemon is stopped; Store fences the old queue.
            c_first_id = c_first_envelope["deliveryId"]
            c_first_before_attach = db_delivery(state, c_first_id)
            c_first_workerd_before_attach = fixture("/fixture/read")
            c_first_attempts_before_attach = attempts_for(
                c_first_workerd_before_attach, c_first_envelope["attemptId"],
            )
            c_first_claims_before_attach = native_claims_for(
                c_first_workerd_before_attach, c_first_envelope["attemptId"],
            )
            c_first_receipts_before_attach = list(receipt_calls["C"])
            with Store(state) as store:
                c_mapping_before_attach = store.get_attachment(runtime_ids["C"])
            require(c_mapping_before_attach is not None
                    and c_mapping_before_attach["nativeBinding"] == sessions["C"]["binding"],
                    "C local attachment did not retain its original binding before fixture attach")
            changed_binding_fields = sorted(
                key for key, value in current_binding.items()
                if c_mapping_before_attach["nativeBinding"].get(key) != value
            )
            require(bool(changed_binding_fields), "C native binding changed without any field delta")
            try:
                c_status_before_attach = await admission_cloud.runtime_status(runtime_ids["C"])
            except Exception as error:
                raise AssertionError("runtime status readback failed before fixture attach: "
                                     + json.dumps({"error": type(error).__name__,
                                                   "wire": wire_evidence[-1:]}, sort_keys=True)) from None
            require(c_status_before_attach["status"] == "present"
                    and c_status_before_attach["storedQualified"] is True,
                    "fixture runtime status did not report the stored qualified C attachment")
            attach_argv = [
                "--state-dir", str(state), "attach",
                "--runtime-id", runtime_ids["C"],
                "--session-id", sessions["C"]["sessionId"],
                "--cloud-config", str(state / "cloud.json"),
                "--expected-runtime-generation", str(c_status_before_attach["runtimeGeneration"]),
                "--expected-attachment-generation", str(c_status_before_attach["attachmentGeneration"]),
            ]
            attach_exit, attach_result = await asyncio.to_thread(run_cli_capture, attach_argv)
            require(attach_exit == 0 and attach_result.get("remoteStatus") == "attached"
                    and attach_result.get("localStatus") == "current",
                    "production attach CLI did not commit and persist the fixture binding")
            c_status_after_attach = await admission_cloud.runtime_status(runtime_ids["C"])
            with Store(state) as store:
                c_mapping_after_attach = store.get_attachment(runtime_ids["C"])
            attached_current = (c_mapping_after_attach is not None
                                and c_status_after_attach["status"] == "present"
                                and c_status_after_attach["runtimeGeneration"]
                                == c_status_before_attach["runtimeGeneration"] + 1
                                and c_status_after_attach["attachmentGeneration"]
                                == c_status_before_attach["attachmentGeneration"] + 1
                                and c_mapping_after_attach["runtimeGeneration"]
                                == c_status_after_attach["runtimeGeneration"]
                                and c_mapping_after_attach["attachmentGeneration"]
                                == c_status_after_attach["attachmentGeneration"]
                                and c_mapping_after_attach["nativeBinding"] == current_binding
                                and c_mapping_after_attach["sessionId"] == sessions["C"]["sessionId"])
            require(attached_current,
                    "production attach CLI mapping mismatch: "
                    + json.dumps({
                        "exit": attach_exit,
                        "remoteStatus": attach_result.get("remoteStatus"),
                        "localStatus": attach_result.get("localStatus"),
                        "statusBefore": {key: c_status_before_attach.get(key) for key in
                                         ("status", "runtimeGeneration", "attachmentGeneration")},
                        "statusAfter": {key: c_status_after_attach.get(key) for key in
                                        ("status", "runtimeGeneration", "attachmentGeneration")},
                        "mappingAfter": ({"runtimeGeneration": c_mapping_after_attach.get("runtimeGeneration"),
                                          "attachmentGeneration": c_mapping_after_attach.get("attachmentGeneration"),
                                          "bindingMatches": c_mapping_after_attach.get("nativeBinding")
                                          == current_binding,
                                          "sessionMatches": c_mapping_after_attach.get("sessionId")
                                          == sessions["C"]["sessionId"]}
                                         if c_mapping_after_attach else None),
                    }, sort_keys=True))
            c_second_after_attach = db_delivery(state, c_second_envelope["deliveryId"])
            c_second_after_attach_reason = db_delivery_reason(state, c_second_envelope["deliveryId"])
            c_second_envelope_after_attach_sha256 = db_delivery_envelope_sha256(
                state, c_second_envelope["deliveryId"],
            )
            c_second_cloud_after_attach = fixture("/fixture/read")
            c_second_transport_after_attach = transport_attempt_snapshot(
                attempts_for(c_second_cloud_after_attach, c_second_envelope["attemptId"]),
            )
            require(c_second_after_attach == {"state": "stale", "attemptState": None}
                    and c_second_after_attach_reason == {
                        "state": "stale", "reason": "attachment_detached",
                    }
                    and c_second_transport_after_attach == c_second_transport_baseline
                    and c_second_envelope_after_attach_sha256 == c_second_envelope_sha256
                    and not native_claims_for(c_second_cloud_after_attach, c_second_envelope["attemptId"])
                    and len(start_calls["C"]) == starts_before_busy_delivery,
                    "explicit attach did not fence old-generation C2 without a claim or native Start")
            c_second_restart_disposition = "stale_after_explicit_fixture_attach"
            c_first_after_attach = db_delivery(state, c_first_id)
            c_first_workerd_after_attach = fixture("/fixture/read")
            c_first_attempts_after_attach = attempts_for(
                c_first_workerd_after_attach, c_first_envelope["attemptId"],
            )
            c_first_claims_after_attach = native_claims_for(
                c_first_workerd_after_attach, c_first_envelope["attemptId"],
            )

            # Reuse C's real CLI session with a fresh fixture nonce; its prior
            # C1 conversation already contains the first nonce by design.
            c1_source_nonce_sha256 = sessions["C"]["provider"].source_nonce_sha256
            sessions["C"]["provider"].nonce = "three-session-source-c-after-attach-" + uuid4().hex
            c3_source_nonce_sha256 = digest(sessions["C"]["provider"].nonce)
            require(c3_source_nonce_sha256 != c1_source_nonce_sha256,
                    "post-attach source nonce was reused")
            sessions["C"]["provider"].source_nonce_sha256 = c3_source_nonce_sha256
            sessions["C"]["provider"].source_path.write_text(
                sessions["C"]["provider"].nonce + "\n",
            )
            sessions["C"]["provider"].turn_main_requests.clear()
            sessions["C"]["provider"].turn_title_count = 0
            sessions["C"]["provider"].phase = "post-attach"
            host_qualifier.CALL_ID = "three-session-source-read-" + uuid4().hex
            c_third = fixture("/fixture/setup", {
                "runtimeId": runtime_ids["C"], "nodeId": node_id,
                "transportPrivateKey": b64(transport_key.private_bytes(
                    serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )),
                "subjectId": "three-session-c-after-attach",
            })
            c_third_envelope = c_third["envelope"]
            dispatch_labels[c_third_envelope["deliveryId"]] = "C-after-attach"
            daemon_task = await start_daemon()
            c_third_status, _ = await asyncio.to_thread(
                listener_delivery, listen_port, c_third["signedDelivery"],
            )
            require(c_third_status == 202, "production listener refused C delivery after fixture attach")
            await wait_until(
                lambda: db_delivery(state, c_third_envelope["deliveryId"])["state"] == "observed",
                "new C delivery did not settle after explicit fixture attach", timeout=30,
            )
            c_third_workerd = fixture("/fixture/read")
            c_third_attempts = attempts_for(c_third_workerd, c_third_envelope["attemptId"])
            c_third_claims = native_claims_for(c_third_workerd, c_third_envelope["attemptId"])
            c_third_start_calls = [start for label in start_calls for start in start_calls[label]
                                   if start["attemptId"] == c_third_envelope["attemptId"]]
            require(len(c_third_attempts) == 1 and c_third_attempts[0]["state"] == "observed"
                    and len(c_third_claims) == 1 and len(c_third_start_calls) == 1
                    and len(start_calls["C"]) == starts_before_busy_delivery + 1,
                    "new-generation C delivery did not claim, start, and settle exactly once")
            c_binding_after_third = await wait_stable_session_binding(
                sessions["C"], sessions["C"]["provider"],
                minimum_turn_main_requests=2, timeout=45,
            )
            c_binding_fields_after_third = sorted(
                key for key, value in c_binding_after_third.items()
                if c_mapping_after_attach["nativeBinding"].get(key) != value
            )
            await stop_daemon(daemon_task)
            daemon_task = None
            pty_drain = {
                label: {"bytesRead": session["ptyPumpStats"]["bytesRead"],
                        "readCount": session["ptyPumpStats"]["readCount"]}
                for label, session in sessions.items()
            }
            require(all(row["bytesRead"] > 0 and row["readCount"] > 0 for row in pty_drain.values()),
                    "one or more native CLI PTYs were not drained during the acceptance run")
            summaries = {
                label: {
                    "runtimeSha256": digest(runtime_ids[label]),
                    "sessionSha256": digest(sessions[label]["sessionId"]),
                    "threadSha256": digest(sessions[label]["binding"]["threadId"]),
                    "nativeStartCount": len(start_calls[label]),
                "initiallySelectedIdle": sessions[label]["initiallySelectedIdle"],
                }
                for label in sessions
            }
            provider_errors = {label: list(session["provider"].errors)
                               for label, session in sessions.items()}
            require(not any(provider_errors.values()),
                    "synthetic provider rejected a CLI request: "
                    + json.dumps(provider_errors, sort_keys=True))
            package_files = {
                str(Path(path).relative_to(installed_proof["packageRoot"])): file_digest
                for path, file_digest in installed_proof["verifiedSha256"].items()
            }
            cloud_root = cloud_source.parents[2]
            workerd_inputs = {}
            for path, file_digest in address["bundle"]["inputs"].items():
                source = Path(path).resolve(strict=True)
                try:
                    relative = source.relative_to(cloud_root)
                except ValueError:
                    continue
                workerd_inputs[str(relative)] = file_digest
            proof = {
                "result": "PASS",
                "qualification": "controlled-three-real-cli-production-daemon-workerd",
                "candidateStatus": "offline-qualified-held-promotion-candidate-pr81",
                "productionAdmissionProven": False,
                "liveMeshProven": False,
                "liveOwnerAccessProven": False,
                "liveManualCanaryProven": False,
                "nativeBinarySha256": args.binary_sha256,
                "codeModeHostSha256": launcher.QUALIFIED_CODE_MODE_HOST_SHA256,
                "installedPackageFilesSha256": package_files,
                "cloudSourceCommit": args.cloud_commit,
                "workerdBundleSha256": address["bundle"]["sha256"],
                "workerdInputsSha256": workerd_inputs,
                "productionEntrypoints": ["event_gateway.daemon.serve", "event_gateway.listener.Listener",
                                          "event_gateway.native.SessionNativeBridge", "event_gateway.gateway.Gateway"],
                "nativeCliSessions": summaries,
                "nativePtyDrain": pty_drain,
                "nativeProcessCleanup": {label: session["processCleanup"]
                                          for label, session in sessions.items()},
                "controlledModelRequests": {label: len(sessions[label]["provider"].requests)
                                             for label in sessions},
                "admissionReadback": {"runtimes": len(admission_readback["runtimes"]),
                                       "nativeBindings": len(admission_readback["native_runtime_bindings"])},
                "idleDispatch": {"allThreeInitiallySelectedAndIdle": all_initially_selected_idle,
                                 "eventTriggeredNativeInput": True,
                                 "liveUserWakeQualified": False},
                "routing": {"AOnly": {"AStarts": a_route_counts["A"], "BStarts": a_route_counts["B"],
                                       "CStarts": a_route_counts["C"], "observed": True},
                            "BOnly": {"AStarts": b_route_counts["A"], "BStarts": b_route_counts["B"],
                                       "CStarts": b_route_counts["C"], "observed": True}},
                "busyC": {"dispatchEligible": not bool(c_second_busy_dispositions()),
                          "listenerAccepted": True,
                          "localStateWhileBusy": "queued", "transportAttemptUnchanged": True,
                          "nativeClaimCreated": False,
                          "nativeStartWhileBusy": False,
                          "productionBusyDisposition": "client_unavailable_or_busy",
                          "busyDispatchCount": len(c_second_busy_dispositions())},
                "sourceNonceTransition": {"firstDelivery": "C1", "freshDelivery": "C3",
                                          "nonReuse": True},
                "busyDeliveryRestart": {"queuedWhileDaemonStopped": True,
                                         "restartedWhileNativeTurnBusy": True,
                                         "queuedAfterBusyRestart": True,
                                         "transportAttemptUnchanged": True,
                                         "nativeClaimCreated": False,
                                         "busyDispatchCountAfterRestart": len(c_second_busy_dispositions())
                                         - busy_result_count,
                                         "bindingUnchangedAfterFirstTurn": same_binding_after_turn,
                                         "disposition": c_second_restart_disposition,
                                         "nativeStartCountAtRestart": starts_before_busy_delivery},
                "explicitFixtureAttach": {
                    "productionCliPath": True, "syntheticFixtureAuthority": True,
                    "remoteStatus": attach_result.get("remoteStatus"),
                    "localStatus": attach_result.get("localStatus"),
                    "runtimeGenerationBefore": c_status_before_attach["runtimeGeneration"],
                    "runtimeGenerationAfter": c_status_after_attach["runtimeGeneration"],
                    "attachmentGenerationBefore": c_status_before_attach["attachmentGeneration"],
                    "attachmentGenerationAfter": c_status_after_attach["attachmentGeneration"],
                    "bindingChangedFields": changed_binding_fields,
                    "storedBindingMatchesCurrentSession": True,
                    "c1LocalBefore": c_first_before_attach,
                    "c1LocalAfter": c_first_after_attach,
                    "c1WorkerdAttemptStatesBefore": sorted(
                        row["state"] for row in c_first_attempts_before_attach
                    ),
                    "c1WorkerdAttemptStatesAfter": sorted(
                        row["state"] for row in c_first_attempts_after_attach
                    ),
                    "c1WorkerdClaimCountsBeforeAfter": [len(c_first_claims_before_attach),
                                                        len(c_first_claims_after_attach)],
                    "c1NativeReceiptStatusesBeforeAttach": c_first_receipts_before_attach[-8:],
                    "c2LocalAfter": c_second_after_attach,
                    "c2FenceReason": c_second_after_attach_reason["reason"],
                    "c2TransportAttemptUnchanged":
                        c_second_transport_after_attach == c_second_transport_baseline,
                    "c2EnvelopeImmutableThroughFence":
                        c_second_envelope_after_attach_sha256 == c_second_envelope_sha256,
                    "c2ClaimCountAfter": len(native_claims_for(
                        c_second_cloud_after_attach, c_second_envelope["attemptId"],
                    )),
                    "c2NativeStartCountAfter": len([start for start in start_calls["C"]
                        if start["attemptId"] == c_second_envelope["attemptId"]]),
                },
                "postAttachC3": {"listenerAccepted": True, "localState": "observed",
                                 "workerdAttemptCount": len(c_third_attempts),
                                 "workerdAttemptState": c_third_attempts[0]["state"],
                                 "workerdClaimCount": len(c_third_claims),
                                 "nativeStartCount": len(c_third_start_calls),
                                 "exactlyOneStartOnC": len(start_calls["C"])
                                 == starts_before_busy_delivery + 1,
                                 "bindingChangedAfterCompletedTurn": bool(c_binding_fields_after_third),
                                 "changedBindingFields": c_binding_fields_after_third},
                "observedAckRestart": {"daemonRestarted": True, "nativeProcessRestarted": False,
                                        "firstReplyLostAfterWorkerdCommit": True,
                                        "ackBodyBytesIdentical": True, "proofNonceChanged": True,
                                        "nativeStartCount": len(start_calls["A"])},
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
                "cloudWireCount": len(wire_evidence),
                "realModelCalls": 0,
                "evidenceNote": "IDs are represented only by SHA-256; credentials, native mappings, and raw wire bodies are omitted.",
            }
            encoded = json.dumps(proof, sort_keys=True)
            require(FIXTURE_ACCESS not in encoded and FIXTURE_AGENT not in encoded
                    and '"nativeBinding":' not in encoded
                    and '"transportPrivateKey":' not in encoded,
                    "proof output contains a credential or native mapping")
            require(len(encoded.encode()) <= 32_768, "proof exceeds fixed metadata bound")
            private_nonce_record = {
                "sourceNonceSha256": {"C1": c1_source_nonce_sha256, "C3": c3_source_nonce_sha256},
                "nonReuse": c1_source_nonce_sha256 != c3_source_nonce_sha256,
            }
            return proof
    finally:
        if daemon_task is not None:
            daemon_task.cancel()
            await asyncio.gather(daemon_task, return_exceptions=True)
        if "C" in sessions:
            sessions["C"]["provider"].release_hold.set()
        client_runtime._send_https = original_send_https
        launcher._session_request = original_session_request
        Store.list_pending = original_list_pending
        Store.list_reconcilable = original_list_reconcilable
        daemon.Gateway.dispatch = original_dispatch
        daemon.Gateway.reconcile = original_reconcile
        daemon.NativeBridgeAdapter.check = original_adapter_check
        daemon.NativeBridgeAdapter.reconcile = original_adapter_reconcile
        SessionNativeBridge.challenge = original_bridge_challenge
        cleanup_error = None
        try:
            broker_cleanup = stop_broker(broker, broker_log)
            if proof is not None:
                proof["brokerCleanup"] = broker_cleanup
        except AssertionError as error:
            cleanup_error = error
        if cleanup_error is not None and sys.exc_info()[0] is None:
            raise cleanup_error
        if cleanup_error is not None:
            print(str(cleanup_error), file=sys.stderr)
        if private_nonce_record is not None:
            private_path = Path(args.output).with_name(Path(args.output).stem + ".private-causal.json")
            try:
                private_json(private_path, private_nonce_record)
            except OSError as error:
                if cleanup_error is None:
                    raise AssertionError("private nonce causal record unavailable: "
                                         + type(error).__name__) from None
                print("private nonce causal record unavailable: " + type(error).__name__,
                      file=sys.stderr)
        if state_root.exists():
            import shutil
            shutil.rmtree(state_root)


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package-source", "binary", "binary-sha256", "node", "cloud-source",
                 "esbuild", "miniflare", "output"):
        parser.add_argument("--" + name, required=True)
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
