"""Offline installed-wheel qualification of native admission and real source reads."""
import argparse
from concurrent.futures import Future
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shlex
import sys
import tempfile
import threading
import time
from uuid import uuid4

CLI_SHA = "62eac2a58bdac388850948aa82bf341c376e8653010d628de12ba642a2e343a3"
HOST_SHA = "679eedaea70529aa1cffc9bc0a0788c186412663544fa76c09d63b57f383a65a"
HELPERS = {
    "native-github-source-qualification.py": "04ef38a3d69ca8787856769c6b83956deb88a7576c7e237b33c3b68550dea33a",
    "native-release-launcher-smoke.py": "073ddf6a43248db44345e0a20d09f11ced91740186d741b9038b7f7bea5dd33e",
    "qualification-installed.py": "22002b7e599c266b512546c67ff383a643846624adb2b188520250d19fcd061c",
}
CALL_ID = "offline-source-read"


def require(value, message):
    if not value:
        raise AssertionError(message)


def verified_helper(name):
    path = Path(__file__).with_name(name)
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == HELPERS[name], "frozen helper digest mismatch")
    # Import a fresh private snapshot of the verified bytes, never the mutable
    # original path or pre-existing bytecode beside it.
    temporary = tempfile.TemporaryDirectory(prefix="nhq-helper-")
    try:
        snapshot = Path(temporary.name) / name
        fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        spec = importlib.util.spec_from_file_location(name.replace("-", "_"), snapshot)
        require(spec is not None and spec.loader is not None, "private helper loader unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module._private_helper = temporary
        return module
    except BaseException:
        temporary.cleanup()
        raise


def completed(identity):
    return {"type": "response.completed", "response": {"id": identity, "usage": {
        "input_tokens": 0, "input_tokens_details": None, "output_tokens": 0,
        "output_tokens_details": None, "total_tokens": 0}}}


def source_program(path):
    arguments = {"cmd": "/bin/cat " + shlex.quote(str(path)), "login": False,
                 "max_output_tokens": 1000, "yield_time_ms": 1000}
    return "text(await tools.exec_command(" + json.dumps(arguments) + "));"


def verify_output(requests, nonce):
    require(len(requests) == 2, "expected exactly two synthetic model requests")
    require(nonce not in json.dumps(requests[0]), "source leaked before tool execution")
    outputs = [item for item in requests[1].get("input", [])
               if item.get("type") == "custom_tool_call_output" and item.get("call_id") == CALL_ID]
    require(len(outputs) == 1, "missing unique source-read output")
    values = []
    for item in outputs[0].get("output", []):
        try:
            values.append(json.loads(item.get("text", "")))
        except (ValueError, TypeError):
            continue
    require(len(values) == 1 and isinstance(values[0], dict)
            and values[0].get("exit_code") == 0 and values[0].get("output") == nonce + "\n",
            "tool did not return the fresh source nonce with exit zero")
    return outputs[0]


def request_kind(request):
    tools = request.get("tools", [])
    if any(tool.get("name") == "exec" for tool in tools):
        return "main"
    schema = request.get("text", {}).get("format", {}).get("schema", {})
    prompt = json.dumps(request.get("input", []))
    if (tools == [] and schema.get("required") == ["title"]
            and set(schema.get("properties", {})) == {"title"}
            and "Generate a concise, single-line task title" in prompt):
        return "title"
    raise AssertionError("unexpected synthetic request kind")


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        try:
            require(self.path == "/v1/responses", "unexpected provider endpoint")
            require(not self.headers.get("Authorization"), "unexpected credentials")
            require(not self.headers.get("Content-Encoding"), "compressed provider request")
            size = int(self.headers["Content-Length"])
            require(0 < size < 4_000_000, "unexpected provider request size")
            request = json.loads(self.rfile.read(size))
            self.server.requests.append(request)
            kind = request_kind(request)
            if kind == "title":
                self.server.title_requests.append(request)
                require(len(self.server.title_requests) == 1, "extra title request")
                events = [{"type": "response.output_item.done", "item": {
                    "type": "message", "role": "assistant", "id": "offline-title",
                    "content": [{"type": "output_text", "text": '{"title":"Read offline source"}'}]}},
                    completed("offline-title")]
            else:
                self.server.main_requests.append(request)
                require(len(self.server.main_requests) <= 2, "unexpected extra main request")
            if kind == "main" and len(self.server.main_requests) == 1:
                events = [{"type": "response.created", "response": {"id": "offline-1"}},
                          {"type": "response.output_item.done", "item": {
                              "type": "custom_tool_call", "call_id": CALL_ID, "name": "exec",
                              "input": self.server.program}}, completed("offline-1")]
            elif kind == "main":
                events = [{"type": "response.output_item.done", "item": {
                    "type": "message", "role": "assistant", "id": "offline-message",
                    "content": [{"type": "output_text", "text": "Offline read completed."}]}},
                    completed("offline-2")]
            payload = "".join("data: " + json.dumps(event) + "\n\n" for event in events).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as error:
            self.server.errors.append(str(error))
            self.send_error(500)


def start_request(binding):
    now = int(time.time() * 1000)
    return {**{key: binding[key] for key in (
        "clientId", "serverInstanceId", "serverGeneration", "threadId", "generation")},
        "attemptId": str(uuid4()), "deliveryId": "dly_" + secrets.token_hex(32),
        "clientUserMessageId": str(uuid4()), "permitId": "offline-" + secrets.token_hex(16),
        "permitIssuedAt": now, "permitExpiresAt": now + 5000,
        "event": {"eventId": str(uuid4()), "source": "manual", "sourceStateVersion": "offline-1",
                  "canonicalSubject": {"kind": "manual", "subjectId": "offline-source-read"},
                  "eventReference": "ref_" + str(uuid4())}}


def sandbox_profile(port):
    protected = {str(Path.home() / ".codex"), "/private/tmp/event-live-canary-20261010"}
    if os.environ.get("CODEX_HOME"):
        protected.add(str(Path(os.environ["CODEX_HOME"]).expanduser().resolve()))
    denied_paths = " ".join("(subpath " + json.dumps(path) + ")" for path in sorted(protected))
    return ('(version 1)\n(allow default)\n(deny network*)\n'
            f'(allow network-outbound (remote ip "localhost:{port}"))\n'
            '(allow network* (local unix-socket) (remote unix-socket))\n'
            f'(deny file-read* {denied_paths})\n')


def launch_argv(profile, cache, state, binary, root):
    # Mandatory outer isolation: the child config disables only nested seatbelt.
    return ["/usr/bin/sandbox-exec", "-f", str(profile), sys.executable, "-I", "-B", "-X",
            f"pycache_prefix={cache}", "-m", "event_gateway.cli", "--state-dir", str(state),
            "launch", "--codex-binary", str(binary), "--binary-sha256", CLI_SHA,
            "--cwd", str(root)]


def config_snapshot(path, phase):
    data = path.read_bytes()
    return {phase + "Config": data.decode("utf-8"),
            phase + "ConfigSha256": hashlib.sha256(data).hexdigest()}


@contextmanager
def preserve_final_config(trace, path):
    try:
        yield
    finally:
        trace.update(config_snapshot(path, "final"))


def foreground_operation(launcher, smoke, process, master, tail, *args):
    # A blocked PTY writer can starve native receipt handling; keep consuming output.
    deadline = time.monotonic() + launcher.NATIVE_OPERATION_SECONDS
    future = Future()

    def invoke():
        try:
            future.set_result(launcher.session_native_operation(*args))
        except BaseException as error:
            future.set_exception(error)

    # Failure cleanup must not join an unresponsive RPC worker, including at exit.
    threading.Thread(target=invoke, daemon=True).start()
    while not future.done():
        require(process.poll() is None, "launcher exited during native operation")
        require(time.monotonic() < deadline, "native operation timed out")
        smoke.drain(master, tail)
    require(process.poll() is None, "launcher exited during native operation")
    return future.result()


def require_process_group_stopped(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return
    raise AssertionError("owned process group survived cleanup")


def qualify(args, launcher, smoke, server, github_fixture=None, installed_helper=None):
    host = args.binary.parent / "codex-code-mode-host"
    require(hashlib.sha256(args.binary.read_bytes()).hexdigest() == CLI_SHA, "CLI digest mismatch")
    require(hashlib.sha256(host.read_bytes()).hexdigest() == HOST_SHA, "host digest mismatch")
    temporary_root = Path("/tmp").resolve()  # nosec B108 - Short AF_UNIX root; TemporaryDirectory creates a private random child.
    with tempfile.TemporaryDirectory(prefix="nhq-", dir=temporary_root) as directory:
        root = Path(directory)
        state = root / "state"
        home = smoke.write_config(root, server.server_port)
        config = home / "config.toml"
        data = config.read_text().replace('model="mock-astra"', 'model="mock-model"')
        data = data.replace(f':{server.server_port}"', f':{server.server_port}/v1"')
        # The outer seatbelt remains active; macOS forbids applying a second seatbelt.
        data = 'approval_policy="never"\nsandbox_mode="danger-full-access"\n' + data
        data += '\n[features]\ncode_mode_only=true\ncode_mode_host=true\napps=false\n'
        config.write_text(data)
        source = root / ("source-" + secrets.token_hex(16) + ".txt")
        nonce = "source-nonce-" + secrets.token_hex(32)
        source.write_text(nonce + "\n")
        source.chmod(0o600)
        server.program = (github_fixture.prepare(source, nonce, args.package_source, installed_helper)
                          if github_fixture else source_program(source))
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        require(nonce not in server.program, "fixture must not supply source content")
        profile = root / "offline.sb"
        profile.write_text(sandbox_profile(server.server_port))
        cache = root / "child-cache"
        cache.mkdir(mode=0o700)
        argv = launch_argv(profile, cache, state, args.binary, root)
        server.trace.update(**config_snapshot(config, "initial"), sandboxProfile=profile.read_text(),
                            sourceNonce=nonce, sourceSha256=source_digest, sourceProgram=server.program,
                            argv=argv, nativeStarts=0)
        tail = bytearray()
        server.tail = tail
        with preserve_final_config(server.trace, config), smoke.foreground_process(root, home, argv) as (process, master):
            socket_path, status, binding, challenge = smoke.wait_selection(
                launcher, state, process, master, tail)
            smoke.check_selection(status, binding, challenge)
            require(not server.requests, "provider called before native admission")
            request = start_request(binding)
            session = socket_path.name[2:-5]
            server.trace.update(binding=binding, request=request, nativeStarts=1)
            started = foreground_operation(launcher, smoke, process, master, tail,
                                           state, session, binding, "nativeStart", request)
            server.trace["started"] = started
            require(started["outcome"]["status"] == "started", "native Start was not accepted")
            deadline = time.monotonic() + 90
            while len(server.main_requests) < 2:
                require(process.poll() is None, "launcher exited during source read")
                require(time.monotonic() < deadline, "source read timed out: " + tail.decode(errors="replace"))
                require(not server.errors, str(server.errors))
                smoke.drain(master, tail)
            receipt = foreground_operation(launcher, smoke, process, master, tail,
                                           state, session, binding, "nativeReceipt", request)
            server.trace["receipt"] = receipt
            output = (github_fixture.verify_output(server.main_requests, nonce, source, verify_output)
                      if github_fixture else verify_output(server.main_requests, nonce))
            require(all(item.get("client_metadata", {}).get("turn_id") == started["outcome"]["turnId"]
                        and item.get("client_metadata", {}).get("thread_id") == binding["threadId"]
                        for item in server.main_requests), "main provider request identity mismatch")
            require(receipt["outcome"]["status"] == "inputRecorded", "durable input receipt missing")
            require(receipt["outcome"]["turnId"] == started["outcome"]["turnId"], "receipt turn mismatch")
            # Wait until the foreground is idle again before sending /quit.
            smoke.wait_selection(launcher, state, process, master, tail)
            code = smoke.quit_foreground(process, master, tail, socket_path, binding["backendPid"])
        require_process_group_stopped(process.pid)
        require(hashlib.sha256(args.binary.read_bytes()).hexdigest() == CLI_SHA, "CLI changed")
        require(hashlib.sha256(host.read_bytes()).hexdigest() == HOST_SHA, "host changed")
        require(len(server.main_requests) == 2 and len(server.title_requests) <= 1 and not server.errors, "unexpected provider activity")
        require(not any(cache.iterdir()), "child wrote bytecode")
        require(hashlib.sha256(source.read_bytes()).hexdigest() == source_digest, "source mutated")
        return {"result": "PASS", "nativeBinarySha256": CLI_SHA, "codeModeHostSha256": HOST_SHA,
                "sourceSha256": source_digest, "sourceWrittenBeforeSubmission": True,
                "sourceNonce": nonce, "sourceProgram": server.program, "toolOutput": output,
                "nativeStarts": 1, "started": started, "receipt": receipt,
                "binding": binding, "syntheticModelRequests": len(server.requests),
                "mainTurnModelRequests": len(server.main_requests), "titleModelRequests": len(server.title_requests),
                "realModelCalls": 0, "innerSandboxMode": "danger-full-access",
                "outerSandboxEnforced": True, "authCopied": False, "noAuthorizationHeaders": True,
                "sandboxProfile": profile.read_text(),
                "initialConfigSha256": server.trace["initialConfigSha256"],
                "finalConfigSha256": server.trace["finalConfigSha256"],
                "controlSocketRemoved": True, "backendStopped": True, "ownedProcessGroupEmpty": True,
                "terminationExitCode": code, "childBytecodeCacheFreshAndEmpty": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--package-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-source-read", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new proof path")
    proof = {"result": "BLOCKED", "realModelCalls": 0}
    server = None
    try:
        helper = verified_helper("qualification-installed.py")
        provenance = helper.verify_installed(args.package_source)
        helper.verified_python()
        smoke = verified_helper("native-release-launcher-smoke.py")
        launcher = importlib.import_module("event_gateway.launcher")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        server.requests, server.errors, server.trace, server.tail = [], [], {}, bytearray()
        server.main_requests, server.title_requests = [], []
        proof["installedPackagePreflight"] = provenance
        proof["frozenHelperSha256"] = HELPERS
        threading.Thread(target=server.serve_forever, daemon=True).start()
        github_fixture = verified_helper("native-github-source-qualification.py") if args.github_source_read else None
        proof = qualify(args, launcher, smoke, server, github_fixture, helper.__file__)
        if github_fixture:
            proof.update(qualification="offline-native-github-source-read", realCloudCalls=0,
                         syntheticTransportCalls=1, requestSignatureVerified=True,
                         liveAuthorizationProved=False)
        proof["installedPackagePreflight"] = provenance
        proof["frozenHelperSha256"] = HELPERS
    except Exception as error:
        proof.update(errorType=type(error).__name__, error=str(error))
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
            proof["providerErrors"] = server.errors
            proof["providerRequests"] = server.requests
            proof["trace"] = server.trace
            proof["terminalTail"] = server.tail.decode(errors="replace")
        with args.output.open("x") as stream:
            stream.write(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof))
    return 0 if proof["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
