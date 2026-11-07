"""Prepare a bounded macOS Codex fixture for an owner-run stock pilot.

This fixture creates no Cloud state and never queues references. Keep the
reported CODEX_HOME only for fixture Gateway/TUI processes; the Gateway must
retain the real HOME needed by its installed token helper. Send one JSONL
control at a time: status, start_busy, release, progress (reference), evidence
(idleReference and busyReference), or stop.
"""

import argparse
import http.server
import json
import os
from pathlib import Path
import re
import signal
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_stock_codex_busy import (  # noqa: E402
    PtyDrain, _assistant_has_marker, _clean_terminal, _read_until, _reap_tui, _remote_tui,
)
from probe_stock_codex_queue import (  # noqa: E402
    _environment,
    _message_texts,
    _response_events,
    _seed,
)

HELD_PROMPT = "synthetic busy turn marker"
HELD_REPLY = "synthetic held response e3 marker"
SESSION_A = "Seed synthetic session A."
SESSION_B = "Seed synthetic session B."
REFERENCE = re.compile(r"ref_[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
MAX_LIFETIME_SECONDS = 900
MAX_CONTROL_BYTES = 4096
MAX_OUTPUT_BYTES = 8192
MAX_PROVIDER_REQUEST_BYTES = 4 * 1024 * 1024
MAX_PROVIDER_REQUESTS = 128


def _latest_user_markers(payload):
    items = payload.get("input", [])
    latest = next((item for item in reversed(items)
                   if isinstance(item, dict) and item.get("role") == "user"), None)
    return _message_texts({"input": [latest]}) if latest is not None else []


def _request_record(number, payload, held):
    markers = _message_texts(payload)
    return {
        "number": number,
        "references": sorted({item for item in markers if REFERENCE.fullmatch(item)}),
        "latestUserReferences": sorted({item for item in _latest_user_markers(payload)
                                         if REFERENCE.fullmatch(item)}),
        "sessionMarkers": [marker for marker in (SESSION_A, SESSION_B) if marker in markers],
        "heldPrompt": held,
        "containsHeldPrompt": HELD_PROMPT in markers,
        "heldAssistantMarker": HELD_REPLY if _assistant_has_marker(payload, HELD_REPLY) else None,
    }


def _pop_control_line(buffer):
    newline = buffer.find(b"\n")
    if newline >= MAX_CONTROL_BYTES or (newline < 0 and len(buffer) > MAX_CONTROL_BYTES):
        raise RuntimeError("control_line_too_large")
    if newline < 0:
        return None
    line = bytes(buffer[:newline + 1])
    del buffer[:newline + 1]
    return line


class PilotProvider(http.server.ThreadingHTTPServer):
    """Loopback-only Responses provider with an operator-controlled held reply."""

    daemon_threads = True
    block_on_close = False

    def __init__(self, address):
        self.requests = []
        self.events = []
        self.lock = threading.Lock()
        self.hold_started = threading.Event()
        self.release_hold = threading.Event()
        self.held_response_written = threading.Event()
        self.held_request_number = None
        self.hold_claimed = False
        self.active_requests = 0
        self.active_requests_done = threading.Event()
        self.active_requests_done.set()
        self.started_at = time.monotonic()
        provider = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def finish(self):
                try:
                    super().finish()
                finally:
                    if getattr(self, "_pilot_tracked", False):
                        with provider.lock:
                            provider.active_requests -= 1
                            if provider.active_requests == 0:
                                provider.active_requests_done.set()

            def do_POST(self):
                with provider.lock:
                    provider.active_requests += 1
                    provider.active_requests_done.clear()
                    self._pilot_tracked = True
                raw_length = self.headers.get("Content-Length", "0")
                if (not raw_length.isdecimal() or len(raw_length) > 10
                        or int(raw_length) > MAX_PROVIDER_REQUEST_BYTES):
                    self.close_connection = True
                    self.send_error(413)
                    return
                try:
                    self.connection.settimeout(5)
                    payload = json.loads(self.rfile.read(int(raw_length)))
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                    payload = {}
                except (OSError, TimeoutError):
                    self.send_error(408)
                    return
                markers = _message_texts(payload)
                with provider.lock:
                    if len(provider.requests) >= MAX_PROVIDER_REQUESTS:
                        self.send_error(429)
                        return
                    number = len(provider.requests) + 1
                    held = not provider.hold_claimed and HELD_PROMPT in markers
                    if held:
                        provider.hold_claimed = True
                        provider.held_request_number = number
                    provider.requests.append(_request_record(number, payload, held))
                    provider.events.append({"event": "request", "number": number})
                if held:
                    provider.hold_started.set()
                    provider.release_hold.wait(MAX_LIFETIME_SECONDS)
                reply = HELD_REPLY if held else "synthetic response e3 marker"
                events = _response_events(number, reply)
                body = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                               for event in events).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not provider._write_response(self.wfile, body, number):
                    return
                if held:
                    provider.held_response_written.set()

        super().__init__(address, Handler)

    def _write_response(self, writer, body, number):
        try:
            with self.lock:
                writer.write(body)
                writer.flush()
                self.events.append({"event": "response_written", "number": number})
        except OSError:
            return False
        return True


def pilot_evidence(requests, events, idle_reference, busy_reference, baseline=0):
    """Require two exact refs in A, with busy ref after A's held reply."""
    if (not isinstance(idle_reference, str) or not REFERENCE.fullmatch(idle_reference)
            or not isinstance(busy_reference, str) or not REFERENCE.fullmatch(busy_reference)
            or idle_reference == busy_reference):
        return {"passed": False, "reason": "invalid_reference_pair"}
    observed = requests[baseline:]
    idle = [row for row in observed if idle_reference in row.get("latestUserReferences", [])]
    busy = [row for row in observed if busy_reference in row.get("latestUserReferences", [])]
    holds = [row for row in observed if row.get("heldPrompt") is True]
    if len(idle) != 1 or len(busy) != 1 or len(holds) != 1:
        return {"passed": False, "reason": "reference_or_hold_cardinality"}
    idle, busy, held = idle[0], busy[0], holds[0]
    if (idle.get("number", 0) >= held.get("number", 0)
            or busy.get("number", 0) <= held.get("number", 0)
            or idle.get("latestUserReferences") != [idle_reference]
            or busy.get("latestUserReferences") != [busy_reference]
            or idle.get("sessionMarkers") != [SESSION_A]
            or busy.get("sessionMarkers") != [SESSION_A]
            or held.get("sessionMarkers") != [SESSION_A]
            or any(SESSION_B in row.get("sessionMarkers", []) for row in observed)
            or busy.get("heldAssistantMarker") != HELD_REPLY):
        return {"passed": False, "reason": "wrong_session_or_order"}
    names = [(event.get("event"), event.get("number")) for event in events]
    try:
        held_request = names.index(("request", held["number"]))
        held_response = names.index(("response_written", held["number"]))
        busy_request = names.index(("request", busy["number"]))
        idle_request = names.index(("request", idle["number"]))
        idle_response = names.index(("response_written", idle["number"]))
        release = names.index(("hold_release", held["number"]))
    except (ValueError, KeyError):
        return {"passed": False, "reason": "held_response_missing"}
    if not idle_request < idle_response < held_request < release < held_response < busy_request:
        return {"passed": False, "reason": "held_response_missing"}
    return {"passed": True, "reason": None, "idleReference": idle_reference,
            "busyReference": busy_reference, "idleRequest": idle["number"],
            "heldRequest": held["number"], "busyRequest": busy["number"]}


def pilot_progress(requests, events, reference, baseline=0):
    """Return bounded proof that one exact ref reached the synthetic provider in A."""
    if not isinstance(reference, str) or not REFERENCE.fullmatch(reference):
        return {"status": "invalid", "reason": "invalid_reference"}
    observed = requests[baseline:]
    matches = [row for row in observed if reference in row.get("latestUserReferences", [])]
    if not matches:
        return {"status": "pending", "reason": "request_not_observed"}
    if len(matches) != 1:
        return {"status": "invalid", "reason": "reference_not_unique"}
    row = matches[0]
    if (row.get("latestUserReferences") != [reference]
            or row.get("sessionMarkers") != [SESSION_A]
            or any(SESSION_B in item.get("sessionMarkers", []) for item in observed)):
        return {"status": "invalid", "reason": "wrong_session_or_input"}
    number = row.get("number")
    names = [(event.get("event"), event.get("number")) for event in events]
    try:
        request_index = names.index(("request", number))
    except ValueError:
        return {"status": "pending", "reason": "request_event_missing"}
    try:
        response_index = names.index(("response_written", number))
    except ValueError:
        response_index = None
    if response_index is not None and response_index <= request_index:
        return {"status": "invalid", "reason": "event_order_invalid"}

    held_rows = [item for item in observed if item.get("heldPrompt") is True]
    if held_rows:
        if len(held_rows) != 1:
            return {"status": "invalid", "reason": "held_request_not_unique"}
        held_number = held_rows[0].get("number")
        try:
            held_request_index = names.index(("request", held_number))
        except ValueError:
            return {"status": "pending", "reason": "held_request_not_observed"}
        if number < held_number:
            if response_index is None:
                return {"status": "pending", "reason": "response_not_written"}
            if not request_index < response_index < held_request_index:
                return {"status": "invalid", "reason": "idle_response_not_before_held_request"}
            return {"status": "observed", "request": number, "session": "A",
                    "responseWritten": True, "phase": "before_held_request"}
        try:
            release_index = names.index(("hold_release", held_number))
            held_response_index = names.index(("response_written", held_number))
        except ValueError:
            return {"status": "pending", "reason": "held_response_not_written"}
        if not held_request_index < release_index < held_response_index:
            return {"status": "invalid", "reason": "held_event_order_invalid"}
        if (number <= held_number or row.get("heldAssistantMarker") != HELD_REPLY
                or request_index <= held_response_index):
            return {"status": "invalid", "reason": "not_after_held_response"}
        return {"status": "observed", "request": number, "session": "A",
                "responseWritten": response_index is not None, "phase": "after_held_response"}
    if response_index is None:
        return {"status": "pending", "reason": "response_not_written"}
    return {"status": "observed", "request": number, "session": "A",
            "responseWritten": True, "phase": "idle"}


def _owned_daemon_socket(fixture_root, reported_path):
    try:
        root = Path(fixture_root).resolve(strict=True)
        reported = Path(reported_path)
        reported.parent.resolve(strict=True).relative_to(root)
        alias = reported.lstat()
        if alias.st_uid != os.getuid() or not (stat.S_ISSOCK(alias.st_mode) or stat.S_ISLNK(alias.st_mode)):
            return False
        # Stock Codex's private alias targets its same-user socket outside CODEX_HOME.
        target = reported.resolve(strict=True).stat()
        return stat.S_ISSOCK(target.st_mode) and target.st_uid == os.getuid()
    except (OSError, ValueError):
        return False


def _stop_owned_updater(home, record):
    """Stop only the recorded, same-user updater whose start time and image still match."""
    try:
        pid = record.get("pid")
        if type(pid) is not int or pid <= 1:
            return False
        def ps(field):
            result = subprocess.run(["ps", "-p", str(pid), "-o", f"{field}="],
                                    text=True, capture_output=True, timeout=2)
            return result.stdout.strip() if result.returncode == 0 else ""

        if ps("uid") != str(os.getuid()):
            return False
        if " ".join(ps("lstart").split()) != " ".join(str(record.get("processStartTime", "")).split()):
            return False
        # macOS ps reports the image path; an unproved/basename-only image fails closed.
        executable = Path(ps("comm")).resolve(strict=True)
        executable.relative_to(Path(home).resolve(strict=True))
        if not executable.is_file():
            return False
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = ps("stat")
            if not state or "Z" in state:
                return True
            time.sleep(0.1)
        return False
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


class PilotFixture:
    def __init__(self, binary):
        self.binary = Path(binary).resolve(strict=True)
        self.started = time.monotonic()
        self.home = Path(tempfile.mkdtemp(prefix="stock-codex-e3-local-"))
        os.chmod(self.home, 0o700)
        self.provider = PilotProvider(("127.0.0.1", 0))
        self.provider_thread = threading.Thread(target=self.provider.serve_forever, daemon=True)
        self.provider_thread.start()
        self.tuis = []
        self.drains = []
        self.daemon_started = False
        self.daemon_ownership_unproved = False
        self.stopped = False
        self.cleanup_done = False
        self.thread_a = None
        self.thread_b = None
        self.socket_path = None
        self.observation_baseline = 0
        self.control_buffer = bytearray()
        try:
            config_path = self.home / "config.toml"
            config_path.write_text(
                "check_for_update_on_startup = false\nmodel_provider = \"loopback\"\n"
                "model = \"synthetic\"\nmodel_reasoning_effort = \"low\"\n"
                "[features]\nplugins = false\nplugin_discovery_prefetch = false\n"
                "[model_providers.loopback]\nname = \"Synthetic loopback\"\n"
                f"base_url = \"http://127.0.0.1:{self.provider.server_address[1]}/v1\"\n"
                "wire_api = \"responses\"\nrequires_openai_auth = false\nsupports_websockets = false\n")
            os.chmod(config_path, 0o600)
            self.thread_a = _seed(self.binary, self.home, SESSION_A)
            self.thread_b = _seed(self.binary, self.home, SESSION_B)
            self.daemon_ownership_unproved = True
            result = subprocess.run([str(self.binary), "app-server", "daemon", "start"],
                                    env=_environment(self.home), text=True, capture_output=True, timeout=15)
            if result.returncode:
                raise RuntimeError("daemon_start_failed")
            daemon = json.loads(result.stdout)
            self.socket_path = daemon.get("socketPath")
            if not self.socket_path:
                raise RuntimeError("daemon_socket_missing")
            if not _owned_daemon_socket(self.home, self.socket_path):
                raise RuntimeError("daemon_socket_owner_unproved")
            self.daemon_started = True
            self.daemon_ownership_unproved = False
            self._open_tui(self.thread_b, "B")
            self._open_tui(self.thread_a, "A")
            self.observation_baseline = len(self.provider.requests)
        except BaseException:
            cleanup = self.stop()
            print(json.dumps({"cleanup": cleanup}, separators=(",", ":")), flush=True)
            raise

    def _open_tui(self, thread_id, label):
        process, master = _remote_tui(self.binary, self.home, thread_id, self.socket_path)
        self.tuis.append((process, master))
        ready = _read_until(master, process, b"", lambda data: "Ask Codex to do anything" in _clean_terminal(data), 10)
        if "Ask Codex to do anything" not in _clean_terminal(ready):
            raise RuntimeError(f"tui_{label.lower()}_not_ready")
        drain = PtyDrain(master)
        drain.start()
        self.drains.append(drain)

    def status(self):
        return {"status": "ready", "codeHome": str(self.home), "provider": f"http://127.0.0.1:{self.provider.server_address[1]}/v1",
                "daemonSocket": self.socket_path, "conversationA": self.thread_a, "conversationB": self.thread_b,
                "lifetimeRemainingSeconds": max(0, int(MAX_LIFETIME_SECONDS - (time.monotonic() - self.started))),
                "tuiAReady": bool(self.tuis and self.tuis[-1][0].poll() is None),
                "tuiBReady": bool(len(self.tuis) == 2 and self.tuis[0][0].poll() is None)}

    def start_busy(self):
        if self.provider.hold_started.is_set():
            raise RuntimeError("busy_already_started")
        process, master = self.tuis[-1]
        os.write(master, HELD_PROMPT.encode())
        deadline = min(time.monotonic() + 3, self.started + MAX_LIFETIME_SECONDS)
        while time.monotonic() < deadline and process.poll() is None:
            if HELD_PROMPT in _clean_terminal(self.drains[-1].snapshot()):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("busy_prompt_not_visible")
        os.write(master, b"\r")
        if not self.provider.hold_started.wait(min(12, max(0, self.started + MAX_LIFETIME_SECONDS - time.monotonic()))):
            raise RuntimeError("held_start_timeout")
        return {"heldStart": True, "request": self.provider.held_request_number, "marker": HELD_PROMPT}

    def release(self):
        if not self.provider.hold_started.is_set():
            raise RuntimeError("busy_not_started")
        with self.provider.lock:
            self.provider.events.append({"event": "hold_release", "number": self.provider.held_request_number})
        self.provider.release_hold.set()
        if not self.provider.held_response_written.wait(min(10, max(0, self.started + MAX_LIFETIME_SECONDS - time.monotonic()))):
            raise RuntimeError("held_response_timeout")
        return {"released": True, "heldResponseWritten": True, "marker": HELD_REPLY}

    def evidence(self, idle_reference, busy_reference):
        with self.provider.lock:
            requests, events = list(self.provider.requests), list(self.provider.events)
        return pilot_evidence(requests, events, idle_reference, busy_reference, self.observation_baseline)

    def progress(self, reference):
        with self.provider.lock:
            requests, events = list(self.provider.requests), list(self.provider.events)
        return pilot_progress(requests, events, reference, self.observation_baseline)

    def _read_control_line(self, deadline):
        descriptor = sys.stdin.fileno()
        while time.monotonic() < deadline:
            line = _pop_control_line(self.control_buffer)
            if line is not None:
                return line
            wait = min(1, max(0, deadline - time.monotonic()))
            if select.select([descriptor], [], [], wait)[0]:
                chunk = os.read(descriptor, MAX_CONTROL_BYTES + 1 - len(self.control_buffer))
                if not chunk:
                    return None
                self.control_buffer.extend(chunk)
        return b""

    def serve(self):
        deadline = self.started + MAX_LIFETIME_SECONDS
        while not self.stopped and time.monotonic() < deadline:
            line = self._read_control_line(deadline)
            if line == b"":
                continue
            if not line:
                break
            try:
                command = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise RuntimeError("invalid_control_json") from None
            if type(command) is not dict or command.get("command") not in {"status", "start_busy", "release", "progress", "evidence", "stop"}:
                raise RuntimeError("invalid_control_command")
            name = command["command"]
            if name == "status":
                result = self.status()
            elif name == "start_busy":
                result = self.start_busy()
            elif name == "release":
                result = self.release()
            elif name == "progress":
                result = self.progress(command.get("reference"))
            elif name == "evidence":
                result = self.evidence(command.get("idleReference"), command.get("busyReference"))
                if not result["passed"]:
                    raise RuntimeError(result["reason"])
            else:
                result = {"stopped": True}
                self.stopped = True
            encoded = json.dumps(result, separators=(",", ":"))
            if len(encoded.encode()) > MAX_OUTPUT_BYTES:
                raise RuntimeError("control_output_too_large")
            print(encoded, flush=True)
        if time.monotonic() >= deadline:
            raise RuntimeError("fixture_deadline")

    def stop(self):
        if getattr(self, "cleanup_done", False):
            return self.cleanup_result
        self.stopped = True
        if getattr(self, "provider", None):
            self.provider.release_hold.set()
        drain_results = [drain.stop() for drain in getattr(self, "drains", [])]
        tui_results = []
        for process, master in getattr(self, "tuis", []):
            tui_results.append(_reap_tui(process).get("killedAndReaped", False))
            try:
                os.close(master)
            except OSError:
                tui_results[-1] = False
        daemon_stopped = not self.daemon_started and not self.daemon_ownership_unproved
        updater_stopped = not self.daemon_started
        if self.daemon_started:
            updater_record = None
            try:
                updater_record = json.loads((self.home / "app-server-daemon" / "daemon-updater.pid").read_text())
            except (OSError, json.JSONDecodeError):
                pass
            try:
                cleanup_env = _environment(self.home)
                cleanup_env.pop("HOME", None)
                result = subprocess.run([str(self.binary), "app-server", "daemon", "stop"],
                                        env=cleanup_env, text=True, capture_output=True, timeout=15)
                daemon = json.loads(result.stdout)
                daemon_stopped = result.returncode == 0 and daemon.get("status") == "stopped"
            except (OSError, subprocess.TimeoutExpired):
                daemon_stopped = False
            except (json.JSONDecodeError, AttributeError):
                daemon_stopped = False
            if isinstance(updater_record, dict):
                updater_stopped = _stop_owned_updater(self.home, updater_record)
        provider_stopped = False
        if getattr(self, "provider", None):
            self.provider.shutdown()
            self.provider.server_close()
            if getattr(self, "provider_thread", None):
                self.provider_thread.join(timeout=2)
                handler_stopped = self.provider.active_requests_done.wait(12)
                provider_stopped = not self.provider_thread.is_alive() and handler_stopped
        clean = all(drain_results) and all(tui_results) and daemon_stopped and updater_stopped and provider_stopped
        cleanup_error = None
        if clean:
            try:
                shutil.rmtree(self.home, ignore_errors=False)
            except OSError as error:
                clean = False
                cleanup_error = {"type": type(error).__name__, "errno": error.errno}
        self.cleanup_result = {"clean": clean, "daemonStopped": daemon_stopped,
                              "updaterStopped": updater_stopped,
                              "daemonOwnershipUnproved": self.daemon_ownership_unproved,
                              "providerStopped": provider_stopped, "drainsStopped": all(drain_results),
                              "tuisReaped": all(tui_results),
                              "codeHomeRemoved": clean,
                              "cleanupError": cleanup_error,
                              "retainedCodeHome": None if clean else str(self.home)}
        self.cleanup_done = True
        return self.cleanup_result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("the local Codex pilot fixture requires macOS")
    fixture = None
    exit_code = 0
    try:
        fixture = PilotFixture(args.binary)
        fixture.serve()
    except Exception as error:
        print(json.dumps({"error": str(error) if str(error).isidentifier() else "fixture_failed"}), flush=True)
        exit_code = 1
    finally:
        if fixture:
            cleanup = fixture.stop()
            print(json.dumps({"cleanup": cleanup}, separators=(",", ":")), flush=True)
            if not cleanup["clean"]:
                exit_code = 1
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
