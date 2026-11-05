"""Bounded synthetic busy-turn ordering proof for the stock Codex queue adapter."""

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import re
import select
import struct
import subprocess
import sys
import tempfile
import threading
import termios
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_stock_codex_queue import (
    _environment,
    _message_texts,
    _queue_targets,
    _response_events,
    _seed,
)


def _remote_tui(binary, home, thread_id, socket_path):
    master, slave = pty.openpty()
    try:
        import fcntl
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
        command = [str(binary), "--no-alt-screen", "resume", "--include-non-interactive",
                   "--remote", f"unix://{socket_path}", thread_id, "-C", str(home)]
        process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                   env=_environment(home), close_fds=True)
    except BaseException:
        os.close(master)
        raise
    finally:
        os.close(slave)
    time.sleep(1.25)
    return process, master


HELD_PROMPT = "synthetic busy turn marker"
HELD_REPLY = "synthetic held response e1 marker"
QUEUE_REFERENCE = "ref_55555555-5555-4555-8555-555555555555"
SESSION_A = "Seed synthetic session A."
SESSION_B = "Seed synthetic session B."


def _assistant_has_marker(payload, marker):
    for item in payload.get("input", []):
        if not isinstance(item, dict) or item.get("role") != "assistant":
            continue
        content = item.get("content", [])
        if isinstance(content, str) and content == marker:
            return True
        if isinstance(content, list) and any(
                isinstance(part, dict) and part.get("text") == marker for part in content):
            return True
    return False


def _identifier_hash(value):
    if not isinstance(value, str):
        return None
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _request_structure(payload):
    """Keep protocol shape while excluding all request text and opaque IDs."""
    input_items = payload.get("input", [])
    items = []
    if isinstance(input_items, list):
        for item in input_items[:16]:
            if not isinstance(item, dict):
                items.append({"valueType": type(item).__name__})
                continue
            content = item.get("content", [])
            content_types = []
            if isinstance(content, list):
                content_types = [part.get("type") for part in content[:16]
                                 if isinstance(part, dict) and isinstance(part.get("type"), str)]
            elif isinstance(content, str):
                content_types = ["string"]
            items.append({
                "type": item.get("type") if isinstance(item.get("type"), str) else None,
                "role": item.get("role") if isinstance(item.get("role"), str) else None,
                "contentTypes": content_types,
            })
    previous_response_id = payload.get("previous_response_id")
    return {
        "topLevelFields": sorted(key for key in payload if isinstance(key, str))[:64],
        "model": payload.get("model") if isinstance(payload.get("model"), str) else None,
        "stream": payload.get("stream") if isinstance(payload.get("stream"), bool) else None,
        "previousResponseIdPresent": isinstance(previous_response_id, str),
        "previousResponseIdSha256": _identifier_hash(previous_response_id),
        "inputItems": items,
    }


_TITLE_GENERATION = re.compile(r"\b(?:generate|create|write|choose|suggest)\b.{0,80}\btitle\b", re.I | re.S)


def _classify_request_purpose(payload, reference):
    user_text = []
    for item in payload.get("input", []):
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        content = item.get("content", [])
        if isinstance(content, str):
            user_text.append(content)
        elif isinstance(content, list):
            user_text.extend(part["text"] for part in content
                             if isinstance(part, dict) and isinstance(part.get("text"), str))
    joined = "\n".join(user_text)
    if reference in joined:
        return "queued_followup"
    if HELD_PROMPT in joined and _TITLE_GENERATION.search(joined):
        return "background_title_generation"
    if not joined:
        return "unknown_marker_free_request"
    return "unclassified_user_request"


def _valid_followup(request, reference, held_reply):
    texts = request.get("synthetic_user_text", [])
    return (
        reference in texts
        and SESSION_A in texts
        and SESSION_B not in texts
        and request.get("heldAssistantMarker") == held_reply
    )


def _clean_terminal(raw):
    text = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
    clean = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", text)
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", clean)


def _read_until(master, process, initial, predicate, timeout):
    output = initial
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and process.poll() is None:
        clean = _clean_terminal(output)
        if predicate(clean):
            return output
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                output += os.read(master, 4096)
            except OSError:
                break
    return output


class PtyDrain:
    def __init__(self, master):
        self.master = master
        self.stop_event = threading.Event()
        self.buffer = bytearray()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    def _run(self):
        while not self.stop_event.is_set():
            ready, _, _ = select.select([self.master], [], [], 0.1)
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                return
            self.buffer.extend(chunk)
            if len(self.buffer) > 65536:
                del self.buffer[:-32768]

    def snapshot(self):
        return bytes(self.buffer)

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=2)
        return not self.thread.is_alive()


def _pty_diagnostic(raw):
    clean = _clean_terminal(raw)
    safe_lines = []
    for line in clean.splitlines()[-12:]:
        line = re.sub(r"/private/(?:tmp|var/folders)/\S+", "<private-path>", line)
        line = line.strip()
        if line and any(word in line.lower() for word in
                        ("error", "working", "synthetic", "ask codex", "warning")):
            safe_lines.append(line[:160])
    return {
        "workingVisible": "Working" in clean,
        "composerVisible": "Ask Codex to do anything" in clean,
        "providerErrorVisible": any(word in clean.lower() for word in
                                     ("model error", "provider error", "authentication error")),
        "markerVisibleAfterEnter": HELD_PROMPT in clean,
        "sanitizedTail": safe_lines,
    }


def _ordered_excerpt(output):
    clean = _clean_terminal(output)
    busy = clean.find(HELD_PROMPT)
    held_reply = clean.find(HELD_REPLY, busy)
    reference = clean.find(QUEUE_REFERENCE, held_reply)
    followup_reply = clean.find("synthetic response", reference)
    passed = min(busy, held_reply, reference, followup_reply) >= 0
    return {
        "passed": passed,
        "excerpt": (clean[busy:followup_reply + len("synthetic response")].strip()
                    if passed else ""),
    }


def _client_view(raw):
    text = _clean_terminal(raw)
    lowered = text.lower()
    return {
        "originalPromptVisible": HELD_PROMPT in text,
        "workingVisible": "Working" in text,
        "queuedReferenceVisible": QUEUE_REFERENCE in text,
        "heldAssistantResponseVisible": HELD_REPLY in text,
        "heldResponseBeforeQueuedReference": (
            HELD_REPLY in text and QUEUE_REFERENCE in text
            and text.find(HELD_REPLY) < text.find(QUEUE_REFERENCE)),
        "explicitCancellationSignalVisible": any(
            phrase in lowered for phrase in ("turn cancelled", "turn canceled", "turn interrupted")),
    }


def _classify_held_window(requests, held_number, reference):
    later = [row for row in requests if row["number"] > held_number]
    known = [row["number"] for row in later
             if reference in row["synthetic_user_text"]
             or row["structure"]["previousResponseIdPresent"]]
    background = [row["number"] for row in later
                  if row.get("purposeClassification") == "background_title_generation"]
    unknown = [row["number"] for row in later if row["number"] not in known
               and row["number"] not in background]
    return {
        "classifiedFollowupNumbers": known,
        "backgroundTitleGenerationNumbers": background,
        "unknownRequestNumbers": unknown,
        "noClassifiedFollowupBeforeRelease": not known,
    }


def _session_stayed_idle(requests, baseline, marker):
    return not any(marker in row["synthetic_user_text"] for row in requests[baseline:])


def _busy_gate_passed(result):
    client = result.get("clientStateBeforeFollowupCompletion", {})
    return bool(
        result.get("queueExit") == 0 and result.get("queueTargetsExactThreadA")
        and result.get("queueAcceptedWhileHeld")
        and result.get("noClassifiedFollowupBeforeRelease")
        and not result.get("heldWindowClassification", {}).get("unknownRequestNumbers")
        and result.get("noProviderWriteErrorBeforeRelease")
        and result.get("heldResponseWrittenBeforeFollowupRequest")
        and result.get("followupIncludesHeldAssistantResponse")
        and client.get("workingVisible")
        and client.get("heldAssistantResponseVisible")
        and not client.get("explicitCancellationSignalVisible")
        and result.get("BStayedIdle") and result.get("BStillOpenWhileHeld")
        and result.get("TuiAStillRunningWhileHeld")
        and result.get("TuiAStillRunningAfterFollowup")
        and result.get("followupResponseWritten")
    )


def _wait_for_ordered_excerpt(drain, initial, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        output = initial + drain.snapshot()
        excerpt = _ordered_excerpt(output)
        if excerpt["passed"]:
            return excerpt
        time.sleep(0.1)
    return _ordered_excerpt(initial + drain.snapshot())


def _reap_tui(process, timeout=3):
    result = {"pid": process.pid, "wasRunning": process.poll() is None}
    if result["wasRunning"]:
        try:
            process.kill()
            process.wait(timeout=timeout)
            result["killedAndReaped"] = True
        except subprocess.TimeoutExpired:
            result["killedAndReaped"] = False
            result["waitTimeoutSeconds"] = timeout
        except OSError as error:
            result["killedAndReaped"] = False
            result["errorType"] = type(error).__name__
    else:
        result["exitCode"] = process.returncode
        result["killedAndReaped"] = True
    return result


class HeldResponseProvider(http.server.ThreadingHTTPServer):
    """Records bounded metadata and holds the selected synthetic responses."""

    def __init__(self, address, private_capture_path=None):
        self.requests = []
        self.events = []
        self.lock = threading.Lock()
        self.hold_started = threading.Event()
        self.release_hold = threading.Event()
        self.held_response_written = threading.Event()
        self.held_request_number = None
        self.hold_claimed = False
        self.response_write_errors = []
        self.started_at = time.monotonic()
        self.private_capture_path = private_capture_path
        self.followup_hold_started = threading.Event()
        self.release_followup_hold = threading.Event()
        self.followup_response_written = threading.Event()
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                try:
                    payload = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    payload = {}
                texts = _message_texts(payload)
                structure = _request_structure(payload)
                with server.lock:
                    number = len(server.requests) + 1
                    hold_kind = None
                    if not server.hold_claimed and HELD_PROMPT in texts:
                        server.hold_claimed = True
                        hold_kind = "held_turn"
                        server.held_request_number = number
                    elif QUEUE_REFERENCE in texts:
                        hold_kind = "queued_followup"
                    server.requests.append({
                        "number": number,
                        "synthetic_user_text": texts,
                        "heldAssistantMarker": (
                            HELD_REPLY if _assistant_has_marker(payload, HELD_REPLY) else None),
                        "structure": structure,
                        "purposeClassification": _classify_request_purpose(payload, QUEUE_REFERENCE),
                        "elapsedSeconds": round(time.monotonic() - server.started_at, 3),
                    })
                    server.events.append({"event": "provider_request", "number": number})
                    if hold_kind == "held_turn":
                        server.events.append({"event": "held_request", "number": number})
                    if number == 4 and server.private_capture_path is not None:
                        fd = os.open(server.private_capture_path,
                                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        os.fchmod(fd, 0o600)
                        with os.fdopen(fd, "wb") as capture:
                            capture.write(raw)
                if hold_kind == "held_turn":
                    server.hold_started.set()
                    server.release_hold.wait(20)
                elif hold_kind == "queued_followup":
                    server.followup_hold_started.set()
                    server.release_followup_hold.wait(15)
                events = _response_events(
                    number, HELD_REPLY if hold_kind == "held_turn" else "synthetic response")
                response_id_hash = None
                for event in events:
                    response = event.get("response")
                    if isinstance(response, dict) and isinstance(response.get("id"), str):
                        response_id_hash = _identifier_hash(response["id"])
                body = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                               for event in events).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    with server.lock:
                        self.wfile.write(body)
                        self.wfile.flush()
                        server.events.append({"event": "response_written", "number": number})
                        server.events.append({"event": "stream_completed", "number": number,
                                              "responseIdSha256": response_id_hash,
                                              "elapsedSeconds": round(time.monotonic() - server.started_at, 3)})
                except OSError:
                    with server.lock:
                        server.response_write_errors.append(number)
                        server.events.append({"event": "response_write_error", "number": number})
                else:
                    if hold_kind == "held_turn":
                        server.held_response_written.set()
                    elif hold_kind == "queued_followup":
                        server.followup_response_written.set()

        super().__init__(address, Handler)


def qualify(binary, private_request_capture=None):
    binary = Path(binary).resolve(strict=True)
    result = {"binary": str(binary)}
    with tempfile.TemporaryDirectory(prefix="stock-codex-e1-busy-") as directory:
        home = Path(directory)
        provider = HeldResponseProvider(("127.0.0.1", 0), private_request_capture)
        threading.Thread(target=provider.serve_forever, daemon=True).start()
        (home / "config.toml").write_text(
            "check_for_update_on_startup = false\nmodel_provider = \"loopback\"\n"
            "model = \"synthetic\"\nmodel_reasoning_effort = \"low\"\n"
            "[model_providers.loopback]\nname = \"Synthetic loopback\"\n"
            f"base_url = \"http://127.0.0.1:{provider.server_address[1]}/v1\"\n"
            "wire_api = \"responses\"\nrequires_openai_auth = false\n"
            "supports_websockets = false\n")
        daemon_stop_required = False
        tuis = []
        drains = []
        b_request_baseline = None
        try:
            version = subprocess.run(
                [str(binary), "--version"], env=_environment(home), text=True,
                capture_output=True, timeout=10)
            result["version"] = version.stdout.strip()
            if version.returncode:
                raise RuntimeError("version_probe_failed")
            thread_a = _seed(binary, home, SESSION_A)
            thread_b = _seed(binary, home, SESSION_B)
            result["threadA"] = thread_a
            result["threadB"] = thread_b
            daemon_stop_required = True
            daemon = subprocess.run(
                [str(binary), "app-server", "daemon", "start"],
                env=_environment(home), text=True, capture_output=True, timeout=15)
            result["daemonStartExit"] = daemon.returncode
            if daemon.returncode:
                raise RuntimeError("daemon_start_failed")
            daemon_info = json.loads(daemon.stdout)
            result["daemonVersion"] = daemon_info.get("cliVersion")
            socket_path = daemon_info.get("socketPath")
            result["privateUnixSocketPresent"] = bool(socket_path and Path(socket_path).exists())
            result["serverOwnership"] = "documented-local-unix-app-server"
            result["tuiConnectionMode"] = "explicit --remote unix://<daemon socket>"
            result["queueConnectionMode"] = "stock default local-daemon selector (no --remote)"
            if not result["privateUnixSocketPresent"]:
                raise RuntimeError("daemon_unix_socket_missing")

            b_request_baseline = len(provider.requests)
            tui_b, master_b = _remote_tui(binary, home, thread_b, socket_path)
            tuis.append((tui_b, master_b))
            b_ready = _read_until(master_b, tui_b, b"", lambda text: "Ask Codex to do anything" in text, 10)
            result["BPromptReady"] = "Ask Codex to do anything" in _clean_terminal(b_ready)
            if not result["BPromptReady"]:
                result["BSubmitDiagnostic"] = _pty_diagnostic(b_ready)
            drain_b = PtyDrain(master_b)
            drain_b.start()
            drains.append(("B", drain_b))

            tui_a, master_a = _remote_tui(binary, home, thread_a, socket_path)
            tuis.append((tui_a, master_a))
            a_ready = _read_until(master_a, tui_a, b"", lambda text: "Ask Codex to do anything" in text, 10)
            result["APromptReady"] = "Ask Codex to do anything" in _clean_terminal(a_ready)
            if not result["APromptReady"]:
                result["ASubmitDiagnostic"] = _pty_diagnostic(a_ready)
            if not result["BPromptReady"] or not result["APromptReady"]:
                raise RuntimeError("tui_prompt_not_ready")

            os.write(master_a, HELD_PROMPT.encode())
            typed = _read_until(master_a, tui_a, a_ready,
                                lambda text: HELD_PROMPT in text, 3)
            result["HeldPromptVisible"] = HELD_PROMPT in _clean_terminal(typed)
            if not result["HeldPromptVisible"]:
                raise RuntimeError("busy_prompt_not_rendered")
            drain_a = PtyDrain(master_a)
            drain_a.start()
            drains.append(("A", drain_a))
            os.write(master_a, b"\r")
            result["heldTurnReachedProvider"] = provider.hold_started.wait(12)
            if not result["heldTurnReachedProvider"]:
                result["submitDiagnostic"] = _pty_diagnostic(drain_a.snapshot())
                raise RuntimeError("held_turn_not_received")
            held_number = provider.held_request_number
            result["heldRequestNumber"] = held_number

            queued = subprocess.run(
                [str(binary), "queue", "--thread", thread_a, "--message", QUEUE_REFERENCE,
                 "--resume"],
                env=_environment(home), text=True, capture_output=True, timeout=15)
            result["queue"] = {"exit": queued.returncode, "output": queued.stdout.strip()}
            result["queueExit"] = queued.returncode
            result["queueTargetsExactThreadA"] = _queue_targets(queued, thread_a)
            with provider.lock:
                provider.events.append({
                    "event": "queue_accepted" if result["queueTargetsExactThreadA"] else "queue_rejected",
                    "number": held_number,
                    "elapsedSeconds": round(time.monotonic() - provider.started_at, 3),
                })
            time.sleep(0.5)
            with provider.lock:
                result["providerRequestCountWhileHeld"] = len(provider.requests)
                result["heldWindowClassification"] = _classify_held_window(
                    provider.requests, held_number, QUEUE_REFERENCE)
                result["noClassifiedFollowupBeforeRelease"] = result[
                    "heldWindowClassification"]["noClassifiedFollowupBeforeRelease"]
                result["noProviderWriteErrorBeforeRelease"] = not provider.response_write_errors
                result["clientStateAtQueueAcceptance"] = _client_view(typed + drain_a.snapshot())
            result["BStillOpenWhileHeld"] = tui_b.poll() is None
            result["TuiAStillRunningWhileHeld"] = tui_a.poll() is None
            with provider.lock:
                provider.events.append({"event": "hold_release", "number": held_number,
                                       "elapsedSeconds": round(time.monotonic() - provider.started_at, 3)})
            provider.release_hold.set()
            result["heldResponseWritten"] = provider.held_response_written.wait(10)
            if not result["heldResponseWritten"]:
                raise RuntimeError("held_response_not_delivered")
            result["followupRequestObserved"] = provider.followup_hold_started.wait(12)
            if not result["followupRequestObserved"]:
                raise RuntimeError("queued_followup_not_received")
            result["clientStateBeforeFollowupCompletion"] = _client_view(
                typed + drain_a.snapshot())
            provider.release_followup_hold.set()
            result["followupResponseWritten"] = provider.followup_response_written.wait(10)
            with provider.lock:
                rows_after_hold = list(provider.requests[held_number:])
            followup = next((row for row in rows_after_hold
                             if _valid_followup(row, QUEUE_REFERENCE, HELD_REPLY)), None)
            result["followup"] = followup
            result["followupIncludesHeldAssistantResponse"] = followup is not None
            result["TuiAStillRunningAfterFollowup"] = tui_a.poll() is None
            result["orderedTuiExcerpt"] = _wait_for_ordered_excerpt(drain_a, typed)
            with provider.lock:
                final_requests = list(provider.requests)
                result["events"] = list(provider.events)
                result["providerWriteErrors"] = list(provider.response_write_errors)
                result["BStayedIdle"] = _session_stayed_idle(
                    final_requests, b_request_baseline, SESSION_B)
            event_names = [(event["event"], event.get("number")) for event in result["events"]]
            held_write = event_names.index(("response_written", held_number)) if ("response_written", held_number) in event_names else -1
            followup_number = followup["number"] if followup else -1
            followup_request = event_names.index(("provider_request", followup_number)) if ("provider_request", followup_number) in event_names else -1
            release_index = event_names.index(("hold_release", held_number)) if ("hold_release", held_number) in event_names else -1
            held_event = event_names.index(("held_request", held_number)) if ("held_request", held_number) in event_names else -1
            queue_event = event_names.index(("queue_accepted", held_number)) if ("queue_accepted", held_number) in event_names else -1
            result["queueAcceptedWhileHeld"] = held_event >= 0 and held_event < queue_event < release_index
            result["heldResponseWrittenBeforeFollowupRequest"] = (
                release_index >= 0 and held_write > release_index and followup_request > held_write)
            result["passed"] = _busy_gate_passed(result)
            result["result"] = "bounded_synthetic_busy_passed" if result["passed"] else "bounded_synthetic_busy_failed"
        except Exception as error:
            result["passed"] = False
            result["result"] = "bounded_synthetic_busy_failed"
            message = re.sub(r"/private/(?:tmp|var/folders)/\S+", "<private-path>", str(error))
            result["error"] = {"type": type(error).__name__, "message": message[:160]}
        finally:
            provider.release_hold.set()
            provider.release_followup_hold.set()
            drain_cleanup = []
            for label, drain in drains:
                drain_cleanup.append({"label": label, "stopped": drain.stop(), "timeoutSeconds": 2})
            result["ptyDrainCleanup"] = drain_cleanup
            if "submitDiagnostic" not in result and drains:
                result["submitDiagnostic"] = _pty_diagnostic(drains[-1][1].snapshot())
            tui_cleanup = []
            for process, master in tuis:
                item = _reap_tui(process)
                tui_cleanup.append(item)
                try:
                    os.close(master)
                    item["ptyMasterClosed"] = True
                except OSError:
                    item["ptyMasterClosed"] = False
            result["tuiCleanup"] = tui_cleanup
            if daemon_stop_required:
                try:
                    stopped = subprocess.run(
                        [str(binary), "app-server", "daemon", "stop"],
                        env=_environment(home), text=True, capture_output=True, timeout=15)
                    try:
                        status = json.loads(stopped.stdout).get("status")
                    except (json.JSONDecodeError, AttributeError):
                        status = None
                    result["daemonCleanup"] = {"exit": stopped.returncode, "status": status,
                                                "timeoutSeconds": 15}
                    cleanup_ok = stopped.returncode == 0 and status == "stopped"
                except subprocess.TimeoutExpired:
                    result["daemonCleanup"] = {"timeout": True, "timeoutSeconds": 15}
                    cleanup_ok = False
                if (not cleanup_ok or any(not item["stopped"] for item in drain_cleanup) or any(
                        not item["killedAndReaped"] or not item.get("ptyMasterClosed")
                        for item in tui_cleanup)):
                    result["passed"] = False
                    result["result"] = "bounded_synthetic_busy_failed"
                    result["error"] = "daemon_cleanup_failed"
            with provider.lock:
                final_requests = list(provider.requests)
                if b_request_baseline is not None:
                    result["BStayedIdle"] = _session_stayed_idle(
                        final_requests, b_request_baseline, SESSION_B)
                result["events"] = list(provider.events)
                result["providerWriteErrors"] = list(provider.response_write_errors)
                result["providerRequestSummary"] = [
                    {"number": row["number"],
                     "syntheticUserMarkers": row["synthetic_user_text"],
                     "heldAssistantMarker": row["heldAssistantMarker"],
                     "structure": row["structure"],
                     "purposeClassification": row["purposeClassification"],
                     "elapsedSeconds": row["elapsedSeconds"]}
                    for row in final_requests]
            if result.get("passed") and not result.get("BStayedIdle"):
                result["passed"] = False
                result["result"] = "bounded_synthetic_busy_failed"
                result["error"] = "session_b_activity_observed"
            provider.shutdown()
            provider.server_close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--private-request-capture", type=Path,
                        help="Mode-0600 private capture of request 4 only; do not publish")
    args = parser.parse_args()
    result = qualify(args.binary, args.private_request_capture)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")
    if not result.get("passed"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
