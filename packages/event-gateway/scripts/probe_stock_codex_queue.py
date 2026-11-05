"""Bounded stock Codex TUI/daemon qualification using a loopback Responses fixture."""

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import termios
import threading
import time


def _response_events(number, response_text="synthetic response"):
    item_id, response_id, text = f"msg_{number}", f"resp_{number}", response_text
    item = {"id": item_id, "type": "message", "role": "assistant",
            "status": "completed", "content": [{"type": "output_text", "text": text,
                                                        "annotations": []}]}
    return [
        {"type": "response.created", "response": {"id": response_id, "object": "response",
         "created_at": 1, "status": "in_progress", "model": "synthetic", "output": []}},
        {"type": "response.output_item.added", "output_index": 0,
         "item": {**item, "status": "in_progress", "content": []}},
        {"type": "response.content_part.added", "item_id": item_id, "output_index": 0,
         "content_index": 0, "part": {"type": "output_text", "text": ""}},
        {"type": "response.output_text.delta", "item_id": item_id, "output_index": 0,
         "content_index": 0, "delta": text},
        {"type": "response.output_text.done", "item_id": item_id, "output_index": 0,
         "content_index": 0, "text": text},
        {"type": "response.content_part.done", "item_id": item_id, "output_index": 0,
         "content_index": 0, "part": {"type": "output_text", "text": text}},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": {"id": response_id, "object": "response",
         "created_at": 1, "status": "completed", "model": "synthetic", "output": [item]}},
    ]


def _message_texts(payload):
    texts = []
    for item in payload.get("input", []):
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        content = item.get("content", [])
        if isinstance(content, list):
            texts.extend(part["text"][:100] for part in content
                         if isinstance(part, dict) and isinstance(part.get("text"), str)
                         and (part["text"].startswith("ref_")
                              or part["text"].startswith("Seed synthetic ")
                              or part["text"] == "synthetic busy turn marker"))
        elif isinstance(content, str):
            if (content.startswith("ref_") or content.startswith("Seed synthetic ")
                    or content == "synthetic busy turn marker"):
                texts.append(content[:100])
    return texts


class LoopbackProvider(http.server.ThreadingHTTPServer):
    """A tiny local Responses endpoint; it records only bounded synthetic user text."""

    def __init__(self, address):
        self.requests = []
        self.lock = threading.Lock()
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
                with server.lock:
                    number = len(server.requests) + 1
                    server.requests.append({"number": number, "synthetic_user_text": texts})
                body = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                               for event in _response_events(number)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        super().__init__(address, Handler)


def _wait_for(provider, predicate, after=0, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with provider.lock:
            found = next((row for row in provider.requests[after:] if predicate(row)), None)
        if found:
            return found
        time.sleep(0.05)
    return None


def _provider_request_count(provider):
    with provider.lock:
        return len(provider.requests)


def _provider_requests_since(provider, baseline):
    with provider.lock:
        return list(provider.requests[baseline:])


def _has_session_marker(request, marker):
    return marker in request.get("synthetic_user_text", [])


def _targets_session(request, reference, expected_marker, forbidden_marker):
    texts = request.get("synthetic_user_text", [])
    return reference in texts and expected_marker in texts and forbidden_marker not in texts


def _tui(binary, home, thread_id):
    master, slave = pty.openpty()
    import fcntl
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    command = [str(binary), "--no-alt-screen", "resume", "--include-non-interactive", thread_id]
    command.extend(("-C", str(home)))
    process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                               env=_environment(home), close_fds=True)
    os.close(slave)
    time.sleep(1.25)
    return process, master


def _open_tui_with_baseline(provider, binary, home, thread_id):
    baseline = _provider_request_count(provider)
    process, master = _tui(binary, home, thread_id)
    return process, master, baseline


def _stop_tui(process, master):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    os.close(master)
    return process.returncode


def _environment(home):
    # Do not inherit user credentials, config, or tool-specific variables.
    return {"PATH": os.defpath, "HOME": str(home), "CODEX_HOME": str(home),
            "CODEX_DISABLE_AUTOUPDATER": "1", "TERM": "xterm-256color"}


def _cli(binary, home, *args, timeout=25):
    return subprocess.run([str(binary), *args], env=_environment(home), text=True,
                          capture_output=True, timeout=timeout)


def _queue_targets(result, thread_id):
    match = re.fullmatch(
        r"Queued message ([0-9a-f-]{36}) for thread ([0-9a-f-]{36})\.\n?",
        result.stdout,
    )
    return result.returncode == 0 and match is not None and match.group(2) == thread_id


def _seed(binary, home, prompt):
    result = _cli(binary, home, "exec", "--json", "--skip-git-repo-check", "-C",
                  str(home), prompt)
    if result.returncode:
        raise RuntimeError("synthetic_thread_seed_failed")
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    return next(event["thread_id"] for event in events if event.get("type") == "thread.started")


def qualify(binary):
    binary = Path(binary).resolve(strict=True)
    if not os.access(binary, os.X_OK):
        raise ValueError("--binary must be executable")
    result = {"binary": str(binary), "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix="stock-codex-e1-") as directory:
        home = Path(directory)
        probe = LoopbackProvider(("127.0.0.1", 0))
        threading.Thread(target=probe.serve_forever, daemon=True).start()
        (home / "config.toml").write_text(
            "check_for_update_on_startup = false\nmodel_provider = \"loopback\"\n"
            "model = \"synthetic\"\nmodel_reasoning_effort = \"low\"\n"
            "[model_providers.loopback]\nname = \"Synthetic loopback\"\n"
            f"base_url = \"http://127.0.0.1:{probe.server_address[1]}/v1\"\n"
            "wire_api = \"responses\"\nrequires_openai_auth = false\n"
            "supports_websockets = false\n")
        daemon_started = False
        tuis = []
        try:
            version = _cli(binary, home, "--version")
            if version.returncode:
                raise RuntimeError("codex_version_failed")
            result["version"] = version.stdout.strip()
            thread_a = _seed(binary, home, "Seed synthetic session A.")
            thread_b = _seed(binary, home, "Seed synthetic session B.")
            result["threadA"] = thread_a
            result["threadB"] = thread_b
            daemon_started = True
            daemon = _cli(binary, home, "app-server", "daemon", "start")
            if daemon.returncode:
                raise RuntimeError("private_daemon_start_failed")
            result["daemonStart"] = json.loads(daemon.stdout)

            session_a_marker = "Seed synthetic session A."
            session_b_marker = "Seed synthetic session B."
            tui_b, pty_b, cross_session_baseline = _open_tui_with_baseline(
                probe, binary, home, thread_b)
            tuis.append((tui_b, pty_b))
            result["requestsBeforeCrossSessionTui"] = cross_session_baseline
            first_ref = "ref_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            queued = _cli(binary, home, "queue", "--thread", thread_a, "--message", first_ref, "--resume")
            result["queueAWhileBOpen"] = {"exit": queued.returncode, "output": queued.stdout.strip()}
            result["queueAWhileBOpenTargetsExactUUID"] = _queue_targets(queued, thread_a)
            first = _wait_for(
                probe,
                lambda row: _targets_session(row, first_ref, session_a_marker, session_b_marker),
                cross_session_baseline,
            )
            result["crossSessionTargetedA"] = first is not None
            result["BStillOpen"] = tui_b.poll() is None
            time.sleep(0.5)
            post_cross_session_requests = _provider_requests_since(probe, cross_session_baseline)
            result["BStayedIdle"] = not any(
                _has_session_marker(row, session_b_marker) for row in post_cross_session_requests)
            if (not first or not result["queueAWhileBOpenTargetsExactUUID"]
                    or not result["BStillOpen"] or not result["BStayedIdle"]):
                raise RuntimeError("explicit_session_queue_not_observed")
            result["responseForA"] = first
            result["BExit"] = _stop_tui(tui_b, pty_b)

            tui_a, pty_a = _tui(binary, home, thread_a)
            tuis.append((tui_a, pty_a))
            result["AExit"] = _stop_tui(tui_a, pty_a)
            status = _cli(binary, home, "app-server", "daemon", "version")
            result["daemonAfterTuiExit"] = json.loads(status.stdout).get("status")
            second_ref = "ref_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            before_closed_queue = len(probe.requests)
            queued = _cli(binary, home, "queue", "--thread", thread_a,
                          "--message", second_ref, "--resume")
            result["queueAWithTuiClosed"] = {"exit": queued.returncode, "output": queued.stdout.strip()}
            result["queueAWithTuiClosedTargetsExactUUID"] = _queue_targets(queued, thread_a)
            second = _wait_for(
                probe,
                lambda row: _targets_session(row, second_ref, session_a_marker, session_b_marker),
                before_closed_queue,
            )
            result["closedTuiDaemonResume"] = second is not None
            if (not second or not result["queueAWithTuiClosedTargetsExactUUID"]
                    or result["daemonAfterTuiExit"] != "running"):
                raise RuntimeError("closed_tui_daemon_resume_unproved")

            tui_a, pty_a, reopen_baseline = _open_tui_with_baseline(
                probe, binary, home, thread_a)
            tuis.append((tui_a, pty_a))
            result["reopenedA"] = tui_a.poll() is None
            if not result["reopenedA"]:
                raise RuntimeError("same_uuid_tui_reopen_not_observed")
            result["reopenRequestCount"] = reopen_baseline
            time.sleep(1)
            result["postReopenRequestCount"] = _provider_request_count(probe)
            result["reopenCausedNoNewProviderRequest"] = (
                result["reopenRequestCount"] == result["postReopenRequestCount"])
            if not result["reopenCausedNoNewProviderRequest"]:
                raise RuntimeError("reopen_replayed_queued_input")
            result["AReopenExit"] = _stop_tui(tui_a, pty_a)

            duplicate_ref = "ref_dddddddd-dddd-4ddd-8ddd-dddddddddddd"
            thread_c = _seed(binary, home, "Seed synthetic duplicate-check session.")
            first_dup = _cli(binary, home, "queue", "--thread", thread_c, "--message", duplicate_ref)
            second_dup = _cli(binary, home, "queue", "--thread", thread_c, "--message", duplicate_ref)
            result["duplicateCommands"] = [first_dup.stdout.strip(), second_dup.stdout.strip()]
            result["duplicateAcceptedSeparately"] = (
                first_dup.returncode == second_dup.returncode == 0
                and first_dup.stdout != second_dup.stdout)
            if not result["duplicateAcceptedSeparately"]:
                raise RuntimeError("duplicate_queue_behavior_unexpected")
            result["providerRequests"] = probe.requests
            result["result"] = "bounded_synthetic_nonbusy_checks_passed"
        finally:
            for process, master in tuis:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                try:
                    os.close(master)
                except OSError:
                    pass
            if daemon_started:
                stopped = _cli(binary, home, "app-server", "daemon", "stop")
                try:
                    status = json.loads(stopped.stdout).get("status")
                except (json.JSONDecodeError, AttributeError):
                    status = None
                result["daemonCleanup"] = {"exit": stopped.returncode, "status": status}
                if stopped.returncode or status != "stopped":
                    raise RuntimeError("private_daemon_cleanup_failed")
            probe.shutdown()
            probe.server_close()
    return result


def qualify_upgrade(previous_binary, current_binary):
    """Seed a synthetic thread with the prior official CLI and resume it with current."""
    previous_binary = Path(previous_binary).resolve(strict=True)
    current_binary = Path(current_binary).resolve(strict=True)
    result = {
        "previousBinarySha256": hashlib.sha256(previous_binary.read_bytes()).hexdigest(),
        "currentBinarySha256": hashlib.sha256(current_binary.read_bytes()).hexdigest(),
    }
    with tempfile.TemporaryDirectory(prefix="stock-codex-e1-upgrade-") as directory:
        home = Path(directory)
        probe = LoopbackProvider(("127.0.0.1", 0))
        threading.Thread(target=probe.serve_forever, daemon=True).start()
        (home / "config.toml").write_text(
            "check_for_update_on_startup = false\nmodel_provider = \"loopback\"\n"
            "model = \"synthetic\"\nmodel_reasoning_effort = \"low\"\n"
            "[model_providers.loopback]\nname = \"Synthetic loopback\"\n"
            f"base_url = \"http://127.0.0.1:{probe.server_address[1]}/v1\"\n"
            "wire_api = \"responses\"\nrequires_openai_auth = false\n"
            "supports_websockets = false\n")
        previous_daemon_stop_required = False
        current_daemon_stop_required = False
        try:
            previous_version = _cli(previous_binary, home, "--version")
            current_version = _cli(current_binary, home, "--version")
            if previous_version.returncode or current_version.returncode:
                raise RuntimeError("upgrade_version_probe_failed")
            result["previousVersion"] = previous_version.stdout.strip()
            result["currentVersion"] = current_version.stdout.strip()
            expected_current_version = result["currentVersion"].removeprefix("codex-cli ")

            thread_id = _seed(previous_binary, home, "Seed synthetic prior-version session.")
            result["persistedThreadId"] = thread_id
            previous_daemon_stop_required = True
            old_daemon = _cli(previous_binary, home, "app-server", "daemon", "start")
            if old_daemon.returncode:
                raise RuntimeError("previous_version_daemon_start_failed")
            result["previousDaemonStart"] = json.loads(old_daemon.stdout).get("status")
            if result["previousDaemonStart"] != "started":
                raise RuntimeError("previous_version_daemon_identity_unproved")
            stop_old = _cli(previous_binary, home, "app-server", "daemon", "stop")
            result["previousDaemonStopExit"] = stop_old.returncode
            old_stop_info = json.loads(stop_old.stdout) if stop_old.stdout.strip() else {}
            result["previousDaemonStopStatus"] = old_stop_info.get("status")
            if stop_old.returncode or old_stop_info.get("status") != "stopped":
                raise RuntimeError("previous_version_daemon_stop_failed")
            previous_daemon_stop_required = False

            current_daemon_stop_required = True
            new_daemon = _cli(current_binary, home, "app-server", "daemon", "start")
            if new_daemon.returncode:
                raise RuntimeError("current_version_daemon_start_failed")
            new_daemon_info = json.loads(new_daemon.stdout)
            result["currentDaemonVersion"] = new_daemon_info.get("cliVersion")
            result["currentDaemonStart"] = new_daemon_info.get("status")
            if (result["currentDaemonVersion"] != expected_current_version
                    or result["currentDaemonStart"] != "started"):
                raise RuntimeError("current_version_daemon_identity_unproved")

            reference = "ref_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
            before_queue = len(probe.requests)
            queued = _cli(current_binary, home, "queue", "--thread", thread_id,
                          "--message", reference, "--resume")
            result["queue"] = {"exit": queued.returncode, "output": queued.stdout.strip()}
            seen = _wait_for(probe, lambda row: reference in row["synthetic_user_text"],
                             before_queue)
            result["queueTargetsExactPriorUUID"] = _queue_targets(queued, thread_id)
            result["sameThreadResumedAfterUpgrade"] = bool(
                result["queueTargetsExactPriorUUID"] and seen)
            result["matchingSyntheticRequest"] = seen
            result["result"] = "bounded_same_home_upgrade_passed"
            if not result["sameThreadResumedAfterUpgrade"]:
                raise RuntimeError("current_version_did_not_resume_prior_thread")
        finally:
            cleanup_failures = []
            for label, binary, required in (
                ("current", current_binary, current_daemon_stop_required),
                ("previous", previous_binary, previous_daemon_stop_required),
            ):
                if not required:
                    continue
                stopped = _cli(binary, home, "app-server", "daemon", "stop")
                try:
                    status = json.loads(stopped.stdout).get("status")
                except (json.JSONDecodeError, AttributeError):
                    status = None
                result.setdefault("daemonCleanup", {})[label] = {
                    "exit": stopped.returncode, "status": status}
                if stopped.returncode != 0 or status != "stopped":
                    cleanup_failures.append(label)
            probe.shutdown()
            probe.server_close()
            if cleanup_failures:
                raise RuntimeError("daemon_cleanup_failed:" + ",".join(cleanup_failures))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=shutil.which("codex"), help="stock Codex executable")
    parser.add_argument("--upgrade-from", type=Path,
                        help="seed the private home with this prior-version CLI, then run one current-version resume")
    parser.add_argument("--output", type=Path, help="write sanitized JSON result here")
    args = parser.parse_args()
    if not args.binary:
        parser.error("codex executable not found; pass --binary")
    result = (qualify_upgrade(args.upgrade_from, args.binary) if args.upgrade_from else
              qualify(args.binary))
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
