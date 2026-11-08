"""Pure evidence-gate tests for the local stock Codex pilot fixture."""

from pathlib import Path
import asyncio
import errno
from contextlib import redirect_stdout
from contextlib import redirect_stderr
from copy import deepcopy
import io
import os
import socket
import subprocess  # nosec B404 -- Only DEVNULL and mocked argument-only CLI calls; no shell.
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from prepare_stock_codex_pilot import (  # noqa: E402
    HELD_REPLY,
    HELD_PROMPT,
    MAX_CONTROL_BYTES,
    PilotFixture,
    PilotProvider,
    SESSION_A,
    SESSION_B,
    _owned_daemon_socket,
    _stop_owned_updater,
    main,
    _request_record,
    _pop_control_line,
    pilot_evidence,
    pilot_progress,
)
from probe_stock_codex_queue import _cli  # noqa: E402
from event_gateway.stock_codex import StockCodexAdapter  # noqa: E402

IDLE_REF = "ref_11111111-1111-4111-8111-111111111111"
BUSY_REF = "ref_22222222-2222-4222-8222-222222222222"
OTHER_REF = "ref_33333333-3333-4333-8333-333333333333"


def _evidence_inputs():
    requests = [
        {"number": 1, "references": [IDLE_REF], "latestUserReferences": [IDLE_REF], "sessionMarkers": [SESSION_A],
         "heldPrompt": False, "heldAssistantMarker": None},
        {"number": 2, "references": [], "latestUserReferences": [], "sessionMarkers": [SESSION_A],
         "heldPrompt": True, "heldAssistantMarker": None},
        {"number": 3, "references": [IDLE_REF, BUSY_REF], "latestUserReferences": [BUSY_REF], "sessionMarkers": [SESSION_A],
         "heldPrompt": False, "heldAssistantMarker": HELD_REPLY},
    ]
    events = [
        {"event": "request", "number": 1},
        {"event": "response_written", "number": 1},
        {"event": "request", "number": 2},
        {"event": "hold_release", "number": 2},
        {"event": "response_written", "number": 2},
        {"event": "request", "number": 3},
    ]
    return requests, events


class PilotEvidenceTests(unittest.TestCase):
    def test_linux_is_rejected_before_fixture_construction(self):
        fixture = Mock()
        fixture.stop.return_value = {"clean": True}
        with patch("prepare_stock_codex_pilot.sys.platform", "linux"), \
                patch("prepare_stock_codex_pilot.sys.argv", ["fixture", "--binary", "/unused"]), \
                patch("prepare_stock_codex_pilot.PilotFixture", return_value=fixture) as constructor, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit):
            main()
        constructor.assert_not_called()

    def test_response_event_is_recorded_before_followup_request_can_acquire_lock(self):
        provider = PilotProvider.__new__(PilotProvider)
        provider.lock = threading.Lock()
        provider.events = []
        write_entered = threading.Event()
        finish_write = threading.Event()
        followup_started = threading.Event()

        class PausedWriter:
            def write(self, _body):
                write_entered.set()
                if not finish_write.wait(2):
                    raise TimeoutError("test writer release timeout")

            def flush(self):
                pass

        response = threading.Thread(target=provider._write_response,
                                    args=(PausedWriter(), b"response", 1))
        response.start()
        self.assertTrue(write_entered.wait(1))
        lock_available_during_write = provider.lock.acquire(blocking=False)
        if lock_available_during_write:
            provider.lock.release()

        def record_followup():
            followup_started.set()
            with provider.lock:
                provider.events.append({"event": "request", "number": 2})

        followup = threading.Thread(target=record_followup)
        followup.start()
        self.assertTrue(followup_started.wait(1))
        finish_write.set()
        response.join(timeout=2)
        followup.join(timeout=2)
        self.assertFalse(response.is_alive())
        self.assertFalse(followup.is_alive())
        self.assertFalse(lock_available_during_write)
        self.assertEqual(provider.events, [
            {"event": "response_written", "number": 1},
            {"event": "request", "number": 2},
        ])

    def test_constructor_keyboard_interrupt_runs_cleanup_and_reraises(self):
        with tempfile.TemporaryDirectory(prefix="e3-interrupt-") as directory:
            binary = Path(directory) / "codex"
            binary.write_text("unused by patched seed")
            provider = SimpleNamespace(
                server_address=("127.0.0.1", 12345), serve_forever=Mock(),
                release_hold=threading.Event(), shutdown=Mock(), server_close=Mock(),
                active_requests_done=threading.Event(),
            )
            provider.active_requests_done.set()
            provider_thread = Mock()
            provider_thread.is_alive.return_value = False
            original_stop = PilotFixture.stop
            homes = []

            def stop_and_record(fixture):
                homes.append(fixture.home)
                return original_stop(fixture)

            with patch("prepare_stock_codex_pilot.PilotProvider", return_value=provider), \
                    patch("prepare_stock_codex_pilot.threading.Thread", return_value=provider_thread), \
                    patch("prepare_stock_codex_pilot._seed", side_effect=KeyboardInterrupt), \
                    patch.object(PilotFixture, "stop", autospec=True, side_effect=stop_and_record) as stop, \
                    redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt):
                PilotFixture(binary)

            stop.assert_called_once()
            provider.shutdown.assert_called_once()
            self.assertEqual(len(homes), 1)
            self.assertFalse(homes[0].exists())

    def test_stock_cli_probe_does_not_inherit_control_stdin(self):
        with tempfile.TemporaryDirectory(prefix="e3-cli-stdin-") as directory:
            with patch("probe_stock_codex_queue.subprocess.run") as run:
                _cli("/fixture/codex", Path(directory), "--version")
            self.assertIs(run.call_args.kwargs.get("stdin"), subprocess.DEVNULL)

    def test_private_socket_alias_proves_ownership_without_accepting_an_unrelated_socket(self):
        with tempfile.TemporaryDirectory(prefix="e3-socket-") as directory:
            fixture_root = Path(directory) / "fixture"
            fixture_root.mkdir(mode=0o700)
            target = Path(directory) / "daemon.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon:
                daemon.bind(str(target))
                alias = fixture_root / "control.sock"
                alias.symlink_to(target)
                self.assertTrue(_owned_daemon_socket(fixture_root, alias))
                self.assertFalse(_owned_daemon_socket(fixture_root, target))
            regular = fixture_root / "regular"
            regular.write_text("not a socket")
            self.assertFalse(_owned_daemon_socket(fixture_root, regular))

    def test_owned_updater_is_signalled_only_after_identity_checks_and_gone(self):
        with tempfile.TemporaryDirectory(prefix="e3-updater-") as directory:
            home = Path(directory)
            executable = home / "packages" / "app-server-daemon" / "codex"
            executable.parent.mkdir(parents=True)
            executable.write_text("fixture executable")
            start = "Wed Nov 4 23:01:38 2026"
            fields = {"uid": str(os.getuid()), "lstart": start,
                      "comm": str(executable), "stat": ""}

            def run(args, **_kwargs):
                return SimpleNamespace(returncode=0, stdout=fields[args[-1][:-1]] + "\n")

            with patch("prepare_stock_codex_pilot.subprocess.run", side_effect=run), \
                    patch("prepare_stock_codex_pilot.os.kill") as kill:
                self.assertTrue(_stop_owned_updater(home, {"pid": 1234, "processStartTime": start}))
                kill.assert_called_once()

    def test_updater_identity_mismatches_never_signal(self):
        with tempfile.TemporaryDirectory(prefix="e3-updater-") as directory:
            home = Path(directory)
            executable = home / "codex"
            executable.write_text("fixture executable")
            start = "Wed Nov 4 23:01:38 2026"
            for field, value, record in (
                ("uid", "999", {"pid": 1234, "processStartTime": start}),
                ("lstart", "Thu Nov 5 00:00:00 2026", {"pid": 1234, "processStartTime": start}),
                ("comm", "/usr/bin/codex", {"pid": 1234, "processStartTime": start}),
                ("uid", str(os.getuid()), {"pid": 1, "processStartTime": start}),
            ):
                fields = {"uid": str(os.getuid()), "lstart": start,
                          "comm": str(executable), "stat": ""}
                fields[field] = value

                def run(args, **_kwargs):
                    return SimpleNamespace(returncode=0, stdout=fields[args[-1][:-1]] + "\n")

                with self.subTest(field=field, value=value), \
                        patch("prepare_stock_codex_pilot.subprocess.run", side_effect=run), \
                        patch("prepare_stock_codex_pilot.os.kill") as kill:
                    self.assertFalse(_stop_owned_updater(home, record))
                    kill.assert_not_called()

    def test_rmtree_failure_is_reported_and_home_is_retained(self):
        with tempfile.TemporaryDirectory(prefix="e3-cleanup-") as directory:
            fixture = PilotFixture.__new__(PilotFixture)
            fixture.home = Path(directory) / "private-home"
            fixture.home.mkdir()
            fixture.stopped = False
            fixture.daemon_started = False
            fixture.daemon_ownership_unproved = False
            fixture.provider = SimpleNamespace(
                release_hold=threading.Event(), shutdown=Mock(), server_close=Mock(),
                active_requests_done=threading.Event(),
            )
            fixture.provider.active_requests_done.set()
            fixture.provider_thread = Mock()
            fixture.provider_thread.is_alive.return_value = False
            with patch("prepare_stock_codex_pilot.shutil.rmtree",
                       side_effect=OSError(errno.EACCES, "permission denied")):
                receipt = fixture.stop()
            self.assertFalse(receipt["clean"])
            self.assertEqual(receipt["cleanupError"], {"type": "PermissionError", "errno": errno.EACCES})
            self.assertEqual(receipt["retainedCodeHome"], str(fixture.home))

    def test_control_line_limit_includes_newline(self):
        with self.assertRaisesRegex(RuntimeError, "control_line_too_large"):
            _pop_control_line(bytearray(b" " * MAX_CONTROL_BYTES + b"\n"))

    def test_exact_ordered_idle_and_busy_refs_in_a_pass(self):
        requests, events = _evidence_inputs()
        result = pilot_evidence(requests, events, IDLE_REF, BUSY_REF)
        self.assertTrue(result["passed"])
        self.assertEqual((result["idleRequest"], result["heldRequest"], result["busyRequest"]), (1, 2, 3))

    def test_progress_proves_completed_idle_request_before_held_turn(self):
        requests, events = _evidence_inputs()
        observed_requests, observed_events = requests[:1], events[:2]
        original_requests, original_events = deepcopy(observed_requests), deepcopy(observed_events)
        result = pilot_progress(observed_requests, observed_events, IDLE_REF)
        self.assertEqual(result, {"status": "observed", "request": 1, "session": "A",
                                  "responseWritten": True, "phase": "idle"})
        self.assertEqual(observed_requests, original_requests)
        self.assertEqual(observed_events, original_events)

    def test_progress_reports_pending_until_exact_idle_response_is_written(self):
        requests, events = _evidence_inputs()
        self.assertEqual(pilot_progress([], [], IDLE_REF),
                         {"status": "pending", "reason": "request_not_observed"})
        self.assertEqual(pilot_progress(requests[:1], events[:1], IDLE_REF),
                         {"status": "pending", "reason": "response_not_written"})
        self.assertEqual(pilot_progress(requests[:2], [events[0], events[2]], IDLE_REF),
                         {"status": "pending", "reason": "response_not_written"})

    def test_progress_rejects_idle_response_that_finishes_after_held_request(self):
        requests, events = _evidence_inputs()
        events.remove({"event": "response_written", "number": 1})
        events.insert(events.index({"event": "request", "number": 2}) + 1,
                      {"event": "response_written", "number": 1})
        self.assertEqual(pilot_progress(requests[:2], events, IDLE_REF),
                         {"status": "invalid", "reason": "idle_response_not_before_held_request"})

    def test_progress_jsonl_command_routes_without_fixture_construction(self):
        fixture = PilotFixture.__new__(PilotFixture)
        fixture.started = time.monotonic()
        fixture.stopped = False
        fixture.progress = Mock(return_value={"status": "pending", "reason": "request_not_observed"})
        commands = [
            (f'{{"command":"progress","reference":"{IDLE_REF}"}}\n').encode(),
            b'{"command":"stop"}\n',
        ]
        with patch.object(fixture, "_read_control_line", side_effect=commands), \
                redirect_stdout(io.StringIO()) as output:
            fixture.serve()
        fixture.progress.assert_called_once_with(IDLE_REF)
        self.assertEqual(output.getvalue().splitlines(), [
            '{"status":"pending","reason":"request_not_observed"}', '{"stopped":true}',
        ])

    def test_progress_gates_busy_request_on_held_response_and_exposes_no_content(self):
        requests, events = _evidence_inputs()
        result = pilot_progress(requests, events, BUSY_REF)
        self.assertEqual(result, {"status": "observed", "request": 3, "session": "A",
                                  "responseWritten": False, "phase": "after_held_response"})
        self.assertNotIn("synthetic busy turn marker", repr(result))
        self.assertNotIn("synthetic held response e3 marker", repr(result))

    def test_progress_rejects_held_request_without_session_a_marker(self):
        requests, events = _evidence_inputs()
        requests[1]["sessionMarkers"] = []
        self.assertEqual(pilot_progress(requests, events, BUSY_REF),
                         {"status": "invalid", "reason": "wrong_session_or_input"})

    def test_progress_rejects_busy_request_before_held_response(self):
        requests, events = _evidence_inputs()
        events.remove({"event": "request", "number": 3})
        events.insert(events.index({"event": "response_written", "number": 2}),
                      {"event": "request", "number": 3})
        self.assertEqual(pilot_progress(requests, events, BUSY_REF),
                         {"status": "invalid", "reason": "not_after_held_response"})

    def test_progress_rejects_wrong_session_and_duplicate_exact_reference(self):
        requests, events = _evidence_inputs()
        wrong_session = [dict(requests[0], sessionMarkers=[SESSION_B])]
        self.assertEqual(pilot_progress(wrong_session, events[:2], IDLE_REF),
                         {"status": "invalid", "reason": "wrong_session_or_input"})
        duplicate = [requests[0], dict(requests[0], number=4)]
        self.assertEqual(pilot_progress(duplicate, events[:2], IDLE_REF),
                         {"status": "invalid", "reason": "reference_not_unique"})

    def test_progress_rejects_malformed_reference_without_echoing_it(self):
        result = pilot_progress([], [], "private prompt text")
        self.assertEqual(result, {"status": "invalid", "reason": "invalid_reference"})

    def test_historic_refs_and_held_prompt_do_not_reclassify_followup(self):
        payload = {"input": [
            {"role": "user", "content": [{"type": "input_text", "text": SESSION_A},
                                            {"type": "input_text", "text": IDLE_REF},
                                            {"type": "input_text", "text": HELD_PROMPT}]},
            {"role": "assistant", "content": [{"type": "output_text", "text": HELD_REPLY}]},
            {"role": "user", "content": [{"type": "input_text", "text": BUSY_REF}]},
        ]}
        record = _request_record(3, payload, held=False)
        self.assertEqual(record["references"], [IDLE_REF, BUSY_REF])
        self.assertEqual(record["latestUserReferences"], [BUSY_REF])
        self.assertFalse(record["heldPrompt"])
        self.assertTrue(record["containsHeldPrompt"])

    def test_request_record_recognizes_only_exact_canonical_selector(self):
        message_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        captured = {}

        async def fake_create_subprocess_exec(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            process = Mock()
            process.wait = Mock(return_value=asyncio.sleep(0, result=0))
            return process

        adapter = StockCodexAdapter(message_id, "/unused/codex")
        with patch("event_gateway.stock_codex._binary_is_executable", return_value=True), \
                patch("event_gateway.stock_codex.asyncio.create_subprocess_exec",
                      side_effect=fake_create_subprocess_exec):
            asyncio.run(adapter.submit(IDLE_REF, canonical_message_id=message_id))
        args = captured["args"]
        selector = args[args.index("--message") + 1]

        def response_input(text):
            return {"input": [{"role": "user", "content": [
                {"type": "input_text", "text": SESSION_A},
                {"type": "input_text", "text": text},
            ]}]}

        record = _request_record(1, response_input(selector), held=False)
        self.assertEqual(record["references"], [IDLE_REF])
        self.assertEqual(record["latestUserReferences"], [IDLE_REF])
        events = [{"event": "request", "number": 1}, {"event": "response_written", "number": 1}]
        self.assertEqual(pilot_progress([record], events, IDLE_REF)["status"], "observed")
        self.assertEqual(pilot_progress([record], events, BUSY_REF),
                         {"status": "pending", "reason": "request_not_observed"})

        spoofed_session = {"input": [{"role": "user", "content": [
            {"type": "input_text", "text": selector},
            {"type": "input_image", "text": SESSION_A},
        ]}]}
        spoofed_record = _request_record(1, spoofed_session, held=False)
        self.assertEqual(spoofed_record["references"], [IDLE_REF])
        self.assertEqual(spoofed_record["sessionMarkers"], [])
        self.assertEqual(pilot_progress([spoofed_record], events, IDLE_REF),
                         {"status": "invalid", "reason": "wrong_session_or_input"})

        invalid = [
            selector.replace(message_id, "aaaaaaaa-aaaa-3aaa-8aaa-aaaaaaaaaaaa"),
            selector + " extra",
            f"quoted history: {selector}",
            f"Messaging event reference: {IDLE_REF}\nCanonical message ID: {message_id}\nread this message",
        ]
        for text in invalid:
            with self.subTest(text=text):
                bad_record = _request_record(1, response_input(text), held=False)
                self.assertEqual(bad_record["references"], [])
                self.assertEqual(bad_record["latestUserReferences"], [])

        for part_type in ("input_image", None):
            malformed_part = {"text": selector}
            if part_type is not None:
                malformed_part["type"] = part_type
            bad_record = _request_record(1, {"input": [{"role": "user", "content": [malformed_part]}]},
                                         held=False)
            self.assertEqual(bad_record["latestUserReferences"], [])

        history_only = {"input": [
            {"role": "user", "content": [{"type": "input_text", "text": selector}]},
            {"role": "user", "content": [{"type": "input_text", "text": "followup without a reference"}]},
        ]}
        history_record = _request_record(1, history_only, held=False)
        self.assertEqual(history_record["references"], [IDLE_REF])
        self.assertEqual(history_record["latestUserReferences"], [])

        bare_record = _request_record(1, response_input(IDLE_REF), held=False)
        self.assertEqual(bare_record["latestUserReferences"], [IDLE_REF])
        string_record = _request_record(1, {"input": [{"role": "user", "content": IDLE_REF}]}, held=False)
        self.assertEqual(string_record["latestUserReferences"], [IDLE_REF])

    def test_request_record_ignores_text_on_non_input_text_parts(self):
        for part in ({"type": "input_image", "text": IDLE_REF}, {"text": IDLE_REF}):
            with self.subTest(part=part):
                record = _request_record(1, {"input": [{"role": "user", "content": [part]}]}, held=False)
                self.assertEqual(record["references"], [])
                self.assertEqual(record["latestUserReferences"], [])

    def test_held_assistant_marker_requires_output_text(self):
        for part in ({"type": "input_image", "text": HELD_REPLY}, {"text": HELD_REPLY}):
            with self.subTest(part=part):
                record = _request_record(1, {"input": [
                    {"role": "assistant", "content": [part]},
                ]}, held=False)
                self.assertIsNone(record["heldAssistantMarker"])
        record = _request_record(1, {"input": [
            {"role": "assistant", "content": [{"type": "output_text", "text": HELD_REPLY}]},
        ]}, held=False)
        self.assertEqual(record["heldAssistantMarker"], HELD_REPLY)

    def test_unrelated_reference_does_not_satisfy_busy_target(self):
        requests, events = _evidence_inputs()
        requests[2]["latestUserReferences"] = [OTHER_REF]
        result = pilot_evidence(requests, events, IDLE_REF, BUSY_REF)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "reference_or_hold_cardinality")

    def test_history_only_busy_reference_does_not_pass(self):
        requests, events = _evidence_inputs()
        requests[2]["latestUserReferences"] = []
        result = pilot_evidence(requests, events, IDLE_REF, BUSY_REF)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "reference_or_hold_cardinality")

    def test_reference_in_wrong_session_does_not_pass(self):
        requests, events = _evidence_inputs()
        requests[2]["sessionMarkers"] = ["other-session"]
        result = pilot_evidence(requests, events, IDLE_REF, BUSY_REF)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "wrong_session_or_order")

    def test_busy_reference_before_held_response_does_not_pass(self):
        requests, events = _evidence_inputs()
        busy_request = {"event": "request", "number": 3}
        events.remove(busy_request)
        events.insert(events.index({"event": "response_written", "number": 2}), busy_request)
        result = pilot_evidence(requests, events, IDLE_REF, BUSY_REF)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "held_response_missing")

    def test_b_activity_after_baseline_does_not_pass(self):
        requests, events = _evidence_inputs()
        requests.append({"number": 4, "references": [], "latestUserReferences": [],
                         "sessionMarkers": [SESSION_B], "heldPrompt": False,
                         "heldAssistantMarker": None})
        events.extend([{"event": "request", "number": 4}, {"event": "response_written", "number": 4}])
        result = pilot_evidence(requests, events, IDLE_REF, BUSY_REF)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "wrong_session_or_order")

    def test_busy_followup_without_original_response_does_not_pass(self):
        requests, events = _evidence_inputs()
        events.remove({"event": "response_written", "number": 2})
        result = pilot_evidence(requests, events, IDLE_REF, BUSY_REF)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "held_response_missing")


if __name__ == "__main__":
    unittest.main()
