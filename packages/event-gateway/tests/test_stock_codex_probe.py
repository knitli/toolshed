import threading
import unittest
import os
import pty
import json
import tempfile
import sys
import io
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
import subprocess  # nosec B404 -- Only mocked process errors and TimeoutExpired fixtures.
from unittest.mock import Mock
from unittest.mock import patch

from scripts import probe_stock_codex_queue as probe
from scripts.probe_stock_codex_busy import (
    HELD_PROMPT,
    HELD_REPLY,
    QUEUE_REFERENCE,
    _busy_gate_passed,
    _client_view,
    _classify_held_window,
    _classify_request_purpose,
    _ordered_excerpt,
    _reap_tui,
    _request_structure,
    _valid_followup,
)


class StockCodexProbeTests(unittest.TestCase):
    def test_request_context_rejects_other_or_mixed_session_history(self):
        reference = "ref_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        session_a = "Seed synthetic session A."
        session_b = "Seed synthetic session B."
        payload = {
            "input": [{"role": "user", "content": [
                {"type": "input_text", "text": session_b},
                {"type": "input_text", "text": reference},
            ]}],
        }

        request = {"synthetic_user_text": probe._message_texts(payload)}

        self.assertFalse(probe._targets_session(request, reference, session_a, session_b))
        request["synthetic_user_text"].append(session_a)
        self.assertFalse(probe._targets_session(request, reference, session_a, session_b))
        request["synthetic_user_text"].remove(session_b)
        self.assertTrue(probe._targets_session(request, reference, session_a, session_b))

    def test_tui_startup_replay_is_included_in_preopen_request_window(self):
        session_b = "Seed synthetic session B."
        provider = SimpleNamespace(requests=[
            {"number": 1, "synthetic_user_text": ["Seed synthetic session A."]},
            {"number": 2, "synthetic_user_text": [session_b]},
        ], lock=threading.Lock())

        def open_tui_with_startup_replay(*_args):
            with provider.lock:
                provider.requests.append({"number": 3, "synthetic_user_text": [session_b]})
            return object(), object()

        with patch.object(probe, "_tui", side_effect=open_tui_with_startup_replay):
            _process, _master, baseline = probe._open_tui_with_baseline(
                provider, "codex", "/private", "thread-b")

        after_open = probe._provider_requests_since(provider, baseline)
        self.assertEqual(baseline, 2)
        self.assertTrue(any(probe._has_session_marker(row, session_b) for row in after_open))

    def test_busy_followup_requires_original_assistant_response_in_history(self):
        reference = "ref_55555555-5555-4555-8555-555555555555"
        held_reply = "synthetic held response e1 marker"
        request = {"synthetic_user_text": ["Seed synthetic session A.", reference]}

        self.assertFalse(_valid_followup(request, reference, held_reply))
        request["heldAssistantMarker"] = held_reply
        self.assertTrue(_valid_followup(request, reference, held_reply))
        request["synthetic_user_text"].append("Seed synthetic session B.")
        self.assertFalse(_valid_followup(request, reference, held_reply))

    def test_ordered_busy_excerpt_accepts_text_and_bytes(self):
        excerpt = f"{HELD_PROMPT} {HELD_REPLY} {QUEUE_REFERENCE} synthetic response"

        text_result = _ordered_excerpt(excerpt)
        bytes_result = _ordered_excerpt(excerpt.encode())

        self.assertTrue(text_result["passed"])
        self.assertEqual(text_result, bytes_result)

    def test_request_structure_records_protocol_shape_without_payload_text(self):
        payload = {
            "model": "synthetic",
            "stream": True,
            "previous_response_id": "resp_private_identifier",
            "instructions": "must never appear in the report",
            "input": [{"type": "message", "role": "assistant", "content": [
                {"type": "output_text", "text": "private prompt text"},
            ]}],
        }

        structure = _request_structure(payload)

        self.assertEqual(structure["model"], "synthetic")
        self.assertTrue(structure["stream"])
        self.assertTrue(structure["previousResponseIdPresent"])
        self.assertEqual(len(structure["previousResponseIdSha256"]), 16)
        self.assertEqual(structure["inputItems"], [{
            "type": "message", "role": "assistant", "contentTypes": ["output_text"],
        }])
        self.assertNotIn("private prompt text", str(structure))
        self.assertNotIn("must never appear in the report", str(structure))

    def test_tui_cleanup_kills_and_reaps_popen_with_a_bounded_wait(self):
        process = SimpleNamespace(pid=42, returncode=None, poll=Mock(return_value=None),
                                  kill=Mock(), wait=Mock(return_value=-9))

        result = _reap_tui(process, timeout=3)

        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=3)
        self.assertTrue(result["killedAndReaped"])

    def test_tui_cleanup_reports_unreaped_popen_timeout_as_failure(self):
        process = SimpleNamespace(pid=43, returncode=None, poll=Mock(return_value=None),
                                  kill=Mock(),
                                  wait=Mock(side_effect=subprocess.TimeoutExpired("codex", 3)))

        result = _reap_tui(process, timeout=3)

        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=3)
        self.assertFalse(result["killedAndReaped"])
        self.assertEqual(result["waitTimeoutSeconds"], 3)

    def test_marker_free_request_is_reported_unknown_not_as_interruption(self):
        requests = [
            {"number": 3, "synthetic_user_text": [HELD_PROMPT],
             "structure": {"previousResponseIdPresent": False}},
            {"number": 4, "synthetic_user_text": [],
             "structure": {"previousResponseIdPresent": False}},
            {"number": 5, "synthetic_user_text": [QUEUE_REFERENCE],
             "structure": {"previousResponseIdPresent": False}},
        ]

        classification = _classify_held_window(requests, 3, QUEUE_REFERENCE)

        self.assertEqual(classification["unknownRequestNumbers"], [4])
        self.assertEqual(classification["classifiedFollowupNumbers"], [5])
        self.assertFalse(classification["noClassifiedFollowupBeforeRelease"])

    def test_client_view_checks_response_and_queued_reference_display_order(self):
        response_first = f"{HELD_PROMPT} Working {HELD_REPLY} {QUEUE_REFERENCE}"
        reference_first = f"{HELD_PROMPT} Working {QUEUE_REFERENCE} {HELD_REPLY}"

        self.assertTrue(_client_view(response_first)["heldResponseBeforeQueuedReference"])
        self.assertFalse(_client_view(reference_first)["heldResponseBeforeQueuedReference"])

    def test_title_generation_classification_requires_the_busy_marker_and_title_instruction(self):
        title_request = {"input": [{"role": "user", "content": [
            {"type": "input_text", "text": f"{HELD_PROMPT}; generate a title"},
        ]}]}
        unknown_request = {"input": [{"role": "user", "content": [
            {"type": "input_text", "text": HELD_PROMPT},
        ]}]}

        self.assertEqual(_classify_request_purpose(title_request, QUEUE_REFERENCE),
                         "background_title_generation")
        self.assertEqual(_classify_request_purpose(unknown_request, QUEUE_REFERENCE),
                         "unclassified_user_request")

    def test_upgrade_request_requires_prior_version_seed_and_queue_reference(self):
        reference = "ref_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        request = {"synthetic_user_text": [
            "Seed synthetic prior-version session.", reference,
        ]}

        self.assertTrue(probe._upgrade_request_matches(request, reference))
        self.assertFalse(probe._upgrade_request_matches(
            {"synthetic_user_text": [reference]}, reference))
        self.assertFalse(probe._upgrade_request_matches(
            {"synthetic_user_text": ["Seed synthetic unrelated session.", reference]}, reference))
        self.assertFalse(probe._upgrade_request_matches(
            {"synthetic_user_text": ["Seed synthetic prior-version session."]}, reference))

    def test_tui_startup_failure_closes_both_pty_descriptors(self):
        master, slave = pty.openpty()
        try:
            with patch.object(probe.pty, "openpty", return_value=(master, slave)), \
                    patch("fcntl.ioctl", side_effect=OSError("injected ioctl failure")):
                with self.assertRaises(OSError):
                    probe._tui("codex", "/private", "thread-id")
        finally:
            leaked = []
            for fd in (master, slave):
                try:
                    os.fstat(fd)
                except OSError:
                    continue
                leaked.append(fd)
                os.close(fd)
            self.assertEqual(leaked, [], "startup failure leaked a PTY descriptor")

    def test_tui_cleanup_records_kill_and_reap_errors_but_closes_pty(self):
        master, slave = pty.openpty()
        os.close(slave)
        process = SimpleNamespace(pid=51, poll=Mock(return_value=None), kill=Mock(
            side_effect=OSError("injected kill failure")), wait=Mock(
                side_effect=subprocess.TimeoutExpired("codex", 3)))
        failures = []
        try:
            probe._cleanup_tui(process, master, failures)
            self.assertEqual([failure["step"] for failure in failures], ["kill", "reap"])
            process.wait.assert_called_once_with(timeout=3)
            process.kill.assert_called_once_with()
            with self.assertRaises(OSError):
                os.fstat(master)
        finally:
            try:
                os.close(master)
            except OSError:
                pass

    def test_graceful_tui_stop_closes_pty_even_when_signal_and_reap_fail(self):
        master, slave = pty.openpty()
        os.close(slave)
        process = SimpleNamespace(pid=52, returncode=None, poll=Mock(return_value=None),
                                  send_signal=Mock(side_effect=OSError("injected signal failure")),
                                  kill=Mock(side_effect=OSError("injected kill failure")),
                                  wait=Mock(side_effect=[subprocess.TimeoutExpired("codex", 8),
                                                         subprocess.TimeoutExpired("codex", 3)]))
        failures = []
        try:
            probe._stop_tui(process, master, failures)
            self.assertEqual([failure["step"] for failure in failures], [
                "interrupt", "kill", "reap_after_kill",
            ])
            with self.assertRaises(OSError):
                os.fstat(master)
        finally:
            try:
                os.close(master)
            except OSError:
                pass

    def test_final_tui_cleanup_does_not_close_reused_master_descriptor(self):
        master, slave = pty.openpty()
        owner = [master]
        process = SimpleNamespace(pid=53, returncode=0, poll=Mock(return_value=0),
                                  wait=Mock(return_value=0))
        failures = []
        reused = None
        extras = []
        try:
            probe._stop_tui(process, owner, failures)
            self.assertIsNone(owner[0])
            for _ in range(16):
                descriptor = os.open(os.devnull, os.O_RDONLY)
                if descriptor == master:
                    reused = descriptor
                    break
                extras.append(descriptor)
            self.assertEqual(reused, master, "test did not reuse the closed PTY descriptor")

            probe._cleanup_tui(process, owner, failures)

            os.fstat(reused)
            self.assertEqual(failures, [])
        finally:
            for descriptor in extras + ([reused] if reused is not None else []) + [slave]:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_daemon_timeout_and_provider_shutdown_failure_do_not_skip_later_cleanup(self):
        failures = []
        probe_server = SimpleNamespace(shutdown=Mock(side_effect=TimeoutError("injected timeout")),
                                       server_close=Mock())
        with patch.object(probe, "_cli", side_effect=subprocess.TimeoutExpired("codex", 25)):
            outcome = probe._stop_daemon("codex", "/private", "previous", failures)
        probe._close_provider(probe_server, failures)

        self.assertEqual(outcome, {"errorType": "TimeoutExpired"})
        self.assertEqual(probe_server.shutdown.call_count, 1)
        self.assertEqual(probe_server.server_close.call_count, 1)
        self.assertEqual([(failure["resource"], failure["step"])
                          for failure in failures], [
            ("daemon:previous", "stop"), ("provider", "shutdown"),
        ])

    def test_main_writes_cleanup_failure_report_then_exits_nonzero(self):
        report = {"result": "bounded_synthetic_nonbusy_checks_failed", "cleanupOk": False,
                  "cleanupFailures": [{"resource": "daemon:qualification", "step": "stop",
                                       "errorType": "TimeoutExpired"}]}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "cleanup.json"
            stdout = io.StringIO()
            with patch.object(sys, "argv", ["probe_stock_codex_queue.py", "--binary", "codex",
                                             "--output", str(output)]), \
                    patch.object(probe, "qualify", return_value=report), \
                    redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as raised:
                    probe.main()

            self.assertEqual(raised.exception.code, 1)
            self.assertEqual(json.loads(output.read_text()), report)
            self.assertIn('"cleanupOk": false', stdout.getvalue())

    def test_busy_gate_requires_held_response_then_exact_followup_but_not_visible_ref(self):
        result = {
            "queueExit": 0,
            "queueTargetsExactThreadA": True,
            "queueAcceptedWhileHeld": True,
            "noClassifiedFollowupBeforeRelease": True,
            "heldWindowClassification": {
                "backgroundTitleGenerationNumbers": [4], "unknownRequestNumbers": [],
            },
            "noProviderWriteErrorBeforeRelease": True,
            "heldResponseWrittenBeforeFollowupRequest": True,
            "followupIncludesHeldAssistantResponse": True,
            "clientStateBeforeFollowupCompletion": {
                "workingVisible": True, "heldAssistantResponseVisible": True,
                "explicitCancellationSignalVisible": False, "queuedReferenceVisible": False,
            },
            "BStayedIdle": True,
            "BStillOpenWhileHeld": True,
            "TuiAStillRunningWhileHeld": True,
            "TuiAStillRunningAfterFollowup": True,
            "followupResponseWritten": True,
        }

        self.assertTrue(_busy_gate_passed(result))
        result["heldWindowClassification"]["unknownRequestNumbers"] = [4]
        self.assertFalse(_busy_gate_passed(result))
        result["heldWindowClassification"]["unknownRequestNumbers"] = []
        result["heldResponseWrittenBeforeFollowupRequest"] = False
        self.assertFalse(_busy_gate_passed(result))


if __name__ == "__main__":
    unittest.main()
