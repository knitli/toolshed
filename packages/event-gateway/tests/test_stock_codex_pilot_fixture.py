"""Pure evidence-gate tests for the local stock Codex pilot fixture."""

from pathlib import Path
import errno
from contextlib import redirect_stdout
import io
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from prepare_stock_codex_pilot import (  # noqa: E402
    HELD_REPLY,
    HELD_PROMPT,
    MAX_CONTROL_BYTES,
    PilotFixture,
    SESSION_A,
    SESSION_B,
    _owned_daemon_socket,
    _stop_owned_updater,
    _request_record,
    _pop_control_line,
    pilot_evidence,
)
from probe_stock_codex_queue import _cli  # noqa: E402

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

    def test_historic_refs_and_held_prompt_do_not_reclassify_followup(self):
        payload = {"input": [
            {"role": "user", "content": [{"text": SESSION_A}, {"text": IDLE_REF}, {"text": HELD_PROMPT}]},
            {"role": "assistant", "content": [{"text": HELD_REPLY}]},
            {"role": "user", "content": [{"text": BUSY_REF}]},
        ]}
        record = _request_record(3, payload, held=False)
        self.assertEqual(record["references"], [IDLE_REF, BUSY_REF])
        self.assertEqual(record["latestUserReferences"], [BUSY_REF])
        self.assertFalse(record["heldPrompt"])
        self.assertTrue(record["containsHeldPrompt"])

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
