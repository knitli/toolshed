"""Keep the foreground smoke responsive to arbitrarily split PTY queries."""

from pathlib import Path
import runpy
import unittest
from unittest.mock import Mock, patch


SOURCE = (
    Path(__file__).resolve().parents[1]
    / "docs/native-bridge/native-release-launcher-smoke.py"
)


class NativeReleaseSmokeTests(unittest.TestCase):
    def test_redraw_stability_covers_commit_latency_and_rejects_binding_changes(self):
        smoke = runpy.run_path(str(SOURCE), run_name="smoke_test")
        check = smoke["check_redraw_stability"]
        binding = {"threadId": "thread", "generation": 1, "serverGeneration": 1}
        status = {"selection": "selected", "threadId": "thread",
                  "automaticWakeEnabled": False, "attached": False}
        for changed in (None, "generation", "serverGeneration", "no-output"):
            with self.subTest(changed=changed):
                clock = [0.0]
                current = dict(binding)
                if changed in ("generation", "serverGeneration"):
                    current[changed] += 1
                challenge = {"witness": {**current, "eligible": True}, "validUntilMonotonic": 100}
                process = Mock()
                process.poll.return_value = None

                def drain(*_):
                    clock[0] += 0.5
                    return 0 if changed == "no-output" else 1

                with (
                    patch.dict(check.__globals__, {
                        "drain": drain,
                        "current_selection": Mock(return_value=(None, status, current, challenge)),
                    }),
                    patch("time.monotonic", side_effect=lambda: clock[0]),
                    patch("fcntl.ioctl") as resize,
                ):
                    if changed:
                        with self.assertRaisesRegex(
                            AssertionError, "insufficient terminal output"
                            if changed == "no-output" else "binding changed",
                        ):
                            check(None, None, process, 7, bytearray(), binding)
                    else:
                        proof = check(None, None, process, 7, bytearray(), binding)
                        self.assertEqual(proof, {"samples": 6, "activeSamples": 6, "elapsedSeconds": 3.0,
                                                 "bindingUnchanged": True})
                        resize.assert_not_called()
                        process.send_signal.assert_not_called()

    def test_non_draw_fences_require_both_generations_and_stable_identity(self):
        smoke = runpy.run_path(str(SOURCE), run_name="smoke_test")
        check = smoke["check_non_draw_fences"]
        binding = {"threadId": "thread", "clientId": "client", "connectionId": "connection",
                   "backendPid": 123, "serverInstanceId": "server",
                   "generation": 1, "serverGeneration": 1}
        status = {"selection": "selected", "threadId": "thread",
                  "automaticWakeEnabled": False, "attached": False}
        for phase in ("resize", "clearing composer"):
            for invalid in (None, "unchanged", "generation", "serverGeneration", "clientId",
                            "connectionId", "backendPid", "serverInstanceId", "threadId"):
                with self.subTest(phase=phase, invalid=invalid):
                    resized = {**binding, "generation": 2, "serverGeneration": 2}
                    cleared = {**binding, "generation": 3, "serverGeneration": 3}
                    previous, current = ((binding, resized) if phase == "resize"
                                         else (resized, cleared))
                    if invalid == "unchanged":
                        current.update(previous)
                    elif invalid in ("generation", "serverGeneration"):
                        current[invalid] = previous[invalid]
                    elif invalid is not None:
                        current[invalid] = 456 if invalid == "backendPid" else "changed"
                    clock = [0.0]
                    process = Mock()
                    process.poll.return_value = None
                    launcher = Mock()
                    launcher.session_status.return_value = {"selection": "unavailable"}

                    def drain(*_):
                        clock[0] += 1

                    def selection(value):
                        return (None, {**status, "threadId": value["threadId"]}, value,
                                {"witness": {**value, "eligible": True}, "validUntilMonotonic": 100})

                    with (
                        patch.dict(check.__globals__, {
                            "drain": drain,
                            "current_selection": Mock(return_value=selection(resized)),
                            "wait_selection": Mock(return_value=selection(cleared)),
                        }),
                        patch("time.monotonic", side_effect=lambda: clock[0]),
                        patch("fcntl.ioctl"),
                        patch("os.write"),
                    ):
                        if invalid is None:
                            result = check(launcher, None, process, 7, bytearray(),
                                           Path("c-session.sock"), binding)
                            self.assertTrue(all(result.values()))
                        else:
                            with self.assertRaisesRegex(AssertionError, phase):
                                check(launcher, None, process, 7, bytearray(),
                                      Path("c-session.sock"), binding)
                        self.assertLessEqual(clock[0], 5)

    def test_cursor_query_split_at_every_boundary_gets_one_response(self):
        drain = runpy.run_path(str(SOURCE), run_name="smoke_test")["drain"]
        responses = [(b"\x1b[6n", b"\x1b[1;1R")]
        for number, color in ((10, b"dddd/dddd/dddd"), (11, b"1111/1111/1111")):
            for ending in (b"\x07", b"\x1b\\"):
                responses.append((f"\x1b]{number};?".encode() + ending,
                                  f"\x1b]{number};rgb:".encode() + color + ending))
        for query, response in responses:
            for split in range(1, len(query)):
                with self.subTest(query=query, split=split):
                    tail = bytearray()
                    with (
                        patch("select.select", return_value=([7], [], [])),
                        patch(
                            "os.read",
                            side_effect=[query[:split], query[split:], b"other output"],
                        ),
                        patch("os.write") as write,
                    ):
                        drain(7, tail)
                        write.assert_not_called()
                        drain(7, tail)
                        drain(7, tail)
                        write.assert_called_once_with(7, response)


if __name__ == "__main__":
    unittest.main()
