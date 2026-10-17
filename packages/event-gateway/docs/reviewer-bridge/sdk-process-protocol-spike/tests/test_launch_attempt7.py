import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace

MODULE_PATH = Path(__file__).parents[1] / "launch.py"
SPEC = importlib.util.spec_from_file_location("launch_attempt7", MODULE_PATH)
LAUNCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCH)


class FakeClock:
    def __init__(self, value):
        """Store a deterministic monotonic clock value."""
        self.value = value

    def monotonic(self):
        return self.value


class FakeStream:
    def __init__(self, fileno):
        """Expose a stable synthetic file descriptor to selectors."""
        self._fileno = fileno

    def fileno(self):
        return self._fileno


class FakeSelector:
    def __init__(self, clock, events):
        """Yield configured readiness events and advance the fake clock."""
        self.clock = clock
        self.events = list(events)
        self.keys = {}

    def __enter__(self):
        """Return the selector context manager."""
        return self

    def __exit__(self, *_args):
        """Leave selector state unchanged on context exit."""
        return False

    def register(self, fileobj, _events, data):
        self.keys[fileobj] = SimpleNamespace(fileobj=fileobj, data=data)

    def get_map(self):
        return dict(self.keys)

    def unregister(self, fileobj):
        del self.keys[fileobj]

    def select(self, timeout):
        if timeout <= 0:
            raise AssertionError("selector wait must be positive")
        if not self.events:
            raise AssertionError("selector requires a configured readiness event")
        delta, event_names = self.events.pop(0)
        self.clock.value += delta
        return [(self.keys[name], LAUNCH.selectors.EVENT_READ) for name in event_names]


class LauncherDeadlineTests(unittest.TestCase):
    def test_rejects_readiness_observed_after_absolute_deadline(self):
        clock = FakeClock(0.0)
        stdout = FakeStream(1)
        stderr = FakeStream(2)
        selector = FakeSelector(clock, [(20.001, [stdout])])
        reads = []
        process = SimpleNamespace(stdout=stdout, stderr=stderr)

        with self.assertRaisesRegex(RuntimeError, "fixture timeout"):
            LAUNCH.collect_output(
                process,
                deadline=20.0,
                streams={"stdout": bytearray(), "stderr": bytearray()},
                selector_factory=lambda: selector,
                read=lambda fd, limit: reads.append((fd, limit)) or b'{"status":"PASS"}\n',
                monotonic=clock.monotonic,
            )

        self.assertGreaterEqual(clock.value, 20.0)
        self.assertEqual(reads, [], "late readiness must be rejected before consuming output")

    def test_reads_fairly_when_both_streams_finish_before_deadline(self):
        clock = FakeClock(19.0)
        stdout = FakeStream(1)
        stderr = FakeStream(2)
        selector = FakeSelector(clock, [
            (0.1, [stdout]),
            (0.1, [stderr]),
            (0.1, [stdout]),
            (0.1, [stderr]),
        ])
        chunks = {1: [b'{"status":"PASS"}\n', b""], 2: [b"warning\n", b""]}
        process = SimpleNamespace(stdout=stdout, stderr=stderr)
        streams = {"stdout": bytearray(), "stderr": bytearray()}

        total = LAUNCH.collect_output(
            process,
            deadline=20.0,
            streams=streams,
            selector_factory=lambda: selector,
            read=lambda fd, _limit: chunks[fd].pop(0),
            monotonic=clock.monotonic,
        )

        self.assertEqual(bytes(streams["stdout"]), b'{"status":"PASS"}\n')
        self.assertEqual(bytes(streams["stderr"]), b"warning\n")
        self.assertEqual(total, len(streams["stdout"]) + len(streams["stderr"]))
        self.assertLess(clock.value, 20.0)

    def test_overflow_retains_accurate_bounded_capture_count(self):
        clock = FakeClock(0.0)
        stdout = FakeStream(1)
        stderr = FakeStream(2)
        selector = FakeSelector(clock, [(0.1, [stdout])])
        process = SimpleNamespace(stdout=stdout, stderr=stderr)
        streams = {"stdout": bytearray(), "stderr": bytearray()}

        with self.assertRaisesRegex(RuntimeError, "fixture aggregate output limit"):
            LAUNCH.collect_output(
                process,
                deadline=20.0,
                streams=streams,
                selector_factory=lambda: selector,
                read=lambda _fd, _limit: b"x" * (LAUNCH.LIMIT + 1),
                monotonic=clock.monotonic,
            )

        self.assertEqual(len(streams["stdout"]), LAUNCH.LIMIT)
        self.assertEqual(LAUNCH.retained_byte_count(streams), LAUNCH.LIMIT)

    def test_wait_uses_only_remaining_time_and_rejects_late_exit_observation(self):
        clock = FakeClock(19.95)
        process = SimpleNamespace()

        def late_wait(timeout):
            process.timeout = timeout
            clock.value = 20.001
            return 0

        process.wait = late_wait
        with self.assertRaisesRegex(RuntimeError, "fixture timeout"):
            LAUNCH.wait_for_exit(process, deadline=20.0, monotonic=clock.monotonic)

        self.assertGreater(process.timeout, 0)
        self.assertLess(process.timeout, 0.1, "wait may not add the old 100 ms minimum")
        self.assertGreaterEqual(clock.value, 20.0)


if __name__ == "__main__":
    unittest.main()
