"""Exercise the shipped CLI boundary in disposable private state."""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess  # nosec B404 - exercise our CLI with fixed interpreter, no shell
import sys
import tempfile
import time
import unittest


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name).resolve() / "state"
        self.command = [sys.executable, "-m", "event_gateway.cli",
                        "--state-dir", str(self.state)]

    def cli(self, *args, code=0):
        result = subprocess.run(  # nosec B603 - fixed interpreter and synthetic test arguments
            self.command + list(args), capture_output=True,
            text=True, timeout=10)
        self.assertEqual(result.returncode, code, result.stderr)
        return result.stdout

    def assert_disabled(self, value):
        self.assertFalse(value["automaticWakeEnabled"])
        self.assertIn("native_client_binding_unavailable", value["blockers"])
        self.assertIn("cloud_authority_not_integrated", value["blockers"])

    def test_help_status_and_attachment_refusal(self):
        self.assertIn("knitli-event-gateway", self.cli("--help"))
        self.assertFalse(self.state.exists())
        self.assert_disabled(json.loads(self.cli("status")))
        result = json.loads(self.cli("attach", "--runtime-id", "runtime-a",
                                     "--thread-id", "thread-a", code=2))
        self.assertFalse(result["attached"])
        self.assertEqual(result["reason"], "native_client_binding_unavailable")
        self.assert_disabled(json.loads(self.cli("status")))

    def test_enrollment_is_pending_and_key_stays_private(self):
        result = json.loads(self.cli("enroll", "--challenge", "owner-123", code=2))
        self.assertEqual(result["status"], "owner_enrollment_pending")
        self.assertEqual(result["reason"], "cloud_enrollment_not_integrated")
        self.assertEqual(result["challenge"], "owner-123")
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        key = self.state / "node-key.pem"
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        original = key.read_bytes()
        again = json.loads(self.cli("enroll", "--challenge", "owner-456", code=2))
        self.assertEqual(result["publicKey"], again["publicKey"])
        self.assertEqual(original, key.read_bytes())
        self.assertNotIn("PRIVATE", json.dumps(result))

    @unittest.skipUnless(os.name == "posix", "Unix control socket")
    def test_daemon_status_and_clean_signal_stop(self):
        process = subprocess.Popen(  # nosec B603 - fixed interpreter and literal daemon command
            self.command + ["run"], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        try:
            socket = self.state / "control.sock"
            deadline = time.monotonic() + 5
            while not socket.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIsNone(process.poll(), "daemon exited before opening control socket")
            self.assertTrue(socket.exists(), "daemon did not open control socket")
            self.assertEqual(stat.S_IMODE(socket.stat().st_mode), 0o600)
            self.assert_disabled(json.loads(self.cli("status")))
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stdout + stderr)
            self.assertFalse(socket.exists())
            self.assert_disabled(json.loads(self.cli("status")))
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
