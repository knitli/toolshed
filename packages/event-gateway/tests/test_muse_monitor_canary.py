"""Offline fixture mechanics only; never start Muse or claim native wake."""

import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import selectors
import subprocess  # nosec B404 -- Runs only the fixed Python fixture below, never a native client.
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/muse_monitor_canary.py'
SPEC = importlib.util.spec_from_file_location('muse_monitor_canary', SCRIPT)
canary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(canary)


class MuseMonitorCanaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve()
        self.prepared = canary.prepare(self.parent)
        self.directory = Path(self.prepared['directory'])

    def manifest(self):
        return json.loads((self.directory / 'manifest.json').read_text())

    def test_private_unique_preparation_and_quoted_invocation(self):
        other = canary.prepare(self.parent, 'busy')
        self.assertNotEqual(other['directory'], self.prepared['directory'])
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.directory / 'manifest.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(set(self.prepared['monitor']), {'description', 'command', 'wake_delay_ms'})
        self.assertEqual(self.prepared['monitor']['wake_delay_ms'], 0)
        command = shlex.split(self.prepared['monitor']['command'])
        self.assertEqual(command, [str(Path(sys.executable).resolve()), str(SCRIPT.resolve()),
                                   'wait', '--directory', str(self.directory)])
        self.assertNotIn(self.manifest()['marker'], json.dumps(self.prepared))
        with self.assertRaises(canary.CanaryError):
            canary.prepare(self.parent, 'not-a-phase')

    def test_no_output_before_trigger_then_exactly_one_line(self):
        output = io.StringIO()

        def pause(_seconds):
            self.assertEqual(output.getvalue(), '')
            self.assertTrue((self.directory / 'ready.json').exists())
            canary.trigger(self.directory)
        canary.wait(self.directory, clock=lambda: 0, pause=pause, output=output)
        self.assertEqual(output.getvalue().count('\n'), 1)
        self.assertEqual(json.loads(output.getvalue()), {'kind': 'muse-monitor-canary', **self.manifest()})
        with self.assertRaises(FileExistsError):
            canary.wait(self.directory, output=io.StringIO())
        with self.assertRaises(FileExistsError):
            canary.trigger(self.directory)

    def test_trigger_before_ready_refused_without_file(self):
        with self.assertRaises(FileNotFoundError):
            canary.trigger(self.directory)
        self.assertFalse((self.directory / 'trigger.json').exists())

    def test_premature_or_wrong_trigger_never_emits(self):
        for premature in (True, False):
            directory = Path(canary.prepare(self.parent)['directory'])
            output = io.StringIO()

            def write_wrong(_seconds=0):
                fd = canary._directory(directory)
                try:
                    canary._write(fd, 'trigger.json', {'runId': 'wrong'})
                finally:
                    os.close(fd)
            if premature:
                write_wrong()
            with self.assertRaises(canary.CanaryError):
                canary.wait(directory, clock=lambda: 0, pause=write_wrong, output=output)
            self.assertEqual(output.getvalue(), '')

    def test_deadline_no_output_and_no_restart_after_timeout(self):
        now = [0.0]
        output = io.StringIO()

        def pause(seconds):
            self.assertGreater(seconds, 0)
            now[0] += 30
        with self.assertRaisesRegex(canary.CanaryError, 'canary_timeout'):
            canary.wait(self.directory, clock=lambda: now[0], pause=pause, output=output)
        self.assertGreaterEqual(now[0], 90)
        self.assertEqual(output.getvalue(), '')
        with self.assertRaises(FileExistsError):
            canary.wait(self.directory, output=output)

    def test_crash_after_ready_prevents_replay(self):
        def crash(_seconds):
            raise RuntimeError('synthetic stop')
        with self.assertRaisesRegex(RuntimeError, 'synthetic stop'):
            canary.wait(self.directory, pause=crash, output=io.StringIO())
        with self.assertRaises(FileExistsError):
            canary.wait(self.directory, output=io.StringIO())

    def test_crash_before_ready_consumes_run_without_replay(self):
        write = canary._write

        def fail_ready(fd, name, value):
            if name == 'ready.json':
                raise OSError('synthetic readiness failure')
            write(fd, name, value)
        with patch.object(canary, '_write', side_effect=fail_ready):
            with self.assertRaises(OSError):
                canary.wait(self.directory, output=io.StringIO())
        self.assertFalse((self.directory / 'ready.json').exists())
        output = io.StringIO()
        with self.assertRaises(FileExistsError):
            canary.wait(self.directory, clock=lambda: 0,
                        pause=lambda _seconds: canary.trigger(self.directory), output=output)
        self.assertEqual(output.getvalue(), '')

    def test_unsafe_directory_and_manifest_refused(self):
        link = self.parent / 'linked'
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(canary.CanaryError):
            canary.wait(link, output=io.StringIO())
        self.directory.chmod(0o755)
        with self.assertRaises(canary.CanaryError):
            canary.wait(self.directory, output=io.StringIO())
        self.directory.chmod(0o700)
        manifest = self.directory / 'manifest.json'
        manifest.chmod(0o644)
        with self.assertRaises(canary.CanaryError):
            canary.wait(self.directory, output=io.StringIO())
        manifest.unlink()
        manifest.symlink_to(self.parent / 'missing')
        with self.assertRaises(OSError):
            canary.wait(self.directory, output=io.StringIO())

    def test_trigger_symlink_refused_and_external_file_unchanged(self):
        external = self.parent / 'external'
        external.write_text('preserve')
        output = io.StringIO()

        def pause(_seconds):
            (self.directory / 'trigger.json').symlink_to(external)
        with self.assertRaises(OSError):
            canary.wait(self.directory, pause=pause, output=output)
        self.assertEqual(external.read_text(), 'preserve')
        self.assertEqual(output.getvalue(), '')

    def test_preexisting_final_and_symlink_are_never_replaced(self):
        fd = canary._directory(self.directory)
        self.addCleanup(os.close, fd)
        existing = self.directory / 'existing.json'
        existing.write_text('preserve')
        existing.chmod(0o600)
        link = self.directory / 'linked.json'
        link.symlink_to(existing)
        for name in ('existing.json', 'linked.json'):
            with self.assertRaises(FileExistsError):
                canary._write(fd, name, {'value': 'replacement'})
            self.assertTrue((self.directory / ('.' + name + '.reserved')).exists())
        self.assertEqual(existing.read_text(), 'preserve')
        self.assertTrue(link.is_symlink())

    def test_failed_publication_retains_reservation(self):
        fd = canary._directory(self.directory)
        self.addCleanup(os.close, fd)
        with patch.object(canary.os, 'rename', side_effect=OSError('synthetic publication failure')):
            with self.assertRaises(OSError):
                canary._write(fd, 'failure.json', {'value': 1})
        self.assertFalse((self.directory / 'failure.json').exists())
        self.assertTrue((self.directory / '.failure.json.reserved').exists())
        self.assertEqual(list(self.directory.glob('.failure.json.*.tmp')), [])
        with self.assertRaises(FileExistsError):
            canary._write(fd, 'failure.json', {'value': 2})

    def paused_writer(self):
        # Fixed reviewed helper code pauses the actual file write after half its bytes.
        code = r"""
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('fixture', sys.argv[1])
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)
fdopen = canary.os.fdopen
class Partial:
    def __init__(self, stream): self.stream = stream
    def __enter__(self): return self
    def __exit__(self, *args): return self.stream.__exit__(*args)
    def flush(self): self.stream.flush()
    def fileno(self): return self.stream.fileno()
    def write(self, raw):
        middle = len(raw) // 2
        self.stream.write(raw[:middle]); self.stream.flush()
        sys.stderr.write('partial\n'); sys.stderr.flush()
        if sys.stdin.readline() != 'release\n': raise RuntimeError('test release missing')
        self.stream.write(raw[middle:])
canary.os.fdopen = lambda *args, **kwargs: Partial(fdopen(*args, **kwargs))
fd = canary._directory(sys.argv[2])
try: canary._write(fd, 'trigger.json', {'runId': 'test-complete-record'})
finally: os.close(fd)
"""
        # No shell/native client: fixed Python source and explicit private fixture paths.
        process = subprocess.Popen(  # nosec B603 -- Fixed fixture-only child and private arguments.
            [sys.executable, '-c', code, str(SCRIPT), str(self.directory)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False)
        self.addCleanup(self.stop_writer, process)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=3), 'publisher did not reach partial write')
        self.assertEqual(process.stderr.readline(), 'partial\n')
        return process

    @staticmethod
    def stop_writer(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=3)

    def test_actual_partial_writer_is_invisible_to_reader_and_competing_writer(self):
        process = self.paused_writer()
        fd = canary._directory(self.directory)
        self.addCleanup(os.close, fd)
        # Reader runs while the other process is deterministically paused mid-write.
        with self.assertRaises(FileNotFoundError):
            canary._read(fd, 'trigger.json')
        with self.assertRaises(FileExistsError):
            canary._write(fd, 'trigger.json', {'runId': 'competitor'})
        self.assertFalse((self.directory / 'trigger.json').exists())
        output, errors = process.communicate('release\n', timeout=3)
        self.assertEqual((process.returncode, output, errors), (0, '', ''))
        self.assertEqual(canary._read(fd, 'trigger.json'), {'runId': 'test-complete-record'})
        self.assertEqual((self.directory / 'trigger.json').stat().st_nlink, 1)

    def test_actual_crash_mid_publication_retains_reservation_without_final(self):
        process = self.paused_writer()
        process.kill()
        process.communicate(timeout=3)
        self.assertFalse((self.directory / 'trigger.json').exists())
        self.assertTrue((self.directory / '.trigger.json.reserved').exists())
        fd = canary._directory(self.directory)
        self.addCleanup(os.close, fd)
        with self.assertRaises(FileExistsError):
            canary._write(fd, 'trigger.json', {'runId': 'restart'})

    def test_cli_real_stdout_line_without_native_client(self):
        # Fixed interpreter/script argv and private fixture directory; no shell or native client.
        process = subprocess.Popen(  # nosec B603 -- Trusted fixture-only argument list, shell=False.
            [sys.executable, str(SCRIPT), 'wait', '--directory', str(self.directory)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
        try:
            deadline = time.monotonic() + 3
            while not (self.directory / 'ready.json').exists() and process.poll() is None:
                if time.monotonic() >= deadline:
                    self.fail('fixture did not become ready')
                time.sleep(0.01)
            canary.trigger(self.directory)
            output, errors = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(errors, '')
            self.assertEqual(output.count('\n'), 1)
            self.assertEqual(json.loads(output), {'kind': 'muse-monitor-canary', **self.manifest()})
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)


if __name__ == '__main__':
    unittest.main()
