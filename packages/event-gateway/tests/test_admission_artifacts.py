"""Check admission proof's binary trust boundary without booting a native client."""

import hashlib
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from event_gateway import launcher


SOURCE = Path(__file__).resolve().parents[1] / 'docs/native-bridge/admission-workerd.py'


class AdmissionArtifactTests(unittest.TestCase):
    def test_preboot_rechecks_hash_and_metadata_of_the_opened_binary(self):
        admission = runpy.run_path(str(SOURCE), run_name='qualification_test')
        qualify = admission['qualify_native']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary = root / 'candidate'
            binary.write_bytes(b'qualified bytes')
            binary.chmod(0o700)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            args = SimpleNamespace(binary=binary, binary_sha=digest)
            gateway = SimpleNamespace(launcher=launcher)
            native = SimpleNamespace(qualify=Mock(return_value='qualified'))
            with patch.object(launcher, 'QUALIFIED_SHA256', digest):
                self.assertEqual(qualify(args, gateway, native), 'qualified')
                native.qualify.assert_called_once_with(binary, input_recorded=True, receipt_version=3)
                native.qualify.reset_mock()
                binary.write_bytes(b'changed between input validation and boot')
                with self.assertRaisesRegex(launcher.LaunchError, 'native_binary_hash_mismatch'):
                    qualify(args, gateway, native)
                with self.assertRaisesRegex(launcher.LaunchError, 'native_binary_hash_mismatch'):
                    admission['AdmissionRun'].proof(SimpleNamespace(args=args, gateway=gateway))
                binary.write_bytes(b'qualified bytes')
                substituted = root / 'substituted'
                substituted.write_bytes(b'qualified bytes')
                substituted.chmod(0o722)
                with substituted.open('rb') as opened, patch.object(Path, 'open', return_value=opened):
                    with self.assertRaisesRegex(launcher.LaunchError, 'unsafe_native_binary'):
                        qualify(args, gateway, native)
                native.qualify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
