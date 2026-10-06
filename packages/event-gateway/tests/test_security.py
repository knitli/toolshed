from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
import os
import stat

from event_gateway.security import (SecurityError, ensure_private_directory,
    load_or_create_signing_key, public_key_text, sign, verify)


class SecurityTests(unittest.TestCase):
    def test_exact_bytes_audience_and_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'state/key.pem'
            key = load_or_create_signing_key(path)
            self.assertEqual(public_key_text(key), public_key_text(load_or_create_signing_key(path)))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            body = b'{"test":1}'
            signature = sign(body, key, 'runtime:one')
            verify(body, signature, public_key_text(key), 'runtime:one')
            other = load_or_create_signing_key(path.parent / 'other.pem')
            for data, sig, trusted, audience in [
                (body + b' ', signature, key.public_key(), 'runtime:one'),
                (body, signature, key.public_key(), 'runtime:two'),
                (body, signature, other.public_key(), 'runtime:one'),
                (body, signature + '=', key.public_key(), 'runtime:one'),
            ]:
                with self.assertRaisesRegex(SecurityError, '^invalid_signature$'):
                    verify(data, sig, trusted, audience)

    def test_failed_initial_write_leaves_no_published_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'state/key.pem'
            with patch('event_gateway.security.os.fsync', side_effect=OSError('write failed')):
                with self.assertRaises((SecurityError, OSError)):
                    load_or_create_signing_key(path)
            self.assertFalse(path.exists())
            self.assertEqual(list(path.parent.iterdir()), [])
            key = load_or_create_signing_key(path)
            self.assertEqual(public_key_text(key), public_key_text(load_or_create_signing_key(path)))

    def test_concurrent_creation_and_directory_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'key.pem'
            synced = []
            original_fsync = os.fsync

            def record_fsync(fd):
                synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
                original_fsync(fd)

            with patch('event_gateway.security.os.fsync', side_effect=record_fsync):
                with ThreadPoolExecutor(max_workers=4) as executor:
                    keys = list(executor.map(lambda _: public_key_text(load_or_create_signing_key(path)), range(8)))
            self.assertEqual(len(set(keys)), 1)
            self.assertIn(True, synced)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_nested_state_directories_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            leaf = root / 'first/second/state'
            ensure_private_directory(leaf)
            for component in (root / 'first', root / 'first/second', leaf):
                self.assertEqual(stat.S_IMODE(component.stat().st_mode), 0o700)

    def test_unsafe_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / 'state/key.pem'
            load_or_create_signing_key(path)
            path.chmod(0o644)
            with self.assertRaises(SecurityError):
                load_or_create_signing_key(path)
            link = path.parent / 'link.pem'
            link.symlink_to(path)
            with self.assertRaises(SecurityError):
                load_or_create_signing_key(link)
            path.parent.chmod(0o755)
            with self.assertRaises(SecurityError):
                ensure_private_directory(path.parent)
            linked_directory = root / 'linked'
            linked_directory.symlink_to(path.parent)
            with self.assertRaises(SecurityError):
                ensure_private_directory(linked_directory)


if __name__ == '__main__':
    unittest.main()
