from pathlib import Path
import tempfile
import unittest

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
            for data, sig, trusted, audience in [(body + b' ', signature, key.public_key(), 'runtime:one'),
                (body, signature, key.public_key(), 'runtime:two'),
                (body, signature, other.public_key(), 'runtime:one'),
                (body, signature + '=', key.public_key(), 'runtime:one')]:
                with self.assertRaisesRegex(SecurityError, '^invalid_signature$'):
                    verify(data, sig, trusted, audience)

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
