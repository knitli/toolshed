r"""
Local v1 authentication seam, not an upstream protocol extension.

X-Event-Key-Id selects a configured trusted public key. X-Event-Audience must
match the configured recipient. X-Event-Signature is unpadded base64url Ed25519
of b'knitli-event-gateway-v1\0' + audience UTF-8 + b'\0' + exact HTTP body.
Verify before parsing, persistence, or deduplication. Public keys use unpadded
base64url raw Ed25519 bytes; private keys never leave their owner-only file.
"""
import base64
import os
import re
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SecurityError(ValueError):
    def __init__(self, code):
        """Initialize an error containing only its safe reason code."""
        self.code = code
        super().__init__(code)


def ensure_private_directory(path):
    path = Path(path).absolute()
    # Reject symlinks in every existing component, including the directory itself.
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            raise SecurityError('unsafe_state_directory')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise SecurityError('unsafe_state_directory')
    return path


def load_or_create_signing_key(path):
    path = Path(path)
    ensure_private_directory(path.parent)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    except OSError:
        raise SecurityError('invalid_signing_key') from None
    else:
        key = Ed25519PrivateKey.generate()
        data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > 4096
            ):
                raise SecurityError('unsafe_signing_key')
            key = serialization.load_pem_private_key(stream.read(4097), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise SecurityError('invalid_signing_key')
            return key
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, SecurityError):
            raise
        raise SecurityError('invalid_signing_key') from None


def _encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def _decode(value, length):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise SecurityError('invalid_signature')
    try:
        data = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except ValueError:
        raise SecurityError('invalid_signature') from None
    if len(data) != length or _encode(data) != value:
        raise SecurityError('invalid_signature')
    return data


def public_key_text(key):
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    return _encode(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _message(body, audience):
    if not isinstance(body, bytes) or not isinstance(audience, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@-]{0,253}', audience):
        raise SecurityError('invalid_audience')
    return b'knitli-event-gateway-v1\0' + audience.encode('ascii') + b'\0' + body


def sign(body, key, audience):
    return _encode(key.sign(_message(body, audience)))


def verify(body, signature, public_key, audience):
    try:
        if isinstance(public_key, str):
            public_key = Ed25519PublicKey.from_public_bytes(_decode(public_key, 32))
        public_key.verify(_decode(signature, 64), _message(body, audience))
    except (InvalidSignature, ValueError, TypeError, AttributeError):
        raise SecurityError('invalid_signature') from None
