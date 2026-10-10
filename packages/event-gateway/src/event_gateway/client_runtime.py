"""Private configuration and bounded stdlib HTTPS composition for explicit CLI calls."""

import asyncio
import base64
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import urlsplit

from .cloud import (
    CloudClient, CloudError, Credentials, _uuid, _native_challenge_request,
    _runtime_status_response,
)
from .protocol import ProtocolError, _depth, _pairs, _timestamp
from .security import SecurityError, ensure_private_directory, load_signing_key

_PENDING_FIELDS = frozenset((
    "version", "operation", "sessionId", "cloudIdentity", "intent", "challenge",
    "evidence", "bodyB64", "safeExpiryAt",
))
_PENDING_OPERATIONS = frozenset(("attach", "renew", "transfer"))
_PENDING_MAX_BYTES = 16_384


def _reject_constant(_):
    raise ValueError("invalid_json")


def _private_json(path, limit, code, *, include_sha256=False):
    path = Path(path).absolute()
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise SecurityError(code)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > limit):
                raise SecurityError(code)
            raw = stream.read(limit + 1)
    except SecurityError:
        raise
    except OSError:
        raise SecurityError(code) from None
    if len(raw) > limit:
        raise SecurityError(code)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_reject_constant)
        _depth(value)
    except (UnicodeError, ValueError, RecursionError):
        raise SecurityError(code) from None
    if include_sha256:
        return value, path, hashlib.sha256(raw).hexdigest()
    return value, path


def load_cloud_config(path):
    """Load identity and a relative credentials filename from a private mode-600 file."""
    config, path = _private_json(path, 4096, "invalid_cloud_config")
    if (not isinstance(config, dict)
            or set(config) != {"version", "origin", "principal", "agent", "nodeId",
                               "nodeGeneration", "credentialsFile"}
            or not isinstance(config["version"], int) or isinstance(config["version"], bool)
            or config["version"] != 1
            or not isinstance(config["credentialsFile"], str)
            or config["credentialsFile"] in ("", ".", "..")
            or Path(config["credentialsFile"]).name != config["credentialsFile"]
            or "\\" in config["credentialsFile"]):
        raise SecurityError("invalid_cloud_config")
    return config, path.parent / config["credentialsFile"]


async def _https_send(method, url, headers, body, timeout, max_response_bytes, follow_redirects):
    """Make one verified HTTPS request in a killable, wall-clock-bounded curl process."""
    if (method != "POST" or follow_redirects is not False
            or not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
            or not math.isfinite(timeout) or not 0 < timeout <= 5
            or not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool)
            or max_response_bytes != 8192
            or not isinstance(body, bytes) or not isinstance(headers, dict)):
        raise ValueError("invalid_transport_request")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment
            or parsed.path == "" or parsed.username or parsed.password):
        raise ValueError("invalid_transport_url")
    if len(body) > 4096 or any(not isinstance(key, str) or not isinstance(value, str)
                               for key, value in headers.items()):
        raise ValueError("invalid_transport_request")
    executable = Path("/usr/bin/curl")
    if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise OSError("https_transport_unavailable")

    def quote(value):
        if not isinstance(value, str) or any(ord(char) < 32 and char not in "\t" for char in value):
            raise ValueError("invalid_transport_request")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n") + '"'

    config = [
        f"url = {quote(url)}", f"request = {quote(method)}",
        f"max-time = {quote(str(timeout))}", f"connect-timeout = {quote(str(timeout))}",
        f"noproxy = {quote('*')}", f"proto = {quote('=https')}",
        f"data-binary = {quote(body.decode('utf-8'))}",
    ]
    config.extend(f"header = {quote(f'{key}: {value}')}" for key, value in headers.items())
    command = [
        str(executable), "-q", "--silent", "--show-error", "--max-redirs", "0",
        "--dump-header", "-", "--output", "-", "--config", "-",
    ]
    environment = {key: value for key, value in os.environ.items()
                   if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "curl_home",
                                          "curl_ca_bundle", "ssl_cert_file", "ssl_cert_dir"}}
    deadline = asyncio.get_running_loop().time() + timeout
    process = None
    config_bytes = ("\n".join(config) + "\n").encode("utf-8")
    try:
        process = await asyncio.create_subprocess_exec(  # nosec B603 - fixed curl args, no shell, secrets only in stdin config
            *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=environment,
        )
        process.stdin.write(config_bytes)
        await asyncio.wait_for(process.stdin.drain(), max(0, deadline - asyncio.get_running_loop().time()))
        process.stdin.close()
        await asyncio.wait_for(process.stdin.wait_closed(), max(0, deadline - asyncio.get_running_loop().time()))
        output = await _collect_curl_response(process, deadline, max_response_bytes)
        if await asyncio.wait_for(process.wait(), max(0, deadline - asyncio.get_running_loop().time())) != 0:
            raise OSError("https_transport_failed")
        return _parse_curl_response(bytes(output), max_response_bytes)
    except TimeoutError:
        raise TimeoutError("https_transport_timeout") from None
    finally:
        await _reap_curl(process)


async def _reap_curl(process):
    if process is not None:
        if process.returncode is None:
            process.kill()
        await process.wait()


async def _collect_curl_response(process, deadline, max_response_bytes):
    output = bytearray()
    header_end = -1
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("https_transport_timeout")
        chunk = await asyncio.wait_for(process.stdout.read(4096), remaining)
        if not chunk:
            break
        output.extend(chunk)
        if header_end < 0:
            header_end = output.find(b"\r\n\r\n")
            if header_end < 0 and len(output) > max_response_bytes:
                raise ValueError("https_response_too_large")
        if header_end >= 0 and len(output) - header_end - 4 > max_response_bytes:
            raise ValueError("https_response_too_large")
        if len(output) > max_response_bytes * 2 + 4:
            raise ValueError("https_response_too_large")
    return output


def _parse_curl_response(output, max_response_bytes):
    """Parse bounded raw response headers followed by the decoded body."""
    cursor = 0
    while True:
        end = output.find(b"\r\n\r\n", cursor)
        if end < 0 or end - cursor > max_response_bytes:
            raise ValueError("invalid_https_response")
        try:
            lines = output[cursor:end].decode("iso-8859-1").split("\r\n")
            status_match = re.fullmatch(r"HTTP/[0-9]+(?:\.[0-9]+)?[ \t]+([0-9]{3})(?:[ \t]+[^\r\n]*)?", lines[0])
            if not status_match:
                raise ValueError
            status = int(status_match.group(1))
            headers = {}
            for line in lines[1:]:
                key, separator, value = line.partition(":")
                name = key.strip().lower()
                if not separator or not name or name in headers:
                    raise ValueError
                headers[name] = value.strip()
        except (UnicodeError, ValueError):
            raise ValueError("invalid_https_response") from None
        cursor = end + 4
        if 100 <= status < 200 and status != 101:
            continue
        body = output[cursor:]
        if len(body) > max_response_bytes:
            raise ValueError("https_response_too_large")
        return status, headers, body


def cloud_identity(cloud):
    """Return the public, immutable CloudClient identity tuple for pending replay."""
    return {
        "origin": cloud.origin, "principal": cloud.principal, "agent": cloud.agent,
        "nodeId": cloud.node_id, "nodeGeneration": cloud.node_generation,
    }


def _pending_slot(state_dir, operation, session_id, *, create=False):
    if operation not in _PENDING_OPERATIONS or not _uuid(session_id):
        raise SecurityError("invalid_pending_commit")
    directory = Path(state_dir).absolute() / ".native-pending"
    if create:
        directory = ensure_private_directory(directory)
    else:
        if any(component.is_symlink() for component in (directory, *directory.parents)):
            raise SecurityError("invalid_pending_commit")
        if not os.path.lexists(directory):
            name = hashlib.sha256((operation + "\0" + session_id).encode("ascii")).hexdigest() + ".json"
            return None, directory / name
        directory = ensure_private_directory(directory)
    name = hashlib.sha256((operation + "\0" + session_id).encode("ascii")).hexdigest() + ".json"
    return directory, directory / name


def _pending_lock(directory):
    lock_path = directory / ".lock"
    fd = None
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise SecurityError("invalid_pending_commit")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except (OSError, SecurityError) as error:
        if fd is not None:
            os.close(fd)
        if isinstance(error, BlockingIOError):
            raise SecurityError("pending_commit_busy") from None
        raise SecurityError("invalid_pending_commit") from None


def _validate_pending_artifact(value, operation, session_id):
    if (not isinstance(value, dict) or set(value) != _PENDING_FIELDS
            or not isinstance(value["version"], int) or isinstance(value["version"], bool)
            or value["version"] != 1
            or value["operation"] != operation or value["sessionId"] != session_id
            or not isinstance(value["cloudIdentity"], dict)
            or set(value["cloudIdentity"]) != {"origin", "principal", "agent", "nodeId", "nodeGeneration"}
            or not isinstance(value["intent"], dict) or not isinstance(value["challenge"], dict)
            or not isinstance(value["evidence"], dict) or not isinstance(value["bodyB64"], str)):
        raise SecurityError("invalid_pending_commit")
    try:
        encoded = value["bodyB64"].encode("ascii")
        body = base64.b64decode(encoded, validate=True)
        if base64.b64encode(body) != encoded or not 1 <= len(body) <= 4096:
            raise ValueError
        _timestamp(value["safeExpiryAt"])
    except (UnicodeError, ValueError, TypeError, ProtocolError):
        raise SecurityError("invalid_pending_commit") from None
    return body


def load_pending_commit_snapshot(state_dir, operation, session_id):
    """Read validated pending data and the hash of the exact same private file bytes."""
    directory, path = _pending_slot(state_dir, operation, session_id)
    if directory is None or not os.path.lexists(path):
        return None, None
    value, _, digest = _private_json(
        path, _PENDING_MAX_BYTES, "invalid_pending_commit", include_sha256=True,
    )
    _validate_pending_artifact(value, operation, session_id)
    return value, digest


def load_pending_commit(state_dir, operation, session_id):
    """Read one closed pending commit artifact without following filesystem links."""
    return load_pending_commit_snapshot(state_dir, operation, session_id)[0]


def save_pending_commit(state_dir, operation, session_id, artifact):
    """Create a secret-free mode-600 replay artifact atomically and without replacement."""
    directory, path = _pending_slot(state_dir, operation, session_id, create=True)
    _validate_pending_artifact(artifact, operation, session_id)
    return _save_private_record(directory, path, artifact, "pending_commit_exists")


def _save_private_record(directory, path, value, exists_code, *, successor_session_id=None):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(raw) > _PENDING_MAX_BYTES:
        raise SecurityError("invalid_pending_commit")
    lock_fd = _pending_lock(directory)
    temporary = None
    try:
        if os.path.lexists(path):
            raise SecurityError(exists_code)
        if successor_session_id is not None:
            if any(os.path.lexists(_pending_slot(directory.parent, operation, successor_session_id)[1])
                   for operation in _PENDING_OPERATIONS):
                raise SecurityError("reconciliation_successor_not_fresh")
            for existing_path in directory.glob("*.reconcile.json"):
                existing, _ = _private_json(existing_path, _PENDING_MAX_BYTES, "invalid_reconciliation")
                if not isinstance(existing, dict):
                    raise SecurityError("invalid_reconciliation")
                _validate_reconciliation(existing, existing.get("originalOperation"),
                                         existing.get("originalSessionId"))
                if existing["successorSessionId"] == successor_session_id:
                    raise SecurityError("reconciliation_successor_reserved")
        fd, temporary = tempfile.mkstemp(prefix=".commit-", dir=directory)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return path
    except OSError:
        raise SecurityError("pending_commit_unavailable") from None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
        os.close(lock_fd)


def _validate_reconciliation(value, operation, session_id):
    fields = {"version", "originalArtifactSha256", "originalOperation", "originalSessionId",
              "cloudIdentity", "runtimeId", "successorSessionId", "nodePublicKey", "observed", "intent"}
    if (not isinstance(value, dict) or set(value) != fields
            or type(value["version"]) is not int or value["version"] != 1
            or operation not in ("attach", "renew") or value["originalOperation"] != operation
            or not _uuid(value["originalSessionId"]) or value["originalSessionId"] != session_id
            or not _uuid(value["successorSessionId"]) or value["successorSessionId"] == session_id
            or not isinstance(value["originalArtifactSha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["originalArtifactSha256"])
            or not isinstance(value["nodePublicKey"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value["nodePublicKey"])
            or not isinstance(value["cloudIdentity"], dict)
            or set(value["cloudIdentity"]) != {"origin", "principal", "agent", "nodeId", "nodeGeneration"}):
        raise SecurityError("invalid_reconciliation")
    try:
        observed = _runtime_status_response(value["observed"], value["runtimeId"])
        intent = _native_challenge_request(value["intent"])
        expected = (observed["runtimeGeneration"], observed["attachmentGeneration"]) if observed["status"] == "present" else (None, None)
        if (intent["operation"] != "attach" or intent["runtimeId"] != value["runtimeId"]
                or (intent["expectedRuntimeGeneration"], intent["expectedAttachmentGeneration"]) != expected):
            raise CloudError("invalid_request")
    except (CloudError, KeyError, TypeError):
        raise SecurityError("invalid_reconciliation") from None


def load_reconciliation(state_dir, operation, original_session_id):
    directory, pending_path = _pending_slot(state_dir, operation, original_session_id)
    path = pending_path.with_suffix(".reconcile.json")
    if directory is None or not os.path.lexists(path):
        return None
    value, _ = _private_json(path, _PENDING_MAX_BYTES, "invalid_reconciliation")
    _validate_reconciliation(value, operation, original_session_id)
    return value


def save_reconciliation(state_dir, operation, original_session_id, link):
    """Durably pin one successor intent before it can send any lifecycle request."""
    directory, path = _pending_slot(state_dir, operation, original_session_id, create=True)
    _validate_reconciliation(link, operation, original_session_id)
    return _save_private_record(directory, path.with_suffix(".reconcile.json"), link,
                                "reconciliation_link_exists",
                                successor_session_id=link["successorSessionId"])


def clear_pending_commit(state_dir, operation, session_id, expected=None):
    """Remove only the exact pending artifact after local mapping persistence succeeds."""
    directory, path = _pending_slot(state_dir, operation, session_id)
    if directory is None:
        return
    lock_fd = _pending_lock(directory)
    try:
        if not os.path.lexists(path):
            return
        current, _ = _private_json(path, _PENDING_MAX_BYTES, "invalid_pending_commit")
        _validate_pending_artifact(current, operation, session_id)
        if expected is not None and current != expected:
            raise SecurityError("pending_commit_changed")
        path.unlink()
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        raise SecurityError("pending_commit_unavailable") from None
    finally:
        os.close(lock_fd)


def pending_commit_summary(artifact):
    """Expose only safe retry metadata; never return the persisted request body or evidence."""
    return {
        "status": "outcome_unknown", "operation": artifact["operation"],
        "challengeId": artifact["challenge"].get("challengeId"),
        "safeExpiryAt": artifact["safeExpiryAt"],
    }


async def _send_https(**request):
    return await _https_send(**request)


def load_cloud_client(config_path, state_dir):
    """Bind a CloudClient to immutable identity, the existing node key, and fresh file tokens."""
    config, credentials_path = load_cloud_config(config_path)
    key = load_signing_key(Path(state_dir) / "node-key.pem")

    async def credentials():
        value, _ = _private_json(credentials_path, 8192, "invalid_credentials")
        if (not isinstance(value, dict) or set(value) != {"accessToken", "agentToken"}
                or not isinstance(value["accessToken"], str)
                or not isinstance(value["agentToken"], str)):
            raise SecurityError("invalid_credentials")
        return Credentials(value["accessToken"], value["agentToken"])

    try:
        return CloudClient(
            origin=config["origin"], principal=config["principal"], agent=config["agent"],
            node_id=config["nodeId"], node_generation=config["nodeGeneration"],
            private_key=key, credentials=credentials, send=_send_https,
        )
    except CloudError:
        raise
    except (KeyError, TypeError, ValueError):
        raise CloudError("invalid_configuration") from None
