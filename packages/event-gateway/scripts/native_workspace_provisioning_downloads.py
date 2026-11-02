#!/usr/bin/env python3
"""Download hash-pinned public provisioning data; never installs or executes it."""

import argparse
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import ssl
import stat
import sys
import threading
import time
from http.client import HTTPSConnection
from urllib.parse import urljoin, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = Path("packages/event-gateway/docs/native-bridge/native-workspace-provisioning-assets.json")
# Reviewed manifest byte digest.
MANIFEST_SHA256 = "e51eaddfd9697f8f69499186e99d298707b979541df3dec1b9aabc19b2081406"
KIND = "native-workspace-provisioning-assets-v1"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ASSET_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ASSETS = 256
MAX_REDIRECTS = 3
TOTAL_TIMEOUT = 1800
ASSET_TIMEOUT = 300
CHUNK_SIZE = 64 * 1024
REDIRECT_HOST = "release-assets.githubusercontent.com"
HEX = re.compile(r"[0-9a-f]{64}\Z")


def _json_no_duplicates(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_json_constant")))


def _read_regular(path, maximum):
    path = Path(os.path.abspath(os.fspath(path)))
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors = [os.open(path.anchor, directory_flags)]
    try:
        for part in path.parts[1:-1]:
            before = os.stat(part, dir_fd=descriptors[-1], follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise ValueError("input_parent_unsafe")
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path.name, flags, dir_fd=descriptors[-1])
        descriptors.append(fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("input_not_regular_or_oversized")
        chunks = []
        remaining = maximum + 1
        while remaining:
            block = os.read(fd, min(CHUNK_SIZE, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise ValueError("input_oversized")
        return data
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def load_manifest(root=ROOT):
    raw = _read_regular(Path(root) / MANIFEST, MAX_MANIFEST_BYTES)
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("manifest_pin_mismatch")
    document = _json_no_duplicates(raw)
    _validate_manifest(document)
    return document


def _validate_url(url, allow_query=False):
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise ValueError("invalid_url")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise ValueError("invalid_url") from None
    if (parts.scheme != "https" or not host or host != host.lower()
            or parts.username is not None or parts.password is not None
            or port is not None or parts.fragment or not parts.path.startswith("/")
            or (parts.query and not allow_query)):
        raise ValueError("invalid_url")
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("invalid_url") from None
    if any(ord(char) < 33 or ord(char) > 126 for char in url):
        raise ValueError("invalid_url")
    if urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, "")) != url:
        raise ValueError("invalid_url")
    return parts


def _validate_manifest(document):
    if (type(document) is not dict or set(document) != {"kind", "qualified", "prepared", "assets"}
            or document["kind"] != KIND or document["qualified"] is not False
            or document["prepared"] is not False or type(document["assets"]) is not list
            or not 1 <= len(document["assets"]) <= MAX_ASSETS):
        raise ValueError("invalid_manifest")
    seen = set()
    for asset in document["assets"]:
        if (type(asset) is not dict or set(asset) != {"name", "url", "sha256", "maxBytes", "redirects"}
                or not isinstance(asset["name"], str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}", asset["name"])
                or asset["name"] in seen or not isinstance(asset["sha256"], str)
                or not HEX.fullmatch(asset["sha256"])
                or type(asset["maxBytes"]) is not int or not 1 <= asset["maxBytes"] <= MAX_ASSET_BYTES
                or type(asset["redirects"]) is not list or len(asset["redirects"]) > MAX_REDIRECTS):
            raise ValueError("invalid_asset")
        seen.add(asset["name"])
        initial = _validate_url(asset["url"])
        for redirect in asset["redirects"]:
            if (type(redirect) is not dict or set(redirect) != {"host", "path"}
                    or redirect["host"] != REDIRECT_HOST
                    or not isinstance(redirect["path"], str) or not redirect["path"].startswith("/")):
                raise ValueError("invalid_redirect_allowance")
            if initial.hostname == redirect["host"]:
                raise ValueError("redirect_loop_allowance")


def _parse_dns_map(raw, manifest):
    mapping = _json_no_duplicates(raw)
    if type(mapping) is not dict:
        raise ValueError("invalid_dns_map")
    required = set()
    for asset in manifest["assets"]:
        required.add(_validate_url(asset["url"]).hostname)
        required.update(item["host"] for item in asset["redirects"])
    if set(mapping) != required:
        raise ValueError("dns_map_hosts_mismatch")
    checked = {}
    for host, addresses in mapping.items():
        if type(addresses) is not list or not 1 <= len(addresses) <= 8:
            raise ValueError("invalid_dns_map_addresses")
        parsed = []
        for address in addresses:
            try:
                value = ipaddress.ip_address(address)
            except (ValueError, TypeError):
                raise ValueError("invalid_dns_map_address") from None
            if value.version != 4 or not value.is_global or str(value) != address:
                raise ValueError("invalid_dns_map_address")
            parsed.append(address)
        if len(set(parsed)) != len(parsed):
            raise ValueError("duplicate_dns_map_address")
        checked[host] = parsed
    return checked


class _PinnedHTTPSConnection(HTTPSConnection):
    """Connect to controller-pinned IPv4 while preserving HTTPS host/SNI checks."""
    def __init__(self, host, address, context, timeout):
        super().__init__(host, port=443, timeout=timeout, context=context)
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _redirect_target(current, location, allowances):
    target = urljoin(current, location)
    parts = _validate_url(target, allow_query=True)
    if not any(parts.hostname == rule["host"] and parts.path == rule["path"]
               for rule in allowances):
        raise ValueError("redirect_not_allowed")
    return target


def _tls_context(ca_bundle_bytes):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ca_bundle_bytes.decode("ascii"))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _set_response_timeout(response, timeout):
    """Best-effort socket timeout; the absolute alarm enforces the deadline."""
    if response.isclosed():
        return
    file_object = getattr(response, "fp", None)
    raw = getattr(file_object, "raw", None)
    sock = getattr(raw, "_sock", None)
    if sock is not None:
        sock.settimeout(timeout)


@contextmanager
def _absolute_deadline(deadline):
    """Enforce a wall-clock deadline across blocking connect/TLS/header/body calls."""
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("deadline_requires_main_thread")
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer[0] > 0 or previous_timer[1] > 0:
        raise RuntimeError("active_real_timer_already_installed")

    def alarm(_signum, _frame):
        raise TimeoutError("download_deadline")

    signal.signal(signal.SIGALRM, alarm)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("download_deadline")
        signal.setitimer(signal.ITIMER_REAL, remaining)
        yield
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            signal.signal(signal.SIGALRM, previous_handler)


def _download_asset(asset, dns, context, directory, deadline, remaining_total, opener=None):
    current = asset["url"]
    visited = 0
    digest = hashlib.sha256()
    size = 0
    destination = directory / asset["name"]
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.fchmod(fd, 0o600)
    connection = None
    try:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("download_total_timeout")
            parts = _validate_url(current, allow_query=visited > 0)
            host = parts.hostname
            if host not in dns:
                raise ValueError("dns_host_unpinned")
            remaining = min(deadline - time.monotonic(), ASSET_TIMEOUT)
            if remaining <= 0:
                raise TimeoutError("download_timeout")
            response = None
            connection = None
            try:
                selected_ip = dns[host][0]
                if opener:
                    response = opener(host, dns[host], current, context, remaining, visited == 0)
                else:
                    connection = _PinnedHTTPSConnection(host, selected_ip, context, remaining)
                    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
                    headers = {"Host": host, "Accept-Encoding": "identity", "Connection": "close"}
                    if visited == 0 and host == "ghcr.io":
                        headers["Authorization"] = "Bearer QQ=="
                    connection.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
                    for name, value in headers.items():
                        connection.putheader(name, value)
                    connection.endheaders()
                    response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    if visited >= MAX_REDIRECTS or not location:
                        raise ValueError("redirect_limit_or_missing_location")
                    current = _redirect_target(current, location, asset["redirects"])
                    visited += 1
                    continue
                if response.status != 200:
                    raise ValueError("download_http_status")
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("download_total_timeout")
                    if connection is not None:
                        _set_response_timeout(response, remaining)
                    if response.isclosed():
                        break
                    block = response.read1(CHUNK_SIZE)
                    if not block:
                        break
                    size += len(block)
                    if size > asset["maxBytes"] or size > remaining_total:
                        raise ValueError("asset_size_limit")
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise OSError("short_write")
                        view = view[written:]
                if size == 0 or digest.hexdigest() != asset["sha256"]:
                    raise ValueError("asset_digest_or_empty_mismatch")
                os.fsync(fd)
                return {"name": asset["name"], "initialUrl": asset["url"],
                        "finalHost": host, "finalPath": parts.path or "/",
                        "selectedIPv4": selected_ip, "status": response.status,
                        "redirectCount": visited, "outcome": "downloaded",
                        "bytes": size, "sha256": digest.hexdigest()}
            finally:
                try:
                    if response is not None:
                        response.close()
                finally:
                    if connection is not None:
                        connection.close()
    except BaseException:
        os.close(fd)
        fd = -1
        if connection is not None:
            connection.close()
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def _secure_output(path):
    path = Path(os.path.abspath(os.fspath(path)))
    if path.exists() or path.is_symlink():
        raise ValueError("output_already_exists")
    parent = path.parent
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current = current / part
        info = current.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in (os.geteuid(), 0)):
            raise ValueError("output_parent_unsafe")
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700, follow_symlinks=False)
    created = path.lstat()
    if stat.S_IMODE(created.st_mode) != 0o700 or created.st_uid != os.geteuid():
        raise ValueError("output_permissions_invalid")
    return path


def download_all(manifest, dns, ca_bundle, ca_sha256, output, opener=None):
    _validate_manifest(manifest)
    canonical_manifest = (json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    manifest_sha256 = hashlib.sha256(canonical_manifest).hexdigest()
    dns = _parse_dns_map(json.dumps(dns, separators=(",", ":")).encode(), manifest)
    bundle = _read_regular(ca_bundle, 16 * 1024 * 1024)
    if not isinstance(ca_sha256, str) or not HEX.fullmatch(ca_sha256) or hashlib.sha256(bundle).hexdigest() != ca_sha256:
        raise ValueError("ca_bundle_pin_mismatch")
    context = _tls_context(bundle)
    target = _secure_output(output)
    deadline = time.monotonic() + TOTAL_TIMEOUT
    records = []
    total = 0
    try:
        for asset in manifest["assets"]:
            start = time.monotonic()
            with _absolute_deadline(min(deadline, start + ASSET_TIMEOUT)):
                record = _download_asset(asset, dns, context, target,
                                         min(deadline, start + ASSET_TIMEOUT),
                                         MAX_TOTAL_BYTES - total, opener)
            records.append(record)
            total += record["bytes"]
            if total > MAX_TOTAL_BYTES:
                raise ValueError("download_total_size_limit")
        receipt = {"kind": KIND, "status": "downloaded-only", "qualified": False,
                   "prepared": False, "manifestSha256": manifest_sha256,
                   "caBundleSha256": ca_sha256,
                   "dnsMap": {host: dns[host] for host in sorted(dns)},
                   "totalBytes": total, "assets": records}
        encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        receipt_path = target / "receipt.json"
        partial_path = target / "receipt.json.partial"
        fd = os.open(partial_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short_receipt_write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(partial_path, receipt_path)
        directory_fd = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return receipt
    except BaseException:
        for child in target.iterdir():
            if child.is_file() and not child.is_symlink():
                child.unlink()
        target.rmdir()
        raise


def _runtime_guard():
    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise RuntimeError("runtime_requires_macos_arm64")
    version = tuple(int(part) for part in platform.mac_ver()[0].split(".") if part.isdigit())
    if not version or version[0] != 15 or sys.version_info < (3, 13):
        raise RuntimeError("runtime_requires_macos15_python313")


def main(argv=None):
    _runtime_guard()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dns-map", required=True, help="controller-supplied host to IPv4 JSON")
    parser.add_argument("--ca-bundle", required=True, help="controller-supplied public CA bundle")
    parser.add_argument("--ca-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    manifest = load_manifest()
    dns = _parse_dns_map(_read_regular(args.dns_map, 64 * 1024), manifest)
    receipt = download_all(manifest, dns, args.ca_bundle, args.ca_sha256, args.output)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
