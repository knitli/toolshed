#!/usr/bin/env python3
"""Build the fixed stdin bundle and receiver for guest-only provisioning downloads."""

import base64
import hashlib
import json
from pathlib import Path
import re

import native_workspace_provisioning_downloads as downloader


KIND = "native-workspace-provisioning-guest-bundle-v1"
LEGACY_RESULT_KIND = "native-workspace-provisioning-guest-download-v1"
RESULT_KIND = "native-workspace-provisioning-guest-download-v2"
MAX_BUNDLE_BYTES = 1024 * 1024
MAX_CA_BYTES = 512 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
SOURCE_PATH = "packages/event-gateway/scripts/native_workspace_provisioning_downloads.py"
MANIFEST_PATH = "packages/event-gateway/docs/native-bridge/native-workspace-provisioning-assets.json"
MANIFEST_SHA256 = downloader.MANIFEST_SHA256
# PR239 sealed this exact manifest before GHCR redirect destinations were added.
RETAINED_MANIFEST_SHA256 = "e51eaddfd9697f8f69499186e99d298707b979541df3dec1b9aabc19b2081406"
SOURCE_SHA256 = "6fbc9081316f7eb5f432ed227b7fd05526cd542db9d0392e5af4c9fc3bcf8cc1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
ROOT = Path(__file__).resolve().parents[3]
GUEST_ROOT = re.compile(r"/Users/admin/\.knitli-native-provisioning-[a-z0-9_]{8}\Z")
LEGACY_GUEST_ROOT = re.compile(r"/private/tmp/knitli-native-provisioning-[a-z0-9_]{8}\Z")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _loader():
    """Return fixed receiver source with its source and manifest pins embedded."""
    template = r'''import base64, hashlib, json, os, pathlib, platform, re, stat, sys, tempfile, types
MAX_INPUT = 1048576
SOURCE_SHA256 = SOURCE_PIN
MANIFEST_SHA256 = MANIFEST_PIN
SOURCE_PATH = 'packages/event-gateway/scripts/native_workspace_provisioning_downloads.py'
MANIFEST_PATH = 'packages/event-gateway/docs/native-bridge/native-workspace-provisioning-assets.json'
HEX = re.compile(r'[0-9a-f]{64}\Z')
def fail(code): raise SystemExit(code)
# Reject the host interpreter before reading input or creating guest files.
version = tuple(int(part) for part in platform.mac_ver()[0].split('.') if part.isdigit())
if sys.platform != 'darwin' or platform.machine() != 'arm64' or not version or version[0] != 15 or sys.version_info < (3, 13): fail(31)
def pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError('duplicate_json_key')
        result[key] = value
    return result
def digest(data): return hashlib.sha256(data).hexdigest()
raw = sys.stdin.buffer.read(MAX_INPUT + 1)
if len(raw) > MAX_INPUT: fail(32)
try:
    doc = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_constant')))
except (UnicodeError, ValueError, RecursionError): fail(33)
fields = {'kind','sourceBase64','sourceSha256','manifestBase64','manifestSha256','caBundleBase64','caBundleSha256','dnsMap'}
if type(doc) is not dict or set(doc) != fields or doc['kind'] != 'native-workspace-provisioning-guest-bundle-v1': fail(34)
try:
    source = base64.b64decode(doc['sourceBase64'], validate=True)
    manifest_raw = base64.b64decode(doc['manifestBase64'], validate=True)
    ca_bytes = base64.b64decode(doc['caBundleBase64'], validate=True)
except (TypeError, ValueError): fail(35)
if (doc['sourceSha256'] != SOURCE_SHA256 or digest(source) != SOURCE_SHA256
        or doc['manifestSha256'] != MANIFEST_SHA256 or digest(manifest_raw) != MANIFEST_SHA256
        or type(doc['caBundleSha256']) is not str or not HEX.fullmatch(doc['caBundleSha256'])
        or not ca_bytes or len(ca_bytes) > 524288 or digest(ca_bytes) != doc['caBundleSha256']): fail(36)
try:
    manifest = json.loads(manifest_raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_constant')))
except (UnicodeError, ValueError, RecursionError): fail(37)
module = types.ModuleType('native_workspace_provisioning_downloads')
root = pathlib.Path(tempfile.mkdtemp(prefix='.knitli-native-provisioning-', dir='/Users/admin'))
try:
    os.chmod(root, 0o700)
    module.__file__ = str(root / SOURCE_PATH)
    exec(compile(source, module.__file__, 'exec'), module.__dict__)
    module._runtime_guard()
    module._validate_manifest(manifest)
    dns = module._parse_dns_map(json.dumps(doc['dnsMap'], separators=(',', ':')).encode(), manifest)
    def put(relative, data):
        parts = pathlib.PurePosixPath(relative).parts
        if pathlib.PurePosixPath(relative).is_absolute() or not parts or '..' in parts or '\\' in relative: fail(38)
        parent = root
        for part in parts[:-1]:
            parent = parent / part
            try: os.mkdir(parent, 0o700)
            except FileExistsError:
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700: fail(38)
        path = parent / parts[-1]
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600: fail(38)
    put(SOURCE_PATH, source)
    put(MANIFEST_PATH, manifest_raw)
    data_dir = root / 'provisioning-data'
    ca_path = data_dir / 'public-roots.pem'
    put('provisioning-data/public-roots.pem', ca_bytes)
    loaded_manifest = module.load_manifest(root=root)
    downloads = root / 'downloads'
    receipt = module.download_all(loaded_manifest, dns, ca_path, doc['caBundleSha256'], downloads)
    def identity(info): return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    directory_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    root_fd = os.open(root, directory_flags)
    try:
        root_info = os.fstat(root_fd)
        if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o700: fail(40)
        downloads_fd = os.open('downloads', directory_flags, dir_fd=root_fd)
        try:
            downloads_info = os.fstat(downloads_fd)
            if downloads_info.st_uid != os.getuid() or stat.S_IMODE(downloads_info.st_mode) != 0o700: fail(40)
            downloads_identity = identity(downloads_info)
            records = {item['name']: item for item in receipt['assets']}
            expected_names = {asset['name'] for asset in loaded_manifest['assets']} | {'receipt.json'}
            names = []
            with os.scandir(downloads_fd) as entries:
                for entry in entries:
                    if len(names) >= len(expected_names): fail(41)
                    names.append(entry.name)
            if len(names) != len(expected_names) or set(names) != expected_names: fail(41)
            def read_file(name, maximum, capture=False):
                fd = os.open(name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), dir_fd=downloads_fd)
                try:
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                            or not 1 <= info.st_size <= maximum): fail(42)
                    before = identity(info)
                    digest, size, chunks = hashlib.sha256(), 0, []
                    while True:
                        block = os.read(fd, 65536)
                        if not block: break
                        size += len(block)
                        if size > maximum: fail(42)
                        digest.update(block)
                        if capture: chunks.append(block)
                    if identity(os.fstat(fd)) != before or size != info.st_size: fail(43)
                    return size, digest.hexdigest(), b''.join(chunks) if capture else None
                finally:
                    os.close(fd)
            inventory_assets = []
            for asset in loaded_manifest['assets']:
                record = records.get(asset['name'])
                if type(record) is not dict: fail(44)
                size, checksum, _ = read_file(asset['name'], asset['maxBytes'])
                if (size != record['bytes'] or checksum != asset['sha256']
                        or checksum != record['sha256']): fail(44)
                inventory_assets.append({'name': asset['name'], 'bytes': size, 'sha256': checksum})
            _, receipt_digest, receipt_bytes = read_file('receipt.json', 1048576, capture=True)
            if receipt_bytes != (json.dumps(receipt, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'): fail(45)
            if identity(os.fstat(downloads_fd)) != downloads_identity: fail(43)
            pre_stop_inventory = {'assets': inventory_assets, 'receiptSha256': receipt_digest}
        finally:
            os.close(downloads_fd)
    finally:
        os.close(root_fd)
    result = {'kind':'native-workspace-provisioning-guest-download-v2','qualified':False,'prepared':False,'guestRoot':str(root),'bundleSha256':digest(raw),'downloadReceipt':receipt,'preStopInventory':pre_stop_inventory}
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    if len(encoded) > 131072: fail(39)
    sys.stdout.buffer.write(encoded)
except BaseException:
    import shutil
    shutil.rmtree(root, ignore_errors=True)
    raise
'''
    return template.replace("SOURCE_PIN", repr(SOURCE_SHA256)).replace(
        "MANIFEST_PIN", repr(MANIFEST_SHA256))


def build_bundle(root=ROOT, caBytes=None, dnsMap=None):
    """Read the protected two-file closure and create a bounded, data-only stdin bundle."""
    if not isinstance(caBytes, bytes) or not 1 <= len(caBytes) <= MAX_CA_BYTES:
        raise ValueError("invalid_ca_bundle_bytes")
    source = downloader._read_regular(Path(root) / SOURCE_PATH, 64 * 1024)
    manifest_raw = downloader._read_regular(Path(root) / MANIFEST_PATH,
                                             downloader.MAX_MANIFEST_BYTES)
    source_sha256 = _digest(source)
    if source_sha256 != SOURCE_SHA256:
        raise ValueError("provisioning_source_pin_mismatch")
    manifest_sha256 = _digest(manifest_raw)
    if manifest_sha256 != MANIFEST_SHA256:
        raise ValueError("provisioning_manifest_pin_mismatch")
    manifest = downloader._json_no_duplicates(manifest_raw)
    downloader._validate_manifest(manifest)
    if type(dnsMap) is not dict:
        raise ValueError("invalid_dns_map")
    dns_map = downloader._parse_dns_map(_canonical(dnsMap), manifest)
    document = {
        "kind": KIND,
        "sourceBase64": base64.b64encode(source).decode("ascii"),
        "sourceSha256": source_sha256,
        "manifestBase64": base64.b64encode(manifest_raw).decode("ascii"),
        "manifestSha256": manifest_sha256,
        "caBundleBase64": base64.b64encode(caBytes).decode("ascii"),
        "caBundleSha256": _digest(caBytes),
        "dnsMap": dns_map,
    }
    payload = _canonical(document)
    if len(payload) > MAX_BUNDLE_BYTES:
        raise ValueError("provisioning_guest_bundle_oversized")
    return {"payload": payload, "bundleSha256": _digest(payload),
            "sourceSha256": source_sha256, "manifestSha256": manifest_sha256,
            "manifestBytes": manifest_raw, "dnsMap": dns_map,
            "caBundleSha256": document["caBundleSha256"], "loader": _loader()}


def validate_payload(raw, *, manifest_bytes, dns_map, ca_sha256, bundle_sha256):
    """Validate the exact stdin document and its entire digest before guest admission."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("payload_size_invalid")
    manifest, checked_dns = validate_binding(manifest_bytes=manifest_bytes, dns_map=dns_map,
                                             ca_sha256=ca_sha256,
                                             bundle_sha256=bundle_sha256)
    if _digest(raw) != bundle_sha256:
        raise ValueError("payload_digest_mismatch")
    try:
        document = downloader._json_no_duplicates(raw)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("payload_invalid_json") from None
    expected_fields = {"kind", "sourceBase64", "sourceSha256", "manifestBase64",
                       "manifestSha256", "caBundleBase64", "caBundleSha256", "dnsMap"}
    if type(document) is not dict or set(document) != expected_fields:
        raise ValueError("payload_shape_invalid")
    if document["kind"] != KIND:
        raise ValueError("payload_kind_invalid")
    try:
        source = base64.b64decode(document["sourceBase64"], validate=True)
        embedded_manifest = base64.b64decode(document["manifestBase64"], validate=True)
        ca_bytes = base64.b64decode(document["caBundleBase64"], validate=True)
    except (TypeError, ValueError):
        raise ValueError("payload_base64_invalid") from None
    if (len(source) > 64 * 1024 or document["sourceSha256"] != SOURCE_SHA256
            or _digest(source) != SOURCE_SHA256):
        raise ValueError("payload_source_pin_mismatch")
    if (embedded_manifest != manifest_bytes or document["manifestSha256"] != MANIFEST_SHA256
            or _digest(embedded_manifest) != MANIFEST_SHA256):
        raise ValueError("payload_manifest_pin_mismatch")
    if (not ca_bytes or len(ca_bytes) > MAX_CA_BYTES or document["caBundleSha256"] != ca_sha256
            or _digest(ca_bytes) != ca_sha256):
        raise ValueError("payload_ca_pin_mismatch")
    if type(document["dnsMap"]) is not dict or document["dnsMap"] != checked_dns:
        raise ValueError("payload_dns_map_mismatch")
    # The external manifest remains authoritative; this confirms the pinned decode completed.
    if not manifest["assets"]:
        raise ValueError("payload_manifest_pin_mismatch")
    return document


def validate_binding(*, manifest_bytes, dns_map, ca_sha256, bundle_sha256,
                     allow_retained_manifest=False):
    """Validate identity inputs retained by root state without reading repo or guest files."""
    if type(allow_retained_manifest) is not bool:
        raise ValueError("retained_manifest_option_invalid")
    if (not isinstance(manifest_bytes, bytes) or not manifest_bytes
            or len(manifest_bytes) > MAX_MANIFEST_BYTES
            or _digest(manifest_bytes) not in ({MANIFEST_SHA256, RETAINED_MANIFEST_SHA256}
                                                if allow_retained_manifest else {MANIFEST_SHA256})):
        raise ValueError("manifest_binding_mismatch")
    if (not isinstance(ca_sha256, str) or not HEX.fullmatch(ca_sha256)
            or not isinstance(bundle_sha256, str) or not HEX.fullmatch(bundle_sha256)):
        raise ValueError("digest_binding_invalid")
    try:
        manifest = downloader._json_no_duplicates(manifest_bytes)
        downloader._validate_manifest(manifest)
        if type(dns_map) is not dict:
            raise ValueError("invalid_dns_map")
        checked_dns = downloader._parse_dns_map(_canonical(dns_map), manifest)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("binding_inputs_invalid") from error
    return manifest, checked_dns


def validate_result(raw, *, manifest_bytes, dns_map, ca_sha256, bundle_sha256,
                    allow_retained_manifest=False, allow_legacy_result=False):
    """Validate the receipt against identity pins; retained mode admits journal history paths."""
    if type(allow_legacy_result) is not bool:
        raise ValueError("legacy_result_option_invalid")
    manifest, checked_dns = validate_binding(manifest_bytes=manifest_bytes, dns_map=dns_map,
                                             ca_sha256=ca_sha256,
                                             bundle_sha256=bundle_sha256,
                                             allow_retained_manifest=allow_retained_manifest)
    if isinstance(raw, bytes):
        if len(raw) > MAX_OUTPUT_BYTES:
            raise ValueError("result_oversized")
        try:
            result = downloader._json_no_duplicates(raw)
        except (UnicodeError, ValueError, RecursionError):
            raise ValueError("result_invalid_json") from None
    elif type(raw) is dict:
        result = raw
        try:
            if len(_canonical(result)) > MAX_OUTPUT_BYTES:
                raise ValueError("result_oversized")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise ValueError("result_invalid_json") from None
    else:
        raise ValueError("result_type_invalid")

    result_kind = result.get("kind") if type(result) is dict else None
    legacy_result = (allow_retained_manifest or allow_legacy_result) and result_kind == LEGACY_RESULT_KIND
    expected_wrapper = {"kind", "qualified", "prepared", "guestRoot", "bundleSha256",
                        "downloadReceipt"} | (set() if legacy_result else {"preStopInventory"})
    if type(result) is not dict or set(result) != expected_wrapper:
        raise ValueError("result_shape_invalid")
    if (result["kind"] != (LEGACY_RESULT_KIND if legacy_result else RESULT_KIND)
            or result["qualified"] is not False
            or result["prepared"] is not False or result["bundleSha256"] != bundle_sha256
            or not isinstance(result["guestRoot"], str)
            or not (GUEST_ROOT.fullmatch(result["guestRoot"])
                    # Prior completed journals recorded roots in temporary storage.
                    or (allow_retained_manifest and LEGACY_GUEST_ROOT.fullmatch(result["guestRoot"])))):
        raise ValueError("result_binding_mismatch")

    receipt = result["downloadReceipt"]
    expected_receipt = {"kind", "status", "qualified", "prepared", "manifestSha256",
                         "caBundleSha256", "dnsMap", "totalBytes", "assets"}
    if type(receipt) is not dict or set(receipt) != expected_receipt:
        raise ValueError("download_receipt_shape_invalid")
    if (receipt["kind"] != downloader.KIND or receipt["status"] != "downloaded-only"
            or receipt["qualified"] is not False or receipt["prepared"] is not False
            or receipt["manifestSha256"] != _digest(manifest_bytes)
            or receipt["caBundleSha256"] != ca_sha256 or receipt["dnsMap"] != checked_dns
            or type(receipt["totalBytes"]) is not int or not 0 <= receipt["totalBytes"] <= downloader.MAX_TOTAL_BYTES
            or type(receipt["assets"]) is not list
            or len(receipt["assets"]) != len(manifest["assets"])):
        raise ValueError("download_receipt_binding_mismatch")

    record_fields = {"name", "initialUrl", "finalHost", "finalPath", "selectedIPv4",
                     "status", "redirectCount", "outcome", "bytes", "sha256"}
    total = 0
    for asset, record in zip(manifest["assets"], receipt["assets"]):
        if type(record) is not dict or set(record) != record_fields:
            raise ValueError("download_asset_shape_invalid")
        initial = downloader._validate_url(asset["url"])
        if (record["name"] != asset["name"] or record["initialUrl"] != asset["url"]
                or type(record["status"]) is not int or record["status"] != 200
                or record["outcome"] != "downloaded"
                or type(record["redirectCount"]) is not int
                or not 0 <= record["redirectCount"] <= downloader.MAX_REDIRECTS
                or type(record["bytes"]) is not int or not 1 <= record["bytes"] <= asset["maxBytes"]
                or record["sha256"] != asset["sha256"]):
            raise ValueError("download_asset_binding_mismatch")
        final_host = record["finalHost"]
        final_path = record["finalPath"]
        if type(final_host) is not str or type(final_path) is not str:
            raise ValueError("download_asset_destination_invalid")
        if record["redirectCount"] == 0:
            allowed_destination = (final_host == initial.hostname
                                   and final_path == (initial.path or "/"))
        else:
            allowed_destination = any(rule["host"] == final_host and rule["path"] == final_path
                                      for rule in asset["redirects"])
        addresses = checked_dns.get(final_host)
        if (not allowed_destination or type(record["selectedIPv4"]) is not str
                or addresses is None or record["selectedIPv4"] != addresses[0]):
            raise ValueError("download_asset_destination_invalid")
        total += record["bytes"]
    if total != receipt["totalBytes"]:
        raise ValueError("download_receipt_total_mismatch")
    if not legacy_result:
        inventory = result["preStopInventory"]
        if (type(inventory) is not dict or set(inventory) != {"assets", "receiptSha256"}
                or type(inventory["assets"]) is not list
                or not isinstance(inventory["receiptSha256"], str)
                or not HEX.fullmatch(inventory["receiptSha256"])):
            raise ValueError("pre_stop_inventory_shape_invalid")
        expected_inventory = [{"name": record["name"], "bytes": record["bytes"],
                               "sha256": record["sha256"]} for record in receipt["assets"]]
        if (len(inventory["assets"]) != len(expected_inventory)
                or any(type(row) is not dict or set(row) != {"name", "bytes", "sha256"}
                       or not isinstance(row["name"], str) or type(row["bytes"]) is not int
                       or not isinstance(row["sha256"], str) or not HEX.fullmatch(row["sha256"])
                       for row in inventory["assets"])):
            raise ValueError("pre_stop_inventory_shape_invalid")
        if inventory["assets"] != expected_inventory:
            raise ValueError("pre_stop_inventory_binding_mismatch")
        if inventory["receiptSha256"] != _digest(_canonical(receipt) + b"\n"):
            raise ValueError("pre_stop_inventory_receipt_mismatch")
    return result


def command_template(tart_path, vm_name):
    """Return only the fixed stdin receiver command; no payload is interpolated into argv."""
    return [str(tart_path), "exec", "-i", vm_name, "/usr/bin/sudo", "-n", "-u", "admin",
            "-g", "staff", "/usr/bin/env", "-i",
            "PATH=/opt/homebrew/bin:/usr/bin:/bin", "HOME=/Users/admin", "TMPDIR=/private/tmp",
            "LC_ALL=C", "/opt/homebrew/bin/python3", "-I", "-B", "-c", _loader()]
