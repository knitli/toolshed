"""Fixed offline inventory of the Python default TLS trust roots."""

import hashlib
import json
import os
import platform
import ssl
import stat
import sys

SCHEMA_VERSION = "gateway-public-root-inventory-v1"
ROOT_INVENTORY_SCOPE = "materialized_default_ca_roots_without_connections"
MAX_ROOTS = 512
MAX_TOTAL_DER_BYTES = 2 * 1024 * 1024
MAX_ROOT_DER_BYTES = 2 * 1024 * 1024
MAX_CAFILE_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024
GATEWAY_CA_SHA256 = "a1c2722d8f42c698d98dad65487eb2467fb9117c60205d84907231ecf6aa9102"
_HEX = frozenset("0123456789abcdef")
SOURCE_FILES = {"probe": "gateway_public_root_inventory_probe.py"}
MAX_SOURCE_BYTES = 256 * 1024
MAX_BUNDLE_ARG = 128 * 1024
COLLECTION_ERROR_CODES = frozenset({
    "tls_environment_override_present",
    "default_context_unavailable",
    "default_context_flags_invalid",
    "default_roots_unavailable",
    "default_roots_invalid",
    "default_roots_empty",
    "root_der_invalid",
    "root_fingerprint_collision",
    "root_inventory_too_large",
    "gateway_ca_present_in_default_roots",
    "default_cafile_path_invalid",
    "default_cafile_invalid",
    "default_cafile_unavailable",
    "default_capath_path_invalid",
    "report_schema_invalid",
    "report_capath_invalid",
    "report_context_invalid",
    "report_roots_invalid",
    "report_digest_invalid",
    "report_cafile_invalid",
    "report_too_large",
    "probe_failed",
})
BUNDLE_ERROR_CODES = frozenset({
    "gateway_public_root_inventory_source_unsafe",
    "gateway_public_root_inventory_source_oversized",
    "gateway_public_root_inventory_source_unavailable",
    "gateway_public_root_inventory_bundle_oversized",
})
FIXED_ENV = {
    "HOME": "/Users/admin",
    "USER": "admin",
    "LOGNAME": "admin",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "LC_ALL": "C",
    "LANG": "C",
}


class ProbeError(ValueError):
    """A fixed, safe error suitable for the bounded CLI response."""


def _error(code):
    raise ProbeError(code)


def _fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def _mtime_ns(info):
    value = getattr(info, "st_mtime_ns", None)
    return value if type(value) is int else int(info.st_mtime * 1e9)


def _runtime_platform():
    uname = os.uname()
    return f"{uname.sysname}/{uname.release}/{uname.machine}"


def _add_root(roots, total, cert):
    if type(cert) is not bytes or not cert or len(cert) > MAX_ROOT_DER_BYTES:
        _error("root_der_invalid")
    digest = _fingerprint(cert)
    prior = roots.get(digest)
    if prior is not None:
        if prior != cert:
            _error("root_fingerprint_collision")
        return total
    if digest == GATEWAY_CA_SHA256:
        _error("gateway_ca_present_in_default_roots")
    total += len(cert)
    if len(roots) + 1 > MAX_ROOTS or total > MAX_TOTAL_DER_BYTES:
        _error("root_inventory_too_large")
    roots[digest] = cert
    return total


def _root_inventory(context):
    try:
        certs = context.get_ca_certs(binary_form=True)
    except Exception:  # noqa: BLE001 - normalize library failures to a fixed safe code
        _error("default_roots_unavailable")
    if type(certs) is not list:
        _error("default_roots_invalid")
    if not certs:
        _error("default_roots_empty")
    if len(certs) > MAX_ROOTS:
        _error("root_inventory_too_large")
    roots, total = {}, 0
    for cert in certs:
        total = _add_root(roots, total, cert)
    items = [
        {"derSha256": digest, "derBytes": len(roots[digest])}
        for digest in sorted(roots)
    ]
    canonical = "\n".join(item["derSha256"] for item in items).encode("ascii")
    return {
        "publicRootCount": len(items),
        "publicRootDerBytes": total,
        "publicRoots": items,
        "publicTrustRootsSha256": _fingerprint(canonical),
    }


def _cafile_inventory(path):
    result = {
        "path": path,
        "state": "unavailable",
        "bytes": None,
        "sha256": None,
        "stat": None,
    }
    if path is None:
        return result
    if type(path) is not str or not path or len(path) > 4096:
        _error("default_cafile_path_invalid")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > MAX_CAFILE_BYTES
        ):
            _error("default_cafile_invalid")
        content = bytearray()
        while len(content) <= MAX_CAFILE_BYTES:
            block = os.read(descriptor, min(65536, MAX_CAFILE_BYTES + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        if (
            len(content) > MAX_CAFILE_BYTES
            or len(content) != before.st_size
            or _file_identity(before) != _file_identity(after)
        ):
            _error("default_cafile_invalid")
    except ProbeError:
        raise
    except (OSError, ValueError):
        _error("default_cafile_unavailable")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    info = after
    result.update(
        state="present",
        bytes=len(content),
        sha256=_fingerprint(content),
        stat={
            "mode": stat.S_IMODE(info.st_mode),
            "sizeBytes": info.st_size,
            "mtimeNs": _mtime_ns(info),
            "device": info.st_dev,
            "inode": info.st_ino,
        },
    )
    return result


def _file_identity(info):
    ctime_ns = getattr(info, "st_ctime_ns", None)
    if type(ctime_ns) is not int:
        ctime_ns = int(info.st_ctime * 1e9)
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        _mtime_ns(info),
        ctime_ns,
    )


def _capath_metadata(path):
    result = {"path": path, "resolvedPath": None, "state": "unavailable", "stat": None}
    if path is None:
        return result
    if type(path) is not str or not path or len(path) > 4096:
        _error("default_capath_path_invalid")
    try:
        info = os.stat(path)
    except OSError:
        return result
    result.update(
        resolvedPath=os.path.realpath(path),
        state="present",
        stat={
            "mode": stat.S_IMODE(info.st_mode),
            "sizeBytes": info.st_size,
            "mtimeNs": _mtime_ns(info),
        },
    )
    return result


def _exact_keys(value, keys):
    return type(value) is dict and set(value) == set(keys)


def _validate_runtime(runtime):
    if not _exact_keys(runtime, ("pythonResolvedPath", "pythonVersion", "platform")):
        _error("report_schema_invalid")
    if any(type(value) is not str or not value or len(value) > 4096
           for value in runtime.values()):
        _error("report_schema_invalid")


def _validate_paths(paths):
    keys = ("cafile", "capath", "opensslCafile", "opensslCapath", "cafileEnv", "capathEnv")
    if not _exact_keys(paths, keys) or any(
        value is not None and (type(value) is not str or len(value) > 4096)
        for value in paths.values()
    ):
        _error("report_schema_invalid")


def _validate_context(context):
    keys = ("checkHostname", "verifyMode", "verifyFlags", "cadataUsed", "cadataSource", "trustSource")
    if not _exact_keys(context, keys):
        _error("report_schema_invalid")
    if (
        type(context["checkHostname"]) is not bool or context["checkHostname"] is not True
        or type(context["verifyMode"]) is not int or context["verifyMode"] != int(ssl.CERT_REQUIRED)
        or type(context["verifyFlags"]) is not int
        or type(context["cadataUsed"]) is not bool or context["cadataUsed"] is not False
        or context["cadataSource"] != "none"
        or context["trustSource"] != "ssl.create_default_context"
    ):
        _error("report_context_invalid")


def _validate_capath(capath, expected_path):
    if (
        not _exact_keys(capath, ("path", "resolvedPath", "state", "stat"))
        or capath["state"] not in ("present", "unavailable")
        or capath["path"] != expected_path
    ):
        _error("report_capath_invalid")
    if capath["state"] == "present":
        metadata = capath["stat"]
        if (
            not _exact_keys(metadata, ("mode", "sizeBytes", "mtimeNs"))
            or type(capath["resolvedPath"]) is not str or not capath["resolvedPath"]
            or any(type(value) is not int for value in metadata.values())
        ):
            _error("report_capath_invalid")
    elif capath["resolvedPath"] is not None or capath["stat"] is not None:
        _error("report_capath_invalid")


def _validate_roots(report):
    roots = report["publicRoots"]
    if type(roots) is not list or not roots or len(roots) > MAX_ROOTS:
        _error("report_roots_invalid")
    previous, total = "", 0
    for root in roots:
        if not _exact_keys(root, ("derSha256", "derBytes")):
            _error("report_roots_invalid")
        digest, size = root["derSha256"], root["derBytes"]
        if (
            type(digest) is not str or len(digest) != 64
            or any(c not in _HEX for c in digest) or digest <= previous
            or type(size) is not int or size <= 0
        ):
            _error("report_roots_invalid")
        if digest == GATEWAY_CA_SHA256:
            _error("gateway_ca_present_in_default_roots")
        previous, total = digest, total + size
    if (
        total > MAX_TOTAL_DER_BYTES
        or type(report["publicRootCount"]) is not int
        or report["publicRootCount"] != len(roots)
        or type(report["publicRootDerBytes"]) is not int
        or report["publicRootDerBytes"] != total
    ):
        _error("report_roots_invalid")
    canonical = "\n".join(root["derSha256"] for root in roots).encode("ascii")
    if report["publicTrustRootsSha256"] != _fingerprint(canonical):
        _error("report_digest_invalid")


def _validate_cafile(cafile, expected_path):
    if not _exact_keys(cafile, ("path", "state", "bytes", "sha256", "stat")):
        _error("report_cafile_invalid")
    if cafile["path"] != expected_path:
        _error("report_cafile_invalid")
    if cafile["state"] == "unavailable":
        if any(cafile[key] is not None for key in ("bytes", "sha256", "stat")):
            _error("report_cafile_invalid")
        return
    if cafile["state"] != "present":
        _error("report_cafile_invalid")
    metadata = cafile["stat"]
    if (
        not _exact_keys(metadata, ("mode", "sizeBytes", "mtimeNs", "device", "inode"))
        or type(cafile["bytes"]) is not int or not 0 <= cafile["bytes"] <= MAX_CAFILE_BYTES
        or type(metadata["sizeBytes"]) is not int or metadata["sizeBytes"] != cafile["bytes"]
        or any(type(metadata[key]) is not int for key in ("mode", "mtimeNs", "device", "inode"))
        or type(cafile["sha256"]) is not str or len(cafile["sha256"]) != 64
        or any(c not in _HEX for c in cafile["sha256"])
    ):
        _error("report_cafile_invalid")


def validate_report(report):
    """Validate the complete fixed report schema and its derived values."""
    keys = (
        "schemaVersion", "runtime", "defaultVerifyPaths", "context", "rootInventoryScope",
        "capathMetadata", "publicRootCount", "publicRootDerBytes", "publicRoots",
        "publicTrustRootsSha256", "defaultCafile",
    )
    if not _exact_keys(report, keys) or report["schemaVersion"] != SCHEMA_VERSION:
        _error("report_schema_invalid")
    _validate_runtime(report["runtime"])
    paths = report["defaultVerifyPaths"]
    _validate_paths(paths)
    _validate_context(report["context"])
    if report["rootInventoryScope"] != ROOT_INVENTORY_SCOPE:
        _error("report_roots_invalid")
    _validate_capath(report["capathMetadata"], paths["capath"])
    _validate_roots(report)
    _validate_cafile(report["defaultCafile"], paths["cafile"])
    try:
        encoded = json.dumps(report, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    except (TypeError, ValueError, UnicodeError):
        _error("report_schema_invalid")
    # Reserve envelope headroom for status and the fixed source hash in guest output.
    if len(encoded) + 257 > MAX_REPORT_BYTES:
        _error("report_too_large")
    return report


def collect():
    if "SSL_CERT_FILE" in os.environ or "SSL_CERT_DIR" in os.environ:
        _error("tls_environment_override_present")
    try:
        paths = ssl.get_default_verify_paths()
        context = ssl.create_default_context()
    except Exception:  # noqa: BLE001 - normalize SSL initialization failures
        _error("default_context_unavailable")
    if context.check_hostname is not True or context.verify_mode != ssl.CERT_REQUIRED:
        _error("default_context_flags_invalid")
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "runtime": {
            "pythonResolvedPath": os.path.realpath(sys.executable),
            "pythonVersion": platform.python_version(),
            "platform": _runtime_platform(),
        },
        "defaultVerifyPaths": {
            "cafile": paths.cafile,
            "capath": paths.capath,
            "opensslCafile": paths.openssl_cafile,
            "opensslCapath": paths.openssl_capath,
            "cafileEnv": paths.openssl_cafile_env,
            "capathEnv": paths.openssl_capath_env,
        },
        "context": {
            "checkHostname": bool(context.check_hostname),
            "verifyMode": int(context.verify_mode),
            "verifyFlags": int(context.verify_flags),
            "cadataUsed": False,
            "cadataSource": "none",
            "trustSource": "ssl.create_default_context",
        },
        "rootInventoryScope": ROOT_INVENTORY_SCOPE,
        "capathMetadata": _capath_metadata(paths.capath),
        **_root_inventory(context),
        "defaultCafile": _cafile_inventory(paths.cafile),
    }
    return validate_report(result)


def build_bundle():
    import scpreferences_guest_probe as shared

    try:
        bundle = shared._build_source_bundle(
            SOURCE_FILES,
            {"probe": os.path.realpath(__file__)},
            error_prefix="gateway_public_root_inventory",
            max_source_bytes=MAX_SOURCE_BYTES,
            max_bundle_arg=MAX_BUNDLE_ARG,
        )
        bundle["loader"] = shared._source_loader(
            set(SOURCE_FILES.values()),
            "gateway_public_root_inventory_probe",
            "collect_guest",
            "gateway-public-root-inventory-",
            guest_setup="os.environ.clear()\nos.environ.update("
            + repr(FIXED_ENV)
            + ")",
            call_args=repr(bundle["sourceSha256"]),
        )
    except shared.canary.CanaryError as exc:
        code = exc.args[0] if exc.args and type(exc.args[0]) is str else ""
        _error(code if code in BUNDLE_ERROR_CODES else "bundle_invalid")
    except Exception:  # noqa: BLE001 - bundle preflight must not expose arbitrary errors
        _error("bundle_invalid")
    return bundle


def command_template(tart_path, vm_name, loader):
    fixed = [key + "=" + value for key, value in FIXED_ENV.items()]
    return [
        str(tart_path),
        "exec",
        vm_name,
        "/usr/bin/sudo",
        "-n",
        "-u",
        "admin",
        "-g",
        "staff",
        "--",
        "/usr/bin/env",
        "-i",
        *fixed,
        "/usr/bin/python3",
        "-I",
        "-c",
        loader,
        "<fixed-source-bundle-b64>",
    ]


def collect_guest(source_sha256):
    try:
        report = collect()
    except ProbeError as exc:
        code = exc.args[0] if exc.args and type(exc.args[0]) is str else "probe_failed"
        report = {"errorCode": code if code in COLLECTION_ERROR_CODES else "probe_failed"}
    except Exception:  # noqa: BLE001 - guest output must not expose tracebacks
        report = {"errorCode": "probe_failed"}
    # The shared loader uses status only to set its process exit code; the host validates report.
    return {"status": "passed", "sourceSha256": source_sha256, "report": report}


def validate_guest_output(stdout, stderr, expected_source_sha256):
    if type(stdout) is not bytes or type(stderr) is not bytes:
        _error("guest_output_invalid")
    if len(stdout) > MAX_REPORT_BYTES or len(stderr) > MAX_REPORT_BYTES or stderr:
        _error("guest_output_invalid")
    try:
        envelope = json.loads(stdout)
    except (ValueError, UnicodeError, RecursionError):
        _error("guest_output_invalid")
    if (
        not _exact_keys(envelope, ("status", "sourceSha256", "report"))
        or envelope["status"] != "passed"
        or type(envelope["sourceSha256"]) is not dict
        or envelope["sourceSha256"] != expected_source_sha256
    ):
        _error("guest_output_invalid")
    guest_report = envelope["report"]
    if _exact_keys(guest_report, ("errorCode",)):
        code = guest_report["errorCode"]
        if type(code) is str and code in COLLECTION_ERROR_CODES:
            _error(code)
        _error("guest_output_invalid")
    return validate_report(guest_report)


def main(argv=None):
    """No configurable inputs; print one bounded JSON result and exit."""
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        code = "arguments_not_supported"
        status = 2
        payload = {"errorCode": code}
    else:
        try:
            payload = collect()
            status = 0
        except ProbeError as exc:
            code = (
                exc.args[0] if exc.args and type(exc.args[0]) is str else "probe_failed"
            )
            if code not in COLLECTION_ERROR_CODES:
                code = "probe_failed"
            payload, status = {"errorCode": code}, 1
        except Exception:  # noqa: BLE001 - CLI must never expose a traceback
            payload, status = {"errorCode": "probe_failed"}, 1
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        encoded = b'{"errorCode":"report_too_large"}'
        status = 1
    sys.stdout.buffer.write(encoded + b"\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
