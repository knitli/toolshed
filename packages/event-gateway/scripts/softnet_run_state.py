"""Root-only admission state for supervised Softnet recovery runs."""

from contextlib import AbstractContextManager
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import plistlib
import re
import stat
import time
import uuid

import qualify_offline_macos_vm as canary
import native_workspace_provisioning_guest as provisioning_guest
import softnet_recovery as recovery

STATE_KIND = "softnet-run-state"
STATE_VERSION = 1
IDENTITY_KEYS = {"vmName", "macAddress", "tartBinarySha256", "softnetBinarySha256",
                 "admissionSha256"}
PROBE_IDENTITY_KEYS = IDENTITY_KEYS | {"probeIPv4"}
ROUTE_IDENTITY_KEYS = IDENTITY_KEYS | {
    "identityProbeIPv4", "positiveOriginIPv4", "publicTrustRootsSha256"}
PROVISIONING_IDENTITY_KEYS = IDENTITY_KEYS | {
    "provisioningBundleSha256", "provisioningCaSha256", "provisioningDnsMap",
    "provisioningManifest"}
COMMAND_FAILURE_KIND = "softnet-command-failure-v1"
COMMAND_FAILURE_PHASES = {"prelaunch", "vm-start", "vm-readiness", "preference-readback",
                          "provisioning-command", "provisioning-receipt", "guest-shutdown"}
# Keep the fixed record cap aligned with both retained tails plus metadata.
MAX_COMMAND_FAILURE_BYTES = 2 * canary.COMMAND_FAILURE_TAIL_BYTES + 8 * 1024
# Match the shared runner's observed-byte limit.
MAX_COMMAND_FAILURE_OUTPUT_BYTES = canary.MAX_COMMAND_FAILURE_OBSERVED_BYTES
PUBLIC_PROBE_HOST = "event-native-probe-83fc4c309835.knitli.workers.dev"
PUBLIC_PROBE_PATH = "/probe"
PUBLIC_PROBE_BODY_SHA256 = "773cdcdb36ecbdb7c720d4d135911f7d35252d862b10094f788d96a965b80600"
ROUTE_POSITIVE_HOST = "knitli.app"
ROUTE_POSITIVE_PATH = "/site.webmanifest"
ROUTE_POSITIVE_CONTENT_TYPE = "application/manifest+json"
ROUTE_POSITIVE_BODY_BYTES = 456
ROUTE_POSITIVE_BODY_SHA256 = "096b1a4b927c04b0417ab1f49372e110c96d4db153cf3d6048f9d25c8b11d493"
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMAND_ERROR_TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
COMMAND_ERROR_CODE = re.compile(r"[a-z0-9_]{1,128}\Z")
MAC_ADDRESS = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
ROOT_ENTRIES = {"controller.lock"}
RUN_ENTRIES = {"identity.plist", "complete.plist", "reserved", "snapshot.plist", "restored",
               "launch.plist", "stop.plist", "helper-logs", "vm-logs", "disposition.plist",
               "probe.plist", "route-probe.plist", "provisioning-download.json",
               "guest-shutdown.plist", "command-failure.plist"}
LOG_FILES = {"tart-stdout.bin", "tart-stderr.bin"}
DISPOSITION_FILES = ("identity.plist", "reserved", "snapshot.plist", "restored",
                     "launch.plist", "stop.plist", "helper-logs/tart-stdout.bin",
                     "helper-logs/tart-stderr.bin", "vm-logs/tart-stdout.bin",
                     "vm-logs/tart-stderr.bin")
COMMAND_FAILURE_FILE = "command-failure.plist"
DISPOSITION_KIND = "softnet-failed-restored-disposition"
MAX_LOG_BYTES = canary.MAX_SHORT_OUTPUT
PROBE_DURATION_LIMIT_NS = 15_000_000_000
PROBE_TIMEOUT_LIMIT_NS = 25_000_000_000
ROUTE_DURATION_LIMIT_NS = 12_000_000_000
# Timeout/oversize failure receipts include bounded guest cleanup/unwind after the 12s deadline.
# This is the fixed 25s supervised command backstop; successful and ordinary reports stay at 12s.
ROUTE_TIMEOUT_LIMIT_NS = 25_000_000_000
ROUTE_REPORT_LIMIT = 4 * 1024


def _require(condition, message):
    if not condition:
        raise recovery.RecoveryError(message)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _identity_record(run_id, identity, *, allow_retained_manifest=False):
    _require(type(allow_retained_manifest) is bool, "invalid_identity")
    _require(isinstance(identity, dict) and set(identity) in (
        IDENTITY_KEYS, PROBE_IDENTITY_KEYS, ROUTE_IDENTITY_KEYS, PROVISIONING_IDENTITY_KEYS),
             "invalid_identity")
    _require(isinstance(identity["vmName"], str) and 0 < len(identity["vmName"]) <= 128
             and "\x00" not in identity["vmName"], "invalid_identity")
    _require(isinstance(identity["macAddress"], str)
             and MAC_ADDRESS.fullmatch(identity["macAddress"]), "invalid_identity")
    _require(identity["tartBinarySha256"] == canary.TART_BINARY_SHA256, "invalid_identity")
    _require(all(isinstance(identity[key], str) and HEX_SHA256.fullmatch(identity[key])
                 for key in ("softnetBinarySha256", "admissionSha256")), "invalid_identity")
    for key in ("probeIPv4", "identityProbeIPv4", "positiveOriginIPv4"):
        if key in identity:
            _require(isinstance(identity[key], str), "invalid_identity")
            try:
                probe_ip = ipaddress.ip_address(identity[key])
            except (TypeError, ValueError):
                raise recovery.RecoveryError("invalid_identity") from None
            _require(isinstance(probe_ip, ipaddress.IPv4Address) and probe_ip.is_global,
                     "invalid_identity")
    if "identityProbeIPv4" in identity:
        _require(isinstance(identity.get("positiveOriginIPv4"), str)
                 and isinstance(identity.get("publicTrustRootsSha256"), str)
                 and HEX_SHA256.fullmatch(identity["publicTrustRootsSha256"]), "invalid_identity")
    if "provisioningBundleSha256" in identity:
        try:
            provisioning_guest.validate_binding(
                manifest_bytes=identity["provisioningManifest"],
                dns_map=identity["provisioningDnsMap"],
                ca_sha256=identity["provisioningCaSha256"],
                bundle_sha256=identity["provisioningBundleSha256"],
                allow_retained_manifest=allow_retained_manifest)
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise recovery.RecoveryError("invalid_identity") from None
    return {"kind": STATE_KIND, "version": STATE_VERSION, "runId": run_id,
            "identity": identity}


def _plist(data, reason):
    try:
        return plistlib.loads(data)
    except (ValueError, TypeError, OverflowError) as error:
        raise recovery.RecoveryError(reason) from error


def _stop_evidence_shape(evidence):
    return (isinstance(evidence, dict)
            and set(evidence) == {"vmReaped", "helperReaped", "vmStopped"}
            and all(type(evidence[key]) is bool for key in evidence))


def _valid_stop_evidence(evidence):
    return _stop_evidence_shape(evidence) and all(evidence.values())


def _check_guest_shutdown(fd):
    raw = recovery._read(fd, "guest-shutdown.plist")
    value = _plist(raw, "invalid_guest_shutdown")
    _require(isinstance(value, dict) and set(value) == {
        "kind", "version", "requestAccepted", "vmRunExitCode", "vmStopped"}
        and value["kind"] == "softnet-guest-shutdown-v1"
        and type(value["version"]) is int and value["version"] == 1
        and value["requestAccepted"] is True
        and type(value["vmRunExitCode"]) is int and value["vmRunExitCode"] == 0
        and value["vmStopped"] is True, "invalid_guest_shutdown")
    return raw, value


def _failed_restored_files(root, name, *, receipt_present=False, expected_vm_reaped=None,
                           allow_legacy_result=False):
    """Validate the narrow failed-restored state and return hashes of retained evidence."""
    path = Path(root) / name
    fd = recovery._directory(path)
    try:
        entries = set(os.listdir(fd))
        required = {"identity.plist", "reserved", "snapshot.plist", "restored", "launch.plist",
                    "stop.plist", "helper-logs", "vm-logs"}
        _require(not ("complete.plist" in entries and "disposition.plist" in entries),
                 "conflicting_disposition")
        _require("complete.plist" not in entries
                 and (receipt_present or "disposition.plist" not in entries)
                 and required <= entries, "ineligible_disposition")
        _require(_check_run_directory(root, name, allow_retained_manifest=receipt_present,
                                      allow_legacy_result=allow_legacy_result)
                 is False, "ineligible_disposition")
        identity_bytes = recovery._read(fd, "identity.plist")
        identity = _plist(identity_bytes, "invalid_identity")["identity"]
        _check_launch(fd, identity)
        stop_bytes, stop = _check_stop(fd)
        _require(stop["helperReaped"] is True and stop["vmStopped"] is True
                 and type(stop["vmReaped"]) is bool,
                 "ineligible_disposition")
        if expected_vm_reaped is not None:
            _require(type(expected_vm_reaped) is bool, "invalid_expected_vm_reaped")
            _require(stop["vmReaped"] is expected_vm_reaped, "disposition_stop_mode_mismatch")
        _require(recovery._read(fd, "reserved") == b""
                 and recovery._read(fd, "restored") == b"restored\n", "invalid_incomplete_run")
        snapshot = _plist(recovery._read(fd, "snapshot.plist"), "invalid_snapshot")
        _require(isinstance(snapshot, dict)
                 and set(snapshot) == {"version", "present", "before", "target"}
                 and type(snapshot["version"]) is int and snapshot["version"] == 1
                 and type(snapshot["present"]) is bool
                 and type(snapshot["before"]) is bytes and type(snapshot["target"]) is bytes
                 and (snapshot["present"] or snapshot["before"] == b""), "invalid_snapshot")
        for blob in (snapshot["before"] if snapshot["present"] else None, snapshot["target"]):
            if blob is not None:
                _require(len(blob) <= recovery.MAX_BLOB and blob.startswith(b"bplist00"),
                         "invalid_snapshot")
        disposition_files = DISPOSITION_FILES
        if "probe.plist" in entries:
            _require("probeIPv4" in identity, "invalid_probe")
            disposition_files = (*DISPOSITION_FILES, "probe.plist")
        if "route-probe.plist" in entries:
            _require("identityProbeIPv4" in identity, "invalid_route_probe")
            _check_route_probe(fd, identity)
            disposition_files = (*disposition_files, "route-probe.plist")
        if "provisioning-download.json" in entries:
            _require("provisioningBundleSha256" in identity, "invalid_provisioning_download")
            _check_provisioning_download(
                fd, identity, allow_retained_manifest=receipt_present,
                allow_legacy_result=allow_legacy_result)
            disposition_files = (*disposition_files, "provisioning-download.json")
        if "guest-shutdown.plist" in entries:
            _require("provisioningBundleSha256" in identity
                     and "provisioning-download.json" in entries,
                     "invalid_guest_shutdown")
            _check_guest_shutdown(fd)
            disposition_files = (*disposition_files, "guest-shutdown.plist")
        if COMMAND_FAILURE_FILE in entries:
            _check_command_failure(fd)
            disposition_files = (*disposition_files, COMMAND_FAILURE_FILE)
        hashes = {}
        for relative in disposition_files:
            parts = relative.split("/")
            if len(parts) == 1:
                data = recovery._read(fd, relative)
            else:
                log_fd = recovery._directory(path / parts[0])
                try:
                    with os.fdopen(recovery._file(log_fd, parts[1], os.O_RDONLY), "rb") as stream:
                        info = os.fstat(stream.fileno())
                        _require(info.st_size <= MAX_LOG_BYTES, "oversized_run_log")
                        data = stream.read(MAX_LOG_BYTES + 1)
                        _require(len(data) <= MAX_LOG_BYTES, "oversized_run_log")
                finally:
                    os.close(log_fd)
            hashes[relative] = _digest(data)
        for log_name in ("helper-logs", "vm-logs"):
            _check_log_directory(root, name, log_name, complete=True)
        return hashes
    finally:
        os.close(fd)


def _observation(value):
    _require(isinstance(value, dict) and set(value) == {
        "observedAtUnixNs", "vmStopped", "processesQuiet", "preferencesOriginal"},
        "invalid_disposition_observation")
    _require(type(value["observedAtUnixNs"]) is int and value["observedAtUnixNs"] > 0
             and value["vmStopped"] is True and value["processesQuiet"] is True
             and value["preferencesOriginal"] is True, "invalid_disposition_observation")


def _check_disposition(root, name):
    run = Path(root) / name
    fd = recovery._directory(run)
    try:
        record = _plist(recovery._read(fd, "disposition.plist"), "invalid_disposition")
        current_hashes = _failed_restored_files(root, name, receipt_present=True)
        _require(isinstance(record, dict) and set(record) == {
            "kind", "version", "runId", "approvalReference", "observation", "fileSha256"}
            and record["kind"] == DISPOSITION_KIND and type(record["version"]) is int
            and record["version"] == 1 and record["runId"] == name
            and isinstance(record["approvalReference"], str)
            and 0 < len(record["approvalReference"].strip()) <= 256
            and "\x00" not in record["approvalReference"]
            and isinstance(record["fileSha256"], dict)
            and set(record["fileSha256"]) == set(current_hashes)
            and all(isinstance(digest, str) and HEX_SHA256.fullmatch(digest)
                    for digest in record["fileSha256"].values()), "invalid_disposition")
        _observation(record["observation"])
        _require(record["fileSha256"] == current_hashes, "invalid_disposition")
    finally:
        os.close(fd)


def _check_launch(fd, identity):
    launch = _plist(recovery._read(fd, "launch.plist"), "invalid_launch")
    _require(isinstance(launch, dict) and set(launch) == {"vmName", "macAddress"}
             and launch == {key: identity[key] for key in ("vmName", "macAddress")},
             "invalid_launch")


def _check_stop(fd):
    stop_bytes = recovery._read(fd, "stop.plist")
    stop = _plist(stop_bytes, "invalid_stop")
    _require(_stop_evidence_shape(stop), "invalid_stop")
    return stop_bytes, stop


def _check_command_failure(fd):
    raw = recovery._read(fd, COMMAND_FAILURE_FILE)
    _require(len(raw) <= MAX_COMMAND_FAILURE_BYTES, "oversized_command_failure")
    record = _plist(raw, "invalid_command_failure")
    keys = {"kind", "phase", "errorType", "errorCode", "stdoutTail", "stderrTail",
            "stdoutObservedBytes", "stderrObservedBytes", "exitCode"}
    _require(isinstance(record, dict) and set(record) == keys
             and record["kind"] == COMMAND_FAILURE_KIND
             and isinstance(record["phase"], str)
             and record["phase"] in COMMAND_FAILURE_PHASES
             and isinstance(record["errorType"], str)
             and COMMAND_ERROR_TYPE.fullmatch(record["errorType"])
             and isinstance(record["errorCode"], str)
             and COMMAND_ERROR_CODE.fullmatch(record["errorCode"])
             and isinstance(record["stdoutTail"], bytes)
             and len(record["stdoutTail"]) <= canary.COMMAND_FAILURE_TAIL_BYTES
             and isinstance(record["stderrTail"], bytes)
             and len(record["stderrTail"]) <= canary.COMMAND_FAILURE_TAIL_BYTES
             and type(record["stdoutObservedBytes"]) is int
             and len(record["stdoutTail"]) <= record["stdoutObservedBytes"]
             <= MAX_COMMAND_FAILURE_OUTPUT_BYTES
             and type(record["stderrObservedBytes"]) is int
             and len(record["stderrTail"]) <= record["stderrObservedBytes"]
             <= MAX_COMMAND_FAILURE_OUTPUT_BYTES
             and (record["exitCode"] is None
                  or (type(record["exitCode"]) is int and record["exitCode"] != 0
                      and -255 <= record["exitCode"] <= 255)), "invalid_command_failure")
    return raw, record


def _check_probe(fd, identity):
    raw = recovery._read(fd, "probe.plist")
    report = _plist(raw, "invalid_probe")
    duration_limit_ns = (PROBE_TIMEOUT_LIMIT_NS
                         if isinstance(report, dict) and report.get("error") == "total_timeout"
                         else PROBE_DURATION_LIMIT_NS)
    _require(isinstance(report, dict) and set(report) == {
        "kind", "method", "host", "path", "destinationIPv4", "port",
        "startedAtUnixNs", "finishedAtUnixNs", "tlsVerified",
        "gatewayContextVerified", "expectedHostPosturePassed", "status",
        "bodyBytes", "bodySha256", "verified", "error"}
        and report["kind"] == "native-guest-public-probe-v1"
        and report["method"] == "GET" and report["host"] == PUBLIC_PROBE_HOST
        and report["path"] == PUBLIC_PROBE_PATH
        and report["destinationIPv4"] == identity.get("probeIPv4")
        and type(report["port"]) is int and report["port"] == 443
        and type(report["startedAtUnixNs"]) is int and report["startedAtUnixNs"] > 0
        and type(report["finishedAtUnixNs"]) is int
        and report["finishedAtUnixNs"] >= report["startedAtUnixNs"]
        and report["finishedAtUnixNs"] - report["startedAtUnixNs"] <= duration_limit_ns
        and type(report["tlsVerified"]) is bool
        and type(report["gatewayContextVerified"]) is bool
        and type(report["expectedHostPosturePassed"]) is bool
        and type(report["status"]) is int and 0 <= report["status"] <= 599
        and type(report["bodyBytes"]) is int and 0 <= report["bodyBytes"] <= 17
        and isinstance(report["bodySha256"], str) and HEX_SHA256.fullmatch(report["bodySha256"])
        and type(report["verified"]) is bool
        and isinstance(report["error"], str)
        and report["error"] in {"", "total_timeout", "transport_error",
                                "gateway_context_invalid"}
        and (report["gatewayContextVerified"] or report["error"] != ""), "invalid_probe")
    expected_success = (report["tlsVerified"] and report["gatewayContextVerified"]
                        and report["status"] == 200
                        and report["bodyBytes"] == 16
                        and report["bodySha256"] == PUBLIC_PROBE_BODY_SHA256
                        and report["error"] == "")
    _require(report["verified"] is expected_success, "invalid_probe")
    return raw, report


def _check_route_probe(fd, identity):
    raw = recovery._read(fd, "route-probe.plist")
    _require(0 < len(raw) <= ROUTE_REPORT_LIMIT, "invalid_route_probe")
    report = _plist(raw, "invalid_route_probe")
    timeout = (isinstance(report, dict) and isinstance(report.get("error"), str)
               and report["error"] in {"timeout", "report_too_large"})
    duration_limit = ROUTE_TIMEOUT_LIMIT_NS if timeout else ROUTE_DURATION_LIMIT_NS
    _require(isinstance(report, dict) and set(report) == {
        "kind", "identityHost", "identityPath", "identityDestinationIPv4", "identityStatus",
        "identityTlsVerified", "identityBodyBytes", "identityBodySha256", "identityNoStore",
        "identityNoGatewayMarkers", "identityError", "positiveHost", "positivePath",
        "positiveDestinationIPv4", "positiveStatus", "positiveTlsVerified",
        "positiveContentType", "positiveBodyBytes", "positiveBodySha256", "positiveError",
        "publicTrustRootsSha256", "gatewayCaAbsent", "startedAtUnixNs", "finishedAtUnixNs",
        "verified", "error"}
        and report["kind"] == "native-guest-route-contract-v1"
        and report["identityHost"] == PUBLIC_PROBE_HOST and report["identityPath"] == PUBLIC_PROBE_PATH
        and report["identityDestinationIPv4"] == identity.get("identityProbeIPv4")
        and report["positiveHost"] == ROUTE_POSITIVE_HOST and report["positivePath"] == ROUTE_POSITIVE_PATH
        and report["positiveDestinationIPv4"] == identity.get("positiveOriginIPv4")
        and isinstance(report["publicTrustRootsSha256"], str)
        and type(report["gatewayCaAbsent"]) is bool
        and type(report["startedAtUnixNs"]) is int and report["startedAtUnixNs"] > 0
        and type(report["finishedAtUnixNs"]) is int
        and report["finishedAtUnixNs"] >= report["startedAtUnixNs"]
        and report["finishedAtUnixNs"] - report["startedAtUnixNs"] <= duration_limit
        and type(report["identityStatus"]) is int and 0 <= report["identityStatus"] <= 599
        and type(report["identityTlsVerified"]) is bool
        and type(report["identityBodyBytes"]) is int and 0 <= report["identityBodyBytes"] <= 8192
        and isinstance(report["identityBodySha256"], str) and HEX_SHA256.fullmatch(report["identityBodySha256"])
        and type(report["identityNoStore"]) is bool
        and type(report["identityNoGatewayMarkers"]) is bool
        and isinstance(report["identityError"], str)
        and report["identityError"] in {"", "timeout", "transport_error", "tls_error",
                                         "trust_override", "trust_roots_invalid", "trust_roots_mismatch",
                                         "body_too_large", "report_too_large"}
        and type(report["positiveStatus"]) is int and 0 <= report["positiveStatus"] <= 599
        and type(report["positiveTlsVerified"]) is bool
        and isinstance(report["positiveContentType"], str)
        and report["positiveContentType"] in {"", ROUTE_POSITIVE_CONTENT_TYPE}
        and type(report["positiveBodyBytes"]) is int and 0 <= report["positiveBodyBytes"] <= 8192
        and isinstance(report["positiveBodySha256"], str) and HEX_SHA256.fullmatch(report["positiveBodySha256"])
        and isinstance(report["positiveError"], str)
        and report["positiveError"] in {"", "timeout", "transport_error", "tls_error",
                                         "trust_override", "trust_roots_invalid", "trust_roots_mismatch",
                                         "body_too_large", "report_too_large"}
        and type(report["verified"]) is bool
        and isinstance(report["error"], str)
        and report["error"] in {"", "timeout", "transport_error", "tls_error", "trust_override",
                                "trust_roots_invalid", "trust_roots_mismatch", "body_too_large",
                                "predicate_failed", "report_too_large"}, "invalid_route_probe")
    preflight_errors = {"trust_override", "trust_roots_invalid", "trust_roots_mismatch"}
    if report["error"] in preflight_errors:
        empty_hash = _digest(b"")
        _require(report["identityError"] == report["error"]
                 and report["positiveError"] == report["error"]
                 and report["publicTrustRootsSha256"] == ""
                 and report["gatewayCaAbsent"] is False
                 and report["identityStatus"] == 0 and report["positiveStatus"] == 0
                 and report["identityTlsVerified"] is False
                 and report["positiveTlsVerified"] is False
                 and report["identityBodyBytes"] == 0 and report["positiveBodyBytes"] == 0
                 and report["identityBodySha256"] == empty_hash
                 and report["positiveBodySha256"] == empty_hash
                 and report["identityNoStore"] is False
                 and report["identityNoGatewayMarkers"] is False
                 and report["positiveContentType"] == ""
                 and report["verified"] is False, "invalid_route_probe")
        return raw, report
    if report["error"] == "report_too_large":
        empty_hash = _digest(b"")
        _require(report["identityError"] == report["error"]
                 and report["positiveError"] == report["error"]
                 and report["publicTrustRootsSha256"] == identity.get("publicTrustRootsSha256")
                 and report["gatewayCaAbsent"] is True
                 and report["identityStatus"] == 0 and report["positiveStatus"] == 0
                 and report["identityTlsVerified"] is False
                 and report["positiveTlsVerified"] is False
                 and report["identityBodyBytes"] == 0 and report["positiveBodyBytes"] == 0
                 and report["identityBodySha256"] == empty_hash
                 and report["positiveBodySha256"] == empty_hash
                 and report["identityNoStore"] is False
                 and report["identityNoGatewayMarkers"] is False
                 and report["positiveContentType"] == ""
                 and report["verified"] is False, "invalid_route_probe")
        return raw, report
    _require(report["publicTrustRootsSha256"] == identity.get("publicTrustRootsSha256")
             and report["gatewayCaAbsent"] is True, "invalid_route_probe")
    empty_hash = _digest(b"")
    identity_ok = (report["identityTlsVerified"] and report["identityStatus"] == 404
                   and report["identityBodyBytes"] == 0 and report["identityBodySha256"] == empty_hash
                   and report["identityNoStore"] and report["identityNoGatewayMarkers"]
                   and report["identityError"] == "")
    positive_ok = (report["positiveTlsVerified"] and report["positiveStatus"] == 200
                   and report["positiveContentType"] == ROUTE_POSITIVE_CONTENT_TYPE
                   and report["positiveBodyBytes"] == ROUTE_POSITIVE_BODY_BYTES
                   and report["positiveBodySha256"] == ROUTE_POSITIVE_BODY_SHA256
                   and report["positiveError"] == "")
    expected_error = "" if identity_ok and positive_ok else (
        report["positiveError"] or report["identityError"] or "predicate_failed")
    _require(report["verified"] is (identity_ok and positive_ok)
             and report["error"] == expected_error, "invalid_route_probe")
    return raw, report


def _check_provisioning_download(fd, identity, *, allow_retained_manifest=False,
                                 allow_legacy_result=False):
    raw = recovery._read(fd, "provisioning-download.json")
    _require(0 < len(raw) <= provisioning_guest.MAX_OUTPUT_BYTES,
             "invalid_provisioning_download")
    try:
        result = provisioning_guest.validate_result(
            raw, manifest_bytes=identity["provisioningManifest"],
            dns_map=identity["provisioningDnsMap"],
            ca_sha256=identity["provisioningCaSha256"],
            bundle_sha256=identity["provisioningBundleSha256"],
            allow_retained_manifest=allow_retained_manifest,
            allow_legacy_result=allow_legacy_result)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise recovery.RecoveryError("invalid_provisioning_download") from None
    return raw, result


def _check_log_directory(root, run_name, name, *, complete):
    fd = recovery._directory(Path(root) / run_name / name)
    try:
        files = set(os.listdir(fd))
        _require(files <= LOG_FILES and (not complete or files == LOG_FILES), "invalid_run_logs")
        for filename in files:
            handle = recovery._file(fd, filename, os.O_RDONLY)
            try:
                _require(os.fstat(handle).st_size <= MAX_LOG_BYTES, "oversized_run_log")
            finally:
                os.close(handle)
    finally:
        os.close(fd)


def _check_run_directory(root, name, *, allow_retained_manifest=False, allow_legacy_result=False):
    path = Path(root) / name
    fd = recovery._directory(path)
    try:
        entries = set(os.listdir(fd))
        _require(entries <= RUN_ENTRIES and "identity.plist" in entries, "invalid_run_entries")
        identity_bytes = recovery._read(fd, "identity.plist")
        identity_record = _plist(identity_bytes, "invalid_identity")
        _require(isinstance(identity_record, dict)
                 and set(identity_record) == {"kind", "version", "runId", "identity"}
                 and identity_record["kind"] == STATE_KIND
                 and type(identity_record["version"]) is int
                 and identity_record["version"] == STATE_VERSION
                 and identity_record["runId"] == name, "invalid_identity")
        expected = _identity_record(name, identity_record["identity"],
                                    allow_retained_manifest=allow_retained_manifest)
        _require(identity_record == expected, "invalid_identity")
        identity = identity_record["identity"]
        probe_mode = "probeIPv4" in identity
        route_mode = "identityProbeIPv4" in identity
        provisioning_mode = "provisioningBundleSha256" in identity
        _require(sum((probe_mode, route_mode, provisioning_mode)) <= 1
                 and ("probe.plist" not in entries or probe_mode)
                 and ("route-probe.plist" not in entries or route_mode)
                 and ("provisioning-download.json" not in entries or provisioning_mode),
                 "invalid_probe_mode")
        if "launch.plist" in entries:
            _check_launch(fd, identity_record["identity"])
        probe_bytes = None
        probe = None
        if "probe.plist" in entries:
            probe_bytes, probe = _check_probe(fd, identity)
        route_probe_bytes = None
        route_probe = None
        if "route-probe.plist" in entries:
            route_probe_bytes, route_probe = _check_route_probe(fd, identity)
        provisioning_download_bytes = None
        if "provisioning-download.json" in entries:
            provisioning_download_bytes, _ = _check_provisioning_download(
                fd, identity, allow_retained_manifest=allow_retained_manifest,
                allow_legacy_result=allow_legacy_result)
        guest_shutdown_bytes = None
        if "guest-shutdown.plist" in entries:
            _require(provisioning_mode and provisioning_download_bytes is not None,
                     "invalid_guest_shutdown")
            guest_shutdown_bytes, _ = _check_guest_shutdown(fd)
        stop_bytes = stop = None
        if "stop.plist" in entries:
            stop_bytes, stop = _check_stop(fd)
        complete_present = "complete.plist" in entries
        if COMMAND_FAILURE_FILE in entries:
            _check_command_failure(fd)
            _require(provisioning_mode and not complete_present,
                     "invalid_command_failure_mode")
        _require(not (complete_present and "disposition.plist" in entries),
                 "conflicting_disposition")
        for log_name in ("helper-logs", "vm-logs"):
            if log_name in entries:
                _check_log_directory(root, name, log_name, complete=complete_present)
        if not complete_present:
            _require(not ("restored" in entries and "snapshot.plist" not in entries),
                     "invalid_incomplete_run")
            return False
        if probe_mode:
            _require(probe is not None and probe["verified"], "invalid_probe")
        if route_mode:
            _require(route_probe is not None and route_probe["verified"], "invalid_route_probe")
        if provisioning_mode:
            _require(provisioning_download_bytes is not None, "invalid_provisioning_download")
        required = {"snapshot.plist", "restored", "reserved", "launch.plist", "stop.plist",
                    "helper-logs", "vm-logs"}
        if probe_mode:
            required.add("probe.plist")
        if route_mode:
            required.add("route-probe.plist")
        if provisioning_mode:
            required.add("provisioning-download.json")
        _require(required <= entries, "invalid_completion")
        _require(recovery._read(fd, "reserved") == b"", "invalid_completion")
        _require(_valid_stop_evidence(stop), "invalid_completion")
        snapshot = recovery._read(fd, "snapshot.plist")
        restored = recovery._read(fd, "restored")
        _require(restored == b"restored\n", "invalid_completion")
        complete = _plist(recovery._read(fd, "complete.plist"), "invalid_completion")
        complete_keys = {"version", "identitySha256", "snapshotSha256",
                         "restoredSha256", "stopSha256", "stopEvidence"}
        if probe_mode:
            complete_keys.add("probeSha256")
        if route_mode:
            complete_keys.add("routeProbeSha256")
        if provisioning_mode:
            complete_keys.add("provisioningDownloadSha256")
        if guest_shutdown_bytes is not None:
            complete_keys.add("guestShutdownSha256")
        _require(isinstance(complete, dict)
                 and set(complete) == complete_keys
                 and type(complete["version"]) is int and complete["version"] == 1
                 and complete["identitySha256"] == _digest(identity_bytes)
                 and complete["snapshotSha256"] == _digest(snapshot)
                 and complete["restoredSha256"] == _digest(restored)
                 and complete["stopSha256"] == _digest(stop_bytes)
                 and complete["stopEvidence"] == stop
                 and (not probe_mode or complete["probeSha256"] == _digest(probe_bytes))
                 and (not route_mode or complete["routeProbeSha256"] == _digest(route_probe_bytes))
                 and (not provisioning_mode or complete["provisioningDownloadSha256"]
                      == _digest(provisioning_download_bytes))
                 and (guest_shutdown_bytes is None or complete["guestShutdownSha256"]
                      == _digest(guest_shutdown_bytes))
                 and _valid_stop_evidence(complete["stopEvidence"]), "invalid_completion")
        return True
    finally:
        os.close(fd)


class State(AbstractContextManager):
    """Hold one non-waiting root lock across admission and the supervised run."""

    def __init__(self, root):
        """Bind this controller state to its root-owned directory."""
        self.root = Path(root)
        self._root_fd = None
        self._lock_fd = None
        self._active = None

    def __enter__(self):
        """Lock the state and reject unresolved retained runs."""
        self._acquire_lock()
        try:
            self._scan()
            return self
        except BaseException:
            self._close()
            raise

    def _acquire_lock(self):
        _require(self._root_fd is None and self._lock_fd is None, "state_already_entered")
        _require(os.geteuid() == recovery.OWNER_UID, "root_required")
        self._root_fd = recovery._directory(self.root)
        try:
            try:
                self._lock_fd = recovery._file(
                    self._root_fd, "controller.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL)
                os.fsync(self._lock_fd)
                os.fsync(self._root_fd)
            except FileExistsError:
                self._lock_fd = recovery._file(self._root_fd, "controller.lock", os.O_RDWR)
            _require(os.fstat(self._lock_fd).st_size == 0, "invalid_controller_lock")
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise recovery.RecoveryError("controller_busy") from error
        except BaseException:
            self._close()
            raise

    def __exit__(self, *_):
        """Release the controller lock and root directory descriptor."""
        self._close()
        return False

    def _close(self):
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def _scan(self, *, allowed_unresolved=None):
        entries = set(os.listdir(self._root_fd))
        _require(entries <= ROOT_ENTRIES | {name for name in entries if RUN_ID.fullmatch(name)},
                 "invalid_state_entries")
        unresolved = []
        for name in sorted(entries - ROOT_ENTRIES):
            info = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == recovery.OWNER_UID
                     and stat.S_IMODE(info.st_mode) == 0o700, "invalid_run_directory")
            if "disposition.plist" in os.listdir(self.root / name):
                _check_disposition(self.root, name)
            elif not _check_run_directory(self.root, name, allow_retained_manifest=True):
                unresolved.append(name)
        _require(set(unresolved) <= ({allowed_unresolved} if allowed_unresolved else set()),
                 "unresolved_run")

    def begin(self, identity):
        _require(self._root_fd is not None and self._active is None, "state_not_ready")
        run_id = uuid.uuid4().hex
        _identity_record(run_id, identity)
        os.mkdir(run_id, 0o700, dir_fd=self._root_fd)
        os.fsync(self._root_fd)
        run_fd = recovery._directory(self.root / run_id)
        try:
            identity_bytes = plistlib.dumps(
                _identity_record(run_id, identity), fmt=plistlib.FMT_BINARY, sort_keys=True)
            recovery._publish(run_fd, "identity.plist", identity_bytes)
        finally:
            os.close(run_fd)
        self._active = (run_id, self.root / run_id, identity_bytes)
        return self._active[1], run_id

    def complete(self, run, stop_evidence):
        _require(self._root_fd is not None and self._active is not None, "state_not_ready")
        run_id, run_path, identity_bytes = self._active
        _require(Path(run) == run_path and run_path.name == run_id, "invalid_active_run")
        _require(_valid_stop_evidence(stop_evidence), "invalid_stop_evidence")
        run_fd = recovery._directory(run_path)
        try:
            entries = set(os.listdir(run_fd))
            required = {"identity.plist", "reserved", "snapshot.plist", "restored", "launch.plist",
                        "stop.plist", "helper-logs", "vm-logs"}
            identity = plistlib.loads(identity_bytes)["identity"]
            probe_mode = "probeIPv4" in identity
            route_mode = "identityProbeIPv4" in identity
            provisioning_mode = "provisioningBundleSha256" in identity
            if "probeIPv4" in identity:
                required.add("probe.plist")
            if "identityProbeIPv4" in identity:
                required.add("route-probe.plist")
            if provisioning_mode:
                required.add("provisioning-download.json")
                required.add("guest-shutdown.plist")
            _require(sum((probe_mode, route_mode, provisioning_mode)) <= 1
                     and ("probe.plist" not in entries or probe_mode)
                     and ("route-probe.plist" not in entries or route_mode)
                     and ("guest-shutdown.plist" not in entries or provisioning_mode)
                     and ("provisioning-download.json" not in entries or provisioning_mode),
                     "invalid_probe_mode")
            _require(entries <= RUN_ENTRIES, "invalid_run_entries")
            _require("disposition.plist" not in entries, "conflicting_disposition")
            if COMMAND_FAILURE_FILE in entries:
                _check_command_failure(run_fd)
                _require(provisioning_mode, "invalid_command_failure_mode")
                raise recovery.RecoveryError("invalid_command_failure_completion")
            _require(required <= entries, "invalid_run_entries")
            _require(recovery._read(run_fd, "identity.plist") == identity_bytes,
                     "invalid_identity")
            _check_launch(run_fd, identity)
            stop_bytes, recorded_stop = _check_stop(run_fd)
            _require(recorded_stop == stop_evidence, "stop_evidence_mismatch")
            _require(recovery._read(run_fd, "reserved") == b"", "invalid_completion")
            snapshot = recovery._read(run_fd, "snapshot.plist")
            restored = recovery._read(run_fd, "restored")
            _require(restored == b"restored\n", "invalid_completion")
            _check_log_directory(run_path.parent, run_id, "helper-logs", complete=True)
            _check_log_directory(run_path.parent, run_id, "vm-logs", complete=True)
            record = {"version": 1, "identitySha256": _digest(identity_bytes),
                      "snapshotSha256": _digest(snapshot), "restoredSha256": _digest(restored),
                      "stopSha256": _digest(stop_bytes),
                      "stopEvidence": stop_evidence}
            if probe_mode:
                probe_bytes, probe = _check_probe(run_fd, identity)
                _require(probe["verified"], "invalid_probe")
                record["probeSha256"] = _digest(probe_bytes)
            if route_mode:
                route_bytes, route_report = _check_route_probe(run_fd, identity)
                _require(route_report["verified"], "invalid_route_probe")
                record["routeProbeSha256"] = _digest(route_bytes)
            if provisioning_mode:
                download_bytes, _ = _check_provisioning_download(run_fd, identity)
                record["provisioningDownloadSha256"] = _digest(download_bytes)
                guest_shutdown_bytes, _ = _check_guest_shutdown(run_fd)
                record["guestShutdownSha256"] = _digest(guest_shutdown_bytes)
            recovery._publish(run_fd, "complete.plist",
                              plistlib.dumps(record, fmt=plistlib.FMT_BINARY, sort_keys=True))
        finally:
            os.close(run_fd)
        self._active = None


def dispose_failed_restored(root, run_id, approval_reference, *, expected_vm_reaped, observe):
    """Record a root operator's disposition using trusted root-installed observation code."""
    _require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id), "invalid_run_id")
    _require(isinstance(approval_reference, str)
             and 0 < len(approval_reference.strip()) <= 256
             and "\x00" not in approval_reference, "invalid_approval_reference")
    _require(type(expected_vm_reaped) is bool, "invalid_expected_vm_reaped")
    _require(callable(observe), "invalid_disposition_observer")
    state = State(root)
    state._acquire_lock()
    try:
        state._scan(allowed_unresolved=run_id)
        run_path = state.root / run_id
        before = _failed_restored_files(
            state.root, run_id, expected_vm_reaped=expected_vm_reaped, allow_legacy_result=True)
        run_fd = recovery._directory(run_path)
        try:
            identity = _plist(recovery._read(run_fd, "identity.plist"), "invalid_identity")["identity"]
        finally:
            os.close(run_fd)
        observation = observe(run_path, identity)
        _observation(observation)
        state._scan(allowed_unresolved=run_id)
        after = _failed_restored_files(
            state.root, run_id, expected_vm_reaped=expected_vm_reaped, allow_legacy_result=True)
        _require(before == after, "disposition_source_changed")
        _require(0 <= time.time_ns() - observation["observedAtUnixNs"] <= 30_000_000_000,
                 "stale_disposition_observation")
        record = {"kind": DISPOSITION_KIND, "version": 1, "runId": run_id,
                  "approvalReference": approval_reference, "observation": observation,
                  "fileSha256": after}
        run_fd = recovery._directory(run_path)
        try:
            recovery._publish(run_fd, "disposition.plist",
                              plistlib.dumps(record, fmt=plistlib.FMT_BINARY, sort_keys=True))
        finally:
            os.close(run_fd)
        state._scan()
    finally:
        state._close()

