"""One fixed anonymous HTTPS observation for the native guest identity probe."""

import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
import threading
import time

HOST = "event-native-probe-83fc4c309835.knitli.workers.dev"
PATH = "/probe"
EXPECTED = b"knitli-probe-v1\n"
PORT = 443
CONNECT_TIMEOUT = 5.0
TOTAL_TIMEOUT = 15.0
MAX_BODY = 16
USER_AGENT = "knitli-event-native-probe/83fc4c309835"
POSITIVE_HOST = "knitli.app"
POSITIVE_PATH = "/site.webmanifest"
POSITIVE_CONTENT_TYPE = "application/manifest+json"
POSITIVE_BODY_BYTES = 456
POSITIVE_BODY_SHA256 = "096b1a4b927c04b0417ab1f49372e110c96d4db153cf3d6048f9d25c8b11d493"
ROUTE_TIMEOUT = 12.0
ROUTE_LEG_TIMEOUT = 5.0
ROUTE_MAX_BODY = 8 * 1024
ROUTE_MAX_REPORT = 4 * 1024
ROUTE_MAX_CA_CERTS = 512
ROUTE_MAX_CA_BYTES = 2 * 1024 * 1024
ROUTE_USER_AGENT = "knitli-event-native-guest-route/1"
# Gateway inspection uses this account CA, absent from the disposable guest's system bundle.
GATEWAY_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIDHTCCAsOgAwIBAgIUPtX8/cZsXvA2nXi+X+2mi1EBd+0wCgYIKoZIzj0EAwIw
gcAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMRkwFwYDVQQKExBDbG91ZGZsYXJlLCBJbmMuMRswGQYDVQQL
ExJ3d3cuY2xvdWRmbGFyZS5jb20xTDBKBgNVBAMTQ0dhdGV3YXkgQ0EgLSBDbG91
ZGZsYXJlIE1hbmFnZWQgRzEgNWRlZjUyNTkxOGE3ODVlZWRhNmRlY2Y2NmNmNmI5
OWIwHhcNMjUwMzI3MjIxMTAwWhcNMzAwMzI3MjIxMTAwWjCBwDELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28x
GTAXBgNVBAoTEENsb3VkZmxhcmUsIEluYy4xGzAZBgNVBAsTEnd3dy5jbG91ZGZs
YXJlLmNvbTFMMEoGA1UEAxNDR2F0ZXdheSBDQSAtIENsb3VkZmxhcmUgTWFuYWdl
ZCBHMSA1ZGVmNTI1OTE4YTc4NWVlZGE2ZGVjZjY2Y2Y2Yjk5YjBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABGU2lmMwAVyzI/yc/ic5/MORMFaBv+0eLhj87rSdnI+A
GXtXF+Q0zfZT+1iaBXvuYUw6vbdzHBenmET1yYRTy5SjgZgwgZUwDgYDVR0PAQH/
BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFGsxo456KDdUP0ZgYjGl
q0hB8lURMFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jcmwuY2xvdWRmbGFyZS5j
b20vMzMwMGJkYmYtZWJkYS00NjE1LTlkYmMtNmRjOTU1NTA4YjQ3LmNybDAKBggq
hkjOPQQDAgNIADBFAiEA4YyckDdhuNZ/+UzyZQ3qxgdWEHwb7aKJ7tnG3NCleIoC
IDIkVX0GDj9oLOkWbXULm36mRFEs+h+X4RSffYJfrk2S
-----END CERTIFICATE-----"""


class ProbeError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _target(value):
    if not isinstance(value, str):
        raise ProbeError("destination_invalid")
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        raise ProbeError("destination_invalid") from None
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise ProbeError("destination_invalid")
    return str(address)


def probe_once(destination):
    """Connect to the host-pinned IP while retaining fixed HTTP Host and TLS SNI."""
    destination = _target(destination)
    started_ns = time.time_ns()
    deadline = time.monotonic() + TOTAL_TIMEOUT
    raw_socket = [None]
    abort_socket = [None]
    expired = threading.Event()
    finished = threading.Event()

    def abort_at_deadline():
        if not finished.is_set():
            expired.set()
            target = abort_socket[0] or raw_socket[0]
            if target is not None:
                try:
                    target.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    timer = threading.Timer(TOTAL_TIMEOUT, abort_at_deadline)
    tls_socket = None
    status = 0
    body = b""
    tls_verified = False
    gateway_context_verified = False
    expected_host_posture_passed = False
    error = ""
    try:
        timer.start()
        if expired.is_set():
            raise ProbeError("total_timeout")
        raw_socket[0] = socket.create_connection((destination, PORT), timeout=CONNECT_TIMEOUT)
        remaining = deadline - time.monotonic()
        if expired.is_set() or remaining <= 0:
            raise ProbeError("total_timeout")
        raw_socket[0].settimeout(remaining)
        # Keep a second descriptor because wrap_socket detaches the raw Python socket;
        # the deadline thread needs an owned handle throughout handshake and response reads.
        abort_socket[0] = socket.socket(fileno=os.dup(raw_socket[0].fileno()))
        tls_socket = ssl.create_default_context(cadata=GATEWAY_CA_PEM).wrap_socket(
            raw_socket[0], server_hostname=HOST, do_handshake_on_connect=False)
        tls_socket.settimeout(remaining)
        tls_socket.do_handshake()
        tls_verified = True
        remaining = deadline - time.monotonic()
        if expired.is_set() or remaining <= 0:
            raise ProbeError("total_timeout")
        tls_socket.settimeout(remaining)
        tls_socket.sendall(
            (f"GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: {USER_AGENT}\r\n"
             "Connection: close\r\n\r\n").encode("ascii"))
        response = http.client.HTTPResponse(tls_socket)
        response.begin()
        gateway_marker = response.getheader("x-knitli-probe-gateway")
        host_posture = response.getheader("x-knitli-probe-host")
        gateway_context_verified = (gateway_marker == "v1" and host_posture in {"0", "1"})
        expected_host_posture_passed = host_posture == "1"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("total_timeout")
        tls_socket.settimeout(remaining)
        body = response.read(MAX_BODY + 1)
        status = response.status
        if not gateway_context_verified:
            error = "gateway_context_invalid"
        if expired.is_set() or time.monotonic() > deadline:
            error = "total_timeout"
    except ProbeError as probe_error:
        error = probe_error.code
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
        error = ("total_timeout" if expired.is_set() or time.monotonic() >= deadline
                 else "transport_error")
    finally:
        finished.set()
        timer.cancel()
        if timer.is_alive():
            timer.join(timeout=0.2)
        if tls_socket is not None:
            tls_socket.close()
        elif raw_socket[0] is not None:
            raw_socket[0].close()
        if abort_socket[0] is not None:
            abort_socket[0].close()
    if expired.is_set() or time.monotonic() >= deadline:
        error = "total_timeout"
    finished_ns = time.time_ns()
    return {
        "kind": "native-guest-public-probe-v1",
        "method": "GET",
        "host": HOST,
        "path": PATH,
        "destinationIPv4": destination,
        "port": PORT,
        "startedAtUnixNs": started_ns,
        "finishedAtUnixNs": finished_ns,
        "tlsVerified": tls_verified,
        "gatewayContextVerified": gateway_context_verified,
        "expectedHostPosturePassed": expected_host_posture_passed,
        "status": status,
        "bodyBytes": len(body),
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "verified": (error == "" and gateway_context_verified and status == 200
                     and body == EXPECTED and len(body) == MAX_BODY),
        "error": error,
    }


def _route_request(host, path, destination, deadline, total_expired, context):
    """Make one bounded request using fixed host identity and the guest default roots."""
    destination = _target(destination)
    started = time.monotonic()
    leg_deadline = min(deadline, started + ROUTE_LEG_TIMEOUT)
    raw_socket = [None]
    abort_socket = None
    tls_socket = None
    leg_expired = threading.Event()
    finished = threading.Event()

    def abort_at_deadline():
        if not finished.is_set():
            leg_expired.set()
            target = abort_socket or raw_socket[0]
            if target is not None:
                try:
                    target.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    timer = threading.Timer(max(0.001, leg_deadline - time.monotonic()), abort_at_deadline)
    try:
        timer.start()
        remaining = leg_deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("timeout")
        raw_socket[0] = socket.create_connection((destination, PORT), timeout=remaining)
        abort_socket = socket.socket(fileno=os.dup(raw_socket[0].fileno()))
        remaining = leg_deadline - time.monotonic()
        if total_expired.is_set() or leg_expired.is_set() or remaining <= 0:
            raise ProbeError("timeout")
        raw_socket[0].settimeout(remaining)
        tls_socket = context.wrap_socket(raw_socket[0], server_hostname=host,
                                         do_handshake_on_connect=False)
        tls_socket.settimeout(remaining)
        tls_socket.do_handshake()
        tls_verified = True
        tls_socket.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                            f"User-Agent: {ROUTE_USER_AGENT}\r\nConnection: close\r\n\r\n").encode("ascii"))
        response = http.client.HTTPResponse(tls_socket)
        response.begin()
        status = response.status
        content_type = response.getheader("Content-Type", "").strip().lower()
        if content_type != POSITIVE_CONTENT_TYPE:
            content_type = ""
        cache_control = response.getheader("Cache-Control", "")
        no_store = any(part.strip().lower() == "no-store"
                       for part in cache_control.split(","))
        no_gateway_markers = (response.getheader("x-knitli-probe-gateway") is None
                              and response.getheader("x-knitli-probe-host") is None)
        remaining = leg_deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("timeout")
        tls_socket.settimeout(remaining)
        body = response.read(ROUTE_MAX_BODY + 1)
        if len(body) > ROUTE_MAX_BODY:
            raise ProbeError("body_too_large")
        if total_expired.is_set() or leg_expired.is_set() or time.monotonic() >= leg_deadline:
            raise ProbeError("timeout")
        return {"status": status, "tlsVerified": tls_verified, "bodyBytes": len(body),
                "bodySha256": hashlib.sha256(body).hexdigest(), "contentType": content_type,
                "noStore": no_store, "noGatewayMarkers": no_gateway_markers,
                "error": ""}, body
    except ProbeError as error:
        return {"status": 0, "tlsVerified": False, "bodyBytes": 0,
                "bodySha256": hashlib.sha256(b"").hexdigest(), "contentType": "",
                "noStore": False, "noGatewayMarkers": False, "error": error.code}, b""
    except ssl.SSLError:
        return {"status": 0, "tlsVerified": False, "bodyBytes": 0,
                "bodySha256": hashlib.sha256(b"").hexdigest(), "contentType": "",
                "noStore": False, "noGatewayMarkers": False, "error": "tls_error"}, b""
    except (OSError, http.client.HTTPException, TimeoutError):
        code = ("timeout" if total_expired.is_set() or leg_expired.is_set()
                or time.monotonic() >= leg_deadline else "transport_error")
        return {"status": 0, "tlsVerified": False, "bodyBytes": 0,
                "bodySha256": hashlib.sha256(b"").hexdigest(), "contentType": "",
                "noStore": False, "noGatewayMarkers": False, "error": code}, b""
    finally:
        finished.set()
        timer.cancel()
        if timer.is_alive():
            timer.join(timeout=0.2)
        if tls_socket is not None:
            tls_socket.close()
        elif raw_socket[0] is not None:
            raw_socket[0].close()
        if abort_socket is not None:
            abort_socket.close()


def _public_context(expected_roots_sha256):
    # Python/OpenSSL honors these variables; they would redirect roots outside the guest image.
    if "SSL_CERT_FILE" in os.environ or "SSL_CERT_DIR" in os.environ:
        raise ProbeError("trust_override")
    try:
        context = ssl.create_default_context()
        certs = context.get_ca_certs(binary_form=True)
    except (OSError, ssl.SSLError, TypeError, ValueError):
        raise ProbeError("trust_roots_invalid") from None
    if not isinstance(certs, (list, tuple)) or not 0 < len(certs) <= ROUTE_MAX_CA_CERTS:
        raise ProbeError("trust_roots_invalid")
    if any(not isinstance(cert, bytes) or not cert for cert in certs) \
            or sum(map(len, certs)) > ROUTE_MAX_CA_BYTES:
        raise ProbeError("trust_roots_invalid")
    by_fingerprint = {hashlib.sha256(cert).hexdigest(): cert for cert in certs}
    fingerprints = sorted(by_fingerprint)
    roots_sha256 = hashlib.sha256("\n".join(fingerprints).encode("ascii")).hexdigest()
    gateway_der = ssl.PEM_cert_to_DER_cert(GATEWAY_CA_PEM)
    gateway_ca_absent = hashlib.sha256(gateway_der).hexdigest() not in fingerprints
    if roots_sha256 != expected_roots_sha256 or not gateway_ca_absent:
        raise ProbeError("trust_roots_mismatch")
    pem_bundle = "".join(ssl.DER_cert_to_PEM_cert(by_fingerprint[fingerprint])
                          for fingerprint in fingerprints)
    try:
        route_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        route_context.verify_mode = ssl.CERT_REQUIRED
        route_context.check_hostname = True
        route_context.load_verify_locations(cadata=pem_bundle)
        effective_fingerprints = sorted({hashlib.sha256(cert).hexdigest()
                                         for cert in route_context.get_ca_certs(binary_form=True)})
    except (OSError, ssl.SSLError, TypeError, ValueError):
        raise ProbeError("trust_roots_invalid") from None
    effective_sha256 = hashlib.sha256("\n".join(effective_fingerprints).encode("ascii")).hexdigest()
    if effective_fingerprints != fingerprints or effective_sha256 != expected_roots_sha256:
        raise ProbeError("trust_roots_mismatch")
    return route_context, roots_sha256, gateway_ca_absent


def route_contract(identity_destination, positive_destination, expected_roots_sha256):
    """Observe exactly the fixed public origin and identity route, in positive-first order."""
    identity_destination = _target(identity_destination)
    positive_destination = _target(positive_destination)
    started_ns = time.time_ns()
    if not isinstance(expected_roots_sha256, str) or len(expected_roots_sha256) != 64 \
            or any(character not in "0123456789abcdef" for character in expected_roots_sha256):
        return _fixed_failure_report(identity_destination, positive_destination,
                                     started_ns, "trust_roots_invalid")
    try:
        context, roots_sha256, gateway_ca_absent = _public_context(expected_roots_sha256)
    except ProbeError as error:
        if error.code not in {"trust_override", "trust_roots_invalid", "trust_roots_mismatch"}:
            raise
        return _fixed_failure_report(identity_destination, positive_destination,
                                     started_ns, error.code)
    deadline = time.monotonic() + ROUTE_TIMEOUT
    expired = threading.Event()
    timer = threading.Timer(ROUTE_TIMEOUT, expired.set)
    timer.start()
    try:
        positive, positive_body = _route_request(
            POSITIVE_HOST, POSITIVE_PATH, positive_destination, deadline, expired, context)
        identity, identity_body = _route_request(
            HOST, PATH, identity_destination, deadline, expired, context)
    finally:
        timer.cancel()
        if timer.is_alive():
            timer.join(timeout=0.2)
    positive_ok = (positive["error"] == "" and positive["tlsVerified"]
                   and positive["status"] == 200
                   and positive["contentType"] == POSITIVE_CONTENT_TYPE
                   and positive["bodyBytes"] == POSITIVE_BODY_BYTES
                   and positive["bodySha256"] == POSITIVE_BODY_SHA256)
    identity_ok = (identity["error"] == "" and identity["tlsVerified"]
                   and identity["status"] == 404 and identity["bodyBytes"] == 0
                   and identity["bodySha256"] == hashlib.sha256(b"").hexdigest()
                   and identity["noStore"] and identity["noGatewayMarkers"])
    error = "" if positive_ok and identity_ok else (
        positive["error"] or identity["error"] or "predicate_failed")
    report = {
        "kind": "native-guest-route-contract-v1",
        "identityHost": HOST, "identityPath": PATH,
        "identityDestinationIPv4": identity_destination,
        "identityStatus": identity["status"], "identityTlsVerified": identity["tlsVerified"],
        "identityBodyBytes": identity["bodyBytes"], "identityBodySha256": identity["bodySha256"],
        "identityNoStore": identity["noStore"],
        "identityNoGatewayMarkers": identity["noGatewayMarkers"],
        "identityError": identity["error"],
        "positiveHost": POSITIVE_HOST, "positivePath": POSITIVE_PATH,
        "positiveDestinationIPv4": positive_destination,
        "positiveStatus": positive["status"], "positiveTlsVerified": positive["tlsVerified"],
        "positiveContentType": positive["contentType"],
        "positiveBodyBytes": positive["bodyBytes"], "positiveBodySha256": positive["bodySha256"],
        "positiveError": positive["error"],
        "publicTrustRootsSha256": roots_sha256, "gatewayCaAbsent": gateway_ca_absent,
        "startedAtUnixNs": started_ns, "finishedAtUnixNs": time.time_ns(),
        "verified": positive_ok and identity_ok, "error": error,
    }
    if len(json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")) > ROUTE_MAX_REPORT:
        return _fixed_failure_report(
            identity_destination, positive_destination, started_ns, "report_too_large",
            roots_sha256=roots_sha256, gateway_ca_absent=gateway_ca_absent)
    return report


def _fixed_failure_report(identity_destination, positive_destination, started_ns, error,
                          *, roots_sha256="", gateway_ca_absent=False):
    # The fixed fields and canonical IPs, with at most one 64-hex roots hash, keep this fallback
    # below the 4 KiB route-report cap even when the attempted success report exceeded it.
    preflight_errors = {"trust_override", "trust_roots_invalid", "trust_roots_mismatch"}
    if error not in preflight_errors | {"report_too_large"}:
        raise ProbeError("invalid_route_failure")
    if error == "report_too_large":
        if (not isinstance(roots_sha256, str) or len(roots_sha256) != 64
                or any(character not in "0123456789abcdef" for character in roots_sha256)
                or gateway_ca_absent is not True):
            raise ProbeError("invalid_route_failure")
    elif roots_sha256 != "" or gateway_ca_absent is not False:
        raise ProbeError("invalid_route_failure")
    empty_hash = hashlib.sha256(b"").hexdigest()
    report = {
        "kind": "native-guest-route-contract-v1",
        "identityHost": HOST, "identityPath": PATH,
        "identityDestinationIPv4": identity_destination, "identityStatus": 0,
        "identityTlsVerified": False, "identityBodyBytes": 0,
        "identityBodySha256": empty_hash, "identityNoStore": False,
        "identityNoGatewayMarkers": False, "identityError": error,
        "positiveHost": POSITIVE_HOST, "positivePath": POSITIVE_PATH,
        "positiveDestinationIPv4": positive_destination, "positiveStatus": 0,
        "positiveTlsVerified": False, "positiveContentType": "",
        "positiveBodyBytes": 0, "positiveBodySha256": empty_hash,
        "positiveError": error, "publicTrustRootsSha256": roots_sha256,
        "gatewayCaAbsent": gateway_ca_absent, "startedAtUnixNs": started_ns,
        "finishedAtUnixNs": time.time_ns(), "verified": False, "error": error,
    }
    return report


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 4 and args[0] == "--guest-route-contract":
        try:
            report = route_contract(args[1], args[2], args[3])
        except ProbeError as error:
            report = {"kind": "native-guest-route-contract-v1", "verified": False,
                      "error": error.code}
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    if len(args) != 1:
        print('{"kind":"native-guest-public-probe-v1","verified":false,"error":"invalid_arguments"}')
        return 0
    try:
        report = probe_once(args[0])
    except ProbeError as error:
        report = {"kind": "native-guest-public-probe-v1", "verified": False,
                  "error": error.code}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
