"""One fixed anonymous HTTPS observation for the native guest identity probe."""

import hashlib
import http.client
import ipaddress
import json
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


class ProbeError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _target(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
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
    expired = threading.Event()
    finished = threading.Event()

    def abort_at_deadline():
        if not finished.is_set():
            expired.set()
            if raw_socket[0] is not None:
                try:
                    raw_socket[0].shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    timer = threading.Timer(TOTAL_TIMEOUT, abort_at_deadline)
    tls_socket = None
    status = 0
    body = b""
    tls_verified = False
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
        tls_socket = ssl.create_default_context().wrap_socket(raw_socket[0], server_hostname=HOST)
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
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("total_timeout")
        tls_socket.settimeout(remaining)
        body = response.read(MAX_BODY + 1)
        status = response.status
        if expired.is_set() or time.monotonic() > deadline:
            error = "total_timeout"
    except ProbeError as probe_error:
        error = probe_error.code
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
        error = "total_timeout" if expired.is_set() else "transport_error"
    finally:
        finished.set()
        timer.cancel()
        if timer.is_alive():
            timer.join(timeout=0.2)
        if tls_socket is not None:
            tls_socket.close()
        elif raw_socket[0] is not None:
            raw_socket[0].close()
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
        "status": status,
        "bodyBytes": len(body),
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "verified": error == "" and status == 200 and body == EXPECTED and len(body) == MAX_BODY,
        "error": error,
    }


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
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
