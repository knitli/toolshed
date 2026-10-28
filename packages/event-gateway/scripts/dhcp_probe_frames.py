"""Small Ethernet/IPv4/UDP DHCP probe codec for a disposable VM harness."""

import ipaddress
import struct


_COOKIE = b"\x63\x82\x53\x63"
_BROADCAST = b"\xff" * 6
_IP_BROADCAST = b"\xff" * 4
_MAX_FRAME_SIZE = 2048
_MIN_BOOTP_PAYLOAD_SIZE = 300


def _mac_bytes(mac):
    if not isinstance(mac, bytes) or len(mac) != 6 or mac == b"\0" * 6 or mac[0] & 1:
        raise ValueError("MAC must be a nonzero unicast six-byte value")
    return mac


def _xid_bytes(xid):
    if not isinstance(xid, int) or isinstance(xid, bool) or not 0 <= xid <= 0xFFFFFFFF:
        raise ValueError("transaction id must be an unsigned 32-bit integer")
    return struct.pack("!I", xid)


def _client_option(client_id):
    if not isinstance(client_id, bytes) or not 1 <= len(client_id) <= 255:
        raise ValueError("client id must be 1 to 255 opaque bytes")
    return b"\x3d" + bytes((len(client_id),)) + client_id


def _checksum(data):
    if len(data) & 1:
        data += b"\0"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _frame(mac, xid, client_id, request=None):
    mac = _mac_bytes(mac)
    _xid_bytes(xid)
    options = b"\x35\x01" + (b"\x01" if request is None else b"\x03") + _client_option(client_id)
    if request is None:
        options += b"\x37\x05\x01\x03\x06\x33\x36"
    else:
        offered_ip, server_id = request
        options += b"\x32\x04" + ipaddress.IPv4Address(offered_ip).packed
        options += b"\x36\x04" + ipaddress.IPv4Address(server_id).packed
        options += b"\x37\x05\x01\x03\x06\x33\x36"
    options += b"\xff"
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000,
                        b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                        mac + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    payload = bootp + _COOKIE + options
    payload += b"\0" * max(0, _MIN_BOOTP_PAYLOAD_SIZE - len(payload))
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), xid & 0xFFFF,
                            0, 64, 17, 0, b"\0" * 4, _IP_BROADCAST)
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    return _BROADCAST + mac + b"\x08\x00" + ip_header + udp


def build_discover(mac, xid, client_id):
    """Build a broadcast DHCPDISCOVER frame."""
    return _frame(mac, xid, client_id)


def build_request(mac, xid, client_id, offered_ip, server_id):
    """Build a broadcast DHCPREQUEST selecting the offered address and server."""
    return _frame(mac, xid, client_id, (offered_ip, server_id))


def _ipv4_payload(frame):
    if len(frame) > _MAX_FRAME_SIZE:
        raise ValueError("Ethernet frame exceeds maximum size")
    if len(frame) < 14:
        raise ValueError("truncated Ethernet frame")
    if frame[12:14] != b"\x08\x00":
        return None
    if len(frame) < 34:
        raise ValueError("truncated IPv4 packet")
    ip = frame[14:]
    if ip[0] >> 4 != 4 or (ip[0] & 15) < 5:
        raise ValueError("invalid IPv4 header")
    ihl = (ip[0] & 15) * 4
    if len(ip) < ihl:
        raise ValueError("truncated IPv4 header")
    total_length = struct.unpack_from("!H", ip, 2)[0]
    if total_length < ihl + 8 or len(ip) < total_length:
        raise ValueError("invalid or truncated IPv4 length")
    if _checksum(ip[:ihl]) != 0:
        raise ValueError("invalid IPv4 checksum")
    if ip[9] != 17:
        return None
    if struct.unpack_from("!H", ip, 6)[0] & 0x3FFF:
        raise ValueError("fragmented DHCP packet")
    return ip[ihl:total_length]


def _bootp_reply(udp):
    if udp is None:
        return None
    src, dst, udp_length = struct.unpack_from("!HHH", udp)
    if (src, dst) != (67, 68):
        return None
    if udp_length < 8 + 240 or udp_length != len(udp):
        raise ValueError("invalid or truncated UDP length")
    bootp = udp[8:]
    if bootp[0] != 2 or bootp[1:3] != b"\x01\x06":
        raise ValueError("invalid BOOTREPLY hardware fields")
    if bootp[236:240] != _COOKIE:
        raise ValueError("invalid DHCP cookie")
    return bootp


def _parse_options(options):
    values = {}
    pos = 0
    ended = False
    while pos < len(options):
        code = options[pos]
        pos += 1
        if code == 0:
            continue
        if code == 255:
            ended = True
            break
        if pos >= len(options):
            raise ValueError("truncated DHCP option length")
        size = options[pos]
        pos += 1
        if pos + size > len(options):
            raise ValueError("truncated DHCP option value")
        if code in (53, 51, 54):
            if code in values:
                raise ValueError("duplicate required DHCP option")
            values[code] = options[pos:pos + size]
        pos += size
    if not ended:
        raise ValueError("missing DHCP end option")
    if any(code not in values for code in (53, 51, 54)):
        raise ValueError("missing required DHCP option")
    if len(values[53]) != 1 or len(values[51]) != 4 or len(values[54]) != 4:
        raise ValueError("invalid required DHCP option length")
    return values


def parse_reply(frame, mac, xid, message_type, server_id=None):
    """Return yiaddr/server_id/lease_seconds, None for unrelated frames, or ValueError for malformed replies."""
    mac = _mac_bytes(mac)
    xid_bytes = _xid_bytes(xid)
    if message_type not in (2, 5):
        raise ValueError("expected message type must be OFFER (2) or ACK (5)")
    expected_server = ipaddress.IPv4Address(server_id).packed if server_id is not None else None
    udp = _ipv4_payload(frame)
    bootp = _bootp_reply(udp)
    if bootp is None or bootp[4:8] != xid_bytes or bootp[28:34] != mac:
        return None
    values = _parse_options(bootp[240:])
    if values[53][0] not in (2, 5) or values[53][0] != message_type:
        raise ValueError("unexpected DHCP message type")
    if expected_server is not None and values[54] != expected_server:
        raise ValueError("DHCP reply came from an unexpected server")
    return {
        "yiaddr": str(ipaddress.IPv4Address(bootp[16:20])),
        "server_id": str(ipaddress.IPv4Address(values[54])),
        "lease_seconds": struct.unpack("!I", values[51])[0],
    }
