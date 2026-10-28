import ipaddress
import struct
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from dhcp_probe_frames import build_discover, build_request, parse_reply


MAC = bytes.fromhex("02 11 22 33 44 55")
XID = 0x12345678
CLIENT_ID = b"opaque\x00id"


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def offer_frame(msg_type=2, xid=XID, chaddr=MAC, server="192.0.2.1", lease=3600,
                extra_options=b"", fragment=0):
    """Independent response fixture builder; deliberately does not use the codec."""
    options = (b"\x35\x01" + bytes((msg_type,)) + b"\x33\x04" + struct.pack("!I", lease)
               + b"\x36\x04" + ipaddress.IPv4Address(server).packed + extra_options + b"\xff")
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0,
                        b"\0" * 4, ipaddress.IPv4Address("192.0.2.44").packed,
                        b"\0" * 8, b"\0" * 4, chaddr + b"\0" * 10,
                        b"\0" * 64, b"\0" * 128) + bytes.fromhex("63 82 53 63") + options
    udp = struct.pack("!HHHH", 67, 68, 8 + len(bootp), 0) + bootp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x4321, fragment,
                     64, 17, 0, ipaddress.IPv4Address("192.0.2.1").packed,
                     ipaddress.IPv4Address("255.255.255.255").packed)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return b"\xff" * 6 + bytes.fromhex("02 00 00 00 00 01") + b"\x08\x00" + ip + udp


class DhcpProbeFramesTests(unittest.TestCase):
    def test_discover_and_request_wire_fields(self):
        discover = build_discover(MAC, XID, CLIENT_ID)
        self.assertEqual(discover[:6], b"\xff" * 6)
        self.assertEqual(discover[6:12], MAC)
        self.assertEqual(discover[12:14], b"\x08\x00")
        ip = discover[14:34]
        self.assertEqual(_checksum(ip), 0)
        self.assertEqual(ip[9], 17)
        udp = discover[34:]
        self.assertEqual(struct.unpack_from("!HHH", udp), (68, 67, len(udp)))
        self.assertEqual(udp[6:8], b"\0\0")
        bootp = udp[8:]
        self.assertEqual(struct.unpack_from("!BBBBIHH", bootp), (1, 1, 6, 0, XID, 0, 0x8000))
        self.assertEqual(bootp[28:34], MAC)
        self.assertEqual(bootp[236:240], bytes.fromhex("63 82 53 63"))
        self.assertIn(b"\x35\x01\x01\x3d" + bytes((len(CLIENT_ID),)) + CLIENT_ID, bootp[240:])

        request = build_request(MAC, XID, CLIENT_ID, "192.0.2.44", "192.0.2.1")
        request_options = request[14 + 20 + 8 + 240:]
        self.assertIn(b"\x35\x01\x03", request_options)
        self.assertIn(b"\x32\x04\xc0\x00\x02\x2c", request_options)
        self.assertIn(b"\x36\x04\xc0\x00\x02\x01", request_options)

    def test_outgoing_bootp_payload_meets_300_octet_minimum(self):
        for frame in (build_discover(MAC, XID, CLIENT_ID),
                      build_request(MAC, XID, CLIENT_ID, "192.0.2.44", "192.0.2.1")):
            udp = frame[34:]
            udp_length = struct.unpack_from("!H", udp, 4)[0]
            bootp = udp[8:udp_length]
            self.assertEqual(len(bootp), 300)
            options = bootp[240:]
            end = options.index(b"\xff")
            self.assertEqual(options[end + 1:], b"\0" * (len(options) - end - 1))

    def test_invalid_identity_and_client_id_bounds_rejected(self):
        for mac, cid in ((b"\x01" + MAC[1:], CLIENT_ID), (MAC, b""), (MAC, b"x" * 256)):
            with self.subTest(mac=mac, client_len=len(cid)), self.assertRaises(ValueError):
                build_discover(mac, XID, cid)
        with self.assertRaises(ValueError):
            build_discover(MAC, -1, CLIENT_ID)

    def test_offer_parser_returns_only_selected_fields(self):
        self.assertEqual(parse_reply(offer_frame(), MAC, XID, 2, "192.0.2.1"), {
            "yiaddr": "192.0.2.44", "server_id": "192.0.2.1", "lease_seconds": 3600,
        })

    def test_ack_parser_accepts_expected_server(self):
        self.assertEqual(parse_reply(offer_frame(msg_type=5), MAC, XID, 5, "192.0.2.1"), {
            "yiaddr": "192.0.2.44", "server_id": "192.0.2.1", "lease_seconds": 3600,
        })

    def test_unrelated_identity_is_ignored(self):
        self.assertIsNone(parse_reply(offer_frame(xid=XID + 1), MAC, XID, 2))
        self.assertIsNone(parse_reply(offer_frame(chaddr=b"\x02\x11\x22\x33\x44\x56"), MAC, XID, 2))

    def test_wrong_expected_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpected DHCP message type"):
            parse_reply(offer_frame(), MAC, XID, 5)

    def test_selected_server_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpected server"):
            parse_reply(offer_frame(), MAC, XID, 2, "192.0.2.9")

    def test_duplicate_required_option_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate required"):
            parse_reply(offer_frame(extra_options=b"\x35\x01\x02"), MAC, XID, 2)

    def test_malformed_option_length_is_rejected(self):
        frame = offer_frame(extra_options=b"\x63\x05\x01")
        with self.assertRaisesRegex(ValueError, "truncated DHCP option value"):
            parse_reply(frame, MAC, XID, 2)

    def test_fragment_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "fragmented"):
            parse_reply(offer_frame(fragment=0x2000), MAC, XID, 2)

    def test_bad_ip_checksum_is_rejected(self):
        frame = bytearray(offer_frame())
        frame[24] ^= 1
        with self.assertRaisesRegex(ValueError, "IPv4 checksum"):
            parse_reply(bytes(frame), MAC, XID, 2)

    def test_truncated_ip_packet_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "truncated IPv4 length"):
            parse_reply(offer_frame()[:-1], MAC, XID, 2)

    def test_oversized_frame_is_rejected(self):
        frame = offer_frame() + b"\0" * (2049 - len(offer_frame()))
        with self.assertRaisesRegex(ValueError, "maximum size"):
            parse_reply(frame, MAC, XID, 2)


if __name__ == "__main__":
    unittest.main()
