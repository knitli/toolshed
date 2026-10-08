"""Private socket presence survives late replies without granting a Start."""

import json
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from event_gateway import native_reader
from test_native_bridge import native, peer, receive, send, witness


class NativePresenceTests(unittest.TestCase):
    def test_late_reply_is_discarded_before_fresh_different_thread(self):
        old = witness()
        fresh = {**old, "nonce": 2, "sequence": 2, "threadId": str(uuid4())}
        release = threading.Event()

        def handle(channel):
            self.assertEqual(receive(channel), {"nonce": 1})
            self.assertTrue(release.wait(1))
            send(channel, old)
            self.assertEqual(receive(channel), {"nonce": 2})
            send(channel, fresh)
            self.assertIsNone(receive(channel))

        with peer(handle) as bridge, patch.object(native_reader, "WITNESS_SECONDS", 0.03):
            self.assertIsNone(bridge.challenge_readonly())
            self.assertFalse(bridge.closed)
            self.assertIsNone(bridge.witness)
            release.set()
            self.assertIsNone(bridge.challenge_readonly())
            self.assertFalse(bridge.closed)
            result = bridge.challenge_readonly()
            self.assertEqual(result["threadId"], fresh["threadId"])
            self.assertNotEqual(result["threadId"], old["threadId"])
            self.assertGreater(bridge.valid_until, time.monotonic())
            self.assertLessEqual(bridge.valid_until - time.monotonic(), 0.03)
            self.assertIsNone(bridge.witness)

    def test_split_reply_retains_partial_frame_across_timeouts(self):
        row = witness()
        encoded = json.dumps(row).encode() + b"\n"
        middle, finish = threading.Event(), threading.Event()

        def handle(channel):
            self.assertEqual(receive(channel), {"nonce": 1})
            channel.sendall(encoded[:20])
            self.assertTrue(middle.wait(1))
            channel.sendall(encoded[20:50])
            self.assertTrue(finish.wait(1))
            channel.sendall(encoded[50:])
            self.assertEqual(receive(channel), {"nonce": 2})
            send(channel, {**row, "nonce": 2, "sequence": 2})
            self.assertIsNone(receive(channel))

        with peer(handle) as bridge, patch.object(native_reader, "WITNESS_SECONDS", 0.03):
            self.assertIsNone(bridge.challenge_readonly())
            middle.set()
            self.assertIsNone(bridge.challenge_readonly())
            finish.set()
            self.assertIsNone(bridge.challenge_readonly())
            self.assertFalse(bridge.closed)
            self.assertEqual(bridge.challenge_readonly()["threadId"], row["threadId"])
            self.assertIsNone(bridge.witness)

    def test_readonly_presence_clears_prior_start_grant(self):
        row = witness()

        def handle(channel):
            self.assertEqual(receive(channel), {"nonce": 1})
            send(channel, row)
            self.assertEqual(receive(channel), {"nonce": 2})
            send(channel, {**row, "nonce": 2, "sequence": 2})
            self.assertIsNone(receive(channel))

        with peer(handle) as bridge:
            bridge.challenge()
            self.assertIsNotNone(bridge.witness)
            current = bridge.challenge_readonly()
            self.assertTrue(current["eligible"])
            self.assertIsNone(bridge.witness)
            with self.assertRaises(native_reader.BridgeError):
                bridge.start(native.synthetic_request(current))
            self.assertEqual(bridge.attempts, {})

    def test_malformed_presence_reply_closes_channel(self):
        def handle(channel):
            self.assertEqual(receive(channel), {"nonce": 1})
            send(channel, witness(eligible="true"))
            self.assertIsNone(receive(channel))

        with peer(handle) as bridge:
            with self.assertRaises(native_reader.BridgeError):
                bridge.challenge_readonly()
            self.assertTrue(bridge.closed)
            self.assertIsNone(bridge.witness)

    def test_default_challenge_timeout_still_closes_channel(self):
        def handle(channel):
            self.assertEqual(receive(channel), {"nonce": 1})
            self.assertIsNone(receive(channel))

        with peer(handle) as bridge, patch.object(native_reader, "WITNESS_SECONDS", 0.03):
            with self.assertRaises(native_reader.BridgeError):
                bridge.challenge()
            self.assertTrue(bridge.closed)


if __name__ == "__main__":
    unittest.main()
