"""Keep the foreground smoke responsive to arbitrarily split PTY queries."""

from pathlib import Path
import runpy
import unittest
from unittest.mock import patch


SOURCE = (
    Path(__file__).resolve().parents[1]
    / "docs/native-bridge/native-release-launcher-smoke.py"
)


class NativeReleaseSmokeTests(unittest.TestCase):
    def test_cursor_query_split_at_every_boundary_gets_one_response(self):
        drain = runpy.run_path(str(SOURCE), run_name="smoke_test")["drain"]
        query = b"\x1b[6n"
        for split in range(1, len(query)):
            with self.subTest(split=split):
                tail = bytearray()
                with (
                    patch("select.select", return_value=([7], [], [])),
                    patch(
                        "os.read",
                        side_effect=[query[:split], query[split:], b"other output"],
                    ),
                    patch("os.write") as write,
                ):
                    drain(7, tail)
                    write.assert_not_called()
                    drain(7, tail)
                    drain(7, tail)
                    write.assert_called_once_with(7, b"\x1b[1;1R")


if __name__ == "__main__":
    unittest.main()
