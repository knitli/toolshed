import hashlib
import json
import os
from pathlib import Path
import subprocess  # nosec B404 -- Fixed child interpreter tests signal interruption without a shell.
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
import native_workspace_provisioning_downloads as downloads  # noqa: E402


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None):
        """Set the fixture HTTP status, response body and optional headers."""
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.offset = 0
        self.closed = False
        self.close_calls = 0

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, amount=-1):
        if amount == 0:
            return b""
        if self.offset >= len(self.body):
            return b""
        end = len(self.body) if amount < 0 else min(len(self.body), self.offset + amount)
        block = self.body[self.offset:end]
        self.offset = end
        return block

    def read1(self, amount=-1):
        return self.read(amount)

    def isclosed(self):
        return self.closed or self.offset >= len(self.body)

    def close(self):
        self.closed = True
        self.close_calls += 1


def asset(body=b"fixture", url="https://example.test/data.bin", redirects=None, maximum=100):
    return {"name": "data.bin", "url": url, "sha256": hashlib.sha256(body).hexdigest(),
            "maxBytes": maximum, "redirects": redirects or []}


def manifest(item=None):
    return {"kind": downloads.KIND, "qualified": False, "prepared": False,
            "assets": [item or asset()]}


def release_fixture():
    """Provide release bytes and an exact redirect for both transport paths."""
    body = b"release"
    item = asset(body, url="https://ghcr.io/v2/blob",
                 redirects=[{"host": downloads.REDIRECT_HOST, "path": "/download/exact"}])
    redirect = FakeResponse(302, headers={"Location": "https://release-assets.githubusercontent.com/download/exact?token=secret"})
    return body, item, [redirect, FakeResponse(body=body)]


class ProvisioningDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.root = Path(self.temp.name)
        self.ca = self.root / "roots.pem"
        self.ca.write_bytes(b"test CA bundle")
        self.context = Mock()
        self.context.check_hostname = True
        self.context.verify_mode = 2
        self.context_constructor = Mock(return_value=self.context)
        self.context_factory = patch.object(downloads.ssl, "SSLContext", self.context_constructor)
        self.context_factory.start()
        self.addCleanup(self.context_factory.stop)

    def tearDown(self):
        self.temp.cleanup()

    def run_download(self, body=b"fixture", responses=None, item=None, env=None):
        item = item or asset(body=body)
        responses = list(responses or [FakeResponse(body=body)])
        calls = []

        def opener(host, addresses, url, context, timeout, initial):
            calls.append((host, addresses, url, timeout, initial, dict(os.environ)))
            return responses.pop(0)

        output = self.root / "private-output"
        dns = {}
        for record in manifest(item)["assets"]:
            host = downloads._validate_url(record["url"]).hostname
            dns[host] = ["140.82.112.33" if host == "ghcr.io" else "93.184.216.34"]
            for redirect in record["redirects"]:
                dns[redirect["host"]] = ["185.199.108.133"]
        with patch.dict(os.environ, env or {}, clear=False):
            result = downloads.download_all(manifest(item), dns, self.ca,
                hashlib.sha256(self.ca.read_bytes()).hexdigest(), output, opener=opener)
        return result, calls, output

    def test_download_is_hash_checked_private_and_receipt_marks_data_only(self):
        response = FakeResponse(body=b"fixture")
        result, calls, output = self.run_download(responses=[response])
        self.assertEqual(calls[0][4], True)
        self.assertEqual((output.stat().st_mode & 0o777), 0o700)
        self.assertEqual((output / "data.bin").read_bytes(), b"fixture")
        self.assertEqual((output / "data.bin").stat().st_mode & 0o777, 0o600)
        self.assertEqual((output / "receipt.json").stat().st_mode & 0o777, 0o600)
        self.assertFalse((output / "receipt.json.partial").exists())
        self.assertFalse(result["qualified"])
        self.assertFalse(result["prepared"])
        self.assertEqual(result["status"], "downloaded-only")
        self.assertEqual(response.close_calls, 1)
        self.assertEqual(result["manifestSha256"], hashlib.sha256(
            (json.dumps(manifest(), sort_keys=True, indent=2) + "\n").encode()).hexdigest())
        self.assertEqual(result["caBundleSha256"], hashlib.sha256(self.ca.read_bytes()).hexdigest())
        self.assertEqual(result["dnsMap"], {"example.test": ["93.184.216.34"]})
        self.assertEqual(result["assets"][0], {
            "name": "data.bin", "initialUrl": "https://example.test/data.bin",
            "finalHost": "example.test", "finalPath": "/data.bin",
            "selectedIPv4": "93.184.216.34", "status": 200, "redirectCount": 0,
            "outcome": "downloaded", "bytes": 7, "sha256": hashlib.sha256(b"fixture").hexdigest(),
        })

    def test_receipt_survives_partial_writes_and_is_atomically_published(self):
        real_write = os.write
        calls = []

        def short_write(fd, data):
            calls.append(len(data))
            return real_write(fd, data[:max(1, len(data) // 3)])

        with patch.object(downloads.os, "write", side_effect=short_write):
            result, _, output = self.run_download()
        self.assertGreater(len(calls), 2)
        self.assertEqual(json.loads((output / "receipt.json").read_text()), result)
        self.assertFalse((output / "receipt.json.partial").exists())

    def test_redirect_must_match_exact_allowance_and_never_reuses_auth(self):
        body, item, responses = release_fixture()
        redirect, final = responses
        result, calls, _ = self.run_download(body, responses, item)
        self.assertEqual([call[4] for call in calls], [True, False])
        self.assertNotIn("token=secret", json.dumps(result))
        self.assertEqual(calls[1][0], downloads.REDIRECT_HOST)
        self.assertEqual([redirect.close_calls, final.close_calls], [1, 1])
        self.assertEqual(result["assets"][0]["redirectCount"], 1)
        self.assertEqual(result["assets"][0]["selectedIPv4"], "185.199.108.133")

    def test_direct_https_sends_only_fixed_initial_ghcr_auth_and_connects_to_pinned_ips(self):
        _, item, responses = release_fixture()
        redirect, final = responses
        requests = []
        connections = []

        class FakeConnection:
            def __init__(self, host, address, context, timeout):
                self.host, self.address = host, address
                self.request_data = {"headers": {}}
                connections.append(self)

            def putrequest(self, method, path, **kwargs):
                self.request_data.update(method=method, path=path)

            def putheader(self, name, value):
                self.request_data["headers"][name.lower()] = value

            def endheaders(self):
                requests.append(self.request_data.copy())

            def getresponse(self):
                response = responses.pop(0)
                response.fp = Mock()
                return response

            def close(self):
                pass

        output = self.root / "private-output"
        dns = {"ghcr.io": ["140.82.112.33"], downloads.REDIRECT_HOST: ["185.199.108.133"]}
        with (patch.object(downloads, "_PinnedHTTPSConnection", FakeConnection),
              patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9",
                                     "HTTP_AUTHORIZATION": "Bearer ambient",
                                     "COOKIE": "ambient=secret"})):
            receipt = downloads.download_all(manifest(item), dns, self.ca,
                hashlib.sha256(self.ca.read_bytes()).hexdigest(), output)
        self.assertEqual([connection.address for connection in connections],
                         ["140.82.112.33", "185.199.108.133"])
        self.assertEqual(requests[0]["headers"].get("authorization"), "Bearer QQ==")
        self.assertNotIn("authorization", requests[1]["headers"])
        self.assertNotIn("cookie", requests[0]["headers"])
        self.assertNotIn("cookie", requests[1]["headers"])
        self.assertEqual(requests[1]["headers"]["host"], downloads.REDIRECT_HOST)
        self.assertEqual(requests[1]["path"], "/download/exact?token=secret")
        self.assertNotIn("token=secret", json.dumps(receipt))
        self.assertEqual([redirect.close_calls, final.close_calls], [1, 1])

    def test_bad_redirect_is_rejected_before_second_request(self):
        item = asset(url="https://example.test/data.bin",
                     redirects=[{"host": downloads.REDIRECT_HOST, "path": "/allowed"}])
        response = FakeResponse(302, headers={"Location": "https://release-assets.githubusercontent.com/other"})
        responses = [response]
        calls = []

        def opener(*args):
            calls.append(args)
            return responses.pop(0)

        output = self.root / "private-output"
        with self.assertRaisesRegex(ValueError, "redirect_not_allowed"):
            downloads.download_all(manifest(item), {"example.test": ["93.184.216.34"],
                downloads.REDIRECT_HOST: ["185.199.108.133"]}, self.ca,
                hashlib.sha256(self.ca.read_bytes()).hexdigest(), output, opener=opener)
        self.assertEqual(len(calls), 1)
        self.assertEqual(response.close_calls, 1)
        self.assertFalse(output.exists())

    def test_wrong_hash_or_size_cap_removes_partial_output_and_receipt(self):
        item = asset(b"expected", maximum=4)
        bad = {**item, "maxBytes": 32}
        wrong_hash_response = FakeResponse(body=b"different")
        with self.assertRaisesRegex(ValueError, "asset_digest_or_empty_mismatch"):
            self.run_download(b"different", responses=[wrong_hash_response], item=bad)
        self.assertEqual(wrong_hash_response.close_calls, 1)
        self.assertFalse((self.root / "private-output").exists())
        oversized_response = FakeResponse(body=b"12345")
        with self.assertRaisesRegex(ValueError, "asset_size_limit"):
            self.run_download(b"12345", responses=[oversized_response], item=asset(b"12345", maximum=4))
        self.assertEqual(oversized_response.close_calls, 1)
        self.assertFalse((self.root / "private-output").exists())

    def test_non_200_response_is_closed_and_partial_output_is_removed(self):
        response = FakeResponse(503)
        with self.assertRaisesRegex(ValueError, "download_http_status"):
            self.run_download(responses=[response])
        self.assertEqual(response.close_calls, 1)
        self.assertFalse((self.root / "private-output").exists())

    def test_manifest_rejects_noncanonical_or_unsafe_url_and_redirect_schema(self):
        for url in ("http://example.test/x", "https://u@example.test/x", "https://example.test:444/x",
                    "https://example.test/x#frag", "https://example.test/x?query=initial"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                downloads._validate_manifest(manifest(asset(url=url)))
        bad = asset(redirects=[{"host": downloads.REDIRECT_HOST, "pathPrefix": "/x"}])
        with self.assertRaisesRegex(ValueError, "invalid_redirect_allowance"):
            downloads._validate_manifest(manifest(bad))

    def test_ca_bundle_hash_is_required_before_output_creation(self):
        output = self.root / "private-output"
        with self.assertRaisesRegex(ValueError, "ca_bundle_pin_mismatch"):
            downloads.download_all(manifest(), {"example.test": ["93.184.216.34"]},
                                   self.ca, "0" * 64, output, opener=Mock())
        self.assertFalse(output.exists())

    def test_tls_context_uses_the_exact_checked_bundle_bytes(self):
        with patch.object(downloads.ssl, "SSLContext", self.context_constructor):
            context = downloads._tls_context(self.ca.read_bytes())
        self.assertIs(context, self.context)
        self.context_constructor.assert_called_with(downloads.ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations.assert_called_once_with(cadata="test CA bundle")

    def test_deadline_is_checked_between_individual_read1_chunks(self):
        class OneByteResponse(FakeResponse):
            def read1(self, amount=-1):
                return self.read(1)

        response = OneByteResponse(body=b"ab")
        output = self.root / "partial"
        output.mkdir(mode=0o700)
        with patch.object(downloads.time, "monotonic", side_effect=[0, 0, 0, 0, 11]):
            with self.assertRaisesRegex(TimeoutError, "download_total_timeout"):
                downloads._download_asset(asset(b"ab"), {"example.test": ["93.184.216.34"]},
                    self.context, output, 10, 100,
                    opener=lambda *_args: response)
        self.assertEqual(response.close_calls, 1)
        self.assertFalse((output / "data.bin").exists())

    def test_absolute_deadline_alarm_raises_and_restores_prior_handler(self):
        old_handler = Mock()
        installed = []
        set_timer = Mock()

        def install_handler(_signal, handler):
            installed.append(handler)
            return old_handler

        with (patch.object(downloads.signal, "getsignal", return_value=old_handler),
              patch.object(downloads.signal, "getitimer", return_value=(0.0, 0.0)),
              patch.object(downloads.signal, "signal", side_effect=install_handler) as signal_call,
              patch.object(downloads.signal, "setitimer", set_timer)):
            with self.assertRaisesRegex(TimeoutError, "download_deadline"):
                with downloads._absolute_deadline(downloads.time.monotonic() + 60):
                    installed[0](downloads.signal.SIGALRM, None)
        self.assertEqual(installed[1], old_handler)
        self.assertEqual(set_timer.call_count, 2)
        self.assertEqual(set_timer.call_args_list[0].args[0], downloads.signal.ITIMER_REAL)
        self.assertEqual(set_timer.call_args_list[1].args,
                         (downloads.signal.ITIMER_REAL, 0))
        signal_call.assert_any_call(downloads.signal.SIGALRM, old_handler)

    def test_real_deadline_interrupts_blocking_pipe_read_in_child_process(self):
        child = r'''
import os
import sys
import time
sys.path.insert(0, sys.argv[1])
import native_workspace_provisioning_downloads as downloads
read_fd, write_fd = os.pipe()
try:
    try:
        with downloads._absolute_deadline(time.monotonic() + 0.05):
            os.read(read_fd, 1)
    except TimeoutError as error:
        if str(error) != "download_deadline":
            raise
    else:
        raise SystemExit("blocking read returned without deadline")
finally:
    os.close(read_fd)
    os.close(write_fd)
print("pipe-read-interrupted")
'''
        # Repository-controlled child/code, shell=False and a five-second timeout isolate signal behavior.
        result = subprocess.run([sys.executable, "-c", child, str(SCRIPT_DIR)],  # nosec B603
                                shell=False, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "pipe-read-interrupted\n")
        self.assertEqual(result.stderr, "")

    def test_manifest_loader_reads_fixed_path_and_checks_exact_pin(self):
        doc = manifest()
        raw = json.dumps(doc, separators=(",", ":")).encode()
        fixed = self.root / downloads.MANIFEST
        fixed.parent.mkdir(parents=True)
        fixed.write_bytes(raw)
        with patch.object(downloads, "MANIFEST_SHA256", hashlib.sha256(raw).hexdigest()):
            self.assertEqual(downloads.load_manifest(self.root), doc)
        with patch.object(downloads, "MANIFEST_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "manifest_pin_mismatch"):
                downloads.load_manifest(self.root)

    def test_checked_in_manifest_matches_its_pin_and_fixed_inventory(self):
        document = downloads.load_manifest()
        assets = document["assets"]
        self.assertEqual(len(assets), 120)
        bottles = {item["name"] for item in assets if item["name"].startswith("bottle-")}
        self.assertEqual(len(bottles), 113)
        self.assertTrue({"bottle-glib.tar.gz", "bottle-gstreamer.tar.gz", "bottle-pkgconf.tar.gz",
                         "bottle-just.tar.gz", "bottle-coreutils.tar.gz"} <= bottles)
        self.assertEqual(sum(item["maxBytes"] for item in assets), 445949854)
        self.assertLessEqual(sum(item["maxBytes"] for item in assets), downloads.MAX_TOTAL_BYTES)
        self.assertEqual({downloads._validate_url(item["url"]).hostname for item in assets},
                         {"ghcr.io", "static.rust-lang.org", "github.com"})
        self.assertEqual(sum(bool(item["redirects"]) for item in assets), 1)

    def test_pinned_tls_connection_uses_ip_socket_and_manifest_host_sni(self):
        connection = downloads._PinnedHTTPSConnection("assets.example", "93.184.216.34", self.context, 7)
        raw = Mock()
        wrapped = Mock()
        self.context.wrap_socket.return_value = wrapped
        with patch.object(downloads.socket, "create_connection", return_value=raw) as create:
            connection.connect()
        create.assert_called_once_with(("93.184.216.34", 443), 7)
        self.context.wrap_socket.assert_called_once_with(raw, server_hostname="assets.example")
        self.assertIs(connection.sock, wrapped)

    def test_runtime_guard_fails_closed_outside_supported_host(self):
        with patch.object(downloads.sys, "platform", "linux"), patch.object(downloads.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(RuntimeError, "runtime_requires_macos_arm64"):
                downloads._runtime_guard()

    def test_runtime_guard_rejects_this_macos27_host_before_reading_inputs(self):
        with (patch.object(downloads.sys, "platform", "darwin"),
              patch.object(downloads.platform, "machine", return_value="arm64"),
              patch.object(downloads.platform, "mac_ver", return_value=("27.0.1", (), "")),
              patch.object(downloads, "load_manifest", side_effect=AssertionError("manifest load reached")) as load):
            with self.assertRaisesRegex(RuntimeError, "runtime_requires_macos15_python313"):
                downloads.main(["--dns-map", "/private/tmp/dns.json", "--ca-bundle", "/private/tmp/roots.pem",
                                "--ca-sha256", "0" * 64, "--output", "/private/tmp/out"])
        load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
