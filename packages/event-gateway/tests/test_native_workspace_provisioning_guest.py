"""Offline contract tests for the bounded provisioning guest stdin transport."""

import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import native_workspace_provisioning_downloads as downloader  # noqa: E402
import native_workspace_provisioning_guest as guest  # noqa: E402


def _digest(data):
    return hashlib.sha256(data).hexdigest()


class NativeWorkspaceProvisioningGuestTests(unittest.TestCase):
    """Exercise host verification and the fixed receiver without network access."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest_raw = (guest.ROOT / guest.MANIFEST_PATH).read_bytes()
        self.manifest = downloader._json_no_duplicates(self.manifest_raw)
        self.dns = {}
        for asset in self.manifest["assets"]:
            self.dns[downloader._validate_url(asset["url"]).hostname] = ["1.1.1.1"]
            for redirect in asset["redirects"]:
                self.dns[redirect["host"]] = ["1.0.0.1"]
        self.ca = b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"

    def test_build_bundle_pins_exact_closure_and_rejects_dns_drift(self):
        bundle = guest.build_bundle(guest.ROOT, self.ca, self.dns)
        document = json.loads(bundle["payload"])
        self.assertEqual(set(document), {"kind", "sourceBase64", "sourceSha256", "manifestBase64",
                                        "manifestSha256", "caBundleBase64", "caBundleSha256", "dnsMap"})
        self.assertEqual(document["kind"], guest.KIND)
        self.assertEqual(document["manifestSha256"], guest.MANIFEST_SHA256)
        self.assertEqual(document["sourceSha256"], guest.SOURCE_SHA256)
        self.assertEqual(_digest(bundle["payload"]), bundle["bundleSha256"])
        self.assertLessEqual(len(bundle["payload"]), guest.MAX_BUNDLE_BYTES)
        self.assertEqual(base64.b64decode(document["caBundleBase64"], validate=True), self.ca)
        bad_dns = dict(self.dns)
        bad_dns[next(iter(bad_dns))] = ["127.0.0.1"]
        with self.assertRaisesRegex(ValueError, "invalid_dns_map_address"):
            guest.build_bundle(guest.ROOT, self.ca, bad_dns)

    def test_default_protected_closure_accepts_large_ca_fixture_under_transport_cap(self):
        ca_bytes = bytes(range(256)) * 1302 + bytes(range(171))
        self.assertEqual(len(ca_bytes), 333483)
        bundle = guest.build_bundle(guest.ROOT, ca_bytes, self.dns)
        self.assertLess(len(bundle["payload"]), guest.MAX_BUNDLE_BYTES)
        self.assertEqual(bundle["caBundleSha256"], _digest(ca_bytes))

    def test_command_uses_fixed_stdin_receiver_without_payload_or_secrets_in_argv(self):
        bundle = guest.build_bundle(guest.ROOT, self.ca, self.dns)
        argv = guest.command_template("/fixed/tart", "owned-vm")
        self.assertEqual(argv[:4], ["/fixed/tart", "exec", "-i", "owned-vm"])
        self.assertIn("-c", argv)
        self.assertEqual(argv[-1], bundle["loader"])
        self.assertNotIn(bundle["payload"].decode(), argv)
        self.assertNotIn(self.ca.decode(), "\0".join(argv))
        self.assertEqual(argv[-5:-2], ["/opt/homebrew/bin/python3", "-I", "-B"])
        loader = argv[-1]
        self.assertLess(loader.index("sys.version_info < (3, 13)"), loader.index("sys.stdin.buffer.read"))
        self.assertLess(loader.index("version[0] != 15"), loader.index("tempfile.mkdtemp"))

    def _fixture_bundle(self):
        """Prepare a known stub source; its fixed entry records writes and never downloads."""
        source = b'''\
import json
from pathlib import Path

def _runtime_guard():
    pass

def _validate_manifest(value):
    if type(value) is not dict:
        raise ValueError("bad_manifest")

def _parse_dns_map(raw, manifest):
    return json.loads(raw)

def load_manifest(root):
    path = Path(root) / "packages/event-gateway/docs/native-bridge/native-workspace-provisioning-assets.json"
    return json.loads(path.read_bytes())

def download_all(manifest, dns, ca, ca_sha, output):
    root = Path(__file__).resolve().parents[3]
    source_path = root / "packages/event-gateway/scripts/native_workspace_provisioning_downloads.py"
    manifest_path = root / "packages/event-gateway/docs/native-bridge/native-workspace-provisioning-assets.json"
    assert source_path.stat().st_mode & 0o777 == 0o600
    assert manifest_path.stat().st_mode & 0o777 == 0o600
    assert Path(ca).stat().st_mode & 0o777 == 0o600
    assert Path(output).exists() is False
    return {"kind": "fixture-download-receipt", "status": "downloaded-only",
            "qualified": False, "prepared": False}
'''
        source_hash = _digest(source)
        fixture_root = self.root / "tree"
        (fixture_root / "packages/event-gateway/scripts").mkdir(parents=True)
        (fixture_root / "packages/event-gateway/docs/native-bridge").mkdir(parents=True)
        (fixture_root / guest.SOURCE_PATH).write_bytes(source)
        (fixture_root / guest.MANIFEST_PATH).write_bytes(self.manifest_raw)
        with patch.object(guest, "SOURCE_SHA256", source_hash):
            bundle = guest.build_bundle(fixture_root, self.ca, self.dns)
        return fixture_root, bundle

    def _execute_fixed_loader_fixture(self, loader_source):
        """Run only the generated fixed loader with this test's in-memory bundle fixture."""
        if not isinstance(loader_source, str):
            raise TypeError("expected_fixed_loader_source")
        namespace = {"__name__": "__main__", "__builtins__": __builtins__}
        # The generated loader and stub are repository-owned; payload bytes are never code inputs.
        exec(compile(loader_source, "<fixed-provisioning-loader-fixture>", "exec"),  # nosec B102 -- Fixed loader fixture, explicit namespace, no caller code.
             namespace, namespace)

    def _receive(self, loader, payload, os_version="15.7.0"):
        stdout = io.BytesIO()
        fake_root = self.root / "received-guest-root"

        def mkdtemp(*, prefix):
            self.assertEqual(prefix, "knitli-native-provisioning-")
            fake_root.mkdir(mode=0o700)
            return str(fake_root)
        old_platform = sys.platform
        old_stdin, old_stdout = sys.stdin, sys.stdout
        try:
            with patch.object(sys, "platform", "darwin"), \
                    patch.object(platform, "machine", return_value="arm64"), \
                    patch.object(platform, "mac_ver", return_value=(os_version, ("", "", ""), "")), \
                    patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(payload))), \
                    patch.object(sys, "stdout", types.SimpleNamespace(buffer=stdout)), \
                    patch.object(tempfile, "mkdtemp", side_effect=mkdtemp):
                self._execute_fixed_loader_fixture(loader)
        finally:
            sys.platform = old_platform
            sys.stdin, sys.stdout = old_stdin, old_stdout
        return json.loads(stdout.getvalue()), fake_root

    def test_fixed_loader_writes_private_pinned_files_and_reports_download_only(self):
        fixture_root, bundle = self._fixture_bundle()
        del fixture_root
        result, guest_root = self._receive(bundle["loader"], bundle["payload"])
        self.addCleanup(lambda: shutil.rmtree(guest_root, ignore_errors=True))
        self.assertEqual(set(result), {"kind", "qualified", "prepared", "guestRoot", "bundleSha256",
                                      "downloadReceipt"})
        self.assertEqual(result["kind"], guest.RESULT_KIND)
        self.assertIs(result["qualified"], False)
        self.assertIs(result["prepared"], False)
        self.assertEqual(result["guestRoot"], str(guest_root))
        self.assertEqual(result["bundleSha256"], bundle["bundleSha256"])
        self.assertEqual(result["downloadReceipt"]["status"], "downloaded-only")
        self.assertEqual((guest_root / guest.SOURCE_PATH).read_bytes(), base64.b64decode(
            json.loads(bundle["payload"])["sourceBase64"], validate=True))
        self.assertEqual((guest_root / guest.MANIFEST_PATH).read_bytes(), self.manifest_raw)
        self.assertFalse((guest_root / "downloads").exists())
        self.assertEqual((guest_root / "provisioning-data/public-roots.pem").read_bytes(), self.ca)
        self.assertEqual(guest_root.stat().st_mode & 0o777, 0o700)
        for relative in (
            "packages", "packages/event-gateway", "packages/event-gateway/scripts",
            "packages/event-gateway/docs", "packages/event-gateway/docs/native-bridge",
            "provisioning-data",
        ):
            self.assertEqual((guest_root / relative).stat().st_mode & 0o777, 0o700, relative)

    def test_receiver_rejects_tamper_extra_member_duplicate_keys_and_oversized_input(self):
        _, bundle = self._fixture_bundle()
        document = json.loads(bundle["payload"])
        document["caBundleSha256"] = "0" * 64
        with self.assertRaises(SystemExit):
            self._receive(bundle["loader"], json.dumps(document, separators=(",", ":")).encode())
        document = json.loads(bundle["payload"])
        document["extra"] = "no"
        with self.assertRaises(SystemExit):
            self._receive(bundle["loader"], json.dumps(document, separators=(",", ":")).encode())
        duplicated = bundle["payload"][:-1] + b',"kind":"extra"}'
        with self.assertRaises(SystemExit):
            self._receive(bundle["loader"], duplicated)
        with self.assertRaises(SystemExit):
            self._receive(bundle["loader"], b" " * (guest.MAX_BUNDLE_BYTES + 1))

    def test_ca_pin_test_detects_a_bypassed_guard_and_macos27_is_rejected_before_input(self):
        _, bundle = self._fixture_bundle()
        document = json.loads(bundle["payload"])
        document["caBundleSha256"] = "0" * 64
        tampered = json.dumps(document, separators=(",", ":")).encode()
        with self.assertRaises(SystemExit):
            self._receive(bundle["loader"], tampered)
        bypass = bundle["loader"].replace(
            "or digest(ca_bytes) != doc['caBundleSha256']", "or False")
        self.assertNotEqual(bypass, bundle["loader"])
        accepted, root = self._receive(bypass, tampered)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        self.assertIs(accepted["qualified"], False)
        with self.assertRaises(SystemExit) as rejected:
            self._receive(bundle["loader"], bundle["payload"], os_version="27.0.0")
        self.assertEqual(rejected.exception.code, 31)

    def _valid_result(self, dns_map=None):
        selected_dns = self.dns if dns_map is None else dns_map
        bundle = guest.build_bundle(guest.ROOT, self.ca, selected_dns)
        assets = []
        for asset in self.manifest["assets"]:
            initial = downloader._validate_url(asset["url"])
            host = initial.hostname
            assets.append({
                "name": asset["name"], "initialUrl": asset["url"],
                "finalHost": host, "finalPath": initial.path or "/",
                "selectedIPv4": selected_dns[host][0], "status": 200,
                "redirectCount": 0, "outcome": "downloaded", "bytes": 1,
                "sha256": asset["sha256"],
            })
        receipt = {
            "kind": downloader.KIND, "status": "downloaded-only", "qualified": False,
            "prepared": False, "manifestSha256": guest.MANIFEST_SHA256,
            "caBundleSha256": bundle["caBundleSha256"], "dnsMap": selected_dns,
            "totalBytes": len(assets), "assets": assets,
        }
        return bundle, {
            "kind": guest.RESULT_KIND, "qualified": False, "prepared": False,
            "guestRoot": "/private/tmp/knitli-native-provisioning-abcdefgh",
            "bundleSha256": bundle["bundleSha256"], "downloadReceipt": receipt,
        }

    def _validate(self, bundle, result):
        return guest.validate_result(result, manifest_bytes=bundle["manifestBytes"],
                                     dns_map=bundle["dnsMap"],
                                     ca_sha256=bundle["caBundleSha256"],
                                     bundle_sha256=bundle["bundleSha256"])

    def test_result_validator_accepts_exact_raw_and_parsed_receipts(self):
        bundle, result = self._valid_result()
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        self.assertLessEqual(len(encoded), guest.MAX_OUTPUT_BYTES)
        self.assertEqual(self._validate(bundle, encoded), result)
        self.assertEqual(self._validate(bundle, result), result)
        manifest, dns = guest.validate_binding(
            manifest_bytes=bundle["manifestBytes"], dns_map=bundle["dnsMap"],
            ca_sha256=bundle["caBundleSha256"], bundle_sha256=bundle["bundleSha256"])
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(dns, self.dns)

    def test_result_validator_rejects_receipt_tamper_and_extra_or_qualified_fields(self):
        bundle, original = self._valid_result()
        wrong_digest = copy.deepcopy(original)
        wrong_digest["downloadReceipt"]["assets"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "download_asset_binding_mismatch"):
            self._validate(bundle, wrong_digest)

        wrong_size = copy.deepcopy(original)
        wrong_size["downloadReceipt"]["assets"][0]["bytes"] = True
        with self.assertRaisesRegex(ValueError, "download_asset_binding_mismatch"):
            self._validate(bundle, wrong_size)

        wrong_destination = copy.deepcopy(original)
        wrong_destination["downloadReceipt"]["assets"][0]["finalPath"] = "/unauthorized"
        with self.assertRaisesRegex(ValueError, "download_asset_destination_invalid"):
            self._validate(bundle, wrong_destination)

        dns_drift = copy.deepcopy(original)
        dns_drift["downloadReceipt"]["dnsMap"][next(iter(self.dns))] = ["8.8.8.8"]
        with self.assertRaisesRegex(ValueError, "download_receipt_binding_mismatch"):
            self._validate(bundle, dns_drift)

        extra = copy.deepcopy(original)
        extra["downloadReceipt"]["qualified"] = True
        with self.assertRaisesRegex(ValueError, "download_receipt_binding_mismatch"):
            self._validate(bundle, extra)

        extra["downloadReceipt"].pop("qualified")
        extra["surprise"] = False
        with self.assertRaisesRegex(ValueError, "result_shape_invalid"):
            self._validate(bundle, extra)

    def test_result_validator_rejects_bad_state_binding_and_oversized_json(self):
        bundle, result = self._valid_result()
        qualified = copy.deepcopy(result)
        qualified["qualified"] = True
        with self.assertRaisesRegex(ValueError, "result_binding_mismatch"):
            self._validate(bundle, qualified)
        with self.assertRaisesRegex(ValueError, "manifest_binding_mismatch"):
            guest.validate_binding(manifest_bytes=b"{}", dns_map=self.dns,
                                   ca_sha256=bundle["caBundleSha256"],
                                   bundle_sha256=bundle["bundleSha256"])
        with self.assertRaisesRegex(ValueError, "digest_binding_invalid"):
            guest.validate_binding(manifest_bytes=bundle["manifestBytes"], dns_map=self.dns,
                                   ca_sha256="invalid", bundle_sha256=bundle["bundleSha256"])
        with self.assertRaisesRegex(ValueError, "result_oversized"):
            self._validate(bundle, b" " * (guest.MAX_OUTPUT_BYTES + 1))

    def test_result_validator_requires_first_pinned_address_not_any_dns_answer(self):
        dns_map = copy.deepcopy(self.dns)
        host = downloader._validate_url(self.manifest["assets"][0]["url"]).hostname
        dns_map[host] = [dns_map[host][0], "8.8.8.8"]
        bundle, result = self._valid_result(dns_map)
        self.assertEqual(self._validate(bundle, result), result)

        second_answer = copy.deepcopy(result)
        second_answer["downloadReceipt"]["assets"][0]["selectedIPv4"] = "8.8.8.8"
        self.assertIn("8.8.8.8", dns_map[host])
        with self.assertRaisesRegex(ValueError, "download_asset_destination_invalid"):
            self._validate(bundle, second_answer)

    def test_payload_validator_accepts_built_bundle_before_execution(self):
        ca_bytes = bytes(range(256)) * 1302 + bytes(range(171))
        bundle = guest.build_bundle(guest.ROOT, ca_bytes, self.dns)
        document = guest.validate_payload(
            bundle["payload"], manifest_bytes=bundle["manifestBytes"],
            dns_map=bundle["dnsMap"], ca_sha256=bundle["caBundleSha256"],
            bundle_sha256=bundle["bundleSha256"])
        self.assertEqual(document["kind"], guest.KIND)
        self.assertEqual(document["dnsMap"], self.dns)
        self.assertEqual(_digest(bundle["payload"]), bundle["bundleSha256"])

    def test_payload_validator_rejects_rehashed_embedded_tampering(self):
        ca_bytes = bytes(range(256)) * 1302 + bytes(range(171))
        bundle = guest.build_bundle(guest.ROOT, ca_bytes, self.dns)

        def changed_payload(change):
            document = json.loads(bundle["payload"])
            change(document)
            return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

        def check(raw, code):
            with self.assertRaisesRegex(ValueError, code):
                guest.validate_payload(raw, manifest_bytes=bundle["manifestBytes"],
                                       dns_map=bundle["dnsMap"],
                                       ca_sha256=bundle["caBundleSha256"],
                                       bundle_sha256=_digest(raw))

        source_tamper = changed_payload(lambda doc: doc.update(
            sourceBase64=base64.b64encode(b"changed-source").decode()))
        check(source_tamper, "payload_source_pin_mismatch")

        manifest_tamper = changed_payload(lambda doc: doc.update(
            manifestBase64=base64.b64encode(b"{}").decode()))
        check(manifest_tamper, "payload_manifest_pin_mismatch")

        ca_tamper = changed_payload(lambda doc: doc.update(
            caBundleBase64=base64.b64encode(b"changed-ca").decode()))
        check(ca_tamper, "payload_ca_pin_mismatch")

        def change_dns(document):
            host = next(iter(document["dnsMap"]))
            document["dnsMap"][host] = ["8.8.8.8"]
        check(changed_payload(change_dns), "payload_dns_map_mismatch")

        extra = changed_payload(lambda doc: doc.update(extra=False))
        check(extra, "payload_shape_invalid")

        with self.assertRaisesRegex(ValueError, "payload_digest_mismatch"):
            guest.validate_payload(bundle["payload"], manifest_bytes=bundle["manifestBytes"],
                                   dns_map=bundle["dnsMap"],
                                   ca_sha256=bundle["caBundleSha256"],
                                   bundle_sha256="0" * 64)


if __name__ == "__main__":
    unittest.main()
