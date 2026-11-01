"""Offline fixture tests; synthetic DER bytes only, with no TLS/network calls."""

import hashlib
import io
import json
import os
import socket
import ssl
import stat
import subprocess  # nosec B404 -- APIs are patched to reject process execution in the collector test.
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import gateway_public_root_inventory_probe as probe


def _root_bytes(seed, padding=b""):
    """Opaque nonempty fixture bytes; these tests do not parse or claim X.509 validity."""
    return b"opaque-root-" + seed.to_bytes(4, "big") + padding


class FakeContext:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED
    verify_flags = 0

    def __init__(self, roots):
        """Set the fixture roots returned by this context."""
        self.roots = roots

    def get_ca_certs(self, binary_form=False):
        if binary_form is not True:
            raise AssertionError("binary DER form is required")
        return list(self.roots)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.roots = [_root_bytes(2), _root_bytes(1)]
        self.context = FakeContext(self.roots)
        self.paths = types.SimpleNamespace(
            cafile="/fixture/ca-bundle.pem",
            capath="/fixture/certs",
            openssl_cafile="/fixture/openssl-ca.pem",
            openssl_capath="/fixture/openssl-certs",
            openssl_cafile_env="SSL_CERT_FILE",
            openssl_capath_env="SSL_CERT_DIR",
        )
        self.file_bytes = b"fixture PEM bundle metadata only; no certificates"
        self.info = os.stat_result(
            (stat.S_IFREG | 0o644, 1, 1, 1, 501, 20, len(self.file_bytes), 0, 0, 0)
        )
        self.capath_info = os.stat_result(
            (stat.S_IFDIR | 0o755, 2, 1, 1, 501, 20, 4096, 0, 0, 0)
        )

    def _collect(self):
        def fake_stat(path):
            return self.capath_info if path == self.paths.capath else self.info

        reads = iter((self.file_bytes, b""))
        with (
            mock.patch.dict(probe.os.environ, {}, clear=True),
            mock.patch.object(
                probe.ssl, "get_default_verify_paths", return_value=self.paths
            ),
            mock.patch.object(
                probe.ssl, "create_default_context", return_value=self.context
            ) as create_default_context,
            mock.patch.object(
                probe.os,
                "uname",
                return_value=types.SimpleNamespace(
                    sysname="fixture-system",
                    release="fixture-release",
                    machine="fixture-machine",
                ),
            ),
            mock.patch.object(probe.os, "stat", side_effect=fake_stat),
            mock.patch.object(probe.os, "open", return_value=123),
            mock.patch.object(probe.os, "fstat", return_value=self.info),
            mock.patch.object(probe.os, "read", side_effect=lambda *_args: next(reads)),
            mock.patch.object(probe.os, "close"),
        ):
            report = probe.collect()
        create_default_context.assert_called_once_with()
        return report

    def test_report_has_exact_schema_sorted_unique_digest_and_scope(self):
        self.context.roots.append(self.roots[0])
        report = self._collect()
        hashes = sorted({hashlib.sha256(cert).hexdigest() for cert in self.roots})
        expected = hashlib.sha256("\n".join(hashes).encode("ascii")).hexdigest()
        self.assertEqual(report["schemaVersion"], "gateway-public-root-inventory-v1")
        self.assertEqual(
            report["rootInventoryScope"],
            "materialized_default_ca_roots_without_connections",
        )
        self.assertEqual(
            report["runtime"]["platform"],
            "fixture-system/fixture-release/fixture-machine",
        )
        self.assertEqual(report["publicRootCount"], 2)
        self.assertEqual(report["publicTrustRootsSha256"], expected)
        self.assertEqual([row["derSha256"] for row in report["publicRoots"]], hashes)
        self.assertEqual(
            report["context"],
            {
                "checkHostname": True,
                "verifyMode": int(ssl.CERT_REQUIRED),
                "verifyFlags": 0,
                "cadataUsed": False,
                "cadataSource": "none",
                "trustSource": "ssl.create_default_context",
            },
        )
        self.assertEqual(
            report["defaultCafile"]["sha256"],
            hashlib.sha256(self.file_bytes).hexdigest(),
        )
        self.assertEqual(report["capathMetadata"]["state"], "present")
        self.assertIs(probe.validate_report(report), report)

    def test_environment_overrides_are_rejected_before_context_creation(self):
        for key in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            with (
                self.subTest(key=key),
                mock.patch.dict(probe.os.environ, {key: ""}, clear=True),
                mock.patch.object(probe.ssl, "create_default_context") as create,
            ):
                with self.assertRaisesRegex(
                    probe.ProbeError, "tls_environment_override_present"
                ):
                    probe.collect()
                create.assert_not_called()

    def test_context_must_keep_hostname_and_required_certificate_checks(self):
        self.context.check_hostname = False
        with (
            mock.patch.dict(probe.os.environ, {}, clear=True),
            mock.patch.object(
                probe.ssl, "get_default_verify_paths", return_value=self.paths
            ),
            mock.patch.object(
                probe.ssl, "create_default_context", return_value=self.context
            ),
            self.assertRaisesRegex(probe.ProbeError, "default_context_flags_invalid"),
        ):
            probe.collect()

    def test_root_inventory_rejects_empty_set_nonbytes_and_oversize_items(self):
        with self.assertRaisesRegex(probe.ProbeError, "default_roots_empty"):
            probe._root_inventory(FakeContext([]))
        for cert in (b"", "not bytes", b"x" * (probe.MAX_ROOT_DER_BYTES + 1)):
            with (
                self.subTest(type=type(cert).__name__, size=len(cert)),
                self.assertRaisesRegex(probe.ProbeError, "root_der_invalid"),
            ):
                probe._root_inventory(FakeContext([cert]))

    def test_gateway_ca_fingerprint_is_rejected(self):
        pinned_gateway_ca_sha256 = (
            "a1c2722d8f42c698d98dad65487eb2467fb9117c60205d84907231ecf6aa9102"
        )
        self.assertEqual(probe.GATEWAY_CA_SHA256, pinned_gateway_ca_sha256)
        cert = self.roots[0]
        with (
            mock.patch.object(
                probe, "GATEWAY_CA_SHA256", hashlib.sha256(cert).hexdigest()
            ),
            self.assertRaisesRegex(
                probe.ProbeError, "gateway_ca_present_in_default_roots"
            ),
        ):
            probe._root_inventory(FakeContext([cert]))

    def test_root_count_and_total_der_caps_fail_closed(self):
        too_many = [_root_bytes(i) for i in range(513)]
        with self.assertRaisesRegex(probe.ProbeError, "root_inventory_too_large"):
            probe._root_inventory(FakeContext(too_many))
        duplicates = [self.roots[0]] * (probe.MAX_ROOTS + 1)
        with self.assertRaisesRegex(probe.ProbeError, "root_inventory_too_large"):
            probe._root_inventory(FakeContext(duplicates))
        large = [_root_bytes(i, b"x" * 4096) for i in range(512)]
        with self.assertRaisesRegex(probe.ProbeError, "root_inventory_too_large"):
            probe._root_inventory(FakeContext(large))

    def test_cafile_is_read_and_hashed_only_within_size_bound(self):
        reads = iter((self.file_bytes, b""))
        with (
            mock.patch.object(probe.os, "open", return_value=123),
            mock.patch.object(probe.os, "fstat", return_value=self.info) as fstat,
            mock.patch.object(probe.os, "read", side_effect=lambda *_args: next(reads)),
            mock.patch.object(probe.os, "close") as close,
        ):
            result = probe._cafile_inventory("/fixture/ca-bundle.pem")
        self.assertEqual(fstat.call_count, 2)
        close.assert_called_once_with(123)
        self.assertEqual(result["bytes"], len(self.file_bytes))
        self.assertEqual(result["sha256"], hashlib.sha256(self.file_bytes).hexdigest())
        self.assertEqual(result["stat"]["device"], self.info.st_dev)
        self.assertEqual(result["stat"]["inode"], self.info.st_ino)
        oversized = os.stat_result(
            (
                stat.S_IFREG | 0o644,
                1,
                1,
                1,
                501,
                20,
                probe.MAX_CAFILE_BYTES + 1,
                0,
                0,
                0,
            )
        )
        with (
            mock.patch.object(probe.os, "open", return_value=123),
            mock.patch.object(probe.os, "fstat", return_value=oversized),
            mock.patch.object(probe.os, "close"),
            self.assertRaisesRegex(probe.ProbeError, "default_cafile_invalid"),
        ):
            probe._cafile_inventory("/fixture/too-big.pem")

    def test_cafile_file_identity_must_be_stable_during_read(self):
        changed = os.stat_result(
            (stat.S_IFREG | 0o644, 2, 1, 1, 501, 20, len(self.file_bytes), 0, 0, 0)
        )
        reads = iter((self.file_bytes, b""))
        with (
            mock.patch.object(probe.os, "open", return_value=123),
            mock.patch.object(probe.os, "fstat", side_effect=(self.info, changed)),
            mock.patch.object(probe.os, "read", side_effect=lambda *_args: next(reads)),
            mock.patch.object(probe.os, "close"),
            self.assertRaisesRegex(probe.ProbeError, "default_cafile_invalid"),
        ):
            probe._cafile_inventory("/fixture/ca-bundle.pem")

    def test_report_validator_rejects_digest_order_scope_and_context_mutations(self):
        baseline = self._collect()
        variants = []
        wrong_digest = dict(baseline)
        wrong_digest["publicTrustRootsSha256"] = "0" * 64
        variants.append((wrong_digest, "report_digest_invalid"))
        wrong_order = dict(baseline)
        wrong_order["publicRoots"] = list(reversed(baseline["publicRoots"]))
        variants.append((wrong_order, "report_roots_invalid"))
        wrong_scope = dict(baseline)
        wrong_scope["rootInventoryScope"] = "all_potential_trust_roots"
        variants.append((wrong_scope, "report_roots_invalid"))
        empty_roots = dict(baseline)
        empty_roots["publicRoots"] = []
        empty_roots["publicRootCount"] = 0
        empty_roots["publicRootDerBytes"] = 0
        empty_roots["publicTrustRootsSha256"] = hashlib.sha256(b"").hexdigest()
        variants.append((empty_roots, "report_roots_invalid"))
        wrong_context = dict(baseline)
        wrong_context["context"] = dict(baseline["context"], cadataUsed=True)
        variants.append((wrong_context, "report_context_invalid"))
        for key, value in (
            ("checkHostname", 1),
            ("cadataUsed", 0),
            ("verifyFlags", True),
            ("verifyMode", True),
        ):
            wrong_bool_type = dict(baseline)
            wrong_bool_type["context"] = dict(baseline["context"], **{key: value})
            variants.append((wrong_bool_type, "report_context_invalid"))
        for report, error in variants:
            with (
                self.subTest(error=error),
                self.assertRaisesRegex(probe.ProbeError, error),
            ):
                probe.validate_report(report)

    def test_cli_rejects_all_arguments_without_using_them(self):
        output = io.BytesIO()
        fake_stdout = types.SimpleNamespace(buffer=output)
        with (
            mock.patch.object(probe.sys, "stdout", fake_stdout),
            mock.patch.object(probe, "collect") as collect,
        ):
            status = probe.main(["--cafile", "/untrusted/input"])
        self.assertEqual(status, 2)
        self.assertEqual(
            output.getvalue(), b'{"errorCode":"arguments_not_supported"}\n'
        )
        collect.assert_not_called()

    def test_guest_bundle_uses_one_fixed_source_and_binds_host_hash_argument(self):
        hashes = {"probe": "a" * 64}
        calls = []

        def build(files, paths, **kwargs):
            calls.append((files, paths, kwargs))
            return {
                "argument": "fixed-bundle",
                "sourceSha256": hashes,
                "bundleSha256": "b" * 64,
            }

        def loader(files, module, function, prefix, **kwargs):
            calls.append((files, module, function, prefix, kwargs))
            return "fixed-loader"

        shared = types.SimpleNamespace(
            _build_source_bundle=build,
            _source_loader=loader,
        )
        with mock.patch.dict(sys.modules, {"scpreferences_guest_probe": shared}):
            bundle = probe.build_bundle()
        self.assertEqual(bundle["loader"], "fixed-loader")
        self.assertEqual(
            calls[0][0], {"probe": "gateway_public_root_inventory_probe.py"}
        )
        self.assertEqual(
            calls[1][1:4],
            (
                "gateway_public_root_inventory_probe",
                "collect_guest",
                "gateway-public-root-inventory-",
            ),
        )
        self.assertEqual(calls[1][4]["call_args"], repr(hashes))
        self.assertNotIn("SSL_CERT_FILE", calls[1][4]["guest_setup"])
        self.assertNotIn("SSL_CERT_DIR", calls[1][4]["guest_setup"])

    def test_command_template_has_only_fixed_guest_invocation(self):
        command = probe.command_template("/fixed/tart", "owned-clone", "loader")
        self.assertEqual(
            command[:12],
            [
                "/fixed/tart",
                "exec",
                "owned-clone",
                "/usr/bin/sudo",
                "-n",
                "-u",
                "admin",
                "-g",
                "staff",
                "--",
                "/usr/bin/env",
                "-i",
            ],
        )
        self.assertEqual(
            command[-5:],
            [
                "/usr/bin/python3",
                "-I",
                "-c",
                "loader",
                "<fixed-source-bundle-b64>",
            ],
        )
        self.assertNotIn("SSL_CERT_FILE=", " ".join(command))
        self.assertNotIn("SSL_CERT_DIR=", " ".join(command))

    def test_guest_output_requires_exact_envelope_source_hash_and_empty_stderr(self):
        report = self._collect()
        hashes = {"probe": "a" * 64}
        envelope = {"status": "passed", "sourceSha256": hashes, "report": report}
        stdout = json.dumps(envelope, separators=(",", ":")).encode()
        self.assertEqual(probe.validate_guest_output(stdout, b"", hashes), report)
        with self.assertRaisesRegex(probe.ProbeError, "guest_output_invalid"):
            probe.validate_guest_output(stdout, b"diagnostic", hashes)
        with self.assertRaisesRegex(probe.ProbeError, "guest_output_invalid"):
            probe.validate_guest_output(stdout, b"", {"probe": "c" * 64})

    def test_platform_metadata_path_does_not_spawn_a_process(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("process creation is forbidden in the inventory probe")

        with (
            mock.patch.object(subprocess, "Popen", side_effect=forbidden),
            mock.patch.object(subprocess, "run", side_effect=forbidden),
            mock.patch.object(probe.os, "system", side_effect=forbidden),
            mock.patch.object(probe.os, "popen", side_effect=forbidden),
            mock.patch.object(socket, "socket", side_effect=forbidden),
            mock.patch.object(socket, "create_connection", side_effect=forbidden),
            mock.patch.object(socket, "getaddrinfo", side_effect=forbidden),
        ):
            report = self._collect()
        self.assertEqual(
            report["runtime"]["platform"],
            "fixture-system/fixture-release/fixture-machine",
        )


if __name__ == "__main__":
    unittest.main()
