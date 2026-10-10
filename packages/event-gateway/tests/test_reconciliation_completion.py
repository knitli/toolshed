"""Completed reconciliation permits only renewal of its exact current attachment."""
import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
import time
import unittest
from unittest.mock import patch

from event_gateway import cli, client_runtime
from event_gateway.cloud import _iso
from event_gateway.store import Store
import test_native_reconciliation as fixtures


class ReconciliationCompletionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NativeReconciliationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.original = self.fixture.pending()

    def complete(self):
        f = self.fixture
        code, result, _, _ = f.invoke()
        self.assertEqual(code, 0, result)
        self.marker = f.old_path.with_suffix(".reconcile.completed.json")
        self.assertTrue(self.marker.is_file())
        with Store(f.state) as store:
            self.mapping = store.get_attachment(f.runtime_id)
        return f

    def renewal(self):
        f = self.fixture
        return {**copy.deepcopy(self.original), "operation": "renew", "sessionId": f.session,
                "safeExpiryAt": _iso(time.time() + 60), "intent": {
                    "operation": "renew", "runtimeId": f.runtime_id,
                    "expectedRuntimeGeneration": f.response["runtimeGeneration"],
                    "expectedAttachmentGeneration": f.response["attachmentGeneration"],
                    "expectedNativeBinding": copy.deepcopy(f.binding),
                }}

    def save_renewal(self, artifact, mapping, key):
        f = self.fixture
        return client_runtime.save_pending_commit(
            f.state, "renew", f.session, artifact, current_mapping=mapping, node_public_key=key)

    def test_marker_is_immutable_and_exact_renewal_allows_updated_lease(self):
        f = self.complete()
        marker_bytes = self.marker.read_bytes()
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        client_runtime.complete_reconciliation(
            f.state, f.session, f.identity, f.cloud.node_public_key, f.response, self.mapping)
        self.assertEqual(self.marker.read_bytes(), marker_bytes)
        changed_response = {**f.response, "leaseUntil": _iso(time.time() + 180)}
        changed_mapping = {**self.mapping,
                           "leaseExpiresAt": client_runtime._timestamp(changed_response["leaseUntil"]) / 1000}
        with self.assertRaises(client_runtime.SecurityError) as caught:
            client_runtime.complete_reconciliation(
                f.state, f.session, f.identity, f.cloud.node_public_key, changed_response, changed_mapping)
        self.assertEqual(caught.exception.code, "reconciliation_completion_changed")
        artifact = self.renewal()
        self.save_renewal(artifact, changed_mapping, f.cloud.node_public_key)
        self.assertEqual(client_runtime.load_pending_commit(f.state, "renew", f.session), artifact)
        self.assertEqual(self.marker.read_bytes(), marker_bytes)
        f.assert_original_preserved()

    def test_renewal_rejects_changed_identity_binding_runtime_generations_or_key(self):
        f = self.complete()
        marker_bytes = self.marker.read_bytes()
        for changed in ("runtimeId", "cloudIdentity", "nativeBinding", "runtimeGeneration",
                        "attachmentGeneration", "nodePublicKey", "staleMapping", "missingMapping"):
            with self.subTest(changed=changed):
                artifact, mapping, key = self.renewal(), copy.deepcopy(self.mapping), f.cloud.node_public_key
                if changed == "runtimeId":
                    artifact["intent"]["runtimeId"] = fixtures.identifier()
                elif changed == "cloudIdentity":
                    artifact["cloudIdentity"]["nodeGeneration"] += 1
                elif changed == "nativeBinding":
                    artifact["intent"]["expectedNativeBinding"]["generation"] += 1
                elif changed in ("runtimeGeneration", "attachmentGeneration"):
                    artifact["intent"]["expected" + changed[0].upper() + changed[1:]] += 1
                elif changed == "nodePublicKey":
                    key = "A" * 42 + "B"
                elif changed == "staleMapping":
                    mapping["attachmentGeneration"] += 1
                else:
                    mapping = None
                with self.assertRaises(client_runtime.SecurityError) as caught:
                    self.save_renewal(artifact, mapping, key)
                self.assertEqual(caught.exception.code, "reconciliation_successor_reserved")
                self.assertIsNone(client_runtime.load_pending_commit(f.state, "renew", f.session))
                self.assertEqual(self.marker.read_bytes(), marker_bytes)
        f.assert_original_preserved()

    def test_missing_completion_refuses_renewal_even_with_current_mapping(self):
        f = self.complete()
        self.marker.unlink()
        with self.assertRaises(client_runtime.SecurityError) as caught:
            self.save_renewal(self.renewal(), self.mapping, f.cloud.node_public_key)
        self.assertEqual(caught.exception.code, "reconciliation_successor_reserved")
        self.assertIsNone(client_runtime.load_pending_commit(f.state, "renew", f.session))

    def test_completion_does_not_release_successor_for_another_original(self):
        f = self.complete()
        original_path, original_bytes = f.old_path, f.old_bytes
        marker_bytes = self.marker.read_bytes()
        f.old_session = fixtures.identifier()
        f.pending()
        commits_before = len(f.cloud.commits)
        code, result, _, challenge = f.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(result["reason"], "reconciliation_successor_reserved")
        challenge.assert_not_called()
        self.assertEqual(len(f.cloud.commits), commits_before)
        self.assertEqual(self.marker.read_bytes(), marker_bytes)
        self.assertEqual(original_path.read_bytes(), original_bytes)
        f.assert_original_preserved()

    def test_completion_directory_sync_failure_retains_pending_and_retries(self):
        f = self.fixture
        marker = f.old_path.with_suffix(".reconcile.completed.json")
        real_fsync = os.fsync

        def fail_after_marker_publish(fd):
            if marker.exists():
                raise OSError("completion sync unavailable")
            return real_fsync(fd)

        with patch.object(client_runtime.os, "fsync", side_effect=fail_after_marker_publish):
            code, result, _, _ = f.invoke()
        self.assertEqual(code, 2, result)
        self.assertTrue(marker.exists())
        retained = marker.read_bytes()
        self.assertIsNotNone(client_runtime.load_pending_commit(f.state, "attach", f.session))
        f.assert_original_preserved()
        code, result, _, challenge = f.invoke()
        self.assertEqual(code, 0, result)
        challenge.assert_not_called()
        self.assertEqual(marker.read_bytes(), retained)
        self.assertIsNone(client_runtime.load_pending_commit(f.state, "attach", f.session))
        f.assert_original_preserved()

    def test_failed_mapping_readback_retains_pending_without_completion(self):
        f = self.fixture
        with patch.object(cli, "_read_native_mapping", return_value=None):
            code, result, _, _ = f.invoke()
        self.assertEqual(code, 2, result)
        self.assertEqual(result["reason"], "reconciliation_completion_unavailable")
        self.assertIsNotNone(client_runtime.load_pending_commit(f.state, "attach", f.session))
        self.assertFalse(f.old_path.with_suffix(".reconcile.completed.json").exists())
        f.assert_original_preserved()
        code, result, _, challenge = f.invoke()
        self.assertEqual(code, 0, result)
        challenge.assert_not_called()
        self.assertTrue(f.old_path.with_suffix(".reconcile.completed.json").is_file())
        self.assertIsNone(client_runtime.load_pending_commit(f.state, "attach", f.session))

    def test_ordinary_cli_renew_after_completion_preserves_marker(self):
        f = self.fixture
        self.assertEqual(f.invoke()[0], 0)
        marker = f.old_path.with_suffix(".reconcile.completed.json")
        marker_bytes = marker.read_bytes() if marker.exists() else None

        async def renew(intent, challenge, evidence, *, on_first_send=None,
                        prepared_body=None, recovery=False):
            if on_first_send:
                on_first_send(b'{"fixture":"renew"}')
            return {**f.response, "status": "renewed", "leaseUntil": _iso(time.time() + 180)}

        args = ["--state-dir", str(f.state), "renew", "--runtime-id", f.runtime_id,
                "--session-id", f.session, "--cloud-config", str(f.state / "cloud.json"),
                "--expected-runtime-generation", str(f.response["runtimeGeneration"]),
                "--expected-attachment-generation", str(f.response["attachmentGeneration"])]
        output, error = io.StringIO(), io.StringIO()
        with (patch.object(f.cloud, "renew", side_effect=renew, create=True),
              patch.object(cli, "load_cloud_client", return_value=f.cloud),
              patch.object(cli, "session_binding", return_value=f.binding),
              patch.object(cli, "session_challenge", return_value=f.evidence),
              redirect_stdout(output), redirect_stderr(error)):
            code = cli.main(args)
        result = json.loads(output.getvalue() or error.getvalue())
        self.assertEqual(code, 0, result)
        self.assertEqual(result["remoteStatus"], "renewed")
        self.assertEqual(result["localStatus"], "current")
        self.assertIsNone(client_runtime.load_pending_commit(f.state, "renew", f.session))
        self.assertEqual(marker.read_bytes(), marker_bytes)
        f.assert_original_preserved()
