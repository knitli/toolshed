"""Reconcile unknown native commits through authoritative, generation-fenced status."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from event_gateway import cli
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway.cloud import CloudClient, CloudError, Credentials, _iso, canonical_node_proof
from event_gateway import client_runtime
from event_gateway.store import Store


def identifier():
    return str(uuid.uuid4())


class NativeReconciliationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name).resolve() / "state"
        self.runtime_id, self.old_session, self.session = identifier(), identifier(), identifier()
        self.binding = {
            "clientId": identifier(), "connectionId": identifier(), "backendPid": 123,
            "threadId": identifier(), "generation": 5,
            "serverInstanceId": identifier(), "serverGeneration": 8,
        }
        self.identity = {
            "origin": "https://events.example.com", "principal": "adam@knitli.com",
            "agent": "codex", "nodeId": identifier(), "nodeGeneration": 4,
        }
        self.challenge = {
            "challengeId": identifier(), "issuedAt": _iso(time.time()),
            "expiresAt": _iso(time.time() + 30),
        }
        self.evidence = {
            "observedAt": self.challenge["issuedAt"],
            "validUntilMonotonic": time.monotonic() + 10, "witness": {"fixture": True},
        }
        self.response = {
            "status": "attached", "runtimeId": self.runtime_id,
            "runtimeGeneration": 7, "attachmentGeneration": 12,
            "nodeId": self.identity["nodeId"], "nodeGeneration": 4,
            "leaseUntil": _iso(time.time() + 90), "nativeBinding": self.binding,
        }
        self.observation = {
            "status": "present", "runtimeId": self.runtime_id, "observedAt": _iso(time.time()),
            "runtimeGeneration": 7, "attachmentGeneration": 11,
            "nodeId": self.identity["nodeId"], "nodeGeneration": 4,
            "leaseUntil": _iso(time.time() - 60), "storedQualified": True,
            "nativeBinding": {**self.binding, "generation": 1},
        }
        owner = self

        class FakeCloud:
            origin = owner.identity["origin"]
            principal = owner.identity["principal"]
            agent = owner.identity["agent"]
            node_id = owner.identity["nodeId"]
            node_generation = owner.identity["nodeGeneration"]
            node_public_key = "A" * 43

            def __init__(self):
                self.status_calls, self.intents, self.commits = [], [], []
                self.status_error = self.commit_error = None
                self.before_send = lambda: None

            async def runtime_status(self, runtime_id):
                self.status_calls.append(runtime_id)
                if self.status_error:
                    raise self.status_error
                return copy.deepcopy(owner.observation)

            async def native_challenge(self, intent):
                self.intents.append(copy.deepcopy(intent))
                return owner.challenge

            async def attach(self, intent, challenge, evidence, *, on_first_send=None,
                             prepared_body=None, recovery=False):
                self.before_send()
                self.commits.append((copy.deepcopy(intent), prepared_body, recovery))
                if on_first_send:
                    on_first_send(b'{"fixture":"prepared-attach"}')
                if self.commit_error:
                    raise self.commit_error
                return owner.response

        self.cloud = FakeCloud()

    def pending(self, operation="attach"):
        intent = {
            "operation": operation, "runtimeId": self.runtime_id,
            "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
            "expectedNativeBinding": {**self.binding, "generation": 1},
        }
        if operation == "renew":
            intent.update(expectedRuntimeGeneration=7, expectedAttachmentGeneration=11)
        if operation == "transfer":
            intent = {
                "operation": "transfer", "sourceRuntimeId": identifier(),
                "expectedSourceRuntimeGeneration": 2, "expectedSourceAttachmentGeneration": 3,
                "replacementRuntimeId": self.runtime_id,
                "expectedReplacementRuntimeGeneration": 7,
                "expectedReplacementAttachmentGeneration": 11,
                "expectedNativeBinding": self.binding,
            }
        artifact = {
            "version": 1, "operation": operation, "sessionId": self.old_session,
            "cloudIdentity": self.identity, "intent": intent,
            "challenge": self.challenge,
            "evidence": {"observedAt": self.challenge["issuedAt"], "witness": {"old": True}},
            "bodyB64": base64.b64encode(b'{"original":"immutable"}').decode(),
            "safeExpiryAt": _iso(time.time() - 120),
        }
        cli.save_pending_commit(self.state, operation, self.old_session, artifact)
        self.old_path = next(
            path for path in (self.state / ".native-pending").glob("*.json")
            if json.loads(path.read_text()).get("sessionId") == self.old_session
        )
        self.old_bytes = self.old_path.read_bytes()
        return artifact

    def invoke(self, command="reconcile", operation="attach", session=None):
        args = ["--state-dir", str(self.state), command]
        if command == "runtime-status":
            args += ["--runtime-id", self.runtime_id]
        else:
            args += ["--operation", operation, "--original-session-id", self.old_session,
                     "--session-id", session or self.session]
        args += ["--cloud-config", str(self.state / "cloud.json")]
        output, error = io.StringIO(), io.StringIO()
        with (
            patch.object(cli, "load_cloud_client", return_value=self.cloud),
            patch.object(cli, "session_binding", return_value=self.binding) as binding,
            patch.object(cli, "session_challenge", return_value=self.evidence) as challenge,
            redirect_stdout(output), redirect_stderr(error),
        ):
            code = cli.main(args)
        raw = output.getvalue() or error.getvalue()
        return code, json.loads(raw), binding, challenge

    def assert_original_preserved(self):
        self.assertEqual(self.old_path.read_bytes(), self.old_bytes)

    def test_runtime_status_needs_no_live_launcher_or_local_mapping(self):
        code, result, binding, challenge = self.invoke("runtime-status")
        self.assertEqual(code, 0)
        self.assertEqual(result, self.observation)
        self.assertEqual(self.cloud.status_calls, [self.runtime_id])
        binding.assert_not_called()
        challenge.assert_not_called()
        self.assertEqual(self.cloud.commits, [])
        self.assertFalse(self.state.exists())

    def test_missing_status_is_distinct_from_denied_and_unavailable(self):
        self.observation = {
            "status": "missing", "runtimeId": self.runtime_id, "observedAt": _iso(time.time()),
        }
        code, result, _, _ = self.invoke("runtime-status")
        self.assertEqual(code, 0)
        self.assertEqual(result, self.observation)
        for reason in ("denied", "request_timeout", "invalid_response"):
            with self.subTest(reason=reason):
                self.cloud.status_error = CloudError(reason)
                code, result, binding, challenge = self.invoke("runtime-status")
                self.assertEqual(code, 2)
                self.assertEqual(result, {"runtimeStatus": None, "reason": reason})
                binding.assert_not_called()
                challenge.assert_not_called()

    def test_expired_old_commit_uses_observed_non_one_generations(self):
        root = self.state
        for operation in ("attach", "renew"):
            with self.subTest(operation=operation):
                self.state = root / operation
                self.old_session, self.session = identifier(), identifier()
                self.pending(operation)
                observed_links = []
                self.cloud.before_send = lambda: observed_links.append(
                    client_runtime.load_reconciliation(self.state, operation, self.old_session))
                code, result, _, _ = self.invoke(operation=operation)
                self.assertEqual(code, 0, result)
                self.assertEqual(result["originalHistoricalOutcome"], "unknown")
                self.assertEqual(result["localStatus"], "current")
                self.assertEqual(result["remoteStatus"], "attached")
                intent = self.cloud.commits[-1][0]
                self.assertEqual(intent["operation"], "attach")
                self.assertEqual(intent["runtimeId"], self.runtime_id)
                self.assertEqual(intent["expectedRuntimeGeneration"], 7)
                self.assertEqual(intent["expectedAttachmentGeneration"], 11)
                self.assertEqual(intent["expectedNativeBinding"], self.binding)
                self.assertEqual(observed_links[0]["intent"], intent)
                self.assertEqual(observed_links[0]["successorSessionId"], self.session)
                self.assertEqual(observed_links[0]["originalArtifactSha256"],
                                 hashlib.sha256(self.old_bytes).hexdigest())
                self.assertEqual(self.old_path.with_suffix(".reconcile.json").stat().st_mode & 0o777,
                                 0o600)
                self.assert_original_preserved()
                with Store(self.state) as store:
                    mapping = store.get_attachment(self.runtime_id)
                    self.assertEqual(mapping["sessionId"], self.session)
                    self.assertEqual(mapping["attachmentGeneration"], 12)

    def test_missing_runtime_uses_null_cas_only_after_authoritative_read(self):
        self.pending()
        self.observation = {
            "status": "missing", "runtimeId": self.runtime_id, "observedAt": _iso(time.time()),
        }
        self.response.update(runtimeGeneration=1, attachmentGeneration=1)
        code, result, _, _ = self.invoke()
        self.assertEqual(code, 0, result)
        self.assertEqual(self.cloud.status_calls, [self.runtime_id])
        intent = self.cloud.commits[0][0]
        self.assertIsNone(intent["expectedRuntimeGeneration"])
        self.assertIsNone(intent["expectedAttachmentGeneration"])
        self.assert_original_preserved()

    def test_status_failure_preserves_old_without_successor_commit(self):
        self.pending()
        for reason in ("denied", "request_timeout", "invalid_response"):
            with self.subTest(reason=reason):
                self.cloud.status_error = CloudError(reason)
                code, result, _, challenge = self.invoke()
                self.assertEqual(code, 2)
                self.assertIn(reason, json.dumps(result))
                challenge.assert_not_called()
                self.assertEqual(self.cloud.commits, [])
                self.assert_original_preserved()
                self.assertIsNone(client_runtime.load_reconciliation(
                    self.state, "attach", self.old_session))

    def test_transfer_reconciliation_fails_closed(self):
        self.pending("transfer")
        code, result, _, challenge = self.invoke(operation="transfer")
        self.assertEqual(code, 2)
        self.assertIn("unsupported_transfer_reconciliation", json.dumps(result))
        self.assertEqual(self.cloud.status_calls, [])
        self.assertEqual(self.cloud.commits, [])
        challenge.assert_not_called()
        self.assert_original_preserved()

    def test_original_session_cannot_be_its_own_successor(self):
        self.pending()
        code, result, _, challenge = self.invoke(session=self.old_session)
        self.assertEqual(code, 2)
        self.assertIn("reconciliation_successor_required", json.dumps(result))
        self.assertEqual(self.cloud.commits, [])
        challenge.assert_not_called()
        self.assert_original_preserved()

    def test_cloud_identity_change_refused_before_status_or_commit(self):
        self.pending()
        self.cloud.node_generation += 1
        code, result, _, challenge = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("reconciliation_identity_mismatch", json.dumps(result))
        self.assertEqual(self.cloud.status_calls, [])
        self.assertEqual(self.cloud.commits, [])
        challenge.assert_not_called()
        self.assert_original_preserved()

    def test_ambiguous_successor_retry_reuses_link_intent_and_exact_body(self):
        self.pending()
        self.cloud.commit_error = CloudError("request_timeout", ambiguous=True)
        code, result, _, _ = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(result["reason"], "commit_outcome_unknown")
        link = client_runtime.load_reconciliation(self.state, "attach", self.old_session)
        self.assertIsNotNone(link)
        successor = cli.load_pending_commit(self.state, "attach", self.session)
        self.assertIsNotNone(successor)
        self.assert_original_preserved()
        self.observation["runtimeGeneration"] = 99
        self.cloud.commit_error = None
        code, result, _, challenge = self.invoke()
        self.assertEqual(code, 0, result)
        self.assertEqual(self.cloud.status_calls, [self.runtime_id])
        challenge.assert_not_called()
        self.assertEqual(self.cloud.commits[-1][0], self.cloud.commits[0][0])
        self.assertEqual(self.cloud.commits[-1][1], base64.b64decode(successor["bodyB64"]))
        self.assertTrue(self.cloud.commits[-1][2])
        self.assertEqual(client_runtime.load_reconciliation(
            self.state, "attach", self.old_session), link)
        self.assert_original_preserved()

    def test_key_or_successor_change_cannot_replace_existing_link(self):
        self.pending()
        self.cloud.commit_error = CloudError("request_timeout", ambiguous=True)
        self.invoke()
        link = client_runtime.load_reconciliation(self.state, "attach", self.old_session)
        for changed in ("key", "session"):
            with self.subTest(changed=changed):
                self.cloud.node_public_key = ("B" if changed == "key" else "A") * 43
                code, result, _, challenge = self.invoke(
                    session=identifier() if changed == "session" else self.session)
                self.assertEqual(code, 2)
                self.assertIn("reconciliation_link_mismatch", json.dumps(result))
                challenge.assert_not_called()
                self.assertEqual(len(self.cloud.commits), 1)
                self.assertEqual(client_runtime.load_reconciliation(
                    self.state, "attach", self.old_session), link)
                self.assert_original_preserved()

    def test_cas_race_does_not_install_mapping_or_erase_old_evidence(self):
        self.pending()
        self.cloud.commit_error = CloudError("conflict")
        code, result, _, _ = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("conflict", json.dumps(result))
        self.assert_original_preserved()
        self.assertIsNotNone(client_runtime.load_reconciliation(
            self.state, "attach", self.old_session))
        with Store(self.state) as store:
            self.assertIsNone(store.get_attachment(self.runtime_id))

    def test_local_persist_failure_keeps_both_pending_commits_and_link(self):
        self.pending()
        with patch.object(cli, "_store_native_mapping", return_value=(False, "local_operation_unavailable")):
            code, result, _, _ = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(result["remoteStatus"], "attached")
        self.assert_original_preserved()
        self.assertIsNotNone(cli.load_pending_commit(self.state, "attach", self.session))
        self.assertIsNotNone(client_runtime.load_reconciliation(
            self.state, "attach", self.old_session))

    def test_interrupted_challenge_leaves_link_for_identical_retry(self):
        self.pending()
        with patch.object(self.cloud, "native_challenge", side_effect=KeyboardInterrupt):
            code, result, _, _ = self.invoke()
        self.assertEqual(code, 130)
        self.assertEqual(result, {"reason": "interrupted"})
        link = client_runtime.load_reconciliation(self.state, "attach", self.old_session)
        self.assertIsNotNone(link)
        self.assertIsNone(cli.load_pending_commit(self.state, "attach", self.session))
        self.assertEqual(self.cloud.commits, [])
        self.assert_original_preserved()
        self.observation["attachmentGeneration"] = 44
        code, result, _, _ = self.invoke()
        self.assertEqual(code, 0, result)
        self.assertEqual(self.cloud.status_calls, [self.runtime_id])
        self.assertEqual(self.cloud.commits[0][0], link["intent"])
        self.assert_original_preserved()

    def test_retry_changed_binding_cannot_rewrite_link_or_send(self):
        self.pending()
        self.cloud.commit_error = CloudError("request_timeout", ambiguous=True)
        self.invoke()
        link = client_runtime.load_reconciliation(self.state, "attach", self.old_session)
        self.binding = {**self.binding, "generation": self.binding["generation"] + 1}
        code, result, _, challenge = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(result["lastError"], "pending_binding_changed")
        challenge.assert_not_called()
        self.assertEqual(len(self.cloud.commits), 1)
        self.assertEqual(client_runtime.load_reconciliation(
            self.state, "attach", self.old_session), link)
        self.assert_original_preserved()


    def test_different_original_cannot_claim_reserved_successor(self):
        root = self.state
        for first_completes in (False, True):
            with self.subTest(first_completes=first_completes):
                self.state = root / str(first_completes)
                self.old_session, self.session = identifier(), identifier()
                self.pending()
                first_session, first_path, first_bytes = self.old_session, self.old_path, self.old_bytes
                if first_completes:
                    self.assertEqual(self.invoke()[0], 0)
                else:
                    with patch.object(self.cloud, "native_challenge", side_effect=KeyboardInterrupt):
                        self.assertEqual(self.invoke()[0], 130)
                link = client_runtime.load_reconciliation(self.state, "attach", first_session)
                self.assertIsNotNone(link)
                self.assertIsNone(cli.load_pending_commit(self.state, "attach", self.session))
                self.old_session = identifier()
                self.pending()
                commits_before, challenges_before = len(self.cloud.commits), len(self.cloud.intents)
                code, result, _, challenge = self.invoke()
                self.assertEqual(code, 2)
                self.assertIn("reconciliation_successor_reserved", json.dumps(result))
                self.assertEqual(len(self.cloud.commits), commits_before)
                self.assertEqual(len(self.cloud.intents), challenges_before)
                challenge.assert_not_called()
                self.assert_original_preserved()
                self.assertEqual(first_path.read_bytes(), first_bytes)
                self.assertEqual(client_runtime.load_reconciliation(
                    self.state, "attach", first_session), link)
                self.assertIsNone(client_runtime.load_reconciliation(
                    self.state, "attach", self.old_session))

    def test_link_fsync_failures_send_nothing_and_remain_retryable(self):
        root = self.state
        real_fsync = os.fsync
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at):
                self.state = root / str(fail_at)
                self.old_session, self.session = identifier(), identifier()
                self.pending()
                calls = []

                def failing_fsync(fd):
                    calls.append(fd)
                    if len(calls) == fail_at:
                        raise OSError("synthetic fsync failure")
                    return real_fsync(fd)

                commits_before, challenges_before = len(self.cloud.commits), len(self.cloud.intents)
                with patch.object(client_runtime.os, "fsync", side_effect=failing_fsync):
                    code, result, _, challenge = self.invoke()
                self.assertEqual(code, 2)
                self.assertIn("pending_commit_unavailable", json.dumps(result))
                self.assertEqual(len(self.cloud.commits), commits_before)
                self.assertEqual(len(self.cloud.intents), challenges_before)
                challenge.assert_not_called()
                self.assert_original_preserved()
                self.assertIsNone(cli.load_pending_commit(self.state, "attach", self.session))
                retained = client_runtime.load_reconciliation(self.state, "attach", self.old_session)
                self.assertEqual(retained is not None, fail_at == 2)
                status_before = len(self.cloud.status_calls)
                code, result, _, _ = self.invoke()
                self.assertEqual(code, 0, result)
                self.assertEqual(len(self.cloud.status_calls) - status_before, 1 if fail_at == 1 else 0)
                if retained is not None:
                    self.assertEqual(client_runtime.load_reconciliation(
                        self.state, "attach", self.old_session), retained)
                self.assert_original_preserved()


class RuntimeStatusCloudTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.runtime_id, self.node_id = identifier(), identifier()
        self.key = Ed25519PrivateKey.generate()
        self.requests = []
        self.http_status = 200
        self.transport_error = None
        self.response = {
            "status": "present", "runtimeId": self.runtime_id, "observedAt": _iso(time.time()),
            "runtimeGeneration": 7, "nodeId": self.node_id, "nodeGeneration": 4,
            "attachmentGeneration": 11, "leaseUntil": _iso(time.time() - 90),
            "storedQualified": True,
            "nativeBinding": {
                "clientId": identifier(), "connectionId": identifier(), "backendPid": 123,
                "threadId": identifier(), "generation": 5,
                "serverInstanceId": identifier(), "serverGeneration": 8,
            },
        }
        self.client = CloudClient(
            origin="https://events.example.com", principal="adam@knitli.com", agent="codex",
            node_id=self.node_id, node_generation=4, private_key=self.key,
            credentials=self.credentials, send=self.send,
        )

    async def credentials(self):
        return Credentials("synthetic-access", "synthetic-agent")

    async def send(self, **request):
        self.requests.append(request)
        if self.transport_error:
            raise self.transport_error
        return self.http_status, {"content-type": "application/json"}, json.dumps(self.response).encode()

    async def test_status_signed_post_covers_exact_runtime_body_and_path(self):
        result = await self.client.runtime_status(self.runtime_id)
        self.assertEqual(result, self.response)
        request, = self.requests
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["url"], "https://events.example.com/v1/runtimes/status")
        self.assertEqual(json.loads(request["body"]), {"runtimeId": self.runtime_id})
        self.assertFalse(request["follow_redirects"])
        headers = request["headers"]
        self.assertEqual(headers["cf-access-token"], "synthetic-access")
        self.assertEqual(headers["authorization"], "Bearer synthetic-agent")
        proof = json.loads(headers["x-event-node-proof"])
        self.assertEqual(proof["nodeId"], self.node_id)
        self.assertEqual(proof["nodeGeneration"], 4)
        self.key.public_key().verify(
            base64.urlsafe_b64decode(proof["signature"] + "=="),
            canonical_node_proof(self.client.principal, self.client.origin,
                                 "/v1/runtimes/status", request["body"], proof),
        )

    async def test_missing_and_unqualified_present_are_valid_distinct_observations(self):
        self.response.update(storedQualified=False, nativeBinding=None)
        result = await self.client.runtime_status(self.runtime_id)
        self.assertEqual(result, self.response)
        self.response = {
            "status": "missing", "runtimeId": self.runtime_id, "observedAt": _iso(time.time()),
        }
        self.assertEqual(await self.client.runtime_status(self.runtime_id), self.response)

    async def test_strict_status_union_rejects_malformed_and_conflicting_fields(self):
        present = copy.deepcopy(self.response)
        cases = [
            {**present, "runtimeId": identifier()},
            {**present, "status": "denied"},
            {**present, "observedAt": "invalid"},
            {**present, "leaseUntil": "invalid"},
            {**present, "storedQualified": True, "nativeBinding": None},
            {**present, "storedQualified": 1},
            {**present, "runtimeGeneration": True},
            {**present, "nodeGeneration": False},
            {**present, "attachmentGeneration": True},
            {**present, "attachmentGeneration": 0},
            {**present, "extra": "not-in-contract"},
            {**present, "nativeBinding": {**present["nativeBinding"], "generation": True}},
            {**present, "nativeBinding": {**present["nativeBinding"], "extra": "unknown"}},
            {key: value for key, value in present.items() if key != "observedAt"},
            {**present, "status": "missing"},
            {"status": "missing", "runtimeId": self.runtime_id},
        ]
        for response in cases:
            with self.subTest(response=response):
                self.response = response
                with self.assertRaises(CloudError) as caught:
                    await self.client.runtime_status(self.runtime_id)
                self.assertEqual(caught.exception.code, "invalid_response")

    async def test_denial_http_unavailability_and_transport_failure_are_never_missing(self):
        for status, response, error, reason in (
            (403, {"error": "denied"}, None, "denied"),
            (503, {"error": "unavailable"}, None, "unavailable"),
            (200, {}, TimeoutError(), "request_timeout"),
            (200, {}, OSError("synthetic transport failure"), "unavailable"),
        ):
            with self.subTest(status=status, reason=reason):
                self.http_status, self.response, self.transport_error = status, response, error
                with self.assertRaises(CloudError) as caught:
                    await self.client.runtime_status(self.runtime_id)
                self.assertEqual(caught.exception.code, reason)

    async def test_invalid_runtime_id_refused_without_transport(self):
        for runtime_id in ("", "not-a-uuid", None, True):
            with self.subTest(runtime_id=runtime_id):
                with self.assertRaises(CloudError) as caught:
                    await self.client.runtime_status(runtime_id)
                self.assertEqual(caught.exception.code, "invalid_request")
        self.assertEqual(self.requests, [])
