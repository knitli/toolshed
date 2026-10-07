import asyncio
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway.cloud import CloudClient, CloudError, Credentials, canonical_node_proof
from event_gateway.protocol import _timestamp, derive_delivery_id


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "contracts/event-control-v1/fixtures.json").read_text())
NOW = _timestamp(FIXTURE["admitted"]["permitIssuedAt"]) / 1000
NODE = FIXTURE["admitted"]["nodeId"]
JSON_HEADERS = {"content-type": "application/json"}


class ExportPinTests(unittest.TestCase):
    def test_modified_source_refused_before_evaluation(self):
        # A local fixture under this checkout lets git identify the real revision
        # without creating commits or requiring another repository in CI.
        with tempfile.TemporaryDirectory(prefix="cloud-pin-test-", dir=ROOT) as directory:
            scratch = Path(directory)
            source = scratch / "packages/event-runtime/src"
            source.mkdir(parents=True)
            contract = ROOT / "contracts/event-control-v1"
            exporter = scratch / "export.mjs"
            shutil.copyfile(contract / "export.mjs", exporter)
            pin = json.loads((contract / "manifest.json").read_text())
            pin["revision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            for name in pin["sources"]:
                (source / Path(name).name).write_text("export const harmless = true;\n")
                pin["sources"][name] = hashlib.sha256((source / Path(name).name).read_bytes()).hexdigest()
            dependency = scratch / "zod"
            dependency.mkdir()
            (dependency / "package.json").write_text(json.dumps({"version": pin["zodVersion"]}))
            (dependency / "index.js").write_text("export const z = {};\n")
            (scratch / "manifest.json").write_text(json.dumps(pin))
            marker = scratch / "must-not-execute"
            (source / "contracts.ts").write_text(
                "import {writeFileSync} from 'node:fs';\n"
                "writeFileSync(process.env.EVENT_EXPORT_TEST_MARKER, 'executed');\n"
            )
            result = subprocess.run(
                ["node", str(exporter), str(scratch), str(dependency / "index.js"), "--check"],
                capture_output=True, text=True, timeout=10,
                env={**os.environ, "EVENT_EXPORT_TEST_MARKER": str(marker)},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists(), "modified source executed before its pin was checked")
            self.assertIn("source pin mismatch before evaluation", result.stderr)


class CloudTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.requests = []
        self.credential_calls = 0
        self.result = copy.deepcopy(FIXTURE["admitted"])
        self.status = 200
        self.now = NOW
        self.client = CloudClient(
            origin="https://events.example.com", principal=FIXTURE["original"]["principal"],
            agent=FIXTURE["original"]["agent"], node_id=NODE, node_generation=1,
            private_key=self.key, credentials=self.credentials, send=self.send, clock=lambda: self.now,
        )

    async def credentials(self):
        self.credential_calls += 1
        return Credentials(f"human-proof-{self.credential_calls}", f"agent-proof-{self.credential_calls}")

    async def send(self, **request):
        self.requests.append(request)
        return self.status, JSON_HEADERS, json.dumps(self.result).encode()

    async def test_source_canonical_vector_and_signed_exact_request(self):
        vector = FIXTURE["nodeProof"]
        self.assertEqual(canonical_node_proof(vector["principal"], vector["binding"]["audience"],
                                             vector["binding"]["path"], vector["body"].encode(),
                                             vector["proof"]).decode(), vector["canonical"])
        manifest = json.loads((ROOT / "contracts/event-control-v1/manifest.json").read_text())
        self.assertEqual(hashlib.sha256((ROOT / "contracts/event-control-v1/fixtures.json").read_bytes()).hexdigest(),
                         manifest["fixturesSha256"])
        result = await self.client.claim(FIXTURE["original"])
        self.assertEqual(result, FIXTURE["admitted"])
        self.assertNotEqual(result["envelope"]["expiresAt"], FIXTURE["original"]["expiresAt"])
        request = self.requests[-1]
        self.assertEqual(request["body"].decode(), vector["body"])
        self.assertEqual(request["method"], "POST")
        self.assertFalse(request["follow_redirects"])
        self.assertEqual(request["timeout"], 5)
        self.assertEqual(request["max_response_bytes"], 8192)
        proof = json.loads(request["headers"]["x-event-node-proof"])
        self.assertEqual(set(proof), {"nodeId", "nodeGeneration", "issuedAt", "nonce", "signature"})
        self.key.public_key().verify(base64.urlsafe_b64decode(proof["signature"] + "=="),
                                     canonical_node_proof(self.client.principal, self.client.origin,
                                                          "/v1/dispatch/claim", request["body"], proof))

    async def test_fresh_credentials_and_nonce_on_every_request(self):
        await self.client.claim(FIXTURE["original"])
        await self.client.claim(FIXTURE["original"])
        first, second = (request["headers"] for request in self.requests)
        self.assertEqual(self.credential_calls, 2)
        self.assertNotEqual(first["authorization"], second["authorization"])
        self.assertNotEqual(first["cf-access-token"], second["cf-access-token"])
        self.assertNotEqual(json.loads(first["x-event-node-proof"])["nonce"],
                            json.loads(second["x-event-node-proof"])["nonce"])
        self.assertNotIn("secret", repr(Credentials("secret", "secret")))

    async def test_delayed_claim_refreshes_transport_but_rejects_stale_reply(self):
        self.now += 3600
        self.result["permitIssuedAt"] = "2026-10-05T13:00:58.000Z"
        self.result["permitExpiresAt"] = "2026-10-05T13:01:03.000Z"
        self.result["envelope"]["issuedAt"] = "2026-10-05T13:00:58.000Z"
        self.result["envelope"]["expiresAt"] = "2026-10-05T13:01:58.000Z"
        try:
            result = await self.client.claim(FIXTURE["original"])
        except CloudError as error:
            self.fail("queued claim could not request refresh: " + error.code)
        self.assertEqual(result, self.result)
        self.assertEqual(len(self.requests), 1)
        self.result["envelope"] = copy.deepcopy(FIXTURE["original"])
        with self.assertRaisesRegex(CloudError, "^invalid_envelope$"):
            await self.client.claim(FIXTURE["original"])
        self.result = copy.deepcopy(FIXTURE["admitted"])
        with self.assertRaisesRegex(CloudError, "^permit_expired$"):
            await self.client.claim(FIXTURE["original"])

    async def test_closed_claim_response_and_permit_fences(self):
        mutations = {
            "extra": lambda value: value.update(extra=True),
            "missing_permit": lambda value: value.pop("permitId"),
            "bad_permit": lambda value: value.update(permitId="bad"),
            "wrong_node": lambda value: value.update(nodeId=FIXTURE["admitted"]["permitId"]),
            "wrong_status": lambda value: value.update(status="allowed"),
            "future": lambda value: value.update(permitIssuedAt="2026-10-05T12:00:59.000Z", permitExpiresAt="2026-10-05T12:01:04.000Z"),
            "expired": lambda value: value.update(permitIssuedAt="2026-10-05T12:00:53.000Z", permitExpiresAt="2026-10-05T12:00:58.000Z"),
            "too_long": lambda value: value.update(permitExpiresAt="2026-10-05T12:01:04.000Z"),
            "invalid_time": lambda value: value.update(permitIssuedAt=None),
            "old_envelope": lambda value: value.update(envelope=FIXTURE["original"]),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.result = copy.deepcopy(FIXTURE["admitted"])
                mutate(self.result)
                with self.assertRaises(CloudError):
                    await self.client.claim(FIXTURE["original"])

    async def test_every_admitted_semantic_field_binds_original(self):
        replacements = {
            "principal": "other@example.com", "agent": "other", "nodeGeneration": 2,
            "runtimeGeneration": 9, "attachmentGeneration": 9,
            "runtimeId": NODE, "attemptId": NODE, "eventId": NODE,
            "sourceStateVersion": "different", "policyRevision": 2,
            "eventReference": "ref_different", "reasonCode": "different",
            "observedAt": "2026-10-05T11:59:44.000Z",
            "canonicalSubject": {"kind": "manual", "subjectId": "different"},
        }
        for key, replacement in replacements.items():
            with self.subTest(key=key):
                self.result = copy.deepcopy(FIXTURE["admitted"])
                self.result["envelope"][key] = replacement
                self.result["envelope"]["deliveryId"] = derive_delivery_id(self.result["envelope"])
                with self.assertRaises(CloudError):
                    await self.client.claim(FIXTURE["original"])

    async def test_input_identity_rejected_before_http(self):
        envelope = copy.deepcopy(FIXTURE["original"])
        envelope["agent"] = "different"
        with self.assertRaises(CloudError):
            await self.client.claim(envelope)
        self.assertEqual(self.requests, [])

    async def test_closed_budget(self):
        self.result = copy.deepcopy(FIXTURE["overBudget"])
        self.assertEqual(await self.client.claim(FIXTURE["original"]), self.result)
        for key, bad in (("used", True), ("remaining", 1), ("limit", 11), ("windowMs", 2), ("extra", 0)):
            self.result = copy.deepcopy(FIXTURE["overBudget"])
            self.result["budget"][key] = bad
            with self.subTest(key=key), self.assertRaises(CloudError):
                await self.client.claim(FIXTURE["original"])

    async def test_http_refusal_codes_and_no_redirects(self):
        for status, body, code in ((403, {"error": "denied"}, "denied"),
                                   (503, {"error": "runtime_disabled"}, "runtime_disabled"),
                                   (409, {"error": "native_binding_unqualified"}, "native_binding_unqualified"),
                                   (500, {"error": "secret-server-text"}, "unavailable"),
                                   (302, {}, "redirect_refused")):
            self.status, self.result = status, body
            with self.subTest(status=status), self.assertRaisesRegex(CloudError, f"^{code}$"):
                await self.client.claim(FIXTURE["original"])

    async def test_untrusted_wire_body_is_closed_bounded_and_unambiguous(self):
        for raw, headers in ((b" " * 8193 + json.dumps(FIXTURE["admitted"]).encode(), JSON_HEADERS), (b'{}', {"content-type": "text/html"}),
                             (b'{}', {"content-type": "application/json", "content-encoding": "gzip"}),
                             (b'{"status":1,"status":2}', JSON_HEADERS),
                             (b'\xff', JSON_HEADERS), (b'NaN', JSON_HEADERS), (b'[]', JSON_HEADERS),
                             (b'{', JSON_HEADERS), (b'[' * 34 + b']' * 34, JSON_HEADERS)):
            async def send(**_):
                return 200, headers, raw
            self.client._send = send
            with self.subTest(raw=raw[:30]), self.assertRaisesRegex(CloudError, "^invalid_response$"):
                await self.client.claim(FIXTURE["original"])

    async def test_credentials_and_transport_errors_do_not_escape(self):
        async def fails(**_):
            raise RuntimeError("secret-secret-secret")
        self.client._send = fails
        with self.assertRaisesRegex(CloudError, "^unavailable$"):
            await self.client.claim(FIXTURE["original"])
        async def bad_credentials():
            raise RuntimeError("secret-secret-secret")
        self.client._credentials = bad_credentials
        with self.assertRaisesRegex(CloudError, "^unavailable$"):
            await self.client.claim(FIXTURE["original"])

    async def test_deadline_includes_credentials(self):
        cancelled = asyncio.Event()
        async def hangs():
            try:
                await asyncio.sleep(60)
            finally:
                cancelled.set()
        self.client._credentials = hangs
        with self.assertRaisesRegex(CloudError, "^request_timeout$"):
            await self.client.claim(FIXTURE["original"])
        self.assertTrue(cancelled.is_set())
        self.assertEqual(self.requests, [])

    async def test_credential_cloud_error_is_sanitized(self):
        async def fails():
            raise CloudError("synthetic-provider-detail")
        self.client._credentials = fails
        with self.assertRaisesRegex(CloudError, "^unavailable$") as caught:
            await self.client.claim(FIXTURE["original"])
        self.assertEqual(caught.exception.code, "unavailable")

    async def test_transport_cloud_error_is_sanitized(self):
        async def fails(**_):
            raise CloudError("synthetic-transport-detail")
        self.client._send = fails
        with self.assertRaisesRegex(CloudError, "^unavailable$") as caught:
            await self.client.claim(FIXTURE["original"])
        self.assertEqual(caught.exception.code, "unavailable")

    async def test_external_timeouts_and_cancellation_remain_truthful(self):
        for port in ("_credentials", "_send"):
            for error in (TimeoutError, asyncio.CancelledError):
                async def fails(**_):
                    raise error()
                self.client._credentials, self.client._send = self.credentials, self.send
                setattr(self.client, port, fails)
                expected = asyncio.CancelledError if error is asyncio.CancelledError else CloudError
                with self.subTest(port=port, error=error.__name__), self.assertRaises(expected) as caught:
                    await self.client.claim(FIXTURE["original"])
                if error is TimeoutError:
                    self.assertEqual(caught.exception.code, "request_timeout")

    def acknowledgment(self):
        protocol = json.loads((ROOT / "contracts/event-v1/protocol-v1.json").read_text())
        return copy.deepcopy(protocol["validAcknowledgments"][0])

    async def test_ack_retry_keeps_native_identity_and_only_sends_ack(self):
        ack = self.acknowledgment()
        self.result = {"status": "submitted", "current": False}
        self.now += 3600  # Legitimate reconciliation after transport freshness expires.
        for _ in range(2):
            self.assertEqual(await self.client.acknowledge(FIXTURE["original"], ack), self.result)
        self.assertEqual(len(self.requests), 2)
        self.assertTrue(all(request["url"].endswith("/v1/ack") for request in self.requests))
        self.assertEqual(self.requests[0]["body"], self.requests[1]["body"])
        self.assertNotEqual(self.requests[0]["headers"]["x-event-node-proof"],
                            self.requests[1]["headers"]["x-event-node-proof"])
        ack["status"] = "observed"
        ack["nativeCorrelation"] = {"kind": "turn", "submissionId": "subm_7e87", "turnId": "turn_7e87"}
        self.result = {"status": "observed", "current": True}
        self.assertEqual(await self.client.acknowledge(FIXTURE["original"], ack), self.result)

    async def test_ack_identity_and_closed_reply(self):
        ack = self.acknowledgment()
        for result in ({"status": "observed", "current": True, "extra": 1},
                       {"status": "unknown", "current": False}, {"status": "observed", "current": 1},
                       {"status": "observed", "current": False}, {"status": "submitted", "current": True}):
            self.result = result
            with self.assertRaises(CloudError):
                await self.client.acknowledge(FIXTURE["original"], ack)
        ack["attemptId"] = NODE
        self.requests.clear()
        with self.assertRaises(CloudError):
            await self.client.acknowledge(FIXTURE["original"], ack)
        self.assertEqual(self.requests, [])

    def challenge(self):
        challenge = {"nodeId": NODE, "challengeId": FIXTURE["admitted"]["permitId"],
                     "expiresAt": "2026-10-05T12:01:58.000Z"}
        x = base64.urlsafe_b64encode(self.key.public_key().public_bytes_raw()).rstrip(b"=").decode()
        challenge["signingPayload"] = json.dumps(["event-node-enrollment-v1", self.client.principal,
            challenge["challengeId"], challenge["expiresAt"], NODE, x, "100.96.0.1", 8789,
            [self.client.agent]], separators=(",", ":"))
        return challenge

    async def test_exact_owner_challenge_completion_signature(self):
        self.result = {"nodeId": NODE, "generation": 1}
        challenge = self.challenge()
        self.assertEqual(await self.client.complete_enrollment(challenge, mesh_ip="100.96.0.1",
                         mesh_port=8789, agents=[self.client.agent]), self.result)
        request = self.requests[-1]
        self.assertTrue(request["url"].endswith("/v1/nodes/complete"))
        self.assertNotIn("x-event-node-proof", request["headers"])
        payload = json.loads(request["body"])
        self.assertEqual(set(payload), {"challengeId", "signature"})
        self.key.public_key().verify(base64.urlsafe_b64decode(payload["signature"] + "=="),
                                    challenge["signingPayload"].encode())

    async def test_challenge_tampering_and_completion_identity_rejected(self):
        for key, value in (("nodeId", FIXTURE["admitted"]["permitId"]), ("signingPayload", "arbitrary"),
                           ("expiresAt", "2026-10-05T11:00:00.000Z"), ("challengeId", "bad")):
            challenge = self.challenge()
            challenge[key] = value
            with self.subTest(key=key), self.assertRaises(CloudError):
                await self.client.complete_enrollment(challenge, mesh_ip="100.96.0.1", mesh_port=8789, agents=[self.client.agent])
        self.assertEqual(self.requests, [])
        for result in ({"nodeId": NODE, "generation": 2}, {"nodeId": NODE, "generation": True},
                       {"nodeId": FIXTURE["admitted"]["permitId"], "generation": 1}):
            self.result = result
            with self.assertRaises(CloudError):
                await self.client.complete_enrollment(self.challenge(), mesh_ip="100.96.0.1", mesh_port=8789, agents=[self.client.agent])

    async def test_attach_renew_never_qualify(self):
        for method in (self.client.attach, self.client.renew):
            for status, result in ((409, {"error": "native_binding_unqualified"}), (200, {"status": "qualified"})):
                self.status, self.result = status, result
                with self.assertRaisesRegex(CloudError, "^native_binding_unqualified$"):
                    await method(FIXTURE["original"]["runtimeId"])


if __name__ == "__main__":
    unittest.main()
