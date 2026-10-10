"""Consume cloud-exported runtime status and node-proof vectors unchanged."""

import base64
import hashlib
import json
from pathlib import Path
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway.cloud import (
    CloudClient, CloudError, Credentials, _runtime_status_response, canonical_node_proof,
)
from event_gateway.protocol import _timestamp


FIXTURE = json.loads((Path(__file__).resolve().parents[1]
                      / "contracts/event-control-v1/fixtures.json").read_text())["nativeAdmission"]["runtimeStatus"]


class RuntimeStatusContractTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        vector = FIXTURE["nodeProof"]
        self.key = Ed25519PrivateKey.generate()
        self.requests = []

        async def credentials():
            return Credentials("synthetic-access", "synthetic-agent")

        async def send(**request):
            self.requests.append(request)
            return 200, {"content-type": "application/json"}, json.dumps(FIXTURE["responses"]["missing"]).encode()

        self.client = CloudClient(
            origin=vector["binding"]["audience"], principal=vector["principal"], agent=vector["agent"],
            node_id=vector["proof"]["nodeId"], node_generation=vector["proof"]["nodeGeneration"],
            private_key=self.key, credentials=credentials, send=send,
            clock=lambda: _timestamp(vector["proof"]["issuedAt"]) / 1000,
            nonce=lambda: uuid.UUID(vector["proof"]["nonce"]),
        )

    async def test_exact_exported_request_and_canonical_node_proof_are_signed(self):
        vector = FIXTURE["nodeProof"]
        result = await self.client.runtime_status(FIXTURE["request"]["runtimeId"])
        self.assertEqual(result, FIXTURE["responses"]["missing"])
        request, = self.requests
        self.assertEqual(request["method"], vector["binding"]["method"])
        self.assertEqual(request["url"], vector["binding"]["audience"] + vector["binding"]["path"])
        self.assertEqual(request["body"], vector["body"].encode())
        self.assertEqual(json.loads(request["body"]), FIXTURE["request"])
        self.assertEqual(hashlib.sha256(request["body"]).hexdigest(), vector["binding"]["bodySha256"])
        proof = json.loads(request["headers"]["x-event-node-proof"])
        signature = proof.pop("signature")
        self.assertEqual(proof, vector["proof"])
        self.assertEqual(canonical_node_proof(
            vector["principal"], vector["binding"]["audience"], vector["binding"]["path"],
            request["body"], proof,
        ), vector["canonical"].encode())
        self.key.public_key().verify(base64.urlsafe_b64decode(signature + "=="),
                                     vector["canonical"].encode())

    def test_exported_response_acceptance_and_rejection_parity(self):
        runtime_id = FIXTURE["request"]["runtimeId"]
        for name, response in FIXTURE["responses"].items():
            with self.subTest(accepted=name):
                self.assertEqual(_runtime_status_response(response, runtime_id), response)
        for rejection in FIXTURE["rejections"]:
            if rejection.get("request"):
                continue
            with self.subTest(rejected=rejection["name"]):
                with self.assertRaises(CloudError) as caught:
                    _runtime_status_response(rejection["value"], runtime_id)
                self.assertEqual(caught.exception.code, "invalid_response")
        expired = FIXTURE["responses"]["expired"]
        self.assertLess(_timestamp(expired["leaseUntil"]), _timestamp(expired["observedAt"]))
        self.assertEqual((expired["runtimeGeneration"], expired["attachmentGeneration"]), (7, 9))

    async def test_exported_request_rejections_never_reach_transport(self):
        for rejection in FIXTURE["rejections"]:
            if not rejection.get("request"):
                continue
            value = rejection["value"]
            with self.subTest(rejected=rejection["name"]):
                extra = {key: item for key, item in value.items() if key != "runtimeId"}
                if extra:
                    # This public API accepts only a runtime ID, never an arbitrary request DTO.
                    with self.assertRaises(TypeError):
                        await self.client.runtime_status(value["runtimeId"], **extra)
                else:
                    with self.assertRaises(CloudError) as caught:
                        await self.client.runtime_status(value["runtimeId"])
                    self.assertEqual(caught.exception.code, "invalid_request")
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
