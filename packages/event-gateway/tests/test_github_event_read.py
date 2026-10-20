"""Opaque GitHub event references use the existing authenticated read boundary."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway import cli
from event_gateway.cloud import CloudClient, CloudError, Credentials, _github_event_response

REQUEST = {"eventReference": "ref_12345678-1234-4123-8123-123456789012"}
RESULT = {"status": "ok", "subject": {"installationId": 1, "repositoryId": 2, "prNumber": 3},
          "sourceVersion": 4, "eventKind": "ci", "reasonCode": "check_failed",
          "candidateGeneration": 1, "observedAt": 1000}


class GitHubEventReadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.requests = []
        self.result = copy.deepcopy(RESULT)

        async def send(**request):
            self.requests.append(request)
            return 200, {"content-type": "application/json"}, json.dumps(self.result).encode()

        self.credentials = AsyncMock(return_value=Credentials("access", "agent"))
        self.client = CloudClient(
            origin="https://events.example.com", principal="user@example.com", agent="codex",
            node_id="12345678-1234-4123-8123-123456789012", node_generation=1,
            private_key=Ed25519PrivateKey.generate(), credentials=self.credentials, send=send,
        )

    async def test_signed_metadata_read_and_closed_refusals(self):
        self.assertEqual(await self.client.github_event_read(REQUEST), RESULT)
        self.assertEqual(self.requests[0]["url"], "https://events.example.com/v1/github/event/read")
        self.assertEqual(json.loads(self.requests[0]["body"]), REQUEST)
        self.assertIn("x-event-node-proof", self.requests[0]["headers"])
        for status in ("unavailable", "conflict"):
            self.result = {"status": status}
            self.assertEqual(await self.client.github_event_read(REQUEST), self.result)

    async def test_invalid_reference_never_acquires_credentials_or_sends(self):
        for request in ({}, {**REQUEST, "subject": {}}, {"eventReference": "latest"},
                        {"eventReference": True}, {"eventReference": "ref_" + "a" * 37}):
            with self.subTest(request=request), self.assertRaisesRegex(CloudError, "^invalid_request$"):
                await self.client.github_event_read(request)
        self.credentials.assert_not_called()
        self.assertFalse(self.requests)

    async def test_pinned_cloud_vectors(self):
        corpus = json.loads((Path(__file__).resolve().parents[1] /
            "contracts/event-control-v1/fixtures.json").read_text())["githubEventRead"]
        for vector in corpus["requests"]:
            with self.subTest(request=vector["name"]):
                if vector["accepted"]:
                    self.assertEqual(await self.client.github_event_read(vector["value"]), self.result)
                else:
                    with self.assertRaisesRegex(CloudError, "^invalid_request$"):
                        await self.client.github_event_read(vector["value"])
        for vector in corpus["results"]:
            with self.subTest(result=vector["name"]):
                self.result = vector["value"]
                if vector["accepted"]:
                    self.assertEqual(await self.client.github_event_read(corpus["request"]), self.result)
                else:
                    with self.assertRaisesRegex(CloudError, "^invalid_response$"):
                        await self.client.github_event_read(corpus["request"])

    def test_unbounded_or_malformed_metadata_is_rejected(self):
        invalid = [{**RESULT, "body": "provider text"}, {"status": "unavailable", "subject": {}},
                   {**RESULT, "subject": {**RESULT["subject"], "prNumber": True}},
                   {**RESULT, "subject": None}, {**RESULT, "eventKind": "message"},
                   {**RESULT, "reasonCode": "unknown"}]
        for key in ("sourceVersion", "candidateGeneration", "observedAt"):
            invalid.extend({**RESULT, key: value} for value in (0, True, 2**53, 1.5))
        for value in invalid:
            with self.subTest(value=value), self.assertRaisesRegex(CloudError, "^invalid_response$"):
                _github_event_response(value)


class GitHubEventReadCliTests(unittest.TestCase):
    def test_metadata_output_and_safe_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            args = ["--state-dir", str(Path(directory).resolve()), "github-event-read",
                    "--cloud-config", "/unused", "--event-reference", REQUEST["eventReference"]]
            for result, exit_code in ((RESULT, 0), ({"status": "unavailable"}, 2),
                                      (CloudError("denied"), 2)):
                client = AsyncMock()
                if isinstance(result, CloudError):
                    client.github_event_read.side_effect = result
                else:
                    client.github_event_read.return_value = result
                with patch.object(cli, "load_cloud_client", return_value=client), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(cli.main(args), exit_code)
                client.github_event_read.assert_awaited_once_with(REQUEST)
                self.assertEqual(json.loads(output.getvalue()),
                                 {"eventRead": None, "reason": "denied"} if isinstance(result, CloudError) else result)
