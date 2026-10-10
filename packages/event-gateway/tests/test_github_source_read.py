"""GitHub readback trust boundary and supported one-page command."""
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
from event_gateway.cloud import CloudClient, CloudError, Credentials

SUBJECT = {"installationId": 1, "repositoryId": 2, "prNumber": 3}
REQUEST = {"subject": SUBJECT, "fromVersion": 2, "toVersion": 3}
CURSOR = {"subjectKey": "[1,2,3]", "fromVersion": 2, "toVersion": 3,
          "anchorVersion": 4, "anchorEpoch": 1, "revision": "r1", "policyRevision": "p1", "offset": 1}
PAGE = {"status": "ok", "subject": SUBJECT, "requestedRange": {"fromVersion": 2, "toVersion": 3},
        "coverageStartVersion": 1, "anchor": {"sourceVersion": 4, "epoch": 1, "observedAt": 0},
        "items": [{"phase": "anchor", "sourceVersion": 4, "epoch": 1, "recordType": "terminal",
                   "recordKey": "state", "value": {"from": None, "to": "open"}}],
        "nextCursor": CURSOR, "complete": False}


class SourceReadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.requests = []
        self.result = copy.deepcopy(PAGE)
        self.http_status = 200

        async def send(**request):
            self.requests.append(request)
            return self.http_status, {"content-type": "application/json"}, json.dumps(self.result).encode()

        self.credentials = AsyncMock(return_value=Credentials("access", "agent"))
        self.client = CloudClient(
            origin="https://events.example.com", principal="user@example.com", agent="codex",
            node_id="12345678-1234-4123-8123-123456789012", node_generation=1,
            private_key=Ed25519PrivateKey.generate(), credentials=self.credentials, send=send,
        )

    async def test_signed_one_page_and_continuation(self):
        self.assertEqual(await self.client.github_source_read(REQUEST), PAGE)
        wire = self.requests[0]
        self.assertEqual(wire["url"], "https://events.example.com/v1/github/source/read")
        self.assertEqual(json.loads(wire["body"]), REQUEST)
        self.assertIn("x-event-node-proof", wire["headers"])
        self.assertEqual(wire["max_response_bytes"], 8192)
        self.assertFalse(wire["follow_redirects"])
        self.result.update(nextCursor=None, complete=True)
        self.result["items"][0].update(phase="transition", sourceVersion=3)
        await self.client.github_source_read({**REQUEST, "cursor": CURSOR})
        self.assertEqual(len(self.requests), 2)

    async def test_retained_anchor_can_precede_current_lifecycle_epoch(self):
        self.result["anchor"]["epoch"] = 2
        self.result["nextCursor"]["anchorEpoch"] = 2
        await self.client.github_source_read(REQUEST)
        self.result["items"].append({**self.result["items"][0], "epoch": 2})
        self.result["nextCursor"]["offset"] = 2
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_read(REQUEST)

    async def test_closed_projection_for_every_record_type(self):
        projections = {
            "version": {"complete": True, "observedAt": 0, "candidateGeneration": 0,
                        "coverageStartVersion": 1, "candidate": {"headSha": "a" * 40,
                        "baseSha": "b" * 40, "observedMergeSha": None}, "state": "open"},
            "finding": {"sourceId": "review:1", "from": None, "to": {"presence": "present",
                        "kind": "review", "sourceHeadSha": None, "fingerprint": "a" * 64,
                        "disposition": "open", "outdated": False}},
            "request": {"kind": "review_request", "identity": "user:1", "from": None, "to": "present"},
            "run": {"from": None, "to": {"presence": "present", "kind": "check", "sourceId": "1",
                    "headSha": "a" * 40, "attempt": None, "status": None, "conclusion": None,
                    "startedAt": None, "completedAt": None}},
        }
        for kind, projection in projections.items():
            with self.subTest(kind=kind):
                self.result["items"][0].update(recordType=kind, value=copy.deepcopy(projection))
                await self.client.github_source_read(REQUEST)
                self.result["items"][0]["value"]["providerBody"] = "private raw metadata"
                with self.assertRaisesRegex(CloudError, "^invalid_response$"):
                    await self.client.github_source_read(REQUEST)
        self.result["items"][0]["value"] = copy.deepcopy(projections["run"])
        self.result["items"][0]["value"]["to"]["url"] = "private"
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_read(REQUEST)

    async def test_invalid_requests_never_load_credentials_or_send(self):
        cases = [None, {**REQUEST, "extra": 1}, {**REQUEST, "fromVersion": True},
                 {**REQUEST, "toVersion": 2**53}, {**REQUEST, "fromVersion": 4},
                 {**REQUEST, "subject": {**SUBJECT, "repositoryId": False}},
                 {**REQUEST, "cursor": {**CURSOR, "subjectKey": "[1,2,4]"}},
                 {**REQUEST, "cursor": {**CURSOR, "offset": -1}},
                 {**REQUEST, "cursor": {**CURSOR, "revision": "x" * 257}}]
        for request in cases:
            with self.subTest(request=request), self.assertRaisesRegex(CloudError, "^invalid_request$"):
                await self.client.github_source_read(request)
        self.credentials.assert_not_called()
        self.assertFalse(self.requests)

    async def test_response_binding_and_projection_fail_closed(self):
        mutations = [
            lambda p: p["subject"].update(repositoryId=True),
            lambda p: p["requestedRange"].update(toVersion=4),
            lambda p: p.update(complete=True),
            lambda p: p.update(coverageStartVersion=3),
            lambda p: p["anchor"].update(epoch=True),
            lambda p: p["nextCursor"].update(offset=0),
            lambda p: p["nextCursor"].update(anchorVersion=5),
            lambda p: p["items"][0].update(epoch=2),
            lambda p: p["items"][0].update(recordType="raw"),
            lambda p: p["items"][0].update(sourceVersion=1),
            lambda p: p["items"][0]["value"].update(to={"secret": "bad"}),
            lambda p: p.update(items=[]),
            lambda p: p.update(extra="secret"),
        ]
        for mutate in mutations:
            self.result = copy.deepcopy(PAGE)
            mutate(self.result)
            with self.subTest(mutation=mutate), self.assertRaisesRegex(CloudError, "^invalid_response$"):
                await self.client.github_source_read(REQUEST)
        self.result = copy.deepcopy(PAGE)
        self.result["nextCursor"].update(offset=2, revision="changed")
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_read({**REQUEST, "cursor": CURSOR})

    async def test_explicit_outcomes_and_no_retry(self):
        for status in ("conflict", "coverage_unavailable"):
            self.result = {"status": status}
            self.assertEqual(await self.client.github_source_read(REQUEST), self.result)
            self.result["body"] = "private"
            with self.assertRaisesRegex(CloudError, "^invalid_response$"):
                await self.client.github_source_read(REQUEST)
        self.http_status, self.result = 403, {"error": "denied"}
        before = len(self.requests)
        with self.assertRaisesRegex(CloudError, "^denied$"):
            await self.client.github_source_read(REQUEST)
        self.assertEqual(len(self.requests), before + 1)


class SourceReadCliTests(unittest.TestCase):
    def test_one_page_command_and_safe_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            args = ["--state-dir", str(Path(directory).resolve()), "github-source-read", "--cloud-config", "/unused",
                    "--installation-id", "1", "--repository-id", "2", "--pr-number", "3",
                    "--from-version", "2", "--to-version", "3"]
            for result, expected in ((PAGE, 0), ({"status": "conflict"}, 2),
                                     ({"status": "coverage_unavailable"}, 2), (CloudError("denied"), 2)):
                client = AsyncMock()
                if isinstance(result, CloudError):
                    client.github_source_read.side_effect = result
                else:
                    client.github_source_read.return_value = result
                stdout = io.StringIO()
                with patch.object(cli, "load_cloud_client", return_value=client), redirect_stdout(stdout):
                    self.assertEqual(cli.main(args + ["--cursor", json.dumps(CURSOR)]), expected)
                client.github_source_read.assert_awaited_once_with({**REQUEST, "cursor": CURSOR})
                self.assertEqual(json.loads(stdout.getvalue()),
                                 {"sourceRead": None, "reason": "denied"} if isinstance(result, CloudError) else result)
            for cursor in ('{"offset":1,"offset":2}', "[", "x" * 4097):
                with patch.object(cli, "load_cloud_client") as load, redirect_stdout(io.StringIO()) as stdout:
                    self.assertEqual(cli.main(args + ["--cursor", cursor]), 2)
                    load.assert_not_called()
                    self.assertEqual(json.loads(stdout.getvalue()), {"sourceRead": None, "reason": "invalid_request"})
