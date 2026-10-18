"""Current-source material stays private until all pages and digest are verified."""
import base64
import copy
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import subprocess  # nosec B404 - used only for the fixed process-death fixture below.
import sys
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway import cli
from event_gateway.cloud import CloudClient, CloudError, Credentials, canonical_node_proof

SUBJECT = {"installationId": 1, "repositoryId": 2, "prNumber": 3}
REQUEST = {"subject": SUBJECT, "sourceId": "comment:7", "fingerprint": "f" * 64,
           "fromVersion": 3, "toVersion": 5}
BODY = "private 😀 first\nsecond é page"


def material_cursor(offset, binding="a" * 64, **extra):
    value = {"binding": binding, "offset": offset, **extra}
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def pages(chunks=None):
    chunks = chunks or ["private 😀 first\n", "second é page"]
    body = "".join(chunks)
    digest = hashlib.sha256(body.encode()).hexdigest()
    total = len(body.encode("utf-16-le")) // 2
    result, offset = [], 0
    for index, chunk in enumerate(chunks):
        last = index == len(chunks) - 1
        result.append({"status": "ok", **{key: copy.deepcopy(REQUEST[key]) for key in ("subject", "sourceId", "fingerprint")},
                       "requestedRange": {"fromVersion": 3, "toVersion": 5}, "firstVersion": 4,
                       "bodyDigest": digest, "offset": offset, "totalLength": total,
                       "body": chunk, "nextCursor": None if last else material_cursor(offset + len(chunk.encode("utf-16-le")) // 2),
                       "complete": last})
        offset += len(chunk.encode("utf-16-le")) // 2
    return result


class MaterialReadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.requests, self.results = [], pages()
        self.key = Ed25519PrivateKey.generate()
        self.credentials = AsyncMock(return_value=Credentials("access", "agent"))

        async def send(**request):
            self.requests.append(request)
            result = self.results.pop(0)
            if isinstance(result, Exception):
                raise result
            return 200, {"content-type": "application/json"}, json.dumps(result).encode()

        self.client = CloudClient(origin="https://events.example.com", principal="user@example.com",
            agent="codex", node_id="12345678-1234-4123-8123-123456789012", node_generation=1,
            private_key=self.key, credentials=self.credentials, send=send)

    async def test_exact_producer_range_fixture(self):
        # Copied producer DTO fixture; this does not rotate the trusted contract.
        fixture = json.loads((Path(__file__).parent / "fixtures/github-material-read-v1.json").read_text())
        self.results = [fixture["response"]]
        result = await self.client.github_source_material_all(fixture["request"])
        self.assertEqual(result, fixture["response"])
        self.assertEqual(json.loads(self.requests[-1]["body"]), fixture["request"])
        for status in ("unavailable", "deleted", "conflict"):
            self.results = [fixture[status]]
            self.assertEqual(await self.client.github_source_material_all(fixture["request"]), fixture[status])

    async def test_unicode_all_pages_and_exact_signed_path(self):
        result = await self.client.github_source_material_all(REQUEST)
        self.assertEqual(result["body"], BODY)
        self.assertTrue(result["complete"])
        self.assertEqual(result["offset"], 0)
        self.assertEqual(self.credentials.await_count, 2)
        for wire in self.requests:
            self.assertEqual(json.loads(wire["body"])["fromVersion"], 3)
            self.assertEqual(json.loads(wire["body"])["toVersion"], 5)
        self.assertEqual(json.loads(self.requests[1]["body"])["cursor"], material_cursor(len("private 😀 first\n".encode("utf-16-le")) // 2))
        for request in self.requests:
            self.assertEqual(request["url"], "https://events.example.com/v1/github/source/material")
            self.assertEqual(request["max_response_bytes"], 8192)
            self.assertFalse(request["follow_redirects"])
            proof = json.loads(request["headers"]["x-event-node-proof"])
            signature = base64.urlsafe_b64decode(proof["signature"] + "==")
            self.key.public_key().verify(signature, canonical_node_proof(self.client.principal,
                self.client.origin, "/v1/github/source/material", request["body"], proof))
            with self.assertRaises(InvalidSignature):
                self.key.public_key().verify(signature, canonical_node_proof(self.client.principal,
                    self.client.origin, "/v1/github/source/read", request["body"], proof))

    async def test_closed_request_rejects_invalid_input_before_credentials(self):
        invalid = [None, {**REQUEST, "extra": True}, {**REQUEST, "subject": {**SUBJECT, "prNumber": True}},
                   {**REQUEST, "sourceId": "arbitrary"}, {**REQUEST, "fingerprint": "F" * 64},
                   {**REQUEST, "cursor": None}, {**REQUEST, "cursor": "bad cursor"},
                   {**REQUEST, "sourceId": "thread-comment:" + "x" * 4096}]
        for request in invalid:
            with self.subTest(request=request), self.assertRaisesRegex(CloudError, "^invalid_request$"):
                await self.client.github_source_material(request)
        with self.assertRaisesRegex(CloudError, "^invalid_request$"):
            await self.client.github_source_material_all({**REQUEST, "cursor": "start"})
        self.credentials.assert_not_called()
        self.assertEqual(self.requests, [])

    async def test_range_required_ordered_and_safe_before_credentials(self):
        invalid = [{key: value for key, value in REQUEST.items() if key != removed}
                   for removed in ("fromVersion", "toVersion")]
        invalid += [{**REQUEST, **change} for change in (
            {"fromVersion": True}, {"toVersion": 2**53}, {"fromVersion": 0},
            {"fromVersion": 6}, {"toVersion": 2})]
        for request in invalid:
            with self.assertRaisesRegex(CloudError, "^invalid_request$"):
                await self.client.github_source_material_all(request)
        self.credentials.assert_not_called()
        self.assertEqual(self.requests, [])

    async def test_every_page_echoes_exact_range_and_first_version_is_covered(self):
        changes = [{"requestedRange": {"fromVersion": 2, "toVersion": 5}},
                   {"requestedRange": {"fromVersion": 3, "toVersion": True}},
                   {"requestedRange": {"fromVersion": 3, "toVersion": 5, "extra": 1}},
                   {"requestedRange": None}, {"firstVersion": 2}, {"firstVersion": 6}]
        for index in (0, 1):
            for change in changes:
                self.results = pages()
                self.results[index].update(change)
                with self.subTest(page=index, change=change), self.assertRaisesRegex(CloudError, "^invalid_response$"):
                    await self.client.github_source_material_all(REQUEST)
        self.results = pages()
        del self.results[0]["requestedRange"]
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_material_all(REQUEST)

    async def test_cursor_cannot_rebind_page_to_another_requested_range(self):
        self.results = [pages()[1]]
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_material({**REQUEST, "fromVersion": 4, "cursor": material_cursor(len("private 😀 first\n".encode("utf-16-le")) // 2)})

    async def test_closed_response_types_and_echoes(self):
        mutations = [lambda p: p.update(extra="raw"), lambda p: p.update(firstVersion=True),
            lambda p: p.update(offset=True), lambda p: p.update(totalLength=1048577),
            lambda p: p.update(bodyDigest="z" * 64), lambda p: p.update(body="\ud800"),
            lambda p: p.update(body="x" * 2049), lambda p: p.update(nextCursor="bad cursor"),
            lambda p: p.update(complete=1), lambda p: p.update(sourceId="comment:9"),
            lambda p: p.update(fingerprint="a" * 64), lambda p: p["subject"].update(repositoryId=True),
            lambda p: p.update(body=""), lambda p: p.update(offset=1)]
        for mutation in mutations:
            self.results = pages()
            mutation(self.results[0])
            with self.subTest(mutation=mutation), self.assertRaisesRegex(CloudError, "^invalid_response$"):
                await self.client.github_source_material(REQUEST)

    async def test_changed_identity_gaps_and_digest_swaps_fail(self):
        for mutation in [lambda p: p.update(firstVersion=5), lambda p: p.update(bodyDigest="b" * 64),
                         lambda p: p.update(offset=p["offset"] + 1),
                         lambda p: p.update(body=p["body"].replace("second", "tamper"))]:
            self.results = pages()
            mutation(self.results[1])
            with self.subTest(mutation=mutation), self.assertRaisesRegex(CloudError, "^invalid_response$"):
                await self.client.github_source_material_all(REQUEST)
        self.results = pages()
        for page in self.results:
            page["bodyDigest"] = "a" * 64
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_material_all(REQUEST)

    async def test_cursor_cycle_fails_and_terminal_refusals_return_no_partial_body(self):
        self.results = pages(["a", "b", "c"])
        self.results[1]["nextCursor"] = self.results[0]["nextCursor"]
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_material_all(REQUEST)
        for status in ("unavailable", "deleted", "conflict"):
            self.results = [pages()[0], {"status": status}]
            self.assertEqual(await self.client.github_source_material_all(REQUEST), {"status": status})
            self.results = [{"status": status, "body": "private"}]
            with self.assertRaisesRegex(CloudError, "^invalid_response$"):
                await self.client.github_source_material_all(REQUEST)

    async def test_failure_then_retry_restarts_and_uses_fresh_credentials(self):
        self.results = [pages()[0], OSError("private transport error")]
        with self.assertRaisesRegex(CloudError, "^unavailable$"):
            await self.client.github_source_material_all(REQUEST)
        self.results = pages()
        result = await self.client.github_source_material_all(REQUEST)
        self.assertEqual(result["body"], BODY)
        self.assertNotIn("cursor", json.loads(self.requests[2]["body"]))
        self.assertEqual(self.credentials.await_count, 4)

    async def test_traversal_bound_refuses_without_partial_result(self):
        offset = 0

        async def endless(request):
            nonlocal offset
            page = {**pages(["x"])[0], "body": "x", "offset": offset,
                    "totalLength": 4097, "complete": False, "nextCursor": f"page_{offset}"}
            offset += 1
            return page

        with patch.object(self.client, "github_source_material", side_effect=endless):
            with self.assertRaisesRegex(CloudError, "^material_read_limit$"):
                await self.client.github_source_material_all(REQUEST)
        self.assertEqual(offset, 4096)

    async def test_cursor_page_cannot_be_empty_for_nonempty_material(self):
        page = pages(["x"])[0]
        page.update(offset=1, body="")
        self.results = [page]
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_material({**REQUEST, "cursor": "continuation"})

    async def test_single_page_rejects_wrong_next_offset(self):
        self.results = pages()
        self.results[0]["nextCursor"] = material_cursor(1)
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_material(REQUEST)

    async def test_single_page_rejects_continuation_binding_switch(self):
        sequence = pages(["a", "b", "c"])
        self.results = [sequence[1]]
        self.results[0]["nextCursor"] = material_cursor(2, "b" * 64)
        with self.assertRaisesRegex(CloudError, "^invalid_response$"):
            await self.client.github_source_material({**REQUEST, "cursor": sequence[0]["nextCursor"]})

    async def test_cursor_structure_and_json_number_semantics(self):
        malformed = ["a", "bad_cursor", material_cursor(True), material_cursor(1.5),
                     material_cursor(-1), material_cursor(1048577), material_cursor(1, extra=1),
                     material_cursor(1, "A" * 64)]
        for cursor in malformed:
            with self.subTest(cursor=cursor):
                self.results = [pages(["a", "b"])[1]]
                with self.assertRaisesRegex(CloudError, "^invalid_response$"):
                    await self.client.github_source_material({**REQUEST, "cursor": cursor})
        for offset in (1, 1.0):
            self.results = [pages(["a", "b"])[1]]
            self.assertEqual((await self.client.github_source_material(
                {**REQUEST, "cursor": material_cursor(offset)}))["body"], "b")
        binding_json = json.dumps("a" * 64)
        for literal, accepted in (("1e0", True), ("-0", True),
                                  ("1e999", False), ("NaN", False), ("Infinity", False),
                                  ("NaN, \"offset\": 1", False),
                                  ("2, \"offset\": 1", True)):
            cursor_json = '{"binding":' + binding_json + ',"offset":' + literal + '}'
            cursor = base64.urlsafe_b64encode(cursor_json.encode()).rstrip(b"=").decode()
            page = pages(["a", "b"])[1]
            if literal == "-0":
                page = pages(["a"])[0]
            self.results = [page]
            with self.subTest(literal=literal):
                if accepted:
                    await self.client.github_source_material({**REQUEST, "cursor": cursor})
                else:
                    with self.assertRaisesRegex(CloudError, "^invalid_response$"):
                        await self.client.github_source_material({**REQUEST, "cursor": cursor})
        self.results = [{"status": "unavailable"}]
        self.assertEqual(await self.client.github_source_material({**REQUEST, "cursor": "opaque"}),
                         {"status": "unavailable"})

    async def test_empty_material_digest_is_verified(self):
        self.results = pages([""])
        self.assertEqual((await self.client.github_source_material_all(REQUEST))["body"], "")


class MaterialCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "finding.txt"
        self.args = ["--state-dir", str(self.root), "github-source-material", "--cloud-config", "/unused",
                     "--installation-id", "1", "--repository-id", "2", "--pr-number", "3",
                     "--from-version", "3", "--to-version", "5",
                     "--source-id", "comment:7", "--fingerprint", "f" * 64,
                     "--private-output", str(self.output)]
        self.client = AsyncMock()
        self.client.github_source_material_all.return_value = {**pages()[-1], "body": BODY}

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=self.client), redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(self.args)
        self.assertNotIn("private 😀", stdout.getvalue() + stderr.getvalue())
        return status, stdout.getvalue(), stderr.getvalue()

    def test_private_output_only_no_text_or_identity_on_terminal(self):
        status, stdout, _ = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout), {"materialRead": "written", "complete": True})
        self.assertEqual(self.output.read_text(), BODY)
        self.client.github_source_material_all.assert_awaited_once_with(REQUEST)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(self.invoke()[0], 2)  # Existing output is never overwritten.
        self.assertEqual(self.output.read_text(), BODY)

    def test_cli_requires_both_range_bounds_before_loading_credentials(self):
        for flag in ("--from-version", "--to-version"):
            index = self.args.index(flag)
            arguments = self.args[:index] + self.args[index + 2:]
            with patch.object(cli, "load_cloud_client") as load, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    cli.main(arguments)
                self.assertEqual(error.exception.code, 2)
                load.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_midpage_failure_leaves_no_output(self):
        for result in (CloudError("invalid_response"), {"status": "conflict"}, {"status": "deleted"}):
            if isinstance(result, Exception):
                self.client.github_source_material_all.side_effect = result
            else:
                self.client.github_source_material_all.side_effect = None
                self.client.github_source_material_all.return_value = result
            self.assertEqual(self.invoke()[0], 2)
            self.assertFalse(self.output.exists())

    def test_symlink_and_public_output_are_rejected_without_read(self):
        target = self.root / "target"
        target.write_text("unchanged")
        target.chmod(0o600)
        self.output.symlink_to(target)
        self.assertEqual(self.invoke()[0], 2)
        self.client.github_source_material_all.assert_not_called()
        self.assertEqual(target.read_text(), "unchanged")
        self.output.unlink()
        self.root.chmod(0o755)
        self.assertEqual(self.invoke()[0], 2)
        self.client.github_source_material_all.assert_not_called()
        self.root.chmod(0o700)
        self.output.write_text("public existing file")
        self.output.chmod(0o644)
        self.assertEqual(self.invoke()[0], 2)
        self.assertEqual(self.output.read_text(), "public existing file")

    def test_output_failure_removes_file_and_permission_change_blocks_write(self):
        with patch.object(cli.os, "fsync", side_effect=OSError("private filesystem detail")):
            self.assertEqual(self.invoke()[0], 2)
        self.assertFalse(self.output.exists())

        async def changed_permission(_):
            self.root.chmod(0o755)
            return {**pages()[-1], "body": BODY}

        self.client.github_source_material_all.side_effect = changed_permission
        self.assertEqual(self.invoke()[0], 2)
        self.assertFalse(self.output.exists())
        self.root.chmod(0o700)

    def test_atomic_publication_cannot_replace_concurrent_target(self):
        real_link = cli.os.link

        def collision(*args, **kwargs):
            self.output.write_text("other writer")
            return real_link(*args, **kwargs)

        with patch.object(cli.os, "link", side_effect=collision):
            self.assertEqual(self.invoke()[0], 2)
        self.assertEqual(self.output.read_text(), "other writer")
        self.assertEqual(list(self.root.glob(".finding-material-*")), [])

    def test_cleanup_failure_can_leave_only_complete_final_and_private_temporary(self):
        with patch.object(cli.os, "unlink", side_effect=OSError("cleanup failed")):
            self.assertEqual(self.invoke()[0], 2)
        self.assertEqual(self.output.read_text(), BODY)
        temporary, = self.root.glob(".finding-material-*")
        self.assertEqual(temporary.read_text(), BODY)
        self.assertEqual(stat.S_IMODE(temporary.stat().st_mode), 0o600)

    def test_process_death_before_publication_never_exposes_partial_final(self):
        code = """import os, sys
from event_gateway.cli import _publish_material
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
os.fsync = lambda fd: os._exit(17)
_publish_material(fd, 'finding.txt', 'private incomplete write')
"""
        result = subprocess.run(  # nosec B603 - fixed interpreter and literal fixture code, no shell.
            [sys.executable, "-c", code, str(self.root)], capture_output=True, check=False)
        self.assertEqual(result.returncode, 17)
        self.assertFalse(self.output.exists())
        temporary, = self.root.glob(".finding-material-*")
        self.assertEqual(stat.S_IMODE(temporary.stat().st_mode), 0o600)

    def test_symlink_parent_is_rejected(self):
        directory = self.root / "real"
        directory.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        self.args[-1] = str(alias / "finding.txt")
        self.assertEqual(self.invoke()[0], 2)
        self.client.github_source_material_all.assert_not_called()
        self.assertFalse((directory / "finding.txt").exists())
