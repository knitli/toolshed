"""Exercise the trusted verifier with candidate bytes, without credentials/network."""
import base64
import hashlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import textwrap
import unittest
from unittest.mock import patch


PACKAGE = Path(__file__).resolve().parents[1]
WORKFLOW = PACKAGE.parents[1] / ".github/workflows/event-gateway-contract.yml"
SOURCE = textwrap.dedent(WORKFLOW.read_text().split("<<'PYTHON'\n", 1)[1].rsplit("          PYTHON", 1)[0])
with tempfile.TemporaryDirectory() as policy_directory:
    policy_path = Path(policy_directory) / "verifier.py"
    policy_path.write_text(SOURCE)
    POLICY = runpy.run_path(str(policy_path), run_name="workflow_test")["verify_contract"].__globals__
HEAD = "a" * 40
SNAPSHOT = "packages/event-gateway/contracts/"
PATHS = (
    "event-v1/protocol.schema.json", "event-v1/protocol.ts",
    "event-v1/policy.ts", "event-v1/protocol-v1.json", "event-v1/manifest.json",
    "event-control-v1/fixtures.json", "event-control-v1/manifest.json",
)


def family(name, blobs):
    return {"name": name, "hashes": {
        path: hashlib.sha256(blobs[SNAPSHOT + path]).hexdigest() for path in PATHS}}


class ContractWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.original = {SNAPSHOT + path: (PACKAGE / "contracts" / path).read_bytes()
                         for path in PATHS}
        self.blobs = self.original.copy()
        self.reads = []
        self.api_reads = []
        self.tree = {"truncated": False, "tree": [
            {"path": SNAPSHOT + path, "type": "blob", "mode": "100644"} for path in PATHS]}
        self.rotated = {path: value + b"\n" for path, value in self.original.items()}
        for path in ("event-v1/manifest.json", "event-control-v1/manifest.json"):
            manifest = json.loads(self.original[SNAPSHOT + path])
            if "files" in manifest:
                for entry in manifest["files"]:
                    entry["sha256"] = hashlib.sha256(
                        self.rotated[SNAPSHOT + "event-v1/" + entry["file"]]).hexdigest()
            else:
                manifest["fixturesSha256"] = hashlib.sha256(
                    self.rotated[SNAPSHOT + "event-control-v1/fixtures.json"]).hexdigest()
            self.rotated[SNAPSHOT + path] = (json.dumps(manifest, indent=2) + "\n").encode()
        self.families = (family("original", self.original), family("rotated", self.rotated))

    def read_blob(self, path, ref, token):
        self.assertEqual(ref, HEAD)
        self.assertEqual(token, "test-token")
        self.reads.append(path)
        return self.blobs[path]

    def verify(self, families=None, head=HEAD):
        def request(endpoint, token, payload=None):
            self.api_reads.append(endpoint)
            self.assertEqual(endpoint, f"git/trees/{HEAD}?recursive=1")
            self.assertEqual(token, "test-token")
            self.assertIsNone(payload)
            return self.tree
        replacements = {"read_blob": self.read_blob, "request_json": request}
        if families is not None:
            replacements["FAMILIES"] = families
        with patch.dict(POLICY, replacements):
            return POLICY["verify_contract"](head, "test-token")

    def test_checked_in_snapshot_and_fixed_paths(self):
        accepted = self.verify()
        self.assertIn(accepted, [entry["name"] for entry in POLICY["FAMILIES"]])
        self.assertCountEqual(self.reads, [SNAPSHOT + path for path in PATHS])

    def test_complete_approved_families(self):
        for name, blobs in (("original", self.original), ("rotated", self.rotated)):
            with self.subTest(family=name):
                self.blobs = blobs.copy()
                self.assertEqual(self.verify(self.families), name)

    def test_crossed_families_rejected_for_every_file(self):
        for path in PATHS:
            with self.subTest(path=path):
                self.blobs = self.original.copy()
                self.blobs[SNAPSHOT + path] = self.rotated[SNAPSHOT + path]
                with self.assertRaises(ValueError):
                    self.verify(self.families)

    def test_every_fixed_file_change_or_omission_rejected(self):
        for path in PATHS:
            for missing in (False, True):
                with self.subTest(path=path, missing=missing):
                    self.blobs = self.original.copy()
                    if missing:
                        del self.blobs[SNAPSHOT + path]
                    else:
                        self.blobs[SNAPSHOT + path] += b"unapproved"
                    with self.assertRaises((ValueError, KeyError)):
                        self.verify(self.families)

    def test_candidate_metadata_cannot_authorize_new_bytes(self):
        # Both manifests truthfully hash the new bytes, but only trusted policy
        # can authorize a new complete family.
        self.blobs = self.rotated.copy()
        with self.assertRaises(ValueError):
            self.verify(self.families[:1])

    def test_malformed_head_does_not_read(self):
        for head in (None, 123, "main", "a" * 39, "a" * 41, "A" * 40, HEAD + "\n"):
            with self.subTest(head=head):
                self.reads.clear()
                self.api_reads.clear()
                with self.assertRaises(ValueError):
                    self.verify(head=head)
                self.assertEqual(self.reads, [])
                self.assertEqual(self.api_reads, [])

    def test_redirects_are_refused(self):
        with self.assertRaises(ValueError):
            POLICY["NoRedirect"]().redirect_request(None, None, 302, "", {}, "https://attacker.invalid")

    def read_response(self, raw):
        with patch.object(POLICY["urllib"].request, "build_opener") as opener:
            response = io.BytesIO(raw)
            opener.return_value.open.return_value = response
            result = POLICY["read_blob"]("fixed-path", HEAD, "test-token")
            requested = opener.return_value.open.call_args.args[0]
            self.assertEqual(requested.full_url,
                             "https://api.github.com/repos/knitli/toolshed/contents/fixed-path?ref=" + HEAD)
            return result

    def test_blob_response_accepts_base64_file(self):
        self.assertEqual(self.read_response(json.dumps({
            "type": "file", "encoding": "base64", "content": "ZG\nF0YQ==\n", "size": 4,
        }).encode()), b"data")

    def test_blob_response_is_bounded(self):
        # Valid JSON past the limit distinguishes the size guard from JSON errors.
        raw = json.dumps({"type": "file", "encoding": "base64",
                          "content": "", "size": 0}).encode()
        with self.assertRaises(ValueError):
            self.read_response(raw + b" " * POLICY["LIMIT"])

    def test_blob_response_rejects_nonfiles_encoding_and_size(self):
        valid = {"type": "file", "encoding": "base64",
                 "content": base64.b64encode(b"data").decode(), "size": 4}
        for change in ({"type": "symlink"}, {"type": "dir"}, {"encoding": "none"},
                       {"content": "ZGF0YQ==!!!!"}, {"size": 5}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    self.read_response(json.dumps(valid | change).encode())

    def refresh(self, heads=(HEAD,), during_verification=None, event_name="push", event=None,
                before_request=None):
        if event is None:
            event = {"ref": "refs/heads/main"}
        workflow_sha = "c" * 40
        main_sha = "d" * 40
        workflow_source = b"trusted workflow bytes"
        self.current_policy = workflow_source
        self.current_heads = dict(enumerate(heads, 1))
        posts = self.runner_posts = []
        candidate_reads = self.runner_candidate_reads = []
        self.runner_api_reads = []

        def request(endpoint, token, payload=None):
            self.assertEqual(token, "test-token")
            self.runner_api_reads.append(endpoint)
            if before_request is not None:
                before_request(endpoint, payload)
            if endpoint.startswith("git/trees/"):
                self.assertIn(endpoint, [f"git/trees/{head}?recursive=1" for head in heads])
                return self.tree
            if endpoint == "pulls?state=open&per_page=50&page=1":
                return [{"number": number, "head": {"sha": head}}
                        for number, head in enumerate(heads, 1)]
            if endpoint.startswith("pulls/"):
                number = int(endpoint.split("/")[1])
                return {"state": "open", "head": {"sha": self.current_heads[number]}}
            if endpoint == "git/ref/heads/main":
                return {"object": {"sha": main_sha}}
            self.assertTrue(endpoint.startswith("statuses/"), endpoint)
            posts.append((endpoint, payload))
            return {}

        def read(path, ref, token):
            nonlocal during_verification
            self.assertEqual(token, "test-token")
            if path == ".github/workflows/event-gateway-contract.yml":
                self.assertIn(ref, (workflow_sha, main_sha))
                return workflow_source if ref == workflow_sha else self.current_policy
            self.assertIn(ref, heads)
            candidate_reads.append((path, ref))
            if during_verification is not None:
                during_verification()
                during_verification = None
            return self.blobs[path]

        with patch.dict(POLICY, {"request_json": request, "read_blob": read}):
            results = POLICY["revalidate"]("test-token", "https://example.test/run", workflow_sha,
                                            event_name, event)
        return results, posts, candidate_reads

    def test_policy_refresh_verifies_every_open_head(self):
        heads = (HEAD, "b" * 40)
        results, posts, reads = self.refresh(heads)
        self.assertEqual(results, [(1, heads[0], "success"), (2, heads[1], "success")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + head, state) for head in heads
                          for state in ("pending", "success")])
        self.assertCountEqual(reads, [(SNAPSHOT + path, head) for head in heads for path in PATHS])
        for _, payload in posts:
            self.assertEqual(payload["context"], "Event Gateway / trusted contract")
            self.assertEqual(payload["target_url"], "https://example.test/run")

    def test_changed_head_during_verification_has_no_final_status(self):
        def advance_head():
            self.current_heads[1] = "b" * 40
        results, posts, reads = self.refresh(during_verification=advance_head)
        self.assertEqual(results, [])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + HEAD, "pending")])
        self.assertEqual(len(reads), len(PATHS))

    def test_changed_policy_during_verification_has_no_final_status(self):
        def advance_policy():
            self.current_policy = b"new trusted workflow bytes"
        results, posts, reads = self.refresh(during_verification=advance_policy)
        self.assertEqual(results, [])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + HEAD, "pending")])
        self.assertEqual(len(reads), len(PATHS))

    def test_unauthorized_bytes_publish_failure_on_exact_head(self):
        self.blobs[SNAPSHOT + "event-control-v1/fixtures.json"] += b"unapproved"
        results, posts, reads = self.refresh()
        self.assertEqual(results, [(1, HEAD, "failure")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + HEAD, "pending"), ("statuses/" + HEAD, "failure")])
        self.assertCountEqual(reads, [(SNAPSHOT + path, HEAD) for path in PATHS])

    def test_candidate_symlink_rejected_despite_canonical_contents(self):
        for entry in self.tree["tree"]:
            with self.subTest(path=entry["path"]):
                entry["mode"] = "120000"
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.verify()
                self.assertEqual(self.reads, [])
                entry["mode"] = "100644"

    def test_truncated_candidate_tree_rejected(self):
        self.tree["truncated"] = True
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.reads, [])

    def test_workflow_run_refreshes_only_triggering_head(self):
        target = "b" * 40
        results, posts, reads = self.refresh(
            (HEAD, target), event_name="workflow_run", event={"workflow_run": {"head_sha": target}})
        self.assertEqual(results, [(2, target, "success")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + target, "pending"), ("statuses/" + target, "success")])
        self.assertCountEqual(reads, [(SNAPSHOT + path, target) for path in PATHS])

    def test_pull_target_refreshes_only_candidate_without_listing(self):
        target = "b" * 40
        results, posts, reads = self.refresh(
            (HEAD, target), event_name="pull_request_target",
            event={"pull_request": {"number": 2, "head": {"sha": target}}})
        self.assertEqual(results, [(2, target, "success")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + target, "pending"), ("statuses/" + target, "success")])
        self.assertCountEqual(reads, [(SNAPSHOT + path, target) for path in PATHS])
        self.assertFalse(any(endpoint.startswith("pulls?") for endpoint in self.runner_api_reads))

    def test_transport_failure_publishes_error_on_exact_head(self):
        def unavailable():
            raise OSError("temporary transport outage")
        results, posts, _ = self.refresh(during_verification=unavailable)
        self.assertEqual(results, [(1, HEAD, "error")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + HEAD, "pending"), ("statuses/" + HEAD, "error")])

    def transient_errors(self):
        error = POLICY["urllib"].error
        return (error.HTTPError("https://api.github.com", 429, "limited", {}, None),
                error.HTTPError("https://api.github.com", 503, "unavailable", {}, None),
                error.URLError("temporary outage"), TimeoutError("temporary timeout"))

    def test_get_transient_failure_recovers(self):
        for failure in self.transient_errors():
            with self.subTest(failure=type(failure).__name__, code=getattr(failure, "code", None)):
                with patch.object(POLICY["urllib"].request, "build_opener") as opener, \
                        patch.object(POLICY["time"], "sleep"):
                    opener.return_value.open.side_effect = [failure, io.BytesIO(b'{"ok":true}')]
                    try:
                        result = POLICY["request_json"]("git/ref/heads/main", "test-token")
                    except OSError as error:
                        self.fail(f"transient GET did not recover: {error}")
                    self.assertEqual(result, {"ok": True})
                    self.assertEqual(opener.return_value.open.call_count, 2)

    def test_get_transient_failure_exhausts_three_attempts(self):
        for failure in self.transient_errors():
            with self.subTest(failure=type(failure).__name__, code=getattr(failure, "code", None)):
                with patch.object(POLICY["urllib"].request, "build_opener") as opener, \
                        patch.object(POLICY["time"], "sleep"):
                    opener.return_value.open.side_effect = failure
                    with self.assertRaises(OSError):
                        POLICY["request_json"]("git/ref/heads/main", "test-token")
                    self.assertEqual(opener.return_value.open.call_count, 3)

    def test_status_post_transport_failure_is_not_retried(self):
        for failure in self.transient_errors():
            with self.subTest(failure=type(failure).__name__, code=getattr(failure, "code", None)):
                with patch.object(POLICY["urllib"].request, "build_opener") as opener, \
                        patch.object(POLICY["time"], "sleep") as sleep:
                    opener.return_value.open.side_effect = failure
                    with self.assertRaises(OSError):
                        POLICY["request_json"]("statuses/" + HEAD, "test-token", {"state": "success"})
                    self.assertEqual(opener.return_value.open.call_count, 1)
                    sleep.assert_not_called()


    def test_publication_failure_continues_batch_and_reports_partial_failure(self):
        later_head = "b" * 40
        for failure in (OSError("temporary publication outage"),
                        json.JSONDecodeError("malformed API response", "", 0),
                        KeyError("missing API field"), TypeError("invalid API shape")):
            for failed_endpoint, failed_state in (
                ("statuses/" + HEAD, "pending"),
                ("statuses/" + HEAD, "success"),
                ("pulls/1", None),
            ):
                with self.subTest(error=type(failure).__name__, endpoint=failed_endpoint,
                                  state=failed_state):
                    failed_requests = []

                    def unavailable(endpoint, payload):
                        state = payload["state"] if payload is not None else None
                        if (endpoint, state) == (failed_endpoint, failed_state):
                            failed_requests.append((endpoint, state))
                            raise failure

                    with self.assertRaises((ValueError, KeyError, TypeError, OSError)) as raised:
                        self.refresh((HEAD, later_head), before_request=unavailable)
                    self.assertEqual(
                        [(endpoint, payload["state"]) for endpoint, payload in self.runner_posts
                         if endpoint == "statuses/" + later_head],
                        [("statuses/" + later_head, "pending"), ("statuses/" + later_head, "success")],
                    )
                    self.assertCountEqual(
                        [path for path, head in self.runner_candidate_reads if head == later_head],
                        [SNAPSHOT + path for path in PATHS],
                    )
                    self.assertEqual(failed_requests, [(failed_endpoint, failed_state)])
                    self.assertIsInstance(raised.exception, OSError)
