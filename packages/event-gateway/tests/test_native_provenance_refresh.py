import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import test_native_ci_provenance as fixtures

V = fixtures.V


class SweepAPI(fixtures.FakeAPI):
    def __init__(self):
        """Use a valid promotion with mutable artifact metadata."""
        super().__init__()
        self.published = []
        self.deleted = False
        for path in (V.SCRIPT, V.VERIFIER_WORKFLOW):
            self.blobs[path, fixtures.MAIN] = b"trusted policy"

    def request(self, endpoint, payload=None):
        if endpoint == "graphql" and payload["query"] == V.OPEN_PULLS_QUERY:
            return {"data": {"repository": {"databaseId": V.REPOSITORY_ID,
                    "pullRequests": {"nodes": [{"number": 1, "headRefOid": fixtures.HEAD}],
                                     "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}
        if endpoint == "graphql":
            return super().request(endpoint, payload)
        if payload is not None:
            self.published.append((endpoint, payload))
            return {}
        if endpoint == "":
            return {"id": V.REPOSITORY_ID}
        if endpoint == "git/ref/heads/main":
            return {"object": {"sha": fixtures.MAIN}}
        if endpoint.startswith("pulls?state=open"):
            return [{"number": 1, "head": {"sha": fixtures.HEAD}}]
        if endpoint == "pulls/1":
            return {"state": "open", "head": {"sha": fixtures.HEAD}}
        if endpoint == "actions/artifacts/456" and self.deleted:
            raise urllib.error.HTTPError("https://api.github.com/artifacts/456", 404,
                                         "artifact deleted", None, None)
        return super().request(endpoint)


class NativeProvenanceRefreshTests(unittest.TestCase):
    def sweep(self, api, event_name="schedule", ref="refs/heads/main", workflow_sha=fixtures.MAIN):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps({}))
            environment = {"GITHUB_REPOSITORY": V.REPOSITORY, "GH_TOKEN": self.id(),
                           "WORKFLOW_SHA": workflow_sha, "GITHUB_EVENT_PATH": str(event),
                           "GITHUB_EVENT_NAME": event_name, "GITHUB_REF": ref,
                           "GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "123"}
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(V, "GitHub", return_value=api), \
                    contextlib.redirect_stdout(io.StringIO()):
                V.main()
        return [payload["state"] for _, payload in api.published]

    def test_hourly_sweep_replaces_success_when_artifact_expires(self):
        api = SweepAPI()
        self.assertEqual(self.sweep(api), ["pending", "success"])
        api.artifact["expired"] = True
        self.assertEqual(self.sweep(api), ["pending", "success", "pending", "failure"])
        self.assertEqual(api.calls.count("actions/artifacts/456"), 2)

    def test_manual_refresh_replaces_success_when_artifact_deleted(self):
        api = SweepAPI()
        self.assertEqual(self.sweep(api), ["pending", "success"])
        api.deleted = True
        self.assertEqual(self.sweep(api, "workflow_dispatch"),
                         ["pending", "success", "pending", "error"])

    def test_refresh_keeps_unchanged_protected_pins_without_artifacts(self):
        api = SweepAPI()
        api.blobs[V.LAUNCHER, fixtures.HEAD] = fixtures.launcher()
        api.deleted = True
        self.assertEqual(self.sweep(api), ["pending", "success"])
        self.assertNotIn("actions/artifacts/456", api.calls)

    def test_refresh_rejects_non_main_before_publishing(self):
        for event in ("schedule", "workflow_dispatch"):
            api = SweepAPI()
            with self.subTest(event=event), self.assertRaises(ValueError):
                self.sweep(api, event, "refs/heads/untrusted")
            self.assertEqual(api.published, [])

    def test_refresh_withholds_status_when_only_registry_policy_is_stale(self):
        api = SweepAPI()
        for path in (V.SCRIPT, V.VERIFIER_WORKFLOW, V.LAUNCHER, fixtures.REGISTRY, *V.INPUTS.values(), *fixtures.RECIPE_ASSETS):
            api.blobs[path, fixtures.BUILD] = api.blobs[path, fixtures.MAIN]
        api.blobs[fixtures.REGISTRY, fixtures.BUILD] += b"\n# stale workflow registry\n"
        self.assertEqual(self.sweep(api, workflow_sha=fixtures.BUILD), [])
        self.assertNotIn(("download", 456), api.calls)

    def test_final_success_withheld_if_main_changes_after_verification(self):
        api = SweepAPI()
        new_main = "e" * 40
        api.blobs.update({(path, new_main): value for (path, revision), value in list(api.blobs.items())
                          if revision == fixtures.MAIN})
        original = api.request
        reads = 0

        def request(endpoint, payload=None):
            nonlocal reads
            if endpoint == "git/ref/heads/main":
                reads += 1
                return {"object": {"sha": fixtures.MAIN if reads < 3 else new_main}}
            return original(endpoint, payload)

        with patch.object(api, "request", side_effect=request):
            self.assertEqual(self.sweep(api), ["pending"])


if __name__ == "__main__":
    unittest.main()
