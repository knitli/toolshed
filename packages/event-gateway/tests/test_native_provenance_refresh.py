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
        super().__init__()
        self.published = []
        self.deleted = False
        for path in (V.SCRIPT, V.VERIFIER_WORKFLOW):
            self.blobs[path, fixtures.MAIN] = b"trusted policy"

    def request(self, endpoint, payload=None):
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
    def sweep(self, api, event_name="schedule", ref="refs/heads/main"):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps({}))
            environment = {"GITHUB_REPOSITORY": V.REPOSITORY, "GH_TOKEN": "fixture",
                           "WORKFLOW_SHA": fixtures.MAIN, "GITHUB_EVENT_PATH": str(event),
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


if __name__ == "__main__":
    unittest.main()
