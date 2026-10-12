#!/usr/bin/env python3
"""Verify native pin promotions using protected-main code and GitHub build artifacts."""

import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = "knitli/toolshed"
REPOSITORY_ID = 1200860702
API = "https://api.github.com/repos/" + REPOSITORY + "/"
WORKFLOW = ".github/workflows/event-native-build.yml"
VERIFIER_WORKFLOW = ".github/workflows/event-native-provenance.yml"
SCRIPT = "packages/event-gateway/scripts/verify_native_ci_provenance.py"
LAUNCHER = "packages/event-gateway/src/event_gateway/launcher.py"
PROVENANCE = "packages/event-gateway/docs/native-bridge/native-release-provenance.json"
INPUTS = {
    "builderSha256": "packages/event-gateway/scripts/package_native_client.py",
    "producerSha256": "packages/event-gateway/scripts/produce_native_ci_artifact.py",
    "workflowSha256": WORKFLOW,
    "sourceManifestSha256": "packages/event-gateway/docs/native-bridge/native-metadata-v1-source-manifest.json",
    "patchSha256": "packages/event-gateway/docs/native-bridge/native-metadata-v1-implementation.patch",
}
CONTEXT = "Event Gateway / native provenance"
LIMIT = 2 * 1024 * 1024
ARCHIVE_LIMIT = 600 * 1024 * 1024
MEMBERS = {"codex": 500 * 1024 * 1024,
           "codex-code-mode-host": 100 * 1024 * 1024,
           "build-receipt.json": LIMIT}


def require(condition):
    if not condition:
        raise ValueError("native_provenance_mismatch")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(value, size=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % size, value) is not None


def positive(value):
    return type(value) is int and value > 0


def pins(source):
    """Parse fixed literal assignments; candidate Python is never imported."""
    require(len(source) <= LIMIT)
    tree = ast.parse(source)
    names = {"QUALIFIED_SHA256", "QUALIFIED_CODE_MODE_HOST_SHA256"}
    result = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in names:
            assignments = [item for item in tree.body if isinstance(item, ast.Assign)
                           and len(item.targets) == 1 and item.targets[0] is node]
            require(len(assignments) == 1 and node.id not in result)
            value = assignments[0].value
            require(isinstance(value, ast.Constant) and sha(value.value))
            result[node.id] = value.value
    require(set(result) == names)
    return result


def launcher_code(source):
    """Only the two digest literals may differ from protected main launcher code."""
    pins(source)
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {
                "QUALIFIED_SHA256", "QUALIFIED_CODE_MODE_HOST_SHA256"}:
            node.value = ast.Constant(value="<qualified-digest>")
    return ast.dump(tree, include_attributes=False)


def selection(value):
    keys = {"schemaVersion", "repositoryId", "runId", "runAttempt", "headSha",
            "artifactId", "artifactSha256", "binarySha256", "codeModeHostSha256"}
    require(isinstance(value, dict) and set(value) == keys)
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and type(value["repositoryId"]) is int and value["repositoryId"] == REPOSITORY_ID)
    require(all(positive(value[key]) for key in ("runId", "runAttempt", "artifactId")))
    require(sha(value["headSha"], 40) and all(sha(value[key]) for key in
            ("artifactSha256", "binarySha256", "codeModeHostSha256")))
    return value


def artifact_name(selected):
    return f"native-client-{selected['runId']}-{selected['runAttempt']}"


def verify_metadata(selected, workflow, run, artifact):
    require(workflow.get("path") == WORKFLOW and positive(workflow.get("id")))
    require(run.get("id") == selected["runId"] and run.get("run_attempt") == selected["runAttempt"]
            and run.get("workflow_id") == workflow["id"] and run.get("head_sha") == selected["headSha"]
            and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and run.get("status") == "completed" and run.get("conclusion") == "success")
    require(run.get("repository", {}).get("id") == REPOSITORY_ID
            and run.get("head_repository", {}).get("id") == REPOSITORY_ID)
    origin = artifact.get("workflow_run", {})
    require(artifact.get("id") == selected["artifactId"] and artifact.get("name") == artifact_name(selected)
            and artifact.get("expired") is False and artifact.get("digest") == "sha256:" + selected["artifactSha256"]
            and positive(artifact.get("size_in_bytes")) and artifact["size_in_bytes"] <= ARCHIVE_LIMIT)
    require(origin.get("id") == selected["runId"] and origin.get("repository_id") == REPOSITORY_ID
            and origin.get("head_repository_id") == REPOSITORY_ID and origin.get("head_sha") == selected["headSha"]
            and origin.get("head_branch") == "main")


def verify_archive(path, selected, inputs, manifest):
    """Hash bounded archive members without extracting or executing any artifact."""
    require(path.stat().st_size <= ARCHIVE_LIMIT)
    with path.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == selected["artifactSha256"])
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(len(members) == len(MEMBERS) and {item.filename for item in members} == set(MEMBERS))
        hashes = {}
        receipt = None
        for item in members:
            require(not item.is_dir() and not item.flag_bits & 1
                    and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
                    and 0 < item.file_size <= MEMBERS[item.filename])
            with archive.open(item) as stream:
                if item.filename == "build-receipt.json":
                    receipt = json.loads(stream.read(LIMIT + 1))
                else:
                    require(struct.unpack("<II", stream.read(8)) == (0xFEEDFACF, 0x0100000C))
            with archive.open(item) as stream:
                hashes[item.filename] = hashlib.file_digest(stream, "sha256").hexdigest()
    require(hashes["codex"] == selected["binarySha256"]
            and hashes["codex-code-mode-host"] == selected["codeModeHostSha256"])
    require(isinstance(receipt, dict) and receipt.get("schemaVersion") == 1
            and receipt.get("kind") == "native-client-ci-build" and receipt.get("repositoryId") == REPOSITORY_ID
            and receipt.get("runId") == selected["runId"] and receipt.get("runAttempt") == selected["runAttempt"]
            and receipt.get("headSha") == selected["headSha"] and receipt.get("artifactName") == artifact_name(selected)
            and receipt.get("inputs") == inputs)
    build = receipt.get("build", {})
    require(isinstance(build, dict) and isinstance(build.get("codeModeHost"), dict))
    require(build.get("upstreamCommit") == manifest["baseCommit"]
            and build.get("patchSha256") == inputs["patchSha256"]
            and build.get("sourceManifestSha256") == inputs["sourceManifestSha256"]
            and build.get("patchedFileSha256") == manifest["fileSha256"]
            and build.get("patchedFileCount") == manifest["fileCount"]
            and build.get("binarySha256") == hashes["codex"]
            and build.get("codeModeHost", {}).get("executableSha256") == hashes["codex-code-mode-host"]
            and build.get("host") == "aarch64-apple-darwin"
            and sha(build.get("normalizedCargoLockSha256")))
    environment = receipt.get("environment", {})
    require(isinstance(environment, dict))
    require(environment.get("runnerArch") == "ARM64" and all(isinstance(environment.get(key), str)
            and environment[key] for key in ("runnerImageOS", "runnerImageVersion", "sdkVersion", "clangVersion", "linkerVersion")))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)
        self._blob_cache = {}

    def request(self, endpoint, payload=None, *, accept="application/vnd.github+json", response_limit=LIMIT):
        request = urllib.request.Request(API + endpoint if endpoint else API.rstrip("/"),
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={"Authorization": "Bearer " + self.token, "Accept": accept,
                     "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"})
        with self.opener.open(request, timeout=30) as response:
            raw = response.read(response_limit + 1)
        require(len(raw) <= response_limit)
        return json.loads(raw)

    def blob(self, path, revision):
        require(sha(revision, 40))
        key = (revision, path)
        if key in self._blob_cache:
            return self._blob_cache[key]
        value = self.request("contents/" + path + "?" + urllib.parse.urlencode({"ref": revision}),
                             accept="application/vnd.github.object+json")
        require(value.get("type") == "file" and sha(value.get("sha"), 40)
                and positive(value.get("size")) and value["size"] <= LIMIT)
        blob = self.request("git/blobs/" + value["sha"], response_limit=3 * 1024 * 1024)
        require(blob.get("sha") == value["sha"] and blob.get("encoding") == "base64"
                and blob.get("size") == value["size"])
        raw = base64.b64decode("".join(blob["content"].splitlines()), validate=True)
        require(len(raw) <= LIMIT and blob["size"] == len(raw))
        # Only validated immutable bytes live in this run-local cache. Mutable
        # main/head refs and artifact availability are always read afresh.
        self._blob_cache[key] = raw
        return raw

    def download(self, artifact_id, destination):
        # Only the authenticated GitHub API chooses the unauthenticated download URL.
        request = urllib.request.Request(API + f"actions/artifacts/{artifact_id}/zip",
            headers={"Authorization": "Bearer " + self.token})
        try:
            self.opener.open(request, timeout=30).close()
            raise ValueError("artifact_redirect_missing")
        except urllib.error.HTTPError as response:
            require(response.code == 302)
            location = response.headers.get("Location", "")
        parsed = urllib.parse.urlsplit(location)
        require(parsed.scheme == "https" and parsed.username is None and parsed.password is None
                and parsed.port in (None, 443) and parsed.hostname is not None
                and (parsed.hostname.endswith(".blob.core.windows.net")
                     or parsed.hostname.endswith(".githubusercontent.com")))
        size = 0
        with self.opener.open(urllib.request.Request(location), timeout=60) as response, destination.open("xb") as output:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                require(size <= ARCHIVE_LIMIT)
                output.write(chunk)


def verify_candidate(api, head, main):
    require(sha(head, 40) and sha(main, 40))
    tree = api.request(f"git/trees/{head}?recursive=1")
    require(tree.get("truncated") is False)
    entries = {entry["path"]: entry for entry in tree["tree"]}
    require(entries.get(LAUNCHER, {}).get("type") == "blob"
            and entries[LAUNCHER].get("mode") in ("100644", "100755"))
    candidate_source = api.blob(LAUNCHER, head)
    approved_source = api.blob(LAUNCHER, main)
    require(launcher_code(candidate_source) == launcher_code(approved_source))
    candidate = pins(candidate_source)
    approved = pins(approved_source)
    if candidate == approved:
        return "Current main-authorized native pins unchanged"
    require(entries.get(PROVENANCE, {}).get("type") == "blob"
            and entries[PROVENANCE].get("mode") in ("100644", "100755"))
    selected = selection(json.loads(api.blob(PROVENANCE, head)))
    require(candidate["QUALIFIED_SHA256"] == selected["binarySha256"]
            and candidate["QUALIFIED_CODE_MODE_HOST_SHA256"] == selected["codeModeHostSha256"])
    workflow = api.request("actions/workflows/event-native-build.yml")
    run = api.request(f"actions/runs/{selected['runId']}/attempts/{selected['runAttempt']}")
    artifact = api.request(f"actions/artifacts/{selected['artifactId']}")
    verify_metadata(selected, workflow, run, artifact)
    comparison = api.request(f"compare/{selected['headSha']}...{main}")
    require(comparison.get("status") in ("ahead", "identical"))
    inputs = {}
    for name, path in INPUTS.items():
        trusted = api.blob(path, main)
        require(api.blob(path, selected["headSha"]) == trusted and api.blob(path, head) == trusted)
        inputs[name] = digest(trusted)
    manifest = json.loads(api.blob(INPUTS["sourceManifestSha256"], main))
    with tempfile.TemporaryDirectory(prefix="native-ci-verification-") as directory:
        archive = Path(directory) / "artifact.zip"
        api.download(selected["artifactId"], archive)
        verify_archive(archive, selected, inputs, manifest)
    return "Native pin matches verified main CI build artifact"


def open_pulls(api):
    page = 1
    while True:
        pulls = api.request(f"pulls?state=open&per_page=50&page={page}")
        require(isinstance(pulls, list))
        yield from pulls
        if len(pulls) < 50:
            return
        page += 1


def current_policy(api, workflow_sha, main):
    return all(api.blob(path, workflow_sha) == api.blob(path, main)
               for path in (SCRIPT, VERIFIER_WORKFLOW, LAUNCHER, *INPUTS.values()))


def publish(api, number, head, state, description, workflow_sha):
    pull = api.request(f"pulls/{number}")
    main = api.request("git/ref/heads/main")["object"]["sha"]
    if pull["state"] != "open" or pull["head"]["sha"] != head or not current_policy(api, workflow_sha, main):
        return False
    api.request(f"statuses/{head}", {"state": state, "context": CONTEXT, "description": description,
        "target_url": os.environ["GITHUB_SERVER_URL"] + "/" + REPOSITORY + "/actions/runs/" + os.environ["GITHUB_RUN_ID"]})
    return True


def main():
    require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY)
    api = GitHub(os.environ["GH_TOKEN"])
    require(api.request("")["id"] == REPOSITORY_ID)
    workflow_sha = os.environ["WORKFLOW_SHA"]
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    event_name = os.environ["GITHUB_EVENT_NAME"]
    if event_name == "pull_request_target":
        pulls = [event["pull_request"]]
    else:
        require(event_name == "workflow_run"
                or event_name == "push" and event.get("ref") == "refs/heads/main"
                or event_name in ("schedule", "workflow_dispatch")
                and os.environ.get("GITHUB_REF") == "refs/heads/main")
        pulls = open_pulls(api)
    failed = False
    for pull in pulls:
        number, head = pull["number"], pull["head"]["sha"]
        require(positive(number) and sha(head, 40))
        try:
            if not publish(api, number, head, "pending", "Checking native pin build provenance", workflow_sha):
                continue
            trusted_main = api.request("git/ref/heads/main")["object"]["sha"]
            try:
                description = verify_candidate(api, head, trusted_main)
                state = "success"
            except (ValueError, KeyError, TypeError, SyntaxError, RecursionError, struct.error, zipfile.BadZipFile):
                description, state = "Native pin lacks matching main CI build provenance", "failure"
            except (OSError, urllib.error.URLError):
                description, state = "Native build provenance unavailable; retry verification", "error"
            if publish(api, number, head, state, description, workflow_sha):
                print(f"PR #{number}: {state}")
        except (ValueError, KeyError, TypeError, OSError, urllib.error.URLError):
            failed = True
            print(f"PR #{number}: native provenance status publication unavailable")
    require(not failed)


if __name__ == "__main__":
    main()
