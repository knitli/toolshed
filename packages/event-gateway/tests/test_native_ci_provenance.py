import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import warnings
from unittest.mock import patch
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_native_ci_provenance.py"
SPEC = importlib.util.spec_from_file_location("native_ci_verifier", SCRIPT)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
HEAD, MAIN, BUILD = "a" * 40, "b" * 40, "c" * 40


def launcher(binary="1" * 64, host="2" * 64):
    return (f'QUALIFIED_SHA256 = "{binary}"\n'
            f'QUALIFIED_CODE_MODE_HOST_SHA256 = "{host}"\n'
            'def qualified_binary(data):\n    return data == QUALIFIED_SHA256\n').encode()


def fixture():
    binary = struct.pack("<II", 0xFEEDFACF, 0x0100000C) + b"actual cli bytes"
    host = struct.pack("<II", 0xFEEDFACF, 0x0100000C) + b"actual host bytes"
    manifest = {"baseCommit": "d" * 40, "fileSha256": {"src/main.rs": "e" * 64}, "fileCount": 1}
    blobs = {path: (name + " reviewed recipe").encode() for name, path in V.INPUTS.items()}
    blobs[V.INPUTS["sourceManifestSha256"]] = json.dumps(manifest).encode()
    inputs = {name: V.digest(blobs[path]) for name, path in V.INPUTS.items()}
    selected = {"schemaVersion": 1, "repositoryId": V.REPOSITORY_ID, "runId": 123,
                "runAttempt": 2, "headSha": BUILD, "artifactId": 456,
                "artifactSha256": "0" * 64, "binarySha256": V.digest(binary),
                "codeModeHostSha256": V.digest(host)}
    receipt = {"schemaVersion": 1, "kind": "native-client-ci-build", "repositoryId": V.REPOSITORY_ID,
               "runId": 123, "runAttempt": 2, "headSha": BUILD,
               "artifactName": "native-client-123-2", "inputs": inputs,
               "environment": {"runnerArch": "ARM64", "runnerImageOS": "macos",
                               "runnerImageVersion": "20261012", "sdkVersion": "27",
                               "clangVersion": "clang 18", "linkerVersion": "ld 1"},
               "build": {"upstreamCommit": manifest["baseCommit"], "patchSha256": inputs["patchSha256"],
                         "sourceManifestSha256": inputs["sourceManifestSha256"],
                         "patchedFileSha256": manifest["fileSha256"], "patchedFileCount": 1,
                         "binarySha256": V.digest(binary), "codeModeHost": {"executableSha256": V.digest(host)},
                         "host": "aarch64-apple-darwin", "normalizedCargoLockSha256": "f" * 64}}
    return selected, inputs, manifest, blobs, [("codex", binary), ("codex-code-mode-host", host),
                                              ("build-receipt.json", json.dumps(receipt).encode())]


def archive_bytes(members):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w") as archive:
            for name, data in members:
                archive.writestr(name, data)
    return stream.getvalue()


def metadata(selected):
    workflow = {"path": V.WORKFLOW, "id": 42}
    run = {"id": 123, "run_attempt": 2, "workflow_id": 42, "head_sha": BUILD,
           "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
           "repository": {"id": V.REPOSITORY_ID}, "head_repository": {"id": V.REPOSITORY_ID}}
    artifact = {"id": 456, "name": "native-client-123-2", "expired": False,
                "digest": "sha256:" + selected["artifactSha256"], "size_in_bytes": 100,
                "workflow_run": {"id": 123, "repository_id": V.REPOSITORY_ID,
                                 "head_repository_id": V.REPOSITORY_ID, "head_sha": BUILD, "head_branch": "main"}}
    return workflow, run, artifact


class FakeAPI:
    def __init__(self):
        """Initialize a valid build and candidate fixture."""
        self.selected, self.inputs, self.manifest, recipes, members = fixture()
        self.archive = archive_bytes(members)
        self.selected["artifactSha256"] = V.digest(self.archive)
        self.workflow, self.run, self.artifact = metadata(self.selected)
        self.blobs = {(path, revision): data for path, data in recipes.items() for revision in (HEAD, MAIN, BUILD)}
        self.blobs[V.LAUNCHER, MAIN] = launcher()
        self.blobs[V.LAUNCHER, HEAD] = launcher(self.selected["binarySha256"], self.selected["codeModeHostSha256"])
        self.blobs[V.PROVENANCE, HEAD] = json.dumps(self.selected).encode()
        self.tree = {"truncated": False, "tree": [{"path": path, "type": "blob", "mode": "100644"}
                                                   for path in (V.LAUNCHER, V.PROVENANCE)]}
        self.calls = []
        self.comparison = "ahead"

    def request(self, endpoint, payload=None):
        if payload is not None:
            raise AssertionError("Verification must not write remotely")
        self.calls.append(endpoint)
        return {f"git/trees/{HEAD}?recursive=1": self.tree,
                "actions/workflows/event-native-build.yml": self.workflow,
                "actions/runs/123/attempts/2": self.run,
                "actions/artifacts/456": self.artifact,
                f"compare/{BUILD}...{MAIN}": {"status": self.comparison}}[endpoint]

    def blob(self, path, revision):
        self.calls.append((path, revision))
        return self.blobs[path, revision]

    def download(self, artifact_id, destination):
        self.calls.append(("download", artifact_id))
        destination.write_bytes(self.archive)


class NativeCIProvenanceTests(unittest.TestCase):
    def test_pins_parse_literals_without_executing_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            source = launcher() + f'open({str(marker)!r}, "w").write("bad")\n'.encode()
            self.assertEqual(V.pins(source)["QUALIFIED_SHA256"], "1" * 64)
            self.assertFalse(marker.exists())
        for source in (launcher() + b'QUALIFIED_SHA256 = "' + b"3" * 64 + b'"\n',
                       launcher().replace(b'"' + b"1" * 64 + b'"', b'get_digest()'),
                       launcher() + b'if True:\n    QUALIFIED_SHA256 = "' + b"3" * 64 + b'"\n',
                       launcher() + b'def override():\n    QUALIFIED_SHA256 = "' + b"3" * 64 + b'"\n',
                       launcher().replace(b"QUALIFIED_SHA256 =", b"QUALIFIED_SHA256: str =")):
            with self.subTest(source=source), self.assertRaises(ValueError):
                V.pins(source)

    def test_selection_rejects_untrusted_identity_and_open_schema(self):
        good = fixture()[0]
        self.assertEqual(V.selection(good), good)
        for key, value in {"schemaVersion": True, "repositoryId": 1, "runId": True,
                           "runAttempt": 0, "artifactId": -1, "headSha": "main",
                           "artifactSha256": "A" * 64, "binarySha256": "short", "codeModeHostSha256": None,
                           "extra": "ignored?"}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                V.selection({**good, key: value})
        with self.assertRaises(ValueError):
            V.selection({k: v for k, v in good.items() if k != "artifactId"})

    def test_metadata_rejects_wrong_execution_or_artifact(self):
        selected = fixture()[0]
        good = metadata(selected)
        V.verify_metadata(selected, *good)
        vectors = [(0, "path", "evil.yml"), (0, "id", 0), (1, "repository", {"id": 1}),
                   (1, "head_repository", {"id": 1}), (1, "workflow_id", 9), (1, "event", "pull_request"),
                   (1, "head_branch", "feature"), (1, "head_sha", HEAD), (1, "run_attempt", 1),
                   (1, "id", 124), (1, "conclusion", "failure"), (1, "status", "in_progress"),
                   (2, "id", 789), (2, "expired", True), (2, "digest", "sha256:" + "9" * 64),
                   (2, "name", "native-client-123-1"), (2, "size_in_bytes", V.ARCHIVE_LIMIT + 1)]
        vectors += [(2, "workflow_run", {**good[2]["workflow_run"], key: value}) for key, value in
                    [("id", 999), ("repository_id", 1), ("head_repository_id", 1), ("head_sha", HEAD), ("head_branch", "feature")]]
        for index, key, value in vectors:
            with self.subTest(index=index, key=key):
                changed = copy.deepcopy(good)
                changed[index][key] = value
                with self.assertRaises(ValueError):
                    V.verify_metadata(selected, *changed)

    def check_archive(self, members, *, selection_change=None, raw_change=None, limits=None):
        selected, inputs, manifest, _, _ = fixture()
        raw = archive_bytes(members)
        if raw_change:
            raw = raw_change(raw)
        selected["artifactSha256"] = V.digest(raw)
        selected.update(selection_change or {})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.zip"
            path.write_bytes(raw)
            with patch.dict(V.MEMBERS, limits or {}):
                V.verify_archive(path, selected, inputs, manifest)

    def test_archive_hashes_physical_bytes_and_arm64_magic(self):
        members = fixture()[4]
        self.check_archive(members)
        for name, data in [("codex", members[0][1] + b"changed"),
                           ("codex", b"not macho"), ("codex-code-mode-host", struct.pack("<II", 0xFEEDFACF, 7))]:
            with self.subTest(name=name, data=data), self.assertRaises(ValueError):
                self.check_archive([(n, data if n == name else b) for n, b in members])
        with self.assertRaises(ValueError):
            self.check_archive(members, selection_change={"artifactSha256": "0" * 64})
        for limits in ({"codex": 8}, {"build-receipt.json": 8}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                self.check_archive(members, limits=limits)
        with patch.object(V, "ARCHIVE_LIMIT", 8), self.assertRaises(ValueError):
            self.check_archive(members)

    def test_archive_rejects_extra_duplicate_symlink_traversal_and_encryption(self):
        members = fixture()[4]
        link = zipfile.ZipInfo("codex")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        vectors = [members + [("extra", b"x")], [members[0], members[0], members[2]],
                   [(link, b"target"), *members[1:]], [("../codex", members[0][1]), *members[1:]]]
        for index, vector in enumerate(vectors):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.check_archive(vector)

        def encrypted(raw):
            data = bytearray(raw)
            for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
                position = data.index(signature) + offset
                struct.pack_into("<H", data, position, struct.unpack_from("<H", data, position)[0] | 1)
            return bytes(data)
        with self.assertRaises(ValueError):
            self.check_archive(members, raw_change=encrypted)

    def test_receipt_must_match_run_recipe_and_physical_outputs(self):
        members = fixture()[4]
        receipt = json.loads(members[2][1])
        vectors = [("runAttempt", 1), ("headSha", HEAD), ("artifactName", "other"),
                   ("inputs", {}), ("environment", {**receipt["environment"], "runnerArch": "X64"})]
        vectors += [("build", {**receipt["build"], key: value}) for key, value in
                    [("binarySha256", "0" * 64), ("codeModeHost", {"executableSha256": "0" * 64}),
                     ("upstreamCommit", HEAD), ("patchedFileSha256", {}), ("patchedFileCount", 2),
                     ("patchSha256", "0" * 64), ("host", "x86_64-apple-darwin")]]
        for key, value in vectors:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check_archive([*members[:2], ("build-receipt.json", json.dumps({**receipt, key: value}).encode())])

    def test_unchanged_pins_skip_artifact_fetch_but_never_allow_launcher_rewrites(self):
        api = FakeAPI()
        api.blobs[V.LAUNCHER, HEAD] = launcher()
        self.assertIn("unchanged", V.verify_candidate(api, HEAD, MAIN))
        self.assertFalse(any(isinstance(call, str) and call.startswith("actions/") or
                             isinstance(call, tuple) and call[0] == "download" for call in api.calls))
        for source in (launcher() + b'globals()["QUALIFIED_SHA256"] = "bad"\n',
                       launcher().replace(b"return data == QUALIFIED_SHA256", b"return True")):
            api = FakeAPI()
            api.blobs[V.LAUNCHER, HEAD] = source
            with self.subTest(source=source), self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)

    def test_changed_pins_require_producer_selection(self):
        api = FakeAPI()
        api.tree["tree"] = api.tree["tree"][:1]
        with self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertNotIn(("download", 456), api.calls)

    def test_verified_promotion_binds_artifact_main_ancestry_and_all_three_recipes(self):
        api = FakeAPI()
        self.assertIn("verified main CI", V.verify_candidate(api, HEAD, MAIN))
        self.assertIn(("download", 456), api.calls)
        self.assertIn(f"compare/{BUILD}...{MAIN}", api.calls)
        for path in V.INPUTS.values():
            for revision in (HEAD, MAIN, BUILD):
                self.assertIn((path, revision), api.calls)
        for comparison in ("behind", "diverged"):
            api = FakeAPI()
            api.comparison = comparison
            with self.subTest(comparison=comparison), self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)
            self.assertNotIn(("download", 456), api.calls)
        for revision in (HEAD, BUILD):
            for path in V.INPUTS.values():
                api = FakeAPI()
                api.blobs[path, revision] += b"substitution"
                with self.subTest(revision=revision, path=path), self.assertRaises(ValueError):
                    V.verify_candidate(api, HEAD, MAIN)
                self.assertNotIn(("download", 456), api.calls)
