import base64
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
from types import MappingProxyType
import stat
import subprocess  # nosec B404 - Fixed isolated Python child tests sibling import provenance.
import sys
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
REGISTRY = "packages/event-gateway/scripts/native_recipe_registry.py"
RECIPE_ASSETS = tuple(sorted({"packages/event-gateway/docs/native-bridge/" + asset.path
    for recipe in V.R.RECIPES.values()
    for asset in (recipe.manifest, *recipe.parents, *recipe.ordered_patches)}))


def launcher(binary="1" * 64, host="2" * 64):
    return (f'QUALIFIED_SHA256 = "{binary}"\n'
            f'QUALIFIED_CODE_MODE_HOST_SHA256 = "{host}"\n'
            'def qualified_binary(data):\n    return data == QUALIFIED_SHA256\n').encode()


def fixture():
    binary = struct.pack("<II", 0xFEEDFACF, 0x0100000C) + b"actual cli bytes"
    host = struct.pack("<II", 0xFEEDFACF, 0x0100000C) + b"actual host bytes"
    with gzip.open(Path(__file__).parent / "fixtures/native-legacy-v1-inputs.json.gz", "rt") as stream:
        frozen = json.load(stream)["blobs"]
    blobs = {path: base64.b64decode(frozen[path]) if path in frozen else (SCRIPT.parents[3] / path).read_bytes()
             for path in V.INPUTS.values()}
    manifest = json.loads(blobs[V.INPUTS["sourceManifestSha256"]])
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
                         "patchedFileSha256": manifest["fileSha256"], "patchedFileCount": manifest["fileCount"],
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
        for revision in (HEAD, MAIN):
            self.blobs[REGISTRY, revision] = (SCRIPT.parents[3] / REGISTRY).read_bytes()
        for path in RECIPE_ASSETS:
            for revision in (HEAD, MAIN, BUILD):
                self.blobs[path, revision] = (SCRIPT.parents[3] / path).read_bytes()
        self.blobs[V.LAUNCHER, MAIN] = launcher()
        self.blobs[V.LAUNCHER, HEAD] = launcher(self.selected["binarySha256"], self.selected["codeModeHostSha256"])
        self.blobs[V.PROVENANCE, HEAD] = json.dumps(self.selected).encode()
        self.tree = {"truncated": False, "tree": [{"path": path, "type": "blob", "mode": "100644"}
                                                   for path in (V.LAUNCHER, V.PROVENANCE)]}
        self.calls = []
        self.comparison = {"status": "BEHIND", "baseTarget": {"oid": MAIN}, "headTarget": {"oid": BUILD}}

    def replace_receipt(self, receipt):
        with zipfile.ZipFile(io.BytesIO(self.archive)) as archive:
            members = [(name, archive.read(name)) for name in ("codex", "codex-code-mode-host")]
        self.archive = archive_bytes([*members, ("build-receipt.json", json.dumps(receipt).encode())])
        self.selected["artifactSha256"] = V.digest(self.archive)
        self.artifact["digest"] = "sha256:" + self.selected["artifactSha256"]
        self.artifact["size_in_bytes"] = len(self.archive)
        self.blobs[V.PROVENANCE, HEAD] = json.dumps(self.selected).encode()

    def request(self, endpoint, payload=None):
        if endpoint == "graphql" and payload["query"] == V.ANCESTRY_QUERY:
            self.calls.append((endpoint, payload["variables"]["build"]))
            return {"data": {"repository": {"databaseId": V.REPOSITORY_ID,
                                             "ref": {"compare": self.comparison}}}}
        if payload is not None:
            raise AssertionError("Verification must not write remotely")
        self.calls.append(endpoint)
        return {f"git/trees/{HEAD}?recursive=1": self.tree,
                "actions/workflows/event-native-build.yml": self.workflow,
                "actions/runs/123/attempts/2": self.run,
                "actions/artifacts/456": self.artifact,
                }[endpoint]

    def blob(self, path, revision):
        self.calls.append((path, revision))
        return self.blobs[path, revision]

    def download(self, artifact_id, destination):
        self.calls.append(("download", artifact_id))
        destination.write_bytes(self.archive)


class NativeCIProvenanceTests(unittest.TestCase):
    def test_push_trigger_covers_every_trusted_policy_input(self):
        workflow = (SCRIPT.parents[3] / V.VERIFIER_WORKFLOW).read_text()
        push = workflow.split("\n  push:\n", 1)[1]
        paths = push.split("\n    paths:\n", 1)[1].split("\n\n", 1)[0]
        triggered = {line.removeprefix("      - ") for line in paths.splitlines()}
        required = {V.SCRIPT, V.VERIFIER_WORKFLOW, V.LAUNCHER, REGISTRY, *V.INPUTS.values(), *RECIPE_ASSETS}
        self.assertFalse(required - triggered, required - triggered)

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
        self.assertFalse(any(isinstance(call, tuple) and call[0] in {REGISTRY, *V.INPUTS.values()} for call in api.calls))
        self.assertFalse(any(isinstance(call, str) and call.startswith("actions/") or
                             isinstance(call, tuple) and call[0] == "download" for call in api.calls))
        for source in (launcher() + b'globals()["QUALIFIED_SHA256"] = "bad"\n',
                       launcher().replace(b"return data == QUALIFIED_SHA256", b"return True")):
            api = FakeAPI()
            api.blobs[V.LAUNCHER, HEAD] = source
            with self.subTest(source=source), self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)

    def test_build_foundation_allows_unchanged_release_but_requires_reviewed_recipe_for_promotion(self):
        api = FakeAPI()
        api.blobs[V.LAUNCHER, HEAD] = launcher()
        for path in V.INPUTS.values():
            api.blobs[path, HEAD] += b" new Core-idle recipe"
        self.assertIn("unchanged", V.verify_candidate(api, HEAD, MAIN))
        self.assertNotIn(("download", 456), api.calls)
        api.blobs[V.LAUNCHER, HEAD] = launcher(api.selected["binarySha256"],
                                               api.selected["codeModeHostSha256"])
        with self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertNotIn(("download", 456), api.calls)

    def test_changed_pins_require_producer_selection(self):
        api = FakeAPI()
        api.tree["tree"] = api.tree["tree"][:1]
        with self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertNotIn(("download", 456), api.calls)

    def frozen_launcher(self, name, expected):
        with gzip.open(Path(__file__).parent / "fixtures" / name, "rb") as stream:
            source = stream.read(V.LIMIT + 1)
        self.assertLessEqual(len(source), V.LIMIT)
        self.assertEqual(V.digest(source), expected)
        return source

    def terminal_query_transition(self):
        api = FakeAPI()
        api.blobs[V.LAUNCHER, MAIN] = self.frozen_launcher(
            "reviewed-launcher-before-terminal-query.py.gz",
            "4ca29e5aec4aa7bbe753d2910839b1d77002b6ccbf7941d3358d3518aee8cfed")
        api.blobs[V.LAUNCHER, HEAD] = self.frozen_launcher(
            "reviewed-launcher-terminal-query.py.gz",
            "b35f40b9968d66471ba420cf8b6ea46f482e7f49c43bd0e6ddca99aefa6275b5")
        return api

    def test_exact_terminal_query_source_transition_keeps_both_binary_pins(self):
        api = self.terminal_query_transition()
        self.assertEqual(V.verify_candidate(api, HEAD, MAIN),
                         "Current main-authorized native pins unchanged")
        self.assertEqual(api.calls, [f"git/trees/{HEAD}?recursive=1",
                                     (V.LAUNCHER, HEAD), (V.LAUNCHER, MAIN)])

    def test_terminal_query_transition_rejects_changed_source_or_digest_pair(self):
        for revision in (MAIN, HEAD):
            api = self.terminal_query_transition()
            api.blobs[V.LAUNCHER, revision] += b"# not the reviewed source bytes\n"
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)
            self.assertNotIn(("download", 456), api.calls)
        for name in ("QUALIFIED_SHA256", "QUALIFIED_CODE_MODE_HOST_SHA256"):
            api = self.terminal_query_transition()
            source = api.blobs[V.LAUNCHER, HEAD]
            api.blobs[V.LAUNCHER, HEAD] = source.replace(V.pins(source)[name].encode(), b"0" * 64)
            with self.subTest(name=name), self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)
            self.assertNotIn(("download", 456), api.calls)

    def test_terminal_query_source_cannot_also_promote_attested_binary(self):
        api = self.terminal_query_transition()
        source = api.blobs[V.LAUNCHER, HEAD]
        api.blobs[V.LAUNCHER, HEAD] = source.replace(
            V.pins(source)["QUALIFIED_SHA256"].encode(), api.selected["binarySha256"].encode())
        with self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertNotIn(("download", 456), api.calls)

    def core_idle_transition(self):
        source = self.frozen_launcher(
            "reviewed-launcher-before-terminal-query.py.gz",
            "4ca29e5aec4aa7bbe753d2910839b1d77002b6ccbf7941d3358d3518aee8cfed")
        # Replay the reviewed two-line witness change; retain this fixture after pin promotion.
        for name, value in zip(("QUALIFIED_SHA256", "QUALIFIED_CODE_MODE_HOST_SHA256"),
                               V.REVIEWED_LAUNCHER_TRANSITION[2:]):
            source = source.replace(V.pins(source)[name].encode(), value.encode())
        old_fields = b'"serverGeneration", "leaseMs",'
        new_fields = b'"serverGeneration", "leaseMs", "nativeCoreTurnState",'
        check = b'            and value["nativeCoreTurnState"] in ("busy", "idle", "unknown")\n'
        base = source.replace(new_fields, old_fields).replace(check, b"")
        candidate = base.replace(old_fields, new_fields).replace(
            b'            and value["eligible"] is True\n',
            b'            and value["eligible"] is True\n' + check)
        api = FakeAPI()
        api.blobs[V.LAUNCHER, MAIN] = base
        api.blobs[V.LAUNCHER, HEAD] = candidate
        return api

    def test_reviewed_core_idle_source_passes_but_source_mutations_fail(self):
        api = self.core_idle_transition()
        self.assertNotEqual(V.launcher_code(api.blobs[V.LAUNCHER, MAIN]),
                            V.launcher_code(api.blobs[V.LAUNCHER, HEAD]))
        self.assertIn("unchanged", V.verify_candidate(api, HEAD, MAIN))
        self.assertEqual(api.calls, [f"git/trees/{HEAD}?recursive=1",
                                     (V.LAUNCHER, HEAD), (V.LAUNCHER, MAIN)])
        for revision in (MAIN, HEAD):
            api = self.core_idle_transition()
            api.blobs[V.LAUNCHER, revision] += b"# unreviewed source bytes\n"
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)
            self.assertNotIn(("download", 456), api.calls)

    def test_reviewed_core_idle_source_cannot_also_promote_attested_binary(self):
        api = self.core_idle_transition()
        source = api.blobs[V.LAUNCHER, HEAD]
        source = source.replace(V.pins(source)["QUALIFIED_SHA256"].encode(),
                                api.selected["binarySha256"].encode())
        api.blobs[V.LAUNCHER, HEAD] = source
        with self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertEqual(api.calls, [f"git/trees/{HEAD}?recursive=1",
                                     (V.LAUNCHER, HEAD), (V.LAUNCHER, MAIN)])

    def observation_transition(self):
        api = FakeAPI()
        base = launcher()
        candidate = base + b"def native_observation():\n    return False\n"
        api.blobs[V.LAUNCHER, HEAD] = candidate
        return api, (V.digest(base), V.digest(candidate), "1" * 64, "2" * 64)

    def test_exact_reviewed_launcher_transition_keeps_pins_without_artifact_fetch(self):
        api, transition = self.observation_transition()
        with patch.object(V, "REVIEWED_LAUNCHER_TRANSITION", transition, create=True):
            self.assertIn("unchanged", V.verify_candidate(api, HEAD, MAIN))
        self.assertEqual(api.calls, [f"git/trees/{HEAD}?recursive=1",
                                     (V.LAUNCHER, HEAD), (V.LAUNCHER, MAIN)])

    def test_reviewed_transition_rejects_every_other_source_byte_sequence(self):
        for revision, suffix in ((MAIN, b"# different base\n"),
                                 (HEAD, b"# different candidate\n"),
                                 (HEAD, b"def unexpected():\n    return True\n"),
                                 (HEAD, b'globals()["QUALIFIED_SHA256"] = "bad"\n')):
            api, transition = self.observation_transition()
            api.blobs[V.LAUNCHER, revision] += suffix
            with self.subTest(revision=revision, suffix=suffix), \
                    patch.object(V, "REVIEWED_LAUNCHER_TRANSITION", transition, create=True), \
                    self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)

    def test_reviewed_transition_requires_the_exact_unchanged_pin_pair(self):
        for index in (2, 3):
            api, transition = self.observation_transition()
            wrong_pair = list(transition)
            wrong_pair[index] = "0" * 64
            with self.subTest(index=index), \
                    patch.object(V, "REVIEWED_LAUNCHER_TRANSITION", tuple(wrong_pair), create=True), \
                    self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)
        api, _ = self.observation_transition()
        api.blobs[V.LAUNCHER, HEAD] = launcher(api.selected["binarySha256"],
                                               api.selected["codeModeHostSha256"]) + b"def native_observation():\n    return False\n"
        transition = (V.digest(api.blobs[V.LAUNCHER, MAIN]), V.digest(api.blobs[V.LAUNCHER, HEAD]),
                      api.selected["binarySha256"], api.selected["codeModeHostSha256"])
        with patch.object(V, "REVIEWED_LAUNCHER_TRANSITION", transition, create=True), \
                self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertNotIn(("download", 456), api.calls)

    def test_candidate_policy_cannot_authorize_its_own_launcher_change(self):
        api, transition = self.observation_transition()
        api.blobs[V.SCRIPT, HEAD] = f"REVIEWED_LAUNCHER_TRANSITION = {transition!r}\n".encode()
        with self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertNotIn((V.SCRIPT, HEAD), api.calls)

    def test_verified_promotion_binds_artifact_main_ancestry_and_all_three_recipes(self):
        api = FakeAPI()
        self.assertIn("verified main CI", V.verify_candidate(api, HEAD, MAIN))
        self.assertIn(("download", 456), api.calls)
        self.assertIn(("graphql", BUILD), api.calls)
        for path in V.INPUTS.values():
            for revision in (HEAD, MAIN, BUILD):
                self.assertIn((path, revision), api.calls)
        for comparison in ("AHEAD", "DIVERGED"):
            api = FakeAPI()
            api.comparison["status"] = comparison
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

    def test_legacy_fixture_does_not_read_mutable_current_builder_inputs(self):
        original = Path.read_bytes
        mutable = {SCRIPT.parents[3] / V.INPUTS[name]
                   for name in ("builderSha256", "producerSha256", "workflowSha256")}
        def read(path):
            if path in mutable:
                raise AssertionError("legacy fixture read mutable current input")
            return original(path)
        with patch.object(Path, "read_bytes", read):
            inputs = fixture()[1]
        self.assertTrue(V.R.matches_historical_inputs("core-idle-v1", 1, inputs))

    def test_registered_legacy_build_survives_current_builder_policy_drift(self):
        api = FakeAPI()
        for name in ("builderSha256", "producerSha256", "workflowSha256"):
            path = V.INPUTS[name]
            for revision in (HEAD, MAIN):
                api.blobs[path, revision] += b"\n# newer protected policy\n"
        self.assertEqual(len(api.manifest["fileSha256"]), 57)
        self.assertIn("verified main CI", V.verify_candidate(api, HEAD, MAIN))
        self.assertIn(("download", 456), api.calls)
        self.assertNotIn((REGISTRY, BUILD), api.calls)
        for path in V.INPUTS.values():
            self.assertIn((path, BUILD), api.calls)

    def test_unregistered_build_tuple_is_rejected_even_when_candidate_and_main_match(self):
        for name, path in V.INPUTS.items():
            api = FakeAPI()
            changed = api.blobs[path, BUILD] + b"\n"
            for revision in (BUILD, HEAD, MAIN):
                api.blobs[path, revision] = changed
            receipt = json.loads(fixture()[4][2][1])
            receipt["inputs"][name] = V.digest(changed)
            if name in ("patchSha256", "sourceManifestSha256"):
                receipt["build"][name] = V.digest(changed)
            api.replace_receipt(receipt)
            with self.subTest(field=name):
                with self.assertRaises(ValueError):
                    V.verify_candidate(api, HEAD, MAIN)
                self.assertNotIn(("download", 456), api.calls)

    def test_legacy_resolver_cannot_mix_individually_registered_build_hashes(self):
        original = FakeAPI()
        alternate = FakeAPI()
        for name in ("builderSha256", "producerSha256", "workflowSha256"):
            alternate.blobs[V.INPUTS[name], BUILD] += b"\n# synthetic reviewed fixture\n"
        first = V.R.HistoricalInputs(**original.inputs)
        second = V.R.HistoricalInputs(**{name: V.digest(alternate.blobs[path, BUILD])
                                         for name, path in V.INPUTS.items()})
        records = MappingProxyType({("core-idle-v1", 1): (first, second), ("terminal-query-v1", 1): ()})
        with patch.object(V.R, "HISTORICAL_INPUTS", records):
            for api in (original, alternate):
                inputs, manifest = V.resolve_legacy_build_inputs(api, HEAD, BUILD, MAIN)
                self.assertEqual(inputs, {name: V.digest(api.blobs[path, BUILD]) for name, path in V.INPUTS.items()})
                self.assertEqual(manifest["fileCount"], 57)
            original.blobs[V.INPUTS["builderSha256"], BUILD] = alternate.blobs[V.INPUTS["builderSha256"], BUILD]
            with self.assertRaises(ValueError):
                V.resolve_legacy_build_inputs(original, HEAD, BUILD, MAIN)

    def test_registered_tuple_still_requires_fixed_legacy_manifest_and_patch(self):
        for name in ("sourceManifestSha256", "patchSha256"):
            api = FakeAPI()
            api.blobs[V.INPUTS[name], BUILD] += b"\n"
            inputs = {field: V.digest(api.blobs[path, BUILD]) for field, path in V.INPUTS.items()}
            record = V.R.HistoricalInputs(**inputs)
            with self.subTest(field=name), patch.object(V.R, "HISTORICAL_INPUTS",
                    MappingProxyType({("core-idle-v1", 1): (record,)})), self.assertRaises(ValueError):
                V.resolve_legacy_build_inputs(api, HEAD, BUILD, MAIN)

    def test_candidate_registry_cannot_self_authorize_a_promotion(self):
        api = FakeAPI()
        api.blobs[REGISTRY, HEAD] += b"\nraise AssertionError('candidate registry executed')\n"
        with self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertNotIn(("download", 456), api.calls)

    def test_historical_receipt_cannot_claim_current_policy_hashes(self):
        api = FakeAPI()
        path = V.INPUTS["builderSha256"]
        for revision in (HEAD, MAIN):
            api.blobs[path, revision] += b"\n# current builder\n"
        receipt = json.loads(fixture()[4][2][1])
        receipt["inputs"]["builderSha256"] = V.digest(api.blobs[path, MAIN])
        api.replace_receipt(receipt)
        with self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertIn(("download", 456), api.calls)

    def test_v1_selection_cannot_request_v2_or_terminal_recipe(self):
        for change in ({"schemaVersion": 2}, {"recipe": {"family": "terminal-query-v1", "revision": 1}},
                       {"family": "terminal-query-v1"}):
            api = FakeAPI()
            api.blobs[V.PROVENANCE, HEAD] = json.dumps({**api.selected, **change}).encode()
            with self.subTest(change=change), self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)
            self.assertNotIn(("download", 456), api.calls)
        for schema in (2, True):
            api = FakeAPI()
            receipt = json.loads(fixture()[4][2][1])
            receipt["schemaVersion"] = schema
            api.replace_receipt(receipt)
            with self.subTest(receipt_schema=schema), self.assertRaises(ValueError):
                V.verify_candidate(api, HEAD, MAIN)
            self.assertIn(("download", 456), api.calls)

    def test_v1_build_rejects_terminal_71_source_closure(self):
        api = FakeAPI()
        terminal = (SCRIPT.parents[1] / "docs/native-bridge/terminal-query-candidate-preparation/manifest.json").read_bytes()
        self.assertEqual(json.loads(terminal)["fileCount"], 71)
        api.blobs[V.INPUTS["sourceManifestSha256"], BUILD] = terminal
        with self.assertRaises(ValueError):
            V.verify_candidate(api, HEAD, MAIN)
        self.assertNotIn(("download", 456), api.calls)

    def test_isolated_import_loads_fixed_sibling_registry_without_search_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "hostile-import-executed"
            (root / "native_recipe_registry.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\nraise RuntimeError('hostile import')\n")
            code = ("import runpy; namespace=runpy.run_path(" + repr(str(SCRIPT)) + "); "
                    "assert namespace['R'].__file__ == " + repr(str(SCRIPT.with_name('native_recipe_registry.py'))) + "; "
                    "assert namespace['R'].recipe().family == 'core-idle-v1'")
            completed = subprocess.run(  # nosec B603 - Fixed interpreter/code; private fixture paths, no shell.
                                       [sys.executable, "-I", "-B", "-c", code], cwd=root,
                                       capture_output=True, text=True, timeout=20,
                                       env={**V.os.environ, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(marker.exists())
            missing = root / "missing-sibling"
            missing.mkdir()
            isolated = missing / SCRIPT.name
            isolated.write_bytes(SCRIPT.read_bytes())
            failed = subprocess.run(  # nosec B603 - Fixed interpreter/code; private fixture paths, no shell.
                                    [sys.executable, "-I", "-B", "-c",
                                     "import runpy; runpy.run_path(" + repr(str(isolated)) + ")"],
                                    cwd=root, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("FileNotFoundError", failed.stderr)
            self.assertFalse(marker.exists())


class GitHubTransportTests(unittest.TestCase):
    def api(self, responses):
        api = V.GitHub("test-token")
        opener = unittest.mock.Mock()
        opener.open.side_effect = responses
        api.opener = opener
        return api, opener

    def response(self, value):
        return io.BytesIO(json.dumps(value).encode())

    def blob_fixture(self, raw):
        import base64
        import hashlib
        oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
        metadata = {"type": "file", "encoding": "none", "content": "", "sha": oid, "size": len(raw)}
        blob = {"encoding": "base64", "content": base64.encodebytes(raw).decode(), "sha": oid, "size": len(raw)}
        return metadata, blob

    def test_large_patch_uses_pinned_git_blob_and_preserves_bytes(self):
        raw = (SCRIPT.parents[3] / V.INPUTS["patchSha256"]).read_bytes()
        self.assertGreater(len(raw), 1024 * 1024)
        metadata, blob = self.blob_fixture(raw)
        api, opener = self.api([self.response(metadata), self.response(blob)])
        self.assertEqual(api.blob(V.INPUTS["patchSha256"], HEAD), raw)
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual(requests[1].full_url, V.API + "git/blobs/" + metadata["sha"])
        self.assertIn("ref=" + HEAD, requests[0].full_url)
        self.assertEqual(requests[0].get_header("Accept"), "application/vnd.github.object+json")
        self.assertTrue(all(request.get_header("Authorization") == "Bearer test-token" for request in requests))

    def policy_api(self):
        api = V.GitHub("test-token")
        current = {"main": MAIN, "head": HEAD, "changed": False}
        objects = {}

        def request(endpoint, payload=None, **kwargs):
            if endpoint.startswith("pulls/"):
                return {"state": "open", "head": {"sha": current["head"]}}
            if endpoint == "git/ref/heads/main":
                return {"object": {"sha": current["main"]}}
            if endpoint.startswith("statuses/"):
                return {}
            if endpoint.startswith("contents/"):
                path, revision = endpoint.removeprefix("contents/").split("?ref=")
                raw = path.encode()
                if current["changed"] and revision == current["main"] and path == V.SCRIPT:
                    raw += b" changed policy"
                metadata, blob = self.blob_fixture(raw)
                objects[metadata["sha"]] = blob
                return metadata
            if endpoint.startswith("git/blobs/"):
                return objects[endpoint.removeprefix("git/blobs/")]
            raise AssertionError(endpoint)

        api.request = unittest.mock.Mock(side_effect=request)
        return api, current

    def test_multi_pull_publication_fetches_immutable_policy_once_per_revision(self):
        api, _ = self.policy_api()
        with patch.dict(V.os.environ, {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "999"}):
            for number in range(1, 16):
                for state in ("pending", "success"):
                    self.assertTrue(V.publish(api, number, HEAD, state, "checked", BUILD))
        endpoints = [call.args[0] for call in api.request.call_args_list]
        paths = {V.SCRIPT, V.VERIFIER_WORKFLOW, V.LAUNCHER, REGISTRY, *V.INPUTS.values(), *RECIPE_ASSETS}
        # Two HTTP reads per path/revision, shared across both phases of all PRs.
        self.assertEqual(sum(e.startswith("contents/") for e in endpoints), 2 * len(paths))
        self.assertEqual(sum(e.startswith("git/blobs/") for e in endpoints), 2 * len(paths))
        self.assertEqual(endpoints.count("git/ref/heads/main"), 30)
        self.assertEqual(sum(e.startswith("pulls/") for e in endpoints), 30)
        self.assertEqual(sum(e.startswith("statuses/") for e in endpoints), 30)

    def test_cached_policy_rekeys_changed_main_and_never_caches_mutable_head(self):
        api, current = self.policy_api()
        with patch.dict(V.os.environ, {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "999"}):
            self.assertTrue(V.publish(api, 7, HEAD, "pending", "checked", BUILD))
            current.update(main="d" * 40, changed=True)
            self.assertFalse(V.publish(api, 7, HEAD, "success", "checked", BUILD))
            current.update(main=MAIN, head="e" * 40)
            self.assertFalse(V.publish(api, 7, HEAD, "success", "checked", BUILD))
        endpoints = [call.args[0] for call in api.request.call_args_list]
        self.assertIn("contents/" + V.SCRIPT + "?ref=" + "d" * 40, endpoints)
        self.assertEqual(endpoints.count("pulls/7"), 3)
        self.assertEqual(endpoints.count("git/ref/heads/main"), 3)
        self.assertEqual(sum(e.startswith("statuses/") for e in endpoints), 1)

    def test_blob_cache_never_retains_transport_or_validation_failures(self):
        metadata, blob = self.blob_fixture(b"reviewed bytes")
        for failure in (V.urllib.error.URLError("offline"),
                        {**blob, "sha": "d" * 40}):
            responses = ([failure] if isinstance(failure, Exception) else
                         [self.response(metadata), self.response(failure)])
            responses += [self.response(metadata), self.response(blob)]
            api, opener = self.api(responses)
            with self.subTest(failure=type(failure).__name__):
                with self.assertRaises((ValueError, V.urllib.error.URLError)):
                    api.blob(V.LAUNCHER, HEAD)
                self.assertEqual(api.blob(V.LAUNCHER, HEAD), b"reviewed bytes")
                requests = opener.open.call_count
                self.assertEqual(api.blob(V.LAUNCHER, HEAD), b"reviewed bytes")
                self.assertEqual(opener.open.call_count, requests)

    def test_blob_rejects_wrong_identity_size_encoding_and_oversize(self):
        metadata, blob = self.blob_fixture(b"reviewed bytes")
        vectors = [({**metadata, "sha": "../other"}, blob),
                   ({**metadata, "type": "symlink"}, blob),
                   ({**metadata, "size": V.LIMIT + 1}, blob),
                   (metadata, {**blob, "sha": "d" * 40}),
                   (metadata, {**blob, "size": blob["size"] + 1}),
                   (metadata, {**blob, "encoding": "none"}),
                   (metadata, {**blob, "content": "!!!!"}),
                   (metadata, {**blob, "content": "c3Vic3RpdHV0ZWQ="})]
        for index, (meta, value) in enumerate(vectors):
            api, _ = self.api([self.response(meta), self.response(value)])
            with self.subTest(index=index), self.assertRaises(ValueError):
                api.blob(V.LAUNCHER, HEAD)

    def test_blob_decoded_limit_allows_base64_expansion_but_bounds_response(self):
        raw = b"x" * V.LIMIT
        metadata, blob = self.blob_fixture(raw)
        api, _ = self.api([self.response(metadata), self.response(blob)])
        self.assertEqual(api.blob(V.LAUNCHER, HEAD), raw)
        api, _ = self.api([self.response(metadata), io.BytesIO(b" " * (3 * 1024 * 1024 + 1))])
        with self.assertRaises(ValueError):
            api.blob(V.LAUNCHER, HEAD)

    def test_request_bounds_response_and_does_not_follow_redirect(self):
        api, opener = self.api([io.BytesIO(b" " * (V.LIMIT + 1))])
        with self.assertRaises(ValueError):
            api.request("pulls")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, V.API + "pulls")
        self.assertIsNone(V.NoRedirect().redirect_request(request, None, 302, "Found", {}, "https://evil.test/"))
        error = V.urllib.error.HTTPError(request.full_url, 302, "Found", {"Location": "https://evil.test/"}, None)
        api, opener = self.api([error])
        with self.assertRaises(V.urllib.error.HTTPError):
            api.request("pulls")
        self.assertEqual(opener.open.call_count, 1)

    def redirect(self, location, code=302):
        return V.urllib.error.HTTPError(V.API + "actions/artifacts/456/zip", code, "Found", {"Location": location}, None)

    def test_download_only_api_gets_token_and_destination_is_exclusive(self):
        location = "https://production.blob.core.windows.net/container/artifact?signature=secret"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "artifact.zip"
            api, opener = self.api([self.redirect(location), io.BytesIO(b"archive")])
            api.download(456, target)
            self.assertEqual(target.read_bytes(), b"archive")
            first, second = [call.args[0] for call in opener.open.call_args_list]
            self.assertEqual(first.get_header("Authorization"), "Bearer test-token")
            self.assertEqual(first.full_url, V.API + "actions/artifacts/456/zip")
            self.assertEqual(second.full_url, location)
            self.assertIsNone(second.get_header("Authorization"))
            api, _ = self.api([self.redirect(location), io.BytesIO(b"replacement")])
            with self.assertRaises(FileExistsError):
                api.download(456, target)
            self.assertEqual(target.read_bytes(), b"archive")

    def test_download_rejects_unsafe_redirects_and_bounds_stream(self):
        locations = ["http://a.blob.core.windows.net/x", "https://evil.test/x",
                     "https://a.blob.core.windows.net.evil.test/x", "https://blob.core.windows.net/x",
                     "https://user:secret@a.githubusercontent.com/x", "https://a.githubusercontent.com:444/x"]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "artifact.zip"
            for location in locations:
                api, opener = self.api([self.redirect(location)])
                with self.subTest(location=location), self.assertRaises(ValueError):
                    api.download(456, target)
                self.assertEqual(opener.open.call_count, 1)
                self.assertFalse(target.exists())
            location = "https://a.githubusercontent.com/x"
            api, _ = self.api([self.redirect(location), io.BytesIO(b"12345")])
            with patch.object(V, "ARCHIVE_LIMIT", 4), self.assertRaises(ValueError):
                api.download(456, target)
            self.assertEqual(target.read_bytes(), b"")

    def test_download_rejects_missing_or_repeated_redirect(self):
        location = "https://a.githubusercontent.com/x"
        vectors = [[io.BytesIO(b"not a redirect")], [self.redirect(location, 301)],
                   [self.redirect(location), self.redirect("https://evil.test/x")]]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "artifact.zip"
            for responses in vectors:
                api, opener = self.api(responses)
                with self.subTest(responses=len(responses)), self.assertRaises((ValueError, V.urllib.error.HTTPError)):
                    api.download(456, target)
                self.assertEqual(opener.open.call_count, len(responses))
                self.assertFalse(target.exists())
                for call in opener.open.call_args_list[1:]:
                    self.assertIsNone(call.args[0].get_header("Authorization"))


class ProvenanceDriverTests(unittest.TestCase):
    def driver(self, event_name, event, *, fresh_head=HEAD, policy_changed=False, registry_changed=False, asset_changed=False):
        api = unittest.mock.Mock()
        pull = {"number": 7, "head": {"sha": HEAD}, "state": "open"}
        statuses = []
        reads = 0

        def request(endpoint, payload=None):
            nonlocal reads
            if endpoint == "":
                return {"id": V.REPOSITORY_ID}
            if endpoint == "graphql":
                return {"data": {"repository": {"databaseId": V.REPOSITORY_ID, "pullRequests": {
                    "nodes": [{"number": 7, "headRefOid": HEAD}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}
            if endpoint == "pulls/7":
                reads += 1
                return {**pull, "head": {"sha": HEAD if reads == 1 else fresh_head}}
            if endpoint == "git/ref/heads/main":
                return {"object": {"sha": MAIN}}
            if endpoint == "statuses/" + HEAD:
                statuses.append(payload)
                return {}
            raise AssertionError(endpoint)

        def blob(path, revision):
            return b"changed" if (policy_changed or registry_changed and path == REGISTRY or asset_changed and path == RECIPE_ASSETS[-1]) and reads > 1 and revision == MAIN else b"policy"

        api.request.side_effect = request
        api.blob.side_effect = blob
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event))
            env = {"GITHUB_REPOSITORY": V.REPOSITORY, "GH_TOKEN": str(unittest.mock.sentinel.github_token),
                   "WORKFLOW_SHA": BUILD,
                   "GITHUB_EVENT_PATH": str(event_path), "GITHUB_EVENT_NAME": event_name,
                   "GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "999"}
            with patch.dict(V.os.environ, env), patch.object(V, "GitHub", return_value=api), \
                    patch.object(V, "verify_candidate", return_value="Verified") as verify, \
                    patch("sys.stdout", new_callable=io.StringIO):
                V.main()
                verify.assert_called_once_with(api, HEAD, MAIN)
        return statuses

    def test_supported_events_publish_on_current_head(self):
        events = [("pull_request_target", {"pull_request": {"number": 7, "head": {"sha": HEAD}}}),
                  ("workflow_run", {"workflow_run": {
                      "name": "Native client candidate build", "path": V.WORKFLOW,
                      "status": "completed", "event": "workflow_dispatch", "head_branch": "main",
                      "repository": {"id": V.REPOSITORY_ID}, "head_repository": {"id": V.REPOSITORY_ID}}}),
                  ("push", {"ref": "refs/heads/main"})]
        for name, event in events:
            with self.subTest(event=name):
                statuses = self.driver(name, event)
                self.assertEqual([status["state"] for status in statuses], ["pending", "success"])
                self.assertTrue(all(status["context"] == V.CONTEXT for status in statuses))

    def test_final_status_withheld_after_head_or_policy_changes(self):
        for options in ({"fresh_head": "d" * 40}, {"policy_changed": True}, {"registry_changed": True}, {"asset_changed": True}):
            with self.subTest(options=options):
                statuses = self.driver("push", {"ref": "refs/heads/main"}, **options)
                self.assertEqual([status["state"] for status in statuses], ["pending"])

    def gateway_run(self, numbers=(), repository_id=V.REPOSITORY_ID):
        return {"name": "Event Gateway", "path": ".github/workflows/event-gateway.yml",
                "status": "completed", "event": "pull_request", "head_sha": HEAD,
                "repository": {"id": V.REPOSITORY_ID}, "head_repository": {"id": repository_id},
                "pull_requests": [{"number": number,
                                   "head": {"sha": HEAD, "repo": {"id": repository_id}},
                                   "base": {"ref": "main", "repo": {"id": V.REPOSITORY_ID}}}
                                  for number in numbers]}

    def current_pull(self, number, head=HEAD, repository_id=V.REPOSITORY_ID, base="main", state="open"):
        return {"number": number, "state": state, "head": {"sha": head, "repo": {"id": repository_id}},
                "base": {"ref": base, "repo": {"id": V.REPOSITORY_ID}}}

    def workflow_scan(self, run, current):
        api = unittest.mock.Mock()
        publications = []

        def request(endpoint, payload=None):
            if endpoint == "":
                return {"id": V.REPOSITORY_ID}
            if endpoint == "graphql":
                return {"data": {"repository": {"databaseId": V.REPOSITORY_ID, "pullRequests": {
                    "nodes": [{"number": n, "headRefOid": p["head"]["sha"]} for n, p in current.items()],
                    "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}
            if endpoint.startswith("pulls/"):
                return current[int(endpoint.removeprefix("pulls/"))]
            if endpoint == "git/ref/heads/main":
                return {"object": {"sha": MAIN}}
            if endpoint.startswith("statuses/"):
                publications.append((endpoint, payload["state"]))
                return {}
            raise AssertionError(endpoint)

        api.request.side_effect = request
        api.blob.return_value = b"unchanged trusted policy"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps({"workflow_run": run}))
            env = {"GITHUB_REPOSITORY": V.REPOSITORY, "GH_TOKEN": str(unittest.mock.sentinel.github_token),
                   "WORKFLOW_SHA": BUILD, "GITHUB_EVENT_PATH": str(path), "GITHUB_EVENT_NAME": "workflow_run",
                   "GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "999"}
            with patch.dict(V.os.environ, env, clear=True), patch.object(V, "GitHub", return_value=api), \
                    patch.object(V, "verify_candidate", return_value="Verified") as verify, \
                    patch("sys.stdout", new_callable=io.StringIO):
                V.main()
        return publications, [call.args[0] for call in api.request.call_args_list], verify.call_args_list

    def test_gateway_completion_targets_embedded_pull_without_open_scan(self):
        statuses, endpoints, verified = self.workflow_scan(self.gateway_run([7]), {
            7: self.current_pull(7), 8: self.current_pull(8, "d" * 40)})
        self.assertEqual(statuses, [("statuses/" + HEAD, "pending"), ("statuses/" + HEAD, "success")])
        self.assertNotIn("graphql", endpoints)
        self.assertNotIn("pulls/8", endpoints)
        self.assertEqual(len(verified), 1)

    def test_gateway_completion_never_refreshes_stale_closed_or_other_base_pull(self):
        for pull in (self.current_pull(7, "d" * 40), self.current_pull(7, state="closed"),
                     self.current_pull(7, base="release"), self.current_pull(7, repository_id=999)):
            with self.subTest(pull=pull):
                statuses, endpoints, verified = self.workflow_scan(self.gateway_run([7]), {7: pull})
                self.assertEqual(statuses, [])
                self.assertEqual(verified, [])
                self.assertNotIn("graphql", endpoints)

    def test_gateway_empty_fork_association_filters_head_and_repository(self):
        statuses, endpoints, verified = self.workflow_scan(self.gateway_run(repository_id=999), {
            7: self.current_pull(7, repository_id=999), 8: self.current_pull(8),
            9: self.current_pull(9, "d" * 40, repository_id=999)})
        self.assertEqual([state for _, state in statuses], ["pending", "success"])
        self.assertEqual(endpoints.count("graphql"), 1)
        self.assertNotIn("pulls/9", endpoints)
        self.assertEqual(len(verified), 1)
        statuses, _, verified = self.workflow_scan(self.gateway_run(), {9: self.current_pull(9, "d" * 40)})
        self.assertEqual((statuses, verified), ([], []))

    def test_gateway_multiple_pulls_at_same_head_are_checked_and_deduplicated(self):
        statuses, endpoints, verified = self.workflow_scan(self.gateway_run([7, 8, 7]), {
            7: self.current_pull(7), 8: self.current_pull(8)})
        self.assertEqual([state for _, state in statuses], ["pending", "success", "pending", "success"])
        self.assertEqual(len(verified), 2)
        self.assertEqual(endpoints.count("pulls/7"), 3)  # selection, pending, final
        self.assertEqual(endpoints.count("pulls/8"), 3)

    def test_new_native_build_still_refreshes_different_open_heads(self):
        run = {"name": "Native client candidate build", "path": V.WORKFLOW,
               "status": "completed", "event": "workflow_dispatch", "head_branch": "main",
               "repository": {"id": V.REPOSITORY_ID}, "head_repository": {"id": V.REPOSITORY_ID}}
        statuses, endpoints, verified = self.workflow_scan(run, {
            7: self.current_pull(7), 8: self.current_pull(8, "d" * 40)})
        self.assertEqual(statuses, [("statuses/" + head, state)
                                   for head in (HEAD, "d" * 40) for state in ("pending", "success")])
        self.assertEqual(endpoints.count("graphql"), 1)
        self.assertEqual(len(verified), 2)

    def test_gateway_run_identity_is_validated_before_publication(self):
        for update in ({"repository": {"id": 999}}, {"head_sha": "invalid"}, {"status": "in_progress"},
                       {"path": "untrusted.yml"}, {"event": "workflow_dispatch"},
                       {"head_repository": {"id": True}}, {"pull_requests": None}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.workflow_scan({**self.gateway_run([7]), **update}, {7: self.current_pull(7)})
