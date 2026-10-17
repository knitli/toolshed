from contextlib import redirect_stderr
import io
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import sys
import struct
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
    import native_recipe_registry as registry

    spec = importlib.util.spec_from_file_location("native_ci_producer", SCRIPTS / "produce_native_ci_artifact.py")
    PRODUCER = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(PRODUCER)


def vars_asset(asset):
    return {"path": asset.path, "bytes": asset.bytes, "sha256": asset.sha256}


class NativeCIProducerTests(unittest.TestCase):
    def env(self):
        return {"GITHUB_REPOSITORY_ID": "1200860702", "GITHUB_REPOSITORY": "knitli/toolshed",
                "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "RUNNER_ARCH": "ARM64", "GITHUB_SHA": "a" * 40,
                "GITHUB_WORKFLOW_REF": "knitli/toolshed/.github/workflows/event-native-build.yml@refs/heads/main",
                "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}

    def test_identity_rejects_each_untrusted_dispatch_dimension(self):
        good = self.env()
        self.assertEqual(PRODUCER.identity(good)["runAttempt"], 2)
        for key, value in {"GITHUB_REPOSITORY_ID": "1", "GITHUB_REPOSITORY": "fork/toolshed",
                           "GITHUB_REF": "refs/heads/pr", "GITHUB_EVENT_NAME": "pull_request",
                           "RUNNER_ARCH": "X64", "GITHUB_SHA": "main",
                           "GITHUB_WORKFLOW_REF": "knitli/toolshed/.github/workflows/evil.yml@refs/heads/main",
                           "GITHUB_RUN_ID": "0", "GITHUB_RUN_ATTEMPT": "-1"}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                PRODUCER.identity({**good, key: value})

    def test_platform_gate_rejects_non_arm_macos_before_commands(self):
        for system, machine in (("Linux", "arm64"), ("Darwin", "x86_64")):
            with patch.object(PRODUCER.platform, "system", return_value=system), \
                    patch.object(PRODUCER.platform, "machine", return_value=machine), \
                    patch.object(PRODUCER, "command") as command:
                with self.assertRaises(ValueError):
                    PRODUCER.environment(self.env())
                command.assert_not_called()

    def test_receipt_binds_actual_outputs_and_rejects_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def package(_source, binary, evidence, _host, **kwargs):
                self.assertEqual(kwargs, {"prime_dependencies": True, "family": "core-idle-v1", "revision": 1})
                binary.write_bytes(b"cli")
                (binary.parent / "codex-code-mode-host").write_bytes(b"host")
                evidence.write_text("{}")
                return {"recipe": {"family": "core-idle-v1", "revision": 1,
                                   "manifestSha256": registry.recipe().manifest.sha256},
                        "sourceManifestSha256": registry.recipe().manifest.sha256,
                        "appliedPatches": [vars_asset(a) for a in registry.recipe().ordered_patches],
                        "binarySha256": PRODUCER.builder.sha256(b"cli"),
                        "codeModeHost": {"executableSha256": PRODUCER.builder.sha256(b"host")}}
            with patch.dict(os.environ, self.env(), clear=True), \
                    patch.object(PRODUCER, "command", return_value="a" * 40), \
                    patch.object(PRODUCER, "environment", return_value={"sdkVersion": "27.0"}), \
                    patch.object(PRODUCER.builder, "package", side_effect=package):
                receipt = PRODUCER.produce(root, root / "host.tar.gz", root / "output")
                self.assertEqual(receipt["artifactName"], "native-client-123-2")
                self.assertEqual(set(p.name for p in (root / "output").iterdir()),
                                 {"codex", "codex-code-mode-host", "build-receipt.json"})
                self.assertEqual(receipt["inputs"]["producerSha256"],
                                 PRODUCER.builder.sha256_file(Path(PRODUCER.__file__)))

                self.assertEqual(receipt["inputs"]["sourceManifestSha256"],
                                 PRODUCER.builder.SOURCE_MANIFEST_SHA256)
                self.assertEqual(receipt["schemaVersion"], 2)
                self.assertEqual(receipt["recipe"], receipt["build"]["recipe"])
                self.assertEqual(set(receipt["inputs"]), {
                    "builderSha256", "producerSha256", "workflowSha256",
                    "registrySha256", "sourceManifestSha256",
                })
                self.assertEqual(receipt["inputs"]["registrySha256"],
                                 PRODUCER.builder.sha256_file(Path(registry.__file__)))

                def substituted(*args, **kwargs):
                    evidence = package(*args, **kwargs)
                    args[1].write_bytes(b"substituted")
                    return evidence
                with patch.object(PRODUCER.builder, "package", side_effect=substituted), \
                        self.assertRaisesRegex(ValueError, "native_producer_output_changed"):
                    PRODUCER.produce(root, root / "host.tar.gz", root / "bad-output")
                self.assertFalse((root / "bad-output/build-receipt.json").exists())

    def test_terminal_receipt_rejects_changed_recipe_identity_and_assets(self):
        selected = registry.recipe("terminal-query-v1", 1)
        identity = {"family": selected.family, "revision": selected.revision,
                    "manifestSha256": selected.manifest.sha256}
        assets = (selected.manifest, *selected.parents, *selected.ordered_patches)
        scenarios = [(name, None) for name in (
            "valid", "family", "revision", "manifestSha256", "sourceManifestSha256", "appliedPatches",
            "bool-revision", "extra-key", "missing-recipe",
        )] + [("asset", asset.path) for asset in assets]
        for scenario, asset_path in scenarios:
            with self.subTest(scenario=scenario, asset=asset_path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                built = False
                original_read = PRODUCER.builder.registry._read_asset

                def read_asset(asset):
                    data = original_read(asset)
                    if built and scenario == "asset" and asset.path == asset_path:
                        return data + b"tampered"
                    return data

                def package(_source, binary, evidence, _host, **kwargs):
                    nonlocal built
                    self.assertEqual(kwargs, {"prime_dependencies": True,
                                              "family": selected.family, "revision": 1})
                    binary.write_bytes(b"cli")
                    (binary.parent / "codex-code-mode-host").write_bytes(b"host")
                    evidence.write_text("{}")
                    build_identity = dict(identity)
                    if scenario in identity:
                        build_identity[scenario] = 2 if scenario == "revision" else "wrong"
                    if scenario == "bool-revision":
                        build_identity["revision"] = True
                    elif scenario == "extra-key":
                        build_identity["unexpected"] = "value"
                    built = True
                    build = {"recipe": build_identity,
                            "sourceManifestSha256": selected.manifest.sha256,
                            "appliedPatches": [vars_asset(a) for a in selected.ordered_patches],
                            "binarySha256": PRODUCER.builder.sha256(b"cli"),
                            "codeModeHost": {"executableSha256": PRODUCER.builder.sha256(b"host")}}
                    if scenario == "sourceManifestSha256":
                        build[scenario] = "0" * 64
                    elif scenario == "appliedPatches":
                        build[scenario] = list(reversed(build[scenario]))
                    if scenario == "missing-recipe":
                        del build["recipe"]
                    return build

                with patch.dict(os.environ, self.env(), clear=True), \
                        patch.object(PRODUCER, "command", return_value="a" * 40), \
                        patch.object(PRODUCER, "environment", return_value={}), \
                        patch.object(PRODUCER.builder, "package", side_effect=package), \
                        patch.object(PRODUCER.builder.registry, "_read_asset", side_effect=read_asset):
                    if scenario == "valid":
                        receipt = PRODUCER.produce(root, root / "host", root / "output",
                                                   family=selected.family, revision=1)
                        self.assertEqual(receipt["recipe"], identity)
                        self.assertEqual(receipt["inputs"]["sourceManifestSha256"], selected.manifest.sha256)
                    else:
                        with self.assertRaises(ValueError):
                            PRODUCER.produce(root, root / "host", root / "output",
                                             family=selected.family, revision=1)
                        self.assertFalse((root / "output/build-receipt.json").exists())

    def test_current_producer_receipt_passes_current_verifier(self):
        import test_native_ci_provenance as provenance

        binary = struct.pack("<II", 0xFEEDFACF, 0x0100000C) + b"mock cli"
        host = struct.pack("<II", 0xFEEDFACF, 0x0100000C) + b"mock host"
        for family in ("core-idle-v1", "terminal-query-v1"):
            with self.subTest(family=family), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                validated = registry.validate_recipe(family)
                selected = validated.recipe
                inventory = hashlib.sha256()
                for path, digest in sorted(validated.file_sha256.items()):
                    inventory.update(path.encode() + b"\0" + bytes.fromhex(digest))

                def package(_source, output, evidence, _host, **kwargs):
                    self.assertEqual(kwargs, {"family": family, "revision": 1, "prime_dependencies": True})
                    output.write_bytes(binary)
                    (output.parent / "codex-code-mode-host").write_bytes(host)
                    evidence.write_text("{}")
                    return {
                        "recipe": {"family": family, "revision": 1,
                                   "manifestSha256": selected.manifest.sha256},
                        "sourceManifestSha256": selected.manifest.sha256,
                        "upstreamCommit": selected.upstream_commit,
                        "archiveScope": {"selection": "git archive of the pinned commit without pathspecs",
                                         "extractionFilter": "tarfile.data_filter"},
                        "appliedPatches": [vars_asset(a) for a in selected.ordered_patches],
                        "patchedFileCount": selected.file_count,
                        "patchedFileSha256": dict(validated.file_sha256),
                        "patchedSourceInventoryBeforeBuildSha256": inventory.hexdigest(),
                        "patchedSourceInventoryAfterBuildSha256": inventory.hexdigest(),
                        "binarySha256": hashlib.sha256(binary).hexdigest(),
                        "codeModeHost": {"executableSha256": hashlib.sha256(host).hexdigest()},
                        "host": "aarch64-apple-darwin", "normalizedCargoLockSha256": "f" * 64,
                    }

                environment = {"runnerArch": "ARM64", "runnerImageOS": "macos",
                               "runnerImageVersion": "fixture", "sdkVersion": "27",
                               "clangVersion": "clang fixture", "linkerVersion": "ld fixture"}
                with patch.dict(os.environ, {**self.env(), "GITHUB_SHA": provenance.BUILD}, clear=True), \
                        patch.object(PRODUCER, "command", return_value=provenance.BUILD), \
                        patch.object(PRODUCER, "environment", return_value=environment), \
                        patch.object(PRODUCER.builder, "package", side_effect=package):
                    receipt = PRODUCER.produce(root, root / "unused-host", root / "output", family=family)
                api = provenance.FakeAPI()
                api.archive = provenance.archive_bytes([
                    (name, (root / "output" / name).read_bytes())
                    for name in ("codex", "codex-code-mode-host", "build-receipt.json")])
                api.selected.update(schemaVersion=2, recipe=receipt["recipe"],
                                    artifactSha256=hashlib.sha256(api.archive).hexdigest(),
                                    binarySha256=hashlib.sha256(binary).hexdigest(),
                                    codeModeHostSha256=hashlib.sha256(host).hexdigest())
                api.workflow, api.run, api.artifact = provenance.metadata(api.selected)
                api.artifact["size_in_bytes"] = len(api.archive)
                paths = {*provenance.V.INPUTS.values(), provenance.REGISTRY, *provenance.RECIPE_ASSETS}
                for path in paths:
                    for revision in (provenance.HEAD, provenance.BUILD, provenance.MAIN):
                        api.blobs[path, revision] = (PRODUCER.builder.ROOT / path).read_bytes()
                api.blobs[provenance.V.LAUNCHER, provenance.HEAD] = provenance.launcher(
                    api.selected["binarySha256"], api.selected["codeModeHostSha256"])
                api.blobs[provenance.V.PROVENANCE, provenance.HEAD] = json.dumps(api.selected).encode()
                self.assertEqual(provenance.V.verify_candidate(api, provenance.HEAD, provenance.MAIN),
                                 "Native pin matches verified main CI build artifact")
                self.assertIn(("download", 456), api.calls)
                receipt["inputs"]["registrySha256"] = "0" * 64
                api.replace_receipt(receipt)
                with self.assertRaises(ValueError):
                    provenance.V.verify_candidate(api, provenance.HEAD, provenance.MAIN)

    def test_producer_cli_and_workflow_recipe_contract(self):
        required = ["producer", "--source", "source", "--host-archive", "host", "--output-dir", "output"]
        for family in (None, "core-idle-v1", "terminal-query-v1"):
            argv = required + ([] if family is None else ["--family", family])
            with patch.object(sys, "argv", argv), patch.object(PRODUCER, "produce") as produce:
                PRODUCER.main()
                self.assertEqual(produce.call_args.kwargs, {
                    "family": family or "core-idle-v1", "revision": 1,
                })
        for invalid in (["--family", "unknown"], ["--revision", "2"]):
            with patch.object(sys, "argv", required + invalid), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                PRODUCER.main()
            self.assertEqual(error.exception.code, 2)
        workflow = (SCRIPTS.parents[2] / ".github/workflows/event-native-build.yml").read_text()
        self.assertIn("default: core-idle-v1", workflow)
        self.assertIn("options:\n          - core-idle-v1\n          - terminal-query-v1", workflow)
        self.assertIn("NATIVE_RECIPE_FAMILY: ${{ inputs.family }}", workflow)
        self.assertIn('--family "$NATIVE_RECIPE_FAMILY" --revision 1', workflow)
        self.assertNotIn('--family ${{', workflow)
