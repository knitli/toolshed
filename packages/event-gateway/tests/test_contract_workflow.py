"""Exercise the trusted verifier with candidate bytes, without credentials/network."""
import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import textwrap
import unittest
import zipfile
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
MESSAGING_V2_PATHS = (
    "messaging-v2/messaging-protocol-semantics-v2.json",
    "messaging-v2/messaging-v2-wire.json",
    "messaging-v2/source-receipt.json",
    "messaging-v2/wire-source-receipt.json",
)
MESSAGING_V2_ADOPTION_FIXTURE = {
    "name": "test-only-assigned-stock-profile",
    "adoption": "trusted",
    "hashes": {path: "0" * 64 for path in MESSAGING_V2_PATHS},
}
DORMANT_V2_ARCHIVE = "tests/fixtures/messaging-v2-dormant-contract.zip"
DORMANT_V2_ARCHIVE_SHA256 = "6e19bee4a5ee9ae77fc33e465f1dc113bf78d0f9495bfe77b35ab22c8850113e"
ACTIVE_V2_NAME = "active-assigned-stock-v2"
ACTIVE_V2_SOURCE_SHA = "e954904603b3467e30bbeaf7446977b61fbcb9ef"
ACTIVE_V2_SOURCE_TREE = "f47bb9345aa17f9b504965bd5c319163b569c9df"
ACTIVE_V2_ARCHIVE = "tests/fixtures/messaging-v2-active-assigned-stock.zip"
ACTIVE_V2_ARCHIVE_SHA256 = "adc3842002feb70851031312e85571866e216b25342382a99365c29d099b395c"
ACTIVE_V2_HASHES = {
    "messaging-v2/messaging-protocol-semantics-v2.json": "0553380db6fbe8c9af557aea5847ce22cb52917da1daadb4491524e1f2cdf22f",
    "messaging-v2/messaging-v2-wire.json": "a66d74967f5470e193bfcb250cdc130fd22081b88c42b62c24fecf01d269f032",
    "messaging-v2/source-receipt.json": "6a972450486b48eccdfc8a82f077139689bf5b3b5990c4a3ca7836c247f922df",
    "messaging-v2/wire-source-receipt.json": "4fd527d2d963d07a01c9b2d8491bee4813ad4f826eb4537698aba6ea6c1e58e2",
}
ACTIVE_V2_SOURCE_HASHES = {
    "apps/os/packages/event-runtime/src/messaging/protocol-v2.ts": "3f91122c7bd2d78d072ad51a9fb2fef4adfb99e3277bf4052196a54a74238193",
    "apps/os/packages/event-runtime/src/protocol.ts": "b9927658cd80cfb52222bcc20ffe748acbea0c16da06f0f283b55c6046b9284d",
    "apps/os/packages/event-runtime/src/policy.ts": "2de281e76f796aa92b7809eff8039c74847bd0fd8303ef8453d408dcb39e15e3",
    "apps/os/packages/event-runtime/__tests__/fixtures/messaging-protocol-semantics-v2.json": (
        ACTIVE_V2_HASHES["messaging-v2/messaging-protocol-semantics-v2.json"]
    ),
    "apps/os/packages/event-runtime/__tests__/fixtures/messaging-v2-wire.json": ACTIVE_V2_HASHES["messaging-v2/messaging-v2-wire.json"],
    "apps/os/pnpm-lock.yaml": "62f84801e3d426df4a97a54bc48c1a547d9ae3f0205166cc92d9b7391e581549",
}
ACTIVE_V2_SCHEMA_HASHES = {
    "package.json": "a046ed85fa09571dba539fee9ef236152d12dabd1f229b014ec3bd2ebaad9000",
    "v4/core/checks.js": "bc42543274218aa7ef72192b3218d2a4a399e53df8de240a04d9ff275096f563",
    "v4/core/util.js": "728f52b496620336775eafcdb91c0a574380086e53f215b55c58eedc1422c49c",
}
STOCK_NAME = 'assigned-stock-github-delivery'
STOCK_REVISION = '9503b8e2a99fbe099a4b90cb576a17dcf4b786aa'
STOCK_ARCHIVE = 'tests/fixtures/assigned-stock-contract-family.zip'
STOCK_ARCHIVE_SHA256 = 'eb8836acab853d0f05cdb6be375d1f6459ae9ee48db62e2f1d0048a2656bbe37'
STOCK_FAMILY = {'name': 'assigned-stock-github-delivery',
 'eventRevision': '9503b8e2a99fbe099a4b90cb576a17dcf4b786aa',
 'controlRevision': '9503b8e2a99fbe099a4b90cb576a17dcf4b786aa',
 'hashes': {'event-v1/protocol.schema.json': '4f52187100e98eef2dadbfbe319e41fc0af6aa82ee1c185ec152171d20cbfb23',
            'event-v1/protocol.ts': 'b9927658cd80cfb52222bcc20ffe748acbea0c16da06f0f283b55c6046b9284d',
            'event-v1/policy.ts': '2de281e76f796aa92b7809eff8039c74847bd0fd8303ef8453d408dcb39e15e3',
            'event-v1/protocol-v1.json': '3f34e88d5cf1fb42318ba76435e77668551877250e00e8ca430ae697a6a271dd',
            'event-v1/manifest.json': 'd20cb06b70b0144a4b3266efd02cd6054ebed7db0708e4385c5594039d8fdfca',
            'event-control-v1/fixtures.json': 'f17a12d3b67094c60f56280258cf43835302e8797a925ca21626f1a95f7e96c1',
            'event-control-v1/manifest.json': '84a90e9ff7b2b6586bf73cc4c23419044d32fb5751201a2baaf65c5cc2eb4bfa'}}
WATCH_NAME = 'assigned-stock-watch-lease-renewal'
WATCH_EVENT_REVISION = '9503b8e2a99fbe099a4b90cb576a17dcf4b786aa'
WATCH_CONTROL_REVISION = 'cf74332d0d9544f64a3c8bfac6ae27fbbe17ba49'
WATCH_ARCHIVE = 'tests/fixtures/assigned-stock-watch-lease-family.zip'
WATCH_ARCHIVE_SHA256 = 'f27db38aa08a33dc596aa079c0c2440e4dc05463f8ca5282d390db96f8350f1c'
WATCH_FAMILY = {'name': 'assigned-stock-watch-lease-renewal',
 'eventRevision': '9503b8e2a99fbe099a4b90cb576a17dcf4b786aa',
 'controlRevision': 'cf74332d0d9544f64a3c8bfac6ae27fbbe17ba49',
 'hashes': {'event-v1/protocol.schema.json': '4f52187100e98eef2dadbfbe319e41fc0af6aa82ee1c185ec152171d20cbfb23',
            'event-v1/protocol.ts': 'b9927658cd80cfb52222bcc20ffe748acbea0c16da06f0f283b55c6046b9284d',
            'event-v1/policy.ts': '2de281e76f796aa92b7809eff8039c74847bd0fd8303ef8453d408dcb39e15e3',
            'event-v1/protocol-v1.json': '3f34e88d5cf1fb42318ba76435e77668551877250e00e8ca430ae697a6a271dd',
            'event-v1/manifest.json': 'd20cb06b70b0144a4b3266efd02cd6054ebed7db0708e4385c5594039d8fdfca',
            'event-control-v1/fixtures.json': '0527c67cc768cf2f0376667e8752089b120561cc42c046f2a127f1dd24abba3f',
            'event-control-v1/manifest.json': '6181e885acff32d31ed2196230c2d6f328336afd900b9ae250e93de596be58fe'}}
HISTORICAL_ARCHIVE_SHA256 = "ad1e41e5add910d6bbf56960717fff9bdf6aae1ddd1f7a87bea2f5af3582b879"



def family(name, blobs):
    return {"name": name, "hashes": {
        path: hashlib.sha256(blobs[SNAPSHOT + path]).hexdigest() for path in PATHS}}


class ContractWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.original = {SNAPSHOT + path: (PACKAGE / "contracts" / path).read_bytes()
                         for path in PATHS}
        self.blobs = self.original.copy()
        self.messaging_v2 = {
            SNAPSHOT + path: (PACKAGE / "contracts" / path).read_bytes()
            for path in MESSAGING_V2_PATHS
        }
        self.blobs.update(self.messaging_v2)
        self.reads = []
        self.api_reads = []
        self.tree = {"truncated": False, "tree": [
            {"path": SNAPSHOT + path, "type": "blob", "mode": "100644"}
            for path in (*PATHS, *MESSAGING_V2_PATHS)]}
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

    def verify_messaging_v2(self, profiles=None, head=HEAD):
        def request(endpoint, token, payload=None):
            self.api_reads.append(endpoint)
            self.assertEqual(endpoint, f"git/trees/{HEAD}?recursive=1")
            self.assertEqual(token, "test-token")
            self.assertIsNone(payload)
            return self.tree
        replacements = {"read_blob": self.read_blob, "request_json": request}
        if profiles is not None:
            replacements["MESSAGING_V2_PROFILES"] = profiles
        with patch.dict(POLICY, replacements):
            return POLICY["verify_messaging_v2_contract"](head, "test-token")

    def active_contract_blobs(self):
        with zipfile.ZipFile(PACKAGE / ACTIVE_V2_ARCHIVE) as archive:
            return {SNAPSHOT + path: archive.read(f"snapshots/{ACTIVE_V2_NAME}/{path}")
                    for path in MESSAGING_V2_PATHS}

    def test_dormant_messaging_v2_profile_is_provenance_only(self):
        archive_path = PACKAGE / DORMANT_V2_ARCHIVE
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                         DORMANT_V2_ARCHIVE_SHA256)
        with zipfile.ZipFile(archive_path) as archive:
            self.assertCountEqual(archive.namelist(), MESSAGING_V2_PATHS)
            self.messaging_v2 = {SNAPSHOT + path: archive.read(path)
                                 for path in MESSAGING_V2_PATHS}
        self.blobs.update(self.messaging_v2)
        self.assertEqual(self.verify_messaging_v2(),
                         ("dormant-source-conformance", "dormant"))
        receipt = json.loads(self.messaging_v2[SNAPSHOT + MESSAGING_V2_PATHS[2]])
        self.assertFalse(receipt["trustedPolicyAdoption"])
        self.assertCountEqual(self.reads, [SNAPSHOT + path for path in MESSAGING_V2_PATHS])

    def test_active_messaging_v2_archive_pins_exact_merged_source_and_schema(self):
        archive_path = PACKAGE / ACTIVE_V2_ARCHIVE
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), ACTIVE_V2_ARCHIVE_SHA256)
        with zipfile.ZipFile(archive_path) as archive:
            metadata = json.loads(archive.read("metadata.json"))
            expected_members = {"metadata.json"}
            expected_members.update(f"snapshots/{ACTIVE_V2_NAME}/{path}" for path in MESSAGING_V2_PATHS)
            expected_members.update(f"sources/{ACTIVE_V2_SOURCE_SHA}/{path}" for path in ACTIVE_V2_SOURCE_HASHES)
            expected_members.update(f"dependencies/zod@4.6.5/{path}" for path in ACTIVE_V2_SCHEMA_HASHES)
            self.assertEqual(len(archive.namelist()), len(set(archive.namelist())))
            self.assertEqual(set(archive.namelist()), expected_members)
            self.assertEqual(metadata["profile"], ACTIVE_V2_NAME)
            self.assertEqual(metadata["adoption"], "active")
            self.assertEqual(metadata["sourceCommit"], ACTIVE_V2_SOURCE_SHA)
            self.assertEqual(metadata["sourceTree"], ACTIVE_V2_SOURCE_TREE)
            self.assertEqual(metadata["contractHashes"], ACTIVE_V2_HASHES)
            self.assertEqual({entry["path"]: entry["sha256"] for entry in metadata["sourceFiles"]},
                             ACTIVE_V2_SOURCE_HASHES)
            for path, digest in ACTIVE_V2_SOURCE_HASHES.items():
                archived = archive.read(f"sources/{ACTIVE_V2_SOURCE_SHA}/{path}")
                self.assertEqual(hashlib.sha256(archived).hexdigest(), digest)
            schema = metadata["schemaDependency"]
            self.assertEqual((schema["package"], schema["version"]), ("zod", "4.6.5"))
            self.assertEqual({entry["path"]: entry["sha256"] for entry in schema["files"]},
                             ACTIVE_V2_SCHEMA_HASHES)
            for path, digest in ACTIVE_V2_SCHEMA_HASHES.items():
                archived = archive.read(f"dependencies/zod@4.6.5/{path}")
                self.assertEqual(hashlib.sha256(archived).hexdigest(), digest)
            self.assertEqual(json.loads(archive.read("dependencies/zod@4.6.5/package.json"))["version"], "4.6.5")
            for contract_path in MESSAGING_V2_PATHS:
                blob = archive.read(f"snapshots/{ACTIVE_V2_NAME}/{contract_path}")
                self.assertEqual(hashlib.sha256(blob).hexdigest(), ACTIVE_V2_HASHES[contract_path])
            for receipt_path, fixture_path, fixture_hash in (
                (
                    MESSAGING_V2_PATHS[2],
                    "apps/os/packages/event-runtime/__tests__/fixtures/messaging-protocol-semantics-v2.json",
                    ACTIVE_V2_HASHES[MESSAGING_V2_PATHS[0]],
                ),
                (
                    MESSAGING_V2_PATHS[3],
                    "apps/os/packages/event-runtime/__tests__/fixtures/messaging-v2-wire.json",
                    ACTIVE_V2_HASHES[MESSAGING_V2_PATHS[1]],
                ),
            ):
                receipt = json.loads(archive.read(f"snapshots/{ACTIVE_V2_NAME}/{receipt_path}"))
                self.assertEqual(receipt["purpose"], "active_assigned_stock_v2_policy_adoption")
                self.assertTrue(receipt["trustedPolicyAdoption"])
                self.assertEqual(receipt["sourceCommit"], ACTIVE_V2_SOURCE_SHA)
                self.assertEqual(receipt["sourceTree"], ACTIVE_V2_SOURCE_TREE)
                self.assertEqual({entry["path"]: entry["sha256"] for entry in receipt["sourceFiles"]},
                                 ACTIVE_V2_SOURCE_HASHES)
                self.assertEqual(receipt["schemaDependency"], schema)
                self.assertEqual(receipt["fixture"]["sha256"], fixture_hash)
                self.assertEqual(receipt["fixture"]["file"], fixture_path)

        profiles = POLICY["MESSAGING_V2_PROFILES"]
        dormant = next(profile for profile in profiles if profile["name"] == "dormant-source-conformance")
        active = next(profile for profile in profiles if profile["name"] == ACTIVE_V2_NAME)
        self.assertEqual(dormant["adoption"], "dormant")
        self.assertEqual(dormant["hashes"], {
            "messaging-v2/messaging-protocol-semantics-v2.json": "74c37fe03b019c153a4ac81c11253618a1444eea63d794d70e9899699e2f786d",
            "messaging-v2/messaging-v2-wire.json": "9b5c4030c7059f68c55d1e0a2dad51eb276ed585b8dac18b437ff9ae97900129",
            "messaging-v2/source-receipt.json": "ec07eabf0dbeecfeb1170e48f435b4ffdcbb0554516aff24153f0d276572ad7d",
            "messaging-v2/wire-source-receipt.json": "146dc8c15c41d1c4da9a59537cf693d6a3a6dcad30dc2e7d94f9d129a5bc3e88",
        })
        self.assertEqual((active["adoption"], active["hashes"]), ("active", ACTIVE_V2_HASHES))
        self.blobs.update(self.active_contract_blobs())
        self.assertEqual(self.verify_messaging_v2(), (ACTIVE_V2_NAME, "active"))

    def test_active_messaging_v2_profile_rejects_each_single_blob_mutation(self):
        active = next(profile for profile in POLICY["MESSAGING_V2_PROFILES"]
                      if profile["name"] == ACTIVE_V2_NAME)
        for path in MESSAGING_V2_PATHS:
            with self.subTest(path=path):
                self.blobs = self.active_contract_blobs()
                self.blobs[SNAPSHOT + path] += b"mutation"
                with self.assertRaisesRegex(ValueError, "Messaging v2 contract profile not authorized"):
                    self.verify_messaging_v2((active,))

    def test_active_messaging_v2_profile_publishes_distinct_status(self):
        self.blobs.update(self.active_contract_blobs())
        results, posts, _ = self.refresh()
        self.assertEqual(results, [(1, HEAD, "success", "success")])
        v2_posts = [payload for _, payload in posts
                    if payload["context"] == "Event Gateway / Messaging v2 contract"]
        self.assertEqual([(payload["state"], payload["description"]) for payload in v2_posts], [
            ("pending", "Checking exact Messaging v2 contract profile"),
            ("success", "Active trusted Messaging v2 profile verified: " + ACTIVE_V2_NAME),
        ])
        self.assertEqual(sum(payload["state"] == "success" for _, payload in posts
                             if payload["context"] == "Event Gateway / trusted contract"), 1)

    def test_messaging_v2_profile_fixture_is_test_only_and_exact(self):
        profile = dict(MESSAGING_V2_ADOPTION_FIXTURE, hashes={
            path: hashlib.sha256(self.messaging_v2[SNAPSHOT + path]).hexdigest()
            for path in MESSAGING_V2_PATHS
        })
        self.assertEqual(self.verify_messaging_v2((profile,)),
                         ("test-only-assigned-stock-profile", "trusted"))
        self.blobs[SNAPSHOT + MESSAGING_V2_PATHS[0]] += b"mutation"
        with self.assertRaisesRegex(ValueError, "Messaging v2 contract profile not authorized"):
            self.verify_messaging_v2((profile,))

    def test_messaging_v2_profile_rejects_omitted_source_receipt(self):
        self.tree["tree"] = [entry for entry in self.tree["tree"]
                              if entry["path"] != SNAPSHOT + MESSAGING_V2_PATHS[2]]
        with self.assertRaisesRegex(ValueError, "not a regular Git blob"):
            self.verify_messaging_v2()
        self.assertEqual(self.reads, [])

    def approved_snapshot(self, name):
        # Read immutable data only: no extraction, source evaluation, or Git/network dependency.
        archive_path = PACKAGE / {
            STOCK_NAME: STOCK_ARCHIVE,
            WATCH_NAME: WATCH_ARCHIVE,
        }.get(name, "tests/fixtures/trusted-contract-families.zip")
        with zipfile.ZipFile(archive_path) as archive:
            return {SNAPSHOT + path: archive.read(f"snapshots/{name}/{path}") for path in PATHS}


    def assert_archived_sources(self, archive, revision, hashes):
        metadata = json.loads(archive.read("metadata.json"))
        self.assertEqual(metadata["sources"][revision], hashes)
        for path, digest in hashes.items():
            self.assertEqual(hashlib.sha256(archive.read(f"sources/{revision}/{path}")).hexdigest(), digest)

    def test_actual_approved_families_and_frozen_policy(self):
        historical_path = PACKAGE / "tests/fixtures/trusted-contract-families.zip"
        self.assertEqual(hashlib.sha256(historical_path.read_bytes()).hexdigest(), HISTORICAL_ARCHIVE_SHA256)
        with zipfile.ZipFile(historical_path) as archive:
            historical = json.loads(archive.read("metadata.json"))
        with zipfile.ZipFile(PACKAGE / STOCK_ARCHIVE) as archive:
            stock = json.loads(archive.read("metadata.json"))
        with zipfile.ZipFile(PACKAGE / WATCH_ARCHIVE) as archive:
            watch = json.loads(archive.read("metadata.json"))
        self.assertEqual(stock["families"], [STOCK_FAMILY])
        self.assertEqual(watch["families"], [WATCH_FAMILY])
        self.assertEqual(list(POLICY["FAMILIES"]), historical["families"] + [STOCK_FAMILY, WATCH_FAMILY])
        self.assertEqual(len(historical["families"]), 15)
        self.assertEqual(set(historical["snapshots"]), {
            "legacy", "no-start", "native-start", "native-input-recorded",
            "native-admission", "native-runtime-status", "github-source-readback", "github-source-control",
            "github-watch-control", "github-watch-owner-rpc", "github-pinned-history-read",
            "cloud-guard-baseline-messaging-v2-dispatch", "github-initial-custody",
            "github-initial-plan-material", "github-material-page-parity",
        })
        self.assertEqual(tuple(POLICY["PATHS"]), PATHS)
        self.assertEqual(tuple(POLICY["MESSAGING_V2_PATHS"]), MESSAGING_V2_PATHS)
        for expected in historical["families"] + [STOCK_FAMILY, WATCH_FAMILY]:
            with self.subTest(family=expected["name"]):
                self.blobs = self.approved_snapshot(expected["name"])
                self.reads.clear()
                self.api_reads.clear()
                self.assertEqual(self.verify(), expected["name"])
                self.assertCountEqual(self.reads, [SNAPSHOT + path for path in PATHS])
                self.assertEqual(self.api_reads, [f"git/trees/{HEAD}?recursive=1"])

    def assert_complete_family_authorization(self, name):
        self.blobs = self.approved_snapshot(name)
        self.assertEqual(self.verify(), name)
        previous = tuple(entry for entry in POLICY["FAMILIES"] if entry["name"] != name)
        with self.assertRaisesRegex(ValueError, "contract family not authorized"):
            self.verify(previous)

    def test_material_page_parity_requires_complete_authorization(self):
        self.assert_complete_family_authorization("github-material-page-parity")

    def test_material_page_parity_snapshot_mutation_or_omission_rejected(self):
        self.assert_mutation_or_omission_rejected("github-material-page-parity")

    def test_material_page_parity_all_source_hashes_required(self):
        self.assert_source_hash_mutation_or_omission_rejected("github-material-page-parity")

    def test_material_page_parity_changes_only_fixture_and_manifest_bytes(self):
        name = "github-material-page-parity"
        revision = "5d3c326677bab6cb8ac3115dcbc65e7956676ba9"
        blobs = self.approved_snapshot(name)
        previous = self.approved_snapshot("github-initial-plan-material")
        control = json.loads(blobs[SNAPSHOT + "event-control-v1/manifest.json"])
        baseline = json.loads(previous[SNAPSHOT + "event-control-v1/manifest.json"])
        self.assertEqual(control["revision"], revision)
        self.assertEqual(control["sources"], baseline["sources"])
        self.assertEqual(len(control["sources"]), 57)
        self.assertEqual({key: value for key, value in control.items() if key != "fixturesSha256"},
                         {key: value for key, value in baseline.items() if key != "fixturesSha256"})
        event = json.loads(blobs[SNAPSHOT + "event-v1/manifest.json"])
        self.assertEqual(event["commit"], "7b63bee97395a70e05ffb08ee214e8351f6dda06")
        for path in PATHS:
            with self.subTest(path=path):
                if path.startswith("event-v1/"):
                    self.assertEqual(blobs[SNAPSHOT + path], previous[SNAPSHOT + path])
                else:
                    self.assertNotEqual(blobs[SNAPSHOT + path], previous[SNAPSHOT + path])
        self.assertEqual(hashlib.sha256(blobs[SNAPSHOT + "event-control-v1/fixtures.json"]).hexdigest(),
                         control["fixturesSha256"])
        with zipfile.ZipFile(PACKAGE / "tests/fixtures/trusted-contract-families.zip") as archive:
            metadata = json.loads(archive.read("metadata.json"))
            self.assertEqual(metadata["sources"][revision], control["sources"])
            for path, expected in control["sources"].items():
                self.assertEqual(hashlib.sha256(archive.read(f"sources/{revision}/{path}")).hexdigest(), expected)

    def test_material_page_parity_preserves_all_fourteen_historical_families(self):
        name = "github-material-page-parity"
        with zipfile.ZipFile(PACKAGE / "tests/fixtures/trusted-contract-families.zip") as archive:
            names = archive.namelist()
            self.assertEqual(len(names), 449)
            self.assertEqual(len(set(names)), len(names))
            previous = {path: hashlib.sha256(archive.read(path)).hexdigest() for path in names
                        if path != "metadata.json" and not path.startswith(f"snapshots/{name}/")}
            self.assertEqual(len(previous), 441)
            digest = hashlib.sha256(json.dumps(previous, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.assertEqual(digest, "7050913e01c9ee22535c7155d794f36ddfc427103fda5a808508dcfbb9afcf8e")
            metadata = json.loads(archive.read("metadata.json"))
        self.assertEqual(metadata["families"][-1]["name"], name)
        metadata["families"] = metadata["families"][:-1]
        del metadata["snapshots"][name]
        self.assertEqual(len(metadata["families"]), 14)
        digest = hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest, "40cc24844994321d83bd284854c8ca1829d8714f27c57b5b0e507b75a17a2221")

    def test_initial_plan_material_requires_complete_authorization(self):
        self.assert_complete_family_authorization("github-initial-plan-material")

    def test_initial_plan_material_snapshot_mutation_or_omission_rejected(self):
        self.assert_mutation_or_omission_rejected("github-initial-plan-material")

    def test_initial_plan_material_all_source_hashes_required(self):
        self.assert_source_hash_mutation_or_omission_rejected("github-initial-plan-material")

    def test_initial_plan_material_exact_source_provenance_and_retained_bytes(self):
        name = "github-initial-plan-material"
        revision = "5d3c326677bab6cb8ac3115dcbc65e7956676ba9"
        blobs = self.approved_snapshot(name)
        previous = self.approved_snapshot("github-initial-custody")
        control = json.loads(blobs[SNAPSHOT + "event-control-v1/manifest.json"])
        baseline = json.loads(previous[SNAPSHOT + "event-control-v1/manifest.json"])
        additional = {"apps/os/packages/event-runtime/src/github/" + path for path in
                      ("reconciliation-planner.ts", "initial-plan-material-read.ts")}
        self.assertEqual(len(control["sources"]), 57)
        self.assertEqual(set(control["sources"]), set(baseline["sources"]) | additional)
        self.assertEqual(control["revision"], revision)
        self.assertEqual(control["zodVersion"], "4.6.5")
        for path in PATHS:
            if path != "event-control-v1/manifest.json":
                self.assertEqual(blobs[SNAPSHOT + path], previous[SNAPSHOT + path])
        with zipfile.ZipFile(PACKAGE / "tests/fixtures/trusted-contract-families.zip") as archive:
            metadata = json.loads(archive.read("metadata.json"))
            self.assertEqual(metadata["snapshots"][name], "prepared-export:" + revision)
            sources = {path: archive.read(f"sources/{revision}/{path}") for path in control["sources"]}
            self.assert_archived_sources(archive, revision, control["sources"])
        # Bind changed new source bytes to the manifest before testing trusted policy rejection.
        for path in additional:
            with self.subTest(source=path):
                candidate = json.loads(blobs[SNAPSHOT + "event-control-v1/manifest.json"])
                candidate["sources"][path] = hashlib.sha256(sources[path] + b"\n").hexdigest()
                self.blobs = blobs.copy()
                self.blobs[SNAPSHOT + "event-control-v1/manifest.json"] = (json.dumps(candidate, indent=2) + "\n").encode()
                with self.assertRaisesRegex(ValueError, "contract family not authorized"):
                    self.verify()

    def test_initial_plan_material_preserves_all_thirteen_historical_families(self):
        name = "github-initial-plan-material"
        revision = "5d3c326677bab6cb8ac3115dcbc65e7956676ba9"
        with zipfile.ZipFile(PACKAGE / "tests/fixtures/trusted-contract-families.zip") as archive:
            names = [path for path in archive.namelist()
                     if not path.startswith("snapshots/github-material-page-parity/")]
            self.assertEqual(len(names), 442)
            self.assertEqual(len(set(names)), len(names))
            previous = {path: hashlib.sha256(archive.read(path)).hexdigest() for path in names
                        if path != "metadata.json" and not path.startswith(f"snapshots/{name}/")
                        and not path.startswith(f"sources/{revision}/")}
            self.assertEqual(len(previous), 377)
            digest = hashlib.sha256(json.dumps(previous, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.assertEqual(digest, "89f1ee386be8e8fd67dfe44726f98d6c16d93359dc81e5cfd18144da58b6aa20")
            metadata = json.loads(archive.read("metadata.json"))
        metadata["families"] = [entry for entry in metadata["families"]
                                if entry["name"] != "github-material-page-parity"]
        metadata["snapshots"].pop("github-material-page-parity", None)
        self.assertEqual(metadata["families"][-1]["name"], name)
        metadata["families"] = metadata["families"][:-1]
        del metadata["snapshots"][name]
        del metadata["sources"][revision]
        self.assertEqual(len(metadata["families"]), 13)
        digest = hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest, "a615fb4ff1840b533773b9a3ae9e5ddd5ff7edf65352bdd87030a59a1d9da24e")

    def test_initial_custody_requires_complete_authorization(self):
        name = "github-initial-custody"
        self.blobs = self.approved_snapshot(name)
        self.assertEqual(self.verify(), name)
        previous = tuple(entry for entry in POLICY["FAMILIES"] if entry["name"] != name)
        with self.assertRaisesRegex(ValueError, "contract family not authorized"):
            self.verify(previous)

    def test_initial_custody_snapshot_mutation_or_omission_rejected(self):
        self.assert_mutation_or_omission_rejected("github-initial-custody")

    def test_initial_custody_source_hash_mutation_or_omission_rejected(self):
        self.assert_source_hash_mutation_or_omission_rejected("github-initial-custody")

    def test_initial_custody_exact_source_provenance_and_retained_event_bytes(self):
        name = "github-initial-custody"
        revision = "3ad64222999bc2aaa60f50623120e302edc5f8bd"
        event_revision = "7b63bee97395a70e05ffb08ee214e8351f6dda06"
        blobs = self.approved_snapshot(name)
        previous = self.approved_snapshot("cloud-guard-baseline-messaging-v2-dispatch")
        control = json.loads(blobs[SNAPSHOT + "event-control-v1/manifest.json"])
        event = json.loads(blobs[SNAPSHOT + "event-v1/manifest.json"])
        baseline = json.loads(previous[SNAPSHOT + "event-control-v1/manifest.json"])
        additional = {
            'github/conversion-manifest-store.ts',
            'github/conversion-planning.ts',
            'github/initial-conversion.ts',
            'github/initial-watch-host-store.ts',
            'github/initial-watch-preparation.ts',
            'github/material-cache.ts',
            'github/material-delete.ts',
            'github/material-read-contract.ts',
            'github/material-read.ts',
            'github/reconciliation-internal.ts',
            'github/reconciliation-store.ts',
            'github/source-reference-contract.ts',
            'github/source-reference-store.ts',
            'quarantine-inventory.ts',
            'quarantine-inventory-contract.ts',
            'quarantine-inventory-validation.ts',
        }
        expected_paths = set(baseline["sources"]) | {
            "apps/os/packages/event-runtime/src/" + path for path in additional}
        self.assertEqual(len(baseline["sources"]), 39)
        self.assertEqual(len(expected_paths), 55)
        self.assertEqual(set(control["sources"]), expected_paths)
        self.assertEqual(control["revision"], revision)
        self.assertEqual(control["zodVersion"], "4.6.5")
        self.assertEqual(event["commit"], event_revision)
        for path in PATHS:
            if path != "event-control-v1/manifest.json":
                self.assertEqual(blobs[SNAPSHOT + path], previous[SNAPSHOT + path])
        with zipfile.ZipFile(PACKAGE / "tests/fixtures/trusted-contract-families.zip") as archive:
            metadata = json.loads(archive.read("metadata.json"))
            self.assertEqual(metadata["snapshots"][name], "prepared-export:" + revision)
            self.assert_archived_sources(archive, revision, control["sources"])
            # This historical revision is a 41-source union; retain it and verify
            # the four event entries as a subset, not as a replacement source map.
            self.assertEqual(len(metadata["sources"][event_revision]), 41)
            self.assertEqual(len(event["files"]), 4)
            for entry in event["files"]:
                path = entry["originalPath"]
                self.assertEqual(metadata["sources"][event_revision][path], entry["sha256"])
                source = archive.read(f"sources/{event_revision}/{path}")
                self.assertEqual(hashlib.sha256(source).hexdigest(), entry["sha256"])
                self.assertEqual(blobs[SNAPSHOT + "event-v1/" + entry["file"]], source)
        self.assertEqual(hashlib.sha256(blobs[SNAPSHOT + "event-control-v1/fixtures.json"]).hexdigest(),
                         control["fixturesSha256"])

    def test_initial_custody_preserves_all_historical_archive_payloads_and_metadata(self):
        name = "github-initial-custody"
        revision = "3ad64222999bc2aaa60f50623120e302edc5f8bd"
        with zipfile.ZipFile(PACKAGE / "tests/fixtures/trusted-contract-families.zip") as archive:
            names = [path for path in archive.namelist()
                     if not path.startswith("snapshots/github-material-page-parity/")]
            names = [path for path in names
                     if not path.startswith("snapshots/github-initial-plan-material/")
                     and not path.startswith("sources/5d3c326677bab6cb8ac3115dcbc65e7956676ba9/")]
            self.assertEqual(len(names), 378)
            self.assertEqual(len(set(names)), len(names))
            previous = {path: hashlib.sha256(archive.read(path)).hexdigest() for path in names
                        if path != "metadata.json" and not path.startswith(f"snapshots/{name}/")
                        and not path.startswith(f"sources/{revision}/")}
            self.assertEqual(len(previous), 315)
            digest = hashlib.sha256(json.dumps(previous, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.assertEqual(digest, "519d70205b0741bf8e8db2b97bba0f2f1b88f3acc0b491a596208e6f7b0dd1e4")
            metadata = json.loads(archive.read("metadata.json"))
        metadata["families"] = [entry for entry in metadata["families"]
                                if entry["name"] != "github-material-page-parity"]
        metadata["snapshots"].pop("github-material-page-parity", None)
        metadata["families"] = [entry for entry in metadata["families"]
                                if entry["name"] != "github-initial-plan-material"]
        del metadata["snapshots"]["github-initial-plan-material"]
        del metadata["sources"]["5d3c326677bab6cb8ac3115dcbc65e7956676ba9"]
        self.assertEqual(metadata["families"][-1]["name"], name)
        metadata["families"] = metadata["families"][:-1]
        del metadata["snapshots"][name]
        del metadata["sources"][revision]
        self.assertEqual(len(metadata["families"]), 12)
        digest = hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest, "678cd6587803547f685115676d9bcd9c1b58b3f7d50f3d8b6e34842960427980")

    def test_initial_custody_semantic_corpus_and_self_rehashed_mutation(self):
        name = "github-initial-custody"
        blobs = self.approved_snapshot(name)
        path = SNAPSHOT + "event-v1/protocol-v1.json"
        fixture = json.loads(blobs[path])
        self.assert_semantic_corpus(blobs)
        fixture["semanticVectors"]["rawCases"][0]["expectedError"] = "invalid_schema"
        self.blobs = blobs.copy()
        self.blobs[path] = (json.dumps(fixture, indent=2) + "\n").encode()
        manifest_path = SNAPSHOT + "event-v1/manifest.json"
        manifest = json.loads(blobs[manifest_path])
        for entry in manifest["files"]:
            if entry["file"] == "protocol-v1.json":
                entry["sha256"] = hashlib.sha256(self.blobs[path]).hexdigest()
        self.blobs[manifest_path] = (json.dumps(manifest, indent=2) + "\n").encode()
        with self.assertRaisesRegex(ValueError, "contract family not authorized"):
            self.verify()

    def test_guard_baseline_requires_complete_authorization(self):
        name = "cloud-guard-baseline-messaging-v2-dispatch"
        self.blobs = self.approved_snapshot(name)
        self.assertEqual(self.verify(), name)
        historical = tuple(family for family in POLICY["FAMILIES"] if family["name"] != name)
        with self.assertRaisesRegex(ValueError, "contract family not authorized"):
            self.verify(historical)

    def test_guard_baseline_mutation_or_omission_rejected(self):
        self.assert_mutation_or_omission_rejected("cloud-guard-baseline-messaging-v2-dispatch")

    def test_guard_baseline_source_hash_mutation_or_omission_rejected(self):
        self.assert_source_hash_mutation_or_omission_rejected("cloud-guard-baseline-messaging-v2-dispatch")

    def test_guard_baseline_immutable_source_provenance(self):
        name = "cloud-guard-baseline-messaging-v2-dispatch"
        revision = "7b63bee97395a70e05ffb08ee214e8351f6dda06"
        blobs = self.approved_snapshot(name)
        control = json.loads(blobs[SNAPSHOT + "event-control-v1/manifest.json"])
        event = json.loads(blobs[SNAPSHOT + "event-v1/manifest.json"])
        self.assertEqual(control["revision"], revision)
        self.assertEqual(event["commit"], revision)
        self.assertEqual(len(control["sources"]), 39)
        for path in ("github/host-storage-version.ts", "messaging/protocol-v2.ts"):
            self.assertIn("apps/os/packages/event-runtime/src/" + path, control["sources"])
        expected = dict(control["sources"])
        for entry in event["files"]:
            path = entry["originalPath"]
            if path in expected:
                self.assertEqual(expected[path], entry["sha256"])
            expected[path] = entry["sha256"]
        with zipfile.ZipFile(PACKAGE / "tests/fixtures/trusted-contract-families.zip") as archive:
            metadata = json.loads(archive.read("metadata.json"))
            self.assertEqual(metadata["sources"][revision], expected)
            for path, digest in expected.items():
                source = archive.read(f"sources/{revision}/{path}")
                self.assertEqual(hashlib.sha256(source).hexdigest(), digest)
            for entry in event["files"]:
                self.assertEqual(blobs[SNAPSHOT + "event-v1/" + entry["file"]],
                                 archive.read(f"sources/{revision}/{entry['originalPath']}"))
        self.assertEqual(hashlib.sha256(blobs[SNAPSHOT + "event-control-v1/fixtures.json"]).hexdigest(),
                         control["fixturesSha256"])

    def test_native_admission_mutation_or_omission_rejected_for_all_required_blobs(self):
        self.assert_mutation_or_omission_rejected("native-admission")

    def test_native_runtime_status_mutation_or_omission_rejected_for_all_required_blobs(self):
        self.assert_mutation_or_omission_rejected("native-runtime-status")

    def test_github_source_readback_mutation_or_omission_rejected_for_all_required_blobs(self):
        self.assert_mutation_or_omission_rejected("github-source-readback")

    def test_github_source_readback_accepted_with_all_authorized_hashes(self):
        self.blobs = self.approved_snapshot("github-source-readback")
        self.assertEqual(self.verify(), "github-source-readback")

    def assert_mutation_or_omission_rejected(self, name):
        # PATHS explicitly includes both control fixtures.json and manifest.json.
        original = self.approved_snapshot(name)
        for path in PATHS:
            for missing in (False, True):
                with self.subTest(path=path, missing=missing):
                    self.blobs = original.copy()
                    if missing:
                        del self.blobs[SNAPSHOT + path]
                    else:
                        self.blobs[SNAPSHOT + path] += b"unapproved"
                    with self.assertRaises((ValueError, KeyError)):
                        self.verify()

    def test_native_admission_manifest_source_provenance(self):
        self.assert_manifest_source_provenance(
            "native-admission", "038716741534afe804fb75b9eab15dba6ddbee11")

    def test_native_runtime_status_manifest_source_provenance(self):
        self.assert_manifest_source_provenance(
            "native-runtime-status", "7675f40a4053795de03458c2741da4e3a475ce29",
            ("native-runtime-store", "native-admission-gate"))

    def test_github_source_readback_manifest_source_provenance(self):
        self.assert_manifest_source_provenance(
            "github-source-readback", "7d738a387cdbaab795e1538a240c1b85b6b7a0f7",
            ("native-runtime-store", "native-admission-gate", "github/readback-contract",
             "read-authority", "request-deadline", "github/host", "github/controller",
             "github/client", "github/grants", "github/state", "github/ingress"),
            ("apps/os/packages/gatekeeper-memory/src/principals.ts",
             "apps/os/packages/openapi-operator/src/access.ts",
             "apps/os/packages/gatekeeper-messaging/src/agent-token.ts"))

    def test_github_source_control_mutation_or_omission_rejected(self):
        self.assert_mutation_or_omission_rejected("github-source-control")

    def test_github_source_control_manifest_source_provenance(self):
        self.assert_manifest_source_provenance(
            "github-source-control", "c25ade9233013d97d56ed0fdfddf75453071066b",
            ("native-runtime-store", "native-admission-gate", "github/readback-contract",
             "read-authority", "request-deadline", "github/host", "github/controller",
             "github/client", "github/grants", "github/state", "github/ingress",
             "github/source-control", "github/watches", "manual-canary", "manual-canary-scope",
             "native-admission-canary", "admin-api", "admin-types"),
            ("apps/os/packages/gatekeeper-memory/src/principals.ts",
             "apps/os/packages/openapi-operator/src/access.ts",
             "apps/os/packages/gatekeeper-messaging/src/agent-token.ts",
             "apps/os/packages/gatekeeper-memory/src/auth.ts",
             "apps/os/packages/gatekeeper-memory/src/admin-security.ts"))
        control = json.loads(self.approved_snapshot("github-source-control")[
            SNAPSHOT + "event-control-v1/manifest.json"])
        self.assertEqual(len(control["sources"]), 32)
        self.assertEqual(control["zodVersion"], "4.6.5")

    def test_github_watch_control_accepted_with_all_authorized_hashes(self):
        self.blobs = self.approved_snapshot("github-watch-control")
        self.assertEqual(self.verify(), "github-watch-control")

    def test_github_watch_control_requires_its_complete_authorization(self):
        self.blobs = self.approved_snapshot("github-watch-control")
        legacy = tuple(entry for entry in POLICY["FAMILIES"] if entry["name"] != "github-watch-control")
        with self.assertRaisesRegex(ValueError, "contract family not authorized"):
            self.verify(legacy)

    def test_github_watch_control_mutation_or_omission_rejected(self):
        self.assert_mutation_or_omission_rejected("github-watch-control")

    def test_github_watch_control_manifest_source_provenance(self):
        self.assert_manifest_source_provenance(
            "github-watch-control", "ccdb861eb9126ccd8319d50da5cd6689f91435dd",
            ("native-runtime-store", "native-admission-gate", "github/readback-contract",
             "read-authority", "request-deadline", "github/host", "github/controller",
             "github/client", "github/grants", "github/state", "github/ingress",
             "github/source-control", "github/watches", "github/watch-store", "github/watch-control-internal",
             "manual-canary", "manual-canary-scope",
             "native-admission-canary", "admin-api", "admin-types"),
            ("apps/os/packages/gatekeeper-memory/src/principals.ts",
             "apps/os/packages/openapi-operator/src/access.ts",
             "apps/os/packages/gatekeeper-messaging/src/agent-token.ts",
             "apps/os/packages/gatekeeper-memory/src/auth.ts",
             "apps/os/packages/gatekeeper-memory/src/admin-security.ts"))
        control = json.loads(self.approved_snapshot("github-watch-control")[
            SNAPSHOT + "event-control-v1/manifest.json"])
        self.assertEqual(len(control["sources"]), 34)
        self.assertEqual(control["zodVersion"], "4.6.5")

    def test_github_watch_owner_rpc_accepted_with_all_authorized_hashes(self):
        self.blobs = self.approved_snapshot("github-watch-owner-rpc")
        self.assertEqual(self.verify(), "github-watch-owner-rpc")

    def test_github_watch_owner_rpc_requires_its_complete_authorization(self):
        self.blobs = self.approved_snapshot("github-watch-owner-rpc")
        legacy = tuple(entry for entry in POLICY["FAMILIES"] if entry["name"] != "github-watch-owner-rpc")
        with self.assertRaisesRegex(ValueError, "contract family not authorized"):
            self.verify(legacy)

    def test_github_watch_owner_rpc_mutation_or_omission_rejected(self):
        self.assert_mutation_or_omission_rejected("github-watch-owner-rpc")

    def test_github_watch_owner_rpc_manifest_source_provenance(self):
        self.assert_manifest_source_provenance(
            "github-watch-owner-rpc", "b152b1b92fec860354cacd406b0d72274a97713c",
            ("native-runtime-store", "native-admission-gate", "github/readback-contract",
             "read-authority", "request-deadline", "github/host", "github/controller",
             "github/client", "github/grants", "github/state", "github/ingress",
             "github/source-control", "github/watches", "github/watch-store", "github/watch-control-internal",
             "github/watch-kernel", "github/watch-owner-proof",
             "manual-canary", "manual-canary-scope",
             "native-admission-canary", "admin-api", "admin-types"),
            ("apps/os/packages/gatekeeper-memory/src/principals.ts",
             "apps/os/packages/openapi-operator/src/access.ts",
             "apps/os/packages/gatekeeper-messaging/src/agent-token.ts",
             "apps/os/packages/gatekeeper-memory/src/auth.ts",
             "apps/os/packages/gatekeeper-memory/src/admin-security.ts"),
            event_revision="59940bde10db5584247c8648c985f246f546226f")
        control = json.loads(self.approved_snapshot("github-watch-owner-rpc")[
            SNAPSHOT + "event-control-v1/manifest.json"])
        self.assertEqual(len(control["sources"]), 36)
        self.assertEqual(control["zodVersion"], "4.6.5")

    def test_github_watch_owner_rpc_rejects_changed_or_omitted_source_hashes(self):
        self.assert_source_hash_mutation_or_omission_rejected("github-watch-owner-rpc")

    def test_github_pinned_history_read_accepted_with_all_authorized_hashes(self):
        self.blobs = self.approved_snapshot("github-pinned-history-read")
        self.assertEqual(self.verify(), "github-pinned-history-read")

    def test_github_pinned_history_read_requires_its_complete_authorization(self):
        self.blobs = self.approved_snapshot("github-pinned-history-read")
        legacy = tuple(entry for entry in POLICY["FAMILIES"] if entry["name"] != "github-pinned-history-read")
        with self.assertRaisesRegex(ValueError, "contract family not authorized"):
            self.verify(legacy)

    def test_github_pinned_history_read_mutation_or_omission_rejected(self):
        self.assert_mutation_or_omission_rejected("github-pinned-history-read")

    def test_github_pinned_history_read_manifest_source_provenance(self):
        self.assert_manifest_source_provenance(
            "github-pinned-history-read", "49122dd4ac2a358d87e8cd727fd8e817ae183dac",
            ("native-runtime-store", "native-admission-gate", "github/readback-contract",
             "read-authority", "request-deadline", "github/host", "github/controller",
             "github/client", "github/pinned-read-contract", "github/grants", "github/state", "github/ingress",
             "github/source-control", "github/watches", "github/watch-store", "github/watch-control-internal",
             "github/watch-kernel", "github/watch-owner-proof",
             "manual-canary", "manual-canary-scope",
             "native-admission-canary", "admin-api", "admin-types"),
            ("apps/os/packages/gatekeeper-memory/src/principals.ts",
             "apps/os/packages/openapi-operator/src/access.ts",
             "apps/os/packages/gatekeeper-messaging/src/agent-token.ts",
             "apps/os/packages/gatekeeper-memory/src/auth.ts",
             "apps/os/packages/gatekeeper-memory/src/admin-security.ts"),
            event_revision="59940bde10db5584247c8648c985f246f546226f")
        control = json.loads(self.approved_snapshot("github-pinned-history-read")[
            SNAPSHOT + "event-control-v1/manifest.json"])
        self.assertEqual(len(control["sources"]), 37)
        self.assertEqual(control["zodVersion"], "4.6.5")

    def test_github_pinned_history_read_rejects_changed_or_omitted_source_hashes(self):
        self.assert_source_hash_mutation_or_omission_rejected("github-pinned-history-read")

    def test_github_pinned_history_read_preserves_event_and_control_dto_bytes(self):
        previous = self.approved_snapshot("github-watch-owner-rpc")
        current = self.approved_snapshot("github-pinned-history-read")
        for path in PATHS:
            if path != "event-control-v1/manifest.json":
                with self.subTest(path=path):
                    self.assertEqual(current[SNAPSHOT + path], previous[SNAPSHOT + path])

    def test_github_watch_owner_rpc_semantic_corpus(self):
        self.assert_semantic_corpus(self.approved_snapshot("github-watch-owner-rpc"))

    def assert_semantic_corpus(self, blobs):
        vectors = json.loads(blobs[SNAPSHOT + "event-v1/protocol-v1.json"])["semanticVectors"]
        self.assertEqual(sum(len(vectors[key]) for key in
                             ("rawCases", "digestCases", "bindingCases")), 45)
        check = runpy.run_path(str(PACKAGE / "scripts/check_semantic_vectors.py"))["check"]
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "semantic.json"
            corpus.write_text(json.dumps(vectors))
            with redirect_stdout(io.StringIO()) as output:
                check(corpus)
        self.assertEqual(output.getvalue().strip(), "PASS: 45 canonical semantic verdicts")

    def test_github_watch_owner_rpc_rejects_self_rehashed_semantic_verdict(self):
        self.blobs = self.approved_snapshot("github-watch-owner-rpc")
        path = SNAPSHOT + "event-v1/protocol-v1.json"
        fixture = json.loads(self.blobs[path])
        fixture["semanticVectors"]["rawCases"][0]["expectedError"] = "invalid_schema"
        self.blobs[path] = (json.dumps(fixture, indent=2) + "\n").encode()
        manifest_path = SNAPSHOT + "event-v1/manifest.json"
        manifest = json.loads(self.blobs[manifest_path])
        for entry in manifest["files"]:
            if entry["file"] == "protocol-v1.json":
                entry["sha256"] = hashlib.sha256(self.blobs[path]).hexdigest()
        self.blobs[manifest_path] = (json.dumps(manifest, indent=2) + "\n").encode()
        with self.assertRaisesRegex(ValueError, "contract family not authorized"):
            self.verify()

    def test_github_source_control_rejects_changed_or_omitted_source_hashes(self):
        self.assert_source_hash_mutation_or_omission_rejected("github-source-control")

    def test_github_watch_control_rejects_changed_or_omitted_source_hashes(self):
        self.assert_source_hash_mutation_or_omission_rejected("github-watch-control")

    def assert_source_hash_mutation_or_omission_rejected(self, name):
        original = self.approved_snapshot(name)
        path = SNAPSHOT + "event-control-v1/manifest.json"
        for source in json.loads(original[path])["sources"]:
            for missing in (False, True):
                with self.subTest(source=source, missing=missing):
                    manifest = json.loads(original[path])
                    if missing:
                        del manifest["sources"][source]
                    else:
                        manifest["sources"][source] = "0" * 64
                    self.blobs = original.copy()
                    self.blobs[path] = (json.dumps(manifest, indent=2) + "\n").encode()
                    with self.assertRaises(ValueError):
                        self.verify()

    def assert_manifest_source_provenance(
            self, name, control_revision, additional_sources=(), external_sources=(),
            event_revision="ed23882eac491e26e070e3ef26cf8c0e9e702b38"):
        # This proves fixture provenance separately from the verifier's raw snapshot hash gate.
        blobs = self.approved_snapshot(name)
        event = json.loads(blobs[SNAPSHOT + "event-v1/manifest.json"])
        control = json.loads(blobs[SNAPSHOT + "event-control-v1/manifest.json"])
        self.assertEqual(event["commit"], event_revision)
        self.assertEqual(control["revision"], control_revision)
        source_root = "apps/os/packages/event-runtime/"
        event_paths = {source_root + path for path in (
            "src/protocol.schema.json", "src/protocol.ts", "src/policy.ts",
            "__tests__/fixtures/protocol-v1.json",
        )}
        control_paths = {source_root + "src/" + source + ".ts" for source in (
            "contracts", "api", "registry", "coordinator", "coordinator-admission",
            "authority-client", "protocol", "policy", "native-admission-contract",
        ) + additional_sources} | set(external_sources)
        self.assertEqual({entry["originalPath"] for entry in event["files"]}, event_paths)
        self.assertEqual(len(event["files"]), len(event_paths))
        self.assertEqual(set(control["sources"]), control_paths)
        with zipfile.ZipFile(PACKAGE / "tests/fixtures/trusted-contract-families.zip") as archive:
            metadata = json.loads(archive.read("metadata.json"))
            event_hashes = {entry["originalPath"]: entry["sha256"] for entry in event["files"]}
            for revision, hashes in ((event["commit"], event_hashes),
                                     (control["revision"], control["sources"])):
                self.assertEqual(metadata["sources"][revision], hashes)
                for path, expected in hashes.items():
                    with self.subTest(revision=revision, source=path):
                        source = archive.read(f"sources/{revision}/{path}")
                        self.assertEqual(hashlib.sha256(source).hexdigest(), expected)
            for entry in event["files"]:
                source = archive.read(f"sources/{event['commit']}/{entry['originalPath']}")
                self.assertEqual(blobs[SNAPSHOT + "event-v1/" + entry["file"]], source)
        self.assertEqual(hashlib.sha256(blobs[SNAPSHOT + "event-control-v1/fixtures.json"]).hexdigest(),
                         control["fixturesSha256"])

    def test_stock_family_requires_complete_authorization(self):
        self.assert_complete_family_authorization(STOCK_NAME)

    def test_stock_family_every_snapshot_mutation_or_omission_is_rejected(self):
        self.assert_mutation_or_omission_rejected(STOCK_NAME)

    def _stock_source_maps(self, blobs):
        event = json.loads(blobs[SNAPSHOT + "event-v1/manifest.json"])
        control = json.loads(blobs[SNAPSHOT + "event-control-v1/manifest.json"])
        event_entries = {entry["originalPath"]: entry for entry in event["files"]}
        control_sources = control["sources"]
        self.assertEqual(event["commit"], STOCK_REVISION)
        self.assertEqual(control["revision"], STOCK_REVISION)
        self.assertEqual(len(event_entries), 4)
        overlap = set(event_entries) & set(control_sources)
        self.assertEqual(len(overlap), 2)
        merged = dict(control_sources)
        for path, entry in event_entries.items():
            if path in merged:
                self.assertEqual(merged[path], entry["sha256"], path)
            merged[path] = entry["sha256"]
        return event, control, event_entries, control_sources, merged

    def test_stock_family_all_source_hash_mutations_and_omissions_are_rejected(self):
        original = self.approved_snapshot(STOCK_NAME)
        _event, _control, event_entries, control_sources, merged = self._stock_source_maps(original)
        event_path = SNAPSHOT + "event-v1/manifest.json"
        control_path = SNAPSHOT + "event-control-v1/manifest.json"
        for path, expected_hash in merged.items():
            for missing in (False, True):
                with self.subTest(source=path, missing=missing):
                    event = json.loads(original[event_path])
                    control = json.loads(original[control_path])
                    if path in control_sources:
                        if missing:
                            del control["sources"][path]
                        else:
                            control["sources"][path] = "0" * 64 if expected_hash != "0" * 64 else "1" * 64
                    if path in event_entries:
                        if missing:
                            event["files"] = [entry for entry in event["files"]
                                              if entry["originalPath"] != path]
                        else:
                            for entry in event["files"]:
                                if entry["originalPath"] == path:
                                    entry["sha256"] = "0" * 64 if expected_hash != "0" * 64 else "1" * 64
                    self.blobs = original.copy()
                    self.blobs[event_path] = (json.dumps(event, indent=2) + "\n").encode()
                    self.blobs[control_path] = (json.dumps(control, indent=2) + "\n").encode()
                    with self.assertRaises(ValueError):
                        self.verify()

    def test_stock_family_exact_revisions_overlap_and_archived_source_bytes(self):
        blobs = self.approved_snapshot(STOCK_NAME)
        event, control, event_entries, _control_sources, merged = self._stock_source_maps(blobs)
        self.assertEqual(STOCK_FAMILY["eventRevision"], STOCK_REVISION)
        self.assertEqual(STOCK_FAMILY["controlRevision"], STOCK_REVISION)
        self.assertEqual(event["commit"], control["revision"])
        with zipfile.ZipFile(PACKAGE / STOCK_ARCHIVE) as archive:
            metadata = json.loads(archive.read("metadata.json"))
            self.assertEqual(metadata["families"], [STOCK_FAMILY])
            self.assertEqual(metadata["snapshots"], {STOCK_NAME: "prepared-export:" + STOCK_REVISION})
            self.assert_archived_sources(archive, STOCK_REVISION, merged)
            for path, entry in event_entries.items():
                self.assertEqual(archive.read(f"sources/{STOCK_REVISION}/{path}"),
                                 blobs[SNAPSHOT + "event-v1/" + entry["file"]])
                self.assertEqual(hashlib.sha256(archive.read(f"sources/{STOCK_REVISION}/{path}")).hexdigest(),
                                 entry["sha256"])

    def test_stock_family_archive_sha_and_closed_member_inventory(self):
        blobs = self.approved_snapshot(STOCK_NAME)
        _event, _control, _event_entries, _control_sources, merged = self._stock_source_maps(blobs)
        archive_path = PACKAGE / STOCK_ARCHIVE
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), STOCK_ARCHIVE_SHA256)
        expected = (["metadata.json"]
                    + [f"snapshots/{STOCK_NAME}/{path}" for path in PATHS]
                    + [f"sources/{STOCK_REVISION}/{path}" for path in sorted(merged)])
        with zipfile.ZipFile(archive_path) as archive:
            names = archive.namelist()
            self.assertEqual(len(names), len(expected))
            self.assertEqual(len(set(names)), len(expected))
            self.assertEqual(names, expected)
            for info in archive.infolist():
                self.assertEqual(info.date_time, (2026, 10, 20, 0, 0, 0))

    def test_watch_renewal_family_requires_complete_authorization(self):
        self.assert_complete_family_authorization(WATCH_NAME)

    def test_watch_renewal_family_rejects_each_snapshot_mutation_or_omission(self):
        self.assert_mutation_or_omission_rejected(WATCH_NAME)

    def test_watch_renewal_family_rejects_each_control_source_hash_mutation_or_omission(self):
        self.assert_source_hash_mutation_or_omission_rejected(WATCH_NAME)

    def test_watch_renewal_family_exact_source_provenance_and_closed_archive(self):
        blobs = self.approved_snapshot(WATCH_NAME)
        event = json.loads(blobs[SNAPSHOT + 'event-v1/manifest.json'])
        control = json.loads(blobs[SNAPSHOT + 'event-control-v1/manifest.json'])
        event_sources = {entry['originalPath']: entry['sha256'] for entry in event['files']}
        self.assertEqual((event['commit'], control['revision']),
                         (WATCH_EVENT_REVISION, WATCH_CONTROL_REVISION))
        self.assertEqual(control['zodVersion'], '4.6.5')
        self.assertEqual(len(event_sources), 4)
        self.assertEqual(len(control['sources']), 109)
        self.assertEqual(hashlib.sha256(blobs[SNAPSHOT + 'event-control-v1/fixtures.json']).hexdigest(),
                         control['fixturesSha256'])

        archive_path = PACKAGE / WATCH_ARCHIVE
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), WATCH_ARCHIVE_SHA256)
        with zipfile.ZipFile(archive_path) as archive:
            metadata = json.loads(archive.read('metadata.json'))
            self.assertEqual(metadata['families'], [WATCH_FAMILY])
            self.assertEqual(metadata['snapshots'], {
                WATCH_NAME: 'prepared-export:' + WATCH_CONTROL_REVISION,
            })
            self.assertEqual(set(metadata['sources']), {WATCH_EVENT_REVISION, WATCH_CONTROL_REVISION})
            self.assert_archived_sources(archive, WATCH_EVENT_REVISION, event_sources)
            self.assert_archived_sources(archive, WATCH_CONTROL_REVISION, control['sources'])
            for entry in event['files']:
                self.assertEqual(archive.read(f"sources/{WATCH_EVENT_REVISION}/{entry['originalPath']}"),
                                 blobs[SNAPSHOT + 'event-v1/' + entry['file']])
            expected = (['metadata.json']
                        + [f'snapshots/{WATCH_NAME}/{path}' for path in PATHS]
                        + [f'sources/{WATCH_EVENT_REVISION}/{path}' for path in sorted(event_sources)]
                        + [f'sources/{WATCH_CONTROL_REVISION}/{path}' for path in sorted(control['sources'])])
            names = archive.namelist()
            self.assertEqual(names, expected)
            self.assertEqual(len(names), len(set(names)))
            for info in archive.infolist():
                self.assertEqual(info.date_time, (2026, 11, 7, 0, 0, 0))

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
                before_request=None, v2_profiles=None, during_v2_verification=None):
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
            nonlocal during_verification, during_v2_verification
            self.assertEqual(token, "test-token")
            if path == ".github/workflows/event-gateway-contract.yml":
                self.assertIn(ref, (workflow_sha, main_sha))
                return workflow_source if ref == workflow_sha else self.current_policy
            self.assertIn(ref, heads)
            candidate_reads.append((path, ref))
            if during_verification is not None:
                callback = during_verification
                during_verification = None
                callback()
            if path in {SNAPSHOT + v2_path for v2_path in MESSAGING_V2_PATHS} \
                    and during_v2_verification is not None:
                callback = during_v2_verification
                during_v2_verification = None
                callback()
            return self.blobs[path]

        replacements = {"request_json": request, "read_blob": read}
        if v2_profiles is not None:
            replacements["MESSAGING_V2_PROFILES"] = v2_profiles
        with patch.dict(POLICY, replacements):
            results = POLICY["revalidate"]("test-token", "https://example.test/run", workflow_sha,
                                            event_name, event)
        return results, posts, candidate_reads

    def test_policy_refresh_verifies_every_open_head(self):
        heads = (HEAD, "b" * 40)
        results, posts, reads = self.refresh(heads)
        self.assertEqual(results, [(1, heads[0], "success", "success"),
                                   (2, heads[1], "success", "success")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + head, state) for head in heads
                          for state in ("pending", "pending", "success", "success")])
        self.assertCountEqual(reads, [(SNAPSHOT + path, head) for head in heads
                                      for path in (*PATHS, *MESSAGING_V2_PATHS)])
        for _, payload in posts:
            self.assertIn(payload["context"], ("Event Gateway / trusted contract",
                                                "Event Gateway / Messaging v2 contract"))
            self.assertEqual(payload["target_url"], "https://example.test/run")
        self.assertIn("Active trusted Messaging v2 profile verified: " + ACTIVE_V2_NAME,
                      [payload["description"] for _, payload in posts])

    def test_trusted_messaging_v2_profile_has_distinct_status(self):
        profile = dict(MESSAGING_V2_ADOPTION_FIXTURE, hashes={
            path: hashlib.sha256(self.messaging_v2[SNAPSHOT + path]).hexdigest()
            for path in MESSAGING_V2_PATHS
        })
        results, posts, _ = self.refresh(v2_profiles=(profile,))
        self.assertEqual(results, [(1, HEAD, "success", "success")])
        v2_posts = [payload for _, payload in posts
                    if payload["context"] == "Event Gateway / Messaging v2 contract"]
        self.assertEqual([(payload["state"], payload["description"]) for payload in v2_posts], [
            ("pending", "Checking exact Messaging v2 contract profile"),
            ("success", "Trusted Messaging v2 profile verified: test-only-assigned-stock-profile"),
        ])
        self.assertNotIn("Dormant", " ".join(payload["description"] for payload in v2_posts))

    def test_v1_success_does_not_imply_messaging_v2_success(self):
        self.blobs[SNAPSHOT + MESSAGING_V2_PATHS[0]] += b"unapproved"
        results, posts, _ = self.refresh()
        self.assertEqual(results, [(1, HEAD, "success", "failure")])
        statuses = {payload["context"]: payload["state"] for _, payload in posts
                    if payload["state"] != "pending"}
        self.assertEqual(statuses, {
            "Event Gateway / trusted contract": "success",
            "Event Gateway / Messaging v2 contract": "failure",
        })
        with self.assertRaisesRegex(ValueError, "Messaging v2 contract verification did not succeed"):
            POLICY["require_messaging_v2_success"](results)

    def test_messaging_v2_verifier_error_fails_job(self):
        def unavailable():
            raise OSError("temporary source blob outage")
        results, posts, _ = self.refresh(during_v2_verification=unavailable)
        self.assertEqual(results, [(1, HEAD, "success", "error")])
        v2_final = [payload for _, payload in posts
                    if payload["context"] == "Event Gateway / Messaging v2 contract"
                    and payload["state"] != "pending"]
        self.assertEqual([(payload["state"], payload["description"]) for payload in v2_final], [
            ("error", "Messaging v2 contract could not be fetched; retry verification"),
        ])
        with self.assertRaisesRegex(ValueError, "Messaging v2 contract verification did not succeed"):
            POLICY["require_messaging_v2_success"](results)

    def test_changed_head_during_verification_has_no_final_status(self):
        def advance_head():
            self.current_heads[1] = "b" * 40
        results, posts, reads = self.refresh(during_verification=advance_head)
        self.assertEqual(results, [])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + HEAD, "pending"), ("statuses/" + HEAD, "pending")])
        self.assertEqual(len(reads), len(PATHS) + len(MESSAGING_V2_PATHS))

    def test_changed_policy_during_verification_has_no_final_status(self):
        def advance_policy():
            self.current_policy = b"new trusted workflow bytes"
        results, posts, reads = self.refresh(during_verification=advance_policy)
        self.assertEqual(results, [])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + HEAD, "pending"), ("statuses/" + HEAD, "pending")])
        self.assertEqual(len(reads), len(PATHS) + len(MESSAGING_V2_PATHS))

    def test_unauthorized_bytes_publish_failure_on_exact_head(self):
        self.blobs[SNAPSHOT + "event-control-v1/fixtures.json"] += b"unapproved"
        results, posts, reads = self.refresh()
        self.assertEqual(results, [(1, HEAD, "failure", "success")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + HEAD, "pending"), ("statuses/" + HEAD, "pending"),
                          ("statuses/" + HEAD, "failure"), ("statuses/" + HEAD, "success")])
        self.assertCountEqual(reads, [(SNAPSHOT + path, HEAD) for path in (*PATHS, *MESSAGING_V2_PATHS)])

    def test_candidate_symlink_rejected_despite_canonical_contents(self):
        for entry in self.tree["tree"]:
            if entry["path"] not in {SNAPSHOT + path for path in PATHS}:
                continue
            with self.subTest(path=entry["path"]):
                entry["mode"] = "120000"
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.verify()
                self.assertEqual(self.reads, [])
                entry["mode"] = "100644"

    def test_messaging_v2_symlink_rejected_despite_canonical_contents(self):
        for entry in self.tree["tree"]:
            if entry["path"] not in {SNAPSHOT + path for path in MESSAGING_V2_PATHS}:
                continue
            with self.subTest(path=entry["path"]):
                entry["mode"] = "120000"
                self.reads.clear()
                with self.assertRaisesRegex(ValueError, "not a regular Git blob"):
                    self.verify_messaging_v2()
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
        self.assertEqual(results, [(2, target, "success", "success")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + target, "pending"), ("statuses/" + target, "pending"),
                          ("statuses/" + target, "success"), ("statuses/" + target, "success")])
        self.assertCountEqual(reads, [(SNAPSHOT + path, target) for path in (*PATHS, *MESSAGING_V2_PATHS)])

    def test_pull_target_refreshes_only_candidate_without_listing(self):
        target = "b" * 40
        results, posts, reads = self.refresh(
            (HEAD, target), event_name="pull_request_target",
            event={"pull_request": {"number": 2, "head": {"sha": target}}})
        self.assertEqual(results, [(2, target, "success", "success")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + target, "pending"), ("statuses/" + target, "pending"),
                          ("statuses/" + target, "success"), ("statuses/" + target, "success")])
        self.assertCountEqual(reads, [(SNAPSHOT + path, target) for path in (*PATHS, *MESSAGING_V2_PATHS)])
        self.assertFalse(any(endpoint.startswith("pulls?") for endpoint in self.runner_api_reads))

    def test_transport_failure_publishes_error_on_exact_head(self):
        def unavailable():
            raise OSError("temporary transport outage")
        results, posts, _ = self.refresh(during_verification=unavailable)
        self.assertEqual(results, [(1, HEAD, "error", "success")])
        self.assertEqual([(endpoint, payload["state"]) for endpoint, payload in posts],
                         [("statuses/" + HEAD, "pending"), ("statuses/" + HEAD, "pending"),
                          ("statuses/" + HEAD, "error"), ("statuses/" + HEAD, "success")])

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

                    output = io.StringIO()
                    with redirect_stdout(output), self.assertRaises(
                            (ValueError, KeyError, TypeError, OSError)) as raised:
                        self.refresh((HEAD, later_head), before_request=unavailable)
                    self.assertEqual(
                        [(endpoint, payload["state"]) for endpoint, payload in self.runner_posts
                         if endpoint == "statuses/" + later_head],
                        [("statuses/" + later_head, "pending"), ("statuses/" + later_head, "pending"),
                         ("statuses/" + later_head, "success"), ("statuses/" + later_head, "success")],
                    )
                    self.assertCountEqual(
                        [path for path, head in self.runner_candidate_reads if head == later_head],
                        [SNAPSHOT + path for path in (*PATHS, *MESSAGING_V2_PATHS)],
                    )
                    self.assertEqual(failed_requests, [(failed_endpoint, failed_state)])
                    self.assertIsInstance(raised.exception, OSError)
                    self.assertIn(f"PR #1: {type(failure).__name__}", output.getvalue())
                    self.assertNotIn(str(failure), output.getvalue())
