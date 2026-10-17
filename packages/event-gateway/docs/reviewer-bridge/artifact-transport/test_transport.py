"""Offline transport contracts; the fake request seam never accesses a network."""

import copy
import hashlib
import io
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile
import json

import transport as subject

POLICY = dict(
    repository="knitli/knitli-site",
    repositoryId=1058277548,
    runId="123",
    runAttempt="2",
    workflowSha="711e265cc280cad7c4a44ba6d2d72f40a1378fec",
    sourceHeadSha="d" * 40,
)
HOST = "fixture.invalid"
TOKEN = "private-test-token"
PRODUCER = {
    "completion.json": b"completion",
    "envelope.json": b"envelope",
    "snapshot.json": b"snapshot",
}
SEALED = {
    "reviewer-host-handoff.json": b"handoff",
    "attestation.sigstore.json": b"attestation",
}


def archive(entries, compression=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with (
        warnings.catch_warnings(),
        zipfile.ZipFile(out, "w", compression=compression) as z,
    ):
        warnings.simplefilter("ignore", UserWarning)
        for name, value in entries:
            z.writestr(name, value)
    return out.getvalue()


class Fake:
    def __init__(self):
        """Prepare synthetic metadata and archives without network access."""
        self.calls = []
        self.counts = {}
        self.hook = None
        self.run = dict(
            id=123,
            run_attempt=2,
            repository=dict(
                id=1058277548, full_name=POLICY["repository"], private=True
            ),
            status="completed",
            conclusion="success",
            event="workflow_dispatch",
            head_branch="main",
            head_sha=POLICY["sourceHeadSha"],
            path=subject._CALLER,
            referenced_workflows=[
                dict(
                    path=subject._REUSABLE + "@" + POLICY["workflowSha"],
                    sha=POLICY["workflowSha"],
                )
            ],
        )
        self.blobs = {1: archive(PRODUCER.items()), 2: archive(SEALED.items())}
        self.metadata = [
            self.meta(i, kind) for i, kind in [(1, "producer"), (2, "sealed")]
        ]

    def meta(self, i, kind):
        return dict(
            id=i,
            name=f"reviewer-host-{kind}-123-2",
            expired=False,
            size_in_bytes=len(self.blobs[i]),
            digest="sha256:" + hashlib.sha256(self.blobs[i]).hexdigest(),
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
            expires_at="2099-01-01T00:00:00Z",
            workflow_run=dict(
                id=123,
                repository_id=1058277548,
                head_repository_id=1058277548,
                head_branch="main",
                head_sha=POLICY["sourceHeadSha"],
            ),
        )

    def replace_blob(self, i, data):
        self.blobs[i] = data
        self.metadata[i - 1] = self.meta(i, "producer" if i == 1 else "sealed")

    def __call__(self, url, *, headers, maximum, deadline):
        self.calls.append((url, dict(headers), maximum, deadline))
        self.counts[url] = self.counts.get(url, 0) + 1
        if url.startswith("https://" + HOST + "/"):
            i = int(url.split("/")[3].split("?")[0])
            response = subject.Response(url, 200, {}, self.blobs[i])
        elif url.endswith("/zip"):
            i = int(url.split("/")[-2])
            response = subject.Response(
                url, 302, {"Location": f"https://{HOST}/{i}?signed=private-url"}, b""
            )
        else:
            if "/artifacts?" in url:
                value = dict(total_count=len(self.metadata), artifacts=self.metadata)
            elif "/artifacts/" in url:
                value = self.metadata[int(url.split("/")[-1]) - 1]
            else:
                value = self.run
            response = subject.Response(
                url, 200, {}, json.dumps(copy.deepcopy(value)).encode()
            )
        return self.hook(url, self.counts[url], response) if self.hook else response


def changed(response, value):
    return subject.Response(
        response.url, response.status, response.headers, json.dumps(value).encode()
    )


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve()
        self.hosts = patch.object(subject, "_DOWNLOAD_HOSTS", frozenset({HOST}))
        self.hosts.start()
        self.addCleanup(self.hosts.stop)

    def refused(self, fake, policy=None):
        if policy is None:
            policy = POLICY
        with self.assertRaises(subject.Refused) as caught:
            with subject.transport(policy, TOKEN, fake, self.parent):
                self.fail("unexpected transport publication")
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertNotIn("private-url", str(caught.exception))
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_exact_bytes_authentication_and_context_cleanup(self):
        fake = Fake()
        with subject.transport(POLICY, TOKEN, fake, self.parent) as bundle:
            location = bundle.directory
            self.assertEqual(
                {p.name: p.read_bytes() for p in location.iterdir()}, PRODUCER
            )
            self.assertEqual(bundle.handoff_bytes, SEALED["reviewer-host-handoff.json"])
            self.assertEqual(
                bundle.attestation_bytes, SEALED["attestation.sigstore.json"]
            )
            self.assertEqual(stat.S_IMODE(location.stat().st_mode), 0o700)
            for p in location.iterdir():
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertFalse(location.exists())

    def test_exact_pinned_upload_action_archives(self):
        fixtures = Path(__file__).with_name("fixtures")
        archives = {
            1: ("producer", "34497e87b4aff7c02dc3390510c67e8a96ecfe82d4442382ff587a014de20474"),
            2: ("sealed", "902bbc3da82579a5259c2685d7d4a32442297cb3873401ff28c7c4c90dba6cfc"),
        }
        expected = {
            "completion.json": "5d750355a575dc163b3035738e37768522bc4858d8f43b6b58c7b7a981844a2a",
            "envelope.json": "5c8b9e42274a574697eaa3d33096f9093cacebe9f7764fd843cabcb8bcca5350",
            "snapshot.json": "2c46636cf215777d809118f4526729ce8371d2d43aa1d78452c1be664a62f56c",
        }
        fake = Fake()
        for identity, (kind, digest) in archives.items():
            data = (fixtures / f"{kind}.zip").read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            fake.replace_blob(identity, data)
        with subject.transport(POLICY, TOKEN, fake, self.parent) as bundle:
            location = bundle.directory
            self.assertEqual(
                {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in location.iterdir()},
                expected,
            )
            self.assertEqual(hashlib.sha256(bundle.handoff_bytes).hexdigest(),
                             "e7ea35ecfacbd363949297af4a74b119ae57afa2ab1627ddef0a8f14d046e9e5")
            self.assertEqual(hashlib.sha256(bundle.attestation_bytes).hexdigest(),
                             "370b82c935303b56e3344d1f2990e7a977a5a0c6aa055717ff0d359c2812a201")
        self.assertFalse(location.exists())
        self.assertEqual(list(self.parent.iterdir()), [])
        self.assertEqual(len(fake.calls), 14)
        for url, headers, maximum, deadline in fake.calls:
            self.assertGreater(maximum, 0)
            if url.startswith(subject._API):
                self.assertEqual(headers["Authorization"], "Bearer " + TOKEN)
            else:
                self.assertNotIn("Authorization", headers)
                self.assertNotIn("X-GitHub-Api-Version", headers)
            self.assertEqual(headers["Accept-Encoding"], "identity")

    def test_consumer_exception_cleans_bundle(self):
        with self.assertRaisesRegex(RuntimeError, "consumer"):
            with subject.transport(POLICY, TOKEN, Fake(), self.parent):
                raise RuntimeError("consumer")
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_production_hosts_are_closed(self):
        with patch.object(subject, "_DOWNLOAD_HOSTS", frozenset()):
            self.refused(Fake())

    def test_policy_and_initial_run_refusal(self):
        for key, value in [
            ("repository", "other/repo"),
            ("workflowSha", "f" * 40),
            ("runAttempt", "02"),
        ]:
            with self.subTest(policy=key):
                fake = Fake()
                self.refused(fake, {**POLICY, key: value})
                self.assertEqual(fake.calls, [])
        for key, value in [
            ("run_attempt", 3),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("head_sha", "f" * 40),
        ]:
            with self.subTest(run=key):
                fake = Fake()
                fake.run[key] = value
                self.refused(fake)

    def test_listing_identity_expiry_duplicates_and_short_pagination(self):
        mutations = [
            lambda f: f.metadata[0].update(expired=True),
            lambda f: f.metadata[0].update(expires_at="2020-01-01T00:00:00Z"),
            lambda f: f.metadata[0].update(name="reviewer-host-producer-123-1"),
            lambda f: f.metadata[0]["workflow_run"].update(id=999),
            lambda f: f.metadata.append(copy.deepcopy(f.metadata[0])),
            lambda f: f.metadata.append({**f.metadata[0], "id": 3}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                fake = Fake()
                mutate(fake)
                self.refused(fake)
        fake = Fake()
        fake.hook = lambda url, n, r: (
            changed(r, dict(total_count=101, artifacts=fake.metadata))
            if "/artifacts?" in url
            else r
        )
        self.refused(fake)

    def test_metadata_and_run_fences_after_download(self):
        for point in ("list", "get", "run", "rerun"):
            with self.subTest(point=point):
                fake = Fake()

                def hook(url, n, r):
                    selected = (
                        (point == "list" and "/artifacts?" in url)
                        or (point == "get" and url.endswith("/artifacts/1"))
                        or (point in ("run", "rerun") and url.endswith("/runs/123"))
                    )
                    if selected and n == 2:
                        value = json.loads(r.body)
                        if point == "list":
                            value["artifacts"][0]["updated_at"] = "2026-01-02T00:00:00Z"
                        elif point == "get":
                            value["updated_at"] = "2026-01-02T00:00:00Z"
                        elif point == "rerun":
                            value["run_attempt"] = 3
                        else:
                            value["additional_observation"] = "changed"
                        return changed(r, value)
                    return r

                fake.hook = hook
                self.refused(fake)
                self.assertTrue(
                    any(url.startswith("https://" + HOST) for url, *_ in fake.calls)
                )

    def test_redirect_variants_never_receive_credentials(self):
        variants = [
            f"http://{HOST}/1?q=x",
            f"https://user@{HOST}/1?q=x",
            f"https://{HOST}:443/1?q=x",
            f"https://{HOST}.evil/1?q=x",
            f"https://{HOST}/1",
            f"https://{HOST}/1?q=x#fragment",
            f"https://{HOST}/1?q=x\n",
            f"//{HOST}/1?q=x",
            "https://api.github.com/1?q=x",
        ]
        for location in variants:
            with self.subTest(location=location):
                fake = Fake()
                fake.hook = lambda url, n, r: (
                    subject.Response(url, 302, {"Location": location}, b"")
                    if url.endswith("/zip")
                    else r
                )
                self.refused(fake)
                self.assertTrue(
                    all(url.startswith(subject._API) for url, *_ in fake.calls)
                )

    def test_response_identity_headers_digest_size_and_second_redirect(self):
        for case in (
            "url",
            "status",
            "length",
            "encoding",
            "duplicate_header",
            "digest",
            "oversize",
            "redirect",
        ):
            with self.subTest(case=case):
                fake = Fake()

                def hook(url, n, r):
                    if not url.startswith("https://" + HOST):
                        return r
                    if case == "url":
                        return subject.Response(url + "x", 200, {}, r.body)
                    if case in ("status", "redirect"):
                        return subject.Response(
                            url, 302, {"Location": "https://evil.invalid"}, b""
                        )
                    if case == "length":
                        return subject.Response(
                            url, 200, {"Content-Length": "1"}, r.body
                        )
                    if case == "encoding":
                        return subject.Response(
                            url, 200, {"Content-Encoding": "gzip"}, r.body
                        )
                    if case == "duplicate_header":
                        return subject.Response(
                            url, 200, {"X-A": "a", "x-a": "b"}, r.body
                        )
                    if case == "digest":
                        return subject.Response(
                            url, 200, {}, bytes([r.body[0] ^ 1]) + r.body[1:]
                        )
                    return subject.Response(url, 200, {}, r.body + b"x")

                fake.hook = hook
                self.refused(fake)

    def test_timeout_and_seam_error_are_sanitized(self):
        def fail(*args, **kwargs):
            raise TimeoutError(TOKEN + " private-url")

        self.refused(fail)
        fake = Fake()
        with patch.object(subject.time, "monotonic", side_effect=[0, 0, 61]):
            self.refused(fake)

    def test_zip_boundaries_through_actual_transport(self):
        def rename(name):
            return archive(
                [(name, b"x"), ("envelope.json", b"e"), ("snapshot.json", b"s")]
            )

        symlink = zipfile.ZipInfo("completion.json")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        corrupt = bytearray(archive(PRODUCER.items()))
        corrupt[30 + len("completion.json")] ^= 1
        cases = {
            "traversal": rename("../completion.json"),
            "absolute": rename("/completion.json"),
            "backslash": rename("..\\completion.json"),
            "symlink": archive(
                [(symlink, b"target"), ("envelope.json", b"e"), ("snapshot.json", b"s")]
            ),
            "duplicate": archive(
                [
                    ("completion.json", b"a"),
                    ("completion.json", b"b"),
                    ("snapshot.json", b"s"),
                ]
            ),
            "missing": archive([("completion.json", b"a"), ("envelope.json", b"e")]),
            "extra": archive([*PRODUCER.items(), ("extra.json", b"x")]),
            "crc": bytes(corrupt),
            "truncated": archive(PRODUCER.items())[:-1],
            "bomb": archive(
                [
                    ("completion.json", b"x" * 65537),
                    ("envelope.json", b"e"),
                    ("snapshot.json", b"s"),
                ],
                zipfile.ZIP_DEFLATED,
            ),
            "total": archive(
                [(name, b"x" * 65536) for name in PRODUCER], zipfile.ZIP_DEFLATED
            ),
            "empty": archive(
                [
                    ("completion.json", b""),
                    ("envelope.json", b"e"),
                    ("snapshot.json", b"s"),
                ]
            ),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                fake = Fake()
                fake.replace_blob(1, data)
                self.refused(fake)
        fake = Fake()
        fake.replace_blob(
            2,
            archive(
                [
                    ("reviewer-host-handoff.json", b"x" * 4097),
                    ("attestation.sigstore.json", b"a"),
                ]
            ),
        )
        self.refused(fake)

    def test_complete_pagination_and_changing_totals(self):
        for drift in (False, True):
            with self.subTest(drift=drift):
                fake = Fake()
                items = fake.metadata + [
                    dict(id=i, name="unrelated") for i in range(3, 102)
                ]

                def hook(url, n, r):
                    if "/artifacts?" not in url:
                        return r
                    page = int(url.rsplit("=", 1)[1])
                    return changed(
                        r,
                        dict(
                            total_count=102 if drift and page == 2 else 101,
                            artifacts=items[(page - 1) * 100 : page * 100],
                        ),
                    )

                fake.hook = hook
                if drift:
                    self.refused(fake)
                else:
                    with subject.transport(POLICY, TOKEN, fake, self.parent) as bundle:
                        self.assertEqual(bundle.handoff_bytes, b"handoff")
                    self.assertEqual(
                        sum("/artifacts?" in url for url, *_ in fake.calls), 4
                    )

    def test_streamed_zip_data_descriptors_supported(self):
        class Unseekable(io.BytesIO):
            def seek(self, *args):
                raise io.UnsupportedOperation("stream")

        buffer = Unseekable()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for name, value in PRODUCER.items():
                z.writestr(name, value)
        fake = Fake()
        fake.replace_blob(1, buffer.getvalue())
        with subject.transport(POLICY, TOKEN, fake, self.parent) as bundle:
            self.assertEqual(
                (bundle.directory / "completion.json").read_bytes(), b"completion"
            )

    def test_final_expiry_fence_and_cleanup(self):
        fake = Fake()
        clock = [1800000000.0]

        def hook(url, n, response):
            if url.endswith("/runs/123") and n == 2:
                clock[0] = (
                    4102444801.0  # After the metadata expiry, at final run reread.
                )
            return response

        fake.hook = hook
        with patch.object(subject.time, "time", side_effect=lambda: clock[0]):
            self.refused(fake)
        self.assertEqual(len(fake.calls), 14)

    def test_central_directory_preflight_rejects_hidden_records_and_zip64(self):
        ordinary = archive(PRODUCER.items())
        offset = struct.unpack_from("<L", ordinary, len(ordinary) - 6)[0]
        name_len, extra_len, comment_len = struct.unpack_from(
            "<3H", ordinary, offset + 28
        )
        record = ordinary[offset : offset + 46 + name_len + extra_len + comment_len]
        hidden = bytearray(ordinary[:-22] + record + ordinary[-22:])
        struct.pack_into(
            "<L", hidden, len(hidden) - 10, len(ordinary) - 22 - offset + len(record)
        )
        zip64 = bytearray(ordinary)
        struct.pack_into("<L", zip64, offset + 20, 0xFFFFFFFF)
        for data in (bytes(hidden), bytes(zip64)):
            with self.subTest(kind="hidden" if data == bytes(hidden) else "zip64"):
                fake = Fake()
                fake.replace_blob(1, data)
                self.refused(fake)
        # The count/size guard must reject hidden records before ZipFile allocates them.
        with patch.object(
            subject.zipfile,
            "ZipFile",
            side_effect=AssertionError("allocated before preflight"),
        ):
            with self.assertRaises(subject.Refused):
                subject._unzip(bytes(hidden), subject._PRODUCER, 128 * 1024)

    def test_valid_archive_with_wrong_authenticated_digest_is_refused(self):
        fake = Fake()
        fake.metadata[0]["digest"] = "sha256:" + "0" * 64
        self.refused(fake)

    def test_parent_leaf_permissions_refused_before_network(self):
        for mode in (0o755, 0o750, 0o770, 0o777, 0o1700):
            with self.subTest(mode=oct(mode)):
                self.parent.chmod(mode)
                try:
                    fake = Fake()
                    self.refused(fake)
                    self.assertEqual(fake.calls, [])
                finally:
                    self.parent.chmod(0o700)

    def test_parent_alias_and_symlinked_ancestor_refused(self):
        physical = self.parent / "physical"
        physical.mkdir(mode=0o700)
        leaf = physical / "leaf"
        leaf.mkdir(mode=0o700)
        alias = self.parent / "alias"
        alias.symlink_to(physical, target_is_directory=True)
        for parent in (alias, alias / "leaf"):
            with self.subTest(parent=parent):
                fake = Fake()
                with self.assertRaises(subject.Refused):
                    with subject.transport(POLICY, TOKEN, fake, parent):
                        self.fail("aliased scratch accepted")
                self.assertEqual(fake.calls, [])
                self.assertEqual(list(leaf.iterdir()), [])
        subject._private_parent(leaf)

    def test_writable_ancestors_refused_even_if_sticky(self):
        ancestor = self.parent / "ancestor"
        ancestor.mkdir(mode=0o700)
        leaf = ancestor / "leaf"
        leaf.mkdir(mode=0o700)
        for mode in (0o720, 0o702, 0o777, 0o1777):
            with self.subTest(mode=oct(mode)):
                ancestor.chmod(mode)
                try:
                    fake = Fake()
                    with self.assertRaises(subject.Refused):
                        with subject.transport(POLICY, TOKEN, fake, leaf):
                            self.fail("writable ancestor accepted")
                    self.assertEqual(fake.calls, [])
                    self.assertEqual(list(leaf.iterdir()), [])
                finally:
                    ancestor.chmod(0o700)

    def test_foreign_owner_leaf_and_ancestor_refused(self):
        original = Path.lstat
        for target in (self.parent, self.parent.parent):
            with self.subTest(target=target):

                def foreign(path, *args, **kwargs):
                    info = original(path, *args, **kwargs)
                    if path == target:
                        fields = list(info)
                        fields[4] = os.getuid() + 100001
                        return os.stat_result(fields)
                    return info

                fake = Fake()
                with patch.object(Path, "lstat", foreign):
                    self.refused(fake)
                self.assertEqual(fake.calls, [])

    def test_private_parent_beneath_fixed_system_sticky_root(self):
        system_temp = (
            Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
        )
        system_temp = system_temp.resolve(strict=True)
        info = system_temp.lstat()
        if (
            system_temp not in (Path("/private/tmp"), Path("/tmp"))
            or info.st_uid != 0
            or not info.st_mode & stat.S_ISVTX
        ):
            self.skipTest("system sticky temporary root is unavailable")
        with tempfile.TemporaryDirectory(dir=system_temp) as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            with subject.transport(POLICY, TOKEN, Fake(), parent) as bundle:
                self.assertEqual(bundle.handoff_bytes, b"handoff")
            self.assertEqual(list(parent.iterdir()), [])

    def test_deflated_archives_supported(self):
        fake = Fake()
        fake.replace_blob(1, archive(PRODUCER.items(), zipfile.ZIP_DEFLATED))
        with subject.transport(POLICY, TOKEN, fake, self.parent) as bundle:
            self.assertEqual(
                (bundle.directory / "snapshot.json").read_bytes(),
                PRODUCER["snapshot.json"],
            )


if __name__ == "__main__":
    unittest.main()
