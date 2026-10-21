"""Exercise bounded Store error replies over the private Unix control socket."""
from contextlib import asynccontextmanager, redirect_stdout
import asyncio
import io
import json
from pathlib import Path
import stat
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from event_gateway import cli, daemon
from event_gateway.cloud import CloudError, _iso
from event_gateway.store import Store, StoreError


TEMPORARY_ROOT = Path("/tmp").resolve()  # nosec B108 - private subdirectory with a short Unix socket path


def control_socket_ready(path):
    # The socket appears before the daemon applies its private permissions.
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISSOCK(mode) and stat.S_IMODE(mode) == 0o600


@asynccontextmanager
async def running_daemon(state_dir):
    task = asyncio.create_task(daemon.serve(state_dir))
    socket_path = Path(state_dir) / "control.sock"
    deadline = asyncio.get_running_loop().time() + 3
    try:
        while not control_socket_ready(socket_path):
            if task.done():
                await task
            if asyncio.get_running_loop().time() >= deadline:
                raise AssertionError("daemon did not open its Unix control socket")
            await asyncio.sleep(0.01)
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


class DaemonWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_stock_renewal_uses_only_current_assigned_mapping_and_stops(self):
        mapping = {
            "runtimeId": str(uuid.uuid4()), "principal": "owner@example.com", "agent": "codex",
            "nodeId": str(uuid.uuid4()), "nodeGeneration": 2, "runtimeGeneration": 4,
            "attachmentGeneration": 7, "leaseExpiresAt": time.time() + 90,
            "runtimeProfile": {"profile": "assigned_stock_client", "client": "codex",
                               "conversationId": str(uuid.uuid4())},
        }
        stop = asyncio.Event()

        class FakeStore:
            def __init__(self):
                self.renewed = []

            @staticmethod
            def clock():
                return time.time()

            @staticmethod
            def list_attachments():
                return [mapping, {**mapping, "principal": "other@example.com"},
                        {**mapping, "runtimeId": str(uuid.uuid4()),
                         "runtimeProfile": {"profile": "native"}}]

            def renew_stock_attachment(self, expected, lease):
                self.renewed.append((expected, lease))
                stop.set()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = mapping["nodeId"], mapping["nodeGeneration"]

            def __init__(self):
                self.requests = []

            async def assigned_stock(self, request):
                self.requests.append(request)
                return {"leaseUntil": _iso(time.time() + 90)}

        store, cloud = FakeStore(), FakeCloud()
        with patch.object(daemon, "STOCK_RENEW_INTERVAL", 0.01):
            await asyncio.wait_for(daemon._stock_renewal_worker(store, cloud, stop), 1)
        self.assertEqual(cloud.requests, [{
            "operation": "renew", "runtimeId": mapping["runtimeId"],
            "conversationId": mapping["runtimeProfile"]["conversationId"],
            "expectedRuntimeGeneration": 4, "expectedAttachmentGeneration": 7,
        }])
        self.assertEqual(store.renewed[0][0], mapping)

    async def test_stock_renewal_suspends_mapping_when_local_cas_fails(self):
        mapping = {
            "runtimeId": str(uuid.uuid4()), "principal": "owner@example.com", "agent": "codex",
            "nodeId": str(uuid.uuid4()), "nodeGeneration": 2, "runtimeGeneration": 4,
            "attachmentGeneration": 7, "leaseExpiresAt": time.time() + 90,
            "runtimeProfile": {"profile": "assigned_stock_client", "client": "codex",
                               "conversationId": str(uuid.uuid4())},
        }
        stop = asyncio.Event()

        class FakeStore:
            @staticmethod
            def clock():
                return time.time()

            @staticmethod
            def list_attachments():
                return [mapping]

            @staticmethod
            def renew_stock_attachment(_expected, _lease):
                return False

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = mapping["nodeId"], mapping["nodeGeneration"]
            calls = 0

            async def assigned_stock(self, _request):
                self.calls += 1
                return {"leaseUntil": _iso(time.time() + 180)}

        cloud = FakeCloud()
        asyncio.get_running_loop().call_later(0.01, stop.set)
        with patch.object(daemon, "STOCK_RENEW_INTERVAL", 0.001):
            await asyncio.wait_for(daemon._stock_renewal_worker(FakeStore(), cloud, stop), 1)
        self.assertEqual(cloud.calls, 1)

    async def test_stock_renewal_suspends_definitive_refusal_for_mapping(self):
        mapping = {
            "runtimeId": str(uuid.uuid4()), "principal": "owner@example.com", "agent": "codex",
            "nodeId": str(uuid.uuid4()), "nodeGeneration": 2, "runtimeGeneration": 4,
            "attachmentGeneration": 7, "leaseExpiresAt": time.time() + 90,
            "runtimeProfile": {"profile": "assigned_stock_client", "client": "codex",
                               "conversationId": str(uuid.uuid4())},
        }
        stop = asyncio.Event()
        reads = 0

        class FakeStore:
            @staticmethod
            def clock():
                return time.time()

            def list_attachments(self):
                nonlocal reads
                reads += 1
                if reads >= 3:
                    stop.set()
                return [mapping]

            @staticmethod
            def renew_stock_attachment(*_args):
                raise AssertionError("refused renewal changed local lease")

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = mapping["nodeId"], mapping["nodeGeneration"]
            calls = 0

            async def assigned_stock(self, _request):
                self.calls += 1
                raise CloudError("assigned_stock_disabled")

        cloud = FakeCloud()
        with patch.object(daemon, "STOCK_RENEW_INTERVAL", 0.001):
            await asyncio.wait_for(daemon._stock_renewal_worker(FakeStore(), cloud, stop), 1)
        self.assertEqual(cloud.calls, 1)

    async def test_stock_renewal_prunes_suspension_after_mapping_disappears(self):
        mapping = {
            "runtimeId": str(uuid.uuid4()), "principal": "owner@example.com", "agent": "codex",
            "nodeId": str(uuid.uuid4()), "nodeGeneration": 2, "runtimeGeneration": 4,
            "attachmentGeneration": 7, "leaseExpiresAt": time.time() + 90,
            "runtimeProfile": {"profile": "assigned_stock_client", "client": "codex",
                               "conversationId": str(uuid.uuid4())},
        }
        stop = asyncio.Event()
        reads = 0

        class FakeStore:
            @staticmethod
            def clock():
                return time.time()

            def list_attachments(self):
                nonlocal reads
                reads += 1
                return [] if reads == 2 else [mapping]

            @staticmethod
            def renew_stock_attachment(_expected, _lease):
                stop.set()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = mapping["nodeId"], mapping["nodeGeneration"]

            def __init__(self):
                self.requests = []

            async def assigned_stock(self, request):
                self.requests.append(dict(request))
                if len(self.requests) == 1:
                    raise CloudError("assigned_stock_disabled")
                return {"leaseUntil": _iso(time.time() + 90)}

        cloud = FakeCloud()
        with patch.object(daemon, "STOCK_RENEW_INTERVAL", 0.001):
            await asyncio.wait_for(daemon._stock_renewal_worker(FakeStore(), cloud, stop), 1)
        self.assertEqual(len(cloud.requests), 2)
        self.assertEqual(cloud.requests[0], cloud.requests[1])

    async def test_stock_renewal_retries_same_request_after_unknown_transport(self):
        mapping = {
            "runtimeId": str(uuid.uuid4()), "principal": "owner@example.com", "agent": "codex",
            "nodeId": str(uuid.uuid4()), "nodeGeneration": 2, "runtimeGeneration": 4,
            "attachmentGeneration": 7, "leaseExpiresAt": time.time() + 90,
            "runtimeProfile": {"profile": "assigned_stock_client", "client": "codex",
                               "conversationId": str(uuid.uuid4())},
        }
        stop = asyncio.Event()

        class FakeStore:
            @staticmethod
            def clock():
                return time.time()

            @staticmethod
            def list_attachments():
                return [mapping]

            @staticmethod
            def renew_stock_attachment(_expected, _lease):
                stop.set()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = mapping["nodeId"], mapping["nodeGeneration"]

            def __init__(self):
                self.requests = []

            async def assigned_stock(self, request):
                self.requests.append(dict(request))
                if len(self.requests) == 1:
                    raise CloudError("request_timeout", ambiguous=True)
                return {"leaseUntil": _iso(time.time() + 90)}

        cloud = FakeCloud()
        real_wait_for = asyncio.wait_for

        async def fast_retry_wait(awaitable, timeout):
            return await real_wait_for(awaitable, 0.001 if timeout <= 2 else timeout)

        with patch.object(daemon.asyncio, "wait_for", side_effect=fast_retry_wait), \
                patch.object(daemon, "STOCK_RENEW_INTERVAL", 0.01):
            await real_wait_for(daemon._stock_renewal_worker(FakeStore(), cloud, stop), 1)
        self.assertEqual(cloud.requests[0], cloud.requests[1])

    async def test_unexpected_stock_worker_exit_fences_dispatch_and_stops_daemon(self):
        dispatch = {"listenerReady": True, "workerRunning": True}
        stop = asyncio.Event()

        async def failed_renewal():
            raise RuntimeError("unexpected renewal failure")

        task = asyncio.create_task(failed_renewal())
        task.add_done_callback(lambda _task: daemon._stop_dispatch(dispatch, None, stop))
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0)
        self.assertEqual(dispatch, {"listenerReady": False, "workerRunning": False})
        self.assertTrue(stop.is_set())

    async def test_readiness_waits_for_private_socket_permissions(self):
        start_server = asyncio.start_unix_server
        created, release = asyncio.Event(), asyncio.Event()

        async def delayed_start(*args, **kwargs):
            server = await start_server(*args, **kwargs)
            Path(kwargs["path"]).chmod(0o755)
            created.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                server.close()
                await server.wait_closed()
                raise
            return server

        async def status(state):
            async with running_daemon(state):
                return await daemon.request(state, {"command": "status"})

        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            state = await self.state_dir(directory, "readiness")
            with patch.object(asyncio, "start_unix_server", side_effect=delayed_start):
                request = asyncio.create_task(status(state))
                try:
                    await asyncio.wait_for(created.wait(), timeout=3)
                    await asyncio.sleep(0.03)
                    self.assertFalse(request.done(), "fixture accepted an unready socket")
                finally:
                    release.set()
                    response = await asyncio.wait_for(request, timeout=3)
                self.assertFalse(response["automaticWakeEnabled"])

    async def test_get_attachment_reads_through_live_writer_with_closed_request(self):
        runtime_id = str(uuid.uuid4())
        mapping = {"runtimeId": runtime_id, "fixture": "private-mapping"}
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            state = await self.state_dir(directory, "readback")
            with patch.object(Store, "get_attachment", return_value=mapping) as read:
                async with running_daemon(state):
                    self.assertEqual(await daemon.request(state, {
                        "command": "get-attachment", "runtimeId": runtime_id,
                    }), {"mapping": mapping})
                    for invalid in (
                        {"command": "get-attachment", "runtimeId": "invalid"},
                        {"command": "get-attachment", "runtimeId": runtime_id, "extra": True},
                        {"command": "get-attachment"},
                    ):
                        self.assertEqual(await daemon.request(state, invalid), {"reason": "unsupported_command"})
            read.assert_called_once_with(runtime_id)

    async def test_cli_readback_uses_live_daemon_without_opening_second_writer(self):
        runtime_id = str(uuid.uuid4())
        mapping = {"runtimeId": runtime_id, "fixture": "private-mapping"}
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            state = await self.state_dir(directory, "readback-cli")
            with patch.object(Store, "get_attachment", return_value=mapping):
                async with running_daemon(state):
                    with patch.object(cli, "Store", side_effect=AssertionError("second writer opened")):
                        self.assertEqual(await asyncio.to_thread(cli._read_native_mapping, state, runtime_id), mapping)

    async def test_cli_readback_timeout_does_not_fall_back_to_writer(self):
        runtime_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            state = await self.state_dir(directory, "readback-timeout")
            (state / "control.sock").touch()
            with (patch.object(cli, "request", side_effect=TimeoutError),
                  patch.object(cli, "Store", side_effect=AssertionError("second writer opened"))):
                with self.assertRaises(cli.CloudError) as caught:
                    await asyncio.to_thread(cli._read_native_mapping, state, runtime_id)
            self.assertEqual(caught.exception.code, "local_mapping_unavailable")

    async def state_dir(self, parent, label):
        path = Path(parent) / label
        path.mkdir(mode=0o700)
        return path

    async def test_malformed_attachment_returns_bounded_store_code(self):
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            state = await self.state_dir(directory, "malformed")
            async with running_daemon(state):
                response = await daemon.request(state, {
                    "command": "put-attachment", "mapping": {},
                })
        self.assertEqual(response, {"reason": "invalid_attachment"})

    async def test_capacity_and_stale_transfer_errors_return_codes_without_details(self):
        cases = (
            ("capacity", "capacity", {
                "command": "put-attachment", "mapping": {"runtimeId": "target"},
            }),
            ("stale", "stale_transfer", {
                "command": "transfer-attachment", "mapping": {"runtimeId": "target"},
                "transfer": {"sourceRuntimeId": "source"},
            }),
        )
        for label, code, command in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
                state = await self.state_dir(directory, label)
                with patch.object(
                    Store, "put_attachment",
                    side_effect=StoreError(code, "private database detail"),
                ):
                    async with running_daemon(state):
                        response = await daemon.request(state, command)
                self.assertEqual(response, {"reason": code})
                self.assertNotIn("private", json.dumps(response))
                self.assertLessEqual(len(json.dumps(response).encode()), 128)

    async def _run_cli_with_store_error(self, operation, failure_code):
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            state = Path(directory) / "state"
            binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                       "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                       "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
            cloud_id = {"origin": "https://events.example.com", "principal": "adam@knitli.com",
                        "agent": "codex", "nodeId": str(uuid.uuid4()), "nodeGeneration": 1}
            challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time()),
                         "expiresAt": _iso(time.time() + 30)}
            response = {
                "status": "attached" if operation == "attach" else "transferred",
                "runtimeId": str(uuid.uuid4()), "runtimeGeneration": 7,
                "nodeId": cloud_id["nodeId"], "nodeGeneration": 1, "attachmentGeneration": 9,
                "leaseUntil": _iso(time.time() + 90), "nativeBinding": binding,
            }
            if operation == "transfer":
                response.update(
                    sourceRuntimeId=str(uuid.uuid4()), sourceRuntimeGeneration=3,
                    sourceAttachmentGeneration=4,
                )

            class FakeCloud:
                origin, principal, agent = cloud_id["origin"], cloud_id["principal"], cloud_id["agent"]
                node_id, node_generation = cloud_id["nodeId"], cloud_id["nodeGeneration"]

                async def native_challenge(self, _intent):
                    return challenge

                async def _commit(self, *_args, on_first_send=None, **_kwargs):
                    if on_first_send is not None:
                        on_first_send(json.dumps({"nativeEvidence": {
                            "observedAt": _args[2]["observedAt"], "witness": _args[2]["witness"],
                        }}).encode())
                    return response

                async def attach(self, *args, **kwargs):
                    return await self._commit(*args, **kwargs)

                async def transfer(self, *args, **kwargs):
                    return await self._commit(*args, **kwargs)

            fake = FakeCloud()
            session_id = str(uuid.uuid4())
            runtime_id = response["runtimeId"]
            argv = ["--state-dir", str(state), operation]
            if operation == "attach":
                argv.extend(("--runtime-id", runtime_id))
                failed_method = "put_attachment"
            else:
                argv.extend((
                    "--source-runtime-id", response["sourceRuntimeId"],
                    "--expected-source-runtime-generation", "2",
                    "--expected-source-attachment-generation", "3",
                    "--replacement-runtime-id", runtime_id,
                    "--expected-replacement-runtime-generation", "7",
                    "--expected-replacement-attachment-generation", "8",
                ))
                failed_method = "revoke_transfer_source"
            argv.extend(("--session-id", session_id, "--cloud-config", str(state / "cloud.json")))
            binding_results = [binding, binding]
            if operation == "transfer":
                binding_results[1] = OSError("launcher socket disappeared")
            output = io.StringIO()
            with patch.object(
                Store, failed_method,
                side_effect=StoreError(failure_code, "private database detail"),
            ), patch.object(cli, "load_cloud_client", return_value=fake), \
                    patch.object(cli, "session_binding", side_effect=binding_results), \
                    patch.object(cli, "session_challenge", return_value={
                        "observedAt": challenge["issuedAt"],
                        "validUntilMonotonic": time.monotonic() + 0.5,
                        "witness": {"fixture": True},
                    }), redirect_stdout(output):
                async with running_daemon(state):
                    code = await asyncio.to_thread(cli.main, argv)
            result = json.loads(output.getvalue())
            self.assertEqual(code, 2)
            self.assertEqual(result["remoteStatus"], response["status"])
            self.assertEqual(result["localStatus"], "unavailable")
            self.assertEqual(result["lastError"], failure_code)
            self.assertIsNotNone(cli.load_pending_commit(state, operation, session_id))

    async def test_cli_preserves_committed_outcome_and_pending_artifact_on_store_errors(self):
        await self._run_cli_with_store_error("attach", "capacity")
        await self._run_cli_with_store_error("transfer", "stale_transfer")
