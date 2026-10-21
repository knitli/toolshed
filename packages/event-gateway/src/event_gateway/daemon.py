"""Private control daemon with explicitly configured authenticated delivery."""

import asyncio
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat

from .client_runtime import _private_json, load_cloud_client
from .cloud import CloudError, _timestamp, _uuid
from .gateway import Gateway
from .listener import Listener
from .native import NativeBridgeAdapter, SessionNativeBridge
from .security import SecurityError, _decode
from .store import Store, StoreError


BLOCKERS = ["native_client_binding_unavailable", "cloud_authority_not_integrated"]


def status(store, dispatch=None):
    if dispatch is not None:
        enabled = dispatch["listenerReady"] and dispatch["workerRunning"]
        return {
            "stage": "configured_dispatch", "automaticWakeEnabled": enabled,
            "blockers": [] if enabled else ["dispatch_stopping"],
            "dispatch": dict(dispatch), "store": store.status(),
        }
    return {
        "stage": "foundation",
        "automaticWakeEnabled": False,
        "blockers": BLOCKERS,
        "store": store.status(),
    }


def _execute_control_command(store, request_value, dispatch=None):
    if request_value == {"command": "status"}:
        return status(store, dispatch)
    if (isinstance(request_value, dict)
            and set(request_value) == {"command", "runtimeId"}
            and request_value["command"] == "get-attachment"
            and _uuid(request_value["runtimeId"])):
        return {"mapping": store.get_attachment(request_value["runtimeId"])}
    if (
        isinstance(request_value, dict)
        and set(request_value) == {"command", "runtimeId"}
        and request_value["command"] == "detach"
        and isinstance(request_value["runtimeId"], str)
    ):
        store.detach(request_value["runtimeId"])
        return {"detached": True}
    if (isinstance(request_value, dict)
            and set(request_value) == {"command", "mapping"}
            and request_value["command"] == "put-attachment"):
        stored = store.put_attachment(request_value["mapping"])
        return {"stored": True, "runtimeId": stored["runtimeId"]}
    if (isinstance(request_value, dict)
            and set(request_value) == {"command", "mapping", "transfer"}
            and request_value["command"] == "transfer-attachment"):
        stored = store.put_attachment(request_value["mapping"], transfer=request_value["transfer"])
        return {"stored": True, "runtimeId": stored["runtimeId"]}
    if (isinstance(request_value, dict)
            and set(request_value) == {"command", "mapping", "transfer"}
            and request_value["command"] == "revoke-transfer-source"):
        return store.revoke_transfer_source(
            request_value["mapping"], transfer=request_value["transfer"],
        )
    return {"reason": "unsupported_command"}


_LISTEN_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "100.64.0.0/10", "fc00::/7", "::1/128",
))
WORKER_INTERVAL = 0.5
WORKER_CONCURRENCY = 4
WORKER_TIMEOUT = 45
STOCK_RENEW_INTERVAL = 30
STOCK_RENEW_PENDING_LIMIT = 8
STOCK_RENEW_BATCH_LIMIT = 3
STOCK_RENEW_RETRY_INITIAL = 1
STOCK_RENEW_RETRY_MAX = 30
# shortcut: Pending responses are process-local; journal them if restart recovery is required.
# The cap mirrors contract policy maxRuntimesPerAgent (8).


def load_dispatch_config(path, state_dir):
    """Load explicit private listener trust, without creating keys or grants."""
    config, path = _private_json(path, 8192, "invalid_dispatch_config")
    try:
        base_fields = {"version", "cloudConfig", "listenHost", "listenPort", "transportKeys"}
        if (not isinstance(config, dict)
                or set(config) not in (base_fields, base_fields | {"stockCodexBinary"})
                or not isinstance(config["version"], int) or isinstance(config["version"], bool)
                or config["version"] != 1
                or not isinstance(config["cloudConfig"], str)
                or config["cloudConfig"] in ("", ".", "..")
                or Path(config["cloudConfig"]).name != config["cloudConfig"]
                or "\\" in config["cloudConfig"]
                or not isinstance(config["listenHost"], str) or "%" in config["listenHost"]
                or not isinstance(config["listenPort"], int) or isinstance(config["listenPort"], bool)
                or not 1 <= config["listenPort"] <= 65535
                or not isinstance(config["transportKeys"], dict)
                or not 1 <= len(config["transportKeys"]) <= 16):
            raise ValueError
        if "stockCodexBinary" in config and (
                not isinstance(config["stockCodexBinary"], str)
                or not Path(config["stockCodexBinary"]).is_absolute()
                or "\0" in config["stockCodexBinary"]):
            raise ValueError
        if "stockCodexBinary" in config and (
                not Path(config["stockCodexBinary"]).is_file()
                or not os.access(config["stockCodexBinary"], os.X_OK)):
            raise ValueError
        address = ipaddress.ip_address(config["listenHost"])
        if not any(address in network for network in _LISTEN_NETWORKS):
            raise ValueError
        for key_id, key in config["transportKeys"].items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", key_id):
                raise ValueError
            _decode(key, 32)
    except (ValueError, TypeError):
        raise SecurityError("invalid_dispatch_config") from None
    cloud = load_cloud_client(path.parent / config["cloudConfig"], state_dir)
    return config, cloud


async def _work_batch(rows, cursor, operation):
    # Rotate beyond unavailable rows; one slow runtime cannot monopolize a pass.
    if not rows:
        return 0
    start = cursor % len(rows)
    selected = (rows[start:] + rows[:start])[:WORKER_CONCURRENCY]

    async def process(row):
        try:
            async with asyncio.timeout(WORKER_TIMEOUT):
                await operation(row["deliveryId"])
        except (ValueError, OSError, TimeoutError):
            # Durable queued/unknown state remains the source of retry truth.
            pass

    async with asyncio.TaskGroup() as tasks:
        for row in selected:
            tasks.create_task(process(row))
    return start + len(selected)


async def _dispatch_worker(gateway, stop):
    reconcile_cursor = dispatch_cursor = 0
    while not stop.is_set():
        reconcile_cursor = await _work_batch(
            gateway.store.list_reconcilable(), reconcile_cursor, gateway.reconcile,
        )
        if stop.is_set():
            break
        dispatch_cursor = await _work_batch(
            gateway.store.list_pending(), dispatch_cursor, gateway.dispatch,
        )
        try:
            await asyncio.wait_for(stop.wait(), WORKER_INTERVAL)
        except TimeoutError:
            pass


# Keep retries, deadlines and suspension beside the exact-mapping renewal fence.
async def _renew_stock_mapping(store, cloud, stop, mapping, suspended):  # noqa: MC0001
    """Renew one exact live assigned-stock mapping with bounded retries."""
    fingerprint = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
    try:
        profile = mapping["runtimeProfile"]
        request = {
            "operation": "renew", "runtimeId": mapping["runtimeId"],
            "conversationId": profile["conversationId"],
            "expectedRuntimeGeneration": mapping["runtimeGeneration"],
            "expectedAttachmentGeneration": mapping["attachmentGeneration"],
        }
    except (KeyError, TypeError, ValueError):
        suspended.add(fingerprint)
        return
    for attempt in range(3):
        if stop.is_set():
            break
        request_started_at = store.clock()
        if mapping["leaseExpiresAt"] <= request_started_at:
            break
        try:
            # Expiry gates when a request may start, not how long its response
            # may take: cloud renewal can commit before expiry and reply after it.
            async with asyncio.timeout(5):
                response = await cloud.assigned_stock(request)
            # shortcut: Keep the thread-bound Store on its owner loop until DB access is serialized.
            lease_expires_at = _timestamp(response["leaseUntil"]) / 1000
            try:
                renewed = store.renew_stock_attachment(mapping, lease_expires_at)
            except StoreError as error:
                if error.code in ("capacity", "storage_unavailable"):
                    return lease_expires_at
                raise
            if not renewed:
                suspended.add(fingerprint)
            break
        except (CloudError, TimeoutError) as error:
            if isinstance(error, CloudError) and (
                    error.code == "invalid_response" or error.definitive_refusal
                    or not error.ambiguous):
                suspended.add(fingerprint)
                break
            if attempt == 2:
                break
        except (KeyError, TypeError, ValueError):
            suspended.add(fingerprint)
            break
        delay = (1, 2)[attempt]
        remaining = mapping["leaseExpiresAt"] - store.clock()
        if remaining <= 0:
            break
        try:
            await asyncio.wait_for(stop.wait(), min(delay, remaining))
            break
        except TimeoutError:
            pass


# Keep pending-response recovery and cloud-poll scheduling in one owner-loop sequence.
async def _stock_renewal_worker(store, cloud, stop):  # noqa: MC0001
    """Renew only live assigned-stock mappings already present in the local ledger."""
    suspended = set()
    pending = {}
    loop = asyncio.get_running_loop()
    next_cloud_poll = loop.time()
    while not stop.is_set():
        persisted_runtime_ids = set()
        now = store.clock()
        for fingerprint, item in list(pending.items()):
            if item["leaseExpiresAt"] <= now:
                del pending[fingerprint]
                continue
            try:
                current = store.get_attachment(item["mapping"]["runtimeId"])
            except sqlite3.Error:
                delay = item["retryDelay"]
                item["retryAt"] = loop.time() + delay
                item["retryDelay"] = min(delay * 2, STOCK_RENEW_RETRY_MAX)
                continue
            if current != item["mapping"]:
                del pending[fingerprint]
                continue
            if item["retryAt"] > loop.time():
                continue
            try:
                renewed = store.renew_stock_attachment(
                    item["mapping"], item["leaseExpiresAt"])
            except StoreError as error:
                if error.code not in ("capacity", "storage_unavailable"):
                    raise
                delay = item["retryDelay"]
                item["retryAt"] = loop.time() + delay
                item["retryDelay"] = min(delay * 2, STOCK_RENEW_RETRY_MAX)
                continue
            del pending[fingerprint]
            if renewed:
                persisted_runtime_ids.add(item["mapping"]["runtimeId"])

        if loop.time() >= next_cloud_poll:
            attachments = store.list_attachments()
            suspended.intersection_update(
                json.dumps(mapping, sort_keys=True, separators=(",", ":"))
                for mapping in attachments
                if isinstance(mapping.get("runtimeProfile"), dict)
                and mapping["runtimeProfile"].get("profile") == "assigned_stock_client"
            )
            renewals = []
            pending_runtime_ids = {
                item["mapping"]["runtimeId"] for item in pending.values()
            }
            for mapping in attachments:
                profile = mapping.get("runtimeProfile")
                if not isinstance(profile, dict) or profile.get("profile") != "assigned_stock_client":
                    continue
                if any(mapping.get(key) != getattr(cloud, client_key) for key, client_key in (
                        ("principal", "principal"), ("agent", "agent"),
                        ("nodeId", "node_id"), ("nodeGeneration", "node_generation"))):
                    continue
                fingerprint = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
                if (fingerprint not in suspended
                        and mapping["runtimeId"] not in pending_runtime_ids
                        and mapping["runtimeId"] not in persisted_runtime_ids):
                    renewals.append(mapping)
            available_slots = max(0, STOCK_RENEW_PENDING_LIMIT - len(pending))
            renewals = renewals[:min(STOCK_RENEW_BATCH_LIMIT, available_slots)]
            async with asyncio.TaskGroup() as tasks:
                task_mappings = [
                    (mapping, tasks.create_task(
                        _renew_stock_mapping(store, cloud, stop, mapping, suspended)))
                    for mapping in renewals
                ]
            for mapping, task in task_mappings:
                lease_expires_at = task.result()
                if lease_expires_at is not None:
                    fingerprint = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
                    pending[fingerprint] = {
                        "mapping": mapping,
                        "leaseExpiresAt": lease_expires_at,
                        "retryAt": loop.time() + STOCK_RENEW_RETRY_INITIAL,
                        "retryDelay": min(STOCK_RENEW_RETRY_INITIAL * 2, STOCK_RENEW_RETRY_MAX),
                    }
            next_cloud_poll = loop.time() + STOCK_RENEW_INTERVAL
        wait_for = max(0.001, next_cloud_poll - loop.time())
        if pending:
            wait_for = min(wait_for, min(
                max(0.001, item["retryAt"] - loop.time())
                for item in pending.values()))
        try:
            await asyncio.wait_for(stop.wait(), wait_for)
        except TimeoutError:
            pass


def _stop_dispatch(dispatch, listener, stop):
    """Fence readiness and admission before waiting for any shutdown work."""
    if dispatch is not None:
        dispatch.update(listenerReady=False, workerRunning=False)
    if listener is not None:
        listener.stop_accepting()
    stop.set()


def _control_handler(store, dispatch):
    """Bind bounded control requests to the daemon's single Store."""
    active = 0

    async def control(reader, writer):
        nonlocal active
        if active >= 8:
            writer.close()
            await writer.wait_closed()
            return
        active += 1
        try:
            async with asyncio.timeout(5):
                line = await reader.readline()
                if len(line) > 4096:
                    raise ValueError("request_too_large")
                request_value = json.loads(line)
                try:
                    result = _execute_control_command(store, request_value, dispatch)
                except StoreError as error:
                    result = {"reason": error.code}
                writer.write(json.dumps(result).encode() + b"\n")
                await writer.drain()
        except (ValueError, TimeoutError, ConnectionError):
            pass
        finally:
            active -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    return control


async def serve(state_dir, *, dispatch_config=None):
    configured = load_dispatch_config(dispatch_config, state_dir) if dispatch_config is not None else None
    with Store(state_dir) as store:
        path = Path(state_dir) / "control.sock"
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("unsafe_control_socket")
            # Writer lock proves no other gateway owns this socket.
            path.unlink()
        control_tasks = set()
        closing = False
        listener = server = worker = stock_worker = None
        dispatch = None
        stop = asyncio.Event()
        signals = []
        loop = asyncio.get_running_loop()

        def connected(reader, writer):
            if closing:
                writer.close()
                return
            task = asyncio.create_task(control(reader, writer))
            control_tasks.add(task)
            task.add_done_callback(control_tasks.discard)

        try:
            if configured is not None:
                config, cloud = configured
                gateway = Gateway(
                    store, cloud,
                    lambda mapping: NativeBridgeAdapter(mapping, SessionNativeBridge(state_dir, mapping)),
                    audience=cloud.node_id, keys=config["transportKeys"],
                    stock_codex_binary=config.get("stockCodexBinary"),
                )
                listener = Listener(gateway)
                await listener.start(config["listenHost"], config["listenPort"])
                worker = asyncio.create_task(_dispatch_worker(gateway, stop))
                worker.add_done_callback(lambda _task: _stop_dispatch(dispatch, listener, stop))
                if config.get("stockCodexBinary"):
                    stock_worker = asyncio.create_task(_stock_renewal_worker(store, cloud, stop))
                    stock_worker.add_done_callback(
                        lambda _task: _stop_dispatch(dispatch, listener, stop),
                    )
                dispatch = {"listenerReady": True, "workerRunning": True,
                            "authorityConfigured": True, "liveWakeVerified": False}
            control = _control_handler(store, dispatch)
            server = await asyncio.start_unix_server(connected, path=path, limit=4096)
            os.chmod(path, 0o600)
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _stop_dispatch, dispatch, listener, stop)
                signals.append(sig)
            await stop.wait()
            if worker is not None and worker.done():
                await worker
            if stock_worker is not None and stock_worker.done():
                await stock_worker
        finally:
            closing = True
            _stop_dispatch(dispatch, listener, stop)
            if server is not None:
                server.close()
            if worker is not None:
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)
            if stock_worker is not None:
                stock_worker.cancel()
                await asyncio.gather(stock_worker, return_exceptions=True)
            if listener is not None:
                await listener.close()
            if control_tasks:
                _, pending = await asyncio.wait(control_tasks, timeout=6)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*control_tasks, return_exceptions=True)
            if server is not None:
                await server.wait_closed()
            path.unlink(missing_ok=True)
            for sig in signals:
                loop.remove_signal_handler(sig)


async def request(state_dir, value):
    path = Path(state_dir) / "control.sock"
    info = path.lstat()
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError("unsafe_control_socket")
    async with asyncio.timeout(5):
        reader, writer = await asyncio.open_unix_connection(path, limit=8192)
        try:
            writer.write(json.dumps(value).encode() + b"\n")
            await writer.drain()
            return json.loads(await reader.readline())
        finally:
            writer.close()
            await writer.wait_closed()
