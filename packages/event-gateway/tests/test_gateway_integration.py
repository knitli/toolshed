import base64
import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway.cloud import CloudClient, Credentials, _iso, canonical_node_proof
from event_gateway.gateway import Gateway
from event_gateway.native import IDENTITY as NATIVE_IDENTITY, NativeBridgeAdapter
from event_gateway.protocol import _timestamp, parse_acknowledgment
from event_gateway.security import sign
from event_gateway.store import IDENTITY, Store

FIXTURE = json.loads((Path(__file__).resolve().parents[1]
                     / "contracts/event-control-v1/fixtures.json").read_text())
NOW = _timestamp(FIXTURE["admitted"]["permitIssuedAt"]) / 1000


class InjectedBridge:
    def __init__(self, path, thread_id):
        """Bind the fake bridge to the durable ledger and selected thread."""
        self.path = path
        self.witness = {"eligible": True, "clientId": str(uuid.uuid4()), "generation": 2,
                        "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 1, "threadId": thread_id}
        self.calls, self.at_start = [], []
        self.outcome = "terminalNotStarted"
        self.retained = {}
        self.drop_start = False

    def challenge(self):
        self.calls.append(("challenge", None))
        return dict(self.witness)

    def start(self, request):
        self.calls.append(("start", copy.deepcopy(request)))
        # The real adapter invokes us in another thread: observe committed SQLite
        # state through a separate reader before recording any native outcome.
        with closing(sqlite3.connect(self.path / "ledger.sqlite")) as reader:
            row = reader.execute(
                "SELECT state,native_request,admission FROM attempts WHERE delivery_id=? AND attempt_id=?",
                (request["deliveryId"], request["attemptId"]),
            ).fetchone()
        self.at_start.append(None if row is None else (row[0], json.loads(row[1]), json.loads(row[2])))
        if self.outcome == "started":
            outcome = {"status": "started", "turnId": request["clientUserMessageId"], "replayed": False}
        else:
            outcome = {"status": "terminalNotStarted", "reason": "busy", "receiptId": str(uuid.uuid4()), "replayed": False}
        self.retained[request["attemptId"]] = outcome
        if self.drop_start:
            raise TimeoutError("native start registered; response lost")
        return outcome

    def restore_attempt(self, request):
        self.calls.append(("restore", copy.deepcopy(request)))

    def receipt(self, request):
        self.calls.append(("receipt", copy.deepcopy(request)))
        return {**self.retained[request["attemptId"]], "replayed": True}


class GatewayIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = NOW
        self.store = Store(Path(self.tmp.name).resolve() / "private", clock=lambda: self.now)
        self.addCleanup(self.close_store)
        self.envelope = copy.deepcopy(FIXTURE["original"])
        self.mapping = {key: self.envelope[key] for key in IDENTITY}
        self.mapping.update(leaseExpiresAt=self.now + 86400, nativeThreadId=str(uuid.uuid4()))
        self.store.put_attachment(self.mapping)
        self.key = Ed25519PrivateKey.generate()
        self.requests, self.admissions, self.settled = [], {}, {}
        self.credential_calls = 0
        self.drop_settlement = self.drop_ack = self.drop_observed_ack = False
        self.observed_response = None
        self.accepted_acks = {}
        self.bridge = InjectedBridge(self.store.path, self.mapping["nativeThreadId"])
        self.client = CloudClient(
            origin="https://events.example.com", principal=self.envelope["principal"], agent=self.envelope["agent"],
            node_id=FIXTURE["admitted"]["nodeId"], node_generation=self.envelope["nodeGeneration"],
            private_key=self.key, credentials=self.credentials, send=self.send, clock=lambda: self.now,
        )
        self.gateway = Gateway(self.store, self.client, lambda mapping: NativeBridgeAdapter(mapping, self.bridge),
                               audience="integration", keys={"test": self.key.public_key()}, clock=lambda: self.now)
        body = json.dumps(self.envelope).encode()
        self.ident = self.gateway.accept(body, signature=sign(body, self.key, "integration"),
                                         audience="integration", key_id="test")["deliveryId"]

    def close_store(self):
        self.store.close()

    async def credentials(self):
        self.credential_calls += 1
        return Credentials(f"access-{self.credential_calls}", f"agent-{self.credential_calls}")

    async def send(self, **request):
        self.requests.append(copy.deepcopy(request))
        path = request["url"].removeprefix(self.client.origin)
        proof = json.loads(request["headers"]["x-event-node-proof"])
        self.key.public_key().verify(base64.urlsafe_b64decode(proof["signature"] + "=="),
            canonical_node_proof(self.client.principal, self.client.origin, path, request["body"], proof))
        self.assertEqual(request["method"], "POST")
        self.assertFalse(request["follow_redirects"])
        self.assertEqual((request["timeout"], request["max_response_bytes"]), (5, 8192))
        body = json.loads(request["body"])
        attempt = self.store.current_attempt(self.ident)
        if path == "/v1/dispatch/claim":
            self.assertEqual(body, {key: attempt["envelope"][key] for key in ("deliveryId", "attemptId")})
            self.assertEqual(attempt["state"], "claiming")
            self.assertGreater(attempt["reserved_bytes"], 0)
            if body["attemptId"] not in self.admissions:
                self.admissions[body["attemptId"]] = {
                    "status": "admitted", "permitId": str(uuid.uuid4()), "nodeId": self.client.node_id,
                    "permitIssuedAt": _iso(self.now), "permitExpiresAt": _iso(self.now + 5),
                    "envelope": {**attempt["envelope"], "issuedAt": _iso(self.now), "expiresAt": _iso(self.now + 60)},
                }
            result = self.admissions[body["attemptId"]]
        elif path == "/v1/dispatch/settle-no-start":
            admission = self.admissions[body["attemptId"]]
            self.assertEqual(attempt["state"], "settlement_pending")
            self.assertEqual(attempt["admission"], admission)
            self.assertEqual(body, {"deliveryId": self.ident, "attemptId": attempt["attempt_id"],
                                  "permitId": admission["permitId"], "nodeGeneration": self.envelope["nodeGeneration"],
                                  "evidence": attempt["evidence"]})
            result = {**body, "status": "not_started", "nodeId": self.client.node_id}
            if body["attemptId"] in self.settled:
                self.assertEqual(result, self.settled[body["attemptId"]])
            self.settled[body["attemptId"]] = result
            if self.drop_settlement:
                self.drop_settlement = False
                raise TimeoutError("settlement accepted; response lost")
        elif path == "/v1/ack":
            observed = body["status"] == "observed"
            column = "native_observed_ack" if observed else "native_ack"
            # A separate reader proves the receipt and immutable DTO committed before HTTP.
            with closing(sqlite3.connect(self.store.path / "ledger.sqlite")) as reader:
                reader.row_factory = sqlite3.Row
                persisted = reader.execute("SELECT * FROM attempts WHERE delivery_id=? AND attempt_id=?",
                                           (self.ident, attempt["attempt_id"])).fetchone()
            self.assertEqual(json.loads(persisted[column]), body)
            full_receipt = json.loads(persisted["input_recorded_receipt"] if observed else
                                      persisted["started_receipt"] or persisted["input_recorded_receipt"])
            self.assertEqual({key: full_receipt[key] for key in NATIVE_IDENTITY},
                             {key: attempt["native_request"][key] for key in NATIVE_IDENTITY})
            self.assertEqual(full_receipt["outcome"]["turnId"], body["nativeCorrelation"]["turnId"])
            self.assertEqual(body["nativeCorrelation"]["permitId"], attempt["admission"]["permitId"])
            if observed:
                self.assertEqual(attempt["ack_state"], "submitted")
                self.assertEqual(full_receipt["outcome"]["status"], "inputRecorded")
                self.assertEqual(full_receipt["outcome"]["itemId"], body["nativeCorrelation"]["itemId"])
                self.assertEqual(self.accepted_acks[(attempt["attempt_id"], "submitted")], attempt["native_ack"])
                if self.observed_response == "reject":
                    return 400, {"content-type": "application/json"}, b'{"error":"invalid_request"}'
                if self.observed_response == "invalid":
                    return 200, {"content-type": "application/json"}, b'{"status":"submitted","current":false}'
            identity = (attempt["attempt_id"], body["status"])
            replayed = identity in self.accepted_acks
            if replayed:
                self.assertEqual(self.accepted_acks[identity], body)
            self.accepted_acks[identity] = copy.deepcopy(body)
            result = {"status": body["status"], "current": observed and not replayed}
            if observed and self.drop_observed_ack:
                self.drop_observed_ack = False
                raise TimeoutError("observed ACK accepted; response lost")
            if not observed and self.drop_ack:
                self.drop_ack = False
                raise TimeoutError("submitted ACK accepted; response lost")
        else:
            self.fail("Unexpected cloud path: " + path)
        return 200, {"content-type": "application/json"}, json.dumps(result).encode()

    async def test_real_clients_retire_terminal_no_start_then_ack_started_receipt(self):
        first_attempt = self.envelope["attemptId"]
        self.assertEqual((await self.gateway.dispatch(self.ident))["status"], "queued")
        second_attempt = self.store.delivery_envelope(self.ident)["attemptId"]
        self.assertNotEqual(second_attempt, first_attempt)
        first_request = [value for name, value in self.bridge.calls if name == "start"][0]
        self.assertEqual(self.bridge.at_start, [("submitting", first_request, self.admissions[first_attempt])])
        self.assertEqual(self.settled[first_attempt]["evidence"], {
            "type": "native_terminal_no_start", "receiptId": self.bridge.retained[first_attempt]["receiptId"],
        })
        self.bridge.outcome = "started"
        self.drop_ack = True
        started = await self.gateway.dispatch(self.ident)
        self.assertEqual(started["status"], "submitted")
        self.assertEqual(started["reason"], "native_started_ack_pending")
        current = self.store.current_attempt(self.ident)
        native = current["native_request"]
        acknowledgment = current["native_ack"]
        self.assertEqual(current["started_receipt"]["outcome"]["turnId"], native["clientUserMessageId"])
        self.assertEqual(self.bridge.at_start[-1], ("submitting", native, self.admissions[second_attempt]))
        self.assertTrue(self.store.native_receipt(self.ident)["ack_pending"])
        native_calls_before_retry = copy.deepcopy(self.bridge.calls)
        self.store.close()
        self.store = Store(self.bridge.path, clock=lambda: self.now)
        self.gateway.store = self.store
        self.now += 3600
        self.assertEqual((await self.gateway.reconcile(self.ident))["status"], "submitted")
        acks = self.requests[-2:]
        self.assertEqual(acks[0]["body"], acks[1]["body"])
        self.assertEqual(self.bridge.calls, native_calls_before_retry + [("restore", native), ("receipt", native)])
        self.assertEqual(self.store.current_attempt(self.ident)["native_ack"], acknowledgment)
        self.assertFalse(self.store.native_receipt(self.ident)["ack_pending"])
        before = len(self.requests), len(self.bridge.calls)
        self.assertEqual((await self.gateway.reconcile(self.ident))["status"], "submitted")
        self.assertEqual((len(self.requests), len(self.bridge.calls)), (before[0], before[1] + 2))
        self.assertEqual(self.bridge.calls[-2:], [("restore", native), ("receipt", native)])
        self.assertEqual([item["url"].removeprefix(self.client.origin) for item in self.requests],
                         ["/v1/dispatch/claim", "/v1/dispatch/settle-no-start", "/v1/dispatch/claim", "/v1/ack", "/v1/ack"])
        self.assertNotEqual(acks[0]["headers"]["x-event-node-proof"], acks[1]["headers"]["x-event-node-proof"])
        self.assertNotEqual(acks[0]["headers"]["authorization"], acks[1]["headers"]["authorization"])

    async def test_observed_receipt_signed_ack_retries_exact_after_restart(self):
        self.bridge.outcome = "started"
        self.assertEqual((await self.gateway.dispatch(self.ident))["status"], "submitted")
        registered = self.store.current_attempt(self.ident)
        native = registered["native_request"]
        outcome = {"status": "inputRecorded", "turnId": native["clientUserMessageId"],
                   "itemId": str(uuid.uuid4()), "replayed": True}
        self.bridge.retained[registered["attempt_id"]] = outcome
        before_native = copy.deepcopy(self.bridge.calls)
        self.drop_observed_ack = True
        result = await self.gateway.reconcile(self.ident)
        self.assertEqual((result["status"], result["reason"]), ("submitted", "native_observed_ack_pending"))
        current = self.store.current_attempt(self.ident)
        observed_ack = current["native_observed_ack"]
        self.assertEqual(current["input_recorded_receipt"], {
            **{key: native[key] for key in NATIVE_IDENTITY}, "outcome": outcome})
        self.assertEqual(current["started_receipt"], registered["started_receipt"])
        self.assertEqual(current["native_ack"], registered["native_ack"])
        self.assertEqual(current["ack_state"], "submitted")
        self.assertEqual(observed_ack["nativeCorrelation"], {
            "kind": "native_input_recorded", "permitId": native["permitId"],
            "turnId": outcome["turnId"], "itemId": outcome["itemId"]})
        self.assertEqual(parse_acknowledgment(json.dumps(observed_ack).encode(), now_ms=self.now * 1000), observed_ack)
        self.assertTrue(self.store.native_receipt(self.ident)["ack_pending"])
        self.assertGreater(current["reserved_bytes"], 0)
        self.assertEqual(self.bridge.calls, before_native + [("restore", native), ("receipt", native)])
        calls_after_observation = copy.deepcopy(self.bridge.calls)
        self.store.close()
        self.store = Store(self.bridge.path, clock=lambda: self.now)
        self.gateway.store = self.store
        self.now += 3600
        self.assertEqual((await self.gateway.reconcile(self.ident))["status"], "observed")
        restored = self.store.current_attempt(self.ident)
        self.assertEqual(restored["input_recorded_receipt"], current["input_recorded_receipt"])
        self.assertEqual(restored["started_receipt"], registered["started_receipt"])
        self.assertEqual(restored["native_observed_ack"], observed_ack)
        self.assertEqual(restored["native_ack"], registered["native_ack"])
        self.assertEqual(restored["ack_state"], "observed")
        self.assertEqual(restored["reserved_bytes"], 0)
        self.assertFalse(self.store.native_receipt(self.ident)["ack_pending"])
        observed_requests = self.requests[-2:]
        self.assertEqual([json.loads(item["body"]) for item in observed_requests], [observed_ack, observed_ack])
        self.assertEqual(observed_requests[0]["body"], observed_requests[1]["body"])
        for header in ("authorization", "cf-access-token", "x-event-node-proof"):
            self.assertNotEqual(observed_requests[0]["headers"][header], observed_requests[1]["headers"][header])
        self.assertEqual(self.bridge.calls, calls_after_observation)
        self.assertEqual([item["url"].removeprefix(self.client.origin) for item in self.requests],
                         ["/v1/dispatch/claim", "/v1/ack", "/v1/ack", "/v1/ack"])
        before = len(self.requests), len(self.bridge.calls)
        await self.gateway.reconcile(self.ident)
        await self.gateway.dispatch(self.ident)
        self.assertEqual((len(self.requests), len(self.bridge.calls)), before)
        self.assertEqual(self.store.list_reconcilable(), [])

    async def test_old_cloud_rejection_keeps_exact_observed_phase_pending(self):
        self.bridge.outcome = "started"
        await self.gateway.dispatch(self.ident)
        registered = self.store.current_attempt(self.ident)
        native = registered["native_request"]
        self.bridge.retained[registered["attempt_id"]] = {
            "status": "inputRecorded", "turnId": native["clientUserMessageId"],
            "itemId": str(uuid.uuid4()), "replayed": True}
        for response in ("reject", "invalid"):
            self.observed_response = response
            result = await self.gateway.reconcile(self.ident)
            self.assertEqual((result["status"], result["reason"]), ("submitted", "native_observed_ack_pending"))
            pending = self.store.current_attempt(self.ident)
            self.assertEqual(pending["ack_state"], "submitted")
            self.assertTrue(self.store.native_receipt(self.ident)["ack_pending"])
            self.assertGreater(pending["reserved_bytes"], 0)
            self.store.close()
            self.store = Store(self.bridge.path, clock=lambda: self.now)
            self.gateway.store = self.store
            self.now += 3600
        self.assertEqual(self.requests[-2]["body"], self.requests[-1]["body"])
        self.assertEqual(json.loads(self.requests[-1]["body"]), pending["native_observed_ack"])
        self.assertEqual([name for name, _ in self.bridge.calls], ["challenge", "challenge", "start", "restore", "receipt"])
        self.assertNotIn((registered["attempt_id"], "observed"), self.accepted_acks)
        before_native = copy.deepcopy(self.bridge.calls)
        self.observed_response = None
        self.assertEqual((await self.gateway.reconcile(self.ident))["status"], "observed")
        self.assertEqual(self.requests[-2]["body"], self.requests[-1]["body"])
        self.assertEqual(self.bridge.calls, before_native)
        self.assertEqual(self.store.current_attempt(self.ident)["native_ack"], registered["native_ack"])

    async def test_input_recorded_only_recovery_registers_then_observes_without_fake_started(self):
        self.bridge.outcome = "started"
        self.bridge.drop_start = True
        self.assertEqual((await self.gateway.dispatch(self.ident))["status"], "ambiguous")
        attempted = self.store.current_attempt(self.ident)
        native = attempted["native_request"]
        self.assertIsNone(attempted["started_receipt"])
        self.assertIsNone(attempted["native_ack"])
        outcome = {"status": "inputRecorded", "turnId": native["clientUserMessageId"],
                   "itemId": str(uuid.uuid4()), "replayed": True}
        self.bridge.retained[attempted["attempt_id"]] = outcome
        before_native = copy.deepcopy(self.bridge.calls)
        self.assertEqual((await self.gateway.reconcile(self.ident))["status"], "observed")
        recovered = self.store.current_attempt(self.ident)
        self.assertIsNone(recovered["started_receipt"])
        self.assertEqual(recovered["input_recorded_receipt"], {
            **{key: native[key] for key in NATIVE_IDENTITY}, "outcome": outcome})
        self.assertEqual([json.loads(item["body"])["status"] for item in self.requests[1:]], ["submitted", "observed"])
        self.assertEqual(self.bridge.calls, before_native + [("restore", native), ("receipt", native)])
        self.assertEqual(recovered["native_ack"]["nativeCorrelation"], {
            "kind": "native_turn_started", "permitId": native["permitId"], "turnId": outcome["turnId"]})
        self.assertEqual(recovered["native_observed_ack"]["nativeCorrelation"], {
            "kind": "native_input_recorded", "permitId": native["permitId"],
            "turnId": outcome["turnId"], "itemId": outcome["itemId"]})
        before = len(self.requests), len(self.bridge.calls)
        await self.gateway.reconcile(self.ident)
        await self.gateway.dispatch(self.ident)
        self.assertEqual((len(self.requests), len(self.bridge.calls)), before)
        self.assertFalse(self.store.native_receipt(self.ident)["ack_pending"])

    async def test_lost_settlement_response_retries_exact_signed_retirement_without_native_replay(self):
        self.drop_settlement = True
        result = await self.gateway.dispatch(self.ident)
        self.assertEqual(result["status"], "settlement_pending")
        old = self.store.current_attempt(self.ident)
        before_native = copy.deepcopy(self.bridge.calls)
        self.store.close()
        self.store = Store(self.bridge.path, clock=lambda: self.now)
        self.gateway.store = self.store
        self.now += 3600  # The original immutable admission is now historical.
        self.assertEqual(self.store.current_attempt(self.ident)["admission"], old["admission"])
        self.assertEqual((await self.gateway.reconcile(self.ident))["status"], "queued")
        self.assertNotEqual(self.store.delivery_envelope(self.ident)["attemptId"], old["attempt_id"])
        self.assertEqual(self.bridge.calls, before_native)
        settlements = [item for item in self.requests if item["url"].endswith("/settle-no-start")]
        self.assertEqual(len(settlements), 2)
        self.assertEqual(settlements[0]["body"], settlements[1]["body"])
        self.assertNotEqual(settlements[0]["headers"]["x-event-node-proof"], settlements[1]["headers"]["x-event-node-proof"])
        self.assertNotEqual(settlements[0]["headers"]["authorization"], settlements[1]["headers"]["authorization"])
        self.assertEqual(len(self.admissions), 1)
        self.assertEqual(len(self.settled), 1)


if __name__ == "__main__":
    unittest.main()
