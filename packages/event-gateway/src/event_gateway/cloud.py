"""Closed Event control-plane client. Injected ports only; no CLI/native path."""

import asyncio
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import re
import time
from functools import partial
from urllib.parse import urlsplit
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .protocol import (
    ProtocolError, _SCHEMA, _depth, _pairs, _timestamp, acknowledgment_matches_delivery,
    matches_delivery_id, parse_acknowledgment, parse_envelope,
)


class CloudError(ValueError):
    """Only fixed local/server codes escape the credential boundary."""

    def __init__(self, code, *, ambiguous=False):
        """Store the error code."""
        self.code = code
        self.ambiguous = ambiguous
        super().__init__(code)


@dataclass(frozen=True)
class Credentials:
    access_token: str = field(repr=False)
    agent_token: str = field(repr=False)


def _valid_credentials(credential):
    return isinstance(credential, Credentials) and all(
        isinstance(token, str) and token and len(token) <= 16384 and not re.search(r"\s", token)
        for token in (credential.access_token, credential.agent_token)
    ) and len(credential.agent_token) <= 4096


def _json(value):
    rendered = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    # Match well-formed JSON.stringify for lone UTF-16 surrogates without
    # escaping ordinary non-ASCII text or attempting an invalid UTF-8 encode.
    rendered = "".join(
        f"\\u{ord(char):04x}" if 0xD800 <= ord(char) <= 0xDFFF else char
        for char in rendered
    )
    return rendered.encode("utf-8")


def _same_json_value(actual, expected):
    """Compare parsed JSON semantically while keeping booleans distinct from integers."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (actual.keys() == expected.keys()
                and all(_same_json_value(actual[key], expected[key]) for key in expected))
    if isinstance(expected, list):
        return (len(actual) == len(expected)
                and all(_same_json_value(left, right) for left, right in zip(actual, expected)))
    return actual == expected


def _closed(value, keys, *, code="invalid_response"):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise CloudError(code)


def _response(status, headers, raw):
    # HTTP status must be an integer, never Python's bool subtype.
    if type(status) is not int or not isinstance(headers, dict):  # pylint: disable=unidiomatic-typecheck
        raise CloudError("invalid_response")
    if 300 <= status < 400:
        raise CloudError("redirect_refused")
    content_type = headers.get("content-type", "")
    if (not isinstance(content_type, str) or content_type.split(";")[0].strip().lower() != "application/json"
            or "content-encoding" in headers or not isinstance(raw, bytes) or len(raw) > 8192):
        raise CloudError("invalid_response")

    def reject_constant(_):
        raise CloudError("invalid_response")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=reject_constant)
        _depth(value)
    except (ValueError, RecursionError):
        raise CloudError("invalid_response") from None
    if status != 200:
        _closed(value, ("error",))
        code = value["error"]
        if isinstance(code, str) and code in _ERRORS.get(status, set()):
            raise CloudError(code)
        raise CloudError("unavailable")
    return value


def _uuid(value):
    return isinstance(value, str) and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value
    ) is not None


def _generation(value):
    # bool is an int subtype but cannot identify a generation.
    return type(value) is int and 0 < value <= 9007199254740991  # pylint: disable=unidiomatic-typecheck


def _safe_uint(value):
    return type(value) is int and 0 <= value <= _SAFE_INTEGER  # pylint: disable=unidiomatic-typecheck


_SAFE_INTEGER = 9007199254740991
_NATIVE_BINDING_FIELDS = frozenset((
    "clientId", "connectionId", "backendPid", "threadId", "generation",
    "serverInstanceId", "serverGeneration",
))
_NATIVE_WITNESS_FIELDS = frozenset((
    "version", "nonce", "clientId", "backendPid", "connectionId", "threadId",
    "generation", "eligible", "sequence", "cause", "serverInstanceId",
    "serverGeneration", "leaseMs",
))


def _native_binding(value, *, code="invalid_request"):
    _closed(value, _NATIVE_BINDING_FIELDS, code=code)
    if (any(not _uuid(value[key]) for key in (
            "clientId", "connectionId", "threadId", "serverInstanceId"))
            or type(value["backendPid"]) is not int  # pylint: disable=unidiomatic-typecheck
            or not 1 <= value["backendPid"] <= 2**32 - 1
            or any(not _safe_uint(value[key]) for key in ("generation", "serverGeneration"))):
        raise CloudError(code)
    return value


def _native_witness(value, *, code="invalid_request"):
    _closed(value, _NATIVE_WITNESS_FIELDS, code=code)
    if (type(value["version"]) is not int or value["version"] != 2  # pylint: disable=unidiomatic-typecheck
            or type(value["nonce"]) is not int or not 0 <= value["nonce"] <= _SAFE_INTEGER  # pylint: disable=unidiomatic-typecheck
            or value["eligible"] is not True
            or type(value["sequence"]) is not int or not 1 <= value["sequence"] <= _SAFE_INTEGER  # pylint: disable=unidiomatic-typecheck
            or not isinstance(value["cause"], str)
            or len(value["cause"].encode("utf-16-le", "surrogatepass")) // 2 > 128
            or type(value["leaseMs"]) is not int or not 1 <= value["leaseMs"] <= _SAFE_INTEGER):  # pylint: disable=unidiomatic-typecheck
        raise CloudError(code)
    binding = {key: value[key] for key in _NATIVE_BINDING_FIELDS}
    _native_binding(binding, code=code)
    return value


def _native_challenge_request(value):
    if not isinstance(value, dict) or value.get("operation") not in ("attach", "renew", "transfer"):
        raise CloudError("invalid_request")
    operation = value["operation"]
    _native_binding(value.get("expectedNativeBinding"))
    if operation == "attach":
        _closed(value, ("operation", "runtimeId", "expectedRuntimeGeneration",
                        "expectedAttachmentGeneration", "expectedNativeBinding"), code="invalid_request")
        if (not _uuid(value["runtimeId"])
                or (value["expectedRuntimeGeneration"] is None) != (value["expectedAttachmentGeneration"] is None)
                or (value["expectedRuntimeGeneration"] is not None
                    and (not _generation(value["expectedRuntimeGeneration"])
                         or not _generation(value["expectedAttachmentGeneration"])
                         or value["expectedRuntimeGeneration"] >= _SAFE_INTEGER
                         or value["expectedAttachmentGeneration"] >= _SAFE_INTEGER))):
            raise CloudError("invalid_request")
    elif operation == "renew":
        _closed(value, ("operation", "runtimeId", "expectedRuntimeGeneration",
                        "expectedAttachmentGeneration", "expectedNativeBinding"), code="invalid_request")
        if (not _uuid(value["runtimeId"])
                or not _generation(value["expectedRuntimeGeneration"])
                or not _generation(value["expectedAttachmentGeneration"])):
            raise CloudError("invalid_request")
    else:
        _closed(value, ("operation", "sourceRuntimeId", "expectedSourceRuntimeGeneration",
                        "expectedSourceAttachmentGeneration", "replacementRuntimeId",
                        "expectedReplacementRuntimeGeneration", "expectedReplacementAttachmentGeneration",
                        "expectedNativeBinding"), code="invalid_request")
        if (not _uuid(value["sourceRuntimeId"]) or not _uuid(value["replacementRuntimeId"])
                or value["sourceRuntimeId"] == value["replacementRuntimeId"]
                or any(not _generation(value[key]) for key in (
                    "expectedSourceRuntimeGeneration", "expectedSourceAttachmentGeneration",
                    "expectedReplacementRuntimeGeneration", "expectedReplacementAttachmentGeneration"))
                or value["expectedSourceRuntimeGeneration"] >= _SAFE_INTEGER
                or value["expectedSourceAttachmentGeneration"] >= _SAFE_INTEGER
                or value["expectedReplacementAttachmentGeneration"] >= _SAFE_INTEGER):
            raise CloudError("invalid_request")
    return json.loads(_json(value))


def _native_challenge_response(value, *, code="invalid_response"):
    _closed(value, ("challengeId", "issuedAt", "expiresAt"), code=code)
    try:
        issued, expires = _timestamp(value["issuedAt"]), _timestamp(value["expiresAt"])
    except (ProtocolError, TypeError):
        raise CloudError(code) from None
    if not _uuid(value["challengeId"]) or expires - issued != 30_000:
        raise CloudError(code)
    return value


def _native_evidence(value, expected_binding):
    _closed(value, ("observedAt", "witness"))
    try:
        _timestamp(value["observedAt"])
    except (ProtocolError, TypeError):
        raise CloudError("invalid_request") from None
    witness = _native_witness(value["witness"])
    binding = {key: witness[key] for key in _NATIVE_BINDING_FIELDS}
    if binding != expected_binding:
        raise CloudError("native_binding_changed")
    return {"observedAt": value["observedAt"], "witness": json.loads(_json(witness))}


def _native_local_evidence(value, expected_binding):
    _closed(value, ("observedAt", "validUntilMonotonic", "witness"))
    deadline = value["validUntilMonotonic"]
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)  # pylint: disable=unidiomatic-typecheck
            or time.monotonic() >= deadline):
        raise CloudError("native_evidence_expired")
    evidence = _native_evidence(
        {"observedAt": value["observedAt"], "witness": value["witness"]}, expected_binding,
    )
    remaining = deadline - time.monotonic()
    if not 0 < remaining <= min(value["witness"]["leaseMs"], 750) / 1000:
        raise CloudError("native_evidence_expired")
    return evidence, deadline


def _native_commit_body(operation, request, challenge, evidence):
    fields = {
        "attach": ("runtimeId", "expectedRuntimeGeneration", "expectedAttachmentGeneration"),
        "renew": ("runtimeId", "expectedRuntimeGeneration", "expectedAttachmentGeneration"),
        "transfer": ("sourceRuntimeId", "expectedSourceRuntimeGeneration",
                     "expectedSourceAttachmentGeneration", "replacementRuntimeId",
                     "expectedReplacementRuntimeGeneration", "expectedReplacementAttachmentGeneration"),
    }[operation]
    return {"challengeId": challenge["challengeId"],
            **{key: request[key] for key in fields}, "nativeEvidence": evidence}


def _prepared_native_commit_body(prepared_body, expected_body):
    if prepared_body is None:
        return _json(expected_body)
    if not isinstance(prepared_body, bytes) or not 1 <= len(prepared_body) <= 4096:
        raise CloudError("invalid_pending_commit")

    def reject_constant(_):
        raise ValueError("invalid_json")

    try:
        parsed_body = json.loads(prepared_body.decode("utf-8"), object_pairs_hook=_pairs,
                                 parse_constant=reject_constant)
        _depth(parsed_body)
    except (UnicodeError, ValueError, RecursionError, ProtocolError):
        raise CloudError("invalid_pending_commit") from None
    if not _same_json_value(parsed_body, expected_body):
        raise CloudError("invalid_pending_commit")
    return prepared_body


def _native_commit_timing(challenge, evidence):
    observed_at = _timestamp(evidence["observedAt"])
    challenge_issued = _timestamp(challenge["issuedAt"])
    challenge_expires = _timestamp(challenge["expiresAt"])
    witness_lease = min(evidence["witness"]["leaseMs"], 750)
    return observed_at, challenge_issued, challenge_expires, witness_lease


def _native_commit_send_fence(on_first_send, body_bytes, *, recovery, deadline,
                              observed_at, challenge_issued, challenge_expires, witness_lease):
    def before_send(proof, *, attempt):
        if attempt == 0 and on_first_send is not None:
            if not callable(on_first_send):
                raise CloudError("invalid_configuration")
            on_first_send(body_bytes)
        # An exact receipt replay skips the original native evidence deadline.
        if recovery or attempt > 0:
            return
        if time.monotonic() >= deadline:
            raise CloudError("native_evidence_expired")
        try:
            proof_issued = _timestamp(proof["issuedAt"])
        except (ProtocolError, TypeError):
            raise CloudError("invalid_configuration") from None
        if (not challenge_issued <= observed_at <= proof_issued < challenge_expires
                or proof_issued - observed_at > witness_lease):
            raise CloudError("native_evidence_expired")

    return before_send


def _native_attached_response(value, status, request, client):
    _closed(value, ("status", "runtimeId", "runtimeGeneration", "nodeId", "nodeGeneration",
                    "attachmentGeneration", "leaseUntil", "nativeBinding"), code="invalid_response")
    try:
        _timestamp(value["leaseUntil"])
    except (ProtocolError, TypeError):
        raise CloudError("invalid_response") from None
    if (value["status"] != status or value["runtimeId"] != request["runtimeId"]
            or not _generation(value["runtimeGeneration"])
            or value["nodeId"] != client.node_id
            or not _generation(value["nodeGeneration"])
            or value["nodeGeneration"] != client.node_generation
            or not _generation(value["attachmentGeneration"])):
        raise CloudError("invalid_response")
    binding = _native_binding(value["nativeBinding"], code="invalid_response")
    if binding != request["expectedNativeBinding"]:
        raise CloudError("identity_mismatch")
    if status == "renewed":
        expected_runtime, expected_attachment = (
            request["expectedRuntimeGeneration"], request["expectedAttachmentGeneration"],
        )
    else:
        expected_runtime = (request["expectedRuntimeGeneration"] or 0) + 1
        expected_attachment = (request["expectedAttachmentGeneration"] or 0) + 1
    if (value["runtimeGeneration"] != expected_runtime
            or value["attachmentGeneration"] != expected_attachment):
        raise CloudError("invalid_response")
    return json.loads(_json(value))


def _native_transfer_response(value, request, client):
    _closed(value, ("status", "sourceRuntimeId", "sourceRuntimeGeneration",
                    "sourceAttachmentGeneration", "runtimeId", "runtimeGeneration", "nodeId",
                    "nodeGeneration", "attachmentGeneration", "leaseUntil", "nativeBinding"),
            code="invalid_response")
    try:
        _timestamp(value["leaseUntil"])
    except (ProtocolError, TypeError):
        raise CloudError("invalid_response") from None
    if (value["status"] != "transferred"
            or value["sourceRuntimeId"] != request["sourceRuntimeId"]
            or value["runtimeId"] != request["replacementRuntimeId"]
            or value["sourceRuntimeGeneration"] != request["expectedSourceRuntimeGeneration"] + 1
            or value["sourceAttachmentGeneration"] != request["expectedSourceAttachmentGeneration"] + 1
            or value["runtimeGeneration"] != request["expectedReplacementRuntimeGeneration"]
            or value["attachmentGeneration"] != request["expectedReplacementAttachmentGeneration"] + 1
            or value["nodeId"] != client.node_id or value["nodeGeneration"] != client.node_generation
            or any(not _generation(value[key]) for key in (
                "nodeGeneration",
                "sourceRuntimeGeneration", "sourceAttachmentGeneration", "runtimeGeneration",
                "attachmentGeneration"))):
        raise CloudError("invalid_response")
    binding = _native_binding(value["nativeBinding"], code="invalid_response")
    if binding != request["expectedNativeBinding"]:
        raise CloudError("identity_mismatch")
    return json.loads(_json(value))


_PRINCIPAL_SCHEMA = _SCHEMA["anyOf"][0]["anyOf"][0]["properties"]["principal"]


def _principal(value):
    return (isinstance(value, str) and len(value) <= _PRINCIPAL_SCHEMA["maxLength"]
            and re.fullmatch(_PRINCIPAL_SCHEMA["pattern"], value) is not None)


def _iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _historical_envelope(envelope, now_ms):
    try:
        parsed = parse_envelope(_json(envelope), now_ms=min(now_ms, _timestamp(envelope["issuedAt"])))
    except (ProtocolError, ValueError, TypeError, KeyError, RecursionError):
        raise CloudError("invalid_envelope") from None
    if not matches_delivery_id(parsed):
        raise CloudError("identity_mismatch")
    return parsed


def validate_admission(admission, expected_envelope, *, now_ms, node_id=None):
    """Validate recovery identity, not permission to start; expired permits stay immutable."""
    _closed(admission, ("status", "permitId", "nodeId", "permitIssuedAt", "permitExpiresAt", "envelope"))
    if (admission["status"] != "admitted" or not _uuid(admission["permitId"])
            or not _uuid(admission["nodeId"]) or (node_id is not None and admission["nodeId"] != node_id)):
        raise CloudError("invalid_response")
    try:
        issued, expires = _timestamp(admission["permitIssuedAt"]), _timestamp(admission["permitExpiresAt"])
    except (ProtocolError, TypeError):
        raise CloudError("invalid_response") from None
    if expires - issued != 5000 or issued > now_ms:
        raise CloudError("permit_expired")
    expected = _historical_envelope(expected_envelope, now_ms)
    admitted = _historical_envelope(admission["envelope"], now_ms)

    def semantic(item):
        return {key: value for key, value in item.items() if key not in ("issuedAt", "expiresAt")}

    if (semantic(admitted) != semantic(expected) or _timestamp(admitted["issuedAt"]) > issued
            or _timestamp(admitted["expiresAt"]) < expires):
        raise CloudError("identity_mismatch")
    return json.loads(_json(admission))


def _no_start_evidence(evidence, *, code):
    if not isinstance(evidence, dict):
        raise CloudError(code)
    if evidence.get("type") == "local_not_submitted":
        _closed(evidence, ("type",), code=code)
    elif evidence.get("type") == "native_terminal_no_start":
        _closed(evidence, ("type", "receiptId"), code=code)
        if not _uuid(evidence["receiptId"]):
            raise CloudError(code)
    else:
        raise CloudError(code)


def canonical_node_proof(principal, audience, path, body, proof):
    return _json(["event-node-proof-v1", principal, audience, "POST", path,
                  hashlib.sha256(body).hexdigest(), proof["nodeId"],
                  proof["nodeGeneration"], proof["issuedAt"], proof["nonce"]])


# HTTP failures expose only codes actually emitted by Event's public routes.
_ERRORS = {
    400: {"invalid", "invalid_request", "invalid_json", "invalid_body", "duplicate_json_key",
          "content_type", "content_encoding"},
    403: {"denied", "node_proof_required", "node_denied", "acknowledgment_denied"},
    404: {"not_found"}, 405: {"method_not_allowed"},
    408: {"request_timeout"},
    409: {"invalid", "conflict", "expired", "capacity", "not_found", "native_binding_unqualified", "coordinator_capacity"},
    413: {"request_too_large"}, 415: {"content_type", "content_encoding"},
    503: {"runtime_disabled", "unavailable", "authority_unavailable", "invalid_dispatch_response", "registry_unavailable"},
}
_NATIVE_COMMIT_PATHS = frozenset((
    "/v1/runtimes/attach", "/v1/runtimes/renew", "/v1/runtimes/transfer",
))


class CloudClient:
    """Closed Event API client with injected credential and HTTP ports."""

    # Ports: credentials() -> Credentials; send(**kwargs) -> (status, headers, bytes).
    # send must honor timeout, max_response_bytes and follow_redirects=False before
    # reading bytes or following any response. No default network port is installed.
    # Node generation is an immutable snapshot: construct anew after reenrollment.

    def __init__(self, *, origin, principal, agent, node_id, node_generation,
                 private_key, credentials, send, clock=time.time, nonce=uuid.uuid4):
        """Validate an immutable identity binding and inject its credential/HTTP ports."""
        if not isinstance(origin, str) or not isinstance(agent, str):
            raise CloudError("invalid_configuration")
        try:
            parsed = urlsplit(origin)
        except ValueError:
            raise CloudError("invalid_configuration") from None
        if (parsed.scheme != "https" or not parsed.hostname or len(parsed.hostname) > 253
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", parsed.hostname)
                or origin != f"https://{parsed.hostname}"
                or not _principal(principal) or not re.fullmatch(r"[a-z0-9-]{1,32}", agent)
                or not _uuid(node_id) or not _generation(node_generation)
                or not isinstance(private_key, Ed25519PrivateKey)):
            raise CloudError("invalid_configuration")
        self.origin, self.principal, self.agent = origin, principal, agent
        self.node_id, self.node_generation = node_id, node_generation
        self._key, self._credentials, self._send = private_key, credentials, send
        self._clock, self._nonce = clock, nonce

    def _sign(self, body):
        return base64.urlsafe_b64encode(self._key.sign(body)).rstrip(b"=").decode()

    async def _post_headers(self, path, body, *, node_proof, before_send):
        try:
            credential = await self._credentials()
        except TimeoutError:
            raise CloudError("request_timeout") from None
        except Exception:
            raise CloudError("unavailable") from None
        if not _valid_credentials(credential):
            raise CloudError("credentials_unavailable")
        headers = {"content-type": "application/json", "cf-access-token": credential.access_token,
                   "authorization": "Bearer " + credential.agent_token}
        if node_proof:
            proof = {"nodeId": self.node_id, "nodeGeneration": self.node_generation,
                     "issuedAt": _iso(self._clock()), "nonce": str(self._nonce())}
            if not _uuid(proof["nonce"]):
                raise CloudError("invalid_configuration")
            proof["signature"] = self._sign(canonical_node_proof(self.principal, self.origin, path, body, proof))
            headers["x-event-node-proof"] = _json(proof).decode()
            if before_send is not None:
                before_send(proof)
        return headers

    async def _send_post(self, path, headers, body):
        try:
            return await self._send(
                method="POST", url=self.origin + path, headers=headers, body=body,
                timeout=5, max_response_bytes=8192, follow_redirects=False,
            )
        except TimeoutError:
            raise CloudError("request_timeout", ambiguous=True) from None
        except Exception:
            # The transport may have sent the request before it failed.
            raise CloudError("unavailable", ambiguous=True) from None

    @staticmethod
    def _post_response(path, status, response_headers, raw):
        try:
            return _response(status, response_headers, raw)
        except CloudError as error:
            definitive_refusal = (
                status in (400, 403, 409)
                and error.code not in ("invalid_response", "unavailable", "redirect_refused")
            )
            if path in _NATIVE_COMMIT_PATHS and not definitive_refusal:
                raise CloudError(error.code, ambiguous=True) from None
            raise

    async def _post(self, path, value, *, node_proof=True, encoded_body=None, before_send=None):
        send_started = False
        try:
            async with asyncio.timeout(5):
                body = encoded_body if encoded_body is not None else _json(value)
                if len(body) > 4096:
                    raise CloudError("invalid_request")
                headers = await self._post_headers(
                    path, body, node_proof=node_proof, before_send=before_send,
                )
                send_started = True
                status, response_headers, raw = await self._send_post(path, headers, body)
                return self._post_response(path, status, response_headers, raw)
        except CloudError:
            raise
        except TimeoutError:
            code = "request_timeout"
            raise CloudError(code, ambiguous=send_started) from None
        except Exception:
            # Provider/transport errors can quote credentials: never propagate them.
            raise CloudError("unavailable", ambiguous=send_started) from None

    def _envelope(self, envelope, *, historical=False):
        try:
            now_ms = self._clock() * 1000
            if historical:
                # Relax expiration for queued work without moving the clock forward.
                now_ms = min(now_ms, _timestamp(envelope["issuedAt"]))
            parsed = parse_envelope(_json(envelope), now_ms=now_ms)
        except (ProtocolError, ValueError, TypeError, KeyError, RecursionError):
            raise CloudError("invalid_envelope") from None
        if (not matches_delivery_id(parsed) or parsed["principal"] != self.principal
                or parsed["agent"] != self.agent or parsed["nodeGeneration"] != self.node_generation):
            raise CloudError("identity_mismatch")
        return parsed

    async def claim(self, envelope):
        expected = self._envelope(envelope, historical=True)
        result = await self._post("/v1/dispatch/claim", {key: expected[key] for key in ("deliveryId", "attemptId")})
        if isinstance(result, dict) and result.get("status") == "over_budget":
            _closed(result, ("status", "budget"))
            budget = result["budget"]
            _closed(budget, ("used", "remaining", "limit", "windowMs"))
            # Budget counters reject booleans even though isinstance(True, int).
            if (any(type(budget[key]) is not int or budget[key] < 0 for key in budget)  # pylint: disable=unidiomatic-typecheck
                    or budget["limit"] != 10 or budget["windowMs"] != 3600000
                    or budget["used"] < budget["limit"]
                    or budget["remaining"] != max(0, 10 - budget["used"])):
                raise CloudError("invalid_response")
            return result
        return validate_admission(result, expected, now_ms=self._clock() * 1000, node_id=self.node_id)

    async def settle_no_start(self, admission, evidence):
        _closed(admission, ("status", "permitId", "nodeId", "permitIssuedAt", "permitExpiresAt", "envelope"))
        expected = self._envelope(admission["envelope"], historical=True)
        admitted = validate_admission(admission, expected, now_ms=self._clock() * 1000, node_id=self.node_id)
        _no_start_evidence(evidence, code="invalid_request")
        body = {key: admitted["envelope"][key] for key in ("deliveryId", "attemptId", "nodeGeneration")}
        body.update(permitId=admitted["permitId"], evidence=json.loads(_json(evidence)))
        result = await self._post("/v1/dispatch/settle-no-start", body)
        _closed(result, ("status", "deliveryId", "attemptId", "permitId", "nodeId", "nodeGeneration", "evidence"))
        _no_start_evidence(result["evidence"], code="invalid_response")
        if (not _generation(result["nodeGeneration"])
                or result != {**body, "status": "not_started", "nodeId": self.node_id}):
            raise CloudError("invalid_response")
        return result

    async def acknowledge(self, envelope, acknowledgment):
        # ACK may outlive transport freshness; future timestamps remain fenced.
        parsed = self._envelope(envelope, historical=True)
        try:
            ack = parse_acknowledgment(_json(acknowledgment), now_ms=self._clock() * 1000)
        except (ProtocolError, KeyError, TypeError, ValueError, RecursionError):
            raise CloudError("invalid_acknowledgment") from None
        if not acknowledgment_matches_delivery(parsed, ack):
            raise CloudError("identity_mismatch")
        result = await self._post("/v1/ack", ack)
        _closed(result, ("status", "current"))
        # A watermark flag must be a JSON boolean, not a truthy integer.
        if (result["status"] != ack["status"] or not isinstance(result["current"], bool)
                or (result["status"] == "submitted" and result["current"])):
            raise CloudError("invalid_response")
        return result

    async def complete_enrollment(self, challenge, *, mesh_ip, mesh_port, agents):
        # The caller supplies the reviewed owner-approved binding, never raw bytes to sign.
        _closed(challenge, ("challengeId", "nodeId", "expiresAt", "signingPayload"), code="invalid_challenge")
        if (not _uuid(challenge["challengeId"]) or challenge["nodeId"] != self.node_id
                or not isinstance(challenge["signingPayload"], str)):
            raise CloudError("invalid_challenge")
        try:
            if not isinstance(mesh_ip, str):
                raise ValueError()
            mesh_address = ipaddress.IPv4Address(mesh_ip)
            if (mesh_address not in ipaddress.IPv4Network("100.64.0.0/10")
                    # Reject bool despite its integer inheritance.
                    or type(mesh_port) is not int or not 1 <= mesh_port <= 65535  # pylint: disable=unidiomatic-typecheck
                    or not isinstance(agents, list) or not 1 <= len(agents) <= 128
                    or any(not isinstance(agent, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", agent) for agent in agents)
                    or len(set(agents)) != len(agents) or self.agent not in agents):
                raise ValueError()
            expires = _timestamp(challenge["expiresAt"])
        except (ValueError, TypeError):
            raise CloudError("invalid_challenge") from None
        public_x = base64.urlsafe_b64encode(self._key.public_key().public_bytes_raw()).rstrip(b"=").decode()
        expected = _json(["event-node-enrollment-v1", self.principal, challenge["challengeId"],
                          challenge["expiresAt"], self.node_id, public_x, str(mesh_address), mesh_port, sorted(agents)]).decode()
        now_ms = self._clock() * 1000
        if (not now_ms < expires <= now_ms + 300000
                or challenge["signingPayload"] != expected):
            raise CloudError("invalid_challenge")
        result = await self._post("/v1/nodes/complete", {"challengeId": challenge["challengeId"],
                                  "signature": self._sign(expected.encode())}, node_proof=False)
        _closed(result, ("nodeId", "generation"))
        if not _uuid(result["nodeId"]) or not _generation(result["generation"]):
            raise CloudError("invalid_response")
        if result["nodeId"] != self.node_id or result["generation"] != self.node_generation:
            raise CloudError("identity_mismatch")
        return result

    async def native_challenge(self, request):
        """Record one exact attach, renew, or transfer intent before local sampling."""
        request = _native_challenge_request(request)
        result = await self._post("/v1/runtimes/challenge", request)
        return _native_challenge_response(result)

    async def attach(self, request, challenge, native_evidence, *, prepared_body=None,
                     on_first_send=None, recovery=False):
        """Commit one challenged attach and validate its exact owned mapping."""
        return await self._native_commit(
            "attach", request, challenge, native_evidence, prepared_body=prepared_body,
            on_first_send=on_first_send, recovery=recovery,
        )

    async def renew(self, request, challenge, native_evidence, *, prepared_body=None,
                    on_first_send=None, recovery=False):
        """Commit one challenged lease renewal without changing generations."""
        return await self._native_commit(
            "renew", request, challenge, native_evidence, prepared_body=prepared_body,
            on_first_send=on_first_send, recovery=recovery,
        )

    async def transfer(self, request, challenge, native_evidence, *, prepared_body=None,
                       on_first_send=None, recovery=False):
        """Atomically revoke the source and bind the replacement using both CAS pairs."""
        return await self._native_commit(
            "transfer", request, challenge, native_evidence, prepared_body=prepared_body,
            on_first_send=on_first_send, recovery=recovery,
        )

    def _native_commit_validator(self, operation, request):
        return {
            "attach": lambda value: _native_attached_response(value, "attached", request, self),
            "renew": lambda value: _native_attached_response(value, "renewed", request, self),
            "transfer": lambda value: _native_transfer_response(value, request, self),
        }[operation]

    async def _retry_native_commit(self, path, body, body_bytes, before_send, response_validator):
        ambiguous_prior = False
        for attempt in range(2):
            try:
                response = await self._post(
                    path, body, encoded_body=body_bytes,
                    before_send=partial(before_send, attempt=attempt),
                )
            except CloudError as error:
                if attempt == 0 and error.ambiguous:
                    ambiguous_prior = True
                    continue
                if ambiguous_prior:
                    raise CloudError(error.code, ambiguous=True) from None
                raise
            try:
                return response_validator(response)
            except CloudError as error:
                # A 200 response with an invalid body can follow a committed request.
                raise CloudError(error.code, ambiguous=True) from None
        raise CloudError("commit_outcome_unknown", ambiguous=True)

    async def _native_commit(self, operation, request, challenge, native_evidence, *,
                             prepared_body=None, on_first_send=None, recovery=False):
        request = _native_challenge_request(request)
        if request["operation"] != operation:
            raise CloudError("invalid_request")
        challenge = _native_challenge_response(challenge)
        if recovery:
            evidence = _native_evidence(native_evidence, request["expectedNativeBinding"])
            deadline = None
        else:
            evidence, deadline = _native_local_evidence(
                native_evidence, request["expectedNativeBinding"],
            )
        timing = _native_commit_timing(challenge, evidence)
        body = _native_commit_body(operation, request, challenge, evidence)
        body_bytes = _prepared_native_commit_body(prepared_body, body)
        path = f"/v1/runtimes/{operation}"
        before_send = _native_commit_send_fence(
            on_first_send, body_bytes, recovery=recovery, deadline=deadline,
            observed_at=timing[0], challenge_issued=timing[1],
            challenge_expires=timing[2], witness_lease=timing[3],
        )
        return await self._retry_native_commit(
            path, body, body_bytes, before_send, self._native_commit_validator(operation, request),
        )
