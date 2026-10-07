"""Closed Event control-plane client. Injected ports only; no CLI/native path."""

import asyncio
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import time
from urllib.parse import urlsplit
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .protocol import (
    ProtocolError, _SCHEMA, _depth, _pairs, _timestamp, acknowledgment_matches_delivery,
    matches_delivery_id, parse_acknowledgment, parse_envelope,
)


class CloudError(ValueError):
    """Only fixed local/server codes escape the credential boundary."""

    def __init__(self, code):
        """Store the error code."""
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Credentials:
    access_token: str = field(repr=False)
    agent_token: str = field(repr=False)


def _json(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


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


_PRINCIPAL_SCHEMA = _SCHEMA["anyOf"][0]["anyOf"][0]["properties"]["principal"]


def _principal(value):
    return (isinstance(value, str) and len(value) <= _PRINCIPAL_SCHEMA["maxLength"]
            and re.fullmatch(_PRINCIPAL_SCHEMA["pattern"], value) is not None)


def _iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


async def _call(port, **kwargs):
    try:
        return await port(**kwargs)
    except TimeoutError:
        raise
    except Exception:
        raise CloudError("unavailable") from None


def canonical_node_proof(principal, audience, path, body, proof):
    return _json(["event-node-proof-v1", principal, audience, "POST", path,
                  hashlib.sha256(body).hexdigest(), proof["nodeId"],
                  proof["nodeGeneration"], proof["issuedAt"], proof["nonce"]])


# HTTP failures expose only codes actually emitted by Event's public routes.
_ERRORS = {
    400: {"invalid", "invalid_request", "invalid_json", "duplicate_json_key", "content_type", "content_encoding"},
    403: {"denied", "node_proof_required", "node_denied", "acknowledgment_denied"},
    404: {"not_found"}, 405: {"method_not_allowed"},
    408: {"request_timeout"},
    409: {"invalid", "conflict", "expired", "capacity", "not_found", "native_binding_unqualified", "coordinator_capacity"},
    413: {"request_too_large"}, 415: {"content_type", "content_encoding"},
    503: {"runtime_disabled", "unavailable", "authority_unavailable", "invalid_dispatch_response", "registry_unavailable"},
}


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

    async def _post(self, path, value, *, node_proof=True):
        try:
            async with asyncio.timeout(5):
                body = _json(value)
                if len(body) > 4096:
                    raise CloudError("invalid_request")
                credential = await _call(self._credentials)
                if not isinstance(credential, Credentials) or any(
                    not isinstance(token, str) or not token or len(token) > 16384
                    or re.search(r"\s", token)
                    for token in (credential.access_token, credential.agent_token)
                ) or len(credential.agent_token) > 4096:
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
                status, response_headers, raw = await _call(
                    self._send, method="POST", url=self.origin + path, headers=headers, body=body,
                    timeout=5, max_response_bytes=8192, follow_redirects=False,
                )
                return _response(status, response_headers, raw)
        except CloudError:
            raise
        except TimeoutError:
            raise CloudError("request_timeout") from None
        except Exception:
            # Provider/transport errors can quote credentials: never propagate them.
            raise CloudError("unavailable") from None

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
        _closed(result, ("status", "permitId", "nodeId", "permitIssuedAt", "permitExpiresAt", "envelope"))
        if result["status"] != "admitted" or not _uuid(result["permitId"]) or result["nodeId"] != self.node_id:
            raise CloudError("invalid_response")
        try:
            issued, expires = _timestamp(result["permitIssuedAt"]), _timestamp(result["permitExpiresAt"])
        except (ProtocolError, TypeError):
            raise CloudError("invalid_response") from None
        if expires - issued != 5000 or not issued <= self._clock() * 1000 < expires:
            raise CloudError("permit_expired")
        admitted = self._envelope(result["envelope"])
        # Only transport lifetime may refresh at admission. All semantic fields bind.

        def semantic(item):
            return {key: value for key, value in item.items() if key not in ("issuedAt", "expiresAt")}
        if (semantic(admitted) != semantic(expected) or _timestamp(admitted["issuedAt"]) > issued
                or _timestamp(admitted["expiresAt"]) < expires):
            raise CloudError("identity_mismatch")
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

    async def attach(self, runtime_id):
        return await self._unqualified("/v1/runtimes/attach", runtime_id)

    async def renew(self, runtime_id):
        return await self._unqualified("/v1/runtimes/renew", runtime_id)

    async def _unqualified(self, path, runtime_id):
        if not _uuid(runtime_id):
            raise CloudError("invalid_request")
        await self._post(path, {"runtimeId": runtime_id})
        raise CloudError("native_binding_unqualified")
