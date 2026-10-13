"""NOT_READY: fixture-only ports; no network, native, credentials or process launcher."""

import base64
import binascii
import copy
from datetime import datetime
import fcntl
import hashlib
import io
import json
import logging
import math
import os
import re
from pathlib import Path
import stat
import time
from urllib.parse import urlsplit

LIMITS = {"publication": 7, "nativeStart": 4, "restart": 3}
MAX_JOURNAL = 1024 * 1024
CASE_ORDER = ("A1", "B1", "C1", "C2", "C3", "B2", "A2")
NATIVE_BINDING_FIELDS = (
    "clientId",
    "connectionId",
    "backendPid",
    "threadId",
    "generation",
    "serverInstanceId",
    "serverGeneration",
)
PHASE_SCHEMAS = {
    "begin_case": {"caseId"},
    "publication_intent": {"caseId", "subject", "eventSha256", "requestSha256"},
    "publication_result": {"caseId", "outcome", "responseSha256"},
    "claim_intent": {"caseId", "subject", "requestSha256"},
    "claim_result": {"caseId", "outcome", "responseSha256"},
    "start_intent": {"caseId", "subject", "requestSha256"},
    "start_outcome": {"caseId", "requestSha256", "outcome", "receiptSha256"},
    "ack_latch": {
        "caseId",
        "phase",
        "requestSha256",
        "storeWitnessSha256",
        "deliveryId",
        "attemptId",
        "eventId",
        "permitId",
        "turnId",
        "itemId",
    },
    "ack_complete": {"caseId", "phase", "requestSha256", "responseSha256", "current"},
    "queue_c2": {"caseId", "storeWitnessSha256"},
    "restart_intent": {
        "token",
        "caseId",
        "reason",
        "oldPid",
        "oldStartId",
        "socketSha256",
    },
    "restart_complete": {"token", "newPid", "newStartId"},
    "reattach": {
        "oldCaseId",
        "newCaseId",
        "oldEventSha256",
        "newEventSha256",
        "oldBinding",
        "newBinding",
        "expectedRuntimeGeneration",
        "expectedAttachmentGeneration",
        "runtimeGeneration",
        "attachmentGeneration",
    },
    "complete_case": {"caseId", "attemptId", "storeAckState", "storeWitnessSha256"},
}


class Refused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def exact_type(value, expected):
    """Use exact JSON-native types; in particular, bool must not pass as int."""
    return type(value) is expected  # pylint: disable=unidiomatic-typecheck


def encoded(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def invalid(_value):
        raise Refused("nonfinite_json")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def uuid(value):
    """Match the event protocol's lowercase UUID v4/v7 identifier contract."""
    return (
        exact_type(value, str)
        and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            value,
        )
        is not None
    )


def _validate_ack_target_pair(targets):
    """Require submitted and observed ACKs to refer to the same event/runtime."""
    submitted = targets["submitted"]
    observed = targets["observed"]
    shared_request_fields = (
        "deliveryId",
        "attemptId",
        "nodeGeneration",
        "eventId",
        "runtimeId",
        "schemaVersion",
        "principal",
        "agent",
        "runtimeGeneration",
        "attachmentGeneration",
        "deliveredSourceStateVersion",
    )
    require(
        submitted["subject"] == observed["subject"]
        and submitted["nodeId"] == observed["nodeId"]
        and all(
            submitted["request"][key] == observed["request"][key]
            for key in shared_request_fields
        )
        and submitted["request"]["nativeCorrelation"]["permitId"]
        == observed["request"]["nativeCorrelation"]["permitId"]
        and submitted["request"]["nativeCorrelation"]["turnId"]
        == observed["request"]["nativeCorrelation"]["turnId"]
        and (
            ("consumerGeneration" in submitted["request"])
            == ("consumerGeneration" in observed["request"])
        )
        and (
            "consumerGeneration" not in submitted["request"]
            or submitted["request"]["consumerGeneration"]
            == observed["request"]["consumerGeneration"]
        ),
        "ack_event_identity_mismatch",
    )


def manifest_checked(value):
    require(
        exact_type(value, dict)
        and set(value) == {"version", "origin", "subjects", "targets", "claims"}
        and exact_type(value["version"], int)
        and value["version"] == 1,
        "invalid_manifest",
    )
    origin = value["origin"]
    require(exact_type(origin, str), "invalid_origin")
    try:
        parsed = urlsplit(origin)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and parsed.port is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and origin == "https://" + parsed.hostname
            and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", parsed.hostname)
        )
    except ValueError:
        valid = False
    require(valid, "invalid_origin")
    subjects = value["subjects"]
    require(
        exact_type(subjects, list)
        and 1 <= len(subjects) <= 7
        and len(set(subjects)) == len(subjects)
        and all(exact_type(s, str) and 0 < len(s) <= 128 for s in subjects),
        "invalid_subjects",
    )
    require(
        exact_type(value["targets"], dict)
        and set(value["targets"]) == {"submitted", "observed", "settle"},
        "invalid_targets",
    )
    for action, target in value["targets"].items():
        require(
            exact_type(target, dict)
            and set(target)
            in (
                {"subject", "request", "nodeId"},
                {"subject", "request", "nodeId", "wireSha256"},
            )
            and target["subject"] in subjects
            and uuid(target["nodeId"]),
            "invalid_target",
        )
        require(
            "wireSha256" not in target or hash_text(target["wireSha256"]),
            "invalid_target_wire_hash",
        )
        request = target["request"]
        require(
            exact_type(request, dict)
            and exact_type(request.get("deliveryId"), str)
            and re.fullmatch(r"dly_[0-9a-f]{64}", request["deliveryId"])
            and uuid(request.get("attemptId"))
            and exact_type(request.get("nodeGeneration"), int)
            and request["nodeGeneration"] > 0,
            "invalid_target_identity",
        )
        if action == "settle":
            require(
                set(request)
                == {"deliveryId", "attemptId", "nodeGeneration", "permitId", "evidence"}
                and uuid(request["permitId"])
                and exact_type(request["evidence"], dict)
                and set(request["evidence"]) == {"type", "receiptId"}
                and request["evidence"]["type"] == "native_terminal_no_start"
                and uuid(request["evidence"]["receiptId"]),
                "invalid_terminal_target",
            )
        else:
            required = {
                "schemaVersion",
                "eventId",
                "deliveryId",
                "attemptId",
                "principal",
                "agent",
                "runtimeId",
                "nodeGeneration",
                "runtimeGeneration",
                "attachmentGeneration",
                "deliveredSourceStateVersion",
                "acknowledgedAt",
                "status",
                "nativeCorrelation",
            }
            require(
                set(request) in (required, required | {"consumerGeneration"})
                and exact_type(request["schemaVersion"], int)
                and request["schemaVersion"] == 1
                and all(uuid(request[k]) for k in ("eventId", "runtimeId"))
                and all(
                    exact_type(request[k], int) and 0 < request[k] < 2**53
                    for k in (
                        "nodeGeneration",
                        "runtimeGeneration",
                        "attachmentGeneration",
                    )
                )
                and (
                    "consumerGeneration" not in request
                    or exact_type(request["consumerGeneration"], int)
                    and 0 < request["consumerGeneration"] < 2**53
                )
                and all(
                    exact_type(request[k], str) and 0 < len(request[k]) <= 256
                    for k in ("principal", "agent", "deliveredSourceStateVersion")
                )
                and exact_type(request["acknowledgedAt"], str)
                and re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",
                    request["acknowledgedAt"],
                ),
                "invalid_closed_ack_schema",
            )
            try:
                datetime.fromisoformat(request["acknowledgedAt"].replace("Z", "+00:00"))
            except ValueError:
                raise Refused("invalid_closed_ack_schema") from None
            require(
                request.get("status") == action
                and exact_type(request.get("nativeCorrelation"), dict),
                "invalid_ack_target",
            )
            correlation = request["nativeCorrelation"]
            keys = {"kind", "permitId", "turnId"} | (
                {"itemId"} if action == "observed" else set()
            )
            require(
                set(correlation) == keys
                and correlation["kind"]
                == (
                    "native_input_recorded"
                    if action == "observed"
                    else "native_turn_started"
                )
                and all(uuid(correlation[k]) for k in keys - {"kind"}),
                "invalid_native_correlation",
            )
    _validate_ack_target_pair(value["targets"])
    require(
        exact_type(value["claims"], list) and len(value["claims"]) <= 7,
        "invalid_claims",
    )
    for claim in value["claims"]:
        require(
            exact_type(claim, dict)
            and set(claim) == {"subject", "request"}
            and claim["subject"] in subjects
            and exact_type(claim["request"], dict)
            and set(claim["request"]) == {"deliveryId", "attemptId"}
            and exact_type(claim["request"]["deliveryId"], str)
            and re.fullmatch(r"dly_[0-9a-f]{64}", claim["request"]["deliveryId"])
            and uuid(claim["request"]["attemptId"]),
            "invalid_claim",
        )
    require(len(encoded(value)) <= 32768, "manifest_too_large")
    return decode(encoded(value))


def valid_response(manifest, action, value):
    target = manifest["targets"][action]
    if action == "settle":
        return exact_type(value, dict) and encoded(value) == encoded(
            {**target["request"], "nodeId": target["nodeId"], "status": "not_started"}
        )
    return (
        exact_type(value, dict)
        and set(value) == {"status", "current"}
        and value["status"] == action
        and exact_type(value["current"], bool)
        and (action != "submitted" or value["current"] is False)
    )


def hash_text(value):
    return exact_type(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def raw_response_matches(value):
    """Check the returned replay's captured raw body against its exact digest."""
    encoded_body = value.get("responseRawBase64")
    if not exact_type(encoded_body, str):
        return False
    try:
        raw = base64.b64decode(encoded_body, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(raw) > 8192 or base64.b64encode(raw).decode("ascii") != encoded_body:
        return False
    if digest(raw) != value.get("responseSha256"):
        return False
    try:
        return encoded(decode(raw)) == encoded(value.get("response"))
    except (Refused, TypeError, ValueError):
        return False


def target_request_sha256(target):
    return target.get("wireSha256", digest(encoded(target["request"])))


def phase_plan_checked(value, manifest):
    require(
        exact_type(value, dict)
        and set(value)
        == {
            "version",
            "order",
            "cases",
            "faultTargets",
            "nativeBusySignal",
        }
        and exact_type(value["version"], int)
        and value["version"] == 1,
        "invalid_phase_plan",
    )
    require(
        value["order"] == list(CASE_ORDER)
        and exact_type(value["cases"], dict)
        and set(value["cases"]) == set(CASE_ORDER),
        "invalid_phase_order",
    )
    cases = value["cases"]
    require(
        exact_type(value["faultTargets"], dict)
        and value["faultTargets"] == {"submitted": "A1", "observed": "A1"},
        "invalid_fault_targets",
    )
    subjects = []
    for case_id in CASE_ORDER:
        case = cases[case_id]
        require(
            exact_type(case, dict)
            and set(case)
            == {
                "subject",
                "eventSha256",
                "publicationSha256",
                "claimSha256",
                "startSha256",
                "binding",
                "nodeGeneration",
                "runtimeGeneration",
                "attachmentGeneration",
            },
            "invalid_phase_case",
        )
        subjects.append(case["subject"])
        dynamic_c3 = case_id == "C3"
        require(
            exact_type(case["subject"], str)
            and 0 < len(case["subject"]) <= 128
            and (dynamic_c3 or hash_text(case["eventSha256"]))
            and (dynamic_c3 or hash_text(case["publicationSha256"]))
            and (case_id in ("C2", "C3") or hash_text(case["claimSha256"]))
            and (case_id in ("C2", "B2", "A2", "C3") or hash_text(case["startSha256"])),
            "invalid_phase_case_identity",
        )
        if dynamic_c3:
            require(
                case["eventSha256"] is None
                and case["publicationSha256"] is None
                and case["claimSha256"] is None
                and case["startSha256"] is None
                and case["binding"] is None
                and case["runtimeGeneration"] is None
                and case["attachmentGeneration"] is None,
                "c3_must_be_bound_by_reattach_readback",
            )
        elif case_id == "C2":
            require(
                case["claimSha256"] is None and case["startSha256"] is None,
                "c2_must_not_claim_or_start",
            )
        if not dynamic_c3:
            require(
                exact_type(case["binding"], dict)
                and set(case["binding"]) == set(NATIVE_BINDING_FIELDS)
                and all(
                    uuid(case["binding"][key])
                    for key in (
                        "clientId",
                        "connectionId",
                        "threadId",
                        "serverInstanceId",
                    )
                )
                and exact_type(case["binding"]["backendPid"], int)
                and 0 < case["binding"]["backendPid"] < 2**32
                and all(
                    exact_type(case["binding"][key], int)
                    and 0 < case["binding"][key] < 2**53
                    for key in ("generation", "serverGeneration")
                )
                and all(
                    exact_type(case[key], int) and 0 < case[key] < 2**53
                    for key in (
                        "nodeGeneration",
                        "runtimeGeneration",
                        "attachmentGeneration",
                    )
                ),
                "invalid_phase_binding",
            )
        if dynamic_c3:
            require(
                exact_type(case["nodeGeneration"], int)
                and 0 < case["nodeGeneration"] < 2**53,
                "invalid_phase_binding",
            )
    require(
        len(set(subjects)) == len(CASE_ORDER) and subjects == manifest["subjects"],
        "phase_subjects_mismatch",
    )
    require(
        cases["C3"]["nodeGeneration"] == cases["C2"]["nodeGeneration"],
        "reattach_node_generation_changed",
    )
    for claim in manifest["claims"]:
        case = next(
            (item for item in cases.values() if item["subject"] == claim["subject"]),
            None,
        )
        require(
            case is not None
            and case["claimSha256"] is not None
            and digest(encoded(claim["request"])) == case["claimSha256"],
            "phase_claim_mismatch",
        )
    require(
        {item["subject"] for item in manifest["claims"]}
        == set(subjects) - {cases["C2"]["subject"], cases["C3"]["subject"]},
        "phase_claim_coverage",
    )
    for action, case_id in value["faultTargets"].items():
        require(
            manifest["targets"][action]["subject"] == cases[case_id]["subject"],
            "phase_fault_target_mismatch",
        )
    # This slice cannot qualify the developing Core busy signal. A manifest
    # boolean/hash is not proof that the native bridge observed it safely.
    require(
        value["nativeBusySignal"] is None,
        "native_busy_signal_requires_reviewed_bridge_proof",
    )
    require(len(encoded(value)) <= 32768, "phase_plan_too_large")
    return decode(encoded(value))


def _new_phase_state():
    return {
        "nextIndex": 0,
        "active": None,
        "cases": {
            case_id: {
                "begun": False,
                "publicationIntent": None,
                "publicationOutcome": None,
                "claimIntent": None,
                "claimOutcome": None,
                "startIntent": None,
                "startOutcome": None,
                "ackLatches": {},
                "faults": {},
                "complete": False,
                "queued": False,
            }
            for case_id in CASE_ORDER
        },
        "publications": 0,
        "startAttempts": 0,
        "acceptedStarts": 0,
        "restartTokens": {},
        "reattached": False,
        "reattachReadback": None,
        "nativeSignalGateRefused": False,
    }


def _apply_fault_projection(plan, state, kind, value):
    """Derive fault-phase readiness from the same append-only transport records."""
    if plan is None or kind not in (
        "arm",
        "hold",
        "replay",
        "returned",
        "witness",
        "send",
    ):
        return
    require("caseId" in value, "phase_transport_case_required")
    case_id, action = value["caseId"], value.get("action")
    require(
        case_id in CASE_ORDER and state["active"] == case_id,
        "phase_transport_out_of_case",
    )
    if kind == "send" and action is None:
        phase_case = state["cases"][case_id]
        require(
            phase_case["claimIntent"] == value["requestSha256"]
            and phase_case["claimOutcome"] is None,
            "phase_claim_send_without_intent",
        )
        return
    require(
        case_id == "A1"
        and action in plan["faultTargets"]
        and plan["faultTargets"][action] == case_id,
        "unallocated_phase_fault",
    )
    phase_case = state["cases"][case_id]
    fault = phase_case["faults"].setdefault(
        action,
        {
            "armed": False,
            "held": False,
            "replay": False,
            "returned": False,
            "returnedResponseSha256": None,
            "returnedCurrent": None,
            "witnessed": False,
        },
    )
    if kind == "send":
        latch = phase_case["ackLatches"].get(action)
        require(
            latch is not None and latch["requestSha256"] == value["requestSha256"],
            "phase_ack_send_without_exact_latch",
        )
        require(
            latch["storeWitnessSha256"] == digest(encoded(value["durableBeforeSend"])),
            "phase_ack_store_witness_changed",
        )
        if value["replay"]:
            require(fault["held"] and fault["replay"], "phase_replay_before_restart")
        else:
            require(fault["armed"] and not fault["witnessed"], "phase_send_without_arm")
    elif kind == "arm":
        require(
            not fault["armed"] and phase_case["ackLatches"].get(action) is not None,
            "phase_duplicate_fault",
        )
        fault["armed"] = True
    elif kind == "witness":
        require(fault["armed"] and not fault["witnessed"], "phase_commit_witness_order")
        fault["witnessed"] = True
    elif kind == "hold":
        require(fault["witnessed"] and not fault["held"], "phase_hold_without_commit")
        fault["held"] = True
    elif kind == "replay":
        require(fault["held"] and not fault["replay"], "phase_replay_before_restart")
        restart_id = "R1" if action == "submitted" else "R2"
        require(
            state["restartTokens"].get(restart_id, {}).get("complete") is True,
            "phase_replay_before_owned_restart",
        )
        fault["replay"] = True
    elif kind == "returned":
        require(
            fault["replay"] and not fault["returned"], "phase_return_without_replay"
        )
        fault["returned"] = True
        fault["returnedResponseSha256"] = value["responseSha256"]
        fault["returnedCurrent"] = value["response"].get("current")


def _phase_begin_case(plan, state, fields, manifest, case_id, cases):
    """Apply the validated begin_case transition to the projected state."""
    require(
        state["active"] is None
        and state["nextIndex"] < len(CASE_ORDER)
        and case_id == CASE_ORDER[state["nextIndex"]],
        "case_order_violation",
    )
    if state["nextIndex"]:
        previous = CASE_ORDER[state["nextIndex"] - 1]
        require(cases[previous]["complete"], "previous_case_incomplete")
    if case_id == "C2":
        state["nativeSignalGateRefused"] = plan["nativeBusySignal"] is None
        require(plan["nativeBusySignal"] is not None, "native_busy_signal_unqualified")
    if case_id == "C3":
        require(state["reattached"], "reattach_not_recorded")
    state["active"] = case_id
    state["nextIndex"] += 1
    cases[case_id]["begun"] = True


def _phase_publication_intent(plan, state, fields, manifest, case_id, cases):
    """Apply the validated publication_intent transition to the projected state."""
    case = cases[case_id]
    expected = plan["cases"][case_id]
    if case_id == "C3":
        require(state["reattachReadback"] is not None, "reattach_not_recorded")
        expected_event_sha = state["reattachReadback"]["eventSha256"]
    else:
        expected_event_sha = expected["eventSha256"]
    require(
        state["active"] == case_id
        and case["publicationIntent"] is None
        and fields["subject"] == expected["subject"]
        and fields["eventSha256"] == expected_event_sha
        and hash_text(fields["requestSha256"])
        and (
            expected["publicationSha256"] is None
            or fields["requestSha256"] == expected["publicationSha256"]
        ),
        "invalid_publication_intent",
    )
    require(state["publications"] < LIMITS["publication"], "budget_exhausted")
    case["publicationIntent"] = fields["requestSha256"]
    state["publications"] += 1


def _phase_publication_result(plan, state, fields, manifest, case_id, cases):
    """Apply the validated publication_result transition to the projected state."""
    case = cases[case_id]
    require(
        state["active"] == case_id
        and case["publicationIntent"] is not None
        and case["publicationOutcome"] is None
        and fields["outcome"] in ("accepted", "refused", "ambiguous")
        and (
            (fields["outcome"] == "ambiguous" and fields["responseSha256"] is None)
            or hash_text(fields["responseSha256"])
        ),
        "invalid_publication_result",
    )
    case["publicationOutcome"] = fields["outcome"]


def _phase_claim_intent(plan, state, fields, manifest, case_id, cases):
    """Apply the validated claim_intent transition to the projected state."""
    case = cases[case_id]
    expected = plan["cases"][case_id]
    require(
        state["active"] == case_id
        and case["publicationOutcome"] == "accepted"
        and case["claimIntent"] is None
        and case_id in ("A1", "B1", "C1", "C3", "B2", "A2")
        and fields["subject"] == expected["subject"]
        and hash_text(fields["requestSha256"])
        and (
            expected["claimSha256"] is None
            or fields["requestSha256"] == expected["claimSha256"]
        ),
        "replacement_claim_fenced",
    )
    case["claimIntent"] = fields["requestSha256"]


def _phase_claim_result(plan, state, fields, manifest, case_id, cases):
    """Apply the validated claim_result transition to the projected state."""
    case = cases[case_id]
    require(
        state["active"] == case_id
        and case["claimIntent"] is not None
        and case["claimOutcome"] is None
        and fields["outcome"] in ("accepted", "refused", "ambiguous")
        and (
            (fields["outcome"] == "ambiguous" and fields["responseSha256"] is None)
            or hash_text(fields["responseSha256"])
        ),
        "invalid_claim_result",
    )
    case["claimOutcome"] = fields["outcome"]


def _phase_start_intent(plan, state, fields, manifest, case_id, cases):
    """Apply the validated start_intent transition to the projected state."""
    case = cases[case_id]
    require(
        state["active"] == case_id
        and case["claimIntent"] is not None
        and case["claimOutcome"] == "accepted"
        and case["startIntent"] is None
        and case_id in ("A1", "B1", "C1", "C3")
        and fields["subject"] == plan["cases"][case_id]["subject"]
        and hash_text(fields["requestSha256"])
        and (
            plan["cases"][case_id]["startSha256"] is None
            or fields["requestSha256"] == plan["cases"][case_id]["startSha256"]
        ),
        "invalid_native_start_intent",
    )
    require(state["startAttempts"] < LIMITS["nativeStart"], "budget_exhausted")
    case["startIntent"] = fields["requestSha256"]
    state["startAttempts"] += 1


def _phase_start_outcome(plan, state, fields, manifest, case_id, cases):
    """Apply the validated start_outcome transition to the projected state."""
    case = cases[case_id]
    require(
        state["active"] == case_id
        and case["startIntent"] == fields["requestSha256"]
        and case["startOutcome"] is None
        and fields["outcome"] in ("started", "terminalNotStarted", "unknown")
        and hash_text(fields["receiptSha256"]),
        "invalid_native_start_outcome",
    )
    case["startOutcome"] = fields["outcome"]
    if fields["outcome"] == "started":
        require(
            state["acceptedStarts"] < LIMITS["nativeStart"],
            "accepted_start_budget_exhausted",
        )
        state["acceptedStarts"] += 1


def _phase_ack_latch(plan, state, fields, manifest, case_id, cases):
    """Apply the validated ack_latch transition to the projected state."""
    case = cases[case_id]
    phase = fields["phase"]
    target_record = None if manifest is None else manifest["targets"].get(phase)
    target = None if target_record is None else target_record["request"]
    require(
        state["active"] == case_id
        and case["startOutcome"] == "started"
        and phase in ("submitted", "observed")
        and phase not in case["ackLatches"]
        and hash_text(fields["requestSha256"])
        and hash_text(fields["storeWitnessSha256"]),
        "invalid_ack_latch",
    )
    require(
        target is not None
        and fields["requestSha256"] == target_request_sha256(target_record)
        and fields["deliveryId"] == target["deliveryId"]
        and fields["attemptId"] == target["attemptId"]
        and fields["eventId"] == target["eventId"]
        and fields["permitId"] == target["nativeCorrelation"]["permitId"]
        and fields["turnId"] == target["nativeCorrelation"]["turnId"]
        and fields["itemId"] == target["nativeCorrelation"].get("itemId"),
        "ack_latch_identity_mismatch",
    )
    if phase == "observed":
        require("submitted" in case["ackLatches"], "observed_before_submitted_latch")
    case["ackLatches"][phase] = {
        "requestSha256": fields["requestSha256"],
        "storeWitnessSha256": fields["storeWitnessSha256"],
        "deliveryId": fields["deliveryId"],
        "attemptId": fields["attemptId"],
        "eventId": fields["eventId"],
        "permitId": fields["permitId"],
        "turnId": fields["turnId"],
        "itemId": fields["itemId"],
        "complete": None,
    }


def _phase_ack_complete(plan, state, fields, manifest, case_id, cases):
    """Apply the validated ack_complete transition to the projected state."""
    case = cases[case_id]
    phase = fields["phase"]
    latch = case["ackLatches"].get(phase)
    require(
        state["active"] == case_id
        and latch is not None
        and latch["complete"] is None
        and latch["requestSha256"] == fields["requestSha256"]
        and hash_text(fields["responseSha256"])
        and exact_type(fields["current"], bool)
        and (phase != "submitted" or fields["current"] is False),
        "invalid_ack_completion",
    )
    fault = case["faults"].get(phase, {})
    require(
        fault.get("returned") is True
        and fault.get("returnedResponseSha256") == fields["responseSha256"]
        and fault.get("returnedCurrent") == fields["current"],
        "ack_completion_without_returned_replay",
    )
    latch["complete"] = {
        "responseSha256": fields["responseSha256"],
        "current": fields["current"],
    }


def _phase_queue_c2(plan, state, fields, manifest, case_id, cases):
    """Apply the validated queue_c2 transition to the projected state."""
    case = cases["C2"]
    require(
        state["active"] == "C2"
        and case["publicationOutcome"] == "accepted"
        and case["claimIntent"] is None
        and not case["queued"]
        and plan["nativeBusySignal"] is not None
        and hash_text(fields["storeWitnessSha256"]),
        "c2_queue_unqualified",
    )
    case["queued"] = True


def _phase_restart_intent(plan, state, fields, manifest, case_id, cases):
    """Apply the validated restart_intent transition to the projected state."""
    restart_id = fields["token"]
    reason_for = {
        "R1": ("A1", "after_submitted_ack"),
        "R2": ("A1", "after_observed_ack_commit"),
        "R3": ("C2", "after_c2_queued"),
    }
    require(
        restart_id in reason_for
        and restart_id not in state["restartTokens"]
        and len(state["restartTokens"]) < LIMITS["restart"]
        and (case_id, fields["reason"]) == reason_for[restart_id]
        and state["active"] == case_id
        and exact_type(fields["oldPid"], int)
        and fields["oldPid"] > 0
        and exact_type(fields["oldStartId"], str)
        and 0 < len(fields["oldStartId"]) <= 128
        and hash_text(fields["socketSha256"]),
        "invalid_restart_intent",
    )
    case = cases[case_id]
    if restart_id == "R1":
        require(
            case["faults"].get("submitted", {}).get("held") is True,
            "submitted_ack_boundary_missing",
        )
    elif restart_id == "R2":
        require(
            "R1" in state["restartTokens"]
            and state["restartTokens"]["R1"]["complete"]
            and case["ackLatches"].get("submitted", {}).get("complete") is not None
            and case["faults"].get("observed", {}).get("held") is True,
            "observed_ack_boundary_missing",
        )
    else:
        require(case["queued"], "c2_queue_boundary_missing")
    _validate_restart_predecessor(state, restart_id, fields)
    state["restartTokens"][restart_id] = {
        "caseId": case_id,
        "oldPid": fields["oldPid"],
        "oldStartId": fields["oldStartId"],
        "socketSha256": fields["socketSha256"],
        "complete": False,
    }


def _validate_restart_predecessor(state, restart_id, fields):
    """Bind each later restart intent to the preceding completion identity."""
    predecessor_id = {"R2": "R1", "R3": "R2"}.get(restart_id)
    if predecessor_id is None:
        return
    predecessor = state["restartTokens"].get(predecessor_id)
    require(
        predecessor is not None
        and predecessor["complete"] is True
        and fields["oldPid"] == predecessor["newPid"]
        and fields["oldStartId"] == predecessor["newStartId"],
        "restart_identity_not_chained",
    )


def _phase_restart_complete(plan, state, fields, manifest, case_id, cases):
    """Apply the validated restart_complete transition to the projected state."""
    restart_id = fields["token"]
    restart = state["restartTokens"].get(restart_id)
    require(
        restart is not None
        and not restart["complete"]
        and exact_type(fields["newPid"], int)
        and fields["newPid"] > 0
        and exact_type(fields["newStartId"], str)
        and 0 < len(fields["newStartId"]) <= 128
        and (
            fields["newPid"] != restart["oldPid"]
            or fields["newStartId"] != restart["oldStartId"]
        ),
        "invalid_restart_completion",
    )
    restart.update(
        newPid=fields["newPid"], newStartId=fields["newStartId"], complete=True
    )


def _phase_reattach(plan, state, fields, manifest, case_id, cases):
    """Apply the validated reattach transition to the projected state."""
    require(
        state["active"] == "C2"
        and fields["oldCaseId"] == "C2"
        and fields["newCaseId"] == "C3"
        and state["cases"]["C2"]["queued"]
        and state["restartTokens"].get("R3", {}).get("complete") is True
        and hash_text(fields["oldEventSha256"])
        and hash_text(fields["newEventSha256"])
        and fields["oldEventSha256"] == plan["cases"]["C2"]["eventSha256"]
        and exact_type(fields["oldBinding"], dict)
        and fields["oldBinding"] == plan["cases"]["C2"]["binding"]
        and exact_type(fields["newBinding"], dict)
        and fields["expectedRuntimeGeneration"]
        == plan["cases"]["C2"]["runtimeGeneration"]
        and fields["expectedAttachmentGeneration"]
        == plan["cases"]["C2"]["attachmentGeneration"]
        and fields["runtimeGeneration"] == fields["expectedRuntimeGeneration"] + 1
        and fields["attachmentGeneration"] == fields["expectedAttachmentGeneration"] + 1
        and not state["reattached"],
        "invalid_reattach",
    )
    old, new = fields["oldBinding"], fields["newBinding"]
    require(
        set(new) == set(NATIVE_BINDING_FIELDS)
        and all(
            uuid(new[key])
            for key in ("clientId", "connectionId", "threadId", "serverInstanceId")
        )
        and exact_type(new["backendPid"], int)
        and 0 < new["backendPid"] < 2**32
        and all(
            exact_type(new[key], int) and 0 < new[key] < 2**53
            for key in ("generation", "serverGeneration")
        ),
        "invalid_reattach_binding",
    )
    physical = (
        "clientId",
        "connectionId",
        "backendPid",
        "threadId",
        "serverInstanceId",
    )
    require(
        all(old[key] == new[key] for key in physical)
        and new["generation"] >= old["generation"]
        and new["serverGeneration"] >= old["serverGeneration"]
        and (
            new["generation"] > old["generation"]
            or new["serverGeneration"] > old["serverGeneration"]
        )
        and fields["newEventSha256"] != fields["oldEventSha256"],
        "reattach_identity_mismatch",
    )
    state["reattachReadback"] = {
        "eventSha256": fields["newEventSha256"],
        "binding": copy.deepcopy(new),
        "runtimeGeneration": fields["runtimeGeneration"],
        "attachmentGeneration": fields["attachmentGeneration"],
    }
    state["reattached"] = True


def _phase_complete_case(plan, state, fields, manifest, case_id, cases):
    """Apply the validated complete_case transition to the projected state."""
    case = cases[case_id]
    require(
        state["active"] == case_id
        and case["publicationOutcome"] == "accepted"
        and fields["storeAckState"] in ("observed", "queued", "fenced")
        and (fields["attemptId"] is None or uuid(fields["attemptId"]))
        and hash_text(fields["storeWitnessSha256"]),
        "case_completion_unproven",
    )
    if case_id == "A1":
        require(
            case["startOutcome"] == "started"
            and state["restartTokens"].get("R1", {}).get("complete") is True
            and state["restartTokens"].get("R2", {}).get("complete") is True
            and case["ackLatches"].get("submitted", {}).get("complete") is not None
            and case["ackLatches"].get("observed", {}).get("complete") is not None
            and uuid(fields["attemptId"])
            and fields["attemptId"] == case["ackLatches"]["submitted"]["attemptId"]
            and fields["attemptId"] == case["ackLatches"]["observed"]["attemptId"]
            and fields["storeAckState"] == "observed"
            and case["faults"].get("submitted", {}).get("returned") is True
            and case["faults"].get("observed", {}).get("returned") is True,
            "a1_recovery_incomplete",
        )
    elif case_id in ("B1", "C1", "C3"):
        require(
            case["startOutcome"] == "started"
            and fields["storeAckState"] == "observed"
            and uuid(fields["attemptId"]),
            "successful_start_case_incomplete",
        )
    elif case_id == "C2":
        require(
            case["queued"]
            and fields["storeAckState"] == "queued"
            and state["restartTokens"].get("R3", {}).get("complete") is True,
            "c2_recovery_incomplete",
        )
    elif case_id in ("B2", "A2"):
        require(
            case["startIntent"] is None and fields["storeAckState"] == "fenced",
            "fence_case_started_unexpectedly",
        )
        require(
            case["claimIntent"] is None or case["claimOutcome"] == "refused",
            "fence_case_cloud_outcome_unproven",
        )
    case["complete"] = True
    state["active"] = None


_PHASE_HANDLERS = {
    "begin_case": _phase_begin_case,
    "publication_intent": _phase_publication_intent,
    "publication_result": _phase_publication_result,
    "claim_intent": _phase_claim_intent,
    "claim_result": _phase_claim_result,
    "start_intent": _phase_start_intent,
    "start_outcome": _phase_start_outcome,
    "ack_latch": _phase_ack_latch,
    "ack_complete": _phase_ack_complete,
    "queue_c2": _phase_queue_c2,
    "restart_intent": _phase_restart_intent,
    "restart_complete": _phase_restart_complete,
    "reattach": _phase_reattach,
    "complete_case": _phase_complete_case,
}


def _apply_phase(plan, state, value, manifest=None):
    """Validate and apply one ordered, hash-chained phase transition."""
    require(
        plan is not None and exact_type(value, dict) and "at" in value,
        "phase_plan_required",
    )
    operation = value["op"]
    require(
        operation in PHASE_SCHEMAS
        and set(value) == PHASE_SCHEMAS[operation] | {"op", "at"},
        "invalid_phase_record",
    )
    fields = {key: item for key, item in value.items() if key not in ("op", "at")}
    cases = state["cases"]
    case_id = fields.get("caseId")
    if case_id is not None:
        require(case_id in cases, "unknown_case")
    handler = _PHASE_HANDLERS.get(operation)
    require(handler is not None, "invalid_phase_operation")
    handler(plan, state, fields, manifest, case_id, cases)


def validate_reattach(
    plan,
    readback,
):
    """Validate one closed reattach readback without rewriting its old identity."""
    require(
        exact_type(readback, dict)
        and set(readback)
        == {
            "oldCaseId",
            "newCaseId",
            "oldEventSha256",
            "newEventSha256",
            "oldBinding",
            "newBinding",
            "runtimeGeneration",
            "attachmentGeneration",
        },
        "invalid_reattach_readback",
    )
    old_case_id = readback["oldCaseId"]
    new_case_id = readback["newCaseId"]
    old_event_sha256 = readback["oldEventSha256"]
    new_event_sha256 = readback["newEventSha256"]
    old_binding = readback["oldBinding"]
    new_binding = readback["newBinding"]
    runtime_generation = readback["runtimeGeneration"]
    attachment_generation = readback["attachmentGeneration"]
    require(old_case_id == "C2" and new_case_id == "C3", "invalid_reattach_cases")
    old = plan["cases"][old_case_id]
    require(
        old_event_sha256 == old["eventSha256"]
        and hash_text(new_event_sha256)
        and old_binding == old["binding"]
        and exact_type(new_binding, dict)
        and set(new_binding) == set(NATIVE_BINDING_FIELDS),
        "reattach_envelope_or_binding_changed",
    )
    require(
        all(
            uuid(new_binding[key])
            for key in ("clientId", "connectionId", "threadId", "serverInstanceId")
        )
        and exact_type(new_binding["backendPid"], int)
        and 0 < new_binding["backendPid"] < 2**32
        and all(
            exact_type(new_binding[key], int) and 0 < new_binding[key] < 2**53
            for key in ("generation", "serverGeneration")
        ),
        "invalid_reattach_binding",
    )
    physical = (
        "clientId",
        "connectionId",
        "backendPid",
        "threadId",
        "serverInstanceId",
    )
    require(
        all(old_binding[key] == new_binding[key] for key in physical)
        and new_binding["generation"] >= old_binding["generation"]
        and new_binding["serverGeneration"] >= old_binding["serverGeneration"]
        and new_event_sha256 != old_event_sha256
        and (
            new_binding["generation"] > old_binding["generation"]
            or new_binding["serverGeneration"] > old_binding["serverGeneration"]
        ),
        "reattach_identity_mismatch",
    )
    require(
        runtime_generation == old["runtimeGeneration"] + 1
        and attachment_generation == old["attachmentGeneration"] + 1,
        "reattach_cas_mismatch",
    )
    return {
        "oldEventSha256": old_event_sha256,
        "newEventSha256": new_event_sha256,
        "oldBinding": copy.deepcopy(old_binding),
        "newBinding": copy.deepcopy(new_binding),
        "expectedRuntimeGeneration": old["runtimeGeneration"],
        "expectedAttachmentGeneration": old["attachmentGeneration"],
        "runtimeGeneration": runtime_generation,
        "attachmentGeneration": attachment_generation,
    }


class RecoveryOrchestrator:
    """Phase journal facade; effect owners remain the production caller's responsibility."""

    def __init__(self, journal):
        """Bind the facade to a validated phase-plan journal."""
        require(
            isinstance(journal, Journal) and journal.phase_plan is not None,
            "phase_plan_required",
        )
        self.journal = journal

    @staticmethod
    def _payload_hash(payload):
        return digest(payload if exact_type(payload, bytes) else encoded(payload))

    def readiness(self):
        """Report blockers; offline fixture state never grants live authority."""
        return {
            "ready": False,
            "blockers": [
                "native_core_busy_signal_not_promoted",
                "owned_daemon_os_restart_supervisor_not_wired",
                "production_store_readback_not_wired",
                "live_deployment_provenance_not_verified",
                "live_window_and_owner_approval_not_recorded",
            ],
        }

    def begin_case(self, case_id):
        self.journal.phase("begin_case", caseId=case_id)

    def publication_intent(self, case_id, request_bytes, *, event_sha256=None):
        case = self.journal.phase_plan["cases"][case_id]
        if event_sha256 is None:
            event_sha256 = case["eventSha256"]
        if event_sha256 is None and case_id == "C3":
            readback = self.journal.snapshot()["phase"]["reattachReadback"]
            require(readback is not None, "reattach_not_recorded")
            event_sha256 = readback["eventSha256"]
        self.journal.phase(
            "publication_intent",
            caseId=case_id,
            subject=case["subject"],
            eventSha256=event_sha256,
            requestSha256=self._payload_hash(request_bytes),
        )

    def publication_result(self, case_id, outcome, response_bytes=None):
        response_hash = (
            None if outcome == "ambiguous" else self._payload_hash(response_bytes)
        )
        self.journal.phase(
            "publication_result",
            caseId=case_id,
            outcome=outcome,
            responseSha256=response_hash,
        )

    def claim_intent(self, case_id, request):
        case = self.journal.phase_plan["cases"][case_id]
        self.journal.phase(
            "claim_intent",
            caseId=case_id,
            subject=case["subject"],
            requestSha256=self._payload_hash(request),
        )

    def claim_result(self, case_id, outcome, response_bytes=None):
        response_hash = (
            None if outcome == "ambiguous" else self._payload_hash(response_bytes)
        )
        self.journal.phase(
            "claim_result",
            caseId=case_id,
            outcome=outcome,
            responseSha256=response_hash,
        )

    def start_intent(self, case_id, request):
        case = self.journal.phase_plan["cases"][case_id]
        self.journal.phase(
            "start_intent",
            caseId=case_id,
            subject=case["subject"],
            requestSha256=self._payload_hash(request),
        )

    def start_outcome(self, case_id, request, outcome, receipt):
        self.journal.phase(
            "start_outcome",
            caseId=case_id,
            requestSha256=self._payload_hash(request),
            outcome=outcome,
            receiptSha256=self._payload_hash(receipt),
        )

    def ack_latch(self, case_id, phase, request_bytes, store_witness):
        request = (
            decode(request_bytes) if exact_type(request_bytes, bytes) else request_bytes
        )
        correlation = request.get("nativeCorrelation", {})
        self.journal.phase(
            "ack_latch",
            caseId=case_id,
            phase=phase,
            requestSha256=self._payload_hash(request_bytes),
            storeWitnessSha256=self._payload_hash(store_witness),
            deliveryId=request.get("deliveryId"),
            attemptId=request.get("attemptId"),
            eventId=request.get("eventId"),
            permitId=correlation.get("permitId"),
            turnId=correlation.get("turnId"),
            itemId=correlation.get("itemId"),
        )

    def ack_complete(self, case_id, phase, request_bytes, response_bytes, current):
        self.journal.phase(
            "ack_complete",
            caseId=case_id,
            phase=phase,
            requestSha256=self._payload_hash(request_bytes),
            responseSha256=self._payload_hash(response_bytes),
            current=current,
        )

    def restart_intent(
        self, restart_id, case_id, reason, *, old_pid, old_start_id, socket_bytes
    ):
        self.journal.phase(
            "restart_intent",
            token=restart_id,
            caseId=case_id,
            reason=reason,
            oldPid=old_pid,
            oldStartId=old_start_id,
            socketSha256=self._payload_hash(socket_bytes),
        )

    def restart_complete(self, restart_id, *, new_pid, new_start_id):
        self.journal.phase(
            "restart_complete",
            token=restart_id,
            newPid=new_pid,
            newStartId=new_start_id,
        )

    def record_reattach(self, **readback):
        """Latch exact observed output without modifying the old event/binding."""
        require(
            set(readback)
            == {
                "oldCaseId",
                "newCaseId",
                "oldEventSha256",
                "newEventSha256",
                "oldBinding",
                "newBinding",
                "runtimeGeneration",
                "attachmentGeneration",
            },
            "invalid_reattach_readback",
        )
        facts = validate_reattach(self.journal.phase_plan, readback)
        self.journal.phase(
            "reattach",
            oldCaseId=readback["oldCaseId"],
            newCaseId=readback["newCaseId"],
            **facts,
        )

    def complete_case(self, case_id, *, store_ack_state, attempt_id, store_witness):
        self.journal.phase(
            "complete_case",
            caseId=case_id,
            storeAckState=store_ack_state,
            attemptId=attempt_id,
            storeWitnessSha256=self._payload_hash(store_witness),
        )


class Journal:
    """Append-only hash chain, exclusive lock, fixed expiry and conservative counters."""

    def __init__(
        self, directory, manifest, *, clock=time.time, create=False, phase_plan=None
    ):
        """Open or create the private fixture journal and validate its contract."""
        self.manifest = manifest_checked(manifest)
        self.phase_plan = (
            None
            if phase_plan is None
            else phase_plan_checked(phase_plan, self.manifest)
        )
        self.manifest_hash = digest(
            encoded(
                self.manifest
                if self.phase_plan is None
                else {"manifest": self.manifest, "phasePlan": self.phase_plan}
            )
        )
        self.clock = clock
        self.directory = Path(directory)
        require(
            self.directory.is_absolute()
            and not any(
                p.is_symlink() for p in (self.directory, *self.directory.parents)
            ),
            "unsafe_directory",
        )
        info = self.directory.stat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "unsafe_directory",
        )
        self.path = self.directory / "journal.jsonl"
        self._transaction(lambda state, append: None, initialize=create)

    def _read_rows(self, raw):
        require(
            0 < len(raw) <= MAX_JOURNAL and raw.endswith(b"\n"),
            "truncated_or_oversized_journal",
        )
        rows = []
        previous = "0" * 64
        for number, line in enumerate(raw.splitlines()):
            row = decode(line)
            require(
                exact_type(row, dict)
                and set(row) == {"sequence", "previous", "kind", "value", "sha256"}
                and exact_type(row["sequence"], int)
                and row["sequence"] == number
                and row["previous"] == previous,
                "invalid_journal_record",
            )
            payload = {
                key: row[key] for key in ("sequence", "previous", "kind", "value")
            }
            require(row["sha256"] == digest(encoded(payload)), "corrupt_journal_record")
            previous = row["sha256"]
            rows.append(row)
        return rows

    def _read(self, stream):
        rows = self._read_rows(stream.read(MAX_JOURNAL + 1))
        header = rows[0]
        require(
            header["kind"] == "header"
            and set(header["value"]) == {"manifestSha256", "startedAt", "expiresAt"}
            and header["value"]["manifestSha256"] == self.manifest_hash,
            "changed_manifest",
        )
        start, expiry = header["value"]["startedAt"], header["value"]["expiresAt"]
        require(
            (exact_type(start, int) or exact_type(start, float))
            and math.isfinite(start)
            and expiry == start + 1200,
            "invalid_fixed_deadline",
        )
        state = {
            "rows": rows,
            "expiresAt": expiry,
            "startedAt": start,
            "lastTime": start,
            "counts": {key: 0 for key in LIMITS},
            "reservedSubjects": {key: set() for key in LIMITS},
            "armed": set(),
            "witnesses": {},
            "held": set(),
            "replays": set(),
            "returned": set(),
            "nonces": set(),
            "sends": 0,
            "sendKeys": set(),
            "actionSends": {},
            "aborted": False,
            "phase": _new_phase_state() if self.phase_plan is not None else None,
        }
        for row in rows[1:]:
            self._apply_record(state, row, expiry)
        return state

    def _validate_record_schema(self, kind, value, phase_mode):
        schemas = {
            "reserve": {"counter", "subject"},
            "arm": {"action", "caseId"} if phase_mode else {"action"},
            "hold": {"action", "caseId"} if phase_mode else {"action"},
            "replay": {"action", "caseId"} if phase_mode else {"action"},
            "returned": (
                {
                    "action",
                    "caseId",
                    "responseSha256",
                    "responseRawBase64",
                    "response",
                }
                if phase_mode
                else {"action", "responseSha256", "responseRawBase64", "response"}
            ),
            "witness": (
                {
                    "action",
                    "caseId",
                    "requestSha256",
                    "responseSha256",
                    "response",
                    "nodeProofNonce",
                }
                if phase_mode
                else {
                    "action",
                    "requestSha256",
                    "responseSha256",
                    "response",
                    "nodeProofNonce",
                }
            ),
            "send": (
                {
                    "action",
                    "caseId",
                    "subject",
                    "requestSha256",
                    "nonce",
                    "replay",
                    "durableBeforeSend",
                }
                if phase_mode
                else {
                    "action",
                    "subject",
                    "requestSha256",
                    "nonce",
                    "replay",
                    "durableBeforeSend",
                }
            ),
            "abort": {"reason"},
            "phase": None,
        }
        require(
            kind in schemas
            and exact_type(value, dict)
            and (
                kind == "phase"
                and self.phase_plan is not None
                or kind != "phase"
                and set(value) == schemas[kind] | {"at"}
            ),
            "invalid_closed_record_schema",
        )

    def _apply_record(self, state, row, expiry):
        kind, value = row["kind"], row["value"]
        require(not state["aborted"], "records_after_abort")
        phase_mode = self.phase_plan is not None
        self._validate_record_schema(kind, value, phase_mode)
        require(
            (exact_type(value.get("at"), int) or exact_type(value.get("at"), float))
            and state["lastTime"] <= value["at"] <= expiry,
            "invalid_record_time",
        )
        state["lastTime"] = value["at"]
        require(
            kind
            in (
                "reserve",
                "arm",
                "send",
                "witness",
                "hold",
                "replay",
                "returned",
                "abort",
                "phase",
            ),
            "unknown_record_kind",
        )
        if kind == "phase":
            self._project_phase_record(state, value)
        elif kind == "reserve":
            self._project_reservation(state, value, phase_mode)
        elif kind in ("arm", "hold", "replay", "returned"):
            self._project_fault_record(state, kind, value)
        elif kind == "witness":
            self._project_witness(state, value)
        elif kind == "send":
            self._project_send(state, value, phase_mode)
        elif kind == "abort":
            self._project_abort(state, value)
        if phase_mode:
            _apply_fault_projection(self.phase_plan, state["phase"], kind, value)

    def _project_phase_record(self, state, value):
        _apply_phase(self.phase_plan, state["phase"], value, self.manifest)
        operation = value["op"]
        if operation == "publication_intent":
            state["reservedSubjects"]["publication"].add(value["subject"])
            state["counts"]["publication"] += 1
        elif operation == "start_intent":
            subject = value["subject"]
            require(
                subject not in state["reservedSubjects"]["nativeStart"],
                "duplicate_subject_reservation",
            )
            state["reservedSubjects"]["nativeStart"].add(subject)
            state["counts"]["nativeStart"] += 1
        elif operation == "restart_intent":
            state["counts"]["restart"] += 1

    def _project_reservation(self, state, value, phase_mode):
        require(
            not phase_mode
            or value.get("counter") not in ("publication", "nativeStart", "restart"),
            "phase_budget_requires_intent",
        )
        counter, subject = value["counter"], value["subject"]
        require(
            counter in LIMITS and subject in self.manifest["subjects"],
            "invalid_reservation",
        )
        if counter in ("publication", "nativeStart"):
            require(
                subject not in state["reservedSubjects"][counter],
                "duplicate_subject_reservation",
            )
        state["reservedSubjects"][counter].add(subject)
        state["counts"][counter] += 1
        require(state["counts"][counter] <= LIMITS[counter], "budget_corrupt")

    def _project_fault_record(self, state, kind, value):
        target_name = {
            "arm": "armed",
            "hold": "held",
            "replay": "replays",
            "returned": "returned",
        }[kind]
        action = value["action"]
        require(
            action in self.manifest["targets"] and action not in state[target_name],
            "duplicate_fault_record",
        )
        if kind in ("hold", "replay"):
            require(action in state["witnesses"], "fault_without_commit_witness")
        if kind == "replay":
            require(action in state["held"], "replay_before_hold")
        if kind == "returned":
            require(
                action in state["replays"]
                and (action, True) in state["sendKeys"]
                and hash_text(value["responseSha256"])
                and raw_response_matches(value)
                and valid_response(self.manifest, action, value["response"]),
                "returned_without_valid_replay",
            )
        state[target_name].add(action)

    def _project_witness(self, state, value):
        action = value["action"]
        require(
            action in state["armed"] and action not in state["witnesses"],
            "duplicate_commit_witness",
        )
        send = state["actionSends"].get((action, False))
        require(
            send is not None
            and value["requestSha256"] == send["requestSha256"]
            and value["nodeProofNonce"] == send["nonce"]
            and hash_text(value["responseSha256"])
            and valid_response(self.manifest, action, value["response"]),
            "invalid_commit_witness",
        )
        state["witnesses"][action] = value

    def _project_send(self, state, value, phase_mode):
        action, replay = value["action"], value["replay"]
        phase_case = (
            None if not phase_mode else state["phase"]["cases"].get(value.get("caseId"))
        )
        phase_publication = (
            phase_case is not None and phase_case["publicationOutcome"] == "accepted"
        )
        require(
            exact_type(replay, bool)
            and (
                value["subject"] in state["reservedSubjects"]["publication"]
                or phase_publication
            )
            and hash_text(value["requestSha256"]),
            "unreserved_or_invalid_send",
        )
        if action is None:
            self._project_claim_send(state, value, phase_mode, phase_case, replay)
        else:
            self._project_action_send(state, value, phase_mode, phase_case, replay)
        require(
            uuid(value["nonce"]) and value["nonce"] not in state["nonces"],
            "reused_node_nonce",
        )
        state["nonces"].add(value["nonce"])
        state["sends"] += 1

    def _project_claim_send(self, state, value, phase_mode, phase_case, replay):
        if phase_mode:
            require(
                replay is False
                and value["durableBeforeSend"] is None
                and phase_case is not None
                and value["caseId"] == state["phase"]["active"]
                and phase_case["claimIntent"] == value["requestSha256"]
                and (
                    value["caseId"] == "C3"
                    or any(
                        item["subject"] == value["subject"]
                        and digest(encoded(item["request"])) == value["requestSha256"]
                        for item in self.manifest["claims"]
                    )
                ),
                "invalid_claim_send",
            )
        else:
            require(
                not state["armed"]
                and replay is False
                and value["durableBeforeSend"] is None
                and any(
                    item["subject"] == value["subject"]
                    and digest(encoded(item["request"])) == value["requestSha256"]
                    for item in self.manifest["claims"]
                ),
                "invalid_claim_send",
            )

    def _project_action_send(self, state, value, phase_mode, phase_case, replay):
        action = value["action"]
        target = self.manifest["targets"].get(action)
        durable = value["durableBeforeSend"]
        base_witness = {
            "action": action,
            "subject": value["subject"],
            "requestSha256": value["requestSha256"],
            "committed": True,
        }
        if phase_mode and target is not None:
            durable_valid = self._has_phase_witness(
                durable, base_witness, target, value["requestSha256"], action
            )
        else:
            durable_valid = durable == base_witness
        require(
            action in self.manifest["targets"]
            and action in state["armed"]
            and (action, replay) not in state["sendKeys"]
            and (not replay or action in state["replays"])
            and target is not None
            and value["subject"] == target["subject"]
            and value["requestSha256"] == target_request_sha256(target)
            and durable_valid,
            "invalid_action_send",
        )
        state["sendKeys"].add((action, replay))
        state["actionSends"][(action, replay)] = value

    @staticmethod
    def _has_phase_witness(durable, base_witness, target, request_sha256, action):
        return (
            exact_type(durable, dict)
            and set(durable)
            == set(base_witness)
            | {
                "attemptId",
                "ackState",
                "nativeReceiptSha256",
                "acknowledgmentSha256",
            }
            and all(durable.get(key) == item for key, item in base_witness.items())
            and durable["attemptId"] == target["request"]["attemptId"]
            and durable["acknowledgmentSha256"] == request_sha256
            and hash_text(durable["nativeReceiptSha256"])
            and (
                durable["ackState"] is None
                if action == "submitted"
                else durable["ackState"] == "submitted"
            )
        )

    @staticmethod
    def _project_abort(state, value):
        require(
            value["reason"]
            in (
                "transport_failed_without_commit_oracle",
                "invalid_success_or_expired_window",
                "hold_failed_without_crash",
            ),
            "invalid_abort",
        )
        state["aborted"] = True

    def _transaction(self, operation, initialize=False, allow_expired=False):
        flags = os.O_RDWR | os.O_NOFOLLOW
        created = False
        if initialize:
            try:
                fd = os.open(self.path, flags | os.O_CREAT | os.O_EXCL, 0o600)
                created = True
            except FileExistsError:
                raise Refused("journal_already_exists_use_explicit_reopen") from None
        else:
            fd = os.open(self.path, flags)
        with os.fdopen(fd, "r+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            info = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1,
                "unsafe_journal",
            )
            now = self.clock()
            require(
                (exact_type(now, int) or exact_type(now, float)) and math.isfinite(now),
                "invalid_clock",
            )
            if created:
                header_value = {
                    "manifestSha256": self.manifest_hash,
                    "startedAt": now,
                    "expiresAt": now + 1200,
                }
                payload = {
                    "sequence": 0,
                    "previous": "0" * 64,
                    "kind": "header",
                    "value": header_value,
                }
                header_raw = (
                    encoded({**payload, "sha256": digest(encoded(payload))}) + b"\n"
                )
                require(len(header_raw) <= MAX_JOURNAL, "journal_full")
                self._read(io.BytesIO(header_raw))
                stream.write(header_raw)
                stream.flush()
                os.fsync(stream.fileno())
                directory_fd = os.open(
                    self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            stream.seek(0)
            planned = stream.read(MAX_JOURNAL + 1)
            state = self._read(io.BytesIO(planned))
            rows = state["rows"]
            pending = []
            if not allow_expired:
                require(not state["aborted"], "run_aborted")
                require(
                    state["lastTime"] <= now < state["expiresAt"],
                    "expired_or_regressed_clock",
                )

            def append(kind, value):
                nonlocal planned
                payload = {
                    "sequence": len(rows),
                    "previous": rows[-1]["sha256"],
                    "kind": kind,
                    "value": {**value, "at": now},
                }
                row = {**payload, "sha256": digest(encoded(payload))}
                raw = encoded(row) + b"\n"
                candidate_size = len(planned) + len(raw)
                require(candidate_size <= MAX_JOURNAL, "journal_full")
                candidate = planned + raw
                # Validate the entire prospective chain before exposing any of
                # this transaction's records on disk. In particular, a valid
                # first record cannot authorize a later invalid record in the
                # same send intent.
                self._read(io.BytesIO(candidate))
                pending.append(raw)
                rows.append(row)
                planned = candidate

            result = operation(state, append)
            if pending:
                stream.seek(0, os.SEEK_END)
                batch = b"".join(pending)
                written = stream.write(batch)
                require(written == len(batch), "journal_write_failed")
                stream.flush()
                os.fsync(stream.fileno())
            return result

    def snapshot(self):
        return self._transaction(lambda state, _append: state, allow_expired=True)

    def reserve(self, counter, subject):
        def reserve(state, append):
            require(
                self.phase_plan is None
                or counter not in ("publication", "nativeStart", "restart"),
                "phase_budget_requires_intent",
            )
            require(
                counter in LIMITS and subject in self.manifest["subjects"],
                "unallocated_effect",
            )
            require(state["counts"][counter] < LIMITS[counter], "budget_exhausted")
            if counter in ("publication", "nativeStart"):
                require(
                    subject not in state["reservedSubjects"][counter],
                    "duplicate_subject_reservation",
                )
            append("reserve", {"counter": counter, "subject": subject})

        self._transaction(reserve)

    def phase(self, operation, **fields):
        """Durably apply one validated phase transition before its external effect."""
        require(self.phase_plan is not None, "phase_plan_required")

        def record(_state, append):
            append("phase", {"op": operation, **fields})

        return self._transaction(record)

    def abort(self, reason):
        self._transaction(lambda _state, append: append("abort", {"reason": reason}))


class TransportFault:
    """Injected send and hold ports only. Caller owns real wiring and crash supervision."""

    def __init__(
        self,
        journal,
        original_send,
        durable_before_send,
        hold_reply,
        *,
        monotonic=time.monotonic,
    ):
        """Bind disposable transport and independently supplied readback ports."""
        self.journal, self.original_send = journal, original_send
        self.durable_before_send, self.hold_reply = durable_before_send, hold_reply
        self.monotonic = monotonic

    async def send(
        self,
        *,
        action=None,
        replay=False,
        subject,
        operation_started_at=None,
        **request,
    ):
        """Persist an exact intent before sending and retain only verified replies."""
        context = self._prepare_context(
            action, replay, subject, operation_started_at, request
        )
        self._persist_intent(context)
        try:
            response = await self.original_send(**request)
        except BaseException:
            self._abort_preserving("transport_failed_without_commit_oracle")
            raise
        if context["claim"]:
            return response
        try:
            raw, value = self._validate_response(context, response)
            self._persist_response(context, raw, value)
        except BaseException:
            self._abort_preserving("invalid_success_or_expired_window")
            raise
        if context["replay"]:
            return response
        await self._hold_or_refuse(context)

    def _prepare_context(self, action, replay, subject, operation_started_at, request):
        manifest = self.journal.manifest
        phase_mode = self.journal.phase_plan is not None
        self._validate_transport_contract(request)
        if action is not None:
            self._validate_operation_deadline(operation_started_at)
        body = decode(request["body"])
        proof = decode(request["headers"]["x-event-node-proof"])
        require(exact_type(proof, dict) and uuid(proof.get("nonce")), "invalid_nonce")
        context = {
            "action": action,
            "claim": action is None,
            "replay": replay,
            "subject": subject,
            "operationStartedAt": operation_started_at,
            "request": request,
            "manifest": manifest,
            "phaseMode": phase_mode,
            "body": body,
            "proof": proof,
            "bodySha256": digest(request["body"]),
        }
        if context["claim"]:
            self._validate_claim_context(context)
        else:
            self._validate_action_context(context)
        return context

    @staticmethod
    def _validate_transport_contract(request):
        require(
            request.get("method") == "POST"
            and exact_type(request.get("body"), bytes)
            and len(request["body"]) <= 4096
            and request.get("follow_redirects") is False
            and request.get("timeout") == 5
            and request.get("max_response_bytes") == 8192,
            "invalid_transport_contract",
        )

    def _validate_operation_deadline(self, operation_started_at):
        require(
            (
                exact_type(operation_started_at, int)
                or exact_type(operation_started_at, float)
            )
            and math.isfinite(operation_started_at)
            and operation_started_at <= self.monotonic() < operation_started_at + 7,
            "insufficient_original_operation_deadline",
        )

    def _validate_claim_context(self, context):
        manifest = context["manifest"]
        request = context["request"]
        body = context["body"]
        require(
            request["url"] == manifest["origin"] + "/v1/dispatch/claim",
            "unallocated_claim",
        )
        if context["phaseMode"]:
            phase = self.journal.snapshot()["phase"]
            phase_case = phase["cases"].get(phase["active"])
            require(
                phase_case is not None
                and phase_case["claimIntent"] == context["bodySha256"]
                and phase["active"] in ("A1", "B1", "C1", "B2", "A2", "C3")
                and (
                    phase["active"] == "C3"
                    or {"subject": context["subject"], "request": body}
                    in manifest["claims"]
                ),
                "unallocated_claim",
            )
        else:
            require(
                {"subject": context["subject"], "request": body} in manifest["claims"],
                "unallocated_claim",
            )

    def _validate_action_context(self, context):
        action = context["action"]
        manifest = context["manifest"]
        require(action in manifest["targets"], "unallocated_action")
        require(
            not context["phaseMode"]
            or action in self.journal.phase_plan["faultTargets"],
            "phase_action_not_fault_allocated",
        )
        target = manifest["targets"][action]
        route = "/v1/dispatch/settle-no-start" if action == "settle" else "/v1/ack"
        require(
            context["subject"] == target["subject"]
            and context["request"]["url"] == manifest["origin"] + route
            and encoded(context["body"]) == encoded(target["request"])
            and (
                "wireSha256" not in target
                or context["bodySha256"] == target["wireSha256"]
            ),
            "target_identity_mismatch",
        )
        witness = self.durable_before_send(action, target, context["bodySha256"])
        context["target"] = target
        context["witness"] = witness
        self._validate_store_witness(context)

    def _validate_store_witness(self, context):
        action = context["action"]
        witness = context["witness"]
        target = context["target"]
        basic = {
            "action": action,
            "subject": context["subject"],
            "requestSha256": context["bodySha256"],
            "committed": True,
        }
        if not context["phaseMode"]:
            require(
                exact_type(witness, dict)
                and set(witness) == set(basic)
                and witness == basic,
                "local_durability_not_verified",
            )
            return
        require(
            self.journal._has_phase_witness(
                witness, basic, target, context["bodySha256"], action
            ),
            "local_durability_not_verified",
        )

    def _persist_intent(self, context):
        self.journal._transaction(
            lambda state, append: self._append_intent(state, append, context)
        )

    def _append_intent(self, state, append, context):
        subject = context["subject"]
        proof = context["proof"]
        require(
            subject in state["reservedSubjects"]["publication"],
            "publication_not_reserved_before_send",
        )
        require(proof["nonce"] not in state["nonces"], "reused_node_nonce")
        case_id = state["phase"]["active"] if context["phaseMode"] else None
        phase_case = None
        if context["phaseMode"]:
            phase_case = state["phase"]["cases"].get(case_id)
            require(
                phase_case is not None
                and phase_case["publicationOutcome"] == "accepted"
                and phase_case["publicationIntent"] is not None,
                "phase_publication_not_accepted",
            )
        if context["claim"]:
            self._append_claim_intent(state, phase_case, context)
        else:
            self._append_action_intent(state, append, phase_case, case_id, context)
        self._append_send_record(append, case_id, context)

    @staticmethod
    def _append_claim_intent(state, phase_case, context):
        if context["phaseMode"]:
            require(
                phase_case["claimIntent"] == context["bodySha256"]
                and phase_case["claimOutcome"] is None,
                "phase_claim_missing_durable_intent",
            )
        else:
            require(not state["armed"], "replacement_claim_fenced_before_network")

    def _append_action_intent(self, state, append, phase_case, case_id, context):
        action = context["action"]
        body_hash = context["bodySha256"]
        witness = context["witness"]
        if context["replay"]:
            require(
                action in state["held"] and action not in state["replays"],
                "replay_not_allocated",
            )
            require(
                state["witnesses"][action]["requestSha256"] == body_hash,
                "replay_body_changed",
            )
            if context["phaseMode"]:
                latch = phase_case["ackLatches"].get(action)
                require(
                    latch is not None
                    and latch["requestSha256"] == body_hash
                    and latch["storeWitnessSha256"] == digest(encoded(witness)),
                    "ack_latch_changed_on_retry",
                )
            append(
                "replay",
                {
                    "action": action,
                    **({"caseId": case_id} if context["phaseMode"] else {}),
                },
            )
            return
        require(action not in state["armed"], "duplicate_fault")
        if context["phaseMode"]:
            self._append_ack_latch(append, phase_case, case_id, context)
        append(
            "arm",
            {"action": action, **({"caseId": case_id} if context["phaseMode"] else {})},
        )

    @staticmethod
    def _append_ack_latch(append, phase_case, case_id, context):
        action = context["action"]
        body_hash = context["bodySha256"]
        witness_hash = digest(encoded(context["witness"]))
        latch = phase_case["ackLatches"].get(action)
        if latch is None:
            ack = context["body"]
            correlation = ack["nativeCorrelation"]
            append(
                "phase",
                {
                    "op": "ack_latch",
                    "caseId": case_id,
                    "phase": action,
                    "requestSha256": body_hash,
                    "storeWitnessSha256": witness_hash,
                    "deliveryId": ack["deliveryId"],
                    "attemptId": ack["attemptId"],
                    "eventId": ack["eventId"],
                    "permitId": correlation["permitId"],
                    "turnId": correlation["turnId"],
                    "itemId": correlation.get("itemId"),
                },
            )
            return
        require(
            latch["requestSha256"] == body_hash
            and latch["storeWitnessSha256"] == witness_hash,
            "ack_latch_changed_on_retry",
        )

    @staticmethod
    def _append_send_record(append, case_id, context):
        append(
            "send",
            {
                "action": context["action"],
                "subject": context["subject"],
                "requestSha256": context["bodySha256"],
                "nonce": context["proof"]["nonce"],
                "replay": context["replay"],
                "durableBeforeSend": None if context["claim"] else context["witness"],
                **({"caseId": case_id} if context["phaseMode"] else {}),
            },
        )

    def _validate_response(self, context, response):
        require(
            self.monotonic() < context["operationStartedAt"] + 7,
            "insufficient_crash_margin",
        )
        status, headers, raw = response
        self._validate_response_envelope(status, headers, raw)
        value = decode(raw)
        self._validate_response_value(context, value)
        return raw, value

    @staticmethod
    def _validate_response_envelope(status, headers, raw):
        require(
            exact_type(status, int)
            and status == 200
            and exact_type(raw, bytes)
            and len(raw) <= 8192
            and headers.get("content-type", "").split(";", 1)[0].strip()
            == "application/json",
            "no_accepted_commit_response",
        )

    @staticmethod
    def _validate_response_value(context, value):
        if context["action"] == "settle":
            target = context["target"]
            expected = {
                **target["request"],
                "nodeId": target["nodeId"],
                "status": "not_started",
            }
            require(
                exact_type(value, dict) and encoded(value) == encoded(expected),
                "settlement_response_mismatch",
            )
            return
        require(
            exact_type(value, dict)
            and set(value) == {"status", "current"}
            and value["status"] == context["action"]
            and exact_type(value["current"], bool)
            and (context["action"] != "submitted" or value["current"] is False),
            "ack_response_mismatch",
        )

    def _persist_response(self, context, raw, value):
        self.journal._transaction(
            lambda state, append: self._append_response(
                state, append, context, raw, value
            )
        )

    @staticmethod
    def _append_response(state, append, context, raw, value):
        action = context["action"]
        case_id = state["phase"]["active"] if context["phaseMode"] else None
        case_fields = {"caseId": case_id} if context["phaseMode"] else {}
        if context["replay"]:
            require(
                action in state["replays"] and action not in state["returned"],
                "duplicate_replay_response",
            )
            append(
                "returned",
                {
                    "action": action,
                    "responseSha256": digest(raw),
                    "responseRawBase64": base64.b64encode(raw).decode("ascii"),
                    "response": value,
                    **case_fields,
                },
            )
            return
        require(action not in state["witnesses"], "duplicate_fault")
        append(
            "witness",
            {
                "action": action,
                "requestSha256": context["bodySha256"],
                "responseSha256": digest(raw),
                "response": value,
                "nodeProofNonce": context["proof"]["nonce"],
                **case_fields,
            },
        )
        append("hold", {"action": action, **case_fields})

    def _abort_preserving(self, reason):
        try:
            self.journal.abort(reason)
        except BaseException as failure:
            category = self._abort_failure_category(failure)
            try:
                logging.getLogger(__name__).warning(
                    "recovery_abort_record_failed:%s", category
                )
            except BaseException:
                pass

    @staticmethod
    def _abort_failure_category(failure):
        if isinstance(failure, Refused):
            return "journal_refused"
        if isinstance(failure, OSError):
            return "journal_io"
        return "unexpected"

    async def _hold_or_refuse(self, context):
        action = context["action"]
        deadline = context["operationStartedAt"] + 8
        try:
            await self.hold_reply(action, deadline)
        except Exception:
            self._abort_preserving("hold_failed_without_crash")
            raise
        self._abort_preserving("hold_failed_without_crash")
        raise Refused("reply_hold_returned_without_owned_crash")
