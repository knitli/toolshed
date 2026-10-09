"""Local lifecycle commands; unproven attachment is a visible refusal."""

import argparse
import asyncio
import base64
from functools import partial
import json
from pathlib import Path
import re
import sys
import time

from .daemon import request, serve, status
from .client_runtime import (
    clear_pending_commit, cloud_identity, load_cloud_client, load_pending_commit,
    pending_commit_summary, save_pending_commit,
)
from .cloud import CloudError, _iso
from .security import (
    ensure_private_directory,
    load_or_create_signing_key,
    public_key_text,
    SecurityError,
)
from .store import Store, StoreError
from .launcher import LaunchError, launch, session_binding, session_challenge, session_status
from .protocol import _timestamp


def main(argv=None):
    parser = argparse.ArgumentParser(prog="knitli-event-gateway")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path.home() / ".local/state/knitli-event-gateway",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("run", help="Run the private control daemon")
    client = commands.add_parser("launch", help="Launch an explicit qualified Codex TUI")
    client.add_argument("--codex-binary", type=Path, required=True)
    client.add_argument("--binary-sha256", required=True)
    client.add_argument("--cwd", type=Path, required=True)
    client.add_argument("--resume", help="Exact native thread UUID")
    presence = commands.add_parser("client-status", help="Query one live launcher selection")
    presence.add_argument("--session-id", required=True)
    enroll = commands.add_parser("enroll", help="Prepare a public node-key request")
    enroll.add_argument("--challenge", required=True)
    attach = commands.add_parser("attach", help="Attach one live native session to a runtime")
    attach.add_argument("--runtime-id", required=True)
    attach.add_argument("--session-id", required=True)
    attach.add_argument("--cloud-config", type=Path, required=True)
    attach.add_argument("--expected-runtime-generation", type=int)
    attach.add_argument("--expected-attachment-generation", type=int)
    renew = commands.add_parser("renew", help="Renew one exact native runtime attachment")
    renew.add_argument("--runtime-id", required=True)
    renew.add_argument("--session-id", required=True)
    renew.add_argument("--cloud-config", type=Path, required=True)
    renew.add_argument("--expected-runtime-generation", type=int, required=True)
    renew.add_argument("--expected-attachment-generation", type=int, required=True)
    transfer = commands.add_parser("transfer", help="Transfer ownership using source and replacement CAS")
    transfer.add_argument("--source-runtime-id", required=True)
    transfer.add_argument("--expected-source-runtime-generation", type=int, required=True)
    transfer.add_argument("--expected-source-attachment-generation", type=int, required=True)
    transfer.add_argument("--replacement-runtime-id", required=True)
    transfer.add_argument("--expected-replacement-runtime-generation", type=int, required=True)
    transfer.add_argument("--expected-replacement-attachment-generation", type=int, required=True)
    transfer.add_argument("--session-id", required=True)
    transfer.add_argument("--cloud-config", type=Path, required=True)
    detach = commands.add_parser("detach")
    detach.add_argument("runtime_id")
    args = parser.parse_args(argv)
    # Keep component identity: resolving symlinks would hide unsafe input.
    state_dir = args.state_dir.absolute()
    if any(part.is_symlink() for part in (state_dir, *state_dir.parents)):
        parser.error("unsafe_state")
    try:
        return _execute_command(args, state_dir, parser)
    except LaunchError as error:
        print(json.dumps({"reason": str(error)}), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"reason": "interrupted"}), file=sys.stderr)
        return 130
    except CloudError as error:
        result_key = {"attach": "attached", "renew": "renewed", "transfer": "transferred"}.get(
            getattr(args, "command", None), "attached",
        )
        if error.ambiguous:
            print(json.dumps({result_key: None, "reason": "commit_outcome_unknown"}))
        else:
            print(json.dumps({result_key: False, "reason": error.code}))
        return 2
    except (StoreError, SecurityError) as error:
        print(json.dumps({"reason": error.code}), file=sys.stderr)
        return 2
    except (OSError, ValueError, TimeoutError):
        print(json.dumps({"reason": "local_operation_unavailable"}), file=sys.stderr)
        return 2


def _execute_command(args, state_dir, parser):
    if args.command == "launch":
        return launch(state_dir, args.codex_binary, args.binary_sha256, args.cwd, resume=args.resume)
    if args.command == "client-status":
        print(json.dumps({"scope": "local_native_presence_only",
                          "presence": session_status(state_dir, args.session_id)}))
        return 0
    if args.command == "run":
        asyncio.run(serve(state_dir))
        return 0
    if args.command in ("attach", "renew", "transfer"):
        return _execute_native_lifecycle(args, state_dir, args.command)
    if args.command == "enroll":
        return _execute_enrollment(args, state_dir, parser)
    return _execute_status_or_detach(args, state_dir)


def _execute_native_lifecycle(args, state_dir, operation):
    result = _native_lifecycle(args, state_dir, operation)
    print(json.dumps(result))
    return 0 if result.get("localStatus") == "current" else 2


def _execute_enrollment(args, state_dir, parser):
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.challenge):
        parser.error("invalid_challenge")
    ensure_private_directory(state_dir)
    key = load_or_create_signing_key(state_dir / "node-key.pem")
    print(json.dumps({
        "status": "owner_enrollment_pending", "publicKey": public_key_text(key),
        "challenge": args.challenge, "reason": "cloud_enrollment_not_integrated",
    }))
    return 2


def _execute_status_or_detach(args, state_dir):
    value = {"command": args.command}
    if args.command == "detach":
        value["runtimeId"] = args.runtime_id
    if (state_dir / "control.sock").exists():
        result = asyncio.run(request(state_dir, value))
    else:
        with Store(state_dir) as store:
            if args.command == "detach":
                store.detach(args.runtime_id)
                result = {"detached": True}
            else:
                result = status(store)
    print(json.dumps(result))
    return 0


def _native_lifecycle(args, state_dir, operation):
    """Challenge, sample, durably record, commit, and persist exact local ownership."""
    result_key = {"attach": "attached", "renew": "renewed", "transfer": "transferred"}[operation]
    context, early_result = _native_context(args, state_dir, operation, result_key)
    if early_result is not None:
        return early_result
    intent, artifact, cloud, binding = context
    persisted = {}
    response, early_result = _commit_native_lifecycle(
        args, state_dir, operation, intent, artifact, cloud, binding, persisted,
    )
    if early_result is not None:
        return early_result
    return _persist_native_lifecycle(
        args, state_dir, operation, binding, cloud, response, artifact, persisted,
    )


def _native_intent(args, operation):
    if operation in ("attach", "renew"):
        return {
            "operation": operation,
            "runtimeId": args.runtime_id,
            "expectedRuntimeGeneration": args.expected_runtime_generation,
            "expectedAttachmentGeneration": args.expected_attachment_generation,
        }
    return {
        "operation": "transfer",
        "sourceRuntimeId": args.source_runtime_id,
        "expectedSourceRuntimeGeneration": args.expected_source_runtime_generation,
        "expectedSourceAttachmentGeneration": args.expected_source_attachment_generation,
        "replacementRuntimeId": args.replacement_runtime_id,
        "expectedReplacementRuntimeGeneration": args.expected_replacement_runtime_generation,
        "expectedReplacementAttachmentGeneration": args.expected_replacement_attachment_generation,
    }


def _native_context(args, state_dir, operation, result_key):
    intent = _native_intent(args, operation)
    artifact = load_pending_commit(state_dir, operation, args.session_id)
    if artifact and any(artifact["intent"].get(key) != value for key, value in intent.items()):
        return None, _pending_unknown(result_key, artifact, "pending_intent_mismatch")
    try:
        cloud = load_cloud_client(args.cloud_config, state_dir)
    except (CloudError, SecurityError) as error:
        if artifact:
            return None, _pending_unknown(
                result_key, artifact, getattr(error, "code", "cloud_config_unavailable"),
            )
        raise
    if artifact and artifact["cloudIdentity"] != cloud_identity(cloud):
        return None, _pending_unknown(result_key, artifact, "pending_identity_changed")
    try:
        binding = session_binding(state_dir, args.session_id)
    except (LaunchError, OSError, TimeoutError):
        if artifact:
            return None, _pending_unknown(result_key, artifact, "native_client_unavailable")
        raise
    intent["expectedNativeBinding"] = binding
    if artifact and artifact["intent"] != intent:
        return None, _pending_unknown(result_key, artifact, "pending_binding_changed")
    if artifact and time.time() * 1000 >= _timestamp(artifact["safeExpiryAt"]):
        return None, _pending_unknown(result_key, artifact, "pending_receipt_window_closed")
    return (intent, artifact, cloud, binding), None


def _save_pending_before_send(body, *, state_dir, args, cloud, intent,
                              challenge, evidence, persisted):
    operation = intent["operation"]
    local_evidence = {"observedAt": evidence["observedAt"], "witness": evidence["witness"]}
    pending = {
        "version": 1, "operation": operation, "sessionId": args.session_id,
        "cloudIdentity": cloud_identity(cloud), "intent": intent,
        "challenge": challenge, "evidence": local_evidence,
        "bodyB64": base64.b64encode(body).decode("ascii"),
        "safeExpiryAt": _iso((_timestamp(challenge["issuedAt"]) + 90_000) / 1000),
    }
    try:
        save_pending_commit(state_dir, operation, args.session_id, pending)
    except SecurityError as error:
        raise CloudError(error.code) from None
    persisted["artifact"] = pending


def _commit_native_call(args, state_dir, operation, intent, artifact, cloud, binding, persisted):
    if artifact:
        body = base64.b64decode(artifact["bodyB64"], validate=True)
        return asyncio.run(getattr(cloud, operation)(
            intent, artifact["challenge"], artifact["evidence"],
            prepared_body=body, recovery=True,
        ))
    try:
        challenge = asyncio.run(cloud.native_challenge(intent))
    except CloudError as error:
        if error.ambiguous:
            raise CloudError("challenge_outcome_unknown") from None
        raise
    evidence = session_challenge(state_dir, args.session_id, challenge["challengeId"], binding)
    persist = partial(
        _save_pending_before_send, state_dir=state_dir,
        args=args, cloud=cloud, intent=intent, challenge=challenge,
        evidence=evidence, persisted=persisted,
    )
    return asyncio.run(getattr(cloud, operation)(
        intent, challenge, evidence, on_first_send=persist,
    ))


def _native_commit_error(error, state_dir, operation, artifact, args, result_key, persisted):
    if artifact:
        return _pending_unknown(result_key, artifact, error.code)
    pending = load_pending_commit(state_dir, operation, args.session_id)
    if error.ambiguous:
        if pending:
            return _pending_unknown(result_key, pending, error.code)
        return {result_key: None, "reason": "commit_outcome_unknown"}
    if pending:
        owned = persisted.get("artifact")
        if owned != pending:
            return _pending_unknown(result_key, pending, error.code)
        try:
            clear_pending_commit(state_dir, operation, args.session_id, expected=owned)
        except SecurityError:
            return _pending_unknown(result_key, pending, "pending_cleanup_unavailable")
    return {result_key: False, "reason": error.code}


def _commit_native_lifecycle(args, state_dir, operation, intent, artifact, cloud,
                             binding, persisted):
    result_key = {"attach": "attached", "renew": "renewed", "transfer": "transferred"}[operation]
    try:
        return _commit_native_call(
            args, state_dir, operation, intent, artifact, cloud, binding, persisted,
        ), None
    except CloudError as error:
        return None, _native_commit_error(
            error, state_dir, operation, artifact, args, result_key, persisted,
        )
    except (OSError, TimeoutError):
        pending = load_pending_commit(state_dir, operation, args.session_id)
        if pending:
            return None, _pending_unknown(result_key, pending, "local_operation_unavailable")
        raise


def _native_mapping(args, operation, cloud, response):
    mapping = {
        "runtimeId": response["runtimeId"], "principal": cloud.principal, "agent": cloud.agent,
        "nodeGeneration": cloud.node_generation, "runtimeGeneration": response["runtimeGeneration"],
        "attachmentGeneration": response["attachmentGeneration"],
        "leaseExpiresAt": _timestamp(response["leaseUntil"]) / 1000,
        "nativeBinding": response["nativeBinding"], "nodeId": response["nodeId"],
    }
    transfer = None
    if operation == "transfer":
        transfer = {
            "sourceRuntimeId": response["sourceRuntimeId"],
            "expectedRuntimeGeneration": args.expected_source_runtime_generation,
            "expectedAttachmentGeneration": args.expected_source_attachment_generation,
            "runtimeGeneration": response["sourceRuntimeGeneration"],
            "attachmentGeneration": response["sourceAttachmentGeneration"],
        }
    return mapping, transfer


def _store_native_mapping(state_dir, operation, mapping, transfer):
    if operation == "transfer":
        command = {"command": "transfer-attachment", "mapping": mapping, "transfer": transfer}
    else:
        command = {"command": "put-attachment", "mapping": mapping}

    def store_mapping_directly():
        with Store(state_dir) as store:
            if operation == "transfer":
                store.put_attachment(mapping, transfer=transfer)
            else:
                store.put_attachment(mapping)
        return {"stored": True, "runtimeId": mapping["runtimeId"]}

    socket_path = state_dir / "control.sock"
    try:
        if not (socket_path.exists() or socket_path.is_symlink()):
            stored = store_mapping_directly()
        else:
            try:
                stored = asyncio.run(request(state_dir, command))
            except (ConnectionRefusedError, FileNotFoundError):
                # Only a definite missing listener permits the Store lock to arbitrate.
                stored = store_mapping_directly()
    except StoreError as error:
        return False, error.code
    except (OSError, ValueError, TimeoutError):
        return False, "local_operation_unavailable"
    if stored == {"stored": True, "runtimeId": mapping["runtimeId"]}:
        return True, None
    return False, _store_response_error(stored)


def _revoke_transfer_source(state_dir, mapping, transfer):
    command = {"command": "revoke-transfer-source", "mapping": mapping, "transfer": transfer}

    def revoke_directly():
        with Store(state_dir) as store:
            return store.revoke_transfer_source(mapping, transfer=transfer)

    socket_path = state_dir / "control.sock"
    try:
        if not (socket_path.exists() or socket_path.is_symlink()):
            result = revoke_directly()
        else:
            try:
                result = asyncio.run(request(state_dir, command))
            except (ConnectionRefusedError, FileNotFoundError):
                # Let Store's normal writer lock arbitrate after a definite stale socket.
                result = revoke_directly()
    except StoreError as error:
        return False, error.code
    except (OSError, ValueError, TimeoutError):
        return False, "local_operation_unavailable"
    if result == {"revoked": True, "runtimeId": transfer["sourceRuntimeId"]}:
        return True, None
    return False, _store_response_error(result)


def _store_response_error(result):
    code = result.get("reason") if isinstance(result, dict) else None
    if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
        return code
    return "invalid_store_response"


def _fence_source_after_confirmed_transfer(state_dir, args, cloud, response):
    mapping, transfer = _native_mapping(args, "transfer", cloud, response)
    fenced, error_code = _revoke_transfer_source(state_dir, mapping, transfer)
    if fenced:
        return None
    return {"remoteStatus": response["status"], "localStatus": "unavailable",
            "reason": "local_transfer_source_fence_unavailable", "runtimeId": response["runtimeId"],
            "lastError": error_code}


def _persist_native_lifecycle(args, state_dir, operation, binding, cloud, response,
                              artifact, persisted):
    try:
        current_binding = session_binding(state_dir, args.session_id)
    except (LaunchError, OSError, TimeoutError):
        if operation == "transfer":
            fence_error = _fence_source_after_confirmed_transfer(
                state_dir, args, cloud, response,
            )
            if fence_error is not None:
                return fence_error
        return {"remoteStatus": response["status"], "localStatus": "not_current",
                "reason": "native_client_unavailable_after_commit", "runtimeId": response["runtimeId"]}
    if current_binding != binding:
        if operation == "transfer":
            fence_error = _fence_source_after_confirmed_transfer(
                state_dir, args, cloud, response,
            )
            if fence_error is not None:
                return fence_error
        return {"remoteStatus": response["status"], "localStatus": "not_current",
                "reason": "native_binding_changed_after_commit", "runtimeId": response["runtimeId"]}
    mapping, transfer = _native_mapping(args, operation, cloud, response)
    stored, error_code = _store_native_mapping(state_dir, operation, mapping, transfer)
    if not stored:
        return {"remoteStatus": response["status"], "localStatus": "unavailable",
                "reason": "local_mapping_unavailable", "runtimeId": mapping["runtimeId"],
                "lastError": error_code}
    if artifact or persisted.get("artifact"):
        pending = artifact or persisted["artifact"]
        try:
            clear_pending_commit(state_dir, operation, args.session_id, expected=pending)
        except SecurityError:
            return {"remoteStatus": response["status"], "localStatus": "unavailable",
                    "reason": "pending_cleanup_unavailable", "runtimeId": mapping["runtimeId"]}
    return {"remoteStatus": response["status"], "localStatus": "current",
            "runtimeId": mapping["runtimeId"], "runtimeGeneration": mapping["runtimeGeneration"],
            "attachmentGeneration": mapping["attachmentGeneration"]}


def _pending_unknown(result_key, artifact, last_error):
    return {
        result_key: None, "reason": "commit_outcome_unknown",
        "lastError": last_error, "pendingCommit": pending_commit_summary(artifact),
    }


if __name__ == "__main__":
    sys.exit(main())
