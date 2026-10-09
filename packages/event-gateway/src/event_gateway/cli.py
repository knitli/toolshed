"""Local lifecycle commands; unproven attachment is a visible refusal."""

import argparse
import asyncio
import base64
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
        if args.command == "launch":
            return launch(state_dir, args.codex_binary, args.binary_sha256,
                          args.cwd, resume=args.resume)
        if args.command == "client-status":
            print(json.dumps({"scope": "local_native_presence_only",
                              "presence": session_status(state_dir, args.session_id)}))
            return 0
        if args.command == "run":
            asyncio.run(serve(state_dir))
            return 0
        if args.command == "attach":
            result = _native_lifecycle(args, state_dir, "attach")
            print(json.dumps(result))
            return 0 if result.get("localStatus") == "current" else 2
        if args.command == "renew":
            result = _native_lifecycle(args, state_dir, "renew")
            print(json.dumps(result))
            return 0 if result.get("localStatus") == "current" else 2
        if args.command == "transfer":
            result = _native_lifecycle(args, state_dir, "transfer")
            print(json.dumps(result))
            return 0 if result.get("localStatus") == "current" else 2
        if args.command == "enroll":
            if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.challenge):
                parser.error("invalid_challenge")
            ensure_private_directory(state_dir)
            key = load_or_create_signing_key(state_dir / "node-key.pem")
            print(
                json.dumps(
                    {
                        "status": "owner_enrollment_pending",
                        "publicKey": public_key_text(key),
                        "challenge": args.challenge,
                        "reason": "cloud_enrollment_not_integrated",
                    }
                )
            )
            return 2
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


def _native_lifecycle(args, state_dir, operation):
    """Challenge, sample, durably record, commit, and persist exact local ownership."""
    result_key = {"attach": "attached", "renew": "renewed", "transfer": "transferred"}[operation]
    if operation in ("attach", "renew"):
        intent = {
            "operation": operation,
            "runtimeId": args.runtime_id,
            "expectedRuntimeGeneration": args.expected_runtime_generation,
            "expectedAttachmentGeneration": args.expected_attachment_generation,
        }
    else:
        intent = {
            "operation": "transfer",
            "sourceRuntimeId": args.source_runtime_id,
            "expectedSourceRuntimeGeneration": args.expected_source_runtime_generation,
            "expectedSourceAttachmentGeneration": args.expected_source_attachment_generation,
            "replacementRuntimeId": args.replacement_runtime_id,
            "expectedReplacementRuntimeGeneration": args.expected_replacement_runtime_generation,
            "expectedReplacementAttachmentGeneration": args.expected_replacement_attachment_generation,
        }

    artifact = load_pending_commit(state_dir, operation, args.session_id)
    if artifact and any(artifact["intent"].get(key) != value for key, value in intent.items()):
        return _pending_unknown(result_key, artifact, "pending_intent_mismatch")
    try:
        cloud = load_cloud_client(args.cloud_config, state_dir)
    except (CloudError, SecurityError) as error:
        if artifact:
            return _pending_unknown(result_key, artifact, getattr(error, "code", "cloud_config_unavailable"))
        raise
    if artifact and artifact["cloudIdentity"] != cloud_identity(cloud):
        return _pending_unknown(result_key, artifact, "pending_identity_changed")
    try:
        binding = session_binding(state_dir, args.session_id)
    except LaunchError:
        if artifact:
            return _pending_unknown(result_key, artifact, "native_client_unavailable")
        raise
    intent["expectedNativeBinding"] = binding
    if artifact and artifact["intent"] != intent:
        return _pending_unknown(result_key, artifact, "pending_binding_changed")
    if artifact and time.time() * 1000 >= _timestamp(artifact["safeExpiryAt"]):
        return _pending_unknown(result_key, artifact, "pending_receipt_window_closed")

    persisted = {}

    async def commit():
        if artifact:
            body = base64.b64decode(artifact["bodyB64"], validate=True)
            return await getattr(cloud, operation)(
                intent, artifact["challenge"], artifact["evidence"],
                prepared_body=body, recovery=True,
            )
        try:
            challenge = await cloud.native_challenge(intent)
        except CloudError as error:
            if error.ambiguous:
                raise CloudError("challenge_outcome_unknown") from None
            raise
        evidence = session_challenge(state_dir, args.session_id, challenge["challengeId"], binding)

        def persist_before_send(body):
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

        return await getattr(cloud, operation)(
            intent, challenge, evidence, on_first_send=persist_before_send,
        )

    try:
        response = asyncio.run(commit())
    except CloudError as error:
        if artifact:
            return _pending_unknown(result_key, artifact, error.code)
        if error.ambiguous:
            pending = load_pending_commit(state_dir, operation, args.session_id)
            if pending:
                return _pending_unknown(result_key, pending, error.code)
            return {result_key: None, "reason": "commit_outcome_unknown"}
        pending = load_pending_commit(state_dir, operation, args.session_id)
        if pending:
            owned = persisted.get("artifact")
            if owned != pending:
                return _pending_unknown(result_key, pending, error.code)
            try:
                clear_pending_commit(state_dir, operation, args.session_id, expected=owned)
            except SecurityError:
                return _pending_unknown(result_key, pending, "pending_cleanup_unavailable")
        return {result_key: False, "reason": error.code}
    try:
        current_binding = session_binding(state_dir, args.session_id)
    except LaunchError:
        return {"remoteStatus": response["status"], "localStatus": "not_current",
                "reason": "native_client_unavailable_after_commit", "runtimeId": response["runtimeId"]}
    if current_binding != binding:
        return {"remoteStatus": response["status"], "localStatus": "not_current",
                "reason": "native_binding_changed_after_commit", "runtimeId": response["runtimeId"]}

    mapping = {
        "runtimeId": response["runtimeId"], "principal": cloud.principal, "agent": cloud.agent,
        "nodeGeneration": cloud.node_generation, "runtimeGeneration": response["runtimeGeneration"],
        "attachmentGeneration": response["attachmentGeneration"],
        "leaseExpiresAt": _timestamp(response["leaseUntil"]) / 1000,
        "nativeBinding": response["nativeBinding"], "nodeId": response["nodeId"],
    }
    if operation == "transfer":
        transfer_cas = {
            "sourceRuntimeId": response["sourceRuntimeId"],
            "expectedRuntimeGeneration": args.expected_source_runtime_generation,
            "expectedAttachmentGeneration": args.expected_source_attachment_generation,
            "runtimeGeneration": response["sourceRuntimeGeneration"],
            "attachmentGeneration": response["sourceAttachmentGeneration"],
        }
        command = {"command": "transfer-attachment", "mapping": mapping, "transfer": transfer_cas}
    else:
        command = {"command": "put-attachment", "mapping": mapping}
    socket_path = state_dir / "control.sock"
    try:
        if socket_path.exists() or socket_path.is_symlink():
            stored = asyncio.run(request(state_dir, command))
        else:
            with Store(state_dir) as store:
                if operation == "transfer":
                    store.put_attachment(mapping, transfer=transfer_cas)
                else:
                    store.put_attachment(mapping)
            stored = {"stored": True, "runtimeId": mapping["runtimeId"]}
    except (StoreError, OSError, ValueError, TimeoutError):
        return {"remoteStatus": response["status"], "localStatus": "unavailable",
                "reason": "local_mapping_unavailable", "runtimeId": mapping["runtimeId"]}
    if stored != {"stored": True, "runtimeId": mapping["runtimeId"]}:
        return {"remoteStatus": response["status"], "localStatus": "unavailable",
                "reason": "local_mapping_unavailable", "runtimeId": mapping["runtimeId"]}
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
