"""Local lifecycle commands; unproven attachment is a visible refusal."""

import argparse
import asyncio
import json
from pathlib import Path
import re
import sys

from .daemon import request, serve, status
from .security import (
    ensure_private_directory,
    load_or_create_signing_key,
    public_key_text,
    SecurityError,
)
from .store import Store, StoreError
from .launcher import LaunchError, launch, session_status


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
    attach = commands.add_parser("attach")
    attach.add_argument("--runtime-id", required=True)
    attach.add_argument("--thread-id", required=True)
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
            print(json.dumps(session_status(state_dir, args.session_id)))
            return 0
        if args.command == "run":
            asyncio.run(serve(state_dir))
            return 0
        if args.command == "attach":
            print(
                json.dumps(
                    {"attached": False, "reason": "native_client_binding_unavailable"}
                )
            )
            return 2
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
    except (StoreError, SecurityError) as error:
        print(json.dumps({"reason": error.code}), file=sys.stderr)
        return 2
    except (OSError, ValueError, TimeoutError):
        print(json.dumps({"reason": "local_operation_unavailable"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
