"""Shared full-schema native witness fixture."""

from uuid import uuid4


def witness(nonce=1, **changes):
    return {
        "version": 2,
        "nonce": nonce,
        "clientId": str(uuid4()),
        "backendPid": 123,
        "connectionId": str(uuid4()),
        "threadId": str(uuid4()),
        "generation": 2,
        "eligible": True,
        "sequence": 1,
        "cause": "heartbeat",
        "serverInstanceId": str(uuid4()),
        "serverGeneration": 1,
        "leaseMs": 750,
        "nativeCoreTurnState": "idle",
        **changes,
    }

