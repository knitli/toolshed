"""Supported stock Codex CLI queue adapter."""

import asyncio
import os
import re
from pathlib import Path
import stat


class StockCodexError(ValueError):
    """A safe stock CLI failure code."""

    def __init__(self, code):
        """Initialize with a safe failure code."""
        self.code = code
        super().__init__(code)


class StockCodexPreflightCancelled(asyncio.CancelledError):
    """Cancellation before process creation, so submission is known not to have started."""


class StockCodexStartFenceError(Exception):
    """The synchronous pre-launch state fence failed before process creation."""

    def __init__(self, cause):
        self.cause = cause
        super().__init__("start_fence_failed")


_REFERENCE = re.compile(r"ref_[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
COMMAND_TIMEOUT = 10


def _canonical_uuid(value):
    from .protocol import ProtocolError, validate_runtime_profile

    try:
        validate_runtime_profile({"profile": "assigned_stock_client", "client": "codex",
                                  "conversationId": value})
        return True
    except ProtocolError:
        return False


def _binary_is_executable(binary_path):
    try:
        binary = os.stat(binary_path)
        return stat.S_ISREG(binary.st_mode) and os.access(binary_path, os.X_OK)
    except OSError:
        return False


class StockCodexAdapter:
    """Queue one opaque event reference in one explicitly assigned conversation."""

    def __init__(self, conversation_id, binary):
        """Bind the adapter to one conversation and CLI binary."""
        if (not _canonical_uuid(conversation_id) or type(binary) is not str  # pylint: disable=unidiomatic-typecheck
                or not Path(binary).is_absolute()):
            raise StockCodexError("invalid_assignment")
        self.conversation_id, self.binary = conversation_id, binary

    # Keep final fencing, process creation and ambiguous-outcome cleanup in one sequence.
    async def submit(self, event_reference, *, before_start=None):  # noqa: MC0001
        """Preflight, synchronously fence, and then queue one opaque reference."""
        if type(event_reference) is not str or not _REFERENCE.fullmatch(event_reference):  # pylint: disable=unidiomatic-typecheck
            raise StockCodexError("invalid_event_reference")
        try:
            executable = await asyncio.to_thread(_binary_is_executable, self.binary)
        except asyncio.CancelledError:
            raise StockCodexPreflightCancelled() from None
        if not executable:
            raise StockCodexError("client_not_started")
        if before_start is not None:
            try:
                before_start()
            except Exception as exc:
                raise StockCodexStartFenceError(exc) from None
        try:
            process = await asyncio.create_subprocess_exec(
                self.binary, "queue", "--thread", self.conversation_id,
                "--message", event_reference,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError:
            raise StockCodexError("command_outcome_unknown") from None
        try:
            async with asyncio.timeout(COMMAND_TIMEOUT):
                code = await process.wait()
        except TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
            raise StockCodexError("command_outcome_unknown") from None
        except asyncio.CancelledError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await asyncio.shield(process.wait())
            raise
        if code != 0:
            raise StockCodexError("command_outcome_unknown")
        return {"status": "command_accepted"}
