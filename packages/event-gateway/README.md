# Knitli event gateway foundation

This package owns local event transport, durable receipts, and harness adapters
for the Event Runtime. **Automatic wake is disabled.** This is the Toolshed
foundation for PR2, not its client-attachment release qualification.

Owner decision, 2026-10-05: build the foundation and investigate Codex bridges
with a separate agent. Do not infer a live client's selected thread from a PID,
working directory, loaded thread, or session-tree ID.

```text
signed metadata → bounded listener → private SQLite spool
  queued → fresh authority + proven client → submitting → submitted → observed
                                              └→ ambiguous (no blind replay)
```

The dispatcher exposes injected integration seams for tests. The shipped CLI
cannot configure a production authority, admit clients, enable the Mesh listener,
or submit native turns. `attach` visibly refuses; `enroll` creates a local key
and prepares an owner request without claiming cloud enrollment. The private
control daemon supports status and detach only. Installation does not start it.

## Install and run

Requires Apple Silicon macOS or Linux and Python 3.13+. Development and CI pin Python 3.13.14
and uv 0.12.15. Use the committed lock:

```sh
cd packages/event-gateway
uv sync --frozen
uv run --frozen knitli-event-gateway --help
uv run --frozen knitli-event-gateway status
uv run --frozen knitli-event-gateway run
```

Build with `uv build --wheel`, then install that wheel in an isolated environment
or with `uv tool install path/to/knitli_event_gateway-0.1.0-py3-none-any.whl`.
The installed wheel embeds the verified contract; no contract fetch happens at
runtime. There is no PyPI publication workflow in this PR.

Default state is `~/.local/state/knitli-event-gateway`, with mode 0700 directories
and 0600 files/socket. `--state-dir PATH` accepts a private directory without
symlink components; use canonical `/private/tmp` paths for macOS scratch tests.
Never place it in a shared or synced directory. Stop the daemon before upgrading;
unsupported database versions refuse to open. Restart quarantines unfinished
native attempts as ambiguous, preserving receipts and explicit recovery needs.

No service is installed or native client resumed on reboot. User-service
installation and full owner enrollment remain qualification work after the
presence/authority seams are implemented.

## Contract and validation

`contracts/event-v1/manifest.json` pins the canonical OS schema, semantic
reference, and fixture bytes at `cd7b288daaccef6c042ad23598668afe2e220925`.

```sh
uv run --frozen python scripts/sync_contract.py --check --fetch
uv run --frozen ruff check src tests scripts
uv run --frozen python -m unittest discover -s tests -v
```

An update requires an explicit reviewed 40-character commit; never a branch or
tag. CI verifies the vendored bytes against upstream Git blobs on Linux and Mac,
runs the shared corpus and local fault tests, and installs the wheel outside
the repository. Snapshot verification does not prove that every Python semantic
edge matches TypeScript: the canonical corpus still lacks portable semantic
boundary vectors. Expanding that corpus and running both validators is an open
cross-repository qualification gate.

`security.py` documents a **proposed local** Ed25519 transport seam (exact bytes,
recipient audience, configured public-key ID). `gateway.Permit` is an injected
admission interface, not a deployed cloud DTO. PR3 must freeze and implement
authenticated owner enrollment, key rotation/revocation, single-use claims,
current authority/source/attachment fences, and acknowledgment recovery. No
offline or cached authority is accepted.

The spool retains accepted metadata, private attachment mappings, deduplication,
and ambiguity. It fences generations, stops at capacity, and never evicts live
work to admit new deliveries. Busy queued work outlives transport freshness and
needs fresh admission later. It preserves all distinct events; source-aware
coalescing remains a later full-gateway gate.

See [client presence evidence](docs/client-presence.md) and
[bridge investigation](docs/codex-bridge-options.md) for the remaining client gate.
Three-session routing, authenticated live Mesh delivery, owner enrollment,
installed user-service lifecycle, and cross-repository semantic conformance
must pass before release. The prior bounded spike is historical evidence only.
