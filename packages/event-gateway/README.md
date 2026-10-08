# Knitli event gateway foundation

This package owns local event transport, durable receipts, and harness adapters
for the Event Runtime. **Automatic wake is disabled.** This is the Toolshed
foundation for PR2, not its client-attachment release qualification.

Owner decision, 2026-10-05: build the foundation and investigate Codex bridges
with a separate agent. Do not infer a live client's selected thread from a PID,
working directory, loaded thread, or session-tree ID.

```text
signed metadata → bounded listener → private SQLite spool
  queued → durable claim → admitted → durable native request → submitted (ACK pending)
                           └→ never written       └→ retained terminal no-start
                                  └──── exact cloud settlement ────┘ → new attempt
  uncertain native outcome → ambiguous (exact receipt recovery; no blind replay)
```

The dispatcher uses the injected cloud claim DTO and private native bridge.
It persists claim intent before network access and the complete native request
before submission. Definite no-start proof retires only the original permit;
unknown outcomes remain fenced. The integrations have no production defaults. The shipped CLI
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

The wheel includes `event_gateway.native_reader.NativeBridge`, the same private
socket reader used by the qualification harness. A qualified host supplies an
already connected private Unix stream and owns client selection and launch.
The reader closes that stream on `close()` or an invalid exchange. Version 2
remains the default; `receipt_version=3` explicitly enables durable receipt
identity. `restore_attempt(request)` consumes the start-once identity for exact
read-only recovery; it grants neither selection nor permission to start.
`NativeBridgeAdapter` connects this reader to the existing gateway admission
and recovery flow. Installing the reader does not attach or launch a client. See the
[combined native restart qualification](docs/native-bridge/packaged-recovery.md).

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
reference, and fixture bytes at `9b1ab6e2c2cf801fe035c766d03f26f1b2f85790`.

```sh
uv run --frozen python scripts/sync_contract.py --check --fetch
uv run --frozen ruff check src tests scripts
uv run --frozen python -m unittest discover -s tests -v
```

An update requires an explicit reviewed 40-character commit; never a branch or
tag. Ordinary Linux/macOS PR CI checks the local manifest hashes offline, runs
the shared corpus and local fault tests, and installs the wheel outside the
repository. It receives no App key. A trusted-main workflow matches all seven
event/control snapshot files, including both manifests, against one complete
reviewed family. Candidate paths must be regular Git blobs; candidate code is
never checked out or executed. Rotations add policy data rather than verifier
branches or fixture-specific tests. Keep reviewed immutable source pins through
unrelated upstream changes; new snapshot bytes require a reviewed policy change
on main before the consumer can pass.

Policy merges automatically revalidate all open PR heads. Retargeting and
gateway CI completion revalidate the affected head, including stacked PRs.
Queued runs remain serialized; publication rechecks the current head and main
policy so obsolete runs cannot overwrite newer results. Transient reads retry
within a bounded budget, and unavailable evidence reports an error rather than
claiming contract drift. Policy-only PRs retain the existing snapshots and can
pass before the policy lands; dependent consumers remain gated until it lands.
Snapshot verification does not prove that every Python semantic
edge matches TypeScript: the canonical corpus still lacks portable semantic
boundary vectors. Expanding that corpus and running both validators is an open
cross-repository qualification gate.

`security.py` documents a **proposed local** Ed25519 transport seam (exact bytes,
recipient audience, configured public-key ID). The dispatcher retains the exact
cloud admission DTO. Recovery of an expired
original permit can authorize its retirement, never a native start. Cloud
settlement must confirm the complete attempt, permit and evidence before one
fresh attempt returns to waiting; the original budget charge remains. No offline
or cached authority is accepted. Direct native starts retain the full original
request/receipt and one immutable
`native_turn_started` submitted ACK. Recovery retries that ACK and may poll the
original request read-only; it never claims or starts again. Registration does
not prove input observation or release the pending slot. A full InputRecorded
receipt permits a separate immutable observed ACK after confirmed registration.
Older cloud parsers leave the exact ACK pending.
See [no-start settlement](docs/no-start-settlement.md) and
[native input observation](docs/native-input-observation.md) for the qualification
gates. The historical [registration ACK proof](docs/native-start-ack-proof.json)
records its 23 individual causal cases, 173 passing source tests, independent
Node vector and installed-wheel qualification; it does not prove the later
observed phase.

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
