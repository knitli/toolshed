# Synthetic coupled terminal-input fixture

This offline Python fixture composes the existing recovery-input and query paths:

`collect_terminal_inputs` → `NativeTerminalEvidenceAdapter` →
`SessionNativeBridge` → launcher control → Python peer `terminalEvidence`.

The collector reads the exact saved envelope, admission, v3 native request, and
InputRecorded receipt from a read-only SQLite connection. Its validated request
and receipt feed the adapter without rebuilding either from current attachment
state.

## Independent original route

Before collection, the fixture freezes the original `state_dir`, `sessionId`,
`nativeThreadId`, full `nativeBinding`, and original trusted node provenance.
These remain independently fixture-owned inputs to the session route. The
collector's narrower `binding` is correlation data: it cannot reconstruct or
replace the original route or establish its provenance.

The Python peer independently owns the original InputRecorded anchor and stable
terminal response. It models an endpoint check; it does not prove native durable
storage behavior.

## Required assertions

- A changed current attachment does not redirect the historical query; the frozen
  original route is used.
- A wrong original route or trusted node fails closed. A missing original
  InputRecorded anchor or mismatched input item yields no accepted terminal
  evidence.
- Repeating the same terminal query returns the same terminal response, including
  its original turn, input item, terminal status, and receipt identity.
- Recovery performs no Start, selection challenge, ACK, settlement, release, or
  journal writes. Fixture setup may seed SQLite; collection and query execution
  must preserve it.

## Evidence boundary

Passing this fixture establishes synthetic Python composition and correlation
only. It provides no native build, provider, installed-client, actual durable
Rust, or cloud acceptance evidence, and grants no recovery or settlement
authority. Actual integration remains gated on final-source qualification, the
native build and required tests, and trusted provenance evidence. This fixture
neither executes native binaries nor publishes artifacts.
