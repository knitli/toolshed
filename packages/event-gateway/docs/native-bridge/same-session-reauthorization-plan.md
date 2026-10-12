# Proposed same-session reauthorization slice

Status: research proposal pending contract review; no adopted public protocol,
schema, production implementation, or live acceptance claim. The
[three-session runbook](three-session-acceptance.md) and
[native selection source spike](../native-selection-spike.md) supply the
controlled qualification context. Explicit fixture reattach demonstrates
recovery after reauthorization, not unattended successive-turn continuity.

## Current boundary

The cumulative native patch deliberately revokes before active-thread events,
server events, non-Draw terminal events, and semantic application events.
Turn-start/completion notifications therefore invalidate an admitted binding;
`nativeStart` itself does not directly increment a generation. Draw and narrowly
validated display-only periodic rate-limit responses preserve selection.
Readiness loss, a 750 ms loop/lease gap, selection change, and reconnect retain
their existing fences. Core idle checks remain authoritative at Start commit.

| Field | Existing lifecycle |
| --- | --- |
| `clientId` | Created once per TUI witness; stable during the same process. |
| `connectionId` | Fresh on connection/reconnection; never continuity proof across reconnect. |
| `backendPid` | Observed from connected server diagnostics; require exact equality. |
| `serverInstanceId` | Server incarnation; require exact equality. |
| `threadId` | Selected native thread; first configuration establishes it, user selection can change it. |
| `generation` | Increments on local thread/eligibility changes and connection; revoke then ready can increment twice. |
| `serverGeneration` | Increments on server selection/readiness change, expiry, or connection close; unchanged renewal preserves it. |

First-thread generation totals depend on startup events. Completion may cause
multiple revoke/ready cycles, not a fixed increment. Nonbinding heartbeat
sequence/nonce/cause and lease timing must not substitute for identity.
Launcher, SessionNativeBridge, and Gateway currently require the complete
admitted tuple. Their refusal after generation rotation is correct.

## Smallest proposed implementation

Reuse `cli.py::_native_lifecycle`, `_commit_native_call`, and
`_persist_native_lifecycle`: authenticated attach, fresh native challenge,
durable pending commit, cloud CAS, and exact post-commit binding check.
Review automatic invocation of this lifecycle before proposing any new public
operation or wire field; retain the native transport and exact Start comparisons.

1. Restrict automatic renewal of authority to an explicit owner allowlist and
   bounded per-runtime retries, elapsed time, and existing delivery/model
   budgets. A failed CAS or challenge grants no delivery or budget exemption.
2. Require the original session ID and exact `clientId`, `connectionId`,
   `backendPid`, `serverInstanceId`, and `threadId`. No successor-session or
   same-thread replacement shortcut. Require unchanged owner/source policy.
3. Settle/reconcile prior attempts using their immutable historical request,
   original binding and receipt version before replacing the mapping. Recover
   lost ACKs idempotently. Unknown Start/ACK state remains quarantined and
   blocks rotation; reauthorization must not turn ambiguity into a new Start.
4. Obtain fresh eligible native evidence, use the current expected cloud
   runtime/attachment generations, commit through the existing authenticated
   attach/CAS path, then verify remote readback and fresh native identity before
   making the new local mapping dispatchable. Journal before remote mutation.
5. Keep queued C2's original envelope immutable and fenced. Recover its durable
   source/watch obligation through the authorized cloud delivery writer for the
   new generation, with deduplication and a fresh valid admission. Never retarget
   C2, reuse its permit, or treat fixture-created C3 as production recovery.

Generation increases alone cannot distinguish an ordinary completed turn from
a user opening/cancelling a picker and returning to the same thread. Existing
fresh equality checks are insufficient to authorize that distinction. Contract
review must identify trusted causal continuity evidence or require explicit
owner reauthorization; deny when that evidence is absent. Reconnect, server
replacement, user selection, and policy changes must remain denied even if the
final thread ID matches.

The [continuity source spike](native-continuity-spike.md) proposes a sticky
continuity-break epoch combined with exact native-started turn correlation.
It remains unqualified; a diagnostic cause string or bare epoch is insufficient.

## Cloud dependency

The [cloud retention foundation #757](https://github.com/knitli/knitli-site/pull/757)
is merged (coordination status).
Retention alone does not settle source observations or implement the delivery
writer that carries a retained source/watch obligation into a new authorized
generation. That cloud settlement/delivery-writer integration and its contract
remain unresolved release dependencies; this proposal does not claim them.

## Proof and release order

Independent native causal-policy tests, local orchestration/journal tests, and
cloud settlement/writer contract work can build and test in parallel.
Release remains ordered: approve the authority/continuity contract; implement
and qualify dependency paths; pin reviewed sources/builds; run controlled
integration; only then run separately authorized live gates from the runbook.

Required behavioral proofs:

- Two successive native turns complete with no manual attach; exact same session
  identity persists, historical requests remain unchanged, and each Start occurs once.
- Busy C2 survives daemon restart, remains fenced after rotation, and its retained
  source obligation produces one newly authorized delivery without losing work.
- Lost observed ACK followed by reauthorization reconciles/settles the old attempt
  first; unresolved ambiguity cannot dispatch a replacement.
- Competing CAS writers yield one committed mapping; the loser does not dispatch.
- User selection including away-and-back, reconnect, server replacement, policy
  change, and missing causal continuity evidence deny automatic reauthorization.
- Crashes before remote commit and after commit/before local persistence recover
  by durable intent and exact readback, without duplicate attach or Start.
- Budget exhaustion and missing owner allowlist stop recovery; stale C2 and old
  permits remain refused after successful reauthorization.
