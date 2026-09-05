# Task 8 authorization verification

Scope: the public/local action authorizers, exact-policy compiler/matcher,
approval renderer, credential binding, and private receipt-to-permit broker.
This is not verification of network dispatch, OAuth, stdio serving, package
publication, or hosted Gatekeeper integration; those are later tasks.

The reviewed baseline is PR #17 merge `f73ea42`. PR #18 separately brings that
baseline onto `main`; it does not contain this Task 8 implementation.

## Mutation evidence

The owner explicitly approved temporary local-only guard mutations. One mutant
was applied at a time, exercised by tests, and reversed before the next mutant.
No mutant was committed or pushed.

| Disabled invariant | Mutated tests (pass/fail) | Restored tests (pass/fail) |
| --- | --- | --- |
| Consume requires the authorized call and credential digests | 32/2 | 34/0 |
| Accepted pending confirmation is single-use | 33/1 | 34/0 |
| Broker must invoke the configured authorizer's consume | 7/3 | 10/0 |
| Per-call and exact-policy receipts are removed on consumption | 30/4 | 34/0 |
| Returned action permits must be registered by this boundary | 6/4 | 10/0 |
| Action permits are removed on consumption | 8/2 | 10/0 |

The first mutant initially survived. Existing tests checked input/grant changes
across confirmation entries, but not direct receipt consumption with another
valid call or live credential grant. Two permanent regressions now check that
boundary and kill the effective mutant. Mutated runs failed behavior assertions,
not compilation or syntax checks.

Focused commands, run from `packages/openapi-mcp`, were:

```sh
bun test tests/action-authorizer.test.ts
bun test tests/action-broker.test.ts
bun test tests/action-authorizer.test.ts tests/action-broker.test.ts
```

The Bun executable was the existing mise-managed installation. The final
combined focused run passed 44 tests with 114 assertions. Production guards
were restored by reversing each scoped patch and were independently inspected.
Initial hash output was not retained intact, so byte-for-byte pre/post checksum
equality is not claimed.

## Integration verification

After restoration:

- `mise exec -- bun test packages/openapi-mcp/tests`: 747 passed, 1 intentional
  full-Graph skip, 0 failed; 3564 assertions.
- `mise exec -- bun run --cwd packages/openapi-mcp build`: passed.
- Scoped Biome checks cover all Task 8 TypeScript/package changes.
- `git diff --check`: passed.
- Worker consumer bundle and type checks keep the runtime free of Node/MCP SDK
  dependencies; private brokers and issuers are not runtime exports.

## Review outcomes

Independent implementation review and scoped fix reviews checked:

- Authoritative detached call/credential commitment comparison, including
  divergent Proxy descriptor/getter views.
- Closed authorization contexts and safe response snapshots before awaits.
- Opaque registered state, immutable built-in decision identity, receipt and
  permit registration, exact tuple checks, expiry, replay, and concurrency.
- Bounded ledgers with no live eviction and collision-safe pending cleanup.
- Explicit first-use reusable-policy consent (`confirm` and `activatePolicy`),
  full displayed constraints, and receipt expiry capped by template/activation.
- Cancel, valid update activation, grant/audience/scope changes, malformed
  cardinalities and decisions, and safe bounded approval rendering.

The two late PR #17 plan findings about governing expiry and reusable-policy
disclosure are addressed here in the plan, implementation, and regressions.
