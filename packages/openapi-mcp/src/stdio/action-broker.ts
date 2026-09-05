import type { ActionDispatchPermit } from "../runtime/action-permit.ts";
import { snapshotCredentialAuthorizationBinding } from "../runtime/credential-binding.ts";
import { OpenApiMcpError } from "../runtime/errors.ts";
import { verifyAndSnapshotPreparedCall } from "../runtime/prepared-call.ts";
import type {
  ActionAuthorizer,
  AuthorizationId,
  AuthorizedActionDecision,
  CredentialAuthorizationBinding,
  PreparedCall,
  Sha256,
} from "../runtime/types.ts";

const permitTtlMs = 120_000;
const digestPattern = /^[0-9a-f]{64}$/;
const baseDecisionKeys = [
  "authorizationId",
  "callDigest",
  "credentialBindingDigest",
  "path",
  "status",
] as const;

interface BoundaryOptions {
  readonly now?: () => number;
}

interface PermitTuple {
  readonly callDigest: Sha256;
  readonly credentialBindingDigest: Sha256;
  readonly expiresAt: number;
}

function denied(): OpenApiMcpError {
  return new OpenApiMcpError("ACTION_DENIED", "Action authorization denied");
}

function snapshotDecision(value: unknown): AuthorizedActionDecision {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw denied();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw denied();

  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) throw denied();
  const keys = ownKeys as string[];
  const allowed = [...baseDecisionKeys, "policyDigest"];
  if (
    keys.some((key) => !allowed.includes(key as (typeof allowed)[number])) ||
    baseDecisionKeys.some((key) => !keys.includes(key))
  ) {
    throw denied();
  }

  const fields: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) {
      throw denied();
    }
    fields[key] = descriptor.value;
  }

  if (
    fields.status !== "authorized" ||
    (fields.path !== "per-call" && fields.path !== "exact-policy") ||
    typeof fields.callDigest !== "string" ||
    !digestPattern.test(fields.callDigest) ||
    typeof fields.credentialBindingDigest !== "string" ||
    !digestPattern.test(fields.credentialBindingDigest) ||
    typeof fields.authorizationId !== "object" ||
    fields.authorizationId === null
  ) {
    throw denied();
  }
  if (
    (fields.path === "exact-policy" &&
      (typeof fields.policyDigest !== "string" ||
        !digestPattern.test(fields.policyDigest))) ||
    (fields.path === "per-call" && "policyDigest" in fields)
  ) {
    throw denied();
  }

  const snapshot = {
    status: "authorized",
    callDigest: fields.callDigest as Sha256,
    credentialBindingDigest: fields.credentialBindingDigest as Sha256,
    path: fields.path,
    authorizationId: fields.authorizationId as AuthorizationId,
    ...(fields.path === "exact-policy"
      ? { policyDigest: fields.policyDigest as Sha256 }
      : {}),
  } satisfies AuthorizedActionDecision;
  return Object.freeze(snapshot);
}

function sameTuple(
  decision: AuthorizedActionDecision,
  call: PreparedCall,
  credential: CredentialAuthorizationBinding,
): boolean {
  return (
    decision.callDigest === call.preparedCallDigest &&
    decision.credentialBindingDigest === credential.bindingDigest &&
    credential.profileId === call.credentialProfileId &&
    credential.profileDigest === call.credentialProfileDigest &&
    credential.slotsDigest === call.reservedSlotsDigest
  );
}

/** Package-private: intentionally absent from every public barrel export. */
export function createActionAuthorizationBoundary(
  authorizer: ActionAuthorizer,
  options: BoundaryOptions = {},
): {
  readonly broker: {
    consume(
      decision: AuthorizedActionDecision,
      call: PreparedCall,
      binding: CredentialAuthorizationBinding,
    ): Promise<ActionDispatchPermit>;
  };
  readonly permits: {
    consume(
      permit: ActionDispatchPermit,
      callDigest: Sha256,
      bindingDigest: Sha256,
    ): void;
  };
} {
  const now = options.now ?? Date.now;
  const ownedPermits = new WeakMap<object, PermitTuple>();

  return Object.freeze({
    broker: Object.freeze({
      async consume(
        untrustedDecision: AuthorizedActionDecision,
        untrustedCall: PreparedCall,
        untrustedBinding: CredentialAuthorizationBinding,
      ): Promise<ActionDispatchPermit> {
        try {
          // Check immutability before snapshotting: a successful frozen check
          // leaves even a Proxy target structurally stable for the subsequent
          // own-data validation. Mutable decisions never cross the await.
          const preserveDecisionIdentity =
            typeof untrustedDecision === "object" &&
            untrustedDecision !== null &&
            Object.isFrozen(untrustedDecision);
          const decision = snapshotDecision(untrustedDecision);
          const callPromise = verifyAndSnapshotPreparedCall(untrustedCall);
          const credentialPromise =
            snapshotCredentialAuthorizationBinding(untrustedBinding);
          const [call, credential] = await Promise.all([
            callPromise,
            credentialPromise,
          ]);
          if (!sameTuple(decision, call, credential)) throw denied();

          await authorizer.consume(
            preserveDecisionIdentity ? untrustedDecision : decision,
            call,
            credential,
          );

          const issuedAt = now();
          if (!Number.isFinite(issuedAt)) throw denied();
          const permit = Object.freeze(
            Object.create(null),
          ) as ActionDispatchPermit;
          ownedPermits.set(
            permit,
            Object.freeze({
              callDigest: call.preparedCallDigest,
              credentialBindingDigest: credential.bindingDigest,
              expiresAt: issuedAt + permitTtlMs,
            }),
          );
          return permit;
        } catch {
          throw denied();
        }
      },
    }),
    permits: Object.freeze({
      consume(
        permit: ActionDispatchPermit,
        callDigest: Sha256,
        bindingDigest: Sha256,
      ): void {
        if (typeof permit !== "object" || permit === null) throw denied();
        const tuple = ownedPermits.get(permit);
        if (
          tuple === undefined ||
          tuple.callDigest !== callDigest ||
          tuple.credentialBindingDigest !== bindingDigest
        ) {
          throw denied();
        }
        const currentTime = now();
        if (!Number.isFinite(currentTime) || currentTime >= tuple.expiresAt) {
          throw denied();
        }
        // No await can intervene between the successful check and deletion.
        ownedPermits.delete(permit);
      },
    }),
  });
}
