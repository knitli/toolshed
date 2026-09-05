import { digestCredentialAuthorizationBinding } from "../../src/runtime/credential-binding.ts";
import { sha256 } from "../../src/runtime/digest.ts";
import { createPreparedCall } from "../../src/runtime/prepared-call.ts";
import type {
  ActionAuthorizer,
  AuthorizationId,
  AuthorizedActionDecision,
  CredentialAuthorizationBinding,
  CredentialSnapshot,
  LocalAuthProfile,
  PreparedCall,
  Sha256,
} from "../../src/runtime/types.ts";
import { digestCredentialProfile } from "../../src/sqlite/auth.ts";

export const profile: LocalAuthProfile = {
  profileId: "fixture",
  revision: 1,
  allowedOrigins: ["https://api.example.test"],
  auth: { type: "bearer-env", env: "FIXTURE_TOKEN" },
  scopes: ["write"],
};
export async function credential(
  overrides: Partial<CredentialAuthorizationBinding> = {},
): Promise<CredentialSnapshot> {
  const payload = {
    profileId: profile.profileId,
    profileDigest: await digestCredentialProfile(profile),
    grantId: "fixture_grant_123",
    scopes: ["write"],
    slotsDigest: await sha256("knitli.openapi-mcp.credential-slots.v1", [
      { placement: "header", name: "authorization" },
    ]),
    ...overrides,
  };
  const { bindingDigest: _, ...input } =
    payload as CredentialAuthorizationBinding;
  return {
    credential: { type: "bearer", token: "fixture-secret" },
    binding: {
      ...input,
      bindingDigest: await digestCredentialAuthorizationBinding(input),
    },
  };
}
export async function prepared(
  overrides: Partial<PreparedCall> = {},
): Promise<PreparedCall> {
  const snapshot = await credential();
  return createPreparedCall({
    pageToken: null,
    version: 2,
    catalogId: "fixture" as PreparedCall["catalogId"],
    releaseId: "release" as PreparedCall["releaseId"],
    operationId: "operation:fixture:write",
    operationDigest: "a".repeat(64) as Sha256,
    manifestDigest: "b".repeat(64) as Sha256,
    credentialProfileId: snapshot.binding.profileId,
    credentialProfileDigest: snapshot.binding.profileDigest,
    reservedSlotsDigest: snapshot.binding.slotsDigest,
    method: "POST",
    origin: "https://api.example.test",
    relativeUrl: "/widgets",
    headers: {},
    body: new TextEncoder().encode("hello"),
    normalizedArguments: {},
    safety: "action",
    actionKind: "create",
    cardinality: { kind: "single" },
    ...overrides,
  });
}
export function authorizer(): ActionAuthorizer {
  const decisions = new WeakSet<object>();
  return {
    async authorize(call, binding) {
      const decision = Object.freeze({
        status: "authorized",
        path: "per-call",
        callDigest: call.preparedCallDigest,
        credentialBindingDigest: binding.bindingDigest,
        authorizationId: Object.freeze({}) as AuthorizationId,
      } satisfies AuthorizedActionDecision);
      decisions.add(decision);
      return decision;
    },
    async consume(decision) {
      if (!decisions.delete(decision))
        throw new Error("Unknown or spent decision");
    },
  };
}
