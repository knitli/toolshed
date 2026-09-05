import { sha256 } from "./digest.ts";
import { OpenApiMcpError } from "./errors.ts";
import { canonicalJsonBounded, parseJsonStrict } from "./strict-json.ts";
import type {
  CredentialAuthorizationBinding,
  JsonObject,
  JsonValue,
  PreparedCall,
  Sha256,
} from "./types.ts";

const domain = "knitli.openapi-mcp.credential-binding.v1";
const digestPattern = /^[0-9a-f]{64}$/;

function hasDisallowedCharacter(value: string, forbidSpace: boolean): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= (forbidSpace ? 0x20 : 0x1f) || code === 0x7f) return true;
  }
  return false;
}

function snapshot(value: unknown, hasDigest: boolean): JsonObject {
  try {
    const json = canonicalJsonBounded(value as JsonValue, {
      maxBytes: 16384,
      maxDepth: 4,
      maxNodes: 256,
    });
    const data = parseJsonStrict(json, {
      maxBytes: 16384,
      maxDepth: 4,
      maxKeys: 256,
    }) as JsonObject;
    if (data === null || Array.isArray(data) || typeof data !== "object")
      throw new Error();
    const expected = [
      "profileId",
      "profileDigest",
      "grantId",
      "scopes",
      "slotsDigest",
    ];
    if (hasDigest) expected.push("bindingDigest");
    if (Object.hasOwn(data, "audience")) expected.push("audience");
    if (Object.keys(data).sort().join(",") !== expected.sort().join(","))
      throw new Error();
    if (
      typeof data.profileId !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(data.profileId)
    )
      throw new Error();
    if (
      typeof data.grantId !== "string" ||
      !/^[A-Za-z0-9_-]{16,128}$/.test(data.grantId)
    )
      throw new Error();
    for (const key of hasDigest
      ? ["profileDigest", "slotsDigest", "bindingDigest"]
      : ["profileDigest", "slotsDigest"]) {
      if (typeof data[key] !== "string" || !digestPattern.test(data[key]))
        throw new Error();
    }
    if (
      Object.hasOwn(data, "audience") &&
      (typeof data.audience !== "string" ||
        data.audience.length === 0 ||
        data.audience.length > 2048 ||
        hasDisallowedCharacter(data.audience, false))
    )
      throw new Error();
    if (!Array.isArray(data.scopes) || data.scopes.length > 64)
      throw new Error();
    const scopes: string[] = [];
    for (const scope of data.scopes) {
      if (
        typeof scope !== "string" ||
        scope.length === 0 ||
        scope.length > 256 ||
        hasDisallowedCharacter(scope, true) ||
        scopes.includes(scope)
      )
        throw new Error();
      scopes.push(scope);
    }
    data.scopes = scopes.sort();
    return data;
  } catch {
    throw new OpenApiMcpError(
      "AUTH_PROFILE_INVALID",
      "Credential binding is invalid",
    );
  }
}

export async function digestCredentialAuthorizationBinding(
  value: Omit<CredentialAuthorizationBinding, "bindingDigest">,
): Promise<Sha256> {
  return sha256(domain, snapshot(value, false));
}

export async function snapshotCredentialAuthorizationBinding(
  value: CredentialAuthorizationBinding,
  call?: Pick<
    PreparedCall,
    "credentialProfileId" | "credentialProfileDigest" | "reservedSlotsDigest"
  >,
): Promise<CredentialAuthorizationBinding> {
  const data = snapshot(value, true);
  const callCommitments =
    call === undefined
      ? undefined
      : {
          profileId: call.credentialProfileId,
          profileDigest: call.credentialProfileDigest,
          slotsDigest: call.reservedSlotsDigest,
        };
  const { bindingDigest, ...payload } = data;
  const expected = await sha256(domain, payload);
  if (
    expected !== bindingDigest ||
    (callCommitments !== undefined &&
      (data.profileId !== callCommitments.profileId ||
        data.profileDigest !== callCommitments.profileDigest ||
        data.slotsDigest !== callCommitments.slotsDigest))
  ) {
    throw new OpenApiMcpError(
      "AUTH_PROFILE_INVALID",
      "Credential binding does not match the prepared call",
    );
  }
  Object.freeze(data.scopes);
  return Object.freeze(data) as unknown as CredentialAuthorizationBinding;
}
