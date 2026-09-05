import { isAbsolute } from "node:path";
import { z } from "zod";
import { parseJsonStrict } from "../runtime/strict-json.ts";
import {
  DEFAULT_RUNTIME_LIMITS,
  resolveRuntimeLimits,
} from "../runtime/versions.ts";
import { isOAuthResource } from "../sqlite/oauth-resource.ts";

const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
const path = z.string().min(1).refine(isAbsolute);
const https = z.string().refine((value) => {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" && !url.username && !url.password && !url.hash
    );
  } catch {
    return false;
  }
});
const origin = https.refine((value) => new URL(value).origin === value);
const scopes = z.array(z.string().min(1).max(256)).max(256);
const auth = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("bearer-env"),
    env: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
  }),
  z.strictObject({
    type: z.literal("api-key-env"),
    env: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
    placement: z.enum(["header", "query"]),
    name: z.string().min(1).max(256),
  }),
  z.strictObject({
    type: z.literal("oauth2-pkce"),
    authorizationEndpoint: https,
    tokenEndpoint: https,
    clientId: z.string().min(1).max(1024),
    scopes,
    resource: z.string().refine(isOAuthResource).optional(),
  }),
]);
const profile = z.strictObject({
  profileId: id,
  revision: z.number().int().positive(),
  allowedOrigins: z.array(origin).min(1).max(256),
  auth,
  audience: z.string().min(1).max(2048).optional(),
  scopes: scopes.optional(),
});
const key = z.strictObject({
  issuer: z
    .string()
    .min(1)
    .max(256)
    .regex(/^[\x21-\x7e]+$/),
  keyId: id,
  publicKey: z
    .string()
    .regex(/^[A-Za-z0-9_-]+$/)
    .max(4096),
});
const digest = z.string().regex(/^[0-9a-f]{64}$/);
const constraint: z.ZodType = z.lazy(() =>
  z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("exact"), value: z.json() }),
    z.strictObject({
      kind: z.literal("string-set"),
      values: z.array(z.string()).min(1).max(256),
    }),
    z.strictObject({
      kind: z.literal("number"),
      min: z.number(),
      max: z.number(),
    }),
    z.strictObject({
      kind: z.literal("object"),
      properties: z.record(z.string(), constraint),
    }),
    z.strictObject({
      kind: z.literal("array"),
      maxItems: z.number().int().nonnegative(),
      items: constraint,
    }),
  ]),
);
const exactPolicy = z.strictObject({
  version: z.literal(1),
  catalogId: id,
  releaseId: id,
  manifestDigest: digest,
  operationId: z.string().startsWith("operation:"),
  operationDigest: digest,
  credentialProfileDigest: digest,
  actionKind: z.enum(["create", "update"]),
  cardinality: z.enum(["single", "bounded"]),
  maxAffected: z.number().int().positive(),
  expiresAt: z.number().int().positive(),
  arguments: constraint,
});
const limits = z.strictObject(
  Object.fromEntries(
    Object.entries(DEFAULT_RUNTIME_LIMITS).map(([name, maximum]) => [
      name,
      z.number().int().min(1).max(maximum).optional(),
    ]),
  ),
);
const schema = z.strictObject({
  version: z.literal(1),
  generationStatePath: path,
  catalogs: z
    .array(
      z.strictObject({ catalogId: id, releaseId: id, path, profileId: id }),
    )
    .min(1)
    .max(256),
  trust: z.strictObject({
    releaseKeys: z.array(key).min(1).max(256),
    rollbackKeys: z.array(key).max(256),
  }),
  allowedOrigins: z.array(origin).min(1).max(256),
  profiles: z.array(profile).min(1).max(256),
  limits: limits.optional(),
  exactPolicies: z.array(exactPolicy).max(256).optional(),
});

export type OpenApiStdioConfig = z.infer<typeof schema>;

/** Operator-only input. Error text never contains submitted values or keys. */
export function parseOpenApiStdioConfig(input: unknown): OpenApiStdioConfig {
  try {
    const value =
      typeof input === "string"
        ? parseJsonStrict(input, {
            maxBytes: 1024 * 1024,
            maxDepth: 40,
            maxKeys: 30_000,
          })
        : input;
    const config = schema.parse(value);
    const profileIds = new Set(config.profiles.map((entry) => entry.profileId));
    if (
      profileIds.size !== config.profiles.length ||
      new Set(config.catalogs.map((entry) => entry.catalogId)).size !==
        config.catalogs.length
    )
      throw new Error();
    if (config.catalogs.some((entry) => !profileIds.has(entry.profileId)))
      throw new Error();
    if (
      config.profiles.some((entry) =>
        entry.allowedOrigins.some(
          (allowed) => !config.allowedOrigins.includes(allowed),
        ),
      )
    )
      throw new Error();
    resolveRuntimeLimits(config.limits);
    return config;
  } catch {
    throw new Error("Invalid OpenAPI stdio configuration");
  }
}
