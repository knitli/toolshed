import { sha256 } from "../runtime/digest.ts";
import { OpenApiMcpError } from "../runtime/errors.ts";
import { parseTypedRecordId } from "../runtime/references.ts";
import {
  canonicalJsonBounded,
  parseJsonStrict,
} from "../runtime/strict-json.ts";
import type {
  CatalogId,
  JsonValue,
  PreparedCall,
  ReleaseId,
  Sha256,
  TypedOperationId,
} from "../runtime/types.ts";

export type ArgumentConstraint =
  | { readonly kind: "exact"; readonly value: JsonValue }
  | { readonly kind: "string-set"; readonly values: readonly string[] }
  | { readonly kind: "number"; readonly min: number; readonly max: number }
  | {
      readonly kind: "object";
      readonly properties: Readonly<Record<string, ArgumentConstraint>>;
    }
  | {
      readonly kind: "array";
      readonly maxItems: number;
      readonly items: ArgumentConstraint;
    };

export interface ExactPolicyTemplate {
  readonly version: 1;
  readonly catalogId: CatalogId;
  readonly releaseId: ReleaseId;
  readonly manifestDigest: Sha256;
  readonly operationId: TypedOperationId;
  readonly operationDigest: Sha256;
  readonly credentialProfileDigest: Sha256;
  readonly actionKind: "create" | "update";
  readonly cardinality: "single" | "bounded";
  readonly maxAffected: number;
  readonly expiresAt: number;
  readonly arguments: ArgumentConstraint;
}

export interface CompiledExactPolicy {
  readonly template: Readonly<ExactPolicyTemplate>;
  readonly policyDigest: Sha256;
}

const POLICY_DOMAIN = "knitli.openapi-mcp.exact-policy.v1";
const MAX_POLICY_BYTES = 64 * 1024;
const MAX_POLICY_DEPTH = 32;
const MAX_POLICY_NODES = 4_096;
const MAX_STRING_SET_VALUES = 256;
const MAX_AFFECTED = 10_000;
const digestPattern = /^[0-9a-f]{64}$/;
const shortIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const templateKeys = [
  "actionKind",
  "arguments",
  "cardinality",
  "catalogId",
  "credentialProfileDigest",
  "expiresAt",
  "manifestDigest",
  "maxAffected",
  "operationDigest",
  "operationId",
  "releaseId",
  "version",
] as const;

function invalid(): OpenApiMcpError {
  return new OpenApiMcpError(
    "INPUT_INVALID",
    "Exact policy template is invalid",
  );
}

function objectWithExactKeys(
  value: unknown,
  keys: readonly string[] | null,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalid();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid();
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) throw invalid();
  const stringKeys = ownKeys as string[];
  if (
    keys !== null &&
    (stringKeys.length !== keys.length ||
      stringKeys.some((key) => !keys.includes(key)))
  ) {
    throw invalid();
  }
  for (const key of stringKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) {
      throw invalid();
    }
  }
  return value as Record<string, unknown>;
}

function ownValue(object: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !("value" in descriptor)) throw invalid();
  return descriptor.value;
}

function shortId(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 128 ||
    value === "." ||
    value === ".." ||
    !shortIdPattern.test(value)
  ) {
    throw invalid();
  }
  return value;
}

function digest(value: unknown): Sha256 {
  if (typeof value !== "string" || !digestPattern.test(value)) throw invalid();
  return value as Sha256;
}

function operationId(value: unknown): TypedOperationId {
  if (typeof value !== "string") throw invalid();
  try {
    const parsed = parseTypedRecordId(value);
    if (!parsed.startsWith("operation:")) throw invalid();
    return parsed as TypedOperationId;
  } catch {
    throw invalid();
  }
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw invalid();
  }
  return value;
}

function freezeJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    for (const item of value) freezeJson(item);
    return Object.freeze(value) as unknown as JsonValue;
  }
  if (typeof value === "object" && value !== null) {
    for (const child of Object.values(value)) freezeJson(child);
    return Object.freeze(value);
  }
  return value;
}

function parseConstraint(value: unknown): ArgumentConstraint {
  const source = objectWithExactKeys(value, null);
  const kind = ownValue(source, "kind");
  if (kind === "exact") {
    objectWithExactKeys(source, ["kind", "value"]);
    return Object.freeze({
      kind,
      value: freezeJson(ownValue(source, "value") as JsonValue),
    });
  }
  if (kind === "string-set") {
    objectWithExactKeys(source, ["kind", "values"]);
    const rawValues = ownValue(source, "values");
    if (
      !Array.isArray(rawValues) ||
      rawValues.length > MAX_STRING_SET_VALUES ||
      rawValues.some((item) => typeof item !== "string")
    ) {
      throw invalid();
    }
    const values = [...(rawValues as string[])];
    if (new Set(values).size !== values.length) throw invalid();
    values.sort();
    return Object.freeze({ kind, values: Object.freeze(values) });
  }
  if (kind === "number") {
    objectWithExactKeys(source, ["kind", "max", "min"]);
    const min = ownValue(source, "min");
    const max = ownValue(source, "max");
    if (
      typeof min !== "number" ||
      typeof max !== "number" ||
      !Number.isFinite(min) ||
      !Number.isFinite(max) ||
      min > max
    ) {
      throw invalid();
    }
    return Object.freeze({ kind, min, max });
  }
  if (kind === "object") {
    objectWithExactKeys(source, ["kind", "properties"]);
    const rawProperties = objectWithExactKeys(
      ownValue(source, "properties"),
      null,
    );
    const properties: Record<string, ArgumentConstraint> = Object.create(null);
    for (const key of Object.keys(rawProperties).sort()) {
      properties[key] = parseConstraint(ownValue(rawProperties, key));
    }
    return Object.freeze({ kind, properties: Object.freeze(properties) });
  }
  if (kind === "array") {
    objectWithExactKeys(source, ["items", "kind", "maxItems"]);
    return Object.freeze({
      kind,
      maxItems: boundedInteger(ownValue(source, "maxItems"), 0, MAX_AFFECTED),
      items: parseConstraint(ownValue(source, "items")),
    });
  }
  throw invalid();
}

function parseTemplate(value: JsonValue): Readonly<ExactPolicyTemplate> {
  const source = objectWithExactKeys(value, templateKeys);
  const version = ownValue(source, "version");
  const actionKind = ownValue(source, "actionKind");
  const cardinality = ownValue(source, "cardinality");
  const maxAffected = boundedInteger(
    ownValue(source, "maxAffected"),
    1,
    MAX_AFFECTED,
  );
  const expiresAt = ownValue(source, "expiresAt");
  if (
    version !== 1 ||
    (actionKind !== "create" && actionKind !== "update") ||
    (cardinality !== "single" && cardinality !== "bounded") ||
    (cardinality === "single" && maxAffected !== 1) ||
    typeof expiresAt !== "number" ||
    !Number.isSafeInteger(expiresAt)
  ) {
    throw invalid();
  }
  return Object.freeze({
    version,
    catalogId: shortId(ownValue(source, "catalogId")) as CatalogId,
    releaseId: shortId(ownValue(source, "releaseId")) as ReleaseId,
    manifestDigest: digest(ownValue(source, "manifestDigest")),
    operationId: operationId(ownValue(source, "operationId")),
    operationDigest: digest(ownValue(source, "operationDigest")),
    credentialProfileDigest: digest(
      ownValue(source, "credentialProfileDigest"),
    ),
    actionKind,
    cardinality,
    maxAffected,
    expiresAt,
    arguments: parseConstraint(ownValue(source, "arguments")),
  });
}

/** Validate and normalize an untrusted startup template before hashing it. */
export async function compileExactPolicy(
  input: unknown,
): Promise<CompiledExactPolicy> {
  try {
    // Both operations are synchronous: no caller-owned data survives to the
    // first await, including through proxies, accessors, or later mutation.
    const snapshotJson = canonicalJsonBounded(input as JsonValue, {
      maxBytes: MAX_POLICY_BYTES,
      maxDepth: MAX_POLICY_DEPTH,
      maxNodes: MAX_POLICY_NODES,
    });
    const snapshot = parseJsonStrict(snapshotJson, {
      maxBytes: MAX_POLICY_BYTES,
      maxDepth: MAX_POLICY_DEPTH,
      maxKeys: MAX_POLICY_NODES,
    });
    const template = parseTemplate(snapshot);
    const policyDigest = await sha256(
      POLICY_DOMAIN,
      template as unknown as JsonValue,
    );
    return Object.freeze({ template, policyDigest });
  } catch {
    throw invalid();
  }
}

function ownJsonObject(value: unknown): Record<string, unknown> | null {
  try {
    return objectWithExactKeys(value, null);
  } catch {
    return null;
  }
}

function isCanonicalArray(value: unknown[]): boolean {
  if (Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1) return false;
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    lengthDescriptor.enumerable ||
    lengthDescriptor.value !== value.length
  ) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) {
      return false;
    }
  }
  return true;
}

function exactJson(left: JsonValue, right: unknown): boolean {
  if (
    left === null ||
    typeof left === "boolean" ||
    typeof left === "number" ||
    typeof left === "string"
  ) {
    return Object.is(left, right) || (left === 0 && right === 0);
  }
  if (Array.isArray(left)) {
    if (
      !Array.isArray(right) ||
      right.length !== left.length ||
      !isCanonicalArray(right)
    ) {
      return false;
    }
    for (let index = 0; index < left.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(right, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !exactJson(left[index], descriptor.value)
      ) {
        return false;
      }
    }
    return true;
  }
  const rightObject = ownJsonObject(right);
  if (rightObject === null) return false;
  const keys = Object.keys(left).sort();
  const rightKeys = Object.keys(rightObject).sort();
  if (
    keys.length !== rightKeys.length ||
    keys.some((key, index) => key !== rightKeys[index])
  ) {
    return false;
  }
  return keys.every((key) => exactJson(left[key], ownValue(rightObject, key)));
}

function matchesConstraint(
  constraint: ArgumentConstraint,
  value: unknown,
): boolean {
  if (constraint.kind === "exact") {
    return exactJson(constraint.value, value);
  }
  if (constraint.kind === "string-set") {
    return typeof value === "string" && constraint.values.includes(value);
  }
  if (constraint.kind === "number") {
    return (
      typeof value === "number" &&
      Number.isFinite(value) &&
      value >= constraint.min &&
      value <= constraint.max
    );
  }
  if (constraint.kind === "array") {
    if (
      !Array.isArray(value) ||
      value.length > constraint.maxItems ||
      !isCanonicalArray(value)
    ) {
      return false;
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !matchesConstraint(constraint.items, descriptor.value)
      ) {
        return false;
      }
    }
    return true;
  }
  const object = ownJsonObject(value);
  if (object === null) return false;
  const expectedKeys = Object.keys(constraint.properties).sort();
  const actualKeys = Object.keys(object).sort();
  if (
    expectedKeys.length !== actualKeys.length ||
    expectedKeys.some((key, index) => key !== actualKeys[index])
  ) {
    return false;
  }
  return expectedKeys.every((key) =>
    matchesConstraint(constraint.properties[key], ownValue(object, key)),
  );
}

/** Return true only when every policy identity and closed constraint matches. */
export function matchesExactPolicy(
  policy: CompiledExactPolicy,
  call: PreparedCall,
  nowMs: number,
): boolean {
  try {
    const template = policy.template;
    if (
      !Number.isSafeInteger(nowMs) ||
      nowMs >= template.expiresAt ||
      call.safety !== "action" ||
      (call.actionKind !== "create" && call.actionKind !== "update") ||
      call.actionKind !== template.actionKind ||
      call.catalogId !== template.catalogId ||
      call.releaseId !== template.releaseId ||
      call.manifestDigest !== template.manifestDigest ||
      call.operationId !== template.operationId ||
      call.operationDigest !== template.operationDigest ||
      call.credentialProfileDigest !== template.credentialProfileDigest
    ) {
      return false;
    }
    if (template.cardinality === "single") {
      if (call.cardinality?.kind !== "single" || template.maxAffected !== 1) {
        return false;
      }
    } else if (
      call.cardinality?.kind !== "bounded" ||
      !Number.isSafeInteger(call.cardinality.maxAffected) ||
      call.cardinality.maxAffected > MAX_AFFECTED ||
      call.cardinality.maxAffected > template.maxAffected ||
      call.cardinality.maxAffected < 1
    ) {
      return false;
    }
    return matchesConstraint(template.arguments, call.normalizedArguments);
  } catch {
    return false;
  }
}
