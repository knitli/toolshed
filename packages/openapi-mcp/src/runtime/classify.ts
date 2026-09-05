import type {
  ActionCardinality,
  ActionKind,
  JsonObject,
  JsonSchemaV4,
  OperationRecordV4,
  SchemaRecordV4,
  TypedSchemaId,
} from "./types.ts";

/** A runtime-derived classification; no value is read from record advisory data. */
export interface OperationClassification {
  readonly safety: "read" | "action";
  readonly actionKind: ActionKind | null;
  readonly cardinality: ActionCardinality | null;
  /** Whether the kind always requires a fresh, per-call confirmation. */
  readonly dangerous: boolean;
  /** Whether the action must be treated as high-risk by the authorizer. */
  readonly highRisk: boolean;
}

const MAX_TOKEN_SOURCE_LENGTH = 1_024;
const MAX_TOKENS = 48;
const MAX_TOKEN_LENGTH = 48;

const communicationTokens = new Set([
  "communicate",
  "email",
  "invite",
  "invitation",
  "mail",
  "message",
  "notify",
  "notification",
  "send",
  "share",
  "sharing",
]);
const authorityTokens = new Set([
  "access",
  "authority",
  "grant",
  "membership",
  "member",
  "permission",
  "privilege",
  "role",
]);
const transactionTokens = new Set([
  "charge",
  "invoice",
  "payment",
  "purchase",
  "refund",
  "transaction",
  "transfer",
]);
const executeTokens = new Set([
  "deploy",
  "execute",
  "invoke",
  "run",
  "start",
  "trigger",
]);
const createTokens = new Set(["add", "create", "provision", "register"]);
const updateTokens = new Set(["modify", "patch", "replace", "set", "update"]);
const bulkTokens = new Set([
  "all",
  "batch",
  "bulk",
  "each",
  "everyone",
  "many",
]);

interface TokenEvidence {
  readonly tokens: readonly string[];
  readonly truncated: boolean;
}

function tokensForSource(source: string): TokenEvidence {
  const inspected = source.slice(0, MAX_TOKEN_SOURCE_LENGTH);
  const words = inspected
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .match(/[a-z0-9]+/g);
  const tokenSource = words ?? [];
  return {
    tokens: tokenSource
      .slice(0, MAX_TOKENS)
      .map((word) => word.slice(0, MAX_TOKEN_LENGTH)),
    truncated:
      source.length > MAX_TOKEN_SOURCE_LENGTH ||
      tokenSource.length > MAX_TOKENS ||
      tokenSource.some((word) => word.length > MAX_TOKEN_LENGTH),
  };
}

function normalizedTokens(operation: OperationRecordV4): TokenEvidence {
  // Each signed source has an independent budget. A source that does not fit
  // cannot be safely classified as routine, because omitted later evidence
  // could establish a dangerous kind or batch cardinality.
  const tokens: string[] = [];
  let truncated = false;
  for (const source of [
    operation.operationId,
    operation.path,
    ...operation.tags,
  ]) {
    const evidence = tokensForSource(source);
    tokens.push(...evidence.tokens);
    truncated ||= evidence.truncated;
  }
  return { tokens, truncated };
}

function hasAny(tokens: readonly string[], candidates: ReadonlySet<string>) {
  return tokens.some(
    (token) =>
      candidates.has(token) ||
      (token.length > 4 &&
        token.endsWith("ies") &&
        candidates.has(`${token.slice(0, -3)}y`)) ||
      (token.length > 4 &&
        token.endsWith("es") &&
        candidates.has(token.slice(0, -2))) ||
      (token.length > 3 &&
        token.endsWith("s") &&
        candidates.has(token.slice(0, -1))),
  );
}

function hasBatchSemantics(
  operation: OperationRecordV4,
  tokens: readonly string[],
) {
  return (
    operation.path === "/$batch" ||
    operation.path.endsWith("/$batch") ||
    tokens.includes("batch")
  );
}

function actionKindFor(
  operation: OperationRecordV4,
  evidence: TokenEvidence,
): ActionKind {
  if (operation.method === "DELETE") return "delete";
  if (evidence.truncated) return "unknown";
  const dangerousMatches: ActionKind[] = [];
  for (const [kind, candidates] of [
    ["communicate", communicationTokens],
    ["authority", authorityTokens],
    ["transaction", transactionTokens],
    ["execute", executeTokens],
  ] as const) {
    if (hasAny(evidence.tokens, candidates)) dangerousMatches.push(kind);
  }
  if (dangerousMatches.length > 0)
    return dangerousMatches.length === 1 ? dangerousMatches[0] : "unknown";
  const routineMatches: ActionKind[] = [];
  for (const [kind, candidates] of [
    ["create", createTokens],
    ["update", updateTokens],
  ] as const) {
    if (hasAny(evidence.tokens, candidates)) routineMatches.push(kind);
  }
  return routineMatches.length === 1 ? routineMatches[0] : "unknown";
}

function isVerifiedArrayBound(schema: JsonSchemaV4): number | null {
  if (typeof schema !== "object" || schema === null || Array.isArray(schema))
    return null;
  if (schema.type !== "array") return null;
  const maxItems = schema.maxItems;
  return typeof maxItems === "number" &&
    Number.isSafeInteger(maxItems) &&
    maxItems > 0
    ? maxItems
    : null;
}

function argumentSection(
  arguments_: JsonObject,
  section: "body" | "headers" | "path" | "query",
): JsonObject | undefined {
  const value = arguments_[section];
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value
    : undefined;
}

function presentParameterSelector(
  arguments_: JsonObject,
  parameter: OperationRecordV4["parameters"][number],
) {
  if (parameter.in === "cookie") return undefined;
  const section = argumentSection(
    arguments_,
    parameter.in === "header" ? "headers" : parameter.in,
  );
  return section !== undefined && Object.hasOwn(section, parameter.name)
    ? section[parameter.name]
    : undefined;
}

function boundedCardinality(
  operation: OperationRecordV4,
  schemas: readonly SchemaRecordV4[],
  normalizedArguments: JsonObject,
): { cardinality: ActionCardinality | null; unprovenArray: boolean } {
  const schemaById = new Map<TypedSchemaId, SchemaRecordV4>();
  const ambiguousSchemaIds = new Set<TypedSchemaId>();
  for (const schema of schemas) {
    if (schemaById.has(schema.id)) ambiguousSchemaIds.add(schema.id);
    else schemaById.set(schema.id, schema);
  }
  let maximum = 0;
  let found = false;
  let unprovenArray = false;
  const containsArray = (value: unknown): boolean => {
    if (Array.isArray(value)) return true;
    return (
      typeof value === "object" &&
      value !== null &&
      Object.values(value).some(containsArray)
    );
  };
  const addBound = (schemaId: TypedSchemaId, selector: unknown) => {
    if (!Array.isArray(selector)) {
      unprovenArray ||= containsArray(selector);
      return;
    }
    // Independent selectors may multiply effects. A single array bound also
    // does not bound nested arrays, so neither shape proves a routine limit.
    if (found || selector.some(containsArray)) {
      unprovenArray = true;
      return;
    }
    if (ambiguousSchemaIds.has(schemaId)) {
      unprovenArray = true;
      return;
    }
    const schema = schemaById.get(schemaId);
    if (schema === undefined) {
      unprovenArray = true;
      return;
    }
    const maxItems = isVerifiedArrayBound(schema.schema);
    if (maxItems === null) {
      unprovenArray = true;
      return;
    }
    maximum = maxItems;
    found = true;
  };
  for (const parameter of operation.parameters) {
    addBound(
      parameter.value.schemaId,
      presentParameterSelector(normalizedArguments, parameter),
    );
  }
  const requestBody = operation.requestBody;
  if (Array.isArray(normalizedArguments.body)) {
    if (requestBody === null || requestBody.content.length !== 1) {
      unprovenArray = true;
    } else {
      addBound(requestBody.content[0].schemaId, normalizedArguments.body);
    }
  } else if (containsArray(normalizedArguments.body)) {
    unprovenArray = true;
  }
  return {
    cardinality:
      !unprovenArray && found && Number.isSafeInteger(maximum) && maximum > 0
        ? { kind: "bounded", maxAffected: maximum }
        : null,
    unprovenArray,
  };
}

function hasTerminalRequiredResourceIdentifier(
  operation: OperationRecordV4,
): boolean {
  const terminalSegment = operation.path.split("/").at(-1);
  return operation.parameters.some(
    (parameter) =>
      parameter.in === "path" &&
      parameter.required &&
      terminalSegment === `{${parameter.name}}` &&
      /^(?:[iI][dD]|[A-Za-z0-9]+(?:Id|ID)|[A-Za-z0-9]+[-_.][iI][dD])$/.test(
        parameter.name,
      ),
  );
}

function cardinalityFor(
  operation: OperationRecordV4,
  tokens: readonly string[],
  schemas: readonly SchemaRecordV4[],
  normalizedArguments: JsonObject,
  truncated: boolean,
): ActionCardinality {
  if (truncated) return { kind: "unknown" };
  if (hasAny(tokens, bulkTokens)) return { kind: "unbounded" };
  const bounded = boundedCardinality(operation, schemas, normalizedArguments);
  if (bounded.unprovenArray) return { kind: "unknown" };
  if (bounded.cardinality !== null) return bounded.cardinality;
  if (hasTerminalRequiredResourceIdentifier(operation))
    return { kind: "single" };
  return { kind: "unknown" };
}

function isDangerous(kind: ActionKind): boolean {
  return kind !== "create" && kind !== "update";
}

/**
 * Recompute safety, action kind, cardinality, and risk from verified records.
 * Compiler-supplied advisory fields intentionally do not participate.
 */
export function classifyOperation(
  operation: OperationRecordV4,
  schemas: readonly SchemaRecordV4[] = [],
  normalizedArguments: JsonObject = {},
): OperationClassification {
  const evidence = normalizedTokens(operation);
  if (
    (operation.method === "GET" || operation.method === "HEAD") &&
    !evidence.truncated &&
    !hasBatchSemantics(operation, evidence.tokens)
  ) {
    return {
      safety: "read",
      actionKind: null,
      cardinality: null,
      dangerous: false,
      highRisk: false,
    };
  }

  const actionKind = actionKindFor(operation, evidence);
  const cardinality = cardinalityFor(
    operation,
    evidence.tokens,
    schemas,
    normalizedArguments,
    evidence.truncated,
  );
  const dangerous = isDangerous(actionKind);
  return {
    safety: "action",
    actionKind,
    cardinality,
    dangerous,
    highRisk:
      dangerous ||
      cardinality.kind === "unknown" ||
      cardinality.kind === "unbounded",
  };
}
