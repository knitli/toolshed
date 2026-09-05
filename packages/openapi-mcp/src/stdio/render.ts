import { OpenApiMcpError } from "../runtime/errors.ts";
import { canonicalJsonBounded } from "../runtime/strict-json.ts";
import type {
  ActionCardinality,
  CredentialAuthorizationBinding,
  JsonValue,
  PreparedCall,
  SafeApprovalPresentation,
  Sha256,
} from "../runtime/types.ts";

const MAX_PRESENTATION_BYTES = 16 * 1024;
const MAX_ARGUMENT_SUMMARY_BYTES = 2_048;
const MAX_DESCRIPTION_BYTES = 512;
const MAX_TEMPLATE_BYTES = 64 * 1024;
const TRUNCATION_MARKER = "TRUNCATED";

interface PolicyActivationInput {
  readonly policyDigest: Sha256;
  readonly expiresAt: number;
  readonly template: unknown;
}

function denied(): OpenApiMcpError {
  return new OpenApiMcpError(
    "ACTION_DENIED",
    "Approval details cannot be displayed safely",
  );
}

function bytes(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function escapedCodePoint(character: string): string {
  const codePoint = character.codePointAt(0);
  if (codePoint === undefined) return "";
  const isControl =
    codePoint <= 0x1f ||
    (codePoint >= 0x7f && codePoint <= 0x9f) ||
    codePoint === 0x2028 ||
    codePoint === 0x2029;
  const isDirectionControl =
    codePoint === 0x061c ||
    (codePoint >= 0x200b && codePoint <= 0x200f) ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069);
  const isAsciiPunctuationOrSpace =
    codePoint <= 0x7e &&
    !(
      (codePoint >= 0x30 && codePoint <= 0x39) ||
      (codePoint >= 0x41 && codePoint <= 0x5a) ||
      (codePoint >= 0x61 && codePoint <= 0x7a)
    );
  if (!isControl && !isDirectionControl && !isAsciiPunctuationOrSpace) {
    return character;
  }
  if (codePoint <= 0xffff) {
    return `\\u${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
  }
  return `\\u{${codePoint.toString(16).toUpperCase()}}`;
}

/** A display encoding, not an HTML or Markdown escaping context. */
function escapeValue(value: string, maxBytes?: number): string {
  let rendered = "";
  for (const character of value) {
    const next = escapedCodePoint(character);
    if (
      maxBytes !== undefined &&
      bytes(rendered) + bytes(next) + bytes(TRUNCATION_MARKER) > maxBytes
    ) {
      return rendered + TRUNCATION_MARKER;
    }
    rendered += next;
  }
  return rendered;
}

function quoted(value: string): string {
  return `"${escapeValue(value)}"`;
}

function quotedDescription(value: string): string {
  return `"${escapeValue(value, MAX_DESCRIPTION_BYTES)}"`;
}

function cardinalityText(cardinality: ActionCardinality): string {
  return cardinality.kind === "bounded"
    ? `bounded (${cardinality.maxAffected})`
    : cardinality.kind;
}

function dataProperties(value: object): readonly [string, unknown][] {
  const entries: [string, unknown][] = [];
  for (const key of Object.keys(value).sort()) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor !== undefined && "value" in descriptor) {
      entries.push([key, descriptor.value]);
    }
  }
  return entries;
}

function valueType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function scalarDescription(value: unknown): string {
  if (typeof value === "string") return quotedDescription(value);
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return quotedDescription(String(value));
  }
  if (Array.isArray(value)) return `array (${value.length} items)`;
  if (typeof value === "object") {
    return `object (${dataProperties(value).length} keys)`;
  }
  return valueType(value);
}

function bodyStructure(body: unknown): readonly string[] {
  const lines: string[] = [];
  const seen = new WeakSet<object>();

  function visit(value: unknown, path: string, depth: number): void {
    if (lines.length >= 128) return;
    if (Array.isArray(value)) {
      if (seen.has(value)) {
        lines.push(`${path}: cyclic array`);
        return;
      }
      seen.add(value);
      const types = [...new Set(value.slice(0, 64).map(valueType))].sort();
      lines.push(
        `${path}: array (${value.length} items; observed types: ${types.join(", ") || "none"})`,
      );
      if (depth < 4 && value.length > 0)
        visit(value[0], `${path}[]`, depth + 1);
      return;
    }
    if (typeof value === "object" && value !== null) {
      if (seen.has(value)) {
        lines.push(`${path}: cyclic object`);
        return;
      }
      seen.add(value);
      const properties = dataProperties(value);
      const keys = properties.map(([key]) => quotedDescription(key)).join(", ");
      lines.push(
        `${path}: object (${properties.length} keys: ${keys || "none"})`,
      );
      if (depth < 4) {
        for (const [key, child] of properties) {
          if (
            Array.isArray(child) ||
            (typeof child === "object" && child !== null)
          ) {
            visit(
              child,
              `${path}.${escapeValue(key, MAX_DESCRIPTION_BYTES)}`,
              depth + 1,
            );
          }
        }
      }
      return;
    }
    lines.push(`${path}: ${valueType(value)}`);
  }

  visit(body, "Body structure", 0);
  return lines;
}

function boundedLines(lines: readonly string[], maximum: number): string {
  let result = "";
  for (const line of lines) {
    const candidate = result.length === 0 ? line : `${result}\n${line}`;
    if (bytes(candidate) <= maximum) {
      result = candidate;
      continue;
    }
    const marker =
      result.length === 0 ? TRUNCATION_MARKER : `\n${TRUNCATION_MARKER}`;
    if (bytes(result) + bytes(marker) <= maximum) result += marker;
    break;
  }
  return result;
}

function argumentSummary(call: PreparedCall): string {
  const lines: string[] = [];
  for (const [section, value] of dataProperties(call.normalizedArguments)) {
    if (section === "body") {
      lines.push(...bodyStructure(value));
      continue;
    }
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      const properties = dataProperties(value);
      lines.push(
        `${escapeValue(section, MAX_DESCRIPTION_BYTES)}: ${properties.length} entries`,
      );
      for (const [key, child] of properties) {
        lines.push(`  ${quotedDescription(key)}: ${scalarDescription(child)}`);
      }
      continue;
    }
    lines.push(
      `${escapeValue(section, MAX_DESCRIPTION_BYTES)}: ${scalarDescription(value)}`,
    );
  }
  return boundedLines(
    lines.length === 0 ? ["none"] : lines,
    MAX_ARGUMENT_SUMMARY_BYTES,
  );
}

function canonicalTemplate(template: unknown): string {
  try {
    return canonicalJsonBounded(template as JsonValue, {
      maxBytes: MAX_TEMPLATE_BYTES,
      maxDepth: 32,
      maxNodes: 4_096,
    });
  } catch {
    throw denied();
  }
}

function frozenCardinality(value: ActionCardinality): ActionCardinality {
  return value.kind === "bounded"
    ? Object.freeze({ kind: value.kind, maxAffected: value.maxAffected })
    : Object.freeze({ kind: value.kind });
}

export function renderApproval(
  call: PreparedCall,
  binding: CredentialAuthorizationBinding,
  activation?: PolicyActivationInput,
): SafeApprovalPresentation {
  try {
    const credentialProfile = escapeValue(binding.profileId);
    const audience = escapeValue(binding.audience ?? "not specified");
    const scopes = Object.freeze(
      binding.scopes.map((scope) => escapeValue(scope)),
    );
    const normalizedArguments = argumentSummary(call);
    const policyActivation = activation
      ? Object.freeze({
          policyDigest: activation.policyDigest,
          expiresAt: activation.expiresAt,
        })
      : undefined;

    const lines = [
      "An external action requires approval.",
      `Catalog: ${quoted(call.catalogId)}`,
      `Release: ${quoted(call.releaseId)}`,
      `Operation: ${quoted(call.operationId)}`,
      `Method: ${quoted(call.method)}`,
      `Origin: ${quoted(call.origin)}`,
      `Relative URL: ${quoted(call.relativeUrl)}`,
      `Action kind: ${quoted(call.actionKind ?? "unknown")}`,
      `Cardinality: ${quoted(cardinalityText(call.cardinality ?? { kind: "unknown" }))}`,
      `Credential profile: "${credentialProfile}"`,
      `Credential audience: "${audience}"`,
      `Credential scopes (${scopes.length}): ${scopes.map((scope) => `"${scope}"`).join(", ") || "none"}`,
      `Operation digest: ${quoted(call.operationDigest)}`,
      `Manifest digest: ${quoted(call.manifestDigest)}`,
      `Credential profile digest: ${quoted(call.credentialProfileDigest)}`,
      `Reserved slots digest: ${quoted(call.reservedSlotsDigest)}`,
      `Prepared call digest: ${quoted(call.preparedCallDigest)}`,
      `Credential binding digest: ${quoted(binding.bindingDigest)}`,
      "Arguments summary:",
      normalizedArguments,
    ];

    if (activation !== undefined) {
      const template = escapeValue(canonicalTemplate(activation.template));
      lines.push(
        "POLICY ACTIVATION WARNING: approving this request also activates reusable standing authority for matching calls.",
        `Policy digest: ${quoted(activation.policyDigest)}`,
        `Policy expiry (Unix milliseconds): ${quoted(String(activation.expiresAt))}`,
        "Complete canonical template constraints:",
        `"${template}"`,
      );
    }

    const message = lines.join("\n");
    if (bytes(message) > MAX_PRESENTATION_BYTES) throw denied();

    return Object.freeze({
      message,
      credentialProfile,
      audience,
      scopes,
      credentialBindingDigest: binding.bindingDigest,
      ...(policyActivation === undefined ? {} : { policyActivation }),
      catalogId: escapeValue(call.catalogId),
      releaseId: escapeValue(call.releaseId),
      operationId: escapeValue(call.operationId),
      method: call.method,
      origin: escapeValue(call.origin),
      relativeUrl: escapeValue(call.relativeUrl),
      actionKind: call.actionKind ?? "unknown",
      cardinality: frozenCardinality(call.cardinality ?? { kind: "unknown" }),
      normalizedArguments,
      preparedCallDigest: call.preparedCallDigest,
    });
  } catch (error) {
    if (error instanceof OpenApiMcpError && error.code === "ACTION_DENIED") {
      throw error;
    }
    throw denied();
  }
}
