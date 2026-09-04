import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { extname } from "node:path";
import { isAlias, isMap, isScalar, isSeq, parseDocument } from "yaml";
import type { OpenApiDoc } from "../load.ts";
import { parseJsonStrict } from "../runtime/strict-json.ts";

export interface CompilerLimits {
  readonly maxSourceBytes: number;
  readonly maxReferencedDocuments: number;
  readonly maxPaths: number;
  readonly maxOperations: number;
  readonly maxSchemas: number;
  readonly maxParametersPerOperation: number;
  readonly maxPropertiesPerSchema: number;
  readonly maxStringBytes: number;
  readonly maxRefLength: number;
  readonly maxJsonDepth: number;
  readonly maxRecordBytes: number;
  readonly maxYamlAliasExpansions: number;
  readonly maxDocumentNodes: number;
  readonly maxDocumentKeys: number;
}

export const DEFAULT_COMPILER_LIMITS: CompilerLimits = Object.freeze({
  maxSourceBytes: 128 * 1024 * 1024,
  maxReferencedDocuments: 1_024,
  maxPaths: 100_000,
  maxOperations: 100_000,
  maxSchemas: 50_000,
  maxParametersPerOperation: 256,
  maxPropertiesPerSchema: 10_000,
  maxStringBytes: 1 * 1024 * 1024,
  maxRefLength: 2_048,
  maxJsonDepth: 64,
  maxRecordBytes: 1 * 1024 * 1024,
  maxYamlAliasExpansions: 100,
  maxDocumentNodes: 1_000_000,
  maxDocumentKeys: 250_000,
});

const forbiddenKeys = new Set(["__proto__", "prototype", "constructor"]);

export async function readFileBoundedV4(
  path: string,
  maxBytes: number,
  label: string,
  allowStreaming = false,
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0)
    throw new Error(`${label} byte limit is invalid`);
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0)
    throw new Error(`${label} requires O_NOFOLLOW support`);
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP")
      throw new Error(`${label} is unsafe or symbolic`, { cause: error });
    throw error;
  }
  try {
    const before = await handle.stat({ bigint: true });
    if (
      (!before.isFile() && !(allowStreaming && before.isFIFO())) ||
      before.nlink !== 1n
    )
      throw new Error(`${label} is not a safe single-link file`);
    if (before.isFile() && before.size > BigInt(maxBytes))
      throw new Error(`${label} exceeds byte limit`);
    const chunks: Uint8Array[] = [];
    let total = 0;
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1) || 1);
    while (true) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        buffer.byteLength,
        null,
      );
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) throw new Error(`${label} exceeds byte limit`);
      chunks.push(Uint8Array.from(buffer.subarray(0, bytesRead)));
    }
    const after = await handle.stat({ bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino)
      throw new Error(`${label} identity changed while reading`);
    const current = await lstat(path, { bigint: true }).catch(() => null);
    if (
      !current ||
      current.isSymbolicLink() ||
      current.dev !== before.dev ||
      current.ino !== before.ino
    )
      throw new Error(`${label} pathname identity changed while reading`);
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

function requirePositiveLimits(limits: CompilerLimits): void {
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 0)
      throw new Error(`${name} is invalid`);
  }
}

function detachAndValidate(value: unknown, limits: CompilerLimits): unknown {
  const active = new WeakSet<object>();
  let nodes = 0;
  let keys = 0;
  const copy = (input: unknown, depth: number): unknown => {
    nodes += 1;
    if (nodes > limits.maxDocumentNodes)
      throw new Error("document exceeds node limit");
    if (depth > limits.maxJsonDepth)
      throw new Error("document exceeds JSON depth limit");
    if (typeof input === "string") {
      if (Buffer.byteLength(input) > limits.maxStringBytes)
        throw new Error("document string exceeds byte limit");
      return input;
    }
    if (
      input === null ||
      typeof input === "boolean" ||
      typeof input === "number"
    )
      return input;
    if (Array.isArray(input)) {
      if (active.has(input))
        throw new Error("document contains an alias cycle");
      active.add(input);
      const result = input.map((entry) => copy(entry, depth + 1));
      active.delete(input);
      return result;
    }
    if (typeof input !== "object")
      throw new Error("document contains a non-JSON value");
    if (active.has(input)) throw new Error("document contains an alias cycle");
    active.add(input);
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(input)) {
      keys += 1;
      if (keys > limits.maxDocumentKeys)
        throw new Error("document exceeds key limit");
      if (forbiddenKeys.has(key))
        throw new Error(`document contains forbidden key ${key}`);
      if (Buffer.byteLength(key) > limits.maxStringBytes)
        throw new Error("document key exceeds string byte limit");
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (descriptor === undefined || !("value" in descriptor))
        throw new Error("document contains an accessor");
      result[key] = copy(descriptor.value, depth + 1);
    }
    active.delete(input);
    return result;
  };
  return copy(value, 0);
}

function validateYamlAst(root: unknown, limits: CompilerLimits): void {
  const stack: Array<{ node: unknown; depth: number }> = [
    { node: root, depth: 0 },
  ];
  let nodes = 0;
  let keys = 0;
  let aliases = 0;
  while (stack.length > 0) {
    const { node, depth } = stack.pop() as { node: unknown; depth: number };
    nodes += 1;
    if (nodes > limits.maxDocumentNodes)
      throw new Error("YAML document exceeds node limit");
    if (depth > limits.maxJsonDepth)
      throw new Error("YAML document exceeds depth limit");
    if (isAlias(node)) {
      aliases += 1;
      if (aliases > limits.maxYamlAliasExpansions)
        throw new Error("YAML alias expansion limit exceeded");
      continue;
    }
    if (isMap(node)) {
      for (const pair of node.items) {
        keys += 1;
        if (keys > limits.maxDocumentKeys)
          throw new Error("YAML document exceeds key limit");
        if (!isScalar(pair.key) || typeof pair.key.value !== "string")
          throw new Error("YAML mapping keys must be strings");
        if (forbiddenKeys.has(pair.key.value))
          throw new Error(`document contains forbidden key ${pair.key.value}`);
        if (Buffer.byteLength(pair.key.value) > limits.maxStringBytes)
          throw new Error("YAML key exceeds string byte limit");
        if (pair.value !== null)
          stack.push({ node: pair.value, depth: depth + 1 });
      }
      continue;
    }
    if (isSeq(node)) {
      for (const child of node.items)
        if (child !== null) stack.push({ node: child, depth: depth + 1 });
      continue;
    }
    if (
      isScalar(node) &&
      typeof node.value === "string" &&
      Buffer.byteLength(node.value) > limits.maxStringBytes
    ) {
      throw new Error("YAML string exceeds byte limit");
    }
  }
}

export function parseDocumentBytesV4(
  bytes: Uint8Array,
  mediaType: "json" | "yaml",
  limitOverrides: Partial<CompilerLimits> = {},
): unknown {
  const limits = { ...DEFAULT_COMPILER_LIMITS, ...limitOverrides };
  requirePositiveLimits(limits);
  if (bytes.byteLength > limits.maxSourceBytes)
    throw new Error("aggregate source bytes exceed limit");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let parsed: unknown;
  if (mediaType === "json") {
    parsed = parseJsonStrict(text, {
      maxBytes: limits.maxSourceBytes,
      maxDepth: limits.maxJsonDepth,
      maxKeys: limits.maxDocumentKeys,
    });
  } else {
    const document = parseDocument(text, {
      version: "1.2",
      schema: "core",
      strict: true,
      uniqueKeys: true,
      stringKeys: true,
      merge: false,
    });
    if (
      document.errors.length > 0 ||
      document.warnings.length > 0 ||
      document.contents === null
    ) {
      const issue = document.errors[0] ?? document.warnings[0];
      throw new Error(
        `invalid YAML document: ${issue?.message ?? "empty document"}`,
      );
    }
    validateYamlAst(document.contents, limits);
    parsed = document.toJS({
      maxAliasCount: limits.maxYamlAliasExpansions,
    });
  }
  return detachAndValidate(parsed, limits);
}

export function parseSpecBytesV4(
  bytes: Uint8Array,
  mediaType: "json" | "yaml",
  limitOverrides: Partial<CompilerLimits> = {},
): OpenApiDoc {
  const detached = parseDocumentBytesV4(
    bytes,
    mediaType,
    limitOverrides,
  ) as OpenApiDoc;
  if (
    !detached ||
    typeof detached !== "object" ||
    typeof detached.openapi !== "string" ||
    !/^3\.(?:0|1)\.[0-9]+$/.test(detached.openapi) ||
    typeof detached.paths !== "object" ||
    detached.paths === null ||
    Array.isArray(detached.paths)
  ) {
    throw new Error("unsupported OpenAPI version or missing paths object");
  }
  return detached;
}

export async function loadSpecV4(
  path: string,
  limitOverrides: Partial<CompilerLimits> = {},
): Promise<OpenApiDoc> {
  const limits = { ...DEFAULT_COMPILER_LIMITS, ...limitOverrides };
  requirePositiveLimits(limits);
  const extension = extname(path).toLowerCase();
  const mediaType =
    extension === ".json"
      ? "json"
      : extension === ".yaml" || extension === ".yml"
        ? "yaml"
        : null;
  if (mediaType === null)
    throw new Error("unsupported OpenAPI media type or file extension");
  let bytes: Uint8Array;
  try {
    bytes = await readFileBoundedV4(
      path,
      limits.maxSourceBytes,
      "source document",
      true,
    );
  } catch (error) {
    if (error instanceof Error && error.message.includes("exceeds byte limit"))
      throw new Error("source bytes exceed limit", { cause: error });
    throw new Error(`source document could not be read`, { cause: error });
  }
  return parseSpecBytesV4(bytes, mediaType, limits);
}

export function redactSourcePath(
  _path: string,
  sourceLabel = "source document",
): string {
  return sourceLabel;
}
