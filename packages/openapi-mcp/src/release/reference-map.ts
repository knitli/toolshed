import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { extname, isAbsolute, posix, relative, resolve, sep } from "node:path";
import { sha256 } from "../runtime/digest.ts";
import { parseJsonStrict } from "../runtime/strict-json.ts";
import type { JsonValue, Sha256 } from "../runtime/types.ts";
import {
  type CompilerLimits,
  DEFAULT_COMPILER_LIMITS,
  parseDocumentBytesV4,
  readFileBoundedV4,
} from "./load-v4.ts";

export interface ReferenceMapEntryV1 {
  readonly uri: string;
  readonly file: string;
  readonly sha256: Sha256;
}

export interface ReferenceMapV1 {
  readonly version: 1;
  readonly entries: readonly ReferenceMapEntryV1[];
}

export interface ResolvedReferenceV1 {
  readonly bytes: Uint8Array;
  readonly mediaType: "json" | "yaml";
}

export interface ReferenceResolver {
  resolve(uri: string): Promise<ResolvedReferenceV1>;
}

export interface ResolvedDocumentV4 {
  readonly uri: string;
  readonly document: Record<string, unknown>;
}

const digestPattern = /^[0-9a-f]{64}$/;
const unreserved = /^[A-Za-z0-9._~-]$/;

function normalizeEscapes(value: string): string {
  let output = "";
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== "%") {
      output += value[index];
      continue;
    }
    const pair = value.slice(index + 1, index + 3);
    if (!/^[0-9A-Fa-f]{2}$/.test(pair))
      throw new Error("URI contains an invalid percent escape");
    const character = String.fromCharCode(Number.parseInt(pair, 16));
    output += unreserved.test(character) ? character : `%${pair.toUpperCase()}`;
    index += 2;
  }
  return output;
}

export function normalizeHttpsUri(value: string): string {
  if (value.length > 2048 || !/^[\x21-\x7e]+$/.test(value))
    throw new Error("source URI is invalid");
  normalizeEscapes(value);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("source URI is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  )
    throw new Error(
      "source URI must be credential-free HTTPS without query or fragment",
    );
  url.pathname = normalizeEscapes(url.pathname || "/");
  return url.href;
}

export function sourceUriFromLabel(label: string): string {
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(label) ||
    label === "." ||
    label === ".."
  ) {
    throw new Error("source label is invalid");
  }
  return `urn:openapi-source:${label}`;
}

function normalizeRelativeGraphUri(value: string, base?: string): string {
  if (
    value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("?") ||
    value.includes("#")
  ) {
    throw new Error("relative reference-map URI is invalid");
  }
  const joined =
    base === undefined ? value : posix.join(posix.dirname(base), value);
  const normalized = normalizeEscapes(joined);
  if (
    !normalized ||
    normalized.startsWith("/") ||
    normalized
      .split("/")
      .some((part) => part === "." || part === ".." || part === "")
  ) {
    throw new Error("relative reference-map URI traverses or is noncanonical");
  }
  return normalized;
}

export function normalizeGraphUri(value: string, baseUri: string): string {
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(value)) return normalizeHttpsUri(value);
  if (value.startsWith("//"))
    throw new Error("network-path references are unsupported");
  if (baseUri.startsWith("https:"))
    return normalizeHttpsUri(new URL(value, baseUri).href);
  return normalizeRelativeGraphUri(
    value,
    baseUri.startsWith("urn:") ? undefined : baseUri,
  );
}

function exactObject(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  )
    throw new Error(`${label} shape is invalid`);
  return value as Record<string, unknown>;
}

export async function loadReferenceMap(
  mapPath: string,
  sourceUri: string,
  limits: CompilerLimits = DEFAULT_COMPILER_LIMITS,
): Promise<ReferenceMapV1> {
  let text: string;
  try {
    const bytes = await readFileBoundedV4(
      mapPath,
      Math.min(limits.maxSourceBytes, 8 * 1024 * 1024),
      "reference map",
    );
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("reference map could not be read");
  }
  const root = exactObject(
    parseJsonStrict(text, {
      maxBytes: Math.min(limits.maxSourceBytes, 8 * 1024 * 1024),
      maxDepth: limits.maxJsonDepth,
      maxKeys: limits.maxDocumentKeys,
    }),
    ["entries", "version"],
    "reference map",
  );
  if (root.version !== 1 || !Array.isArray(root.entries))
    throw new Error("reference map version or entries are invalid");
  if (root.entries.length > limits.maxReferencedDocuments)
    throw new Error("referenced document count exceeds limit");
  const seen = new Set<string>();
  const entries = root.entries.map((raw, index) => {
    const entry = exactObject(
      raw,
      ["file", "sha256", "uri"],
      `reference map entry ${index}`,
    );
    if (
      typeof entry.uri !== "string" ||
      typeof entry.file !== "string" ||
      typeof entry.sha256 !== "string" ||
      !digestPattern.test(entry.sha256)
    ) {
      throw new Error(`reference map entry ${index} is invalid`);
    }
    const uri = normalizeGraphUri(entry.uri, sourceUri);
    if (seen.has(uri))
      throw new Error("duplicate normalized reference-map URI");
    seen.add(uri);
    if (
      isAbsolute(entry.file) ||
      entry.file.includes("\\") ||
      entry.file
        .split("/")
        .some((part) => part === "" || part === "." || part === "..")
    ) {
      throw new Error(
        "reference-map file must be a contained POSIX-relative path",
      );
    }
    return { uri, file: entry.file, sha256: entry.sha256 as Sha256 };
  });
  entries.sort((left, right) =>
    left.uri < right.uri ? -1 : left.uri > right.uri ? 1 : 0,
  );
  return { version: 1, entries };
}

export async function referenceGraphDigest(
  map: ReferenceMapV1,
): Promise<Sha256> {
  return sha256(
    "knitli.openapi-mcp.reference-graph.v1",
    map.entries.map(({ uri, sha256: digest }) => ({
      uri,
      sha256: digest,
    })) as JsonValue,
  );
}

export class ReferenceGraphV4 {
  readonly #entries: Map<string, ReferenceMapEntryV1>;
  readonly #cache = new Map<string, ResolvedDocumentV4>();
  readonly #root: string | null;
  readonly #resolver?: ReferenceResolver;
  readonly #limits: CompilerLimits;
  #bytesUsed: number;

  private constructor(
    readonly sourceUri: string,
    readonly map: ReferenceMapV1,
    root: string | null,
    resolver: ReferenceResolver | undefined,
    limits: CompilerLimits,
    rootBytes: number,
  ) {
    this.#entries = new Map(map.entries.map((entry) => [entry.uri, entry]));
    this.#root = root;
    this.#resolver = resolver;
    this.#limits = limits;
    this.#bytesUsed = rootBytes;
  }

  static async create(options: {
    sourceUri: string;
    mapPath?: string;
    referenceRoot?: string;
    resolver?: ReferenceResolver;
    limits: CompilerLimits;
    rootBytes: number;
  }): Promise<ReferenceGraphV4> {
    const map = options.mapPath
      ? await loadReferenceMap(
          options.mapPath,
          options.sourceUri,
          options.limits,
        )
      : { version: 1 as const, entries: [] };
    if (
      (map.entries.length > 0 || options.resolver) &&
      !options.referenceRoot &&
      !options.resolver
    ) {
      throw new Error("reference root is required for a reference map");
    }
    const root = options.referenceRoot
      ? await realpath(options.referenceRoot).catch(() => {
          throw new Error("reference root is invalid");
        })
      : null;
    return new ReferenceGraphV4(
      options.sourceUri,
      map,
      root,
      options.resolver,
      options.limits,
      options.rootBytes,
    );
  }

  async resolve(
    rawRef: string,
    fromUri: string,
    depth: number,
  ): Promise<{
    uri: string;
    pointer: string;
    document: Record<string, unknown>;
  }> {
    if (Buffer.byteLength(rawRef) > this.#limits.maxRefLength)
      throw new Error("reference exceeds ref length limit");
    if (depth > this.#limits.maxJsonDepth)
      throw new Error("reference depth exceeds limit");
    const hashIndex = rawRef.indexOf("#");
    const rawDocument = hashIndex < 0 ? rawRef : rawRef.slice(0, hashIndex);
    const pointer = hashIndex < 0 ? "#" : `#${rawRef.slice(hashIndex + 1)}`;
    if (rawDocument === "")
      throw new Error(
        "local reference must be resolved against its current document",
      );
    const uri = normalizeGraphUri(rawDocument, fromUri);
    const entry = this.#entries.get(uri);
    if (!entry)
      throw new Error("external reference is absent from the reference map");
    let resolved = this.#cache.get(uri);
    if (!resolved) {
      let bytes: Uint8Array;
      let mediaType: "json" | "yaml";
      if (this.#resolver) {
        const result = await this.#resolver.resolve(uri);
        if (
          result.bytes.byteLength >
          this.#limits.maxSourceBytes - this.#bytesUsed
        )
          throw new Error("aggregate source bytes exceed limit");
        bytes = new Uint8Array(result.bytes);
        mediaType = result.mediaType;
      } else {
        if (!this.#root) throw new Error("reference root is required");
        const candidate = resolve(this.#root, ...entry.file.split("/"));
        const actual = await realpath(candidate).catch(() => {
          throw new Error("reference-map file is unavailable");
        });
        const relation = relative(this.#root, actual);
        if (
          relation === "" ||
          relation === ".." ||
          relation.startsWith(`..${sep}`) ||
          isAbsolute(relation)
        )
          throw new Error("reference-map file escapes reference root");
        bytes = await readFileBoundedV4(
          candidate,
          this.#limits.maxSourceBytes - this.#bytesUsed,
          "referenced document",
        ).catch((error) => {
          if (
            error instanceof Error &&
            error.message.includes("exceeds byte limit")
          )
            throw new Error("aggregate source bytes exceed limit");
          throw new Error("referenced document could not be read");
        });
        const extension = extname(entry.file).toLowerCase();
        mediaType =
          extension === ".json"
            ? "json"
            : extension === ".yaml" || extension === ".yml"
              ? "yaml"
              : (() => {
                  throw new Error("unsupported referenced media type");
                })();
      }
      const actualDigest = createHash("sha256").update(bytes).digest("hex");
      if (actualDigest !== entry.sha256)
        throw new Error("reference-map content digest mismatch");
      if (this.#bytesUsed + bytes.byteLength > this.#limits.maxSourceBytes)
        throw new Error("aggregate source bytes exceed limit");
      this.#bytesUsed += bytes.byteLength;
      const document = parseDocumentBytesV4(bytes, mediaType, {
        ...this.#limits,
        maxSourceBytes: bytes.byteLength,
      });
      if (
        typeof document !== "object" ||
        document === null ||
        Array.isArray(document)
      )
        throw new Error("referenced document must be an object");
      resolved = { uri, document: document as Record<string, unknown> };
      this.#cache.set(uri, resolved);
    }
    return { uri, pointer, document: resolved.document };
  }
}
