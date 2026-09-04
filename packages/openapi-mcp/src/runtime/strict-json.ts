import { OpenApiMcpError } from "./errors.ts";
import type { JsonObject, JsonValue } from "./types.ts";
import { DEFAULT_RUNTIME_LIMITS } from "./versions.ts";

/** Bounds applied while accepting untrusted JSON text. */
export interface StrictJsonLimits {
  maxBytes: number;
  maxDepth: number;
  maxKeys: number;
}

export const DEFAULT_STRICT_JSON_LIMITS: StrictJsonLimits = {
  maxBytes: DEFAULT_RUNTIME_LIMITS.maxManifestBytes,
  maxDepth: DEFAULT_RUNTIME_LIMITS.maxJsonDepth,
  maxKeys: DEFAULT_RUNTIME_LIMITS.maxManifestRecords,
};

const forbiddenKeys = new Set(["__proto__", "prototype", "constructor"]);

function invalidJson(message: string): OpenApiMcpError {
  return new OpenApiMcpError("MANIFEST_INVALID", message);
}

function assertWellFormedString(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw invalidJson("JSON string contains an unpaired surrogate");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw invalidJson("JSON string contains an unpaired surrogate");
    }
  }
}

class StrictJsonParser {
  #position = 0;
  #keyCount = 0;

  constructor(
    readonly text: string,
    readonly limits: StrictJsonLimits,
  ) {}

  parse(): JsonValue {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.#position !== this.text.length) {
      throw invalidJson("JSON input has trailing characters");
    }
    return value;
  }

  private parseValue(depth: number): JsonValue {
    const token = this.text[this.#position];
    switch (token) {
      case "{":
        return this.parseObject(depth);
      case "[":
        return this.parseArray(depth);
      case '"':
        return this.parseString();
      case "t":
        return this.parseLiteral("true", true);
      case "f":
        return this.parseLiteral("false", false);
      case "n":
        return this.parseLiteral("null", null);
      default:
        if (
          token === "-" ||
          (token !== undefined && token >= "0" && token <= "9")
        ) {
          return this.parseNumber();
        }
        throw invalidJson("JSON input has an invalid value");
    }
  }

  private parseObject(depth: number): JsonObject {
    this.assertContainerDepth(depth);
    this.#position += 1;
    this.skipWhitespace();
    const object = Object.create(null) as JsonObject;
    if (this.consume("}")) return object;

    while (true) {
      if (this.text[this.#position] !== '"') {
        throw invalidJson("JSON object key must be a string");
      }
      const key = this.parseString();
      if (forbiddenKeys.has(key)) {
        throw invalidJson("JSON object contains a forbidden prototype key");
      }
      if (Object.hasOwn(object, key)) {
        throw invalidJson("JSON object contains a duplicate key");
      }
      this.#keyCount += 1;
      if (this.#keyCount > this.limits.maxKeys) {
        throw invalidJson("JSON input exceeds its key limit");
      }
      this.skipWhitespace();
      this.expect(":");
      this.skipWhitespace();
      object[key] = this.parseValue(depth + 1);
      this.skipWhitespace();
      if (this.consume("}")) return object;
      this.expect(",");
      this.skipWhitespace();
    }
  }

  private parseArray(depth: number): JsonValue[] {
    this.assertContainerDepth(depth);
    this.#position += 1;
    this.skipWhitespace();
    const values: JsonValue[] = [];
    if (this.consume("]")) return values;

    while (true) {
      values.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      if (this.consume("]")) return values;
      this.expect(",");
      this.skipWhitespace();
    }
  }

  private parseString(): string {
    this.expect('"');
    let value = "";
    while (this.#position < this.text.length) {
      const character = this.text[this.#position];
      if (character === '"') {
        this.#position += 1;
        assertWellFormedString(value);
        return value;
      }
      if (character === "\\") {
        this.#position += 1;
        const escapeSequence = this.text[this.#position];
        this.#position += 1;
        switch (escapeSequence) {
          case '"':
          case "\\":
          case "/":
            value += escapeSequence;
            break;
          case "b":
            value += "\b";
            break;
          case "f":
            value += "\f";
            break;
          case "n":
            value += "\n";
            break;
          case "r":
            value += "\r";
            break;
          case "t":
            value += "\t";
            break;
          case "u": {
            const hex = this.text.slice(this.#position, this.#position + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
              throw invalidJson("JSON string has an invalid Unicode escape");
            }
            value += String.fromCharCode(Number.parseInt(hex, 16));
            this.#position += 4;
            break;
          }
          default:
            throw invalidJson("JSON string has an invalid escape");
        }
        continue;
      }
      if (character === undefined || character.charCodeAt(0) < 0x20) {
        throw invalidJson("JSON string has an unescaped control character");
      }
      value += character;
      this.#position += 1;
    }
    throw invalidJson("JSON string is unterminated");
  }

  private parseNumber(): number {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      this.text.slice(this.#position),
    );
    if (match === null) throw invalidJson("JSON input has an invalid number");
    this.#position += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) {
      throw invalidJson("JSON input has a non-finite number");
    }
    return number;
  }

  private parseLiteral<T extends null | boolean>(literal: string, value: T): T {
    if (!this.text.startsWith(literal, this.#position)) {
      throw invalidJson("JSON input has an invalid literal");
    }
    this.#position += literal.length;
    return value;
  }

  private assertContainerDepth(depth: number): void {
    if (depth >= this.limits.maxDepth) {
      throw invalidJson("JSON input exceeds its nesting depth limit");
    }
  }

  private skipWhitespace(): void {
    while (/[\x20\t\n\r]/.test(this.text[this.#position] ?? "")) {
      this.#position += 1;
    }
  }

  private consume(character: string): boolean {
    if (this.text[this.#position] !== character) return false;
    this.#position += 1;
    return true;
  }

  private expect(character: string): void {
    if (!this.consume(character)) {
      throw invalidJson(`JSON input expected ${character}`);
    }
  }
}

/** Parse JSON without giving duplicate or prototype keys JavaScript object semantics. */
export function parseJsonStrict(
  text: string,
  limits: StrictJsonLimits = DEFAULT_STRICT_JSON_LIMITS,
): JsonValue {
  if (!Number.isSafeInteger(limits.maxBytes) || limits.maxBytes < 0) {
    throw invalidJson("JSON byte limit is invalid");
  }
  if (!Number.isSafeInteger(limits.maxDepth) || limits.maxDepth < 1) {
    throw invalidJson("JSON depth limit is invalid");
  }
  if (!Number.isSafeInteger(limits.maxKeys) || limits.maxKeys < 0) {
    throw invalidJson("JSON key limit is invalid");
  }
  if (new TextEncoder().encode(text).byteLength > limits.maxBytes) {
    throw invalidJson("JSON input exceeds its byte limit");
  }
  return new StrictJsonParser(text, limits).parse();
}

/** Deterministic JSON serialization for logical signed and hashed values. */
export function canonicalJson(value: JsonValue): string {
  return serializeCanonical(value, new Set<object>());
}

export interface BoundedCanonicalJsonLimits {
  maxBytes: number;
  maxDepth: number;
  maxNodes: number;
}

class BoundedCanonicalWriter {
  readonly #chunks: string[] = [];
  readonly #ancestors = new Set<object>();
  #segment = "";
  #bytes = 0;
  #nodes = 0;

  constructor(readonly limits: BoundedCanonicalJsonLimits) {}

  serialize(value: JsonValue): string {
    this.#value(value, 0);
    this.#flush();
    return this.#chunks.join("");
  }

  #write(fragment: string, bytes = fragment.length): void {
    if (this.#bytes + bytes > this.limits.maxBytes) {
      throw invalidJson("Canonical JSON exceeds its byte limit");
    }
    this.#bytes += bytes;
    this.#segment += fragment;
    if (this.#segment.length >= 4096) this.#flush();
  }

  #flush(): void {
    if (this.#segment.length === 0) return;
    this.#chunks.push(this.#segment);
    this.#segment = "";
  }

  #string(value: string): void {
    assertWellFormedString(value);
    this.#write('"');
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index);
      if (code === 0x22) this.#write('\\"');
      else if (code === 0x5c) this.#write("\\\\");
      else if (code === 0x08) this.#write("\\b");
      else if (code === 0x0c) this.#write("\\f");
      else if (code === 0x0a) this.#write("\\n");
      else if (code === 0x0d) this.#write("\\r");
      else if (code === 0x09) this.#write("\\t");
      else if (code < 0x20)
        this.#write(`\\u${code.toString(16).padStart(4, "0")}`);
      else if (code <= 0x7f) this.#write(value[index]);
      else if (code <= 0x7ff) this.#write(value[index], 2);
      else if (code >= 0xd800 && code <= 0xdbff) {
        this.#write(value.slice(index, index + 2), 4);
        index += 1;
      } else this.#write(value[index], 3);
    }
    this.#write('"');
  }

  #container(value: object, depth: number): void {
    if (depth >= this.limits.maxDepth) {
      throw invalidJson("Canonical JSON exceeds its nesting depth limit");
    }
    if (this.#ancestors.has(value)) {
      throw invalidJson("Canonical JSON does not allow cycles");
    }
    this.#ancestors.add(value);
  }

  #value(value: JsonValue, depth: number): void {
    this.#nodes += 1;
    if (this.#nodes > this.limits.maxNodes) {
      throw invalidJson("Canonical JSON exceeds its traversal limit");
    }
    if (value === null) {
      this.#write("null");
      return;
    }
    if (typeof value === "boolean") {
      this.#write(value ? "true" : "false");
      return;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value))
        throw invalidJson("Canonical JSON does not allow non-finite numbers");
      this.#write(JSON.stringify(value));
      return;
    }
    if (typeof value === "string") {
      this.#string(value);
      return;
    }
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw invalidJson("Canonical JSON array has an invalid prototype");
      }
      if (this.#nodes + value.length > this.limits.maxNodes) {
        throw invalidJson("Canonical JSON exceeds its traversal limit");
      }
      for (const key of Reflect.ownKeys(value)) {
        if (typeof key !== "string")
          throw invalidJson("Canonical JSON array has a symbol property");
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !("value" in descriptor)) {
          throw invalidJson("Canonical JSON array has an accessor property");
        }
        if (key === "length") {
          if (descriptor.enumerable || descriptor.value !== value.length) {
            throw invalidJson(
              "Canonical JSON array has an invalid length property",
            );
          }
        } else if (
          !descriptor.enumerable ||
          !isCanonicalArrayIndex(key, value.length)
        ) {
          throw invalidJson(
            "Canonical JSON array has a noncanonical own property",
          );
        }
      }
      this.#container(value, depth);
      try {
        this.#write("[");
        for (let index = 0; index < value.length; index += 1) {
          if (index > 0) this.#write(",");
          const descriptor = Object.getOwnPropertyDescriptor(
            value,
            String(index),
          );
          if (descriptor === undefined || !("value" in descriptor)) {
            throw invalidJson("Canonical JSON does not allow sparse arrays");
          }
          this.#value(descriptor.value as JsonValue, depth + 1);
        }
        this.#write("]");
      } finally {
        this.#ancestors.delete(value);
      }
      return;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && prototype !== Object.prototype) {
      throw invalidJson("Canonical JSON object has an invalid prototype");
    }
    const keys: string[] = [];
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string")
        throw invalidJson("Canonical JSON object has a symbol property");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !("value" in descriptor)
      ) {
        throw invalidJson("Canonical JSON object has an invalid property");
      }
      if (forbiddenKeys.has(key))
        throw invalidJson(
          "Canonical JSON object contains a forbidden prototype key",
        );
      keys.push(key);
      if (this.#nodes + keys.length > this.limits.maxNodes) {
        throw invalidJson("Canonical JSON exceeds its traversal limit");
      }
    }
    keys.sort();
    this.#container(value, depth);
    try {
      this.#write("{");
      for (let index = 0; index < keys.length; index += 1) {
        if (index > 0) this.#write(",");
        const key = keys[index];
        this.#string(key);
        this.#write(":");
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !("value" in descriptor)) {
          throw invalidJson("Canonical JSON object has an accessor property");
        }
        this.#value(descriptor.value as JsonValue, depth + 1);
      }
      this.#write("}");
    } finally {
      this.#ancestors.delete(value);
    }
  }
}

/** Canonicalize hostile values while bounding output and traversal before allocation. */
export function canonicalJsonBounded(
  value: JsonValue,
  limits: BoundedCanonicalJsonLimits,
): string {
  if (!Number.isSafeInteger(limits.maxBytes) || limits.maxBytes < 0) {
    throw invalidJson("Canonical JSON byte limit is invalid");
  }
  if (!Number.isSafeInteger(limits.maxDepth) || limits.maxDepth < 1) {
    throw invalidJson("Canonical JSON depth limit is invalid");
  }
  if (!Number.isSafeInteger(limits.maxNodes) || limits.maxNodes < 1) {
    throw invalidJson("Canonical JSON traversal limit is invalid");
  }
  return new BoundedCanonicalWriter(limits).serialize(value);
}

function serializeCanonical(value: JsonValue, ancestors: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw invalidJson("Canonical JSON does not allow non-finite numbers");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    assertWellFormedString(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw invalidJson("Canonical JSON array has an invalid prototype");
    }
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") {
        throw invalidJson("Canonical JSON array has a symbol property");
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) {
        throw invalidJson("Canonical JSON array has an accessor property");
      }
      if (key === "length") {
        if (descriptor.enumerable || descriptor.value !== value.length) {
          throw invalidJson(
            "Canonical JSON array has an invalid length property",
          );
        }
        continue;
      }
      if (!descriptor.enumerable || !isCanonicalArrayIndex(key, value.length)) {
        throw invalidJson(
          "Canonical JSON array has a noncanonical own property",
        );
      }
    }
    if (ancestors.has(value))
      throw invalidJson("Canonical JSON does not allow cycles");
    ancestors.add(value);
    try {
      const values: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (descriptor === undefined) {
          throw invalidJson("Canonical JSON does not allow sparse arrays");
        }
        if (!("value" in descriptor)) {
          throw invalidJson("Canonical JSON array has an accessor property");
        }
        values.push(
          serializeCanonical(descriptor.value as JsonValue, ancestors),
        );
      }
      return `[${values.join(",")}]`;
    } finally {
      ancestors.delete(value);
    }
  }
  if (typeof value !== "object" || value === null) {
    throw invalidJson("Canonical JSON value is invalid");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) {
    throw invalidJson("Canonical JSON object has an invalid prototype");
  }
  if (ancestors.has(value))
    throw invalidJson("Canonical JSON does not allow cycles");
  ancestors.add(value);
  try {
    const keys: string[] = [];
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") {
        throw invalidJson("Canonical JSON object has a symbol property");
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !descriptor.enumerable) {
        throw invalidJson(
          "Canonical JSON object has a non-enumerable property",
        );
      }
      if (!("value" in descriptor)) {
        throw invalidJson("Canonical JSON object has an accessor property");
      }
      keys.push(key);
    }
    keys.sort();
    const properties = keys.map((key) => {
      if (forbiddenKeys.has(key)) {
        throw invalidJson(
          "Canonical JSON object contains a forbidden prototype key",
        );
      }
      assertWellFormedString(key);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) {
        throw invalidJson("Canonical JSON object has an accessor property");
      }
      return `${JSON.stringify(key)}:${serializeCanonical(descriptor.value as JsonValue, ancestors)}`;
    });
    return `{${properties.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function isCanonicalArrayIndex(key: string, length: number): boolean {
  if (!/^(?:0|[1-9]\d*)$/.test(key)) return false;
  const index = Number(key);
  return (
    Number.isSafeInteger(index) &&
    index >= 0 &&
    index < length &&
    String(index) === key
  );
}
