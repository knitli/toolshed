import { expect, test } from "bun:test";
import {
  canonicalJson,
  parseJsonStrict,
  type StrictJsonLimits,
} from "../src/runtime/strict-json.ts";
import { sha256, verifyEd25519 } from "../src/runtime/digest.ts";
import { OpenApiMcpError } from "../src/runtime/errors.ts";
import {
  decodeOperationRef,
  encodeOperationRef,
  parseTypedRecordId,
} from "../src/runtime/references.ts";

const encoder = new TextEncoder();

function base64url(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let encoded = "";
  let accumulator = 0;
  let bits = 0;

  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      encoded += alphabet[(accumulator >> bits) & 0x3f];
    }
  }
  if (bits > 0) encoded += alphabet[(accumulator << (6 - bits)) & 0x3f];
  return encoded;
}

function refForJson(json: string): string {
  return `opref.v1.${base64url(encoder.encode(json))}`;
}

const smallLimits: StrictJsonLimits = {
  maxBytes: 64,
  maxDepth: 2,
  maxKeys: 2,
};

test("stable errors retain an explanatory safe message", () => {
  expect(new OpenApiMcpError("MANIFEST_INVALID", "JSON input exceeds its byte limit").message).toBe(
    "JSON input exceeds its byte limit",
  );
});

test("canonical JSON has UTF-16 key order and normalizes negative zero", () => {
  expect(canonicalJson({ z: -0, "\u{1f600}": true, "\uffff": false, a: [true, "x"] })).toBe(
    '{"a":[true,"x"],"z":0,"😀":true,"￿":false}',
  );
});

test("canonical JSON rejects sparse arrays instead of silently changing their shape", () => {
  const sparse: unknown[] = [];
  sparse.length = 1;
  expect(() => canonicalJson(sparse as never)).toThrow(/sparse/i);
});

test("strict JSON retains null-prototype objects and observes duplicate keys", () => {
  const parsed = parseJsonStrict('{"a":1,"nested":{"b":true}}');
  expect(Object.getPrototypeOf(parsed)).toBeNull();
  expect(Object.getPrototypeOf((parsed as Record<string, unknown>).nested)).toBeNull();
  expect(() => parseJsonStrict('{"a":1,"a":2}')).toThrow(/duplicate/i);
  expect(() => parseJsonStrict('{"__proto__":{}}')).toThrow(/forbidden/i);
  expect(() => parseJsonStrict('{"constructor":0}')).toThrow(/forbidden/i);
});

test("strict JSON enforces exact byte, depth, and key limits", () => {
  expect(parseJsonStrict('"é"', { ...smallLimits, maxBytes: 4 })).toBe("é");
  expect(() => parseJsonStrict('"é"', { ...smallLimits, maxBytes: 3 })).toThrow(/byte limit/i);
  expect(parseJsonStrict('[[0]]', smallLimits)).toEqual([[0]]);
  expect(() => parseJsonStrict('[[[0]]]', smallLimits)).toThrow(/depth/i);
  expect(parseJsonStrict('{"a":1,"b":2}', smallLimits)).toEqual({ a: 1, b: 2 });
  expect(() => parseJsonStrict('{"a":1,"b":2,"c":3}', smallLimits)).toThrow(/key limit/i);
});

test("strict JSON rejects malformed JSON number and string grammar", () => {
  for (const source of ["01", "1.", "1e", "+1", "NaN", "Infinity", "[1] trailing"]) {
    expect(() => parseJsonStrict(source)).toThrow(/JSON|number|trailing/i);
  }
  expect(parseJsonStrict('"\\uD83D\\uDE00"')).toBe("😀");
  expect(() => parseJsonStrict('"\\uD800"')).toThrow(/surrogate/i);
  expect(() => parseJsonStrict(`"${"\udc00"}"`)).toThrow(/surrogate/i);
  expect(() => canonicalJson({ value: Number.POSITIVE_INFINITY })).toThrow(/finite/i);
  expect(() => canonicalJson({ value: "\ud800" })).toThrow(/surrogate/i);
});

test("SHA-256 hashes a domain separator and canonical JSON", async () => {
  const digest = await sha256("test.domain", { z: 1, a: true });
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode('test.domain\u0000{"a":true,"z":1}'),
  );
  expect(digest).toBe(Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join(""));
});

test("Ed25519 verification accepts valid SPKI material and fails closed", async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const payload = encoder.encode("signed payload");
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, payload));
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));

  expect(await verifyEd25519(payload, base64url(signature), base64url(spki))).toBe(true);
  expect(await verifyEd25519(payload, "not+base64url", base64url(spki))).toBe(false);
  expect(await verifyEd25519(payload, base64url(signature), "AAAA")).toBe(false);
});

test("typed record IDs enforce their qualified ASCII grammar", () => {
  expect(parseTypedRecordId("operation:graph:users.List")).toBe("operation:graph:users.List");
  expect(parseTypedRecordId("schema:graph:#/components/schemas/User~1Name")).toBe(
    "schema:graph:#/components/schemas/User~1Name",
  );
  for (const id of [
    "operation::users.List",
    "operation:graph:.",
    "operation:graph:users/List",
    "operation:graph:users:List",
    "schema:graph:#/components/schemas/",
    "schema:graph:#/components/schemas/User/Name",
    "operation:gräph:users.List",
  ]) {
    expect(() => parseTypedRecordId(id)).toThrow(/OPERATION_REF_INVALID|invalid/i);
  }
});

test("operation refs use an exact canonical manifest-bound payload", () => {
  const payload = {
    catalogId: "work" as never,
    releaseId: "2026-09" as never,
    operationId: "operation:graph:users.List" as const,
    manifestDigest: "a".repeat(64) as never,
  };
  const ref = encodeOperationRef(payload);

  expect(ref).toBe(
    refForJson(
      '{"catalogId":"work","manifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operationId":"operation:graph:users.List","releaseId":"2026-09"}',
    ),
  );
  expect(decodeOperationRef(ref)).toEqual(payload);
  expect(() => decodeOperationRef(`${ref}x`)).toThrow(/OPERATION_REF_INVALID/);
  expect(() => decodeOperationRef(refForJson('{"releaseId":"2026-09","catalogId":"work","operationId":"operation:graph:users.List","manifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'))).toThrow(
    /OPERATION_REF_INVALID/,
  );
  expect(() => decodeOperationRef(refForJson('{"catalogId":"work","releaseId":"2026-09","operationId":"operation:graph:users.List","manifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}'))).toThrow(
    /OPERATION_REF_INVALID/,
  );
});

test("operation-ref encoding reads only own data properties", () => {
  const payload = Object.create(null) as Record<string, unknown>;
  Object.defineProperty(payload, "catalogId", { enumerable: true, get: () => "work" });
  payload.releaseId = "2026-09";
  payload.operationId = "operation:graph:users.List";
  payload.manifestDigest = "a".repeat(64);

  expect(() => encodeOperationRef(payload as never)).toThrow(/OPERATION_REF_INVALID/);
});

test("a syntactically valid manifest-digest substitution remains a valid reference", () => {
  const substituted = refForJson(
    '{"catalogId":"work","manifestDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operationId":"operation:graph:users.List","releaseId":"2026-09"}',
  );

  expect(decodeOperationRef(substituted).manifestDigest).toBe("b".repeat(64));
});
