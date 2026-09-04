import { OpenApiMcpError } from "./errors.ts";
import { canonicalJson } from "./strict-json.ts";
import type { JsonValue, Sha256 } from "./types.ts";

const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return null;
  let accumulator = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const character of value) {
    const digit = base64urlAlphabet.indexOf(character);
    if (digit < 0) return null;
    accumulator = (accumulator << 6) | digit;
    bits += 6;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 0xff);
    }
  }
  if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) return null;
  const decoded = Uint8Array.from(bytes);
  return encodeBase64Url(decoded) === value ? decoded : null;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let accumulator = 0;
  let bits = 0;
  let encoded = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      encoded += base64urlAlphabet[(accumulator >> bits) & 0x3f];
    }
  }
  if (bits > 0) encoded += base64urlAlphabet[(accumulator << (6 - bits)) & 0x3f];
  return encoded;
}

function bytesFor(value: string | Uint8Array): Uint8Array | null {
  return typeof value === "string" ? decodeBase64Url(value) : new Uint8Array(value);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

/** Hash domain-separated canonical JSON using portable Web Crypto. */
export async function sha256(domain: string, value: JsonValue): Promise<Sha256> {
  if (domain.length === 0 || domain.includes("\0")) {
    throw new OpenApiMcpError("MANIFEST_INVALID", "Digest domain must be non-empty and NUL-free");
  }
  const bytes = new TextEncoder().encode(`${domain}\0${canonicalJson(value)}`);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", toArrayBuffer(bytes));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("") as Sha256;
}

/**
 * Verify a base64url Ed25519 signature with a base64url SPKI public key.
 * Malformed material is deliberately an ordinary verification failure.
 */
export async function verifyEd25519(
  payload: Uint8Array | string,
  signature: Uint8Array | string,
  key: Uint8Array | string,
): Promise<boolean> {
  try {
    const signatureBytes = bytesFor(signature);
    const keyBytes = bytesFor(key);
    if (signatureBytes === null || keyBytes === null) return false;
    const payloadBytes = typeof payload === "string" ? new TextEncoder().encode(payload) : new Uint8Array(payload);
    const publicKey = await globalThis.crypto.subtle.importKey(
      "spki",
      toArrayBuffer(keyBytes),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await globalThis.crypto.subtle.verify(
      "Ed25519",
      publicKey,
      toArrayBuffer(signatureBytes),
      toArrayBuffer(payloadBytes),
    );
  } catch {
    return false;
  }
}
